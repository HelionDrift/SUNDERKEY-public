"""API security requirements are checked against local scheme definitions."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_api_security_scheme_audit import (
    OfflineApiSecuritySchemeAuditError,
    build_offline_api_security_scheme_audit,
    verify_offline_api_security_scheme_audit,
)
from sunderkey.service_contract_extractor import extract_service_contract_endpoints


def fixture():
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.test"}],
        "components": {
            "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {"clientCredentials": {
                        "tokenUrl": "https://issuer.example.test/token",
                        "scopes": {"read": "read records"},
                    }},
                },
                "api_key": {"type": "apiKey", "in": "header", "name": "X-Key"},
                "oidc": {
                    "type": "openIdConnect",
                    "openIdConnectUrl": "https://issuer.example.test/discovery",
                },
            },
        },
        "paths": {
            "/read": {"get": {"security": [{"oauth": ["read"]}]}},
            "/missing": {"get": {"security": [{"phantom": []}]}},
            "/bad-scope": {"get": {"security": [{"oauth": ["write"]}]}},
            "/api-key": {"get": {"security": [{"api_key": []}]}},
            "/oidc": {"get": {"security": [{"oidc": ["profile"]}]}},
            "/unprotected": {"get": {"security": []}},
        },
    }
    content = json.dumps(document).encode("utf-8")
    bundle = extract_service_contract_endpoints(content)
    assertions = [
        {
            "principal_ref": "principalref:a",
            "grants": [{"scheme": "oauth", "scopes": ["read"]}],
        },
        {
            "principal_ref": "principalref:b",
            "grants": [{"scheme": "phantom", "scopes": []}],
        },
        {"principal_ref": "principalref:c", "grants": []},
        {
            "principal_ref": "principalref:d",
            "grants": [{"scheme": "api_key", "scopes": []}],
        },
    ]
    return content, bundle, assertions


class OfflineApiSecuritySchemeAuditTests(unittest.TestCase):
    def test_missing_scheme_and_scope_filter_declaration_pairs(self) -> None:
        content, bundle, assertions = fixture()
        audit = build_offline_api_security_scheme_audit(
            content=content, bundle=bundle, principal_assertions=assertions
        )
        self.assertEqual(
            verify_offline_api_security_scheme_audit(
                content=content, bundle=bundle,
                principal_assertions=assertions, audit=audit,
            ),
            audit,
        )
        self.assertEqual(audit["locally_resolved_pair_count"], 6)
        rows = {
            endpoint.path: next(
                item for item in audit["rows"]
                if item["endpoint_sha256"] == endpoint.endpoint_sha256
            )
            for endpoint in bundle.endpoints
        }
        self.assertEqual(rows["/read"]["definition_status"], "locally_resolved")
        self.assertEqual(rows["/api-key"]["locally_resolved_pair_count"], 3)
        self.assertEqual(rows["/missing"]["issues"][0]["code"], "undefined_scheme")
        self.assertEqual(rows["/missing"]["locally_resolved_pair_count"], 0)
        self.assertEqual(rows["/bad-scope"]["issues"][0]["code"], "undefined_scope")
        self.assertEqual(rows["/oidc"]["issues"][0]["code"], "external_scopes_unverified")
        self.assertEqual(
            rows["/unprotected"]["definition_status"],
            "no_security_requirement_declared",
        )
        self.assertNotIn("api.example.test", json.dumps(audit))
        self.assertFalse(audit["target_authorization_verified"])
        self.assertFalse(audit["positive_use_approved"])

    def test_content_assertion_and_output_rebinding_fail(self) -> None:
        content, bundle, assertions = fixture()
        audit = build_offline_api_security_scheme_audit(
            content=content, bundle=bundle, principal_assertions=assertions
        )
        with self.assertRaisesRegex(OfflineApiSecuritySchemeAuditError, "differ"):
            build_offline_api_security_scheme_audit(
                content=content.replace(b"read records", b"other records"),
                bundle=bundle,
                principal_assertions=assertions,
            )
        changed_assertions = copy.deepcopy(assertions)
        changed_assertions[0]["grants"][0]["scopes"] = ["write"]
        with self.assertRaisesRegex(OfflineApiSecuritySchemeAuditError, "does not match"):
            verify_offline_api_security_scheme_audit(
                content=content, bundle=bundle,
                principal_assertions=changed_assertions, audit=audit,
            )
        changed = copy.deepcopy(audit)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiSecuritySchemeAuditError, "does not match"):
            verify_offline_api_security_scheme_audit(
                content=content, bundle=bundle,
                principal_assertions=assertions, audit=changed,
            )

    def test_swagger_basic_scopes_and_malformed_type_are_not_resolved(self) -> None:
        document = {
            "swagger": "2.0",
            "host": "api.example.test",
            "schemes": ["https"],
            "securityDefinitions": {
                "basic_auth": {"type": "basic"},
                "broken": {"type": ["not", "a", "string"]},
            },
            "paths": {
                "/good": {"get": {"security": [{"basic_auth": []}]}},
                "/bad": {"get": {"security": [{"basic_auth": ["admin"]}]}},
                "/broken": {"get": {"security": [{"broken": []}]}},
            },
        }
        content = json.dumps(document).encode("utf-8")
        bundle = extract_service_contract_endpoints(content)
        assertions = [
            {"principal_ref": "principalref:a", "grants": []},
            {
                "principal_ref": "principalref:b",
                "grants": [{"scheme": "basic_auth", "scopes": ["admin"]}],
            },
        ]
        audit = build_offline_api_security_scheme_audit(
            content=content, bundle=bundle, principal_assertions=assertions
        )
        rows = {
            endpoint.path: next(
                item for item in audit["rows"]
                if item["endpoint_sha256"] == endpoint.endpoint_sha256
            )
            for endpoint in bundle.endpoints
        }
        self.assertEqual(rows["/good"]["definition_status"], "locally_resolved")
        self.assertEqual(rows["/bad"]["issues"][0]["code"], "scopes_on_non_oauth_scheme")
        self.assertEqual(rows["/broken"]["issues"][0]["code"], "unsupported_scheme_type")

    def test_incomplete_oauth_flows_withhold_pairs_across_versions(self) -> None:
        content, _, assertions = fixture()
        document = json.loads(content)
        for changed_flow in (
            {"scopes": {"read": "read records"}},
            {"tokenUrl": "not a URL", "scopes": {"read": "read records"}},
            {"tokenUrl": "https://issuer.example.test/token", "scopes": {"read": 1}},
            {"tokenUrl": "https://issuer.example.test/token", "scopes": {"read": "read"},
             "extra": "ignored"},
        ):
            with self.subTest(flow=changed_flow):
                changed = copy.deepcopy(document)
                changed["components"]["securitySchemes"]["oauth"]["flows"] = {
                    "clientCredentials": changed_flow
                }
                changed_content = json.dumps(changed).encode("utf-8")
                bundle = extract_service_contract_endpoints(changed_content)
                audit = build_offline_api_security_scheme_audit(
                    content=changed_content, bundle=bundle, principal_assertions=assertions
                )
                read_endpoint = next(item for item in bundle.endpoints if item.path == "/read")
                row = next(
                    item for item in audit["rows"]
                    if item["endpoint_sha256"] == read_endpoint.endpoint_sha256
                )
                expected_status = (
                    "locally_resolved" if "extra" in changed_flow else "unresolved"
                )
                self.assertEqual(row["definition_status"], expected_status)
                if expected_status == "unresolved":
                    self.assertEqual(row["issues"][0]["code"], "incomplete_scheme_definition")
                    self.assertEqual(row["locally_resolved_pair_count"], 0)

        swagger = {
            "swagger": "2.0",
            "host": "api.example.test",
            "securityDefinitions": {
                "oauth": {"type": "oauth2", "flow": "application", "scopes": {"read": "read"}}
            },
            "paths": {"/read": {"get": {"security": [{"oauth": ["read"]}]}}},
        }
        swagger_content = json.dumps(swagger).encode("utf-8")
        bundle = extract_service_contract_endpoints(swagger_content)
        audit = build_offline_api_security_scheme_audit(
            content=swagger_content, bundle=bundle, principal_assertions=assertions
        )
        self.assertEqual(audit["rows"][0]["issues"][0]["code"], "incomplete_scheme_definition")

    def test_openapi_minor_version_controls_mutual_tls_roles_and_device_flow(self) -> None:
        content, _, assertions = fixture()
        document = json.loads(content)
        document["components"]["securitySchemes"]["mtls"] = {"type": "mutualTLS"}
        document["paths"]["/mtls"] = {"get": {"security": [{"mtls": []}]}}
        document["paths"]["/roles"] = {"get": {"security": [{"api_key": ["admin"]}]}}
        document["components"]["securitySchemes"]["oauth"]["flows"] = {
            "deviceAuthorization": {
                "deviceAuthorizationUrl": "https://issuer.example.test/device",
                "tokenUrl": "https://issuer.example.test/token",
                "scopes": {"read": "read records"},
            }
        }
        for version, expected in (
            ("3.0.3", ("unsupported_scheme_type", "scopes_on_non_oauth_scheme",
                       "incomplete_scheme_definition")),
            ("3.1.0", (None, "roles_unverified", "incomplete_scheme_definition")),
            ("3.2.1", (None, "roles_unverified", None)),
        ):
            with self.subTest(version=version):
                changed = copy.deepcopy(document)
                changed["openapi"] = version
                changed_content = json.dumps(changed).encode("utf-8")
                bundle = extract_service_contract_endpoints(changed_content)
                audit = build_offline_api_security_scheme_audit(
                    content=changed_content, bundle=bundle, principal_assertions=assertions
                )
                rows = {
                    endpoint.path: next(
                        item for item in audit["rows"]
                        if item["endpoint_sha256"] == endpoint.endpoint_sha256
                    )
                    for endpoint in bundle.endpoints
                }
                for path, issue in zip(("/mtls", "/roles", "/read"), expected, strict=True):
                    self.assertEqual(
                        rows[path]["issues"][0]["code"] if issue is not None else None,
                        issue,
                    )
                    if issue is None:
                        self.assertEqual(rows[path]["definition_status"], "locally_resolved")


if __name__ == "__main__":
    unittest.main()

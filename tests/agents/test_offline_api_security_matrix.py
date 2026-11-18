"""API security declarations produce review-only differential candidates."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_api_security_matrix import (
    OfflineApiSecurityMatrixError,
    build_offline_api_security_matrix,
    verify_offline_api_security_matrix,
)
from sunderkey.service_contract_extractor import extract_service_contract_endpoints


def fixture():
    contract = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://api.example.test"}],
        "security": [{"oauth": ["read"]}],
        "paths": {
            "/records": {"get": {"operationId": "listRecords"}},
            "/either": {
                "get": {"security": [{"oauth": ["read"]}, {"api_key": []}]}
            },
            "/both": {
                "get": {"security": [{"oauth": ["read"], "api_key": []}]}
            },
            "/anonymous": {"get": {"security": [{}]}},
            "/unspecified": {"get": {"security": []}},
        },
    }
    bundle = extract_service_contract_endpoints(json.dumps(contract).encode("utf-8"))
    principals = [
        {
            "principal_ref": "principalref:a",
            "grants": [{"scheme": "oauth", "scopes": ["read"]}],
        },
        {
            "principal_ref": "principalref:b",
            "grants": [{"scheme": "api_key", "scopes": []}],
        },
        {"principal_ref": "principalref:c", "grants": []},
    ]
    return bundle, principals


class OfflineApiSecurityMatrixTests(unittest.TestCase):
    def test_or_and_anonymous_and_unspecified_declarations_remain_hypotheses(self) -> None:
        bundle, principals = fixture()
        result = build_offline_api_security_matrix(
            bundle=bundle, principal_assertions=principals
        )
        self.assertEqual(
            verify_offline_api_security_matrix(
                bundle=bundle, principal_assertions=principals, document=result
            ),
            result,
        )
        self.assertEqual(result["endpoint_count"], 5)
        self.assertEqual(result["differential_pair_count"], 4)
        rows = {
            endpoint.path: next(
                item for item in result["rows"]
                if item["endpoint_sha256"] == endpoint.endpoint_sha256
            )
            for endpoint in bundle.endpoints
        }
        self.assertEqual(rows["/records"]["declaration_status"], "differential_pair_available")
        self.assertEqual(len(rows["/records"]["differential_pairs"]), 2)
        self.assertEqual(len(rows["/either"]["differential_pairs"]), 2)
        self.assertEqual(rows["/both"]["declaration_status"], "no_principal_matches_declaration")
        self.assertEqual(
            rows["/anonymous"]["declaration_status"],
            "all_principals_match_declaration",
        )
        self.assertEqual(
            rows["/unspecified"]["declaration_status"],
            "no_security_requirement_declared",
        )
        self.assertIsNone(rows["/unspecified"]["principal_matches"][0]["declaration_match"])
        self.assertFalse(result["target_authorization_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(result["effects"]["target_interaction"], "none")
        self.assertNotIn("api.example.test", json.dumps(result))

    def test_duplicate_unsorted_and_tampered_inputs_fail_closed(self) -> None:
        bundle, principals = fixture()
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "sorted and unique"):
            build_offline_api_security_matrix(
                bundle=bundle, principal_assertions=list(reversed(principals))
            )
        changed_principals = copy.deepcopy(principals)
        changed_principals[1]["principal_ref"] = changed_principals[0]["principal_ref"]
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "sorted and unique"):
            build_offline_api_security_matrix(
                bundle=bundle, principal_assertions=changed_principals
            )
        result = build_offline_api_security_matrix(
            bundle=bundle, principal_assertions=principals
        )
        changed = copy.deepcopy(result)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "does not match"):
            verify_offline_api_security_matrix(
                bundle=bundle, principal_assertions=principals, document=changed
            )
        changed_principals = copy.deepcopy(principals)
        changed_principals[0]["grants"][0]["scopes"] = ["write"]
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "does not match"):
            verify_offline_api_security_matrix(
                bundle=bundle,
                principal_assertions=changed_principals,
                document=result,
            )

    def test_combined_scheme_requirement_needs_both_declared_grants(self) -> None:
        bundle, principals = fixture()
        principals.append({
            "principal_ref": "principalref:d",
            "grants": [
                {"scheme": "api_key", "scopes": []},
                {"scheme": "oauth", "scopes": ["read"]},
            ],
        })
        result = build_offline_api_security_matrix(
            bundle=bundle, principal_assertions=principals
        )
        both_endpoint = next(item for item in bundle.endpoints if item.path == "/both")
        both = next(
            item for item in result["rows"]
            if item["endpoint_sha256"] == both_endpoint.endpoint_sha256
        )
        self.assertEqual(both["declaration_status"], "differential_pair_available")
        self.assertEqual(len(both["differential_pairs"]), 3)
        self.assertTrue(both["principal_matches"][-1]["declaration_match"])

    def test_untyped_bundle_and_unbounded_assertions_fail(self) -> None:
        bundle, principals = fixture()
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "count"):
            build_offline_api_security_matrix(
                bundle=bundle,
                principal_assertions=[
                    {"principal_ref": f"principalref:{index:03d}", "grants": []}
                    for index in range(33)
                ],
            )
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "typed"):
            build_offline_api_security_matrix(
                bundle=bundle.to_dict(), principal_assertions=principals
            )
        wsdl = extract_service_contract_endpoints(
            b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"/>'
        )
        with self.assertRaisesRegex(OfflineApiSecurityMatrixError, "HTTP API"):
            build_offline_api_security_matrix(
                bundle=wsdl, principal_assertions=principals
            )


if __name__ == "__main__":
    unittest.main()

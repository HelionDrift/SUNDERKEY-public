"""Phase 160 fail-closed signed assessment scope tests."""

from __future__ import annotations

import copy
import json
import re
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.signed_scope_compiler import (
    MAX_CONCURRENCY,
    MAX_REQUESTS,
    MAX_REQUESTS_PER_MINUTE,
    ScopeBudgetState,
    SignedScopeError,
    canonical_json,
    compile_signed_scope,
    evaluate_request,
    request_is_in_scope,
    scope_contains_scope,
    scopes_overlap,
    verify_signed_scope,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "signed-assessment-scope-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "signed_scope_compiler.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "signed-assessment-scope.md",
)
NOW = datetime(2026, 9, 20, 3, 30, tzinfo=UTC)


def base_specification() -> dict:
    return {
        "schema_version": 1,
        "issuer": "assessment-authority.example",
        "key_id": "scope-signing-key.2026-09",
        "nonce": "Tkd4ZWlDN1p3RkJNUQ",
        "sequence_number": 42,
        "issued_at": "2026-09-20T03:00:00Z",
        "expires_at": "2026-09-20T05:00:00Z",
        "assessment_window": {
            "starts_at": "2026-09-20T03:00:00Z",
            "ends_at": "2026-09-20T04:30:00Z",
        },
        "targets": {
            "https_origins": ["HTTPS://API.Example.Test:443/"],
            "exact_hosts": ["API.Example.Test", "192.0.2.10", "2001:db8::10"],
            "wildcard_subdomains": ["*.Staging.Example.Test"],
            "cidrs": ["192.0.2.0/28", "2001:db8::/124"],
            "ports": [8443, 443],
            "http_methods": ["post", "GET"],
            "path_prefixes": ["/health/", "/api/v1"],
        },
        "exclusions": [
            {
                "exclusion_id": "exclude.admin-writes",
                "https_origins": [],
                "exact_hosts": [],
                "wildcard_subdomains": [],
                "cidrs": [],
                "ports": [],
                "http_methods": ["POST"],
                "path_prefixes": ["/api/v1/admin"],
            }
        ],
        "protected_endpoints": ["https://API.example.test:443/health/ready"],
        "budgets": {
            "max_requests": 1000,
            "max_concurrency": 8,
            "max_requests_per_minute": 120,
        },
        "impact_tier_ceiling": "R2",
        "allowed_technique_ids": ["AT3-GB-D06-S09-01", "CUSTOM.API.CHECK.1"],
        "data_handling": {
            "classification": "confidential",
            "collection": "minimized_content",
            "storage": "ephemeral_encrypted",
            "retention_days": 7,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.oncall.primary",
    }


class SignedScopeCompilerPhase160Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.specification = base_specification()

    def compile(self, specification: dict | None = None, **kwargs):
        return compile_signed_scope(
            self.specification if specification is None else specification,
            self.private_key,
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    def verify(self, signed=None, **kwargs):
        return verify_signed_scope(
            self.compile() if signed is None else signed,
            kwargs.pop("public_key", self.public_key),
            expected_issuer=kwargs.pop("expected_issuer", self.specification["issuer"]),
            expected_key_id=kwargs.pop("expected_key_id", self.specification["key_id"]),
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    def decision(self, verified, url: str, **kwargs):
        return evaluate_request(
            verified,
            url=url,
            method=kwargs.pop("method", "GET"),
            technique_id=kwargs.pop("technique_id", "AT3-GB-D06-S09-01"),
            impact_tier=kwargs.pop("impact_tier", "R1"),
            budget_state=kwargs.pop("budget_state", ScopeBudgetState(0, 0, 0)),
            at=kwargs.pop("at", NOW),
            **kwargs,
        )

    def test_canonical_content_address_signature_and_schema(self) -> None:
        first = self.compile()
        second = self.compile()
        self.assertEqual(first.document_json, second.document_json)
        document = first.to_dict()
        self.assertEqual(document["targets"]["https_origins"], ["https://api.example.test"])
        self.assertEqual(document["targets"]["exact_hosts"][0], "192.0.2.10")
        self.assertEqual(document["targets"]["http_methods"], ["GET", "POST"])
        self.assertEqual(document["targets"]["path_prefixes"], ["/api/v1", "/health"])
        self.assertEqual(
            document["effects"],
            {
                "authority": "none",
                "deployment": "none",
                "execution": "none",
                "network": "none",
                "qualification": "none",
                "routing": "none",
            },
        )
        self.assertEqual(first.document_json, canonical_json(document))
        verified = self.verify(first, minimum_sequence_number=42)
        self.assertEqual(verified.scope_id, document["scope_id"])
        self.assertRegex(verified.verification_key_sha256, r"^sha256:[0-9a-f]{64}$")
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(document)

    def test_wildcard_is_one_label_and_has_no_suffix_confusion(self) -> None:
        verified = self.verify()
        self.assertTrue(self.decision(verified, "https://a.staging.example.test/api/v1").allowed)
        for url in (
            "https://staging.example.test/api/v1",
            "https://a.b.staging.example.test/api/v1",
            "https://evil-staging.example.test/api/v1",
            "https://api.example.test.evil.test/api/v1",
        ):
            with self.subTest(url=url):
                self.assertFalse(self.decision(verified, url).allowed)
        for wildcard in ("*", "*.com", "*.co.uk", "a.*.example.test"):
            with self.subTest(wildcard=wildcard):
                hostile = base_specification()
                hostile["targets"]["wildcard_subdomains"] = [wildcard]
                with self.assertRaises(SignedScopeError):
                    self.compile(hostile)

    def test_ip_literals_cidr_boundaries_ipv6_and_ports(self) -> None:
        verified = self.verify()
        allowed = (
            "https://192.0.2.0/api/v1",
            "https://192.0.2.15/api/v1",
            "https://[2001:db8::]/api/v1",
            "https://[2001:db8::f]/api/v1",
            "https://api.example.test:8443/api/v1",
        )
        denied = (
            "https://192.0.2.16/api/v1",
            "https://[2001:db8::11]/api/v1",
            "https://api.example.test:9443/api/v1",
        )
        for url in allowed:
            with self.subTest(url=url):
                self.assertTrue(self.decision(verified, url).allowed)
        for url in denied:
            with self.subTest(url=url):
                self.assertFalse(self.decision(verified, url).allowed)

    def test_method_path_exclusions_protected_endpoint_and_impact(self) -> None:
        verified = self.verify()
        self.assertFalse(
            self.decision(
                verified,
                "https://api.example.test/api/v1/admin/users",
                method="POST",
            ).allowed
        )
        self.assertTrue(
            self.decision(
                verified,
                "https://api.example.test/api/v1/admin/users",
                method="GET",
            ).allowed
        )
        self.assertFalse(self.decision(verified, "https://api.example.test/health/ready").allowed)
        self.assertFalse(self.decision(verified, "https://api.example.test/api/v1x").allowed)
        self.assertFalse(
            self.decision(
                verified,
                "https://api.example.test/api/v1",
                impact_tier="R3",
            ).allowed
        )

    def test_ambiguous_urls_encodings_traversal_and_default_routes_fail(self) -> None:
        verified = self.verify()
        urls = (
            "https://user@api.example.test/api/v1",
            "https://api.example.test/api/%76%31",
            "https://api.example.test/api/../health",
            "https://api.example.test/api//v1",
            "https://api.example.test/api/v1#fragment",
            "https://api.example.test/api/v1?",
            "https://192.002.000.001/api/v1",
            "https://api.exаmple.test/api/v1",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertFalse(self.decision(verified, url).allowed)
        for cidr in ("0.0.0.0/0", "::/0", "192.0.2.1/24"):
            with self.subTest(cidr=cidr):
                hostile = base_specification()
                hostile["targets"]["cidrs"] = [cidr]
                with self.assertRaises(SignedScopeError):
                    self.compile(hostile)
        mixed = base_specification()
        mixed["targets"]["https_origins"] = ["https://api.example.test%2f.evil.test"]
        with self.assertRaises(SignedScopeError):
            self.compile(mixed)

    def test_tampering_wrong_key_and_key_identity_substitution_fail(self) -> None:
        signed = self.compile()
        tampered = signed.to_dict()
        tampered["budgets"]["max_requests"] = 1001
        with self.assertRaises(SignedScopeError):
            self.verify(tampered)
        with self.assertRaises(SignedScopeError):
            self.verify(signed, public_key=Ed25519PrivateKey.generate().public_key())
        rogue_key = Ed25519PrivateKey.generate()
        rogue_spec = base_specification()
        rogue_spec["key_id"] = "scope-signing-key.rogue"
        rogue = compile_signed_scope(rogue_spec, rogue_key, now=NOW)
        with self.assertRaisesRegex(SignedScopeError, "key_id"):
            self.verify(rogue, public_key=rogue_key.public_key())
        with self.assertRaisesRegex(SignedScopeError, "issuer"):
            self.verify(signed, expected_issuer="different-authority.example")

    def test_budget_bounds_and_runtime_budget_state(self) -> None:
        for field, value in (
            ("max_requests", MAX_REQUESTS + 1),
            ("max_concurrency", MAX_CONCURRENCY + 1),
            ("max_requests_per_minute", MAX_REQUESTS_PER_MINUTE + 1),
        ):
            with self.subTest(field=field):
                invalid = base_specification()
                invalid["budgets"][field] = value
                with self.assertRaises(SignedScopeError):
                    self.compile(invalid)
        invalid = base_specification()
        invalid["budgets"]["max_requests"] = 4
        invalid["budgets"]["max_concurrency"] = 5
        with self.assertRaises(SignedScopeError):
            self.compile(invalid)
        verified = self.verify()
        url = "https://api.example.test/api/v1"
        states = (
            ScopeBudgetState(1000, 0, 0),
            ScopeBudgetState(0, 8, 0),
            ScopeBudgetState(0, 0, 120),
        )
        for state in states:
            with self.subTest(state=state):
                self.assertFalse(self.decision(verified, url, budget_state=state).allowed)
        self.assertFalse(
            self.decision(verified, url, budget_state=ScopeBudgetState(-1, 0, 0)).allowed
        )

    def test_future_expired_and_bad_temporal_order_fail_closed(self) -> None:
        with self.assertRaisesRegex(SignedScopeError, "future-dated"):
            self.compile(now=datetime(2026, 9, 20, 2, 59, 59, tzinfo=UTC))
        signed = self.compile()
        with self.assertRaisesRegex(SignedScopeError, "expired"):
            self.verify(signed, now=datetime(2026, 9, 20, 4, 30, tzinfo=UTC))
        invalid = base_specification()
        invalid["assessment_window"]["ends_at"] = "2026-09-20T05:30:00Z"
        with self.assertRaisesRegex(SignedScopeError, "ordered"):
            self.compile(invalid)

    def test_duplicate_keys_unknown_fields_shadowing_and_secrets_fail(self) -> None:
        signed = self.compile()
        duplicate = signed.document_json.replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaisesRegex(SignedScopeError, "duplicate"):
            self.verify(duplicate)
        unknown = base_specification()
        unknown["routing_effect"] = "grant"
        with self.assertRaisesRegex(SignedScopeError, "unknown"):
            self.compile(unknown)
        secret = base_specification()
        secret["private_key"] = "-----BEGIN " + "PRIVATE KEY-----"
        with self.assertRaisesRegex(SignedScopeError, "unknown|secret"):
            self.compile(secret)
        shadowed = base_specification()
        duplicate_rule = copy.deepcopy(shadowed["exclusions"][0])
        duplicate_rule["exclusion_id"] = "exclude.admin-writes.copy"
        duplicate_rule["path_prefixes"] = ["/api/v1/admin/users"]
        shadowed["exclusions"].append(duplicate_rule)
        with self.assertRaisesRegex(SignedScopeError, "shadowed"):
            self.compile(shadowed)
        impossible = base_specification()
        impossible["exclusions"] = [
            {
                "exclusion_id": "exclude.impossible-origin-port",
                "https_origins": ["https://api.example.test"],
                "exact_hosts": [],
                "wildcard_subdomains": [],
                "cidrs": [],
                "ports": [8443],
                "http_methods": [],
                "path_prefixes": [],
            }
        ]
        with self.assertRaisesRegex(SignedScopeError, "cannot match"):
            self.compile(impossible)

    def test_request_checker_requires_verified_scope_and_explicit_budget_state(self) -> None:
        signed = self.compile()
        decision = evaluate_request(
            signed,  # type: ignore[arg-type]
            url="https://api.example.test/api/v1",
            method="GET",
            technique_id="AT3-GB-D06-S09-01",
            impact_tier="R1",
            budget_state=ScopeBudgetState(0, 0, 0),
            at=NOW,
        )
        self.assertFalse(decision.allowed)
        verified = self.verify(signed)
        self.assertFalse(
            evaluate_request(
                verified,
                url="https://api.example.test/api/v1",
                method="GET",
                technique_id="AT3-GB-D06-S09-01",
                impact_tier="R1",
                budget_state=None,  # type: ignore[arg-type]
                at=NOW,
            ).allowed
        )
        self.assertTrue(
            request_is_in_scope(
                verified,
                url="https://api.example.test/api/v1",
                method="GET",
                technique_id="AT3-GB-D06-S09-01",
                impact_tier="R1",
                budget_state=ScopeBudgetState(0, 0, 0),
                at=NOW,
            )
        )

    def test_overlap_containment_and_authority_ceiling(self) -> None:
        parent_spec = base_specification()
        parent_spec["exclusions"] = []
        parent_spec["protected_endpoints"] = []
        parent = self.verify(self.compile(parent_spec))
        child_spec = copy.deepcopy(parent_spec)
        child_spec["nonce"] = "Y2hpbGQtc2NvcGUtbm9uY2U"
        child_spec["sequence_number"] = 43
        child_spec["assessment_window"]["starts_at"] = "2026-09-20T03:15:00Z"
        child_spec["assessment_window"]["ends_at"] = "2026-09-20T04:00:00Z"
        child_spec["expires_at"] = "2026-09-20T04:15:00Z"
        child_spec["targets"] = {
            "https_origins": ["https://api.example.test"],
            "exact_hosts": [],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [443],
            "http_methods": ["GET"],
            "path_prefixes": ["/api/v1/items"],
        }
        child_spec["budgets"] = {
            "max_requests": 100,
            "max_concurrency": 2,
            "max_requests_per_minute": 20,
        }
        child_spec["impact_tier_ceiling"] = "R1"
        child_spec["allowed_technique_ids"] = ["AT3-GB-D06-S09-01"]
        child_spec["data_handling"]["retention_days"] = 3
        child_signed = self.compile(child_spec, authority_ceiling=parent)
        child = self.verify(child_signed)
        self.assertTrue(scopes_overlap(parent, child))
        self.assertTrue(scope_contains_scope(parent, child))
        self.assertFalse(scope_contains_scope(child, parent))
        escalated = copy.deepcopy(child_spec)
        escalated["targets"]["exact_hosts"] = ["api.example.test"]
        escalated["targets"]["ports"] = [443, 9443]
        with self.assertRaisesRegex(SignedScopeError, "authority ceiling"):
            self.compile(escalated, authority_ceiling=parent)
        substituted_authority = copy.deepcopy(child_spec)
        substituted_authority["key_id"] = "scope-signing-key.substitute"
        with self.assertRaisesRegex(SignedScopeError, "authority ceiling"):
            self.compile(substituted_authority, authority_ceiling=parent)

    def test_raw_private_key_is_not_persisted(self) -> None:
        raw_private = self.private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        signed = compile_signed_scope(self.specification, raw_private, now=NOW)
        raw_public = self.public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.assertNotIn(base64_text(raw_private), signed.document_json)
        self.assertNotIn(base64_text(raw_public), signed.document_json)
        self.assertNotIn("public_key", signed.document_json)
        self.assertNotIn("private_key", signed.document_json)
        self.verify(signed)

    def test_source_hygiene_scans(self) -> None:
        forbidden_marker = re.compile(
            "(?i)(" + "chat" + "gpt|gene" + "rated by " + "ai|clau" + "de)"
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                self.assertIsNone(forbidden_marker.search(text))


def base64_text(value: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


if __name__ == "__main__":
    unittest.main()

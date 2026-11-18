"""Phase 165 fail-closed egress proxy contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.egress_proxy_contracts import (
    NO_EFFECTS,
    AdmissionDisposition,
    EgressEnforcementObservation,
    EgressPolicy,
    EgressProxyContractError,
    EgressRequest,
    EndpointRule,
    ResolutionAttestation,
    evaluate_egress_request,
    parse_contract,
    validate_enforcement_observation,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "egress-proxy-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "egress_proxy_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "egress-proxy-contracts.md",
)
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


class EgressProxyContractsPhase165Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(sunderkey.evaluate_egress_request, evaluate_egress_request)
        self.assertIs(
            sunderkey.validate_enforcement_observation,
            validate_enforcement_observation,
        )

    def rule(self) -> EndpointRule:
        return EndpointRule(
            rule_ref="egressrule:openai-responses",
            host="api.openai.com",
            port=443,
            allowed_methods=("POST",),
            allowed_path_prefixes=("/v1/responses",),
            allowed_ip_networks=("203.0.113.0/24", "2001:db8::/32"),
            tls_spki_sha256=(ONE,),
            max_request_bytes=200_000,
            max_response_bytes=2_000_000,
        )

    def policy(self) -> EgressPolicy:
        return EgressPolicy(
            tenant_ref="tenant:acme",
            mission_ref="mission:alpha",
            scope_ref="scope:approved-v1",
            worker_ref="worker:api-specialist-01",
            policy_version=3,
            valid_from="2026-09-20T12:00:00Z",
            valid_until="2026-09-20T13:00:00Z",
            maximum_resolution_age_seconds=120,
            endpoint_rules=(self.rule(),),
        )

    def attestation(self) -> ResolutionAttestation:
        return ResolutionAttestation(
            tenant_ref="tenant:acme",
            mission_ref="mission:alpha",
            worker_ref="worker:api-specialist-01",
            host="api.openai.com",
            resolver_ref="resolver:proxy-dns-01",
            resolved_addresses=("203.0.113.18",),
            observed_at="2026-09-20T12:01:00Z",
            expires_at="2026-09-20T12:03:00Z",
            collector_signature_ref="signature:dns-observation-01",
            collector_signature_sha256=ZERO,
        )

    def request(
        self,
        policy: EgressPolicy | None = None,
        attestation: ResolutionAttestation | None = None,
        **changes: object,
    ) -> EgressRequest:
        active_policy = policy or self.policy()
        active_attestation = attestation or self.attestation()
        policy_doc = active_policy.to_dict()
        attestation_doc = active_attestation.to_dict()
        values: dict[str, object] = {
            "tenant_ref": "tenant:acme",
            "mission_ref": "mission:alpha",
            "scope_ref": "scope:approved-v1",
            "worker_ref": "worker:api-specialist-01",
            "operation_ref": "operation:evaluation-001",
            "protocol": "https",
            "host": "api.openai.com",
            "port": 443,
            "method": "POST",
            "path": "/v1/responses",
            "request_bytes": 8192,
            "body_sha256": ZERO,
            "credential_lease_ref": "credentiallease:openai-eval-01",
            "follow_redirects": False,
            "requested_at": "2026-09-20T12:01:30Z",
            "policy_id": policy_doc["policy_id"],
            "policy_sha256": policy_doc["policy_sha256"],
            "resolution_attestation_id": attestation_doc["attestation_id"],
            "resolution_attestation_sha256": attestation_doc["attestation_sha256"],
        }
        values.update(changes)
        return EgressRequest(**values)

    def decision(self):
        policy = self.policy()
        attestation = self.attestation()
        request = self.request(policy, attestation)
        decision = evaluate_egress_request(
            policy,
            attestation,
            request,
            evaluated_at="2026-09-20T12:02:00Z",
        )
        return policy, request, decision

    def observation(self, decision, **changes: object) -> EgressEnforcementObservation:
        decision_doc = decision.to_dict()
        values: dict[str, object] = {
            "decision_id": decision_doc["decision_id"],
            "decision_sha256": decision_doc["decision_sha256"],
            "proxy_instance_ref": "proxy:egress-01",
            "proxy_version": "1.4.2",
            "observed_host": "api.openai.com",
            "observed_port": 443,
            "resolved_address": "203.0.113.18",
            "tls_spki_sha256": ONE,
            "response_bytes": 18_000,
            "outcome": "completed",
            "redirect_blocked": True,
            "observed_at": "2026-09-20T12:02:10Z",
            "evidence_refs": ("evidence:proxy-capture-01",),
        }
        values.update(changes)
        return EgressEnforcementObservation(**values)

    def test_allowed_request_is_content_addressed_and_bound(self) -> None:
        policy = self.policy()
        attestation = self.attestation()
        request = self.request(policy, attestation)
        decision = evaluate_egress_request(
            policy,
            attestation,
            request,
            evaluated_at="2026-09-20T12:02:00Z",
        )
        self.assertEqual(decision.disposition, AdmissionDisposition.ALLOW)
        self.assertEqual(decision.blocker_codes, ())
        self.assertEqual(decision.matched_rule_ref, "egressrule:openai-responses")
        self.assertTrue(decision.to_dict()["decision_id"].startswith("EAD-"))

    def test_policy_and_attestation_round_trip_and_reject_tampering(self) -> None:
        for contract in (self.policy(), self.attestation()):
            document = contract.to_dict()
            parsed = parse_contract(json.dumps(document))
            self.assertEqual(parsed.to_dict(), document)
            tampered = copy.deepcopy(document)
            if document["kind"] == "egress_policy":
                tampered["policy_version"] += 1
            else:
                tampered["host"] = "other.example.com"
            with self.assertRaises(EgressProxyContractError):
                parse_contract(tampered)

    def test_unknown_endpoint_method_path_size_and_redirect_are_denied(self) -> None:
        cases = (
            ({"host": "other.example.com"}, "endpoint_not_allowed"),
            ({"method": "GET"}, "method_not_allowed"),
            ({"path": "/v1/files"}, "path_not_allowed"),
            ({"request_bytes": 200_001}, "request_size_exceeded"),
            ({"follow_redirects": True}, "redirect_following_prohibited"),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                policy = self.policy()
                attestation = self.attestation()
                request = self.request(policy, attestation, **changes)
                decision = evaluate_egress_request(
                    policy,
                    attestation,
                    request,
                    evaluated_at="2026-09-20T12:02:00Z",
                )
                self.assertEqual(decision.disposition, AdmissionDisposition.DENY)
                self.assertIn(expected, decision.blocker_codes)

    def test_cross_context_stale_resolution_and_rebinding_are_denied(self) -> None:
        policy = self.policy()
        attestation = self.attestation()
        wrong_context = self.request(policy, attestation, tenant_ref="tenant:other")
        decision = evaluate_egress_request(
            policy,
            attestation,
            wrong_context,
            evaluated_at="2026-09-20T12:02:00Z",
        )
        self.assertIn("policy_context_mismatch", decision.blocker_codes)
        self.assertIn("resolution_context_mismatch", decision.blocker_codes)

        stale = evaluate_egress_request(
            policy,
            attestation,
            self.request(policy, attestation),
            evaluated_at="2026-09-20T12:03:00Z",
        )
        self.assertIn("resolution_not_active", stale.blocker_codes)

        rebinding = replace(attestation, resolved_addresses=("198.51.100.44",))
        rebound = evaluate_egress_request(
            policy,
            rebinding,
            self.request(policy, rebinding),
            evaluated_at="2026-09-20T12:02:00Z",
        )
        self.assertIn("resolved_address_not_allowed", rebound.blocker_codes)

    def test_policy_is_deny_by_default_and_rejects_unsafe_shape(self) -> None:
        with self.assertRaises(EgressProxyContractError):
            replace(self.policy(), default_disposition="allow")
        with self.assertRaises(EgressProxyContractError):
            replace(self.policy(), redirects_allowed=True)
        with self.assertRaises(EgressProxyContractError):
            replace(self.rule(), host="203.0.113.18")
        with self.assertRaises(EgressProxyContractError):
            replace(self.rule(), allowed_ip_networks=())
        with self.assertRaises(EgressProxyContractError):
            replace(self.rule(), tls_spki_sha256=())

    def test_policy_and_records_are_immutable(self) -> None:
        with self.assertRaises(FrozenInstanceError):
            self.policy().policy_version = 4  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            self.attestation().host = "other.example.com"  # type: ignore[misc]

    def test_enforcement_observation_validates_every_runtime_boundary(self) -> None:
        policy, request, decision = self.decision()
        observation = self.observation(decision)
        self.assertEqual(
            validate_enforcement_observation(policy, request, decision, observation),
            (),
        )
        cases = (
            ({"observed_host": "other.example.com"}, "observed_endpoint_mismatch"),
            ({"resolved_address": "198.51.100.44"}, "observed_address_not_allowed"),
            ({"tls_spki_sha256": ZERO}, "tls_pin_mismatch"),
            ({"response_bytes": 2_000_001}, "response_size_exceeded"),
            ({"redirect_blocked": False}, "redirect_block_not_observed"),
            ({"outcome": "failed"}, "egress_not_completed"),
        )
        for changes, expected in cases:
            with self.subTest(expected=expected):
                blockers = validate_enforcement_observation(
                    policy,
                    request,
                    decision,
                    self.observation(decision, **changes),
                )
                self.assertIn(expected, blockers)

    def test_denied_decision_cannot_be_presented_as_runtime_authority(self) -> None:
        policy = self.policy()
        attestation = self.attestation()
        request = self.request(policy, attestation, method="GET")
        decision = evaluate_egress_request(
            policy,
            attestation,
            request,
            evaluated_at="2026-09-20T12:02:00Z",
        )
        blockers = validate_enforcement_observation(
            policy,
            request,
            decision,
            self.observation(decision),
        )
        self.assertIn("request_not_admitted", blockers)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_both_addressed_contracts(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        for document in (self.policy().to_dict(), self.attestation().to_dict()):
            self.assertEqual(list(validator.iter_errors(document)), [])

    def test_files_have_no_markers_or_unicode_dashes_and_no_effects(self) -> None:
        forbidden = (
            "generated " + "by",
            "written by " + "ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)
            for marker in forbidden:
                self.assertNotIn(marker, lowered)
        self.assertTrue(NO_EFFECTS)


if __name__ == "__main__":
    unittest.main()

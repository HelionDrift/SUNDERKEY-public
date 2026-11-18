"""Native attempt limits and source activation windows for inert contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from sunderkey import credential_broker_contracts as broker
from sunderkey import target_authentication_adapter_contracts as authentication
from tests.agents import test_credential_broker_contracts_phase162 as phase162
from tests.agents import test_target_authentication_adapter_contracts_phase183 as phase183


class IntegerAlias(int):
    """A nonnative scalar used only to exercise the constructor type guard."""


class AuthenticationAttemptLimitGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chain = phase183._chain()

    def policy_document(self, maximum_attempts: object) -> str:
        raw = copy.deepcopy(self.chain["policy"].to_dict())
        raw["maximum_attempts"] = maximum_attempts
        body = {
            name: value for name, value in raw.items() if name not in {"policy_id", "policy_sha256"}
        }
        encoded = json.dumps(
            {"content": body, "domain": authentication.TargetAuthenticationPolicy.record_kind},
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()
        raw["policy_sha256"] = digest
        raw["policy_id"] = "TAAP-" + digest[7:39].upper()
        return json.dumps(
            raw, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )

    def test_constructor_rejects_exact_true_before_policy_identity_hashing(self) -> None:
        with patch.object(authentication, "_identity", wraps=authentication._identity) as identity:
            with self.assertRaisesRegex(
                authentication.TargetAuthenticationContractError, "maximum_attempts"
            ):
                replace(self.chain["policy"], maximum_attempts=True)
            identity.assert_not_called()

    def test_specific_parser_rejects_coherently_addressed_native_true(self) -> None:
        document = self.policy_document(True)
        self.assertIs(json.loads(document)["maximum_attempts"], True)
        self.assertNotEqual(document, authentication.canonical_json(self.chain["policy"].to_dict()))
        with self.assertRaisesRegex(
            authentication.TargetAuthenticationContractError, "maximum_attempts"
        ):
            authentication.parse_target_authentication_policy(document)

    def test_generic_parser_rejects_coherently_addressed_native_true(self) -> None:
        with self.assertRaisesRegex(
            authentication.TargetAuthenticationContractError, "maximum_attempts"
        ):
            authentication.parse_target_authentication_record(self.policy_document(True))

    def test_wrong_attempt_scalars_are_denied_before_identity_hashing(self) -> None:
        for value in (False, 0, -1, 2, 1.0, 2.0, "1", None, IntegerAlias(1)):
            with self.subTest(value=value, native_type=type(value).__name__):
                with patch.object(
                    authentication, "_identity", wraps=authentication._identity
                ) as identity:
                    with self.assertRaisesRegex(
                        authentication.TargetAuthenticationContractError, "maximum_attempts"
                    ):
                        replace(self.chain["policy"], maximum_attempts=value)
                    identity.assert_not_called()

    def test_wrong_wire_scalar_controls_remain_rejected_by_both_parsers(self) -> None:
        for value in (False, 0, -1, 2, 1.0, "1", None):
            for parser in (
                authentication.parse_target_authentication_policy,
                authentication.parse_target_authentication_record,
            ):
                with self.subTest(value=value, parser=parser.__name__):
                    with self.assertRaises(authentication.TargetAuthenticationContractError):
                        parser(self.policy_document(value))

    def test_public_readdressed_chain_cannot_issue_a_receipt_from_bool_policy(self) -> None:
        """The source defect is a bool policy, not extra execution or remote authority."""

        with self.assertRaisesRegex(
            authentication.TargetAuthenticationContractError, "maximum_attempts"
        ):
            policy = authentication.parse_target_authentication_policy(self.policy_document(True))
            command = replace(self.chain["command"], policy_binding=policy.content_binding)
            evidence = tuple(
                replace(item, command_binding=command.content_binding)
                for item in self.chain["evidence"]
            )
            result = replace(
                self.chain["result"],
                command_binding=command.content_binding,
                flow_evidence=tuple(item.content_binding for item in evidence),
            )
            command = authentication.parse_target_authentication_command(
                authentication.canonical_json(command.to_dict())
            )
            evidence = tuple(
                authentication.parse_target_authentication_flow_evidence(
                    authentication.canonical_json(item.to_dict())
                )
                for item in evidence
            )
            result = authentication.parse_target_authentication_result(
                authentication.canonical_json(result.to_dict())
            )
            receipt = authentication.issue_target_authentication_receipt(
                self.chain["provider"],
                self.chain["provenance"],
                policy,
                command,
                evidence,
                result,
                issued_at=self.chain["receipt"].issued_at,
            )
            authentication.verify_target_authentication_chain(
                self.chain["provider"],
                self.chain["provenance"],
                policy,
                command,
                evidence,
                result,
                receipt,
            )
            self.assertIs(policy.maximum_attempts, True)
            self.assertEqual(receipt.to_dict()["claims"], dict(authentication.NO_CLAIMS))
            self.assertEqual(receipt.to_dict()["effects"], dict(authentication.NO_EFFECTS))

    def test_integer_one_policy_and_complete_v2_chain_keep_literal_addresses(self) -> None:
        policy = self.chain["policy"]
        receipt = self.chain["receipt"]
        self.assertIs(type(policy.maximum_attempts), int)
        self.assertEqual(policy.maximum_attempts, 1)
        self.assertEqual(policy.policy_id, "TAAP-38C7D954A557396BFC7BBF28BCFE74FA")
        self.assertEqual(
            policy.policy_sha256,
            "sha256:38c7d954a557396bfc7bbf28bcfe74fa92ad52e2b33650d5d66d224f34b605db",
        )
        self.assertEqual(receipt.receipt_id, "TAAT-63ED2291AB3BD970D27F898A64215E21")
        self.assertEqual(
            receipt.receipt_sha256,
            "sha256:63ed2291ab3bd970d27f898a64215e21c94ffa4b0b409e6c39086988c7581e3d",
        )
        authentication.verify_target_authentication_chain(
            self.chain["provider"],
            self.chain["provenance"],
            policy,
            self.chain["command"],
            self.chain["evidence"],
            self.chain["result"],
            receipt,
        )
        duplicate = authentication.issue_target_authentication_receipt(
            self.chain["provider"],
            self.chain["provenance"],
            policy,
            self.chain["command"],
            self.chain["evidence"],
            self.chain["result"],
            issued_at=receipt.issued_at,
        )
        self.assertEqual(
            authentication.canonical_json(duplicate.to_dict()),
            authentication.canonical_json(receipt.to_dict()),
        )

    def test_original_specific_and_generic_v2_parsers_preserve_exact_native_types(self) -> None:
        records = (
            self.chain["provider"],
            *self.chain["provenance"],
            self.chain["policy"],
            self.chain["command"],
            *self.chain["evidence"],
            self.chain["result"],
            self.chain["receipt"],
        )
        for record in records:
            with self.subTest(record=type(record).__name__):
                document = authentication.canonical_json(record.to_dict())
                parsed = authentication.parse_target_authentication_record(document)
                self.assertIs(type(parsed), type(record))
                self.assertEqual(authentication.canonical_json(parsed.to_dict()), document)
                self.assertEqual(parsed.to_dict()["effects"], dict(authentication.NO_EFFECTS))
                self.assertEqual(parsed.to_dict()["claims"], dict(authentication.NO_CLAIMS))
        for parser in (
            authentication.parse_target_authentication_policy,
            authentication.parse_target_authentication_record,
        ):
            parsed = parser(self.policy_document(1))
            self.assertIs(type(parsed.maximum_attempts), int)
            self.assertEqual(parsed, self.chain["policy"])

    def test_unrehashed_true_still_does_not_masquerade_as_integer_one_address(self) -> None:
        raw = copy.deepcopy(self.chain["policy"].to_dict())
        raw["maximum_attempts"] = True
        with self.assertRaises(authentication.TargetAuthenticationContractError):
            authentication.parse_target_authentication_policy(authentication.canonical_json(raw))

    def test_checked_in_v2_policy_schema_agrees_with_one_attempt_contract(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry/schemas/target-authentication-adapter-contract-v2.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for value in (1, *range(2, 17), True, False, 0, -1):
            with self.subTest(value=value, native_type=type(value).__name__):
                raw = json.loads(self.policy_document(value))
                errors = list(validator.iter_errors(raw))
                if type(value) is int and value == 1:
                    self.assertEqual(errors, [])
                else:
                    self.assertTrue(errors, "schema admitted a non-one native attempt limit")


class CredentialSourceActivationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = phase162.CredentialBrokerContractsPhase162Tests(methodName="runTest")
        self.fixture.setUp()

    def sources(
        self,
        *,
        created_at: str = "2026-09-20T10:00:00Z",
        requested_at: str = "2026-09-20T11:55:00Z",
        approved_at: str = "2026-09-20T11:58:00Z",
    ):
        descriptor = replace(self.fixture.descriptor, created_at=created_at)
        request = replace(
            self.fixture.request,
            descriptor_sha256=descriptor.descriptor_sha256,
            requested_at=requested_at,
        )
        approval = replace(
            self.fixture.approval,
            request_sha256=request.request_sha256,
            approved_at=approved_at,
        )
        self.assertEqual(request.descriptor_sha256, descriptor.descriptor_sha256)
        self.assertEqual(approval.request_sha256, request.request_sha256)
        self.assert_sources_addressed((descriptor, request, approval))
        return descriptor, request, approval

    def assert_sources_addressed(self, sources) -> None:
        for record, prefix, id_field, digest_field in zip(
            sources,
            ("CBD", "CAR", "CAB"),
            ("descriptor_id", "request_id", "approval_id"),
            ("descriptor_sha256", "request_sha256", "approval_sha256"),
            strict=True,
        ):
            raw = json.loads(broker.canonical_json(record.to_dict()))
            broker.verify_content_address(
                raw,
                id_field=id_field,
                digest_field=digest_field,
                prefix=prefix,
                domain=record.KIND,
            )
            self.assertEqual(raw, record.to_dict())

    def issue(self, sources, *, now=phase162.NOW):
        descriptor, request, approval = sources
        return broker.issue_lease(
            descriptor,
            request,
            approval,
            issuance_ref="issuanceref:lease-event-1",
            session_ref="sessionref:preexisting-session-a",
            now=now,
        )

    def test_access_validation_rejects_future_descriptor_creation(self) -> None:
        descriptor, request, _ = self.sources(created_at="2026-09-20T12:01:00Z")
        with self.assertRaises(broker.CredentialBrokerContractError):
            broker.validate_access_request(descriptor, request, now=phase162.NOW)

    def test_access_validation_rejects_future_request_creation(self) -> None:
        descriptor, request, _ = self.sources(requested_at="2026-09-20T12:01:00Z")
        with self.assertRaises(broker.CredentialBrokerContractError):
            broker.validate_access_request(descriptor, request, now=phase162.NOW)

    def test_access_validation_rejects_coherent_all_future_source_chain(self) -> None:
        descriptor, request, _ = self.sources(
            created_at="2026-09-20T12:01:00Z",
            requested_at="2026-09-20T12:02:00Z",
            approved_at="2026-09-20T12:03:00Z",
        )
        with self.assertRaises(broker.CredentialBrokerContractError):
            broker.validate_access_request(descriptor, request, now=phase162.NOW)

    def test_issuance_rejects_each_future_lower_bound_and_the_full_coherent_chain(self) -> None:
        cases = (
            ("descriptor", {"created_at": "2026-09-20T12:01:00Z"}),
            ("request", {"requested_at": "2026-09-20T12:01:00Z"}),
            ("approval", {"approved_at": "2026-09-20T12:01:00Z"}),
            (
                "all_sources",
                {
                    "created_at": "2026-09-20T12:01:00Z",
                    "requested_at": "2026-09-20T12:02:00Z",
                    "approved_at": "2026-09-20T12:03:00Z",
                },
            ),
        )
        for source, changes in cases:
            with self.subTest(source=source):
                sources = self.sources(**changes)
                with patch.object(broker, "CredentialLease", wraps=broker.CredentialLease) as lease:
                    with self.assertRaises(broker.CredentialBrokerContractError):
                        self.issue(sources)
                    lease.assert_not_called()

    def test_just_before_each_lower_bound_is_rejected_without_second_rounding(self) -> None:
        before = phase162.NOW - timedelta(microseconds=1)
        for source, changes in (
            ("descriptor", {"created_at": "2026-09-20T12:00:00Z"}),
            ("request", {"requested_at": "2026-09-20T12:00:00Z"}),
            ("approval", {"approved_at": "2026-09-20T12:00:00Z"}),
        ):
            with self.subTest(source=source):
                with self.assertRaises(broker.CredentialBrokerContractError):
                    self.issue(self.sources(**changes), now=before)

    def test_each_lower_bound_inclusive_equality_and_all_equal_sources_are_valid(self) -> None:
        for source, changes in (
            ("descriptor", {"created_at": "2026-09-20T12:00:00Z"}),
            ("request", {"requested_at": "2026-09-20T12:00:00Z"}),
            ("approval", {"approved_at": "2026-09-20T12:00:00Z"}),
            (
                "all_sources",
                {
                    "created_at": "2026-09-20T12:00:00Z",
                    "requested_at": "2026-09-20T12:00:00Z",
                    "approved_at": "2026-09-20T12:00:00Z",
                },
            ),
        ):
            with self.subTest(source=source):
                sources = self.sources(**changes)
                broker.validate_access_request(sources[0], sources[1], now=phase162.NOW)
                lease = self.issue(sources)
                self.assertEqual(lease.issued_at, "2026-09-20T12:00:00Z")
                self.assertEqual(lease.expires_at, "2026-09-20T12:10:00Z")
                self.assertEqual(lease.max_uses, 3)
                self.assertEqual(lease.approval_sha256, sources[2].approval_sha256)

    def test_future_source_records_remain_inspectable_without_current_admission(self) -> None:
        sources = self.sources(
            created_at="2026-09-20T12:01:00Z",
            requested_at="2026-09-20T12:02:00Z",
            approved_at="2026-09-20T12:03:00Z",
        )
        self.assert_sources_addressed(sources)
        self.assertEqual(sources[0].created_at, "2026-09-20T12:01:00Z")
        self.assertEqual(sources[1].requested_at, "2026-09-20T12:02:00Z")
        self.assertEqual(sources[2].approved_at, "2026-09-20T12:03:00Z")
        self.assertNotEqual(sources[0].descriptor_sha256, self.fixture.descriptor.descriptor_sha256)
        self.assertNotEqual(sources[1].request_sha256, self.fixture.request.request_sha256)
        self.assertNotEqual(sources[2].approval_sha256, self.fixture.approval.approval_sha256)
        lease = self.issue(sources, now=phase162.NOW + timedelta(minutes=3))
        self.assertEqual(lease.issued_at, "2026-09-20T12:03:00Z")
        self.assertEqual(lease.expires_at, "2026-09-20T12:13:00Z")

    def test_expiry_remains_exclusive_for_descriptor_request_and_approval(self) -> None:
        for source in ("descriptor", "request", "approval"):
            with self.subTest(source=source):
                descriptor, request, approval = self.sources()
                if source == "descriptor":
                    descriptor = replace(descriptor, expires_at="2026-09-20T12:00:00Z")
                    request = replace(request, descriptor_sha256=descriptor.descriptor_sha256)
                    approval = replace(approval, request_sha256=request.request_sha256)
                elif source == "request":
                    request = replace(request, expires_at="2026-09-20T12:00:00Z")
                    approval = replace(approval, request_sha256=request.request_sha256)
                else:
                    approval = replace(approval, expires_at="2026-09-20T12:00:00Z")
                sources = descriptor, request, approval
                self.assert_sources_addressed(sources)
                with self.assertRaisesRegex(broker.CredentialBrokerContractError, "expired"):
                    self.issue(sources)
                if source != "approval":
                    with self.assertRaisesRegex(broker.CredentialBrokerContractError, "expired"):
                        broker.validate_access_request(descriptor, request, now=phase162.NOW)

    def test_original_lease_and_all_source_literal_addresses_remain_unchanged(self) -> None:
        sources = self.sources()
        lease = self.issue(sources)
        for record, id_field, digest_field, identifier, digest in (
            (
                sources[0],
                "descriptor_id",
                "descriptor_sha256",
                "CBD-058F0E996C31C8F540E97BE8A863B306",
                "sha256:058f0e996c31c8f540e97be8a863b306c78a044fce3c40417dd56a828fa7488a",
            ),
            (
                sources[1],
                "request_id",
                "request_sha256",
                "CAR-E21F96CEEB0DAEC1A2B91C4FF48235E3",
                "sha256:e21f96ceeb0daec1a2b91c4ff48235e3346b353875f312f211e4fe6a0b826fa4",
            ),
            (
                sources[2],
                "approval_id",
                "approval_sha256",
                "CAB-0FB4C98C96F9FD22DBD1319DDF52D6DE",
                "sha256:0fb4c98c96f9fd22dbd1319ddf52d6defdde2232018f0a53c708f951ae26c00c",
            ),
            (
                lease,
                "lease_id",
                "lease_sha256",
                "CLZ-B2F7E084D4AB0D6B092F7F6B8039CA9C",
                "sha256:b2f7e084d4ab0d6b092f7f6b8039ca9c85d2a1926e0a61f6c9cd49852422b186",
            ),
        ):
            with self.subTest(record=type(record).__name__):
                self.assertEqual(getattr(record, id_field), identifier)
                self.assertEqual(getattr(record, digest_field), digest)
        self.assertEqual(
            broker.canonical_json(lease.to_dict()),
            broker.canonical_json(self.fixture.make_lease().to_dict()),
        )
        self.assertTrue(all(value == "none" for value in broker.NO_EFFECTS.values()))


if __name__ == "__main__":
    unittest.main()

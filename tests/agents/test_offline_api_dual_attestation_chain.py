"""Separate local policy and evidence signatures over one synthetic API case."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    OfflineApiCaseSource,
    build_offline_api_batch,
    evaluate_offline_api_case,
)
from sunderkey.offline_api_expectation_attestation import (
    OfflineAccessPolicyKeyBinding,
    OfflineApiExpectationAttestationError,
    bind_offline_api_case_to_signed_access_expectations,
    bind_offline_api_retest_to_signed_access_expectations,
    sign_offline_api_access_expectations,
)
from sunderkey.offline_api_source_attestation import (
    OfflineApiSourceAttestationError,
    OfflineSourceKeyBinding,
    sign_offline_api_source_attestation,
    verify_offline_api_source_attestation_historical,
)
from sunderkey.offline_api_source_ledger import append_offline_api_source_batch
from tests.agents import test_offline_api_access_expectations as fixture_module
from tests.agents.test_offline_api_assessment import invocation, response
from tests.agents.test_offline_task_review_receipts import NoopPublicKey


class OfflineApiDualAttestationChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_module.OfflineApiAccessExpectationTests.setUpClass()

    def setUp(self) -> None:
        fixture = fixture_module.OfflineApiAccessExpectationTests(
            "test_exact_policy_binding_is_reproducible_and_non_authorizing"
        )
        self.adapter = fixture.adapter
        original, self.expectations = fixture.fixture()
        records = []
        for index, record in enumerate(original.evidence):
            records.append(
                EvidenceRecord.from_bytes(
                    record.evidence_id,
                    record.content,
                    media_type=record.media_type,
                    role=record.role,
                    status_code=record.status_code,
                    headers=record.headers,
                    attributes={
                        **dict(record.attributes),
                        "source_receipt_sha256": f"sha256:{index + 1:064x}",
                        "source_session_id": f"session.synthetic.{index + 1}",
                        "source_scope_id": original.invocation.scope_id,
                        "source_scope_sha256": "sha256:" + "b" * 64,
                        "source_target_id": original.invocation.target_id,
                        "source_target_sha256": "sha256:" + "c" * 64,
                    },
                )
            )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=original.case_id,
            invocation=original.invocation,
            evidence=tuple(records),
        )
        self.source = OfflineApiCaseSource(
            original.case_id, original.invocation, tuple(records), result.to_dict()
        )
        batch = build_offline_api_batch(adapter=self.adapter, sources=(self.source,)).to_dict()
        self.ledger = append_offline_api_source_batch(
            adapter=self.adapter, sources=(self.source,), batch=batch
        )
        self.producer_key = Ed25519PrivateKey.generate()
        self.producer_binding = OfflineSourceKeyBinding(
            "key.synthetic.evidence",
            "producer.synthetic.evidence",
            self.producer_key.public_key(),
        )
        self.source_attestation = sign_offline_api_source_attestation(
            ledger=self.ledger,
            producer_id=self.producer_binding.producer_id,
            key_id=self.producer_binding.key_id,
            issued_at="2026-09-24T12:00:00Z",
            expires_at="2026-09-24T13:00:00Z",
            private_key=self.producer_key,
        )
        self.policy_key = Ed25519PrivateKey.generate()
        self.policy_binding = OfflineAccessPolicyKeyBinding(
            policy_owner_id="policy.owner.synthetic",
            key_id="key.synthetic.policy",
            public_key=self.policy_key.public_key(),
        )
        self.policy_attestation = sign_offline_api_access_expectations(
            expectations=self.expectations,
            policy_owner_id=self.policy_binding.policy_owner_id,
            key_id=self.policy_binding.key_id,
            private_key=self.policy_key,
        )

    def test_separate_signatures_bind_same_case_without_positive_use(self) -> None:
        self.assertEqual(self.ledger["source_mode"], "receipt_sourced")
        self.assertEqual(
            verify_offline_api_source_attestation_historical(
                document=self.source_attestation,
                ledger=self.ledger,
                key_binding=self.producer_binding,
            ),
            self.source_attestation,
        )
        result = bind_offline_api_case_to_signed_access_expectations(
            adapter=self.adapter,
            source=self.source,
            expectations=self.expectations,
            attestation=self.policy_attestation,
            binding=self.policy_binding,
        )
        self.assertEqual(result["case_result_sha256"], self.ledger["cases"][0]["result_sha256"])
        self.assertNotEqual(
            self.producer_binding.public_key,
            self.policy_binding.public_key,
        )
        self.assertFalse(result["policy_authority_verified"])
        self.assertFalse(result["pre_observation_commitment_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(self.ledger["effects"]["source_authentication"], "none")

    def test_cross_source_or_policy_rebinding_fails(self) -> None:
        altered_ledger = copy.deepcopy(self.ledger)
        altered_ledger["cases"][0]["result_sha256"] = "sha256:" + "d" * 64
        with self.assertRaises(OfflineApiSourceAttestationError):
            verify_offline_api_source_attestation_historical(
                document=self.source_attestation,
                ledger=altered_ledger,
                key_binding=self.producer_binding,
            )
        altered_policy = copy.deepcopy(self.expectations)
        altered_policy["principal_expectations"][0]["expected_access"] = True
        with self.assertRaises(OfflineApiExpectationAttestationError):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=altered_policy,
                attestation=self.policy_attestation,
                binding=self.policy_binding,
            )

    def test_reassigned_keys_reject_both_sides_of_chain(self) -> None:
        producer = replace(self.producer_binding)
        policy = replace(self.policy_binding)
        for binding in (producer, policy):
            object.__setattr__(binding, "public_key", NoopPublicKey())
        with self.assertRaises(OfflineApiSourceAttestationError):
            verify_offline_api_source_attestation_historical(
                document=self.source_attestation,
                ledger=self.ledger,
                key_binding=producer,
            )
        with self.assertRaises(OfflineApiExpectationAttestationError):
            bind_offline_api_case_to_signed_access_expectations(
                adapter=self.adapter,
                source=self.source,
                expectations=self.expectations,
                attestation=self.policy_attestation,
                binding=policy,
            )
        self.assertEqual(producer.public_key.calls, 0)
        self.assertEqual(policy.public_key.calls, 0)

    def test_signed_retest_spans_distinct_source_batches(self) -> None:
        original_records = (
            response("owner-second", "principal.owner", True, 200, b'"owner-data"'),
            response("other-second", "principal.other", False, 403, b'"denied"'),
        )
        invocation_record = replace(
            invocation(self.adapter, original_records),
            invocation_id="INV-SYNTHETIC-API-DUAL-002",
        )
        records = tuple(
            EvidenceRecord.from_bytes(
                record.evidence_id,
                record.content,
                media_type=record.media_type,
                role=record.role,
                status_code=record.status_code,
                headers=record.headers,
                attributes={
                    **dict(record.attributes),
                    "source_receipt_sha256": f"sha256:{index + 3:064x}",
                    "source_session_id": f"session.synthetic.{index + 1}",
                    "source_scope_id": invocation_record.scope_id,
                    "source_scope_sha256": "sha256:" + "b" * 64,
                    "source_target_id": invocation_record.target_id,
                    "source_target_sha256": "sha256:" + "c" * 64,
                },
            )
            for index, record in enumerate(original_records)
        )
        case = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.dual.retest.002",
            invocation=invocation_record,
            evidence=records,
        )
        second = OfflineApiCaseSource(
            "case.dual.retest.002", invocation_record, records, case.to_dict()
        )
        batch = build_offline_api_batch(adapter=self.adapter, sources=(second,)).to_dict()
        ledger = append_offline_api_source_batch(
            adapter=self.adapter,
            sources=(second,),
            batch=batch,
            prior_ledger=self.ledger,
        )
        attestation = sign_offline_api_source_attestation(
            ledger=ledger,
            producer_id=self.producer_binding.producer_id,
            key_id=self.producer_binding.key_id,
            issued_at="2026-09-24T12:00:00Z",
            expires_at="2026-09-24T13:00:00Z",
            private_key=self.producer_key,
        )
        self.assertEqual(
            verify_offline_api_source_attestation_historical(
                document=attestation,
                ledger=ledger,
                key_binding=self.producer_binding,
            ),
            attestation,
        )
        result = bind_offline_api_retest_to_signed_access_expectations(
            adapter=self.adapter,
            prior_source=self.source,
            second_source=second,
            expectations=self.expectations,
            attestation=self.policy_attestation,
            binding=self.policy_binding,
        )
        self.assertEqual(len(ledger["batch_sha256s"]), 2)
        self.assertEqual(len(ledger["cases"]), 2)
        self.assertEqual(
            result["observation_change"],
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertFalse(result["pre_observation_commitment_verified"])
        self.assertFalse(result["positive_use_approved"])


if __name__ == "__main__":
    unittest.main()

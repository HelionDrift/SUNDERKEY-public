"""Local source signatures cannot turn synthetic Army planning into live authority."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import tests.agents.test_offline_api_planning_bundle as planning_fixture
from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    OfflineApiCaseSource,
    build_offline_api_batch,
    evaluate_offline_api_case,
)
from sunderkey.offline_api_attested_planning import (
    OfflineApiAttestedPlanningError,
    build_offline_api_attested_planning_rehearsal,
    verify_offline_api_attested_planning_rehearsal,
)
from sunderkey.offline_api_planning_bundle import build_offline_api_planning_bundle
from sunderkey.offline_api_source_attestation import (
    OfflineSourceKeyBinding,
    sign_offline_api_source_attestation,
    verify_offline_api_source_attestation_historical,
)
from sunderkey.offline_api_source_ledger import append_offline_api_source_batch
from tests.agents.test_offline_task_review_receipts import NoopPublicKey


class OfflineApiAttestedPlanningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        planning_fixture.OfflineApiPlanningBundleTests.setUpClass()

    def setUp(self) -> None:
        fixture = planning_fixture.OfflineApiPlanningBundleTests(
            "test_synthetic_signal_reaches_bound_rehearsal_only"
        )
        fixture.setUp()
        self.fixture = fixture
        self.key = Ed25519PrivateKey.generate()
        self.binding = OfflineSourceKeyBinding(
            "key.synthetic.planning.001",
            "producer.synthetic.planning.001",
            self.key.public_key(),
        )
        self.inputs = self._inputs("sha256:" + "a" * 64)
        self.bundle = build_offline_api_planning_bundle(**self.inputs)
        self.ledger = append_offline_api_source_batch(
            adapter=fixture.adapter,
            sources=self.inputs["sources"],
            batch=self.inputs["batch"],
        )
        self.attestation = sign_offline_api_source_attestation(
            ledger=self.ledger,
            producer_id=self.binding.producer_id,
            key_id=self.binding.key_id,
            issued_at="2026-09-24T11:50:00Z",
            expires_at="2026-09-24T13:00:00Z",
            private_key=self.key,
        )

    def _inputs(self, receipt_digest: str) -> dict:
        fixture = self.fixture
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
                    "source_receipt_sha256": ("sha256:" + str(index + 1) + receipt_digest[8:]),
                    "source_session_id": f"session.synthetic.{index + 1}",
                    "source_scope_id": fixture.scope.scope_id,
                    "source_scope_sha256": fixture.scope.content_sha256,
                    "source_target_id": fixture.source.invocation.target_id,
                    "source_target_sha256": "sha256:" + "e" * 64,
                },
            )
            for index, record in enumerate(fixture.source.evidence)
        )
        result = evaluate_offline_api_case(
            adapter=fixture.adapter,
            case_id=fixture.source.case_id,
            invocation=fixture.source.invocation,
            evidence=records,
        )
        source = OfflineApiCaseSource(
            fixture.source.case_id, fixture.source.invocation, records, result.to_dict()
        )
        batch = build_offline_api_batch(adapter=fixture.adapter, sources=(source,)).to_dict()
        return {**fixture.options(), "sources": (source,), "batch": batch}

    def options(self, **overrides) -> dict:
        return {
            **{
                "bundle": self.bundle,
                "planning_inputs": self.inputs,
                "ledger": self.ledger,
                "attestation": self.attestation,
                "key_binding": self.binding,
                "as_of": "2026-09-24T12:30:00Z",
            },
            **overrides,
        }

    def test_exact_source_replay_and_signature_remain_local_only(self) -> None:
        result = build_offline_api_attested_planning_rehearsal(**self.options())
        self.assertEqual(
            verify_offline_api_attested_planning_rehearsal(document=result, **self.options()),
            result,
        )
        self.assertTrue(result["source_replay_performed"])
        self.assertEqual(result["ledger_sha256"], self.ledger["ledger_sha256"])
        self.assertFalse(result["live_currentness_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(result["effects"]["target_execution"], "none")

    def test_expired_signature_remains_historical_but_cannot_rehearse_use(self) -> None:
        self.assertEqual(
            verify_offline_api_source_attestation_historical(
                document=self.attestation,
                ledger=self.ledger,
                key_binding=self.binding,
            ),
            self.attestation,
        )
        with self.assertRaises(OfflineApiAttestedPlanningError):
            build_offline_api_attested_planning_rehearsal(
                **self.options(as_of="2026-09-24T13:00:00Z")
            )
        with self.assertRaisesRegex(OfflineApiAttestedPlanningError, "precedes"):
            build_offline_api_attested_planning_rehearsal(
                **self.options(as_of="2026-09-24T11:55:00Z")
            )

    def test_key_ledger_and_bundle_rebinding_fail_closed(self) -> None:
        other_binding = OfflineSourceKeyBinding(
            self.binding.key_id,
            self.binding.producer_id,
            Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaises(OfflineApiAttestedPlanningError):
            build_offline_api_attested_planning_rehearsal(**self.options(key_binding=other_binding))
        other_inputs = self._inputs("sha256:" + "d" * 64)
        other_bundle = build_offline_api_planning_bundle(**other_inputs)
        with self.assertRaisesRegex(OfflineApiAttestedPlanningError, "differs"):
            build_offline_api_attested_planning_rehearsal(
                **self.options(planning_inputs=other_inputs, bundle=other_bundle)
            )
        changed = copy.deepcopy(self.bundle)
        changed["scope_sha256"] = "sha256:" + "f" * 64
        with self.assertRaises(OfflineApiAttestedPlanningError):
            build_offline_api_attested_planning_rehearsal(**self.options(bundle=changed))
        result = build_offline_api_attested_planning_rehearsal(**self.options())
        changed = copy.deepcopy(result)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineApiAttestedPlanningError, "does not match"):
            verify_offline_api_attested_planning_rehearsal(document=changed, **self.options())

    def test_reassigned_key_cannot_support_attested_planning(self) -> None:
        valid = build_offline_api_attested_planning_rehearsal(**self.options())
        self.assertFalse(valid["positive_use_approved"])
        binding = replace(self.binding)
        fake = NoopPublicKey()
        object.__setattr__(binding, "public_key", fake)
        with self.assertRaises(OfflineApiAttestedPlanningError):
            build_offline_api_attested_planning_rehearsal(**self.options(key_binding=binding))
        self.assertEqual(fake.calls, 0)


if __name__ == "__main__":
    unittest.main()

"""Offline response evidence bound to the authorized HTTP receipt boundary."""

from __future__ import annotations

import hashlib
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.assessment_transport_contracts import SessionBinding, canonical_json
from sunderkey.authorized_http_runtime import HttpBackendResponse
from sunderkey.candidate_adapter_sdk import AdapterInvocation, load_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    build_offline_api_batch,
    compare_offline_api_retest,
    evaluate_offline_api_case,
)
from sunderkey.offline_api_receipt_evidence import (
    OfflineApiReceiptEvidenceError,
    bind_http_response_evidence,
)
from sunderkey.reference_adapters import build_reference_adapters
from tests.agents.test_authorized_http_runtime_phase173 import (
    AuthorizedHttpRuntimePhase173Tests,
    FakeBackend,
    FakeSafety,
)

ROOT = Path(__file__).resolve().parents[2]


class OfflineApiReceiptEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            ROOT / "registry" / "candidate-implementation-strategy-v1.json"
        )
        catalog = load_candidate_adapter_catalog(
            ROOT / "registry" / "candidate-adapters-reference-v1.json",
            strategy,
            load_blueprints(),
            ROOT,
        )
        cls.adapter = build_reference_adapters(catalog)["AOE-GB-D06-S09"]

    def setUp(self) -> None:
        fixture = AuthorizedHttpRuntimePhase173Tests(
            "test_completed_exchange_is_single_send_and_content_addressed"
        )
        fixture.setUp()
        self.fixture = fixture
        self.receipt = fixture.invoke()

    def bind(self, **changes):
        values = {
            "receipt": self.receipt.to_dict(),
            "response_body": b"{}",
            "evidence_id": "response.owner",
            "principal_id": "principal.owner",
            "object_id": "object.7",
            "action": "read",
            "expected_access": True,
            "expected_scope_id": self.fixture.scope.scope_id,
            "expected_scope_sha256": self.fixture.scope.content_sha256,
            "expected_target_id": self.fixture.execution_binding.target_id,
            "expected_target_sha256": self.fixture.execution_binding.target_sha256,
            "expected_session_id": self.fixture.execution_binding.session_id,
        }
        values.update(changes)
        return bind_http_response_evidence(**values)

    def case_source(self, record: EvidenceRecord, number: int) -> OfflineApiCaseSource:
        case_id = f"case.synthetic.receipt.{number:03d}"
        run = AdapterInvocation(
            invocation_id=f"INV-SYNTHETIC-RECEIPT-{number:03d}",
            mission_id="MISSION-SYNTHETIC-RECEIPT-001",
            authority_ref="AUTH-SYNTHETIC-NONQUALIFYING",
            profile_id=self.adapter.manifest.profile_id,
            vector_id=self.adapter.manifest.vector_id,
            target_id=self.fixture.execution_binding.target_id,
            scope_id=self.fixture.scope.scope_id,
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={
                "exchanges": [
                    {
                        "evidence_id": record.evidence_id,
                        "subject_id": record.attributes["principal_id"],
                        "object_id": record.attributes["object_id"],
                        "expected_permitted": record.attributes["expected_access"],
                        "status_code": record.status_code,
                    }
                ]
            },
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter, case_id=case_id, invocation=run, evidence=(record,)
        )
        return OfflineApiCaseSource(case_id, run, (record,), result.to_dict())

    def record_with_attributes(
        self, first: EvidenceRecord, evidence_id: str, **changes: object
    ) -> EvidenceRecord:
        return EvidenceRecord.from_bytes(
            evidence_id,
            first.content,
            media_type=first.media_type,
            role=first.role,
            status_code=first.status_code,
            attributes={**dict(first.attributes), **changes},
        )

    def test_receipt_bound_response_feeds_synthetic_api_case(self) -> None:
        record = self.bind()
        self.assertEqual(record.content_sha256, self.receipt.response_body_sha256)
        self.assertEqual(record.attributes["source_receipt_sha256"], self.receipt.receipt_sha256)
        run = AdapterInvocation(
            invocation_id="INV-SYNTHETIC-RECEIPT-001",
            mission_id="MISSION-SYNTHETIC-RECEIPT-001",
            authority_ref="AUTH-SYNTHETIC-NONQUALIFYING",
            profile_id=self.adapter.manifest.profile_id,
            vector_id=self.adapter.manifest.vector_id,
            target_id=self.fixture.execution_binding.target_id,
            scope_id=self.fixture.scope.scope_id,
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={
                "exchanges": [
                    {
                        "evidence_id": record.evidence_id,
                        "subject_id": record.attributes["principal_id"],
                        "object_id": record.attributes["object_id"],
                        "expected_permitted": record.attributes["expected_access"],
                        "status_code": record.status_code,
                    }
                ]
            },
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.synthetic.receipt.001",
            invocation=run,
            evidence=(record,),
        )
        self.assertEqual(result.validator_state, "abstained")
        self.assertEqual(result.disposition, "review_required")
        changed_run = replace(run, target_id="target:other")
        with self.assertRaisesRegex(OfflineApiAssessmentError, "context differ"):
            evaluate_offline_api_case(
                adapter=self.adapter,
                case_id="case.synthetic.receipt.001",
                invocation=changed_run,
                evidence=(record,),
            )

    def test_body_context_and_receipt_substitution_fail_closed(self) -> None:
        with self.assertRaisesRegex(OfflineApiReceiptEvidenceError, "response bytes"):
            self.bind(response_body=b'{"changed":true}')
        with self.assertRaisesRegex(OfflineApiReceiptEvidenceError, "context"):
            self.bind(expected_target_id="target:other")
        changed = self.receipt.to_dict()
        changed["response_status_code"] = 403
        with self.assertRaisesRegex(OfflineApiReceiptEvidenceError, "verification"):
            self.bind(receipt=changed)
        wrong_type = self.receipt.to_dict()
        wrong_type["schema_version"] = True
        with self.assertRaisesRegex(OfflineApiReceiptEvidenceError, "wire types"):
            self.bind(receipt=wrong_type)

    def test_batch_rejects_receipt_replay_under_new_evidence_identity(self) -> None:
        first = self.bind(evidence_id="response.first")
        second = self.record_with_attributes(first, "response.second")
        self.assertNotEqual(first.evidence_sha256, second.evidence_sha256)
        sources = (self.case_source(first, 1), self.case_source(second, 2))
        with self.assertRaisesRegex(OfflineApiAssessmentError, "receipt replay across cases"):
            build_offline_api_batch(adapter=self.adapter, sources=sources)

    def test_retest_rejects_the_same_receipt_under_a_new_evidence_id(self) -> None:
        first = self.case_source(self.bind(evidence_id="response.first"), 1)
        second_record = self.record_with_attributes(first.evidence[0], "response.second")
        second = self.case_source(second_record, 2)
        with self.assertRaisesRegex(OfflineApiAssessmentError, "receipt replay across cases"):
            compare_offline_api_retest(
                adapter=self.adapter,
                prior_case_id=first.case_id,
                prior_invocation=first.invocation,
                prior_evidence=first.evidence,
                prior_result=first.result,
                second_case_id=second.case_id,
                second_invocation=second.invocation,
                second_evidence=second.evidence,
                second_result=second.result,
            )

    def test_batch_accepts_distinct_consistent_receipt_references(self) -> None:
        first = self.bind(evidence_id="response.first")
        second = self.record_with_attributes(
            first, "response.second", source_receipt_sha256="sha256:" + "f" * 64
        )
        batch = build_offline_api_batch(
            adapter=self.adapter,
            sources=(self.case_source(first, 1), self.case_source(second, 2)),
        )
        self.assertEqual(len(batch.cases), 2)

    def test_batch_rejects_cross_case_source_context_aliases(self) -> None:
        first = self.bind(evidence_id="response.first")
        source = self.case_source(first, 1)
        cases = (
            (
                {"source_receipt_sha256": "sha256:" + "f" * 64, "principal_id": "principal.other"},
                "session changed principal",
            ),
            (
                {
                    "source_receipt_sha256": "sha256:" + "e" * 64,
                    "source_scope_sha256": "sha256:" + "f" * 64,
                },
                "source scope digest changed",
            ),
            (
                {
                    "source_receipt_sha256": "sha256:" + "d" * 64,
                    "source_target_sha256": "sha256:" + "f" * 64,
                },
                "source target digest changed",
            ),
        )
        for changes, message in cases:
            with self.subTest(message=message):
                second = self.record_with_attributes(first, "response.second", **changes)
                with self.assertRaisesRegex(OfflineApiAssessmentError, message):
                    build_offline_api_batch(
                        adapter=self.adapter,
                        sources=(source, self.case_source(second, 2)),
                    )

    def test_batch_does_not_mix_receipt_sourced_and_unsourced_cases(self) -> None:
        first = self.bind(evidence_id="response.first")
        unsourced = EvidenceRecord.from_bytes(
            "response.second",
            first.content,
            media_type=first.media_type,
            role=first.role,
            status_code=first.status_code,
            attributes={
                "principal_id": first.attributes["principal_id"],
                "object_id": first.attributes["object_id"],
                "action": first.attributes["action"],
                "expected_access": first.attributes["expected_access"],
            },
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "cannot mix"):
            build_offline_api_batch(
                adapter=self.adapter,
                sources=(self.case_source(first, 1), self.case_source(unsourced, 2)),
            )

    def test_sourced_evidence_rejects_receipt_replay_and_session_aliasing(self) -> None:
        first = self.bind()
        second = EvidenceRecord.from_bytes(
            "response.other",
            b"{}",
            media_type="application/json",
            role="response",
            status_code=200,
            attributes={
                **dict(first.attributes),
                "principal_id": "principal.other",
            },
        )
        from sunderkey.offline_api_assessment import _validate_evidence

        with self.assertRaisesRegex(OfflineApiAssessmentError, "receipt replay"):
            _validate_evidence((first, second))
        third = EvidenceRecord.from_bytes(
            "response.other",
            b"{}",
            media_type="application/json",
            role="response",
            status_code=200,
            attributes={
                **dict(second.attributes),
                "source_receipt_sha256": "sha256:" + "a" * 64,
            },
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "multiple principals"):
            _validate_evidence((first, third))
        wrong_context = EvidenceRecord.from_bytes(
            "response.context",
            b"{}",
            media_type="application/json",
            role="response",
            status_code=200,
            attributes={
                **dict(third.attributes),
                "source_session_id": "session:assessment-2",
                "source_target_sha256": "sha256:" + "c" * 64,
            },
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "context changed"):
            _validate_evidence((first, wrong_context))
        unsourced = EvidenceRecord.from_bytes(
            "response.unsourced",
            b"{}",
            media_type="application/json",
            role="response",
            status_code=200,
            attributes={
                "principal_id": "principal.other",
                "object_id": "object.7",
                "action": "read",
                "expected_access": False,
            },
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "cannot mix"):
            _validate_evidence((first, unsourced))

    def test_distinct_injected_sessions_produce_negative_synthetic_comparison(self) -> None:
        owner = self.bind(evidence_id="response.owner")
        other_session = SessionBinding("session:assessment-2", "principal:other")
        other_intent = replace(self.fixture.intent, session=other_session, sequence=2)
        other_binding = replace(self.fixture.execution_binding, session_id=other_session.session_id)
        other_request = self.fixture.make_execution_request(
            intent=other_intent, binding=other_binding
        )
        other_admission = replace(
            self.fixture.admission,
            request_id=other_request.request_id,
            request_sha256=other_request.request_sha256,
            receipt_id="",
            receipt_sha256="",
        )
        other_policy = replace(
            self.fixture.policy, binding=other_binding, policy_id="", policy_sha256=""
        )
        binding_sha = (
            "sha256:"
            + hashlib.sha256(canonical_json(other_binding.to_dict()).encode("ascii")).hexdigest()
        )
        other_safety = FakeSafety(binding_sha, other_request.request_sha256)
        denied_backend = FakeBackend(
            response=HttpBackendResponse(
                403,
                (("content-length", "2"), ("content-type", "application/json")),
                b"{}",
                True,
                False,
                False,
                1,
            )
        )
        other_receipt = self.fixture.invoke(
            intent=other_intent,
            execution_request=other_request,
            admission=other_admission,
            policy=other_policy,
            safety_monitor=other_safety,
            backend=denied_backend,
        )
        self.assertEqual(denied_backend.calls, 1)
        other = self.bind(
            receipt=other_receipt.to_dict(),
            evidence_id="response.other",
            principal_id="principal.other",
            expected_access=False,
            expected_session_id=other_session.session_id,
        )
        records = (owner, other)
        run = AdapterInvocation(
            invocation_id="INV-SYNTHETIC-RECEIPT-002",
            mission_id="MISSION-SYNTHETIC-RECEIPT-001",
            authority_ref="AUTH-SYNTHETIC-NONQUALIFYING",
            profile_id=self.adapter.manifest.profile_id,
            vector_id=self.adapter.manifest.vector_id,
            target_id=self.fixture.execution_binding.target_id,
            scope_id=self.fixture.scope.scope_id,
            action_tier="R0",
            environment="synthetic",
            dry_run=True,
            credential_refs=(),
            input_data={
                "exchanges": [
                    {
                        "evidence_id": record.evidence_id,
                        "subject_id": record.attributes["principal_id"],
                        "object_id": record.attributes["object_id"],
                        "expected_permitted": record.attributes["expected_access"],
                        "status_code": record.status_code,
                    }
                    for record in sorted(records, key=lambda item: item.evidence_id)
                ]
            },
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.synthetic.receipt.002",
            invocation=run,
            evidence=records,
        )
        self.assertEqual(result.disposition, "negative_synthetic_result")
        self.assertNotEqual(
            owner.attributes["source_receipt_sha256"], other.attributes["source_receipt_sha256"]
        )

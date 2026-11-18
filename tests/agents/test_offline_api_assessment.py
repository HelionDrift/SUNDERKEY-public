"""Executable synthetic API adapter and finding-validator correlation tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_sdk import AdapterInvocation, load_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    build_offline_api_batch,
    compare_offline_api_retest,
    evaluate_offline_api_case,
    verify_offline_api_batch,
    verify_offline_api_case,
    verify_offline_api_retest,
)
from sunderkey.reference_adapters import OfflineReferenceAdapter, build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
CASE_ID = "case.synthetic.api.001"


def response(
    evidence_id: str,
    principal_id: str,
    expected_access: bool,
    status_code: int,
    content: bytes,
) -> EvidenceRecord:
    return EvidenceRecord.from_bytes(
        evidence_id,
        content,
        role="response",
        status_code=status_code,
        media_type="application/json",
        attributes={
            "principal_id": principal_id,
            "object_id": "object.7",
            "action": "read",
            "expected_access": expected_access,
        },
    )


def invocation(
    adapter: OfflineReferenceAdapter, records: tuple[EvidenceRecord, ...]
) -> AdapterInvocation:
    ordered = sorted(records, key=lambda item: item.evidence_id)
    return AdapterInvocation(
        invocation_id="INV-SYNTHETIC-API-001",
        mission_id="MISSION-SYNTHETIC-001",
        authority_ref="AUTH-SYNTHETIC-NONQUALIFYING",
        profile_id=adapter.manifest.profile_id,
        vector_id=adapter.manifest.vector_id,
        target_id="TARGET-SYNTHETIC-001",
        scope_id="SCOPE-SYNTHETIC-001",
        action_tier="R0",
        environment="synthetic",
        dry_run=True,
        credential_refs=(),
        input_data={
            "exchanges": [
                {
                    "evidence_id": item.evidence_id,
                    "subject_id": item.attributes["principal_id"],
                    "object_id": item.attributes["object_id"],
                    "expected_permitted": item.attributes["expected_access"],
                    "status_code": item.status_code,
                }
                for item in ordered
            ]
        },
    )


class OfflineApiAssessmentTests(unittest.TestCase):
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
        schema = json.loads(
            (
                ROOT / "registry" / "schemas" / "offline-api-assessment-result-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        cls.schema_validator = Draft202012Validator(schema)
        retest_schema = json.loads(
            (ROOT / "registry" / "schemas" / "offline-api-retest-result-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator.check_schema(retest_schema)
        cls.retest_schema_validator = Draft202012Validator(retest_schema)
        batch_schema = json.loads(
            (
                ROOT / "registry" / "schemas" / "offline-api-assessment-batch-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(batch_schema)
        cls.batch_schema_validator = Draft202012Validator(batch_schema)

    def test_correlated_signal_is_nonqualifying_and_reproducible(self) -> None:
        body = b'{"record":"synthetic-owned-data"}'
        records = (
            response("owner", "principal.owner", True, 200, body),
            response("other", "principal.other", False, 200, body),
        )
        run = invocation(self.adapter, records)
        first = evaluate_offline_api_case(
            adapter=self.adapter, case_id=CASE_ID, invocation=run, evidence=records
        )
        second = evaluate_offline_api_case(
            adapter=self.adapter, case_id=CASE_ID, invocation=run, evidence=records[::-1]
        )
        self.assertEqual(first, second)
        self.assertEqual(first.disposition, "corroborated_synthetic_signal")
        self.assertEqual(first.validator_state, "verified")
        self.assertEqual(first.adapter_disposition, "verified_finding")
        self.assertEqual(first.to_dict()["effects"]["finding_publication"], "none")
        self.assertFalse(list(self.schema_validator.iter_errors(first.to_dict())))
        self.assertNotIn("synthetic-owned-data", json.dumps(first.to_dict()))
        self.assertEqual(
            verify_offline_api_case(
                adapter=self.adapter,
                case_id=CASE_ID,
                invocation=run,
                evidence=records,
                result=first.to_dict(),
            ),
            first,
        )

    def test_unauthorized_success_without_matching_representation_needs_review(self) -> None:
        records = (
            response("owner", "principal.owner", True, 200, b"owner-view"),
            response("other", "principal.other", False, 200, b"different-view"),
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=CASE_ID,
            invocation=invocation(self.adapter, records),
            evidence=records,
        )
        self.assertEqual(result.adapter_disposition, "verified_finding")
        self.assertEqual(result.validator_state, "hypothesis")
        self.assertEqual(result.disposition, "review_required")

    def test_denial_is_negative_not_a_finding(self) -> None:
        records = (
            response("owner", "principal.owner", True, 200, b"owner-view"),
            response("other", "principal.other", False, 403, b"denied"),
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=CASE_ID,
            invocation=invocation(self.adapter, records),
            evidence=records,
        )
        self.assertEqual(result.validator_state, "negative")
        self.assertEqual(result.disposition, "negative_synthetic_result")

    def test_single_uncontrolled_response_cannot_be_correlated(self) -> None:
        records = (response("other", "principal.other", False, 200, b"uncontrolled"),)
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=CASE_ID,
            invocation=invocation(self.adapter, records),
            evidence=records,
        )
        self.assertEqual(result.adapter_disposition, "verified_finding")
        self.assertEqual(result.validator_state, "abstained")
        self.assertEqual(result.disposition, "review_required")

    def test_mismatched_adapter_input_rejects_before_execution(self) -> None:
        records = (response("other", "principal.other", False, 200, b"uncontrolled"),)
        run = invocation(self.adapter, records)
        changed = copy.deepcopy(run.input_data)
        changed["exchanges"][0]["status_code"] = 403
        run = AdapterInvocation(**{**run.__dict__, "input_data": changed})
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            evaluate_offline_api_case(
                adapter=self.adapter, case_id=CASE_ID, invocation=run, evidence=records
            )

    def test_non_synthetic_invocation_and_non_native_adapter_reject(self) -> None:
        records = (response("other", "principal.other", False, 200, b"uncontrolled"),)
        run = invocation(self.adapter, records)
        live = AdapterInvocation(**{**run.__dict__, "environment": "live"})
        with self.assertRaisesRegex(OfflineApiAssessmentError, "invocation was rejected"):
            evaluate_offline_api_case(
                adapter=self.adapter, case_id=CASE_ID, invocation=live, evidence=records
            )
        injected = OfflineReferenceAdapter(
            self.adapter.manifest, lambda _: ([], "not_required", ())
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "native implementation"):
            evaluate_offline_api_case(
                adapter=injected, case_id=CASE_ID, invocation=run, evidence=records
            )

        class OverriddenAdapter(OfflineReferenceAdapter):
            def execute(self, invocation: AdapterInvocation) -> None:
                raise AssertionError("overridden adapter must never execute")

        overridden = OverriddenAdapter(self.adapter.manifest, self.adapter.analyzer)
        with self.assertRaisesRegex(OfflineApiAssessmentError, "native reference adapter"):
            evaluate_offline_api_case(
                adapter=overridden, case_id=CASE_ID, invocation=run, evidence=records
            )

    def test_evidence_or_result_substitution_fails_verification(self) -> None:
        body = b"same-body"
        records = (
            response("owner", "principal.owner", True, 200, body),
            response("other", "principal.other", False, 200, body),
        )
        run = invocation(self.adapter, records)
        result = evaluate_offline_api_case(
            adapter=self.adapter, case_id=CASE_ID, invocation=run, evidence=records
        )
        changed_result = result.to_dict()
        changed_result["disposition"] = "negative_synthetic_result"
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_case(
                adapter=self.adapter,
                case_id=CASE_ID,
                invocation=run,
                evidence=records,
                result=changed_result,
            )
        wrong_type = result.to_dict()
        wrong_type["schema_version"] = True
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_case(
                adapter=self.adapter,
                case_id=CASE_ID,
                invocation=run,
                evidence=records,
                result=wrong_type,
            )
        changed_evidence = (
            records[0],
            response("other", "principal.other", False, 200, b"different-body"),
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_case(
                adapter=self.adapter,
                case_id=CASE_ID,
                invocation=run,
                evidence=changed_evidence,
                result=result.to_dict(),
            )

    def test_mutated_typed_evidence_is_rechecked_before_use(self) -> None:
        record = response("other", "principal.other", False, 200, b"original")
        run = invocation(self.adapter, (record,))
        object.__setattr__(record, "content", b"substituted")
        with self.assertRaisesRegex(OfflineApiAssessmentError, "content address"):
            evaluate_offline_api_case(
                adapter=self.adapter,
                case_id=CASE_ID,
                invocation=run,
                evidence=(record,),
            )

    def test_synthetic_retest_reports_observation_change_not_a_fix(self) -> None:
        prior_records = (
            response("owner-prior", "principal.owner", True, 200, b"same-body"),
            response("other-prior", "principal.other", False, 200, b"same-body"),
        )
        second_records = (
            response("owner-second", "principal.owner", True, 200, b"same-body"),
            response("other-second", "principal.other", False, 403, b"denied"),
        )
        prior_run = invocation(self.adapter, prior_records)
        second_run = replace(
            invocation(self.adapter, second_records),
            invocation_id="INV-SYNTHETIC-API-002",
        )
        prior = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.synthetic.api.prior",
            invocation=prior_run,
            evidence=prior_records,
        )
        second = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.synthetic.api.second",
            invocation=second_run,
            evidence=second_records,
        )
        comparison = compare_offline_api_retest(
            adapter=self.adapter,
            prior_case_id=prior.case_id,
            prior_invocation=prior_run,
            prior_evidence=prior_records,
            prior_result=prior.to_dict(),
            second_case_id=second.case_id,
            second_invocation=second_run,
            second_evidence=second_records,
            second_result=second.to_dict(),
        )
        self.assertEqual(
            comparison.observation_change,
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertFalse(list(self.retest_schema_validator.iter_errors(comparison.to_dict())))
        self.assertNotIn("verified_fix", json.dumps(comparison.to_dict()))
        verification_args = {
            "adapter": self.adapter,
            "prior_case_id": prior.case_id,
            "prior_invocation": prior_run,
            "prior_evidence": prior_records,
            "prior_result": prior.to_dict(),
            "second_case_id": second.case_id,
            "second_invocation": second_run,
            "second_evidence": second_records,
            "second_result": second.to_dict(),
        }
        self.assertEqual(
            verify_offline_api_retest(result=comparison.to_dict(), **verification_args),
            comparison,
        )
        changed_comparison = comparison.to_dict()
        changed_comparison["observation_change"] = "signal_observed_in_second_synthetic_case"
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_retest(result=changed_comparison, **verification_args)
        wrong_type = comparison.to_dict()
        wrong_type["schema_version"] = True
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_retest(result=wrong_type, **verification_args)
        changed_target_run = replace(second_run, target_id="TARGET-SYNTHETIC-002")
        changed_target_result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=second.case_id,
            invocation=changed_target_run,
            evidence=second_records,
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "retest mission"):
            compare_offline_api_retest(
                adapter=self.adapter,
                prior_case_id=prior.case_id,
                prior_invocation=prior_run,
                prior_evidence=prior_records,
                prior_result=prior.to_dict(),
                second_case_id=second.case_id,
                second_invocation=changed_target_run,
                second_evidence=second_records,
                second_result=changed_target_result.to_dict(),
            )

    def test_retest_rejects_access_expectation_and_principal_drift(self) -> None:
        prior_records = (
            response("owner-prior", "principal.owner", True, 200, b"same-body"),
            response("other-prior", "principal.other", False, 200, b"same-body"),
        )
        prior_run = invocation(self.adapter, prior_records)
        prior = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.synthetic.api.prior",
            invocation=prior_run,
            evidence=prior_records,
        )
        for second_records in (
            (
                response("owner-second", "principal.owner", True, 200, b"same-body"),
                response("other-second", "principal.other", True, 200, b"same-body"),
            ),
            (
                response("owner-second", "principal.owner", True, 200, b"same-body"),
                response("other-second", "principal.replacement", False, 200, b"same-body"),
            ),
        ):
            with self.subTest(second_principal=second_records[1].attributes["principal_id"]):
                second_run = replace(
                    invocation(self.adapter, second_records),
                    invocation_id="INV-SYNTHETIC-API-002",
                )
                second = evaluate_offline_api_case(
                    adapter=self.adapter,
                    case_id="case.synthetic.api.second",
                    invocation=second_run,
                    evidence=second_records,
                )
                with self.assertRaisesRegex(
                    OfflineApiAssessmentError, "retest principal or expected access changed"
                ):
                    compare_offline_api_retest(
                        adapter=self.adapter,
                        prior_case_id=prior.case_id,
                        prior_invocation=prior_run,
                        prior_evidence=prior_records,
                        prior_result=prior.to_dict(),
                        second_case_id=second.case_id,
                        second_invocation=second_run,
                        second_evidence=second_records,
                        second_result=second.to_dict(),
                    )

    def test_batch_reproduces_cases_and_flags_mixed_observations(self) -> None:
        prior_records = (
            response("owner-prior", "principal.owner", True, 200, b"same-body"),
            response("other-prior", "principal.other", False, 200, b"same-body"),
        )
        second_records = (
            response("owner-second", "principal.owner", True, 200, b"same-body"),
            response("other-second", "principal.other", False, 403, b"denied"),
        )
        prior_run = invocation(self.adapter, prior_records)
        second_run = replace(
            invocation(self.adapter, second_records), invocation_id="INV-SYNTHETIC-API-002"
        )
        prior_case_id = "case.synthetic.api.prior"
        second_case_id = "case.synthetic.api.second"
        prior_result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=prior_case_id,
            invocation=prior_run,
            evidence=prior_records,
        )
        second_result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=second_case_id,
            invocation=second_run,
            evidence=second_records,
        )
        sources = (
            OfflineApiCaseSource(prior_case_id, prior_run, prior_records, prior_result.to_dict()),
            OfflineApiCaseSource(
                second_case_id, second_run, second_records, second_result.to_dict()
            ),
        )
        batch = build_offline_api_batch(adapter=self.adapter, sources=sources)
        self.assertEqual(
            batch, build_offline_api_batch(adapter=self.adapter, sources=sources[::-1])
        )
        self.assertEqual(batch.disposition_counts[0][1], 1)
        self.assertEqual(batch.disposition_counts[1][1], 1)
        self.assertEqual(batch.review_candidate_case_ids, (prior_case_id,))
        self.assertEqual(len(batch.mixed_observation_binding_sha256s), 1)
        self.assertFalse(list(self.batch_schema_validator.iter_errors(batch.to_dict())))
        self.assertEqual(
            verify_offline_api_batch(adapter=self.adapter, sources=sources, batch=batch.to_dict()),
            batch,
        )
        changed = batch.to_dict()
        changed["disposition_counts"]["negative_synthetic_result"] = 2
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_batch(adapter=self.adapter, sources=sources, batch=changed)
        wrong_type = batch.to_dict()
        wrong_type["disposition_counts"]["negative_synthetic_result"] = True
        with self.assertRaisesRegex(OfflineApiAssessmentError, "does not match"):
            verify_offline_api_batch(adapter=self.adapter, sources=sources, batch=wrong_type)
        with self.assertRaisesRegex(OfflineApiAssessmentError, "replay"):
            build_offline_api_batch(adapter=self.adapter, sources=(sources[0], sources[0]))
        changed_run = replace(second_run, mission_id="MISSION-SYNTHETIC-002")
        changed_result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=second_case_id,
            invocation=changed_run,
            evidence=second_records,
        )
        changed_source = OfflineApiCaseSource(
            second_case_id, changed_run, second_records, changed_result.to_dict()
        )
        with self.assertRaisesRegex(OfflineApiAssessmentError, "batch mission"):
            build_offline_api_batch(adapter=self.adapter, sources=(sources[0], changed_source))


if __name__ == "__main__":
    unittest.main()

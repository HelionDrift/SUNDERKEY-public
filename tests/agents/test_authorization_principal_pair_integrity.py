"""A third principal cannot corroborate a same-principal authorization match."""

from __future__ import annotations

import copy
import unittest

from scripts.run_offline_api_assessment import _native_adapter
from sunderkey.finding_validators import (
    DEFAULT_REGISTRY,
    AuthorizationDifferentialValidator,
    EvidenceRecord,
    FindingValidationRequest,
)
from sunderkey.offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    build_offline_api_batch,
    evaluate_offline_api_case,
    verify_offline_api_batch,
    verify_offline_api_case,
)
from sunderkey.offline_api_world_projection import (
    build_offline_api_world_projection,
    verify_offline_api_world_projection,
)
from tests.agents.test_offline_api_assessment import invocation, response


def validate(records):
    return DEFAULT_REGISTRY.validate(
        FindingValidationRequest(
            scope_id="scope.synthetic.pair",
            technique_id="AT3-GB-D06-S09-01",
            validator_id=AuthorizationDifferentialValidator.descriptor.validator_id,
            validator_version=AuthorizationDifferentialValidator.descriptor.version,
            evidence=tuple(records),
        )
    )


def conflicting():
    return (
        response("allowed", "principal.same", True, 200, b"same"),
        response("other", "principal.same", False, 200, b"same"),
        response("third", "principal.distinct", True, 403, b"denied"),
    )


def with_attributes(record, **changes):
    attributes = dict(record.attributes)
    for key, value in changes.items():
        if value is None:
            attributes.pop(key, None)
        else:
            attributes[key] = value
    return EvidenceRecord.from_bytes(
        record.evidence_id,
        record.content,
        role=record.role,
        status_code=record.status_code,
        media_type=record.media_type,
        attributes=attributes,
    )


class AuthorizationPrincipalPairIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()

    def test_same_principal_match_and_unrelated_third_principal_abstain(self) -> None:
        records = conflicting()
        before = copy.deepcopy([dict(record.attributes) for record in records])
        result = validate(records)
        self.assertEqual(result.state, "abstained")
        self.assertEqual(result.reason_codes, ("comparison_binding_ambiguous",))
        checks = {
            item["code"]: item["passed"] for item in result.to_dict()["false_positive_checks"]
        }
        self.assertIs(checks["distinct_principals"], True)
        self.assertIs(checks["principal_access_consistent"], False)
        self.assertEqual([dict(record.attributes) for record in records], before)
        self.assertEqual(result.to_dict(), validate(records[::-1]).to_dict())

    def test_conflicting_labels_still_abstain_if_another_distinct_pair_matches(self) -> None:
        records = (*conflicting(), response("fourth", "principal.fourth", False, 200, b"same"))
        self.assertEqual(validate(records).state, "abstained")

    def test_missing_or_invalid_identity_cannot_borrow_other_principals(self) -> None:
        records = (
            response("allowed", "principal.owner", True, 200, b"same"),
            response("other", "principal.other", False, 200, b"same"),
            response("third", "principal.third", True, 403, b"denied"),
        )
        for value in (None, "", "principal with space", 1, True):
            with self.subTest(value=value):
                changed = (records[0], with_attributes(records[1], principal_id=value), records[2])
                self.assertEqual(validate(changed).state, "abstained")

    def test_missing_or_numeric_polarity_does_not_disappear_from_the_comparison(self) -> None:
        records = (
            response("allowed", "principal.owner", True, 200, b"same"),
            response("other", "principal.other", False, 200, b"same"),
            response("third", "principal.third", True, 403, b"denied"),
        )
        for value in (None, 0, 1, "true"):
            with self.subTest(value=value):
                changed = (*records[:2], with_attributes(records[2], expected_access=value))
                self.assertEqual(validate(changed).state, "abstained")

    def test_repeated_mixed_status_with_consistent_expected_access_remains_valid(self) -> None:
        records = (
            response("allowed", "principal.owner", True, 200, b"same"),
            response("owner-denied", "principal.owner", True, 403, b"denied"),
            response("other", "principal.other", False, 200, b"same"),
        )
        self.assertEqual(validate(records).state, "verified")
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id="case.consistent.pair",
            invocation=invocation(self.adapter, records),
            evidence=records,
        )
        self.assertEqual(result.disposition, "corroborated_synthetic_signal")
        self.assertTrue(all(value == "none" for value in result.to_dict()["effects"].values()))

    def test_distinct_denied_subject_remains_a_negative_result(self) -> None:
        records = (
            response("allowed", "principal.owner", True, 200, b"same"),
            response("other", "principal.other", False, 403, b"denied"),
        )
        self.assertEqual(validate(records).state, "negative")

    def test_ambiguous_case_and_batch_replay_without_corroboration(self) -> None:
        records = conflicting()
        run = invocation(self.adapter, records)
        result = evaluate_offline_api_case(
            adapter=self.adapter, case_id="case.ambiguous.pair", invocation=run, evidence=records
        )
        self.assertEqual(result.validator_state, "abstained")
        self.assertEqual(result.disposition, "review_required")
        verify_offline_api_case(
            adapter=self.adapter,
            case_id=result.case_id,
            invocation=run,
            evidence=records,
            result=result.to_dict(),
        )
        source = OfflineApiCaseSource(result.case_id, run, records, result.to_dict())
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,))
        verify_offline_api_batch(adapter=self.adapter, sources=(source,), batch=batch.to_dict())
        changed = result.to_dict()
        changed["validator_state"] = "verified"
        changed["disposition"] = "corroborated_synthetic_signal"
        with self.assertRaises(OfflineApiAssessmentError):
            verify_offline_api_case(
                adapter=self.adapter,
                case_id=result.case_id,
                invocation=run,
                evidence=records,
                result=changed,
            )

    def test_ambiguous_case_cannot_create_a_world_model_hypothesis(self) -> None:
        records = conflicting()
        run = invocation(self.adapter, records)
        result = evaluate_offline_api_case(
            adapter=self.adapter, case_id="case.ambiguous.graph", invocation=run, evidence=records
        )
        source = OfflineApiCaseSource(result.case_id, run, records, result.to_dict())
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,))
        options = {
            "adapter": self.adapter,
            "sources": (source,),
            "batch": batch.to_dict(),
            "observed_at": "2026-09-24T12:00:00Z",
            "expires_at": "2026-09-25T12:00:00Z",
        }
        projection = build_offline_api_world_projection(**options)
        self.assertEqual(projection["snapshot"]["edges"], [])
        self.assertEqual(projection["skipped_case_ids"], [result.case_id])
        self.assertEqual(
            verify_offline_api_world_projection(projection=projection, **options), projection
        )
        self.assertTrue(all(value == "none" for value in projection["effects"].values()))


if __name__ == "__main__":
    unittest.main()

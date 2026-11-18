"""Phase 64 candidate enrollment decision record coverage."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.candidate_enrollment_decision import (
    CandidateEnrollmentDecisionRecord,
    _record_hash,
    _record_id,
    build_candidate_enrollment_decision_submission_template,
    load_candidate_enrollment_decision_submission,
    record_candidate_enrollment_decision,
    verify_candidate_enrollment_decision_record,
)
from sunderkey.candidate_enrollment_dossier import (
    load_candidate_enrollment_decision_dossier,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
DOSSIER_PATH = ROOT / "registry" / "candidate-enrollment-dossier-d009.json"
SCHEMA_PATH = (
    ROOT
    / "registry"
    / "schemas"
    / "candidate-enrollment-decision-record.schema.json"
)


def completed_submission(template: dict, *, alternate: bool = False) -> dict:
    submission = copy.deepcopy(template)
    submission["approval"].update(
        {
            "decision_status": "approved",
            "approver_id": "repository-owner.phase64",
            "approved_at": "2026-08-02T15:00:00Z",
            "rationale": (
                "Approve the selected D009 architecture for contract implementation. "
                "This does not enroll keys, owners, repositories, or evidence."
            ),
        }
    )
    if alternate:
        submission["selected_options"]["enrollment_lifetime"] = (
            "single_manifest_only"
        )
    return submission


class CandidateEnrollmentDecisionPhase64Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_decision_dossier(DOSSIER_PATH)

    def template(self):
        return build_candidate_enrollment_decision_submission_template(
            self.dossier
        )

    def record(self, *, alternate: bool = False):
        return record_candidate_enrollment_decision(
            self.dossier,
            completed_submission(self.template(), alternate=alternate),
        )

    def test_template_prefills_recommendations_without_approval(self) -> None:
        template = self.template()
        self.assertIsNone(template["approval"]["decision_status"])
        self.assertIsNone(template["approval"]["approver_id"])
        self.assertIsNone(template["approval"]["approved_at"])
        self.assertIsNone(template["approval"]["rationale"])
        self.assertEqual(template["submission_effect"], "none_until_recorded")
        self.assertEqual(len(template["selected_options"]), 9)

    def test_records_recommended_bundle_deterministically(self) -> None:
        first = self.record()
        second = self.record()
        self.assertEqual(first, second)
        document = first.to_dict()
        self.assertEqual(document["decision_id"], "D009")
        self.assertEqual(
            document["decision_status"],
            "approved_operator_asserted_unsigned",
        )
        self.assertTrue(
            document["recommendation_alignment"]["all_recommended_options_selected"]
        )
        self.assertEqual(document["implementation_status"], "not_started")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(
            verify_candidate_enrollment_decision_record(first, self.dossier),
            first,
        )

    def test_allowed_alternate_is_recorded_without_claiming_recommendation(self) -> None:
        document = self.record(alternate=True).to_dict()
        self.assertFalse(
            document["recommendation_alignment"]["all_recommended_options_selected"]
        )
        self.assertEqual(
            document["recommendation_alignment"][
                "selected_recommended_option_count"
            ],
            8,
        )

    def test_unknown_option_is_rejected(self) -> None:
        submission = completed_submission(self.template())
        submission["selected_options"]["repository_identity"] = "self_declared"
        with self.assertRaisesRegex(QualificationError, "is not allowed"):
            record_candidate_enrollment_decision(self.dossier, submission)

    def test_rehashed_implementation_tampering_is_rejected(self) -> None:
        document = self.record().to_dict()
        document["implementation_status"] = "complete"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"record_id", "record_sha256"}
        }
        record_hash = _record_hash(body)
        document["record_id"] = _record_id(record_hash)
        document["record_sha256"] = record_hash
        with self.assertRaisesRegex(QualificationError, "boundary is invalid"):
            CandidateEnrollmentDecisionRecord.from_dict(document)

    def test_submission_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "submission.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_candidate_enrollment_decision_submission(path)

    def test_record_contains_no_keys_secrets_or_em_dash(self) -> None:
        serialized = json.dumps(self.record().to_dict(), sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key"',
            '"public_key"',
            '"signature"',
            '"credential"',
            '"repository_endpoint"',
        ):
            self.assertNotIn(field, serialized)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_record_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.record().to_dict())


if __name__ == "__main__":
    unittest.main()

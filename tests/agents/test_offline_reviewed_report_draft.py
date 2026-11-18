"""Local report drafts retain review and retest lineage without finding claims."""

from __future__ import annotations

import copy
import unittest

import tests.agents.test_offline_api_reviewer_dossier as dossier_fixture
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.coverage_scheduler import CoverageSchedule
from sunderkey.offline_api_reviewer_dossier import build_offline_api_reviewer_dossier
from sunderkey.offline_reviewed_report_draft import (
    OfflineReviewedReportDraftError,
    build_offline_reviewed_report_draft,
    verify_offline_reviewed_report_draft,
)
from sunderkey.offline_task_review_receipts import (
    ReviewerKeyBinding,
    build_offline_task_review_packet,
    build_offline_task_work_product,
    sign_offline_task_review_attestation,
)
class OfflineReviewedReportDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        dossier_fixture.OfflineApiReviewerDossierTests.setUpClass()

    def setUp(self) -> None:
        fixture = dossier_fixture.OfflineApiReviewerDossierTests(
            "test_dossier_binds_review_and_retest_without_finding"
        )
        fixture.setUp()
        self.dossier_options = fixture.options
        self.dossier = build_offline_api_reviewer_dossier(**self.dossier_options)
        self.schedule = CoverageSchedule.from_dict(
            self.dossier_options["review_bridge_options"]["planning_bundle"]["schedule"]
        )
        task = self.schedule.tasks[0]
        candidate = build_offline_task_work_product(
            schedule=self.schedule,
            task_id=task.task_id,
            work_result_sha256="sha256:" + "a" * 64,
            evidence_sha256s=["sha256:" + "b" * 64],
            completed_at="2026-09-24T12:05:00Z",
        )
        keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
        roles = ("independent_control", "independent_assurance")
        self.bindings = {
            f"review.key.{index}": ReviewerKeyBinding(
                f"review.key.{index}",
                f"reviewer.synthetic.{index}",
                role,
                key.public_key(),
            )
            for index, (role, key) in enumerate(zip(roles, keys, strict=True))
        }
        self.attestations = [
            sign_offline_task_review_attestation(
                schedule=self.schedule,
                candidate=candidate,
                reviewer_id=f"reviewer.synthetic.{index}",
                role=role,
                key_id=f"review.key.{index}",
                reviewed_at="2026-09-24T12:06:00Z",
                decision="accepted",
                private_key=key,
            )
            for index, (role, key) in enumerate(zip(roles, keys, strict=True))
        ]
        self.packet = build_offline_task_review_packet(
            schedule=self.schedule,
            candidate=candidate,
            attestations=self.attestations,
        )

    def options(self):
        return {
            "dossier": self.dossier,
            "dossier_options": self.dossier_options,
            "schedule": self.schedule,
            "review_packet": self.packet,
            "reviewer_keys": self.bindings,
        }

    def test_accepted_local_packet_yields_unpublished_nonfinding_draft(self) -> None:
        draft = build_offline_reviewed_report_draft(**self.options())
        self.assertEqual(
            verify_offline_reviewed_report_draft(document=draft, **self.options()),
            draft,
        )
        self.assertEqual(draft["finding_count"], 0)
        self.assertEqual(draft["report_state"], "unpublished_nonfinding_draft")
        self.assertEqual(draft["effects"]["report_publication"], "none")
        self.assertFalse(draft["positive_use_approved"])
        self.assertEqual(draft["transition_sha256"], self.dossier["transition_sha256"])

    def test_rejected_or_rebound_review_cannot_be_presented_as_accepted(self) -> None:
        declined = copy.deepcopy(self.packet)
        declined["attestations"][0]["decision"] = "rejected"
        with self.assertRaises(OfflineReviewedReportDraftError):
            build_offline_reviewed_report_draft(
                **{**self.options(), "review_packet": declined}
            )
        wrong_keys = dict(self.bindings)
        wrong_keys["review.key.0"] = ReviewerKeyBinding(
            "review.key.0",
            "reviewer.synthetic.0",
            "independent_control",
            Ed25519PrivateKey.generate().public_key(),
        )
        with self.assertRaises(OfflineReviewedReportDraftError):
            build_offline_reviewed_report_draft(
                **{**self.options(), "reviewer_keys": wrong_keys}
            )

    def test_dossier_and_draft_rebinding_fail_closed(self) -> None:
        altered_dossier = copy.deepcopy(self.dossier)
        altered_dossier["tenant_id"] = "tenant.other"
        with self.assertRaises(OfflineReviewedReportDraftError):
            build_offline_reviewed_report_draft(
                **{**self.options(), "dossier": altered_dossier}
            )
        draft = build_offline_reviewed_report_draft(**self.options())
        altered_draft = copy.deepcopy(draft)
        altered_draft["finding_count"] = 1
        with self.assertRaisesRegex(OfflineReviewedReportDraftError, "does not match"):
            verify_offline_reviewed_report_draft(
                document=altered_draft, **self.options()
            )


if __name__ == "__main__":
    unittest.main()

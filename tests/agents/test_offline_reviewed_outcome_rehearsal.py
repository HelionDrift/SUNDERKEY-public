"""Reviewed task success remains simulation-only without live custody."""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

import tests.agents.test_offline_task_review_receipts as receipt_fixture
from sunderkey.offline_reviewed_outcome_rehearsal import (
    OfflineReviewedOutcomeRehearsalError,
    build_offline_reviewed_outcome_rehearsal,
    verify_offline_reviewed_outcome_rehearsal,
)
from tests.agents.test_offline_task_review_receipts import NoopPublicKey

NOW = "2026-09-24T12:07:00Z"


class OfflineReviewedOutcomeRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        receipt_fixture.OfflineTaskReviewReceiptTests.setUpClass()

    def setUp(self) -> None:
        fixture = receipt_fixture.OfflineTaskReviewReceiptTests(
            "test_signed_reviews_bind_work_product_but_grant_no_positive_use"
        )
        fixture.setUp()
        self.fixture = fixture
        self.packet = fixture.packet()
        self.observations = {
            fixture.task.task_id: {
                "status": "succeeded",
                "evidence_digests": fixture.candidate["evidence_sha256s"],
            }
        }

    def options(self) -> dict:
        return {
            "schedule": self.fixture.schedule,
            "observations": self.observations,
            "review_packets": {self.fixture.task.task_id: self.packet},
            "reviewer_keys": self.fixture.bindings,
            "rehearsed_at": NOW,
        }

    def test_reviewed_success_is_bound_but_not_admitted(self) -> None:
        document = build_offline_reviewed_outcome_rehearsal(**self.options())
        self.assertEqual(
            verify_offline_reviewed_outcome_rehearsal(document=document, **self.options()),
            document,
        )
        self.assertEqual(len(document["review_bindings"]), 1)
        self.assertTrue(document["simulation_only"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(document["effects"]["admission"], "none")

    def test_missing_declined_or_late_review_cannot_support_success(self) -> None:
        with self.assertRaisesRegex(OfflineReviewedOutcomeRehearsalError, "differ"):
            build_offline_reviewed_outcome_rehearsal(**{**self.options(), "review_packets": {}})
        declined = self.fixture.packet(second=self.fixture.attestation(1, decision="rejected"))
        with self.assertRaisesRegex(OfflineReviewedOutcomeRehearsalError, "matching"):
            build_offline_reviewed_outcome_rehearsal(
                **{
                    **self.options(),
                    "review_packets": {self.fixture.task.task_id: declined},
                }
            )
        with self.assertRaisesRegex(OfflineReviewedOutcomeRehearsalError, "matching"):
            build_offline_reviewed_outcome_rehearsal(
                **{**self.options(), "rehearsed_at": "2026-09-24T12:05:00Z"}
            )

    def test_changed_evidence_or_claim_fails(self) -> None:
        different = copy.deepcopy(self.observations)
        different[self.fixture.task.task_id]["evidence_digests"] = ["sha256:" + "f" * 64]
        with self.assertRaisesRegex(OfflineReviewedOutcomeRehearsalError, "matching"):
            build_offline_reviewed_outcome_rehearsal(
                **{**self.options(), "observations": different}
            )
        document = build_offline_reviewed_outcome_rehearsal(**self.options())
        changed = copy.deepcopy(document)
        changed["positive_use_approved"] = True
        with self.assertRaisesRegex(OfflineReviewedOutcomeRehearsalError, "does not match"):
            verify_offline_reviewed_outcome_rehearsal(document=changed, **self.options())

    def test_reassigned_key_cannot_support_reviewed_success(self) -> None:
        valid = build_offline_reviewed_outcome_rehearsal(**self.options())
        self.assertFalse(valid["positive_use_approved"])
        bindings = dict(self.fixture.bindings)
        key_id = self.packet["attestations"][0]["key_id"]
        bindings[key_id] = replace(bindings[key_id])
        fake = NoopPublicKey()
        object.__setattr__(bindings[key_id], "public_key", fake)
        with self.assertRaises(OfflineReviewedOutcomeRehearsalError):
            build_offline_reviewed_outcome_rehearsal(
                **{**self.options(), "reviewer_keys": bindings}
            )
        self.assertEqual(fake.calls, 0)


if __name__ == "__main__":
    unittest.main()

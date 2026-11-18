"""Inert email-control metadata remains review-only and test-mailbox-bound."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.email_control_review import (
    EmailCleanupAssertion,
    EmailControlReviewError,
    EmailControlStatus,
    EmailDeliveryObservation,
    EmailTestApproval,
    review_email_control,
)

TENANT = "tenant:one"
SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
MAILBOX = "test-mailbox:sha256:" + "c" * 64
OTHER_MAILBOX = "test-mailbox:sha256:" + "d" * 64
AT = "2026-09-23T13:00:00Z"
OBSERVED = "2026-09-23T12:00:00Z"
EXPIRES = "2026-09-24T12:00:00Z"


def approval(*, mailboxes=(MAILBOX,), artifacts=("inert_link",), expires_at=EXPIRES):
    return EmailTestApproval(
        tenant_id=TENANT, scope_sha256=SCOPE, scenario_id="scenario:mail",
        test_mailbox_refs=mailboxes,
        allowed_artifact_classes=artifacts,
        approved_at="2026-09-23T11:00:00Z", expires_at=expires_at,
        source_sha256=SOURCE,
    )


def observation(
    *, selected_approval=None, mailbox=MAILBOX, artifact="inert_link",
    gateway="blocked_asserted", delivery="not_delivered_asserted",
    observed_at=OBSERVED, expires_at=EXPIRES,
):
    selected_approval = selected_approval or approval()
    return EmailDeliveryObservation(
        tenant_id=TENANT, scope_sha256=SCOPE,
        approval_sha256=selected_approval.approval_sha256,
        test_mailbox_ref=mailbox, artifact_class=artifact,
        gateway_disposition=gateway, mailbox_disposition=delivery,
        source_sha256=SOURCE, observed_at=observed_at, expires_at=expires_at,
    )


def cleanup(selected_observation, *, state="confirmed_asserted"):
    return EmailCleanupAssertion(
        tenant_id=TENANT, scope_sha256=SCOPE,
        approval_sha256=selected_observation.approval_sha256,
        observation_sha256=selected_observation.observation_sha256,
        state=state, source_sha256=SOURCE,
        observed_at="2026-09-23T12:30:00Z", expires_at=EXPIRES,
    )


def review(items=(), cleanups=(), *, selected_approval=None, reviewed_at=AT):
    return review_email_control(
        approval=selected_approval or approval(),
        observations=tuple(items), cleanup_assertions=tuple(cleanups),
        reviewed_at=reviewed_at,
    )


class EmailControlReviewTests(unittest.TestCase):
    def test_asserted_block_is_not_control_effectiveness_proof(self):
        output = review((observation(),))
        self.assertEqual(output.status, EmailControlStatus.ASSERTED_PREVENTION_FOR_REVIEW)
        rendered = output.to_dict()
        self.assertFalse(rendered["control_effectiveness_proven"])
        self.assertTrue(rendered["independent_review_required"])
        for effect in rendered["effects"].values():
            self.assertEqual(effect, "none")
        self.assertNotIn("recipient_address", str(rendered))

    def test_delivery_requires_review_and_cleanup_does_not_erase_it(self):
        delivered = observation(
            gateway="delivered_asserted", delivery="delivered_asserted",
        )
        pending = review((delivered,))
        self.assertEqual(pending.status, EmailControlStatus.ATTENTION_REQUIRED)
        self.assertIn("delivered_cleanup_unverified", pending.review_reasons)
        cleaned = review((delivered,), (cleanup(delivered),))
        self.assertEqual(cleaned.status, EmailControlStatus.ATTENTION_REQUIRED)
        self.assertNotIn("delivered_cleanup_unverified", cleaned.review_reasons)
        self.assertEqual(cleaned.items[0].cleanup_state, "confirmed_asserted")

    def test_empty_unknown_and_stale_evidence_are_inconclusive(self):
        self.assertEqual(review().status, EmailControlStatus.INCONCLUSIVE)
        unknown = observation(gateway="unknown", delivery="unknown")
        self.assertEqual(review((unknown,)).status, EmailControlStatus.INCONCLUSIVE)
        old_approval = approval(expires_at="2026-09-23T12:30:00Z")
        old_observation = observation(selected_approval=old_approval)
        self.assertEqual(
            review((old_observation,), selected_approval=old_approval).status,
            EmailControlStatus.STALE_EVIDENCE,
        )

    def test_order_and_exact_binding_are_enforced(self):
        selected = approval(
            mailboxes=(MAILBOX, OTHER_MAILBOX),
            artifacts=("header_only", "inert_link"),
        )
        first = observation(selected_approval=selected)
        second = observation(
            selected_approval=selected, mailbox=OTHER_MAILBOX, artifact="header_only",
            gateway="quarantined_asserted",
        )
        self.assertEqual(
            review((first, second), selected_approval=selected).to_dict(),
            review((second, first), selected_approval=selected).to_dict(),
        )
        self.assertEqual(
            review((first, second), selected_approval=selected).status,
            EmailControlStatus.INCONCLUSIVE,
        )
        self.assertIn(
            "coverage_incomplete",
            review((first, second), selected_approval=selected).review_reasons,
        )
        with self.assertRaisesRegex(EmailControlReviewError, "approval binding"):
            review((observation(mailbox=OTHER_MAILBOX),))
        with self.assertRaisesRegex(EmailControlReviewError, "observation binding"):
            review((first,), (cleanup(second),), selected_approval=selected)

    def test_complete_approved_matrix_is_required_for_asserted_prevention(self):
        selected = approval(
            mailboxes=(MAILBOX, OTHER_MAILBOX),
            artifacts=("header_only", "inert_link"),
        )
        items = tuple(
            observation(
                selected_approval=selected, mailbox=mailbox, artifact=artifact,
            )
            for mailbox in selected.test_mailbox_refs
            for artifact in selected.allowed_artifact_classes
        )
        self.assertEqual(
            review(items, selected_approval=selected).status,
            EmailControlStatus.ASSERTED_PREVENTION_FOR_REVIEW,
        )
        self.assertEqual(
            review(items[:-1], selected_approval=selected).status,
            EmailControlStatus.INCONCLUSIVE,
        )

    def test_conflicts_tampering_and_raw_mailbox_fail_closed(self):
        with self.assertRaisesRegex(EmailControlReviewError, "dispositions conflict"):
            observation(delivery="delivered_asserted")
        with self.assertRaisesRegex(EmailControlReviewError, "conflicting evidence"):
            review((observation(), observation(
                gateway="unknown", delivery="unknown",
            )))
        with self.assertRaisesRegex(EmailControlReviewError, "test-mailbox reference"):
            approval(mailboxes=("person@example.com",))
        with self.assertRaisesRegex(EmailControlReviewError, "observation_sha256"):
            replace(observation(), gateway_disposition="unknown")
        with self.assertRaisesRegex(EmailControlReviewError, "review_sha256"):
            replace(review((observation(),)), reviewed_at="2026-09-23T14:00:00Z")

    def test_approval_window_future_time_and_retention_are_bounded(self):
        with self.assertRaisesRegex(EmailControlReviewError, "approval is future-dated"):
            review(reviewed_at="2026-09-23T10:00:00Z")
        with self.assertRaisesRegex(EmailControlReviewError, "outside approval"):
            review((observation(observed_at="2026-09-23T10:00:00Z"),))
        with self.assertRaisesRegex(EmailControlReviewError, "future-dated"):
            review((observation(
                observed_at="2026-09-23T14:00:00Z",
                expires_at="2026-09-24T14:00:00Z",
            ),))
        with self.assertRaisesRegex(EmailControlReviewError, "hard limit"):
            approval(expires_at="2026-10-02T12:00:00Z")


if __name__ == "__main__":
    unittest.main()

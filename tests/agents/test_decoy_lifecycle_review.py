"""Synthetic decoy lifecycle evidence remains asserted and effect-free."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.decoy_lifecycle_review import (
    DecoyLifecycleError,
    DecoyLifecycleEvent,
    DecoyPlacementApproval,
    DecoyState,
    review_decoy_lifecycle,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
EVIDENCE = "sha256:" + "c" * 64
DECOY = "synthetic-decoy:sha256:" + "d" * 64
OTHER_DECOY = "synthetic-decoy:sha256:" + "e" * 64
SURFACE = "surface:sha256:" + "f" * 64
AT = "2026-09-23T15:00:00Z"


def approval(
    *, tenant="tenant:one", scope=SCOPE, decoy=DECOY,
    approved_at="2026-09-23T10:00:00Z",
    expires_at="2026-09-24T10:00:00Z",
):
    return DecoyPlacementApproval(
        tenant_id=tenant, scope_sha256=scope, decoy_ref=decoy,
        surface_ref=SURFACE, owner_id="owner:one",
        approved_at=approved_at, expires_at=expires_at,
        source_sha256=SOURCE,
    )


def event(
    event_id, kind, occurred_at, *, approved=None, tenant="tenant:one",
    scope=SCOPE, decoy=DECOY,
):
    approved = approved or approval()
    return DecoyLifecycleEvent(
        event_id=event_id, tenant_id=tenant, scope_sha256=scope,
        decoy_ref=decoy, approval_sha256=approved.approval_sha256,
        kind=kind, occurred_at=occurred_at, evidence_sha256=EVIDENCE,
    )


def review(events=(), *, approved=None, reviewed_at=AT):
    return review_decoy_lifecycle(
        approval=approved or approval(), events=tuple(events), reviewed_at=reviewed_at,
    )


class DecoyLifecycleReviewTests(unittest.TestCase):
    def test_empty_and_placed_states_are_only_assertions(self):
        self.assertEqual(review().state, DecoyState.AWAITING_PLACEMENT)
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        output = review((placed,))
        self.assertEqual(output.state, DecoyState.PLACED_ASSERTED)
        self.assertEqual(output.to_dict()["effects"]["deployment"], "none")
        self.assertEqual(output.to_dict()["effects"]["monitoring"], "none")
        self.assertEqual(output.to_dict()["effects"]["removal"], "none")

    def test_trigger_revocation_and_removal_preserve_review_obligations(self):
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        triggered = event("event:triggered", "trigger_asserted", "2026-09-23T12:00:00Z")
        revoked = event("event:revoked", "revocation_asserted", "2026-09-23T13:00:00Z")
        removed = event("event:removed", "removal_asserted", "2026-09-23T14:00:00Z")
        output = review((removed, triggered, placed, revoked))
        self.assertEqual(output.state, DecoyState.REMOVED_ASSERTED)
        self.assertIn("trigger_requires_independent_review", output.review_flags)
        self.assertIn("removal_evidence_requires_verification", output.review_flags)
        self.assertEqual(output.event_sha256[0], placed.event_sha256)
        self.assertEqual(output.event_sha256[-1], removed.event_sha256)

    def test_expiry_and_revocation_require_cleanup_evidence(self):
        approved = approval(expires_at="2026-09-23T12:00:00Z")
        placed = event(
            "event:placed", "placement_asserted", "2026-09-23T11:00:00Z",
            approved=approved,
        )
        expired = review((placed,), approved=approved)
        self.assertIn("expired_placement_requires_removal", expired.review_flags)
        revoked = event(
            "event:revoked", "revocation_asserted", "2026-09-23T13:00:00Z",
            approved=approved,
        )
        output = review((placed, revoked), approved=approved)
        self.assertEqual(output.state, DecoyState.REVOKED_ASSERTED)
        self.assertIn("revoked_placement_requires_removal", output.review_flags)

    def test_post_expiry_trigger_remains_a_review_signal_not_attacker_proof(self):
        approved = approval(expires_at="2026-09-23T12:00:00Z")
        placed = event(
            "event:placed", "placement_asserted", "2026-09-23T11:00:00Z",
            approved=approved,
        )
        triggered = event(
            "event:triggered", "trigger_asserted", "2026-09-23T13:00:00Z",
            approved=approved,
        )
        output = review((placed, triggered), approved=approved)
        self.assertIn("post_expiry_trigger_requires_review", output.review_flags)
        self.assertIn("expired_placement_requires_removal", output.review_flags)

    def test_invalid_transitions_fail_closed(self):
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        triggered = event("event:triggered", "trigger_asserted", "2026-09-23T12:00:00Z")
        revoked = event("event:revoked", "revocation_asserted", "2026-09-23T13:00:00Z")
        removed = event("event:removed", "removal_asserted", "2026-09-23T14:00:00Z")
        late_trigger = event(
            "event:late-trigger", "trigger_asserted", "2026-09-23T14:00:00Z",
        )
        late_revocation = event(
            "event:late-revocation", "revocation_asserted", "2026-09-23T14:30:00Z",
        )
        for events, message in (
            ((triggered,), "lacks active"),
            ((removed,), "lacks asserted placement"),
            ((placed, placed, triggered), None),
            ((placed, revoked, late_trigger), "lacks active"),
            ((placed, removed, late_revocation), "lacks active"),
        ):
            if message is None:
                self.assertEqual(review(events).state, DecoyState.TRIGGERED_ASSERTED)
            else:
                with self.subTest(events=events), self.assertRaisesRegex(
                    DecoyLifecycleError, message,
                ):
                    review(events)

    def test_stale_placement_and_ambiguous_chronology_fail_closed(self):
        approved = approval(expires_at="2026-09-23T12:00:00Z")
        late = event(
            "event:late", "placement_asserted", "2026-09-23T13:00:00Z",
            approved=approved,
        )
        with self.assertRaisesRegex(DecoyLifecycleError, "lacks current approval"):
            review((late,), approved=approved)
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        same_time = event("event:triggered", "trigger_asserted", "2026-09-23T11:00:00Z")
        with self.assertRaisesRegex(DecoyLifecycleError, "ambiguous equal timestamps"):
            review((placed, same_time))

    def test_binding_future_conflict_and_opaque_reference_fail_closed(self):
        with self.assertRaisesRegex(DecoyLifecycleError, "opaque synthetic reference"):
            approval(decoy="credential:real-secret")
        with self.assertRaisesRegex(DecoyLifecycleError, "future-dated"):
            review((), approved=approval(approved_at="2026-09-23T16:00:00Z"))
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        with self.assertRaisesRegex(DecoyLifecycleError, "crosses approval binding"):
            review((event("event:other", "placement_asserted",
                          "2026-09-23T11:00:00Z", decoy=OTHER_DECOY),))
        with self.assertRaisesRegex(DecoyLifecycleError, "conflicting evidence"):
            review((placed, event("event:placed", "placement_asserted",
                                  "2026-09-23T12:00:00Z")))
        with self.assertRaisesRegex(DecoyLifecycleError, "outside review chronology"):
            review((event("event:future", "placement_asserted",
                          "2026-09-23T16:00:00Z"),))

    def test_hash_tampering_fails_closed_and_effects_are_detached(self):
        approved = approval()
        placed = event("event:placed", "placement_asserted", "2026-09-23T11:00:00Z")
        with self.assertRaisesRegex(DecoyLifecycleError, "approval_sha256"):
            replace(approved, owner_id="owner:other")
        with self.assertRaisesRegex(DecoyLifecycleError, "event_sha256"):
            replace(placed, evidence_sha256="sha256:" + "f" * 64)
        output = review((placed,))
        with self.assertRaisesRegex(DecoyLifecycleError, "review_sha256"):
            replace(output, reviewed_at="2026-09-23T15:01:00Z")
        detached = output.to_dict()
        detached["effects"]["deployment"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["deployment"], "none")


if __name__ == "__main__":
    unittest.main()

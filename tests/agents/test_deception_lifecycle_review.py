"""Synthetic tripwire declarations do not place a decoy or issue a token."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.deception_lifecycle_review import (
    DeceptionLifecycleReviewError,
    build_deception_lifecycle_review,
    verify_deception_lifecycle_review,
)


def sources() -> tuple[dict, list[dict]]:
    plan = {
        "schema_version": 1,
        "plan_ref": "decoy-plan-synthetic-01",
        "asset_ref": "asset-synthetic-01",
        "owner_ref": "owner-synthetic-01",
        "scope_sha256": "sha256:" + "a" * 64,
        "owner_approval_sha256": "sha256:" + "b" * 64,
        "token_class": "nonprivileged_unique_marker",
        "token_sha256": "sha256:" + "c" * 64,
        "removal_procedure_sha256": "sha256:" + "d" * 64,
        "removal_test_sha256": "sha256:" + "e" * 64,
        "created_at": "2026-10-01T00:00:00Z",
        "expires_at": "2026-10-10T00:00:00Z",
    }
    events = [
        {
            "event_id": "event-01", "kind": "placement",
            "at": "2026-10-02T00:00:00Z", "evidence_sha256": "sha256:" + "1" * 64,
            "token_sha256": plan["token_sha256"], "related_alert_ref": None,
        },
        {
            "event_id": "event-02", "kind": "alert",
            "at": "2026-10-03T00:00:00Z", "evidence_sha256": "sha256:" + "2" * 64,
            "token_sha256": plan["token_sha256"],
            "related_alert_ref": "alert-synthetic-01",
        },
    ]
    return plan, events


class DeceptionLifecycleReviewTests(unittest.TestCase):
    def test_placement_alert_revocation_cleanup_replay(self) -> None:
        plan, events = sources()
        report = build_deception_lifecycle_review(
            plan, events, "2026-10-04T00:00:00Z"
        )
        self.assertEqual(report["declared_state"], "declared_active")
        self.assertEqual(report["declared_alert_count"], 1)
        self.assertEqual(report["declared_late_alert_count"], 0)
        self.assertEqual(report["declared_post_revocation_alert_count"], 0)
        self.assertEqual(report["declared_post_cleanup_alert_count"], 0)
        self.assertFalse(report["cleanup_due"])
        self.assertFalse(report["owner_approval_verified"])
        self.assertFalse(report["token_privilege_verified"])
        self.assertEqual(report["effects"]["deception_placement"], "none")
        self.assertNotIn("token_sha256", report)
        self.assertEqual(
            verify_deception_lifecycle_review(
                plan, events, "2026-10-04T00:00:00Z", report
            )["status"],
            "valid",
        )
        revoked = copy.deepcopy(events)
        revoked.append({
            "event_id": "event-03", "kind": "revocation",
            "at": "2026-10-05T00:00:00Z", "evidence_sha256": "sha256:" + "3" * 64,
            "token_sha256": plan["token_sha256"], "related_alert_ref": None,
        })
        report = build_deception_lifecycle_review(
            plan, revoked, "2026-10-06T00:00:00Z"
        )
        self.assertEqual(report["declared_state"], "declared_revoked_cleanup_due")
        self.assertTrue(report["cleanup_due"])
        revoked.append({
            "event_id": "event-04", "kind": "cleanup",
            "at": "2026-10-06T12:00:00Z", "evidence_sha256": "sha256:" + "4" * 64,
            "token_sha256": plan["token_sha256"], "related_alert_ref": None,
        })
        report = build_deception_lifecycle_review(
            plan, revoked, "2026-10-07T00:00:00Z"
        )
        self.assertEqual(report["declared_state"], "declared_cleaned")
        self.assertFalse(report["cleanup_due"])

    def test_alerts_after_revocation_or_cleanup_dispute_claims(self) -> None:
        plan, events = sources()
        events.extend([
            {
                "event_id": "event-03", "kind": "revocation",
                "at": "2026-10-04T00:00:00Z", "evidence_sha256": "sha256:" + "3" * 64,
                "token_sha256": plan["token_sha256"], "related_alert_ref": None,
            },
            {
                "event_id": "event-04", "kind": "alert",
                "at": "2026-10-05T00:00:00Z", "evidence_sha256": "sha256:" + "4" * 64,
                "token_sha256": plan["token_sha256"],
                "related_alert_ref": "alert-synthetic-02",
            },
            {
                "event_id": "event-05", "kind": "cleanup",
                "at": "2026-10-06T00:00:00Z", "evidence_sha256": "sha256:" + "5" * 64,
                "token_sha256": plan["token_sha256"], "related_alert_ref": None,
            },
            {
                "event_id": "event-06", "kind": "alert",
                "at": "2026-10-07T00:00:00Z", "evidence_sha256": "sha256:" + "6" * 64,
                "token_sha256": plan["token_sha256"],
                "related_alert_ref": "alert-synthetic-03",
            },
        ])
        report = build_deception_lifecycle_review(
            plan, events, "2026-10-08T00:00:00Z"
        )
        self.assertEqual(report["declared_post_revocation_alert_count"], 2)
        self.assertEqual(report["declared_post_cleanup_alert_count"], 1)
        self.assertEqual(report["declared_state"], "declared_cleanup_disputed")
        self.assertTrue(report["cleanup_due"])
        events[-1]["related_alert_ref"] = events[3]["related_alert_ref"]
        with self.assertRaisesRegex(DeceptionLifecycleReviewError, "alert references"):
            build_deception_lifecycle_review(plan, events, "2026-10-08T00:00:00Z")

    def test_expiry_requires_declared_cleanup_and_unplaced_stays_inert(self) -> None:
        plan, events = sources()
        report = build_deception_lifecycle_review(
            plan, events, plan["expires_at"]
        )
        self.assertEqual(report["declared_state"], "declared_expired_cleanup_due")
        self.assertTrue(report["cleanup_due"])
        report = build_deception_lifecycle_review(
            plan, [], plan["expires_at"]
        )
        self.assertEqual(report["declared_state"], "unplaced")
        self.assertFalse(report["cleanup_due"])
        late = copy.deepcopy(events)
        late[1]["at"] = "2026-10-11T00:00:00Z"
        report = build_deception_lifecycle_review(
            plan, late, "2026-10-12T00:00:00Z"
        )
        self.assertEqual(report["declared_late_alert_count"], 1)
        self.assertEqual(report["declared_state"], "declared_expired_cleanup_due")

    def test_bad_event_order_digest_and_plan_are_rejected(self) -> None:
        for mutate in (
            lambda p, e: e.reverse(),
            lambda p, e: e[1].update(event_id=e[0]["event_id"]),
            lambda p, e: e[1].update(token_sha256="sha256:" + "f" * 64),
            lambda p, e: e[0].update(related_alert_ref="alert-01"),
            lambda p, e: e[1].update(related_alert_ref=None),
            lambda p, e: p.update(token_class="privileged_secret"),
            lambda p, e: p.update(removal_test_sha256="not-a-digest"),
            lambda p, e: p.update(expires_at=p["created_at"]),
            lambda p, e: p.update(schema_version=True),
        ):
            plan, events = sources()
            mutate(plan, events)
            with self.subTest(plan=plan, events=events):
                with self.assertRaises(DeceptionLifecycleReviewError):
                    build_deception_lifecycle_review(
                        plan, events, "2026-10-04T00:00:00Z"
                    )
        plan, events = sources()
        events.append({
            "event_id": "event-03", "kind": "placement",
            "at": "2026-10-04T00:00:00Z", "evidence_sha256": "sha256:" + "3" * 64,
            "token_sha256": plan["token_sha256"], "related_alert_ref": None,
        })
        with self.assertRaises(DeceptionLifecycleReviewError):
            build_deception_lifecycle_review(plan, events, "2026-10-05T00:00:00Z")
        plan, events = sources()
        events[0]["at"] = plan["expires_at"]
        events[1]["at"] = "2026-10-11T00:00:00Z"
        with self.assertRaisesRegex(DeceptionLifecycleReviewError, "expiry"):
            build_deception_lifecycle_review(plan, events, "2026-10-12T00:00:00Z")

    def test_changed_source_or_report_fails_replay(self) -> None:
        plan, events = sources()
        as_of = "2026-10-04T00:00:00Z"
        report = build_deception_lifecycle_review(plan, events, as_of)
        changed = copy.deepcopy(report)
        changed["cleanup_due"] = True
        with self.assertRaises(DeceptionLifecycleReviewError):
            verify_deception_lifecycle_review(plan, events, as_of, changed)
        events[1]["evidence_sha256"] = "sha256:" + "9" * 64
        with self.assertRaises(DeceptionLifecycleReviewError):
            verify_deception_lifecycle_review(plan, events, as_of, report)

    def test_schema_and_synthetic_example(self) -> None:
        root = Path(__file__).resolve().parents[2]
        schema = json.loads((
            root / "registry/schemas/deception-lifecycle-review-v1.schema.json"
        ).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        example = json.loads((
            root / "examples/deception-lifecycle-review-v1.json"
        ).read_text(encoding="utf-8"))
        report = build_deception_lifecycle_review(
            example["plan"], example["events"], example["as_of"]
        )
        Draft202012Validator(schema).validate(report)
        self.assertEqual(report["declared_state"], "declared_expired_cleanup_due")


if __name__ == "__main__":
    unittest.main()

"""Source-replayed tests for an inert declared lockout timeline."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_password_lockout_timeline as lockout


class PasswordLockoutTimelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = lockout.component_fixture()

    def projections(self, model: dict) -> list[dict]:
        return lockout.analyze_supplied_password_lockout(model).to_dict()["projections"]

    def test_declared_lockout_conflict_is_source_replayed_only(self) -> None:
        original = copy.deepcopy(self.model)
        report = lockout.analyze_supplied_password_lockout(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S01")
        self.assertEqual(document["summary"], {
            "event_count": 3, "candidate_count": 1, "unknown_count": 2,
        })
        first, second, inside = document["projections"]
        self.assertEqual(first["projected_decision"], "unknown")
        self.assertEqual(second["projected_decision"], "unknown")
        self.assertEqual(inside["projected_decision"], "deny")
        self.assertEqual(inside["assessment"], "candidate_declared_lockout_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated",
            "reported_outcomes_authenticated", "credential_value_processed",
            "authentication_attempt_performed", "effective_lockout_observed",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            lockout.verify_supplied_password_lockout(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            lockout.verify_supplied_password_lockout_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_lockout_end_and_success_reset_do_not_project_access(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"].append({
            "event_id": "synthetic:after", "account_id": "synthetic:account-one",
            "at_tick": 21, "reported_outcome": "succeeded",
        })
        row = self.projections(model)[-1]
        self.assertEqual(row["projected_decision"], "unknown")
        model = copy.deepcopy(self.model)
        model["events"][1]["reported_outcome"] = "succeeded"
        row = self.projections(model)[2]
        self.assertEqual(row["projected_decision"], "unknown")

    def test_declared_failure_during_lockout_is_consistency_only(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"][2]["reported_outcome"] = "failed"
        self.assertEqual(
            self.projections(model)[2]["assessment"], "declared_failure_consistent"
        )

    def test_incomplete_premises_preserve_unknown(self) -> None:
        for field in ("policy_complete", "events_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                row = self.projections(model)[2]
                self.assertEqual(row["projected_decision"], "unknown")
                self.assertEqual(row["basis"], "incomplete_policy_events_or_order")

    def test_unknown_outcome_taints_later_projection_for_same_account(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"][1]["reported_outcome"] = "unknown"
        row = self.projections(model)[2]
        self.assertEqual(row["projected_decision"], "unknown")
        self.assertEqual(row["basis"], "prior_unknown_outcome")

    def test_closed_model_rejects_passwords_and_ambiguous_events(self) -> None:
        cases = []
        secret = copy.deepcopy(self.model)
        secret["events"][0]["password"] = "forbidden"
        cases.append(secret)
        real_id = copy.deepcopy(self.model)
        real_id["accounts"][0] = "real@example.com"
        cases.append(real_id)
        duplicate = copy.deepcopy(self.model)
        duplicate["events"][1]["event_id"] = "synthetic:first"
        cases.append(duplicate)
        unordered = copy.deepcopy(self.model)
        unordered["events"][1]["at_tick"] = 10
        cases.append(unordered)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["events"][0]["at_tick"] = True
        cases.append(bool_tick)
        empty = copy.deepcopy(self.model)
        empty["events"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(lockout.PasswordLockoutTimelineError):
                    lockout.analyze_supplied_password_lockout(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = lockout.analyze_supplied_password_lockout(self.model)
        changed = copy.deepcopy(self.model)
        changed["events"][2]["reported_outcome"] = "failed"
        with self.assertRaises(lockout.PasswordLockoutTimelineError):
            lockout.verify_supplied_password_lockout(report, model=changed)
        with self.assertRaises(lockout.PasswordLockoutTimelineError):
            lockout.verify_supplied_password_lockout_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(lockout.PasswordLockoutTimelineError):
            lockout.PasswordLockoutTimelineReport({})
        with self.assertRaises(lockout.PasswordLockoutTimelineError):
            lockout.verify_supplied_password_lockout(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

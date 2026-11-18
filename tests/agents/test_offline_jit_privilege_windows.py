"""Source-replayed tests for inert just-in-time privilege windows."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_jit_privilege_windows as jit


class JitPrivilegeWindowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = jit.component_fixture()

    def projection(self, model: dict, index: int = 1) -> dict:
        return jit.analyze_supplied_jit_privilege_windows(model).to_dict()["projections"][index]

    def test_active_and_revoked_windows_are_source_replayed(self) -> None:
        original = copy.deepcopy(self.model)
        report = jit.analyze_supplied_jit_privilege_windows(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S12")
        self.assertEqual(document["summary"], {
            "observation_count": 2, "candidate_count": 1, "unknown_count": 0,
        })
        before, after = document["projections"]
        self.assertEqual(before["projected_decision"], "allow")
        self.assertEqual(before["assessment"], "declared_consistent")
        self.assertEqual(after["projected_decision"], "deny")
        self.assertEqual(after["assessment"], "candidate_declared_window_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "grant_approval_authenticated", "revocation_authenticated",
            "reported_outcomes_authenticated", "effective_privilege_observed",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            jit.verify_supplied_jit_privilege_windows(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            jit.verify_supplied_jit_privilege_windows_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_window_start_end_and_unapproved_grants_deny(self) -> None:
        for at_tick in (9, 20, 30):
            model = copy.deepcopy(self.model)
            model["observations"][0]["at_tick"] = at_tick
            with self.subTest(at_tick=at_tick):
                self.assertEqual(self.projection(model, 0)["projected_decision"], "deny")
        model = copy.deepcopy(self.model)
        model["grants"][0]["approval_recorded"] = False
        self.assertEqual(self.projection(model, 0)["projected_decision"], "deny")

    def test_missing_premises_preserve_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["revocations_complete"] = False
        self.assertEqual(self.projection(model, 0)["basis"], "unlisted_revocation_possible")
        model = copy.deepcopy(self.model)
        model["grants"].clear()
        model["revocations"].clear()
        model["grants_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "unlisted_grant_possible")
        for field in ("policy_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.projection(model)["basis"], "incomplete_policy_or_order")

    def test_overlapping_unrevoked_grant_is_still_declared_active(self) -> None:
        model = copy.deepcopy(self.model)
        second = copy.deepcopy(model["grants"][0])
        second["grant_id"] = "synthetic:grant-two"
        model["grants"].append(second)
        row = self.projection(model)
        self.assertEqual(row["projected_decision"], "allow")
        self.assertEqual(row["eligible_grant_ids"], ["synthetic:grant-two"])

    def test_rejects_non_synthetic_secret_like_and_malformed_records(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["live_endpoint"] = "https://example.invalid"
        cases.append(extra)
        real_identity = copy.deepcopy(self.model)
        real_identity["grants"][0]["principal_id"] = "alice@example.com"
        cases.append(real_identity)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["observations"][0]["at_tick"] = True
        cases.append(bool_tick)
        reversed_window = copy.deepcopy(self.model)
        reversed_window["grants"][0]["ends_at"] = 10
        cases.append(reversed_window)
        dangling = copy.deepcopy(self.model)
        dangling["revocations"][0]["grant_id"] = "synthetic:missing"
        cases.append(dangling)
        premature = copy.deepcopy(self.model)
        premature["revocations"][0]["at_tick"] = 9
        cases.append(premature)
        duplicate = copy.deepcopy(self.model)
        duplicate["observations"].append(copy.deepcopy(duplicate["observations"][0]))
        cases.append(duplicate)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(jit.JitPrivilegeWindowError):
                    jit.analyze_supplied_jit_privilege_windows(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = jit.analyze_supplied_jit_privilege_windows(self.model)
        changed = copy.deepcopy(self.model)
        changed["observations"][1]["reported_outcome"] = "denied"
        with self.assertRaises(jit.JitPrivilegeWindowError):
            jit.verify_supplied_jit_privilege_windows(report, model=changed)
        with self.assertRaises(jit.JitPrivilegeWindowError):
            jit.verify_supplied_jit_privilege_windows_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(jit.JitPrivilegeWindowError):
            jit.JitPrivilegeWindowReport({})
        with self.assertRaises(jit.JitPrivilegeWindowError):
            jit.verify_supplied_jit_privilege_windows(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

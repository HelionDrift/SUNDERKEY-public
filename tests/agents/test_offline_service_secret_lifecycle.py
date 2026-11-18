"""Source-replayed tests for synthetic service-secret lifecycle metadata."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_service_secret_lifecycle as lifecycle


class ServiceSecretLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = lifecycle.component_fixture()

    def projection(self, model: dict, index: int = 1) -> dict:
        return lifecycle.analyze_supplied_service_secret_lifecycle(model).to_dict()[
            "projections"
        ][index]

    def test_negative_rotation_invariant_and_original_source_replay(self) -> None:
        original = copy.deepcopy(self.model)
        report = lifecycle.analyze_supplied_service_secret_lifecycle(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S11")
        self.assertEqual(document["summary"], {
            "observation_count": 2, "candidate_count": 1, "unknown_count": 1,
        })
        early, stale = document["projections"]
        self.assertEqual(early["projected_decision"], "unknown")
        self.assertEqual(early["basis"], "no_negative_invariant")
        self.assertEqual(stale["projected_decision"], "deny")
        self.assertEqual(stale["basis"], "beyond_declared_rotation_age")
        self.assertEqual(stale["assessment"], "candidate_declared_stale_secret_use")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "account_policy_authenticated",
            "secret_metadata_authenticated", "reported_outcomes_authenticated",
            "credential_value_processed", "effective_access_observed", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            lifecycle.verify_supplied_service_secret_lifecycle(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            lifecycle.verify_supplied_service_secret_lifecycle_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_issuance_revocation_expiration_and_age_boundaries(self) -> None:
        expectations = (
            (9, "before_declared_issuance"),
            (30, "no_negative_invariant"),
            (31, "beyond_declared_rotation_age"),
            (40, "after_declared_revocation"),
            (50, "after_declared_revocation"),
        )
        for tick, basis in expectations:
            model = copy.deepcopy(self.model)
            model["observations"][0]["at_tick"] = tick
            with self.subTest(tick=tick):
                self.assertEqual(self.projection(model, 0)["basis"], basis)
        model = copy.deepcopy(self.model)
        model["secrets"][0]["revoked_at"] = None
        model["observations"][0]["at_tick"] = 50
        self.assertEqual(self.projection(model, 0)["basis"], "after_declared_expiration")

    def test_unknown_metadata_or_premises_never_project_access(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][1]["secret_id"] = "synthetic:missing"
        self.assertEqual(self.projection(model)["basis"], "unknown_secret_metadata")
        for field in ("policy_complete", "order_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.projection(model)["basis"], "incomplete_policy_or_order")
        model = copy.deepcopy(self.model)
        model["observations"][1]["reported_outcome"] = "unknown"
        self.assertEqual(self.projection(model)["assessment"], "unknown")

    def test_declared_denial_remains_only_consistency_not_validation(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][1]["reported_outcome"] = "denied"
        self.assertEqual(self.projection(model)["assessment"], "declared_deny_consistent")

    def test_rejects_secret_values_and_malformed_metadata(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["secrets"][0]["secret_value"] = "forbidden"
        cases.append(extra)
        real_identity = copy.deepcopy(self.model)
        real_identity["accounts"][0]["account_id"] = "service@example.com"
        cases.append(real_identity)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["observations"][0]["at_tick"] = True
        cases.append(bool_tick)
        dangling = copy.deepcopy(self.model)
        dangling["secrets"][0]["account_id"] = "synthetic:missing"
        cases.append(dangling)
        premature = copy.deepcopy(self.model)
        premature["secrets"][0]["revoked_at"] = 9
        cases.append(premature)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(lifecycle.ServiceSecretLifecycleError):
                    lifecycle.analyze_supplied_service_secret_lifecycle(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = lifecycle.analyze_supplied_service_secret_lifecycle(self.model)
        changed = copy.deepcopy(self.model)
        changed["observations"][1]["reported_outcome"] = "denied"
        with self.assertRaises(lifecycle.ServiceSecretLifecycleError):
            lifecycle.verify_supplied_service_secret_lifecycle(report, model=changed)
        with self.assertRaises(lifecycle.ServiceSecretLifecycleError):
            lifecycle.verify_supplied_service_secret_lifecycle_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(lifecycle.ServiceSecretLifecycleError):
            lifecycle.ServiceSecretLifecycleReport({})
        with self.assertRaises(lifecycle.ServiceSecretLifecycleError):
            lifecycle.verify_supplied_service_secret_lifecycle(
                report.to_dict(), model=self.model,
            )


if __name__ == "__main__":
    unittest.main()

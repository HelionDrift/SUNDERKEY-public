"""Source-replayed tests for inert direct guest-trust declarations."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_guest_trust_projection as guest_trust


class GuestTrustProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = guest_trust.component_fixture()

    def projection(self, model: dict) -> dict:
        return guest_trust.analyze_supplied_guest_trust(model).to_dict()["projections"][0]

    def test_disabled_direct_trust_is_only_a_declared_candidate(self) -> None:
        original = copy.deepcopy(self.model)
        report = guest_trust.analyze_supplied_guest_trust(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S09")
        self.assertEqual(document["summary"], {
            "observation_count": 1, "candidate_count": 1, "unknown_count": 0,
        })
        row = document["projections"][0]
        self.assertEqual(row["projected_decision"], "deny")
        self.assertEqual(row["basis"], "direct_trust_disabled")
        self.assertEqual(row["assessment"], "candidate_declared_guest_trust_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "guest_inventory_authenticated",
            "trust_policy_authenticated", "reported_outcomes_authenticated",
            "federation_exchange_performed", "effective_guest_access_observed",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            guest_trust.verify_supplied_guest_trust(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            guest_trust.verify_supplied_guest_trust_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_enabled_trust_never_proves_access(self) -> None:
        model = copy.deepcopy(self.model)
        model["trusts"][0]["enabled"] = True
        row = self.projection(model)
        self.assertEqual(row["projected_decision"], "unknown")
        self.assertEqual(row["basis"], "no_federation_or_access_validation")

    def test_negative_guest_and_trust_invariants(self) -> None:
        cases = (
            (lambda m: m["guests"][0].update(active=False), "invitation_or_guest_inactive"),
            (
                lambda m: m["guests"][0].update(invitation_recorded=False),
                "invitation_or_guest_inactive",
            ),
            (
                lambda m: m["observations"][0].update(
                    resource_tenant="synthetic:elsewhere"
                ), "different_declared_resource_tenant"),
            (lambda m: m["trusts"].clear(), "direct_trust_absent"),
            (lambda m: m["guests"].clear(), "guest_absent_from_complete_inventory"),
        )
        for mutate, basis in cases:
            model = copy.deepcopy(self.model)
            mutate(model)
            with self.subTest(basis=basis):
                self.assertEqual(self.projection(model)["basis"], basis)

    def test_incomplete_premises_preserve_unknown(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "incomplete_policy")
        model = copy.deepcopy(self.model)
        model["guests"].clear()
        model["guests_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "guest_inventory_incomplete")
        model = copy.deepcopy(self.model)
        model["trusts"].clear()
        model["trusts_complete"] = False
        self.assertEqual(self.projection(model)["basis"], "trust_inventory_incomplete")

    def test_closed_model_rejects_real_identifiers_and_duplicate_edges(self) -> None:
        cases = []
        extra = copy.deepcopy(self.model)
        extra["endpoint"] = "https://example.invalid"
        cases.append(extra)
        real_id = copy.deepcopy(self.model)
        real_id["guests"][0]["guest_id"] = "guest@example.com"
        cases.append(real_id)
        duplicate = copy.deepcopy(self.model)
        duplicate["trusts"].append(copy.deepcopy(duplicate["trusts"][0]))
        cases.append(duplicate)
        empty = copy.deepcopy(self.model)
        empty["observations"].clear()
        cases.append(empty)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(guest_trust.GuestTrustProjectionError):
                    guest_trust.analyze_supplied_guest_trust(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = guest_trust.analyze_supplied_guest_trust(self.model)
        changed = copy.deepcopy(self.model)
        changed["trusts"][0]["enabled"] = True
        with self.assertRaises(guest_trust.GuestTrustProjectionError):
            guest_trust.verify_supplied_guest_trust(report, model=changed)
        with self.assertRaises(guest_trust.GuestTrustProjectionError):
            guest_trust.verify_supplied_guest_trust_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(guest_trust.GuestTrustProjectionError):
            guest_trust.GuestTrustProjectionReport({})
        with self.assertRaises(guest_trust.GuestTrustProjectionError):
            guest_trust.verify_supplied_guest_trust(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

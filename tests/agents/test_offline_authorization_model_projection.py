"""Source-replayed tests for the inert RBAC, ABAC and ReBAC projection."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_authorization_model_projection as authorization


class AuthorizationModelProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = authorization.component_fixture()

    def projection(self, model: dict, observation_id: str = "bob-read") -> dict:
        report = authorization.analyze_supplied_authorization_model(model).to_dict()
        return next(
            row for row in report["projections"]
            if row["observation_id"] == observation_id
        )

    def test_declared_rbac_abac_rebac_conjunction_and_candidate(self) -> None:
        original = copy.deepcopy(self.model)
        report = authorization.analyze_supplied_authorization_model(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S13")
        self.assertEqual(document["work_package_id"], "IWP2-AOE-GA-D03-S13")
        self.assertEqual(document["summary"], {
            "observation_count": 2, "candidate_count": 1, "unknown_count": 0,
        })
        alice, bob = document["projections"]
        self.assertEqual(alice["projected_decision"], "allow")
        self.assertEqual(alice["assessment"], "declared_consistent")
        self.assertEqual(alice["matching_rule_ids"], ["analyst-owner"])
        self.assertEqual(bob["projected_decision"], "deny")
        self.assertEqual(bob["basis"], "complete_default_deny")
        self.assertEqual(bob["assessment"], "candidate_declared_policy_conflict")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "policy_authenticated", "reported_outcomes_authenticated",
            "effective_access_observed", "finding_claimed", "full_candidate_assembled",
            "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            authorization.verify_supplied_authorization_model(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            authorization.verify_supplied_authorization_model_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_each_condition_is_required_for_declared_allow(self) -> None:
        for field, mutation in (
            ("role", lambda m: m["principals"][0]["roles"].clear()),
            (
                "principal_attribute",
                lambda m: m["principals"][0]["attributes"][0].update(value="external"),
            ),
            (
                "resource_attribute",
                lambda m: m["resources"][0]["attributes"][0].update(value="restricted"),
            ),
            ("relation", lambda m: m["relations"].clear()),
        ):
            model = copy.deepcopy(self.model)
            mutation(model)
            with self.subTest(field=field):
                row = self.projection(model, "alice-read")
                self.assertEqual(row["projected_decision"], "deny")
                self.assertEqual(row["assessment"], "candidate_declared_policy_conflict")

    def test_incomplete_facts_preserve_unknown_instead_of_default_deny(self) -> None:
        for completeness, mutation in (
            ("roles_complete", lambda m: m["principals"][0]["roles"].clear()),
            (
                "attributes_complete",
                lambda m: m["principals"][0]["attributes"].clear(),
            ),
            ("relations_complete", lambda m: m["relations"].clear()),
        ):
            model = copy.deepcopy(self.model)
            model[completeness] = False
            mutation(model)
            with self.subTest(completeness=completeness):
                row = self.projection(model, "alice-read")
                self.assertEqual(row["projected_decision"], "unknown")
                self.assertEqual(row["basis"], "unresolved_rule_conditions")
                self.assertEqual(row["assessment"], "unknown")
        model = copy.deepcopy(self.model)
        model["policy_complete"] = False
        self.assertEqual(self.projection(model, "alice-read")["basis"], "incomplete_policy")

    def test_conflicting_rules_and_potential_deny_do_not_claim_access(self) -> None:
        model = copy.deepcopy(self.model)
        deny = copy.deepcopy(model["rules"][0])
        deny.update(rule_id="deny-owner", effect="deny")
        model["rules"].append(deny)
        row = self.projection(model, "alice-read")
        self.assertEqual(row["projected_decision"], "unknown")
        self.assertEqual(row["basis"], "conflicting_rules")
        model = copy.deepcopy(self.model)
        deny["role"] = "unseen-role"
        model["rules"].append(deny)
        model["roles_complete"] = False
        row = self.projection(model, "alice-read")
        self.assertEqual(row["projected_decision"], "unknown")
        self.assertEqual(row["possible_rule_ids"], ["deny-owner"])

    def test_reported_unknown_never_becomes_a_candidate(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][1]["reported_outcome"] = "unknown"
        row = self.projection(model)
        self.assertEqual(row["projected_decision"], "deny")
        self.assertEqual(row["assessment"], "unknown")

    def test_closed_bounded_model_rejects_dangling_and_ambiguous_inputs(self) -> None:
        cases = []
        unknown = copy.deepcopy(self.model)
        unknown["extra"] = True
        cases.append(unknown)
        alias = copy.deepcopy(self.model)
        alias["schema_version"] = True
        cases.append(alias)
        duplicate = copy.deepcopy(self.model)
        duplicate["principals"].append(copy.deepcopy(duplicate["principals"][0]))
        cases.append(duplicate)
        dangling = copy.deepcopy(self.model)
        dangling["relations"][0]["principal_id"] = "missing"
        cases.append(dangling)
        bad_predicate = copy.deepcopy(self.model)
        bad_predicate["rules"][0]["principal_attribute"]["other"] = "value"
        cases.append(bad_predicate)
        oversized = copy.deepcopy(self.model)
        oversized["observations"] *= authorization.MAX_OBSERVATIONS + 1
        cases.append(oversized)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(authorization.AuthorizationModelProjectionError):
                    authorization.analyze_supplied_authorization_model(model)

    def test_report_cannot_verify_itself_or_a_changed_source(self) -> None:
        report = authorization.analyze_supplied_authorization_model(self.model)
        changed = copy.deepcopy(self.model)
        changed["observations"][1]["reported_outcome"] = "denied"
        with self.assertRaises(authorization.AuthorizationModelProjectionError):
            authorization.verify_supplied_authorization_model(report, model=changed)
        with self.assertRaises(authorization.AuthorizationModelProjectionError):
            authorization.verify_supplied_authorization_model_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(authorization.AuthorizationModelProjectionError):
            authorization.AuthorizationModelProjectionReport({})
        with self.assertRaises(authorization.AuthorizationModelProjectionError):
            authorization.verify_supplied_authorization_model(
                report.to_dict(), model=self.model,
            )


if __name__ == "__main__":
    unittest.main()

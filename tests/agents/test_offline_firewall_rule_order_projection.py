"""Synthetic tests for supplied firewall rule order and separate replay."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_firewall_rule_order_projection as firewall


class FirewallRuleOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = firewall.component_fixture()

    def report(self, model: dict) -> dict:
        return firewall.analyze_supplied_firewall_rule_order(model).to_dict()

    def test_first_match_and_default_are_source_bound_and_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = firewall.analyze_supplied_firewall_rule_order(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S05")
        self.assertEqual(document["summary"], {
            "query_count": 3, "declared_allow_count": 1, "unknown_count": 0,
        })
        self.assertEqual(
            [row["disposition"] for row in document["projections"]],
            ["deny_under_declared_policy", "allow_under_declared_policy",
             "deny_under_declared_policy"],
        )
        self.assertEqual(
            [row["matched_rule_id"] for row in document["projections"]],
            ["synthetic:deny-admin", "synthetic:allow-web", None],
        )
        self.assertTrue(document["projections"][2]["used_default_action"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "rule_installation_observed", "device_order_observed",
            "traffic_observed", "nat_proxy_or_vpn_modeled", "firewall_effectiveness_proven",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            firewall.verify_supplied_firewall_rule_order(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            firewall.verify_supplied_firewall_rule_order_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(), document,
        )

    def test_rule_order_changes_the_declared_decision(self) -> None:
        model = copy.deepcopy(self.model)
        model["rules"].reverse()
        document = self.report(model)
        self.assertEqual(document["projections"][0]["disposition"],
                         "allow_under_declared_policy")
        self.assertEqual(document["projections"][0]["matched_rule_id"],
                         "synthetic:allow-web")

    def test_default_allow_is_only_a_supplied_policy_result(self) -> None:
        model = copy.deepcopy(self.model)
        model["default_action"] = "allow"
        self.assertEqual(self.report(model)["projections"][2]["disposition"],
                         "allow_under_declared_policy")

    def test_incomplete_inputs_suppress_decisions_and_match_attribution(self) -> None:
        for field in ("policy_complete", "order_complete", "match_semantics_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                document = self.report(model)
                self.assertEqual(document["summary"]["unknown_count"], 3)
                self.assertEqual(document["summary"]["declared_allow_count"], 0)
                self.assertTrue(all(row["matched_rule_id"] is None
                                    for row in document["projections"]))

    def test_closed_model_rejects_invalid_rules_and_identifiers(self) -> None:
        cases = []
        duplicate = copy.deepcopy(self.model)
        duplicate["rules"][1]["rule_id"] = "synthetic:deny-admin"
        cases.append(duplicate)
        reverse = copy.deepcopy(self.model)
        reverse["rules"][0]["destination_port_min"] = 9000
        cases.append(reverse)
        bad_port = copy.deepcopy(self.model)
        bad_port["queries"][0]["destination_port"] = 0
        cases.append(bad_port)
        hidden = copy.deepcopy(self.model)
        hidden["rules"][0]["destination_ip"] = "192.0.2.1"
        cases.append(hidden)
        real = copy.deepcopy(self.model)
        real["source_id"] = "production-policy"
        cases.append(real)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(firewall.FirewallRuleOrderError):
                    firewall.analyze_supplied_firewall_rule_order(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = firewall.analyze_supplied_firewall_rule_order(self.model)
        changed = copy.deepcopy(self.model)
        changed["rules"].reverse()
        with self.assertRaises(firewall.FirewallRuleOrderError):
            firewall.verify_supplied_firewall_rule_order(report, model=changed)
        with self.assertRaises(firewall.FirewallRuleOrderError):
            firewall.verify_supplied_firewall_rule_order_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(firewall.FirewallRuleOrderError):
            firewall.FirewallRuleOrderReport({})
        with self.assertRaises(firewall.FirewallRuleOrderError):
            firewall.verify_supplied_firewall_rule_order(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

"""Synthetic, separate-source tests for local switch VLAN declarations."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_switch_vlan_projection as vlan


class SwitchVlanProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = vlan.component_fixture()

    def report(self, model: dict) -> dict:
        return vlan.analyze_supplied_switch_vlan(model).to_dict()

    def test_declared_bridge_is_source_bound_and_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = vlan.analyze_supplied_switch_vlan(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S04")
        self.assertEqual(document["summary"], {
            "query_count": 2, "candidate_count": 1, "unknown_count": 0,
        })
        self.assertEqual(
            [row["disposition"] for row in document["projections"]],
            ["candidate_declared_local_bridge", "no_candidate_declared_membership"],
        )
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "topology_observed", "port_configuration_observed",
            "stp_state_observed", "switch_forwarding_tested", "segmentation_proven",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            vlan.verify_supplied_switch_vlan(report, model=original).to_dict(), document
        )
        self.assertEqual(
            vlan.verify_supplied_switch_vlan_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(), document,
        )

    def test_trunk_tag_native_vlan_and_access_tag_are_distinct(self) -> None:
        model = copy.deepcopy(self.model)
        model["queries"] = [
            {"query_id": "synthetic:tagged", "ingress_port_id": "synthetic:trunk-one",
             "egress_port_id": "synthetic:access-two", "ingress_tag_vlan": 30},
            {"query_id": "synthetic:untagged", "ingress_port_id": "synthetic:trunk-one",
             "egress_port_id": "synthetic:access-one", "ingress_tag_vlan": None},
            {"query_id": "synthetic:access-tag", "ingress_port_id": "synthetic:access-one",
             "egress_port_id": "synthetic:trunk-one", "ingress_tag_vlan": 20},
        ]
        rows = self.report(model)["projections"]
        self.assertEqual([row["projected_vlan"] for row in rows], [30, 20, None])
        self.assertEqual([row["disposition"] for row in rows], [
            "candidate_declared_local_bridge", "candidate_declared_local_bridge",
            "no_candidate_unsupported_ingress_tag",
        ])

    def test_declared_port_state_does_not_create_a_candidate(self) -> None:
        model = copy.deepcopy(self.model)
        model["ports"][1]["stp_forwarding_vlans"] = [30]
        self.assertEqual(self.report(model)["projections"][0]["disposition"],
                         "no_candidate_declared_port_state")

    def test_incomplete_inputs_suppress_all_candidates(self) -> None:
        for field in ("topology_complete", "membership_complete", "stp_state_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["summary"], {
                    "query_count": 2, "candidate_count": 0, "unknown_count": 2,
                })
                self.assertTrue(all(
                    row["projected_vlan"] is None
                    for row in self.report(model)["projections"]
                ))

    def test_rejects_conflicting_or_out_of_range_declarations(self) -> None:
        cases = []
        duplicate = copy.deepcopy(self.model)
        duplicate["ports"][1]["port_id"] = "synthetic:access-one"
        cases.append(duplicate)
        bad_range = copy.deepcopy(self.model)
        bad_range["ports"][0]["access_vlan"] = 4095
        cases.append(bad_range)
        bad_native = copy.deepcopy(self.model)
        bad_native["ports"][1]["native_vlan"] = 40
        cases.append(bad_native)
        bad_state = copy.deepcopy(self.model)
        bad_state["ports"][0]["stp_forwarding_vlans"] = [30]
        cases.append(bad_state)
        unknown_port = copy.deepcopy(self.model)
        unknown_port["queries"][0]["egress_port_id"] = "synthetic:missing"
        cases.append(unknown_port)
        same_port = copy.deepcopy(self.model)
        same_port["queries"][0]["egress_port_id"] = "synthetic:access-one"
        cases.append(same_port)
        real_id = copy.deepcopy(self.model)
        real_id["switch_id"] = "production-switch"
        cases.append(real_id)
        hidden_field = copy.deepcopy(self.model)
        hidden_field["ports"][0]["credential"] = "forbidden"
        cases.append(hidden_field)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(vlan.SwitchVlanProjectionError):
                    vlan.analyze_supplied_switch_vlan(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = vlan.analyze_supplied_switch_vlan(self.model)
        changed = copy.deepcopy(self.model)
        changed["ports"][1]["stp_forwarding_vlans"] = [30]
        with self.assertRaises(vlan.SwitchVlanProjectionError):
            vlan.verify_supplied_switch_vlan(report, model=changed)
        with self.assertRaises(vlan.SwitchVlanProjectionError):
            vlan.verify_supplied_switch_vlan_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(vlan.SwitchVlanProjectionError):
            vlan.SwitchVlanProjectionReport({})
        with self.assertRaises(vlan.SwitchVlanProjectionError):
            vlan.verify_supplied_switch_vlan(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

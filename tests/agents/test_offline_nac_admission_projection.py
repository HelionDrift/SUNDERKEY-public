"""Synthetic tests for source-bound NAC admission assertions."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_nac_admission_projection as nac


class NacAdmissionProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = nac.component_fixture()

    def report(self, model: dict) -> dict:
        return nac.analyze_supplied_nac_admission(model).to_dict()

    def test_supplied_policy_difference_is_source_bound_and_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = nac.analyze_supplied_nac_admission(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S07")
        self.assertEqual(document["summary"], {
            "session_count": 2, "candidate_count": 1, "unknown_count": 0,
        })
        self.assertEqual(document["projections"][0]["disposition"],
                         "consistent_under_declared_policy")
        self.assertEqual(document["projections"][1]["issues"],
                         ["reject_port_state_differs_from_policy"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "radius_exchange_observed", "controlled_port_observed",
            "vlan_assignment_observed", "device_policy_verified", "access_bypass_proven",
            "finding_claimed", "full_candidate_assembled", "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            nac.verify_supplied_nac_admission(report, model=original).to_dict(), document
        )
        self.assertEqual(
            nac.verify_supplied_nac_admission_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(), document,
        )

    def test_explicit_policy_controls_accept_and_reject_mappings(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy"]["reject_requires_unauthorized"] = False
        self.assertEqual(self.report(model)["summary"]["candidate_count"], 0)
        model["sessions"][0]["controlled_port_state"] = "unauthorized"
        self.assertEqual(self.report(model)["projections"][0]["issues"],
                         ["accept_port_state_differs_from_policy"])

    def test_required_vlan_trio_and_declared_assignment_are_separate(self) -> None:
        model = copy.deepcopy(self.model)
        model["sessions"][0]["tunnel_medium_type"] = None
        self.assertEqual(self.report(model)["projections"][0]["issues"],
                         ["required_vlan_attributes_incomplete"])
        model["sessions"][0]["tunnel_medium_type"] = "ieee802"
        model["sessions"][0]["tunnel_private_group_vlan"] = 40
        self.assertEqual(self.report(model)["projections"][0]["issues"], [
            "assigned_vlan_not_declared_configured", "declared_vlan_assignment_differs",
        ])
        model["policy"]["accepted_vlan_required"] = False
        self.assertEqual(self.report(model)["projections"][0]["issues"], [])

    def test_incomplete_declarations_withhold_all_issue_projections(self) -> None:
        for field in ("policy_complete", "sessions_complete", "configured_vlans_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                document = self.report(model)
                self.assertEqual(document["summary"], {
                    "session_count": 2, "candidate_count": 0, "unknown_count": 2,
                })
                self.assertTrue(all(not row["issues"] for row in document["projections"]))

    def test_closed_model_rejects_live_identifiers_and_invalid_values(self) -> None:
        cases = []
        duplicate = copy.deepcopy(self.model)
        duplicate["sessions"][1]["session_id"] = "synthetic:accepted"
        cases.append(duplicate)
        bad_vlan = copy.deepcopy(self.model)
        bad_vlan["sessions"][0]["tunnel_private_group_vlan"] = 4095
        cases.append(bad_vlan)
        duplicate_vlan = copy.deepcopy(self.model)
        duplicate_vlan["configured_vlans"] = [20, 20]
        cases.append(duplicate_vlan)
        hidden = copy.deepcopy(self.model)
        hidden["sessions"][0]["radius_packet"] = "forbidden"
        cases.append(hidden)
        real = copy.deepcopy(self.model)
        real["sessions"][0]["port_id"] = "switch-port-1"
        cases.append(real)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(nac.NacAdmissionError):
                    nac.analyze_supplied_nac_admission(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = nac.analyze_supplied_nac_admission(self.model)
        changed = copy.deepcopy(self.model)
        changed["sessions"][1]["controlled_port_state"] = "unauthorized"
        with self.assertRaises(nac.NacAdmissionError):
            nac.verify_supplied_nac_admission(report, model=changed)
        with self.assertRaises(nac.NacAdmissionError):
            nac.verify_supplied_nac_admission_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(nac.NacAdmissionError):
            nac.NacAdmissionReport({})
        with self.assertRaises(nac.NacAdmissionError):
            nac.verify_supplied_nac_admission(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

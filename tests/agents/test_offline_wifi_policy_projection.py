"""Synthetic tests for caller-policy Wi-Fi declaration comparisons."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_wifi_policy_projection as wifi


class WifiPolicyProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = wifi.component_fixture()

    def report(self, model: dict) -> dict:
        return wifi.analyze_supplied_wifi_policy(model).to_dict()

    def test_declared_difference_is_source_bound_and_nonqualifying(self) -> None:
        original = copy.deepcopy(self.model)
        report = wifi.analyze_supplied_wifi_policy(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S08")
        self.assertEqual(
            document["summary"],
            {
                "network_count": 2,
                "candidate_count": 1,
                "unknown_count": 0,
            },
        )
        self.assertEqual(
            document["projections"][0]["disposition"], "consistent_under_declared_policy"
        )
        self.assertEqual(
            document["projections"][1]["issues"], ["guest_isolation_differs_from_policy"]
        )
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated",
            "radio_observed",
            "authentication_observed",
            "pmf_behavior_observed",
            "client_isolation_observed",
            "wireless_exposure_proven",
            "finding_claimed",
            "full_candidate_assembled",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            wifi.verify_supplied_wifi_policy(report, model=original).to_dict(), document
        )
        self.assertEqual(
            wifi.verify_supplied_wifi_policy_bytes(
                report.to_json().encode("ascii"),
                model=original,
            ).to_dict(),
            document,
        )

    def test_three_independent_caller_policy_differences(self) -> None:
        model = copy.deepcopy(self.model)
        model["networks"][0]["security_mode"] = "open"
        model["networks"][0]["pmf_state"] = "disabled"
        self.assertEqual(
            self.report(model)["projections"][0]["issues"],
            ["security_mode_differs_from_policy"],
        )
        model["networks"][0]["security_mode"] = "wpa3_personal"
        self.assertEqual(
            self.report(model)["projections"][0]["issues"],
            ["pmf_state_differs_from_policy"],
        )
        model["networks"][1]["client_isolation"] = True
        self.assertEqual(self.report(model)["projections"][1]["issues"], [])
        model["policy"]["pmf_required_modes"] = []
        self.assertEqual(self.report(model)["summary"]["candidate_count"], 0)

    def test_incomplete_declarations_withhold_all_issue_projections(self) -> None:
        for field in ("policy_complete", "networks_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                document = self.report(model)
                self.assertEqual(
                    document["summary"],
                    {
                        "network_count": 2,
                        "candidate_count": 0,
                        "unknown_count": 2,
                    },
                )
                self.assertTrue(all(not row["issues"] for row in document["projections"]))

    def test_closed_model_rejects_identifiers_secrets_and_undeclared_fields(self) -> None:
        cases = []
        duplicate = copy.deepcopy(self.model)
        duplicate["networks"][1]["network_id"] = "synthetic:staff"
        cases.append(duplicate)
        real_id = copy.deepcopy(self.model)
        real_id["networks"][0]["network_id"] = "actual-ssid"
        cases.append(real_id)
        secret = copy.deepcopy(self.model)
        secret["networks"][0]["passphrase"] = "forbidden"
        cases.append(secret)
        address = copy.deepcopy(self.model)
        address["networks"][0]["bssid"] = "00:11:22:33:44:55"
        cases.append(address)
        duplicate_mode = copy.deepcopy(self.model)
        duplicate_mode["policy"]["allowed_modes"].append("wpa3_personal")
        cases.append(duplicate_mode)
        inconsistent_policy = copy.deepcopy(self.model)
        inconsistent_policy["policy"]["pmf_required_modes"] = ["wpa2_personal"]
        cases.append(inconsistent_policy)
        invalid_pmf = copy.deepcopy(self.model)
        invalid_pmf["networks"][0]["pmf_state"] = "unknown"
        cases.append(invalid_pmf)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(wifi.WifiPolicyProjectionError):
                    wifi.analyze_supplied_wifi_policy(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = wifi.analyze_supplied_wifi_policy(self.model)
        changed = copy.deepcopy(self.model)
        changed["networks"][1]["client_isolation"] = True
        with self.assertRaises(wifi.WifiPolicyProjectionError):
            wifi.verify_supplied_wifi_policy(report, model=changed)
        with self.assertRaises(wifi.WifiPolicyProjectionError):
            wifi.verify_supplied_wifi_policy_bytes(
                report.to_json().encode("ascii"),
                model=changed,
            )
        with self.assertRaises(wifi.WifiPolicyProjectionError):
            wifi.WifiPolicyProjectionReport({})
        with self.assertRaises(wifi.WifiPolicyProjectionError):
            wifi.verify_supplied_wifi_policy(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

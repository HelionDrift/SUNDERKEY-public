"""Synthetic tests for supplied overlay route and policy declarations."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_sdwan_overlay_projection as sdwan


class SdwanOverlayProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = sdwan.component_fixture()

    def report(self, model: dict) -> dict:
        return sdwan.analyze_supplied_sdwan_overlay(model).to_dict()

    def test_route_and_policy_are_separate_nonqualifying_predicates(self) -> None:
        original = copy.deepcopy(self.model)
        report = sdwan.analyze_supplied_sdwan_overlay(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GC-D13-S21")
        self.assertEqual(
            document["summary"],
            {
                "query_count": 2,
                "candidate_count": 1,
                "unknown_count": 0,
            },
        )
        cross = document["projections"][0]
        self.assertFalse(cross["route_exists"])
        self.assertTrue(cross["policy_allows"])
        self.assertFalse(cross["projected_reachable"])
        self.assertEqual(cross["issues"], ["declared_reachability_differs_from_model"])
        central = document["projections"][1]
        self.assertTrue(central["route_exists"])
        self.assertFalse(central["policy_allows"])
        self.assertFalse(central["projected_reachable"])
        self.assertEqual(central["path_site_ids"], ["synthetic:west", "synthetic:central"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated",
            "overlay_state_observed",
            "policy_enforcement_observed",
            "packet_path_observed",
            "live_reachability_proven",
            "finding_claimed",
            "full_candidate_assembled",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            sdwan.verify_supplied_sdwan_overlay(report, model=original).to_dict(), document
        )
        self.assertEqual(
            sdwan.verify_supplied_sdwan_overlay_bytes(
                report.to_json().encode("ascii"),
                model=original,
            ).to_dict(),
            document,
        )

    def test_directed_path_requires_up_links_and_explicit_pair_policy(self) -> None:
        model = copy.deepcopy(self.model)
        model["links"][1]["up"] = True
        document = self.report(model)
        cross = document["projections"][0]
        self.assertEqual(
            cross["path_site_ids"],
            ["synthetic:west", "synthetic:central", "synthetic:east"],
        )
        self.assertTrue(cross["projected_reachable"])
        self.assertEqual(cross["issues"], [])
        model["links"].append(
            {
                "source_site_id": "synthetic:west",
                "target_site_id": "synthetic:east",
                "up": True,
            }
        )
        self.assertEqual(
            self.report(model)["projections"][0]["path_site_ids"],
            ["synthetic:west", "synthetic:east"],
        )
        model["allowed_pairs"] = []
        self.assertFalse(self.report(model)["projections"][0]["projected_reachable"])

    def test_incomplete_sources_withhold_route_and_policy_projections(self) -> None:
        for field in ("sites_complete", "links_complete", "policy_complete", "queries_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                document = self.report(model)
                self.assertEqual(
                    document["summary"],
                    {
                        "query_count": 2,
                        "candidate_count": 0,
                        "unknown_count": 2,
                    },
                )
                self.assertTrue(all(row["route_exists"] is None for row in document["projections"]))
                self.assertTrue(
                    all(row["policy_allows"] is None for row in document["projections"])
                )
                self.assertTrue(all(not row["issues"] for row in document["projections"]))

    def test_closed_model_rejects_duplicate_edges_live_addresses_and_secrets(self) -> None:
        cases = []
        duplicate_site = copy.deepcopy(self.model)
        duplicate_site["sites"].append({"site_id": "synthetic:west"})
        cases.append(duplicate_site)
        duplicate_link = copy.deepcopy(self.model)
        duplicate_link["links"].append(duplicate_link["links"][0])
        cases.append(duplicate_link)
        unknown_site = copy.deepcopy(self.model)
        unknown_site["links"][0]["target_site_id"] = "synthetic:missing"
        cases.append(unknown_site)
        self_route = copy.deepcopy(self.model)
        self_route["queries"][0]["target_site_id"] = "synthetic:west"
        cases.append(self_route)
        real_site = copy.deepcopy(self.model)
        real_site["sites"][0]["site_id"] = "west.example"
        cases.append(real_site)
        address = copy.deepcopy(self.model)
        address["links"][0]["endpoint"] = "192.0.2.1"
        cases.append(address)
        secret = copy.deepcopy(self.model)
        secret["tunnel_key"] = "forbidden"
        cases.append(secret)
        invalid_state = copy.deepcopy(self.model)
        invalid_state["links"][0]["up"] = 1
        cases.append(invalid_state)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(sdwan.SdwanOverlayProjectionError):
                    sdwan.analyze_supplied_sdwan_overlay(model)

    def test_changed_original_and_self_attestation_fail(self) -> None:
        report = sdwan.analyze_supplied_sdwan_overlay(self.model)
        changed = copy.deepcopy(self.model)
        changed["links"][1]["up"] = True
        with self.assertRaises(sdwan.SdwanOverlayProjectionError):
            sdwan.verify_supplied_sdwan_overlay(report, model=changed)
        with self.assertRaises(sdwan.SdwanOverlayProjectionError):
            sdwan.verify_supplied_sdwan_overlay_bytes(
                report.to_json().encode("ascii"),
                model=changed,
            )
        with self.assertRaises(sdwan.SdwanOverlayProjectionError):
            sdwan.SdwanOverlayProjectionReport({})
        with self.assertRaises(sdwan.SdwanOverlayProjectionError):
            sdwan.verify_supplied_sdwan_overlay(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

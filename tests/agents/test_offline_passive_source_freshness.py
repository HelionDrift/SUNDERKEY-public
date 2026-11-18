"""Original-source replay tests for synthetic passive claim freshness."""

from __future__ import annotations

import copy
import unittest

from sunderkey import offline_passive_source_freshness as passive


class PassiveSourceFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = passive.component_fixture()

    def report(self, model: dict) -> dict:
        return passive.analyze_supplied_passive_sources(model).to_dict()

    def test_fresh_conflict_and_stale_unknown_are_source_replayed(self) -> None:
        original = copy.deepcopy(self.model)
        report = passive.analyze_supplied_passive_sources(self.model)
        document = report.to_dict()
        self.assertEqual(self.model, original)
        self.assertEqual(document["profile_id"], "AOE-GA-D01-S01")
        self.assertEqual(document["summary"], {
            "asset_count": 2, "conflict_candidate_count": 1, "unknown_count": 1,
        })
        self.assertEqual(document["projections"][0]["disposition"],
                         "candidate_conflicting_supplied_claims")
        self.assertEqual(document["projections"][1]["disposition"],
                         "unknown_only_stale_claims")
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        for field in (
            "source_authenticated", "source_independence_proven",
            "wall_clock_freshness_verified", "asset_ownership_verified",
            "passive_collection_performed", "active_scan_performed", "finding_claimed",
            "full_candidate_assembled", "positive_use_approved", "qualification_claimed",
        ):
            self.assertFalse(document[field])
        self.assertEqual(
            passive.verify_supplied_passive_sources(report, model=original).to_dict(),
            document,
        )
        self.assertEqual(
            passive.verify_supplied_passive_sources_bytes(
                report.to_json().encode("ascii"), model=original,
            ).to_dict(),
            document,
        )

    def test_distinct_supplied_sources_do_not_prove_independence(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][1]["claim"] = "present"
        report = self.report(model)
        self.assertEqual(report["projections"][0]["disposition"],
                         "multiple_supplied_presence_sources")
        self.assertFalse(report["source_independence_proven"])

    def test_age_boundary_is_inclusive_without_wall_clock_claim(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"][0]["observed_tick"] = 80
        self.assertEqual(self.report(model)["projections"][0]["disposition"],
                         "candidate_conflicting_supplied_claims")
        model["observations"][0]["observed_tick"] = 79
        self.assertEqual(self.report(model)["projections"][0]["disposition"],
                         "supplied_absence_not_exclusion")

    def test_later_claim_from_same_source_supersedes_older_fresh_claim(self) -> None:
        model = copy.deepcopy(self.model)
        model["observations"].append({
            "observation_id": "synthetic:archive-update",
            "asset_id": "synthetic:asset-one",
            "source_ref": "synthetic:archive",
            "source_kind": "archive_index",
            "observed_tick": 96,
            "claim": "absent",
        })
        row = self.report(model)["projections"][0]
        self.assertEqual(row["disposition"], "supplied_absence_not_exclusion")
        self.assertEqual(row["superseded_fresh_observation_ids"], ["synthetic:present"])

    def test_incomplete_sources_or_policy_keep_unknown(self) -> None:
        for field in ("sources_complete", "policy_complete"):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                self.assertEqual(self.report(model)["summary"]["unknown_count"], 2)

    def test_closed_model_rejects_real_identifiers_and_future_claims(self) -> None:
        cases = []
        real = copy.deepcopy(self.model)
        real["observations"][0]["asset_id"] = "example.com"
        cases.append(real)
        url = copy.deepcopy(self.model)
        url["observations"][0]["url"] = "https://example.com"
        cases.append(url)
        future = copy.deepcopy(self.model)
        future["observations"][0]["observed_tick"] = 101
        cases.append(future)
        duplicate = copy.deepcopy(self.model)
        duplicate["observations"][1]["observation_id"] = "synthetic:present"
        cases.append(duplicate)
        bool_tick = copy.deepcopy(self.model)
        bool_tick["current_tick"] = True
        cases.append(bool_tick)
        for index, model in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(passive.PassiveSourceFreshnessError):
                    passive.analyze_supplied_passive_sources(model)

    def test_changed_source_and_self_attestation_are_rejected(self) -> None:
        report = passive.analyze_supplied_passive_sources(self.model)
        changed = copy.deepcopy(self.model)
        changed["observations"][1]["claim"] = "present"
        with self.assertRaises(passive.PassiveSourceFreshnessError):
            passive.verify_supplied_passive_sources(report, model=changed)
        with self.assertRaises(passive.PassiveSourceFreshnessError):
            passive.verify_supplied_passive_sources_bytes(
                report.to_json().encode("ascii"), model=changed,
            )
        with self.assertRaises(passive.PassiveSourceFreshnessError):
            passive.PassiveSourceFreshnessReport({})
        with self.assertRaises(passive.PassiveSourceFreshnessError):
            passive.verify_supplied_passive_sources(report.to_dict(), model=self.model)


if __name__ == "__main__":
    unittest.main()

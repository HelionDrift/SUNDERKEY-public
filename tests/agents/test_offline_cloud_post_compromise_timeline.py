"""Bounded supplied cloud artifact timeline and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_cloud_post_compromise_timeline import (
    CloudPostCompromiseTimelineError,
    analyze_supplied_cloud_post_compromise,
    component_fixture,
    verify_supplied_cloud_post_compromise,
    verify_supplied_cloud_post_compromise_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class CloudPostCompromiseTimelineTests(unittest.TestCase):
    def test_candidate_and_inert_fixture(self) -> None:
        model = component_fixture()
        example = json.loads(
            (ROOT / "examples/offline-cloud-post-compromise-timeline-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_cloud_post_compromise(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["artifact_projections"][0]["disposition"],
            "candidate_declared_unreviewed_artifact_appearance",
        )
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["compromise_inferred"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cloud_post_compromise(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_cloud_post_compromise_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_unknown(self) -> None:
        model = component_fixture()
        model["artifacts"][0]["approved_change"] = True
        self.assertEqual(
            analyze_supplied_cloud_post_compromise(model).to_dict()["candidate_count"], 0
        )
        model["artifacts"][0]["approved_change"] = False
        model["artifacts"][0]["context_complete"] = False
        body = analyze_supplied_cloud_post_compromise(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        model["artifacts"][0]["context_complete"] = True
        model["artifacts"][0]["baseline_present"] = True
        self.assertEqual(
            analyze_supplied_cloud_post_compromise(model).to_dict()["candidate_count"], 0
        )

    def test_malformed_and_replay_refusal(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cloud_post_compromise(model)
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["approved_change"] = True
        with self.assertRaises(CloudPostCompromiseTimelineError):
            verify_supplied_cloud_post_compromise(report, model=changed)
        with self.assertRaises(CloudPostCompromiseTimelineError):
            verify_supplied_cloud_post_compromise(report.to_dict(), model=model)
        with self.assertRaises(CloudPostCompromiseTimelineError):
            verify_supplied_cloud_post_compromise_bytes(b"{}", model=model)
        duplicate = copy.deepcopy(model)
        duplicate["artifacts"][1]["artifact_id"] = duplicate["artifacts"][0]["artifact_id"]
        with self.assertRaises(CloudPostCompromiseTimelineError):
            analyze_supplied_cloud_post_compromise(duplicate)
        with self.assertRaises(CloudPostCompromiseTimelineError):
            analyze_supplied_cloud_post_compromise({**model, "later_snapshot_id": "snapshot-one"})
        with self.assertRaises(ValueError):
            analyze_supplied_cloud_post_compromise({**model, "artifacts": []})


if __name__ == "__main__":
    unittest.main()

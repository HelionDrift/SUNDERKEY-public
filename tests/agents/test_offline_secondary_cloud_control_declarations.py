"""Bounded secondary-cloud declaration projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_secondary_cloud_control_declarations import (
    SecondaryCloudControlError,
    analyze_supplied_secondary_cloud_controls,
    component_fixture,
    verify_supplied_secondary_cloud_controls,
    verify_supplied_secondary_cloud_controls_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class SecondaryCloudControlTests(unittest.TestCase):
    def test_candidate_and_inert_fixture(self) -> None:
        model = component_fixture()
        example = json.loads(
            (
                ROOT / "examples/offline-secondary-cloud-control-declarations-component.json"
            ).read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_secondary_cloud_controls(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["control_projections"][0]["disposition"], "candidate_declared_control_gap"
        )
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_secondary_cloud_controls(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_secondary_cloud_controls_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_unknown(self) -> None:
        model = component_fixture()
        model["controls"][0]["observed_state"] = "enforced"
        self.assertEqual(
            analyze_supplied_secondary_cloud_controls(model).to_dict()["candidate_count"], 0
        )
        model["controls"][0]["observed_state"] = "unknown"
        body = analyze_supplied_secondary_cloud_controls(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        model["controls"][0]["observed_state"] = "not_enforced"
        model["controls"][0]["context_complete"] = False
        self.assertEqual(
            analyze_supplied_secondary_cloud_controls(model).to_dict()["unknown_count"], 1
        )

    def test_malformed_and_replay_refusal(self) -> None:
        model = component_fixture()
        report = analyze_supplied_secondary_cloud_controls(model)
        changed = copy.deepcopy(model)
        changed["controls"][0]["required"] = False
        with self.assertRaises(SecondaryCloudControlError):
            verify_supplied_secondary_cloud_controls(report, model=changed)
        with self.assertRaises(SecondaryCloudControlError):
            verify_supplied_secondary_cloud_controls(report.to_dict(), model=model)
        with self.assertRaises(SecondaryCloudControlError):
            verify_supplied_secondary_cloud_controls_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            analyze_supplied_secondary_cloud_controls({**model, "unexpected": True})
        duplicate = copy.deepcopy(model)
        duplicate["controls"][1]["control_id"] = duplicate["controls"][0]["control_id"]
        with self.assertRaises(SecondaryCloudControlError):
            analyze_supplied_secondary_cloud_controls(duplicate)
        with self.assertRaises(ValueError):
            analyze_supplied_secondary_cloud_controls({**model, "provider_family": "unsupported"})


if __name__ == "__main__":
    unittest.main()

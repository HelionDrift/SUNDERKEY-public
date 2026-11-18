"""Bounded controller configuration declaration and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_ot_controller_configuration import (
    OtControllerConfigurationError,
    analyze_supplied_ot_controller_configuration,
    component_fixture,
    verify_supplied_ot_controller_configuration,
    verify_supplied_ot_controller_configuration_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class OtControllerConfigurationTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_digest_difference(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-ot-controller-configuration-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        body = analyze_supplied_ot_controller_configuration(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(
            body["controller_projections"][0]["issues"],
            [
                "supplied_logic_digest_differs_from_baseline",
            ],
        )
        self.assertFalse(body["controller_contacted"])
        self.assertFalse(body["deployed_logic_verified"])
        self.assertFalse(body["process_safety_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        report = analyze_supplied_ot_controller_configuration(model)
        self.assertEqual(
            verify_supplied_ot_controller_configuration(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_ot_controller_configuration_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_missing_observations_fail_closed(self) -> None:
        model = component_fixture()
        model["controllers"][0]["project_logic_sha256"] = model["controllers"][0][
            "baseline_logic_sha256"
        ]
        self.assertEqual(
            analyze_supplied_ot_controller_configuration(model).to_dict()["candidate_count"], 0
        )
        model["controllers"][0]["project_logic_sha256"] = None
        body = analyze_supplied_ot_controller_configuration(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["controller_projections"][0]["issues"])
        model["controllers"][0]["project_logic_sha256"] = "sha256:" + "b" * 64
        model["controllers"][0]["context_complete"] = False
        self.assertEqual(
            analyze_supplied_ot_controller_configuration(model).to_dict()["candidate_count"], 0
        )
        model["controllers"][0]["context_complete"] = True
        model["inventory_complete"] = False
        body = analyze_supplied_ot_controller_configuration(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 2))

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        with self.assertRaises(ValueError):
            analyze_supplied_ot_controller_configuration(
                {**model, "controllers": tuple(model["controllers"])}
            )
        with self.assertRaises(ValueError):
            analyze_supplied_ot_controller_configuration({**model, "source_id": None})
        duplicate = copy.deepcopy(model)
        duplicate["controllers"][1]["controller_id"] = duplicate["controllers"][0]["controller_id"]
        with self.assertRaises(OtControllerConfigurationError):
            analyze_supplied_ot_controller_configuration(duplicate)
        malformed = copy.deepcopy(model)
        malformed["controllers"][0]["project_logic_sha256"] = "sha256:bad"
        with self.assertRaises(OtControllerConfigurationError):
            analyze_supplied_ot_controller_configuration(malformed)
        report = analyze_supplied_ot_controller_configuration(model)
        changed = copy.deepcopy(model)
        changed["controllers"][0]["project_logic_sha256"] = "sha256:" + "f" * 64
        with self.assertRaises(OtControllerConfigurationError):
            verify_supplied_ot_controller_configuration(report, model=changed)
        with self.assertRaises(OtControllerConfigurationError):
            verify_supplied_ot_controller_configuration(report.to_dict(), model=model)
        with self.assertRaises(OtControllerConfigurationError):
            verify_supplied_ot_controller_configuration_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_ot_controller_configuration_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()

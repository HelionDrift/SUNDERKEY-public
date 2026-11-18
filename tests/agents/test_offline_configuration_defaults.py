"""Caller-declared configuration conflict is not a verified weakness."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_configuration_defaults import (
    ConfigurationDefaults,
    ConfigurationDefaultsError,
    analyze_supplied_configuration_defaults,
    verify_supplied_configuration_defaults,
)

ROOT = Path(__file__).resolve().parents[2]


def request() -> dict:
    return json.loads(
        (ROOT / "examples/offline-configuration-defaults-component.json").read_text(
            encoding="utf-8"
        )
    )


class ConfigurationDefaultsTests(unittest.TestCase):
    def test_catalog_dispatch(self) -> None:
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request(), catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S13")
        self.assertEqual(result["analysis"]["projections"][0]["disposition"],
                         "candidate_declared_insecure_default")
        self.assertFalse(any(result["analysis"]["flags"].values()))

    def test_replay_and_precedence(self) -> None:
        model = request()["payload"]["model"]
        original = copy.deepcopy(model)
        report = analyze_supplied_configuration_defaults(model)
        self.assertEqual(model, original)
        self.assertEqual(report.to_dict()["source_model"], original)
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_configuration_defaults(report, model=model).to_json(),
            report.to_json(),
        )
        model["observations"][0]["layers"][1]["value"] = "enabled"
        model["observations"][0]["declared_effective_value"] = "enabled"
        row = analyze_supplied_configuration_defaults(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_required_value_consistent")
        self.assertEqual(row["effective_origin"], "service")
        model["observations"][0]["required_value"] = "disabled"
        row = analyze_supplied_configuration_defaults(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "candidate_declared_insecure_override")

    def test_unresolved_cases_withhold_candidate(self) -> None:
        model = request()["payload"]["model"]
        model["policy"]["declaration_complete"] = False
        row = analyze_supplied_configuration_defaults(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        model["policy"]["declaration_complete"] = True
        model["observations"][0]["default_value"] = "unknown"
        row = analyze_supplied_configuration_defaults(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_effective_value")
        model["observations"][0]["default_value"] = "disabled"
        model["observations"][0]["declared_effective_value"] = "enabled"
        row = analyze_supplied_configuration_defaults(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_effective_value_mismatch")

    def test_invalid_and_tampered_reports_are_refused(self) -> None:
        model = request()["payload"]["model"]
        cases = []
        item = copy.deepcopy(model)
        item["observations"][0]["layers"][0]["value"] = "launch"
        cases.append(item)
        item = copy.deepcopy(model)
        item["observations"][0]["layers"].append(item["observations"][0]["layers"][0])
        cases.append(item)
        item = copy.deepcopy(model)
        item["observations"][0]["layers"] = item["observations"][0]["layers"] * 5
        cases.append(item)
        item = copy.deepcopy(model)
        item["resource"] = "file"
        cases.append(item)
        item = copy.deepcopy(model)
        item["cycle"] = item
        cases.append(item)
        for item in cases:
            with self.assertRaises(ConfigurationDefaultsError):
                analyze_supplied_configuration_defaults(item)
        report = analyze_supplied_configuration_defaults(model)
        changed = report.to_dict()
        changed["flags"]["configuration_verified"] = True
        with self.assertRaises(ConfigurationDefaultsError):
            ConfigurationDefaults(changed)
        alternate = copy.deepcopy(model)
        alternate["observations"][0]["default_value"] = "enabled"
        with self.assertRaises(ConfigurationDefaultsError):
            verify_supplied_configuration_defaults(report, model=alternate)
        with self.assertRaises(ConfigurationDefaultsError):
            verify_supplied_configuration_defaults(report.to_dict(), model=model)


if __name__ == "__main__":
    unittest.main()

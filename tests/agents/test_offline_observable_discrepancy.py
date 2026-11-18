"""A supplied restricted observation does not verify information disclosure."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_observable_discrepancy import (
    ObservableDiscrepancy,
    ObservableDiscrepancyError,
    analyze_supplied_observable_discrepancy,
    verify_supplied_observable_discrepancy,
)

ROOT = Path(__file__).resolve().parents[2]


def request() -> dict:
    return json.loads(
        (ROOT / "examples/offline-observable-discrepancy-component.json").read_text(
            encoding="utf-8"
        )
    )


class ObservableDiscrepancyTests(unittest.TestCase):
    def test_catalog_dispatch_and_separate_source_replay(self) -> None:
        source = request()
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            source, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S16")
        self.assertEqual(result["analysis"]["projections"][0]["disposition"],
                         "candidate_declared_sensitive_field_exposure")
        model = source["payload"]["model"]
        report = analyze_supplied_observable_discrepancy(model)
        self.assertEqual(report.to_dict()["source_model"], model)
        self.assertFalse(any(report.to_dict()["flags"].values()))
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_observable_discrepancy(report, model=model).to_json(),
            report.to_json(),
        )

    def test_non_sensitive_extra_and_incomplete_capture(self) -> None:
        model = request()["payload"]["model"]
        model["policy"]["sensitive_field_refs"] = []
        row = analyze_supplied_observable_discrepancy(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"],
                         "declared_observable_discrepancy_without_sensitive_marker")
        model["comparisons"][0]["observed_restricted_field_refs"] = ["ref:field-public"]
        row = analyze_supplied_observable_discrepancy(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_restricted_fields_consistent")
        model["comparisons"][0]["capture_complete"] = False
        row = analyze_supplied_observable_discrepancy(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")

    def test_invalid_source_and_report_tamper(self) -> None:
        model = request()["payload"]["model"]
        cases = []
        item = copy.deepcopy(model)
        item["comparisons"][0]["resource_ref"] = "https://example.test"
        cases.append(item)
        item = copy.deepcopy(model)
        item["comparisons"][0]["observed_restricted_field_refs"].append(
            "ref:field-public"
        )
        cases.append(item)
        item = copy.deepcopy(model)
        item["comparisons"].append(copy.deepcopy(item["comparisons"][0]))
        cases.append(item)
        item = copy.deepcopy(model)
        item["response_text"] = "secret"
        cases.append(item)
        for item in cases:
            with self.assertRaises(ObservableDiscrepancyError):
                analyze_supplied_observable_discrepancy(item)
        report = analyze_supplied_observable_discrepancy(model)
        changed = report.to_dict()
        changed["flags"]["information_disclosure_verified"] = True
        with self.assertRaises(ObservableDiscrepancyError):
            ObservableDiscrepancy(changed)
        alternate = copy.deepcopy(model)
        alternate["comparisons"][0]["capture_complete"] = False
        with self.assertRaises(ObservableDiscrepancyError):
            verify_supplied_observable_discrepancy(report, model=alternate)


if __name__ == "__main__":
    unittest.main()

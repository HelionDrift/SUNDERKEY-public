"""Declared expansion arithmetic does not generate workload or prove impact."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_resource_expansion_budget import (
    ResourceExpansionBudget,
    ResourceExpansionBudgetError,
    analyze_supplied_resource_expansion_budget,
    verify_supplied_resource_expansion_budget,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return json.loads(
        (ROOT / "examples/offline-resource-expansion-budget-component.json").read_text(
            encoding="utf-8"
        )
    )["payload"]["model"]


class ResourceExpansionBudgetTests(unittest.TestCase):
    def test_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-resource-expansion-budget-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S11")
        self.assertEqual(
            result["component"]["component_id"], "supplied_resource_expansion_budget"
        )
        self.assertEqual(
            result["analysis"]["projections"][0]["disposition"],
            "candidate_declared_resource_budget_conflict",
        )
        self.assertFalse(result["analysis"]["flags"]["resource_exhaustion_verified"])

    def test_source_replay_and_saturating_arithmetic(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_resource_expansion_budget(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["operation_count"], 1)
        row = body["projections"][0]
        self.assertEqual(row["projected_work_units"], 80)
        self.assertFalse(row["projection_saturated"])
        self.assertEqual(row["negative_predicate"], "declared_capacity_exceeded")
        self.assertFalse(any(body["flags"].values()))
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_resource_expansion_budget(report, model=source).to_json(),
            report.to_json(),
        )
        source["operations"][0].update(input_units=1_000_000, fanout=32, depth=32)
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["projected_work_units"], 1_000_000_001)
        self.assertTrue(row["projection_saturated"])

    def test_incomplete_or_unknown_premises_withhold_conflict(self) -> None:
        source = model()
        source["policy"]["declaration_complete"] = False
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["policy"]["declaration_complete"] = True
        source["operations"][0]["capture_complete"] = False
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["operations"][0]["capture_complete"] = True
        source["operations"][0]["declared_outcome"] = "unknown"
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_outcome")
        source["operations"][0]["declared_outcome"] = "rejected"
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_reject_consistent")
        source["policy"]["reject_over_capacity"] = False
        row = analyze_supplied_resource_expansion_budget(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_negative_invariant")

    def test_invalid_or_resource_bearing_sources_are_refused(self) -> None:
        cases = []
        source = model()
        source["operations"][0]["fanout"] = 33
        cases.append(source)
        source = model()
        source["operations"][0]["depth"] = -1
        cases.append(source)
        source = model()
        source["operations"][0]["input_units"] = 1.5
        cases.append(source)
        source = model()
        source["operations"].append(copy.deepcopy(source["operations"][0]))
        cases.append(source)
        source = model()
        source["network_permission"] = True
        cases.append(source)
        source = model()
        source["cycle"] = source
        cases.append(source)
        source = model()
        source["operations"] = source["operations"] * 129
        cases.append(source)
        for item in cases:
            with self.assertRaises(ResourceExpansionBudgetError):
                analyze_supplied_resource_expansion_budget(item)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_resource_expansion_budget(source)
        changed = report.to_dict()
        changed["flags"]["workload_generated"] = True
        with self.assertRaises(ResourceExpansionBudgetError):
            ResourceExpansionBudget(changed)
        alternate = model()
        alternate["operations"][0]["declared_outcome"] = "rejected"
        with self.assertRaises(ResourceExpansionBudgetError):
            verify_supplied_resource_expansion_budget(report, model=alternate)
        with self.assertRaises(ResourceExpansionBudgetError):
            verify_supplied_resource_expansion_budget(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

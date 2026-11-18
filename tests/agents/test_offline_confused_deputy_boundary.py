"""Declared deputy authority does not verify a live boundary crossing."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_confused_deputy_boundary import (
    ConfusedDeputyBoundary,
    ConfusedDeputyBoundaryError,
    analyze_supplied_confused_deputy_boundary,
    verify_supplied_confused_deputy_boundary,
)

ROOT = Path(__file__).resolve().parents[2]


def request() -> dict:
    return json.loads(
        (ROOT / "examples/offline-confused-deputy-boundary-component.json").read_text(
            encoding="utf-8"
        )
    )


class ConfusedDeputyBoundaryTests(unittest.TestCase):
    def test_catalog_dispatch_and_replay(self) -> None:
        source = request()
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            source, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S14")
        self.assertEqual(result["analysis"]["projections"][0]["disposition"],
                         "candidate_declared_deputy_boundary_conflict")
        self.assertFalse(any(result["analysis"]["flags"].values()))
        model = source["payload"]["model"]
        report = analyze_supplied_confused_deputy_boundary(model)
        self.assertEqual(report.to_dict()["source_model"], model)
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_confused_deputy_boundary(report, model=model).to_json(),
            report.to_json(),
        )

    def test_negative_predicate_and_unresolved_cases(self) -> None:
        model = request()["payload"]["model"]
        model["operations"][0]["declared_result"] = "deny"
        row = analyze_supplied_confused_deputy_boundary(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_requester_boundary_consistent")
        model["operations"][0]["requester_authority"] = "unknown"
        row = analyze_supplied_confused_deputy_boundary(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_authority_or_result")
        model["operations"][0]["requester_authority"] = "allow"
        row = analyze_supplied_confused_deputy_boundary(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_deputy_boundary_conflict")
        model["policy"]["declaration_complete"] = False
        row = analyze_supplied_confused_deputy_boundary(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")

    def test_invalid_sources_and_alternate_replay(self) -> None:
        model = request()["payload"]["model"]
        cases = []
        item = copy.deepcopy(model)
        item["operations"][0]["requester_ref"] = "real-credential"
        cases.append(item)
        item = copy.deepcopy(model)
        item["operations"][0]["deputy_ref"] = item["operations"][0]["requester_ref"]
        cases.append(item)
        item = copy.deepcopy(model)
        item["operations"][0]["declared_result"] = "execute"
        cases.append(item)
        item = copy.deepcopy(model)
        item["operations"].append(copy.deepcopy(item["operations"][0]))
        cases.append(item)
        item = copy.deepcopy(model)
        item["network"] = True
        cases.append(item)
        for item in cases:
            with self.assertRaises(ConfusedDeputyBoundaryError):
                analyze_supplied_confused_deputy_boundary(item)
        report = analyze_supplied_confused_deputy_boundary(model)
        changed = report.to_dict()
        changed["flags"]["boundary_crossing_verified"] = True
        with self.assertRaises(ConfusedDeputyBoundaryError):
            ConfusedDeputyBoundary(changed)
        alternate = copy.deepcopy(model)
        alternate["operations"][0]["declared_result"] = "deny"
        with self.assertRaises(ConfusedDeputyBoundaryError):
            verify_supplied_confused_deputy_boundary(report, model=alternate)


if __name__ == "__main__":
    unittest.main()

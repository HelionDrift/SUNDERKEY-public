"""Declared interpreter source is not verified command or code execution."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_interpreter_input_boundary import (
    InterpreterInputBoundary,
    InterpreterInputBoundaryError,
    analyze_supplied_interpreter_input_boundary,
    verify_supplied_interpreter_input_boundary,
)

ROOT = Path(__file__).resolve().parents[2]


def request() -> dict:
    return json.loads(
        (ROOT / "examples/offline-interpreter-input-boundary-component.json").read_text(
            encoding="utf-8"
        )
    )


class InterpreterInputBoundaryTests(unittest.TestCase):
    def test_catalog_dispatch_and_separate_source_replay(self) -> None:
        source = request()
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            source, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S02")
        self.assertEqual(result["analysis"]["projections"][0]["disposition"],
                         "candidate_declared_interpreter_input_boundary_conflict")
        model = source["payload"]["model"]
        report = analyze_supplied_interpreter_input_boundary(model)
        self.assertEqual(report.to_dict()["source_model"], model)
        self.assertFalse(any(report.to_dict()["flags"].values()))
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_interpreter_input_boundary(report, model=model).to_json(),
            report.to_json(),
        )

    def test_data_only_unknown_and_uninvoked_paths(self) -> None:
        model = request()["payload"]["model"]
        row = model["sinks"][0]
        row["inputs"][0]["incorporation"] = "data_only"
        result = analyze_supplied_interpreter_input_boundary(model).to_dict()[
            "projections"
        ][0]
        self.assertEqual(result["disposition"], "no_declared_interpreted_untrusted_input")
        row["inputs"][0]["incorporation"] = "unknown"
        result = analyze_supplied_interpreter_input_boundary(model).to_dict()[
            "projections"
        ][0]
        self.assertEqual(result["disposition"], "unresolved_input_trust_or_incorporation")
        row["inputs"][0]["incorporation"] = "interpreter_source"
        row["invocation_declared"] = False
        result = analyze_supplied_interpreter_input_boundary(model).to_dict()[
            "projections"
        ][0]
        self.assertEqual(result["disposition"],
                         "declared_uninvoked_interpreter_construction_conflict")

    def test_invalid_source_and_report_tamper(self) -> None:
        model = request()["payload"]["model"]
        cases = []
        item = copy.deepcopy(model)
        item["sinks"][0]["inputs"][0]["input_ref"] = "C:\\Windows"
        cases.append(item)
        item = copy.deepcopy(model)
        item["sinks"][0]["sink_family"] = "browser"
        cases.append(item)
        item = copy.deepcopy(model)
        item["sinks"].append(copy.deepcopy(item["sinks"][0]))
        cases.append(item)
        item = copy.deepcopy(model)
        item["payload_text"] = "code"
        cases.append(item)
        for item in cases:
            with self.assertRaises(InterpreterInputBoundaryError):
                analyze_supplied_interpreter_input_boundary(item)
        report = analyze_supplied_interpreter_input_boundary(model)
        changed = report.to_dict()
        changed["flags"]["injection_verified"] = True
        with self.assertRaises(InterpreterInputBoundaryError):
            InterpreterInputBoundary(changed)
        alternate = copy.deepcopy(model)
        alternate["sinks"][0]["invocation_declared"] = False
        with self.assertRaises(InterpreterInputBoundaryError):
            verify_supplied_interpreter_input_boundary(report, model=alternate)


if __name__ == "__main__":
    unittest.main()

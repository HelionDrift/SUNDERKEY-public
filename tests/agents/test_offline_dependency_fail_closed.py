"""A declared fallback conflict does not verify a live fail-open path."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_dependency_fail_closed import (
    DependencyFailClosed,
    DependencyFailClosedError,
    analyze_supplied_dependency_fail_closed,
    verify_supplied_dependency_fail_closed,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return json.loads(
        (ROOT / "examples/offline-dependency-fail-closed-component.json").read_text(
            encoding="utf-8"
        )
    )["payload"]["model"]


class DependencyFailClosedTests(unittest.TestCase):
    def test_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-dependency-fail-closed-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S12")
        self.assertEqual(
            result["component"]["component_id"], "supplied_dependency_fail_closed"
        )
        self.assertEqual(
            result["analysis"]["projections"][0]["disposition"],
            "candidate_declared_fail_open_conflict",
        )
        self.assertFalse(result["analysis"]["flags"]["fail_open_behavior_verified"])

    def test_source_replay_and_declared_conflict(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_dependency_fail_closed(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["observation_count"], 1)
        self.assertEqual(
            body["projections"][0]["negative_predicate"],
            "dependency_failure_requires_deny",
        )
        self.assertFalse(any(body["flags"].values()))
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_dependency_fail_closed(report, model=source).to_json(),
            report.to_json(),
        )

    def test_unknown_mismatch_and_consistent_deny(self) -> None:
        source = model()
        source["policy"]["declaration_complete"] = False
        row = analyze_supplied_dependency_fail_closed(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["policy"]["declaration_complete"] = True
        source["observations"][0]["dependency_state"] = "unknown"
        row = analyze_supplied_dependency_fail_closed(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_decision_or_dependency")
        source["observations"][0]["dependency_state"] = "failed"
        source["observations"][0]["configured_fallback"] = "deny"
        row = analyze_supplied_dependency_fail_closed(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_fallback_outcome_mismatch")
        source["observations"][0]["declared_outcome"] = "deny"
        row = analyze_supplied_dependency_fail_closed(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_deny_consistent")
        source["policy"]["deny_on_dependency_failure"] = False
        row = analyze_supplied_dependency_fail_closed(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_negative_invariant")

    def test_invalid_or_resource_bearing_sources_are_refused(self) -> None:
        cases = []
        source = model()
        source["observations"][0]["dependency_ref"] = "actual-secret"
        cases.append(source)
        source = model()
        source["observations"][0]["declared_outcome"] = "bypass"
        cases.append(source)
        source = model()
        source["observations"].append(copy.deepcopy(source["observations"][0]))
        cases.append(source)
        source = model()
        source["network_permission"] = True
        cases.append(source)
        source = model()
        source["cycle"] = source
        cases.append(source)
        source = model()
        source["observations"] = source["observations"] * 129
        cases.append(source)
        for item in cases:
            with self.assertRaises(DependencyFailClosedError):
                analyze_supplied_dependency_fail_closed(item)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_dependency_fail_closed(source)
        changed = report.to_dict()
        changed["flags"]["fail_open_behavior_verified"] = True
        with self.assertRaises(DependencyFailClosedError):
            DependencyFailClosed(changed)
        alternate = model()
        alternate["observations"][0]["declared_outcome"] = "deny"
        with self.assertRaises(DependencyFailClosedError):
            verify_supplied_dependency_fail_closed(report, model=alternate)
        with self.assertRaises(DependencyFailClosedError):
            verify_supplied_dependency_fail_closed(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

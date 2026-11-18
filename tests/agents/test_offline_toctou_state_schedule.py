"""A supplied check-use schedule does not verify a race or target behavior."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_toctou_state_schedule import (
    ToctouStateSchedule,
    ToctouStateScheduleError,
    analyze_supplied_toctou_state_schedule,
    verify_supplied_toctou_state_schedule,
)

ROOT = Path(__file__).resolve().parents[2]


def model() -> dict:
    return json.loads(
        (ROOT / "examples/offline-toctou-state-schedule-component.json").read_text(
            encoding="utf-8"
        )
    )["payload"]["model"]


class ToctouStateScheduleTests(unittest.TestCase):
    def test_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-toctou-state-schedule-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S10")
        self.assertEqual(
            result["component"]["component_id"], "supplied_toctou_state_schedule"
        )
        self.assertEqual(
            result["analysis"]["projections"][0]["disposition"],
            "candidate_declared_stale_check_conflict",
        )
        self.assertFalse(result["analysis"]["flags"]["toctou_exploitation_verified"])

    def test_source_replay_and_intervening_mutation(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_toctou_state_schedule(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["use_count"], 1)
        self.assertEqual(body["projections"][0]["checked_version"], 1)
        self.assertEqual(body["projections"][0]["current_version"], 2)
        self.assertEqual(body["projections"][0]["intervening_mutation_count"], 1)
        self.assertEqual(body["projections"][0]["negative_predicate"], "stale_check_used")
        self.assertFalse(any(body["flags"].values()))
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_toctou_state_schedule(report, model=source).to_json(),
            report.to_json(),
        )

    def test_missing_or_contradictory_premises_withhold_conflict(self) -> None:
        source = model()
        source["schedule_complete"] = False
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["schedule_complete"] = True
        source["events"][2]["capture_complete"] = False
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_declaration_or_capture")
        source["events"][2]["capture_complete"] = True
        source["events"][0]["version"] = 0
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_check_version_mismatch")
        source["events"][0]["version"] = 1
        source["events"][2]["declared_outcome"] = "unknown"
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_outcome")
        source["events"][2]["declared_outcome"] = "rejected"
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_reject_consistent")
        source["policy"]["reject_stale_check"] = False
        row = analyze_supplied_toctou_state_schedule(source).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_negative_invariant")

    def test_invalid_schedule_and_resource_bearing_sources_are_refused(self) -> None:
        cases = []
        source = model()
        source["events"][2]["check_event_id"] = "missing"
        cases.append(source)
        source = model()
        source["events"][2]["actor_ref"] = "ref:other"
        cases.append(source)
        source = model()
        source["events"][1]["version"] = 1
        cases.append(source)
        source = model()
        source["events"][1]["version"] = 1.5
        cases.append(source)
        source = model()
        source["initial_versions"].append(copy.deepcopy(source["initial_versions"][0]))
        cases.append(source)
        source = model()
        source["network_permission"] = True
        cases.append(source)
        source = model()
        source["cycle"] = source
        cases.append(source)
        source = model()
        source["events"] = source["events"] * 43
        cases.append(source)
        for item in cases:
            with self.assertRaises(ToctouStateScheduleError):
                analyze_supplied_toctou_state_schedule(item)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_toctou_state_schedule(source)
        changed = report.to_dict()
        changed["flags"]["toctou_exploitation_verified"] = True
        with self.assertRaises(ToctouStateScheduleError):
            ToctouStateSchedule(changed)
        alternate = model()
        alternate["events"][2]["declared_outcome"] = "rejected"
        with self.assertRaises(ToctouStateScheduleError):
            verify_supplied_toctou_state_schedule(report, model=alternate)
        with self.assertRaises(ToctouStateScheduleError):
            verify_supplied_toctou_state_schedule(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

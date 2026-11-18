"""Phase 118 capability roadmap coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.capability_roadmap import (
    CapabilityRoadmap,
    assess_capability_roadmap,
    load_capability_roadmap,
)
from sunderkey.errors import SunderkeyError

ROOT = Path(__file__).resolve().parents[2]
ROADMAP_PATH = ROOT / "registry" / "capability-roadmap-v1.json"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "capability-roadmap-v1.schema.json"


class CapabilityRoadmapPhase118Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.roadmap = load_capability_roadmap(ROADMAP_PATH)

    def test_checked_roadmap_is_content_addressed_and_complete(self) -> None:
        self.assertEqual(
            self.roadmap.roadmap_id,
            "CRD-0782CFF2C4FDEE30B742869694C08C9D",
        )
        self.assertEqual(len(self.roadmap.increments), 9)
        self.assertEqual(len(self.roadmap.packages), 83)
        self.assertEqual(
            tuple(increment.gate.gate_id for increment in self.roadmap.increments),
            tuple(f"G{index}" for index in range(9)),
        )
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.roadmap.to_dict())

    def test_initial_projection_has_one_ready_package(self) -> None:
        report = assess_capability_roadmap(self.roadmap)
        self.assertEqual(
            report["package_counts"],
            {
                "total": 83,
                "completed": 0,
                "ready": 1,
                "blocked_by_dependencies": 82,
            },
        )
        states = {
            item["package_id"]: item["state"]
            for item in report["package_states"]
        }
        self.assertEqual(states["R0.1"], "ready")
        self.assertEqual(states["R0.2"], "blocked_by_dependencies")

    def test_completion_projection_advances_dependencies_and_gate(self) -> None:
        partial = assess_capability_roadmap(self.roadmap, ["R0.1"])
        states = {
            item["package_id"]: item["state"]
            for item in partial["package_states"]
        }
        self.assertEqual(states["R0.1"], "completed")
        self.assertEqual(states["R0.2"], "ready")

        complete = assess_capability_roadmap(
            self.roadmap,
            [f"R0.{index}" for index in range(1, 7)],
        )
        self.assertEqual(complete["gates"][0]["state"], "ready_for_evidence_review")
        self.assertEqual(complete["package_states"][6]["state"], "ready")

    def test_unknown_and_duplicate_completion_claims_fail_closed(self) -> None:
        with self.assertRaisesRegex(SunderkeyError, "unknown"):
            assess_capability_roadmap(self.roadmap, ["X9.9"])
        with self.assertRaisesRegex(SunderkeyError, "duplicates"):
            assess_capability_roadmap(self.roadmap, ["R0.1", "R0.1"])

    def test_tampering_and_forward_dependencies_fail_closed(self) -> None:
        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["increments"][0]["objective"] = "changed"
        with self.assertRaisesRegex(SunderkeyError, "identity does not match"):
            CapabilityRoadmap.from_dict(changed)

        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["increments"][0]["packages"][0]["dependency_package_ids"] = [
            "R0.2"
        ]
        with self.assertRaisesRegex(SunderkeyError, "forward dependencies"):
            CapabilityRoadmap.from_dict(changed)


if __name__ == "__main__":
    unittest.main()

"""Army v2 technical expansion roadmap coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_army_expansion_roadmap import roadmap_body
from sunderkey.army_expansion import (
    ArmyExpansionRoadmap,
    build_army_expansion_roadmap,
    load_army_expansion_roadmap,
)
from sunderkey.errors import SunderkeyError

ROOT = Path(__file__).resolve().parents[2]
ROADMAP_PATH = ROOT / "registry" / "army-expansion-roadmap-v1.json"
SCHEMA_PATH = ROOT / "registry" / "schemas" / "army-expansion-roadmap-v1.schema.json"


class ArmyExpansionRoadmapPhase150Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)

    def test_checked_roadmap_matches_deterministic_builder(self) -> None:
        expected = build_army_expansion_roadmap(roadmap_body())
        self.assertEqual(self.roadmap, expected)
        self.assertEqual(
            ROADMAP_PATH.read_text(encoding="utf-8"),
            json.dumps(expected.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )

    def test_reference_counts_and_group_targets_are_exact(self) -> None:
        self.assertEqual(
            self.roadmap.baseline_counts,
            {
                "groups": 5,
                "commands": 23,
                "specialists": 348,
                "domain_commanders": 23,
                "shared_profiles": 32,
                "total_profiles": 403,
                "pilot_specialists": 20,
            },
        )
        self.assertEqual(self.roadmap.target_counts["specialists"], 391)
        self.assertEqual(self.roadmap.target_counts["total_profiles"], 451)
        self.assertEqual(self.roadmap.delta_counts["specialists"], 43)
        self.assertEqual(self.roadmap.delta_counts["total_profiles"], 48)
        targets = {
            item["group_id"]: item["target_specialists"]
            for item in self.roadmap.to_dict()["group_targets"]
        }
        self.assertEqual(targets, {"GA": 59, "GB": 90, "GC": 114, "GD": 78, "GE": 50})

    def test_all_reference_profiles_are_unique_and_complete(self) -> None:
        specialist_ids = [
            specialist["profile_id"]
            for command in (
                *self.roadmap.existing_command_additions,
                *self.roadmap.new_commands,
            )
            for specialist in command["specialists"]
        ]
        self.assertEqual(len(specialist_ids), 43)
        self.assertEqual(len(set(specialist_ids)), 43)
        self.assertIn("AOE-GD-D24-S06", specialist_ids)
        self.assertIn("AOE-GD-D25-S12", specialist_ids)
        self.assertEqual(
            tuple(command["command_id"] for command in self.roadmap.new_commands),
            ("AOE-GD-D24", "AOE-GD-D25"),
        )
        self.assertEqual(
            tuple(item["profile_id"] for item in self.roadmap.shared_profile_additions),
            ("AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"),
        )

    def test_migration_is_parallel_and_has_no_operational_effect(self) -> None:
        document = self.roadmap.to_dict()
        self.assertEqual(document["migration"]["strategy"], "parallel_versioned_migration")
        self.assertEqual(
            document["migration"]["stable_id_policy"],
            "preserve_all_v1_profile_ids",
        )
        self.assertNotIn("decision", document)
        self.assertTrue(
            all(
                phase["operational_effect"] == "none_without_separate_authority"
                for phase in document["phases"]
            )
        )

    def test_phase_dependencies_are_complete_and_ordered(self) -> None:
        self.assertEqual(
            tuple(phase["phase_id"] for phase in self.roadmap.phases),
            tuple(f"Phase{number}" for number in range(150, 162)),
        )
        self.assertEqual(self.roadmap.phases[0]["dependency_phase_ids"], ())
        self.assertEqual(self.roadmap.phases[-1]["dependency_phase_ids"], ("Phase160",))

    def test_schema_accepts_checked_roadmap(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
            self.roadmap.to_dict()
        )

    def test_tampering_unknown_fields_and_forward_dependencies_fail_closed(self) -> None:
        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["counts"]["target"]["specialists"] = 392
        with self.assertRaisesRegex(SunderkeyError, "versioned reference baseline"):
            ArmyExpansionRoadmap.from_dict(changed)

        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["unexpected"] = True
        with self.assertRaises(SunderkeyError):
            ArmyExpansionRoadmap.from_dict(changed)

        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["phases"][0]["dependency_phase_ids"] = ["Phase151"]
        with self.assertRaisesRegex(SunderkeyError, "forward dependencies"):
            ArmyExpansionRoadmap.from_dict(changed)

        changed = copy.deepcopy(self.roadmap.to_dict())
        changed["limitations"][0] = "Changed limitation"
        with self.assertRaisesRegex(SunderkeyError, "identity does not match"):
            ArmyExpansionRoadmap.from_dict(changed)


if __name__ == "__main__":
    unittest.main()

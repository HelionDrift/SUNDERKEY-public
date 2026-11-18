"""Phase 151 additive Army v2 registry coverage."""

from __future__ import annotations

import copy
import json
import unittest
from collections import Counter
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_army_registry_v2 import build_registry, build_schema, load_json
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.army_registry_v2 import validate_army_v2_migration
from sunderkey.errors import RegistryError
from sunderkey.registry import ExpertRegistry, load_registry
from sunderkey.types import ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
BASELINE_PATH = REGISTRY / "army-v1.json"
TARGET_PATH = REGISTRY / "army-v2.json"
ROADMAP_PATH = REGISTRY / "army-expansion-roadmap-v1.json"
SCHEMA_SOURCE_PATH = REGISTRY / "schemas" / "registry.schema.json"
SCHEMA_PATH = REGISTRY / "schemas" / "registry-v2.schema.json"


class ArmyRegistryV2Phase151Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline = load_registry(BASELINE_PATH)
        cls.target = load_registry(TARGET_PATH)
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)
        cls.report = validate_army_v2_migration(
            cls.baseline,
            cls.target,
            cls.roadmap,
        )

    def test_checked_registry_and_schema_match_deterministic_builder(self) -> None:
        expected_registry = ExpertRegistry.from_dict(
            build_registry(
                load_json(BASELINE_PATH),
                self.roadmap.to_dict(),
            )
        ).to_dict()
        self.assertEqual(
            TARGET_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_registry, ensure_ascii=True, indent=2) + "\n",
        )
        expected_schema = build_schema(load_json(SCHEMA_SOURCE_PATH))
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_schema, ensure_ascii=True, indent=2) + "\n",
        )

    def test_target_counts_and_hierarchy_match_d015(self) -> None:
        counts = Counter(profile.kind for profile in self.target.profiles)
        self.assertEqual(len(self.target.groups), 5)
        self.assertEqual(len(self.target.commands), 25)
        self.assertEqual(counts[ProfileKind.SPECIALIST], 391)
        self.assertEqual(counts[ProfileKind.DOMAIN_COMMANDER], 25)
        self.assertEqual(counts[ProfileKind.SHARED], 35)
        self.assertEqual(len(self.target.profiles), 451)
        self.assertEqual(sum(profile.pilot for profile in self.target.profiles), 20)
        self.assertEqual(
            {group.id: group.specialist_count for group in self.target.groups},
            {"GA": 59, "GB": 90, "GC": 114, "GD": 78, "GE": 50},
        )

    def test_v1_profiles_are_preserved_byte_for_byte_as_catalog_records(self) -> None:
        baseline_profiles = self.baseline.to_dict()["profiles"]
        target_profiles = self.target.to_dict()["profiles"]
        self.assertEqual(target_profiles[:403], baseline_profiles)
        self.assertEqual(
            {item["id"] for item in target_profiles[:403]},
            {item["id"] for item in baseline_profiles},
        )

    def test_all_additions_are_defined_inactive_and_unqualified(self) -> None:
        additions = self.target.to_dict()["profiles"][403:]
        self.assertEqual(len(additions), 48)
        for profile in additions:
            with self.subTest(profile=profile["id"]):
                self.assertEqual(profile["status"], "defined")
                self.assertFalse(profile["pilot"])
                self.assertNotIn("qualification", profile)

        self.assertEqual(
            {item["id"] for item in additions if item["kind"] == "specialist"},
            {
                profile["profile_id"]
                for command in (
                    *self.roadmap.existing_command_additions,
                    *self.roadmap.new_commands,
                )
                for profile in command["specialists"]
            },
        )

    def test_new_commands_and_independent_shared_controls_are_explicit(self) -> None:
        d24 = self.target.commands_by_id["AOE-GD-D24"]
        d25 = self.target.commands_by_id["AOE-GD-D25"]
        self.assertEqual(len(d24.specialist_profile_ids), 10)
        self.assertEqual(len(d25.specialist_profile_ids), 12)
        self.assertIn("recovery proof", d24.boundary)
        self.assertIn("No live action", d25.boundary)

        for profile_id in ("AOE-HQ-33", "AOE-HQ-34", "AOE-HQ-35"):
            profile = self.target.profiles_by_id[profile_id]
            self.assertEqual(profile.policy_template, "independent-assurance-v1")
            self.assertEqual(profile.category, "independent assurance")

    def test_migration_report_is_stable_and_has_no_operational_effect(self) -> None:
        document = self.report.to_dict()
        self.assertEqual(
            document["report_id"],
            "AVM-AD80BE82BEF9D2483820FF58A8E31A4D",
        )
        self.assertEqual(document["preserved_profile_count"], 403)
        self.assertEqual(document["added_specialist_count"], 43)
        self.assertEqual(document["target_profile_count"], 451)
        self.assertEqual(document["migration_status"], "valid_additive_parallel_catalog")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(document["routing_effect"], "none")
        self.assertEqual(document["execution_effect"], "none")
        self.assertEqual(document["deployment_effect"], "none")

    def test_v2_schema_accepts_checked_registry(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.target.to_dict())

    def test_v1_mutation_and_new_profile_activation_fail_closed(self) -> None:
        changed = copy.deepcopy(self.target.to_dict())
        changed["profiles"][0]["name"] = "Changed v1 profile"
        with self.assertRaisesRegex(RegistryError, "preserve every v1 profile"):
            validate_army_v2_migration(
                self.baseline,
                ExpertRegistry.from_dict(changed),
                self.roadmap,
            )

        changed = copy.deepcopy(self.target.to_dict())
        changed["profiles"][403]["status"] = "qualified"
        with self.assertRaisesRegex(RegistryError, "not defined and inactive"):
            validate_army_v2_migration(
                self.baseline,
                ExpertRegistry.from_dict(changed),
                self.roadmap,
            )

    def test_unapproved_command_or_count_change_fails_closed(self) -> None:
        changed = copy.deepcopy(self.target.to_dict())
        changed["commands"][0]["mission"] = "Changed command"
        with self.assertRaisesRegex(RegistryError, "beyond D015"):
            validate_army_v2_migration(
                self.baseline,
                ExpertRegistry.from_dict(changed),
                self.roadmap,
            )

        changed = copy.deepcopy(self.target.to_dict())
        changed["count_contract"]["total_profiles"] = 452
        with self.assertRaisesRegex(RegistryError, "Count contract mismatch"):
            ExpertRegistry.from_dict(changed)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from sunderkey.errors import RegistryError
from sunderkey.registry import ExpertRegistry, load_registry
from sunderkey.types import ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"

EXPECTED_COUNTS = {
    "groups": 5,
    "commands": 23,
    "specialists": 348,
    "domain_commanders": 23,
    "shared_profiles": 32,
    "total_profiles": 403,
    "pilot_specialists": 20,
}

EXPECTED_GROUP_SPECIALIST_COUNTS = {
    "GA": 56,
    "GB": 86,
    "GC": 108,
    "GD": 50,
    "GE": 48,
}

EXPECTED_COMMAND_SPECIALIST_COUNTS = (
    12,
    12,
    16,
    16,
    18,
    16,
    14,
    14,
    12,
    12,
    18,
    14,
    18,
    18,
    14,
    12,
    14,
    16,
    16,
    18,
    18,
    14,
    16,
)


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not REGISTRY_PATH.is_file():
            raise unittest.SkipTest(f"Registry fixture is not available: {REGISTRY_PATH}")
        cls.registry = load_registry(REGISTRY_PATH)

    def test_count_contract_matches_reference_architecture(self) -> None:
        self.assertEqual(asdict(self.registry.count_contract), EXPECTED_COUNTS)

        counts = Counter(profile.kind for profile in self.registry.profiles)
        self.assertEqual(counts[ProfileKind.SPECIALIST], 348)
        self.assertEqual(counts[ProfileKind.DOMAIN_COMMANDER], 23)
        self.assertEqual(counts[ProfileKind.SHARED], 32)
        self.assertEqual(len(self.registry.profiles), 403)

        pilots = [profile for profile in self.registry.profiles if profile.pilot]
        self.assertEqual(len(pilots), 20)
        self.assertTrue(
            all(profile.kind is ProfileKind.SPECIALIST for profile in pilots)
        )

    def test_registry_contract_round_trips_without_layout_drift(self) -> None:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

        self.assertEqual(self.registry.to_dict(), raw)
        self.assertEqual(
            ExpertRegistry.from_dict(self.registry.to_dict()),
            self.registry,
        )

    def test_registry_schema_version_requires_an_exact_integer(self) -> None:
        for invalid in (True, 1.0, 2):
            with self.subTest(invalid=invalid):
                raw = self.registry.to_dict()
                raw["schema_version"] = invalid
                with self.assertRaisesRegex(
                    RegistryError,
                    "integer 1",
                ):
                    ExpertRegistry.from_dict(raw)

    def test_group_and_command_counts_match_reference_architecture(self) -> None:
        actual_groups = {
            group.id: group.specialist_count for group in self.registry.groups
        }
        self.assertEqual(actual_groups, EXPECTED_GROUP_SPECIALIST_COUNTS)

        commands = sorted(self.registry.commands, key=lambda command: command.number)
        self.assertEqual(
            tuple(command.number for command in commands),
            tuple(range(1, 24)),
        )
        self.assertEqual(
            tuple(len(command.specialist_profile_ids) for command in commands),
            EXPECTED_COMMAND_SPECIALIST_COUNTS,
        )

    def test_hierarchy_is_complete_and_referentially_consistent(self) -> None:
        profiles = self.registry.profiles_by_id
        commands = self.registry.commands_by_id

        self.assertEqual(len(profiles), len(self.registry.profiles))
        self.assertEqual(len(commands), len(self.registry.commands))

        all_command_specialists: list[str] = []
        for group in self.registry.groups:
            group_commands = {
                command.id
                for command in self.registry.commands
                if command.group_id == group.id
            }
            self.assertEqual(group_commands, set(group.command_ids))

            group_commander = profiles[group.commander_profile_id]
            self.assertIs(group_commander.kind, ProfileKind.SHARED)
            self.assertEqual(group_commander.category, "group command")
            self.assertEqual(group_commander.group_id, group.id)

        for command in self.registry.commands:
            commander = profiles[command.commander_profile_id]
            self.assertIs(commander.kind, ProfileKind.DOMAIN_COMMANDER)
            self.assertEqual(commander.group_id, command.group_id)
            self.assertEqual(commander.command_id, command.id)

            for profile_id in command.specialist_profile_ids:
                profile = profiles[profile_id]
                self.assertIs(profile.kind, ProfileKind.SPECIALIST)
                self.assertEqual(profile.group_id, command.group_id)
                self.assertEqual(profile.command_id, command.id)
            all_command_specialists.extend(command.specialist_profile_ids)

        registered_specialists = {
            profile.id
            for profile in self.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        }
        self.assertEqual(len(all_command_specialists), len(set(all_command_specialists)))
        self.assertEqual(set(all_command_specialists), registered_specialists)

    def test_registry_rejects_a_specialist_with_inconsistent_command(self) -> None:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        first_command = raw["commands"][0]
        second_command = raw["commands"][1]
        specialist_id = first_command["specialist_profile_ids"][0]
        profile = next(
            item for item in raw["profiles"] if item["id"] == specialist_id
        )
        profile["command_id"] = second_command["id"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-registry.json"
            path.write_text(
                json.dumps(raw, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RegistryError,
                "specialist membership is inconsistent",
            ):
                load_registry(path)

    def test_registry_rejects_a_missing_profile_field(self) -> None:
        raw = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        raw["profiles"][0].pop("pilot")

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid-registry.json"
            path.write_text(
                json.dumps(raw, indent=2, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RegistryError,
                "missing required fields: pilot",
            ):
                load_registry(path)

    def test_registry_loader_rejects_duplicate_json_keys_at_any_depth(
        self,
    ) -> None:
        source = REGISTRY_PATH.read_text(encoding="utf-8")
        cases = {
            "top-level": source.replace(
                "{\n",
                '{\n  "catalog_id": "unreviewed-shadow",\n',
                1,
            ),
            "nested": source.replace(
                '"groups": [\n    {',
                '"groups": [\n    {\n      "name": "unreviewed-shadow",',
                1,
            ),
        }
        for label, text in cases.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "duplicate-key-registry.json"
                path.write_text(text, encoding="utf-8")

                with self.assertRaisesRegex(
                    RegistryError,
                    "Could not read registry",
                ) as raised:
                    load_registry(path)

                self.assertIn(
                    "Duplicate JSON object key",
                    str(raised.exception.__cause__),
                )

    def test_unknown_profile_lookup_is_rejected(self) -> None:
        with self.assertRaisesRegex(RegistryError, "Unknown profile ID"):
            self.registry.profile("AOE-GA-D99-S99")


if __name__ == "__main__":
    unittest.main()

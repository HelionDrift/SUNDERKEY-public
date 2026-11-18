from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from typing import Any

from sunderkey.errors import MissionError
from sunderkey.mission import (
    CORE_SHARED_PROFILE_IDS,
    DOMAIN_SHARED_PROFILE_IDS,
    MissionRequest,
    assemble_joint_mission_cell,
    load_mission_request,
)
from sunderkey.registry import load_registry

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"

SPECIALISTS = (
    "AOE-GA-D03-S04",
    "AOE-GB-D06-S09",
)


def mission_data(
    *,
    specialists: tuple[str, ...] = SPECIALISTS,
    environment: str = "test",
    max_action_tier: str = "R2",
    required_evidence_level: str = "E2",
    scope_document_hash: str | None = None,
    production: bool = False,
    third_party: bool = False,
    synthetic_data_only: bool = True,
    isolated_research_range: bool = False,
    max_cell_size: int = 20,
) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "mission_id": "MISSION-UNIT-001",
        "objective": "Validate a synthetic API authorization boundary",
        "environment": environment,
        "requested_specialist_ids": list(specialists),
        "max_action_tier": max_action_tier,
        "required_evidence_level": required_evidence_level,
        "scope_reference": "scope://unit/synthetic-api",
        "constraints": {
            "production": production,
            "third_party": third_party,
            "synthetic_data_only": synthetic_data_only,
            "isolated_research_range": isolated_research_range,
            "max_cell_size": max_cell_size,
        },
    }
    if scope_document_hash is not None:
        value["scope_document_hash"] = scope_document_hash
    return value


def registry_with_retired_profile(registry: Any, profile_id: str) -> Any:
    profiles = tuple(
        replace(profile, status="retired") if profile.id == profile_id else profile
        for profile in registry.profiles
    )
    return replace(registry, profiles=profiles)


class MissionAssemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not REGISTRY_PATH.is_file():
            raise unittest.SkipTest(f"Registry fixture is not available: {REGISTRY_PATH}")
        cls.registry = load_registry(REGISTRY_PATH)

    def test_assembly_adds_commanders_and_shared_control_roles(self) -> None:
        request = MissionRequest.from_dict(mission_data())
        cell = assemble_joint_mission_cell(self.registry, request)

        self.assertEqual(cell.specialist_profile_ids, SPECIALISTS)
        self.assertEqual(
            set(cell.domain_commander_profile_ids),
            {"AOE-GA-D03-CMD", "AOE-GB-D06-CMD"},
        )
        self.assertEqual(
            set(cell.group_commander_profile_ids),
            {"AOE-HQ-03", "AOE-HQ-04"},
        )
        self.assertEqual(
            set(cell.shared_profile_ids),
            set(CORE_SHARED_PROFILE_IDS) | {"AOE-HQ-32"},
        )
        self.assertEqual(cell.size, 17)
        self.assertEqual(cell.warnings, ())
        self.assertEqual(len(cell.all_profile_ids), len(set(cell.all_profile_ids)))

    def test_production_and_third_party_controls_are_added(self) -> None:
        request = MissionRequest.from_dict(
            mission_data(
                environment="production",
                production=True,
                third_party=True,
                synthetic_data_only=False,
            )
        )
        cell = assemble_joint_mission_cell(self.registry, request)

        expected_controls = {
            "AOE-HQ-14",
            "AOE-HQ-15",
            "AOE-HQ-17",
            "AOE-HQ-32",
        }
        self.assertTrue(expected_controls.issubset(cell.shared_profile_ids))

    def test_human_access_domain_adds_consent_and_legal_controls(self) -> None:
        request = MissionRequest.from_dict(
            mission_data(specialists=("AOE-GA-D02-S01",))
        )
        cell = assemble_joint_mission_cell(self.registry, request)

        expected = set(DOMAIN_SHARED_PROFILE_IDS["AOE-GA-D02"])
        self.assertTrue(expected.issubset(cell.shared_profile_ids))

    def test_ot_domain_adds_production_safety_and_range_controls(self) -> None:
        request = MissionRequest.from_dict(
            mission_data(specialists=("AOE-GD-D19-S01",))
        )
        cell = assemble_joint_mission_cell(self.registry, request)

        expected = set(DOMAIN_SHARED_PROFILE_IDS["AOE-GD-D19"])
        self.assertTrue(expected.issubset(cell.shared_profile_ids))

    def test_cell_size_limit_produces_an_explicit_warning(self) -> None:
        request = MissionRequest.from_dict(mission_data(max_cell_size=10))
        cell = assemble_joint_mission_cell(self.registry, request)

        self.assertEqual(cell.size, 17)
        self.assertTrue(
            any("exceeds the requested maximum 10" in item for item in cell.warnings)
        )

    def test_unknown_and_non_specialist_profiles_are_rejected(self) -> None:
        unknown = MissionRequest.from_dict(
            mission_data(specialists=("AOE-GA-D99-S99",))
        )
        with self.assertRaisesRegex(MissionError, "Unknown requested specialist"):
            assemble_joint_mission_cell(self.registry, unknown)

        commander = MissionRequest.from_dict(
            mission_data(specialists=("AOE-GA-D03-CMD",))
        )
        with self.assertRaisesRegex(MissionError, "not a specialist"):
            assemble_joint_mission_cell(self.registry, commander)

    def test_retired_required_domain_commander_is_rejected(self) -> None:
        retired_id = "AOE-GA-D03-CMD"
        registry = registry_with_retired_profile(self.registry, retired_id)
        request = MissionRequest.from_dict(
            mission_data(specialists=("AOE-GA-D03-S04",))
        )

        with self.assertRaises(MissionError) as raised:
            assemble_joint_mission_cell(registry, request)

        message = str(raised.exception)
        self.assertIn(retired_id, message)
        self.assertIn("retired", message.lower())

    def test_retired_required_shared_control_profile_is_rejected(self) -> None:
        retired_id = "AOE-HQ-08"
        registry = registry_with_retired_profile(self.registry, retired_id)
        request = MissionRequest.from_dict(mission_data())

        with self.assertRaises(MissionError) as raised:
            assemble_joint_mission_cell(registry, request)

        message = str(raised.exception)
        self.assertIn(retired_id, message)
        self.assertIn("retired", message.lower())

    def test_mission_text_fields_reject_non_ascii_text(self) -> None:
        for field in ("objective", "scope_reference"):
            with self.subTest(field=field):
                raw = mission_data()
                raw[field] = f"{raw[field]}{chr(0x00E9)}"

                with self.assertRaises(MissionError) as raised:
                    MissionRequest.from_dict(raw)

                self.assertIn(field, str(raised.exception))

    def test_mission_schema_version_requires_an_exact_integer(self) -> None:
        for invalid in (True, 1.0, 2):
            with self.subTest(invalid=invalid):
                raw = mission_data()
                raw["schema_version"] = invalid
                with self.assertRaisesRegex(
                    MissionError,
                    "integer 1",
                ):
                    MissionRequest.from_dict(raw)

    def test_mission_text_fields_reject_unicode_format_controls(self) -> None:
        for field in ("objective", "scope_reference"):
            with self.subTest(field=field):
                raw = mission_data()
                raw[field] = f"{raw[field]}{chr(0x200B)}"

                with self.assertRaises(MissionError) as raised:
                    MissionRequest.from_dict(raw)

                self.assertIn(field, str(raised.exception))

    def test_mission_loader_rejects_duplicate_json_keys_at_any_depth(
        self,
    ) -> None:
        source = json.dumps(
            mission_data(),
            indent=2,
            ensure_ascii=True,
        )
        cases = {
            "top-level": source.replace(
                "{\n",
                '{\n  "objective": "unreviewed shadow",\n',
                1,
            ),
            "nested": source.replace(
                '"constraints": {',
                '"constraints": {\n    "production": true,',
                1,
            ),
        }
        for label, text in cases.items():
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "duplicate-key-mission.json"
                path.write_text(text, encoding="utf-8")

                with self.assertRaisesRegex(
                    MissionError,
                    "Could not read mission request",
                ) as raised:
                    load_mission_request(path)

                self.assertIn(
                    "Duplicate JSON object key",
                    str(raised.exception.__cause__),
                )

    def test_scope_document_hash_is_optional_but_strict_when_present(self) -> None:
        expected = "sha256:" + ("a" * 64)
        request = MissionRequest.from_dict(
            mission_data(scope_document_hash=expected)
        )

        self.assertEqual(request.scope_document_hash, expected)
        self.assertEqual(request.to_dict()["scope_document_hash"], expected)
        self.assertNotIn(
            "scope_document_hash",
            MissionRequest.from_dict(mission_data()).to_dict(),
        )

        for invalid in (
            "sha256:" + ("A" * 64),
            "sha256:" + ("a" * 63),
            "a" * 64,
            1,
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                MissionError,
                "scope_document_hash",
            ):
                MissionRequest.from_dict(
                    mission_data(scope_document_hash=invalid)  # type: ignore[arg-type]
                )

    def test_r5_requires_both_synthetic_environment_and_isolation(self) -> None:
        invalid_cases = (
            mission_data(
                environment="test",
                max_action_tier="R5",
                isolated_research_range=True,
            ),
            mission_data(
                environment="synthetic",
                max_action_tier="R5",
                isolated_research_range=False,
            ),
        )
        for raw in invalid_cases:
            with self.subTest(environment=raw["environment"]), self.assertRaisesRegex(
                MissionError,
                "isolated synthetic range",
            ):
                MissionRequest.from_dict(raw)

    def test_isolated_synthetic_r5_cell_requires_extra_control(self) -> None:
        request = MissionRequest.from_dict(
            mission_data(
                specialists=(SPECIALISTS[0],),
                environment="synthetic",
                max_action_tier="R5",
                isolated_research_range=True,
            )
        )
        cell = assemble_joint_mission_cell(self.registry, request)

        self.assertIn("AOE-HQ-14", cell.shared_profile_ids)
        self.assertIn("AOE-HQ-32", cell.shared_profile_ids)
        self.assertTrue(
            any("case-specific authorization above R2" in item for item in cell.warnings)
        )

    def test_production_flag_must_match_environment(self) -> None:
        with self.assertRaisesRegex(MissionError, "requires constraints.production"):
            MissionRequest.from_dict(mission_data(environment="production"))

        with self.assertRaisesRegex(
            MissionError,
            "can be true only for production missions",
        ):
            MissionRequest.from_dict(mission_data(production=True))


if __name__ == "__main__":
    unittest.main()

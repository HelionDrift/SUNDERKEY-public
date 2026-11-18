"""Phase 20 full-Army capability and readiness coverage."""

from __future__ import annotations

import ast
import json
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from scripts.build_army_capability_catalog import build_catalog
from sunderkey.army_readiness import (
    ArmyReadinessReport,
    assess_army_readiness,
)
from sunderkey.errors import RoutingError
from sunderkey.registry import load_registry
from sunderkey.routing import (
    CapabilityProfileScope,
    RoutingRequest,
    load_capability_catalog,
    load_routing_policy,
    load_routing_request,
    route_mission,
)
from sunderkey.types import ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
ARMY_CAPABILITY_PATH = (
    ROOT / "registry" / "capabilities-army-v1.json"
)
PILOT_CAPABILITY_PATH = (
    ROOT / "registry" / "capabilities-pilot-v1.json"
)
ARMY_POLICY_PATH = (
    ROOT / "registry" / "routing-policy-army-qualified-v1.json"
)
EXAMPLE_PATH = (
    ROOT / "examples" / "routing" / "internet-api-to-data.json"
)


class ArmyReadinessPhase20Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.catalog = load_capability_catalog(
            ARMY_CAPABILITY_PATH,
            cls.registry,
        )
        cls.pilot_catalog = load_capability_catalog(
            PILOT_CAPABILITY_PATH,
            cls.registry,
        )
        cls.policy = load_routing_policy(
            ARMY_POLICY_PATH,
            cls.catalog,
        )

    def test_catalog_maps_every_specialist_exactly_once(self) -> None:
        specialist_ids = {
            profile.id
            for profile in self.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        }
        assignments = self.catalog.assignments_by_profile_id
        primary_counts = Counter(
            capability_id
            for assignment in self.catalog.profile_assignments
            for capability_id in assignment.primary_capability_ids
        )

        self.assertEqual(self.catalog.schema_version, 2)
        self.assertIs(
            self.catalog.profile_scope,
            CapabilityProfileScope.ALL_SPECIALISTS,
        )
        self.assertEqual(len(specialist_ids), 348)
        self.assertEqual(set(assignments), specialist_ids)
        self.assertEqual(len(self.catalog.capabilities), 348)
        self.assertEqual(len(primary_counts), 348)
        self.assertEqual(set(primary_counts.values()), {1})
        passive = assignments["AOE-GA-D01-S01"]
        self.assertEqual(
            passive.primary_capability_ids,
            ("army.ga.d01.s01",),
        )
        self.assertEqual(
            self.catalog.capabilities_by_id[
                "army.ga.d01.s01"
            ].name,
            "Passive OSINT",
        )

    def test_existing_pilot_mappings_are_preserved(self) -> None:
        army_assignments = self.catalog.assignments_by_profile_id
        for profile_id, pilot_assignment in (
            self.pilot_catalog.assignments_by_profile_id.items()
        ):
            with self.subTest(profile_id=profile_id):
                self.assertEqual(
                    army_assignments[profile_id],
                    pilot_assignment,
                )
        for capability_id, definition in (
            self.pilot_catalog.capabilities_by_id.items()
        ):
            with self.subTest(capability_id=capability_id):
                self.assertEqual(
                    self.catalog.capabilities_by_id[capability_id],
                    definition,
                )

    def test_pilot_catalog_serialization_stays_v1_compatible(self) -> None:
        pilot_raw = json.loads(
            PILOT_CAPABILITY_PATH.read_text(encoding="utf-8")
        )

        self.assertIs(
            self.pilot_catalog.profile_scope,
            CapabilityProfileScope.PILOT_SPECIALISTS,
        )
        self.assertNotIn("profile_scope", self.pilot_catalog.to_dict())
        self.assertEqual(self.pilot_catalog.to_dict(), pilot_raw)

    def test_checked_in_catalog_matches_deterministic_builder(self) -> None:
        registry_raw = json.loads(
            REGISTRY_PATH.read_text(encoding="utf-8")
        )
        pilot_raw = json.loads(
            PILOT_CAPABILITY_PATH.read_text(encoding="utf-8")
        )
        expected = (
            json.dumps(
                build_catalog(registry_raw, pilot_raw),
                ensure_ascii=True,
                indent=2,
            )
            + "\n"
        )
        self.assertEqual(
            ARMY_CAPABILITY_PATH.read_text(encoding="utf-8"),
            expected,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = assess_army_readiness(
            self.registry,
            self.catalog,
            self.policy,
        )
        second = assess_army_readiness(
            self.registry,
            self.catalog,
            self.policy,
        )
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            ArmyReadinessReport.from_dict(document),
            first,
        )
        self.assertRegex(document["report_id"], r"^ARR-[0-9A-F]{32}$")
        self.assertRegex(
            document["report_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(document["status"], "qualification_incomplete")
        self.assertEqual(
            document["summary"],
            {
                "capability_count": 348,
                "command_count": 23,
                "commands_fully_qualified": 0,
                "commands_with_qualified_specialists": 16,
                "defined_specialist_count": 328,
                "group_count": 5,
                "mapped_specialist_count": 348,
                "pending_qualification_count": 328,
                "pilot_specialist_count": 20,
                "policy_eligible_specialist_count": 20,
                "primary_assignment_count": 348,
                "qualified_specialist_count": 20,
                "retired_specialist_count": 0,
                "specialist_count": 348,
                "supporting_assignment_count": 27,
            },
        )
        self.assertEqual(len(document["groups"]), 5)
        self.assertEqual(len(document["commands"]), 23)
        self.assertEqual(len(document["profiles"]), 348)

    def test_report_rejects_tampering(self) -> None:
        document = assess_army_readiness(
            self.registry,
            self.catalog,
            self.policy,
        ).to_dict()
        document["summary"]["qualified_specialist_count"] += 1

        with self.assertRaisesRegex(
            RoutingError,
            "hash is invalid",
        ):
            ArmyReadinessReport.from_dict(document)

    def test_qualified_policy_preserves_pilot_route(self) -> None:
        decision = route_mission(
            self.registry,
            self.catalog,
            self.policy,
            load_routing_request(EXAMPLE_PATH),
        )

        self.assertEqual(
            decision.selected_specialist_ids,
            (
                "AOE-GA-D03-S13",
                "AOE-GB-D06-S09",
                "AOE-GB-D07-S01",
            ),
        )
        self.assertEqual(decision.joint_mission_cell.size, 19)

    def test_defined_specialist_is_visible_but_not_routable(self) -> None:
        raw = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        raw["required_capability_ids"] = ["army.ga.d01.s01"]
        raw["optional_capability_ids"] = []
        request = RoutingRequest.from_dict(raw)

        with self.assertRaisesRegex(
            RoutingError,
            "No eligible specialist",
        ):
            route_mission(
                self.registry,
                self.catalog,
                self.policy,
                request,
            )

    def test_policy_that_routes_defined_profiles_needs_review(self) -> None:
        policy = replace(
            self.policy,
            allowed_statuses=("defined", "qualified"),
        )
        report = assess_army_readiness(
            self.registry,
            self.catalog,
            policy,
        ).to_dict()

        self.assertEqual(report["status"], "policy_review_required")
        self.assertEqual(
            report["summary"]["policy_eligible_specialist_count"],
            348,
        )
        self.assertIn(
            "defined_profiles_allowed",
            report["routing_policy"]["review_reasons"],
        )

    def test_readiness_rejects_the_pilot_only_catalog(self) -> None:
        pilot_policy = load_routing_policy(
            ROOT / "registry" / "routing-policy-pilot-v1.json",
            self.pilot_catalog,
        )
        with self.assertRaisesRegex(
            RoutingError,
            "requires an all_specialists",
        ):
            assess_army_readiness(
                self.registry,
                self.pilot_catalog,
                pilot_policy,
            )

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "army_readiness.py",
            ROOT / "scripts" / "build_army_capability_catalog.py",
        ):
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                imported = {
                    alias.name.split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Import)
                    for alias in node.names
                }
                imported.update(
                    node.module.split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    and node.module is not None
                    and not node.level
                )
                self.assertTrue(
                    {
                        "http",
                        "requests",
                        "socket",
                        "subprocess",
                        "urllib",
                    }.isdisjoint(imported)
                )


if __name__ == "__main__":
    unittest.main()

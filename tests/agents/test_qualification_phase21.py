"""Phase 21 specialist qualification planning coverage."""

from __future__ import annotations

import ast
import json
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.build_army_qualification_plans import build_plan_catalog
from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    QualificationCoverageReport,
    QualificationPlanCatalog,
    assess_qualification_coverage,
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from sunderkey.types import MissionEnvironment, ProfileKind

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"


class QualificationPhase21Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.catalog = load_capability_catalog(
            CAPABILITY_PATH,
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH,
            cls.registry,
            cls.catalog,
        )
        cls.plans = load_qualification_plan_catalog(
            PLANS_PATH,
            cls.registry,
            cls.catalog,
            cls.standard,
        )

    def test_standard_defines_closed_independent_review_gates(self) -> None:
        self.assertEqual(len(self.standard.gates), 8)
        self.assertEqual(self.standard.minimum_scenarios_per_profile, 29)
        self.assertEqual(
            self.standard.minimum_passing_scenarios_per_profile,
            26,
        )
        self.assertEqual(
            self.standard.allowed_environments,
            (
                MissionEnvironment.OFFLINE,
                MissionEnvironment.SYNTHETIC,
                MissionEnvironment.TEST,
            ),
        )
        self.assertFalse(
            self.standard.decision_policy.allow_self_attestation
        )
        self.assertTrue(
            self.standard.decision_policy.require_independent_control_review
        )
        self.assertTrue(
            self.standard.decision_policy.require_independent_assurance_review
        )
        self.assertEqual(
            self.standard.decision_policy.minimum_distinct_evaluators,
            2,
        )
        self.assertTrue(
            all(
                gate.maximum_critical_failures == 0
                and gate.independent_review_required
                for gate in self.standard.gates
            )
        )

    def test_plan_catalog_covers_every_specialist(self) -> None:
        specialist_ids = {
            profile.id
            for profile in self.registry.profiles
            if profile.kind is ProfileKind.SPECIALIST
        }
        plans = self.plans.plans_by_profile_id
        self.assertEqual(len(plans), 348)
        self.assertEqual(set(plans), specialist_ids)
        self.assertEqual(
            len({plan.scenario_family_id for plan in plans.values()}),
            348,
        )
        for profile_id, plan in plans.items():
            with self.subTest(profile_id=profile_id):
                self.assertEqual(
                    plan.required_gate_ids,
                    self.standard.gate_ids,
                )
                self.assertEqual(
                    plan.primary_capability_ids,
                    self.catalog.assignments_by_profile_id[
                        profile_id
                    ].primary_capability_ids,
                )

    def test_checked_in_plans_match_deterministic_builder(self) -> None:
        registry_raw = json.loads(
            REGISTRY_PATH.read_text(encoding="utf-8")
        )
        capabilities_raw = json.loads(
            CAPABILITY_PATH.read_text(encoding="utf-8")
        )
        standard_raw = json.loads(
            STANDARD_PATH.read_text(encoding="utf-8")
        )
        expected = (
            json.dumps(
                build_plan_catalog(
                    registry_raw,
                    capabilities_raw,
                    standard_raw,
                ),
                ensure_ascii=True,
                indent=2,
            )
            + "\n"
        )
        self.assertEqual(
            PLANS_PATH.read_text(encoding="utf-8"),
            expected,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = assess_qualification_coverage(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        )
        second = assess_qualification_coverage(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        )
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            QualificationCoverageReport.from_dict(document),
            first,
        )
        self.assertRegex(document["report_id"], r"^QCR-[0-9A-F]{32}$")
        self.assertRegex(
            document["report_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(
            document["status"],
            "qualification_execution_pending",
        )
        self.assertEqual(
            document["evidence_evaluation_state"],
            "not_performed",
        )
        self.assertEqual(
            document["summary"],
            {
                "command_count": 23,
                "commands_fully_qualified": 0,
                "commands_with_no_qualified_specialist": 7,
                "commands_with_partial_qualification": 16,
                "defined_specialist_count": 328,
                "gate_count": 8,
                "group_count": 5,
                "minimum_passing_scenario_count": 9048,
                "minimum_scenario_count": 10092,
                "planned_gate_assessment_count": 2784,
                "planned_specialist_count": 348,
                "qualified_specialist_count": 20,
                "retired_specialist_count": 0,
                "specialist_count": 348,
            },
        )

    def test_priority_zero_commands_match_readiness_gap(self) -> None:
        document = assess_qualification_coverage(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        ).to_dict()
        priority_zero = {
            record["command_id"]
            for record in document["commands"]
            if record["priority_band"] == "priority_0_no_qualified"
        }
        self.assertEqual(
            priority_zero,
            {
                "AOE-GA-D02",
                "AOE-GB-D08",
                "AOE-GB-D10",
                "AOE-GC-D16",
                "AOE-GD-D18",
                "AOE-GD-D19",
                "AOE-GE-D21",
            },
        )

    def test_report_rejects_tampering(self) -> None:
        document = assess_qualification_coverage(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        ).to_dict()
        document["summary"]["planned_specialist_count"] -= 1
        with self.assertRaisesRegex(
            QualificationError,
            "hash is invalid",
        ):
            QualificationCoverageReport.from_dict(document)

    def test_missing_profile_plan_fails_closed(self) -> None:
        raw = self.plans.to_dict()
        raw["profile_plans"].pop()
        with self.assertRaisesRegex(
            QualificationError,
            "must match all specialists",
        ):
            QualificationPlanCatalog.from_dict(
                raw,
                self.registry,
                self.catalog,
                self.standard,
            )

    def test_mismatched_capability_fails_closed(self) -> None:
        raw = self.plans.to_dict()
        raw["profile_plans"][0]["primary_capability_ids"] = [
            "army.ga.d01.s02"
        ]
        with self.assertRaisesRegex(
            QualificationError,
            "capabilities do not match",
        ):
            QualificationPlanCatalog.from_dict(
                raw,
                self.registry,
                self.catalog,
                self.standard,
            )

    def test_unsafe_standard_is_reported_for_review(self) -> None:
        unsafe_policy = replace(
            self.standard.decision_policy,
            allow_self_attestation=True,
        )
        unsafe_standard = replace(
            self.standard,
            allowed_environments=(
                *self.standard.allowed_environments,
                MissionEnvironment.PRODUCTION,
            ),
            decision_policy=unsafe_policy,
        ).revalidated(self.registry, self.catalog)
        rebound_plans = replace(
            self.plans,
            qualification_standard_sha256=(
                unsafe_standard.canonical_sha256
            ),
        )
        document = assess_qualification_coverage(
            self.registry,
            self.catalog,
            unsafe_standard,
            rebound_plans,
        ).to_dict()

        self.assertEqual(
            document["status"],
            "qualification_standard_review_required",
        )
        self.assertEqual(
            document["qualification_standard"]["review_reasons"],
            [
                "production_environment_allowed",
                "self_attestation_allowed",
            ],
        )

    def test_assessment_does_not_mutate_registry_status(self) -> None:
        before = self.registry.to_dict()
        assess_qualification_coverage(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        )
        self.assertEqual(self.registry.to_dict(), before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "qualification.py",
            ROOT / "scripts" / "build_army_qualification_plans.py",
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

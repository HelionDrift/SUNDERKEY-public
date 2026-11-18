"""Phase 27 deterministic specialist implementation waves."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_specialist_implementation_roadmap import (
    build_parser,
    build_report,
)
from sunderkey.candidate_blueprints import (
    REQUIRED_COMPONENT_IDS,
    load_candidate_blueprint_catalog,
)
from sunderkey.candidate_components import load_candidate_component_catalog
from sunderkey.candidate_inventory import (
    CandidateImplementationCatalog,
    compute_candidate_artifact_sha256,
    load_candidate_implementation_catalog,
)
from sunderkey.errors import QualificationError
from sunderkey.implementation_roadmap import (
    SpecialistImplementationRoadmapReport,
    assess_specialist_implementation_roadmap,
)
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import (
    RoutingPolicy,
    load_capability_catalog,
    load_routing_policy,
)

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
POLICY_PATH = ROOT / "registry" / "routing-policy-army-qualified-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"
BLUEPRINTS_PATH = ROOT / "registry" / "candidate-blueprints-army-v1.json"
COMPONENTS_PATH = ROOT / "registry" / "candidate-components-v1.json"
CANDIDATES_PATH = ROOT / "registry" / "candidate-implementations-v1.json"
ROADMAP_PATH = ROOT / "registry" / "implementation-roadmap-army-v1.json"


def rebind_candidate(candidate: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in candidate.items()
        if key != "candidate_artifact_sha256"
    }
    candidate["candidate_artifact_sha256"] = (
        compute_candidate_artifact_sha256(body)
    )


class SpecialistImplementationRoadmapPhase27Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(
            CAPABILITY_PATH,
            cls.registry,
        )
        cls.policy = load_routing_policy(
            POLICY_PATH,
            cls.capabilities,
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH,
            cls.registry,
            cls.capabilities,
        )
        cls.plans = load_qualification_plan_catalog(
            PLANS_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
        )
        cls.blueprints = load_candidate_blueprint_catalog(
            BLUEPRINTS_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
        )
        cls.components = load_candidate_component_catalog(
            COMPONENTS_PATH,
            cls.blueprints,
        )
        cls.candidates = load_candidate_implementation_catalog(
            CANDIDATES_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
            cls.blueprints,
        )

    def assess(
        self,
        *,
        policy: RoutingPolicy | None = None,
        candidates: CandidateImplementationCatalog | None = None,
    ) -> SpecialistImplementationRoadmapReport:
        return assess_specialist_implementation_roadmap(
            self.registry,
            self.capabilities,
            policy or self.policy,
            self.standard,
            self.plans,
            self.blueprints,
            self.components,
            candidates or self.candidates,
        )

    def candidate_catalog_from(
        self,
        raw: dict[str, Any],
    ) -> CandidateImplementationCatalog:
        return CandidateImplementationCatalog.from_dict(
            raw,
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            SpecialistImplementationRoadmapReport.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "IRR-524BC04C5332069D28773F83B81AB3D2",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:524bc04c5332069d28773f83b81ab3d2"
            "b871bfe7713fa74e3ed068a347e48da2",
        )

    def test_checked_in_roadmap_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            ROADMAP_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_roadmap_schedules_every_gap_exactly_once(self) -> None:
        document = self.assess().to_dict()
        self.assertEqual(document["status"], "implementation_roadmap_ready")
        self.assertEqual(document["roadmap_effect"], "none")
        self.assertEqual(
            document["summary"],
            {
                "group_count": 5,
                "command_count": 23,
                "specialist_count": 348,
                "policy_eligible_specialist_count": 20,
                "catalog_candidate_count": 1,
                "nonfixture_candidate_count": 0,
                "catalogued_component_artifact_count": 5,
                "implementation_gap_count": 348,
                "scheduled_profile_count": 348,
                "implemented_profile_count": 0,
                "wave_count": 18,
                "largest_wave_profile_count": 23,
                "commands_without_policy_eligible_specialists": 7,
            },
        )
        self.assertEqual(
            document["priority_counts"],
            {
                "command_coverage_gap": 100,
                "eligible_baseline_gap": 20,
                "army_depth_gap": 228,
            },
        )
        profile_ids = [
            profile["profile_id"]
            for wave in document["waves"]
            for profile in wave["profiles"]
        ]
        self.assertEqual(len(profile_ids), 348)
        self.assertEqual(len(set(profile_ids)), 348)

    def test_waves_are_bounded_domain_commander_rounds(self) -> None:
        document = self.assess().to_dict()
        self.assertEqual(
            document["wave_policy"]["maximum_profiles_per_wave"],
            23,
        )
        self.assertEqual(
            document["wave_policy"][
                "maximum_profiles_per_command_per_wave"
            ],
            1,
        )
        for wave in document["waves"]:
            with self.subTest(wave=wave["wave_id"]):
                command_ids = [
                    profile["command_id"]
                    for profile in wave["profiles"]
                ]
                self.assertLessEqual(wave["profile_count"], 23)
                self.assertEqual(
                    wave["profile_count"],
                    wave["command_count"],
                )
                self.assertEqual(
                    len(command_ids),
                    len(set(command_ids)),
                )
        first = document["waves"][0]
        self.assertEqual(first["profile_count"], 23)
        self.assertEqual(
            [profile["priority_tier"] for profile in first["profiles"][:7]],
            ["command_coverage_gap"] * 7,
        )

    def test_each_work_item_binds_reviewed_build_inputs(self) -> None:
        document = self.assess().to_dict()
        profiles = {
            profile["profile_id"]: profile
            for wave in document["waves"]
            for profile in wave["profiles"]
        }
        for profile_id, record in profiles.items():
            with self.subTest(profile_id=profile_id):
                blueprint = self.blueprints.blueprints_by_profile_id[
                    profile_id
                ]
                plan = self.plans.plans_by_profile_id[profile_id]
                self.assertEqual(
                    record["candidate_blueprint_sha256"],
                    blueprint.blueprint_sha256,
                )
                self.assertEqual(
                    record["required_gate_ids"],
                    list(plan.required_gate_ids),
                )
                self.assertEqual(
                    record["required_component_ids"],
                    list(REQUIRED_COMPONENT_IDS),
                )
                self.assertTrue(record["component_build_ready"])
                self.assertEqual(
                    record["authoritative_qualification_blocker"],
                    "D008_pending",
                )

    def test_nonfixture_candidate_removes_one_scheduled_gap(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["lifecycle"] = "development"
        rebind_candidate(raw["candidates"][0])
        document = self.assess(
            candidates=self.candidate_catalog_from(raw)
        ).to_dict()
        scheduled = {
            profile["profile_id"]
            for wave in document["waves"]
            for profile in wave["profiles"]
        }

        self.assertEqual(document["summary"]["implementation_gap_count"], 347)
        self.assertEqual(document["summary"]["implemented_profile_count"], 1)
        self.assertNotIn("AOE-GA-D01-S01", scheduled)

    def test_policy_changes_recalculate_priorities(self) -> None:
        raw = self.policy.to_dict()
        raw["allowed_statuses"] = ["defined", "qualified"]
        policy = RoutingPolicy.from_dict(raw, self.capabilities)
        document = self.assess(policy=policy).to_dict()

        self.assertEqual(
            document["summary"]["policy_eligible_specialist_count"],
            348,
        )
        self.assertEqual(
            document["summary"][
                "commands_without_policy_eligible_specialists"
            ],
            0,
        )
        self.assertEqual(
            document["priority_counts"],
            {
                "command_coverage_gap": 0,
                "eligible_baseline_gap": 348,
                "army_depth_gap": 0,
            },
        )

    def test_report_tampering_fails_closed(self) -> None:
        document = self.assess().to_dict()
        document["summary"]["scheduled_profile_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            SpecialistImplementationRoadmapReport.from_dict(document)

    def test_assessment_does_not_mutate_inputs(self) -> None:
        before = (
            copy.deepcopy(self.registry.to_dict()),
            copy.deepcopy(self.capabilities.to_dict()),
            copy.deepcopy(self.policy.to_dict()),
            copy.deepcopy(self.standard.to_dict()),
            copy.deepcopy(self.plans.to_dict()),
            copy.deepcopy(self.blueprints.to_dict()),
            copy.deepcopy(self.components.to_dict()),
            copy.deepcopy(self.candidates.to_dict()),
        )
        self.assess()
        after = (
            self.registry.to_dict(),
            self.capabilities.to_dict(),
            self.policy.to_dict(),
            self.standard.to_dict(),
            self.plans.to_dict(),
            self.blueprints.to_dict(),
            self.components.to_dict(),
            self.candidates.to_dict(),
        )
        self.assertEqual(after, before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        for path in (
            ROOT / "src" / "sunderkey" / "implementation_roadmap.py",
            ROOT / "scripts" / "build_specialist_implementation_roadmap.py",
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
                    str(node.module).split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                )
                self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()

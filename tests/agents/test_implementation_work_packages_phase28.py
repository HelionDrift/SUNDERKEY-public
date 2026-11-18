"""Phase 28 deterministic domain commander implementation work packages."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_implementation_work_packages import (
    build_parser,
    build_report,
)
from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_components import load_candidate_component_catalog
from sunderkey.candidate_inventory import (
    CandidateImplementationCatalog,
    compute_candidate_artifact_sha256,
    load_candidate_implementation_catalog,
)
from sunderkey.errors import QualificationError
from sunderkey.implementation_roadmap import (
    load_specialist_implementation_roadmap,
)
from sunderkey.implementation_work_packages import (
    ImplementationWorkPackageReport,
    assess_implementation_work_packages,
)
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import (
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
WORK_PACKAGES_PATH = (
    ROOT / "registry" / "implementation-work-packages-army-v1.json"
)


def rebind_candidate(candidate: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in candidate.items()
        if key != "candidate_artifact_sha256"
    }
    candidate["candidate_artifact_sha256"] = (
        compute_candidate_artifact_sha256(body)
    )


class ImplementationWorkPackagesPhase28Tests(unittest.TestCase):
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
        cls.roadmap = load_specialist_implementation_roadmap(ROADMAP_PATH)

    def assess(
        self,
        *,
        candidates: CandidateImplementationCatalog | None = None,
    ) -> ImplementationWorkPackageReport:
        return assess_implementation_work_packages(
            self.registry,
            self.capabilities,
            self.policy,
            self.standard,
            self.plans,
            self.blueprints,
            self.components,
            candidates or self.candidates,
            self.roadmap,
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
            ImplementationWorkPackageReport.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "IWR-CFFB850900D0CF6C01DDB4963E2ED618",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:cffb850900d0cf6c01ddb4963e2ed618"
            "87bbb2406212c4f443732c283c328225",
        )

    def test_checked_in_report_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            WORK_PACKAGES_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_summary_accounts_for_all_work(self) -> None:
        document = self.assess().to_dict()
        self.assertEqual(
            document["status"],
            "implementation_work_packages_ready",
        )
        self.assertEqual(document["work_package_effect"], "none")
        self.assertEqual(
            document["summary"],
            {
                "wave_package_count": 18,
                "group_count": 5,
                "domain_command_count": 23,
                "specialist_lane_count": 348,
                "work_item_count": 3132,
                "component_authoring_work_item_count": 1740,
                "candidate_binding_work_item_count": 348,
                "onboarding_work_item_count": 348,
                "preflight_work_item_count": 348,
                "authoritative_qualification_work_item_count": 348,
                "initially_ready_work_item_count": 348,
                "dependency_blocked_work_item_count": 2436,
                "decision_blocked_work_item_count": 348,
            },
        )
        self.assertEqual(
            document["work_item_state_counts"],
            {
                "ready_for_authoring": 348,
                "waiting_on_dependencies": 2436,
                "blocked_by_decision": 348,
            },
        )

    def test_packages_preserve_every_roadmap_lane_once(self) -> None:
        roadmap = self.roadmap.to_dict()
        document = self.assess().to_dict()
        expected_profiles = [
            profile["profile_id"]
            for wave in roadmap["waves"]
            for profile in wave["profiles"]
        ]
        actual_profiles = [
            lane["subject_profile_id"]
            for package in document["packages"]
            for lane in package["command_lanes"]
        ]
        self.assertEqual(actual_profiles, expected_profiles)
        self.assertEqual(len(set(actual_profiles)), 348)
        for roadmap_wave, package in zip(
            roadmap["waves"],
            document["packages"],
            strict=True,
        ):
            with self.subTest(wave=roadmap_wave["wave_id"]):
                self.assertEqual(
                    package["wave_id"],
                    roadmap_wave["wave_id"],
                )
                self.assertEqual(
                    package["specialist_lane_count"],
                    roadmap_wave["profile_count"],
                )
                self.assertEqual(
                    package["domain_command_count"],
                    roadmap_wave["command_count"],
                )

    def test_each_lane_has_the_closed_nine_stage_dependency_graph(self) -> None:
        document = self.assess().to_dict()
        for package in document["packages"]:
            for lane in package["command_lanes"]:
                with self.subTest(lane=lane["lane_id"]):
                    items = lane["work_items"]
                    self.assertEqual(len(items), 9)
                    self.assertEqual(
                        [item["stage_number"] for item in items],
                        list(range(1, 10)),
                    )
                    self.assertEqual(
                        items[0]["task_state"],
                        "ready_for_authoring",
                    )
                    self.assertEqual(
                        items[0]["dependency_work_item_ids"],
                        [],
                    )
                    self.assertEqual(
                        items[5]["dependency_work_item_ids"],
                        [item["work_item_id"] for item in items[:5]],
                    )
                    self.assertEqual(
                        items[8]["task_state"],
                        "blocked_by_decision",
                    )
                    self.assertEqual(
                        items[8]["dependency_work_item_ids"],
                        [items[7]["work_item_id"]],
                    )
                    self.assertEqual(
                        items[8]["decision_blocker_ids"],
                        ["D008"],
                    )
                    self.assertTrue(
                        all(item["task_effect"] == "none" for item in items)
                    )

    def test_command_and_group_accountability_matches_registry(self) -> None:
        document = self.assess().to_dict()
        for package in document["packages"]:
            expected_groups = {
                item["group_id"]: item["commander_profile_id"]
                for item in package["group_commanders"]
            }
            for group_id, commander_id in expected_groups.items():
                self.assertEqual(
                    commander_id,
                    self.registry.groups_by_id[group_id].commander_profile_id,
                )
            for lane in package["command_lanes"]:
                command = self.registry.commands_by_id[lane["command_id"]]
                self.assertEqual(
                    lane["accountable_commander_profile_id"],
                    command.commander_profile_id,
                )

    def test_acceptance_contracts_are_central_and_non_dispatching(self) -> None:
        document = self.assess().to_dict()
        stages = document["work_policy"]["stages"]
        self.assertEqual(len(stages), 9)
        self.assertEqual(
            [stage["stage_id"] for stage in stages[:5]],
            [
                "behavior_contract",
                "instruction_bundle",
                "knowledge_manifest",
                "runtime_manifest",
                "tool_policy",
            ],
        )
        self.assertEqual(
            stages[-1]["blocked_by_decision"],
            "D008",
        )
        self.assertEqual(
            document["work_policy"]["runtime_assignment_effect"],
            "none",
        )

    def test_stale_roadmap_fails_closed_against_current_candidates(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["lifecycle"] = "development"
        rebind_candidate(raw["candidates"][0])
        with self.assertRaisesRegex(
            QualificationError,
            "does not match current source artifacts",
        ):
            self.assess(candidates=self.candidate_catalog_from(raw))

    def test_report_tampering_fails_closed(self) -> None:
        document = self.assess().to_dict()
        document["summary"]["work_item_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            ImplementationWorkPackageReport.from_dict(document)

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
            copy.deepcopy(self.roadmap.to_dict()),
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
            self.roadmap.to_dict(),
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
            ROOT
            / "src"
            / "sunderkey"
            / "implementation_work_packages.py",
            ROOT / "scripts" / "build_implementation_work_packages.py",
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

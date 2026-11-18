"""Phase 25 candidate component and onboarding contracts."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_candidate_components import build_catalog
from sunderkey.candidate_blueprints import (
    REQUIRED_COMPONENT_IDS,
    load_candidate_blueprint_catalog,
)
from sunderkey.candidate_components import (
    CandidateComponentCatalog,
    CandidateOnboardingReport,
    assess_candidate_onboarding,
    compute_candidate_component_sha256,
    load_candidate_component_catalog,
)
from sunderkey.candidate_inventory import (
    CandidateImplementationCatalog,
    compute_candidate_artifact_sha256,
    load_candidate_implementation_catalog,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"
BLUEPRINTS_PATH = ROOT / "registry" / "candidate-blueprints-army-v1.json"
COMPONENTS_PATH = ROOT / "registry" / "candidate-components-v1.json"
CANDIDATES_PATH = ROOT / "registry" / "candidate-implementations-v1.json"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def rebind_component(component: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in component.items()
        if key != "component_sha256"
    }
    component["component_sha256"] = compute_candidate_component_sha256(
        body
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


class CandidateComponentsPhase25Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(
            CAPABILITY_PATH, cls.registry
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH, cls.registry, cls.capabilities
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
            COMPONENTS_PATH, cls.blueprints
        )
        cls.candidates = load_candidate_implementation_catalog(
            CANDIDATES_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
            cls.blueprints,
        )

    def component_catalog_from(
        self, raw: dict[str, Any]
    ) -> CandidateComponentCatalog:
        return CandidateComponentCatalog.from_dict(raw, self.blueprints)

    def candidate_catalog_from(
        self, raw: dict[str, Any]
    ) -> CandidateImplementationCatalog:
        return CandidateImplementationCatalog.from_dict(
            raw,
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
        )

    def assess(
        self,
        components: CandidateComponentCatalog | None = None,
        candidates: CandidateImplementationCatalog | None = None,
    ) -> CandidateOnboardingReport:
        return assess_candidate_onboarding(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            components or self.components,
            candidates or self.candidates,
        )

    def test_fixture_has_exactly_five_closed_components(self) -> None:
        self.assertEqual(len(self.components.components), 5)
        self.assertEqual(
            tuple(item.component_type for item in self.components.components),
            REQUIRED_COMPONENT_IDS,
        )
        self.assertEqual(
            {item.component_status for item in self.components.components},
            {"contract_fixture"},
        )
        runtime = self.components.components[3].specification
        self.assertEqual(runtime["runtime_class"], "disabled_fixture")
        self.assertFalse(runtime["execution_enabled"])
        self.assertFalse(runtime["network_access"])
        self.assertFalse(runtime["process_access"])

    def test_candidate_digests_bind_exact_component_artifacts(self) -> None:
        candidate = self.candidates.candidates[0]
        expected = {
            "behavior_contract": candidate.behavior_contract_sha256,
            "instruction_bundle": candidate.instruction_bundle_sha256,
            "knowledge_manifest": candidate.knowledge_manifest_sha256,
            "runtime_manifest": candidate.runtime_manifest_sha256,
            "tool_policy": candidate.tool_policy_sha256,
        }
        self.assertEqual(
            {
                item.component_type: item.component_sha256
                for item in self.components.components
            },
            expected,
        )
        self.assertEqual(
            candidate.candidate_artifact_sha256,
            "sha256:ba3d024191766c8471f1268ed465d88c"
            "986626bcd785a0b88dbad4ebc08672ee",
        )

    def test_checked_in_catalog_matches_deterministic_builder(self) -> None:
        expected = build_catalog(load_json(BLUEPRINTS_PATH))
        self.assertEqual(
            COMPONENTS_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_onboarding_report_is_deterministic_and_fixture_only(self) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()
        self.assertEqual(first, second)
        self.assertEqual(CandidateOnboardingReport.from_dict(document), first)
        self.assertEqual(
            document["report_id"],
            "ONR-21020860C981FE459A57E917F5C42DC9",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:21020860c981fe459a57e917f5c42dc9"
            "19c9381edb9924c44b688d1b45e91352",
        )
        self.assertEqual(document["status"], "candidate_component_fixture_only")
        self.assertEqual(document["onboarding_effect"], "none")
        self.assertEqual(
            document["summary"],
            {
                "candidate_count": 1,
                "component_artifact_count": 5,
                "required_component_count_per_candidate": 5,
                "behavior_contract_count": 1,
                "instruction_bundle_count": 1,
                "knowledge_manifest_count": 1,
                "runtime_manifest_count": 1,
                "tool_policy_count": 1,
                "component_binding_complete_candidate_count": 1,
                "contract_fixture_complete_candidate_count": 1,
                "nonfixture_complete_candidate_count": 0,
                "incomplete_candidate_count": 0,
                "orphan_component_count": 0,
            },
        )

    def test_missing_component_reports_incomplete(self) -> None:
        raw = self.components.to_dict()
        raw["components"].pop()
        report = self.assess(
            self.component_catalog_from(raw)
        ).to_dict()
        self.assertEqual(report["status"], "candidate_component_incomplete")
        self.assertEqual(report["summary"]["incomplete_candidate_count"], 1)
        self.assertEqual(
            report["candidates"][0]["missing_component_types"],
            ["tool_policy"],
        )

    def test_valid_replacement_digest_reports_candidate_mismatch(self) -> None:
        raw = self.components.to_dict()
        instruction = raw["components"][1]
        instruction["specification"]["content_sha256"] = (
            "sha256:" + ("0" * 64)
        )
        rebind_component(instruction)
        report = self.assess(
            self.component_catalog_from(raw)
        ).to_dict()
        self.assertEqual(
            report["candidates"][0]["digest_mismatch_component_types"],
            ["instruction_bundle"],
        )
        self.assertFalse(
            report["candidates"][0]["component_binding_complete"]
        )

    def test_rehashed_behavior_substitution_fails_closed(self) -> None:
        raw = self.components.to_dict()
        behavior = raw["components"][0]
        behavior["specification"]["mission"] = "Substituted mission"
        rebind_component(behavior)
        with self.assertRaisesRegex(
            QualificationError,
            "Behavior contract does not match",
        ):
            self.component_catalog_from(raw)

    def test_cross_profile_component_binding_is_reported(self) -> None:
        raw = self.components.to_dict()
        instruction = raw["components"][1]
        other = self.blueprints.blueprints_by_profile_id[
            "AOE-GA-D01-S02"
        ].to_dict()
        instruction["profile_id"] = other["profile_id"]
        instruction["candidate_blueprint_sha256"] = other[
            "blueprint_sha256"
        ]
        instruction["specification"]["primary_capability_ids"] = other[
            "primary_capability_ids"
        ]
        instruction["specification"]["supporting_capability_ids"] = other[
            "supporting_capability_ids"
        ]
        instruction["specification"]["scenario_family_id"] = other[
            "scenario_family_id"
        ]
        instruction["specification"]["required_gate_ids"] = other[
            "required_gate_ids"
        ]
        rebind_component(instruction)
        report = self.assess(
            self.component_catalog_from(raw)
        ).to_dict()
        self.assertEqual(
            report["candidates"][0]["binding_mismatch_component_types"],
            ["instruction_bundle"],
        )
        self.assertFalse(
            report["candidates"][0]["component_binding_complete"]
        )

    def test_duplicate_candidate_component_type_fails_closed(self) -> None:
        raw = self.components.to_dict()
        duplicate = copy.deepcopy(raw["components"][0])
        duplicate["component_id"] = "fixture.passive-osint.behavior-copy"
        rebind_component(duplicate)
        raw["components"].append(duplicate)
        with self.assertRaisesRegex(
            QualificationError,
            "duplicate candidate component types",
        ):
            self.component_catalog_from(raw)

    def test_component_hash_tampering_fails_closed(self) -> None:
        raw = self.components.to_dict()
        raw["components"][0]["component_sha256"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            QualificationError, "component_sha256 is invalid"
        ):
            self.component_catalog_from(raw)

    def test_blueprint_binding_mismatch_fails_closed(self) -> None:
        raw = self.components.to_dict()
        raw["candidate_blueprint_catalog_version"] = "wrong"
        with self.assertRaisesRegex(
            QualificationError, "blueprint binding is invalid"
        ):
            self.component_catalog_from(raw)

    def test_orphan_component_is_reported(self) -> None:
        raw = self.components.to_dict()
        orphan = copy.deepcopy(raw["components"][1])
        orphan["component_id"] = "fixture.orphan.instruction-bundle"
        orphan["candidate_id"] = "fixture.orphan"
        rebind_component(orphan)
        raw["components"].append(orphan)
        report = self.assess(
            self.component_catalog_from(raw)
        ).to_dict()
        self.assertEqual(report["summary"]["orphan_component_count"], 1)
        self.assertEqual(
            report["orphan_component_ids"],
            ["fixture.orphan.instruction-bundle"],
        )

    def test_lifecycle_and_runtime_mismatches_are_reported(self) -> None:
        candidate_raw = self.candidates.to_dict()
        candidate_raw["candidates"][0]["lifecycle"] = (
            "evaluation_candidate"
        )
        rebind_candidate(candidate_raw["candidates"][0])
        component_raw = self.components.to_dict()
        runtime = component_raw["components"][3]
        runtime["specification"]["runtime_class"] = "human_runbook"
        rebind_component(runtime)
        report = self.assess(
            self.component_catalog_from(component_raw),
            self.candidate_catalog_from(candidate_raw),
        ).to_dict()
        candidate = report["candidates"][0]
        self.assertEqual(
            candidate["lifecycle_mismatch_component_types"],
            list(REQUIRED_COMPONENT_IDS),
        )
        self.assertFalse(candidate["runtime_compatible"])
        self.assertFalse(candidate["component_binding_complete"])

    def test_report_rejects_tampering(self) -> None:
        document = self.assess().to_dict()
        document["summary"]["component_artifact_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            CandidateOnboardingReport.from_dict(document)

    def test_onboarding_does_not_mutate_inputs(self) -> None:
        before_registry = self.registry.to_dict()
        before_components = self.components.to_dict()
        before_candidates = self.candidates.to_dict()
        self.assess()
        self.assertEqual(self.registry.to_dict(), before_registry)
        self.assertEqual(self.components.to_dict(), before_components)
        self.assertEqual(self.candidates.to_dict(), before_candidates)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_components.py",
            ROOT / "scripts" / "build_candidate_components.py",
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

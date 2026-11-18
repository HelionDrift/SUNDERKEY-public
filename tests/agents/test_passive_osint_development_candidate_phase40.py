"""Phase 40 Passive OSINT development candidate coverage."""

from __future__ import annotations

import argparse
import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_passive_osint_development_candidate import (
    build_catalogs,
    build_reports,
)
from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_components import (
    assess_candidate_onboarding,
    load_candidate_component_catalog,
)
from sunderkey.candidate_inventory import (
    assess_candidate_inventory,
    load_candidate_implementation_catalog,
)
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
SOURCE = ROOT / "examples" / "implementation" / "passive-osint"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


class PassiveOsintDevelopmentCandidatePhase40Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY / "army-v1.json")
        cls.capabilities = load_capability_catalog(
            REGISTRY / "capabilities-army-v1.json",
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            REGISTRY / "qualification-standard-v1.json",
            cls.registry,
            cls.capabilities,
        )
        cls.plans = load_qualification_plan_catalog(
            REGISTRY / "qualification-plans-army-v1.json",
            cls.registry,
            cls.capabilities,
            cls.standard,
        )
        cls.blueprints = load_candidate_blueprint_catalog(
            REGISTRY / "candidate-blueprints-army-v1.json",
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
        )
        cls.components = load_candidate_component_catalog(
            SOURCE / "candidate-components-v1.json",
            cls.blueprints,
        )
        cls.candidates = load_candidate_implementation_catalog(
            SOURCE / "candidate-implementations-v1.json",
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
            cls.blueprints,
        )

    def builder_arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            registry=str(REGISTRY / "army-v1.json"),
            capabilities=str(REGISTRY / "capabilities-army-v1.json"),
            standard=str(REGISTRY / "qualification-standard-v1.json"),
            plans=str(REGISTRY / "qualification-plans-army-v1.json"),
            blueprints=str(REGISTRY / "candidate-blueprints-army-v1.json"),
            instructions=str(SOURCE / "instruction-bundle-v1.json"),
            knowledge=str(SOURCE / "knowledge-source-manifest-v1.json"),
            runtime=str(SOURCE / "runtime-config-v1.json"),
            tools=str(SOURCE / "tool-manifest-v1.json"),
        )

    def test_checked_catalogs_match_deterministic_builder(self) -> None:
        components, candidates = build_reports(self.builder_arguments())
        self.assertEqual(
            components,
            load_json(SOURCE / "candidate-components-v1.json"),
        )
        self.assertEqual(
            candidates,
            load_json(SOURCE / "candidate-implementations-v1.json"),
        )

    def test_candidate_is_structurally_complete_nonfixture(self) -> None:
        report = assess_candidate_onboarding(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            self.components,
            self.candidates,
        ).to_dict()
        self.assertEqual(report["status"], "candidate_component_complete")
        self.assertEqual(report["onboarding_effect"], "none")
        self.assertEqual(report["summary"]["candidate_count"], 1)
        self.assertEqual(report["summary"]["component_artifact_count"], 5)
        self.assertEqual(
            report["summary"]["nonfixture_complete_candidate_count"],
            1,
        )
        candidate = report["candidates"][0]
        self.assertEqual(candidate["candidate_id"], "development.passive-osint")
        self.assertEqual(candidate["lifecycle"], "development")
        self.assertEqual(candidate["runtime_class"], "model_agent")
        self.assertTrue(candidate["component_binding_complete"])
        self.assertTrue(candidate["nonfixture_component_binding_complete"])
        self.assertIn("can still lack provider", report["limitations"][1])

    def test_inventory_removes_one_implementation_gap_only(self) -> None:
        report = assess_candidate_inventory(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            self.candidates,
        ).to_dict()
        summary = report["summary"]
        self.assertEqual(report["status"], "candidate_implementation_incomplete")
        self.assertEqual(summary["specialist_count"], 348)
        self.assertEqual(summary["development_candidate_count"], 1)
        self.assertEqual(summary["profiles_with_nonfixture_candidates"], 1)
        self.assertEqual(summary["profile_implementation_gap_count"], 347)
        profile = next(
            item
            for item in report["profiles"]
            if item["profile_id"] == "AOE-GA-D01-S01"
        )
        self.assertFalse(profile["implementation_gap"])
        self.assertEqual(
            profile["candidate_inventory_state"],
            "development_candidate_catalogued",
        )

    def test_runtime_and_tool_surfaces_remain_disabled(self) -> None:
        by_type = {item.component_type: item for item in self.components.components}
        runtime = by_type["runtime_manifest"].specification
        self.assertEqual(runtime["provider_ref"], "unselected")
        self.assertEqual(runtime["model_ref"], "unselected")
        self.assertEqual(runtime["hosting_ref"], "unselected")
        self.assertFalse(runtime["execution_enabled"])
        self.assertFalse(runtime["network_access"])
        self.assertFalse(runtime["process_access"])
        tools = by_type["tool_policy"].specification
        self.assertEqual(tools["admission_mode"], "deny_all")
        self.assertEqual(tools["allowed_tool_count"], 0)
        self.assertFalse(tools["credential_access"])
        self.assertFalse(tools["target_access"])
        self.assertFalse(tools["network_access"])
        self.assertFalse(tools["execution_allowed"])

    def test_instruction_bundle_preserves_analysis_only_boundary(self) -> None:
        instructions = load_json(SOURCE / "instruction-bundle-v1.json")
        self.assertEqual(instructions["operating_mode"], "analysis_only")
        self.assertFalse(instructions["output_contract"]["finding_authority"])
        self.assertEqual(
            instructions["output_contract"]["maximum_autonomous_action_tier"],
            "R2",
        )
        prohibited = " ".join(instructions["prohibited_actions"])
        self.assertIn("active scanning", prohibited)
        self.assertIn("credential", prohibited)
        self.assertIn("exploitation", prohibited)

    def test_builder_rejects_enabled_or_selected_runtime(self) -> None:
        inputs = [
            load_json(REGISTRY / "army-v1.json"),
            load_json(REGISTRY / "capabilities-army-v1.json"),
            load_json(REGISTRY / "qualification-standard-v1.json"),
            load_json(REGISTRY / "qualification-plans-army-v1.json"),
            load_json(REGISTRY / "candidate-blueprints-army-v1.json"),
            load_json(SOURCE / "instruction-bundle-v1.json"),
            load_json(SOURCE / "knowledge-source-manifest-v1.json"),
            load_json(SOURCE / "runtime-config-v1.json"),
            load_json(SOURCE / "tool-manifest-v1.json"),
        ]
        for field, changed_value in (
            ("execution_enabled", True),
            ("network_access", True),
            ("provider_selection", "selected-provider"),
            ("model_selection", "selected-model"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(inputs)
                changed[7][field] = changed_value
                with self.assertRaisesRegex(ValueError, "Runtime config"):
                    build_catalogs(*changed)

    def test_builder_rejects_tool_or_retrieval_enablement(self) -> None:
        inputs = [
            load_json(REGISTRY / "army-v1.json"),
            load_json(REGISTRY / "capabilities-army-v1.json"),
            load_json(REGISTRY / "qualification-standard-v1.json"),
            load_json(REGISTRY / "qualification-plans-army-v1.json"),
            load_json(REGISTRY / "candidate-blueprints-army-v1.json"),
            load_json(SOURCE / "instruction-bundle-v1.json"),
            load_json(SOURCE / "knowledge-source-manifest-v1.json"),
            load_json(SOURCE / "runtime-config-v1.json"),
            load_json(SOURCE / "tool-manifest-v1.json"),
        ]
        changed = copy.deepcopy(inputs)
        changed[8]["execution_allowed"] = True
        with self.assertRaisesRegex(ValueError, "Tool manifest"):
            build_catalogs(*changed)
        changed = copy.deepcopy(inputs)
        changed[6]["retrieval_mode"] = "static_manifest"
        with self.assertRaisesRegex(ValueError, "Knowledge source"):
            build_catalogs(*changed)

    def test_builder_has_no_network_storage_or_execution_dependencies(self) -> None:
        path = ROOT / "scripts" / "build_passive_osint_development_candidate.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
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

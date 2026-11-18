"""Phase 155 implementation-ready Army v2 candidate blueprint coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_candidate_blueprints_v2 import build_catalog, build_schema, load_json
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_blueprints_v2 import (
    BLUEPRINT_DOMAIN,
    CATALOG_DOMAIN,
    REQUIRED_COMPONENT_IDS,
    REQUIRED_TEST_STAGES,
    CandidateBlueprintCatalogV2,
    load_candidate_blueprint_catalog_v2,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
REGISTRY_PATH = REGISTRY_DIR / "army-v2.json"
CAPABILITIES_PATH = REGISTRY_DIR / "capabilities-army-v2.json"
ROADMAP_PATH = REGISTRY_DIR / "army-expansion-roadmap-v1.json"
VECTORS_PATH = REGISTRY_DIR / "attack-vectors-v2.json"
STANDARD_PATH = REGISTRY_DIR / "qualification-standard-v2.json"
PLANS_PATH = REGISTRY_DIR / "qualification-plans-army-v2.json"
BLUEPRINTS_PATH = REGISTRY_DIR / "candidate-blueprints-army-v2.json"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "candidate-blueprint-catalog-v2.schema.json"


def rebind_blueprint(blueprint: dict[str, Any]) -> None:
    body = {key: value for key, value in blueprint.items() if key != "blueprint_sha256"}
    blueprint["blueprint_sha256"] = _canonical_sha256(
        {"domain": BLUEPRINT_DOMAIN, "blueprint": body}
    )


def rebind_catalog(document: dict[str, Any]) -> None:
    body = {key: value for key, value in document.items() if key != "catalog_sha256"}
    document["catalog_sha256"] = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})


class CandidateBlueprintsV2Phase155Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(CAPABILITIES_PATH, cls.registry)
        cls.roadmap = load_army_expansion_roadmap(ROADMAP_PATH)
        cls.vectors = load_attack_vector_catalog(
            VECTORS_PATH,
            cls.registry,
            cls.roadmap,
        )
        cls.standard = load_qualification_standard(
            STANDARD_PATH,
            cls.registry,
            cls.capabilities,
        )
        cls.plans = load_qualification_plan_catalog_v2(
            PLANS_PATH,
            cls.registry,
            cls.capabilities,
            cls.vectors,
            cls.standard,
        )
        cls.catalog = load_candidate_blueprint_catalog_v2(
            BLUEPRINTS_PATH,
            cls.registry,
            cls.capabilities,
            cls.vectors,
            cls.standard,
            cls.plans,
        )

    def load_changed(self, document: dict[str, Any]) -> CandidateBlueprintCatalogV2:
        return CandidateBlueprintCatalogV2.from_dict(
            document,
            self.registry,
            self.capabilities,
            self.vectors,
            self.standard,
            self.plans,
        )

    def test_checked_catalog_and_schema_match_deterministic_builder(self) -> None:
        expected = build_catalog(
            load_json(REGISTRY_PATH),
            load_json(CAPABILITIES_PATH),
            load_json(VECTORS_PATH),
            load_json(STANDARD_PATH),
            load_json(PLANS_PATH),
        )
        expected_catalog = self.load_changed(expected)
        self.assertEqual(
            BLUEPRINTS_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(build_schema(), ensure_ascii=True, indent=2) + "\n",
        )

    def test_catalog_is_complete_content_addressed_and_non_operational(self) -> None:
        document = self.catalog.to_dict()
        self.assertEqual(len(document["blueprints"]), 391)
        self.assertEqual(len(self.catalog.blueprints_by_profile_id), 391)
        self.assertEqual(
            document["catalog_sha256"],
            "sha256:450e625ff8fea6529ae99e129e41498d7eb20be8ecc1fb327e9b3be17559a966",
        )
        self.assertEqual(document["blueprint_status"], "defined_unimplemented")
        for field in (
            "qualification_effect",
            "routing_effect",
            "execution_effect",
            "deployment_effect",
        ):
            self.assertEqual(document[field], "none")
        self.assertEqual(document["required_component_ids"], list(REQUIRED_COMPONENT_IDS))
        self.assertEqual(document["required_test_stages"], list(REQUIRED_TEST_STAGES))

    def test_api_blueprint_has_implementable_exact_contracts(self) -> None:
        blueprint = self.catalog.blueprints_by_profile_id["AOE-GB-D06-S09"]
        self.assertEqual(blueprint["vector_id"], "AV-GB-D06-S09-01")
        self.assertEqual(
            blueprint["primary_capability_ids"],
            ["api.authorization.object-level"],
        )
        self.assertEqual(
            blueprint["supporting_capability_ids"],
            ["api.authorization.function-level", "army.gb.d06.s08"],
        )
        self.assertEqual(blueprint["independent_validator_id"], "AOE-HQ-34")
        self.assertIn(
            "api.authorization.object-level",
            blueprint["tool_adapter_requirements"][0],
        )
        self.assertTrue(any("hypotheses" in item for item in blueprint["output_contract"]))
        self.assertEqual(
            [item["stage"] for item in blueprint["test_requirements"]],
            list(REQUIRED_TEST_STAGES),
        )

    def test_high_consequence_blueprints_require_containment_and_restoration(self) -> None:
        for profile_id in ("AOE-GD-D24-S06", "AOE-GD-D25-S01"):
            with self.subTest(profile=profile_id):
                blueprint = self.catalog.blueprints_by_profile_id[profile_id]
                self.assertEqual(blueprint["independent_validator_id"], "AOE-HQ-33")
                self.assertTrue(
                    any(item["stage"] == "containment" for item in blueprint["test_requirements"])
                )
                self.assertTrue(
                    any("residual effects" in item for item in blueprint["restoration_contract"])
                )

    def test_coverage_summary_counts_every_component_and_test_contract(self) -> None:
        summary = self.catalog.coverage_summary
        self.assertEqual(summary["component_requirement_count"], 3910)
        self.assertEqual(summary["test_requirement_count"], 2346)
        for field, count in summary.items():
            if field not in {"component_requirement_count", "test_requirement_count"}:
                with self.subTest(field=field):
                    self.assertEqual(count, 391)

    def test_closed_schema_accepts_checked_catalog(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.catalog.to_dict())

    def test_rehashed_tool_capability_and_test_substitution_fail_closed(self) -> None:
        mutations = (
            ("tool_adapter_requirements", ["Substituted adapter."]),
            ("supporting_capability_ids", ["army.ga.d01.s04"]),
            ("test_requirements", []),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.catalog.to_dict())
                changed["blueprints"][0][field] = value
                rebind_blueprint(changed["blueprints"][0])
                rebind_catalog(changed)
                with self.assertRaisesRegex(
                    QualificationError,
                    "does not match reviewed inputs",
                ):
                    self.load_changed(changed)

    def test_stale_blueprint_and_catalog_hashes_fail_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["blueprints"][0]["blueprint_sha256"] = "sha256:" + ("0" * 64)
        rebind_catalog(changed)
        with self.assertRaisesRegex(QualificationError, "blueprint_sha256 is invalid"):
            self.load_changed(changed)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["limitations"][0] = "Changed limitation."
        with self.assertRaisesRegex(QualificationError, "hash does not match"):
            self.load_changed(changed)

    def test_reordering_and_binding_drift_fail_closed(self) -> None:
        changed = copy.deepcopy(self.catalog.to_dict())
        changed["blueprints"][0], changed["blueprints"][1] = (
            changed["blueprints"][1],
            changed["blueprints"][0],
        )
        rebind_catalog(changed)
        with self.assertRaisesRegex(QualificationError, "vector order"):
            self.load_changed(changed)

        changed = copy.deepcopy(self.catalog.to_dict())
        changed["vector_catalog_sha256"] = "sha256:" + ("0" * 64)
        rebind_catalog(changed)
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            self.load_changed(changed)

    def test_builder_and_loader_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_blueprints_v2.py",
            ROOT / "scripts" / "build_candidate_blueprints_v2.py",
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

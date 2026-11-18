"""Phase 156 commander queues and Army v2 work-package coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_implementation_program_v2 import (
    build_packages_schema,
    build_roadmap_schema,
)
from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_blueprints_v2 import load_candidate_blueprint_catalog_v2
from sunderkey.errors import QualificationError
from sunderkey.implementation_program_v2 import (
    PACKAGE_DOMAIN,
    ROADMAP_DOMAIN,
    VALIDATOR_CAPACITY,
    build_implementation_program_v2,
    load_implementation_work_package_catalog_v2,
    load_specialist_implementation_roadmap_v2,
)
from sunderkey.qualification import _canonical_sha256, load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
REGISTRY_PATH = REGISTRY_DIR / "army-v2.json"
CAPABILITIES_PATH = REGISTRY_DIR / "capabilities-army-v2.json"
D015_PATH = REGISTRY_DIR / "army-expansion-roadmap-v1.json"
VECTORS_PATH = REGISTRY_DIR / "attack-vectors-v2.json"
STANDARD_PATH = REGISTRY_DIR / "qualification-standard-v2.json"
PLANS_PATH = REGISTRY_DIR / "qualification-plans-army-v2.json"
BLUEPRINTS_PATH = REGISTRY_DIR / "candidate-blueprints-army-v2.json"
PACKAGES_PATH = REGISTRY_DIR / "implementation-work-packages-v2.json"
ROADMAP_PATH = REGISTRY_DIR / "specialist-implementation-roadmap-v2.json"
PACKAGES_SCHEMA_PATH = (
    REGISTRY_DIR / "schemas" / "implementation-work-package-catalog-v2.schema.json"
)
ROADMAP_SCHEMA_PATH = REGISTRY_DIR / "schemas" / "specialist-implementation-roadmap-v2.schema.json"


def rebind_package_catalog(document: dict[str, Any]) -> None:
    body = {key: value for key, value in document.items() if key != "catalog_sha256"}
    document["catalog_sha256"] = _canonical_sha256({"domain": PACKAGE_DOMAIN, "catalog": body})


def rebind_roadmap(document: dict[str, Any]) -> None:
    body = {key: value for key, value in document.items() if key != "roadmap_sha256"}
    document["roadmap_sha256"] = _canonical_sha256({"domain": ROADMAP_DOMAIN, "roadmap": body})


class ImplementationProgramV2Phase156Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(CAPABILITIES_PATH, cls.registry)
        cls.d015 = load_army_expansion_roadmap(D015_PATH)
        cls.vectors = load_attack_vector_catalog(
            VECTORS_PATH,
            cls.registry,
            cls.d015,
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
        cls.blueprints = load_candidate_blueprint_catalog_v2(
            BLUEPRINTS_PATH,
            cls.registry,
            cls.capabilities,
            cls.vectors,
            cls.standard,
            cls.plans,
        )
        cls.packages = load_implementation_work_package_catalog_v2(
            PACKAGES_PATH,
            cls.registry,
            cls.capabilities,
            cls.d015,
            cls.vectors,
            cls.plans,
            cls.blueprints,
        )
        cls.roadmap = load_specialist_implementation_roadmap_v2(
            ROADMAP_PATH,
            cls.packages,
            cls.registry,
            cls.capabilities,
            cls.d015,
            cls.vectors,
            cls.plans,
            cls.blueprints,
        )

    def test_checked_artifacts_and_schemas_match_deterministic_builder(self) -> None:
        expected_packages, expected_roadmap = build_implementation_program_v2(
            self.registry,
            self.capabilities,
            self.d015,
            self.vectors,
            self.plans,
            self.blueprints,
        )
        self.assertEqual(
            PACKAGES_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_packages, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            ROADMAP_PATH.read_text(encoding="utf-8"),
            json.dumps(expected_roadmap, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            PACKAGES_SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(build_packages_schema(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(
            ROADMAP_SCHEMA_PATH.read_text(encoding="utf-8"),
            json.dumps(build_roadmap_schema(), ensure_ascii=True, indent=2) + "\n",
        )

    def test_program_covers_every_specialist_and_commander(self) -> None:
        summary = self.packages.coverage_summary
        self.assertEqual(summary["package_count"], 391)
        self.assertEqual(summary["new_specialist_package_count"], 43)
        self.assertEqual(summary["command_count"], 25)
        self.assertEqual(summary["commander_queue_count"], 25)
        self.assertEqual(summary["collaboration_edge_count"], 782)
        self.assertEqual(summary["work_item_count"], 3128)
        self.assertEqual(summary["wave_count"], 30)
        self.assertEqual(len(self.roadmap.commander_queues), 25)

    def test_priority_order_and_formula_are_deterministic(self) -> None:
        scores = [item["priority_score"] for item in self.packages.packages]
        self.assertEqual(scores, sorted(scores, reverse=True))
        for index, package in enumerate(self.packages.packages, start=1):
            with self.subTest(profile=package["profile_id"]):
                self.assertEqual(package["priority_sequence"], index)
                self.assertEqual(
                    package["priority_score"],
                    package["risk_weight"]
                    + package["coverage_gain"]
                    + (6 - package["verification_cost"]),
                )

    def test_wave_capacity_and_command_deconfliction_hold(self) -> None:
        scheduled: list[str] = []
        for wave in self.roadmap.waves:
            with self.subTest(wave=wave["wave_id"]):
                self.assertLessEqual(len(wave["package_ids"]), 20)
                self.assertEqual(
                    len(wave["command_ids"]),
                    len(set(wave["command_ids"])),
                )
                for validator_id, load in wave["validator_load"].items():
                    self.assertLessEqual(load, VALIDATOR_CAPACITY[validator_id])
                scheduled.extend(wave["package_ids"])
        expected = {item["package_id"] for item in self.packages.packages}
        self.assertEqual(set(scheduled), expected)
        self.assertEqual(len(scheduled), len(set(scheduled)))

    def test_commander_queues_cover_each_package_once(self) -> None:
        queued = [
            package_id
            for queue in self.roadmap.commander_queues
            for package_id in queue["package_ids"]
        ]
        self.assertEqual(len(queued), 391)
        self.assertEqual(len(queued), len(set(queued)))
        self.assertTrue(
            all(
                queue["maximum_concurrent_packages"] == 1 for queue in self.roadmap.commander_queues
            )
        )

    def test_api_package_has_exact_ownership_collaboration_and_stage_dag(self) -> None:
        package = next(
            item for item in self.packages.packages if item["profile_id"] == "AOE-GB-D06-S09"
        )
        self.assertEqual(package["commander_profile_id"], "AOE-GB-D06-CMD")
        self.assertEqual(package["group_commander_profile_id"], "AOE-HQ-04")
        self.assertEqual(package["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(
            package["collaboration_package_ids"],
            ["IWP2-AOE-GB-D06-S08", "IWP2-AOE-GB-D06-S10"],
        )
        self.assertEqual(package["external_dependency_package_ids"], [])
        self.assertEqual(len(package["work_items"]), 8)
        self.assertEqual(
            package["work_items"][3]["dependency_work_item_ids"],
            ["IWI2-AOE-GB-D06-S09-02", "IWI2-AOE-GB-D06-S09-03"],
        )

    def test_program_has_no_operational_effect(self) -> None:
        for document in (self.packages.to_dict(), self.roadmap.to_dict()):
            for field in (
                "qualification_effect",
                "routing_effect",
                "execution_effect",
                "deployment_effect",
            ):
                self.assertEqual(document[field], "none")
        self.assertTrue(
            all(item["package_status"] == "scheduled_unassigned" for item in self.packages.packages)
        )

    def test_closed_schemas_accept_checked_artifacts(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        Draft202012Validator(json.loads(PACKAGES_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
            self.packages.to_dict()
        )
        Draft202012Validator(json.loads(ROADMAP_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
            self.roadmap.to_dict()
        )

    def test_rehashed_priority_and_queue_substitution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            changed_packages = copy.deepcopy(self.packages.to_dict())
            changed_packages["packages"][0]["priority_score"] -= 1
            rebind_package_catalog(changed_packages)
            temporary = Path(directory) / "packages.json"
            temporary.write_text(json.dumps(changed_packages), encoding="utf-8")
            with self.assertRaisesRegex(
                QualificationError,
                "does not match reviewed inputs",
            ):
                load_implementation_work_package_catalog_v2(
                    temporary,
                    self.registry,
                    self.capabilities,
                    self.d015,
                    self.vectors,
                    self.plans,
                    self.blueprints,
                )

            changed_roadmap = copy.deepcopy(self.roadmap.to_dict())
            changed_roadmap["commander_queues"][0]["package_ids"].reverse()
            rebind_roadmap(changed_roadmap)
            temporary_roadmap = Path(directory) / "roadmap.json"
            temporary_roadmap.write_text(
                json.dumps(changed_roadmap),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                QualificationError,
                "does not match reviewed inputs",
            ):
                load_specialist_implementation_roadmap_v2(
                    temporary_roadmap,
                    self.packages,
                    self.registry,
                    self.capabilities,
                    self.d015,
                    self.vectors,
                    self.plans,
                    self.blueprints,
                )

    def test_builder_and_loader_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "implementation_program_v2.py",
            ROOT / "scripts" / "build_implementation_program_v2.py",
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

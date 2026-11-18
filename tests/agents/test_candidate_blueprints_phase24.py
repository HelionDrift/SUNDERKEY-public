"""Phase 24 specialist candidate blueprint coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_candidate_blueprints import build_catalog
from sunderkey.candidate_blueprints import (
    REQUIRED_COMPONENT_IDS,
    CandidateBlueprintCatalog,
    CandidateBlueprintCoverageReport,
    assess_candidate_blueprint_coverage,
    compute_candidate_blueprint_sha256,
    load_candidate_blueprint_catalog,
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


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def rebind_blueprint(blueprint: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in blueprint.items()
        if key != "blueprint_sha256"
    }
    blueprint["blueprint_sha256"] = compute_candidate_blueprint_sha256(
        body
    )


class CandidateBlueprintsPhase24Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.capabilities = load_capability_catalog(
            CAPABILITY_PATH,
            cls.registry,
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

    def catalog_from(
        self,
        raw: dict[str, Any],
    ) -> CandidateBlueprintCatalog:
        return CandidateBlueprintCatalog.from_dict(
            raw,
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
        )

    def assess(self) -> CandidateBlueprintCoverageReport:
        return assess_candidate_blueprint_coverage(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
        )

    def test_catalog_covers_every_specialist_exactly_once(self) -> None:
        self.assertEqual(len(self.blueprints.blueprints), 348)
        self.assertEqual(len(self.blueprints.blueprints_by_profile_id), 348)
        self.assertEqual(
            len(
                {
                    blueprint.blueprint_sha256
                    for blueprint in self.blueprints.blueprints
                }
            ),
            348,
        )
        self.assertEqual(
            self.blueprints.required_component_ids,
            REQUIRED_COMPONENT_IDS,
        )

    def test_passive_osint_blueprint_binds_build_and_collaboration_contracts(
        self,
    ) -> None:
        blueprint = self.blueprints.blueprints_by_profile_id[
            "AOE-GA-D01-S01"
        ]
        body = blueprint.body()
        self.assertEqual(body["name"], "Passive OSINT")
        self.assertEqual(
            body["primary_capability_ids"],
            ["army.ga.d01.s01"],
        )
        self.assertEqual(
            body["scenario_family_id"],
            "qualification.aoe-ga-d01-s01",
        )
        self.assertEqual(len(body["required_gate_ids"]), 8)
        self.assertIn(
            "Mission Architecture",
            body["collaboration_contract"],
        )
        self.assertIn("scope token", body["command_boundary"])
        self.assertEqual(
            blueprint.blueprint_sha256,
            "sha256:059a69e45587cdffc4e0fcbc7451e887"
            "6590bf59fbb56c310116b7f4fe85bfbc",
        )

    def test_checked_in_catalog_matches_deterministic_builder(self) -> None:
        expected = build_catalog(
            load_json(REGISTRY_PATH),
            load_json(CAPABILITY_PATH),
            load_json(STANDARD_PATH),
            load_json(PLANS_PATH),
        )
        self.assertEqual(
            BLUEPRINTS_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            CandidateBlueprintCoverageReport.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "CBR-4C14BA0105FB554A77C9193A9789189D",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:4c14ba0105fb554a77c9193a9789189d"
            "2fd55bb1c7fdf89813747af7a18eeddf",
        )

    def test_report_exposes_complete_provider_neutral_build_contracts(
        self,
    ) -> None:
        document = self.assess().to_dict()
        self.assertEqual(document["status"], "blueprint_coverage_complete")
        self.assertEqual(document["blueprint_effect"], "none")
        self.assertEqual(
            document["summary"],
            {
                "group_count": 5,
                "command_count": 23,
                "specialist_count": 348,
                "blueprint_count": 348,
                "required_component_count_per_blueprint": 5,
                "total_component_requirement_count": 1740,
            },
        )
        self.assertEqual(len(document["groups"]), 5)
        self.assertEqual(len(document["commands"]), 23)
        self.assertEqual(len(document["profiles"]), 348)
        self.assertTrue(
            all(
                profile["required_component_ids"]
                == list(REQUIRED_COMPONENT_IDS)
                for profile in document["profiles"]
            )
        )

    def test_missing_blueprint_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["blueprints"].pop()
        with self.assertRaisesRegex(
            QualificationError,
            "must match all specialists",
        ):
            self.catalog_from(raw)

    def test_duplicate_profile_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["blueprints"].append(copy.deepcopy(raw["blueprints"][0]))
        with self.assertRaisesRegex(QualificationError, "duplicate profiles"):
            self.catalog_from(raw)

    def test_blueprint_hash_tampering_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["blueprints"][0]["blueprint_sha256"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            QualificationError,
            "blueprint_sha256 is invalid",
        ):
            self.catalog_from(raw)

    def test_rehashed_content_substitution_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["blueprints"][0]["allowed_actions"][0] = "Substituted action"
        rebind_blueprint(raw["blueprints"][0])
        with self.assertRaisesRegex(
            QualificationError,
            "does not match reviewed inputs",
        ):
            self.catalog_from(raw)

    def test_required_component_substitution_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["required_component_ids"][0:2] = [
            "instruction_bundle",
            "behavior_contract",
        ]
        with self.assertRaisesRegex(
            QualificationError,
            "required components are invalid",
        ):
            self.catalog_from(raw)

    def test_catalog_binding_mismatch_fails_closed(self) -> None:
        raw = self.blueprints.to_dict()
        raw["capability_catalog_version"] = "wrong"
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            self.catalog_from(raw)

    def test_report_rejects_tampering(self) -> None:
        document = self.assess().to_dict()
        document["summary"]["blueprint_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            CandidateBlueprintCoverageReport.from_dict(document)

    def test_coverage_does_not_mutate_registry(self) -> None:
        before = self.registry.to_dict()
        self.assess()
        self.assertEqual(self.registry.to_dict(), before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_blueprints.py",
            ROOT / "scripts" / "build_candidate_blueprints.py",
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

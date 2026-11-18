"""Phase 23 provider-neutral candidate inventory coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path
from typing import Any

from scripts.build_candidate_implementation_catalog import build_catalog
from sunderkey.candidate_blueprints import load_candidate_blueprint_catalog
from sunderkey.candidate_inventory import (
    CandidateImplementationCatalog,
    CandidateInventoryReport,
    assess_candidate_inventory,
    compute_candidate_artifact_sha256,
    load_candidate_implementation_catalog,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_evaluation import (
    load_qualification_evaluation_suite,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"
CANDIDATES_PATH = ROOT / "registry" / "candidate-implementations-v1.json"
BLUEPRINTS_PATH = ROOT / "registry" / "candidate-blueprints-army-v1.json"
COMPONENTS_PATH = ROOT / "registry" / "candidate-components-v1.json"
SUITE_PATH = (
    ROOT / "examples" / "qualification" / "passive-osint-suite.json"
)


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def rebind_candidate(candidate: dict[str, Any]) -> None:
    body = {
        key: value
        for key, value in candidate.items()
        if key != "candidate_artifact_sha256"
    }
    candidate["candidate_artifact_sha256"] = (
        compute_candidate_artifact_sha256(body)
    )


class CandidateInventoryPhase23Tests(unittest.TestCase):
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
        cls.candidates = load_candidate_implementation_catalog(
            CANDIDATES_PATH,
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
            cls.blueprints,
        )

    def catalog_from(
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

    def assess(
        self,
        catalog: CandidateImplementationCatalog | None = None,
    ) -> CandidateInventoryReport:
        return assess_candidate_inventory(
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
            self.blueprints,
            catalog or self.candidates,
        )

    def test_catalog_contains_only_the_explicit_contract_fixture(self) -> None:
        self.assertEqual(len(self.candidates.candidates), 1)
        candidate = self.candidates.candidates[0]
        self.assertEqual(candidate.candidate_id, "fixture.passive-osint")
        self.assertEqual(candidate.candidate_version, "1.0.0")
        self.assertEqual(candidate.profile_id, "AOE-GA-D01-S01")
        self.assertEqual(candidate.lifecycle, "contract_fixture")
        self.assertEqual(candidate.implementation_kind, "agent_bundle")
        self.assertEqual(
            candidate.candidate_artifact_sha256,
            "sha256:ba3d024191766c8471f1268ed465d88c"
            "986626bcd785a0b88dbad4ebc08672ee",
        )
        self.assertEqual(
            candidate.candidate_blueprint_sha256,
            self.blueprints.blueprints_by_profile_id[
                "AOE-GA-D01-S01"
            ].blueprint_sha256,
        )

    def test_checked_in_catalog_matches_deterministic_builder(self) -> None:
        expected = build_catalog(
            load_json(REGISTRY_PATH),
            load_json(CAPABILITY_PATH),
            load_json(STANDARD_PATH),
            load_json(PLANS_PATH),
            load_json(BLUEPRINTS_PATH),
            load_json(COMPONENTS_PATH),
        )
        self.assertEqual(
            CANDIDATES_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_qualification_fixture_binds_catalogued_candidate(self) -> None:
        suite = load_qualification_evaluation_suite(
            SUITE_PATH,
            self.registry,
            self.capabilities,
            self.standard,
            self.plans,
        )
        candidate = self.candidates.candidates[0]
        self.assertEqual(suite.candidate.candidate_id, candidate.candidate_id)
        self.assertEqual(
            suite.candidate.candidate_version,
            candidate.candidate_version,
        )
        self.assertEqual(
            suite.candidate.candidate_artifact_sha256,
            candidate.candidate_artifact_sha256,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.assess()
        second = self.assess()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(CandidateInventoryReport.from_dict(document), first)
        self.assertEqual(
            document["report_id"],
            "CIR-E38B4FC46D619A1B51D24866B74F72C3",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:e38b4fc46d619a1b51d24866b74f72c3"
            "4049aa17443940fd9f5313e67baef0ce",
        )

    def test_report_exposes_all_implementation_gaps(self) -> None:
        document = self.assess().to_dict()
        self.assertEqual(
            document["status"],
            "candidate_implementation_incomplete",
        )
        self.assertEqual(document["inventory_effect"], "none")
        self.assertEqual(
            document["summary"],
            {
                "group_count": 5,
                "command_count": 23,
                "specialist_count": 348,
                "catalog_candidate_count": 1,
                "contract_fixture_candidate_count": 1,
                "development_candidate_count": 0,
                "evaluation_candidate_count": 0,
                "retired_candidate_count": 0,
                "profiles_with_any_candidate": 1,
                "profiles_with_nonfixture_candidates": 0,
                "profiles_with_contract_fixture_only": 1,
                "profiles_with_retired_candidates_only": 0,
                "profiles_without_candidates": 347,
                "profile_implementation_gap_count": 348,
                "commands_with_nonfixture_candidates": 0,
                "commands_with_implementation_gaps": 23,
            },
        )
        passive = next(
            profile
            for profile in document["profiles"]
            if profile["profile_id"] == "AOE-GA-D01-S01"
        )
        self.assertEqual(
            passive["candidate_inventory_state"],
            "contract_fixture_only",
        )
        self.assertTrue(passive["implementation_gap"])

    def test_empty_catalog_is_valid_and_reports_every_profile_missing(
        self,
    ) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"] = []
        document = self.assess(self.catalog_from(raw)).to_dict()
        self.assertEqual(document["summary"]["catalog_candidate_count"], 0)
        self.assertEqual(document["summary"]["profiles_without_candidates"], 348)
        self.assertEqual(
            document["summary"]["profile_implementation_gap_count"],
            348,
        )

    def test_development_candidate_reduces_one_gap_without_qualification(
        self,
    ) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["lifecycle"] = "development"
        rebind_candidate(raw["candidates"][0])
        document = self.assess(self.catalog_from(raw)).to_dict()
        passive = next(
            profile
            for profile in document["profiles"]
            if profile["profile_id"] == "AOE-GA-D01-S01"
        )

        self.assertEqual(document["summary"]["development_candidate_count"], 1)
        self.assertEqual(
            document["summary"]["profile_implementation_gap_count"],
            347,
        )
        self.assertEqual(
            passive["candidate_inventory_state"],
            "development_candidate_catalogued",
        )
        self.assertFalse(passive["implementation_gap"])
        self.assertEqual(passive["registry_status"], "defined")

    def test_component_tampering_invalidates_artifact_identity(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["tool_policy_sha256"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(
            QualificationError,
            "candidate_artifact_sha256 is invalid",
        ):
            self.catalog_from(raw)

    def test_duplicate_candidate_id_fails_closed(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"].append(copy.deepcopy(raw["candidates"][0]))
        with self.assertRaisesRegex(QualificationError, "duplicate candidate IDs"):
            self.catalog_from(raw)

    def test_non_specialist_profile_fails_closed(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["profile_id"] = "AOE-GA-D01-CMD"
        rebind_candidate(raw["candidates"][0])
        with self.assertRaisesRegex(QualificationError, "reference a specialist"):
            self.catalog_from(raw)

    def test_catalog_binding_mismatch_fails_closed(self) -> None:
        raw = self.candidates.to_dict()
        raw["qualification_plan_catalog_version"] = "wrong"
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            self.catalog_from(raw)

    def test_candidate_blueprint_substitution_fails_closed(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["candidate_blueprint_sha256"] = (
            "sha256:" + ("0" * 64)
        )
        rebind_candidate(raw["candidates"][0])
        with self.assertRaisesRegex(
            QualificationError,
            "blueprint binding is invalid",
        ):
            self.catalog_from(raw)

    def test_unknown_lifecycle_fails_closed(self) -> None:
        raw = self.candidates.to_dict()
        raw["candidates"][0]["lifecycle"] = "deployed"
        rebind_candidate(raw["candidates"][0])
        with self.assertRaisesRegex(QualificationError, "lifecycle must be"):
            self.catalog_from(raw)

    def test_report_rejects_tampering(self) -> None:
        document = self.assess().to_dict()
        document["summary"]["profile_implementation_gap_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            CandidateInventoryReport.from_dict(document)

    def test_inventory_does_not_mutate_registry(self) -> None:
        before = self.registry.to_dict()
        self.assess()
        self.assertEqual(self.registry.to_dict(), before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "candidate_inventory.py",
            ROOT / "scripts" / "build_candidate_implementation_catalog.py",
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

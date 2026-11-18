"""Phase 41 Passive OSINT advisory evaluation pack coverage."""

from __future__ import annotations

import argparse
import ast
import copy
import json
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

from scripts.build_passive_osint_evaluation_suite import build_report, build_suite
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_evaluation import load_qualification_evaluation_suite
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


class PassiveOsintEvaluationPackPhase41Tests(unittest.TestCase):
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
        cls.suite = load_qualification_evaluation_suite(
            SOURCE / "evaluation-suite-v1.json",
            cls.registry,
            cls.capabilities,
            cls.standard,
            cls.plans,
        )
        cls.scenarios = load_json(SOURCE / "evaluation-scenarios-v1.json")

    def builder_arguments(self) -> argparse.Namespace:
        return argparse.Namespace(
            registry=str(REGISTRY / "army-v1.json"),
            capabilities=str(REGISTRY / "capabilities-army-v1.json"),
            standard=str(REGISTRY / "qualification-standard-v1.json"),
            plans=str(REGISTRY / "qualification-plans-army-v1.json"),
            candidates=str(SOURCE / "candidate-implementations-v1.json"),
            scenarios=str(SOURCE / "evaluation-scenarios-v1.json"),
        )

    def builder_inputs(self) -> list[dict[str, Any]]:
        return [
            load_json(REGISTRY / "army-v1.json"),
            load_json(REGISTRY / "capabilities-army-v1.json"),
            load_json(REGISTRY / "qualification-standard-v1.json"),
            load_json(REGISTRY / "qualification-plans-army-v1.json"),
            load_json(SOURCE / "candidate-implementations-v1.json"),
            load_json(SOURCE / "evaluation-scenarios-v1.json"),
        ]

    def test_checked_suite_matches_deterministic_builder(self) -> None:
        self.assertEqual(
            build_report(self.builder_arguments()),
            load_json(SOURCE / "evaluation-suite-v1.json"),
        )

    def test_suite_binds_exact_development_candidate(self) -> None:
        self.assertEqual(self.suite.suite_id, "development.passive-osint.qualification")
        self.assertEqual(self.suite.profile_id, "AOE-GA-D01-S01")
        self.assertEqual(
            self.suite.candidate.to_dict(),
            {
                "candidate_id": "development.passive-osint",
                "candidate_version": "1.0.0",
                "candidate_artifact_sha256": (
                    "sha256:faf1afbbaba455b9c4d5a02faaa80b0d3b0f04780fe65a89583087e8b7d0605e"
                ),
            },
        )

    def test_pack_has_exact_minimum_gate_coverage(self) -> None:
        expected = {gate.id: gate.minimum_scenarios for gate in self.standard.gates}
        counts = Counter(case.gate_id for case in self.suite.cases)
        self.assertEqual(counts, expected)
        self.assertEqual(len(self.suite.cases), 29)
        for gate_id, count in expected.items():
            with self.subTest(gate_id=gate_id):
                ordinals = [case.ordinal for case in self.suite.cases if case.gate_id == gate_id]
                self.assertEqual(ordinals, list(range(1, count + 1)))

    def test_source_pack_contains_no_observations_or_result_claims(self) -> None:
        self.assertEqual(self.scenarios["observation_status"], "not_run")
        self.assertTrue(self.scenarios["advisory_only"])
        self.assertEqual(self.scenarios["suite_mode"], "synthetic")
        prohibited_fields = {
            "observation",
            "observations",
            "outcome",
            "result",
            "results",
            "passed",
            "score",
        }
        for case in self.scenarios["cases"]:
            with self.subTest(case_id=case["case_id"]):
                self.assertFalse(set(case) & prohibited_fields)
                self.assertTrue(case["expected_behaviors"])
                self.assertTrue(case["prohibited_behaviors"])
                self.assertTrue(case["critical_failure"])

    def test_pack_preserves_stop_scope_and_data_boundaries(self) -> None:
        by_id = {case["case_id"]: case for case in self.scenarios["cases"]}
        self.assertIn(
            "expands scope",
            by_id["QCASE-AOE-GA-D01-S01-ADV-01"]["critical_failure"],
        )
        self.assertIn(
            "active target interaction",
            by_id["QCASE-AOE-GA-D01-S01-STOP-02"]["critical_failure"],
        )
        self.assertIn(
            "R2 ceiling",
            by_id["QCASE-AOE-GA-D01-S01-SCOPE-03"]["critical_failure"],
        )
        self.assertIn(
            "credential-like material",
            by_id["QCASE-AOE-GA-D01-S01-TOOL-02"]["critical_failure"],
        )

    def test_builder_rejects_candidate_binding_mismatch(self) -> None:
        changed = copy.deepcopy(self.builder_inputs())
        changed[5]["candidate"]["candidate_version"] = "2.0.0"
        with self.assertRaisesRegex(ValueError, "candidate binding"):
            build_suite(*changed)

    def test_builder_rejects_incomplete_or_noncontiguous_gate_cases(self) -> None:
        for mutation in ("missing", "ordinal"):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(self.builder_inputs())
                if mutation == "missing":
                    changed[5]["cases"].pop(0)
                    message = "Scenario count"
                else:
                    changed[5]["cases"][0]["ordinal"] = 2
                    message = "ordinals"
                with self.assertRaisesRegex(ValueError, message):
                    build_suite(*changed)

    def test_builder_has_no_network_storage_or_execution_dependencies(self) -> None:
        path = ROOT / "scripts" / "build_passive_osint_evaluation_suite.py"
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

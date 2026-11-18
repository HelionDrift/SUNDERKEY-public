"""Phase 22 advisory qualification evaluation coverage."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

from scripts.build_qualification_contract_fixture import build_fixture
from sunderkey.errors import QualificationError
from sunderkey.qualification import (
    load_qualification_plan_catalog,
    load_qualification_standard,
)
from sunderkey.qualification_evaluation import (
    QualificationEvaluationReport,
    QualificationEvaluationSuite,
    QualificationObservationSet,
    evaluate_qualification_observations,
    load_qualification_evaluation_suite,
    load_qualification_observation_set,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
CAPABILITY_PATH = ROOT / "registry" / "capabilities-army-v1.json"
STANDARD_PATH = ROOT / "registry" / "qualification-standard-v1.json"
PLANS_PATH = ROOT / "registry" / "qualification-plans-army-v1.json"
SUITE_PATH = (
    ROOT / "examples" / "qualification" / "passive-osint-suite.json"
)
OBSERVATIONS_PATH = (
    ROOT
    / "examples"
    / "qualification"
    / "passive-osint-observations.json"
)
CANDIDATES_PATH = ROOT / "registry" / "candidate-implementations-v1.json"


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


class QualificationEvaluationPhase22Tests(unittest.TestCase):
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
        cls.suite = load_qualification_evaluation_suite(
            SUITE_PATH,
            cls.registry,
            cls.catalog,
            cls.standard,
            cls.plans,
        )
        cls.observations = load_qualification_observation_set(
            OBSERVATIONS_PATH,
            cls.suite,
        )

    def suite_from(self, raw: dict[str, object]) -> QualificationEvaluationSuite:
        return QualificationEvaluationSuite.from_dict(
            raw,
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
        )

    def observations_from(
        self,
        raw: dict[str, object],
    ) -> QualificationObservationSet:
        return QualificationObservationSet.from_dict(raw, self.suite)

    def evaluate(
        self,
        observations: QualificationObservationSet | None = None,
    ) -> QualificationEvaluationReport:
        return evaluate_qualification_observations(
            self.registry,
            self.catalog,
            self.standard,
            self.plans,
            self.suite,
            observations or self.observations,
        )

    def test_fixture_covers_every_gate_with_contiguous_ordinals(self) -> None:
        self.assertEqual(len(self.suite.cases), 29)
        self.assertEqual(len(self.suite.cases_by_id), 29)
        self.assertEqual(
            {case.gate_id for case in self.suite.cases},
            set(self.standard.gate_ids),
        )
        for gate in self.standard.gates:
            cases = [
                case for case in self.suite.cases if case.gate_id == gate.id
            ]
            with self.subTest(gate=gate.id):
                self.assertEqual(len(cases), gate.minimum_scenarios)
                self.assertEqual(
                    [case.ordinal for case in cases],
                    list(range(1, len(cases) + 1)),
                )

    def test_observation_fixture_matches_every_case(self) -> None:
        self.assertEqual(len(self.observations.observations), 29)
        self.assertEqual(
            set(self.observations.observations_by_case_id),
            set(self.suite.cases_by_id),
        )

    def test_checked_in_fixture_matches_deterministic_builder(self) -> None:
        suite, observations = build_fixture(
            load_json(REGISTRY_PATH),
            load_json(CAPABILITY_PATH),
            load_json(STANDARD_PATH),
            load_json(PLANS_PATH),
            load_json(CANDIDATES_PATH),
        )
        expected_suite = json.dumps(
            suite,
            ensure_ascii=True,
            indent=2,
        ) + "\n"
        expected_observations = json.dumps(
            observations,
            ensure_ascii=True,
            indent=2,
        ) + "\n"
        self.assertEqual(
            SUITE_PATH.read_text(encoding="utf-8"),
            expected_suite,
        )
        self.assertEqual(
            OBSERVATIONS_PATH.read_text(encoding="utf-8"),
            expected_observations,
        )

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.evaluate()
        second = self.evaluate()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            QualificationEvaluationReport.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "QER-3465849118A35F60DED12AB5BB702F72",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:3465849118a35f60ded12ab5bb702f72"
            "25b62996b72ef38847e260e5bf7994e8",
        )

    def test_report_is_advisory_and_has_no_qualification_effect(self) -> None:
        document = self.evaluate().to_dict()
        self.assertEqual(document["status"], "advisory_thresholds_met")
        self.assertTrue(document["advisory_only"])
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(
            document["independent_review_evaluation_state"],
            "not_performed",
        )
        self.assertEqual(
            document["summary"],
            {
                "gate_count": 8,
                "gates_meeting_advisory_thresholds": 8,
                "gates_not_meeting_advisory_thresholds": 0,
                "case_count": 29,
                "passed_count": 29,
                "failed_count": 0,
                "critical_failure_count": 0,
            },
        )

    def test_missing_observation_fails_closed(self) -> None:
        raw = self.observations.to_dict()
        raw["observations"].pop()
        with self.assertRaisesRegex(
            QualificationError,
            "must match every suite case",
        ):
            self.observations_from(raw)

    def test_duplicate_case_fails_closed(self) -> None:
        raw = self.suite.to_dict()
        raw["cases"].append(copy.deepcopy(raw["cases"][0]))
        with self.assertRaisesRegex(QualificationError, "duplicate case IDs"):
            self.suite_from(raw)

    def test_unknown_gate_fails_closed(self) -> None:
        raw = self.suite.to_dict()
        raw["cases"][0]["gate_id"] = "qualification.gate.unknown"
        with self.assertRaisesRegex(QualificationError, "unknown gate"):
            self.suite_from(raw)

    def test_production_environment_fails_closed(self) -> None:
        raw = self.suite.to_dict()
        raw["cases"][0]["environment"] = "production"
        with self.assertRaisesRegex(QualificationError, "not allowed"):
            self.suite_from(raw)

    def test_non_advisory_suite_fails_closed(self) -> None:
        raw = self.suite.to_dict()
        raw["advisory_only"] = False
        with self.assertRaisesRegex(QualificationError, "advisory_only"):
            self.suite_from(raw)

    def test_pass_with_critical_failure_fails_closed(self) -> None:
        raw = self.observations.to_dict()
        raw["observations"][0]["critical_failure"] = True
        with self.assertRaisesRegex(
            QualificationError,
            "cannot pass with a critical failure",
        ):
            self.observations_from(raw)

    def test_critical_failure_prevents_advisory_threshold_success(self) -> None:
        raw = self.observations.to_dict()
        raw["observations"][0]["outcome"] = "fail"
        raw["observations"][0]["critical_failure"] = True
        observations = self.observations_from(raw)
        document = self.evaluate(observations).to_dict()

        self.assertEqual(
            document["status"],
            "advisory_thresholds_not_met",
        )
        self.assertEqual(
            document["summary"]["gates_not_meeting_advisory_thresholds"],
            1,
        )
        self.assertEqual(document["summary"]["critical_failure_count"], 1)

    def test_candidate_binding_mismatch_fails_closed(self) -> None:
        raw = self.observations.to_dict()
        raw["candidate"]["candidate_version"] = "2.0.0"
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            self.observations_from(raw)

    def test_suite_catalog_binding_mismatch_fails_closed(self) -> None:
        raw = self.suite.to_dict()
        raw["capability_catalog_version"] = "wrong"
        with self.assertRaisesRegex(QualificationError, "binding is invalid"):
            self.suite_from(raw)

    def test_report_rejects_tampering(self) -> None:
        document = self.evaluate().to_dict()
        document["summary"]["passed_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            QualificationEvaluationReport.from_dict(document)

    def test_evaluation_does_not_mutate_registry_status(self) -> None:
        before = self.registry.to_dict()
        self.evaluate()
        self.assertEqual(self.registry.to_dict(), before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        for path in (
            ROOT / "src" / "sunderkey" / "qualification_evaluation.py",
            ROOT / "scripts" / "build_qualification_contract_fixture.py",
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

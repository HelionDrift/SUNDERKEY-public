"""The pattern fixture command publishes only a complete unsigned result."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import run_offline_pattern_task_relations as command
from sunderkey.offline_pattern_task_relations import (
    PatternTaskRelationsError,
    parse_supplied_pattern_task_relations_plan,
)
from tests.agents.test_offline_pattern_task_relations import (
    expanded_plan_fixture,
    expanded_task_fixture,
    plan_fixture,
    task_fixture,
    twelve_plan_fixture,
    twelve_task_fixture,
    sixteen_plan_fixture,
    sixteen_task_fixture,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "examples/offline-pattern-task-relations.json"
TASK = ROOT / "examples/offline-pattern-task-inputs.json"


class PatternTaskRelationsCliTests(unittest.TestCase):
    def invoke(
        self, plan: Path, task: Path, report: Path | None = None
    ) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--plan-fixture", str(plan), "--task-fixture", str(task)]
        if report is not None:
            argv.extend(("--verify-report-fixture", str(report)))
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = command.main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_checked_fixtures_match_original_models_without_dynamic_results(self) -> None:
        self.assertEqual(json.loads(PLAN.read_text(encoding="utf-8")), plan_fixture())
        self.assertEqual(json.loads(TASK.read_text(encoding="utf-8")), task_fixture())
        for path in (PLAN, TASK):
            content = path.read_text(encoding="utf-8")
            for prefix in ("OSC-", "OST-", "PTR-"):
                self.assertNotIn(prefix, content)

    def test_real_command_prints_only_complete_bounded_relation(self) -> None:
        completed = subprocess.run(
            [
                sys.executable, "-B", str(ROOT / "scripts/run_offline_pattern_task_relations.py"),
                "--plan-fixture", str(PLAN), "--task-fixture", str(TASK),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        report = json.loads(completed.stdout)
        self.assertEqual(report["premise_count"], 3)
        self.assertEqual(report["hypothesis_status"], "matches_declared_expectation")
        self.assertEqual({row["status"] for row in report["premises"]},
                         {"matches_declared_expectation"})
        self.assertEqual(set(report["operational_effects"].values()), {"none"})
        self.assertFalse(report["scope_equivalence_proven"])
        self.assertFalse(report["positive_use_approved"])
        self.assertFalse(report["qualification_claimed"])

    def test_invalid_plan_and_source_prejoin_publish_no_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            invalid_plan = path / "invalid-plan.json"
            invalid_plan.write_bytes(b'{"schema_version":1,"schema_version":1}')
            with patch.object(
                command.components,
                "load_offline_specialist_component_catalog",
                side_effect=AssertionError("catalog must not load"),
            ):
                code, stdout, stderr = self.invoke(invalid_plan, TASK)
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("Duplicate plan member", stderr)

            changed_task = copy.deepcopy(task_fixture())
            changed_task["jobs"][0]["request"]["payload"]["model"]["queries"][0][
                "execution_declared"
            ] = False
            task_path = path / "changed-task.json"
            task_path.write_text(json.dumps(changed_task), encoding="utf-8")
            with patch.object(
                command.components,
                "load_offline_specialist_component_catalog",
                side_effect=AssertionError("catalog must not load"),
            ):
                code, stdout, stderr = self.invoke(PLAN, task_path)
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("source digest differs", stderr)

    def test_parser_rejects_nonfinite_and_oversize_plan(self) -> None:
        for raw in (b'NaN', b'Infinity', b'{' + b' ' * 32_768 + b'}'):
            with self.subTest(raw=raw[:16]):
                with self.assertRaises(PatternTaskRelationsError):
                    parse_supplied_pattern_task_relations_plan(raw)

    def test_six_source_plan_uses_same_stdout_only_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task_path = Path(directory) / "six-job-task.json"
            task_path.write_text(json.dumps(expanded_task_fixture()), encoding="utf-8")
            plan = ROOT / "examples/offline-pattern-task-relations-expanded.json"
            self.assertEqual(json.loads(plan.read_text(encoding="utf-8")),
                             expanded_plan_fixture())
            code, stdout, stderr = self.invoke(plan, task_path)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        body = json.loads(stdout)
        self.assertEqual(body["premise_count"], 6)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["positive_use_approved"])

    def test_twelve_source_plan_uses_same_stdout_only_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task_path = Path(directory) / "twelve-job-task.json"
            task_path.write_text(json.dumps(twelve_task_fixture()), encoding="utf-8")
            plan = ROOT / "examples/offline-pattern-task-relations-twelve.json"
            self.assertEqual(json.loads(plan.read_text(encoding="utf-8")),
                             twelve_plan_fixture())
            code, stdout, stderr = self.invoke(plan, task_path)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        body = json.loads(stdout)
        self.assertEqual(body["premise_count"], 12)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["qualification_claimed"])

    def test_sixteen_source_plan_uses_same_stdout_only_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task_path = Path(directory) / "sixteen-job-task.json"
            task_path.write_text(json.dumps(sixteen_task_fixture()), encoding="utf-8")
            plan = ROOT / "examples/offline-pattern-task-relations-sixteen.json"
            self.assertEqual(json.loads(plan.read_text(encoding="utf-8")),
                             sixteen_plan_fixture())
            code, stdout, stderr = self.invoke(plan, task_path)
        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        body = json.loads(stdout)
        self.assertEqual(body["premise_count"], 16)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["qualification_claimed"])

    def test_saved_report_replays_and_tampering_publishes_nothing(self) -> None:
        code, stdout, stderr = self.invoke(PLAN, TASK)
        self.assertEqual(code, 0, stderr)
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "saved-relation.json"
            report_path.write_text(stdout, encoding="utf-8")
            code, verified, stderr = self.invoke(PLAN, TASK, report_path)
            self.assertEqual(code, 0, stderr)
            self.assertEqual(verified, stdout)
            tampered = json.loads(stdout)
            tampered["positive_use_approved"] = True
            report_path.write_text(json.dumps(tampered), encoding="utf-8")
            code, verified, stderr = self.invoke(PLAN, TASK, report_path)
        self.assertEqual(code, 2)
        self.assertEqual(verified, "")
        self.assertIn("Report differs", stderr)


if __name__ == "__main__":
    unittest.main()

"""Closed explicit relation fixtures and complete-result-only stdout boundaries."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import run_offline_specialist_task_relations as command
from sunderkey.offline_specialist_components import PROFILE_DEFAULT_COMPONENTS
from sunderkey.offline_specialist_task_relations import (
    MAX_MODEL_BYTES,
    OfflineSpecialistTaskRelationsError,
    analyze_offline_specialist_task_relations,
    component_fixture,
    parse_offline_specialist_task_relations_model,
    task_fixture,
)

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "examples" / "offline-specialist-task-relations.json"
TASK = ROOT / "examples" / "offline-specialist-task-relation-inputs.json"


class OfflineSpecialistTaskRelationsCliTests(unittest.TestCase):
    def invoke(self, plan: Path, task: Path) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = command.main(["--plan-fixture", str(plan), "--task-fixture", str(task)])
        return code, stdout.getvalue(), stderr.getvalue()

    def write_fixture(self, directory: str, name: str, value: dict | bytes) -> Path:
        content = value if type(value) is bytes else json.dumps(value).encode("ascii")
        path = Path(directory) / name
        path.write_bytes(content)
        return path

    def test_checked_examples_are_fresh_hash_free_and_preserve_fixed_defaults(self) -> None:
        self.assertEqual(json.loads(PLAN.read_text(encoding="ascii")), component_fixture())
        self.assertEqual(json.loads(TASK.read_text(encoding="ascii")), task_fixture())
        for path in (PLAN, TASK):
            content = path.read_text(encoding="ascii")
            for prefix in ("OSC-", "OST-", "OTR-"):
                self.assertNotIn(prefix, content)
        for job in task_fixture()["jobs"]:
            request = job["request"]
            self.assertEqual(
                request["component_id"], PROFILE_DEFAULT_COMPONENTS[request["profile_id"]]
            )
            self.assertEqual(
                set(request["resources"]), {"network", "filesystem", "process", "credential"}
            )
            self.assertTrue(all(not values for values in request["resources"].values()))

    def test_real_cli_matches_separate_original_current_derivation(self) -> None:
        plan = parse_offline_specialist_task_relations_model(PLAN.read_bytes())
        task_model = command.load_offline_specialist_task_model(TASK)
        catalog = command.load_offline_specialist_component_catalog(repository_root=ROOT)
        parent = command.run_offline_specialist_task(
            task_model, catalog=catalog, repository_root=ROOT
        )
        expected = analyze_offline_specialist_task_relations(
            plan, task_report=parent, task_model=task_model, catalog=catalog, repository_root=ROOT
        ).to_dict()
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "run_offline_specialist_task_relations.py"),
                "--plan-fixture",
                str(PLAN),
                "--task-fixture",
                str(TASK),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(json.loads(completed.stdout), expected)
        self.assertEqual(expected["task_binding"]["job_count"], 2)
        self.assertEqual(len(expected["premise_observations"]), 4)
        self.assertEqual(expected["evaluation_order"], ["known", "unknown", "overall"])
        self.assertEqual(set(expected["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in expected["flags"].values()))

    def test_invalid_dag_denies_before_catalog_or_initial_composition(self) -> None:
        cases = []
        cycle = component_fixture()
        cycle["hypotheses"][0]["dependencies"] = [{"kind": "hypothesis", "id": "known"}]
        cases.append(cycle)
        missing = component_fixture()
        missing["hypotheses"][0]["dependencies"] = [{"kind": "premise", "id": "absent"}]
        cases.append(missing)
        open_plan = component_fixture()
        open_plan["target_authorized"] = True
        cases.append(open_plan)
        with tempfile.TemporaryDirectory() as directory:
            for value in cases:
                with self.subTest(value=value):
                    path = self.write_fixture(directory, "plan.json", value)
                    with patch.object(
                        command, "load_offline_specialist_component_catalog"
                    ) as catalog:
                        with patch.object(command, "run_offline_specialist_task") as compose:
                            code, stdout, stderr = self.invoke(path, TASK)
                            catalog.assert_not_called()
                            compose.assert_not_called()
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertTrue(stderr.startswith("Validation error:"))

    def test_absent_original_joins_deny_before_any_initial_dispatch(self) -> None:
        cases = []
        absent_job = task_fixture()
        absent_job["jobs"][0]["job_id"] = "different-job"
        cases.append(absent_job)
        wrong_selector = task_fixture()
        wrong_selector["jobs"][0]["request"]["component_id"] = "different-component"
        cases.append(wrong_selector)
        absent_flow = task_fixture()
        absent_flow["jobs"][0]["request"]["payload"]["model"]["flows"] = []
        cases.append(absent_flow)
        alias_profile = task_fixture()
        alias_profile["jobs"][0]["request"]["profile_id"] = []
        cases.append(alias_profile)
        alias_selector = task_fixture()
        alias_selector["jobs"][0]["request"]["component_id"] = []
        cases.append(alias_selector)
        wrong_profile = task_fixture()
        wrong_profile["jobs"][0]["request"]["profile_id"] = "AOE-GC-D14-S05"
        cases.append(wrong_profile)
        duplicate_flow = task_fixture()
        flows = duplicate_flow["jobs"][0]["request"]["payload"]["model"]["flows"]
        flows.append(dict(flows[0]))
        cases.append(duplicate_flow)
        with tempfile.TemporaryDirectory() as directory:
            for value in cases:
                with self.subTest(value=value):
                    path = self.write_fixture(directory, "task.json", value)
                    with patch.object(
                        command, "load_offline_specialist_component_catalog"
                    ) as catalog:
                        with patch.object(command, "run_offline_specialist_task") as compose:
                            code, stdout, stderr = self.invoke(PLAN, path)
                            catalog.assert_not_called()
                            compose.assert_not_called()
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertTrue(stderr.startswith("Validation error:"))

    def test_later_resource_grant_denies_before_any_leaf_or_success_stdout(self) -> None:
        model = task_fixture()
        model["jobs"][-1]["request"]["resources"]["network"] = ["not-an-authorized-endpoint"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(directory, "task.json", model)
            with patch(
                "sunderkey.offline_specialist_task.components.run_offline_specialist_component"
            ) as leaf:
                code, stdout, stderr = self.invoke(PLAN, path)
                leaf.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_duplicate_raw_keys_and_oversized_plan_deny_before_composition(self) -> None:
        values = [b'{"schema_version":1,"schema_version":1}', b" " * (MAX_MODEL_BYTES + 1)]
        with tempfile.TemporaryDirectory() as directory:
            for content in values:
                with self.subTest(length=len(content)):
                    path = self.write_fixture(directory, "plan.json", content)
                    with patch.object(command, "run_offline_specialist_task") as compose:
                        code, stdout, stderr = self.invoke(path, TASK)
                        compose.assert_not_called()
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertTrue(stderr.startswith("Validation error:"))

    def test_missing_and_directory_inputs_publish_no_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for plan, task in (
                (Path(directory) / "missing", TASK),
                (Path(directory), TASK),
                (PLAN, Path(directory) / "missing"),
            ):
                with self.subTest(plan=plan, task=task):
                    code, stdout, stderr = self.invoke(plan, task)
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertTrue(stderr.startswith("Validation error:"))

    def test_relation_export_failure_publishes_no_partial_stdout(self) -> None:
        result = Mock()
        result.to_json.side_effect = OfflineSpecialistTaskRelationsError(
            "No bounded complete relation"
        )
        with patch.object(
            command, "load_offline_specialist_component_catalog", return_value=Mock()
        ):
            with patch.object(command, "run_offline_specialist_task", return_value=Mock()):
                with patch.object(
                    command, "analyze_offline_specialist_task_relations", return_value=result
                ):
                    code, stdout, stderr = self.invoke(PLAN, TASK)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_unexpected_programming_failures_are_not_input_verdicts(self) -> None:
        for family in (TypeError, RuntimeError):
            with self.subTest(family=family):
                with patch.object(
                    command, "load_offline_specialist_component_catalog", side_effect=family("bug")
                ):
                    with self.assertRaises(family):
                        self.invoke(PLAN, TASK)

    def test_unknown_execution_option_denies_without_stdout(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as stopped:
                command.main(
                    ["--plan-fixture", str(PLAN), "--task-fixture", str(TASK), "--grant-execution"]
                )
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unrecognized arguments", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

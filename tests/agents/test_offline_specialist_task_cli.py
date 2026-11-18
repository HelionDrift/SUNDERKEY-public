"""Explicit inert fixture intake and complete-result-only task CLI regressions."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from scripts import run_offline_specialist_task as command
from sunderkey.offline_specialist_components import MAX_REQUEST_BYTES
from sunderkey.offline_specialist_task import (
    OfflineSpecialistTaskError,
    load_offline_specialist_task_model,
    run_offline_specialist_task,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "offline-specialist-task.json"


class OfflineSpecialistTaskCliTests(unittest.TestCase):
    def invoke(self, path: Path) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            code = command.main(["--input-fixture", str(path)])
        return code, stdout.getvalue(), stderr.getvalue()

    def write_fixture(self, directory: str, value: dict | bytes) -> Path:
        path = Path(directory) / "task.json"
        content = value if type(value) is bytes else json.dumps(value).encode("utf-8")
        path.write_bytes(content)
        return path

    def test_checked_example_real_cli_matches_pure_task_composition(self) -> None:
        model = load_offline_specialist_task_model(EXAMPLE)
        catalog = command.load_offline_specialist_component_catalog(repository_root=ROOT)
        expected = run_offline_specialist_task(
            model, catalog=catalog, repository_root=ROOT
        ).to_dict()
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "run_offline_specialist_task.py"),
                "--input-fixture",
                str(EXAMPLE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        self.assertEqual(json.loads(completed.stdout), expected)
        self.assertEqual(expected["job_count"], 3)
        self.assertEqual(expected["distinct_component_count"], 3)
        self.assertEqual(expected["distinct_profile_count"], 3)
        self.assertEqual(set(expected["operational_effects"].values()), {"none"})

    def test_later_resource_grant_rejects_before_any_analysis_or_stdout(self) -> None:
        model = load_offline_specialist_task_model(EXAMPLE)
        model["jobs"][-1]["request"]["resources"]["credential"] = ["env:NO_KEY"]
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(directory, model)
            with patch(
                "sunderkey.offline_specialist_task.components.run_offline_specialist_component"
            ) as run:
                code, stdout, stderr = self.invoke(path)
                run.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_leaf_semantic_failure_publishes_no_partial_stdout(self) -> None:
        model = load_offline_specialist_task_model(EXAMPLE)
        changed = copy.deepcopy(model)
        changed["jobs"][0]["request"]["payload"]["model"]["schema_version"] = True
        with tempfile.TemporaryDirectory() as directory:
            code, stdout, stderr = self.invoke(self.write_fixture(directory, changed))
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_duplicate_raw_keys_publish_no_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(directory, b'{"schema_version":1,"schema_version":1}')
            code, stdout, stderr = self.invoke(path)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_missing_fixture_publishes_no_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, stdout, stderr = self.invoke(Path(directory) / "missing.json")
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_oversized_regular_fixture_publishes_no_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_fixture(directory, b" " * (MAX_REQUEST_BYTES + 1))
            code, stdout, stderr = self.invoke(path)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_serialization_failure_publishes_no_stdout(self) -> None:
        result = Mock()
        result.to_json.side_effect = OfflineSpecialistTaskError("No complete bounded report")
        with patch.object(command, "run_offline_specialist_task", return_value=result):
            code, stdout, stderr = self.invoke(EXAMPLE)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertTrue(stderr.startswith("Validation error:"))

    def test_unknown_option_rejects_without_stdout(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            with self.assertRaises(SystemExit) as stopped:
                command.main(["--input-fixture", str(EXAMPLE), "--grant-execution"])
        self.assertEqual(stopped.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("unrecognized arguments", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

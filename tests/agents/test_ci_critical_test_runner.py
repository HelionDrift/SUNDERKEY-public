"""Check the fast CI release-version preflight."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import run_ci_critical_tests, run_ci_test_shard


class CriticalTestRunnerTests(unittest.TestCase):
    def test_manifest_checks_complete_discovery_without_running_tests(self) -> None:
        selector = "tests.agents.test_example.ExampleTests.test_case"

        class ExampleTests(unittest.TestCase):
            def test_case(self) -> None:
                self.fail("Manifest check must not execute this body")

        case = ExampleTests("test_case")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "test_example.py").write_text("", encoding="utf-8")
            with (
                patch.object(run_ci_critical_tests, "CORE_TESTS", (selector,)),
                patch.object(run_ci_critical_tests, "OFFLINE_COMPONENT_TESTS", ()),
                patch.object(run_ci_critical_tests, "OPTIONAL_TESTS", ()),
                patch.object(run_ci_critical_tests, "TESTS_DIRECTORY", directory),
                patch.object(
                    run_ci_critical_tests, "check_release_version_assertions", return_value=True
                ),
                patch.object(run_ci_test_shard, "discover_cases", return_value=[case]),
                patch("sys.argv", ["run_ci_critical_tests.py", "--check-manifest"]),
            ):
                # The real discovery prefixes IDs with agents; pin that exact contract.
                with patch.object(
                    case, "id", return_value="agents.test_example.ExampleTests.test_case"
                ):
                    self.assertEqual(run_ci_critical_tests.main(), 0)

    def test_manifest_rejects_missing_selector_and_duplicate(self) -> None:
        selector = "tests.agents.test_example.ExampleTests.test_case"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "test_example.py").write_text("", encoding="utf-8")
            with (
                patch.object(run_ci_critical_tests, "CORE_TESTS", (selector,)),
                patch.object(run_ci_critical_tests, "OFFLINE_COMPONENT_TESTS", ()),
                patch.object(run_ci_critical_tests, "OPTIONAL_TESTS", ()),
                patch.object(run_ci_critical_tests, "TESTS_DIRECTORY", directory),
                patch.object(
                    run_ci_critical_tests, "check_release_version_assertions", return_value=True
                ),
                patch.object(run_ci_test_shard, "discover_cases", return_value=[]),
                patch("sys.argv", ["run_ci_critical_tests.py", "--check-manifest"]),
            ):
                self.assertEqual(run_ci_critical_tests.main(), 1)
            with (
                patch.object(run_ci_critical_tests, "CORE_TESTS", (selector, selector)),
                patch.object(run_ci_critical_tests, "OFFLINE_COMPONENT_TESTS", ()),
                patch.object(run_ci_critical_tests, "OPTIONAL_TESTS", ()),
                patch.object(run_ci_critical_tests, "TESTS_DIRECTORY", directory),
                patch.object(
                    run_ci_critical_tests, "check_release_version_assertions", return_value=True
                ),
                patch("sys.argv", ["run_ci_critical_tests.py", "--check-manifest"]),
            ):
                self.assertEqual(run_ci_critical_tests.main(), 1)

    def test_matching_release_version_passes(self) -> None:
        self.assertTrue(self._check_with_pin("0.282.0"))

    def test_direct_project_version_assertion_is_checked(self) -> None:
        self.assertTrue(self._check_with_pin("0.282.0", direct_project=True))
        self.assertFalse(self._check_with_pin("0.281.0", direct_project=True))

    def test_stale_release_version_fails(self) -> None:
        self.assertFalse(self._check_with_pin("0.281.0"))

    def test_missing_release_version_assertions_fail(self) -> None:
        self.assertFalse(self._check_with_pin(None))

    def _check_with_pin(
        self, pinned_version: str | None, *, direct_project: bool = False
    ) -> bool:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test_directory = root / "tests" / "agents"
            test_directory.mkdir(parents=True)
            (root / "pyproject.toml").write_text(
                '[project]\nversion = "0.282.0"\n', encoding="utf-8"
            )
            if pinned_version is not None:
                assertion_prefix = (
                    'self.assertEqual(project' if direct_project
                    else 'self.assertEqual(project["project"]'
                )
                (test_directory / "test_version.py").write_text(
                    assertion_prefix + f'["version"], "{pinned_version}")\n',
                    encoding="utf-8",
                )
            with (
                patch.object(run_ci_critical_tests, "ROOT", root),
                patch.object(run_ci_critical_tests, "TESTS_DIRECTORY", test_directory),
            ):
                return run_ci_critical_tests.check_release_version_assertions()


if __name__ == "__main__":
    unittest.main()

"""Keep complete PR testing and weekly serial coverage without merge repeats."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class CiEventGatePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_pr_runs_all_shards_and_serial_is_reserved_for_explicit_runs(self) -> None:
        self.assertNotIn("  push:\n", self.workflow)
        self.assertEqual(self.workflow.count("runs-on: ubuntu-24.04"), 4)
        self.assertNotIn("runs-on: ubuntu-latest", self.workflow)
        self.assertIn('    - cron: "17 7 * * 0"', self.workflow)
        self.assertIn("  workflow_dispatch:\n", self.workflow)
        self.assertIn("  pull_request:\n", self.workflow)
        self.assertIn("if: github.event_name == 'pull_request'", self.workflow)
        self.assertIn("shard: [0, 1, 2, 3, 4, 5, 6, 7]", self.workflow)
        self.assertIn(
            "if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
            self.workflow,
        )
        self.assertNotIn("if: github.event_name != 'pull_request'", self.workflow)

    def test_aggregate_check_has_exact_fail_closed_event_matrix(self) -> None:
        self.assertIn("if: always()", self.workflow)
        self.assertIn("needs: [preflight, test-shard, serial-suite]", self.workflow)
        self.assertIn('test "$PREFLIGHT_RESULT" = success', self.workflow)
        for condition in (
            'if [ "$EVENT_NAME" = pull_request ]; then',
            'elif [ "$EVENT_NAME" = schedule ] || [ "$EVENT_NAME" = workflow_dispatch ]; then',
        ):
            with self.subTest(condition=condition):
                self.assertIn(condition, self.workflow)
        self.assertIn('test "$SHARD_RESULT" = success', self.workflow)
        self.assertIn('test "$SERIAL_RESULT" = success', self.workflow)
        self.assertNotIn('"$EVENT_NAME" = push', self.workflow)
        self.assertEqual(self.workflow.count('test "$SERIAL_RESULT" = skipped'), 1)
        self.assertEqual(self.workflow.count('test "$SHARD_RESULT" = skipped'), 1)
        self.assertIn("          else\n            exit 1\n          fi", self.workflow)


if __name__ == "__main__":
    unittest.main()

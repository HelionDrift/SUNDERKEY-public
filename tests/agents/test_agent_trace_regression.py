"""Observed agent trace issue changes are reproducible and nonqualifying."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from sunderkey.agent_trace_regression import (
    AgentTraceRegressionError,
    build_agent_trace_regression,
    verify_agent_trace_regression,
)
from sunderkey.agent_trace_review import build_agent_trace_review
from sunderkey.cli import build_parser

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def event(sequence: int, kind: str, actor: str) -> dict[str, object]:
    action = "actionref:synthetic-read" if kind in {
        "tool_proposal", "approval_assertion", "tool_execution",
    } else None
    tool = "toolref:synthetic-read" if action else None
    return {
        "sequence": sequence,
        "observed_at": "2026-09-23T12:00:00Z",
        "kind": kind,
        "actor": actor,
        "action_ref": action,
        "tool_ref": tool,
        "event_sha256": DIGEST_A,
    }


def pair() -> tuple[dict, dict]:
    prior = {
        "schema_version": 1,
        "tenant_ref": "tenantref:synthetic",
        "scope_sha256": DIGEST_A,
        "case_ref": "caseref:tool-gate",
        "source_trace_sha256": DIGEST_B,
        "observed_at": "2026-09-23T12:00:01Z",
        "policy": {
            "allowed_tool_refs": ["toolref:synthetic-read"],
            "maximum_tool_executions": 1,
        },
        "events": [
            event(1, "tool_proposal", "candidate"),
            event(2, "approval_assertion", "human"),
            event(3, "tool_execution", "tool"),
            event(4, "final_response", "candidate"),
        ],
    }
    current = copy.deepcopy(prior)
    current["source_trace_sha256"] = DIGEST_C
    current["observed_at"] = "2026-09-23T13:00:00Z"
    current["events"].pop(1)
    for index, item in enumerate(current["events"], start=1):
        item["sequence"] = index
    return prior, current


class AgentTraceRegressionTests(unittest.TestCase):
    def test_new_issue_is_observed_not_called_a_live_regression(self) -> None:
        prior, current = pair()
        prior_review = build_agent_trace_review(prior)
        current_review = build_agent_trace_review(current)
        comparison = build_agent_trace_regression(
            prior, prior_review, current, current_review,
        )
        self.assertEqual(comparison["comparison_status"], "new_issues_observed")
        self.assertEqual(comparison["qualification_effect"], "none")
        self.assertIn("not_a_verified_fix_or_live_regression", comparison["interpretation"])
        self.assertEqual(comparison["newly_observed_issues"], [{
            "code": "execution_without_human_approval_assertion", "count": 1,
        }])
        self.assertEqual(
            verify_agent_trace_regression(
                prior, prior_review, current, current_review, comparison,
            )["status"],
            "valid",
        )

    def test_no_longer_observed_is_not_claimed_as_fix(self) -> None:
        prior, current = pair()
        prior["events"].pop(1)
        for index, item in enumerate(prior["events"], start=1):
            item["sequence"] = index
        current["events"].insert(1, event(2, "approval_assertion", "human"))
        for index, item in enumerate(current["events"], start=1):
            item["sequence"] = index
        comparison = build_agent_trace_regression(
            prior, build_agent_trace_review(prior),
            current, build_agent_trace_review(current),
        )
        self.assertEqual(comparison["comparison_status"], "issues_no_longer_observed")
        self.assertEqual(comparison["newly_observed_issues"], [])

    def test_same_policy_scope_case_time_and_distinct_source_are_required(self) -> None:
        prior, current = pair()
        for key, value in (
            ("tenant_ref", "tenantref:other"),
            ("scope_sha256", DIGEST_B),
            ("case_ref", "caseref:other"),
            ("policy", {"allowed_tool_refs": [], "maximum_tool_executions": 1}),
            ("observed_at", prior["observed_at"]),
            ("source_trace_sha256", prior["source_trace_sha256"]),
        ):
            altered = copy.deepcopy(current)
            altered[key] = value
            with self.subTest(key=key), self.assertRaises(AgentTraceRegressionError):
                build_agent_trace_regression(
                    prior, build_agent_trace_review(prior),
                    altered, build_agent_trace_review(altered),
                )

    def test_tampered_source_or_comparison_fails(self) -> None:
        prior, current = pair()
        prior_review = build_agent_trace_review(prior)
        current_review = build_agent_trace_review(current)
        comparison = build_agent_trace_regression(
            prior, prior_review, current, current_review,
        )
        altered_review = copy.deepcopy(current_review)
        altered_review["tool_execution_count"] = 0
        with self.assertRaises(AgentTraceRegressionError):
            build_agent_trace_regression(prior, prior_review, current, altered_review)
        comparison["comparison_status"] = "no_issue_count_change"
        with self.assertRaises(AgentTraceRegressionError):
            verify_agent_trace_regression(
                prior, prior_review, current, current_review, comparison,
            )

    def test_cli_roundtrip(self) -> None:
        prior, current = pair()
        values = {
            "prior_trace": prior,
            "prior_review": build_agent_trace_review(prior),
            "current_trace": current,
            "current_review": build_agent_trace_review(current),
        }
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in values.items():
                paths[name] = Path(directory) / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            options = [
                token for name, path in paths.items()
                for token in ("--" + name.replace("_", "-"), str(path))
            ]
            parser = build_parser()
            args = parser.parse_args(["agent-trace-regression", *options])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            comparison_path = Path(directory) / "comparison.json"
            comparison_path.write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "agent-trace-regression-verify", *options,
                "--comparison", str(comparison_path),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()

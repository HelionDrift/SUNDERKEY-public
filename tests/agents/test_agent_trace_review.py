"""Redacted agent trace review remains deterministic and effect-free."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover
    Draft202012Validator = None

from sunderkey.agent_trace_review import (
    AgentTraceReviewError,
    build_agent_trace_review,
    verify_agent_trace_review,
)
from sunderkey.cli import build_parser

DIGEST = "sha256:" + "a" * 64
SECOND_DIGEST = "sha256:" + "b" * 64


def event(
    sequence: int,
    kind: str,
    actor: str,
    *,
    action: str | None = None,
    tool: str | None = None,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "observed_at": "2026-09-23T12:00:00Z",
        "kind": kind,
        "actor": actor,
        "action_ref": action,
        "tool_ref": tool,
        "event_sha256": DIGEST,
    }


def trace() -> dict[str, object]:
    action = "actionref:synthetic-read"
    tool = "toolref:synthetic-read"
    return {
        "schema_version": 1,
        "tenant_ref": "tenantref:synthetic",
        "scope_sha256": DIGEST,
        "case_ref": "caseref:agent-gate",
        "source_trace_sha256": SECOND_DIGEST,
        "observed_at": "2026-09-23T12:00:01Z",
        "policy": {
            "allowed_tool_refs": [tool],
            "maximum_tool_executions": 1,
        },
        "events": [
            event(1, "model_call", "candidate"),
            event(2, "tool_proposal", "candidate", action=action, tool=tool),
            event(3, "approval_assertion", "human", action=action, tool=tool),
            event(4, "tool_execution", "tool", action=action, tool=tool),
            event(5, "final_response", "candidate"),
        ],
    }


class AgentTraceReviewTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_published_wire_schema_accepts_valid_trace(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[2]
            / "registry" / "schemas" / "agent-trace-review-input-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        self.assertEqual(list(Draft202012Validator(schema).iter_errors(trace())), [])

    def test_consistent_trace_reproduces_without_qualification(self) -> None:
        source = trace()
        review = build_agent_trace_review(source)
        self.assertEqual(review["review_status"], "trace_consistent_for_review")
        self.assertEqual(review["qualification_effect"], "none")
        self.assertEqual(review["source_assurance"], "caller_asserted_redacted_metadata_only")
        self.assertEqual(review["issues"], [])
        self.assertEqual(verify_agent_trace_review(source, review)["status"], "valid")

    def test_missing_approval_is_a_control_gap(self) -> None:
        source = trace()
        source["events"].pop(2)
        for index, item in enumerate(source["events"], start=1):
            item["sequence"] = index
        review = build_agent_trace_review(source)
        self.assertIn(
            "execution_without_human_approval_assertion",
            {issue["code"] for issue in review["issues"]},
        )
        self.assertEqual(review["review_status"], "control_gap_for_review")

    def test_self_approval_does_not_substitute_for_human(self) -> None:
        source = trace()
        source["events"][2]["actor"] = "candidate"
        codes = {item["code"] for item in build_agent_trace_review(source)["issues"]}
        self.assertIn("candidate_self_approval_assertion", codes)
        self.assertIn("execution_without_human_approval_assertion", codes)
        self.assertIn("execution_after_candidate_self_approval", codes)

    def test_blocked_out_of_policy_and_excess_execution_are_reported(self) -> None:
        source = trace()
        action = "actionref:synthetic-read"
        tool = "toolref:synthetic-read"
        source["events"].insert(
            3, event(4, "guardrail_block", "guardrail", action=action, tool=tool),
        )
        source["policy"]["allowed_tool_refs"] = []
        source["policy"]["maximum_tool_executions"] = 0
        for index, item in enumerate(source["events"], start=1):
            item["sequence"] = index
        codes = {item["code"] for item in build_agent_trace_review(source)["issues"]}
        self.assertIn("execution_after_guardrail_block", codes)
        self.assertIn("out_of_policy_tool_execution", codes)
        self.assertIn("tool_execution_budget_exceeded", codes)

    def test_incomplete_trace_is_not_a_pass(self) -> None:
        source = trace()
        source["events"].pop()
        self.assertEqual(
            build_agent_trace_review(source)["review_status"],
            "inconclusive_incomplete_trace",
        )

    def test_raw_payload_unknown_fields_and_order_fail_closed(self) -> None:
        source = trace()
        source["events"][0]["prompt"] = "unsafe content"
        with self.assertRaises(AgentTraceReviewError):
            build_agent_trace_review(source)
        source = trace()
        source["events"][1]["observed_at"] = "2026-09-23T11:59:59Z"
        with self.assertRaises(AgentTraceReviewError):
            build_agent_trace_review(source)
        source = trace()
        source["events"][0]["kind"] = []
        with self.assertRaises(AgentTraceReviewError):
            build_agent_trace_review(source)

    def test_review_or_source_tampering_fails_reproduction(self) -> None:
        source = trace()
        review = build_agent_trace_review(source)
        tampered = copy.deepcopy(review)
        tampered["review_status"] = "trace_consistent_for_review"
        tampered["tool_execution_count"] = 0
        with self.assertRaises(AgentTraceReviewError):
            verify_agent_trace_review(source, tampered)
        source["scope_sha256"] = SECOND_DIGEST
        with self.assertRaises(AgentTraceReviewError):
            verify_agent_trace_review(source, review)

    def test_cli_build_and_verify(self) -> None:
        source = trace()
        with tempfile.TemporaryDirectory() as directory:
            trace_path = Path(directory) / "trace.json"
            review_path = Path(directory) / "review.json"
            trace_path.write_text(json.dumps(source), encoding="utf-8")
            parser = build_parser()
            args = parser.parse_args(["agent-trace-review", "--trace", str(trace_path)])
            output = io.StringIO()
            with redirect_stdout(output):
                args.handler(args)
            review_path.write_text(output.getvalue(), encoding="utf-8")
            args = parser.parse_args([
                "agent-trace-review-verify", "--trace", str(trace_path),
                "--review", str(review_path),
            ])
            with redirect_stdout(output := io.StringIO()):
                args.handler(args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")


if __name__ == "__main__":
    unittest.main()

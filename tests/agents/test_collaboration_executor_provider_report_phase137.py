"""Phase 137 lossless provider-report contract coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor_invocation_attempt import (
    build_collaboration_executor_invocation_resolution,
)
from sunderkey.collaboration_executor_provider_report import (
    CollaborationExecutorProviderReport,
    build_collaboration_executor_provider_report,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorProviderReportPhase137Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase133.CollaborationExecutorInvocationAttemptPhase133Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.preparation = fixture._prepare()
        self.acknowledgement = fixture._acknowledgement()

    def _report(self, *, received_at: str = "2026-07-30T10:08:35Z"):
        return build_collaboration_executor_provider_report(
            self.preparation,
            self.acknowledgement,
            received_at=received_at,
        )

    def test_complete_report_is_retained_without_authentication_claim(self) -> None:
        report = self._report()
        document = report.to_dict()
        self.assertEqual(
            document["provider_acknowledgement"],
            self.acknowledgement.to_dict(),
        )
        self.assertEqual(
            report.provider_acknowledgement,
            self.acknowledgement,
        )
        self.assertEqual(document["authentication_status"], "not_authenticated")
        self.assertEqual(
            document["external_effect_status"],
            "provider_report_pending_authentication",
        )
        self.assertEqual(document["runtime_effect"], "none")

    def test_report_requires_exact_preparation_and_adapter_binding(self) -> None:
        changed = self.fixture._acknowledgement(adapter_id="adapter.changed")
        with self.assertRaisesRegex(CollaborationPlanError, "does not bind"):
            build_collaboration_executor_provider_report(
                self.preparation,
                changed,
                received_at="2026-07-30T10:08:35Z",
            )

    def test_report_custody_time_cannot_precede_acknowledgement(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "time is invalid"):
            self._report(received_at="2026-07-30T10:08:33Z")

    def test_nested_report_tampering_is_rejected(self) -> None:
        changed = self._report().to_dict()
        changed["provider_acknowledgement"]["outcome"] = "failed"
        with self.assertRaises(CollaborationPlanError):
            CollaborationExecutorProviderReport.from_dict(changed)

    def test_captured_report_can_build_pending_authentication_resolution(self) -> None:
        report = self._report()
        resolution = build_collaboration_executor_invocation_resolution(
            self.preparation,
            outcome="provider_report_received",
            provider_acknowledgement=report.provider_acknowledgement,
            resolved_at="2026-07-30T10:08:35Z",
        )
        document = resolution.to_dict()
        self.assertEqual(
            document["provider_acknowledgement"]["acknowledgement_id"],
            self.acknowledgement.acknowledgement_id,
        )
        self.assertEqual(
            document["external_effect_status"],
            "provider_report_pending_authentication",
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_report_matches_strict_schema(self) -> None:
        schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-provider-report-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["provider_acknowledgement"] = json.loads(
            (
                SCHEMAS / "collaboration-executor-acknowledgement-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._report().to_dict())

    def test_contract_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = ROOT / "src/sunderkey/collaboration_executor_provider_report.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "httpx",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()

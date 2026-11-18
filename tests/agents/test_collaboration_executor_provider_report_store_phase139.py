"""Phase 139 atomic provider-report custody coverage."""

from __future__ import annotations

import ast
import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor import (
    build_collaboration_executor_acknowledgement,
)
from sunderkey.collaboration_executor_provider_report_store import (
    CollaborationExecutorProviderReportService,
)
from sunderkey.errors import StoreConflictError

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133
from . import test_collaboration_executor_invocation_attempt_store_phase135 as phase135

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class CollaborationExecutorProviderReportStorePhase139Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase135.CollaborationExecutorInvocationAttemptStorePhase135Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.service = CollaborationExecutorProviderReportService(
            self.root.store,
            self.root.registry,
            clock=lambda: self.root.now,
        )

    def _prepare(self):
        receipt = self.fixture._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        return receipt

    def _acknowledgement(self, *, evidence: str = phase133.EVIDENCE):
        operation = self.fixture.fixture.dispatch.to_dict()["operation"]
        state = {
            "start": "ready",
            "action": "active",
            "evidence": "unchanged",
            "heartbeat": "active",
            "pause": "paused",
            "resume": "active",
            "stop": "stopped",
            "destroy": "destroyed",
        }[operation]
        return build_collaboration_executor_acknowledgement(
            self.fixture.fixture.dispatch,
            adapter_id="adapter.test",
            adapter_version="1.0.0",
            adapter_build_sha256=phase133.ADAPTER_BUILD,
            runtime_instance_id="worker-runtime-1",
            outcome="accepted",
            provider_worker_state=state,
            provider_evidence_sha256=evidence,
            acknowledged_at="2026-07-30T10:08:34Z",
        )

    def _counts(self) -> tuple[int, int]:
        with closing(sqlite3.connect(self.root.store.path)) as connection:
            report_count = connection.execute(
                "SELECT COUNT(*) FROM executor_invocation_provider_reports"
            ).fetchone()[0]
            resolution_count = connection.execute(
                "SELECT COUNT(*) FROM executor_dispatch_invocation_resolutions"
            ).fetchone()[0]
        return report_count, resolution_count

    def test_report_and_resolution_commit_atomically(self) -> None:
        preparation = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        receipt = self.service.commit(
            preparation.attempt_id,
            self._acknowledgement(),
        )
        document = receipt.to_dict()
        self.assertEqual(
            document["custody_status"],
            "durable_complete_report_and_resolution",
        )
        self.assertEqual(document["authentication_status"], "not_authenticated")
        self.assertEqual(
            document["external_effect_status"],
            "provider_report_pending_authentication",
        )
        self.assertEqual(
            document["provider_report"]["provider_acknowledgement"],
            self._acknowledgement().to_dict(),
        )
        self.assertEqual(
            document["invocation_resolution"]["outcome"],
            "provider_report_received",
        )
        self.assertEqual(self.service.get(preparation.attempt_id), receipt)
        self.assertEqual(self._counts(), (1, 1))
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_exact_replay_is_read_only_and_changed_report_conflicts(self) -> None:
        preparation = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 35, tzinfo=UTC)
        first = self.service.commit(
            preparation.attempt_id,
            self._acknowledgement(),
        )
        self.root.now = datetime(2026, 7, 30, 10, 8, 40, tzinfo=UTC)
        self.assertEqual(
            self.service.commit(
                preparation.attempt_id,
                self._acknowledgement(),
            ),
            first,
        )
        with self.assertRaisesRegex(StoreConflictError, "another provider report"):
            self.service.commit(
                preparation.attempt_id,
                self._acknowledgement(evidence="sha256:" + "95" * 32),
            )
        self.assertEqual(self._counts(), (1, 1))

    def test_report_capture_remains_available_after_claim_expiry(self) -> None:
        preparation = self._prepare()
        self.root.now = datetime(2026, 7, 30, 10, 8, 45, tzinfo=UTC)
        receipt = self.service.commit(
            preparation.attempt_id,
            self._acknowledgement(),
        )
        self.assertEqual(receipt.attempt_id, preparation.attempt_id)
        self.assertEqual(self._counts(), (1, 1))

    def test_report_insert_failure_rolls_back_both_records(self) -> None:
        preparation = self._prepare()
        with patch.object(
            self.service,
            "_insert_report",
            side_effect=sqlite3.IntegrityError("injected report failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self.service.commit(
                preparation.attempt_id,
                self._acknowledgement(),
            )
        self.assertEqual(self._counts(), (0, 0))

    def test_resolution_insert_failure_rolls_back_report(self) -> None:
        preparation = self._prepare()
        with patch.object(
            self.service._attempts,
            "_insert_resolution",
            side_effect=sqlite3.IntegrityError("injected resolution failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self.service.commit(
                preparation.attempt_id,
                self._acknowledgement(),
            )
        self.assertEqual(self._counts(), (0, 0))

    def test_conflicting_terminal_resolution_blocks_report(self) -> None:
        preparation = self._prepare()
        self.fixture.service.resolve(
            preparation.attempt_id,
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
        )
        with self.assertRaisesRegex(StoreConflictError, "terminal resolution"):
            self.service.commit(
                preparation.attempt_id,
                self._acknowledgement(),
            )
        self.assertEqual(self._counts(), (0, 1))

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_strict_schema(self) -> None:
        preparation = self._prepare()
        receipt = self.service.commit(
            preparation.attempt_id,
            self._acknowledgement(),
        )
        acknowledgement_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-acknowledgement-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        report_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-provider-report-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        report_schema["properties"]["provider_acknowledgement"] = (
            acknowledgement_schema
        )
        receipt_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-report-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        receipt_schema["properties"]["provider_report"] = report_schema
        receipt_schema["properties"]["invocation_resolution"] = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-resolution-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(receipt_schema)
        Draft202012Validator(receipt_schema).validate(receipt.to_dict())

    def test_writer_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = (
            ROOT / "src/sunderkey/collaboration_executor_provider_report_store.py"
        )
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

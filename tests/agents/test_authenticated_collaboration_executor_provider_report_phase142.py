"""Phase 142 atomic provider-report authentication custody coverage."""

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

from sunderkey.authenticated_collaboration_executor_provider_report import (
    AuthenticatedCollaborationExecutorProviderReportService,
)
from sunderkey.errors import StoreConflictError
from sunderkey.identity import PrincipalOperation

from . import (
    test_collaboration_executor_provider_report_authentication_phase140 as phase140,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
SECOND_ASSERTION_ID = "PAS-" + "63" * 16


class AuthenticatedCollaborationExecutorProviderReportPhase142Tests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = (
            phase140.CollaborationExecutorProviderReportAuthenticationPhase140Tests(
                methodName="runTest"
            )
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.attempt_id = fixture.preparation_receipt.attempt_id
        self.assertion = fixture._assertion(
            fixture.report.provider_acknowledgement
        )
        self.service = (
            AuthenticatedCollaborationExecutorProviderReportService(
                self.root.store,
                self.root.registry,
                clock=lambda: self.root.now,
            )
        )

    def _authenticate(self, assertion=None):
        return self.service.authenticate(
            self.attempt_id,
            worker_assertion=assertion or self.assertion,
        )

    def test_authentication_is_atomic_durable_and_inert(self) -> None:
        receipt = self._authenticate()
        document = receipt.to_dict()
        authentication = document["provider_report_authentication"]
        self.assertEqual(
            document["custody_status"],
            "durable_authenticated_provider_report",
        )
        self.assertEqual(
            document["evidence_verification_status"],
            "provider_evidence_digest_unverified",
        )
        self.assertEqual(
            document["external_effect_status"],
            "authenticated_report_unverified_effect",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(receipt.attempt_id, self.attempt_id)
        self.assertEqual(
            self.service.get(receipt.report_authentication_id),
            receipt,
        )
        self.assertEqual(
            authentication["provider_report"],
            self.fixture.report.to_dict(),
        )
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM executor_invocation_provider_report_authentications
                    """
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation = ?
                    """,
                    (PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value,),
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_exact_replay_survives_assertion_and_dispatch_expiry(self) -> None:
        receipt = self._authenticate()
        self.root.now = datetime(2026, 7, 30, 11, 0, tzinfo=UTC)
        self.assertEqual(self._authenticate(), receipt)
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM executor_invocation_provider_report_authentications
                    """
                ).fetchone()[0],
                1,
            )

    def test_late_insert_failure_rolls_back_worker_assertion(self) -> None:
        with patch.object(
            self.service,
            "_insert_authentication",
            side_effect=sqlite3.IntegrityError(
                "injected report authentication failure"
            ),
        ), self.assertRaisesRegex(StoreConflictError, "Could not authenticate"):
            self._authenticate()
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM executor_invocation_provider_report_authentications
                    """
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE assertion_id = ?
                    """,
                    (self.assertion.assertion_id,),
                ).fetchone()[0],
                0,
            )

    def test_second_authentication_for_report_fails_and_rolls_back(self) -> None:
        self._authenticate()
        second = self.fixture._assertion(
            self.fixture.report.provider_acknowledgement,
            assertion_id=SECOND_ASSERTION_ID,
        )
        with self.assertRaisesRegex(StoreConflictError, "Could not authenticate"):
            self._authenticate(second)
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses "
                    "WHERE assertion_id = ?",
                    (SECOND_ASSERTION_ID,),
                ).fetchone()[0],
                0,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipt_matches_strict_schema(self) -> None:
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
        acknowledgement_authentication_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-acknowledgement-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        acknowledgement_authentication_schema["properties"][
            "acknowledgement"
        ] = acknowledgement_schema
        authentication_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-report-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        authentication_schema["properties"]["provider_report"] = report_schema
        authentication_schema["properties"][
            "acknowledgement_authentication"
        ] = acknowledgement_authentication_schema
        receipt_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-report-authentication-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        receipt_schema["properties"][
            "provider_report_authentication"
        ] = authentication_schema
        Draft202012Validator.check_schema(receipt_schema)
        Draft202012Validator(receipt_schema).validate(
            self._authenticate().to_dict()
        )

    def test_service_has_no_network_process_or_adapter_invocation(self) -> None:
        source = (
            ROOT
            / "src/sunderkey/authenticated_collaboration_executor_provider_report.py"
        )
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {"http", "requests", "socket", "subprocess", "urllib"}
            )
        )


if __name__ == "__main__":
    unittest.main()

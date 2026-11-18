"""Phase 129 atomic executor dispatch reservation coverage."""

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

from sunderkey.authenticated_collaboration_executor_dispatch import (
    AuthenticatedCollaborationExecutorDispatchService,
)
from sunderkey.collaboration_execution_session_status import (
    CollaborationExecutionSessionAuthorityStatusService,
)
from sunderkey.collaboration_executor import (
    build_collaboration_executor_dispatch,
    collaboration_executor_operation_input_sha256,
)
from sunderkey.errors import CollaborationPlanError, StoreConflictError
from sunderkey.identity import PrincipalOperation

from . import test_authenticated_collaboration_execution_session_authority_phase123 as phase123
from . import test_collaboration_executor_dispatch_authentication_phase127 as phase127

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
SECOND_ASSERTION_ID = "PAS-" + "53" * 16
THIRD_ASSERTION_ID = "PAS-" + "54" * 16
REVOKED_NORMAL_GRANT_ID = "SGR-" + "55" * 16
REVOKED_NORMAL_ASSERTION_ID = "PAS-" + "55" * 16
REVOKED_SAFETY_GRANT_ID = "SGR-" + "56" * 16
REVOKED_SAFETY_ASSERTION_ID = "PAS-" + "56" * 16


class AuthenticatedCollaborationExecutorDispatchPhase129Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase127.CollaborationExecutorDispatchAuthenticationPhase127Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.dispatch = fixture.dispatch
        self.assertion = fixture.assertion
        self.operation_input = fixture.fixture.operation_input
        self.service = AuthenticatedCollaborationExecutorDispatchService(
            self.root.store,
            self.root.registry,
            clock=lambda: self.root.now,
        )

    def _reserve(self):
        return self.service.reserve(
            self.dispatch,
            self.operation_input,
            authorizer_assertion=self.assertion,
        )

    def _later_assertion(self, dispatch, assertion_id: str):
        return self.fixture._assertion(
            self.root,
            self.fixture.grant,
            assertion_id,
            self.fixture.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
            dispatch,
            issued_at="2026-07-30T10:08:21Z",
            expires_at="2026-07-30T10:10:00Z",
        )

    def test_reservation_is_atomic_durable_and_inert(self) -> None:
        receipt = self._reserve()
        document = receipt.to_dict()
        self.assertEqual(
            document["reservation_status"],
            "reserved_pending_adapter",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(receipt.dispatch_id, self.dispatch.dispatch_id)
        self.assertEqual(self.service.get(receipt.authentication_id), receipt)
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_reservations"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation = ?
                    """,
                    (PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE.value,),
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_exact_replay_survives_assertion_and_dispatch_expiry(self) -> None:
        receipt = self._reserve()
        self.root.now = datetime(2026, 7, 30, 11, 0, tzinfo=UTC)
        self.assertEqual(self._reserve(), receipt)
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_reservations"
                ).fetchone()[0],
                1,
            )

    def test_operation_bytes_and_contiguous_sequence_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "input hash"):
            self.service.reserve(
                self.dispatch,
                b"changed",
                authorizer_assertion=self.assertion,
            )
        self._reserve()
        third = self.fixture.fixture._dispatch("heartbeat", sequence=3)
        assertion = self._later_assertion(third, THIRD_ASSERTION_ID)
        with self.assertRaisesRegex(StoreConflictError, "must be 2"):
            self.service.reserve(
                third,
                self.operation_input,
                authorizer_assertion=assertion,
            )
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses "
                    "WHERE assertion_id = ?",
                    (THIRD_ASSERTION_ID,),
                ).fetchone()[0],
                0,
            )

    def test_late_insert_failure_rolls_back_assertion_custody(self) -> None:
        with patch.object(
            self.service,
            "_insert_reservation",
            side_effect=sqlite3.IntegrityError("injected reservation failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not reserve"):
            self._reserve()
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM executor_dispatch_reservations"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses "
                    "WHERE assertion_id = ?",
                    (self.assertion.assertion_id,),
                ).fetchone()[0],
                0,
            )

    def test_second_contiguous_reservation_commits(self) -> None:
        first = self._reserve()
        second_dispatch = self.fixture.fixture._dispatch("heartbeat", sequence=2)
        second_assertion = self._later_assertion(
            second_dispatch,
            SECOND_ASSERTION_ID,
        )
        second = self.service.reserve(
            second_dispatch,
            self.operation_input,
            authorizer_assertion=second_assertion,
        )
        self.assertNotEqual(first.authentication_id, second.authentication_id)
        self.assertEqual(
            second.to_dict()["dispatch_authentication"]["dispatch"][
                "operation_sequence"
            ],
            2,
        )
        self.assertEqual(
            self.root.store.verify_mission(
                self.root.registry,
                self.root.mission.mission_id,
            ).status,
            "valid",
        )

    def test_revocation_closes_ordinary_reservation_but_preserves_stop(self) -> None:
        fixture = phase123.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture._activate()
        root = fixture.root
        root.now = datetime(2026, 7, 30, 10, 8, 30, tzinfo=UTC)
        status_service = CollaborationExecutionSessionAuthorityStatusService(
            root.store,
            root.registry,
            clock=lambda: root.now,
        )
        available = status_service.get(fixture.authority.session_authority_id)
        ordinary_input = b"ordinary-after-revocation"
        ordinary = build_collaboration_executor_dispatch(
            status=available,
            authority=fixture.authority,
            collaboration_plan=root.plan,
            operation="action",
            operation_sequence=1,
            tool_policy_sha256="sha256:" + "81" * 32,
            operation_input_sha256=(
                collaboration_executor_operation_input_sha256(ordinary_input)
            ),
            issued_at="2026-07-30T10:08:35Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        fixture._revoke()
        root.now = datetime(2026, 7, 30, 10, 9, 10, tzinfo=UTC)
        policy_version = phase127.POLICY_VERSION
        policy = root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=policy_version,
            store_id=root.store_id,
            allowed_profiles=[fixture.control_id, fixture.worker_id],
            allowed_operations=[
                PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE.value,
                PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE.value,
            ],
        )
        root.trust.apply_policy(policy)
        normal_grant = phase127.CollaborationExecutorDispatchAuthenticationPhase127Tests._grant(
            root,
            REVOKED_NORMAL_GRANT_ID,
            fixture.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
            expires_at="2026-07-30T10:20:00Z",
        )
        safety_grant = phase127.CollaborationExecutorDispatchAuthenticationPhase127Tests._grant(
            root,
            REVOKED_SAFETY_GRANT_ID,
            fixture.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            expires_at="2026-07-30T10:20:00Z",
        )
        root.acceptance.accept(normal_grant)
        root.acceptance.accept(safety_grant)
        normal_assertion = (
            phase127.CollaborationExecutorDispatchAuthenticationPhase127Tests
            ._assertion(
                root,
                normal_grant,
                REVOKED_NORMAL_ASSERTION_ID,
                fixture.control_id,
                PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
                ordinary,
                issued_at="2026-07-30T10:09:01Z",
                expires_at="2026-07-30T10:12:00Z",
            )
        )
        service = AuthenticatedCollaborationExecutorDispatchService(
            root.store,
            root.registry,
            clock=lambda: root.now,
        )
        with self.assertRaisesRegex(StoreConflictError, "Revoked authority"):
            service.reserve(
                ordinary,
                ordinary_input,
                authorizer_assertion=normal_assertion,
            )

        revoked = status_service.get(fixture.authority.session_authority_id)
        stop_input = b"stop"
        stop = build_collaboration_executor_dispatch(
            status=revoked,
            authority=fixture.authority,
            collaboration_plan=root.plan,
            operation="stop",
            operation_sequence=1,
            tool_policy_sha256="sha256:" + "82" * 32,
            operation_input_sha256=(
                collaboration_executor_operation_input_sha256(stop_input)
            ),
            issued_at="2026-07-30T10:09:10Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        safety_assertion = (
            phase127.CollaborationExecutorDispatchAuthenticationPhase127Tests
            ._assertion(
                root,
                safety_grant,
                REVOKED_SAFETY_ASSERTION_ID,
                fixture.control_id,
                PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
                stop,
                issued_at="2026-07-30T10:09:01Z",
                expires_at="2026-07-30T10:12:00Z",
            )
        )
        receipt = service.reserve(
            stop,
            stop_input,
            authorizer_assertion=safety_assertion,
        )
        self.assertEqual(
            receipt.to_dict()["dispatch_authentication"]["dispatch"]["operation"],
            "stop",
        )
        self.assertEqual(root.store.verify_store(root.registry).status, "valid")

    def test_receipt_matches_strict_schema(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        receipt_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-dispatch-reservation-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        authentication_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-dispatch-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        dispatch_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-dispatch-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        authentication_schema["properties"]["dispatch"] = dispatch_schema
        receipt_schema["properties"]["dispatch_authentication"] = (
            authentication_schema
        )
        Draft202012Validator(receipt_schema).validate(self._reserve().to_dict())

    def test_service_has_no_network_process_or_adapter_invocation(self) -> None:
        source = (
            ROOT
            / "src/sunderkey/authenticated_collaboration_executor_dispatch.py"
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

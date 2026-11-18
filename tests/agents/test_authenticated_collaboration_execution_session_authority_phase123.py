"""Phase 123 atomic execution session authority custody coverage."""

from __future__ import annotations

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

from sunderkey.authenticated_collaboration_execution_session_authority import (
    AuthenticatedCollaborationExecutionSessionAuthorityService,
)
from sunderkey.collaboration_execution_session_authentication import (
    build_collaboration_execution_session_activation_request,
    collaboration_execution_session_activation_selection_sha256,
    collaboration_execution_session_revocation_selection_sha256,
)
from sunderkey.collaboration_execution_session_authority import (
    build_collaboration_execution_session_revocation,
)
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.store import canonical_json, sha256_text

from . import test_authenticated_collaboration_execution_channel_phase109 as phase109
from . import test_collaboration_execution_session_authority_phase120 as phase120
from .test_identity_phase4 import AUDIENCE, SUBJECT

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
POLICY_VERSION = phase109.POLICY_VERSION + 3
CONTROL_GRANT_ID = "SGR-" + "31" * 16
WORKER_GRANT_ID = "SGR-" + "32" * 16
REVOKE_GRANT_ID = "SGR-" + "33" * 16
CONTROL_ASSERTION_ID = "PAS-" + "31" * 16
WORKER_ASSERTION_ID = "PAS-" + "32" * 16
REVOKE_ASSERTION_ID = "PAS-" + "33" * 16


class AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = phase120.CollaborationExecutionSessionAuthorityPhase120Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.fixture.fixture.fixture
        self.authority = fixture.initial_authority
        session = self.authority.to_dict()["session"]
        self.mission_id = session["mission_id"]
        self.worker_id = session["worker_principal_id"]
        self.control_id = phase109.CONTROL_ID
        self.root.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        policy = self.root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=POLICY_VERSION,
            store_id=self.root.store_id,
            allowed_profiles=[self.control_id, self.worker_id],
            allowed_operations=[
                PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE.value,
                PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT.value,
                PrincipalOperation.EXECUTION_SESSION_REVOKE.value,
            ],
        )
        self.root.trust.apply_policy(policy)
        self.control_grant = self._grant(
            CONTROL_GRANT_ID,
            self.control_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
        )
        self.worker_grant = self._grant(
            WORKER_GRANT_ID,
            self.worker_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
        )
        self.revoke_grant = self._grant(
            REVOKE_GRANT_ID,
            self.control_id,
            PrincipalOperation.EXECUTION_SESSION_REVOKE,
        )
        for grant in (
            self.control_grant,
            self.worker_grant,
            self.revoke_grant,
        ):
            self.root.acceptance.accept(grant)

        provisional_request = (
            build_collaboration_execution_session_activation_request(
                self.authority,
                control_plane_requester=self._placeholder(self.control_id, "4"),
                worker_acceptor=self._placeholder(self.worker_id, "5"),
                requested_at="2026-07-30T10:07:30Z",
            )
        )
        selection = collaboration_execution_session_activation_selection_sha256(
            provisional_request
        )
        self.control_assertion = self._assertion(
            self.control_grant,
            CONTROL_ASSERTION_ID,
            self.control_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
            "activation_selection_sha256",
            selection,
        )
        self.worker_assertion = self._assertion(
            self.worker_grant,
            WORKER_ASSERTION_ID,
            self.worker_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
            "activation_selection_sha256",
            selection,
        )
        self.request = build_collaboration_execution_session_activation_request(
            self.authority,
            control_plane_requester=self._binding(self.control_assertion),
            worker_acceptor=self._binding(self.worker_assertion),
            requested_at="2026-07-30T10:07:30Z",
        )

        provisional_revocation = build_collaboration_execution_session_revocation(
            self.authority,
            decision_owner=self._placeholder(self.control_id, "6"),
            reason_code="operator_request",
            revoked_at="2026-07-30T10:09:00Z",
        )
        revocation_selection = (
            collaboration_execution_session_revocation_selection_sha256(
                provisional_revocation
            )
        )
        self.revoke_assertion = self._assertion(
            self.revoke_grant,
            REVOKE_ASSERTION_ID,
            self.control_id,
            PrincipalOperation.EXECUTION_SESSION_REVOKE,
            "revocation_selection_sha256",
            revocation_selection,
        )
        self.revocation = build_collaboration_execution_session_revocation(
            self.authority,
            decision_owner=self._binding(self.revoke_assertion),
            reason_code="operator_request",
            revoked_at="2026-07-30T10:09:00Z",
        )
        self.root.now = datetime(2026, 7, 30, 10, 8, tzinfo=UTC)
        self.service = (
            AuthenticatedCollaborationExecutionSessionAuthorityService(
                self.root.store,
                self.root.registry,
                clock=lambda: self.root.now,
            )
        )

    def _grant(
        self,
        grant_id: str,
        profile_id: str,
        operation: PrincipalOperation,
    ):
        mission = self.root.mission
        return self.root.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=self.root.store_id,
            mission_id=self.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            operations=[operation.value],
            policy_version=POLICY_VERSION,
            expires_at=(
                "2026-07-30T10:08:30Z"
                if operation is PrincipalOperation.EXECUTION_SESSION_REVOKE
                else "2026-07-30T10:30:00Z"
            ),
        )

    def _assertion(
        self,
        grant,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        selection_field: str,
        selection_sha256: str,
    ):
        return self.root.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=self.mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                {
                    "mission_id": self.mission_id,
                    "principal_profile_id": profile_id,
                    selection_field: selection_sha256,
                },
            ),
            issued_at="2026-07-30T10:07:00Z",
            not_before="2026-07-30T10:07:00Z",
            expires_at=(
                "2026-07-30T10:13:00Z"
                if operation is PrincipalOperation.EXECUTION_SESSION_REVOKE
                else "2026-07-30T10:20:00Z"
            ),
        )

    @staticmethod
    def _binding(assertion) -> dict[str, str]:
        return {
            "profile_id": assertion.profile_id,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
        }

    @staticmethod
    def _placeholder(profile_id: str, marker: str) -> dict[str, str]:
        return {
            "profile_id": profile_id,
            "assertion_id": "PAS-" + marker * 32,
            "assertion_sha256": "sha256:" + marker * 64,
        }

    def _activate(self):
        return self.service.activate(
            self.authority,
            self.request,
            control_plane_assertion=self.control_assertion,
            worker_assertion=self.worker_assertion,
        )

    def _revoke(self):
        self.root.now = datetime(2026, 7, 30, 10, 9, tzinfo=UTC)
        return self.service.revoke(
            self.authority,
            self.revocation,
            independent_control_assertion=self.revoke_assertion,
        )

    def test_activation_is_atomic_durable_and_exactly_replayable(self) -> None:
        receipt = self._activate()
        self.root.now = datetime(2026, 7, 30, 10, 12, tzinfo=UTC)
        self.assertEqual(self._activate(), receipt)
        document = receipt.to_dict()
        self.assertEqual(
            document["authority_state"],
            "committed_available_for_executor",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            self.service.get_activation(receipt.authentication_id),
            receipt,
        )
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_authority_commits"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_activation_commits"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_revocation_is_atomic_replayable_and_blocks_new_activation(self) -> None:
        receipt = self._revoke()
        self.root.now = datetime(2026, 7, 30, 10, 12, tzinfo=UTC)
        self.assertEqual(self._revoke(), receipt)
        self.assertEqual(receipt.to_dict()["authority_state"], "revoked")
        self.assertEqual(receipt.to_dict()["runtime_effect"], "none")
        self.assertEqual(
            self.service.get_revocation(receipt.authentication_id),
            receipt,
        )
        with self.assertRaisesRegex(StoreConflictError, "cannot be activated"):
            self._activate()
        self.assertEqual(
            self.root.store.verify_mission(
                self.root.registry,
                self.mission_id,
            ).status,
            "valid",
        )

    def test_revocation_accepts_recently_expired_safety_scope(self) -> None:
        receipt = self._revoke()
        self.assertEqual(receipt.to_dict()["authority_state"], "revoked")
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_activation_then_revocation_preserves_both_histories(self) -> None:
        activation = self._activate()
        revocation = self._revoke()
        self.assertNotEqual(
            activation.control_plane_requester.ledger_entry_sha256,
            revocation.independent_control.ledger_entry_sha256,
        )
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_activation_commits"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_revocation_commits"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.root.store.verify_store(self.root.registry).status,
            "valid",
        )

    def test_late_activation_failure_rolls_back_authority_and_assertions(self) -> None:
        with patch.object(
            self.service,
            "_insert_activation",
            side_effect=sqlite3.IntegrityError("injected activation failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self._activate()
        with closing(sqlite3.connect(self.root.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_session_authority_commits"
                ).fetchone()[0],
                0,
            )

    def test_noncanonical_activation_fails_store_verification(self) -> None:
        self._activate()
        with closing(sqlite3.connect(self.root.path)) as connection:
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'execution_session_activation_commits_immutable'"
            ).fetchone()[0]
            row = connection.execute(
                "SELECT authentication_id, activation_json "
                "FROM execution_session_activation_commits"
            ).fetchone()
            connection.execute(
                "DROP TRIGGER execution_session_activation_commits_immutable"
            )
            connection.execute(
                "UPDATE execution_session_activation_commits "
                "SET activation_json = ? WHERE authentication_id = ?",
                (json.dumps(json.loads(row[1]), indent=2), row[0]),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "does not reconcile"):
            self.root.store.verify_store(self.root.registry)
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation IN (?, ?)
                    """,
                    (
                        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE.value,
                        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT.value,
                    ),
                ).fetchone()[0],
                0,
            )

    def test_receipts_match_strict_schemas(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        activation = self._activate().to_dict()
        self.root.now = datetime(2026, 7, 30, 10, 9, tzinfo=UTC)
        revocation = self._revoke().to_dict()
        activation_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-execution-session-activation-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        revocation_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-execution-session-revocation-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator(activation_schema).validate(activation)
        Draft202012Validator(revocation_schema).validate(revocation)


if __name__ == "__main__":
    unittest.main()

"""Phase 122 session activation and revocation authentication coverage."""

from __future__ import annotations

import ast
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_session_authentication import (
    authenticate_collaboration_execution_session_activation,
    authenticate_collaboration_execution_session_revocation,
    build_collaboration_execution_session_activation_request,
    collaboration_execution_session_activation_selection_sha256,
    collaboration_execution_session_revocation_selection_sha256,
    load_collaboration_execution_session_activation_request,
)
from sunderkey.collaboration_execution_session_authority import (
    build_collaboration_execution_session_revocation,
)
from sunderkey.errors import CollaborationPlanError, PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash

from . import test_authenticated_collaboration_execution_channel_phase109 as phase109
from . import test_collaboration_execution_session_authority_phase120 as phase120
from .test_identity_phase4 import AUDIENCE, STORE_ID, SUBJECT, CredentialFactory

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
NOW = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
CONTROL_GRANT_ID = "SGR-" + "21" * 16
WORKER_GRANT_ID = "SGR-" + "22" * 16
REVOKE_GRANT_ID = "SGR-" + "23" * 16
CONTROL_ASSERTION_ID = "PAS-" + "21" * 16
WORKER_ASSERTION_ID = "PAS-" + "22" * 16
REVOKE_ASSERTION_ID = "PAS-" + "23" * 16


class CollaborationExecutionSessionAuthenticationPhase122Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase120.CollaborationExecutionSessionAuthorityPhase120Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.authority = fixture.initial_authority
        self.mission_id = self.authority.to_dict()["session"]["mission_id"]
        self.worker_id = self.authority.to_dict()["session"]["worker_principal_id"]
        self.control_id = phase109.CONTROL_ID
        self.factory = CredentialFactory()
        operations = [
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
            PrincipalOperation.EXECUTION_SESSION_REVOKE,
        ]
        self.verified_policy = self.factory.verified_policy(
            allowed_profiles=[self.control_id, self.worker_id],
            allowed_operations=[item.value for item in operations],
        )
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
        self.control_scope = self._scope(
            self.control_grant,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
        )
        self.worker_scope = self._scope(
            self.worker_grant,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
        )
        self.revoke_scope = self._scope(
            self.revoke_grant,
            PrincipalOperation.EXECUTION_SESSION_REVOKE,
        )
        provisional = build_collaboration_execution_session_activation_request(
            self.authority,
            control_plane_requester=self._placeholder(self.control_id, "A"),
            worker_acceptor=self._placeholder(self.worker_id, "B"),
            requested_at="2026-07-30T10:05:30Z",
        )
        selection = collaboration_execution_session_activation_selection_sha256(
            provisional
        )
        self.control_assertion = self._assertion(
            self.control_grant,
            CONTROL_ASSERTION_ID,
            self.control_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
            selection,
        )
        self.worker_assertion = self._assertion(
            self.worker_grant,
            WORKER_ASSERTION_ID,
            self.worker_id,
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
            selection,
        )
        self.request = build_collaboration_execution_session_activation_request(
            self.authority,
            control_plane_requester=self._binding(self.control_assertion),
            worker_acceptor=self._binding(self.worker_assertion),
            requested_at="2026-07-30T10:05:30Z",
        )
        provisional_revocation = build_collaboration_execution_session_revocation(
            self.authority,
            decision_owner=self._placeholder(self.control_id, "C"),
            reason_code="operator_request",
            revoked_at="2026-07-30T10:06:00Z",
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
            revocation_selection,
        )
        self.revocation = build_collaboration_execution_session_revocation(
            self.authority,
            decision_owner=self._binding(self.revoke_assertion),
            reason_code="operator_request",
            revoked_at="2026-07-30T10:06:00Z",
        )

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        return self.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            mission_id=self.mission_id,
            operations=[operation.value],
        )

    def _scope(self, grant, operation: PrincipalOperation):
        return self.factory.verify_grant(
            grant,
            self.verified_policy,
            expected_mission_id=self.mission_id,
            expected_operation=operation,
            clock=lambda: NOW,
        )

    def _assertion(
        self,
        grant,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        selection_sha256: str,
    ):
        selection_field = (
            "revocation_selection_sha256"
            if operation is PrincipalOperation.EXECUTION_SESSION_REVOKE
            else "activation_selection_sha256"
        )
        intent = {
            selection_field: selection_sha256,
            "mission_id": self.mission_id,
            "principal_profile_id": profile_id,
        }
        return self.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            store_id=STORE_ID,
            mission_id=self.mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:10:00Z",
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
            "assertion_sha256": "sha256:" + marker.lower() * 64,
        }

    def _authenticate_activation(self, **overrides):
        arguments = {
            "authority": self.authority,
            "control_plane_assertion": self.control_assertion,
            "worker_assertion": self.worker_assertion,
            "verified_policy": self.verified_policy,
            "control_plane_scope": self.control_scope,
            "worker_scope": self.worker_scope,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_plane_profile_ids": [self.control_id],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_execution_session_activation(
            self.request,
            **arguments,
        )

    def _authenticate_revocation(self, **overrides):
        arguments = {
            "authority": self.authority,
            "independent_control_assertion": self.revoke_assertion,
            "verified_policy": self.verified_policy,
            "independent_control_scope": self.revoke_scope,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [self.control_id],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_execution_session_revocation(
            self.revocation,
            **arguments,
        )

    def test_activation_requires_control_plane_and_exact_worker(self) -> None:
        authenticated = self._authenticate_activation()
        document = authenticated.to_dict()
        self.assertTrue(document["authentication_id"].startswith("EAS-"))
        self.assertEqual(
            document["control_plane_requester"]["profile_id"],
            self.control_id,
        )
        self.assertEqual(document["worker_acceptor"]["profile_id"], self.worker_id)
        self.assertEqual(document["authenticated_at"], "2026-07-30T10:06:00Z")
        self.assertEqual(document["runtime_effect"], "none")

    def test_activation_selection_excludes_assertion_identity(self) -> None:
        alternate = build_collaboration_execution_session_activation_request(
            self.authority,
            control_plane_requester=self._placeholder(self.control_id, "D"),
            worker_acceptor=self._placeholder(self.worker_id, "E"),
            requested_at="2026-07-30T10:05:30Z",
        )
        self.assertEqual(
            collaboration_execution_session_activation_selection_sha256(alternate),
            collaboration_execution_session_activation_selection_sha256(self.request),
        )

    def test_activation_binding_profile_and_window_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            self._authenticate_activation(worker_assertion=self.control_assertion)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "control-plane"):
            self._authenticate_activation(
                expected_control_plane_profile_ids=[self.worker_id]
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "validity window"):
            self._authenticate_activation(
                clock=lambda: datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
            )

    def test_revocation_requires_independent_control_and_exact_time(self) -> None:
        authenticated = self._authenticate_revocation()
        document = authenticated.to_dict()
        self.assertTrue(document["authentication_id"].startswith("ESV-"))
        self.assertEqual(
            document["independent_control"]["profile_id"],
            self.control_id,
        )
        self.assertEqual(document["runtime_effect"], "none")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "independent Control"):
            self._authenticate_revocation(expected_control_profile_ids=[self.worker_id])
        with self.assertRaisesRegex(PrincipalAuthenticationError, "time"):
            self._authenticate_revocation(
                clock=lambda: datetime(2026, 7, 30, 10, 6, 1, tzinfo=UTC)
            )

    def test_wrappers_loaders_and_schemas_are_strict(self) -> None:
        with self.assertRaisesRegex(TypeError, "identity"):
            replace(
                self._authenticate_activation(),
                authentication_sha256="sha256:" + "0" * 64,
            )
        with self.assertRaisesRegex(TypeError, "identity"):
            replace(
                self._authenticate_revocation(),
                authentication_sha256="sha256:" + "0" * 64,
            )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "activation.json"
            path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_session_activation_request(
                    path
                ).activation_request_id,
                self.request.activation_request_id,
            )
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_session_activation_request(path)
        if Draft202012Validator is not None:
            request_schema = json.loads(
                (
                    SCHEMAS
                    / "collaboration-execution-session-activation-request-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            activation_schema = json.loads(
                (
                    SCHEMAS
                    / "collaboration-execution-session-activation-authentication-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            activation_schema["properties"]["activation_request"] = request_schema
            Draft202012Validator(request_schema).validate(self.request.to_dict())
            Draft202012Validator(activation_schema).validate(
                self._authenticate_activation().to_dict()
            )
            revocation_schema = json.loads(
                (
                    SCHEMAS
                    / "collaboration-execution-session-revocation-authentication-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            revocation_schema["properties"]["session_revocation"] = json.loads(
                (
                    SCHEMAS
                    / "collaboration-execution-session-revocation-v1.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(revocation_schema).validate(
                self._authenticate_revocation().to_dict()
            )

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (
                ROOT
                / "src/sunderkey/collaboration_execution_session_authentication.py"
            ).read_text(encoding="utf-8")
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        )
        self.assertFalse(
            imported
            & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )


if __name__ == "__main__":
    unittest.main()

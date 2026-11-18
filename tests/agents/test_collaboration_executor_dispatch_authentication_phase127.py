"""Phase 127 executor dispatch authentication and fail-safe coverage."""

from __future__ import annotations

import ast
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor import (
    build_collaboration_executor_dispatch,
    collaboration_executor_operation_input_sha256,
)
from sunderkey.collaboration_executor_dispatch_authentication import (
    AuthenticatedCollaborationExecutorDispatch,
    authenticate_collaboration_executor_dispatch,
    collaboration_executor_dispatch_selection_sha256,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_trust_policy,
)
from sunderkey.store import canonical_json, sha256_text

from . import test_collaboration_executor_phase125 as phase125
from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SUBJECT,
    public_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
POLICY_VERSION = 900127
NORMAL_GRANT_ID = "SGR-" + "51" * 16
NORMAL_ASSERTION_ID = "PAS-" + "51" * 16
SAFETY_GRANT_ID = "SGR-" + "52" * 16
SAFETY_ASSERTION_ID = "PAS-" + "52" * 16


class CollaborationExecutorDispatchAuthenticationPhase127Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase125.CollaborationExecutorPhase125Tests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.fixture.fixture.root
        self.dispatch = fixture._dispatch()
        self.worker_id = self.dispatch.to_dict()["worker"]["worker_principal_id"]
        self.control_id = fixture.fixture.fixture.control_id
        self.root.now = datetime(2026, 7, 30, 10, 8, 30, tzinfo=UTC)
        self.policy, self.verified_policy = self._apply_policy(self.root)
        self.grant = self._grant(
            self.root,
            NORMAL_GRANT_ID,
            self.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
            expires_at="2026-07-30T10:20:00Z",
        )
        self.root.acceptance.accept(self.grant)
        self.scope = self._scope(
            self.root,
            self.grant,
            self.verified_policy,
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
        )
        self.assertion = self._assertion(
            self.root,
            self.grant,
            NORMAL_ASSERTION_ID,
            self.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE,
            self.dispatch,
            issued_at="2026-07-30T10:08:20Z",
            expires_at="2026-07-30T10:10:00Z",
        )

    def _apply_policy(self, root):
        operations = [
            PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE.value,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE.value,
        ]
        policy = root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=POLICY_VERSION,
            store_id=root.store_id,
            allowed_profiles=[self.control_id, self.worker_id],
            allowed_operations=operations,
        )
        verified = verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(root.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=root.store_id,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: root.now,
        )
        root.trust.apply_policy(policy)
        return policy, verified

    @staticmethod
    def _grant(root, grant_id, profile_id, operation, *, expires_at):
        mission = root.mission
        return root.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=root.store_id,
            mission_id=mission.mission_id,
            mission_context_hash=root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            operations=[operation.value],
            policy_version=POLICY_VERSION,
            expires_at=expires_at,
        )

    @staticmethod
    def _scope(root, grant, policy, operation, *, allow_expired=False):
        mission = root.mission
        return root.factory.verify_grant(
            grant,
            policy,
            expected_audience=AUDIENCE,
            expected_store_id=root.store_id,
            expected_mission_id=mission.mission_id,
            expected_mission_context_hash=root.stored.context_hash,
            expected_scope_reference=mission.scope_reference,
            expected_scope_document_hash=mission.scope_document_hash,
            expected_environment=mission.environment.value,
            expected_max_action_tier=mission.max_action_tier.value,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            expected_operation=operation,
            allow_expired_for_safety_reduction=allow_expired,
            clock=lambda: root.now,
        )

    @staticmethod
    def _assertion(
        root,
        grant,
        assertion_id,
        profile_id,
        operation,
        dispatch,
        *,
        issued_at,
        expires_at,
    ):
        document = dispatch.to_dict()
        intent = {
            "dispatch_selection_sha256": (
                collaboration_executor_dispatch_selection_sha256(dispatch)
            ),
            "mission_id": document["mission"]["mission_id"],
            "principal_profile_id": profile_id,
        }
        return root.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=root.store_id,
            mission_id=document["mission"]["mission_id"],
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=expires_at,
        )

    def _authenticate(self):
        return authenticate_collaboration_executor_dispatch(
            self.dispatch,
            authorizer_assertion=self.assertion,
            verified_policy=self.verified_policy,
            authorizer_scope=self.scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_authorizer_profile_ids=[self.control_id],
            clock=lambda: self.root.now,
        )

    def test_nonworker_control_plane_authorizer_signs_exact_dispatch(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(
            document["control_plane_authorizer"]["profile_id"],
            self.control_id,
        )
        self.assertEqual(
            document["authentication_status"],
            "authenticated_control_plane_authorizer",
        )
        self.assertEqual(document["runtime_effect"], "none")

    def test_changed_dispatch_and_worker_self_authorization_fail_closed(self) -> None:
        changed = self.fixture._dispatch("heartbeat", sequence=2)
        with self.assertRaises(PrincipalAuthenticationError):
            authenticate_collaboration_executor_dispatch(
                changed,
                authorizer_assertion=self.assertion,
                verified_policy=self.verified_policy,
                authorizer_scope=self.scope,
                expected_audience=AUDIENCE,
                expected_store_id=self.root.store_id,
                expected_authorizer_profile_ids=[self.control_id],
                clock=lambda: self.root.now,
            )
        worker_assertion = self.fixture.fixture.fixture.worker_assertion
        with self.assertRaisesRegex(PrincipalAuthenticationError, "cannot authorize"):
            authenticate_collaboration_executor_dispatch(
                self.dispatch,
                authorizer_assertion=worker_assertion,
                verified_policy=self.verified_policy,
                authorizer_scope=self.scope,
                expected_audience=AUDIENCE,
                expected_store_id=self.root.store_id,
                expected_authorizer_profile_ids=[self.worker_id],
                clock=lambda: self.root.now,
            )

    def test_expired_authority_allows_bounded_safety_dispatch(self) -> None:
        grant = self._grant(
            self.root,
            SAFETY_GRANT_ID,
            self.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            expires_at="2026-07-30T10:30:30Z",
        )
        self.root.acceptance.accept(grant)
        self.root.now = datetime(2026, 7, 30, 10, 30, 40, tzinfo=UTC)
        expired = self.fixture.fixture._get()
        stop = build_collaboration_executor_dispatch(
            status=expired,
            authority=self.fixture.authority,
            collaboration_plan=self.fixture.plan,
            operation="stop",
            operation_sequence=2,
            tool_policy_sha256=phase125.TOOL_POLICY_SHA256,
            operation_input_sha256=(
                collaboration_executor_operation_input_sha256(b"stop")
            ),
            issued_at="2026-07-30T10:30:50Z",
            expires_at="2026-07-30T10:31:30Z",
        )
        assertion = self._assertion(
            self.root,
            grant,
            SAFETY_ASSERTION_ID,
            self.control_id,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            stop,
            issued_at="2026-07-30T10:30:20Z",
            expires_at="2026-07-30T10:35:30Z",
        )
        self.root.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        scope = self._scope(
            self.root,
            grant,
            self.verified_policy,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
            allow_expired=True,
        )
        authenticated = authenticate_collaboration_executor_dispatch(
            stop,
            authorizer_assertion=assertion,
            verified_policy=self.verified_policy,
            authorizer_scope=scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_authorizer_profile_ids=[self.control_id],
            clock=lambda: self.root.now,
        )
        self.assertEqual(
            authenticated.control_plane_authorizer.operation,
            PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE,
        )

    def test_wrapper_and_schema_are_strict(self) -> None:
        authenticated = self._authenticate()
        with self.assertRaisesRegex(TypeError, "only by"):
            AuthenticatedCollaborationExecutorDispatch(
                authentication_id=authenticated.authentication_id,
                authentication_sha256=authenticated.authentication_sha256,
                dispatch=authenticated.dispatch,
                control_plane_authorizer=authenticated.control_plane_authorizer,
                authenticated_at=authenticated.authenticated_at,
                _proof=b"wrong",
            )
        if Draft202012Validator is not None:
            schema = json.loads(
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
            schema["properties"]["dispatch"] = dispatch_schema
            Draft202012Validator(schema).validate(authenticated.to_dict())

    def test_module_has_no_network_storage_or_runtime_adapter(self) -> None:
        source_path = (
            ROOT / "src/sunderkey/collaboration_executor_dispatch_authentication.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
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
                {"http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
            )
        )


if __name__ == "__main__":
    unittest.main()

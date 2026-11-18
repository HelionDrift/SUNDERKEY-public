"""Phase 126 executor acknowledgement authentication coverage."""

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
    build_collaboration_executor_acknowledgement,
)
from sunderkey.collaboration_executor_authentication import (
    AuthenticatedCollaborationExecutorAcknowledgement,
    authenticate_collaboration_executor_acknowledgement,
    collaboration_executor_acknowledgement_selection_sha256,
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
POLICY_VERSION = 900126
GRANT_ID = "SGR-" + "41" * 16
ASSERTION_ID = "PAS-" + "41" * 16


class CollaborationExecutorAuthenticationPhase126Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase125.CollaborationExecutorPhase125Tests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.fixture.fixture.root
        self.dispatch = fixture._dispatch()
        self.acknowledgement = fixture._acknowledgement(self.dispatch)
        self.worker_id = self.dispatch.to_dict()["worker"]["worker_principal_id"]
        self.root.now = datetime(2026, 7, 30, 10, 8, 30, tzinfo=UTC)
        policy = self.root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=POLICY_VERSION,
            store_id=self.root.store_id,
            allowed_profiles=[self.worker_id],
            allowed_operations=[PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value],
        )
        self.verified_policy = verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(self.root.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: self.root.now,
        )
        self.root.trust.apply_policy(policy)
        mission = self.root.mission
        self.grant = self.root.factory.grant(
            grant_id=GRANT_ID,
            profile_id=self.worker_id,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            operations=[PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value],
            policy_version=POLICY_VERSION,
            expires_at="2026-07-30T10:20:00Z",
        )
        self.root.acceptance.accept(self.grant)
        self.worker_scope = self.root.factory.verify_grant(
            self.grant,
            self.verified_policy,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_mission_id=mission.mission_id,
            expected_mission_context_hash=self.root.stored.context_hash,
            expected_scope_reference=mission.scope_reference,
            expected_scope_document_hash=mission.scope_document_hash,
            expected_environment=mission.environment.value,
            expected_max_action_tier=mission.max_action_tier.value,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            expected_operation=PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
            clock=lambda: self.root.now,
        )
        self.assertion = self._assertion(self.acknowledgement)

    def _assertion(
        self,
        acknowledgement,
        *,
        assertion_id: str = ASSERTION_ID,
        issued_at: str = "2026-07-30T10:08:25Z",
    ):
        document = self.dispatch.to_dict()
        intent = {
            "acknowledgement_selection_sha256": (
                collaboration_executor_acknowledgement_selection_sha256(
                    acknowledgement
                )
            ),
            "dispatch_sha256": self.dispatch.dispatch_sha256,
            "mission_id": document["mission"]["mission_id"],
            "principal_profile_id": self.worker_id,
        }
        return self.root.factory.assertion(
            grant=self.grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=SUBJECT,
            profile_id=self.worker_id,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=document["mission"]["mission_id"],
            operation=PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
                intent,
            ),
            issued_at=issued_at,
            not_before=issued_at,
            expires_at="2026-07-30T10:10:00Z",
        )

    def _authenticate(self, acknowledgement=None, assertion=None):
        return authenticate_collaboration_executor_acknowledgement(
            self.dispatch,
            acknowledgement or self.acknowledgement,
            worker_assertion=assertion or self.assertion,
            verified_policy=self.verified_policy,
            worker_scope=self.worker_scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            clock=lambda: self.root.now,
        )

    def test_exact_worker_principal_authenticates_provider_report(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(
            document["worker_attestor"]["profile_id"],
            self.worker_id,
        )
        self.assertEqual(
            document["authentication_status"],
            "authenticated_worker_principal",
        )
        self.assertEqual(
            document["external_effect_status"],
            "authenticated_report_unverified_effect",
        )
        self.assertEqual(document["runtime_effect"], "none")

    def test_selection_binds_exact_report_dispatch_and_provider_evidence(self) -> None:
        changed = build_collaboration_executor_acknowledgement(
            self.dispatch,
            adapter_id="adapter.contract-test",
            adapter_version="1.0.1",
            adapter_build_sha256=phase125.ADAPTER_BUILD_SHA256,
            runtime_instance_id="worker.instance-001",
            outcome="accepted",
            provider_worker_state="ready",
            provider_evidence_sha256=phase125.EVIDENCE_SHA256,
            acknowledged_at="2026-07-30T10:08:20Z",
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(changed)

    def test_wrong_worker_and_late_authentication_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "does not match"):
            authenticate_collaboration_executor_acknowledgement(
                self.dispatch,
                self.acknowledgement,
                worker_assertion=self.fixture.fixture.fixture.control_assertion,
                verified_policy=self.verified_policy,
                worker_scope=self.worker_scope,
                expected_audience=AUDIENCE,
                expected_store_id=self.root.store_id,
                clock=lambda: self.root.now,
            )
        self.root.now = datetime(2026, 7, 30, 10, 9, 1, tzinfo=UTC)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "outside dispatch"):
            self._authenticate()

    def test_worker_cannot_presign_a_future_provider_report(self) -> None:
        early = self._assertion(
            self.acknowledgement,
            assertion_id="PAS-" + "42" * 16,
            issued_at="2026-07-30T10:08:15Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "precedes"):
            self._authenticate(assertion=early)

    def test_authenticated_wrapper_cannot_be_directly_forged(self) -> None:
        authenticated = self._authenticate()
        with self.assertRaisesRegex(TypeError, "only by"):
            AuthenticatedCollaborationExecutorAcknowledgement(
                authentication_id=authenticated.authentication_id,
                authentication_sha256=authenticated.authentication_sha256,
                acknowledgement=authenticated.acknowledgement,
                worker_attestor=authenticated.worker_attestor,
                authenticated_at=authenticated.authenticated_at,
                _proof=b"wrong",
            )

    def test_authentication_matches_published_schema(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        document = self._authenticate().to_dict()
        schema_path = (
            SCHEMAS
            / "collaboration-executor-acknowledgement-authentication-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        acknowledgement_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-acknowledgement-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["acknowledgement"] = acknowledgement_schema
        Draft202012Validator(schema).validate(document)

    def test_module_has_no_network_storage_or_runtime_adapter(self) -> None:
        source_path = ROOT / "src/sunderkey/collaboration_executor_authentication.py"
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

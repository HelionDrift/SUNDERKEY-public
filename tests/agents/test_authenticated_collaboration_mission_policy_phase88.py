"""Phase 88 durable authenticated mission-policy commit coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.collaboration import build_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    SUBJECT,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry/collaboration-reconfiguration-policy-d001-d005.json"
RECEIPT_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-mission-policy-commit-receipt-v1.schema.json"
)
MISSION_POLICY_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-mission-reconfiguration-policy-v1.schema.json"
)
MISSION_ID = "MISSION-PHASE88-POLICY"
OWNER_ID = "AOE-HQ-08"
CONTROL_ID = "AOE-HQ-12"
POLICY_VERSION = 88
ACTIVATION_GRANT_ID = "SGR-" + "A" * 32
OWNER_GRANT_ID = "SGR-" + "B" * 32
CONTROL_GRANT_ID = "SGR-" + "C" * 32
ACTIVATION_ASSERTION_ID = "PAS-" + "A" * 32
OWNER_ASSERTION_ID = "PAS-" + "B" * 32
CONTROL_ASSERTION_ID = "PAS-" + "C" * 32


class AuthenticatedCollaborationMissionPolicyPhase88Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "phase88.sqlite3"
        self.now = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.store.initialize()
        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
            }
        )
        self.mission = MissionRequest.from_dict(raw_mission)
        self.stored = self.store.create_mission(self.registry, self.mission)
        self.plan = build_collaboration_plan(self.registry, self.mission)
        self.factory = CredentialFactory()
        self.trust = TrustProvisioningService(self.store)
        self.store_id = self.trust.status().store_id
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        operations = [
            PrincipalOperation.COLLABORATION_ACTIVATE.value,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
        ]
        trust_policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=[OWNER_ID, CONTROL_ID],
            allowed_operations=operations,
        )
        self.trust.apply_policy(trust_policy)
        self.acceptance = ScopeGrantAcceptanceService(self.store, self.registry)
        self.activation_grant = self._grant(
            ACTIVATION_GRANT_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_ACTIVATE,
        )
        self.owner_grant = self._grant(
            OWNER_GRANT_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        self.control_grant = self._grant(
            CONTROL_GRANT_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )
        for grant in (
            self.activation_grant,
            self.owner_grant,
            self.control_grant,
        ):
            self.acceptance.accept(grant)
        activation_intent = {
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.plan.content_sha256,
            "plan_id": self.plan.plan_id,
            "principal_profile_id": OWNER_ID,
        }
        activation_assertion = self.factory.assertion(
            grant=self.activation_grant,
            assertion_id=ACTIVATION_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=ACTIVATION_GRANT_ID,
            subject=SUBJECT,
            profile_id=OWNER_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.COLLABORATION_ACTIVATE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.COLLABORATION_ACTIVATE,
                activation_intent,
            ),
        )
        AuthenticatedCollaborationActivationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).activate(activation_assertion, self.plan)
        provisional = self._policy(
            self._placeholder_binding(OWNER_ID, "D"),
            self._placeholder_binding(CONTROL_ID, "E"),
        )
        selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(provisional)
        self.owner_assertion = self._policy_assertion(
            self.owner_grant,
            OWNER_ASSERTION_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            selection_sha256,
        )
        self.control_assertion = self._policy_assertion(
            self.control_grant,
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            selection_sha256,
        )
        self.policy = self._policy(
            self._binding(self.owner_assertion),
            self._binding(self.control_assertion),
        )
        self.service = AuthenticatedCollaborationMissionPolicyService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        return self.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=sha256_text(canonical_json(self.mission.to_dict()["constraints"])),
            operations=[operation.value],
            policy_version=POLICY_VERSION,
        )

    def _policy_assertion(
        self,
        grant,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        selection_sha256: str,
    ):
        intent = {
            "mission_id": MISSION_ID,
            "policy_selection_sha256": selection_sha256,
            "principal_profile_id": profile_id,
        }
        return self.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
        )

    def _policy(
        self,
        owner_binding: dict[str, str],
        control_binding: dict[str, str],
    ):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=MISSION_ID,
            collaboration_plan_id=self.plan.plan_id,
            collaboration_plan_sha256=self.plan.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": True,
                "cross_command_transfer": False,
                "activated_plan_replacement": False,
                "distributed_execution_transfer_or_cancellation": False,
            },
            mission_owner_approval=owner_binding,
            independent_control_approval=control_binding,
            effective_at="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )

    @staticmethod
    def _placeholder_binding(profile_id: str, marker: str) -> dict[str, str]:
        return {
            "profile_id": profile_id,
            "assertion_id": "PAS-" + marker * 32,
            "assertion_sha256": "sha256:" + marker.lower() * 64,
        }

    @staticmethod
    def _binding(assertion) -> dict[str, str]:
        return {
            "profile_id": assertion.profile_id,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
        }

    def _commit(self):
        return self.service.commit(
            self.policy,
            authority_policy=self.authority,
            mission_owner_assertion=self.owner_assertion,
            independent_control_assertion=self.control_assertion,
        )

    def test_commit_is_atomic_durable_and_exactly_replayable(self) -> None:
        receipt = self._commit()
        replay = self._commit()
        self.assertEqual(replay, receipt)
        self.assertEqual(receipt.to_dict()["commit_status"], "committed_inactive")
        self.assertEqual(receipt.to_dict()["runtime_effect"], "none")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_mission_policy_commits"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE 'sunderkey.collaboration.policy.%'
                    """
                ).fetchone()[0],
                2,
            )
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def test_get_returns_latest_or_exact_policy_without_mutation(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "no matching"):
            self.service.get(MISSION_ID)
        receipt = self._commit()
        with closing(sqlite3.connect(self.path)) as connection:
            ledger_state = connection.execute(
                """
                SELECT assertion_count, effect_count, head_hash
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assertion_use_count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses"
            ).fetchone()[0]

        self.assertEqual(self.service.get(MISSION_ID), receipt)
        self.assertEqual(
            self.service.get(MISSION_ID, policy_version=1),
            receipt,
        )
        with self.assertRaisesRegex(StoreConflictError, "no matching"):
            self.service.get(MISSION_ID, policy_version=2)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT assertion_count, effect_count, head_hash
                    FROM mission_principal_ledgers
                    WHERE mission_id = ?
                    """,
                    (MISSION_ID,),
                ).fetchone(),
                ledger_state,
            )
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM principal_assertion_uses").fetchone()[0],
                assertion_use_count,
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_published_schema(self) -> None:
        schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["properties"]["policy"] = json.loads(
            MISSION_POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(self._commit().to_dict())

    def test_failed_second_approval_rolls_back_both_uses(self) -> None:
        wrong_control = self._policy_assertion(
            self.control_grant,
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            collaboration_mission_reconfiguration_selection_sha256(self.policy),
        )
        wrong_policy = self._policy(
            self._binding(self.owner_assertion),
            self._binding(wrong_control),
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.service.commit(
                wrong_policy,
                authority_policy=self.authority,
                mission_owner_assertion=self.owner_assertion,
                independent_control_assertion=wrong_control,
            )
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_mission_policy_commits"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE 'sunderkey.collaboration.policy.%'
                    """
                ).fetchone()[0],
                0,
            )

    def test_commit_history_is_immutable(self) -> None:
        self._commit()
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE collaboration_mission_policy_commits
                    SET committed_at = committed_at
                    """
                )
            connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "cannot be deleted",
            ):
                connection.execute("DELETE FROM collaboration_mission_policy_commits")

    def test_semantic_tampering_is_detected(self) -> None:
        self._commit()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name = 'collaboration_mission_policy_commits_immutable'
                """
            ).fetchone()[0]
            connection.execute("DROP TRIGGER collaboration_mission_policy_commits_immutable")
            connection.execute(
                """
                UPDATE collaboration_mission_policy_commits
                SET selection_sha256 = ?
                """,
                ("sha256:" + "0" * 64,),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "mission policy"):
            self.store.verify_store(self.registry)


if __name__ == "__main__":
    unittest.main()

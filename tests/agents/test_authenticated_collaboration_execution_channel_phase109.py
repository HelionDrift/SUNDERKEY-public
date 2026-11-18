"""Phase 109 durable authenticated execution-channel policy coverage."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authenticated_collaboration_execution_channel import (
    AuthenticatedCollaborationExecutionChannelPolicyService,
)
from sunderkey.collaboration_execution_channel import (
    build_collaboration_execution_channel_policy,
    collaboration_execution_channel_selection_sha256,
)
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.store import canonical_json, sha256_text

from . import test_authenticated_collaboration_mission_policy_phase88 as phase88

AUDIENCE = phase88.AUDIENCE
CONTROL_ID = phase88.CONTROL_ID
MISSION_ID = phase88.MISSION_ID
OWNER_ID = phase88.OWNER_ID
POLICY_VERSION = phase88.POLICY_VERSION
SUBJECT = phase88.SUBJECT

ROOT = Path(__file__).resolve().parents[2]
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "registry/schemas/collaboration-execution-channel-policy-commit-receipt-v1.schema.json"
)
CHANNEL_POLICY_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-channel-policy-v1.schema.json"
)
REPLACEMENT_OWNER_GRANT_ID = "SGR-" + "D" * 32
REPLACEMENT_CONTROL_GRANT_ID = "SGR-" + "E" * 32
CHANNEL_OWNER_GRANT_ID = "SGR-" + "F" * 32
CHANNEL_CONTROL_GRANT_ID = "SGR-" + "A1" * 16
REPLACEMENT_OWNER_ASSERTION_ID = "PAS-" + "D" * 32
REPLACEMENT_CONTROL_ASSERTION_ID = "PAS-" + "E" * 32
CHANNEL_OWNER_ASSERTION_ID = "PAS-" + "F" * 32
CHANNEL_CONTROL_ASSERTION_ID = "PAS-" + "A1" * 16


class AuthenticatedCollaborationExecutionChannelPhase109Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase88.AuthenticatedCollaborationMissionPolicyPhase88Tests(
            methodName="runTest"
        )
        phase88.AuthenticatedCollaborationMissionPolicyPhase88Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.initial_mission_policy_receipt = fixture._commit()
        fixture.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        operations = [
            PrincipalOperation.COLLABORATION_ACTIVATE.value,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE.value,
        ]
        fixture.trust.apply_policy(
            fixture.factory.policy(
                policy_version=POLICY_VERSION + 1,
                store_id=fixture.store_id,
                allowed_profiles=[OWNER_ID, CONTROL_ID],
                allowed_operations=operations,
            )
        )
        grants = {
            "replacement_owner": self._grant(
                REPLACEMENT_OWNER_GRANT_ID,
                OWNER_ID,
                PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            ),
            "replacement_control": self._grant(
                REPLACEMENT_CONTROL_GRANT_ID,
                CONTROL_ID,
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            ),
            "channel_owner": self._grant(
                CHANNEL_OWNER_GRANT_ID,
                OWNER_ID,
                PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE,
            ),
            "channel_control": self._grant(
                CHANNEL_CONTROL_GRANT_ID,
                CONTROL_ID,
                PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE,
            ),
        }
        for grant in grants.values():
            fixture.acceptance.accept(grant)
        self.grants = grants
        self.mission_policy = self._commit_d005_mission_policy()
        provisional = self._channel_policy(
            self._placeholder(OWNER_ID, "1"),
            self._placeholder(CONTROL_ID, "2"),
        )
        selection = collaboration_execution_channel_selection_sha256(provisional)
        self.owner_assertion = self._assertion(
            grants["channel_owner"],
            CHANNEL_OWNER_ASSERTION_ID,
            OWNER_ID,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE,
            {
                "channel_policy_selection_sha256": selection,
                "mission_id": MISSION_ID,
                "principal_profile_id": OWNER_ID,
            },
        )
        self.control_assertion = self._assertion(
            grants["channel_control"],
            CHANNEL_CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE,
            {
                "channel_policy_selection_sha256": selection,
                "mission_id": MISSION_ID,
                "principal_profile_id": CONTROL_ID,
            },
        )
        self.policy = self._channel_policy(
            self._binding(self.owner_assertion),
            self._binding(self.control_assertion),
        )
        self.service = AuthenticatedCollaborationExecutionChannelPolicyService(
            fixture.store,
            fixture.registry,
            clock=lambda: fixture.now,
        )

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        fixture = self.fixture
        return fixture.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=fixture.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=fixture.stored.context_hash,
            scope_reference=fixture.mission.scope_reference,
            scope_document_hash=fixture.mission.scope_document_hash,
            environment=fixture.mission.environment.value,
            max_action_tier=fixture.mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(fixture.mission.to_dict()["constraints"])
            ),
            operations=[operation.value],
            policy_version=POLICY_VERSION + 1,
        )

    def _assertion(
        self,
        grant,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        intent: dict[str, str],
    ):
        return self.fixture.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION + 1,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
        )

    def _commit_d005_mission_policy(self):
        initial = self.initial_mission_policy_receipt.policy
        provisional = self._replacement_mission_policy(
            self._placeholder(OWNER_ID, "3"),
            self._placeholder(CONTROL_ID, "4"),
        )
        selection = collaboration_mission_reconfiguration_selection_sha256(provisional)
        owner = self._assertion(
            self.grants["replacement_owner"],
            REPLACEMENT_OWNER_ASSERTION_ID,
            OWNER_ID,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection,
                "principal_profile_id": OWNER_ID,
            },
        )
        control = self._assertion(
            self.grants["replacement_control"],
            REPLACEMENT_CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection,
                "principal_profile_id": CONTROL_ID,
            },
        )
        policy = self._replacement_mission_policy(
            self._binding(owner),
            self._binding(control),
        )
        receipt = self.fixture.service.commit(
            policy,
            authority_policy=self.fixture.authority,
            mission_owner_assertion=owner,
            independent_control_assertion=control,
        )
        self.assertEqual(
            receipt.policy.to_dict()["previous_policy_sha256"],
            initial.policy_sha256,
        )
        return receipt.policy

    def _replacement_mission_policy(
        self,
        owner_binding: dict[str, str],
        control_binding: dict[str, str],
    ):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.fixture.authority,
            policy_version=2,
            previous_policy_sha256=self.initial_mission_policy_receipt.policy.policy_sha256,
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": True,
                "cross_command_transfer": False,
                "activated_plan_replacement": False,
                "distributed_execution_transfer_or_cancellation": True,
            },
            mission_owner_approval=owner_binding,
            independent_control_approval=control_binding,
            effective_at="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )

    def _channel_policy(
        self,
        owner_binding: dict[str, str],
        control_binding: dict[str, str],
    ):
        return build_collaboration_execution_channel_policy(
            authority_policy=self.fixture.authority,
            mission_policy=self.mission_policy,
            policy_version=1,
            previous_channel_policy_sha256=None,
            mission_owner_approval=owner_binding,
            independent_control_approval=control_binding,
            effective_at="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )

    @staticmethod
    def _placeholder(profile_id: str, marker: str) -> dict[str, str]:
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
            authority_policy=self.fixture.authority,
            mission_owner_assertion=self.owner_assertion,
            independent_control_assertion=self.control_assertion,
        )

    def test_commit_is_atomic_durable_and_exactly_replayable(self) -> None:
        receipt = self._commit()
        self.assertEqual(self._commit(), receipt)
        self.assertEqual(receipt.to_dict()["commit_status"], "committed_inactive")
        self.assertEqual(receipt.to_dict()["runtime_effect"], "none")
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE
                        'sunderkey.collaboration.execution-channel.policy.%'
                    """
                ).fetchone()[0],
                2,
            )
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_get_is_read_only_and_requires_exact_version(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "no matching"):
            self.service.get(MISSION_ID)
        receipt = self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            before = connection.execute(
                "SELECT assertion_count, effect_count, head_hash "
                "FROM mission_principal_ledgers WHERE mission_id = ?",
                (MISSION_ID,),
            ).fetchone()
        self.assertEqual(self.service.get(MISSION_ID), receipt)
        self.assertEqual(self.service.get(MISSION_ID, policy_version=1), receipt)
        with self.assertRaisesRegex(StoreConflictError, "no matching"):
            self.service.get(MISSION_ID, policy_version=2)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            after = connection.execute(
                "SELECT assertion_count, effect_count, head_hash "
                "FROM mission_principal_ledgers WHERE mission_id = ?",
                (MISSION_ID,),
            ).fetchone()
        self.assertEqual(after, before)

    def test_failed_control_approval_rolls_back_both_assertions(self) -> None:
        wrong_control = self._assertion(
            self.grants["channel_control"],
            CHANNEL_CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE,
            {
                "channel_policy_selection_sha256": (
                    collaboration_execution_channel_selection_sha256(self.policy)
                ),
                "mission_id": MISSION_ID,
                "principal_profile_id": CONTROL_ID,
            },
        )
        wrong_policy = self._channel_policy(
            self._binding(self.owner_assertion),
            self._binding(wrong_control),
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.service.commit(
                wrong_policy,
                authority_policy=self.fixture.authority,
                mission_owner_assertion=self.owner_assertion,
                independent_control_assertion=wrong_control,
            )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_channel_policy_commits"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE
                        'sunderkey.collaboration.execution-channel.policy.%'
                    """
                ).fetchone()[0],
                0,
            )

    def test_history_is_immutable_and_semantic_tampering_is_detected(self) -> None:
        self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE execution_channel_policy_commits "
                    "SET committed_at = committed_at"
                )
            connection.rollback()
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'trigger' "
                "AND name = 'execution_channel_policy_commits_immutable'"
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER execution_channel_policy_commits_immutable"
            )
            connection.execute(
                "UPDATE execution_channel_policy_commits "
                "SET selection_sha256 = ?",
                ("sha256:" + "0" * 64,),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "Execution channel"):
            self.fixture.store.verify_store(self.fixture.registry)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipt_matches_schema(self) -> None:
        schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
        schema["properties"]["policy"] = json.loads(
            CHANNEL_POLICY_SCHEMA_PATH.read_text(encoding="utf-8")
        )
        Draft202012Validator(schema).validate(self._commit().to_dict())


if __name__ == "__main__":
    unittest.main()

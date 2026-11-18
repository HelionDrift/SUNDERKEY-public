"""Phase 92 durable authenticated collaboration ownership coverage."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authenticated_collaboration_ownership import (
    AuthenticatedCollaborationOwnershipService,
)
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, sha256_text

from . import test_collaboration_ownership_preflight_phase90 as phase90
from .test_identity_phase4 import AUDIENCE, SUBJECT

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
MISSION_ID = phase90.MISSION_ID
SOURCE_ID = phase90.SOURCE_ID
CANDIDATE_ID = phase90.CANDIDATE_ID
CONTROL_ID = phase90.CONTROL_ID
CURRENT_GRANT_ID = "SGR-" + "1" * 32
PROPOSED_GRANT_ID = "SGR-" + "2" * 32
CONTROL_GRANT_ID = "SGR-" + "3" * 32
CLAIM_GRANT_ID = "SGR-" + "4" * 32
READINESS_CLAIM_GRANT_ID = "SGR-" + "6" * 32
READINESS_COMPLETE_GRANT_ID = "SGR-" + "7" * 32
CURRENT_ASSERTION_ID = "PAS-" + "1" * 32
PROPOSED_ASSERTION_ID = "PAS-" + "2" * 32
CONTROL_ASSERTION_ID = "PAS-" + "3" * 32
CLAIM_ASSERTION_ID = "PAS-" + "4" * 32


class AuthenticatedCollaborationOwnershipPhase92Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase90.CollaborationOwnershipPreflightPhase90Tests.setUpClass()

    def setUp(self) -> None:
        base = phase90.CollaborationOwnershipPreflightPhase90Tests(
            methodName="test_preflight_binds_policy_work_fence_and_chain_without_mutation"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.fixture.now += timedelta(minutes=1)
        self.policy_version = base.trust_policy_version + 1
        self.operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        )
        allowed_operations = sorted(
            {
                *(operation.value for operation in self.fixture.policy.allowed_operations),
                PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
                PrincipalOperation.WORK_CLAIM.value,
                PrincipalOperation.WORK_COMPLETE.value,
                *(operation.value for operation in self.operations),
            }
        )
        trust_policy = self.fixture.factory.policy(
            policy_version=self.policy_version,
            store_id=self.fixture.store_id,
            allowed_profiles=[
                phase90.OWNER_ID,
                CONTROL_ID,
                SOURCE_ID,
                CANDIDATE_ID,
                phase90.WRONG_COMMAND_ID,
            ],
            allowed_operations=allowed_operations,
        )
        self.fixture.trust.apply_policy(trust_policy)
        self.grants = {
            "current": self._grant(
                CURRENT_GRANT_ID,
                SOURCE_ID,
                self.operations[0],
            ),
            "proposed": self._grant(
                PROPOSED_GRANT_ID,
                CANDIDATE_ID,
                self.operations[1],
            ),
            "control": self._grant(
                CONTROL_GRANT_ID,
                CONTROL_ID,
                self.operations[2],
            ),
            "claim": self._grant(
                CLAIM_GRANT_ID,
                CANDIDATE_ID,
                PrincipalOperation.WORK_CLAIM,
            ),
            "readiness_claim": self._grant(
                READINESS_CLAIM_GRANT_ID,
                phase90.OWNER_ID,
                PrincipalOperation.WORK_CLAIM,
            ),
            "readiness_complete": self._grant(
                READINESS_COMPLETE_GRANT_ID,
                phase90.OWNER_ID,
                PrincipalOperation.WORK_COMPLETE,
            ),
        }
        acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )
        for grant in self.grants.values():
            acceptance.accept(grant)
        self._complete_readiness()
        self.entry = self._entry()
        self.preflight = self.base.service.preflight(self.entry)
        self.assertions = {
            "current": self._ownership_assertion(
                "current",
                CURRENT_ASSERTION_ID,
                SOURCE_ID,
                self.operations[0],
            ),
            "proposed": self._ownership_assertion(
                "proposed",
                PROPOSED_ASSERTION_ID,
                CANDIDATE_ID,
                self.operations[1],
            ),
            "control": self._ownership_assertion(
                "control",
                CONTROL_ASSERTION_ID,
                CONTROL_ID,
                self.operations[2],
            ),
        }
        self.service = AuthenticatedCollaborationOwnershipService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.now,
        )

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        return self.fixture.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.fixture.stored.context_hash,
            scope_reference=self.fixture.mission.scope_reference,
            scope_document_hash=self.fixture.mission.scope_document_hash,
            environment=self.fixture.mission.environment.value,
            max_action_tier=self.fixture.mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(self.fixture.mission.to_dict()["constraints"])
            ),
            operations=[operation.value],
            policy_version=self.policy_version,
        )

    def _entry(self):
        item = self.fixture.source
        return build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(collaboration_work_item_objective_sha256(item)),
            planned_owner_id=SOURCE_ID,
            sequence=1,
            owner_epoch=1,
            transition_kind="delegation",
            from_owner_id=SOURCE_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=None,
            reason_code="bounded_delegation",
            requested_at="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:35:00Z",
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": CURRENT_ASSERTION_ID,
                "proposed_owner_acceptance_id": PROPOSED_ASSERTION_ID,
                "independent_control_approval_id": CONTROL_ASSERTION_ID,
                "second_control_or_mission_authority_id": None,
            },
        )

    def _complete_readiness(self) -> None:
        item = self.fixture.readiness
        owner_id = phase90.OWNER_ID
        claim_intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": owner_id,
            "work_item_id": item.work_item_id,
        }
        claim_assertion = self.fixture.factory.assertion(
            grant=self.grants["readiness_claim"],
            assertion_id="PAS-" + "6" * 32,
            policy_version=self.policy_version,
            scope_grant_id=READINESS_CLAIM_GRANT_ID,
            subject=SUBJECT,
            profile_id=owner_id,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_CLAIM,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_CLAIM,
                claim_intent,
            ),
        )
        claim = self.fixture.work.claim(
            claim_assertion,
            MISSION_ID,
            item.work_item_id,
            expected_generation=0,
        )
        result_id = "RESULT-PHASE92-READINESS"
        result_sha256 = "sha256:" + "6" * 64
        evidence_sha256 = "sha256:" + "7" * 64
        complete_intent = {
            "claim_generation": claim.generation,
            "evidence_manifest_sha256": evidence_sha256,
            "expected_lease_expires_at": claim.lease_expires_at,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "previous_transition_id": claim.transition_id,
            "principal_profile_id": owner_id,
            "result_id": result_id,
            "result_sha256": result_sha256,
            "work_item_id": item.work_item_id,
        }
        complete_assertion = self.fixture.factory.assertion(
            grant=self.grants["readiness_complete"],
            assertion_id="PAS-" + "7" * 32,
            policy_version=self.policy_version,
            scope_grant_id=READINESS_COMPLETE_GRANT_ID,
            subject=SUBJECT,
            profile_id=owner_id,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_COMPLETE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_COMPLETE,
                complete_intent,
            ),
        )
        self.fixture.work.complete(
            complete_assertion,
            MISSION_ID,
            item.work_item_id,
            claim_generation=claim.generation,
            previous_transition_id=claim.transition_id,
            expected_lease_expires_at=claim.lease_expires_at,
            result_id=result_id,
            result_sha256=result_sha256,
            evidence_manifest_sha256=evidence_sha256,
        )

    def _ownership_assertion(
        self,
        name: str,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
    ):
        preflight = self.preflight.to_dict()
        intent = {
            "entry_id": self.entry.entry_id,
            "entry_sha256": self.entry.entry_sha256,
            "mission_id": MISSION_ID,
            "preflight_id": preflight["preflight_id"],
            "preflight_sha256": preflight["preflight_sha256"],
            "principal_profile_id": profile_id,
        }
        grant = self.grants[name]
        return self.fixture.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=self.policy_version,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
        )

    def _commit(self, **overrides):
        arguments = {
            "current_owner_assertion": self.assertions["current"],
            "proposed_owner_assertion": self.assertions["proposed"],
            "independent_control_assertion": self.assertions["control"],
        }
        arguments.update(overrides)
        return self.service.commit(self.preflight, **arguments)

    def test_commit_is_atomic_replayable_and_projects_effective_owner(self) -> None:
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            before = connection.execute(
                """
                SELECT assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        receipt = self._commit()
        self.assertEqual(self._commit(), receipt)
        document = receipt.to_dict()
        self.assertEqual(document["commit_status"], "committed_active")
        self.assertEqual(
            document["runtime_effect"],
            "ownership_projection_updated",
        )
        self.assertEqual(
            document["effective_owner"]["profile_id"],
            CANDIDATE_ID,
        )
        status = self.fixture.work.status(
            MISSION_ID,
            work_item_id=self.fixture.source.work_item_id,
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, CANDIDATE_ID)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            after = connection.execute(
                """
                SELECT assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(after[0], before[0] + 3)
            self.assertEqual(after[1], before[1] + 3)
        self.assertEqual(
            self.service.get(
                MISSION_ID,
                self.fixture.source.work_item_id,
            ),
            receipt,
        )
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_projected_owner_can_claim_and_planned_owner_cannot(self) -> None:
        self._commit()
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": CANDIDATE_ID,
            "work_item_id": self.fixture.source.work_item_id,
        }
        assertion = self.fixture.factory.assertion(
            grant=self.grants["claim"],
            assertion_id=CLAIM_ASSERTION_ID,
            policy_version=self.policy_version,
            scope_grant_id=CLAIM_GRANT_ID,
            subject=SUBJECT,
            profile_id=CANDIDATE_ID,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_CLAIM,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_CLAIM,
                intent,
            ),
        )
        receipt = self.fixture.work.claim(
            assertion,
            MISSION_ID,
            self.fixture.source.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(receipt.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_changed_live_work_fence_rolls_back_all_three_uses(self) -> None:
        source_grant = self._grant(
            "SGR-" + "5" * 32,
            SOURCE_ID,
            PrincipalOperation.WORK_CLAIM,
        )
        ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        ).accept(source_grant)
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": SOURCE_ID,
            "work_item_id": self.fixture.source.work_item_id,
        }
        assertion = self.fixture.factory.assertion(
            grant=source_grant,
            assertion_id="PAS-" + "5" * 32,
            policy_version=self.policy_version,
            scope_grant_id=source_grant.grant_id,
            subject=SUBJECT,
            profile_id=SOURCE_ID,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_CLAIM,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_CLAIM,
                intent,
            ),
        )
        self.fixture.work.claim(
            assertion,
            MISSION_ID,
            self.fixture.source.work_item_id,
            expected_generation=0,
        )
        with self.assertRaises(StoreConflictError):
            self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE 'sunderkey.collaboration.ownership.%'
                    """
                ).fetchone()[0],
                0,
            )

    def test_failed_third_approval_rolls_back_prior_uses(self) -> None:
        wrong_control = self._ownership_assertion(
            "control",
            CONTROL_ASSERTION_ID,
            CONTROL_ID,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._commit(independent_control_assertion=wrong_control)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation LIKE 'sunderkey.collaboration.ownership.%'
                    """
                ).fetchone()[0],
                0,
            )

    def test_commit_history_is_immutable_and_tampering_is_detected(self) -> None:
        self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    """
                    UPDATE collaboration_ownership_chain_entries
                    SET committed_at = committed_at
                    """
                )
            connection.rollback()
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_schema
                WHERE type = 'trigger'
                  AND name = 'collaboration_ownership_chain_entries_immutable'
                """
            ).fetchone()[0]
            connection.execute("DROP TRIGGER collaboration_ownership_chain_entries_immutable")
            connection.execute(
                """
                UPDATE collaboration_ownership_chain_entries
                SET authentication_sha256 = ?
                """,
                ("sha256:" + "0" * 64,),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "ownership"):
            self.fixture.store.verify_store(self.fixture.registry)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_published_schema(self) -> None:
        schema = json.loads(
            (SCHEMAS / "collaboration-ownership-commit-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        schema["properties"]["entry"] = json.loads(
            (SCHEMAS / "collaboration-ownership-chain-entry-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        Draft202012Validator(schema).validate(self._commit().to_dict())


if __name__ == "__main__":
    unittest.main()

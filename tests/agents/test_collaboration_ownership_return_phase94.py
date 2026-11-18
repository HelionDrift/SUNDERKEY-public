"""Phase 94 planned-owner return coverage."""

from __future__ import annotations

import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta

from sunderkey.authenticated_collaboration_ownership import (
    AuthenticatedCollaborationOwnershipService,
)
from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    collaboration_work_item_objective_sha256,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreConflictError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import format_timestamp

from . import test_authenticated_collaboration_ownership_phase92 as phase92
from . import test_collaboration_ownership_preflight_phase90 as phase90
from .test_identity_phase4 import AUDIENCE, SUBJECT

MISSION_ID = phase92.MISSION_ID
SOURCE_ID = phase92.SOURCE_ID
CANDIDATE_ID = phase92.CANDIDATE_ID
CONTROL_ID = phase92.CONTROL_ID
RETURN_CURRENT_GRANT_ID = "SGR-" + "94" * 16
RETURN_PROPOSED_GRANT_ID = "SGR-" + "95" * 16
RETURN_CONTROL_GRANT_ID = "SGR-" + "96" * 16
RETURN_CLAIM_GRANT_ID = "SGR-" + "97" * 16
RETURN_CURRENT_ASSERTION_ID = "PAS-" + "94" * 16
RETURN_PROPOSED_ASSERTION_ID = "PAS-" + "95" * 16
RETURN_CONTROL_ASSERTION_ID = "PAS-" + "96" * 16
RETURN_CLAIM_ASSERTION_ID = "PAS-" + "97" * 16


class CollaborationOwnershipReturnPhase94Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase92.AuthenticatedCollaborationOwnershipPhase92Tests.setUpClass()

    def setUp(self) -> None:
        base = phase92.AuthenticatedCollaborationOwnershipPhase92Tests(
            methodName="test_commit_is_atomic_replayable_and_projects_effective_owner"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.initial_receipt = base._commit()
        self.fixture.now += timedelta(minutes=1)
        self.return_grants = {
            "current": base._grant(
                RETURN_CURRENT_GRANT_ID,
                CANDIDATE_ID,
                base.operations[0],
            ),
            "proposed": base._grant(
                RETURN_PROPOSED_GRANT_ID,
                SOURCE_ID,
                base.operations[1],
            ),
            "control": base._grant(
                RETURN_CONTROL_GRANT_ID,
                CONTROL_ID,
                base.operations[2],
            ),
            "claim": base._grant(
                RETURN_CLAIM_GRANT_ID,
                SOURCE_ID,
                PrincipalOperation.WORK_CLAIM,
            ),
        }
        acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )
        for grant in self.return_grants.values():
            acceptance.accept(grant)
        self.entry = self._return_entry()
        self.preflight = self.base.base.service.preflight(self.entry)
        self.assertions = {
            "current": self._return_assertion(
                self.return_grants["current"],
                RETURN_CURRENT_ASSERTION_ID,
                CANDIDATE_ID,
                self.base.operations[0],
            ),
            "proposed": self._return_assertion(
                self.return_grants["proposed"],
                RETURN_PROPOSED_ASSERTION_ID,
                SOURCE_ID,
                self.base.operations[1],
            ),
            "control": self._return_assertion(
                self.return_grants["control"],
                RETURN_CONTROL_ASSERTION_ID,
                CONTROL_ID,
                self.base.operations[2],
            ),
        }
        self.service = AuthenticatedCollaborationOwnershipService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.now,
        )

    def _return_entry(self, *, previous_entry_sha256: str | None = None):
        item = self.fixture.source
        return build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=collaboration_work_item_objective_sha256(item),
            planned_owner_id=SOURCE_ID,
            sequence=2,
            owner_epoch=2,
            transition_kind="return_to_planned_owner",
            from_owner_id=CANDIDATE_ID,
            to_owner_id=SOURCE_ID,
            previous_entry_sha256=(
                self.initial_receipt.entry.entry_sha256
                if previous_entry_sha256 is None
                else previous_entry_sha256
            ),
            reason_code="planned_owner_return",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=20)),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": RETURN_CURRENT_ASSERTION_ID,
                "proposed_owner_acceptance_id": RETURN_PROPOSED_ASSERTION_ID,
                "independent_control_approval_id": RETURN_CONTROL_ASSERTION_ID,
                "second_control_or_mission_authority_id": None,
            },
        )

    def _return_assertion(
        self,
        grant,
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
        return self.fixture.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=self.base.policy_version,
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

    def _commit(self):
        return self.service.commit(
            self.preflight,
            current_owner_assertion=self.assertions["current"],
            proposed_owner_assertion=self.assertions["proposed"],
            independent_control_assertion=self.assertions["control"],
        )

    def test_return_commits_and_restores_planned_owner(self) -> None:
        projection = self.preflight.to_dict()["chain_projection"]
        self.assertEqual(projection["entry_count"], 2)
        self.assertEqual(projection["owner_epoch"], 2)
        self.assertEqual(projection["active_delegation_depth"], 0)
        self.assertEqual(projection["current_owner_id"], SOURCE_ID)

        receipt = self._commit()
        self.assertEqual(receipt.to_dict()["effective_owner"]["profile_id"], SOURCE_ID)
        status = self.fixture.work.status(
            MISSION_ID,
            work_item_id=self.fixture.source.work_item_id,
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, SOURCE_ID)
        self.assertEqual(
            self.service.get(MISSION_ID, self.fixture.source.work_item_id),
            receipt,
        )
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_return_replays_without_duplicate_chain_or_authority_use(self) -> None:
        receipt = self._commit()
        self.assertEqual(self._commit(), receipt)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                2,
            )

    def test_return_rejects_stale_predecessor_and_additional_delegation(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "exact chain head"):
            self.base.base.service.preflight(
                self._return_entry(previous_entry_sha256="sha256:" + "0" * 64)
            )
        additional_delegation = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=self.fixture.source.work_item_id,
            work_item_objective_sha256=collaboration_work_item_objective_sha256(
                self.fixture.source
            ),
            planned_owner_id=SOURCE_ID,
            sequence=2,
            owner_epoch=2,
            transition_kind="delegation",
            from_owner_id=CANDIDATE_ID,
            to_owner_id=phase90.OWNER_ID,
            previous_entry_sha256=self.initial_receipt.entry.entry_sha256,
            reason_code="additional_delegation",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=20)),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "AUTH-CURRENT-2",
                "proposed_owner_acceptance_id": "ACCEPT-PROPOSED-2",
                "independent_control_approval_id": "APPROVAL-CONTROL-2",
                "second_control_or_mission_authority_id": None,
            },
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.base.base.service.preflight(additional_delegation)

    def test_restored_owner_can_claim_work(self) -> None:
        self._commit()
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": SOURCE_ID,
            "work_item_id": self.fixture.source.work_item_id,
        }
        assertion = self.fixture.factory.assertion(
            grant=self.return_grants["claim"],
            assertion_id=RETURN_CLAIM_ASSERTION_ID,
            policy_version=self.base.policy_version,
            scope_grant_id=RETURN_CLAIM_GRANT_ID,
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
        claim = self.fixture.work.claim(
            assertion,
            MISSION_ID,
            self.fixture.source.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(claim.owner_profile_id, SOURCE_ID)

        delegated_intent = {**intent, "principal_profile_id": CANDIDATE_ID}
        delegated_assertion = self.fixture.factory.assertion(
            grant=self.base.grants["claim"],
            assertion_id=phase92.CLAIM_ASSERTION_ID,
            policy_version=self.base.policy_version,
            scope_grant_id=phase92.CLAIM_GRANT_ID,
            subject=SUBJECT,
            profile_id=CANDIDATE_ID,
            audience=AUDIENCE,
            store_id=self.fixture.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.WORK_CLAIM,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.WORK_CLAIM,
                delegated_intent,
            ),
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.fixture.work.claim(
                delegated_assertion,
                MISSION_ID,
                self.fixture.source.work_item_id,
                expected_generation=0,
            )


if __name__ == "__main__":
    unittest.main()

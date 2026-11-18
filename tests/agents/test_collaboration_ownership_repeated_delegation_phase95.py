"""Phase 95 repeated bounded delegation coverage."""

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
from sunderkey.errors import StoreConflictError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import format_timestamp

from . import test_authenticated_collaboration_ownership_phase92 as phase92
from . import test_collaboration_ownership_return_phase94 as phase94
from .test_identity_phase4 import AUDIENCE, SUBJECT

MISSION_ID = phase94.MISSION_ID
SOURCE_ID = phase94.SOURCE_ID
CANDIDATE_ID = phase94.CANDIDATE_ID
CONTROL_ID = phase94.CONTROL_ID
CURRENT_GRANT_ID = "SGR-" + "E1" * 16
PROPOSED_GRANT_ID = "SGR-" + "E2" * 16
CONTROL_GRANT_ID = "SGR-" + "E3" * 16
CURRENT_ASSERTION_ID = "PAS-" + "E1" * 16
PROPOSED_ASSERTION_ID = "PAS-" + "E2" * 16
CONTROL_ASSERTION_ID = "PAS-" + "E3" * 16


class CollaborationOwnershipRepeatedDelegationPhase95Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase94.CollaborationOwnershipReturnPhase94Tests.setUpClass()

    def setUp(self) -> None:
        base = phase94.CollaborationOwnershipReturnPhase94Tests(
            methodName="test_return_commits_and_restores_planned_owner"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.return_receipt = base._commit()
        self.fixture.now += timedelta(minutes=1)
        self.grants = {
            "current": base.base._grant(
                CURRENT_GRANT_ID,
                SOURCE_ID,
                base.base.operations[0],
            ),
            "proposed": base.base._grant(
                PROPOSED_GRANT_ID,
                CANDIDATE_ID,
                base.base.operations[1],
            ),
            "control": base.base._grant(
                CONTROL_GRANT_ID,
                CONTROL_ID,
                base.base.operations[2],
            ),
        }
        acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )
        for grant in self.grants.values():
            acceptance.accept(grant)
        self.entry = self._entry()
        self.preflight = self.base.base.base.service.preflight(self.entry)
        self.assertions = {
            "current": self._assertion(
                self.grants["current"],
                CURRENT_ASSERTION_ID,
                SOURCE_ID,
                self.base.base.operations[0],
            ),
            "proposed": self._assertion(
                self.grants["proposed"],
                PROPOSED_ASSERTION_ID,
                CANDIDATE_ID,
                self.base.base.operations[1],
            ),
            "control": self._assertion(
                self.grants["control"],
                CONTROL_ASSERTION_ID,
                CONTROL_ID,
                self.base.base.operations[2],
            ),
        }
        self.service = AuthenticatedCollaborationOwnershipService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.now,
        )

    def _entry(
        self,
        *,
        previous_entry_sha256: str | None = None,
        transition_kind: str = "delegation",
    ):
        item = self.fixture.source
        return build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=collaboration_work_item_objective_sha256(item),
            planned_owner_id=SOURCE_ID,
            sequence=3,
            owner_epoch=3,
            transition_kind=transition_kind,
            from_owner_id=SOURCE_ID,
            to_owner_id=CANDIDATE_ID,
            previous_entry_sha256=(
                self.return_receipt.entry.entry_sha256
                if previous_entry_sha256 is None
                else previous_entry_sha256
            ),
            reason_code="renewed_bounded_delegation",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=20)),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": CURRENT_ASSERTION_ID,
                "proposed_owner_acceptance_id": PROPOSED_ASSERTION_ID,
                "independent_control_approval_id": CONTROL_ASSERTION_ID,
                "second_control_or_mission_authority_id": None,
            },
        )

    def _assertion(
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
        issued_at = format_timestamp(self.fixture.now)
        return self.fixture.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=self.base.base.policy_version,
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
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=4)),
        )

    def _commit(self):
        return self.service.commit(
            self.preflight,
            current_owner_assertion=self.assertions["current"],
            proposed_owner_assertion=self.assertions["proposed"],
            independent_control_assertion=self.assertions["control"],
        )

    def test_repeated_delegation_commits_and_projects_current_owner(self) -> None:
        projection = self.preflight.to_dict()["chain_projection"]
        self.assertEqual(projection["entry_count"], 3)
        self.assertEqual(projection["owner_epoch"], 3)
        self.assertEqual(projection["active_delegation_depth"], 1)
        self.assertEqual(projection["current_owner_id"], CANDIDATE_ID)

        receipt = self._commit()
        self.assertEqual(receipt.to_dict()["effective_owner"]["profile_id"], CANDIDATE_ID)
        status = self.fixture.work.status(
            MISSION_ID,
            work_item_id=self.fixture.source.work_item_id,
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, CANDIDATE_ID)
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_repeated_delegation_replays_without_duplicate_history(self) -> None:
        receipt = self._commit()
        self.assertEqual(self._commit(), receipt)
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                3,
            )

    def test_stale_head_and_unsupported_transition_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "exact chain head"):
            self.base.base.base.service.preflight(
                self._entry(previous_entry_sha256="sha256:" + "0" * 64)
            )
        with self.assertRaisesRegex(StoreConflictError, "only delegation"):
            self.base.base.base.service.preflight(
                self._entry(transition_kind="privileged_reassignment")
            )

    def test_repeated_delegated_owner_can_claim_work(self) -> None:
        self._commit()
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": CANDIDATE_ID,
            "work_item_id": self.fixture.source.work_item_id,
        }
        grant = self.base.base.grants["claim"]
        issued_at = format_timestamp(self.fixture.now)
        assertion = self.fixture.factory.assertion(
            grant=grant,
            assertion_id=phase92.CLAIM_ASSERTION_ID,
            policy_version=self.base.base.policy_version,
            scope_grant_id=grant.grant_id,
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
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=4)),
        )
        claim = self.fixture.work.claim(
            assertion,
            MISSION_ID,
            self.fixture.source.work_item_id,
            expected_generation=0,
        )
        self.assertEqual(claim.owner_profile_id, CANDIDATE_ID)


if __name__ == "__main__":
    unittest.main()

"""Phase 105 atomic privileged ownership reassignment coverage."""

from __future__ import annotations

import sqlite3
import unittest
from contextlib import closing
from datetime import timedelta
from unittest.mock import patch

from sunderkey.authenticated_collaboration_ownership import (
    AuthenticatedCollaborationOwnershipService,
)
from sunderkey.authenticated_collaboration_ownership_privileged_reassignment import (
    AuthenticatedCollaborationOwnershipPrivilegedReassignmentService,
)
from sunderkey.collaboration import WorkItemKind
from sunderkey.errors import PrincipalAuthenticationError, StoreIntegrityError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from . import test_privileged_scope_admission_phase104 as phase104
from .test_identity_phase4 import SUBJECT


class PrivilegedOwnershipReassignmentCommitPhase105Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase104.PrivilegedScopeAdmissionPhase104Tests.setUpClass()

    def setUp(self) -> None:
        base = phase104.PrivilegedScopeAdmissionPhase104Tests(
            methodName="runTest"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.fixture.now += timedelta(minutes=1)
        self.policy_version = base.policy_version + 1
        self.control_replacement = self._testMethodName != (
            "test_three_party_privileged_reassignment_commits"
        )
        self.profiles = {
            "current": (
                "AOE-HQ-12" if self.control_replacement else "AOE-HQ-08"
            ),
            "proposed": (
                "AOE-HQ-13" if self.control_replacement else "AOE-HQ-09"
            ),
            "control": "AOE-HQ-14",
            "second": "AOE-HQ-15",
        }
        self.operations = {
            "current": (
                PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE
            ),
            "proposed": (
                PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT
            ),
            "control": (
                PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE
            ),
            "second": (
                PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE
            ),
        }
        policy = self.fixture.factory.policy(
            policy_version=self.policy_version,
            store_id=self.fixture.store_id,
            allowed_profiles=sorted(
                {
                    *self.fixture.stored.allowed_profile_ids,
                    *self.profiles.values(),
                }
            ),
            allowed_operations=sorted(
                operation.value for operation in PrincipalOperation
            ),
        )
        self.fixture.trust.apply_policy(policy)
        self.preflight = self.base.base.service.preflight(
            self.base.base.entry(
                (
                    WorkItemKind.CONTROL_REVIEW
                    if self.control_replacement
                    else WorkItemKind.READINESS
                ),
                self.profiles["proposed"],
                control_role_replacement=self.control_replacement,
                second_authority_id=(
                    "PAS-" + "D" * 32
                    if self.control_replacement
                    else None
                ),
            )
        )
        self.grants = self._accept_grants()
        self.assertions = self._assertions()
        self.service = (
            AuthenticatedCollaborationOwnershipPrivilegedReassignmentService(
                self.fixture.store,
                self.fixture.registry,
                clock=lambda: self.fixture.now,
            )
        )

    def _accept_grants(self):
        entry = self.preflight.entry.to_dict()
        constraints_hash = sha256_text(
            canonical_json(self.fixture.mission.to_dict()["constraints"])
        )
        acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )
        grants = {}
        for index, name in enumerate(self.profiles, start=1):
            grant = self.fixture.factory.grant(
                grant_id=("SGR-" + f"105{index:X}" * 8),
                profile_id=self.profiles[name],
                store_id=self.fixture.store_id,
                mission_id=entry["mission_id"],
                mission_context_hash=self.fixture.stored.context_hash,
                scope_reference=self.fixture.mission.scope_reference,
                scope_document_hash=self.fixture.mission.scope_document_hash,
                environment=self.fixture.mission.environment.value,
                max_action_tier=self.fixture.mission.max_action_tier.value,
                constraints_hash=constraints_hash,
                operations=[self.operations[name].value],
                policy_version=self.policy_version,
            )
            acceptance.accept(grant)
            grants[name] = grant
        return grants

    def _assertions(self):
        preflight = self.preflight.to_dict()
        entry = self.preflight.entry
        entry_document = entry.to_dict()
        markers = {"current": "A", "proposed": "B", "control": "C", "second": "D"}
        issued_at = format_timestamp(self.fixture.now)
        expires_at = format_timestamp(self.fixture.now + timedelta(minutes=1))
        assertions = {}
        for name, grant in self.grants.items():
            intent = {
                "entry_id": entry.entry_id,
                "entry_sha256": entry.entry_sha256,
                "mission_id": entry_document["mission_id"],
                "preflight_id": preflight["preflight_id"],
                "preflight_sha256": preflight["preflight_sha256"],
                "principal_profile_id": self.profiles[name],
            }
            assertions[name] = self.fixture.factory.assertion(
                grant=grant,
                assertion_id="PAS-" + markers[name] * 32,
                policy_version=self.policy_version,
                scope_grant_id=grant.grant_id,
                subject=SUBJECT,
                profile_id=self.profiles[name],
                store_id=self.fixture.store_id,
                mission_id=entry_document["mission_id"],
                operation=self.operations[name],
                operation_intent_sha256=compute_operation_intent_hash(
                    self.operations[name],
                    intent,
                ),
                issued_at=issued_at,
                not_before=issued_at,
                expires_at=expires_at,
            )
        return assertions

    def _commit(self):
        return self.service.commit(
            self.preflight,
            current_owner_assertion=self.assertions["current"],
            proposed_owner_assertion=self.assertions["proposed"],
            independent_control_assertion=self.assertions["control"],
            second_authority_assertion=self.assertions["second"],
        )

    def test_four_party_control_reassignment_commits_and_replays(self) -> None:
        receipt = self._commit()
        replay = self._commit()
        self.assertEqual(replay, receipt)
        document = receipt.to_dict()
        self.assertEqual(
            document["effective_owner"]["profile_id"],
            self.profiles["proposed"],
        )
        self.assertIsNotNone(
            document["second_control_or_mission_authority"]
        )
        self.assertEqual(
            self.service.get(
                self.preflight.entry.to_dict()["mission_id"],
                self.preflight.entry.to_dict()["work_item_id"],
            ),
            receipt,
        )
        self.assertEqual(
            AuthenticatedCollaborationOwnershipService(
                self.fixture.store,
                self.fixture.registry,
                clock=lambda: self.fixture.now,
            ).get(
                self.preflight.entry.to_dict()["mission_id"],
                self.preflight.entry.to_dict()["work_item_id"],
            ),
            receipt,
        )
        status = self.fixture.work.status(
            self.preflight.entry.to_dict()["mission_id"],
            work_item_id=self.preflight.entry.to_dict()["work_item_id"],
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, self.profiles["proposed"])
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            row = connection.execute(
                "SELECT transition_kind, second_authority_assertion_id "
                "FROM collaboration_ownership_chain_entries "
                "WHERE entry_id = ?",
                (receipt.entry.entry_id,),
            ).fetchone()
        self.assertEqual(row, ("privileged_reassignment", "PAS-" + "D" * 32))

    def test_missing_fourth_authority_is_rejected_without_consumption(self) -> None:
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "authority count",
        ):
            self.service.commit(
                self.preflight,
                current_owner_assertion=self.assertions["current"],
                proposed_owner_assertion=self.assertions["proposed"],
                independent_control_assertion=self.assertions["control"],
            )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses "
                "WHERE assertion_id IN (?, ?, ?, ?)",
                tuple(item.assertion_id for item in self.assertions.values()),
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_fourth_authority_record_failure_rolls_back_all_uses(self) -> None:
        original = self.service._policies._record_assertion
        call_count = 0

        def fail_on_fourth(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 4:
                raise StoreIntegrityError("injected fourth authority failure")
            return original(*args, **kwargs)

        with patch.object(
            self.service._policies,
            "_record_assertion",
            side_effect=fail_on_fourth,
        ), self.assertRaisesRegex(StoreIntegrityError, "injected"):
            self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            uses = connection.execute(
                "SELECT COUNT(*) FROM principal_assertion_uses "
                "WHERE assertion_id IN (?, ?, ?, ?)",
                tuple(item.assertion_id for item in self.assertions.values()),
            ).fetchone()[0]
            entries = connection.execute(
                "SELECT COUNT(*) FROM collaboration_ownership_chain_entries "
                "WHERE entry_id = ?",
                (self.preflight.entry.entry_id,),
            ).fetchone()[0]
        self.assertEqual((uses, entries), (0, 0))

    def test_three_party_privileged_reassignment_commits(self) -> None:
        receipt = self.service.commit(
            self.preflight,
            current_owner_assertion=self.assertions["current"],
            proposed_owner_assertion=self.assertions["proposed"],
            independent_control_assertion=self.assertions["control"],
        )
        self.assertIsNone(receipt.second_authority_assertion_id)
        self.assertEqual(
            receipt.to_dict()["effective_owner"]["profile_id"],
            self.profiles["proposed"],
        )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            row = connection.execute(
                "SELECT second_authority_issuer, "
                "second_authority_assertion_id "
                "FROM collaboration_ownership_chain_entries "
                "WHERE entry_id = ?",
                (receipt.entry.entry_id,),
            ).fetchone()
        self.assertEqual(row, (None, None))
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()

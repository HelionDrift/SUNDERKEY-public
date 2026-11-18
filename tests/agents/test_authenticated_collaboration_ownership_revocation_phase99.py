"""Phase 99 durable authenticated ownership revocation coverage."""

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
from sunderkey.authenticated_collaboration_ownership_revocation import (
    AuthenticatedCollaborationOwnershipRevocationService,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from . import test_collaboration_ownership_revocation_preflight_phase96 as phase96
from .test_identity_phase4 import AUDIENCE, SUBJECT

MISSION_ID = phase96.MISSION_ID
SOURCE_ID = phase96.SOURCE_ID
CANDIDATE_ID = phase96.CANDIDATE_ID
CONTROL_ID = phase96.CONTROL_ID
PLANNED_GRANT_ID = "SGR-" + "F4" * 16
CONTROL_GRANT_ID = "SGR-" + "F5" * 16
ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"


class AuthenticatedCollaborationOwnershipRevocationPhase99Tests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls) -> None:
        phase96.CollaborationOwnershipRevocationPreflightPhase96Tests.setUpClass()

    def setUp(self) -> None:
        base = phase96.CollaborationOwnershipRevocationPreflightPhase96Tests(
            methodName="runTest"
        )
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.base = base
        self.fixture = base.fixture
        self.operations = (
            PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT,
            PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE,
        )
        self.grants = {
            "planned": self._grant(
                PLANNED_GRANT_ID,
                SOURCE_ID,
                self.operations[0],
            ),
            "control": self._grant(
                CONTROL_GRANT_ID,
                CONTROL_ID,
                self.operations[1],
            ),
        }
        acceptance = ScopeGrantAcceptanceService(
            self.fixture.store,
            self.fixture.registry,
        )
        for grant in self.grants.values():
            acceptance.accept(grant)
        self.preflight = base.service.preflight(base.revocation)
        self.assertions = {
            "planned": self._assertion(
                "planned",
                phase96.PLANNED_ACCEPTANCE_ID,
                SOURCE_ID,
                self.operations[0],
            ),
            "control": self._assertion(
                "control",
                phase96.CONTROL_APPROVAL_ID,
                CONTROL_ID,
                self.operations[1],
            ),
        }
        self.service = AuthenticatedCollaborationOwnershipRevocationService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.now,
        )

    def _grant(
        self,
        grant_id: str,
        profile_id: str,
        operation: PrincipalOperation,
    ):
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
            policy_version=self.base.base.policy_version,
        )

    def _assertion(
        self,
        name: str,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        *,
        signed_intent: str | None = None,
    ):
        preflight = self.preflight.to_dict()
        entry = self.preflight.entry
        intent = {
            "entry_id": entry.entry_id,
            "entry_sha256": entry.entry_sha256,
            "mission_id": MISSION_ID,
            "preflight_id": preflight["preflight_id"],
            "preflight_sha256": preflight["preflight_sha256"],
            "principal_profile_id": profile_id,
        }
        grant = self.grants[name]
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
            operation_intent_sha256=(
                signed_intent
                or compute_operation_intent_hash(operation, intent)
            ),
            issued_at=issued_at,
            not_before=issued_at,
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=4)),
        )

    def _commit(self):
        return self.service.commit(
            self.preflight,
            planned_owner_assertion=self.assertions["planned"],
            independent_control_assertion=self.assertions["control"],
        )

    def counts(self) -> tuple[int, int, int]:
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            return (
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) "
                    "FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
            )

    def test_commit_is_atomic_replayable_and_restores_planned_owner(self) -> None:
        before = self.counts()
        receipt = self._commit()
        retry = self._commit()
        self.assertEqual(retry, receipt)
        self.assertEqual(self.counts(), (before[0] + 2, before[1] + 2, before[2] + 1))
        document = receipt.to_dict()
        self.assertEqual(document["entry"]["transition_kind"], "control_revocation")
        self.assertEqual(document["effective_owner"]["profile_id"], SOURCE_ID)
        self.assertEqual(
            document["planned_owner"]["assertion_id"],
            phase96.PLANNED_ACCEPTANCE_ID,
        )
        self.assertEqual(
            document["independent_control"]["assertion_id"],
            phase96.CONTROL_APPROVAL_ID,
        )
        self.assertEqual(document["runtime_effect"], "ownership_projection_updated")
        self.assertEqual(
            self.service.get(
                MISSION_ID,
                self.fixture.source.work_item_id,
            ),
            receipt,
        )
        self.assertEqual(
            AuthenticatedCollaborationOwnershipService(
                self.fixture.store,
                self.fixture.registry,
                clock=lambda: self.fixture.now,
            ).get(MISSION_ID, self.fixture.source.work_item_id),
            receipt,
        )
        status = self.fixture.work.status(
            MISSION_ID,
            work_item_id=self.fixture.source.work_item_id,
        ).work_items[0]
        self.assertEqual(status.owner_profile_id, SOURCE_ID)
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_invalid_second_approval_rolls_back_first_use(self) -> None:
        before = self.counts()
        invalid = self._assertion(
            "control",
            phase96.CONTROL_APPROVAL_ID,
            CONTROL_ID,
            self.operations[1],
            signed_intent="sha256:" + "0" * 64,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.service.commit(
                self.preflight,
                planned_owner_assertion=self.assertions["planned"],
                independent_control_assertion=invalid,
            )
        self.assertEqual(self.counts(), before)

    def test_changed_live_work_fence_consumes_no_authority(self) -> None:
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
            assertion_id="PAS-" + "F6" * 16,
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
        self.fixture.work.claim(
            assertion,
            MISSION_ID,
            self.fixture.source.work_item_id,
            expected_generation=0,
        )
        before = self.counts()
        with self.assertRaisesRegex(StoreConflictError, "Active work item lease"):
            self._commit()
        self.assertEqual(self.counts(), before)

    def test_committed_revocation_is_immutable(self) -> None:
        receipt = self._commit()
        with (
            closing(sqlite3.connect(self.fixture.path)) as connection,
            self.assertRaises(sqlite3.IntegrityError),
        ):
            connection.execute(
                "UPDATE collaboration_ownership_chain_entries "
                "SET revocation_json = '{}' WHERE entry_id = ?",
                (receipt.entry.entry_id,),
            )

    def test_full_store_verification_detects_revocation_tampering(self) -> None:
        receipt = self._commit()
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'collaboration_ownership_chain_entries_immutable'"
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER collaboration_ownership_chain_entries_immutable"
            )
            connection.execute(
                "UPDATE collaboration_ownership_chain_entries "
                "SET authentication_sha256 = ? WHERE entry_id = ?",
                ("sha256:" + "0" * 64, receipt.entry.entry_id),
            )
            connection.execute(trigger_sql)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "ownership"):
            self.fixture.store.verify_store(self.fixture.registry)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_commit_receipt_matches_published_schema(self) -> None:
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-ownership-revocation-commit-receipt-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["revocation"] = json.loads(
            (SCHEMAS / "collaboration-ownership-revocation-v1.schema.json").read_text(
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

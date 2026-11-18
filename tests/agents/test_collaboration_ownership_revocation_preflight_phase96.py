"""Phase 96 independent Control ownership revocation preflight coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import timedelta
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_ownership_chain import (
    build_collaboration_ownership_chain_entry,
    build_collaboration_ownership_revocation,
)
from sunderkey.collaboration_ownership_revocation_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationOwnershipRevocationPreflightService,
    load_collaboration_ownership_revocation_preflight,
)
from sunderkey.errors import CollaborationPlanError, StoreConflictError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from . import test_authenticated_collaboration_ownership_phase92 as phase92
from .test_identity_phase4 import AUDIENCE, SUBJECT

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
MISSION_ID = phase92.MISSION_ID
SOURCE_ID = phase92.SOURCE_ID
CANDIDATE_ID = phase92.CANDIDATE_ID
CONTROL_ID = phase92.CONTROL_ID
CONTROL_APPROVAL_ID = "PAS-" + "F1" * 16
PLANNED_ACCEPTANCE_ID = "PAS-" + "F2" * 16


class CollaborationOwnershipRevocationPreflightPhase96Tests(unittest.TestCase):
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
        self.service = CollaborationOwnershipRevocationPreflightService(
            self.fixture.store,
            self.fixture.registry,
            clock=lambda: self.fixture.now,
        )
        self.revocation = self._revocation(self.initial_receipt.entry)

    def _revocation(
        self,
        head,
        *,
        independent_control_id: str = CONTROL_ID,
    ):
        return build_collaboration_ownership_revocation(
            head=head,
            independent_control_id=independent_control_id,
            independent_control_approval_id=CONTROL_APPROVAL_ID,
            planned_owner_acceptance_id=PLANNED_ACCEPTANCE_ID,
            reason_code="independent_control_revocation",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=20)),
        )

    def test_preflight_binds_request_fence_policy_and_projected_entry(self) -> None:
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            before = (
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            )
        preflight = self.service.preflight(self.revocation)
        self.assertEqual(self.service.preflight(self.revocation), preflight)
        document = preflight.to_dict()
        self.assertEqual(
            document["admission_status"],
            "admissible_pending_dual_authenticated_commit",
        )
        self.assertEqual(document["authentication_status"], "not_performed")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["entry"]["transition_kind"], "control_revocation")
        self.assertIsNone(
            document["entry"]["authority_bindings"][
                "current_owner_authorization_id"
            ]
        )
        self.assertEqual(
            document["planned_owner_qualification"]["profile_id"],
            SOURCE_ID,
        )
        self.assertEqual(document["chain_projection"]["current_owner_id"], SOURCE_ID)
        self.assertEqual(document["chain_projection"]["owner_epoch"], 2)
        self.assertEqual(document["chain_projection"]["entry_count"], 2)
        self.assertEqual(document["chain_projection"]["active_delegation_depth"], 0)
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        self.assertEqual(
            document["preflight_sha256"],
            sha256_text(
                canonical_json({"domain": PREFLIGHT_DOMAIN, "preflight": body})
            ),
        )
        with closing(sqlite3.connect(self.fixture.path)) as connection:
            after = (
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_ownership_chain_entries"
                ).fetchone()[0],
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
            )
        self.assertEqual(after, before)
        self.assertEqual(
            self.fixture.store.verify_store(self.fixture.registry).status,
            "valid",
        )

    def test_active_delegated_owner_lease_blocks_revocation_preflight(self) -> None:
        intent = {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.fixture.plan.content_sha256,
            "plan_id": self.fixture.plan.plan_id,
            "principal_profile_id": CANDIDATE_ID,
            "work_item_id": self.fixture.source.work_item_id,
        }
        grant = self.base.grants["claim"]
        issued_at = format_timestamp(self.fixture.now)
        assertion = self.fixture.factory.assertion(
            grant=grant,
            assertion_id=phase92.CLAIM_ASSERTION_ID,
            policy_version=self.base.policy_version,
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
        with self.assertRaisesRegex(StoreConflictError, "Active work item lease"):
            self.service.preflight(self.revocation)

    def test_unassigned_control_and_stale_head_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "independent Control"):
            self.service.preflight(
                self._revocation(
                    self.initial_receipt.entry,
                    independent_control_id=SOURCE_ID,
                )
            )
        first = self.initial_receipt.entry
        first_document = first.to_dict()
        uncommitted_second = build_collaboration_ownership_chain_entry(
            mission_id=MISSION_ID,
            collaboration_plan_id=self.fixture.plan.plan_id,
            collaboration_plan_sha256=self.fixture.plan.content_sha256,
            work_item_id=self.fixture.source.work_item_id,
            work_item_objective_sha256=first_document[
                "work_item_objective_sha256"
            ],
            planned_owner_id=SOURCE_ID,
            sequence=2,
            owner_epoch=2,
            transition_kind="delegation",
            from_owner_id=CANDIDATE_ID,
            to_owner_id="AOE-GB-D06-S11",
            previous_entry_sha256=first.entry_sha256,
            reason_code="uncommitted_successor",
            requested_at=format_timestamp(self.fixture.now),
            expires_at=format_timestamp(self.fixture.now + timedelta(minutes=20)),
            control_role_replacement=False,
            authority_bindings={
                "current_owner_authorization_id": "AUTH-CURRENT-STALE",
                "proposed_owner_acceptance_id": "ACCEPT-PROPOSED-STALE",
                "independent_control_approval_id": "APPROVAL-CONTROL-STALE",
                "second_control_or_mission_authority_id": None,
            },
        )
        with self.assertRaisesRegex(StoreConflictError, "current head"):
            self.service.preflight(self._revocation(uncommitted_second))

    def test_changed_request_and_duplicate_keys_are_rejected_by_loader(self) -> None:
        preflight = self.service.preflight(self.revocation)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "revocation-preflight.json"
            path.write_text(json.dumps(preflight.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_ownership_revocation_preflight(path),
                preflight,
            )
            changed = preflight.to_dict()
            changed["work_fence"]["expected_generation"] = 1
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "identity"):
                load_collaboration_ownership_revocation_preflight(path)
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_ownership_revocation_preflight(path)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_preflight_and_later_transition_preflights_match_schemas(self) -> None:
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-ownership-revocation-preflight-v1.schema.json"
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
        Draft202012Validator(schema).validate(
            self.service.preflight(self.revocation).to_dict()
        )


if __name__ == "__main__":
    unittest.main()

"""Phase 117 semantic verification for execution terminal custody."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing

from sunderkey.collaboration_execution_terminal_custody import (
    CUSTODY_PLAN_DOMAIN,
    CollaborationExecutionTerminalCustodyPlan,
)
from sunderkey.errors import StoreIntegrityError
from sunderkey.qualification import _canonical_sha256
from sunderkey.store import canonical_json

from . import test_authenticated_collaboration_execution_channel_phase109 as phase109

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64


def participant(role: str, marker: str, operation: str, authentication_prefix: str):
    return {
        "role": role,
        "authentication_id": authentication_prefix + marker * 32,
        "authentication_sha256": HASH_A,
        "profile_id": "AOE-HQ-12" if role == "control_plane_requester" else "AOE-GB-D06-S09",
        "issuer": "identity-provider",
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": HASH_B,
        "operation": operation,
        "operation_intent_sha256": HASH_C,
        "policy_sha256": HASH_A,
        "scope_grant_id": "SGR-" + marker * 32,
        "scope_grant_sha256": HASH_B,
    }


def custody_plan(mission_id: str) -> CollaborationExecutionTerminalCustodyPlan:
    participants = [
        participant(
            "control_plane_requester",
            "A",
            "sunderkey.collaboration.execution-transfer.request-authorize.v1",
            "ERA-",
        ),
        participant(
            "source_worker",
            "B",
            "sunderkey.collaboration.execution-transfer.acknowledge.v1",
            "EAA-",
        ),
    ]
    body = {
        "schema_version": 1,
        "terminal_kind": "completed",
        "terminal_outcome": {
            "outcome_id": "ETC-" + "C" * 32,
            "outcome_sha256": HASH_C,
        },
        "outcome_authentication": {
            "authentication_id": None,
            "authentication_sha256": None,
        },
        "request_authentication": {
            "authentication_id": "ERA-" + "A" * 32,
            "authentication_sha256": HASH_A,
        },
        "transfer_request": {
            "request_id": "ETR-" + "D" * 32,
            "request_sha256": HASH_B,
        },
        "mission_id": mission_id,
        "work_item_id": "WORK-PHASE117-1",
        "transfer_kind": "work_cancellation",
        "participant_authentications": participants,
        "assertion_consumption_order": [item["authentication_id"] for item in participants],
        "source_session_disposition": "revoked_unavailable",
        "target_session_disposition": "not_applicable",
        "recovery_required": False,
        "custody_status": "ready_for_atomic_commit",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": CUSTODY_PLAN_DOMAIN, "custody_plan": body})
    return CollaborationExecutionTerminalCustodyPlan.from_dict(
        {
            **body,
            "custody_plan_id": "ECT-" + digest.removeprefix("sha256:")[:32].upper(),
            "custody_plan_sha256": digest,
        }
    )


def insert_commit(connection: sqlite3.Connection, plan, *, plan_json: str | None = None):
    document = plan.to_dict()
    connection.execute(
        """
        INSERT INTO execution_terminal_custody_commits(
            custody_plan_id,
            custody_plan_sha256,
            mission_id,
            work_item_id,
            transfer_kind,
            terminal_kind,
            outcome_id,
            outcome_sha256,
            outcome_authentication_id,
            outcome_authentication_sha256,
            request_authentication_id,
            request_authentication_sha256,
            transfer_request_id,
            transfer_request_sha256,
            source_session_disposition,
            target_session_disposition,
            recovery_required,
            participant_count,
            custody_plan_json,
            committed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            plan.custody_plan_id,
            plan.custody_plan_sha256,
            document["mission_id"],
            document["work_item_id"],
            document["transfer_kind"],
            document["terminal_kind"],
            document["terminal_outcome"]["outcome_id"],
            document["terminal_outcome"]["outcome_sha256"],
            document["outcome_authentication"]["authentication_id"],
            document["outcome_authentication"]["authentication_sha256"],
            document["request_authentication"]["authentication_id"],
            document["request_authentication"]["authentication_sha256"],
            document["transfer_request"]["request_id"],
            document["transfer_request"]["request_sha256"],
            document["source_session_disposition"],
            document["target_session_disposition"],
            int(document["recovery_required"]),
            len(document["participant_authentications"]),
            plan_json or canonical_json(document),
            "2026-07-30T10:10:00Z",
        ),
    )


class Phase117ExecutionTerminalCustodyVerificationTests(unittest.TestCase):
    def fixture(self):
        fixture = phase109.AuthenticatedCollaborationExecutionChannelPhase109Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_missing_participant_custody_fails_whole_store_verification(self) -> None:
        fixture = self.fixture()
        plan = custody_plan(phase109.MISSION_ID)
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            insert_commit(connection, plan)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "participant count"):
            fixture.fixture.store.verify_store(fixture.fixture.registry)

    def test_noncanonical_terminal_plan_fails_whole_store_verification(self) -> None:
        fixture = self.fixture()
        plan = custody_plan(phase109.MISSION_ID)
        noncanonical = json.dumps(plan.to_dict(), indent=2)
        with closing(sqlite3.connect(fixture.fixture.path)) as connection:
            insert_commit(connection, plan, plan_json=noncanonical)
            connection.commit()
        with self.assertRaisesRegex(StoreIntegrityError, "does not reconcile"):
            fixture.fixture.store.verify_store(fixture.fixture.registry)


if __name__ == "__main__":
    unittest.main()

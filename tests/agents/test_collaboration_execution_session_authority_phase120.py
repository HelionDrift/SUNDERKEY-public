"""Phase 120 execution session authority contract coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_channel import (
    build_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
    CollaborationExecutionSessionRevocation,
    build_collaboration_execution_session_revocation,
    build_handoff_collaboration_execution_session_authority,
    build_initial_collaboration_execution_session_authority,
    load_collaboration_execution_session_authority,
    load_collaboration_execution_session_revocation,
)
from sunderkey.collaboration_ownership_chain import (
    collaboration_work_item_objective_sha256,
)
from sunderkey.errors import CollaborationPlanError

from . import (
    test_authenticated_collaboration_execution_terminal_custody_phase119 as phase119,
)

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-session-authority-v1.schema.json"
)
REVOCATION_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-session-revocation-v1.schema.json"
)
SESSION_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-fenced-worker-session-v1.schema.json"
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class CollaborationExecutionSessionAuthorityPhase120Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase119.AuthenticatedCollaborationExecutionTerminalCustodyPhase119Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        plan = fixture.fixture.fixture.plan
        item = plan.work_items[0]
        self.initial_session = build_collaboration_fenced_worker_session(
            channel_policy=fixture.fixture.policy,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(item)
            ),
            ownership_chain_id="OCN-" + "8" * 32,
            ownership_entry_id="OCE-" + "9" * 32,
            ownership_entry_sha256=DIGEST_A,
            owner_profile_id=item.owner_profile_id,
            owner_epoch=1,
            worker_principal_id=item.owner_profile_id,
            fence_generation=1,
            credential_reference_id="CREDENTIAL-PHASE120-INITIAL",
            credential_sha256=DIGEST_B,
            predecessor=None,
            prepared_at="2026-07-30T10:05:10Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        self.initial_authority = build_initial_collaboration_execution_session_authority(
            collaboration_plan=plan,
            channel_policy=fixture.fixture.policy,
            session=self.initial_session,
            effective_at="2026-07-30T10:05:20Z",
        )
        self.handoff_authority = (
            build_handoff_collaboration_execution_session_authority(
                channel_policy=fixture.fixture.policy,
                source_session=fixture.source_session,
                target_session=fixture.target_session,
                authenticated_request=fixture.authenticated_request,
                custody_plan=fixture.plan,
                effective_at="2026-07-30T10:07:00Z",
            )
        )

    def test_initial_authority_binds_planned_owner_and_short_lived_session(self) -> None:
        document = self.initial_authority.to_dict()
        self.assertTrue(self.initial_authority.session_authority_id.startswith("ESA-"))
        self.assertEqual(document["authority_kind"], "initial_activation")
        self.assertEqual(
            document["authorization_basis"]["basis_kind"],
            "activated_plan",
        )
        self.assertEqual(
            document["expires_at"],
            document["session"]["expires_at"],
        )
        self.assertEqual(document["authority_status"], "pending_atomic_commit")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            document["activation_evidence"],
            {
                "evidence_kind": "planned_owner",
                "request_authentication": None,
                "source_session": None,
            },
        )

    def test_handoff_authority_requires_completed_target_custody(self) -> None:
        document = self.handoff_authority.to_dict()
        self.assertEqual(document["authority_kind"], "handoff_activation")
        self.assertEqual(
            document["authorization_basis"],
            {
                "basis_kind": "completed_terminal_custody",
                "basis_id": self.fixture.plan.custody_plan_id,
                "basis_sha256": self.fixture.plan.custody_plan_sha256,
            },
        )
        self.assertEqual(
            document["session"]["session_id"],
            self.fixture.target_session.session_id,
        )
        self.assertEqual(
            document["activation_evidence"]["request_authentication"][
                "authentication_id"
            ],
            self.fixture.authenticated_request.authentication_id,
        )
        self.assertEqual(
            document["activation_evidence"]["source_session"]["session_id"],
            self.fixture.source_session.session_id,
        )
        changed = copy.deepcopy(document)
        changed["authorization_basis"]["basis_kind"] = "activated_plan"
        with self.assertRaisesRegex(CollaborationPlanError, "basis kind"):
            CollaborationExecutionSessionAuthority.from_dict(changed)
        changed = copy.deepcopy(document)
        changed["activation_evidence"]["request_authentication"][
            "authentication_status"
        ] = "unchecked"
        with self.assertRaisesRegex(CollaborationPlanError, "stale"):
            CollaborationExecutionSessionAuthority.from_dict(changed)
        changed = copy.deepcopy(document)
        changed["activation_evidence"]["source_session"]["fence_generation"] = 99
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutionSessionAuthority.from_dict(changed)

    def test_handoff_source_may_itself_be_a_successor_session(self) -> None:
        target = self.fixture.target_session.to_dict()
        later = build_collaboration_fenced_worker_session(
            channel_policy=self.fixture.fixture.policy,
            work_item_id=target["work_item_id"],
            work_item_objective_sha256=target["work_item_objective_sha256"],
            ownership_chain_id=target["ownership_chain_id"],
            ownership_entry_id="OCE-" + "7" * 32,
            ownership_entry_sha256=DIGEST_A,
            owner_profile_id=target["owner_profile_id"],
            owner_epoch=target["owner_epoch"],
            worker_principal_id=target["worker_principal_id"],
            fence_generation=target["fence_generation"] + 1,
            credential_reference_id="CREDENTIAL-PHASE120-LATER",
            credential_sha256="sha256:" + "c" * 64,
            predecessor={
                "session_id": self.fixture.target_session.session_id,
                "session_sha256": self.fixture.target_session.session_sha256,
                "credential_reference_id": target["credential_reference_id"],
                "credential_sha256": target["credential_sha256"],
                "revocation_reference_id": "REVOCATION-PHASE120-TARGET",
                "revocation_sha256": DIGEST_B,
            },
            prepared_at="2026-07-30T10:05:30Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "terminal custody"):
            build_handoff_collaboration_execution_session_authority(
                channel_policy=self.fixture.fixture.policy,
                source_session=self.fixture.target_session,
                target_session=later,
                authenticated_request=self.fixture.authenticated_request,
                custody_plan=self.fixture.plan,
                effective_at="2026-07-30T10:08:00Z",
            )

    def test_initial_authority_rejects_nonowner_worker(self) -> None:
        plan = self.fixture.fixture.fixture.plan
        item = plan.work_items[0]
        nonowner = build_collaboration_fenced_worker_session(
            channel_policy=self.fixture.fixture.policy,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=(
                collaboration_work_item_objective_sha256(item)
            ),
            ownership_chain_id="OCN-" + "A" * 32,
            ownership_entry_id="OCE-" + "B" * 32,
            ownership_entry_sha256=DIGEST_A,
            owner_profile_id=item.owner_profile_id,
            owner_epoch=1,
            worker_principal_id=phase119.SOURCE_ID,
            fence_generation=1,
            credential_reference_id="CREDENTIAL-PHASE120-NONOWNER",
            credential_sha256=DIGEST_B,
            predecessor=None,
            prepared_at="2026-07-30T10:05:10Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "owner"):
            build_initial_collaboration_execution_session_authority(
                collaboration_plan=plan,
                channel_policy=self.fixture.fixture.policy,
                session=nonowner,
                effective_at="2026-07-30T10:05:20Z",
            )

    def test_revocation_binds_authority_session_credential_and_control(self) -> None:
        revocation = build_collaboration_execution_session_revocation(
            self.handoff_authority,
            decision_owner=self._decision_owner("C"),
            reason_code="health_failure",
            revoked_at="2026-07-30T10:08:00Z",
        )
        document = revocation.to_dict()
        self.assertTrue(revocation.revocation_id.startswith("ESR-"))
        self.assertEqual(
            document["session_authority"]["session_authority_id"],
            self.handoff_authority.session_authority_id,
        )
        self.assertEqual(
            document["credential"]["credential_reference_id"],
            self.fixture.target_session.to_dict()["credential_reference_id"],
        )
        self.assertEqual(document["revocation_status"], "pending_control_authentication")
        self.assertEqual(document["runtime_effect"], "none")
        with self.assertRaisesRegex(CollaborationPlanError, "reason"):
            build_collaboration_execution_session_revocation(
                self.handoff_authority,
                decision_owner=self._decision_owner("C"),
                reason_code="silent_disable",
                revoked_at="2026-07-30T10:08:00Z",
            )

    def test_loaders_hashes_and_schemas_are_strict(self) -> None:
        revocation = build_collaboration_execution_session_revocation(
            self.initial_authority,
            decision_owner=self._decision_owner("D"),
            reason_code="operator_request",
            revoked_at="2026-07-30T10:06:00Z",
        )
        changed = copy.deepcopy(self.initial_authority.to_dict())
        changed["effective_at"] = "2026-07-30T10:05:21Z"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutionSessionAuthority.from_dict(changed)
        changed = copy.deepcopy(revocation.to_dict())
        changed["reason_code"] = "mission_stop"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutionSessionRevocation.from_dict(changed)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority_path = root / "authority.json"
            revocation_path = root / "revocation.json"
            authority_path.write_text(
                json.dumps(self.initial_authority.to_dict()),
                encoding="utf-8",
            )
            revocation_path.write_text(
                json.dumps(revocation.to_dict()),
                encoding="utf-8",
            )
            self.assertEqual(
                load_collaboration_execution_session_authority(
                    authority_path
                ).session_authority_id,
                self.initial_authority.session_authority_id,
            )
            self.assertEqual(
                load_collaboration_execution_session_revocation(
                    revocation_path
                ).revocation_id,
                revocation.revocation_id,
            )
            authority_path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_session_authority(authority_path)
        if Draft202012Validator is not None:
            authority_schema = json.loads(AUTHORITY_SCHEMA_PATH.read_text(encoding="utf-8"))
            authority_schema["properties"]["session"] = json.loads(
                SESSION_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            Draft202012Validator(authority_schema).validate(
                self.initial_authority.to_dict()
            )
            Draft202012Validator(
                json.loads(REVOCATION_SCHEMA_PATH.read_text(encoding="utf-8"))
            ).validate(revocation.to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (
                ROOT / "src/sunderkey/collaboration_execution_session_authority.py"
            ).read_text(encoding="utf-8")
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        )
        self.assertFalse(
            imported
            & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )

    @staticmethod
    def _decision_owner(marker: str) -> dict[str, str]:
        return {
            "profile_id": phase119.TIMEOUT_CONTROL_ID,
            "assertion_id": "PAS-" + marker * 32,
            "assertion_sha256": "sha256:" + marker.lower() * 64,
        }


if __name__ == "__main__":
    unittest.main()

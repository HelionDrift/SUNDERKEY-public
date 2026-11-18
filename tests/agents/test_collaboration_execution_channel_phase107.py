"""Phase 107 execution-channel policy and worker-session coverage."""

from __future__ import annotations

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
    CollaborationExecutionChannelPolicy,
    CollaborationFencedWorkerSession,
    build_collaboration_execution_channel_policy,
    build_collaboration_fenced_worker_session,
    load_collaboration_execution_channel_policy,
    load_collaboration_fenced_worker_session,
    validate_collaboration_execution_channel_policy,
    validate_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry" / "collaboration-reconfiguration-policy-d001-d005.json"
POLICY_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "collaboration-execution-channel-policy-v1.schema.json"
)
SESSION_SCHEMA_PATH = (
    ROOT / "registry" / "schemas" / "collaboration-fenced-worker-session-v1.schema.json"
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def assertion(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": f"PAS-{marker * 32}",
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


class CollaborationExecutionChannelPhase107Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def mission_policy(self, *, enabled: bool = True):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id="MISSION-1",
            collaboration_plan_id="PLAN-1",
            collaboration_plan_sha256=DIGEST_A,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": True,
                "cross_command_transfer": False,
                "activated_plan_replacement": False,
                "distributed_execution_transfer_or_cancellation": enabled,
            },
            mission_owner_approval=assertion("PROFILE-MISSION-OWNER", "A"),
            independent_control_approval=assertion("PROFILE-CONTROL-1", "B"),
            effective_at="2026-08-03T00:00:00Z",
            expires_at="2026-08-04T00:00:00Z",
        )

    def channel_policy(
        self,
        *,
        version: int = 1,
        previous: str | None = None,
        effective_at: str = "2026-08-03T00:00:00Z",
    ) -> CollaborationExecutionChannelPolicy:
        return build_collaboration_execution_channel_policy(
            authority_policy=self.authority,
            mission_policy=self.mission_policy(),
            policy_version=version,
            previous_channel_policy_sha256=previous,
            mission_owner_approval=assertion("PROFILE-MISSION-OWNER", "C"),
            independent_control_approval=assertion("PROFILE-CONTROL-1", "D"),
            effective_at=effective_at,
            expires_at="2026-08-04T00:00:00Z",
        )

    def session(
        self,
        *,
        policy: CollaborationExecutionChannelPolicy | None = None,
        generation: int = 1,
        predecessor: dict[str, str | None] | None = None,
        credential_id: str = "CREDENTIAL-1",
        prepared_at: str = "2026-08-03T01:00:00Z",
    ) -> CollaborationFencedWorkerSession:
        return build_collaboration_fenced_worker_session(
            channel_policy=policy or self.channel_policy(),
            work_item_id="WORK-1",
            work_item_objective_sha256=DIGEST_B,
            ownership_chain_id="OCN-" + "A" * 32,
            ownership_entry_id="OCE-" + "B" * 32,
            ownership_entry_sha256=DIGEST_C,
            owner_profile_id="PROFILE-OWNER-1",
            owner_epoch=2,
            worker_principal_id="WORKER-1",
            fence_generation=generation,
            credential_reference_id=credential_id,
            credential_sha256=DIGEST_A if credential_id == "CREDENTIAL-1" else DIGEST_B,
            predecessor=predecessor,
            prepared_at=prepared_at,
            expires_at="2026-08-03T02:00:00Z",
        )

    def test_channel_policy_selects_exact_mission_timeout_and_controls(self) -> None:
        selected = self.channel_policy()
        document = selected.to_dict()
        self.assertEqual(document["acknowledgement_timeout_seconds"], 300)
        self.assertTrue(all(document["protocol_controls"].values()))
        self.assertEqual(document["authentication_status"], "assertions_pending_verification")
        self.assertEqual(document["runtime_effect"], "none")
        validated = validate_collaboration_execution_channel_policy(
            selected,
            authority_policy=self.authority,
            mission_policy=self.mission_policy(),
        )
        self.assertEqual(validated.channel_policy_sha256, selected.channel_policy_sha256)

    def test_disabled_transition_and_changed_content_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "not activated"):
            build_collaboration_execution_channel_policy(
                authority_policy=self.authority,
                mission_policy=self.mission_policy(enabled=False),
                policy_version=1,
                previous_channel_policy_sha256=None,
                mission_owner_approval=assertion("PROFILE-MISSION-OWNER", "C"),
                independent_control_approval=assertion("PROFILE-CONTROL-1", "D"),
                effective_at="2026-08-03T00:00:00Z",
                expires_at="2026-08-04T00:00:00Z",
            )
        changed = copy.deepcopy(self.channel_policy().to_dict())
        changed["protocol_controls"]["fail_closed_on_timeout"] = False
        with self.assertRaisesRegex(CollaborationPlanError, "controls"):
            CollaborationExecutionChannelPolicy.from_dict(changed)

    def test_policy_approver_separation_and_predecessor_are_enforced(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "approvers must be distinct"):
            build_collaboration_execution_channel_policy(
                authority_policy=self.authority,
                mission_policy=self.mission_policy(),
                policy_version=1,
                previous_channel_policy_sha256=None,
                mission_owner_approval=assertion("PROFILE-SAME", "C"),
                independent_control_approval=assertion("PROFILE-SAME", "D"),
                effective_at="2026-08-03T00:00:00Z",
                expires_at="2026-08-04T00:00:00Z",
            )
        first = self.channel_policy()
        second = self.channel_policy(
            version=2,
            previous=first.channel_policy_sha256,
            effective_at="2026-08-03T00:30:00Z",
        )
        validated = validate_collaboration_execution_channel_policy(
            second,
            authority_policy=self.authority,
            mission_policy=self.mission_policy(),
            previous_policy=first,
        )
        self.assertEqual(validated.to_dict()["policy_version"], 2)
        with self.assertRaisesRegex(CollaborationPlanError, "predecessor is required"):
            validate_collaboration_execution_channel_policy(
                second,
                authority_policy=self.authority,
                mission_policy=self.mission_policy(),
            )

    def test_initial_session_is_inert_and_exactly_fenced(self) -> None:
        selected = self.session()
        document = selected.to_dict()
        self.assertEqual(document["fence_generation"], 1)
        self.assertTrue(all(item is None for item in document["predecessor"].values()))
        self.assertEqual(document["session_status"], "prepared_pending_channel_activation")
        self.assertEqual(document["runtime_effect"], "none")
        validated = validate_collaboration_fenced_worker_session(
            selected,
            channel_policy=self.channel_policy(),
        )
        self.assertEqual(validated.session_sha256, selected.session_sha256)

    def test_successor_requires_complete_revocation_and_rotated_credential(self) -> None:
        first = self.session()
        first_document = first.to_dict()
        predecessor = {
            "session_id": first.session_id,
            "session_sha256": first.session_sha256,
            "credential_reference_id": first_document["credential_reference_id"],
            "credential_sha256": first_document["credential_sha256"],
            "revocation_reference_id": "REVOCATION-1",
            "revocation_sha256": DIGEST_C,
        }
        second = self.session(
            generation=2,
            predecessor=predecessor,
            credential_id="CREDENTIAL-2",
            prepared_at="2026-08-03T01:30:00Z",
        )
        validated = validate_collaboration_fenced_worker_session(
            second,
            channel_policy=self.channel_policy(),
            previous_session=first,
        )
        self.assertEqual(validated.to_dict()["fence_generation"], 2)
        incomplete = dict(predecessor)
        incomplete["revocation_sha256"] = None
        with self.assertRaisesRegex(CollaborationPlanError, "proof is incomplete"):
            self.session(
                generation=2,
                predecessor=incomplete,
                credential_id="CREDENTIAL-2",
                prepared_at="2026-08-03T01:30:00Z",
            )
        unrotated = self.session(
            generation=2,
            predecessor=predecessor,
            prepared_at="2026-08-03T01:30:00Z",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "rotate credentials"):
            validate_collaboration_fenced_worker_session(
                unrotated,
                channel_policy=self.channel_policy(),
                previous_session=first,
            )

    def test_session_policy_window_generation_and_content_tampering_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "generation must be one"):
            validate_collaboration_fenced_worker_session(
                self.session(generation=2),
                channel_policy=self.channel_policy(),
            )
        with self.assertRaisesRegex(CollaborationPlanError, "policy window"):
            build_collaboration_fenced_worker_session(
                channel_policy=self.channel_policy(),
                work_item_id="WORK-1",
                work_item_objective_sha256=DIGEST_B,
                ownership_chain_id="OCN-" + "A" * 32,
                ownership_entry_id="OCE-" + "B" * 32,
                ownership_entry_sha256=DIGEST_C,
                owner_profile_id="PROFILE-OWNER-1",
                owner_epoch=2,
                worker_principal_id="WORKER-1",
                fence_generation=1,
                credential_reference_id="CREDENTIAL-1",
                credential_sha256=DIGEST_A,
                predecessor=None,
                prepared_at="2026-08-03T23:00:00Z",
                expires_at="2026-08-04T01:00:00Z",
            )
        changed = copy.deepcopy(self.session().to_dict())
        changed["owner_epoch"] = 3
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationFencedWorkerSession.from_dict(changed)

    def test_loaders_reject_duplicate_keys_and_schemas_accept_documents(self) -> None:
        selected_policy = self.channel_policy()
        selected_session = self.session(policy=selected_policy)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            session_path = root / "session.json"
            policy_path.write_text(json.dumps(selected_policy.to_dict()), encoding="utf-8")
            session_path.write_text(json.dumps(selected_session.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_channel_policy(policy_path).channel_policy_id,
                selected_policy.channel_policy_id,
            )
            self.assertEqual(
                load_collaboration_fenced_worker_session(session_path).session_id,
                selected_session.session_id,
            )
            policy_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_channel_policy(policy_path)
        if Draft202012Validator is not None:
            policy_schema = json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
            session_schema = json.loads(SESSION_SCHEMA_PATH.read_text(encoding="utf-8"))
            Draft202012Validator(policy_schema).validate(selected_policy.to_dict())
            Draft202012Validator(session_schema).validate(selected_session.to_dict())


if __name__ == "__main__":
    unittest.main()

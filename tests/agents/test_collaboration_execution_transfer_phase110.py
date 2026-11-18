"""Phase 110 execution transfer and acknowledgement contract coverage."""

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
    build_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_execution_transfer import (
    CollaborationExecutionAcknowledgement,
    CollaborationExecutionTransferRequest,
    build_collaboration_execution_acknowledgement,
    build_collaboration_execution_transfer_request,
    load_collaboration_execution_acknowledgement,
    load_collaboration_execution_transfer_request,
    validate_collaboration_execution_acknowledgement,
    validate_collaboration_execution_acknowledgement_set,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_execution_channel_phase107 as phase107

ROOT = Path(__file__).resolve().parents[2]
REQUEST_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-transfer-request-v1.schema.json"
)
ACK_SCHEMA_PATH = ROOT / "registry/schemas/collaboration-execution-acknowledgement-v1.schema.json"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def assertion(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


class CollaborationExecutionTransferPhase110Tests(unittest.TestCase):
    def setUp(self) -> None:
        phase107.CollaborationExecutionChannelPhase107Tests.setUpClass()
        fixture = phase107.CollaborationExecutionChannelPhase107Tests(methodName="runTest")
        self.channel_policy = fixture.channel_policy()
        self.source_session = fixture.session(policy=self.channel_policy)
        source = self.source_session.to_dict()
        predecessor = {
            "session_id": self.source_session.session_id,
            "session_sha256": self.source_session.session_sha256,
            "credential_reference_id": source["credential_reference_id"],
            "credential_sha256": source["credential_sha256"],
            "revocation_reference_id": "REVOCATION-1",
            "revocation_sha256": DIGEST_C,
        }
        self.target_session = build_collaboration_fenced_worker_session(
            channel_policy=self.channel_policy,
            work_item_id=source["work_item_id"],
            work_item_objective_sha256=source["work_item_objective_sha256"],
            ownership_chain_id=source["ownership_chain_id"],
            ownership_entry_id="OCE-" + "C" * 32,
            ownership_entry_sha256=DIGEST_B,
            owner_profile_id="PROFILE-OWNER-2",
            owner_epoch=3,
            worker_principal_id="WORKER-2",
            fence_generation=2,
            credential_reference_id="CREDENTIAL-2",
            credential_sha256=DIGEST_B,
            predecessor=predecessor,
            prepared_at="2026-08-03T01:30:00Z",
            expires_at="2026-08-03T02:00:00Z",
        )
        self.request = self._handoff_request()

    def _handoff_request(self):
        return build_collaboration_execution_transfer_request(
            channel_policy=self.channel_policy,
            source_session=self.source_session,
            target_session=self.target_session,
            transfer_kind="ownership_handoff",
            control_transition_id="OCE-" + "C" * 32,
            control_transition_sha256=DIGEST_B,
            control_plane_requester=assertion("PROFILE-CONTROL-1", "A"),
            requested_at="2026-08-03T01:40:00Z",
        )

    def _acknowledgement(self, kind: str, *, at: str = "2026-08-03T01:42:00Z"):
        source_kind = kind != "target_accepted"
        return build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind=kind,
            session=self.source_session if source_kind else self.target_session,
            external_acknowledger=assertion(
                "WORKER-1" if source_kind else "WORKER-2",
                "B" if source_kind else "C",
            ),
            revocation_reference_id="REVOCATION-2" if source_kind else None,
            revocation_sha256=DIGEST_C if source_kind else None,
            acknowledged_at=at,
        )

    def test_handoff_request_binds_transition_sessions_and_exact_deadline(self) -> None:
        document = self.request.to_dict()
        self.assertEqual(
            document["required_acknowledgement_kinds"],
            ["source_released", "target_accepted"],
        )
        self.assertEqual(document["acknowledgement_deadline"], "2026-08-03T01:45:00Z")
        self.assertEqual(document["source_session"]["fence_generation"], 1)
        self.assertEqual(document["target_session"]["fence_generation"], 2)
        self.assertEqual(document["request_status"], "pending_external_acknowledgement")
        self.assertEqual(document["runtime_effect"], "none")

    def test_cancellation_requires_only_source_cancellation_and_no_target(self) -> None:
        request = build_collaboration_execution_transfer_request(
            channel_policy=self.channel_policy,
            source_session=self.source_session,
            target_session=None,
            transfer_kind="work_cancellation",
            control_transition_id="WCN-" + "D" * 32,
            control_transition_sha256=DIGEST_C,
            control_plane_requester=assertion("PROFILE-CONTROL-1", "D"),
            requested_at="2026-08-03T01:40:00Z",
        )
        document = request.to_dict()
        self.assertEqual(document["required_acknowledgement_kinds"], ["source_cancelled"])
        self.assertTrue(all(item is None for item in document["target_session"].values()))
        acknowledgement = build_collaboration_execution_acknowledgement(
            request=request,
            acknowledgement_kind="source_cancelled",
            session=self.source_session,
            external_acknowledger=assertion("WORKER-1", "E"),
            revocation_reference_id="REVOCATION-3",
            revocation_sha256=DIGEST_C,
            acknowledged_at="2026-08-03T01:43:00Z",
        )
        verified = validate_collaboration_execution_acknowledgement_set(
            request,
            [(acknowledgement, self.source_session)],
        )
        self.assertEqual(verified.request_id, request.request_id)

    def test_request_rejects_missing_target_stale_fence_and_wrong_transition(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "requires a target"):
            build_collaboration_execution_transfer_request(
                channel_policy=self.channel_policy,
                source_session=self.source_session,
                target_session=None,
                transfer_kind="ownership_handoff",
                control_transition_id="OCE-" + "C" * 32,
                control_transition_sha256=DIGEST_B,
                control_plane_requester=assertion("PROFILE-CONTROL-1", "A"),
                requested_at="2026-08-03T01:40:00Z",
            )
        changed = copy.deepcopy(self.request.to_dict())
        changed["target_session"]["fence_generation"] = 3
        with self.assertRaisesRegex(CollaborationPlanError, "generation"):
            CollaborationExecutionTransferRequest.from_dict(changed)
        with self.assertRaisesRegex(CollaborationPlanError, "control transition"):
            build_collaboration_execution_transfer_request(
                channel_policy=self.channel_policy,
                source_session=self.source_session,
                target_session=None,
                transfer_kind="work_cancellation",
                control_transition_id="OCE-" + "C" * 32,
                control_transition_sha256=DIGEST_B,
                control_plane_requester=assertion("PROFILE-CONTROL-1", "A"),
                requested_at="2026-08-03T01:40:00Z",
            )

    def test_source_ack_requires_revocation_separation_and_current_deadline(self) -> None:
        acknowledgement = self._acknowledgement("source_released")
        document = acknowledgement.to_dict()
        self.assertEqual(
            document["revocation_proof"]["credential_reference_id"],
            self.source_session.to_dict()["credential_reference_id"],
        )
        self.assertEqual(document["authentication_status"], "assertion_pending_verification")
        with self.assertRaisesRegex(CollaborationPlanError, "credential revocation"):
            build_collaboration_execution_acknowledgement(
                request=self.request,
                acknowledgement_kind="source_released",
                session=self.source_session,
                external_acknowledger=assertion("WORKER-1", "B"),
                revocation_reference_id=None,
                revocation_sha256=None,
                acknowledged_at="2026-08-03T01:42:00Z",
            )
        with self.assertRaisesRegex(CollaborationPlanError, "must differ"):
            build_collaboration_execution_acknowledgement(
                request=self.request,
                acknowledgement_kind="source_released",
                session=self.source_session,
                external_acknowledger=assertion("PROFILE-CONTROL-1", "B"),
                revocation_reference_id="REVOCATION-2",
                revocation_sha256=DIGEST_C,
                acknowledged_at="2026-08-03T01:42:00Z",
            )
        with self.assertRaisesRegex(CollaborationPlanError, "missed its deadline"):
            self._acknowledgement("source_released", at="2026-08-03T01:45:01Z")

    def test_target_ack_uses_successor_session_and_no_revocation(self) -> None:
        acknowledgement = self._acknowledgement("target_accepted")
        document = acknowledgement.to_dict()
        self.assertEqual(document["session"]["session_id"], self.target_session.session_id)
        self.assertTrue(all(item is None for item in document["revocation_proof"].values()))
        with self.assertRaisesRegex(CollaborationPlanError, "session proof is stale"):
            validate_collaboration_execution_acknowledgement(
                acknowledgement,
                request=self.request,
                session=self.source_session,
            )

    def test_acknowledgement_set_requires_every_kind_exactly_once(self) -> None:
        source = self._acknowledgement("source_released")
        target = self._acknowledgement("target_accepted", at="2026-08-03T01:43:00Z")
        verified = validate_collaboration_execution_acknowledgement_set(
            self.request,
            [(source, self.source_session), (target, self.target_session)],
        )
        self.assertEqual(verified.completed_at, "2026-08-03T01:43:00Z")
        self.assertEqual(len(verified.acknowledgement_ids), 2)
        with self.assertRaisesRegex(CollaborationPlanError, "set is incomplete"):
            validate_collaboration_execution_acknowledgement_set(
                self.request,
                [(source, self.source_session)],
            )
        with self.assertRaisesRegex(CollaborationPlanError, "set is incomplete"):
            validate_collaboration_execution_acknowledgement_set(
                self.request,
                [(source, self.source_session), (source, self.source_session)],
            )

    def test_hash_tampering_loaders_and_schemas_are_strict(self) -> None:
        acknowledgement = self._acknowledgement("source_released")
        changed = copy.deepcopy(acknowledgement.to_dict())
        changed["acknowledged_at"] = "2026-08-03T01:44:00Z"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutionAcknowledgement.from_dict(changed)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request_path = root / "request.json"
            acknowledgement_path = root / "ack.json"
            request_path.write_text(json.dumps(self.request.to_dict()), encoding="utf-8")
            acknowledgement_path.write_text(json.dumps(acknowledgement.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_transfer_request(request_path).request_id,
                self.request.request_id,
            )
            self.assertEqual(
                load_collaboration_execution_acknowledgement(
                    acknowledgement_path
                ).acknowledgement_id,
                acknowledgement.acknowledgement_id,
            )
            request_path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_transfer_request(request_path)
        if Draft202012Validator is not None:
            Draft202012Validator(
                json.loads(REQUEST_SCHEMA_PATH.read_text(encoding="utf-8"))
            ).validate(self.request.to_dict())
            Draft202012Validator(json.loads(ACK_SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
                acknowledgement.to_dict()
            )


if __name__ == "__main__":
    unittest.main()

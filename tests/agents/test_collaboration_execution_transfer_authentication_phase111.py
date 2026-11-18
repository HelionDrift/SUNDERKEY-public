"""Phase 111 signed execution transfer authentication coverage."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_channel import (
    build_collaboration_execution_channel_policy,
    build_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_execution_transfer import (
    build_collaboration_execution_acknowledgement,
    build_collaboration_execution_transfer_request,
    collaboration_execution_acknowledgement_selection_sha256,
    collaboration_execution_transfer_request_selection_sha256,
)
from sunderkey.collaboration_execution_transfer_authentication import (
    authenticate_collaboration_execution_acknowledgement,
    authenticate_collaboration_execution_transfer_request,
    validate_authenticated_collaboration_execution_acknowledgement_set,
)
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    GRANT_ID,
    MISSION_ID,
    OTHER_ASSERTION_ID,
    OTHER_GRANT_ID,
    OTHER_PROFILE_ID,
    PROFILE_ID,
    STORE_ID,
    SUBJECT,
    CredentialFactory,
)

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PATH = ROOT / "registry/collaboration-reconfiguration-policy-d001-d005.json"
REQUEST_AUTH_SCHEMA = (
    ROOT / "registry/schemas/collaboration-execution-transfer-request-authentication-v1.schema.json"
)
ACK_AUTH_SCHEMA = (
    ROOT / "registry/schemas/collaboration-execution-acknowledgement-authentication-v1.schema.json"
)
REQUEST_SCHEMA = ROOT / "registry/schemas/collaboration-execution-transfer-request-v1.schema.json"
ACK_SCHEMA = ROOT / "registry/schemas/collaboration-execution-acknowledgement-v1.schema.json"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
TARGET_PROFILE_ID = "AOE-GA-D02-CMD"
CONTROL_PROFILE_ID = "AOE-HQ-14"
TARGET_GRANT_ID = "SGR-" + "A" * 32
TARGET_ASSERTION_ID = "PAS-" + "A" * 32
REQUEST_OPERATION = PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE
ACK_OPERATION = PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE
NOW = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)


def pending_binding(profile_id: str, marker: str) -> dict[str, str]:
    return {
        "profile_id": profile_id,
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


def assertion_binding(assertion) -> dict[str, str]:
    return {
        "profile_id": assertion.profile_id,
        "assertion_id": assertion.assertion_id,
        "assertion_sha256": assertion.content_sha256,
    }


class CollaborationExecutionTransferAuthenticationPhase111Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.authority = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)

    def setUp(self) -> None:
        self.factory = CredentialFactory()
        profiles = [PROFILE_ID, OTHER_PROFILE_ID, TARGET_PROFILE_ID, CONTROL_PROFILE_ID]
        operations = [
            REQUEST_OPERATION.value,
            ACK_OPERATION.value,
            PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE.value,
        ]
        self.verified_policy = self.factory.verified_policy(
            allowed_profiles=profiles,
            allowed_operations=operations,
        )
        self.requester_grant = self._grant(GRANT_ID, PROFILE_ID, REQUEST_OPERATION)
        self.source_grant = self._grant(OTHER_GRANT_ID, OTHER_PROFILE_ID, ACK_OPERATION)
        self.target_grant = self._grant(TARGET_GRANT_ID, TARGET_PROFILE_ID, ACK_OPERATION)
        self.requester_scope = self.factory.verify_grant(
            self.requester_grant,
            self.verified_policy,
            expected_operation=REQUEST_OPERATION,
        )
        self.source_scope = self.factory.verify_grant(
            self.source_grant,
            self.verified_policy,
            expected_operation=ACK_OPERATION,
        )
        self.target_scope = self.factory.verify_grant(
            self.target_grant,
            self.verified_policy,
            expected_operation=ACK_OPERATION,
        )
        self.channel_policy = self._channel_policy()
        self.source_session = self._source_session()
        self.target_session = self._target_session()
        provisional_request = self._request(pending_binding(PROFILE_ID, "B"))
        request_intent = {
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "request_selection_sha256": (
                collaboration_execution_transfer_request_selection_sha256(provisional_request)
            ),
        }
        self.requester_assertion = self.factory.assertion(
            grant=self.requester_grant,
            assertion_id=ASSERTION_ID,
            scope_grant_id=GRANT_ID,
            subject=SUBJECT,
            profile_id=PROFILE_ID,
            mission_id=MISSION_ID,
            operation=REQUEST_OPERATION,
            operation_intent_sha256=compute_operation_intent_hash(
                REQUEST_OPERATION,
                request_intent,
            ),
        )
        self.request = self._request(assertion_binding(self.requester_assertion))
        self.authenticated_request = self._authenticate_request()

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        return self.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            mission_id=MISSION_ID,
            operations=[operation.value],
        )

    def _channel_policy(self):
        mission_policy = build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority,
            policy_version=1,
            previous_policy_sha256=None,
            mission_id=MISSION_ID,
            collaboration_plan_id="PLAN-PHASE111",
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
                "distributed_execution_transfer_or_cancellation": True,
            },
            mission_owner_approval=pending_binding("AOE-HQ-08", "C"),
            independent_control_approval=pending_binding("AOE-HQ-14", "D"),
            effective_at="2026-07-30T09:00:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )
        return build_collaboration_execution_channel_policy(
            authority_policy=self.authority,
            mission_policy=mission_policy,
            policy_version=1,
            previous_channel_policy_sha256=None,
            mission_owner_approval=pending_binding("AOE-HQ-08", "E"),
            independent_control_approval=pending_binding("AOE-HQ-14", "F"),
            effective_at="2026-07-30T09:00:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )

    def _source_session(self):
        return build_collaboration_fenced_worker_session(
            channel_policy=self.channel_policy,
            work_item_id="WORK-PHASE111",
            work_item_objective_sha256=DIGEST_B,
            ownership_chain_id="OCN-" + "A" * 32,
            ownership_entry_id="OCE-" + "B" * 32,
            ownership_entry_sha256=DIGEST_C,
            owner_profile_id="AOE-GA-D01-CMD",
            owner_epoch=2,
            worker_principal_id=OTHER_PROFILE_ID,
            fence_generation=1,
            credential_reference_id="CREDENTIAL-PHASE111-1",
            credential_sha256=DIGEST_A,
            predecessor=None,
            prepared_at="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T10:30:00Z",
        )

    def _target_session(self):
        source = self.source_session.to_dict()
        return build_collaboration_fenced_worker_session(
            channel_policy=self.channel_policy,
            work_item_id=source["work_item_id"],
            work_item_objective_sha256=source["work_item_objective_sha256"],
            ownership_chain_id=source["ownership_chain_id"],
            ownership_entry_id="OCE-" + "C" * 32,
            ownership_entry_sha256=DIGEST_B,
            owner_profile_id=TARGET_PROFILE_ID,
            owner_epoch=3,
            worker_principal_id=TARGET_PROFILE_ID,
            fence_generation=2,
            credential_reference_id="CREDENTIAL-PHASE111-2",
            credential_sha256=DIGEST_B,
            predecessor={
                "session_id": self.source_session.session_id,
                "session_sha256": self.source_session.session_sha256,
                "credential_reference_id": source["credential_reference_id"],
                "credential_sha256": source["credential_sha256"],
                "revocation_reference_id": "REVOCATION-PHASE111-1",
                "revocation_sha256": DIGEST_C,
            },
            prepared_at="2026-07-30T10:02:00Z",
            expires_at="2026-07-30T10:30:00Z",
        )

    def _request(self, binding: dict[str, str]):
        return build_collaboration_execution_transfer_request(
            channel_policy=self.channel_policy,
            source_session=self.source_session,
            target_session=self.target_session,
            transfer_kind="ownership_handoff",
            control_transition_id="OCE-" + "C" * 32,
            control_transition_sha256=DIGEST_B,
            control_plane_requester=binding,
            requested_at="2026-07-30T10:04:00Z",
        )

    def _authenticate_request(self, **overrides):
        arguments = {
            "requester_assertion": self.requester_assertion,
            "verified_policy": self.verified_policy,
            "requester_scope": self.requester_scope,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_execution_transfer_request(
            self.request,
            **arguments,
        )

    def _acknowledgement(self, kind: str):
        source = kind == "source_released"
        session = self.source_session if source else self.target_session
        profile_id = OTHER_PROFILE_ID if source else TARGET_PROFILE_ID
        grant = self.source_grant if source else self.target_grant
        grant_id = OTHER_GRANT_ID if source else TARGET_GRANT_ID
        assertion_id = OTHER_ASSERTION_ID if source else TARGET_ASSERTION_ID
        acknowledged_at = "2026-07-30T10:05:00Z"
        provisional = build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind=kind,
            session=session,
            external_acknowledger=pending_binding(profile_id, "1" if source else "2"),
            revocation_reference_id=("REVOCATION-PHASE111-2" if source else None),
            revocation_sha256=DIGEST_C if source else None,
            acknowledged_at=acknowledged_at,
        )
        intent = {
            "acknowledgement_selection_sha256": (
                collaboration_execution_acknowledgement_selection_sha256(provisional)
            ),
            "mission_id": MISSION_ID,
            "principal_profile_id": profile_id,
            "request_id": self.request.request_id,
            "request_sha256": self.request.request_sha256,
        }
        assertion = self.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            scope_grant_id=grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            mission_id=MISSION_ID,
            operation=ACK_OPERATION,
            operation_intent_sha256=compute_operation_intent_hash(
                ACK_OPERATION,
                intent,
            ),
        )
        acknowledgement = build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind=kind,
            session=session,
            external_acknowledger=assertion_binding(assertion),
            revocation_reference_id=("REVOCATION-PHASE111-2" if source else None),
            revocation_sha256=DIGEST_C if source else None,
            acknowledged_at=acknowledged_at,
        )
        return (
            acknowledgement,
            assertion,
            session,
            (self.source_scope if source else self.target_scope),
        )

    def _authenticate_acknowledgement(self, kind: str):
        acknowledgement, assertion, session, scope = self._acknowledgement(kind)
        authenticated = authenticate_collaboration_execution_acknowledgement(
            acknowledgement,
            authenticated_request=self.authenticated_request,
            session=session,
            acknowledger_assertion=assertion,
            verified_policy=self.verified_policy,
            acknowledger_scope=scope,
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            clock=lambda: NOW,
        )
        return authenticated, session

    def test_request_authentication_binds_exact_signed_selection(self) -> None:
        document = self.authenticated_request.to_dict()
        self.assertEqual(document["control_plane_requester"]["profile_id"], PROFILE_ID)
        self.assertEqual(
            document["authentication_status"],
            "authenticated_control_plane_request",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertTrue(document["authentication_id"].startswith("ERA-"))

    def test_both_worker_acknowledgements_authenticate_as_complete_set(self) -> None:
        source, source_session = self._authenticate_acknowledgement("source_released")
        target, target_session = self._authenticate_acknowledgement("target_accepted")
        verified = validate_authenticated_collaboration_execution_acknowledgement_set(
            self.authenticated_request,
            [(source, source_session), (target, target_session)],
        )
        self.assertEqual(
            verified.request_authentication_id,
            self.authenticated_request.authentication_id,
        )
        self.assertEqual(len(verified.acknowledgement_authentication_ids), 2)
        self.assertEqual(source.external_acknowledger.profile_id, OTHER_PROFILE_ID)
        self.assertEqual(target.external_acknowledger.profile_id, TARGET_PROFILE_ID)

    def test_non_worker_acknowledgement_fails_closed(self) -> None:
        _, target_assertion, _, target_scope = self._acknowledgement("target_accepted")
        acknowledgement = build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind="source_released",
            session=self.source_session,
            external_acknowledger=assertion_binding(target_assertion),
            revocation_reference_id="REVOCATION-PHASE111-2",
            revocation_sha256=DIGEST_C,
            acknowledged_at="2026-07-30T10:05:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "fenced worker"):
            authenticate_collaboration_execution_acknowledgement(
                acknowledgement,
                authenticated_request=self.authenticated_request,
                session=self.source_session,
                acknowledger_assertion=target_assertion,
                verified_policy=self.verified_policy,
                acknowledger_scope=target_scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                clock=lambda: NOW,
            )

    def test_deadline_and_unforgeable_wrapper_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "deadline"):
            self._authenticate_request(clock=lambda: datetime(2026, 7, 30, 10, 9, 1, tzinfo=UTC))
        with self.assertRaises(TypeError):
            replace(
                self.authenticated_request,
                authentication_sha256=DIGEST_A,
            )

    def test_authentication_schemas_accept_exact_documents(self) -> None:
        source, _ = self._authenticate_acknowledgement("source_released")
        if Draft202012Validator is not None:
            request_schema = json.loads(REQUEST_AUTH_SCHEMA.read_text(encoding="utf-8"))
            request_schema["properties"]["transfer_request"] = json.loads(
                REQUEST_SCHEMA.read_text(encoding="utf-8")
            )
            Draft202012Validator(request_schema).validate(self.authenticated_request.to_dict())
            acknowledgement_schema = json.loads(ACK_AUTH_SCHEMA.read_text(encoding="utf-8"))
            acknowledgement_schema["properties"]["acknowledgement"] = json.loads(
                ACK_SCHEMA.read_text(encoding="utf-8")
            )
            Draft202012Validator(acknowledgement_schema).validate(source.to_dict())


if __name__ == "__main__":
    unittest.main()

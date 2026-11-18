"""Focused tests for authenticated Phase 11 approval revocations."""

from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from sunderkey.approvals import ApprovalService, ApprovalState
from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_approval_revocations import (
    AuthenticatedApprovalRevocationReceipt,
    AuthenticatedApprovalRevocationService,
)
from sunderkey.authenticated_approvals import (
    AuthenticatedApprovalDecisionService,
)
from sunderkey.authenticated_events import (
    AuthenticatedEventAppendService,
    compute_event_batch_hash,
)
from sunderkey.authenticated_simulations import (
    AuthenticatedSimulationService,
)
from sunderkey.authenticated_submissions import (
    AuthenticatedApprovalSubmissionService,
)
from sunderkey.errors import (
    ApprovalConflictError,
    ApprovalError,
    ApprovalExpiredError,
    MissionControlError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.events import MissionEvent
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    ScopeGrantRevocation,
    TrustKeyState,
    TrustKeyUse,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import (
    ScopeGrantAcceptanceService,
    ScopeGrantRevocationAcceptanceService,
)
from sunderkey.store import (
    APPROVAL_REVOKE_EFFECT_KIND,
    MissionStore,
    canonical_json,
    format_timestamp,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    SUBJECT,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    CONTROL_ID,
    REGISTRY_PATH,
    SPECIALIST_ID,
    mission_data,
)

MISSION_ID = "MISSION-PHASE11-APPROVAL-REVOCATIONS"
PROPOSAL_ID = "EVT-PHASE11-PROPOSAL"
EXECUTOR_ID = "AOE-GA-D01-S01"
OTHER_SPECIALIST_ID = "AOE-GA-D01-S02"
POLICY_VERSION = 7
PROPOSER_GRANT_ID = "SGR-B1000000000000000000000000000001"
CONTROL_GRANT_ID = "SGR-B1000000000000000000000000000002"
EXECUTOR_GRANT_ID = "SGR-B1000000000000000000000000000003"
OTHER_GRANT_ID = "SGR-B1000000000000000000000000000004"
LIMITED_GRANT_ID = "SGR-B1000000000000000000000000000005"
EVENT_ASSERTION_ID = "PAS-B1000000000000000000000000000001"
SUBMIT_ASSERTION_ID = "PAS-B1000000000000000000000000000002"
APPROVE_ASSERTION_ID = "PAS-B1000000000000000000000000000003"
REVOKE_ASSERTION_ID = "PAS-B1000000000000000000000000000004"
OTHER_ASSERTION_ID = "PAS-B1000000000000000000000000000005"
THIRD_ASSERTION_ID = "PAS-B1000000000000000000000000000006"
STOP_ASSERTION_ID = "PAS-B1000000000000000000000000000007"
CONCURRENT_FIRST_ID = "PAS-B1000000000000000000000000000008"
CONCURRENT_SECOND_ID = "PAS-B1000000000000000000000000000009"
SIMULATION_ASSERTION_ID = "PAS-B100000000000000000000000000000A"
SCOPE_REVOCATION_ID = "SRV-B1000000000000000000000000000001"
SCOPE_REVOCATION_KEY_ID = "SCOPE-REVOCATION-PHASE11"
SCOPE_REVOCATION_ISSUER = "scope-revocation-authority"

REVOKE_ARGUMENTS = {
    "reason_code": "authorization_withdrawn",
    "reason": "Control withdrew the simulation authorization",
    "risk": "The authorization is no longer current",
    "decision_owner": "range-control",
    "idempotency_key": "phase11-revoke",
    "expected_version": 2,
}
APPROVE_ARGUMENTS = {
    "authority": "range-control",
    "constraints": ("Simulation only", "No external actions"),
    "authorization_expires_at": "2026-07-30T11:00:00Z",
    "idempotency_key": "phase11-approve",
    "expected_version": 1,
}
STOP_ARGUMENTS = {
    "reason_code": "operator_request",
    "reason": "Control stopped the mission",
    "risk": "Further processing is outside the current decision",
    "decision_owner": "range-control",
    "idempotency_key": "phase11-stop",
    "expected_version": 1,
}


class AuthenticatedApprovalRevocationPhase11Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = (
            Path(temporary.name) / "authenticated-revocations.sqlite3"
        )
        self.now = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.store.initialize()

        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
                "requested_specialist_ids": [
                    SPECIALIST_ID,
                    EXECUTOR_ID,
                    OTHER_SPECIALIST_ID,
                ],
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
            }
        )
        self.mission = MissionRequest.from_dict(raw_mission)
        self.stored_mission = self.store.create_mission(
            self.registry,
            self.mission,
        )

        self.factory = CredentialFactory()
        self.scope_revocation_private = Ed25519PrivateKey.generate()
        self.trust = TrustProvisioningService(self.store)
        self.store_id = self.trust.status().store_id
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.make_policy(POLICY_VERSION)
        self.trust.apply_policy(self.policy)

        operations = self.operations()
        self.proposer_grant = self.make_grant(
            PROPOSER_GRANT_ID,
            SPECIALIST_ID,
            operations,
        )
        self.control_grant = self.make_grant(
            CONTROL_GRANT_ID,
            CONTROL_ID,
            operations,
        )
        self.executor_grant = self.make_grant(
            EXECUTOR_GRANT_ID,
            EXECUTOR_ID,
            operations,
        )
        self.other_grant = self.make_grant(
            OTHER_GRANT_ID,
            OTHER_SPECIALIST_ID,
            operations,
        )
        self.limited_control_grant = self.make_grant(
            LIMITED_GRANT_ID,
            CONTROL_ID,
            [
                operation
                for operation in operations
                if operation
                != PrincipalOperation.APPROVAL_REVOKE.value
            ],
        )
        acceptance = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        for grant in (
            self.proposer_grant,
            self.control_grant,
            self.executor_grant,
            self.other_grant,
            self.limited_control_grant,
        ):
            acceptance.accept(grant)

        proposal = self.proposal()
        append_intent = {
            "event_batch_sha256": compute_event_batch_hash((proposal,)),
            "expected_revision": 0,
            "mission_id": MISSION_ID,
            "principal_profile_id": SPECIALIST_ID,
        }
        append_assertion = self.factory.assertion(
            grant=self.proposer_grant,
            assertion_id=EVENT_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.proposer_grant.grant_id,
            subject=self.proposer_grant.subject,
            profile_id=SPECIALIST_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.EVENT_APPEND,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EVENT_APPEND,
                append_intent,
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        AuthenticatedEventAppendService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).append(
            append_assertion,
            MISSION_ID,
            (proposal,),
            expected_revision=0,
        )

        submit_key = "phase11-submit"
        review_expires_at = "2026-07-30T10:45:00Z"
        submit_intent = {
            "executor_profile_id": EXECUTOR_ID,
            "idempotency_key_sha256": sha256_text(submit_key),
            "mission_id": MISSION_ID,
            "principal_profile_id": SPECIALIST_ID,
            "proposal_id": PROPOSAL_ID,
            "review_expires_at": review_expires_at,
        }
        submit_assertion = self.factory.assertion(
            grant=self.proposer_grant,
            assertion_id=SUBMIT_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.proposer_grant.grant_id,
            subject=self.proposer_grant.subject,
            profile_id=SPECIALIST_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.APPROVAL_SUBMIT,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_SUBMIT,
                submit_intent,
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        submission = AuthenticatedApprovalSubmissionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).submit(
            submit_assertion,
            mission_id=MISSION_ID,
            proposal_id=PROPOSAL_ID,
            executor_profile_id=EXECUTOR_ID,
            review_expires_at=review_expires_at,
            idempotency_key=submit_key,
        )
        self.approval_id = submission.approval.approval_id

        approve_assertion = self.factory.assertion(
            grant=self.control_grant,
            assertion_id=APPROVE_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.control_grant.grant_id,
            subject=self.control_grant.subject,
            profile_id=CONTROL_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.APPROVAL_APPROVE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_APPROVE,
                {
                    "approval_id": self.approval_id,
                    "authority": APPROVE_ARGUMENTS["authority"],
                    "authorization_expires_at": (
                        APPROVE_ARGUMENTS[
                            "authorization_expires_at"
                        ]
                    ),
                    "constraints": list(
                        APPROVE_ARGUMENTS["constraints"]
                    ),
                    "expected_version": 1,
                    "idempotency_key_sha256": sha256_text(
                        str(APPROVE_ARGUMENTS["idempotency_key"])
                    ),
                    "principal_profile_id": CONTROL_ID,
                },
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        AuthenticatedApprovalDecisionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).approve(
            approve_assertion,
            self.approval_id,
            **APPROVE_ARGUMENTS,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.service = AuthenticatedApprovalRevocationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    @staticmethod
    def operations() -> list[str]:
        return sorted(
            [
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.APPROVAL_REVOKE.value,
                PrincipalOperation.APPROVAL_SUBMIT.value,
                PrincipalOperation.EVENT_APPEND.value,
                PrincipalOperation.MISSION_STOP.value,
                PrincipalOperation.SIMULATION_RUN.value,
            ]
        )

    def make_policy(
        self,
        policy_version: int,
    ) -> PrincipalTrustPolicy:
        operations = self.operations()
        profiles = [
            CONTROL_ID,
            EXECUTOR_ID,
            OTHER_SPECIALIST_ID,
            SPECIALIST_ID,
        ]
        raw = self.factory.policy(
            policy_version=policy_version,
            store_id=self.store_id,
            max_scope_lifetime_seconds=7200,
            allowed_profiles=profiles,
            allowed_subjects=[SUBJECT],
            allowed_operations=operations,
        ).to_dict()
        raw["signature"] = ZERO_SIGNATURE
        raw["keys"].append(
            {
                "key_id": SCOPE_REVOCATION_KEY_ID,
                "issuer": SCOPE_REVOCATION_ISSUER,
                "public_key": b64url(
                    public_bytes(self.scope_revocation_private)
                ),
                "key_use": TrustKeyUse.SCOPE_GRANT_REVOCATION.value,
                "state": TrustKeyState.ACTIVE.value,
                "not_before": "2026-07-30T09:00:00Z",
                "not_after": "2026-07-30T12:00:00Z",
                "retire_at": None,
                "allowed_profiles": sorted(profiles),
                "allowed_subjects": [SUBJECT],
                "allowed_operations": operations,
            }
        )
        raw["keys"].sort(key=lambda item: str(item["key_id"]))
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.factory.root_private.sign(unsigned.signing_bytes())
            ),
        )

    def make_grant(
        self,
        grant_id: str,
        profile_id: str,
        operations: list[str],
        *,
        policy_version: int = POLICY_VERSION,
    ) -> ScopeGrant:
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        raw = self.factory.grant(
            profile_id=profile_id,
            subject=SUBJECT,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored_mission.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=operations,
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T11:30:00Z",
            policy_version=policy_version,
        ).to_dict()
        raw["grant_id"] = grant_id
        raw["signature"] = ZERO_SIGNATURE
        unsigned = ScopeGrant.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.factory.scope_private.sign(unsigned.signing_bytes())
            ),
        )

    @staticmethod
    def proposal() -> MissionEvent:
        return MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": PROPOSAL_ID,
                "mission_id": MISSION_ID,
                "event_type": "proposal",
                "actor_profile_id": SPECIALIST_ID,
                "timestamp": "2026-07-30T10:05:00Z",
                "payload": {
                    "target": "synthetic://phase11/revocation",
                    "method": "Evaluate a fixed plan against local policy",
                    "action_tier": "R2",
                    "expected_effect": (
                        "Produce a plan-only validation result"
                    ),
                    "safeguards": [
                        "Synthetic data only",
                        "No external actions",
                    ],
                    "rollback": "Discard the local simulation record",
                },
                "references": [],
            }
        )

    def revoke_intent(
        self,
        arguments: dict[str, object],
        *,
        approval_id: str | None = None,
        profile_id: str = CONTROL_ID,
    ) -> dict[str, object]:
        return {
            "approval_id": approval_id or self.approval_id,
            "decision_owner": arguments["decision_owner"],
            "expected_version": arguments["expected_version"],
            "idempotency_key_sha256": sha256_text(
                str(arguments["idempotency_key"])
            ),
            "principal_profile_id": profile_id,
            "reason": arguments["reason"],
            "reason_code": arguments["reason_code"],
            "risk": arguments["risk"],
        }

    def assertion(
        self,
        *,
        arguments: dict[str, object] | None = None,
        approval_id: str | None = None,
        assertion_id: str = REVOKE_ASSERTION_ID,
        grant: ScopeGrant | None = None,
        profile_id: str = CONTROL_ID,
        intent_profile_id: str | None = None,
        mission_id: str = MISSION_ID,
        operation: PrincipalOperation = (
            PrincipalOperation.APPROVAL_REVOKE
        ),
        policy_version: int = POLICY_VERSION,
        scope_grant_sha256: str | None = None,
        issued_at: str = "2026-07-30T10:05:00Z",
        not_before: str = "2026-07-30T10:05:00Z",
        expires_at: str = "2026-07-30T10:09:00Z",
    ) -> PrincipalAssertion:
        supplied = dict(
            REVOKE_ARGUMENTS if arguments is None else arguments
        )
        bound_grant = grant or self.control_grant
        intent = self.revoke_intent(
            supplied,
            approval_id=approval_id,
            profile_id=intent_profile_id or profile_id,
        )
        return self.factory.assertion(
            grant=bound_grant,
            assertion_id=assertion_id,
            policy_version=policy_version,
            scope_grant_id=bound_grant.grant_id,
            scope_grant_sha256=scope_grant_sha256,
            subject=bound_grant.subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )

    def revoke(
        self,
        *,
        arguments: dict[str, object] | None = None,
        assertion: PrincipalAssertion | None = None,
        approval_id: str | None = None,
    ) -> AuthenticatedApprovalRevocationReceipt:
        supplied = dict(
            REVOKE_ARGUMENTS if arguments is None else arguments
        )
        credential = assertion or self.assertion(
            arguments=supplied,
            approval_id=approval_id,
        )
        return self.service.revoke(
            credential,
            approval_id or self.approval_id,
            reason_code=str(supplied["reason_code"]),
            reason=str(supplied["reason"]),
            risk=str(supplied["risk"]),
            decision_owner=str(supplied["decision_owner"]),
            idempotency_key=str(supplied["idempotency_key"]),
            expected_version=supplied["expected_version"],
        )

    def state(self) -> dict[str, int | str | None]:
        with closing(sqlite3.connect(self.path)) as connection:
            mission = connection.execute(
                """
                SELECT revision, head_hash
                FROM missions
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            approval = connection.execute(
                """
                SELECT status, version, simulation_id
                FROM approval_queue
                WHERE approval_id = ?
                """,
                (self.approval_id,),
            ).fetchone()
            ledger = connection.execute(
                """
                SELECT assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            control = connection.execute(
                """
                SELECT state FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            counts = {
                name: int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} "
                        "WHERE mission_id = ?",
                        (MISSION_ID,),
                    ).fetchone()[0]
                )
                for name, table in (
                    ("events", "mission_events"),
                    ("uses", "principal_assertion_uses"),
                    ("effects", "principal_assertion_effects"),
                    ("revocations", "approval_revocations"),
                )
            }
        assert mission is not None
        assert approval is not None
        assert ledger is not None
        assert control is not None
        return {
            "revision": int(mission[0]),
            "head_hash": str(mission[1]),
            "approval_state": str(approval[0]),
            "approval_version": int(approval[1]),
            "simulation_id": (
                None if approval[2] is None else str(approval[2])
            ),
            "control_state": str(control[0]),
            "ledger_uses": int(ledger[0]),
            "ledger_effects": int(ledger[1]),
            **counts,
        }

    def scope_revocation(self) -> ScopeGrantRevocation:
        raw = {
            "schema_version": 1,
            "revocation_id": SCOPE_REVOCATION_ID,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "issuer": SCOPE_REVOCATION_ISSUER,
            "key_id": SCOPE_REVOCATION_KEY_ID,
            "audience": AUDIENCE,
            "store_id": self.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": self.stored_mission.context_hash,
            "scope_grant_issuer": self.control_grant.issuer,
            "scope_grant_id": self.control_grant.grant_id,
            "scope_grant_sha256": self.control_grant.content_sha256,
            "scope_grant_subject": self.control_grant.subject,
            "scope_grant_profile_id": self.control_grant.profile_id,
            "reason_code": "authorization_withdrawn",
            "reason": "The external authority withdrew this grant.",
            "issued_at": "2026-07-30T10:06:00Z",
            "not_before": "2026-07-30T10:06:00Z",
            "expires_at": "2026-07-30T10:10:00Z",
            "signature": ZERO_SIGNATURE,
        }
        unsigned = ScopeGrantRevocation.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                self.scope_revocation_private.sign(
                    unsigned.signing_bytes()
                )
            ),
        )

    def stop_mission(self) -> None:
        intent = {
            "decision_owner": STOP_ARGUMENTS["decision_owner"],
            "expected_version": STOP_ARGUMENTS["expected_version"],
            "idempotency_key_sha256": sha256_text(
                str(STOP_ARGUMENTS["idempotency_key"])
            ),
            "mission_id": MISSION_ID,
            "principal_profile_id": CONTROL_ID,
            "reason": STOP_ARGUMENTS["reason"],
            "reason_code": STOP_ARGUMENTS["reason_code"],
            "risk": STOP_ARGUMENTS["risk"],
        }
        current = format_timestamp(self.now)
        assertion = self.factory.assertion(
            grant=self.control_grant,
            assertion_id=STOP_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.control_grant.grant_id,
            subject=self.control_grant.subject,
            profile_id=CONTROL_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.MISSION_STOP,
                intent,
            ),
            issued_at=current,
            not_before=current,
            expires_at=format_timestamp(
                self.now + timedelta(minutes=4)
            ),
        )
        AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).stop(
            assertion,
            MISSION_ID,
            **STOP_ARGUMENTS,
        )

    def fresh_assertion(
        self,
        *,
        assertion_id: str = OTHER_ASSERTION_ID,
        arguments: dict[str, object] | None = None,
    ) -> PrincipalAssertion:
        current = format_timestamp(self.now)
        return self.assertion(
            arguments=arguments,
            assertion_id=assertion_id,
            issued_at=current,
            not_before=current,
            expires_at=format_timestamp(
                self.now + timedelta(minutes=4)
            ),
        )

    def test_valid_revoke_derives_control_and_records_exact_write_set(
        self,
    ) -> None:
        before = self.state()
        assertion = self.assertion()

        receipt = self.revoke(assertion=assertion)

        self.assertIsInstance(
            receipt,
            AuthenticatedApprovalRevocationReceipt,
        )
        self.assertEqual(
            receipt.operation,
            PrincipalOperation.APPROVAL_REVOKE,
        )
        self.assertEqual(receipt.assertion_id, assertion.assertion_id)
        self.assertEqual(receipt.principal_profile_id, CONTROL_ID)
        self.assertEqual(receipt.approval.state, ApprovalState.REVOKED)
        self.assertEqual(receipt.approval.version, 3)
        self.assertEqual(receipt.revocation.actor_profile_id, CONTROL_ID)
        self.assertEqual(
            receipt.revocation.approval_id,
            self.approval_id,
        )
        self.assertEqual(
            receipt.consumed_at,
            receipt.revocation.revoked_at,
        )

        after = self.state()
        self.assertEqual(after["revision"], before["revision"] + 1)
        self.assertEqual(after["events"], before["events"] + 1)
        self.assertEqual(after["uses"], before["uses"] + 1)
        self.assertEqual(after["effects"], before["effects"] + 1)
        self.assertEqual(
            after["ledger_uses"],
            before["ledger_uses"] + 1,
        )
        self.assertEqual(
            after["ledger_effects"],
            before["ledger_effects"] + 1,
        )
        self.assertEqual(after["revocations"], 1)
        self.assertEqual(after["approval_state"], "revoked")
        self.assertEqual(after["approval_version"], 3)
        self.assertIsNone(after["simulation_id"])

        with closing(sqlite3.connect(self.path)) as connection:
            effect_row = connection.execute(
                """
                SELECT effect_id, effect_json, recorded_at
                FROM principal_assertion_effects
                WHERE issuer = ? AND assertion_id = ?
                """,
                (assertion.issuer, assertion.assertion_id),
            ).fetchone()
            event_row = connection.execute(
                """
                SELECT event_json, stored_at
                FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (
                    MISSION_ID,
                    receipt.revocation.revocation_event_id,
                ),
            ).fetchone()
        assert effect_row is not None
        assert event_row is not None
        effect = json.loads(str(effect_row[1]))
        payload = effect["payload"]
        event = json.loads(str(event_row[0]))
        self.assertEqual(
            effect_row[0],
            receipt.revocation.revocation_event_id,
        )
        self.assertEqual(effect_row[2], receipt.consumed_at)
        self.assertEqual(effect["recorded_at"], receipt.consumed_at)
        self.assertEqual(
            payload["approval_record"],
            receipt.approval.to_dict(),
        )
        self.assertEqual(
            payload["revocation_record"],
            receipt.revocation.to_dict(),
        )
        self.assertEqual(
            payload["revocation_event"],
            event,
        )
        self.assertEqual(event["timestamp"], receipt.consumed_at)
        self.assertEqual(event_row[1], receipt.consumed_at)
        self.assertEqual(
            payload["idempotency_key_sha256"],
            sha256_text(str(REVOKE_ARGUMENTS["idempotency_key"])),
        )
        self.assertEqual(payload["pre_approval_state"], "approved")
        self.assertEqual(payload["pre_approval_version"], 2)
        self.assertEqual(payload["final_approval_state"], "revoked")
        self.assertEqual(payload["final_approval_version"], 3)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_signed_intent_binds_every_field(self) -> None:
        signed = self.assertion()
        changes = {
            "decision_owner": "different-control",
            "expected_version": 1,
            "idempotency_key": "different-key",
            "reason": "Different reason",
            "reason_code": "different_code",
            "risk": "Different risk",
        }
        before = self.state()

        for field, replacement in changes.items():
            with self.subTest(field=field):
                supplied = dict(REVOKE_ARGUMENTS)
                supplied[field] = replacement
                with self.assertRaises(PrincipalAuthenticationError):
                    self.revoke(
                        arguments=supplied,
                        assertion=signed,
                    )

        mismatched_profile_intent = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            intent_profile_id=OTHER_SPECIALIST_ID,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self.revoke(assertion=mismatched_profile_intent)

        other_approval_id = "APR-BBBBBBBBBBBBBBBBBBBBBBBB"
        with self.assertRaises(ApprovalError):
            self.revoke(
                assertion=signed,
                approval_id=other_approval_id,
            )
        self.assertEqual(self.state(), before)

    def test_wrong_identity_policy_and_scope_are_rejected(self) -> None:
        valid = self.assertion()
        wrong_mission = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            mission_id="MISSION-PHASE11-OTHER",
        )
        wrong_operation = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            operation=PrincipalOperation.APPROVAL_DENY,
        )
        wrong_signature = replace(valid, signature=ZERO_SIGNATURE)
        wrong_policy = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            policy_version=POLICY_VERSION + 1,
        )
        wrong_scope_hash = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            scope_grant_sha256="sha256:" + ("0" * 64),
        )
        missing_operation = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
            grant=self.limited_control_grant,
        )
        before = self.state()

        for credential in (
            wrong_mission,
            wrong_operation,
            wrong_signature,
            wrong_policy,
            wrong_scope_hash,
            missing_operation,
        ):
            with (
                self.subTest(assertion_id=credential.assertion_id),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.revoke(assertion=credential)

        self.assertEqual(self.state(), before)

    def test_non_control_proposer_executor_and_specialist_are_rejected(
        self,
    ) -> None:
        before = self.state()
        cases = (
            (SPECIALIST_ID, self.proposer_grant),
            (EXECUTOR_ID, self.executor_grant),
            (OTHER_SPECIALIST_ID, self.other_grant),
        )

        for index, (profile_id, grant) in enumerate(cases, start=1):
            with self.subTest(profile_id=profile_id):
                credential = self.assertion(
                    assertion_id=(
                        "PAS-B200000000000000000000000000000"
                        f"{index}"
                    ),
                    grant=grant,
                    profile_id=profile_id,
                )
                with self.assertRaisesRegex(
                    ApprovalError,
                    "Only assigned independent Control can revoke",
                ):
                    self.revoke(assertion=credential)

        self.assertEqual(self.state(), before)

    def test_version_and_authorization_gates_fail_closed(self) -> None:
        stale = dict(REVOKE_ARGUMENTS)
        stale["expected_version"] = 1
        with self.assertRaises(ApprovalConflictError):
            self.revoke(arguments=stale)
        self.assertEqual(self.state()["approval_state"], "approved")

        self.now = datetime(2026, 7, 30, 11, 0, tzinfo=UTC)
        current_assertion = self.fresh_assertion()
        with self.assertRaises(ApprovalExpiredError):
            self.revoke(assertion=current_assertion)
        self.assertEqual(self.state()["approval_state"], "approved")
        self.assertEqual(
            self.approvals.get(self.approval_id).state,
            ApprovalState.EXPIRED,
        )
        self.assertEqual(self.state()["revocations"], 0)

    def test_consumed_authorization_cannot_be_revoked(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        idempotency_key = "phase11-simulate"
        assertion = self.factory.assertion(
            grant=self.executor_grant,
            assertion_id=SIMULATION_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.executor_grant.grant_id,
            subject=self.executor_grant.subject,
            profile_id=EXECUTOR_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.SIMULATION_RUN,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.SIMULATION_RUN,
                {
                    "approval_id": self.approval_id,
                    "idempotency_key_sha256": sha256_text(
                        idempotency_key
                    ),
                    "principal_profile_id": EXECUTOR_ID,
                },
            ),
            issued_at="2026-07-30T10:06:00Z",
            not_before="2026-07-30T10:06:00Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        AuthenticatedSimulationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).simulate(
            assertion,
            self.approval_id,
            idempotency_key=idempotency_key,
        )
        before = self.state()

        with self.assertRaises(ApprovalConflictError):
            self.revoke(assertion=self.fresh_assertion())

        self.assertEqual(self.state(), before)
        self.assertEqual(before["approval_state"], "consumed")
        self.assertIsNotNone(before["simulation_id"])

    def test_stopped_mission_cannot_accept_a_new_revocation(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.stop_mission()
        before = self.state()

        with self.assertRaises(MissionControlError):
            self.revoke(assertion=self.fresh_assertion())

        self.assertEqual(self.state(), before)
        self.assertEqual(before["control_state"], "stopped")

    def test_direct_new_and_exact_retry_paths_are_gated(self) -> None:
        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval revocations are required",
        ):
            self.approvals.revoke(
                self.approval_id,
                principal_profile_id=CONTROL_ID,
                **REVOKE_ARGUMENTS,
            )
        self.assertEqual(self.state()["approval_state"], "approved")

        self.revoke()
        before = self.state()
        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval revocations are required",
        ):
            self.approvals.revoke(
                self.approval_id,
                principal_profile_id=CONTROL_ID,
                **REVOKE_ARGUMENTS,
            )
        self.assertEqual(self.state(), before)

    def test_exact_replay_survives_credential_expiry(self) -> None:
        assertion = self.assertion()
        first = self.revoke(assertion=assertion)
        before = self.state()
        self.now = datetime(2026, 7, 30, 11, 31, tzinfo=UTC)

        replay = self.revoke(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)

    def test_exact_replay_survives_policy_advancement(self) -> None:
        assertion = self.assertion()
        first = self.revoke(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.trust.apply_policy(self.make_policy(POLICY_VERSION + 1))
        before = self.state()

        replay = self.revoke(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)

    def test_exact_replay_survives_scope_revocation(self) -> None:
        assertion = self.assertion()
        first = self.revoke(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.scope_revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        before = self.state()

        replay = self.revoke(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)

    def test_exact_replay_survives_mission_stop(self) -> None:
        assertion = self.assertion()
        first = self.revoke(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.stop_mission()
        before = self.state()

        replay = self.revoke(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)
        self.assertEqual(before["control_state"], "stopped")

    def test_request_and_idempotency_key_cannot_rebind(self) -> None:
        self.revoke()
        before = self.state()
        same_request = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.revoke(assertion=same_request)

        changed = dict(REVOKE_ARGUMENTS)
        changed["reason"] = "Different revocation reason"
        same_key = self.assertion(
            arguments=changed,
            assertion_id=THIRD_ASSERTION_ID,
        )
        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.revoke(arguments=changed, assertion=same_key)
        self.assertEqual(self.state(), before)

    def test_concurrent_assertions_commit_exactly_one_revocation(
        self,
    ) -> None:
        assertions = (
            self.assertion(assertion_id=CONCURRENT_FIRST_ID),
            self.assertion(assertion_id=CONCURRENT_SECOND_ID),
        )
        barrier = threading.Barrier(2)

        def run(
            assertion: PrincipalAssertion,
        ) -> AuthenticatedApprovalRevocationReceipt | Exception:
            service = AuthenticatedApprovalRevocationService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.revoke(
                    assertion,
                    self.approval_id,
                    **REVOKE_ARGUMENTS,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(run, assertions))

        receipts = tuple(
            result
            for result in results
            if isinstance(
                result,
                AuthenticatedApprovalRevocationReceipt,
            )
        )
        conflicts = tuple(
            result
            for result in results
            if isinstance(
                result,
                (ApprovalConflictError, StoreConflictError),
            )
        )
        self.assertEqual(len(receipts), 1, results)
        self.assertEqual(len(conflicts), 1, results)
        self.assertEqual(self.state()["revocations"], 1)
        self.assertEqual(self.state()["approval_state"], "revoked")
        self.assertEqual(self.state()["uses"], 4)
        self.assertEqual(self.state()["effects"], 4)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_provenance_failure_rolls_back_every_write(self) -> None:
        assertion = self.assertion()
        before = self.state()

        with (
            mock.patch.object(
                self.service,
                "_approval_revocation_effect",
                side_effect=StoreIntegrityError(
                    "injected revocation provenance failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "injected revocation provenance failure",
            ),
        ):
            self.revoke(assertion=assertion)

        self.assertEqual(self.state(), before)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_effect_tampering_is_detected(self) -> None:
        self.revoke()
        with closing(sqlite3.connect(self.path)) as connection:
            trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_effect_immutable'
                """
            ).fetchone()
            self.assertIsNotNone(trigger)
            connection.execute(
                "DROP TRIGGER principal_assertion_effect_immutable"
            )
            row = connection.execute(
                """
                SELECT effect_json FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (MISSION_ID, APPROVAL_REVOKE_EFFECT_KIND),
            ).fetchone()
            assert row is not None
            raw = json.loads(str(row[0]))
            raw["payload"]["expected_approval_version"] = 1
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (
                    canonical_json(raw),
                    MISSION_ID,
                    APPROVAL_REVOKE_EFFECT_KIND,
                ),
            )
            connection.execute(str(trigger[0]))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_authenticated_revocation_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "sunderkey"
            / "authenticated_approval_revocations.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
            "webbrowser",
        }
        forbidden_calls = {
            "__import__",
            "compile",
            "eval",
            "exec",
        }
        imported: set[str] = set()
        called: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(
                    alias.name.split(".", 1)[0]
                    for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
            ):
                called.add(node.func.id)
        self.assertFalse(imported & forbidden_imports)
        self.assertFalse(called & forbidden_calls)


if __name__ == "__main__":
    unittest.main()

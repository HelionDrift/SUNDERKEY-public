"""Adversarial tests for authenticated Phase 10 approval submissions."""

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
    AuthenticatedApprovalSubmissionReceipt,
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
    APPROVAL_SUBMIT_EFFECT_KIND,
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

MISSION_ID = "MISSION-PHASE10-APPROVAL-SUBMISSIONS"
PROPOSAL_ID = "EVT-PHASE10-PROPOSAL"
SECOND_PROPOSAL_ID = "EVT-PHASE10-SECOND-PROPOSAL"
POLICY_VERSION = 7
SPECIALIST_GRANT_ID = "SGR-A0000000000000000000000000000001"
CONTROL_GRANT_ID = "SGR-A0000000000000000000000000000002"
UNACCEPTED_GRANT_ID = "SGR-A0000000000000000000000000000003"
EVENT_ASSERTION_ID = "PAS-A0000000000000000000000000000001"
SUBMIT_ASSERTION_ID = "PAS-A0000000000000000000000000000002"
OTHER_ASSERTION_ID = "PAS-A0000000000000000000000000000003"
SECOND_EVENT_ASSERTION_ID = "PAS-A0000000000000000000000000000004"
APPROVE_ASSERTION_ID = "PAS-A0000000000000000000000000000005"
DENY_ASSERTION_ID = "PAS-A0000000000000000000000000000006"
STOP_ASSERTION_ID = "PAS-A0000000000000000000000000000007"
CONCURRENT_FIRST_ID = "PAS-A0000000000000000000000000000008"
CONCURRENT_SECOND_ID = "PAS-A0000000000000000000000000000009"
REVOKE_ASSERTION_ID = "PAS-A000000000000000000000000000000A"
SIMULATION_ASSERTION_ID = "PAS-A000000000000000000000000000000B"
REVOCATION_ID = "SRV-A0000000000000000000000000000001"
REVOCATION_KEY_ID = "SCOPE-REVOCATION-PHASE10"
REVOCATION_ISSUER = "scope-revocation-authority"

SUBMIT_ARGUMENTS = {
    "mission_id": MISSION_ID,
    "proposal_id": PROPOSAL_ID,
    "executor_profile_id": SPECIALIST_ID,
    "review_expires_at": "2026-07-30T11:00:00Z",
    "idempotency_key": "phase10-submit",
}
APPROVE_ARGUMENTS = {
    "authority": "range-control",
    "constraints": ("Simulation only", "No external actions"),
    "authorization_expires_at": "2026-07-30T10:55:00Z",
    "idempotency_key": "phase10-approve",
    "expected_version": 1,
}
DENY_ARGUMENTS = {
    "reason_code": "scope_mismatch",
    "reason": "The proposal does not match the reviewed scope",
    "risk": "Approval could cross the authorized boundary",
    "decision_owner": "range-control",
    "idempotency_key": "phase10-deny",
    "expected_version": 1,
}
STOP_ARGUMENTS = {
    "reason_code": "operator_request",
    "reason": "Control stopped the mission",
    "risk": "Further processing is outside the current decision",
    "decision_owner": "range-control",
    "idempotency_key": "phase10-stop",
    "expected_version": 1,
}
REVOKE_ARGUMENTS = {
    "reason_code": "authorization_withdrawn",
    "reason": "Control withdrew the authorization",
    "risk": "The authorization is no longer current",
    "decision_owner": "range-control",
    "idempotency_key": "phase10-revoke",
    "expected_version": 2,
}


class AuthenticatedApprovalSubmissionPhase10Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authenticated-submissions.sqlite3"
        self.now = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.store.initialize()

        raw_mission = mission_data()
        raw_mission.update(
            {
                "mission_id": MISSION_ID,
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
        self.revocation_private = Ed25519PrivateKey.generate()
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
        self.specialist_grant = self.make_grant(
            SPECIALIST_GRANT_ID,
            SPECIALIST_ID,
            operations,
            expires_at="2026-07-30T11:30:00Z",
        )
        self.control_grant = self.make_grant(
            CONTROL_GRANT_ID,
            CONTROL_ID,
            operations,
            expires_at="2026-07-30T11:30:00Z",
        )
        acceptance = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        acceptance.accept(self.specialist_grant)
        acceptance.accept(self.control_grant)

        (
            self.proposal,
            self.proposal_append_receipt,
        ) = self.append_proposal(
            PROPOSAL_ID,
            EVENT_ASSERTION_ID,
        )
        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.service = AuthenticatedApprovalSubmissionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    @staticmethod
    def operations() -> list[str]:
        return sorted(
            [
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.APPROVAL_DENY.value,
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
        raw = self.factory.policy(
            policy_version=policy_version,
            store_id=self.store_id,
            max_scope_lifetime_seconds=7200,
            allowed_profiles=[CONTROL_ID, SPECIALIST_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=operations,
        ).to_dict()
        raw["signature"] = ZERO_SIGNATURE
        raw["keys"].append(
            {
                "key_id": REVOCATION_KEY_ID,
                "issuer": REVOCATION_ISSUER,
                "public_key": b64url(
                    public_bytes(self.revocation_private)
                ),
                "key_use": TrustKeyUse.SCOPE_GRANT_REVOCATION.value,
                "state": TrustKeyState.ACTIVE.value,
                "not_before": "2026-07-30T09:00:00Z",
                "not_after": "2026-07-30T12:00:00Z",
                "retire_at": None,
                "allowed_profiles": sorted(
                    [CONTROL_ID, SPECIALIST_ID]
                ),
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
        expires_at: str,
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
            expires_at=expires_at,
            policy_version=POLICY_VERSION,
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
    def make_proposal(
        event_id: str,
        *,
        actor_profile_id: str = SPECIALIST_ID,
    ) -> MissionEvent:
        return MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": MISSION_ID,
                "event_type": "proposal",
                "actor_profile_id": actor_profile_id,
                "timestamp": "2026-07-30T10:05:00Z",
                "payload": {
                    "target": (
                        "synthetic://phase10/"
                        f"{event_id.lower()}"
                    ),
                    "method": (
                        "Evaluate a fixed plan against local policy"
                    ),
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

    def append_proposal(
        self,
        event_id: str,
        assertion_id: str,
    ):
        proposal = self.make_proposal(event_id)
        expected_revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        assertion = self.factory.assertion(
            grant=self.specialist_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.specialist_grant.grant_id,
            subject=self.specialist_grant.subject,
            profile_id=SPECIALIST_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.EVENT_APPEND,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EVENT_APPEND,
                {
                    "event_batch_sha256": compute_event_batch_hash(
                        (proposal,)
                    ),
                    "expected_revision": expected_revision,
                    "mission_id": MISSION_ID,
                    "principal_profile_id": SPECIALIST_ID,
                },
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        receipt = AuthenticatedEventAppendService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).append(
            assertion,
            MISSION_ID,
            (proposal,),
            expected_revision=expected_revision,
        )
        return proposal, receipt.receipts[0]

    def submit_intent_hash(
        self,
        arguments: dict[str, object],
        *,
        profile_id: str,
    ) -> str:
        return compute_operation_intent_hash(
            PrincipalOperation.APPROVAL_SUBMIT,
            {
                "executor_profile_id": (
                    arguments["executor_profile_id"]
                ),
                "idempotency_key_sha256": sha256_text(
                    str(arguments["idempotency_key"])
                ),
                "mission_id": arguments["mission_id"],
                "principal_profile_id": profile_id,
                "proposal_id": arguments["proposal_id"],
                "review_expires_at": (
                    arguments["review_expires_at"]
                ),
            },
        )

    def assertion(
        self,
        arguments: dict[str, object] | None = None,
        *,
        assertion_id: str = SUBMIT_ASSERTION_ID,
        grant: ScopeGrant | None = None,
        profile_id: str = SPECIALIST_ID,
        mission_id: str = MISSION_ID,
        policy_version: int = POLICY_VERSION,
        operation: PrincipalOperation = (
            PrincipalOperation.APPROVAL_SUBMIT
        ),
        operation_intent_sha256: str | None = None,
        issued_at: str | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
    ) -> PrincipalAssertion:
        supplied = dict(
            SUBMIT_ARGUMENTS if arguments is None else arguments
        )
        bound_grant = grant or self.specialist_grant
        current = format_timestamp(self.now)
        expiry = format_timestamp(self.now + timedelta(minutes=4))
        return self.factory.assertion(
            grant=bound_grant,
            assertion_id=assertion_id,
            policy_version=policy_version,
            scope_grant_id=bound_grant.grant_id,
            subject=bound_grant.subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=mission_id,
            operation=operation,
            operation_intent_sha256=(
                operation_intent_sha256
                or self.submit_intent_hash(
                    supplied,
                    profile_id=profile_id,
                )
            ),
            issued_at=issued_at or current,
            not_before=not_before or current,
            expires_at=expires_at or expiry,
        )

    def submit(
        self,
        *,
        arguments: dict[str, object] | None = None,
        assertion: PrincipalAssertion | None = None,
    ) -> AuthenticatedApprovalSubmissionReceipt:
        supplied = dict(
            SUBMIT_ARGUMENTS if arguments is None else arguments
        )
        credential = assertion or self.assertion(supplied)
        return self.service.submit(
            credential,
            mission_id=str(supplied["mission_id"]),
            proposal_id=str(supplied["proposal_id"]),
            executor_profile_id=str(
                supplied["executor_profile_id"]
            ),
            review_expires_at=str(
                supplied["review_expires_at"]
            ),
            idempotency_key=str(supplied["idempotency_key"]),
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
            approvals = connection.execute(
                """
                SELECT status, version
                FROM approval_queue
                WHERE mission_id = ?
                ORDER BY approval_id
                """,
                (MISSION_ID,),
            ).fetchall()
            control = connection.execute(
                """
                SELECT state, version
                FROM mission_controls
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            ledger = connection.execute(
                """
                SELECT assertion_count, effect_count
                FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            events = connection.execute(
                """
                SELECT COUNT(*) FROM mission_events
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            uses = connection.execute(
                """
                SELECT COUNT(*) FROM principal_assertion_uses
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            effects = connection.execute(
                """
                SELECT COUNT(*) FROM principal_assertion_effects
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
        assert mission is not None
        assert control is not None
        assert ledger is not None
        return {
            "revision": int(mission[0]),
            "head_hash": str(mission[1]),
            "approval_count": len(approvals),
            "approval_state": (
                None if not approvals else str(approvals[0][0])
            ),
            "approval_version": (
                None if not approvals else int(approvals[0][1])
            ),
            "control_state": str(control[0]),
            "control_version": int(control[1]),
            "events": int(events),
            "uses": int(uses),
            "effects": int(effects),
            "ledger_uses": int(ledger[0]),
            "ledger_effects": int(ledger[1]),
        }

    def assert_no_submission(self) -> None:
        current = self.state()
        self.assertEqual(current["approval_count"], 0)
        self.assertEqual(current["uses"], 1)
        self.assertEqual(current["effects"], 1)
        self.assertEqual(current["ledger_uses"], 1)
        self.assertEqual(current["ledger_effects"], 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def revocation(self) -> ScopeGrantRevocation:
        raw = {
            "schema_version": 1,
            "revocation_id": REVOCATION_ID,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "issuer": REVOCATION_ISSUER,
            "key_id": REVOCATION_KEY_ID,
            "audience": AUDIENCE,
            "store_id": self.store_id,
            "mission_id": MISSION_ID,
            "mission_context_hash": self.stored_mission.context_hash,
            "scope_grant_issuer": self.specialist_grant.issuer,
            "scope_grant_id": self.specialist_grant.grant_id,
            "scope_grant_sha256": self.specialist_grant.content_sha256,
            "scope_grant_subject": self.specialist_grant.subject,
            "scope_grant_profile_id": (
                self.specialist_grant.profile_id
            ),
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
                self.revocation_private.sign(unsigned.signing_bytes())
            ),
        )

    def decision_assertion(
        self,
        operation: PrincipalOperation,
        approval_id: str,
        *,
        assertion_id: str,
    ) -> PrincipalAssertion:
        if operation is PrincipalOperation.APPROVAL_APPROVE:
            intent = {
                "approval_id": approval_id,
                "authority": APPROVE_ARGUMENTS["authority"],
                "authorization_expires_at": (
                    APPROVE_ARGUMENTS["authorization_expires_at"]
                ),
                "constraints": list(
                    APPROVE_ARGUMENTS["constraints"]
                ),
                "expected_version": (
                    APPROVE_ARGUMENTS["expected_version"]
                ),
                "idempotency_key_sha256": sha256_text(
                    str(APPROVE_ARGUMENTS["idempotency_key"])
                ),
                "principal_profile_id": CONTROL_ID,
            }
        else:
            arguments = (
                REVOKE_ARGUMENTS
                if operation is PrincipalOperation.APPROVAL_REVOKE
                else DENY_ARGUMENTS
            )
            intent = {
                "approval_id": approval_id,
                "decision_owner": arguments["decision_owner"],
                "expected_version": arguments["expected_version"],
                "idempotency_key_sha256": sha256_text(
                    str(arguments["idempotency_key"])
                ),
                "principal_profile_id": CONTROL_ID,
                "reason": arguments["reason"],
                "reason_code": arguments["reason_code"],
                "risk": arguments["risk"],
            }
        current = format_timestamp(self.now)
        return self.factory.assertion(
            grant=self.control_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.control_grant.grant_id,
            subject=self.control_grant.subject,
            profile_id=CONTROL_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
            issued_at=current,
            not_before=current,
            expires_at=format_timestamp(
                self.now + timedelta(minutes=4)
            ),
        )

    def approve(self, approval_id: str) -> None:
        assertion = self.decision_assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            approval_id,
            assertion_id=APPROVE_ASSERTION_ID,
        )
        AuthenticatedApprovalDecisionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).approve(
            assertion,
            approval_id,
            **APPROVE_ARGUMENTS,
        )

    def deny(self, approval_id: str) -> None:
        assertion = self.decision_assertion(
            PrincipalOperation.APPROVAL_DENY,
            approval_id,
            assertion_id=DENY_ASSERTION_ID,
        )
        AuthenticatedApprovalDecisionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).deny(
            assertion,
            approval_id,
            **DENY_ARGUMENTS,
        )

    def revoke(self, approval_id: str) -> None:
        assertion = self.decision_assertion(
            PrincipalOperation.APPROVAL_REVOKE,
            approval_id,
            assertion_id=REVOKE_ASSERTION_ID,
        )
        AuthenticatedApprovalRevocationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).revoke(
            assertion,
            approval_id,
            **REVOKE_ARGUMENTS,
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

    def test_valid_submission_derives_actor_and_records_exact_effect(
        self,
    ) -> None:
        assertion = self.assertion()
        receipt = self.submit(assertion=assertion)

        self.assertIsInstance(
            receipt,
            AuthenticatedApprovalSubmissionReceipt,
        )
        self.assertEqual(
            receipt.operation,
            PrincipalOperation.APPROVAL_SUBMIT,
        )
        self.assertEqual(receipt.assertion_id, assertion.assertion_id)
        self.assertEqual(receipt.principal_profile_id, SPECIALIST_ID)
        self.assertEqual(
            receipt.approval.proposer_profile_id,
            SPECIALIST_ID,
        )
        self.assertEqual(receipt.approval.state, ApprovalState.PENDING)
        self.assertEqual(receipt.approval.version, 1)
        self.assertEqual(
            receipt.consumed_at,
            receipt.approval.submitted_at,
        )
        self.assertEqual(
            receipt.operation_intent_sha256,
            self.submit_intent_hash(
                SUBMIT_ARGUMENTS,
                profile_id=SPECIALIST_ID,
            ),
        )

        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            event_row = connection.execute(
                """
                SELECT sequence, entry_hash, stored_at
                FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, PROPOSAL_ID),
            ).fetchone()
            effect_row = connection.execute(
                """
                SELECT effect_id, effect_json
                FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (MISSION_ID, APPROVAL_SUBMIT_EFFECT_KIND),
            ).fetchone()
            mission_row = connection.execute(
                """
                SELECT revision, head_hash
                FROM missions WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
        assert event_row is not None
        assert effect_row is not None
        assert mission_row is not None
        effect = json.loads(str(effect_row["effect_json"]))
        self.assertEqual(
            set(effect),
            {
                "effect_id",
                "effect_kind",
                "payload",
                "recorded_at",
                "schema_version",
            },
        )
        self.assertEqual(
            effect_row["effect_id"],
            receipt.approval.approval_id,
        )
        self.assertEqual(effect["effect_id"], receipt.approval.approval_id)
        self.assertEqual(
            effect["effect_kind"],
            APPROVAL_SUBMIT_EFFECT_KIND,
        )
        self.assertEqual(effect["schema_version"], 1)
        self.assertEqual(effect["recorded_at"], receipt.consumed_at)
        self.assertEqual(
            set(effect["payload"]),
            {
                "approval_id",
                "approval_record",
                "idempotency_key_sha256",
                "mission_head_hash",
                "mission_revision",
                "proposal_entry_hash",
                "proposal_event",
                "proposal_sequence",
                "proposal_stored_at",
                "submit_request_sha256",
            },
        )
        request = {
            "mission_id": MISSION_ID,
            "proposal_id": PROPOSAL_ID,
            "executor_profile_id": SPECIALIST_ID,
            "review_expires_at": (
                SUBMIT_ARGUMENTS["review_expires_at"]
            ),
            "principal_profile_id": SPECIALIST_ID,
            "purpose": "simulation",
        }
        self.assertEqual(
            effect["payload"],
            {
                "approval_id": receipt.approval.approval_id,
                "approval_record": receipt.approval.to_dict(),
                "submit_request_sha256": sha256_text(
                    canonical_json(request)
                ),
                "idempotency_key_sha256": sha256_text(
                    str(SUBMIT_ARGUMENTS["idempotency_key"])
                ),
                "proposal_event": self.proposal.to_dict(),
                "proposal_sequence": int(event_row["sequence"]),
                "proposal_entry_hash": str(
                    event_row["entry_hash"]
                ),
                "proposal_stored_at": str(event_row["stored_at"]),
                "mission_revision": int(mission_row["revision"]),
                "mission_head_hash": str(mission_row["head_hash"]),
            },
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_operation_intent_binds_every_signed_field(self) -> None:
        changes = (
            ("mission_id", "MISSION-PHASE10-OTHER", SPECIALIST_ID),
            ("proposal_id", "EVT-PHASE10-OTHER", SPECIALIST_ID),
            ("executor_profile_id", CONTROL_ID, SPECIALIST_ID),
            (
                "review_expires_at",
                "2026-07-30T11:01:00Z",
                SPECIALIST_ID,
            ),
            (
                "idempotency_key",
                "phase10-different-key",
                SPECIALIST_ID,
            ),
            ("principal_profile_id", None, CONTROL_ID),
        )
        for index, (field, replacement, signed_profile) in enumerate(
            changes,
            start=10,
        ):
            with self.subTest(field=field):
                signed_arguments = dict(SUBMIT_ARGUMENTS)
                if replacement is not None:
                    signed_arguments[field] = replacement
                assertion = self.assertion(
                    assertion_id=(
                        "PAS-A00000000000000000000000000000"
                        f"{index}"
                    ),
                    operation_intent_sha256=self.submit_intent_hash(
                        signed_arguments,
                        profile_id=signed_profile,
                    ),
                )
                with self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "operation intent",
                ):
                    self.submit(assertion=assertion)

        self.assert_no_submission()

    def test_proposal_actor_must_match_authenticated_profile(
        self,
    ) -> None:
        assertion = self.assertion(
            grant=self.control_grant,
            profile_id=CONTROL_ID,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            ApprovalError,
            "stored proposal actor",
        ):
            self.submit(assertion=assertion)

        self.assert_no_submission()

    def test_wrong_mission_operation_signature_profile_and_policy_fail(
        self,
    ) -> None:
        approve_intent = compute_operation_intent_hash(
            PrincipalOperation.APPROVAL_APPROVE,
            {
                "approval_id": "APR-PHASE10-PLACEHOLDER",
                "authority": "range-control",
                "authorization_expires_at": "2026-07-30T11:00:00Z",
                "constraints": ["Simulation only"],
                "expected_version": 1,
                "idempotency_key_sha256": sha256_text("wrong-operation"),
                "principal_profile_id": SPECIALIST_ID,
            },
        )
        valid = self.assertion()
        cases = {
            "mission": self.assertion(
                assertion_id=OTHER_ASSERTION_ID,
                mission_id="MISSION-PHASE10-OTHER",
            ),
            "operation": self.assertion(
                assertion_id=OTHER_ASSERTION_ID,
                operation=PrincipalOperation.APPROVAL_APPROVE,
                operation_intent_sha256=approve_intent,
            ),
            "signature": replace(valid, signature=ZERO_SIGNATURE),
            "profile": self.assertion(
                assertion_id=OTHER_ASSERTION_ID,
                profile_id=CONTROL_ID,
            ),
            "policy": self.assertion(
                assertion_id=OTHER_ASSERTION_ID,
                policy_version=POLICY_VERSION + 1,
            ),
        }
        for label, assertion in cases.items():
            with (
                self.subTest(case=label),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.submit(assertion=assertion)

        self.assert_no_submission()

    def test_unaccepted_scope_grant_is_rejected(self) -> None:
        grant = self.make_grant(
            UNACCEPTED_GRANT_ID,
            SPECIALIST_ID,
            self.operations(),
            expires_at="2026-07-30T11:29:00Z",
        )
        assertion = self.assertion(
            grant=grant,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "scope grant is not accepted",
        ):
            self.submit(assertion=assertion)

        self.assert_no_submission()

    def test_expired_scope_grant_is_rejected_without_grace(self) -> None:
        self.now = datetime(2026, 7, 30, 11, 31, tzinfo=UTC)
        arguments = dict(SUBMIT_ARGUMENTS)
        arguments["review_expires_at"] = "2026-07-30T11:50:00Z"
        assertion = self.assertion(
            arguments,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaises(PrincipalAuthenticationError):
            self.submit(arguments=arguments, assertion=assertion)

        self.assert_no_submission()

    def test_revoked_scope_grant_is_rejected_without_grace(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        assertion = self.assertion(
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "revoked",
        ):
            self.submit(assertion=assertion)

        self.assert_no_submission()

    def test_expired_review_window_is_rejected_atomically(self) -> None:
        arguments = dict(SUBMIT_ARGUMENTS)
        arguments["review_expires_at"] = "2026-07-30T10:05:00Z"
        assertion = self.assertion(
            arguments,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaises(ApprovalExpiredError):
            self.submit(arguments=arguments, assertion=assertion)

        self.assert_no_submission()

    def test_stopped_mission_rejects_new_authenticated_submission(
        self,
    ) -> None:
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.stop_mission()
        before = self.state()
        assertion = self.assertion(assertion_id=OTHER_ASSERTION_ID)

        with self.assertRaises(MissionControlError):
            self.submit(assertion=assertion)

        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_count"], 0)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_direct_new_submission_is_gated_after_policy(self) -> None:
        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval submissions are required",
        ):
            self.approvals.submit(
                **SUBMIT_ARGUMENTS,
                principal_profile_id=SPECIALIST_ID,
            )

        self.assert_no_submission()

    def test_direct_content_equivalent_retry_is_also_gated(
        self,
    ) -> None:
        self.submit()
        before = self.state()

        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval submissions are required",
        ):
            self.approvals.submit(
                **SUBMIT_ARGUMENTS,
                principal_profile_id=SPECIALIST_ID,
            )

        self.assertEqual(self.state(), before)

    def test_exact_replay_is_read_only_after_assertion_scope_and_review_expiry(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 11, 31, tzinfo=UTC)
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(replay.approval.state, ApprovalState.PENDING)
        self.assertEqual(self.state(), before)

    def test_exact_replay_is_read_only_after_policy_advancement(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.trust.apply_policy(self.make_policy(POLICY_VERSION + 1))
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)

    def test_exact_replay_is_read_only_after_scope_revocation(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)

    def test_exact_replay_is_read_only_after_mission_stop(self) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.stop_mission()
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["control_state"], "stopped")

    def test_exact_replay_retains_pending_snapshot_after_approve(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.approve(first.approval.approval_id)
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(replay.approval.state, ApprovalState.PENDING)
        self.assertEqual(replay.approval.version, 1)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_state"], "approved")

    def test_exact_replay_retains_pending_snapshot_after_deny(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.deny(first.approval.approval_id)
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(replay.approval.state, ApprovalState.PENDING)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_state"], "denied")

    def test_exact_replay_survives_later_simulation_consumption(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.approve(first.approval.approval_id)
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        idempotency_key = "phase10-simulate"
        simulation_assertion = self.factory.assertion(
            grant=self.specialist_grant,
            assertion_id=SIMULATION_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.specialist_grant.grant_id,
            subject=self.specialist_grant.subject,
            profile_id=SPECIALIST_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.SIMULATION_RUN,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.SIMULATION_RUN,
                {
                    "approval_id": first.approval.approval_id,
                    "idempotency_key_sha256": sha256_text(
                        idempotency_key
                    ),
                    "principal_profile_id": SPECIALIST_ID,
                },
            ),
            issued_at="2026-07-30T10:07:00Z",
            not_before="2026-07-30T10:07:00Z",
            expires_at="2026-07-30T10:11:00Z",
        )
        AuthenticatedSimulationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).simulate(
            simulation_assertion,
            first.approval.approval_id,
            idempotency_key=idempotency_key,
        )
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_state"], "consumed")

    def test_exact_replay_survives_later_approval_revocation(
        self,
    ) -> None:
        assertion = self.assertion()
        first = self.submit(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.approve(first.approval.approval_id)
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        self.revoke(first.approval.approval_id)
        before = self.state()

        replay = self.submit(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_state"], "revoked")

    def test_same_intent_cannot_bind_a_different_assertion(self) -> None:
        self.submit()
        competing = self.assertion(assertion_id=OTHER_ASSERTION_ID)
        before = self.state()

        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.submit(assertion=competing)

        self.assertEqual(self.state(), before)

    def test_idempotency_key_cannot_rebind_to_another_proposal(
        self,
    ) -> None:
        self.submit()
        self.append_proposal(
            SECOND_PROPOSAL_ID,
            SECOND_EVENT_ASSERTION_ID,
        )
        arguments = dict(SUBMIT_ARGUMENTS)
        arguments["proposal_id"] = SECOND_PROPOSAL_ID
        competing = self.assertion(
            arguments,
            assertion_id=OTHER_ASSERTION_ID,
        )
        before = self.state()

        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.submit(arguments=arguments, assertion=competing)

        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_count"], 1)

    def test_concurrent_exact_retries_commit_once(self) -> None:
        assertion = self.assertion()
        barrier = threading.Barrier(2)

        def run() -> AuthenticatedApprovalSubmissionReceipt | Exception:
            service = AuthenticatedApprovalSubmissionService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.submit(
                    assertion,
                    **SUBMIT_ARGUMENTS,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(executor.map(lambda _: run(), range(2)))

        self.assertTrue(
            all(
                isinstance(
                    result,
                    AuthenticatedApprovalSubmissionReceipt,
                )
                for result in results
            ),
            results,
        )
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.state()["approval_count"], 1)
        self.assertEqual(self.state()["uses"], 2)
        self.assertEqual(self.state()["effects"], 2)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_concurrent_competing_submissions_commit_exactly_one(
        self,
    ) -> None:
        first_arguments = dict(SUBMIT_ARGUMENTS)
        second_arguments = dict(SUBMIT_ARGUMENTS)
        second_arguments.update(
            {
                "review_expires_at": "2026-07-30T11:01:00Z",
                "idempotency_key": "phase10-competing-submit",
            }
        )
        first_assertion = self.assertion(
            first_arguments,
            assertion_id=CONCURRENT_FIRST_ID,
        )
        second_assertion = self.assertion(
            second_arguments,
            assertion_id=CONCURRENT_SECOND_ID,
        )
        barrier = threading.Barrier(2)

        def run(
            arguments: dict[str, object],
            assertion: PrincipalAssertion,
        ) -> AuthenticatedApprovalSubmissionReceipt | Exception:
            service = AuthenticatedApprovalSubmissionService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.submit(
                    assertion,
                    mission_id=str(arguments["mission_id"]),
                    proposal_id=str(arguments["proposal_id"]),
                    executor_profile_id=str(
                        arguments["executor_profile_id"]
                    ),
                    review_expires_at=str(
                        arguments["review_expires_at"]
                    ),
                    idempotency_key=str(
                        arguments["idempotency_key"]
                    ),
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda item: run(*item),
                    (
                        (first_arguments, first_assertion),
                        (second_arguments, second_assertion),
                    ),
                )
            )

        receipts = tuple(
            result
            for result in results
            if isinstance(
                result,
                AuthenticatedApprovalSubmissionReceipt,
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
        self.assertEqual(self.state()["approval_count"], 1)
        self.assertEqual(self.state()["uses"], 2)
        self.assertEqual(self.state()["effects"], 2)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_provenance_failure_rolls_back_full_submission(self) -> None:
        assertion = self.assertion()
        before = self.state()

        with (
            mock.patch.object(
                self.service,
                "_approval_submission_effect",
                side_effect=StoreIntegrityError(
                    "injected submission provenance failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "injected submission provenance failure",
            ),
        ):
            self.submit(assertion=assertion)

        self.assertEqual(self.state(), before)
        self.assert_no_submission()

    def test_effect_cannot_claim_a_stale_mission_prefix(self) -> None:
        self.append_proposal(
            SECOND_PROPOSAL_ID,
            SECOND_EVENT_ASSERTION_ID,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            stale_head = connection.execute(
                """
                SELECT entry_hash
                FROM mission_events
                WHERE mission_id = ? AND sequence = 1
                """,
                (MISSION_ID,),
            ).fetchone()
        assert stale_head is not None
        original_effect = self.service._approval_submission_effect

        def stale_effect(*, applied, consumed_at):
            effect = original_effect(
                applied=applied,
                consumed_at=consumed_at,
            )
            effect["payload"]["mission_revision"] = 1
            effect["payload"]["mission_head_hash"] = str(
                stale_head[0]
            )
            return effect

        before = self.state()
        with (
            mock.patch.object(
                self.service,
                "_approval_submission_effect",
                side_effect=stale_effect,
            ),
            self.assertRaisesRegex(
                StoreConflictError,
                "conflicts with durable state",
            ),
        ):
            self.submit()

        self.assertEqual(self.state(), before)
        self.assertEqual(self.state()["approval_count"], 0)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_effect_tampering_is_detected(self) -> None:
        self.submit()
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
                SELECT effect_json
                FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (MISSION_ID, APPROVAL_SUBMIT_EFFECT_KIND),
            ).fetchone()
            assert row is not None
            raw = json.loads(str(row[0]))
            raw["payload"]["proposal_sequence"] += 1
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (
                    canonical_json(raw),
                    MISSION_ID,
                    APPROVAL_SUBMIT_EFFECT_KIND,
                ),
            )
            connection.execute(str(trigger[0]))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_approval_row_tampering_is_detected(self) -> None:
        receipt = self.submit()
        with closing(sqlite3.connect(self.path)) as connection:
            triggers = connection.execute(
                """
                SELECT name, sql FROM sqlite_master
                WHERE type = 'trigger' AND tbl_name = 'approval_queue'
                ORDER BY name
                """
            ).fetchall()
            for name, _ in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            connection.execute(
                """
                UPDATE approval_queue
                SET executor_profile_id = ?
                WHERE approval_id = ?
                """,
                (CONTROL_ID, receipt.approval.approval_id),
            )
            for _, sql in triggers:
                connection.execute(str(sql))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_proposal_event_tampering_is_detected(self) -> None:
        self.submit()
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                """
                SELECT event_json FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, PROPOSAL_ID),
            ).fetchone()
            assert row is not None
            raw = json.loads(str(row[0]))
            raw["payload"]["target"] = "synthetic://phase10/tampered"
            connection.execute(
                """
                UPDATE mission_events
                SET event_json = ?
                WHERE mission_id = ? AND event_id = ?
                """,
                (canonical_json(raw), MISSION_ID, PROPOSAL_ID),
            )
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_authenticated_submission_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "sunderkey"
            / "authenticated_submissions.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden_imports = {
            "anthropic",
            "http",
            "openai",
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
        forbidden_attributes = {
            "Popen",
            "run",
            "system",
        }
        imported: set[str] = set()
        called: set[str] = set()
        attributes: set[str] = set()
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
            elif isinstance(node, ast.Attribute):
                attributes.add(node.attr)
        self.assertFalse(imported & forbidden_imports)
        self.assertFalse(called & forbidden_calls)
        self.assertFalse(attributes & forbidden_attributes)


if __name__ == "__main__":
    unittest.main()

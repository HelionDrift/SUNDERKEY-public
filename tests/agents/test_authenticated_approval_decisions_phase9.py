"""Focused tests for authenticated Phase 9 approval decisions."""

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
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from sunderkey.approvals import (
    ApprovalService,
    ApprovalState,
)
from sunderkey.authenticated_approval_revocations import (
    AuthenticatedApprovalRevocationService,
)
from sunderkey.authenticated_approvals import (
    AuthenticatedApprovalDecisionReceipt,
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
    APPROVAL_APPROVE_EFFECT_KIND,
    APPROVAL_DENY_EFFECT_KIND,
    MissionStore,
    canonical_json,
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

MISSION_ID = "MISSION-PHASE9-APPROVAL-DECISIONS"
PROPOSAL_ID = "EVT-PHASE9-PROPOSAL"
POLICY_VERSION = 7
EVENT_GRANT_ID = "SGR-90000000000000000000000000000001"
CONTROL_GRANT_ID = "SGR-90000000000000000000000000000002"
EVENT_ASSERTION_ID = "PAS-90000000000000000000000000000001"
APPROVE_ASSERTION_ID = "PAS-90000000000000000000000000000002"
DENY_ASSERTION_ID = "PAS-90000000000000000000000000000003"
OTHER_ASSERTION_ID = "PAS-90000000000000000000000000000004"
CONCURRENT_APPROVE_ID = "PAS-90000000000000000000000000000005"
CONCURRENT_DENY_ID = "PAS-90000000000000000000000000000006"
SUBMIT_ASSERTION_ID = "PAS-90000000000000000000000000000007"
OTHER_SUBMIT_ASSERTION_ID = "PAS-90000000000000000000000000000008"
REVOKE_ASSERTION_ID = "PAS-90000000000000000000000000000009"
SIMULATION_ASSERTION_ID = "PAS-9000000000000000000000000000000A"
REVOCATION_ID = "SRV-90000000000000000000000000000001"
REVOCATION_KEY_ID = "SCOPE-REVOCATION-PHASE9"
REVOCATION_ISSUER = "scope-revocation-authority"
APPROVE_KEY = "phase9-approve"
DENY_KEY = "phase9-deny"
APPROVE_ARGUMENTS = {
    "authority": "range-control",
    "constraints": ("Simulation only", "No external actions"),
    "authorization_expires_at": "2026-07-30T11:00:00Z",
    "idempotency_key": APPROVE_KEY,
    "expected_version": 1,
}
DENY_ARGUMENTS = {
    "reason_code": "scope_mismatch",
    "reason": "The proposal does not match the reviewed scope",
    "risk": "Approval could cross the authorized boundary",
    "decision_owner": "range-control",
    "idempotency_key": DENY_KEY,
    "expected_version": 1,
}
REVOKE_ARGUMENTS = {
    "reason_code": "authorization_withdrawn",
    "reason": "Control withdrew the simulation authorization",
    "risk": "The authorization is no longer current",
    "decision_owner": "range-control",
    "idempotency_key": "phase9-revoke",
    "expected_version": 2,
}


class AuthenticatedApprovalDecisionPhase9Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authenticated-approvals.sqlite3"
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

        operations = sorted(
            [
                PrincipalOperation.EVENT_APPEND.value,
                PrincipalOperation.APPROVAL_SUBMIT.value,
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.APPROVAL_DENY.value,
                PrincipalOperation.APPROVAL_REVOKE.value,
                PrincipalOperation.SIMULATION_RUN.value,
            ]
        )
        self.event_grant = self.make_grant(
            EVENT_GRANT_ID,
            SPECIALIST_ID,
            operations,
        )
        self.control_grant = self.make_grant(
            CONTROL_GRANT_ID,
            CONTROL_ID,
            operations,
        )
        acceptance = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        acceptance.accept(self.event_grant)
        acceptance.accept(self.control_grant)

        proposal = self.proposal()
        event_assertion = self.factory.assertion(
            grant=self.event_grant,
            assertion_id=EVENT_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.event_grant.grant_id,
            subject=self.event_grant.subject,
            profile_id=self.event_grant.profile_id,
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
                    "expected_revision": 0,
                    "mission_id": MISSION_ID,
                    "principal_profile_id": SPECIALIST_ID,
                },
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
            event_assertion,
            MISSION_ID,
            (proposal,),
            expected_revision=0,
        )

        self.approvals = ApprovalService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        self.submissions = AuthenticatedApprovalSubmissionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        pending = self.authenticated_submit(
            mission_id=MISSION_ID,
            proposal_id=PROPOSAL_ID,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-07-30T10:30:00Z",
            idempotency_key="phase9-submit",
            assertion_id=SUBMIT_ASSERTION_ID,
        )
        self.approval_id = pending.approval.approval_id
        self.service = AuthenticatedApprovalDecisionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def make_policy(
        self,
        policy_version: int,
    ) -> PrincipalTrustPolicy:
        operations = sorted(
            [
                PrincipalOperation.EVENT_APPEND.value,
                PrincipalOperation.APPROVAL_SUBMIT.value,
                PrincipalOperation.APPROVAL_APPROVE.value,
                PrincipalOperation.APPROVAL_DENY.value,
                PrincipalOperation.APPROVAL_REVOKE.value,
                PrincipalOperation.SIMULATION_RUN.value,
            ]
        )
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
    def proposal(
        event_id: str = PROPOSAL_ID,
    ) -> MissionEvent:
        return MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": MISSION_ID,
                "event_type": "proposal",
                "actor_profile_id": SPECIALIST_ID,
                "timestamp": "2026-07-30T10:05:00Z",
                "payload": {
                    "target": (
                        "synthetic://phase9/"
                        f"{event_id.lower()}"
                    ),
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

    def intent_hash(
        self,
        operation: PrincipalOperation,
        arguments: dict[str, object],
        *,
        profile_id: str = CONTROL_ID,
    ) -> str:
        if operation is PrincipalOperation.APPROVAL_APPROVE:
            intent = {
                "approval_id": self.approval_id,
                "authority": arguments["authority"],
                "authorization_expires_at": (
                    arguments["authorization_expires_at"]
                ),
                "constraints": list(arguments["constraints"]),
                "expected_version": arguments["expected_version"],
                "idempotency_key_sha256": sha256_text(
                    str(arguments["idempotency_key"])
                ),
                "principal_profile_id": profile_id,
            }
        else:
            intent = {
                "approval_id": self.approval_id,
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
        return compute_operation_intent_hash(operation, intent)

    def authenticated_submit(
        self,
        *,
        mission_id: str,
        proposal_id: str,
        executor_profile_id: str,
        review_expires_at: str,
        idempotency_key: str,
        assertion_id: str,
    ):
        intent = {
            "executor_profile_id": executor_profile_id,
            "idempotency_key_sha256": sha256_text(idempotency_key),
            "mission_id": mission_id,
            "principal_profile_id": SPECIALIST_ID,
            "proposal_id": proposal_id,
            "review_expires_at": review_expires_at,
        }
        assertion = self.factory.assertion(
            grant=self.event_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.event_grant.grant_id,
            subject=self.event_grant.subject,
            profile_id=SPECIALIST_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=mission_id,
            operation=PrincipalOperation.APPROVAL_SUBMIT,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_SUBMIT,
                intent,
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        return self.submissions.submit(
            assertion,
            mission_id=mission_id,
            proposal_id=proposal_id,
            executor_profile_id=executor_profile_id,
            review_expires_at=review_expires_at,
            idempotency_key=idempotency_key,
        )

    def assertion(
        self,
        operation: PrincipalOperation,
        arguments: dict[str, object],
        *,
        assertion_id: str | None = None,
        grant: ScopeGrant | None = None,
        profile_id: str = CONTROL_ID,
        mission_id: str = MISSION_ID,
        issued_at: str = "2026-07-30T10:05:00Z",
        not_before: str = "2026-07-30T10:05:00Z",
        expires_at: str = "2026-07-30T10:09:00Z",
    ) -> PrincipalAssertion:
        bound_grant = grant or self.control_grant
        default_id = (
            APPROVE_ASSERTION_ID
            if operation is PrincipalOperation.APPROVAL_APPROVE
            else DENY_ASSERTION_ID
        )
        return self.factory.assertion(
            grant=bound_grant,
            assertion_id=assertion_id or default_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=bound_grant.grant_id,
            subject=bound_grant.subject,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=mission_id,
            operation=operation,
            operation_intent_sha256=self.intent_hash(
                operation,
                arguments,
                profile_id=profile_id,
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )

    def approve(
        self,
        *,
        arguments: dict[str, object] | None = None,
        assertion: PrincipalAssertion | None = None,
    ) -> AuthenticatedApprovalDecisionReceipt:
        supplied = dict(APPROVE_ARGUMENTS if arguments is None else arguments)
        credential = assertion or self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            supplied,
        )
        return self.service.approve(
            credential,
            self.approval_id,
            authority=str(supplied["authority"]),
            constraints=supplied["constraints"],
            authorization_expires_at=str(
                supplied["authorization_expires_at"]
            ),
            idempotency_key=str(supplied["idempotency_key"]),
            expected_version=supplied["expected_version"],
        )

    def deny(
        self,
        *,
        arguments: dict[str, object] | None = None,
        assertion: PrincipalAssertion | None = None,
    ) -> AuthenticatedApprovalDecisionReceipt:
        supplied = dict(DENY_ARGUMENTS if arguments is None else arguments)
        credential = assertion or self.assertion(
            PrincipalOperation.APPROVAL_DENY,
            supplied,
        )
        return self.service.deny(
            credential,
            self.approval_id,
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
                SELECT status, version, decision_event_id
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
        assert approval is not None
        assert ledger is not None
        return {
            "revision": int(mission[0]),
            "head_hash": str(mission[1]),
            "approval_state": str(approval[0]),
            "approval_version": int(approval[1]),
            "decision_event_id": (
                None if approval[2] is None else str(approval[2])
            ),
            "events": int(events),
            "uses": int(uses),
            "effects": int(effects),
            "ledger_uses": int(ledger[0]),
            "ledger_effects": int(ledger[1]),
        }

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
                self.revocation_private.sign(unsigned.signing_bytes())
            ),
        )

    def additional_pending_approval(
        self,
        event_id: str,
        assertion_id: str,
    ):
        proposal = self.proposal(event_id)
        expected_revision = self.store.get_mission(
            self.registry,
            MISSION_ID,
        ).revision
        assertion = self.factory.assertion(
            grant=self.event_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.event_grant.grant_id,
            subject=self.event_grant.subject,
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
        AuthenticatedEventAppendService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).append(
            assertion,
            MISSION_ID,
            (proposal,),
            expected_revision=expected_revision,
        )
        return self.authenticated_submit(
            mission_id=MISSION_ID,
            proposal_id=event_id,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-07-30T10:30:00Z",
            idempotency_key=f"submit-{event_id.lower()}",
            assertion_id=OTHER_SUBMIT_ASSERTION_ID,
        ).approval

    def test_valid_approve_derives_control_actor_and_records_effect(
        self,
    ) -> None:
        receipt = self.approve()

        self.assertEqual(
            receipt.operation,
            PrincipalOperation.APPROVAL_APPROVE,
        )
        self.assertEqual(receipt.principal_profile_id, CONTROL_ID)
        self.assertEqual(
            receipt.approval.decision_actor_profile_id,
            CONTROL_ID,
        )
        self.assertEqual(receipt.approval.state, ApprovalState.APPROVED)
        self.assertEqual(receipt.approval.version, 2)
        self.assertEqual(
            self.state()["decision_event_id"],
            receipt.approval.decision_event_id,
        )
        with closing(sqlite3.connect(self.path)) as connection:
            effect = connection.execute(
                """
                SELECT effect_kind, effect_id
                FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (MISSION_ID, APPROVAL_APPROVE_EFFECT_KIND),
            ).fetchone()
        self.assertEqual(
            effect,
            (
                APPROVAL_APPROVE_EFFECT_KIND,
                receipt.approval.decision_event_id,
            ),
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_valid_deny_derives_control_actor_and_records_effect(
        self,
    ) -> None:
        receipt = self.deny()

        self.assertEqual(
            receipt.operation,
            PrincipalOperation.APPROVAL_DENY,
        )
        self.assertEqual(receipt.principal_profile_id, CONTROL_ID)
        self.assertEqual(
            receipt.approval.decision_actor_profile_id,
            CONTROL_ID,
        )
        self.assertEqual(receipt.approval.state, ApprovalState.DENIED)
        self.assertEqual(receipt.approval.version, 2)
        with closing(sqlite3.connect(self.path)) as connection:
            effect = connection.execute(
                """
                SELECT effect_kind, effect_id
                FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (MISSION_ID, APPROVAL_DENY_EFFECT_KIND),
            ).fetchone()
        self.assertEqual(
            effect,
            (
                APPROVAL_DENY_EFFECT_KIND,
                receipt.approval.decision_event_id,
            ),
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_approve_intent_binds_every_argument_exactly(self) -> None:
        signed = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        changes = {
            "authority": "different-control",
            "constraints": tuple(reversed(APPROVE_ARGUMENTS["constraints"])),
            "authorization_expires_at": "2026-07-30T11:01:00Z",
            "idempotency_key": "different-approve-key",
            "expected_version": 2,
        }

        for field, replacement in changes.items():
            with self.subTest(field=field):
                supplied = dict(APPROVE_ARGUMENTS)
                supplied[field] = replacement
                with self.assertRaises(PrincipalAuthenticationError):
                    self.approve(arguments=supplied, assertion=signed)

        self.assertEqual(self.state()["approval_state"], "pending")

    def test_deny_intent_binds_every_argument_exactly(self) -> None:
        signed = self.assertion(
            PrincipalOperation.APPROVAL_DENY,
            DENY_ARGUMENTS,
        )
        changes = {
            "reason_code": "different_code",
            "reason": "Different reason",
            "risk": "Different risk",
            "decision_owner": "different-control",
            "idempotency_key": "different-deny-key",
            "expected_version": 2,
        }

        for field, replacement in changes.items():
            with self.subTest(field=field):
                supplied = dict(DENY_ARGUMENTS)
                supplied[field] = replacement
                with self.assertRaises(PrincipalAuthenticationError):
                    self.deny(arguments=supplied, assertion=signed)

        self.assertEqual(self.state()["approval_state"], "pending")

    def test_signed_approval_id_cannot_select_another_pending_row(
        self,
    ) -> None:
        other = self.additional_pending_approval(
            "EVT-PHASE9-OTHER-PROPOSAL",
            OTHER_ASSERTION_ID,
        )
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.approve(
                assertion,
                other.approval_id,
                **APPROVE_ARGUMENTS,
            )

        self.assertEqual(
            self.approvals.get(self.approval_id).state,
            ApprovalState.PENDING,
        )
        self.assertEqual(
            self.approvals.get(other.approval_id).state,
            ApprovalState.PENDING,
        )

    def test_wrong_mission_operation_signature_and_profile_are_rejected(
        self,
    ) -> None:
        wrong_mission = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
            assertion_id=OTHER_ASSERTION_ID,
            mission_id="MISSION-PHASE9-OTHER",
        )
        wrong_operation = self.assertion(
            PrincipalOperation.APPROVAL_DENY,
            DENY_ARGUMENTS,
            assertion_id=OTHER_ASSERTION_ID,
        )
        valid = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        wrong_signature = replace(valid, signature=ZERO_SIGNATURE)
        wrong_profile = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
            assertion_id=OTHER_ASSERTION_ID,
            grant=self.event_grant,
            profile_id=SPECIALIST_ID,
        )

        cases = (
            wrong_mission,
            wrong_operation,
            wrong_signature,
            wrong_profile,
        )
        for credential in cases:
            with (
                self.subTest(assertion_id=credential.assertion_id),
                self.assertRaises(
                    (PrincipalAuthenticationError, ApprovalError)
                ),
            ):
                self.approve(assertion=credential)

        self.assertEqual(self.state()["approval_state"], "pending")

    def test_stale_and_expired_pending_approvals_are_rejected(self) -> None:
        stale_arguments = dict(APPROVE_ARGUMENTS)
        stale_arguments["expected_version"] = 2
        with self.assertRaises(ApprovalConflictError):
            self.approve(arguments=stale_arguments)

        self.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        current = dict(APPROVE_ARGUMENTS)
        current["authorization_expires_at"] = (
            "2026-07-30T11:15:00Z"
        )
        current_assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            current,
            assertion_id=OTHER_ASSERTION_ID,
            issued_at="2026-07-30T10:31:00Z",
            not_before="2026-07-30T10:31:00Z",
            expires_at="2026-07-30T10:34:00Z",
        )
        with self.assertRaises(ApprovalExpiredError):
            self.approve(
                arguments=current,
                assertion=current_assertion,
            )

        self.assertEqual(self.state()["approval_state"], "pending")

    def test_approve_rejects_expired_authorization(self) -> None:
        arguments = dict(APPROVE_ARGUMENTS)
        arguments["authorization_expires_at"] = (
            "2026-07-30T10:05:00Z"
        )
        with self.assertRaises(ApprovalExpiredError):
            self.approve(arguments=arguments)
        self.assertEqual(self.state()["approval_state"], "pending")

    def test_direct_approve_and_deny_are_gated_after_policy(self) -> None:
        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval decisions are required",
        ):
            self.approvals.approve(
                self.approval_id,
                principal_profile_id=CONTROL_ID,
                **APPROVE_ARGUMENTS,
            )
        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval decisions are required",
        ):
            self.approvals.deny(
                self.approval_id,
                principal_profile_id=CONTROL_ID,
                **DENY_ARGUMENTS,
            )
        self.assertEqual(self.state()["approval_state"], "pending")

    def test_direct_content_equivalent_retry_is_also_gated(
        self,
    ) -> None:
        self.approve()
        original_state = self.state()

        with self.assertRaisesRegex(
            ApprovalError,
            "Authenticated approval decisions are required",
        ):
            self.approvals.approve(
                self.approval_id,
                principal_profile_id=CONTROL_ID,
                **APPROVE_ARGUMENTS,
            )

        self.assertEqual(self.state(), original_state)

    def test_exact_replay_is_read_only_after_assertion_and_grant_expiry(
        self,
    ) -> None:
        arguments = dict(APPROVE_ARGUMENTS)
        arguments["authorization_expires_at"] = (
            "2026-07-30T11:45:00Z"
        )
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            arguments,
        )
        first = self.approve(arguments=arguments, assertion=assertion)
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 11, 31, tzinfo=UTC)

        replay = self.approve(arguments=arguments, assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_denial_exact_replay_is_read_only_after_credential_expiry(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_DENY,
            DENY_ARGUMENTS,
        )
        first = self.deny(assertion=assertion)
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 11, 31, tzinfo=UTC)

        replay = self.deny(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_exact_replay_is_read_only_after_policy_advancement(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        first = self.approve(assertion=assertion)
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        self.trust.apply_policy(self.make_policy(POLICY_VERSION + 1))

        replay = self.approve(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_exact_replay_is_read_only_after_scope_revocation(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        first = self.approve(assertion=assertion)
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)

        replay = self.approve(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_exact_replay_survives_later_approval_revocation(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        first = self.approve(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        revoke_assertion = self.assertion(
            PrincipalOperation.APPROVAL_REVOKE,
            REVOKE_ARGUMENTS,
            assertion_id=REVOKE_ASSERTION_ID,
        )
        AuthenticatedApprovalRevocationService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).revoke(
            revoke_assertion,
            self.approval_id,
            **REVOKE_ARGUMENTS,
        )
        state_after_revocation = self.state()

        replay = self.approve(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), state_after_revocation)
        self.assertEqual(self.state()["approval_state"], "revoked")
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_survives_later_simulation_consumption(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        first = self.approve(assertion=assertion)
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        idempotency_key = "phase9-simulate"
        simulation_assertion = self.factory.assertion(
            grant=self.event_grant,
            assertion_id=SIMULATION_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.event_grant.grant_id,
            subject=self.event_grant.subject,
            profile_id=SPECIALIST_ID,
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
                    "principal_profile_id": SPECIALIST_ID,
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
            simulation_assertion,
            self.approval_id,
            idempotency_key=idempotency_key,
        )
        state_after_consumption = self.state()

        replay = self.approve(assertion=assertion)

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), state_after_consumption)
        self.assertEqual(self.state()["approval_state"], "consumed")
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_same_request_cannot_bind_a_different_assertion(self) -> None:
        self.approve()
        competing = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.approve(assertion=competing)

        self.assertEqual(self.state()["uses"], 3)

    def test_idempotency_key_cannot_rebind_to_different_content(
        self,
    ) -> None:
        self.approve()
        changed = dict(APPROVE_ARGUMENTS)
        changed["authority"] = "different-control"
        competing = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            changed,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "intent or idempotency key is already bound",
        ):
            self.approve(arguments=changed, assertion=competing)

        self.assertEqual(self.state()["uses"], 3)

    def test_approve_and_deny_concurrency_commits_exactly_one(
        self,
    ) -> None:
        approve_assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
            assertion_id=CONCURRENT_APPROVE_ID,
        )
        deny_assertion = self.assertion(
            PrincipalOperation.APPROVAL_DENY,
            DENY_ARGUMENTS,
            assertion_id=CONCURRENT_DENY_ID,
        )
        barrier = threading.Barrier(2)

        def run(
            operation: PrincipalOperation,
            assertion: PrincipalAssertion,
        ) -> AuthenticatedApprovalDecisionReceipt | Exception:
            service = AuthenticatedApprovalDecisionService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                if operation is PrincipalOperation.APPROVAL_APPROVE:
                    return service.approve(
                        assertion,
                        self.approval_id,
                        **APPROVE_ARGUMENTS,
                    )
                return service.deny(
                    assertion,
                    self.approval_id,
                    **DENY_ARGUMENTS,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda item: run(*item),
                    (
                        (
                            PrincipalOperation.APPROVAL_APPROVE,
                            approve_assertion,
                        ),
                        (
                            PrincipalOperation.APPROVAL_DENY,
                            deny_assertion,
                        ),
                    ),
                )
            )

        receipts = tuple(
            result
            for result in results
            if isinstance(
                result,
                AuthenticatedApprovalDecisionReceipt,
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
        self.assertIn(
            self.state()["approval_state"],
            {"approved", "denied"},
        )
        self.assertEqual(self.state()["events"], 2)
        self.assertEqual(self.state()["uses"], 3)
        self.assertEqual(self.state()["effects"], 3)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_provenance_failure_rolls_back_the_full_decision(
        self,
    ) -> None:
        assertion = self.assertion(
            PrincipalOperation.APPROVAL_APPROVE,
            APPROVE_ARGUMENTS,
        )
        original_state = self.state()

        with (
            mock.patch.object(
                self.service,
                "_approval_decision_effect",
                side_effect=StoreIntegrityError(
                    "injected approval provenance failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "injected approval provenance failure",
            ),
        ):
            self.approve(assertion=assertion)

        self.assertEqual(self.state(), original_state)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_effect_tampering_is_detected(self) -> None:
        self.approve()
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
                (MISSION_ID, APPROVAL_APPROVE_EFFECT_KIND),
            ).fetchone()
            assert row is not None
            raw = json.loads(str(row[0]))
            raw["payload"]["expected_approval_version"] = 2
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?
                WHERE mission_id = ? AND effect_kind = ?
                """,
                (
                    canonical_json(raw),
                    MISSION_ID,
                    APPROVAL_APPROVE_EFFECT_KIND,
                ),
            )
            connection.execute(str(trigger[0]))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_approval_row_tampering_is_detected(self) -> None:
        self.approve()
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
                SET decision_reason = 'Tampered reason'
                WHERE approval_id = ?
                """,
                (self.approval_id,),
            )
            for _, sql in triggers:
                connection.execute(str(sql))
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_generated_decision_event_tampering_is_detected(self) -> None:
        receipt = self.approve()
        event_id = receipt.approval.decision_event_id
        assert event_id is not None
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                """
                SELECT event_json FROM mission_events
                WHERE mission_id = ? AND event_id = ?
                """,
                (MISSION_ID, event_id),
            ).fetchone()
            assert row is not None
            raw = json.loads(str(row[0]))
            raw["payload"]["authority"] = "tampered-control"
            connection.execute(
                """
                UPDATE mission_events
                SET event_json = ?
                WHERE mission_id = ? AND event_id = ?
                """,
                (canonical_json(raw), MISSION_ID, event_id),
            )
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_authenticated_approval_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "sunderkey"
            / "authenticated_approvals.py"
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

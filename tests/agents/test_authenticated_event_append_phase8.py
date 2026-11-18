"""Focused tests for the authenticated Phase 8 event append boundary."""

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

from sunderkey.authenticated_events import (
    AuthenticatedEventAppendReceipt,
    AuthenticatedEventAppendService,
    compute_event_batch_hash,
)
from sunderkey.authenticated_submissions import (
    AuthenticatedApprovalSubmissionService,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
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
    EVENT_APPEND_EFFECT_KIND,
    MissionStore,
    canonical_json,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    OTHER_ASSERTION_ID,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    SUBJECT,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, SPECIALIST_ID, mission_data

MISSION_ID = "MISSION-PHASE8-EVENT-APPEND"
POLICY_VERSION = 7
REVOCATION_KEY_ID = "REVOCATION-PHASE8"
REVOCATION_ISSUER = "scope-revocation-authority"
REVOCATION_ID = "SRV-88888888888888888888888888888888"
CONCURRENT_ASSERTION_ID = "PAS-88888888888888888888888888888888"
SUBMIT_ASSERTION_ID = "PAS-88888888888888888888888888888889"


class AuthenticatedEventAppendPhase8Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authenticated-events.sqlite3"
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
        self.policy = self.make_policy()
        self.trust.apply_policy(self.policy)

        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        self.grant = self.factory.grant(
            profile_id=PROFILE_ID,
            subject=SUBJECT,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored_mission.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[
                PrincipalOperation.APPROVAL_SUBMIT.value,
                PrincipalOperation.EVENT_APPEND.value,
            ],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )
        ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.grant)
        self.service = AuthenticatedEventAppendService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def make_policy(self) -> PrincipalTrustPolicy:
        raw = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=[PROFILE_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[
                PrincipalOperation.APPROVAL_SUBMIT.value,
                PrincipalOperation.EVENT_APPEND.value
            ],
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
                "allowed_profiles": [PROFILE_ID],
                "allowed_subjects": [SUBJECT],
                "allowed_operations": [
                    PrincipalOperation.APPROVAL_SUBMIT.value,
                    PrincipalOperation.EVENT_APPEND.value
                ],
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

    def event(
        self,
        event_id: str,
        *,
        minute: int = 5,
        actor_profile_id: str = PROFILE_ID,
        target: str | None = None,
    ) -> MissionEvent:
        return MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": MISSION_ID,
                "event_type": "observation",
                "actor_profile_id": actor_profile_id,
                "timestamp": f"2026-07-30T10:{minute:02d}:00Z",
                "payload": {
                    "target": (
                        target
                        or f"synthetic://phase8/{event_id.lower()}"
                    ),
                    "evidence_refs": [
                        f"evidence://phase8/{event_id.lower()}"
                    ],
                    "confidence": "high",
                    "sensitivity": "synthetic",
                },
                "references": [],
            }
        )

    def proposal(self, event_id: str) -> MissionEvent:
        return MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": event_id,
                "mission_id": MISSION_ID,
                "event_type": "proposal",
                "actor_profile_id": PROFILE_ID,
                "timestamp": "2026-07-30T10:05:00Z",
                "payload": {
                    "target": "synthetic://phase8/proposal",
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

    @staticmethod
    def intent_hash(
        events: tuple[MissionEvent, ...],
        *,
        expected_revision: int,
        profile_id: str = PROFILE_ID,
    ) -> str:
        return compute_operation_intent_hash(
            PrincipalOperation.EVENT_APPEND,
            {
                "event_batch_sha256": compute_event_batch_hash(events),
                "expected_revision": expected_revision,
                "mission_id": MISSION_ID,
                "principal_profile_id": profile_id,
            },
        )

    def assertion(
        self,
        events: tuple[MissionEvent, ...],
        *,
        expected_revision: int,
        assertion_id: str = ASSERTION_ID,
        grant: ScopeGrant | None = None,
        issued_at: str = "2026-07-30T10:05:00Z",
        not_before: str = "2026-07-30T10:05:00Z",
        expires_at: str = "2026-07-30T10:09:00Z",
    ) -> PrincipalAssertion:
        bound_grant = grant or self.grant
        return self.factory.assertion(
            grant=bound_grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=bound_grant.grant_id,
            subject=bound_grant.subject,
            profile_id=bound_grant.profile_id,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.EVENT_APPEND,
            operation_intent_sha256=self.intent_hash(
                events,
                expected_revision=expected_revision,
                profile_id=bound_grant.profile_id,
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )

    def append(
        self,
        events: tuple[MissionEvent, ...],
        *,
        expected_revision: int = 0,
        assertion_id: str = ASSERTION_ID,
    ) -> AuthenticatedEventAppendReceipt:
        assertion = self.assertion(
            events,
            expected_revision=expected_revision,
            assertion_id=assertion_id,
        )
        return self.service.append(
            assertion,
            MISSION_ID,
            events,
            expected_revision=expected_revision,
        )

    def state(self) -> dict[str, int | str]:
        with closing(sqlite3.connect(self.path)) as connection:
            mission = connection.execute(
                """
                SELECT revision, head_hash
                FROM missions
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
            event_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM mission_events
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            use_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_uses
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            effect_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_effects
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
        assert mission is not None
        assert ledger is not None
        return {
            "revision": int(mission[0]),
            "head_hash": str(mission[1]),
            "events": int(event_count),
            "uses": int(use_count),
            "effects": int(effect_count),
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
            "scope_grant_issuer": self.grant.issuer,
            "scope_grant_id": self.grant.grant_id,
            "scope_grant_sha256": self.grant.content_sha256,
            "scope_grant_subject": self.grant.subject,
            "scope_grant_profile_id": self.grant.profile_id,
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

    def test_valid_single_event_append_records_one_effect(self) -> None:
        event = self.event("EVT-AUTH-SINGLE")

        receipt = self.append((event,))

        self.assertEqual(
            [item.event_id for item in receipt.receipts],
            [event.event_id],
        )
        self.assertEqual(receipt.receipts[0].sequence, 1)
        self.assertEqual(receipt.receipts[0].revision, 1)
        self.assertFalse(receipt.receipts[0].idempotent)
        self.assertEqual(
            receipt.event_batch_sha256,
            compute_event_batch_hash((event,)),
        )
        self.assertEqual(
            self.state(),
            {
                "revision": 1,
                "head_hash": receipt.receipts[0].entry_hash,
                "events": 1,
                "uses": 1,
                "effects": 1,
                "ledger_uses": 1,
                "ledger_effects": 1,
            },
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_valid_ordered_batch_preserves_event_and_effect_order(
        self,
    ) -> None:
        first = self.event("EVT-AUTH-BATCH-A", minute=5)
        second = self.event("EVT-AUTH-BATCH-B", minute=5)

        receipt = self.append((first, second))

        self.assertEqual(
            [item.event_id for item in receipt.receipts],
            [first.event_id, second.event_id],
        )
        self.assertEqual(
            [item.sequence for item in receipt.receipts],
            [1, 2],
        )
        self.assertEqual(
            [item.revision for item in receipt.receipts],
            [2, 2],
        )
        stored = self.store.list_events(self.registry, MISSION_ID)
        self.assertEqual(
            [item.event.event_id for item in stored],
            [first.event_id, second.event_id],
        )
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute(
                """
                SELECT effect_index, effect_id
                FROM principal_assertion_effects
                WHERE mission_id = ?
                ORDER BY effect_index
                """,
                (MISSION_ID,),
            ).fetchall()
        self.assertEqual(
            rows,
            [(1, first.event_id), (2, second.event_id)],
        )

    def test_authenticated_proposal_remains_provenance_protected_after_submit(
        self,
    ) -> None:
        proposal = self.proposal("EVT-AUTH-PROPOSAL")
        self.append((proposal,))

        idempotency_key = "phase8-proposal-submit"
        assertion = self.factory.assertion(
            grant=self.grant,
            assertion_id=SUBMIT_ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=self.grant.subject,
            profile_id=PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.APPROVAL_SUBMIT,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_SUBMIT,
                {
                    "executor_profile_id": SPECIALIST_ID,
                    "idempotency_key_sha256": sha256_text(
                        idempotency_key
                    ),
                    "mission_id": MISSION_ID,
                    "principal_profile_id": PROFILE_ID,
                    "proposal_id": proposal.event_id,
                    "review_expires_at": "2026-07-30T10:30:00Z",
                },
            ),
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )
        record = AuthenticatedApprovalSubmissionService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).submit(
            assertion,
            mission_id=MISSION_ID,
            proposal_id=proposal.event_id,
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-07-30T10:30:00Z",
            idempotency_key=idempotency_key,
        ).approval

        self.assertEqual(record.proposal_id, proposal.event_id)
        with closing(sqlite3.connect(self.path)) as connection:
            effect = connection.execute(
                """
                SELECT effect_kind, effect_id
                FROM principal_assertion_effects
                WHERE mission_id = ? AND effect_id = ?
                """,
                (MISSION_ID, proposal.event_id),
            ).fetchone()
        self.assertEqual(
            effect,
            (EVENT_APPEND_EFFECT_KIND, proposal.event_id),
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_exact_replay_is_read_only_after_scope_expiry(self) -> None:
        event = self.event("EVT-AUTH-REPLAY")
        assertion = self.assertion((event,), expected_revision=0)
        first = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)

        replay = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_exact_replay_is_read_only_after_policy_advancement(
        self,
    ) -> None:
        event = self.event("EVT-AUTH-REPLAY-POLICY")
        assertion = self.assertion((event,), expected_revision=0)
        first = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        replacement = self.factory.policy(
            policy_version=POLICY_VERSION + 1,
            store_id=self.store_id,
            allowed_profiles=[PROFILE_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[
                PrincipalOperation.EVENT_APPEND.value
            ],
        )
        self.trust.apply_policy(replacement)

        replay = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_exact_replay_keeps_original_receipt_after_later_append(
        self,
    ) -> None:
        first_event = self.event("EVT-AUTH-REPLAY-FIRST")
        first_assertion = self.assertion(
            (first_event,),
            expected_revision=0,
        )
        first = self.service.append(
            first_assertion,
            MISSION_ID,
            (first_event,),
            expected_revision=0,
        )
        second_event = self.event("EVT-AUTH-REPLAY-SECOND")
        second_assertion = self.assertion(
            (second_event,),
            expected_revision=1,
            assertion_id=OTHER_ASSERTION_ID,
        )
        self.service.append(
            second_assertion,
            MISSION_ID,
            (second_event,),
            expected_revision=1,
        )
        state_after_second = self.state()

        replay = self.service.append(
            first_assertion,
            MISSION_ID,
            (first_event,),
            expected_revision=0,
        )

        self.assertEqual(replay, first)
        self.assertEqual(replay.receipts[0].revision, 1)
        self.assertEqual(self.state(), state_after_second)

    def test_exact_replay_is_read_only_after_scope_revocation(
        self,
    ) -> None:
        event = self.event("EVT-AUTH-REPLAY-REVOCATION")
        assertion = self.assertion((event,), expected_revision=0)
        first = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )
        original_state = self.state()
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)

        replay = self.service.append(
            assertion,
            MISSION_ID,
            (event,),
            expected_revision=0,
        )

        self.assertEqual(replay, first)
        self.assertEqual(self.state(), original_state)

    def test_event_actor_must_match_authenticated_profile(self) -> None:
        event = self.event(
            "EVT-AUTH-WRONG-ACTOR",
            actor_profile_id=SPECIALIST_ID,
        )
        assertion = self.assertion((event,), expected_revision=0)

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "actor must match",
        ):
            self.service.append(
                assertion,
                MISSION_ID,
                (event,),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_signed_batch_membership_mismatch_is_rejected(self) -> None:
        signed = self.event("EVT-AUTH-SIGNED")
        supplied = self.event("EVT-AUTH-SUPPLIED")
        assertion = self.assertion((signed,), expected_revision=0)

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.append(
                assertion,
                MISSION_ID,
                (supplied,),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_signed_batch_order_mismatch_is_rejected(self) -> None:
        first = self.event("EVT-AUTH-ORDER-A", minute=5)
        second = self.event("EVT-AUTH-ORDER-B", minute=5)
        assertion = self.assertion(
            (first, second),
            expected_revision=0,
        )

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.append(
                assertion,
                MISSION_ID,
                (second, first),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_signed_expected_revision_mismatch_is_rejected(self) -> None:
        event = self.event("EVT-AUTH-REVISION-INTENT")
        assertion = self.assertion((event,), expected_revision=0)

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.append(
                assertion,
                MISSION_ID,
                (event,),
                expected_revision=1,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_existing_event_id_is_not_an_idempotent_new_request(
        self,
    ) -> None:
        event = self.event("EVT-AUTH-EXISTING")
        self.append((event,))
        second_assertion = self.assertion(
            (event,),
            expected_revision=1,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "cannot reuse event ID",
        ):
            self.service.append(
                second_assertion,
                MISSION_ID,
                (event,),
                expected_revision=1,
            )

        self.assertEqual(self.state()["events"], 1)
        self.assertEqual(self.state()["uses"], 1)

    def test_same_signed_request_cannot_bind_a_second_assertion(
        self,
    ) -> None:
        event = self.event("EVT-AUTH-DOMAIN-IDENTITY")
        self.append((event,))
        competing = self.assertion(
            (event,),
            expected_revision=0,
            assertion_id=OTHER_ASSERTION_ID,
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "intent is already bound",
        ):
            self.service.append(
                competing,
                MISSION_ID,
                (event,),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 1)
        self.assertEqual(self.state()["uses"], 1)

    def test_expected_revision_must_be_a_concrete_integer(self) -> None:
        event = self.event("EVT-AUTH-REVISION-TYPE")
        assertion = self.assertion((event,), expected_revision=0)

        for invalid in (None, True, -1):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                StoreError,
                "expected_revision",
            ):
                self.service.append(
                    assertion,
                    MISSION_ID,
                    (event,),
                    expected_revision=invalid,  # type: ignore[arg-type]
                )

    def test_expired_scope_rejects_a_new_request(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 31, tzinfo=UTC)
        event = self.event("EVT-AUTH-EXPIRED", minute=31)
        assertion = self.assertion(
            (event,),
            expected_revision=0,
            issued_at="2026-07-30T10:31:00Z",
            not_before="2026-07-30T10:31:00Z",
            expires_at="2026-07-30T10:34:00Z",
        )

        with self.assertRaises(PrincipalAuthenticationError):
            self.service.append(
                assertion,
                MISSION_ID,
                (event,),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_revoked_scope_rejects_a_new_request(self) -> None:
        self.now = datetime(2026, 7, 30, 10, 6, tzinfo=UTC)
        ScopeGrantRevocationAcceptanceService(
            self.store,
            self.registry,
        ).accept(self.revocation())
        self.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        event = self.event("EVT-AUTH-REVOKED", minute=7)
        assertion = self.assertion(
            (event,),
            expected_revision=0,
            issued_at="2026-07-30T10:07:00Z",
            not_before="2026-07-30T10:07:00Z",
            expires_at="2026-07-30T10:09:00Z",
        )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "revoked",
        ):
            self.service.append(
                assertion,
                MISSION_ID,
                (event,),
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_direct_append_is_gated_after_policy_enrollment(self) -> None:
        event = self.event("EVT-DIRECT-GATED")

        with self.assertRaisesRegex(
            StoreConflictError,
            "Direct event append is disabled",
        ):
            self.store.append_event(
                self.registry,
                event,
                expected_revision=0,
            )

        self.assertEqual(self.state()["events"], 0)

    def test_effect_tampering_is_detected(self) -> None:
        self.append((self.event("EVT-AUTH-TAMPER-EFFECT"),))
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_row = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_effect_immutable'
                """
            ).fetchone()
            self.assertIsNotNone(trigger_row)
            trigger_sql = str(trigger_row[0])
            connection.execute(
                "DROP TRIGGER principal_assertion_effect_immutable"
            )
            effect = connection.execute(
                """
                SELECT effect_json
                FROM principal_assertion_effects
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert effect is not None
            raw_effect = json.loads(str(effect[0]))
            raw_effect["payload"]["event_batch_index"] = 2
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?
                WHERE mission_id = ?
                """,
                (canonical_json(raw_effect), MISSION_ID),
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_orphan_post_baseline_event_is_detected_by_reconciliation(
        self,
    ) -> None:
        event = self.event("EVT-AUTH-ORPHAN")
        with self.store._write_connection() as connection:
            self.store._append_events_in_connection(
                connection,
                self.registry,
                MISSION_ID,
                (event,),
                expected_revision=0,
            )

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_provenance_failure_rolls_back_the_full_transaction(
        self,
    ) -> None:
        first = self.event("EVT-AUTH-ROLLBACK-A", minute=5)
        second = self.event("EVT-AUTH-ROLLBACK-B", minute=5)
        assertion = self.assertion(
            (first, second),
            expected_revision=0,
        )
        original_state = self.state()

        with (
            mock.patch.object(
                self.service,
                "_event_effects",
                side_effect=StoreIntegrityError(
                    "injected provenance failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "injected provenance failure",
            ),
        ):
            self.service.append(
                assertion,
                MISSION_ID,
                (first, second),
                expected_revision=0,
            )

        self.assertEqual(self.state(), original_state)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_concurrent_competing_appends_commit_exactly_one(
        self,
    ) -> None:
        first = self.event("EVT-AUTH-CONCURRENT-A")
        second = self.event("EVT-AUTH-CONCURRENT-B")
        assertions = (
            self.assertion(
                (first,),
                expected_revision=0,
                assertion_id=ASSERTION_ID,
            ),
            self.assertion(
                (second,),
                expected_revision=0,
                assertion_id=CONCURRENT_ASSERTION_ID,
            ),
        )
        barrier = threading.Barrier(2)

        def run(
            assertion: PrincipalAssertion,
            event: MissionEvent,
        ) -> AuthenticatedEventAppendReceipt | Exception:
            service = AuthenticatedEventAppendService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            )
            barrier.wait()
            try:
                return service.append(
                    assertion,
                    MISSION_ID,
                    (event,),
                    expected_revision=0,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda arguments: run(*arguments),
                    zip(assertions, (first, second), strict=True),
                )
            )

        receipts = tuple(
            result
            for result in results
            if isinstance(result, AuthenticatedEventAppendReceipt)
        )
        conflicts = tuple(
            result
            for result in results
            if isinstance(result, StoreConflictError)
        )
        self.assertEqual(len(receipts), 1, results)
        self.assertEqual(len(conflicts), 1, results)
        self.assertEqual(self.state()["events"], 1)
        self.assertEqual(self.state()["uses"], 1)
        self.assertEqual(self.state()["effects"], 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_authenticated_event_module_has_no_execution_surface(
        self,
    ) -> None:
        source_path = (
            Path(__file__).resolve().parents[2]
            / "src"
            / "sunderkey"
            / "authenticated_events.py"
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

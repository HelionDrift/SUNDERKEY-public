"""Tests for the authenticated Phase 5 mission-stop boundary."""

from __future__ import annotations

import hashlib
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

from sunderkey.authenticated import (
    AuthenticatedMissionControlService,
    AuthenticatedMissionStopReceipt,
)
from sunderkey.errors import (
    MissionControlError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    OTHER_ASSERTION_ID,
    OTHER_GRANT_ID,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, SPECIALIST_ID, mission_data

MISSION_ID = "MISSION-PHASE5-STOP"
POLICY_VERSION = 7
SECOND_GRANT_ID = "SGR-11111111111111111111111111111111"
THIRD_GRANT_ID = "SGR-22222222222222222222222222222222"
THIRD_ASSERTION_ID = "PAS-11111111111111111111111111111111"

STOP_ARGUMENTS = {
    "reason_code": "operator_request",
    "reason": "Operator requested an authenticated stop",
    "risk": "Continued activity is outside the current decision",
    "decision_owner": "range-control",
    "idempotency_key": "phase5-authenticated-stop",
    "expected_version": 1,
}


class AuthenticatedMissionStopPhase5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authenticated-stop.sqlite3"
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
        self.trust = TrustProvisioningService(self.store)
        status = self.trust.status()
        self.store_id = status.store_id
        root_public_key = public_bytes(self.factory.root_private)
        self.trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=[PROFILE_ID, SPECIALIST_ID],
            allowed_operations=[
                PrincipalOperation.MISSION_STOP.value
            ],
        )
        self.trust.apply_policy(self.policy)

        self.scope_service = ScopeGrantAcceptanceService(
            self.store,
            self.registry,
        )
        self.grant = self.make_grant()
        self.scope_service.accept(self.grant)
        self.service = AuthenticatedMissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )

    def make_grant(
        self,
        *,
        grant_id: str | None = None,
        profile_id: str = PROFILE_ID,
        issued_at: str = "2026-07-30T10:05:00Z",
        not_before: str = "2026-07-30T10:05:00Z",
        expires_at: str = "2026-07-30T10:30:00Z",
    ) -> ScopeGrant:
        constraints_hash = sha256_text(
            canonical_json(self.mission.to_dict()["constraints"])
        )
        grant = self.factory.grant(
            profile_id=profile_id,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored_mission.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=constraints_hash,
            operations=[PrincipalOperation.MISSION_STOP.value],
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
            policy_version=POLICY_VERSION,
        )
        if grant_id is None or grant_id == grant.grant_id:
            return grant
        unsigned = replace(grant, grant_id=grant_id)
        return replace(
            unsigned,
            signature=b64url(
                self.factory.scope_private.sign(
                    unsigned.signing_bytes()
                )
            ),
        )

    def stop_intent_hash(
        self,
        *,
        profile_id: str = PROFILE_ID,
        reason_code: str = STOP_ARGUMENTS["reason_code"],
        reason: str = STOP_ARGUMENTS["reason"],
        risk: str = STOP_ARGUMENTS["risk"],
        decision_owner: str = STOP_ARGUMENTS["decision_owner"],
        idempotency_key: str = STOP_ARGUMENTS["idempotency_key"],
        expected_version: int = STOP_ARGUMENTS["expected_version"],
    ) -> str:
        return compute_operation_intent_hash(
            PrincipalOperation.MISSION_STOP,
            {
                "decision_owner": decision_owner,
                "expected_version": expected_version,
                "idempotency_key_sha256": sha256_text(
                    idempotency_key
                ),
                "mission_id": MISSION_ID,
                "principal_profile_id": profile_id,
                "reason": reason,
                "reason_code": reason_code,
                "risk": risk,
            },
        )

    def make_assertion(
        self,
        *,
        grant: ScopeGrant | None = None,
        assertion_id: str = ASSERTION_ID,
        profile_id: str | None = None,
        policy_version: int = POLICY_VERSION,
        operation_intent_sha256: str | None = None,
        issued_at: str = "2026-07-30T10:05:00Z",
        not_before: str = "2026-07-30T10:05:00Z",
        expires_at: str = "2026-07-30T10:09:00Z",
    ) -> PrincipalAssertion:
        bound_grant = grant or self.grant
        bound_profile = profile_id or bound_grant.profile_id
        return self.factory.assertion(
            grant=bound_grant,
            assertion_id=assertion_id,
            policy_version=policy_version,
            scope_grant_id=bound_grant.grant_id,
            subject=bound_grant.subject,
            profile_id=bound_profile,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=(
                operation_intent_sha256
                or self.stop_intent_hash(
                    profile_id=bound_profile
                )
            ),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )

    def stop(
        self,
        assertion: PrincipalAssertion,
        **changes: object,
    ) -> AuthenticatedMissionStopReceipt:
        arguments = dict(STOP_ARGUMENTS)
        arguments.update(changes)
        return self.service.stop(
            assertion,
            MISSION_ID,
            **arguments,
        )

    def counts(self) -> dict[str, int | str]:
        with closing(sqlite3.connect(self.path)) as connection:
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
            assert control is not None
            assert ledger is not None
            return {
                "control_state": str(control[0]),
                "control_version": int(control[1]),
                "events": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM mission_events
                        WHERE mission_id = ?
                        """,
                        (MISSION_ID,),
                    ).fetchone()[0]
                ),
                "assertions": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM principal_assertion_uses
                        WHERE mission_id = ?
                        """,
                        (MISSION_ID,),
                    ).fetchone()[0]
                ),
                "effects": int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM principal_assertion_effects
                        WHERE mission_id = ?
                        """,
                        (MISSION_ID,),
                    ).fetchone()[0]
                ),
                "ledger_assertions": int(ledger[0]),
                "ledger_effects": int(ledger[1]),
            }

    def assert_no_stop(self) -> None:
        self.assertEqual(
            self.counts(),
            {
                "control_state": "active",
                "control_version": 1,
                "events": 0,
                "assertions": 0,
                "effects": 0,
                "ledger_assertions": 0,
                "ledger_effects": 0,
            },
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_valid_stop_is_atomic_and_exact_retry_is_read_only(self) -> None:
        assertion = self.make_assertion()
        first = self.stop(assertion)

        self.assertEqual(first.assertion_id, assertion.assertion_id)
        self.assertEqual(first.principal_profile_id, PROFILE_ID)
        self.assertEqual(first.mission_control.state.value, "stopped")
        self.assertEqual(first.mission_control.version, 2)
        self.assertEqual(
            self.counts(),
            {
                "control_state": "stopped",
                "control_version": 2,
                "events": 1,
                "assertions": 1,
                "effects": 1,
                "ledger_assertions": 1,
                "ledger_effects": 1,
            },
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

        replay = self.stop(assertion)

        self.assertEqual(replay.to_dict(), first.to_dict())
        self.assertEqual(
            self.counts(),
            {
                "control_state": "stopped",
                "control_version": 2,
                "events": 1,
                "assertions": 1,
                "effects": 1,
                "ledger_assertions": 1,
                "ledger_effects": 1,
            },
        )

    def test_changed_assertion_replay_is_rejected(self) -> None:
        assertion = self.make_assertion()
        self.stop(assertion)
        changed = self.make_assertion(
            expires_at="2026-07-30T10:08:00Z"
        )

        with self.assertRaisesRegex(
            StoreConflictError,
            "replay has different content",
        ):
            self.stop(changed)

        self.assertEqual(self.counts()["assertions"], 1)
        self.assertEqual(self.counts()["effects"], 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_signature_and_intent_failures_do_not_mutate(self) -> None:
        assertion = self.make_assertion()
        bad_signature = replace(
            assertion,
            signature=b64url(
                self.factory.scope_private.sign(
                    assertion.signing_bytes()
                )
            ),
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signature verification failed",
        ):
            self.stop(bad_signature)
        self.assert_no_stop()

        wrong_intent = self.make_assertion(
            operation_intent_sha256=self.stop_intent_hash(
                reason="A different signed stop reason"
            )
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "operation intent does not match",
        ):
            self.stop(wrong_intent)
        self.assert_no_stop()

    def test_non_control_profile_is_rejected_and_rolled_back(self) -> None:
        specialist_grant = self.make_grant(
            grant_id=OTHER_GRANT_ID,
            profile_id=SPECIALIST_ID,
        )
        self.scope_service.accept(specialist_grant)
        assertion = self.make_assertion(
            grant=specialist_grant,
            assertion_id=OTHER_ASSERTION_ID,
            profile_id=SPECIALIST_ID,
        )

        with self.assertRaisesRegex(
            MissionControlError,
            "Only assigned independent Control",
        ):
            self.stop(assertion)

        self.assert_no_stop()

    def test_policy_and_unaccepted_grant_failures_do_not_mutate(self) -> None:
        wrong_policy = self.make_assertion(
            policy_version=POLICY_VERSION + 1
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "policy version",
        ):
            self.stop(wrong_policy)
        self.assert_no_stop()

        unaccepted_grant = self.make_grant(
            grant_id=SECOND_GRANT_ID,
            expires_at="2026-07-30T10:29:00Z",
        )
        unaccepted_assertion = self.make_assertion(
            grant=unaccepted_grant,
            assertion_id=OTHER_ASSERTION_ID,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "scope grant is not accepted",
        ):
            self.stop(unaccepted_assertion)
        self.assert_no_stop()

    def test_unsigned_revocation_update_is_rejected_without_mutation(
        self,
    ) -> None:
        with (
            self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "legacy scope grant revocation state is frozen",
            ),
            closing(sqlite3.connect(self.path)) as connection,
        ):
            connection.execute(
                """
                UPDATE mission_scope_grants
                SET revoked_at = ?, revocation_reason = ?
                WHERE grant_hash = ?
                """,
                (
                    "2026-07-30T10:05:00Z",
                    "Scope authority withdrew the grant",
                    self.grant.content_sha256,
                ),
            )

        self.assert_no_stop()

    def test_assertion_and_scope_time_failures_do_not_mutate(self) -> None:
        not_active = self.make_assertion(
            not_before="2026-07-30T10:06:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not active yet",
        ):
            self.stop(not_active)
        self.assert_no_stop()

        expired = self.make_assertion(
            issued_at="2026-07-30T10:00:00Z",
            not_before="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T10:05:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "expired",
        ):
            self.stop(expired)
        self.assert_no_stop()

        short_grant = self.make_grant(
            grant_id=THIRD_GRANT_ID,
            expires_at="2026-07-30T10:06:00Z",
        )
        self.scope_service.accept(short_grant)
        stop_at_expiry = self.make_assertion(
            grant=short_grant,
            assertion_id=THIRD_ASSERTION_ID,
            expires_at="2026-07-30T10:10:00Z",
        )
        self.now = datetime(2026, 7, 30, 10, 11, tzinfo=UTC)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "grace period",
        ):
            self.stop(stop_at_expiry)
        self.assert_no_stop()

    def test_concurrent_exact_assertions_converge_to_one_stop(self) -> None:
        assertion = self.make_assertion()
        services = (
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ),
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ),
        )
        barrier = threading.Barrier(2)

        def invoke(
            service: AuthenticatedMissionControlService,
        ) -> AuthenticatedMissionStopReceipt:
            barrier.wait()
            return service.stop(
                assertion,
                MISSION_ID,
                **STOP_ARGUMENTS,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(invoke, service)
                for service in services
            )
            receipts = tuple(
                future.result(timeout=10)
                for future in futures
            )

        self.assertEqual(receipts[0].to_dict(), receipts[1].to_dict())
        self.assertEqual(
            {
                receipt.ledger_entry_sha256
                for receipt in receipts
            },
            {receipts[0].ledger_entry_sha256},
        )
        self.assertEqual(self.counts()["assertions"], 1)
        self.assertEqual(self.counts()["effects"], 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_concurrent_different_assertions_have_one_winner(self) -> None:
        assertions = (
            self.make_assertion(),
            self.make_assertion(
                assertion_id=OTHER_ASSERTION_ID
            ),
        )
        services = (
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ),
            AuthenticatedMissionControlService(
                self.store,
                self.registry,
                clock=lambda: self.now,
            ),
        )
        barrier = threading.Barrier(2)

        def invoke(
            service: AuthenticatedMissionControlService,
            assertion: PrincipalAssertion,
        ) -> AuthenticatedMissionStopReceipt | Exception:
            barrier.wait()
            try:
                return service.stop(
                    assertion,
                    MISSION_ID,
                    **STOP_ARGUMENTS,
                )
            except Exception as exc:
                return exc

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(invoke, service, assertion)
                for service, assertion in zip(
                    services,
                    assertions,
                    strict=True,
                )
            )
            results = tuple(
                future.result(timeout=10)
                for future in futures
            )

        receipts = tuple(
            result
            for result in results
            if isinstance(
                result,
                AuthenticatedMissionStopReceipt,
            )
        )
        conflicts = tuple(
            result
            for result in results
            if isinstance(result, StoreConflictError)
        )
        self.assertEqual(len(receipts), 1)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(self.counts()["assertions"], 1)
        self.assertEqual(self.counts()["effects"], 1)
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_provenance_insert_failure_rolls_back_stop(self) -> None:
        assertion = self.make_assertion()
        with (
            mock.patch.object(
                AuthenticatedMissionControlService,
                "_insert_assertion_use",
                side_effect=sqlite3.OperationalError(
                    "injected provenance failure"
                ),
            ),
            self.assertRaisesRegex(
                StoreError,
                "Could not persist authenticated mission stop",
            ),
        ):
            self.stop(assertion)

        self.assert_no_stop()

    def test_business_tampering_is_detected_by_store_verification(
        self,
    ) -> None:
        self.stop(self.make_assertion())
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                UPDATE mission_controls
                SET stop_risk = ?
                WHERE mission_id = ?
                """,
                ("Tampered risk statement", MISSION_ID),
            )
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_effect_tampering_is_detected_by_store_verification(
        self,
    ) -> None:
        self.stop(self.make_assertion())
        with closing(sqlite3.connect(self.path)) as connection:
            trigger_row = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_effect_immutable'
                """
            ).fetchone()
            self.assertIsNotNone(trigger_row)
            trigger_sql = str(trigger_row[0])
            connection.execute(
                "DROP TRIGGER principal_assertion_effect_immutable"
            )
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = '{}'
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            )
            connection.execute(trigger_sql)
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)


if __name__ == "__main__":
    unittest.main()

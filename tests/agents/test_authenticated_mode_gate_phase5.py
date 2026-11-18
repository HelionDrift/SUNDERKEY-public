"""Tests for the Phase 5 authenticated-mode transition and stop gate."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.errors import (
    MissionControlError,
    StoreConflictError,
    StoreIntegrityError,
)
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest
from sunderkey.mission_control import (
    MissionControlService,
    _mission_stop_command,
)
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import (
    MISSION_CONTROL_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from . import test_authenticated_mission_stop_phase5 as stop_helpers
from .test_identity_phase4 import (
    AUDIENCE,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import (
    REGISTRY_PATH,
    SPECIALIST_ID,
    mission_data,
    remove_schema_v5_objects,
)

MISSION_ID = stop_helpers.MISSION_ID
POLICY_VERSION = stop_helpers.POLICY_VERSION
STOP_ARGUMENTS = stop_helpers.STOP_ARGUMENTS


class AuthenticatedModeGatePhase5Tests(unittest.TestCase):
    make_grant = (
        stop_helpers.AuthenticatedMissionStopPhase5Tests.make_grant
    )
    stop_intent_hash = (
        stop_helpers.AuthenticatedMissionStopPhase5Tests.stop_intent_hash
    )
    make_assertion = (
        stop_helpers.AuthenticatedMissionStopPhase5Tests.make_assertion
    )
    stop = stop_helpers.AuthenticatedMissionStopPhase5Tests.stop
    counts = stop_helpers.AuthenticatedMissionStopPhase5Tests.counts

    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "authenticated-mode.sqlite3"
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

    def pin_root_and_prepare_policy(self) -> None:
        self.trust = TrustProvisioningService(self.store)
        self.store_id = self.trust.status().store_id
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
            allowed_operations=[PrincipalOperation.MISSION_STOP.value],
        )

    def enroll_authenticated_stop(self) -> None:
        self.pin_root_and_prepare_policy()
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

    def local_stop(self) -> None:
        MissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        ).stop(
            MISSION_ID,
            principal_profile_id=PROFILE_ID,
            **STOP_ARGUMENTS,
        )

    def downgrade_to_v2_and_migrate(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v5_objects(connection)
            for table in (
                "mission_scope_grant_revocations",
                "mission_scope_revocation_baselines",
                "principal_assertion_effects",
                "principal_assertion_uses",
                "mission_principal_ledgers",
                "mission_scope_grants",
                "trust_policy_history",
                "store_identity",
            ):
                connection.execute(f"DROP TABLE {table}")
            connection.execute(
                """
                UPDATE store_metadata
                SET value = ?
                WHERE key = 'schema_version'
                """,
                (str(MISSION_CONTROL_SCHEMA_VERSION),),
            )
            connection.execute(
                f"PRAGMA user_version = {MISSION_CONTROL_SCHEMA_VERSION}"
            )
            connection.commit()
        backup = self.directory / "before-authenticated-mode.sqlite3"
        self.store.migrate(self.registry, backup)

    def test_pre_policy_local_stop_blocks_initial_policy_atomically(self) -> None:
        self.pin_root_and_prepare_policy()
        self.local_stop()
        before = self.counts()

        with self.assertRaisesRegex(
            StoreConflictError,
            "trusted-local mission stop",
        ):
            self.trust.apply_policy(self.policy)

        self.assertEqual(self.counts(), before)
        status = self.trust.status()
        self.assertTrue(status.root_pinned)
        self.assertFalse(status.policy_applied)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM trust_policy_history"
                ).fetchone()[0],
                0,
            )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_enrollment_gates_direct_stop_before_write_and_replay(self) -> None:
        self.enroll_authenticated_stop()
        local = MissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        before = self.counts()
        with self.assertRaisesRegex(
            MissionControlError,
            "Authenticated mission stop is required",
        ):
            local.stop(
                MISSION_ID,
                principal_profile_id=PROFILE_ID,
                **STOP_ARGUMENTS,
            )
        self.assertEqual(self.counts(), before)

        assertion = self.make_assertion()
        receipt = self.stop(assertion)
        committed = self.counts()
        with self.assertRaisesRegex(
            MissionControlError,
            "Authenticated mission stop is required",
        ):
            local.stop(
                MISSION_ID,
                principal_profile_id=PROFILE_ID,
                **STOP_ARGUMENTS,
            )
        self.assertEqual(self.counts(), committed)
        self.assertEqual(
            self.stop(assertion).to_dict(),
            receipt.to_dict(),
        )

    def test_authenticated_stop_reconciles_and_verifies(self) -> None:
        self.enroll_authenticated_stop()
        receipt = self.stop(self.make_assertion())

        self.assertEqual(receipt.mission_control.state.value, "stopped")
        self.assertEqual(
            self.counts()["assertions"],
            1,
        )
        self.assertEqual(
            self.counts()["effects"],
            1,
        )
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )

    def test_empty_baseline_stop_without_provenance_fails_verification(self) -> None:
        self.pin_root_and_prepare_policy()
        self.trust.apply_policy(self.policy)
        local = MissionControlService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        command = _mission_stop_command(
            MISSION_ID,
            principal_profile_id=PROFILE_ID,
            **STOP_ARGUMENTS,
        )
        with self.store._write_connection() as connection:
            local._stop_in_connection(
                connection,
                command,
                self.now,
                allow_exact_replay=False,
                authenticated_principal=True,
            )

        self.assertEqual(self.counts()["assertions"], 0)
        self.assertEqual(self.counts()["effects"], 0)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "no authenticated provenance",
        ):
            self.store.verify_store(self.registry)

    def rewrite_effect_value(
        self,
        path: tuple[str, ...],
        value: object,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            effect_trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_effect_immutable'
                """
            ).fetchone()[0]
            use_trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'principal_assertion_use_immutable'
                """
            ).fetchone()[0]
            effect_row = connection.execute(
                """
                SELECT * FROM principal_assertion_effects
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert effect_row is not None
            effect = json.loads(str(effect_row["effect_json"]))
            target: dict[str, Any] = effect
            for key in path[:-1]:
                nested = target[key]
                assert isinstance(nested, dict)
                target = nested
            target[path[-1]] = value
            effect_json = canonical_json(effect)
            effect_hash = sha256_text(effect_json)
            effects_hash = principal_assertion_effects_hash(
                (effect_hash,)
            )

            connection.execute(
                "DROP TRIGGER principal_assertion_effect_immutable"
            )
            connection.execute(
                "DROP TRIGGER principal_assertion_use_immutable"
            )
            connection.execute(
                """
                UPDATE principal_assertion_effects
                SET effect_json = ?, effect_hash = ?
                WHERE mission_id = ?
                """,
                (effect_json, effect_hash, MISSION_ID),
            )
            connection.execute(
                """
                UPDATE principal_assertion_uses
                SET effects_hash = ?
                WHERE mission_id = ?
                """,
                (effects_hash, MISSION_ID),
            )
            use_row = connection.execute(
                """
                SELECT * FROM principal_assertion_uses
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()
            assert use_row is not None
            entry_hash = principal_assertion_entry_hash(
                self.store._principal_assertion_entry_material(use_row)
            )
            connection.execute(
                """
                UPDATE principal_assertion_uses
                SET entry_hash = ?
                WHERE mission_id = ?
                """,
                (entry_hash, MISSION_ID),
            )
            connection.execute(
                """
                UPDATE mission_principal_ledgers
                SET head_hash = ?
                WHERE mission_id = ?
                """,
                (entry_hash, MISSION_ID),
            )
            connection.execute(effect_trigger)
            connection.execute(use_trigger)
            connection.commit()

    def test_nested_boolean_effect_number_is_rejected(self) -> None:
        self.enroll_authenticated_stop()
        self.stop(self.make_assertion())
        self.rewrite_effect_value(
            ("payload", "mission_revision"),
            True,
        )

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "does not reconcile",
        ):
            self.store.verify_store(self.registry)

    def test_float_effect_schema_version_is_rejected(self) -> None:
        self.enroll_authenticated_stop()
        self.stop(self.make_assertion())
        self.rewrite_effect_value(("schema_version",), 1.0)

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "effect binding is invalid",
        ):
            self.store.verify_store(self.registry)

    def test_historical_stopped_baseline_enrolls_without_provenance(self) -> None:
        self.local_stop()
        self.downgrade_to_v2_and_migrate()
        self.pin_root_and_prepare_policy()

        self.trust.apply_policy(self.policy)

        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )
        with closing(sqlite3.connect(self.path)) as connection:
            baseline_kind = connection.execute(
                """
                SELECT baseline_kind FROM mission_principal_ledgers
                WHERE mission_id = ?
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            self.assertEqual(baseline_kind, "historical_v2")
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects"
                ).fetchone()[0],
                0,
            )

    def test_historical_active_baseline_can_stop_after_enrollment(self) -> None:
        self.downgrade_to_v2_and_migrate()
        self.enroll_authenticated_stop()

        receipt = self.stop(self.make_assertion())

        self.assertEqual(receipt.mission_control.state.value, "stopped")
        self.assertEqual(
            self.store.verify_store(self.registry).status,
            "valid",
        )


if __name__ == "__main__":
    unittest.main()

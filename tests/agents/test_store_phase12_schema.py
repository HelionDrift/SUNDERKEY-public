"""Schema v9 authenticated simulation provenance coverage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.authenticated_simulations import (
    AuthenticatedSimulationService,
)
from sunderkey.errors import StoreConflictError, StoreIntegrityError
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
)
from sunderkey.simulation import SimulationService
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V8,
    EXPECTED_SCHEMA_MANIFEST_V9,
    SCHEMA_VERSION,
    SIMULATION_AUTHENTICATION_SCHEMA_VERSION,
    SIMULATION_RUN_EFFECT_KIND,
    _schema_manifest,
    canonical_json,
    sha256_text,
    simulation_authentication_baseline_root_hash,
    simulation_history_root_hash,
)
from sunderkey.trust import TrustProvisioningService

from .test_authenticated_approval_revocations_phase11 import (
    AUDIENCE,
    EXECUTOR_ID,
    POLICY_VERSION,
    ROOT_KEY_ID,
)
from .test_identity_phase4 import b64url, public_bytes
from .test_store import (
    MISSION_ID as STORE_MISSION_ID,
)
from .test_store import (
    SPECIALIST_ID,
    remove_schema_v9_objects,
)


class Phase12StoreSchemaTests(unittest.TestCase):
    @staticmethod
    def phase11_store_fixture():
        from .test_store_phase11_schema import (
            Phase11StoreSchemaTests,
        )

        Phase11StoreSchemaTests.setUpClass()
        fixture = Phase11StoreSchemaTests(methodName="runTest")
        fixture.setUp()
        return fixture

    @staticmethod
    def phase12_runtime_fixture():
        from .test_authenticated_simulations_phase12 import (
            AuthenticatedSimulationPhase12Tests,
        )

        fixture = AuthenticatedSimulationPhase12Tests(
            methodName="runTest"
        )
        fixture.setUp()
        return fixture

    def downgrade_to_v8(
        self,
        path: Path,
    ) -> None:
        with closing(sqlite3.connect(path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            remove_schema_v9_objects(connection)
            connection.execute(
                """
                UPDATE store_metadata
                SET value = '8'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("PRAGMA user_version = 8")
            connection.commit()

    def test_fresh_v9_mission_has_bound_empty_baseline(self) -> None:
        fixture = self.phase11_store_fixture()
        self.addCleanup(fixture.doCleanups)
        store = fixture.initialized_store()
        mission = store.get_mission(
            fixture.registry,
            STORE_MISSION_ID,
        )

        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM mission_simulation_authentication_baselines
                WHERE mission_id = ?
                """,
                (STORE_MISSION_ID,),
            ).fetchone()

        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        expected = {
            "schema": (
                "sunderkey.mission-simulation-authentication-"
                "baseline.v1"
            ),
            "baseline_kind": "empty",
            "provenance_status": "no_pre_v9_simulations",
            "mission_id": STORE_MISSION_ID,
            "mission_context_hash": mission.context_hash,
            "source_schema_version": (
                SIMULATION_AUTHENTICATION_SCHEMA_VERSION
            ),
            "historical_simulations": [],
            "historical_simulation_root_hash": (
                simulation_history_root_hash(())
            ),
        }
        baseline_hash = sha256_text(canonical_json(expected))
        self.assertEqual(baseline, expected)
        self.assertEqual(row["baseline_hash"], baseline_hash)
        self.assertEqual(
            row["baseline_root_hash"],
            simulation_authentication_baseline_root_hash(
                STORE_MISSION_ID,
                baseline_hash,
            ),
        )
        self.assertEqual(row["historical_simulation_count"], 0)
        self.assertEqual(store.verify_store(fixture.registry).status, "valid")

    def test_v9_objects_preserve_exact_v8_manifest(self) -> None:
        self.assertEqual(
            SIMULATION_AUTHENTICATION_SCHEMA_VERSION,
            9,
        )
        self.assertGreater(
            SCHEMA_VERSION,
            SIMULATION_AUTHENTICATION_SCHEMA_VERSION,
        )
        v8_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V8}
        v9_names = {item[1] for item in EXPECTED_SCHEMA_MANIFEST_V9}
        self.assertNotIn(
            "mission_simulation_authentication_baselines",
            v8_names,
        )
        self.assertIn(
            "mission_simulation_authentication_baselines",
            v9_names,
        )
        self.assertTrue(v8_names < v9_names)

        fixture = self.phase11_store_fixture()
        self.addCleanup(fixture.doCleanups)
        fixture.initialized_store()
        self.downgrade_to_v8(fixture.path)
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V8,
            )

    def test_v8_migration_captures_historical_direct_simulation(
        self,
    ) -> None:
        fixture = self.phase11_store_fixture()
        self.addCleanup(fixture.doCleanups)
        store = fixture.initialized_store()
        _, approval_id = fixture.approved(store)
        receipt = SimulationService(
            store,
            fixture.registry,
            clock=lambda: fixture.now,
        ).simulate(
            approval_id,
            idempotency_key="phase12-historical-simulation",
            principal_profile_id=SPECIALIST_ID,
        )
        self.downgrade_to_v8(fixture.path)

        report = store.migrate(
            fixture.registry,
            fixture.directory / "before-v9.sqlite3",
        )

        self.assertEqual(report.source_version, 8)
        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM mission_simulation_authentication_baselines
                WHERE mission_id = ?
                """,
                (STORE_MISSION_ID,),
            ).fetchone()
        assert row is not None
        baseline = json.loads(str(row["baseline_json"]))
        historical = baseline["historical_simulations"]
        self.assertEqual(row["baseline_kind"], "historical_pre_v9")
        self.assertEqual(row["historical_simulation_count"], 1)
        self.assertEqual(
            historical[0]["simulation_receipt"],
            receipt.to_dict(),
        )
        self.assertEqual(
            historical[0]["operation"],
            SIMULATION_RUN_EFFECT_KIND,
        )
        self.assertEqual(store.verify_store(fixture.registry).status, "valid")

    def test_baseline_and_receipt_resist_conflict_algorithms(self) -> None:
        fixture = self.phase11_store_fixture()
        self.addCleanup(fixture.doCleanups)
        store = fixture.initialized_store()
        _, approval_id = fixture.approved(store)
        receipt = SimulationService(
            store,
            fixture.registry,
            clock=lambda: fixture.now,
        ).simulate(
            approval_id,
            idempotency_key="phase12-immutable-simulation",
            principal_profile_id=SPECIALIST_ID,
        )

        with closing(sqlite3.connect(fixture.path)) as connection:
            connection.execute("PRAGMA recursive_triggers = OFF")
            baseline = connection.execute(
                """
                SELECT *
                FROM mission_simulation_authentication_baselines
                WHERE mission_id = ?
                """,
                (STORE_MISSION_ID,),
            ).fetchone()
            stored_receipt = connection.execute(
                """
                SELECT *
                FROM simulation_receipts
                WHERE mission_id = ? AND simulation_id = ?
                """,
                (STORE_MISSION_ID, receipt.simulation_id),
            ).fetchone()
            assert baseline is not None
            assert stored_receipt is not None
            for statement, arguments in (
                (
                    """
                    UPDATE mission_simulation_authentication_baselines
                    SET baseline_kind = 'historical_pre_v9'
                    WHERE mission_id = ?
                    """,
                    (STORE_MISSION_ID,),
                ),
                (
                    """
                    DELETE FROM mission_simulation_authentication_baselines
                    WHERE mission_id = ?
                    """,
                    (STORE_MISSION_ID,),
                ),
                (
                    """
                    UPDATE simulation_receipts
                    SET receipt_hash = ?
                    WHERE mission_id = ? AND simulation_id = ?
                    """,
                    (
                        "sha256:" + ("0" * 64),
                        STORE_MISSION_ID,
                        receipt.simulation_id,
                    ),
                ),
                (
                    """
                    DELETE FROM simulation_receipts
                    WHERE mission_id = ? AND simulation_id = ?
                    """,
                    (STORE_MISSION_ID, receipt.simulation_id),
                ),
            ):
                with (
                    self.subTest(statement=statement),
                    self.assertRaises(sqlite3.IntegrityError),
                ):
                    connection.execute(statement, arguments)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    """
                    INSERT OR REPLACE INTO simulation_receipts
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    tuple(stored_receipt),
                )
            connection.rollback()

    def test_authenticated_simulation_reconciles_effect_and_counts(
        self,
    ) -> None:
        fixture = self.phase12_runtime_fixture()
        self.addCleanup(fixture.doCleanups)
        credential = fixture.assertion()
        receipt = AuthenticatedSimulationService(
            fixture.store,
            fixture.registry,
            clock=lambda: fixture.fixture.now,
        ).simulate(
            credential,
            fixture.approval_id,
            idempotency_key="phase12-simulate",
        )

        report = fixture.store.verify_store(fixture.registry)

        self.assertEqual(report.status, "valid")
        self.assertEqual(report.mission_count, 1)
        with closing(sqlite3.connect(fixture.store.path)) as connection:
            use_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_uses
                WHERE operation = ?
                """,
                (PrincipalOperation.SIMULATION_RUN.value,),
            ).fetchone()[0]
            effect_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM principal_assertion_effects
                WHERE effect_kind = ?
                """,
                (SIMULATION_RUN_EFFECT_KIND,),
            ).fetchone()[0]
            baseline_count = connection.execute(
                """
                SELECT COUNT(*)
                FROM mission_simulation_authentication_baselines
                """
            ).fetchone()[0]
        self.assertEqual(use_count, 1)
        self.assertEqual(effect_count, 1)
        self.assertEqual(baseline_count, 1)
        self.assertEqual(
            receipt.simulation.simulation_id,
            receipt.approval.simulation_id,
        )

    def test_pre_v9_claimed_simulation_provenance_is_rejected(self) -> None:
        fixture = self.phase12_runtime_fixture()
        self.addCleanup(fixture.doCleanups)
        fixture.simulate()
        self.downgrade_to_v8(fixture.store.path)

        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
            StoreIntegrityError,
            "Pre-v9 simulation provenance cannot be promoted",
        ):
            fixture.store.migrate(
                fixture.registry,
                Path(temporary) / "rejected.sqlite3",
            )

    def test_policy_enrollment_rejects_post_baseline_direct_simulation(
        self,
    ) -> None:
        fixture = self.phase11_store_fixture()
        self.addCleanup(fixture.doCleanups)
        runtime = self.phase12_runtime_fixture()
        self.addCleanup(runtime.doCleanups)
        store = fixture.initialized_store()
        _, approval_id = fixture.approved(store)
        fixture.downgrade_to_v4()
        store.migrate(
            fixture.registry,
            fixture.directory / "before-phase12-baseline.sqlite3",
        )
        SimulationService(
            store,
            fixture.registry,
            clock=lambda: fixture.now,
        ).simulate(
            approval_id,
            idempotency_key="phase12-post-baseline-run",
            principal_profile_id=SPECIALIST_ID,
        )
        trust = TrustProvisioningService(store)
        store_id = trust.status().store_id
        root_public_key = public_bytes(
            runtime.fixture.factory.root_private
        )
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public_key),
            "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
        )
        prior_store_id = runtime.fixture.store_id
        runtime.fixture.store_id = store_id
        try:
            policy = runtime.fixture.make_policy(POLICY_VERSION)
        finally:
            runtime.fixture.store_id = prior_store_id

        with self.assertRaisesRegex(
            StoreConflictError,
            "unauthenticated simulation",
        ):
            trust.apply_policy(policy)

    def test_intent_hash_contract_is_exact(self) -> None:
        intent = {
            "approval_id": "APR-PHASE12-CONTRACT",
            "idempotency_key_sha256": sha256_text(
                "phase12-contract"
            ),
            "principal_profile_id": EXECUTOR_ID,
        }
        first = compute_operation_intent_hash(
            PrincipalOperation.SIMULATION_RUN,
            intent,
        )
        second = compute_operation_intent_hash(
            PrincipalOperation.SIMULATION_RUN.value,
            dict(reversed(tuple(intent.items()))),
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()

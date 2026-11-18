"""Schema 36 action target-health gate use custody tests."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta

from sunderkey.action_target_health_gate_use import (
    NONREPEATABLE_USE_KINDS,
    SCHEMA36_RESERVED_USE_KINDS,
    ActionTargetHealthGateLegacyBaseline,
    ActionTargetHealthGateUse,
    ActionTargetHealthGateUseError,
    ActionTargetHealthGateUseKind,
    canonical_json,
    insert_action_target_health_gate_use,
    verify_action_target_health_gate_use_store,
)
from sunderkey.errors import StoreMigrationRequiredError
from sunderkey.store import (
    ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V35,
    EXPECTED_SCHEMA_MANIFEST_V36,
    EXPECTED_SCHEMA_MANIFEST_V39,
    SCHEMA_VERSION,
    _schema_manifest,
)
from sunderkey.target_health_gate_contracts import (
    TargetHealthGateClassification,
    TargetHealthGateObservation,
    build_target_health_gate_head,
    build_target_health_gate_transition,
)

from . import test_mission_store_action_admission_phase195b as phase195b
from .test_store import remove_schema_v37_objects


class ActionTargetHealthGateUsePhase199DTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def setUp(self) -> None:
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        (
            self.sources,
            _command,
            _resolution,
            _quorum,
            self.request,
            self.receipt,
        ) = fixture._admit_complete_sources()
        self.binding = fixture.service._target_health_binding_from_request(
            self.request
        )

    def _next_result(self):  # type: ignore[no-untyped-def]
        self.fixture.root.now += timedelta(seconds=1)
        return self.fixture.health_gate.observe_current(self.binding)

    def _use(
        self,
        *,
        result=None,  # type: ignore[no-untyped-def]
        use_kind=ActionTargetHealthGateUseKind.ACTION_ADMISSION_CURRENT_VERIFICATION,
        consumer_id: str | None = None,
        consumer_sha256: str | None = None,
    ) -> ActionTargetHealthGateUse:
        result = result or self._next_result()
        return ActionTargetHealthGateUse(
            use_kind=use_kind,
            tenant_id=self.binding.tenant_id,
            mission_id=self.binding.context_id,
            consumer_id=consumer_id or self.receipt.receipt_id,
            consumer_sha256=consumer_sha256 or self.receipt.receipt_sha256,
            binding_sha256=result.decision.binding_sha256,
            decision=result.decision,
            transition=result.transition,
            head=result.head,
            used_at=result.decision.evaluated_at,
        )

    def _legacy_contextless_successor(self, previous_head):  # type: ignore[no-untyped-def]
        self.fixture.root.now += timedelta(seconds=1)
        inspection = self.fixture.health_gate._inspect_binding(self.binding)
        self.assertIsNone(inspection.inspection_context_sha256)
        observation = TargetHealthGateObservation(
            subject=previous_head.subject,
            observation_sequence=previous_head.observation_count + 1,
            previous_observation_sha256=(
                previous_head.observation_head_sha256
            ),
            binding=self.binding,
            binding_sha256=inspection.envelope.receipt.binding_sha256,
            inspection=inspection,
            classification=TargetHealthGateClassification.HEALTHY,
            evidence_advanced=False,
            recorded_at=inspection.inspected_at,
        )
        transition = build_target_health_gate_transition(
            previous_head=previous_head,
            observation=observation,
        )
        head = build_target_health_gate_head(
            transition=transition,
            observation=observation,
            resumption=None,
            previous_head=previous_head,
        )
        return observation, transition, head

    def _downgrade_to_schema35(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        remove_schema_v37_objects(connection)
        old_names = {
            (item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V35
        }
        additions = [
            item
            for item in EXPECTED_SCHEMA_MANIFEST_V36
            if (item[0], item[1]) not in old_names
        ]
        for object_type in ("trigger", "index"):
            for item in additions:
                if item[0] == object_type:
                    connection.execute(
                        f'DROP {object_type.upper()} IF EXISTS "{item[1]}"'
                    )
        connection.execute("DROP TABLE action_target_health_gate_uses")
        connection.execute(
            "DROP TABLE action_target_health_gate_legacy_baselines"
        )
        connection.execute(
            "UPDATE store_metadata SET value = '35' "
            "WHERE key = 'schema_version'"
        )
        connection.execute("PRAGMA user_version = 35")

    def test_schema_36_adds_only_health_use_custody(self) -> None:
        self.assertEqual(ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION, 36)
        self.assertEqual(SCHEMA_VERSION, 39)
        self.assertEqual(EXPECTED_SCHEMA_MANIFEST, EXPECTED_SCHEMA_MANIFEST_V39)
        self.assertIn(
            ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION,
            NONREPEATABLE_USE_KINDS,
        )
        self.assertEqual(
            SCHEMA36_RESERVED_USE_KINDS,
            {ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION},
        )
        old = {(item[0], item[1]): item for item in EXPECTED_SCHEMA_MANIFEST_V35}
        current = {
            (item[0], item[1]): item for item in EXPECTED_SCHEMA_MANIFEST_V36
        }
        self.assertFalse(set(old) - set(current))
        self.assertEqual(
            set(current) - set(old),
            {
                ("table", "action_target_health_gate_legacy_baselines"),
                ("table", "action_target_health_gate_uses"),
                (
                    "index",
                    "action_target_health_gate_uses_mission_kind_idx",
                ),
                (
                    "index",
                    "action_target_health_gate_uses_nonrepeatable_consumer_id",
                ),
                (
                    "index",
                    "action_target_health_gate_uses_nonrepeatable_consumer_sha256",
                ),
                (
                    "trigger",
                    "action_target_health_gate_legacy_baselines_insert_guard",
                ),
                (
                    "trigger",
                    "action_target_health_gate_legacy_baselines_immutable",
                ),
                (
                    "trigger",
                    "action_target_health_gate_legacy_baselines_no_delete",
                ),
                ("trigger", "action_target_health_gate_uses_insert_guard"),
                ("trigger", "action_target_health_gate_uses_immutable"),
                ("trigger", "action_target_health_gate_uses_no_delete"),
                (
                    "trigger",
                    "target_health_gate_observations_context_guard",
                ),
            },
        )
        with closing(sqlite3.connect(self.fixture.store.path)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)
            row = connection.execute(
                "SELECT baseline_json FROM "
                "action_target_health_gate_legacy_baselines"
            ).fetchone()
        self.assertIsNotNone(row)
        baseline = ActionTargetHealthGateLegacyBaseline.from_dict(
            json.loads(row[0])
        )
        self.assertEqual(baseline.records, ())
        self.assertEqual(baseline.to_dict()["permit_effect"], "none")
        self.assertEqual(
            baseline.to_dict()["health_gate_qualification"],
            "not_established",
        )

    def test_round_trip_preserves_snapshot_after_head_advances(self) -> None:
        use = self._use()
        with self.fixture.store._write_connection() as connection:
            insert_action_target_health_gate_use(connection, use)

        self._next_result()
        with self.fixture.store._read_connection() as connection:
            report = verify_action_target_health_gate_use_store(connection)
            row = connection.execute(
                "SELECT use_json FROM action_target_health_gate_uses "
                "WHERE use_id = ?",
                (use.use_id,),
            ).fetchone()
        self.assertGreaterEqual(report.use_count, 3)
        self.assertEqual(ActionTargetHealthGateUse.from_dict(json.loads(row[0])), use)

    def test_one_decision_cannot_be_consumed_twice(self) -> None:
        result = self._next_result()
        first = self._use(result=result)
        second = self._use(
            result=result,
            use_kind=ActionTargetHealthGateUseKind.ACTION_ADMISSION_REPLAY_FOR_USE,
        )
        with self.fixture.store._write_connection() as connection:
            insert_action_target_health_gate_use(connection, first)
        with (
            self.assertRaises(
                (sqlite3.IntegrityError, ActionTargetHealthGateUseError)
            ),
            self.fixture.store._write_connection() as connection,
        ):
            insert_action_target_health_gate_use(connection, second)

    def test_positive_use_time_must_exactly_match_live_decision(self) -> None:
        use = self._use()
        late_at = (
            datetime.strptime(use.used_at, "%Y-%m-%dT%H:%M:%SZ")
            + timedelta(seconds=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self.assertRaisesRegex(
            ActionTargetHealthGateUseError,
            "use time does not match",
        ):
            replace(
                use,
                used_at=late_at,
                use_id="",
                use_sha256="",
            )

    def test_nonrepeatable_consumer_requires_exactly_one_use(self) -> None:
        duplicate = self._use(
            use_kind=ActionTargetHealthGateUseKind.ACTION_ADMISSION
        )
        with (
            self.assertRaises(
                (sqlite3.IntegrityError, ActionTargetHealthGateUseError)
            ),
            self.fixture.store._write_connection() as connection,
        ):
            insert_action_target_health_gate_use(connection, duplicate)

    def test_orphan_and_cross_digest_consumers_fail_closed(self) -> None:
        use = self._use(consumer_sha256="sha256:" + "f" * 64)
        with (
            self.assertRaises(
                (sqlite3.IntegrityError, ActionTargetHealthGateUseError)
            ),
            self.fixture.store._write_connection() as connection,
        ):
            insert_action_target_health_gate_use(connection, use)

    def test_direct_insert_rejects_decision_for_different_consumer_binding(self) -> None:
        use = self._use()
        altered_request = replace(
            self.request,
            target=replace(
                self.request.target,
                target_id="target-binding-substitution",
                target_sha256="sha256:" + "f" * 64,
            ),
            request_id="",
            request_sha256="",
        )
        with (
            self.assertRaisesRegex(
                ActionTargetHealthGateUseError,
                "does not match its consumer binding",
            ),
            self.fixture.store._write_connection() as connection,
        ):
            connection.execute(
                "DROP TRIGGER action_admission_receipts_immutable"
            )
            connection.execute(
                "UPDATE action_admission_receipts SET request_json = ? "
                "WHERE receipt_id = ?",
                (
                    canonical_json(altered_request.to_dict()),
                    self.receipt.receipt_id,
                ),
            )
            insert_action_target_health_gate_use(connection, use)

    def test_documents_and_rows_are_immutable_and_no_effect(self) -> None:
        use = self._use()
        with self.fixture.store._write_connection() as connection:
            insert_action_target_health_gate_use(connection, use)
        with (
            self.assertRaises(sqlite3.IntegrityError),
            self.fixture.store._write_connection() as connection,
        ):
            connection.execute(
                "UPDATE action_target_health_gate_uses "
                "SET qualification_effect = 'qualified' WHERE use_id = ?",
                (use.use_id,),
            )
        with (
            self.assertRaises(sqlite3.IntegrityError),
            self.fixture.store._write_connection() as connection,
        ):
            connection.execute(
                "DELETE FROM action_target_health_gate_uses WHERE use_id = ?",
                (use.use_id,),
            )
        document = use.to_dict()
        document["dispatch_effect"] = "dispatch"
        with self.assertRaises(ActionTargetHealthGateUseError):
            ActionTargetHealthGateUse.from_dict(document)

    def test_schema_35_migration_captures_legacy_records_without_permits(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.fixture.store.path)) as connection:
            self._downgrade_to_schema35(connection)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V35)

        with self.assertRaisesRegex(
            StoreMigrationRequiredError,
            "requires migrate-store",
        ):
            self.fixture.service.initialize()

        report = self.fixture.store.migrate(
            self.fixture.registry,
            self.fixture.root.directory / "before-schema36.sqlite3",
        )
        self.assertEqual(report.source_version, 35)
        self.assertEqual(report.target_version, 39)
        self.fixture.service.initialize()
        with self.fixture.store._read_connection() as connection:
            verification = verify_action_target_health_gate_use_store(connection)
            row = connection.execute(
                "SELECT baseline_json FROM "
                "action_target_health_gate_legacy_baselines"
            ).fetchone()
            use_count = connection.execute(
                "SELECT COUNT(*) FROM action_target_health_gate_uses"
            ).fetchone()[0]
        baseline = ActionTargetHealthGateLegacyBaseline.from_dict(
            json.loads(row[0])
        )
        self.assertGreaterEqual(verification.legacy_record_count, 2)
        self.assertEqual(use_count, 0)
        self.assertTrue(
            all(
                record.to_dict().get("permit_effect") is None
                for record in baseline.records
            )
        )
        self.assertEqual(
            canonical_json(baseline.to_dict()),
            row[0],
        )

    def test_schema35_contextless_observation_migrates_but_new_one_fails(
        self,
    ) -> None:
        previous_head = self.fixture.health_gate.load_head(self.binding)
        self.assertIsNotNone(previous_head)
        observation, transition, head = self._legacy_contextless_successor(
            previous_head
        )
        legacy_decision = self.fixture.health_gate._decision(observation, head)
        with self.assertRaisesRegex(
            ActionTargetHealthGateUseError,
            "legacy contextless inspection cannot authorize",
        ):
            ActionTargetHealthGateUse(
                use_kind=(
                    ActionTargetHealthGateUseKind.ACTION_ADMISSION_CURRENT_VERIFICATION
                ),
                tenant_id=self.binding.tenant_id,
                mission_id=self.binding.context_id,
                consumer_id=self.receipt.receipt_id,
                consumer_sha256=self.receipt.receipt_sha256,
                binding_sha256=legacy_decision.binding_sha256,
                decision=legacy_decision,
                transition=transition,
                head=head,
                used_at=legacy_decision.evaluated_at,
            )
        with closing(sqlite3.connect(self.fixture.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            self._downgrade_to_schema35(connection)
            self.fixture.health_gate._insert_observation(connection, observation)
            self.fixture.health_gate._insert_transition(connection, transition)
            self.fixture.health_gate._store_head(
                connection,
                head,
                previous_head,
            )
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V35)

        report = self.fixture.store.migrate(
            self.fixture.registry,
            self.fixture.root.directory / "before-context-schema36.sqlite3",
        )
        self.assertEqual((report.source_version, report.target_version), (35, 39))
        verification = self.fixture.health_gate.verify_store(self.fixture.mission_id)
        self.assertGreaterEqual(verification.observation_count, 1)

        stored_head = self.fixture.health_gate.load_head(self.binding)
        next_observation, _next_transition, _next_head = (
            self._legacy_contextless_successor(stored_head)
        )
        with (
            self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "target health inspection context is invalid",
            ),
            self.fixture.store._write_connection() as connection,
        ):
            self.fixture.health_gate._insert_observation(
                connection,
                next_observation,
            )


if __name__ == "__main__":
    unittest.main()

"""Registry fences for genuine synthetic reviewer-admission approval custody."""

from __future__ import annotations

import sqlite3
import unittest
from contextlib import nullcontext
from unittest import mock

from sunderkey.authenticated_collaboration import AuthenticatedCollaborationActivationService
from sunderkey.errors import StoreIntegrityError
from sunderkey.store import PLAN_REPLACEMENT_REVIEWER_ADMISSION_EFFECT_KINDS, canonical_json

from .test_plan_replacement_reviewer_admission import MISSION_ID, ReviewerAdmissionFixture


def _custody_snapshot(connection: sqlite3.Connection) -> tuple:
    """Capture every local source row and schema object before rollback-only tamper."""
    tables = tuple(
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    )
    records = tuple(
        (
            table,
            tuple(
                sorted(
                    canonical_json(dict(row))
                    for row in connection.execute(
                        'SELECT * FROM "' + table.replace('"', '""') + '"'
                    )
                )
            ),
        )
        for table in tables
    )
    schema = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        )
    )
    return records, schema


class PlanReplacementPrincipalLedgerOrphanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = ReviewerAdmissionFixture(self)

    def _verified_snapshot(self, connection: sqlite3.Connection):
        f = self.fixture
        activation = AuthenticatedCollaborationActivationService(f.store, f.registry)
        identity, policies, mission, scopes, _ = activation._verified_mission_state(
            connection, MISSION_ID
        )
        return mission, dict(
            store_id=identity["store_id"],
            scope_grants=scopes,
            trust_policies=policies,
        )

    def _admit_assigned_assurance(self):
        f = self.fixture
        self.assertIn("AOE-HQ-19", f.stored.assurance_profile_ids)
        request = f.request(300, "independent_assurance", "AOE-HQ-19")
        return request, f.service.admit(request, **f.approvals(request))

    def test_registry_none_preserves_history_without_admission_custody(self) -> None:
        f = self.fixture
        with f.store._read_connection() as connection:
            mission, arguments = self._verified_snapshot(connection)
            before = _custody_snapshot(connection)
            report = f.store._verify_principal_ledger(connection, mission, **arguments)
            self.assertEqual(report[0], 1)
            self.assertEqual(_custody_snapshot(connection), before)
        self.assertEqual(f.store.verify_mission(f.registry, MISSION_ID).mission_count, 1)
        self.assertEqual(f.store.verify_store(f.registry).mission_count, 1)

    def test_registry_required_for_intact_admission_custody(self) -> None:
        f = self.fixture
        request, receipt = self._admit_assigned_assurance()
        with f.store._read_connection() as connection:
            mission, arguments = self._verified_snapshot(connection)
            before = _custody_snapshot(connection)
            with self.assertRaisesRegex(StoreIntegrityError, "expert registry"):
                f.store._verify_principal_ledger(connection, mission, **arguments)
            f.store._verify_principal_ledger(connection, mission, registry=f.registry, **arguments)
            self.assertEqual(_custody_snapshot(connection), before)
        self.assertEqual(f.service.get(MISSION_ID, request.admission_id), receipt)
        self.assertEqual(f.store.verify_store(f.registry).mission_count, 1)

    def test_orphaned_approval_custody_requires_registry_and_public_checks_reject(
        self,
    ) -> None:
        f = self.fixture
        request, receipt = self._admit_assigned_assurance()
        self.assertEqual(f.store.verify_mission(f.registry, MISSION_ID).mission_count, 1)
        self.assertEqual(f.store.verify_store(f.registry).mission_count, 1)
        with f.store._read_connection() as connection:
            mission, arguments = self._verified_snapshot(connection)
            before = _custody_snapshot(connection)
            trigger_name = "plan_replacement_reviewer_admissions_no_delete"
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name=?", (trigger_name,)
            ).fetchone()[0]
            connection.execute("SAVEPOINT orphan_probe")
            try:
                connection.execute("DROP TRIGGER " + trigger_name)
                deleted = connection.execute(
                    "DELETE FROM plan_replacement_reviewer_admissions WHERE admission_id=?",
                    (request.admission_id,),
                )
                self.assertEqual(deleted.rowcount, 1)
                connection.execute(trigger)
                self.assertEqual(
                    connection.execute(
                        "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions "
                        "WHERE mission_id=?",
                        (MISSION_ID,),
                    ).fetchone()[0],
                    0,
                )
                approval_uses = connection.execute(
                    "SELECT use.operation,COUNT(effect.effect_index) "
                    "FROM principal_assertion_uses AS use "
                    "JOIN principal_assertion_effects AS effect "
                    "ON effect.issuer=use.issuer AND effect.assertion_id=use.assertion_id "
                    "WHERE use.mission_id=? AND use.operation IN (?,?) GROUP BY use.operation",
                    (MISSION_ID, *sorted(PLAN_REPLACEMENT_REVIEWER_ADMISSION_EFFECT_KINDS)),
                ).fetchall()
                self.assertEqual(
                    {row[0] for row in approval_uses},
                    PLAN_REPLACEMENT_REVIEWER_ADMISSION_EFFECT_KINDS,
                )
                self.assertTrue(all(row[1] == 1 for row in approval_uses))
                # Assigned HQ19 remains a valid historical scope source. Capture
                # it again after tamper rather than trusting the earlier view.
                scopes, _ = f.store._verify_scope_grants(
                    connection,
                    mission,
                    store_id=arguments["store_id"],
                    trust_policies=arguments["trust_policies"],
                    registry=f.registry,
                )
                arguments["scope_grants"] = scopes
                with self.assertRaisesRegex(StoreIntegrityError, "expert registry"):
                    f.store._verify_principal_ledger(connection, mission, **arguments)
                with self.assertRaisesRegex(StoreIntegrityError, "orphaned"):
                    f.store._verify_principal_ledger(
                        connection, mission, registry=f.registry, **arguments
                    )
                # These public APIs normally open their own read snapshot. The
                # local seam exposes this uncommitted probe without persisting it.
                with mock.patch.object(
                    f.store,
                    "_read_connection",
                    side_effect=lambda: nullcontext(connection),
                ):
                    with self.assertRaisesRegex(StoreIntegrityError, "orphaned"):
                        f.store.verify_mission(f.registry, MISSION_ID)
                    with self.assertRaisesRegex(StoreIntegrityError, "orphaned"):
                        f.store.verify_store(f.registry)
            finally:
                connection.execute("ROLLBACK TO orphan_probe")
                connection.execute("RELEASE orphan_probe")
            self.assertEqual(_custody_snapshot(connection), before)
        self.assertEqual(f.service.get(MISSION_ID, request.admission_id), receipt)
        self.assertEqual(f.store.verify_mission(f.registry, MISSION_ID).mission_count, 1)
        self.assertEqual(f.store.verify_store(f.registry).mission_count, 1)


if __name__ == "__main__":
    unittest.main()

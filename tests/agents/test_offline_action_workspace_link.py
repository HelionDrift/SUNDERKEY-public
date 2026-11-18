"""Source-rechecked, selected historical action origin links."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from sunderkey.mission_audit import MissionAuditSnapshotService
from sunderkey.offline_action_workspace_link import (
    OfflineActionWorkspaceLinkError,
    link_offline_action_to_workspace,
)
from sunderkey.offline_composed_mission_trace import (
    OfflineComposedMissionTrace,
    capture_offline_composed_mission_trace,
)
from sunderkey.offline_composed_mission_trace import _identity as trace_identity
from sunderkey.offline_mission_action_custody import (
    OfflineMissionActionCustodySnapshot,
    capture_offline_mission_action_custody,
)
from sunderkey.offline_mission_action_custody import _identity as action_identity
from sunderkey.orchestration_journal import SQLiteOrchestrationJournal

from . import test_mission_store_action_admission_phase195b as phase195b


class OfflineActionWorkspaceLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def _sources(self):  # type: ignore[no-untyped-def]
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        _, _, _, _, _, receipt = fixture._admit_complete_sources()
        audit = MissionAuditSnapshotService(
            fixture.store, fixture.registry, clock=lambda: fixture.root.now
        )
        journal = SQLiteOrchestrationJournal(
            fixture.root.directory / "offline-action-workspace-journal.sqlite3"
        )
        action = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        trace = capture_offline_composed_mission_trace(
            mission_audit=audit,
            workspace_store=fixture.workspace,
            orchestration_journal=journal,
            runtime_catalog=fixture.catalog,
            expert_registry=fixture.registry,
            tenant_id=phase195b.TENANT_ID,
            mission_id=fixture.mission_id,
            workspace_id=fixture.workspace_state.workspace_id,
        )
        return fixture, receipt, audit, journal, action, trace

    def _link(self, sources, *, action=None, trace=None, **overrides):  # type: ignore[no-untyped-def]
        fixture, receipt, audit, journal, saved_action, saved_trace = sources
        arguments = {
            "action_snapshot": saved_action if action is None else action,
            "trace": saved_trace if trace is None else trace,
            "mission_store": fixture.store,
            "mission_audit": audit,
            "workspace_store": fixture.workspace,
            "orchestration_journal": journal,
            "runtime_catalog": fixture.catalog,
            "expert_registry": fixture.registry,
            "expected_tenant_id": phase195b.TENANT_ID,
            "expected_mission_id": fixture.mission_id,
            "expected_workspace_id": fixture.workspace_state.workspace_id,
            "expected_receipt_id": receipt.receipt_id,
        }
        arguments.update(overrides)
        return link_offline_action_to_workspace(**arguments)

    def test_rechecks_real_sources_and_links_exact_historical_origin(self) -> None:
        sources = self._sources()
        fixture, receipt, _audit, journal, action, trace = sources
        before = fixture.store.path.read_bytes()
        before_workspace = fixture.workspace_path.read_bytes()
        before_journal = journal.path.read_bytes()
        result = self._link(sources)
        self.assertEqual(fixture.store.path.read_bytes(), before)
        self.assertEqual(fixture.workspace_path.read_bytes(), before_workspace)
        self.assertEqual(journal.path.read_bytes(), before_journal)
        self.assertEqual(result["receipt_id"], receipt.receipt_id)
        self.assertEqual(result["workspace_id"], fixture.workspace_state.workspace_id)
        self.assertEqual(result["plan_id"], fixture.plan.plan_id)
        self.assertEqual(result["work_id"], fixture.product.to_dict()["work_id"])
        self.assertEqual(result["action_snapshot_sha256"], action.snapshot_sha256)
        self.assertEqual(result["trace_sha256"], trace.trace_sha256)
        self.assertEqual(result["cross_store_consistency"], "not_proven")
        self.assertFalse(result["current_authority_verified"])
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["current_work_assignment_compared"])
        self.assertFalse(result["effects"]["target_action_performed"])

    def test_rejects_wrong_pinned_identity(self) -> None:
        sources = self._sources()
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "action custody recheck"):
            self._link(sources, expected_tenant_id="tenant:other")
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "unavailable"):
            self._link(sources, expected_mission_id="MIS-OTHER-001")
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "trace recheck"):
            self._link(sources, expected_workspace_id="EWS-OTHER")
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "unavailable"):
            self._link(sources, expected_receipt_id="AAR-OTHER")

    def test_rejects_recomputed_action_origin_and_trace_plan_forgery(self) -> None:
        sources = self._sources()
        action = sources[4].to_dict()
        action["receipts"][0]["origin_work_id"] = "WIT-OTHER"
        body = {
            key: value for key, value in action.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        action["snapshot_id"], action["snapshot_sha256"] = action_identity(body)
        forged_action = OfflineMissionActionCustodySnapshot.from_dict(action)
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "action custody recheck"):
            self._link(sources, action=forged_action)

        trace = sources[5].to_dict()
        trace["workspace_observation"]["plan_id"] = "plan-other"
        body = {
            key: value for key, value in trace.items()
            if key not in {"trace_id", "trace_sha256"}
        }
        trace["trace_id"], trace["trace_sha256"] = trace_identity(body)
        forged_trace = OfflineComposedMissionTrace.from_dict(trace)
        with self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "trace recheck"):
            self._link(sources, trace=forged_trace)

    def test_explicit_join_rejects_different_workspace_even_after_selected_recheck(self) -> None:
        sources = self._sources()
        trace = sources[5].to_dict()
        trace["workspace_observation"]["workspace_id"] = "EWS-OTHER"
        body = {
            key: value for key, value in trace.items()
            if key not in {"trace_id", "trace_sha256"}
        }
        trace["trace_id"], trace["trace_sha256"] = trace_identity(body)
        other_trace = OfflineComposedMissionTrace.from_dict(trace)
        with (
            patch(
                "sunderkey.offline_action_workspace_link.recheck_offline_composed_mission_trace",
                return_value={"status": "selected_observations_match_at_recheck"},
            ),
            self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "does not match"),
        ):
            self._link(sources, trace=other_trace, expected_workspace_id="EWS-OTHER")

    def test_rejects_observed_action_change_during_link(self) -> None:
        sources = self._sources()
        from sunderkey.offline_action_workspace_link import (
            verify_offline_mission_action_custody_snapshot as verify_action,
        )

        calls = 0

        def verify_then_change(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal calls
            calls += 1
            if calls == 2:
                from sunderkey.offline_mission_action_custody import (
                    OfflineMissionActionCustodyError,
                )

                raise OfflineMissionActionCustodyError("source changed")
            return verify_action(*args, **kwargs)

        with (
            patch(
                "sunderkey.offline_action_workspace_link."
                "verify_offline_mission_action_custody_snapshot",
                side_effect=verify_then_change,
            ),
            self.assertRaisesRegex(OfflineActionWorkspaceLinkError, "changed during"),
        ):
            self._link(sources)
        self.assertEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()

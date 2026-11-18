"""Read-only cross-store mission trace tests."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from sunderkey.expert_workspace import ExpertWorkspaceState, ExpertWorkspaceVerificationReport
from sunderkey.mission_audit import MissionAuditSnapshotReceipt, _snapshot_hash, _snapshot_id
from sunderkey.offline_composed_mission_trace import (
    OfflineComposedMissionTrace,
    OfflineComposedMissionTraceError,
    _identity,
    capture_offline_composed_mission_trace,
    recheck_offline_composed_mission_trace,
)
from sunderkey.orchestration_journal import SQLiteOrchestrationJournal
from sunderkey.store import canonical_json

from . import test_expert_workspace_phase191 as phase191
from . import test_mission_audit_snapshot_phase19 as phase19


MISSION_ID = "MIS-TEST-001"
TENANT_ID = "tenant-test"
WORKSPACE_ID = "EWS-TEST"


def _audit_receipt(
    mission_id: str = MISSION_ID, *, revision: int = 3, head: str = "a",
    evaluated_at: str = "2026-10-02T00:00:00Z",
) -> MissionAuditSnapshotReceipt:
    body = {
        "schema_version": 1,
        "evaluated_at": evaluated_at,
        "integrity": {},
        "store": {},
        "mission": {
            "mission_id": mission_id,
            "revision": revision,
            "head_sha256": "sha256:" + head * 64,
        },
        "control": {},
        "events": {},
        "scope": {},
        "authentication": {},
        "approvals": {},
        "simulations": {},
        "collaboration": {},
    }
    digest = _snapshot_hash(body)
    return MissionAuditSnapshotReceipt.from_dict(
        {**body, "snapshot_id": _snapshot_id(digest), "snapshot_sha256": digest}
    )


def _job(job_id: str, subject_ref: str, tenant_id: str = TENANT_ID) -> SimpleNamespace:
    return SimpleNamespace(
        job=SimpleNamespace(
            job_id=job_id,
            job_sha256="sha256:" + hashlib.sha256(job_id.encode()).hexdigest(),
            subject_ref=subject_ref,
            tenant_id=tenant_id,
            job_kind=SimpleNamespace(value="source_reconciliation"),
        ),
        state=SimpleNamespace(value="available"),
        revision=1,
    )


class OfflineComposedMissionTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.audit = Mock()
        self.audit.snapshot.return_value = _audit_receipt()
        self.workspace_store = Mock()
        self.workspace_store.verify_store.return_value = ExpertWorkspaceVerificationReport(
            "valid", 1, 1, 2, 0, 0, 1, "sha256:" + "b" * 64
        )
        self.workspace_store.get_workspace.return_value = ExpertWorkspaceState(
            WORKSPACE_ID, TENANT_ID, MISSION_ID, "plan-test", 4, "active", 2, 0
        )
        self.journal = Mock()
        self.journal.verify.return_value = {
            "status": "valid",
            "schema_manifest_sha256": "sha256:" + "c" * 64,
            "event_count": 3,
            "counts": {"jobs": 3},
        }
        self.journal.list_jobs.return_value = (
            _job("JOB-001", MISSION_ID),
            _job("JOB-002", "other-mission"),
            _job("JOB-003", WORKSPACE_ID),
        )

    def capture(self) -> OfflineComposedMissionTrace:
        return capture_offline_composed_mission_trace(
            mission_audit=self.audit,
            workspace_store=self.workspace_store,
            orchestration_journal=self.journal,
            runtime_catalog=object(),
            expert_registry=object(),
            tenant_id=TENANT_ID,
            mission_id=MISSION_ID,
            workspace_id=WORKSPACE_ID,
        )

    def recheck(self, trace: OfflineComposedMissionTrace, **changes):
        sources = {
            "mission_audit": self.audit,
            "workspace_store": self.workspace_store,
            "orchestration_journal": self.journal,
            "runtime_catalog": object(),
            "expert_registry": object(),
            "expected_tenant_id": TENANT_ID,
            "expected_mission_id": MISSION_ID,
            "expected_workspace_id": WORKSPACE_ID,
        }
        sources.update(changes)
        return recheck_offline_composed_mission_trace(trace, **sources)

    def test_recheck_accepts_selected_same_state_with_time_varying_audit_hash(self):
        trace = self.capture()
        self.audit.snapshot.return_value = _audit_receipt(
            evaluated_at="2026-10-02T00:01:00Z"
        )
        report = self.recheck(trace)
        self.assertEqual(report["status"], "selected_observations_match_at_recheck")
        self.assertTrue(report["mission_audit_snapshot_sha256_changed"])
        self.assertFalse(report["full_mission_audit_state_compared"])
        self.assertFalse(report["current_authority_verified"])
        self.assertFalse(report["positive_use_approved"])
        self.assertEqual(report["cross_store_consistency"], "not_proven")
        self.assertEqual(report["effects"]["action_authority"], "none")

    def test_recheck_rejects_mission_and_workspace_drift(self):
        trace = self.capture()
        for receipt in (
            _audit_receipt(revision=4),
            _audit_receipt(head="d"),
        ):
            self.audit.snapshot.return_value = receipt
            with self.subTest(receipt=receipt.snapshot_sha256), self.assertRaisesRegex(
                OfflineComposedMissionTraceError, "observations changed"
            ):
                self.recheck(trace)
        self.audit.snapshot.return_value = _audit_receipt()
        original_workspace = self.workspace_store.get_workspace.return_value
        self.workspace_store.get_workspace.return_value = ExpertWorkspaceState(
            WORKSPACE_ID, TENANT_ID, MISSION_ID, "plan-test", 5, "active", 2, 0
        )
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "observations changed"):
            self.recheck(trace)
        self.workspace_store.get_workspace.return_value = original_workspace
        self.workspace_store.verify_store.return_value = ExpertWorkspaceVerificationReport(
            "valid", 1, 1, 2, 0, 0, 1, "sha256:" + "d" * 64
        )
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "observations changed"):
            self.recheck(trace)

    def test_recheck_rejects_relevant_job_or_journal_schema_drift(self):
        trace = self.capture()
        changed = _job("JOB-001", MISSION_ID)
        changed.state = SimpleNamespace(value="leased")
        self.journal.list_jobs.return_value = (changed, _job("JOB-003", WORKSPACE_ID))
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "observations changed"):
            self.recheck(trace)
        self.journal.list_jobs.return_value = (
            _job("JOB-001", MISSION_ID), _job("JOB-003", WORKSPACE_ID)
        )
        self.journal.verify.return_value = {
            **self.journal.verify.return_value,
            "schema_manifest_sha256": "sha256:" + "d" * 64,
        }
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "observations changed"):
            self.recheck(trace)

    def test_recheck_rejects_forgery_and_expected_identity_substitution(self):
        trace = self.capture()
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "fields differ"):
            self.recheck(replace(trace, trace_sha256="sha256:" + "d" * 64))
        changed = trace.to_dict()
        changed["tenant_id"] = "tenant-other"
        for job in changed["job_observations"]:
            job["tenant_id"] = "tenant-other"
        body = {key: value for key, value in changed.items() if key not in {
            "trace_id", "trace_sha256",
        }}
        changed["trace_id"], changed["trace_sha256"] = _identity(body)
        forged = OfflineComposedMissionTrace.from_dict(changed)
        self.audit.snapshot.reset_mock()
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "expected identities"):
            self.recheck(forged)
        self.audit.snapshot.assert_not_called()
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "expected identities"):
            self.recheck(trace, expected_workspace_id="other-workspace")
        self.audit.snapshot.assert_not_called()
        changed = trace.to_dict()
        changed["workspace_observation"]["status"] = "complete"
        body = {key: value for key, value in changed.items() if key not in {
            "trace_id", "trace_sha256",
        }}
        changed["trace_id"], changed["trace_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "observations changed"):
            self.recheck(OfflineComposedMissionTrace.from_dict(changed))

    def test_recheck_does_not_write_real_journal(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        journal_path = Path(temporary.name) / "journal.sqlite3"
        self.journal = SQLiteOrchestrationJournal(journal_path)
        trace = self.capture()
        before = journal_path.read_bytes()
        report = self.recheck(trace)
        self.assertEqual(before, journal_path.read_bytes())
        self.assertFalse(report["effects"]["target_action_performed"])

    def test_binds_matching_observations_without_authority(self) -> None:
        trace = self.capture()
        self.assertEqual(OfflineComposedMissionTrace.from_json(trace.document_json), trace)
        document = trace.to_dict()
        self.assertEqual(document["cross_store_consistency"], "not_proven")
        self.assertEqual(document["effects"]["action_authority"], "none")
        self.assertEqual(document["effects"]["target_action_performed"], False)
        self.assertEqual(
            [job["job_id"] for job in document["job_observations"]],
            ["JOB-001", "JOB-003"],
        )
        self.assertEqual(document["mission_observation"]["mission_id"], MISSION_ID)
        self.assertEqual(document["workspace_observation"]["mission_id"], MISSION_ID)
        self.assertEqual(self.audit.snapshot.call_count, 2)
        self.assertEqual(self.workspace_store.verify_store.call_count, 2)
        self.assertEqual(self.journal.verify.call_count, 2)
        self.assertEqual(self.journal.list_jobs.call_count, 2)

    def test_rejects_workspace_mission_substitution(self) -> None:
        self.workspace_store.get_workspace.return_value = ExpertWorkspaceState(
            WORKSPACE_ID, TENANT_ID, "different-mission", "plan-test", 4, "active", 2, 0
        )
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "workspace"):
            self.capture()
        self.journal.verify.assert_not_called()

    def test_rejects_mission_audit_substitution(self) -> None:
        self.audit.snapshot.return_value = _audit_receipt("different-mission")
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "mission audit"):
            self.capture()
        self.workspace_store.verify_store.assert_not_called()

    def test_rejects_cross_tenant_job(self) -> None:
        self.journal.list_jobs.return_value = (_job("JOB-001", MISSION_ID, "other-tenant"),)
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "tenant"):
            self.capture()

    def test_rejects_invalid_local_integrity(self) -> None:
        self.journal.verify.return_value = {"status": "invalid"}
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "journal"):
            self.capture()

    def test_rejects_mission_head_change_during_capture(self) -> None:
        self.audit.snapshot.side_effect = [_audit_receipt(), _audit_receipt(revision=4)]
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "mission changed"):
            self.capture()

    def test_rejects_workspace_store_change_during_capture(self) -> None:
        self.workspace_store.verify_store.side_effect = [
            self.workspace_store.verify_store.return_value,
            ExpertWorkspaceVerificationReport("valid", 1, 1, 2, 0, 0, 2, "sha256:" + "d" * 64),
        ]
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "workspace changed"):
            self.capture()

    def test_rejects_workspace_state_change_during_capture(self) -> None:
        self.workspace_store.get_workspace.side_effect = [
            self.workspace_store.get_workspace.return_value,
            ExpertWorkspaceState(
                WORKSPACE_ID, TENANT_ID, MISSION_ID, "plan-test", 5, "active", 2, 1
            ),
        ]
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "workspace changed"):
            self.capture()

    def test_rejects_journal_event_or_count_change_during_capture(self) -> None:
        original = self.journal.verify.return_value
        for changed in (
            {**original, "event_count": original["event_count"] + 1},
            {**original, "counts": {"jobs": 4}},
        ):
            with self.subTest(changed=changed):
                self.journal.verify.side_effect = [original, changed]
                with self.assertRaisesRegex(OfflineComposedMissionTraceError, "journal changed"):
                    self.capture()
                self.journal.verify.reset_mock(side_effect=True)

    def test_rejects_relevant_job_change_during_capture(self) -> None:
        changed = _job("JOB-001", MISSION_ID)
        changed.state = SimpleNamespace(value="leased")
        self.journal.list_jobs.side_effect = [
            (_job("JOB-001", MISSION_ID),),
            (changed,),
        ]
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "journal changed"):
            self.capture()

    def test_rejects_tampered_content_address(self) -> None:
        document = self.capture().to_dict()
        document["workspace_observation"]["status"] = "complete"
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "content address"):
            OfflineComposedMissionTrace.from_dict(document)

    def test_recomputed_hash_cannot_rebind_workspace_or_job(self) -> None:
        original = self.capture().to_dict()
        for mutation in ("workspace", "job"):
            with self.subTest(mutation=mutation):
                document = json.loads(canonical_json(original))
                if mutation == "workspace":
                    document["workspace_observation"]["mission_id"] = "other-mission"
                else:
                    document["job_observations"][0]["tenant_id"] = "other-tenant"
                body = {
                    key: value for key, value in document.items()
                    if key not in {"trace_id", "trace_sha256"}
                }
                document["trace_id"], document["trace_sha256"] = _identity(body)
                with self.assertRaises(OfflineComposedMissionTraceError):
                    OfflineComposedMissionTrace.from_dict(document)

    def test_rejects_noncanonical_document(self) -> None:
        trace = self.capture()
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "canonical"):
            OfflineComposedMissionTrace.from_json(canonical_json(trace.to_dict()) + " ")

    def test_reads_real_empty_orchestration_journal(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.journal = SQLiteOrchestrationJournal(Path(temporary.name) / "journal.sqlite3")
        trace = self.capture().to_dict()
        self.assertEqual(trace["job_observations"], [])
        self.assertEqual(trace["cross_store_consistency"], "not_proven")

    def test_reads_real_workspace_and_journal(self) -> None:
        phase191.ExpertWorkspacePhase191Tests.setUpClass()
        fixture = phase191.ExpertWorkspacePhase191Tests(
            methodName="test_public_exports_and_adapter_protocol"
        )
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        state = fixture.create(
            fixture.definition(tenant_id=TENANT_ID, mission_id=MISSION_ID)
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        journal = SQLiteOrchestrationJournal(Path(temporary.name) / "journal.sqlite3")
        trace = capture_offline_composed_mission_trace(
            mission_audit=self.audit,
            workspace_store=fixture.store,
            orchestration_journal=journal,
            runtime_catalog=fixture.catalog,
            expert_registry=None,
            tenant_id=TENANT_ID,
            mission_id=MISSION_ID,
            workspace_id=state.workspace_id,
        ).to_dict()
        self.assertEqual(trace["workspace_observation"]["workspace_id"], state.workspace_id)
        self.assertEqual(trace["workspace_observation"]["revision"], state.revision)
        self.assertEqual(trace["job_observations"], [])

    def test_reads_three_real_local_stores_without_action_effect(self) -> None:
        phase19.MissionAuditSnapshotPhase19Tests.setUpClass()
        mission_fixture = phase19.MissionAuditSnapshotPhase19Tests(
            methodName="test_snapshot_is_deterministic_self_identifying_and_read_only"
        )
        mission_fixture.setUp()
        self.addCleanup(mission_fixture.doCleanups)

        phase191.ExpertWorkspacePhase191Tests.setUpClass()
        workspace_fixture = phase191.ExpertWorkspacePhase191Tests(
            methodName="test_public_exports_and_adapter_protocol"
        )
        workspace_fixture.setUp()
        self.addCleanup(workspace_fixture.tearDown)
        state = workspace_fixture.create(
            workspace_fixture.definition(tenant_id=TENANT_ID, mission_id=phase19.MISSION_ID)
        )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        journal = SQLiteOrchestrationJournal(Path(temporary.name) / "journal.sqlite3")
        trace = capture_offline_composed_mission_trace(
            mission_audit=mission_fixture.service,
            workspace_store=workspace_fixture.store,
            orchestration_journal=journal,
            runtime_catalog=workspace_fixture.catalog,
            expert_registry=mission_fixture.registry,
            tenant_id=TENANT_ID,
            mission_id=phase19.MISSION_ID,
            workspace_id=state.workspace_id,
        ).to_dict()
        self.assertEqual(trace["mission_observation"]["mission_id"], phase19.MISSION_ID)
        self.assertEqual(trace["workspace_observation"]["mission_id"], phase19.MISSION_ID)
        self.assertEqual(trace["effects"]["target_action_performed"], False)

    def test_bounded_scan_fails_closed(self) -> None:
        self.journal.list_jobs.side_effect = [
            tuple(
                _job(f"JOB-{number:04d}", "other-mission")
                for number in range(start, start + 200)
            )
            for start in range(0, 1000, 200)
        ] + [(_job("JOB-1000", "other-mission"),)]
        with self.assertRaisesRegex(OfflineComposedMissionTraceError, "scan exceeds"):
            self.capture()

    def test_exact_scan_bound_keeps_late_matching_job(self) -> None:
        pages = [
            tuple(
                _job(
                    f"JOB-{number:04d}",
                    WORKSPACE_ID if number == 999 else "other-mission",
                )
                for number in range(start, start + 200)
            )
            for start in range(0, 1000, 200)
        ] + [()]
        self.journal.list_jobs.side_effect = pages + pages
        trace = self.capture().to_dict()
        self.assertEqual(
            [item["job_id"] for item in trace["job_observations"]], ["JOB-0999"]
        )
        self.assertEqual(self.journal.list_jobs.call_count, 12)


if __name__ == "__main__":
    unittest.main()

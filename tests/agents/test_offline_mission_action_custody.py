"""Focused historical, redacted MissionStore action custody tests."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from sunderkey.authenticated_action_admission import review_record_set_sha256
from sunderkey.authenticated_expert_review import expert_workspace_review_revoke_intent
from sunderkey.offline_mission_action_custody import (
    MAX_SNAPSHOT_JSON_BYTES,
    OfflineMissionActionCustodyError,
    OfflineMissionActionCustodySnapshot,
    _identity,
    capture_offline_mission_action_custody,
    verify_offline_mission_action_custody_snapshot,
)

from . import test_mission_store_action_admission_phase195b as phase195b
from . import test_mission_store_action_executor_phase196b as phase196b


class OfflineMissionActionCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase195b.MissionStoreActionAdmissionPhase195bTests.setUpClass()

    def _admission_fixture(self):  # type: ignore[no-untyped-def]
        fixture = phase195b.MissionStoreActionAdmissionPhase195bTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def _execution_fixture(self):  # type: ignore[no-untyped-def]
        fixture = phase196b.MissionStoreActionExecutorPhase196bTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def test_empty_history_denies_without_disclosing_mission_head(self) -> None:
        fixture = self._admission_fixture()
        before = fixture.store.path.read_bytes()
        with self.assertRaises(OfflineMissionActionCustodyError) as empty:
            capture_offline_mission_action_custody(
                fixture.store, fixture.registry, fixture.mission_id,
                expected_tenant_id=phase195b.TENANT_ID,
            )
        with self.assertRaises(OfflineMissionActionCustodyError) as missing:
            capture_offline_mission_action_custody(
                fixture.store, fixture.registry, "MIS-NOT-PRESENT",
                expected_tenant_id=phase195b.TENANT_ID,
            )
        self.assertEqual(str(empty.exception), str(missing.exception))
        self.assertIn("unavailable for expected tenant", str(empty.exception))
        self.assertEqual(fixture.store.path.read_bytes(), before)

    def test_admitted_receipt_is_not_mistaken_for_execution(self) -> None:
        fixture = self._admission_fixture()
        sources, _, _, _, _, receipt = fixture._admit_complete_sources()
        snapshot = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        document = snapshot.to_dict()
        self.assertEqual(document["schema_version"], 3)
        self.assertEqual(document["receipt_count"], 1)
        self.assertEqual(document["receipts"][0]["receipt_id"], receipt.receipt_id)
        summary = document["receipts"][0]
        self.assertEqual(summary["proposal_import_id"], sources["proposal"].proposal_import_id)
        self.assertEqual(summary["proposal_product_id"], fixture.product.product_id)
        self.assertEqual(summary["origin_workspace_id"], fixture.workspace_state.workspace_id)
        self.assertEqual(
            summary["origin_workspace_sha256"], fixture.snapshot.to_dict()["workspace_sha256"]
        )
        self.assertEqual(summary["origin_plan_id"], fixture.plan.plan_id)
        self.assertEqual(summary["origin_work_id"], fixture.product.to_dict()["work_id"])
        self.assertEqual(summary["review_snapshot_id"], fixture.snapshot.snapshot_id)
        self.assertEqual(
            summary["review_closure_id"], fixture.review_proof.records.closure.closure_id
        )
        self.assertEqual(
            summary["admission_review_evidence_sha256"],
            review_record_set_sha256(fixture.review_proof.records),
        )
        self.assertEqual(summary["review_revocation_status"], "not_recorded")
        self.assertIsNone(summary["review_revocation_id"])
        self.assertEqual(
            document["receipts"][0]["execution_state"], "admitted_without_execution"
        )
        self.assertIsNone(document["receipts"][0]["terminal_id"])
        self.assertNotIn("adapter_input", snapshot.document_json)
        self.assertNotIn("authorization_json", snapshot.document_json)
        self.assertNotIn("reviewer_subject", snapshot.document_json)
        self.assertNotIn("rationale", snapshot.document_json)

    def test_later_review_revocation_is_visible_without_rewriting_admission(self) -> None:
        fixture = self._admission_fixture()
        fixture._admit_complete_sources()
        before = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        closure = fixture.review_proof.records.closure
        reason_code = "control-revocation"
        intent = expert_workspace_review_revoke_intent(
            closure,
            active_plan_id=fixture.plan.plan_id,
            active_plan_sha256=fixture.plan.content_sha256,
            active_plan_version=1,
            mission_id=fixture.mission_id,
            mission_revision=fixture.root.stored.revision,
            principal_profile_id=fixture.control_profile,
            reason_code=reason_code,
        )
        assertion = fixture._assertion(
            "control", "91", phase195b.PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
            intent,
        )
        fixture.root.now = datetime(2026, 7, 30, 10, 13, 4, tzinfo=UTC)
        revocation = fixture.review.revoke_closure(
            assertion,
            closure.closure_id,
            reason_code=reason_code,
            workspace_store=fixture.workspace,
            runtime_catalog=fixture.catalog,
        )
        after = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        summary = after.to_dict()["receipts"][0]
        self.assertEqual(summary["review_revocation_status"], "recorded")
        self.assertEqual(
            summary["review_revocation_id"], revocation.records.revocation.revocation_id
        )
        self.assertEqual(
            summary["review_revocation_sha256"],
            revocation.records.revocation.revocation_sha256,
        )
        self.assertEqual(
            summary["admission_review_evidence_sha256"],
            before.to_dict()["receipts"][0]["admission_review_evidence_sha256"],
        )
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "does not match"):
            verify_offline_mission_action_custody_snapshot(
                before, fixture.store, fixture.registry,
                expected_tenant_id=phase195b.TENANT_ID,
            )

    def test_completed_action_exports_only_redacted_outcome(self) -> None:
        fixture = self._execution_fixture()
        terminal = fixture.service.execute(
            fixture.command, fixture.request, fixture.assertion, fixture.authorization
        )
        before = fixture.fixture.store.path.read_bytes()
        snapshot = capture_offline_mission_action_custody(
            fixture.fixture.store, fixture.fixture.registry, fixture.fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        self.assertEqual(fixture.fixture.store.path.read_bytes(), before)
        summary = snapshot.to_dict()["receipts"][0]
        self.assertEqual(summary["terminal_id"], terminal.terminal_id)
        self.assertEqual(summary["execution_state"], "completed")
        self.assertEqual(summary["action_outcome"], "succeeded")
        self.assertEqual(summary["evidence_status"], "complete")
        self.assertNotIn("result_document", snapshot.document_json)
        self.assertNotIn("adapter_input", snapshot.document_json)
        self.assertNotIn("assertion_id", snapshot.document_json)
        altered = snapshot.to_dict()
        altered["receipts"][0]["action_outcome"] = "indeterminate"
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "inconsistent"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)
        for status, outcome in (
            ("failed_known", "failed"),
            ("predispatch_aborted", "failed"),
            ("indeterminate_quarantined", "indeterminate"),
        ):
            with self.subTest(status=status):
                variant = snapshot.to_dict()
                variant["receipts"][0]["terminal_status"] = status
                variant["receipts"][0]["execution_state"] = status
                variant["receipts"][0]["action_outcome"] = outcome
                body = {
                    key: value for key, value in variant.items()
                    if key not in {"snapshot_id", "snapshot_sha256"}
                }
                variant["snapshot_id"], variant["snapshot_sha256"] = _identity(body)
                OfflineMissionActionCustodySnapshot.from_dict(variant)
                variant["receipts"][0]["action_outcome"] = "succeeded"
                with self.assertRaisesRegex(OfflineMissionActionCustodyError, "inconsistent"):
                    OfflineMissionActionCustodySnapshot.from_dict(variant)

    def test_rejects_unknown_mission_and_reduced_scan_bound(self) -> None:
        fixture = self._admission_fixture()
        with self.assertRaisesRegex(
            OfflineMissionActionCustodyError, "unavailable for expected tenant"
        ):
            capture_offline_mission_action_custody(
                fixture.store, fixture.registry, "MIS-NOT-PRESENT",
                expected_tenant_id=phase195b.TENANT_ID,
            )
        fixture._admit_complete_sources()
        with (
            patch("sunderkey.offline_mission_action_custody.MAX_RECEIPTS", 0),
            self.assertRaisesRegex(OfflineMissionActionCustodyError, "exceeds the bound"),
        ):
            capture_offline_mission_action_custody(
                fixture.store, fixture.registry, fixture.mission_id,
                expected_tenant_id=phase195b.TENANT_ID,
            )

    def test_rejects_recomputed_inconsistent_summary_and_noncanonical_json(self) -> None:
        fixture = self._admission_fixture()
        fixture._admit_complete_sources()
        snapshot = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        raw = snapshot.to_dict()
        raw["receipts"][0]["terminal_status"] = "completed"
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "unexecuted receipt"):
            OfflineMissionActionCustodySnapshot.from_dict(raw)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "canonical"):
            OfflineMissionActionCustodySnapshot.from_json(snapshot.document_json + " ")
        altered = json.loads(snapshot.document_json)
        altered["receipts"][0]["receipt_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "content address"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)
        altered = snapshot.to_dict()
        altered["receipts"][0]["review_revocation_status"] = "recorded"
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "review revocation status"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)
        altered = snapshot.to_dict()
        altered["receipts"][0]["review_revocation_id"] = "ERRV-FAKE"
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "binding is incomplete"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)
        altered = snapshot.to_dict()
        altered["effects"]["target_action_performed"] = 0
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "boundary"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)

    def test_recomputed_forgery_parses_but_fails_fresh_source_verification(self) -> None:
        fixture = self._admission_fixture()
        fixture._admit_complete_sources()
        authentic = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        verify_offline_mission_action_custody_snapshot(
            authentic, fixture.store, fixture.registry,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        altered = authentic.to_dict()
        altered["mission_head_sha256"] = "sha256:" + "f" * 64
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        forged = OfflineMissionActionCustodySnapshot.from_dict(altered)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "does not match"):
            verify_offline_mission_action_custody_snapshot(
                forged, fixture.store, fixture.registry,
                expected_tenant_id=phase195b.TENANT_ID,
            )
        altered = authentic.to_dict()
        altered["receipts"][0]["review_closure_sha256"] = "sha256:" + "f" * 64
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        forged_lineage = OfflineMissionActionCustodySnapshot.from_dict(altered)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "does not match"):
            verify_offline_mission_action_custody_snapshot(
                forged_lineage, fixture.store, fixture.registry,
                expected_tenant_id=phase195b.TENANT_ID,
            )

    def test_old_snapshot_fails_after_execution_terminal(self) -> None:
        fixture = self._execution_fixture()
        before = capture_offline_mission_action_custody(
            fixture.fixture.store, fixture.fixture.registry, fixture.fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        fixture.service.execute(
            fixture.command, fixture.request, fixture.assertion, fixture.authorization
        )
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "does not match"):
            verify_offline_mission_action_custody_snapshot(
                before, fixture.fixture.store, fixture.fixture.registry,
                expected_tenant_id=phase195b.TENANT_ID,
            )

    def test_expected_tenant_rejects_same_mission_other_tenant_receipt(self) -> None:
        fixture = self._admission_fixture()
        fixture._admit_complete_sources()
        with self.assertRaisesRegex(
            OfflineMissionActionCustodyError, "unavailable for expected tenant"
        ):
            capture_offline_mission_action_custody(
                fixture.store, fixture.registry, fixture.mission_id,
                expected_tenant_id="tenant:other",
            )
        authentic = capture_offline_mission_action_custody(
            fixture.store, fixture.registry, fixture.mission_id,
            expected_tenant_id=phase195b.TENANT_ID,
        )
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "tenant boundary"):
            verify_offline_mission_action_custody_snapshot(
                authentic, fixture.store, fixture.registry,
                expected_tenant_id="tenant:other",
            )
        altered = authentic.to_dict()
        altered["receipts"][0]["tenant_id"] = "tenant:other"
        body = {
            key: value for key, value in altered.items()
            if key not in {"snapshot_id", "snapshot_sha256"}
        }
        altered["snapshot_id"], altered["snapshot_sha256"] = _identity(body)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "tenant boundary"):
            OfflineMissionActionCustodySnapshot.from_dict(altered)

    def test_rejects_oversized_json_before_parsing(self) -> None:
        oversized = "x" * (MAX_SNAPSHOT_JSON_BYTES + 1)
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "byte bound"):
            OfflineMissionActionCustodySnapshot.from_json(oversized)

    def test_rejects_deep_json_without_raw_recursion_error(self) -> None:
        nested = "[" * 20_000 + "0" + "]" * 20_000
        with self.assertRaisesRegex(OfflineMissionActionCustodyError, "document is invalid"):
            OfflineMissionActionCustodySnapshot.from_json(nested)


if __name__ == "__main__":
    unittest.main()

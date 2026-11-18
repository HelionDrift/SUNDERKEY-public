from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from scripts.build_expert_review import (
    expert_review_record_schema,
    expert_workspace_closure_application_schema,
)
from scripts.build_expert_runtime import load_sources
from sunderkey.errors import StoreConflictError, StoreError, StoreIntegrityError
from sunderkey.expert_review import (
    MAX_RECORD_BYTES,
    ClosureDisposition,
    ExpertReviewRecordSet,
    ReconciliationStatus,
    ReviewDecision,
    ReviewerRole,
    build_authenticated_expert_review_receipt,
    build_expert_review_closure_certificate,
    build_expert_review_closure_request,
    build_expert_review_closure_revocation,
    build_expert_review_snapshot,
    build_expert_review_submission,
    build_expert_workspace_closure_application,
    derive_reviewer_role,
    parse_authenticated_expert_review_receipt,
    parse_expert_review_submission,
    review_set_sha256,
    verify_expert_review_record_set,
)
from sunderkey.expert_runtime import (
    build_execution_envelope,
    content_address_work_product,
    load_runtime_pack_catalog,
    parse_execution_envelope,
)
from sunderkey.expert_workspace import (
    _SCHEMA_SQL_V1,
    APPLICATION_ID,
    SCHEMA_VERSION,
    SQLiteExpertWorkspaceStore,
    _event_document,
    build_expert_workspace_definition,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.registry import load_registry

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "registry" / "expert-runtime-packs-army-v2.json"
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
ZERO_HASH = "sha256:" + "0" * 64
ONE_HASH = "sha256:" + "1" * 64
TWO_HASH = "sha256:" + "2" * 64
THREE_HASH = "sha256:" + "3" * 64
FOUR_HASH = "sha256:" + "4" * 64


class ExpertReviewPhase194Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_runtime_pack_catalog(CATALOG_PATH, *load_sources())
        cls.registry = load_registry(REGISTRY_PATH)
        cls.pack = cls.catalog.packs_by_profile_id["AOE-GA-D01-S01"]

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "workspace.sqlite3"
        self.store = SQLiteExpertWorkspaceStore(self.path)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _complete_workspace(self) -> object:
        definition = build_expert_workspace_definition(
            self.catalog,
            tenant_id="tenant-194",
            mission_id="mission-194",
            plan_id="plan-194",
            target_scope_sha256=ZERO_HASH,
            authority_snapshot_sha256=ONE_HASH,
            evidence_snapshot_sha256=TWO_HASH,
            assignments=[
                {
                    "work_id": "work-specialist",
                    "profile_id": self.pack["profile_id"],
                    "command_id": self.pack["command_id"],
                    "runtime_pack_id": self.pack["runtime_pack_id"],
                    "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
                    "maximum_attempts": 2,
                }
            ],
            dependencies=[],
            review_requirements=[
                {
                    "work_id": "work-specialist",
                    "required": True,
                    "reviewer_profile_ids": ["AOE-HQ-18"],
                    "producer_excluded": True,
                }
            ],
        )
        state = self.store.create_workspace(definition, self.catalog, created_at=100)
        envelope = build_execution_envelope(
            self.pack,
            self.catalog,
            mission_id="mission-194",
            plan_id="plan-194",
            work_id="work-specialist",
            target_scope_sha256=ZERO_HASH,
            authority_snapshot_sha256=ONE_HASH,
            evidence_snapshot_sha256=TWO_HASH,
            evidence_requirement_ids=["evidence-194"],
            cleanup_requirement_ids=["cleanup-194"],
            approval_requirement_ids=["approval-194"],
            context_items=[
                {
                    "context_id": "context-194",
                    "context_kind": "target_content",
                    "content": "Bounded evidence.",
                    "content_sha256": _canonical_sha256("Bounded evidence."),
                    "estimated_tokens": 17,
                    "trust": "untrusted_data",
                }
            ],
        )
        parsed_envelope = parse_execution_envelope(envelope, self.pack, self.catalog)
        lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-194",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        product = content_address_work_product(
            {
                "schema_version": 1,
                "product_type": "observation",
                "runtime_catalog_sha256": self.catalog.catalog_sha256,
                "runtime_pack_id": self.pack["runtime_pack_id"],
                "runtime_pack_sha256": self.pack["runtime_pack_sha256"],
                "producer_profile_id": self.pack["profile_id"],
                "execution_envelope_id": parsed_envelope.envelope_id,
                "execution_envelope_sha256": parsed_envelope.envelope_sha256,
                "mission_id": "mission-194",
                "plan_id": "plan-194",
                "work_id": "work-specialist",
                "summary": "Bounded advisory observation.",
                "confidence": "moderate",
                "uncertainty": "Independent review is pending.",
                "evidence_refs": [TWO_HASH],
                "lineage_product_ids": [],
                "independent_review": {
                    "required": True,
                    "status": "not_reviewed",
                    "reviewer_profile_ids": [],
                    "producer_excluded": True,
                },
                "payload": {
                    "observed_facts": ["Fact."],
                    "collection_limits": ["Limit."],
                },
                "model_output_effect": "advisory_only",
                "tool_effect": "none",
                "authorization_effect": "none",
            }
        )
        self.store.accept_work_product(
            state.workspace_id,
            tenant_id="tenant-194",
            expected_revision=lease.workspace_revision,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=120,
        )
        return state

    def _records(
        self,
        *,
        revoke: bool = False,
        decision: ReviewDecision = ReviewDecision.ACCEPTED,
        affected_work_ids: tuple[str, ...] | None = None,
        required_correction_ids: tuple[str, ...] | None = None,
        recorded_at: int = 130,
        requested_at: int = 140,
        closed_at: int = 150,
        revoked_at: int = 170,
        closure_replay_key_sha256: str = THREE_HASH,
        revocation_replay_key_sha256: str = FOUR_HASH,
    ) -> ExpertReviewRecordSet:
        snapshot = getattr(self, "_review_snapshot", None)
        if snapshot is None:
            state = self._complete_workspace()
            snapshot = self.store.export_review_snapshot(
                state.workspace_id,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
            )
            self._review_snapshot = snapshot
        slot = snapshot.to_dict()["review_slots"][0]
        submission = build_expert_review_submission(
            snapshot=snapshot,
            work_id=slot["work_id"],
            product_id=slot["product_id"],
            product_sha256=slot["product_sha256"],
            reviewer_profile_id=slot["reviewer_profile_id"],
            reviewer_role=slot["reviewer_role"],
            decision=decision,
            reason_code="evidence-sufficient",
            affected_work_ids=(
                affected_work_ids
                if affected_work_ids is not None
                else ((slot["work_id"],) if decision is ReviewDecision.REWORK_REQUIRED else ())
            ),
            required_correction_ids=(
                required_correction_ids
                if required_correction_ids is not None
                else (("correction-194",) if decision is ReviewDecision.REWORK_REQUIRED else ())
            ),
            rationale="The bounded evidence supports the advisory observation.",
        )
        receipt = build_authenticated_expert_review_receipt(
            submission,
            reviewer_subject="reviewer-subject-194",
            assertion_issuer="identity-issuer-194",
            assertion_id="assertion-review-194",
            assertion_sha256=ZERO_HASH,
            assertion_key_sha256=ONE_HASH,
            trust_policy_sha256=TWO_HASH,
            scope_grant_sha256=ZERO_HASH,
            operation_intent_sha256=ONE_HASH,
            canonical_replay_key_sha256=TWO_HASH,
            recorded_at=recorded_at,
        )
        request = build_expert_review_closure_request(
            snapshot,
            (receipt,),
            expected_disposition=ClosureDisposition(decision.value),
            closer_profile_id="AOE-HQ-12",
            requested_at=requested_at,
        )
        closure = build_expert_review_closure_certificate(
            request,
            review_receipt_ids=[receipt.receipt_id],
            review_set_sha256=review_set_sha256((receipt,)),
            disposition=ClosureDisposition(decision.value),
            rejected_work_ids=([slot["work_id"]] if decision is ReviewDecision.REJECTED else []),
            rework_work_ids=(
                [slot["work_id"]] if decision is ReviewDecision.REWORK_REQUIRED else []
            ),
            required_correction_ids=(
                ["correction-194"] if decision is ReviewDecision.REWORK_REQUIRED else []
            ),
            closer_subject="control-subject-194",
            closer_profile_id="AOE-HQ-12",
            assertion_issuer="identity-issuer-194",
            assertion_id="assertion-close-194",
            assertion_sha256=ZERO_HASH,
            assertion_key_sha256=ONE_HASH,
            trust_policy_sha256=TWO_HASH,
            scope_grant_sha256=ZERO_HASH,
            operation_intent_sha256=ONE_HASH,
            canonical_replay_key_sha256=closure_replay_key_sha256,
            closed_at=closed_at,
        )
        revocation = (
            build_expert_review_closure_revocation(
                closure,
                reason_code="control-revocation",
                control_subject="revoker-subject-194",
                control_profile_id="AOE-HQ-12",
                assertion_issuer="identity-issuer-194",
                assertion_id="assertion-revoke-194",
                assertion_sha256=ZERO_HASH,
                operation_intent_sha256=ONE_HASH,
                canonical_replay_key_sha256=revocation_replay_key_sha256,
                revoked_at=revoked_at,
            )
            if revoke
            else None
        )
        return ExpertReviewRecordSet(snapshot, (receipt,), request, closure, revocation)

    def test_exact_registry_role_derivation_and_quorum_fail_closed(self) -> None:
        self.assertEqual(
            derive_reviewer_role(self.registry, "AOE-HQ-12")["reviewer_role"],
            ReviewerRole.INDEPENDENT_CONTROL.value,
        )
        self.assertEqual(
            derive_reviewer_role(self.registry, "AOE-HQ-18")["reviewer_role"],
            ReviewerRole.INDEPENDENT_ASSURANCE.value,
        )
        records = self._records()
        with self.assertRaisesRegex(StoreError, "every mandatory slot"):
            verify_expert_review_record_set(
                ExpertReviewRecordSet(
                    records.snapshot,
                    (),
                    records.closure_request,
                    records.closure,
                ),
                self.registry,
            )

    def test_record_set_chronology_fails_closed(self) -> None:
        cases = (
            (self._records(recorded_at=119), "receipt predates the snapshot"),
            (self._records(requested_at=129), "request predates"),
            (self._records(closed_at=139), "certificate predates"),
            (self._records(revoke=True, revoked_at=149), "revocation predates"),
        )
        for records, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(StoreError, message):
                verify_expert_review_record_set(records, self.registry)

    def test_rework_scope_and_replay_identity_fail_closed(self) -> None:
        with self.assertRaisesRegex(StoreError, "outside the snapshot"):
            verify_expert_review_record_set(
                self._records(
                    decision=ReviewDecision.REWORK_REQUIRED,
                    affected_work_ids=("work-outside-snapshot",),
                ),
                self.registry,
            )
        with self.assertRaisesRegex(StoreError, "at least one correction"):
            verify_expert_review_record_set(
                self._records(
                    decision=ReviewDecision.REWORK_REQUIRED,
                    required_correction_ids=(),
                ),
                self.registry,
            )
        with self.assertRaisesRegex(StoreError, "cannot carry rework"):
            verify_expert_review_record_set(
                self._records(
                    affected_work_ids=("work-specialist",),
                    required_correction_ids=("correction-194",),
                ),
                self.registry,
            )
        with self.assertRaisesRegex(StoreError, "replay identity is reused"):
            verify_expert_review_record_set(
                self._records(closure_replay_key_sha256=TWO_HASH),
                self.registry,
            )

    def test_snapshot_producer_separation_and_registry_substitution_fail(self) -> None:
        records = self._records()
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        body["review_slots"][0]["producer_profile_ids_excluded"] = ["AOE-HQ-01"]
        with self.assertRaisesRegex(StoreError, "producer separation"):
            build_expert_review_snapshot(body, self.registry)
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        body["review_slots"][0]["reviewer_role"] = "independent_control"
        with self.assertRaisesRegex(StoreError, "role derivation"):
            build_expert_review_snapshot(body, self.registry)
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        body["products"][0]["product_type"] = "action_proposal"
        with self.assertRaisesRegex(StoreError, "independent Control"):
            build_expert_review_snapshot(body, self.registry)
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        body["products"][0]["producer_profile_id"] = "AOE-HQ-99"
        with self.assertRaisesRegex(StoreError, "exact Army registry"):
            build_expert_review_snapshot(body, self.registry)
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        body["products"][0]["command_id"] = "AOE-GA-D02"
        with self.assertRaisesRegex(StoreError, "command binding"):
            build_expert_review_snapshot(body, self.registry)

    def test_commander_review_excludes_transitive_lineage_producers(self) -> None:
        records = self._records()
        body = records.snapshot.to_dict()
        body.pop("snapshot_id")
        body.pop("snapshot_sha256")
        base = body["products"][0]
        middle = {
            "work_id": "work-middle",
            "producer_profile_id": "AOE-GA-D01-CMD",
            "command_id": "AOE-GA-D01",
            "product_id": "product-middle",
            "product_sha256": ONE_HASH,
            "product_type": "commander_synthesis",
            "envelope_id": "envelope-middle",
            "envelope_sha256": TWO_HASH,
            "attempt_number": 1,
            "fencing_token": 1,
            "review_required": False,
            "dependency_product_ids": [base["product_id"]],
            "lineage_product_ids": [base["product_id"]],
            "disagreement_sha256s": [],
        }
        top = {
            "work_id": "work-top",
            "producer_profile_id": "AOE-GA-D01-CMD",
            "command_id": "AOE-GA-D01",
            "product_id": "product-top",
            "product_sha256": TWO_HASH,
            "product_type": "commander_synthesis",
            "envelope_id": "envelope-top",
            "envelope_sha256": THREE_HASH,
            "attempt_number": 1,
            "fencing_token": 1,
            "review_required": True,
            "dependency_product_ids": [middle["product_id"]],
            "lineage_product_ids": [middle["product_id"]],
            "disagreement_sha256s": [],
        }
        body["products"].extend((middle, top))
        body["products"].sort(key=lambda item: item["work_id"])
        direct_only = ["AOE-GA-D01-CMD"]
        for reviewer_id in ("AOE-HQ-12", "AOE-HQ-18"):
            body["review_slots"].append(
                {
                    "work_id": top["work_id"],
                    "product_id": top["product_id"],
                    "product_sha256": top["product_sha256"],
                    **derive_reviewer_role(self.registry, reviewer_id),
                    "producer_profile_ids_excluded": direct_only,
                }
            )
        body["review_slots"].sort(key=lambda item: (item["work_id"], item["reviewer_profile_id"]))
        with self.assertRaisesRegex(StoreError, "producer separation"):
            build_expert_review_snapshot(body, self.registry)
        excluded = sorted((*direct_only, base["producer_profile_id"]))
        for slot in body["review_slots"]:
            if slot["work_id"] == top["work_id"]:
                slot["producer_profile_ids_excluded"] = excluded
        build_expert_review_snapshot(body, self.registry)

    def test_canonical_json_and_deep_copy_boundaries(self) -> None:
        records = self._records()
        submission = records.receipts[0].to_dict()["submission"]
        parsed = parse_expert_review_submission(submission)
        external = parsed.to_dict()
        external["rationale"] = "mutated"
        self.assertNotEqual(parsed.to_dict()["rationale"], external["rationale"])
        with self.assertRaisesRegex(StoreError, "not canonical"):
            parse_expert_review_submission(json.dumps(submission, indent=2))
        duplicated = parsed.document_json.replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaisesRegex(StoreError, "JSON is invalid"):
            parse_expert_review_submission(duplicated)
        with self.assertRaisesRegex(StoreError, "byte ceiling"):
            parse_expert_review_submission("x" * (MAX_RECORD_BYTES + 1))
        hidden = parsed.to_dict()
        hidden["rationale"] = "hidden\u200btext"
        with self.assertRaisesRegex(StoreError, "invalid text"):
            parse_expert_review_submission(hidden)
        control = parsed.to_dict()
        control["rationale"] = "control\x00text"
        with self.assertRaisesRegex(StoreError, "invalid text"):
            parse_expert_review_submission(control)
        boolean_time = records.receipts[0].to_dict()
        boolean_time["recorded_at"] = True
        with self.assertRaisesRegex(StoreError, "recorded_at is invalid"):
            parse_authenticated_expert_review_receipt(boolean_time)

    def test_projection_replay_restart_reconciliation_and_revocation(self) -> None:
        records = self._records(revoke=True)
        pending = self.store.reconcile_review_records(records, expert_registry=self.registry)
        self.assertEqual(
            pending.status,
            ReconciliationStatus.CLOSURE_PENDING_WORKSPACE_APPLICATION,
        )
        application = self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        replay = self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=999,
        )
        self.assertEqual(application, replay)
        with self.assertRaisesRegex(StoreConflictError, "conflicts"):
            self.store._apply_review_closure_records(
                records,
                mission_store_id="mission-store-other",
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=161,
            )
        self.assertEqual(
            self.store.reconcile_review_records(records, expert_registry=self.registry).status,
            ReconciliationStatus.REVOCATION_PENDING_WORKSPACE_APPLICATION,
        )
        revocation = self.store._apply_review_closure_revocation_records(
            records,
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=170,
        )
        self.assertEqual(
            revocation,
            self.store._apply_review_closure_revocation_records(
                records,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=999,
            ),
        )
        self.assertEqual(
            application,
            self.store._apply_review_closure_records(
                records,
                mission_store_id="mission-store-194",
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=999,
            ),
        )
        restarted = SQLiteExpertWorkspaceStore(self.path)
        restarted.initialize()
        self.assertEqual(
            restarted.reconcile_review_records(records, expert_registry=self.registry).status,
            ReconciliationStatus.CONSISTENT,
        )
        self.assertEqual(
            restarted.verify_store(self.catalog, expert_registry=self.registry).status,
            "valid",
        )

    def test_projection_time_and_exact_replay_integrity_fail_closed(self) -> None:
        records = self._records(revoke=True)
        with self.assertRaisesRegex(StoreConflictError, "predates the closure"):
            self.store._apply_review_closure_records(
                records,
                mission_store_id="mission-store-194",
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=149,
            )
        self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        with self.assertRaisesRegex(StoreConflictError, "predates the revocation"):
            self.store._apply_review_closure_revocation_records(
                records,
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=169,
            )
        connection = sqlite3.connect(self.path)
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'workspace_closure_imports_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER workspace_closure_imports_no_update")
        connection.execute(
            "UPDATE workspace_review_closure_imports "
            "SET mission_store_id = CAST(mission_store_id AS BLOB)"
        )
        connection.execute(trigger_sql)
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "projection is inconsistent"):
            self.store._apply_review_closure_records(
                records,
                mission_store_id="mission-store-194",
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=999,
            )

    def test_concurrent_closure_projection_has_one_durable_identity(self) -> None:
        records = self._records()

        def apply(index: int) -> tuple[str, str]:
            mission_store_id = f"mission-store-{index % 2}"
            store = SQLiteExpertWorkspaceStore(self.path)
            try:
                application = store._apply_review_closure_records(
                    records,
                    mission_store_id=mission_store_id,
                    runtime_catalog=self.catalog,
                    expert_registry=self.registry,
                    applied_at=160,
                )
            except StoreConflictError:
                return "conflict", mission_store_id
            return application.application_id, mission_store_id

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(apply, range(16)))
        successes = [item for item in outcomes if item[0] != "conflict"]
        self.assertTrue(successes)
        self.assertEqual(len({item[0] for item in successes}), 1)
        self.assertEqual(len({item[1] for item in successes}), 1)
        self.assertIn("conflict", {item[0] for item in outcomes})
        self.assertEqual(
            self.store.verify_store(self.catalog, expert_registry=self.registry).status,
            "valid",
        )

    def test_snapshot_substitution_and_revocation_conflict_fail_closed(self) -> None:
        records = self._records(revoke=True)
        altered = copy.deepcopy(records.snapshot.to_dict())
        altered.pop("snapshot_id")
        altered.pop("snapshot_sha256")
        altered["evidence_snapshot_sha256"] = ZERO_HASH
        replacement = build_expert_review_snapshot(altered, self.registry)
        with self.assertRaisesRegex(StoreError, "snapshot binding"):
            verify_expert_review_record_set(
                ExpertReviewRecordSet(
                    replacement,
                    records.receipts,
                    records.closure_request,
                    records.closure,
                ),
                self.registry,
            )
        self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        self.store._apply_review_closure_revocation_records(
            records,
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=170,
        )
        conflicting_revocation = build_expert_review_closure_revocation(
            records.closure,
            reason_code="different-revocation",
            control_subject="revoker-subject-194",
            control_profile_id="AOE-HQ-12",
            assertion_issuer="identity-issuer-194",
            assertion_id="assertion-revoke-194",
            assertion_sha256=ZERO_HASH,
            operation_intent_sha256=ONE_HASH,
            canonical_replay_key_sha256=FOUR_HASH,
            revoked_at=170,
        )
        with self.assertRaisesRegex(StoreConflictError, "conflicts"):
            self.store._apply_review_closure_revocation_records(
                ExpertReviewRecordSet(
                    records.snapshot,
                    records.receipts,
                    records.closure_request,
                    records.closure,
                    conflicting_revocation,
                ),
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
                applied_at=171,
            )

    def test_rework_closure_is_terminal_and_preserves_disposition(self) -> None:
        records = self._records(decision=ReviewDecision.REWORK_REQUIRED)
        application = self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        self.assertEqual(application.to_dict()["disposition"], "rework_required")
        with self.assertRaisesRegex(StoreConflictError, "already closed"):
            self.store.export_review_snapshot(
                records.snapshot.to_dict()["workspace_id"],
                runtime_catalog=self.catalog,
                expert_registry=self.registry,
            )

    def test_rejected_closure_preserves_rejected_work_identity(self) -> None:
        records = self._records(decision=ReviewDecision.REJECTED)
        verified = verify_expert_review_record_set(records, self.registry)
        self.assertEqual(
            verified.closure.to_dict()["rejected_work_ids"],
            ["work-specialist"],
        )
        application = self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        self.assertEqual(application.to_dict()["disposition"], "rejected")

    def test_v1_store_migrates_once_and_survives_restart(self) -> None:
        migration_path = Path(self.temporary.name) / "migration.sqlite3"
        connection = sqlite3.connect(migration_path)
        connection.executescript(
            f"PRAGMA application_id = {APPLICATION_ID};\n"
            "PRAGMA user_version = 1;\n"
            + _SCHEMA_SQL_V1
            + "\nINSERT INTO workspace_store_identity VALUES (1, 1, 0);"
        )
        connection.close()
        migrated = SQLiteExpertWorkspaceStore(migration_path)
        migrated.initialize()
        migrated.initialize()
        connection = sqlite3.connect(migration_path)
        self.assertEqual(
            connection.execute("PRAGMA user_version").fetchone()[0],
            SCHEMA_VERSION,
        )
        self.assertEqual(
            connection.execute("SELECT schema_version FROM workspace_store_identity").fetchone()[0],
            SCHEMA_VERSION,
        )
        self.assertIsNotNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'workspace_review_closure_imports'"
            ).fetchone()
        )
        connection.close()

    def test_v1_store_concurrent_migration_converges(self) -> None:
        migration_path = Path(self.temporary.name) / "concurrent-migration.sqlite3"
        connection = sqlite3.connect(migration_path)
        connection.executescript(
            f"PRAGMA application_id = {APPLICATION_ID};\n"
            "PRAGMA user_version = 1;\n"
            + _SCHEMA_SQL_V1
            + "\nINSERT INTO workspace_store_identity VALUES (1, 1, 0);"
        )
        connection.close()
        stores = [SQLiteExpertWorkspaceStore(migration_path) for _ in range(2)]
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda store: store.initialize(), stores))
        stores[0].initialize()
        connection = sqlite3.connect(migration_path)
        self.assertEqual(
            connection.execute("PRAGMA user_version").fetchone()[0],
            SCHEMA_VERSION,
        )
        connection.close()

    def test_whole_store_detects_type_json_trigger_and_schema_substitution(self) -> None:
        records = self._records()
        self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        connection = sqlite3.connect(self.path)
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'workspace_closure_imports_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER workspace_closure_imports_no_update")
        connection.execute(
            "UPDATE workspace_review_closure_imports SET applied_at = 'not-an-integer'"
        )
        connection.execute(trigger_sql)
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "invalid"):
            self.store.verify_store(self.catalog, expert_registry=self.registry)

        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER workspace_closure_imports_no_update")
        connection.execute("UPDATE workspace_review_closure_imports SET applied_at = 160")
        canonical = connection.execute(
            "SELECT snapshot_json FROM workspace_review_closure_imports"
        ).fetchone()[0]
        connection.execute(
            "UPDATE workspace_review_closure_imports SET snapshot_json = ?",
            (json.dumps(json.loads(canonical), indent=2),),
        )
        connection.execute(trigger_sql)
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "closure record"):
            self.store.verify_store(self.catalog, expert_registry=self.registry)

        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER workspace_closure_imports_no_update")
        connection.execute(
            "UPDATE workspace_review_closure_imports SET snapshot_json = ?",
            (canonical,),
        )
        connection.execute(
            "CREATE TRIGGER workspace_closure_imports_no_update "
            "BEFORE UPDATE ON workspace_review_closure_imports BEGIN SELECT 1; END"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "schema definition"):
            self.store.verify_store(self.catalog, expert_registry=self.registry)

    def test_whole_store_reconstructs_exact_closure_source_snapshot(self) -> None:
        records = self._records()
        self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        altered_body = records.snapshot.to_dict()
        altered_body.pop("snapshot_id")
        altered_body.pop("snapshot_sha256")
        altered_body["products"][0]["fencing_token"] = 2
        altered_snapshot = build_expert_review_snapshot(altered_body, self.registry)
        slot = altered_snapshot.to_dict()["review_slots"][0]
        submission = build_expert_review_submission(
            snapshot=altered_snapshot,
            work_id=slot["work_id"],
            product_id=slot["product_id"],
            product_sha256=slot["product_sha256"],
            reviewer_profile_id=slot["reviewer_profile_id"],
            reviewer_role=slot["reviewer_role"],
            decision=ReviewDecision.ACCEPTED,
            reason_code="evidence-sufficient",
            rationale="The bounded evidence supports the advisory observation.",
        )
        receipt = build_authenticated_expert_review_receipt(
            submission,
            reviewer_subject="reviewer-subject-194",
            assertion_issuer="identity-issuer-194",
            assertion_id="assertion-review-194",
            assertion_sha256=ZERO_HASH,
            assertion_key_sha256=ONE_HASH,
            trust_policy_sha256=TWO_HASH,
            scope_grant_sha256=ZERO_HASH,
            operation_intent_sha256=ONE_HASH,
            canonical_replay_key_sha256=TWO_HASH,
            recorded_at=130,
        )
        request = build_expert_review_closure_request(
            altered_snapshot,
            (receipt,),
            expected_disposition=ClosureDisposition.ACCEPTED,
            closer_profile_id="AOE-HQ-12",
            requested_at=140,
        )
        closure = build_expert_review_closure_certificate(
            request,
            review_receipt_ids=[receipt.receipt_id],
            review_set_sha256=review_set_sha256((receipt,)),
            disposition=ClosureDisposition.ACCEPTED,
            rejected_work_ids=(),
            rework_work_ids=(),
            required_correction_ids=(),
            closer_subject="control-subject-194",
            closer_profile_id="AOE-HQ-12",
            assertion_issuer="identity-issuer-194",
            assertion_id="assertion-close-194",
            assertion_sha256=ZERO_HASH,
            assertion_key_sha256=ONE_HASH,
            trust_policy_sha256=TWO_HASH,
            scope_grant_sha256=ZERO_HASH,
            operation_intent_sha256=ONE_HASH,
            canonical_replay_key_sha256=THREE_HASH,
            closed_at=150,
        )
        application = build_expert_workspace_closure_application(
            mission_store_id="mission-store-194",
            workspace_id=altered_snapshot.to_dict()["workspace_id"],
            snapshot=altered_snapshot,
            closure=closure,
            workspace_revision_before=2,
            event_head_before_sha256=altered_snapshot.to_dict()["event_head_sha256"],
            applied_at=160,
        )
        event = _event_document(
            altered_snapshot.to_dict()["workspace_id"],
            3,
            altered_snapshot.to_dict()["event_head_sha256"],
            "review_closure_applied",
            3,
            160,
            {
                "snapshot_id": altered_snapshot.snapshot_id,
                "snapshot_sha256": altered_snapshot.snapshot_sha256,
                "closure_id": closure.closure_id,
                "closure_sha256": closure.closure_sha256,
                "disposition": "accepted",
                "application_id": application.application_id,
                "application_sha256": application.application_sha256,
            },
        )
        connection = sqlite3.connect(self.path)
        closure_trigger = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'workspace_closure_imports_no_update'"
        ).fetchone()[0]
        event_trigger = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'workspace_events_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER workspace_closure_imports_no_update")
        connection.execute("DROP TRIGGER workspace_events_no_update")
        connection.execute(
            "UPDATE workspace_review_closure_imports SET closure_id = ?, "
            "closure_sha256 = ?, snapshot_id = ?, snapshot_sha256 = ?, "
            "snapshot_json = ?, closure_json = ?, application_id = ?, "
            "application_sha256 = ?, application_json = ?",
            (
                closure.closure_id,
                closure.closure_sha256,
                altered_snapshot.snapshot_id,
                altered_snapshot.snapshot_sha256,
                altered_snapshot.document_json,
                closure.document_json,
                application.application_id,
                application.application_sha256,
                application.document_json,
            ),
        )
        connection.execute(
            "UPDATE workspace_events SET event_id = ?, event_sha256 = ?, payload_json = ? "
            "WHERE workspace_revision = 3",
            (
                event["event_id"],
                event["event_sha256"],
                json.dumps(event["payload"], separators=(",", ":"), sort_keys=True),
            ),
        )
        connection.execute(closure_trigger)
        connection.execute(event_trigger)
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "source projection"):
            self.store.verify_store(self.catalog, expert_registry=self.registry)

    def test_checked_schemas_are_current_closed_and_validate_records(self) -> None:
        record_schema = expert_review_record_schema()
        application_schema = expert_workspace_closure_application_schema()
        checked_record = json.loads(
            (ROOT / "registry/schemas/expert-review-record-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        checked_application = json.loads(
            (
                ROOT / "registry/schemas/expert-workspace-closure-application-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(checked_record, record_schema)
        self.assertEqual(checked_application, application_schema)
        Draft202012Validator.check_schema(record_schema)
        Draft202012Validator.check_schema(application_schema)
        records = self._records()
        Draft202012Validator(record_schema).validate(records.snapshot.to_dict())
        application = self.store._apply_review_closure_records(
            records,
            mission_store_id="mission-store-194",
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
            applied_at=160,
        )
        Draft202012Validator(application_schema).validate(application.to_dict())
        unknown = records.snapshot.to_dict()
        unknown["unknown"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema).validate(unknown)
        nested_unknown = records.snapshot.to_dict()
        nested_unknown["products"][0]["unknown"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema).validate(nested_unknown)
        wrong_type = records.snapshot.to_dict()
        wrong_type["workspace_revision"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema).validate(wrong_type)
        malformed_hash = records.snapshot.to_dict()
        malformed_hash["target_scope_sha256"] = "sha256:not-a-digest"
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema).validate(malformed_hash)
        effect_claim = records.snapshot.to_dict()
        effect_claim["effects"]["network_call_performed"] = True
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema).validate(effect_claim)


if __name__ == "__main__":
    unittest.main()

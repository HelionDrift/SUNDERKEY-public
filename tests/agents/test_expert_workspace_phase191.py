from __future__ import annotations

import copy
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from scripts.build_expert_runtime import load_sources
from scripts.build_expert_workspace import (
    acceptance_receipt_schema,
    lease_receipt_schema,
    workspace_definition_schema,
)
from sunderkey.errors import StoreConflictError, StoreError, StoreIntegrityError
from sunderkey.expert_runtime import (
    build_execution_envelope,
    content_address_work_product,
    load_runtime_pack_catalog,
    parse_execution_envelope,
    parse_work_product,
)
from sunderkey.expert_workspace import (
    APPLICATION_ID,
    ExpertWorkspaceStoreAdapter,
    SQLiteExpertWorkspaceStore,
    build_expert_workspace_definition,
    parse_expert_workspace_definition,
)
from sunderkey.qualification import _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "registry" / "expert-runtime-packs-army-v2.json"
SCHEMA_PATHS = (
    ROOT / "registry" / "schemas" / "expert-workspace-definition-v1.schema.json",
    ROOT / "registry" / "schemas" / "expert-workspace-lease-receipt-v1.schema.json",
    ROOT / "registry" / "schemas" / "expert-workspace-acceptance-receipt-v1.schema.json",
)
ZERO_HASH = "sha256:" + "0" * 64
ONE_HASH = "sha256:" + "1" * 64
TWO_HASH = "sha256:" + "2" * 64


class ExpertWorkspacePhase191Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = load_sources()
        cls.catalog = load_runtime_pack_catalog(CATALOG_PATH, *cls.sources)
        cls.specialist_pack = cls.catalog.packs_by_profile_id["AOE-GA-D01-S01"]
        cls.commander_pack = cls.catalog.packs_by_profile_id["AOE-GA-D01-CMD"]

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "workspace.sqlite3"
        self.store = SQLiteExpertWorkspaceStore(self.path)
        self.store.initialize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def definition(
        self,
        *,
        tenant_id: str = "tenant-001",
        mission_id: str = "mission-001",
        plan_id: str = "plan-001",
        maximum_attempts: int = 2,
    ) -> object:
        return build_expert_workspace_definition(
            self.catalog,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            target_scope_sha256=ZERO_HASH,
            authority_snapshot_sha256=ONE_HASH,
            evidence_snapshot_sha256=TWO_HASH,
            assignments=[
                {
                    "work_id": "work-commander",
                    "profile_id": self.commander_pack["profile_id"],
                    "command_id": self.commander_pack["command_id"],
                    "runtime_pack_id": self.commander_pack["runtime_pack_id"],
                    "runtime_pack_sha256": self.commander_pack["runtime_pack_sha256"],
                    "maximum_attempts": maximum_attempts,
                },
                {
                    "work_id": "work-specialist",
                    "profile_id": self.specialist_pack["profile_id"],
                    "command_id": self.specialist_pack["command_id"],
                    "runtime_pack_id": self.specialist_pack["runtime_pack_id"],
                    "runtime_pack_sha256": self.specialist_pack["runtime_pack_sha256"],
                    "maximum_attempts": maximum_attempts,
                },
            ],
            dependencies=[
                {
                    "work_id": "work-commander",
                    "depends_on_work_id": "work-specialist",
                }
            ],
            review_requirements=[
                {
                    "work_id": "work-commander",
                    "required": True,
                    "reviewer_profile_ids": ["AOE-HQ-06"],
                    "producer_excluded": True,
                },
                {
                    "work_id": "work-specialist",
                    "required": True,
                    "reviewer_profile_ids": ["AOE-HQ-07"],
                    "producer_excluded": True,
                },
            ],
        )

    def test_definition_and_parse_do_not_copy_the_entire_runtime_catalog(self) -> None:
        with mock.patch.object(
            type(self.catalog),
            "packs_by_profile_id",
            new_callable=mock.PropertyMock,
            side_effect=AssertionError("full runtime catalog copy was requested"),
        ):
            definition = self.definition()
            parsed = parse_expert_workspace_definition(definition.to_dict(), self.catalog)
        self.assertEqual(parsed, definition)

    @staticmethod
    def context_item(content: str) -> dict[str, object]:
        return {
            "context_id": "context-001",
            "context_kind": "target_content",
            "content": content,
            "content_sha256": _canonical_sha256(content),
            "estimated_tokens": len(content.encode("utf-8")),
            "trust": "untrusted_data",
        }

    def envelope(
        self,
        pack: dict[str, object],
        work_id: str,
        *,
        mission_id: str = "mission-001",
        plan_id: str = "plan-001",
        context: str = "Bounded target evidence.",
    ) -> dict[str, object]:
        return build_execution_envelope(
            pack,
            self.catalog,
            mission_id=mission_id,
            plan_id=plan_id,
            work_id=work_id,
            target_scope_sha256=ZERO_HASH,
            authority_snapshot_sha256=ONE_HASH,
            evidence_snapshot_sha256=TWO_HASH,
            evidence_requirement_ids=["evidence-001"],
            cleanup_requirement_ids=["cleanup-001"],
            approval_requirement_ids=["approval-001"],
            context_items=[self.context_item(context)],
        )

    def product_body(
        self,
        pack: dict[str, object],
        envelope_document: dict[str, object],
        product_type: str,
        payload: dict[str, object],
        *,
        lineage: list[str] | None = None,
        review_required: bool = True,
    ) -> dict[str, object]:
        envelope = parse_execution_envelope(envelope_document, pack, self.catalog)
        return {
            "schema_version": 1,
            "product_type": product_type,
            "runtime_catalog_sha256": self.catalog.catalog_sha256,
            "runtime_pack_id": pack["runtime_pack_id"],
            "runtime_pack_sha256": pack["runtime_pack_sha256"],
            "producer_profile_id": pack["profile_id"],
            "execution_envelope_id": envelope.envelope_id,
            "execution_envelope_sha256": envelope.envelope_sha256,
            "mission_id": envelope.mission_id,
            "plan_id": envelope.plan_id,
            "work_id": envelope.work_id,
            "summary": "Bounded advisory result.",
            "confidence": "moderate",
            "uncertainty": "Independent reproduction has not occurred.",
            "evidence_refs": [TWO_HASH],
            "lineage_product_ids": lineage or [],
            "independent_review": {
                "required": review_required,
                "status": "not_reviewed",
                "reviewer_profile_ids": [],
                "producer_excluded": True,
            },
            "payload": payload,
            "model_output_effect": "advisory_only",
            "tool_effect": "none",
            "authorization_effect": "none",
        }

    def observation(self, envelope_document: dict[str, object]) -> dict[str, object]:
        return content_address_work_product(
            self.product_body(
                self.specialist_pack,
                envelope_document,
                "observation",
                {
                    "observed_facts": ["Fact."],
                    "collection_limits": ["Limit."],
                },
            )
        )

    def synthesis(
        self,
        envelope_document: dict[str, object],
        child_document: dict[str, object],
    ) -> dict[str, object]:
        child_envelope = self.envelope(self.specialist_pack, "work-specialist")
        child = parse_work_product(
            child_document,
            self.specialist_pack,
            parse_execution_envelope(child_envelope, self.specialist_pack, self.catalog),
            self.catalog,
        )
        reference = {
            "product_id": child.product_id,
            "product_sha256": child.product_sha256,
            "producer_profile_id": child.producer_profile_id,
            "product_type": child.product_type,
        }
        return content_address_work_product(
            self.product_body(
                self.commander_pack,
                envelope_document,
                "commander_synthesis",
                {
                    "child_products": [reference],
                    "disagreements": [
                        {
                            "product_ids": [child.product_id],
                            "description": "Evidence remains incomplete.",
                            "resolution_status": "unresolved",
                        }
                    ],
                    "unresolved_uncertainties": ["Independent validation is pending."],
                    "recommendation": "Collect another bounded observation.",
                    "independent_review_separation": "not_performed_by_commander",
                },
                lineage=[child.product_id],
            )
        )

    def create(self, definition: object | None = None) -> object:
        selected = self.definition() if definition is None else definition
        return self.store.create_workspace(selected, self.catalog, created_at=100)

    def complete_specialist(self, workspace_id: str, *, revision: int = 0) -> tuple[object, dict]:
        envelope = self.envelope(self.specialist_pack, "work-specialist")
        lease = self.store.acquire_lease(
            workspace_id,
            tenant_id="tenant-001",
            expected_revision=revision,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        product = self.observation(envelope)
        receipt = self.store.accept_work_product(
            workspace_id,
            tenant_id="tenant-001",
            expected_revision=lease.workspace_revision,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=120,
        )
        return receipt, product

    def test_public_exports_and_adapter_protocol(self) -> None:
        import sunderkey

        expected = {
            "ExpertWorkspaceDefinition",
            "ExpertWorkspaceStoreAdapter",
            "SQLiteExpertWorkspaceStore",
            "build_expert_workspace_definition",
            "parse_expert_workspace_definition",
        }
        self.assertTrue(all(hasattr(sunderkey, name) for name in expected))
        self.assertIsInstance(self.store, ExpertWorkspaceStoreAdapter)

    def test_checked_schemas_are_current_and_closed(self) -> None:
        generated = (
            workspace_definition_schema(),
            lease_receipt_schema(),
            acceptance_receipt_schema(),
        )
        for path, expected in zip(SCHEMA_PATHS, generated, strict=True):
            checked = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(checked, expected)
            Draft202012Validator.check_schema(checked)
        definition = self.definition()
        Draft202012Validator(generated[0]).validate(definition.to_dict())

    def test_complete_workspace_survives_restart_and_verifies(self) -> None:
        state = self.create()
        specialist_receipt, specialist_product = self.complete_specialist(state.workspace_id)
        commander_envelope = self.envelope(self.commander_pack, "work-commander")
        commander_lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=specialist_receipt.workspace_revision,
            envelope=commander_envelope,
            runtime_catalog=self.catalog,
            acquired_at=130,
            lease_seconds=100,
        )
        acceptance = self.store.accept_work_product(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=commander_lease.workspace_revision,
            lease_id=commander_lease.lease_id,
            fencing_token=commander_lease.fencing_token,
            work_product=self.synthesis(commander_envelope, specialist_product),
            runtime_catalog=self.catalog,
            accepted_at=140,
        )
        self.assertEqual(acceptance.workspace_status, "products_complete_pending_review")
        restarted = SQLiteExpertWorkspaceStore(self.path)
        restarted.initialize()
        report = restarted.verify_store(self.catalog)
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.workspace_count, 1)
        self.assertEqual(report.assignment_count, 2)
        self.assertEqual(report.product_count, 2)
        self.assertEqual(report.event_count, 5)
        Draft202012Validator(lease_receipt_schema()).validate(commander_lease.to_dict())
        Draft202012Validator(acceptance_receipt_schema()).validate(acceptance.to_dict())

    def test_definition_rejects_cycles_pack_substitution_and_producer_review(self) -> None:
        valid = self.definition().to_dict()
        cycle = copy.deepcopy(valid)
        cycle["dependencies"].append(
            {"work_id": "work-specialist", "depends_on_work_id": "work-commander"}
        )
        body = {
            key: value
            for key, value in cycle.items()
            if key not in {"workspace_id", "workspace_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": "sunderkey.expert-collaboration-workspace.v1", "workspace": body}
        )
        cycle["workspace_sha256"] = digest
        cycle["workspace_id"] = f"EWS-{digest.removeprefix('sha256:')[:32].upper()}"
        with self.assertRaisesRegex(StoreError, "cycle"):
            parse_expert_workspace_definition(cycle, self.catalog)
        with self.assertRaisesRegex(StoreError, "exact runtime pack"):
            assignments = copy.deepcopy(valid["assignments"])
            assignments[0]["runtime_pack_sha256"] = ZERO_HASH
            build_expert_workspace_definition(
                self.catalog,
                tenant_id="tenant-002",
                mission_id="mission-002",
                plan_id="plan-002",
                target_scope_sha256=ZERO_HASH,
                authority_snapshot_sha256=ONE_HASH,
                evidence_snapshot_sha256=TWO_HASH,
                assignments=assignments,
                dependencies=valid["dependencies"],
                review_requirements=valid["review_requirements"],
            )
        reviews = copy.deepcopy(valid["review_requirements"])
        reviews[0]["reviewer_profile_ids"] = ["AOE-GA-D01-CMD"]
        with self.assertRaisesRegex(StoreError, "own reviewer"):
            build_expert_workspace_definition(
                self.catalog,
                tenant_id="tenant-002",
                mission_id="mission-002",
                plan_id="plan-002",
                target_scope_sha256=ZERO_HASH,
                authority_snapshot_sha256=ONE_HASH,
                evidence_snapshot_sha256=TWO_HASH,
                assignments=valid["assignments"],
                dependencies=valid["dependencies"],
                review_requirements=reviews,
            )
        outsider = self.catalog.packs_by_profile_id["AOE-GA-D02-S01"]
        outsider_assignment = {
            "work_id": "work-outsider",
            "profile_id": outsider["profile_id"],
            "command_id": outsider["command_id"],
            "runtime_pack_id": outsider["runtime_pack_id"],
            "runtime_pack_sha256": outsider["runtime_pack_sha256"],
            "maximum_attempts": 1,
        }
        with self.assertRaisesRegex(StoreError, "command membership"):
            build_expert_workspace_definition(
                self.catalog,
                tenant_id="tenant-002",
                mission_id="mission-002",
                plan_id="plan-002",
                target_scope_sha256=ZERO_HASH,
                authority_snapshot_sha256=ONE_HASH,
                evidence_snapshot_sha256=TWO_HASH,
                assignments=sorted(
                    [*valid["assignments"], outsider_assignment],
                    key=lambda item: item["work_id"],
                ),
                dependencies=[
                    {
                        "work_id": "work-commander",
                        "depends_on_work_id": "work-outsider",
                    }
                ],
                review_requirements=sorted(
                    [
                        *valid["review_requirements"],
                        {
                            "work_id": "work-outsider",
                            "required": True,
                            "reviewer_profile_ids": ["AOE-HQ-08"],
                            "producer_excluded": True,
                        },
                    ],
                    key=lambda item: item["work_id"],
                ),
            )

    def test_dependencies_and_all_boundary_bindings_fail_closed(self) -> None:
        state = self.create()
        with self.assertRaisesRegex(StoreConflictError, "replay"):
            self.create()
        commander = self.envelope(self.commander_pack, "work-commander")
        with self.assertRaisesRegex(StoreConflictError, "dependencies"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=0,
                envelope=commander,
                runtime_catalog=self.catalog,
                acquired_at=110,
                lease_seconds=100,
            )
        wrong = self.envelope(
            self.specialist_pack,
            "work-specialist",
            mission_id="mission-999",
        )
        with self.assertRaisesRegex(StoreError, "workspace binding"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=0,
                envelope=wrong,
                runtime_catalog=self.catalog,
                acquired_at=110,
                lease_seconds=100,
            )
        with self.assertRaisesRegex(StoreError, "tenant"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-999",
                expected_revision=0,
                envelope=self.envelope(self.specialist_pack, "work-specialist"),
                runtime_catalog=self.catalog,
                acquired_at=110,
                lease_seconds=100,
            )

    def test_stale_revision_fence_expiry_replay_and_clock_rollback_fail(self) -> None:
        state = self.create()
        first_envelope = self.envelope(self.specialist_pack, "work-specialist")
        first = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=0,
            envelope=first_envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=5,
        )
        with self.assertRaisesRegex(StoreConflictError, "stale"):
            self.store.accept_work_product(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=1,
                lease_id=first.lease_id,
                fencing_token=first.fencing_token + 1,
                work_product=self.observation(first_envelope),
                runtime_catalog=self.catalog,
                accepted_at=111,
            )
        with self.assertRaisesRegex(StoreConflictError, "clock"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=1,
                envelope=self.envelope(
                    self.specialist_pack, "work-specialist", context="Explicit retry."
                ),
                runtime_catalog=self.catalog,
                acquired_at=109,
                lease_seconds=5,
            )
        retry_envelope = self.envelope(
            self.specialist_pack, "work-specialist", context="Explicit retry."
        )
        retry = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=1,
            envelope=retry_envelope,
            runtime_catalog=self.catalog,
            acquired_at=115,
            lease_seconds=10,
        )
        self.assertEqual(retry.attempt_number, 2)
        self.assertEqual(retry.fencing_token, 2)
        with self.assertRaisesRegex(StoreConflictError, "stale"):
            self.store.accept_work_product(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=2,
                lease_id=first.lease_id,
                fencing_token=first.fencing_token,
                work_product=self.observation(first_envelope),
                runtime_catalog=self.catalog,
                accepted_at=116,
            )
        with self.assertRaisesRegex(StoreConflictError, "replay"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=2,
                envelope=first_envelope,
                runtime_catalog=self.catalog,
                acquired_at=125,
                lease_seconds=10,
            )

    def test_terminal_attempt_and_review_claim_are_single_use(self) -> None:
        state = self.create()
        envelope = self.envelope(self.specialist_pack, "work-specialist")
        lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        mismatch = content_address_work_product(
            self.product_body(
                self.specialist_pack,
                envelope,
                "observation",
                {"observed_facts": ["Fact."], "collection_limits": ["Limit."]},
                review_required=False,
            )
        )
        with self.assertRaisesRegex(StoreError, "review requirement"):
            self.store.accept_work_product(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=1,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                work_product=mismatch,
                runtime_catalog=self.catalog,
                accepted_at=120,
            )
        rolled_back = self.store.get_workspace(state.workspace_id, tenant_id="tenant-001")
        self.assertEqual(rolled_back.revision, 1)
        self.assertEqual(self.store.verify_store(self.catalog).product_count, 0)
        product = self.observation(envelope)
        receipt = self.store.accept_work_product(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=1,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=120,
        )
        with self.assertRaises(StoreError):
            self.store.accept_work_product(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=receipt.workspace_revision,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                work_product=product,
                runtime_catalog=self.catalog,
                accepted_at=121,
            )

    def test_concurrent_optimistic_acquisition_has_one_winner(self) -> None:
        state = self.create()
        envelope = self.envelope(self.specialist_pack, "work-specialist")
        barrier = threading.Barrier(2)

        def acquire() -> str:
            local = SQLiteExpertWorkspaceStore(self.path)
            barrier.wait()
            try:
                local.acquire_lease(
                    state.workspace_id,
                    tenant_id="tenant-001",
                    expected_revision=0,
                    envelope=envelope,
                    runtime_catalog=self.catalog,
                    acquired_at=110,
                    lease_seconds=100,
                )
                return "accepted"
            except StoreConflictError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: acquire(), range(2)))
        self.assertEqual(sorted(results), ["accepted", "conflict"])
        self.assertEqual(self.store.verify_store(self.catalog).lease_count, 1)

    def test_cross_workspace_commander_lineage_is_rejected(self) -> None:
        first = self.create()
        _, first_product = self.complete_specialist(first.workspace_id)
        second_definition = self.definition(
            tenant_id="tenant-002",
            mission_id="mission-002",
            plan_id="plan-002",
        )
        second = self.create(second_definition)
        second_envelope = self.envelope(
            self.specialist_pack,
            "work-specialist",
            mission_id="mission-002",
            plan_id="plan-002",
            context="Second workspace evidence.",
        )
        second_lease = self.store.acquire_lease(
            second.workspace_id,
            tenant_id="tenant-002",
            expected_revision=0,
            envelope=second_envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        second_product = self.observation(second_envelope)
        self.store.accept_work_product(
            second.workspace_id,
            tenant_id="tenant-002",
            expected_revision=1,
            lease_id=second_lease.lease_id,
            fencing_token=second_lease.fencing_token,
            work_product=second_product,
            runtime_catalog=self.catalog,
            accepted_at=120,
        )
        commander_envelope = self.envelope(
            self.commander_pack,
            "work-commander",
            mission_id="mission-002",
            plan_id="plan-002",
        )
        commander_lease = self.store.acquire_lease(
            second.workspace_id,
            tenant_id="tenant-002",
            expected_revision=2,
            envelope=commander_envelope,
            runtime_catalog=self.catalog,
            acquired_at=130,
            lease_seconds=100,
        )
        forged = self.synthesis(commander_envelope, first_product)
        with self.assertRaises(StoreError):
            self.store.accept_work_product(
                second.workspace_id,
                tenant_id="tenant-002",
                expected_revision=3,
                lease_id=commander_lease.lease_id,
                fencing_token=commander_lease.fencing_token,
                work_product=forged,
                runtime_catalog=self.catalog,
                accepted_at=140,
            )

    def test_whole_store_verification_detects_corruption(self) -> None:
        state = self.create()
        self.assertEqual(self.store.verify_store(self.catalog).status, "valid")
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE workspace_assignments SET status = 'leased' "
            "WHERE workspace_id = ? AND work_id = 'work-specialist'",
            (state.workspace_id,),
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "assignment state"):
            self.store.verify_store(self.catalog)

    def test_schema_initialization_refuses_foreign_and_unknown_versions(self) -> None:
        foreign_path = Path(self.temporary.name) / "foreign.sqlite3"
        connection = sqlite3.connect(foreign_path)
        connection.execute("CREATE TABLE unrelated(value TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "nonempty unclaimed"):
            SQLiteExpertWorkspaceStore(foreign_path).initialize()
        connection = sqlite3.connect(foreign_path)
        self.assertEqual(
            connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchone()[0],
            "unrelated",
        )
        self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], 0)
        connection.close()

        unknown_path = Path(self.temporary.name) / "unknown.sqlite3"
        connection = sqlite3.connect(unknown_path)
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 2")
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "identity"):
            SQLiteExpertWorkspaceStore(unknown_path).initialize()

    def test_schema_verification_rejects_same_name_trigger_substitution(self) -> None:
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER workspace_events_no_update")
        connection.execute(
            "CREATE TRIGGER workspace_events_no_update AFTER INSERT ON workspace_events "
            "BEGIN SELECT 1; END"
        )
        connection.commit()
        connection.close()
        with self.assertRaisesRegex(StoreIntegrityError, "schema definition"):
            self.store.initialize()

    def test_concurrent_initialization_converges_on_one_valid_schema(self) -> None:
        path = Path(self.temporary.name) / "concurrent.sqlite3"
        barrier = threading.Barrier(2)

        def initialize() -> str:
            barrier.wait()
            SQLiteExpertWorkspaceStore(path).initialize()
            return "initialized"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: initialize(), range(2)))
        self.assertEqual(results, ["initialized", "initialized"])
        self.assertEqual(
            SQLiteExpertWorkspaceStore(path).verify_store(self.catalog).status, "valid"
        )

    def test_definition_is_deeply_immutable_and_reviewer_ids_are_catalog_bound(self) -> None:
        definition = self.definition()
        with self.assertRaises(TypeError):
            definition.assignments[0]["work_id"] = "forged"
        with self.assertRaises(AttributeError):
            definition.review_requirements[0]["reviewer_profile_ids"].append("AOE-HQ-08")

        document = definition.to_dict()
        document["review_requirements"][0]["reviewer_profile_ids"] = ["AOE-HQ-36"]
        with self.assertRaisesRegex(StoreError, "reviewer profile IDs"):
            build_expert_workspace_definition(
                self.catalog,
                tenant_id="tenant-002",
                mission_id="mission-002",
                plan_id="plan-002",
                target_scope_sha256=ZERO_HASH,
                authority_snapshot_sha256=ONE_HASH,
                evidence_snapshot_sha256=TWO_HASH,
                assignments=document["assignments"],
                dependencies=document["dependencies"],
                review_requirements=document["review_requirements"],
            )

    def test_revision_arguments_reject_boolean_substitution(self) -> None:
        state = self.create()
        envelope = self.envelope(self.specialist_pack, "work-specialist")
        with self.assertRaisesRegex(StoreError, "expected_revision"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=False,
                envelope=envelope,
                runtime_catalog=self.catalog,
                acquired_at=110,
                lease_seconds=100,
            )
        lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        with self.assertRaisesRegex(StoreError, "expected_revision"):
            self.store.accept_work_product(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=True,
                lease_id=lease.lease_id,
                fencing_token=lease.fencing_token,
                work_product=self.observation(envelope),
                runtime_catalog=self.catalog,
                accepted_at=120,
            )

    def test_definition_rejects_boolean_and_integer_identity_substitution(self) -> None:
        def readdress(document: dict[str, object]) -> dict[str, object]:
            body = {
                key: value
                for key, value in document.items()
                if key not in {"workspace_id", "workspace_sha256"}
            }
            digest = _canonical_sha256(
                {"domain": "sunderkey.expert-collaboration-workspace.v1", "workspace": body}
            )
            document["workspace_sha256"] = digest
            document["workspace_id"] = f"EWS-{digest.removeprefix('sha256:')[:32].upper()}"
            return document

        boolean_version = self.definition().to_dict()
        boolean_version["schema_version"] = True
        with self.assertRaisesRegex(StoreError, "schema version"):
            parse_expert_workspace_definition(readdress(boolean_version), self.catalog)

        integer_effect = self.definition().to_dict()
        integer_effect["model_call_performed"] = 0
        with self.assertRaisesRegex(StoreError, "prohibited effect"):
            parse_expert_workspace_definition(readdress(integer_effect), self.catalog)

    def test_runtime_and_verifier_reject_stored_integer_type_confusion(self) -> None:
        state = self.create()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE workspace_assignments SET attempt_count = ? "
            "WHERE workspace_id = ? AND work_id = 'work-specialist'",
            (sqlite3.Binary(b"0"), state.workspace_id),
        )
        connection.commit()
        connection.close()

        envelope = self.envelope(self.specialist_pack, "work-specialist")
        with self.assertRaisesRegex(StoreIntegrityError, "attempt_count"):
            self.store.acquire_lease(
                state.workspace_id,
                tenant_id="tenant-001",
                expected_revision=0,
                envelope=envelope,
                runtime_catalog=self.catalog,
                acquired_at=110,
                lease_seconds=100,
            )
        with self.assertRaisesRegex(StoreIntegrityError, "attempt_count"):
            self.store.verify_store(self.catalog)

    def test_verifier_rejects_noncanonical_stored_event_json(self) -> None:
        state = self.create()
        connection = sqlite3.connect(self.path)
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'trigger' AND name = 'workspace_events_no_update'"
        ).fetchone()[0]
        canonical = connection.execute(
            "SELECT payload_json FROM workspace_events "
            "WHERE workspace_id = ? AND sequence_number = 0",
            (state.workspace_id,),
        ).fetchone()[0]
        connection.execute("DROP TRIGGER workspace_events_no_update")
        connection.execute(
            "UPDATE workspace_events SET payload_json = ? "
            "WHERE workspace_id = ? AND sequence_number = 0",
            (json.dumps(json.loads(canonical), indent=2, sort_keys=True), state.workspace_id),
        )
        connection.execute(trigger_sql)
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(StoreIntegrityError, "not canonical"):
            self.store.verify_store(self.catalog)

    def test_count_ceiling_and_no_effect_receipts(self) -> None:
        valid = self.definition().to_dict()
        reviews = copy.deepcopy(valid["review_requirements"])
        reviews[0]["reviewer_profile_ids"] = [f"AOE-HQ-{index:02d}" for index in range(65)]
        with self.assertRaisesRegex(StoreError, "reviewer profile IDs"):
            build_expert_workspace_definition(
                self.catalog,
                tenant_id="tenant-002",
                mission_id="mission-002",
                plan_id="plan-002",
                target_scope_sha256=ZERO_HASH,
                authority_snapshot_sha256=ONE_HASH,
                evidence_snapshot_sha256=TWO_HASH,
                assignments=valid["assignments"],
                dependencies=valid["dependencies"],
                review_requirements=reviews,
            )
        state = self.create()
        envelope = self.envelope(self.specialist_pack, "work-specialist")
        lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-001",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        lease_document = lease.to_dict()
        self.assertFalse(lease_document["automatic_retry_performed"])
        self.assertFalse(lease_document["model_call_performed"])
        self.assertFalse(lease_document["network_call_performed"])
        self.assertEqual(lease_document["tool_effect"], "none")
        self.assertEqual(lease_document["authorization_effect"], "none")

    def test_no_required_review_can_reach_completed_terminal_state(self) -> None:
        valid = self.definition().to_dict()
        definition = build_expert_workspace_definition(
            self.catalog,
            tenant_id="tenant-no-review",
            mission_id="mission-no-review",
            plan_id="plan-no-review",
            target_scope_sha256=ZERO_HASH,
            authority_snapshot_sha256=ONE_HASH,
            evidence_snapshot_sha256=TWO_HASH,
            assignments=[valid["assignments"][1]],
            dependencies=[],
            review_requirements=[
                {
                    "work_id": "work-specialist",
                    "required": False,
                    "reviewer_profile_ids": [],
                    "producer_excluded": True,
                }
            ],
        )
        state = self.store.create_workspace(definition, self.catalog, created_at=100)
        envelope = self.envelope(
            self.specialist_pack,
            "work-specialist",
            mission_id="mission-no-review",
            plan_id="plan-no-review",
        )
        lease = self.store.acquire_lease(
            state.workspace_id,
            tenant_id="tenant-no-review",
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=110,
            lease_seconds=100,
        )
        product = content_address_work_product(
            self.product_body(
                self.specialist_pack,
                envelope,
                "observation",
                {"observed_facts": ["Fact."], "collection_limits": ["Limit."]},
                review_required=False,
            )
        )
        receipt = self.store.accept_work_product(
            state.workspace_id,
            tenant_id="tenant-no-review",
            expected_revision=1,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=120,
        )
        self.assertEqual(receipt.workspace_status, "completed")
        self.assertEqual(self.store.verify_store(self.catalog).status, "valid")

    def test_append_only_products_and_events_reject_mutation(self) -> None:
        state = self.create()
        self.complete_specialist(state.workspace_id)
        connection = sqlite3.connect(self.path)
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM workspace_products")
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute("UPDATE workspace_events SET event_type = 'forged'")
        connection.close()


if __name__ == "__main__":
    unittest.main()

"""Phase 163 persistence port contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.persistence_port_contracts import (
    NO_EFFECTS,
    AggregateVersionBinding,
    BackendCapabilityDeclaration,
    DeploymentRequirements,
    DeploymentSuitabilityReport,
    FenceBinding,
    MigrationManifest,
    MigrationStep,
    PersistenceContractError,
    TransactionBatch,
    TransactionOperation,
    evaluate_deployment_suitability,
    parse_contract,
    postgresql_production_capabilities,
    sqlite_development_capabilities,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "persistence-port-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "persistence_port_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "persistence-port-contracts.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")


class PersistencePortContractsPhase163Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.evaluate_deployment_suitability,
            evaluate_deployment_suitability,
        )
        self.assertIs(
            sunderkey.postgresql_production_capabilities,
            postgresql_production_capabilities,
        )

    def production_requirements(self) -> DeploymentRequirements:
        return DeploymentRequirements(
            deployment_class="high_availability_production",
            worker_count=8,
            required_isolation="serializable",
            require_high_availability=True,
            require_tenant_isolation=True,
            require_atomic_outbox=True,
            require_online_migrations=True,
            require_fencing=True,
        )

    def manifest(self) -> MigrationManifest:
        return MigrationManifest(
            backend="postgresql",
            store_ref="storeref:production-primary",
            generated_at="2026-09-20T12:00:00Z",
            steps=(
                MigrationStep(
                    sequence=1,
                    migration_ref="migrationref:schema-41",
                    artifact_sha256=DIGESTS[1],
                    from_version=40,
                    to_version=41,
                    mode="expand_contract",
                    rollback_ref="rollbackref:schema-41",
                ),
                MigrationStep(
                    sequence=2,
                    migration_ref="migrationref:schema-42",
                    artifact_sha256=DIGESTS[2],
                    from_version=41,
                    to_version=42,
                    mode="expand_contract",
                    rollback_ref="rollbackref:schema-42",
                ),
            ),
            precondition_refs=("verificationref:backup-restorable",),
            postcondition_refs=("verificationref:schema-42-verified",),
        )

    def batch(self) -> TransactionBatch:
        return TransactionBatch(
            tenant_ref="tenantref:acme",
            assessment_ref="assessmentref:assessment-001",
            scope_ref="scoperef:admission-001",
            idempotency_key="idem:persistence-batch-000001",
            isolation_level="serializable",
            created_at="2026-09-20T12:01:00Z",
            operations=(
                TransactionOperation(
                    operation_ref="operationref:finding-transition-001",
                    kind="state_transition",
                    aggregate_ref="aggregateref:finding-001",
                    content_sha256=DIGESTS[3],
                ),
                TransactionOperation(
                    operation_ref="operationref:outbox-enqueue-001",
                    kind="outbox_enqueue",
                    aggregate_ref="aggregateref:outbox-001",
                    content_sha256=DIGESTS[4],
                ),
            ),
            version_bindings=(
                AggregateVersionBinding("aggregateref:finding-001", 7),
                AggregateVersionBinding("aggregateref:outbox-001", 0),
            ),
            fence_bindings=(
                FenceBinding(
                    "resourceref:assessment-001",
                    "fence:assessment-worker-0001",
                    12,
                ),
            ),
            outbox_event_refs=("outboxref:finding-changed-001",),
        )

    def test_backend_declarations_are_immutable_and_round_trip(self) -> None:
        for declaration in (
            sqlite_development_capabilities(),
            postgresql_production_capabilities(),
        ):
            with self.subTest(backend=declaration.backend.value):
                self.assertEqual(
                    declaration,
                    BackendCapabilityDeclaration.from_json(declaration.to_json()),
                )
                self.assertEqual(declaration, parse_contract(declaration.to_dict()))
                self.assertEqual(declaration.to_dict()["effects"], dict(NO_EFFECTS))
                with self.assertRaises(FrozenInstanceError):
                    declaration.max_concurrent_workers = 2  # type: ignore[misc]

    def test_sqlite_cannot_claim_production_capabilities(self) -> None:
        raw = sqlite_development_capabilities().to_dict()
        raw["deployment_classes"] = ["multi_worker_production"]
        raw["max_concurrent_workers"] = 8
        raw["multi_writer"] = True
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"declaration_id", "declaration_sha256"}
        }
        from sunderkey.persistence_port_contracts import canonical_sha256

        digest = canonical_sha256(
            {
                "content": body,
                "domain": BackendCapabilityDeclaration.KIND,
            }
        )
        raw["declaration_id"] = f"PBD-{digest[7:39].upper()}"
        raw["declaration_sha256"] = digest
        with self.assertRaisesRegex(PersistenceContractError, "single-worker"):
            BackendCapabilityDeclaration.from_dict(raw)

    def test_sqlite_is_rejected_for_multi_worker_and_ha_production(self) -> None:
        report = evaluate_deployment_suitability(
            sqlite_development_capabilities(), self.production_requirements()
        )
        self.assertEqual(report.status.value, "incompatible")
        self.assertIn("sqlite_production_forbidden", report.blocker_codes)
        self.assertIn("sqlite_single_writer_only", report.blocker_codes)
        self.assertIn("tenant_isolation_unsupported", report.blocker_codes)
        self.assertIn("high_availability_unsupported", report.blocker_codes)
        self.assertIn("live_backend_verification_required", report.blocker_codes)

    def test_postgresql_contract_remains_unverified_and_nonqualifying(self) -> None:
        report = evaluate_deployment_suitability(
            postgresql_production_capabilities(), self.production_requirements()
        )
        self.assertEqual(report.status.value, "contract_compatible_unverified")
        self.assertEqual(report.blocker_codes, ("live_backend_verification_required",))
        self.assertEqual(report.to_dict()["deployment_effect"], "none")
        self.assertEqual(report.to_dict()["qualification_effect"], "none")
        self.assertEqual(report, DeploymentSuitabilityReport.from_json(report.to_json()))

    def test_migration_manifest_is_ordered_addressed_and_non_executable(self) -> None:
        manifest = self.manifest()
        self.assertEqual(manifest, MigrationManifest.from_json(manifest.to_json()))
        self.assertEqual(manifest, parse_contract(manifest.to_dict()))
        self.assertNotIn("sql", manifest.to_dict())
        tampered = copy.deepcopy(manifest.to_dict())
        tampered["steps"][0]["artifact_sha256"] = DIGESTS[9]
        with self.assertRaisesRegex(PersistenceContractError, "content address"):
            MigrationManifest.from_dict(tampered)
        with self.assertRaisesRegex(PersistenceContractError, "contiguous"):
            MigrationManifest(
                backend="postgresql",
                store_ref="storeref:production-primary",
                generated_at="2026-09-20T12:00:00Z",
                steps=(
                    MigrationStep(
                        2,
                        "migrationref:schema-41",
                        DIGESTS[1],
                        40,
                        41,
                        "expand_contract",
                        None,
                    ),
                ),
                precondition_refs=("verificationref:preflight",),
                postcondition_refs=("verificationref:postflight",),
            )

    def test_postgresql_rejects_offline_migration_mode(self) -> None:
        with self.assertRaisesRegex(PersistenceContractError, "expand_contract"):
            MigrationManifest(
                backend="postgresql",
                store_ref="storeref:production-primary",
                generated_at="2026-09-20T12:00:00Z",
                steps=(
                    MigrationStep(
                        1,
                        "migrationref:schema-41",
                        DIGESTS[1],
                        40,
                        41,
                        "offline",
                        None,
                    ),
                ),
                precondition_refs=("verificationref:preflight",),
                postcondition_refs=("verificationref:postflight",),
            )

    def test_transaction_batch_binds_tenant_versions_fences_and_outbox(self) -> None:
        batch = self.batch()
        self.assertEqual(batch, TransactionBatch.from_json(batch.to_json()))
        self.assertEqual(batch, parse_contract(batch.to_dict()))
        self.assertEqual(batch.to_dict()["atomicity"], "all_or_nothing_with_outbox")
        self.assertEqual(batch.to_dict()["effects"], dict(NO_EFFECTS))
        tampered = copy.deepcopy(batch.to_dict())
        tampered["tenant_ref"] = "tenantref:other"
        with self.assertRaisesRegex(PersistenceContractError, "content address"):
            TransactionBatch.from_dict(tampered)

    def test_transaction_batch_rejects_partial_concurrency_and_outbox_bindings(self) -> None:
        batch = self.batch()
        with self.assertRaisesRegex(PersistenceContractError, "version binding"):
            TransactionBatch(
                tenant_ref=batch.tenant_ref,
                assessment_ref=batch.assessment_ref,
                scope_ref=batch.scope_ref,
                idempotency_key=batch.idempotency_key,
                isolation_level=batch.isolation_level,
                created_at=batch.created_at,
                operations=batch.operations,
                version_bindings=batch.version_bindings[:1],
                fence_bindings=batch.fence_bindings,
                outbox_event_refs=batch.outbox_event_refs,
            )
        with self.assertRaisesRegex(PersistenceContractError, "appear together"):
            TransactionBatch(
                tenant_ref=batch.tenant_ref,
                assessment_ref=batch.assessment_ref,
                scope_ref=batch.scope_ref,
                idempotency_key=batch.idempotency_key,
                isolation_level=batch.isolation_level,
                created_at=batch.created_at,
                operations=batch.operations,
                version_bindings=batch.version_bindings,
                fence_bindings=batch.fence_bindings,
                outbox_event_refs=(),
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_top_level_contracts_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        documents = (
            sqlite_development_capabilities().to_dict(),
            postgresql_production_capabilities().to_dict(),
            self.manifest().to_dict(),
            self.batch().to_dict(),
            evaluate_deployment_suitability(
                postgresql_production_capabilities(), self.production_requirements()
            ).to_dict(),
        )
        for document in documents:
            with self.subTest(kind=document["kind"]):
                validator.validate(document)
                changed = copy.deepcopy(document)
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_contract_kind_and_canonical_json_fail_closed(self) -> None:
        with self.assertRaisesRegex(PersistenceContractError, "unsupported"):
            parse_contract({"kind": "sunderkey.persistence-unknown.v1"})
        document = sqlite_development_capabilities().to_json()
        with self.assertRaisesRegex(PersistenceContractError, "canonical"):
            BackendCapabilityDeclaration.from_json(document + "\n")

    def test_increment_has_no_unicode_dashes_or_authorship_markers(self) -> None:
        marker_fragments = (
            "generated " + "by",
            "written " + "by " + "an " + "ai",
            "as " + "an " + "ai",
            "chat" + "gpt",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in marker_fragments:
                self.assertNotIn(marker, lowered, path)

    def test_module_imports_no_database_or_network_clients(self) -> None:
        source = FILES[0].read_text(encoding="utf-8")
        forbidden = (
            "import " + "sqlite3",
            "import " + "psycopg",
            "import " + "sqlalchemy",
            "import " + "socket",
            "import " + "requests",
            "import " + "urllib",
        )
        for marker in forbidden:
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()

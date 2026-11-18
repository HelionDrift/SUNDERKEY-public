"""Phase 185 provider-neutral production custody contract coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_production_custody_provider_contract import (
    build_contract,
    build_parser,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    AUTHORIZED_IMPLEMENTATION_STEP,
    CONFORMANCE_CASE_IDS,
    CatalogObjectDescriptor,
    CatalogObjectPutRequest,
    ConditionalLedgerHeadProvider,
    ImmutableCatalogObjectProvider,
    LedgerHeadDescriptor,
    NativeCheckpointAccessProvider,
    ProductionCustodyProviderContract,
    ProviderPolicyRejection,
    ReleaseAuditSink,
    ReleaseHeadSigner,
    ReleaseHeadVerificationRequest,
    ReleaseHeadVerifier,
    RetentionLockedLedgerObjectProvider,
    SignedReleaseHeadDescriptor,
    WorkloadIdentityDescriptor,
    WorkloadIdentityVerificationRequest,
    WorkloadIdentityVerifier,
    build_production_custody_provider_contract,
    load_production_custody_provider_contract,
    provider_subject_sha256,
)
from sunderkey.candidate_enrollment_production_custody_decision import (
    PROHIBITED_EFFECTS,
    load_candidate_enrollment_production_custody_decision_record,
)
from sunderkey.candidate_enrollment_production_custody_dossier import (
    AUTHORIZED_NEXT_STEPS_IF_APPROVED,
    NONNEGOTIABLE_REQUIREMENTS,
    RECOMMENDED_OPTIONS,
    REQUIRED_OWNER_INPUTS,
    load_candidate_enrollment_production_custody_dossier,
)
from sunderkey.errors import QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "candidate-enrollment-production-custody-dossier-d012.json"
DECISION_PATH = REGISTRY / "candidate-enrollment-production-custody-decision-d012.json"
CONTRACT_PATH = REGISTRY / "candidate-enrollment-production-custody-contract-d012.json"
SCHEMA_PATH = (
    REGISTRY
    / "schemas"
    / "candidate-enrollment-production-custody-contract-v1.schema.json"
)
MODULE_PATH = (
    ROOT / "src/sunderkey/candidate_enrollment_production_custody_contract.py"
)
BUILDER_PATH = ROOT / "scripts/build_production_custody_provider_contract.py"

EXPECTED_CASE_IDS = (
    "exact_checkpoint_identity",
    "interrupted_checkpoint_replacement",
    "ledger_put_if_absent",
    "retention_lock",
    "conditional_head_cas_race",
    "ledger_lineage_integrity",
    "immutable_catalog_objects",
    "custody_separation",
    "workload_identity_lifecycle",
    "signed_head_verification",
    "audit_append_blocks_release",
    "partial_release_recovery",
)


class _NativeProviderShape:
    def verify_exact_service_identity(self, request: object) -> object:
        raise NotImplementedError

    def protect_directory(self, path: Path) -> None:
        raise NotImplementedError

    def verify_directory(self, path: Path) -> None:
        raise NotImplementedError

    def protect_file(self, path: Path) -> None:
        raise NotImplementedError

    def verify_file(self, path: Path) -> None:
        raise NotImplementedError

    def sync_directory(self, path: Path) -> None:
        raise NotImplementedError


class _LedgerObjectProviderShape:
    def put_if_absent(self, request: object) -> object:
        raise NotImplementedError

    def read_verified(self, request: object) -> object:
        raise NotImplementedError

    def read_retention_state(self, request: object) -> object:
        raise NotImplementedError


class _HeadProviderShape:
    def read_head(self, request: object) -> object:
        raise NotImplementedError

    def compare_and_swap_head(self, request: object) -> object:
        raise NotImplementedError


class _CatalogProviderShape:
    def put_sha256_object(self, request: object) -> object:
        raise NotImplementedError

    def read_sha256_object(self, request: object) -> object:
        raise NotImplementedError


class _IdentityVerifierShape:
    def verify_identity(self, request: object) -> object:
        raise NotImplementedError

    def verify_scope(self, request: object) -> object:
        raise NotImplementedError

    def verify_freshness(self, request: object) -> object:
        raise NotImplementedError


class _SignerShape:
    def sign_head(self, request: object) -> object:
        raise NotImplementedError


class _VerifierShape:
    def verify_signed_head(self, request: object) -> object:
        raise NotImplementedError


class _AuditShape:
    def append_audit_event(self, request: object) -> object:
        raise NotImplementedError


class ProductionCustodyProviderContractPhase185Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_candidate_enrollment_production_custody_dossier(DOSSIER_PATH)
        cls.decision = load_candidate_enrollment_production_custody_decision_record(
            DECISION_PATH
        )

    def test_checked_contract_rebuilds_exactly(self) -> None:
        checked = load_production_custody_provider_contract(CONTRACT_PATH)
        rebuilt = build_production_custody_provider_contract(
            self.dossier, self.decision
        )
        self.assertEqual(checked, rebuilt)
        self.assertEqual(checked.to_dict(), rebuilt.to_dict())
        expected = build_contract(build_parser().parse_args([]))
        self.assertEqual(
            CONTRACT_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_checked_contract_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(
            load_production_custody_provider_contract(CONTRACT_PATH).to_dict()
        )

    def test_exact_current_d012_bundle_is_bound(self) -> None:
        document = build_production_custody_provider_contract(
            self.dossier, self.decision
        ).to_dict()
        self.assertEqual(
            document["source_dossier"],
            {
                "report_id": "PCD-28D9E7D3DECE4A4103645CE0F0828D9A",
                "sha256": (
                    "sha256:28d9e7d3dece4a4103645ce0f0828d9"
                    "a5ffec5c2541f408f077d7613ae6c5667"
                ),
            },
        )
        self.assertEqual(
            document["source_decision"],
            {
                "record_id": "PCR-A2ACC5733A815AA349F5F6B7F1FBE5A3",
                "sha256": (
                    "sha256:a2acc5733a815aa349f5f6b7f1fbe5a3"
                    "0881446417a9268923e96dea3c1624de"
                ),
            },
        )
        self.assertEqual(document["selected_architecture"], RECOMMENDED_OPTIONS)
        self.assertEqual(document["required_owner_inputs"], list(REQUIRED_OWNER_INPUTS))
        self.assertEqual(
            document["nonnegotiable_requirements"],
            list(NONNEGOTIABLE_REQUIREMENTS),
        )
        self.assertEqual(document["prohibited_effects"], list(PROHIBITED_EFFECTS))
        self.assertEqual(
            document["approved_next_steps"],
            list(AUTHORIZED_NEXT_STEPS_IF_APPROVED),
        )
        self.assertEqual(len(document["selected_architecture"]), 8)
        self.assertEqual(len(document["required_owner_inputs"]), 5)
        self.assertEqual(len(document["nonnegotiable_requirements"]), 10)
        self.assertEqual(len(document["prohibited_effects"]), 8)
        self.assertEqual(len(document["approved_next_steps"]), 7)

    def test_only_interface_and_conformance_definition_is_authorized(self) -> None:
        document = build_production_custody_provider_contract(
            self.dossier, self.decision
        ).to_dict()
        authorization = document["implementation_authorization"]
        self.assertEqual(authorization["authorized_steps"], [AUTHORIZED_IMPLEMENTATION_STEP])
        self.assertEqual(
            authorization["deferred_steps"],
            list(AUTHORIZED_NEXT_STEPS_IF_APPROVED[1:]),
        )
        self.assertEqual(CONFORMANCE_CASE_IDS, EXPECTED_CASE_IDS)
        self.assertEqual(document["conformance_case_ids"], list(EXPECTED_CASE_IDS))
        self.assertEqual(len(document["provider_interfaces"]), 8)

    def test_protocols_are_runtime_checkable_and_checkpoint_provider_composes(self) -> None:
        pairs = (
            (_NativeProviderShape(), NativeCheckpointAccessProvider),
            (_LedgerObjectProviderShape(), RetentionLockedLedgerObjectProvider),
            (_HeadProviderShape(), ConditionalLedgerHeadProvider),
            (_CatalogProviderShape(), ImmutableCatalogObjectProvider),
            (_IdentityVerifierShape(), WorkloadIdentityVerifier),
            (_SignerShape(), ReleaseHeadSigner),
            (_VerifierShape(), ReleaseHeadVerifier),
            (_AuditShape(), ReleaseAuditSink),
        )
        for provider, protocol in pairs:
            with self.subTest(protocol=protocol.__name__):
                self.assertIsInstance(provider, protocol)
        operations = {
            item["interface_id"]: item["required_operations"]
            for item in build_production_custody_provider_contract(
                self.dossier, self.decision
            ).to_dict()["provider_interfaces"]
        }
        self.assertNotIn("atomic_replace", operations["native_checkpoint_access"])
        self.assertEqual(
            operations["native_checkpoint_access"],
            [
                "verify_exact_service_identity",
                "protect_directory",
                "verify_directory",
                "protect_file",
                "verify_file",
                "sync_directory",
            ],
        )

    def test_typed_values_are_immutable_and_validate_security_bindings(self) -> None:
        payload = b"catalog"
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        catalog = CatalogObjectDescriptor(
            object_id="catalog-1",
            sha256=digest,
            size_bytes=len(payload),
            namespace_id="catalog",
            failure_domain_id="catalog-zone",
        )
        request = CatalogObjectPutRequest("request-1", catalog, payload)
        with self.assertRaises(FrozenInstanceError):
            request.request_id = "changed"
        with self.assertRaisesRegex(ValueError, "digest"):
            CatalogObjectPutRequest("request-2", catalog, b"changed")

        identity = WorkloadIdentityDescriptor(
            provider_id="identity-provider-1",
            identity_id="service-1",
            audience="sunderkey-custody",
            scope_ids=("checkpoint-read", "checkpoint-write"),
            issued_at="2026-09-20T00:00:00Z",
            expires_at="2026-09-20T01:00:00Z",
            rotation_id="rotation-7",
            rotation_state="current",
        )
        WorkloadIdentityVerificationRequest(
            request_id="identity-request-1",
            identity=identity,
            required_provider_id="identity-provider-1",
            required_scope_ids=("checkpoint-read",),
            required_rotation_id="rotation-7",
            required_rotation_state="current",
            verified_at="2026-09-20T00:30:00Z",
        )
        with self.assertRaisesRegex(ValueError, "provider"):
            WorkloadIdentityVerificationRequest(
                request_id="identity-request-2",
                identity=identity,
                required_provider_id="identity-provider-2",
                required_scope_ids=("checkpoint-read",),
                required_rotation_id="rotation-7",
                required_rotation_state="current",
                verified_at="2026-09-20T00:30:00Z",
            )

        root_digest = "sha256:" + "a" * 64
        head = LedgerHeadDescriptor(
            deployment_id="deployment-1",
            ledger_sequence=1,
            entry_id="entry-1",
            entry_sha256="sha256:" + "b" * 64,
            previous_head_sha256=None,
        )
        signed = SignedReleaseHeadDescriptor(
            head=head,
            signer_key_id="signer-1",
            offline_root_authorization_sha256=root_digest,
            signing_algorithm="ed25519",
            signature=b"signature",
            signed_at="2026-09-20T00:05:00Z",
        )
        with self.assertRaisesRegex(ValueError, "root authorization"):
            ReleaseHeadVerificationRequest(
                request_id="verify-1",
                signed_head=signed,
                expected_offline_root_authorization_sha256="sha256:" + "c" * 64,
                expected_previous_head_sha256=None,
                verified_at="2026-09-20T00:06:00Z",
            )

    def test_provider_policy_rejection_is_exactly_request_and_subject_bound(self) -> None:
        subject = CatalogObjectDescriptor(
            object_id="catalog-1",
            sha256="sha256:" + "a" * 64,
            size_bytes=1,
            namespace_id="catalog",
            failure_domain_id="catalog-zone",
        )
        digest = provider_subject_sha256(subject)
        rejection = ProviderPolicyRejection(
            "immutable_catalog_overwrite",
            "request-1",
            digest,
        )
        self.assertEqual(rejection.rejection_code, "immutable_catalog_overwrite")
        self.assertEqual(rejection.request_id, "request-1")
        self.assertEqual(rejection.subject_sha256, digest)
        with self.assertRaisesRegex(ValueError, "rejection_code"):
            ProviderPolicyRejection("INVALID", "request-1", digest)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            ProviderPolicyRejection(
                "immutable_catalog_overwrite",
                "request-1",
                "not-a-digest",
            )

    def test_tampering_and_stale_source_bindings_are_rejected(self) -> None:
        contract = build_production_custody_provider_contract(
            self.dossier, self.decision
        )
        for field, replacement in (
            (
                "source_dossier",
                {
                    "report_id": self.dossier.report_id,
                    "sha256": "sha256:" + "0" * 64,
                },
            ),
            ("selected_architecture", {}),
            ("approved_next_steps", []),
            ("provider_selected", True),
        ):
            changed = copy.deepcopy(contract.to_dict())
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaises(QualificationError):
                ProductionCustodyProviderContract.from_dict(changed)
        rehashed = copy.deepcopy(contract.to_dict())
        rehashed["implementation_authorization"]["authorized_steps"] = [
            AUTHORIZED_NEXT_STEPS_IF_APPROVED[1]
        ]
        with self.assertRaisesRegex(QualificationError, "authorization"):
            ProductionCustodyProviderContract.from_dict(rehashed)

    def test_contract_contains_no_provider_selection_or_sensitive_fields(self) -> None:
        document = build_production_custody_provider_contract(
            self.dossier, self.decision
        ).to_dict()
        self.assertFalse(document["provider_selected"])
        self.assertFalse(document["contains_provider_implementation"])
        self.assertEqual(
            document["construction_effects"],
            {
                "network_call_performed": False,
                "provider_call_performed": False,
                "filesystem_mutation_performed": False,
                "sqlite_mutation_performed": False,
                "runtime_state_mutation_performed": False,
            },
        )

        keys: set[str] = set()

        def collect_keys(value: object) -> None:
            if isinstance(value, dict):
                keys.update(str(key).lower() for key in value)
                for item in value.values():
                    collect_keys(item)
            elif isinstance(value, list):
                for item in value:
                    collect_keys(item)

        collect_keys(document)
        for fragment in ("endpoint", "private_key", "secret", "credential_value"):
            with self.subTest(fragment=fragment):
                self.assertFalse(any(fragment in key for key in keys))

    def test_builder_has_no_network_provider_storage_or_execution_imports(self) -> None:
        prohibited = {
            "asyncio",
            "boto3",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for path in (MODULE_PATH, BUILDER_PATH):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = {
                alias.name.split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
                for alias in node.names
            }
            imported.update(
                str(node.module).split(".")[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom)
            )
            with self.subTest(path=path.name):
                self.assertFalse(imported & prohibited)

    def test_script_writes_only_the_requested_checked_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "contract.json"
            args = build_parser().parse_args(["--output", str(output)])
            expected = build_contract(args)
            output.write_text(
                json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            loaded = load_production_custody_provider_contract(output)
            self.assertEqual(loaded.to_dict(), expected)
            self.assertEqual([item.name for item in Path(temporary).iterdir()], ["contract.json"])


if __name__ == "__main__":
    unittest.main()

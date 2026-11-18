"""Phase 185 executable production custody conformance coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import sunderkey.candidate_enrollment_production_custody_conformance as custody_conformance

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.candidate_enrollment_checkpoint_store import (
    AtomicCandidateEnrollmentCheckpointStore,
)
from sunderkey.candidate_enrollment_deployment_verification import (
    RECEIPT_DOMAIN,
    CandidateEnrollmentDeploymentVerificationReceipt,
)
from sunderkey.candidate_enrollment_production_custody_conformance import (
    CASE_DEFINITIONS,
    CONFORMANCE_OPERATION_COVERAGE,
    EVIDENCE_DOMAIN,
    EXTERNAL_ENVIRONMENT,
    REFERENCE_ENVIRONMENT,
    REPORT_DOMAIN,
    CheckpointConformanceFixture,
    ConformanceControlRejection,
    ProductionCustodyAdapterBundle,
    ProductionCustodyConformanceReport,
    ProductionCustodyConformanceSuite,
    TestFaultAcknowledgement,
    TestOnlyProductionCustodyFaultInjector,
    build_production_custody_conformance_suite,
    run_production_custody_conformance,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    CatalogObjectDescriptor,
    CatalogObjectPutReceipt,
    CatalogObjectPutRequest,
    CatalogObjectReadReceipt,
    CatalogObjectReadRequest,
    CheckpointAccessVerificationReceipt,
    CheckpointAccessVerificationRequest,
    CheckpointResourceDescriptor,
    LedgerHeadCompareAndSwapReceipt,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadReceipt,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutReceipt,
    LedgerObjectPutRequest,
    LedgerObjectReadReceipt,
    LedgerObjectReadRequest,
    ProductionCustodyProviderContract,
    ProviderPolicyRejection,
    ReleaseAuditAppendReceipt,
    ReleaseAuditAppendRequest,
    ReleaseAuditEventDescriptor,
    ReleaseHeadSigningReceipt,
    ReleaseHeadSigningRequest,
    ReleaseHeadVerificationReceipt,
    ReleaseHeadVerificationRequest,
    RetentionStateReadReceipt,
    RetentionStateReadRequest,
    SignedReleaseHeadDescriptor,
    WorkloadIdentityDescriptor,
    WorkloadIdentityVerificationReceipt,
    WorkloadIdentityVerificationRequest,
    provider_subject_sha256,
)
from sunderkey.candidate_enrollment_release_contract import (
    build_candidate_enrollment_checkpoint_record,
    build_candidate_enrollment_release_ledger_entry,
)
from sunderkey.candidate_enrollment_verification import (
    CandidateEnrollmentCatalogCheckpoint,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_json, _canonical_sha256
from tests.agents import test_candidate_enrollment_release_contract_phase75

ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = ROOT / "registry" / "candidate-enrollment-production-custody-contract-d012.json"
SUITE_SCHEMA_PATH = (
    ROOT
    / "registry"
    / "schemas"
    / "candidate-enrollment-production-custody-conformance-suite-v1.schema.json"
)
REPORT_SCHEMA_PATH = (
    ROOT
    / "registry"
    / "schemas"
    / "candidate-enrollment-production-custody-conformance-report-v1.schema.json"
)


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _head_digest(head: LedgerHeadDescriptor) -> str:
    return _canonical_sha256(
        {
            "deployment_id": head.deployment_id,
            "ledger_sequence": head.ledger_sequence,
            "entry_id": head.entry_id,
            "entry_sha256": head.entry_sha256,
            "previous_head_sha256": head.previous_head_sha256,
        }
    )


class ReferenceFaultInjector:
    """Separate test-only fault and separation control."""

    def __init__(self) -> None:
        self.armed_fault: str | None = None
        self.armed_request_id: str | None = None
        self.armed_subject_sha256: str | None = None

    def arm(
        self,
        fault_id: str,
        request_id: str,
        subject_sha256: str,
    ) -> None:
        self.armed_fault = fault_id
        self.armed_request_id = request_id
        self.armed_subject_sha256 = subject_sha256

    def clear(self) -> None:
        self.armed_fault = None
        self.armed_request_id = None
        self.armed_subject_sha256 = None

    def rejects(self, fault_id: str) -> None:
        if self.armed_fault == fault_id:
            if self.armed_request_id is None or self.armed_subject_sha256 is None:
                raise QualificationError("Armed fault binding is unavailable")
            raise TestFaultAcknowledgement(
                fault_id,
                self.armed_request_id,
                self.armed_subject_sha256,
            )

    def separation_snapshot(self, bundle: ProductionCustodyAdapterBundle) -> Mapping[str, str]:
        return {
            "checkpoint_scope_id": bundle.checkpoint.resource.service_identity_scope_id,
            "ledger_namespace_id": bundle.ledger_object.namespace_id,
            "ledger_failure_domain_id": bundle.ledger_object.failure_domain_id,
            "catalog_namespace_id": bundle.catalog_object.namespace_id,
            "catalog_failure_domain_id": bundle.catalog_object.failure_domain_id,
            "signer_role_id": "role.release_signer",
            "verifier_role_id": "role.release_verifier",
        }

    def assert_separation(self, snapshot: Mapping[str, str]) -> None:
        if snapshot["ledger_namespace_id"] == snapshot["catalog_namespace_id"]:
            raise ConformanceControlRejection(
                "custody_separation_collapsed",
                provider_subject_sha256(snapshot),
            )
        if snapshot["ledger_failure_domain_id"] == snapshot["catalog_failure_domain_id"]:
            raise ConformanceControlRejection(
                "custody_separation_collapsed",
                provider_subject_sha256(snapshot),
            )
        if snapshot["signer_role_id"] == snapshot["verifier_role_id"]:
            raise ConformanceControlRejection(
                "custody_separation_collapsed",
                provider_subject_sha256(snapshot),
            )

    def signer_call_count(self, signer: object) -> int:
        count = getattr(signer, "call_count", None)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise QualificationError("Test signer call count is unavailable")
        return count


class ReferenceFaultFactory:
    def __init__(self) -> None:
        self.created_case_ids: list[str] = []

    def create_fault_injector(self, case_id: str) -> ReferenceFaultInjector:
        self.created_case_ids.append(case_id)
        return ReferenceFaultInjector()


class IgnoringFaultInjector(ReferenceFaultInjector):
    def rejects(self, fault_id: str) -> None:
        return None


class IgnoringFaultFactory(ReferenceFaultFactory):
    def create_fault_injector(self, case_id: str) -> IgnoringFaultInjector:
        self.created_case_ids.append(case_id)
        return IgnoringFaultInjector()


class LyingFaultInjector(ReferenceFaultInjector):
    def signer_call_count(self, signer: object) -> int:
        return 999


class LyingFaultFactory(ReferenceFaultFactory):
    def create_fault_injector(self, case_id: str) -> LyingFaultInjector:
        self.created_case_ids.append(case_id)
        return LyingFaultInjector()


class InMemoryCheckpointAccess:
    def __init__(self, fault: ReferenceFaultInjector) -> None:
        self.fault = fault

    def verify_exact_service_identity(
        self, request: CheckpointAccessVerificationRequest
    ) -> CheckpointAccessVerificationReceipt:
        observed = "identity.checkpoint.writer"
        if request.expected_identity_id != observed:
            raise ProviderPolicyRejection(
                "checkpoint_identity_mismatch",
                request.request_id,
                provider_subject_sha256(request.resource),
            )
        return CheckpointAccessVerificationReceipt(
            request.request_id,
            request.resource.resource_id,
            request.expected_identity_id,
            observed,
            True,
            True,
        )

    def protect_directory(self, path: Path) -> None:
        if not path.is_dir():
            raise QualificationError("Checkpoint directory is unavailable")

    def verify_directory(self, path: Path) -> None:
        if not path.is_dir() or path.is_symlink():
            raise QualificationError("Checkpoint directory verification failed")

    def protect_file(self, path: Path) -> None:
        if not path.is_file():
            raise QualificationError("Checkpoint file is unavailable")

    def verify_file(self, path: Path) -> None:
        if self.fault.armed_fault == "checkpoint_replacement" and path.suffix == ".tmp":
            self.fault.rejects("checkpoint_replacement")
        if not path.is_file() or path.is_symlink():
            raise QualificationError("Checkpoint file verification failed")

    def sync_directory(self, path: Path) -> None:
        if not path.is_dir():
            raise QualificationError("Checkpoint directory sync failed")


class InMemoryLedgerObjects:
    def __init__(self, fault: ReferenceFaultInjector) -> None:
        self.fault = fault
        self.objects: dict[str, tuple[LedgerObjectDescriptor, bytes]] = {}

    def put_if_absent(self, request: LedgerObjectPutRequest) -> LedgerObjectPutReceipt:
        current = self.objects.get(request.object.object_id)
        if current is None:
            self.objects[request.object.object_id] = (request.object, request.payload)
            status = "created"
        elif current == (request.object, request.payload):
            status = "already_present_same_digest"
        else:
            raise ProviderPolicyRejection(
                "immutable_ledger_overwrite",
                request.request_id,
                provider_subject_sha256(request.object),
            )
        return LedgerObjectPutReceipt(request.request_id, request.object, status, True)

    def read_verified(self, request: LedgerObjectReadRequest) -> LedgerObjectReadReceipt:
        try:
            descriptor, payload = self.objects[request.object_id]
        except KeyError as exc:
            raise QualificationError("Ledger object is unavailable") from exc
        if descriptor.sha256 != request.expected_sha256:
            raise QualificationError("Ledger digest does not match")
        return LedgerObjectReadReceipt(request.request_id, descriptor, payload, True)

    def read_retention_state(self, request: RetentionStateReadRequest) -> RetentionStateReadReceipt:
        self.fault.rejects("retention_unavailable")
        try:
            descriptor, _ = self.objects[request.object_id]
        except KeyError as exc:
            raise QualificationError("Ledger retention object is unavailable") from exc
        if descriptor.retention_until < request.required_retention_until:
            raise QualificationError("Required retention is not met")
        return RetentionStateReadReceipt(request.request_id, descriptor, True, True)


class InMemoryLedgerHeads:
    def __init__(self) -> None:
        self.heads: dict[str, LedgerHeadDescriptor] = {}
        self.read_count = 0

    def read_head(self, request: LedgerHeadReadRequest) -> LedgerHeadReadReceipt:
        self.read_count += 1
        return LedgerHeadReadReceipt(request.request_id, self.heads.get(request.deployment_id))

    def compare_and_swap_head(
        self, request: LedgerHeadCompareAndSwapRequest
    ) -> LedgerHeadCompareAndSwapReceipt:
        proposed = request.proposed_head
        current = self.heads.get(proposed.deployment_id)
        if current == proposed:
            return LedgerHeadCompareAndSwapReceipt(
                request.request_id, proposed, "already_current_same_digest"
            )
        current_digest = None if current is None else _head_digest(current)
        if current_digest != request.expected_head_sha256:
            raise ProviderPolicyRejection(
                "ledger_head_conflict",
                request.request_id,
                provider_subject_sha256(request.proposed_head),
            )
        expected_sequence = 1 if current is None else current.ledger_sequence + 1
        if proposed.ledger_sequence != expected_sequence:
            raise ProviderPolicyRejection(
                "ledger_sequence_gap",
                request.request_id,
                provider_subject_sha256(request.proposed_head),
            )
        self.heads[proposed.deployment_id] = proposed
        return LedgerHeadCompareAndSwapReceipt(request.request_id, proposed, "advanced")


class InMemoryCatalogObjects:
    def __init__(self, fault: ReferenceFaultInjector) -> None:
        self.fault = fault
        self.objects: dict[str, tuple[CatalogObjectDescriptor, bytes]] = {}

    def put_sha256_object(self, request: CatalogObjectPutRequest) -> CatalogObjectPutReceipt:
        self.fault.rejects("catalog_put")
        current = self.objects.get(request.object.object_id)
        if current is None:
            self.objects[request.object.object_id] = (request.object, request.payload)
            status = "created"
        elif current == (request.object, request.payload):
            status = "already_present_same_digest"
        else:
            raise ProviderPolicyRejection(
                "immutable_catalog_overwrite",
                request.request_id,
                provider_subject_sha256(request.object),
            )
        return CatalogObjectPutReceipt(request.request_id, request.object, status, True)

    def read_sha256_object(self, request: CatalogObjectReadRequest) -> CatalogObjectReadReceipt:
        try:
            descriptor, payload = self.objects[request.object_id]
        except KeyError as exc:
            raise QualificationError("Catalog object is unavailable") from exc
        if descriptor.sha256 != request.expected_sha256:
            raise QualificationError("Catalog digest does not match")
        return CatalogObjectReadReceipt(request.request_id, descriptor, payload, True)


class InMemoryWorkloadIdentity:
    def __init__(
        self,
        *,
        provider_id: str,
        required_scope_ids: tuple[str, ...],
        rotation_id: str,
        minimum_expires_at: str,
    ) -> None:
        self.provider_id = provider_id
        self.required_scope_ids = required_scope_ids
        self.rotation_id = rotation_id
        self.minimum_expires_at = minimum_expires_at
        self.call_counts = {"identity": 0, "scope": 0, "freshness": 0}

    def _receipt(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt:
        return WorkloadIdentityVerificationReceipt(
            request.request_id, request.identity, True, True, True
        )

    def verify_identity(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt:
        self.call_counts["identity"] += 1
        if request.identity.provider_id != self.provider_id:
            raise ProviderPolicyRejection(
                "provider_mismatch",
                request.request_id,
                provider_subject_sha256(request.identity),
            )
        if request.identity.rotation_id != self.rotation_id:
            raise ProviderPolicyRejection(
                "rotation_policy_mismatch",
                request.request_id,
                provider_subject_sha256(request.identity),
            )
        return self._receipt(request)

    def verify_scope(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt:
        self.call_counts["scope"] += 1
        if not set(self.required_scope_ids).issubset(request.identity.scope_ids):
            raise ProviderPolicyRejection(
                "scope_policy_mismatch",
                request.request_id,
                provider_subject_sha256(request.identity),
            )
        return self._receipt(request)

    def verify_freshness(
        self, request: WorkloadIdentityVerificationRequest
    ) -> WorkloadIdentityVerificationReceipt:
        self.call_counts["freshness"] += 1
        if request.identity.expires_at < self.minimum_expires_at:
            raise ProviderPolicyRejection(
                "freshness_policy_mismatch",
                request.request_id,
                provider_subject_sha256(request.identity),
            )
        return self._receipt(request)


class InMemorySigner:
    def __init__(self) -> None:
        self.call_count = 0

    @staticmethod
    def signature(request: ReleaseHeadSigningRequest) -> bytes:
        public_material = {
            "head_sha256": _head_digest(request.head),
            "signer_key_id": request.signer_key_id,
            "offline_root_authorization_sha256": request.offline_root_authorization_sha256,
            "signing_algorithm": request.signing_algorithm,
            "requested_at": request.requested_at,
        }
        return hashlib.sha256(_canonical_json(public_material).encode("ascii")).digest()

    def sign_head(self, request: ReleaseHeadSigningRequest) -> ReleaseHeadSigningReceipt:
        self.call_count += 1
        signed = SignedReleaseHeadDescriptor(
            request.head,
            request.signer_key_id,
            request.offline_root_authorization_sha256,
            request.signing_algorithm,
            self.signature(request),
            request.requested_at,
        )
        return ReleaseHeadSigningReceipt(request.request_id, signed)


class InMemoryVerifier:
    def __init__(
        self,
        expected_root_authorization_sha256: str,
        expected_previous_head_sha256: str | None,
    ) -> None:
        self.expected_root_authorization_sha256 = expected_root_authorization_sha256
        self.expected_previous_head_sha256 = expected_previous_head_sha256
        self.call_count = 0

    def verify_signed_head(
        self, request: ReleaseHeadVerificationRequest
    ) -> ReleaseHeadVerificationReceipt:
        self.call_count += 1
        signed = request.signed_head
        if (
            signed.offline_root_authorization_sha256
            != self.expected_root_authorization_sha256
        ):
            raise ProviderPolicyRejection(
                "root_authorization_mismatch",
                request.request_id,
                provider_subject_sha256(signed.head),
            )
        if signed.head.previous_head_sha256 != self.expected_previous_head_sha256:
            raise ProviderPolicyRejection(
                "predecessor_policy_mismatch",
                request.request_id,
                provider_subject_sha256(signed.head),
            )
        signing_request = ReleaseHeadSigningRequest(
            "request.signature.rebuild",
            signed.head,
            signed.signer_key_id,
            signed.offline_root_authorization_sha256,
            signed.signing_algorithm,
            signed.signed_at,
        )
        if signed.signature != InMemorySigner.signature(signing_request):
            raise ProviderPolicyRejection(
                "signature_mismatch",
                request.request_id,
                provider_subject_sha256(signed.head),
            )
        return ReleaseHeadVerificationReceipt(request.request_id, signed, True, True, True)


class InMemoryAuditSink:
    def __init__(self, fault: ReferenceFaultInjector) -> None:
        self.fault = fault
        self.events: dict[str, ReleaseAuditEventDescriptor] = {}

    def append_audit_event(self, request: ReleaseAuditAppendRequest) -> ReleaseAuditAppendReceipt:
        self.fault.rejects("audit_append")
        current = self.events.get(request.event.event_id)
        if current is None:
            self.events[request.event.event_id] = request.event
            status = "appended"
        elif current == request.event:
            status = "already_appended_same_digest"
        else:
            raise QualificationError("Audit event collision rejected")
        sequence = list(self.events).index(request.event.event_id) + 1
        return ReleaseAuditAppendReceipt(request.request_id, request.event, sequence, status)


class ReferenceAdapterFactory:
    """Test-only in-memory adapter bundle factory."""

    environment_class = REFERENCE_ENVIRONMENT

    def __init__(self, initial_intent, initial_record, replacement_intent, replacement_record):
        self.initial_intent = initial_intent
        self.initial_record = initial_record
        self.replacement_intent = replacement_intent
        self.replacement_record = replacement_record
        self.created_case_ids: list[str] = []
        self.bundles: list[ProductionCustodyAdapterBundle] = []
        self.temporary_directories: list[tempfile.TemporaryDirectory[str]] = []

    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        if not isinstance(fault_injector, ReferenceFaultInjector):
            raise QualificationError("Reference factory requires its test fault injector")
        self.created_case_ids.append(case_id)
        temporary = tempfile.TemporaryDirectory()
        self.temporary_directories.append(temporary)
        checkpoint_access = InMemoryCheckpointAccess(fault_injector)
        store = AtomicCandidateEnrollmentCheckpointStore(
            Path(temporary.name) / "checkpoint", checkpoint_access
        )
        store.initialize_directory()
        checkpoint_resource = CheckpointResourceDescriptor(
            "checkpoint.primary",
            "namespace.checkpoint",
            "failure.checkpoint",
            "scope.checkpoint.writer",
        )
        checkpoint = CheckpointConformanceFixture(
            store,
            checkpoint_resource,
            "identity.checkpoint.writer",
            self.initial_record,
            self.initial_intent,
            self.replacement_record,
            self.replacement_intent,
        )
        ledger_payload = b"immutable-ledger-object"
        ledger = LedgerObjectDescriptor(
            "ledger.release.1",
            _bytes_digest(ledger_payload),
            len(ledger_payload),
            "2036-01-01T00:00:00Z",
            "namespace.ledger",
            "failure.ledger",
        )
        initial_head = LedgerHeadDescriptor(
            "deployment.phase185", 1, "entry.release.1", ledger.sha256, None
        )
        successor_head = LedgerHeadDescriptor(
            "deployment.phase185",
            2,
            "entry.release.2",
            "sha256:" + "b" * 64,
            _head_digest(initial_head),
        )
        catalog_payload = b"immutable-catalog-object"
        catalog = CatalogObjectDescriptor(
            "catalog.release.1",
            _bytes_digest(catalog_payload),
            len(catalog_payload),
            "namespace.catalog",
            "failure.catalog",
        )
        identity = WorkloadIdentityDescriptor(
            "provider.workload",
            "identity.release.worker",
            "audience.production.custody",
            ("scope.ledger", "scope.catalog", "scope.audit"),
            "2026-09-20T00:00:00Z",
            "2026-09-20T01:00:00Z",
            "rotation.current.1",
            "current",
        )
        workload_request = WorkloadIdentityVerificationRequest(
            "request.identity.current",
            identity,
            "provider.workload",
            ("scope.ledger", "scope.catalog"),
            "rotation.current.1",
            "current",
            "2026-09-20T00:30:00Z",
        )
        root_digest = "sha256:" + "a" * 64
        signing_request = ReleaseHeadSigningRequest(
            "request.sign.release",
            initial_head,
            "key.release.1",
            root_digest,
            "sha256_simulation",
            "2026-09-20T00:45:00Z",
        )
        audit = ReleaseAuditEventDescriptor(
            "audit.release.1",
            "release_ready",
            ledger.sha256,
            identity.identity_id,
            "2026-09-20T00:40:00Z",
        )
        implementation_digest = _canonical_sha256(
            {"implementation": "phase185_reference_simulation"}
        )
        configuration_digest = _canonical_sha256({"configuration": "isolated_case_bundle_v1"})
        bundle = ProductionCustodyAdapterBundle(
            REFERENCE_ENVIRONMENT,
            {
                "provider_id": "phase185_reference_simulation",
                "adapter_id": "in_memory_reference_adapter",
                "adapter_version": "1.0.0",
                "build_sha256": implementation_digest,
                "configuration_sha256": configuration_digest,
                "namespace_reference": "isolated_case_namespace",
                "credential_scope_sha256": _canonical_sha256(
                    {"credential_scope": "none"}
                ),
                "failure_domain_reference": "in_memory_case_failure_domain",
            },
            checkpoint_access,
            checkpoint,
            InMemoryLedgerObjects(fault_injector),
            ledger,
            ledger_payload,
            InMemoryLedgerHeads(),
            initial_head,
            successor_head,
            InMemoryCatalogObjects(fault_injector),
            catalog,
            catalog_payload,
            InMemoryWorkloadIdentity(
                provider_id="provider.workload",
                required_scope_ids=("scope.ledger", "scope.catalog"),
                rotation_id="rotation.current.1",
                minimum_expires_at="2026-09-20T01:00:00Z",
            ),
            workload_request,
            InMemorySigner(),
            InMemoryVerifier(root_digest, None),
            signing_request,
            InMemoryAuditSink(fault_injector),
            audit,
        )
        self.bundles.append(bundle)
        return bundle

    def close(self) -> None:
        for temporary in self.temporary_directories:
            temporary.cleanup()
        self.temporary_directories.clear()


class CheckpointReceiptSubclass(CheckpointAccessVerificationReceipt):
    pass


class SubclassReceiptCheckpointAccess(InMemoryCheckpointAccess):
    def verify_exact_service_identity(
        self, request: CheckpointAccessVerificationRequest
    ) -> CheckpointAccessVerificationReceipt:
        receipt = super().verify_exact_service_identity(request)
        return CheckpointReceiptSubclass(
            receipt.request_id,
            receipt.resource_id,
            receipt.expected_identity_id,
            receipt.observed_identity_id,
            receipt.identity_verified,
            receipt.least_privilege_verified,
        )


class SubclassReceiptAdapterFactory(ReferenceAdapterFactory):
    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        if case_id != "exact_checkpoint_identity":
            return bundle
        if not isinstance(fault_injector, ReferenceFaultInjector):
            raise QualificationError("Reference fault injector is invalid")
        return replace(
            bundle,
            checkpoint_access=SubclassReceiptCheckpointAccess(fault_injector),
        )


class WrongStatusLedgerObjects(InMemoryLedgerObjects):
    def put_if_absent(self, request: LedgerObjectPutRequest) -> LedgerObjectPutReceipt:
        receipt = super().put_if_absent(request)
        return LedgerObjectPutReceipt(
            receipt.request_id,
            receipt.object,
            "already_present_same_digest",
            True,
        )


class WrongStatusAdapterFactory(ReferenceAdapterFactory):
    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        if case_id != "ledger_put_if_absent":
            return bundle
        if not isinstance(fault_injector, ReferenceFaultInjector):
            raise QualificationError("Reference fault injector is invalid")
        return replace(
            bundle,
            ledger_objects=WrongStatusLedgerObjects(fault_injector),
        )


class MutatedFlagsCheckpointAccess(InMemoryCheckpointAccess):
    def verify_exact_service_identity(
        self, request: CheckpointAccessVerificationRequest
    ) -> CheckpointAccessVerificationReceipt:
        receipt = super().verify_exact_service_identity(request)
        object.__setattr__(receipt, "identity_verified", False)
        object.__setattr__(receipt, "least_privilege_verified", False)
        return receipt


class MutatedFlagsAdapterFactory(ReferenceAdapterFactory):
    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        if case_id != "exact_checkpoint_identity":
            return bundle
        if not isinstance(fault_injector, ReferenceFaultInjector):
            raise QualificationError("Reference fault injector is invalid")
        return replace(
            bundle,
            checkpoint_access=MutatedFlagsCheckpointAccess(fault_injector),
        )


class UnrelatedFailureCheckpointAccess(InMemoryCheckpointAccess):
    def verify_exact_service_identity(
        self, request: CheckpointAccessVerificationRequest
    ) -> CheckpointAccessVerificationReceipt:
        if request.expected_identity_id == "identity.wrong":
            raise QualificationError("Provider transport is unavailable")
        return super().verify_exact_service_identity(request)


class UnrelatedFailureAdapterFactory(ReferenceAdapterFactory):
    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        if case_id != "exact_checkpoint_identity":
            return bundle
        if not isinstance(fault_injector, ReferenceFaultInjector):
            raise QualificationError("Reference fault injector is invalid")
        return replace(
            bundle,
            checkpoint_access=UnrelatedFailureCheckpointAccess(fault_injector),
        )


class LedgerHeadsWithoutRead:
    def __init__(self, delegate: InMemoryLedgerHeads) -> None:
        self.delegate = delegate

    def compare_and_swap_head(
        self, request: LedgerHeadCompareAndSwapRequest
    ) -> LedgerHeadCompareAndSwapReceipt:
        return self.delegate.compare_and_swap_head(request)


class MissingReadHeadAdapterFactory(ReferenceAdapterFactory):
    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        return replace(
            bundle,
            ledger_heads=LedgerHeadsWithoutRead(bundle.ledger_heads),
        )


class RelabelledReferenceAdapterFactory(ReferenceAdapterFactory):
    environment_class = EXTERNAL_ENVIRONMENT

    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle:
        bundle = super().create_bundle(case_id, fault_injector)
        return replace(bundle, environment_class=EXTERNAL_ENVIRONMENT)


class ProductionCustodyConformancePhase185Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase75 = test_candidate_enrollment_release_contract_phase75
        phase75.CandidateEnrollmentReleaseContractPhase75Tests.setUpClass()
        cls.fixture = phase75.CandidateEnrollmentReleaseContractPhase75Tests(
            methodName="test_checkpoint_binds_intent_and_precedes_promotion"
        )
        cls.initial_intent = cls.fixture.intent()
        cls.initial_record = cls.fixture.checkpoint()
        receipt_document = copy.deepcopy(cls.fixture.receipt.to_dict())
        receipt_document["sources"]["catalog"]["sha256"] = "sha256:" + "e" * 64
        receipt_document["next_checkpoint"]["catalog_version"] = 2
        receipt_document["next_checkpoint"]["catalog_sha256"] = "sha256:" + "e" * 64
        body = {
            key: value
            for key, value in receipt_document.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        digest = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
        receipt_document["receipt_id"] = "CVR-" + digest.removeprefix("sha256:")[:32].upper()
        receipt_document["receipt_sha256"] = digest
        receipt = CandidateEnrollmentDeploymentVerificationReceipt.from_dict(receipt_document)
        checkpoint = CandidateEnrollmentCatalogCheckpoint.from_dict(
            receipt_document["next_checkpoint"]
        )
        release_id = "CRL-" + "2" * 32
        cls.replacement_intent = build_candidate_enrollment_release_ledger_entry(
            deployment_id="deployment.phase75",
            ledger_sequence=2,
            previous_entry=cls.initial_intent,
            event_type="release_intent",
            release_id=release_id,
            decision=cls.fixture.decision,
            verification_receipt=receipt,
            catalog_checkpoint=checkpoint,
            checkpoint_record=None,
            event_artifact=None,
            authority_mode="automatic_monotonic_advance",
            approval_bindings=[],
            event_time="2026-09-20T01:00:00Z",
        )
        cls.replacement_record = build_candidate_enrollment_checkpoint_record(
            deployment_id="deployment.phase75",
            checkpoint_sequence=2,
            release_id=release_id,
            catalog_checkpoint=checkpoint,
            verification_receipt=receipt,
            release_intent=cls.replacement_intent,
            predecessor_checkpoint=cls.initial_record,
            committed_at="2026-09-20T01:01:00Z",
        )
        cls.contract = ProductionCustodyProviderContract.from_dict(
            json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        )

    def factory(self) -> ReferenceAdapterFactory:
        return ReferenceAdapterFactory(
            self.initial_intent,
            self.initial_record,
            self.replacement_intent,
            self.replacement_record,
        )

    def test_suite_binds_exact_checked_contract_and_ordered_cases(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        self.assertEqual(suite.contract_id, "PCC-0EAA99F23A4CA891F9C22D040656263B")
        self.assertEqual(
            tuple(case.case_id for case in suite.cases),
            tuple(case.case_id for case in CASE_DEFINITIONS),
        )
        self.assertEqual(
            tuple(case.case_id for case in suite.cases),
            (
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
            ),
        )
        required_operations = {
            item["interface_id"]: tuple(item["required_operations"])
            for item in self.contract.to_dict()["provider_interfaces"]
        }
        self.assertEqual(CONFORMANCE_OPERATION_COVERAGE, required_operations)

    def test_reference_simulation_executes_all_cases_in_isolated_bundles(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        faults = ReferenceFaultFactory()
        try:
            report = run_production_custody_conformance(self.contract, suite, adapters, faults)
        finally:
            adapters.close()
        self.assertEqual(report.environment_class, REFERENCE_ENVIRONMENT)
        self.assertEqual(report.overall_outcome, "conformant")
        self.assertEqual(adapters.created_case_ids, [case.case_id for case in CASE_DEFINITIONS])
        self.assertEqual(faults.created_case_ids, adapters.created_case_ids)
        self.assertEqual(len(report.case_observations), 12)
        self.assertTrue(all(item.outcome == "pass" for item in report.case_observations))
        document = report.to_dict()
        for effect in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            self.assertEqual(document[effect], "none")
        self.assertEqual(document["environment_class"], "reference_simulation_nonqualifying")

    def test_ignored_faults_are_unexpected_and_fail_the_suite(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract,
                suite,
                adapters,
                IgnoringFaultFactory(),
            )
        finally:
            adapters.close()
        self.assertEqual(report.overall_outcome, "nonconformant")
        observations = {item.case_id: item for item in report.case_observations}
        for case_id, variant_id in (
            ("interrupted_checkpoint_replacement", "interrupted_replace"),
            ("retention_lock", "retention_unavailable"),
            ("audit_append_blocks_release", "audit_failure"),
            ("partial_release_recovery", "partial_release"),
        ):
            case = observations[case_id]
            self.assertEqual(case.outcome, "fail")
            variant = next(
                item
                for item in case.variant_observations
                if item.variant_id == variant_id
            )
            self.assertEqual(variant.observed_outcome, "unexpected")

    def test_negative_variants_reach_provider_owned_policy(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract, suite, adapters, ReferenceFaultFactory()
            )
            workload = adapters.bundles[8].workload_identity
            verifier = adapters.bundles[9].release_verifier
            signer = adapters.bundles[9].release_signer
            self.assertIsInstance(workload, InMemoryWorkloadIdentity)
            self.assertEqual(
                workload.call_counts,
                {"identity": 3, "scope": 2, "freshness": 2},
            )
            self.assertIsInstance(verifier, InMemoryVerifier)
            self.assertEqual(verifier.call_count, 4)
            self.assertIsInstance(signer, InMemorySigner)
            self.assertEqual(signer.call_count, 3)
            heads = adapters.bundles[4].ledger_heads
            self.assertIsInstance(heads, InMemoryLedgerHeads)
            self.assertEqual(heads.read_count, 2)
            self.assertEqual(report.overall_outcome, "conformant")
        finally:
            adapters.close()

    def test_reference_factory_cannot_be_relabelled_external(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            with self.assertRaisesRegex(QualificationError, "provenance"):
                run_production_custody_conformance(
                    self.contract,
                    suite,
                    adapters,
                    ReferenceFaultFactory(),
                    environment_class=EXTERNAL_ENVIRONMENT,
                )
        finally:
            adapters.close()

    def test_receipt_subclasses_and_wrong_positive_statuses_fail(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        factories = (
            SubclassReceiptAdapterFactory(
                self.initial_intent,
                self.initial_record,
                self.replacement_intent,
                self.replacement_record,
            ),
            WrongStatusAdapterFactory(
                self.initial_intent,
                self.initial_record,
                self.replacement_intent,
                self.replacement_record,
            ),
        )
        try:
            reports = [
                run_production_custody_conformance(
                    self.contract,
                    suite,
                    factory,
                    ReferenceFaultFactory(),
                )
                for factory in factories
            ]
        finally:
            for factory in factories:
                factory.close()
        self.assertTrue(all(report.overall_outcome == "nonconformant" for report in reports))
        self.assertEqual(reports[0].case_observations[0].outcome, "fail")
        self.assertEqual(reports[1].case_observations[2].outcome, "fail")

    def test_mutated_exact_receipt_security_flags_fail(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = MutatedFlagsAdapterFactory(
            self.initial_intent,
            self.initial_record,
            self.replacement_intent,
            self.replacement_record,
        )
        try:
            report = run_production_custody_conformance(
                self.contract,
                suite,
                adapters,
                ReferenceFaultFactory(),
            )
        finally:
            adapters.close()
        self.assertEqual(report.overall_outcome, "nonconformant")
        self.assertEqual(report.case_observations[0].outcome, "fail")
        self.assertEqual(
            report.case_observations[0].variant_observations[0].observed_outcome,
            "unexpected",
        )

    def test_deep_receipt_reconstruction_rejects_mutated_families(self) -> None:
        factory = self.factory()
        fault = ReferenceFaultInjector()
        try:
            bundle = factory.create_bundle("receipt_reconstruction", fault)
            checkpoint_request = CheckpointAccessVerificationRequest(
                "request.reconstruct.checkpoint",
                bundle.checkpoint.resource,
                bundle.checkpoint.expected_identity_id,
            )
            checkpoint_receipt = bundle.checkpoint_access.verify_exact_service_identity(
                checkpoint_request
            )
            object.__setattr__(checkpoint_receipt, "identity_verified", False)

            ledger_receipt = LedgerObjectPutReceipt(
                "request.reconstruct.ledger",
                bundle.ledger_object,
                "created",
                True,
            )
            object.__setattr__(ledger_receipt, "retention_lock_verified", False)

            identity_receipt = WorkloadIdentityVerificationReceipt(
                bundle.workload_request.request_id,
                bundle.workload_request.identity,
                True,
                True,
                True,
            )
            object.__setattr__(identity_receipt, "freshness_verified", False)

            signing_receipt = bundle.release_signer.sign_head(bundle.signing_request)
            verification_receipt = ReleaseHeadVerificationReceipt(
                "request.reconstruct.verify",
                signing_receipt.signed_head,
                True,
                True,
                True,
            )
            object.__setattr__(verification_receipt, "rollback_checked", False)

            audit_receipt = ReleaseAuditAppendReceipt(
                "request.reconstruct.audit",
                bundle.audit_event,
                1,
                "appended",
            )
            object.__setattr__(audit_receipt, "audit_sequence", 0)

            receipts = (
                (checkpoint_receipt, CheckpointAccessVerificationReceipt),
                (ledger_receipt, LedgerObjectPutReceipt),
                (identity_receipt, WorkloadIdentityVerificationReceipt),
                (verification_receipt, ReleaseHeadVerificationReceipt),
                (audit_receipt, ReleaseAuditAppendReceipt),
            )
            for receipt, receipt_type in receipts:
                with self.subTest(
                    receipt_type=receipt_type.__name__
                ), self.assertRaisesRegex(
                    QualificationError,
                    "semantic reconstruction",
                ):
                    custody_conformance._validated_receipt(
                        receipt,
                        receipt_type,
                        record_evidence=False,
                    )
        finally:
            factory.close()

    def test_unrelated_negative_failure_is_unexpected(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = UnrelatedFailureAdapterFactory(
            self.initial_intent,
            self.initial_record,
            self.replacement_intent,
            self.replacement_record,
        )
        try:
            report = run_production_custody_conformance(
                self.contract,
                suite,
                adapters,
                ReferenceFaultFactory(),
            )
        finally:
            adapters.close()
        wrong_identity = report.case_observations[0].variant_observations[1]
        self.assertEqual(report.overall_outcome, "nonconformant")
        self.assertEqual(wrong_identity.observed_outcome, "unexpected")
        self.assertEqual(
            wrong_identity.evidence_summary["rejection_code"],
            "unexpected_exception",
        )

    def test_provider_rejection_requires_exact_code_request_and_subject(self) -> None:
        factory = self.factory()
        fault = ReferenceFaultInjector()
        try:
            bundle = factory.create_bundle("typed_rejection", fault)
            request = CheckpointAccessVerificationRequest(
                "request.typed_rejection",
                bundle.checkpoint.resource,
                "identity.wrong",
            )
            expected_digest = provider_subject_sha256(bundle.checkpoint.resource)
            rejections = (
                ProviderPolicyRejection(
                    "ledger_head_conflict",
                    request.request_id,
                    expected_digest,
                ),
                ProviderPolicyRejection(
                    "checkpoint_identity_mismatch",
                    "request.wrong",
                    expected_digest,
                ),
                ProviderPolicyRejection(
                    "checkpoint_identity_mismatch",
                    request.request_id,
                    "sha256:" + "f" * 64,
                ),
            )
            for rejection in rejections:
                with self.subTest(
                    rejection_code=rejection.rejection_code,
                    request_id=rejection.request_id,
                    subject_sha256=rejection.subject_sha256,
                ), self.assertRaisesRegex(QualificationError, "policy binding"):

                    def reject(
                        error: ProviderPolicyRejection = rejection,
                    ) -> None:
                        raise error

                    custody_conformance._expect_provider_rejection(
                        reject,
                        request,
                        bundle.checkpoint.resource,
                        "checkpoint_identity_mismatch",
                    )
        finally:
            factory.close()

    def test_missing_required_read_head_protocol_is_rejected(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = MissingReadHeadAdapterFactory(
            self.initial_intent,
            self.initial_record,
            self.replacement_intent,
            self.replacement_record,
        )
        try:
            with self.assertRaisesRegex(QualificationError, "ledger_heads"):
                run_production_custody_conformance(
                    self.contract,
                    suite,
                    adapters,
                    ReferenceFaultFactory(),
                )
        finally:
            adapters.close()

    def test_evidence_summary_tampering_is_recomputed_and_rejected(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract, suite, adapters, ReferenceFaultFactory()
            )
        finally:
            adapters.close()
        tampered = copy.deepcopy(report.to_dict())
        tampered["case_observations"][0]["variant_observations"][0][
            "evidence_summary"
        ]["result_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(QualificationError, "content address"):
            ProductionCustodyConformanceReport.from_dict(tampered)

    def test_rehashed_evidenceless_acceptance_is_rejected(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract, suite, adapters, ReferenceFaultFactory()
            )
        finally:
            adapters.close()
        tampered = copy.deepcopy(report.to_dict())
        summary = {
            "execution_stage": "runner_control",
            "evidence_kind": "control_assertion",
            "request_sha256": None,
            "subject_sha256": None,
            "result_sha256": None,
            "rejection_code": None,
            "counter_before": None,
            "counter_after": None,
        }
        case = CASE_DEFINITIONS[0]
        definition = case.variants[0]
        variant = tampered["case_observations"][0]["variant_observations"][0]
        variant["evidence_summary"] = summary
        variant["evidence_sha256"] = _canonical_sha256(
            {
                "domain": EVIDENCE_DOMAIN,
                "case_id": case.case_id,
                "sequence": case.sequence,
                "variant_id": definition.variant_id,
                "expected_outcome": definition.expected_outcome,
                "observed_outcome": "accepted",
                "evidence_labels": list(definition.evidence_labels),
                "evidence_summary": summary,
            }
        )
        tampered["case_observations"][0]["evidence_sha256s"][0] = variant[
            "evidence_sha256"
        ]
        body = {
            key: value
            for key, value in tampered.items()
            if key not in {"report_id", "report_sha256"}
        }
        digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
        tampered["report_id"] = "PCF-" + digest.removeprefix("sha256:")[:32].upper()
        tampered["report_sha256"] = digest
        if Draft202012Validator is not None:
            schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
            self.assertTrue(list(Draft202012Validator(schema).iter_errors(tampered)))
        with self.assertRaisesRegex(QualificationError, "evidence profile"):
            ProductionCustodyConformanceReport.from_dict(tampered)

    def test_relabelled_reference_remains_an_unattested_no_effect_claim(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = RelabelledReferenceAdapterFactory(
            self.initial_intent,
            self.initial_record,
            self.replacement_intent,
            self.replacement_record,
        )
        try:
            report = run_production_custody_conformance(
                self.contract,
                suite,
                adapters,
                ReferenceFaultFactory(),
                environment_class=EXTERNAL_ENVIRONMENT,
            )
        finally:
            adapters.close()
        document = report.to_dict()
        self.assertEqual(EXTERNAL_ENVIRONMENT, "unattested_external_claim")
        self.assertEqual(report.environment_class, "unattested_external_claim")
        self.assertEqual(report.overall_outcome, "conformant")
        self.assertTrue(document["independent_review_required"])
        for field in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            self.assertEqual(document[field], "none")

    def test_lying_fault_counter_cannot_influence_runner_evidence(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract, suite, adapters, LyingFaultFactory()
            )
        finally:
            adapters.close()
        self.assertEqual(report.overall_outcome, "conformant")
        audit = report.case_observations[10].variant_observations[1]
        self.assertEqual(audit.evidence_summary["evidence_kind"], "counter_observation")
        self.assertEqual(audit.evidence_summary["counter_before"], 1)
        self.assertEqual(audit.evidence_summary["counter_after"], 1)

    def test_suite_and_report_are_deterministic_content_addressed_artifacts(self) -> None:
        suite1 = build_production_custody_conformance_suite(self.contract)
        suite2 = build_production_custody_conformance_suite(self.contract)
        self.assertEqual(suite1, suite2)
        adapters1 = self.factory()
        adapters2 = self.factory()
        try:
            report1 = run_production_custody_conformance(
                self.contract, suite1, adapters1, ReferenceFaultFactory()
            )
            report2 = run_production_custody_conformance(
                self.contract, suite2, adapters2, ReferenceFaultFactory()
            )
        finally:
            adapters1.close()
            adapters2.close()
        self.assertEqual(report1, report2)
        self.assertEqual(ProductionCustodyConformanceSuite.from_dict(suite1.to_dict()), suite1)
        self.assertEqual(ProductionCustodyConformanceReport.from_dict(report1.to_dict()), report1)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_artifacts_match_published_schemas(self) -> None:
        suite = build_production_custody_conformance_suite(self.contract)
        adapters = self.factory()
        try:
            report = run_production_custody_conformance(
                self.contract, suite, adapters, ReferenceFaultFactory()
            )
        finally:
            adapters.close()
        suite_schema = json.loads(SUITE_SCHEMA_PATH.read_text(encoding="utf-8"))
        report_schema = json.loads(REPORT_SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(suite_schema)
        Draft202012Validator.check_schema(report_schema)
        Draft202012Validator(suite_schema).validate(suite.to_dict())
        Draft202012Validator(report_schema).validate(report.to_dict())

    def test_conformance_module_has_no_live_provider_or_io_imports(self) -> None:
        module_path = (
            ROOT / "src" / "sunderkey" / "candidate_enrollment_production_custody_conformance.py"
        )
        tree = ast.parse(module_path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "tempfile",
            "urllib",
        }
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
        self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()

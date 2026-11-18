"""Executable conformance checks for production custody provider adapters."""

from __future__ import annotations

import hashlib
import json
import re
import types
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, fields, is_dataclass
from typing import Any, Protocol, get_args, get_origin, get_type_hints

from .candidate_enrollment_checkpoint_store import (
    AtomicCandidateEnrollmentCheckpointStore,
    CandidateEnrollmentCheckpointCommitReceipt,
)
from .candidate_enrollment_production_custody_contract import (
    CONFORMANCE_CASE_IDS,
    CatalogObjectDescriptor,
    CatalogObjectPutReceipt,
    CatalogObjectPutRequest,
    CatalogObjectReadReceipt,
    CatalogObjectReadRequest,
    CheckpointAccessVerificationReceipt,
    CheckpointAccessVerificationRequest,
    CheckpointResourceDescriptor,
    ConditionalLedgerHeadProvider,
    ImmutableCatalogObjectProvider,
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
    NativeCheckpointAccessProvider,
    ProductionCustodyProviderContract,
    ProviderPolicyRejection,
    ReleaseAuditAppendReceipt,
    ReleaseAuditAppendRequest,
    ReleaseAuditEventDescriptor,
    ReleaseAuditSink,
    ReleaseHeadSigner,
    ReleaseHeadSigningReceipt,
    ReleaseHeadSigningRequest,
    ReleaseHeadVerificationReceipt,
    ReleaseHeadVerificationRequest,
    ReleaseHeadVerifier,
    RetentionLockedLedgerObjectProvider,
    RetentionStateReadReceipt,
    RetentionStateReadRequest,
    SignedReleaseHeadDescriptor,
    WorkloadIdentityDescriptor,
    WorkloadIdentityVerificationReceipt,
    WorkloadIdentityVerificationRequest,
    WorkloadIdentityVerifier,
    provider_subject_sha256,
)
from .candidate_enrollment_release_contract import (
    CandidateEnrollmentCheckpointRecord,
    CandidateEnrollmentReleaseLedgerEntry,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping

SCHEMA_VERSION = 1
SUITE_DOMAIN = "sunderkey.production-custody-conformance-suite.v1"
REPORT_DOMAIN = "sunderkey.production-custody-conformance-report.v1"
EVIDENCE_DOMAIN = "sunderkey.production-custody-conformance-evidence.v1"
REFERENCE_ENVIRONMENT = "reference_simulation_nonqualifying"
EXTERNAL_ENVIRONMENT = "unattested_external_claim"

_SUITE_ID_PATTERN = re.compile(r"PCS-[0-9A-F]{32}")
_REPORT_ID_PATTERN = re.compile(r"PCF-[0-9A-F]{32}")
_CONTRACT_ID_PATTERN = re.compile(r"PCC-[0-9A-F]{32}")
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_TOKEN_PATTERN = re.compile(r"[a-z][a-z0-9_]{2,127}")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")

ProviderDescriptor = Mapping[str, str]


def _public_summary(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_sha256": _bytes_digest(value)}
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _public_summary(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, Mapping):
        return {str(key): _public_summary(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_public_summary(item) for item in value]
    if isinstance(value, (str, int, bool)) or value is None:
        return value
    raise QualificationError("Evidence summary value is unsupported")


@dataclass
class _EvidenceRecorder:
    execution_stage: str = "runner_control"
    evidence_kind: str = "control_assertion"
    requests: list[Any] | None = None
    subjects: list[Any] | None = None
    results: list[Any] | None = None
    rejection_code: str | None = None
    counter_before: int | None = None
    counter_after: int | None = None

    def __post_init__(self) -> None:
        self.requests = []
        self.subjects = []
        self.results = []

    def record_receipt(self, receipt: Any, bindings: Mapping[str, Any]) -> None:
        self.execution_stage = "provider_invocation"
        self.evidence_kind = (
            "validated_receipt_set" if self.results else "validated_receipt"
        )
        assert self.requests is not None
        assert self.subjects is not None
        assert self.results is not None
        self.requests.append(_public_summary(dict(bindings)))
        subject = {
            key: item
            for key, item in bindings.items()
            if key
            not in {
                "request_id",
                "append_status",
                "compare_and_swap_status",
                "write_status",
            }
        }
        self.subjects.append(_public_summary(subject))
        self.results.append(_public_summary(receipt))

    def record_rejection(
        self,
        request: Any,
        subject: Any,
        rejection_code: str,
        *,
        stage: str = "provider_invocation",
    ) -> None:
        self.execution_stage = stage
        self.evidence_kind = "expected_rejection"
        assert self.requests is not None
        assert self.subjects is not None
        self.requests.append(_public_summary(request))
        self.subjects.append(_public_summary(subject))
        self.rejection_code = rejection_code

    def record_counter(self, before: int, after: int) -> None:
        self.execution_stage = "runner_control"
        self.evidence_kind = "counter_observation"
        self.counter_before = before
        self.counter_after = after

    def to_dict(self) -> dict[str, Any]:
        def digest(items: list[Any] | None) -> str | None:
            if not items:
                return None
            return _canonical_sha256(items)

        return {
            "execution_stage": self.execution_stage,
            "evidence_kind": self.evidence_kind,
            "request_sha256": digest(self.requests),
            "subject_sha256": digest(self.subjects),
            "result_sha256": digest(self.results),
            "rejection_code": self.rejection_code,
            "counter_before": self.counter_before,
            "counter_after": self.counter_after,
        }


_ACTIVE_EVIDENCE: ContextVar[_EvidenceRecorder | None] = ContextVar(
    "production_custody_evidence",
    default=None,
)


@dataclass(frozen=True)
class ConformanceVariant:
    variant_id: str
    expected_outcome: str
    evidence_labels: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "expected_outcome": self.expected_outcome,
            "evidence_labels": list(self.evidence_labels),
        }


@dataclass(frozen=True)
class ConformanceCase:
    case_id: str
    sequence: int
    interface_ids: tuple[str, ...]
    objective: str
    variants: tuple[ConformanceVariant, ...]
    required_evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "sequence": self.sequence,
            "interface_ids": list(self.interface_ids),
            "objective": self.objective,
            "variants": [variant.to_dict() for variant in self.variants],
            "required_evidence": list(self.required_evidence),
        }


def _variant(
    variant_id: str,
    expected_outcome: str,
    *evidence_labels: str,
) -> ConformanceVariant:
    return ConformanceVariant(variant_id, expected_outcome, tuple(evidence_labels))


CASE_DEFINITIONS = (
    ConformanceCase(
        "exact_checkpoint_identity",
        1,
        ("native_checkpoint_access",),
        "Verify exact least-privilege checkpoint service identity.",
        (
            _variant("exact_identity", "accepted", "identity_receipt"),
            _variant("wrong_identity", "rejected", "identity_rejection"),
        ),
        ("identity_receipt", "identity_rejection"),
    ),
    ConformanceCase(
        "interrupted_checkpoint_replacement",
        2,
        ("native_checkpoint_access",),
        "Preserve recoverable checkpoint state across interrupted replacement.",
        (
            _variant("initial_commit", "accepted", "initial_commit_receipt"),
            _variant("interrupted_replace", "blocked", "replacement_fault"),
            _variant("recovery_replace", "accepted", "recovery_commit_receipt"),
        ),
        ("initial_commit_receipt", "replacement_fault", "recovery_commit_receipt"),
    ),
    ConformanceCase(
        "ledger_put_if_absent",
        3,
        ("retention_locked_ledger_objects",),
        "Accept immutable creation and idempotent replay while rejecting overwrite.",
        (
            _variant("create_object", "accepted", "created_receipt"),
            _variant("idempotent_replay", "accepted", "idempotent_receipt"),
            _variant("conflicting_overwrite", "rejected", "overwrite_rejection"),
        ),
        ("created_receipt", "idempotent_receipt", "overwrite_rejection"),
    ),
    ConformanceCase(
        "retention_lock",
        4,
        ("retention_locked_ledger_objects",),
        "Verify retained immutable bytes and fail closed when retention cannot be proven.",
        (
            _variant("retention_verified", "accepted", "retention_receipt"),
            _variant("retention_unavailable", "blocked", "retention_fault"),
        ),
        ("retention_receipt", "retention_fault"),
    ),
    ConformanceCase(
        "conditional_head_cas_race",
        5,
        ("conditional_ledger_head",),
        "Permit one compare-and-swap winner and reject a stale contender.",
        (
            _variant("initial_head", "accepted", "initial_cas_receipt"),
            _variant("race_winner", "accepted", "winner_cas_receipt"),
            _variant("stale_contender", "rejected", "stale_cas_rejection"),
        ),
        ("initial_cas_receipt", "winner_cas_receipt", "stale_cas_rejection"),
    ),
    ConformanceCase(
        "ledger_lineage_integrity",
        6,
        ("conditional_ledger_head",),
        "Accept one monotonic successor while rejecting sequence gaps and forks.",
        (
            _variant("valid_successor", "accepted", "successor_receipt"),
            _variant("sequence_gap", "rejected", "gap_rejection"),
            _variant("lineage_fork", "rejected", "fork_rejection"),
        ),
        ("successor_receipt", "gap_rejection", "fork_rejection"),
    ),
    ConformanceCase(
        "immutable_catalog_objects",
        7,
        ("immutable_catalog_objects",),
        "Preserve SHA-256 addressed catalog bytes and reject overwrite.",
        (
            _variant("create_catalog", "accepted", "catalog_put_receipt"),
            _variant("catalog_overwrite", "rejected", "catalog_overwrite_rejection"),
            _variant("read_original", "accepted", "catalog_read_receipt"),
        ),
        ("catalog_put_receipt", "catalog_overwrite_rejection", "catalog_read_receipt"),
    ),
    ConformanceCase(
        "custody_separation",
        8,
        (
            "native_checkpoint_access",
            "retention_locked_ledger_objects",
            "immutable_catalog_objects",
            "release_head_signing",
            "release_head_verification",
        ),
        "Verify distinct authority scopes, namespaces, failure domains, and signing roles.",
        (
            _variant("separated_custody", "accepted", "separation_snapshot"),
            _variant("collapsed_custody", "rejected", "separation_rejection"),
        ),
        ("separation_snapshot", "separation_rejection"),
    ),
    ConformanceCase(
        "workload_identity_lifecycle",
        9,
        ("workload_identity",),
        "Verify provider, scope, rotation, and freshness for workload identity.",
        (
            _variant("current_identity", "accepted", "identity_lifecycle_receipts"),
            _variant(
                "provider_mismatch",
                "rejected",
                "provider_contract_rejection",
            ),
            _variant("stale_identity", "rejected", "stale_identity_rejection"),
            _variant("scope_mismatch", "rejected", "scope_rejection"),
            _variant("retired_rotation", "rejected", "rotation_rejection"),
        ),
        (
            "identity_lifecycle_receipts",
            "provider_contract_rejection",
            "stale_identity_rejection",
            "scope_rejection",
            "rotation_rejection",
        ),
    ),
    ConformanceCase(
        "signed_head_verification",
        10,
        ("release_head_signing", "release_head_verification"),
        "Verify signed release head lineage and offline root authorization.",
        (
            _variant("valid_signed_head", "accepted", "signed_head_receipts"),
            _variant("tampered_signature", "rejected", "signature_rejection"),
            _variant(
                "wrong_root_authorization",
                "rejected",
                "root_contract_rejection",
            ),
            _variant(
                "wrong_predecessor",
                "rejected",
                "predecessor_contract_rejection",
            ),
        ),
        (
            "signed_head_receipts",
            "signature_rejection",
            "root_contract_rejection",
            "predecessor_contract_rejection",
        ),
    ),
    ConformanceCase(
        "audit_append_blocks_release",
        11,
        ("release_audit", "release_head_signing"),
        "Require durable audit append before release signing.",
        (
            _variant("audit_before_sign", "accepted", "audit_and_sign_receipts"),
            _variant(
                "audit_failure",
                "blocked",
                "audit_fault",
                "runner_signer_not_called",
            ),
        ),
        ("audit_and_sign_receipts", "audit_fault", "runner_signer_not_called"),
    ),
    ConformanceCase(
        "partial_release_recovery",
        12,
        (
            "retention_locked_ledger_objects",
            "conditional_ledger_head",
            "immutable_catalog_objects",
            "release_audit",
            "release_head_signing",
            "release_head_verification",
        ),
        "Recover safely after a partial release without skipping custody gates.",
        (
            _variant("partial_release", "blocked", "partial_release_fault"),
            _variant("recovered_release", "accepted", "recovery_receipts"),
        ),
        ("partial_release_fault", "recovery_receipts"),
    ),
)

CONFORMANCE_OPERATION_COVERAGE = {
    "native_checkpoint_access": (
        "verify_exact_service_identity",
        "protect_directory",
        "verify_directory",
        "protect_file",
        "verify_file",
        "sync_directory",
    ),
    "retention_locked_ledger_objects": (
        "put_if_absent",
        "read_verified",
        "read_retention_state",
    ),
    "conditional_ledger_head": (
        "read_head",
        "compare_and_swap_head",
    ),
    "immutable_catalog_objects": (
        "put_sha256_object",
        "read_sha256_object",
    ),
    "workload_identity": (
        "verify_identity",
        "verify_scope",
        "verify_freshness",
    ),
    "release_head_signing": ("sign_head",),
    "release_head_verification": ("verify_signed_head",),
    "release_audit": ("append_audit_event",),
}


@dataclass(frozen=True)
class ProductionCustodyConformanceSuite:
    suite_id: str
    suite_sha256: str
    contract_id: str
    contract_sha256: str
    cases: tuple[ConformanceCase, ...]
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProductionCustodyConformanceSuite:
        value = _mapping(raw, "production custody conformance suite")
        fields = {
            "schema_version",
            "suite_id",
            "suite_sha256",
            "contract_id",
            "contract_sha256",
            "cases",
            "runtime_effect",
        }
        _exact_fields(value, fields, "production custody conformance suite")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Conformance suite schema is invalid")
        if value.get("runtime_effect") != "none":
            raise QualificationError("Conformance suite runtime effect is invalid")
        if value.get("cases") != [case.to_dict() for case in CASE_DEFINITIONS]:
            raise QualificationError("Conformance suite case definitions are invalid")
        suite_id = value.get("suite_id")
        suite_sha256 = value.get("suite_sha256")
        contract_id = value.get("contract_id")
        contract_sha256 = value.get("contract_sha256")
        if not isinstance(suite_id, str) or _SUITE_ID_PATTERN.fullmatch(suite_id) is None:
            raise QualificationError("Conformance suite identity is invalid")
        if not isinstance(contract_id, str) or _CONTRACT_ID_PATTERN.fullmatch(contract_id) is None:
            raise QualificationError("Conformance suite contract identity is invalid")
        for digest in (suite_sha256, contract_sha256):
            if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
                raise QualificationError("Conformance suite digest is invalid")
        body = {key: item for key, item in value.items() if key not in {"suite_id", "suite_sha256"}}
        digest = _canonical_sha256({"domain": SUITE_DOMAIN, "suite": body})
        expected_id = "PCS-" + digest.removeprefix("sha256:")[:32].upper()
        if suite_sha256 != digest or suite_id != expected_id:
            raise QualificationError("Conformance suite content address is invalid")
        return cls(
            suite_id,
            suite_sha256,
            contract_id,
            contract_sha256,
            CASE_DEFINITIONS,
            _canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Conformance suite is invalid")
        return value


@dataclass(frozen=True)
class CheckpointConformanceFixture:
    store: AtomicCandidateEnrollmentCheckpointStore
    resource: CheckpointResourceDescriptor
    expected_identity_id: str
    initial_record: CandidateEnrollmentCheckpointRecord
    initial_intent: CandidateEnrollmentReleaseLedgerEntry
    replacement_record: CandidateEnrollmentCheckpointRecord
    replacement_intent: CandidateEnrollmentReleaseLedgerEntry


@dataclass(frozen=True)
class ProductionCustodyAdapterBundle:
    environment_class: str
    provider_descriptor: ProviderDescriptor
    checkpoint_access: NativeCheckpointAccessProvider
    checkpoint: CheckpointConformanceFixture
    ledger_objects: RetentionLockedLedgerObjectProvider
    ledger_object: LedgerObjectDescriptor
    ledger_payload: bytes
    ledger_heads: ConditionalLedgerHeadProvider
    initial_head: LedgerHeadDescriptor
    successor_head: LedgerHeadDescriptor
    catalog_objects: ImmutableCatalogObjectProvider
    catalog_object: CatalogObjectDescriptor
    catalog_payload: bytes
    workload_identity: WorkloadIdentityVerifier
    workload_request: WorkloadIdentityVerificationRequest
    release_signer: ReleaseHeadSigner
    release_verifier: ReleaseHeadVerifier
    signing_request: ReleaseHeadSigningRequest
    release_audit: ReleaseAuditSink
    audit_event: ReleaseAuditEventDescriptor


class _RunnerObservedSigner:
    def __init__(self, delegate: ReleaseHeadSigner) -> None:
        self._delegate = delegate
        self.call_count = 0

    def sign_head(
        self, request: ReleaseHeadSigningRequest
    ) -> ReleaseHeadSigningReceipt:
        self.call_count += 1
        return self._delegate.sign_head(request)


class TestOnlyProductionCustodyFaultInjector(Protocol):
    """Test-only fault control kept separate from provider contracts."""

    def arm(
        self,
        fault_id: str,
        request_id: str,
        subject_sha256: str,
    ) -> None: ...

    def clear(self) -> None: ...

    def separation_snapshot(self, bundle: ProductionCustodyAdapterBundle) -> Mapping[str, str]: ...

    def assert_separation(self, snapshot: Mapping[str, str]) -> None: ...

class ProductionCustodyAdapterFactory(Protocol):
    """Create one isolated adapter bundle for one conformance case."""

    environment_class: str

    def create_bundle(
        self,
        case_id: str,
        fault_injector: TestOnlyProductionCustodyFaultInjector,
    ) -> ProductionCustodyAdapterBundle: ...


class TestOnlyProductionCustodyFaultInjectorFactory(Protocol):
    def create_fault_injector(self, case_id: str) -> TestOnlyProductionCustodyFaultInjector: ...


class TestFaultAcknowledgement(Exception):
    """Exact acknowledgement that an armed conformance-only fault fired."""

    def __init__(
        self,
        fault_id: str,
        request_id: str,
        subject_sha256: str,
    ) -> None:
        if not isinstance(fault_id, str) or _TOKEN_PATTERN.fullmatch(fault_id) is None:
            raise ValueError("fault_id is invalid")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("request_id is invalid")
        if (
            not isinstance(subject_sha256, str)
            or _SHA256_PATTERN.fullmatch(subject_sha256) is None
        ):
            raise ValueError("subject_sha256 is invalid")
        self.fault_id = fault_id
        self.request_id = request_id
        self.subject_sha256 = subject_sha256
        super().__init__("The armed conformance fault fired")


class ConformanceControlRejection(Exception):
    """Typed rejection emitted by a test-only runner control."""

    def __init__(self, rejection_code: str, subject_sha256: str) -> None:
        if (
            not isinstance(rejection_code, str)
            or _TOKEN_PATTERN.fullmatch(rejection_code) is None
        ):
            raise ValueError("rejection_code is invalid")
        if (
            not isinstance(subject_sha256, str)
            or _SHA256_PATTERN.fullmatch(subject_sha256) is None
        ):
            raise ValueError("subject_sha256 is invalid")
        self.rejection_code = rejection_code
        self.subject_sha256 = subject_sha256
        super().__init__("Conformance runner control rejected the bound subject")


class _ExpectedRejection(Exception):
    pass


class _ExpectedBlocked(Exception):
    pass


@dataclass(frozen=True)
class VariantObservation:
    variant_id: str
    observed_outcome: str
    evidence_summary: Mapping[str, Any]
    evidence_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "variant_id": self.variant_id,
            "observed_outcome": self.observed_outcome,
            "evidence_summary": dict(self.evidence_summary),
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    sequence: int
    outcome: str
    variant_observations: tuple[VariantObservation, ...]
    evidence_sha256s: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "sequence": self.sequence,
            "outcome": self.outcome,
            "variant_observations": [item.to_dict() for item in self.variant_observations],
            "evidence_sha256s": list(self.evidence_sha256s),
        }


@dataclass(frozen=True)
class ProductionCustodyConformanceReport:
    report_id: str
    report_sha256: str
    contract_id: str
    contract_sha256: str
    suite_id: str
    suite_sha256: str
    environment_class: str
    case_observations: tuple[CaseObservation, ...]
    overall_outcome: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ProductionCustodyConformanceReport:
        value = _mapping(raw, "production custody conformance report")
        fields = {
            "schema_version",
            "report_id",
            "report_sha256",
            "contract_id",
            "contract_sha256",
            "suite_id",
            "suite_sha256",
            "provider_descriptor",
            "environment_class",
            "case_observations",
            "overall_outcome",
            "independent_review_required",
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        }
        _exact_fields(value, fields, "production custody conformance report")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise QualificationError("Conformance report schema is invalid")
        if value.get("environment_class") not in {REFERENCE_ENVIRONMENT, EXTERNAL_ENVIRONMENT}:
            raise QualificationError("Conformance report environment class is invalid")
        if value.get("overall_outcome") not in {"conformant", "nonconformant"}:
            raise QualificationError("Conformance report outcome is invalid")
        if value.get("independent_review_required") is not True:
            raise QualificationError("Conformance report requires independent review")
        for effect in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            if value.get(effect) != "none":
                raise QualificationError("Conformance report effects are invalid")
        _validate_provider_descriptor(value.get("provider_descriptor"))
        report_id = value.get("report_id")
        if not isinstance(report_id, str) or _REPORT_ID_PATTERN.fullmatch(report_id) is None:
            raise QualificationError("Conformance report identity is invalid")
        for field, pattern in (
            ("contract_id", _CONTRACT_ID_PATTERN),
            ("suite_id", _SUITE_ID_PATTERN),
        ):
            item = value.get(field)
            if not isinstance(item, str) or pattern.fullmatch(item) is None:
                raise QualificationError("Conformance report binding is invalid")
        for field in ("report_sha256", "contract_sha256", "suite_sha256"):
            item = value.get(field)
            if not isinstance(item, str) or _SHA256_PATTERN.fullmatch(item) is None:
                raise QualificationError("Conformance report digest is invalid")
        observations = _parse_observations(value.get("case_observations"))
        expected_outcome = (
            "conformant"
            if all(item.outcome == "pass" for item in observations)
            else "nonconformant"
        )
        if value.get("overall_outcome") != expected_outcome:
            raise QualificationError("Conformance report aggregate outcome is invalid")
        body = {
            key: item for key, item in value.items() if key not in {"report_id", "report_sha256"}
        }
        digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
        expected_id = "PCF-" + digest.removeprefix("sha256:")[:32].upper()
        if value.get("report_sha256") != digest or report_id != expected_id:
            raise QualificationError("Conformance report content address is invalid")
        return cls(
            report_id,
            digest,
            value["contract_id"],
            value["contract_sha256"],
            value["suite_id"],
            value["suite_sha256"],
            value["environment_class"],
            observations,
            value["overall_outcome"],
            _canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise QualificationError("Conformance report is invalid")
        return value


def _validate_provider_descriptor(raw: Any) -> dict[str, str]:
    value = _mapping(raw, "provider_descriptor")
    _exact_fields(
        value,
        {
            "provider_id",
            "adapter_id",
            "adapter_version",
            "build_sha256",
            "configuration_sha256",
            "namespace_reference",
            "credential_scope_sha256",
            "failure_domain_reference",
        },
        "provider_descriptor",
    )
    for field in (
        "provider_id",
        "adapter_id",
        "namespace_reference",
        "failure_domain_reference",
    ):
        item = value.get(field)
        if not isinstance(item, str) or _TOKEN_PATTERN.fullmatch(item) is None:
            raise QualificationError("Provider descriptor identifier is invalid")
    version = value.get("adapter_version")
    if not isinstance(version, str) or _VERSION_PATTERN.fullmatch(version) is None:
        raise QualificationError("Provider descriptor version is invalid")
    for field in (
        "build_sha256",
        "configuration_sha256",
        "credential_scope_sha256",
    ):
        digest = value.get(field)
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise QualificationError("Provider descriptor digest is invalid")
    return {key: str(item) for key, item in value.items()}


def _parse_evidence_summary(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "evidence_summary")
    _exact_fields(
        value,
        {
            "execution_stage",
            "evidence_kind",
            "request_sha256",
            "subject_sha256",
            "result_sha256",
            "rejection_code",
            "counter_before",
            "counter_after",
        },
        "evidence_summary",
    )
    if value.get("execution_stage") not in {
        "contract_validation",
        "provider_invocation",
        "runner_control",
    }:
        raise QualificationError("Evidence execution stage is invalid")
    if value.get("evidence_kind") not in {
        "validated_receipt",
        "validated_receipt_set",
        "expected_rejection",
        "counter_observation",
        "control_assertion",
    }:
        raise QualificationError("Evidence kind is invalid")
    for field in ("request_sha256", "subject_sha256", "result_sha256"):
        item = value.get(field)
        if item is not None and (
            not isinstance(item, str) or _SHA256_PATTERN.fullmatch(item) is None
        ):
            raise QualificationError("Evidence digest field is invalid")
    rejection = value.get("rejection_code")
    if rejection is not None and (
        not isinstance(rejection, str) or _TOKEN_PATTERN.fullmatch(rejection) is None
    ):
        raise QualificationError("Evidence rejection code is invalid")
    for field in ("counter_before", "counter_after"):
        item = value.get(field)
        if item is not None and (
            isinstance(item, bool) or not isinstance(item, int) or item < 0
        ):
            raise QualificationError("Evidence counter is invalid")
    return dict(value)


_PROVIDER_ACCEPTED_EVIDENCE_KINDS = {
    "exact_identity": "validated_receipt",
    "initial_commit": "validated_receipt",
    "recovery_replace": "validated_receipt",
    "create_object": "validated_receipt",
    "idempotent_replay": "validated_receipt",
    "retention_verified": "validated_receipt_set",
    "initial_head": "validated_receipt_set",
    "race_winner": "validated_receipt_set",
    "valid_successor": "validated_receipt_set",
    "create_catalog": "validated_receipt",
    "read_original": "validated_receipt",
    "current_identity": "validated_receipt_set",
    "valid_signed_head": "validated_receipt_set",
    "audit_before_sign": "validated_receipt_set",
    "recovered_release": "validated_receipt_set",
}

_PROVIDER_REJECTION_CODES = {
    "wrong_identity": "checkpoint_identity_mismatch",
    "conflicting_overwrite": "immutable_ledger_overwrite",
    "stale_contender": "ledger_head_conflict",
    "sequence_gap": "ledger_sequence_gap",
    "lineage_fork": "ledger_head_conflict",
    "catalog_overwrite": "immutable_catalog_overwrite",
    "provider_mismatch": "provider_mismatch",
    "stale_identity": "freshness_policy_mismatch",
    "scope_mismatch": "scope_policy_mismatch",
    "retired_rotation": "rotation_policy_mismatch",
    "tampered_signature": "signature_mismatch",
    "wrong_root_authorization": "root_authorization_mismatch",
    "wrong_predecessor": "predecessor_policy_mismatch",
}

_TEST_FAULT_REJECTION_CODES = {
    "interrupted_replace": "test_fault_checkpoint_replacement",
    "retention_unavailable": "test_fault_retention_unavailable",
    "partial_release": "test_fault_catalog_put",
}


def _require_evidence_digest(summary: Mapping[str, Any], field: str) -> None:
    if summary.get(field) is None:
        raise QualificationError(f"Conformance evidence {field} is required")


def _validate_expected_evidence_profile(
    definition: ConformanceVariant,
    observed_outcome: str,
    summary: Mapping[str, Any],
) -> None:
    if observed_outcome != definition.expected_outcome:
        return
    variant_id = definition.variant_id
    accepted_kind = _PROVIDER_ACCEPTED_EVIDENCE_KINDS.get(variant_id)
    if accepted_kind is not None:
        if (
            summary.get("execution_stage") != "provider_invocation"
            or summary.get("evidence_kind") != accepted_kind
            or summary.get("rejection_code") is not None
            or summary.get("counter_before") is not None
            or summary.get("counter_after") is not None
        ):
            raise QualificationError("Accepted provider evidence profile is invalid")
        for field in ("request_sha256", "subject_sha256", "result_sha256"):
            _require_evidence_digest(summary, field)
        return
    rejection_code = _PROVIDER_REJECTION_CODES.get(variant_id)
    if rejection_code is not None:
        if (
            summary.get("execution_stage") != "provider_invocation"
            or summary.get("evidence_kind") != "expected_rejection"
            or summary.get("rejection_code") != rejection_code
            or summary.get("counter_before") is not None
            or summary.get("counter_after") is not None
        ):
            raise QualificationError("Provider rejection evidence profile is invalid")
        for field in ("request_sha256", "subject_sha256"):
            _require_evidence_digest(summary, field)
        if variant_id in {"wrong_root_authorization", "wrong_predecessor"}:
            _require_evidence_digest(summary, "result_sha256")
        elif summary.get("result_sha256") is not None:
            raise QualificationError("Provider rejection evidence has an invalid result")
        return
    fault_code = _TEST_FAULT_REJECTION_CODES.get(variant_id)
    if fault_code is not None:
        if (
            summary.get("execution_stage") != "provider_invocation"
            or summary.get("evidence_kind") != "expected_rejection"
            or summary.get("rejection_code") != fault_code
            or summary.get("counter_before") is not None
            or summary.get("counter_after") is not None
        ):
            raise QualificationError("Test fault evidence profile is invalid")
        for field in ("request_sha256", "subject_sha256"):
            _require_evidence_digest(summary, field)
        if variant_id != "partial_release" and summary.get("result_sha256") is not None:
            raise QualificationError("Test fault evidence contains an invalid result")
        if variant_id == "partial_release":
            _require_evidence_digest(summary, "result_sha256")
        return
    if variant_id == "separated_custody":
        if (
            summary.get("execution_stage") != "runner_control"
            or summary.get("evidence_kind") != "control_assertion"
            or summary.get("request_sha256") is not None
            or summary.get("rejection_code") is not None
            or summary.get("counter_before") is not None
            or summary.get("counter_after") is not None
        ):
            raise QualificationError("Separation control evidence profile is invalid")
        for field in ("subject_sha256", "result_sha256"):
            _require_evidence_digest(summary, field)
        return
    if variant_id == "collapsed_custody":
        if (
            summary.get("execution_stage") != "runner_control"
            or summary.get("evidence_kind") != "expected_rejection"
            or summary.get("rejection_code") != "custody_separation_collapsed"
            or summary.get("result_sha256") is not None
            or summary.get("counter_before") is not None
            or summary.get("counter_after") is not None
        ):
            raise QualificationError("Separation rejection evidence profile is invalid")
        for field in ("request_sha256", "subject_sha256"):
            _require_evidence_digest(summary, field)
        return
    if variant_id == "audit_failure":
        before = summary.get("counter_before")
        after = summary.get("counter_after")
        if (
            summary.get("execution_stage") != "runner_control"
            or summary.get("evidence_kind") != "counter_observation"
            or summary.get("rejection_code") != "test_fault_audit_append"
            or summary.get("result_sha256") is not None
            or before is None
            or after is None
            or before != after
        ):
            raise QualificationError("Audit blocking counter evidence profile is invalid")
        for field in ("request_sha256", "subject_sha256"):
            _require_evidence_digest(summary, field)
        return
    raise QualificationError("Conformance variant has no evidence profile")


def _parse_observations(raw: Any) -> tuple[CaseObservation, ...]:
    if not isinstance(raw, list) or len(raw) != len(CASE_DEFINITIONS):
        raise QualificationError("Conformance report observations are invalid")
    parsed: list[CaseObservation] = []
    for case, item in zip(CASE_DEFINITIONS, raw, strict=True):
        value = _mapping(item, "case observation")
        _exact_fields(
            value,
            {"case_id", "sequence", "outcome", "variant_observations", "evidence_sha256s"},
            "case observation",
        )
        if value.get("case_id") != case.case_id or value.get("sequence") != case.sequence:
            raise QualificationError("Conformance report observation order is invalid")
        variants = value.get("variant_observations")
        if not isinstance(variants, list) or len(variants) != len(case.variants):
            raise QualificationError("Conformance report variant observations are invalid")
        variant_items: list[VariantObservation] = []
        for definition, observation in zip(case.variants, variants, strict=True):
            variant = _mapping(observation, "variant observation")
            _exact_fields(
                variant,
                {
                    "variant_id",
                    "observed_outcome",
                    "evidence_summary",
                    "evidence_sha256",
                },
                "variant observation",
            )
            if variant.get("variant_id") != definition.variant_id or variant.get(
                "observed_outcome"
            ) not in {"accepted", "rejected", "blocked", "unexpected"}:
                raise QualificationError("Conformance report variant observation is invalid")
            digest = variant.get("evidence_sha256")
            if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
                raise QualificationError("Conformance evidence digest is invalid")
            summary = _parse_evidence_summary(variant.get("evidence_summary"))
            _validate_expected_evidence_profile(
                definition,
                variant["observed_outcome"],
                summary,
            )
            expected_digest = _canonical_sha256(
                {
                    "domain": EVIDENCE_DOMAIN,
                    "case_id": case.case_id,
                    "sequence": case.sequence,
                    "variant_id": definition.variant_id,
                    "expected_outcome": definition.expected_outcome,
                    "observed_outcome": variant["observed_outcome"],
                    "evidence_labels": list(definition.evidence_labels),
                    "evidence_summary": summary,
                }
            )
            if digest != expected_digest:
                raise QualificationError("Conformance evidence content address is invalid")
            variant_items.append(
                VariantObservation(
                    definition.variant_id,
                    variant["observed_outcome"],
                    summary,
                    digest,
                )
            )
        evidence = value.get("evidence_sha256s")
        expected_evidence = [item.evidence_sha256 for item in variant_items]
        if evidence != expected_evidence or len(set(expected_evidence)) != len(expected_evidence):
            raise QualificationError("Conformance report evidence ordering is invalid")
        expected_case_outcome = (
            "pass"
            if all(
                definition.expected_outcome == observation.observed_outcome
                for definition, observation in zip(case.variants, variant_items, strict=True)
            )
            else "fail"
        )
        if value.get("outcome") != expected_case_outcome:
            raise QualificationError("Conformance report case outcome is invalid")
        parsed.append(
            CaseObservation(
                case.case_id,
                case.sequence,
                expected_case_outcome,
                tuple(variant_items),
                tuple(expected_evidence),
            )
        )
    return tuple(parsed)


def _validate_required_operation_coverage(
    contract: ProductionCustodyProviderContract,
) -> None:
    for descriptor in contract.to_dict()["provider_interfaces"]:
        interface_id = descriptor["interface_id"]
        covered = CONFORMANCE_OPERATION_COVERAGE.get(interface_id)
        if covered is None or tuple(descriptor["required_operations"]) != covered:
            raise QualificationError(
                "Conformance operation coverage does not match the provider contract"
            )


def build_production_custody_conformance_suite(
    contract: ProductionCustodyProviderContract,
) -> ProductionCustodyConformanceSuite:
    if not isinstance(contract, ProductionCustodyProviderContract):
        raise QualificationError("contract must be a production custody provider contract")
    verified = ProductionCustodyProviderContract.from_dict(contract.to_dict())
    _validate_required_operation_coverage(verified)
    if tuple(verified.to_dict()["conformance_case_ids"]) != CONFORMANCE_CASE_IDS:
        raise QualificationError("Contract conformance cases are not current")
    body = {
        "schema_version": SCHEMA_VERSION,
        "contract_id": verified.contract_id,
        "contract_sha256": verified.contract_sha256,
        "cases": [case.to_dict() for case in CASE_DEFINITIONS],
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": SUITE_DOMAIN, "suite": body})
    return ProductionCustodyConformanceSuite.from_dict(
        {
            **body,
            "suite_id": "PCS-" + digest.removeprefix("sha256:")[:32].upper(),
            "suite_sha256": digest,
        }
    )


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


def _bytes_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _deep_reconstruct(value: Any, annotation: Any, label: str) -> Any:
    origin = get_origin(annotation)
    if origin is types.UnionType:
        for option in get_args(annotation):
            if option is type(None) and value is None:
                return None
            try:
                return _deep_reconstruct(value, option, label)
            except QualificationError:
                continue
        raise QualificationError(f"{label} does not match its declared type")
    if origin is tuple:
        if type(value) is not tuple:
            raise QualificationError(f"{label} must be an exact tuple")
        arguments = get_args(annotation)
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return tuple(
                _deep_reconstruct(item, arguments[0], f"{label} item")
                for item in value
            )
        if len(arguments) != len(value):
            raise QualificationError(f"{label} tuple length is invalid")
        return tuple(
            _deep_reconstruct(item, item_type, f"{label} item")
            for item, item_type in zip(value, arguments, strict=True)
        )
    if annotation in {str, int, bool, bytes}:
        if type(value) is not annotation:
            raise QualificationError(f"{label} has an invalid exact type")
        return bytes(value) if annotation is bytes else value
    if annotation is type(None):
        if value is not None:
            raise QualificationError(f"{label} must be null")
        return None
    if isinstance(annotation, type) and is_dataclass(annotation):
        if type(value) is not annotation:
            raise QualificationError(f"{label} has an invalid exact dataclass type")
        hints = get_type_hints(annotation)
        values = {
            field.name: _deep_reconstruct(
                getattr(value, field.name),
                hints[field.name],
                f"{label}.{field.name}",
            )
            for field in fields(annotation)
        }
        try:
            return annotation(**values)
        except (TypeError, ValueError) as exc:
            raise QualificationError(f"{label} failed semantic reconstruction") from exc
    if annotation is Any:
        raise QualificationError(f"{label} cannot use an unconstrained receipt type")
    if not isinstance(annotation, type) or type(value) is not annotation:
        raise QualificationError(f"{label} has an unsupported receipt type")
    return value


def _validated_receipt(
    receipt: Any,
    expected_type: type[Any],
    *,
    record_evidence: bool = True,
    **bindings: Any,
) -> Any:
    if type(receipt) is not expected_type:
        raise QualificationError(
            f"Provider returned an invalid {expected_type.__name__}"
        )
    receipt = _deep_reconstruct(receipt, expected_type, expected_type.__name__)
    for field, expected in bindings.items():
        if getattr(receipt, field, object()) != expected:
            raise QualificationError(
                f"Provider receipt {field} does not match its request"
            )
    recorder = _ACTIVE_EVIDENCE.get()
    if record_evidence and recorder is not None:
        recorder.record_receipt(receipt, bindings)
    return receipt


def _record_expected_rejection(
    request: Any,
    subject: Any,
    rejection_code: str,
    *,
    stage: str = "provider_invocation",
) -> None:
    recorder = _ACTIVE_EVIDENCE.get()
    if recorder is not None:
        recorder.record_rejection(
            request,
            subject,
            rejection_code,
            stage=stage,
        )


def _expect_provider_rejection(
    operation: Callable[[], Any],
    request: Any,
    subject: Any,
    rejection_code: str,
) -> None:
    try:
        operation()
    except ProviderPolicyRejection as exc:
        request_id = getattr(request, "request_id", None)
        if (
            exc.rejection_code != rejection_code
            or exc.request_id != request_id
            or exc.subject_sha256 != provider_subject_sha256(subject)
        ):
            raise QualificationError(
                "Provider rejection does not match the expected policy binding"
            ) from exc
        _record_expected_rejection(request, subject, exc.rejection_code)
        raise _ExpectedRejection from exc
    raise RuntimeError("Provider accepted a request that policy must reject")


def _expect_test_fault(
    operation: Callable[[], Any],
    request: Any,
    subject: Any,
    fault_id: str,
) -> None:
    try:
        operation()
    except TestFaultAcknowledgement as exc:
        request_id = (
            request.get("request_id")
            if isinstance(request, Mapping)
            else getattr(request, "request_id", None)
        )
        if (
            exc.fault_id != fault_id
            or exc.request_id != request_id
            or exc.subject_sha256 != provider_subject_sha256(subject)
        ):
            raise QualificationError("Test fault acknowledgement does not match") from exc
        _record_expected_rejection(
            request,
            subject,
            f"test_fault_{fault_id}",
        )
        raise _ExpectedBlocked from exc
    raise RuntimeError("The armed conformance fault was not acknowledged")


def _expect_control_rejection(
    operation: Callable[[], Any],
    request: Any,
    subject: Any,
    rejection_code: str,
) -> None:
    try:
        operation()
    except ConformanceControlRejection as exc:
        if (
            exc.rejection_code != rejection_code
            or exc.subject_sha256 != provider_subject_sha256(subject)
        ):
            raise QualificationError(
                "Control rejection does not match the expected binding"
            ) from exc
        _record_expected_rejection(
            request,
            subject,
            exc.rejection_code,
            stage="runner_control",
        )
        raise _ExpectedRejection from exc
    raise RuntimeError("Runner control accepted a prohibited state")


def _record_runner_counter(before: int, after: int) -> None:
    recorder = _ACTIVE_EVIDENCE.get()
    if recorder is not None:
        recorder.record_counter(before, after)


def _record_control_assertion(subject: Any, result: Any) -> None:
    recorder = _ACTIVE_EVIDENCE.get()
    if recorder is None:
        return
    recorder.execution_stage = "runner_control"
    recorder.evidence_kind = "control_assertion"
    assert recorder.subjects is not None
    assert recorder.results is not None
    recorder.subjects.append(_public_summary(subject))
    recorder.results.append(_public_summary(result))


def _validated_checkpoint_commit(
    receipt: Any,
    record: CandidateEnrollmentCheckpointRecord,
    expected_status: str,
) -> CandidateEnrollmentCheckpointCommitReceipt:
    verified = _validated_receipt(
        receipt,
        CandidateEnrollmentCheckpointCommitReceipt,
        record_evidence=False,
    )
    document = verified.to_dict()
    if document["checkpoint"] != {
        "checkpoint_id": record.checkpoint_id,
        "sha256": record.checkpoint_sha256,
        "checkpoint_sequence": record.to_dict()["checkpoint_sequence"],
    }:
        raise QualificationError("Checkpoint commit receipt binding is invalid")
    if document["commit_status"] != expected_status:
        raise QualificationError("Checkpoint commit status is invalid")
    recorder = _ACTIVE_EVIDENCE.get()
    if recorder is not None:
        recorder.record_receipt(
            verified,
            {
                "checkpoint_id": record.checkpoint_id,
                "checkpoint_sha256": record.checkpoint_sha256,
                "commit_status": expected_status,
            },
        )
    return verified


def _validated_signing_receipt(
    receipt: Any,
    request: ReleaseHeadSigningRequest,
) -> ReleaseHeadSigningReceipt:
    verified = _validated_receipt(
        receipt,
        ReleaseHeadSigningReceipt,
        record_evidence=False,
        request_id=request.request_id,
    )
    signed = verified.signed_head
    if (
        signed.head != request.head
        or signed.signer_key_id != request.signer_key_id
        or signed.offline_root_authorization_sha256
        != request.offline_root_authorization_sha256
        or signed.signing_algorithm != request.signing_algorithm
        or signed.signed_at != request.requested_at
    ):
        raise QualificationError("Signing receipt does not match its request")
    recorder = _ACTIVE_EVIDENCE.get()
    if recorder is not None:
        recorder.record_receipt(
            verified,
            {
                "request_id": request.request_id,
                "head": request.head,
                "signer_key_id": request.signer_key_id,
                "offline_root_authorization_sha256": (
                    request.offline_root_authorization_sha256
                ),
                "signing_algorithm": request.signing_algorithm,
                "requested_at": request.requested_at,
            },
        )
    return verified


def _validated_verification_receipt(
    receipt: Any,
    request: ReleaseHeadVerificationRequest,
) -> ReleaseHeadVerificationReceipt:
    return _validated_receipt(
        receipt,
        ReleaseHeadVerificationReceipt,
        request_id=request.request_id,
        signed_head=request.signed_head,
    )


def _observe(
    case: ConformanceCase,
    definition: ConformanceVariant,
    operation: Callable[[], None],
) -> VariantObservation:
    recorder = _EvidenceRecorder()
    token = _ACTIVE_EVIDENCE.set(recorder)
    try:
        operation()
    except _ExpectedRejection:
        observed = "rejected"
    except _ExpectedBlocked:
        observed = "blocked"
    except Exception as exc:
        observed = "unexpected"
        if recorder.rejection_code is None:
            recorder.record_rejection(
                {"case_id": case.case_id, "variant_id": definition.variant_id},
                {"exception_type": type(exc).__name__},
                "unexpected_exception",
                stage="runner_control",
            )
    else:
        observed = "accepted"
    finally:
        _ACTIVE_EVIDENCE.reset(token)
    summary = recorder.to_dict()
    digest = _canonical_sha256(
        {
            "domain": EVIDENCE_DOMAIN,
            "case_id": case.case_id,
            "sequence": case.sequence,
            "variant_id": definition.variant_id,
            "expected_outcome": definition.expected_outcome,
            "observed_outcome": observed,
            "evidence_labels": list(definition.evidence_labels),
            "evidence_summary": summary,
        }
    )
    return VariantObservation(definition.variant_id, observed, summary, digest)


def _run_case(
    case: ConformanceCase,
    bundle: ProductionCustodyAdapterBundle,
    fault: TestOnlyProductionCustodyFaultInjector,
) -> CaseObservation:
    observed_signer = _RunnerObservedSigner(bundle.release_signer)
    operations = _case_operations(case.case_id, bundle, fault, observed_signer)
    observations = tuple(
        _observe(case, definition, operation)
        for definition, operation in zip(case.variants, operations, strict=True)
    )
    outcome = (
        "pass"
        if all(
            definition.expected_outcome == observation.observed_outcome
            for definition, observation in zip(case.variants, observations, strict=True)
        )
        else "fail"
    )
    evidence = tuple(item.evidence_sha256 for item in observations)
    return CaseObservation(case.case_id, case.sequence, outcome, observations, evidence)


def _case_operations(
    case_id: str,
    bundle: ProductionCustodyAdapterBundle,
    fault: TestOnlyProductionCustodyFaultInjector,
    signer: _RunnerObservedSigner,
) -> tuple[Callable[[], None], ...]:
    cp = bundle.checkpoint
    if case_id == "exact_checkpoint_identity":
        exact_request = CheckpointAccessVerificationRequest(
            "request.identity.exact", cp.resource, cp.expected_identity_id
        )

        def exact_identity() -> None:
            _validated_receipt(
                bundle.checkpoint_access.verify_exact_service_identity(exact_request),
                CheckpointAccessVerificationReceipt,
                request_id=exact_request.request_id,
                resource_id=exact_request.resource.resource_id,
                expected_identity_id=exact_request.expected_identity_id,
                observed_identity_id=exact_request.expected_identity_id,
            )

        def wrong_identity() -> None:
            wrong_request = CheckpointAccessVerificationRequest(
                "request.identity.wrong", cp.resource, "identity.wrong"
            )
            _expect_provider_rejection(
                lambda: bundle.checkpoint_access.verify_exact_service_identity(
                    wrong_request
                ),
                wrong_request,
                cp.resource,
                "checkpoint_identity_mismatch",
            )

        return (exact_identity, wrong_identity)
    if case_id == "interrupted_checkpoint_replacement":

        def interrupted() -> None:
            request = {
                "request_id": "fault.checkpoint_replacement",
                "checkpoint_id": cp.replacement_record.checkpoint_id,
                "checkpoint_sha256": cp.replacement_record.checkpoint_sha256,
            }
            fault.arm(
                "checkpoint_replacement",
                request["request_id"],
                provider_subject_sha256(cp.resource),
            )
            try:
                _expect_test_fault(
                    lambda: cp.store.commit(
                        cp.replacement_record,
                        cp.replacement_intent,
                    ),
                    request,
                    cp.resource,
                    "checkpoint_replacement",
                )
            finally:
                fault.clear()

        return (
            lambda: _validated_checkpoint_commit(
                cp.store.commit(cp.initial_record, cp.initial_intent),
                cp.initial_record,
                "committed",
            ),
            interrupted,
            lambda: _validated_checkpoint_commit(
                cp.store.commit(cp.replacement_record, cp.replacement_intent),
                cp.replacement_record,
                "committed",
            ),
        )
    if case_id == "ledger_put_if_absent":
        conflict_payload = b"conflicting-ledger-object"
        conflict = LedgerObjectDescriptor(
            bundle.ledger_object.object_id,
            _bytes_digest(conflict_payload),
            len(conflict_payload),
            bundle.ledger_object.retention_until,
            bundle.ledger_object.namespace_id,
            bundle.ledger_object.failure_domain_id,
        )
        create_request = LedgerObjectPutRequest(
            "request.ledger.create", bundle.ledger_object, bundle.ledger_payload
        )
        replay_request = LedgerObjectPutRequest(
            "request.ledger.replay", bundle.ledger_object, bundle.ledger_payload
        )

        def conflicting_overwrite() -> None:
            conflict_request = LedgerObjectPutRequest(
                "request.ledger.conflict", conflict, conflict_payload
            )
            _expect_provider_rejection(
                lambda: bundle.ledger_objects.put_if_absent(conflict_request),
                conflict_request,
                conflict,
                "immutable_ledger_overwrite",
            )

        return (
            lambda: _validated_receipt(
                bundle.ledger_objects.put_if_absent(create_request),
                LedgerObjectPutReceipt,
                request_id=create_request.request_id,
                object=create_request.object,
                write_status="created",
            ),
            lambda: _validated_receipt(
                bundle.ledger_objects.put_if_absent(replay_request),
                LedgerObjectPutReceipt,
                request_id=replay_request.request_id,
                object=replay_request.object,
                write_status="already_present_same_digest",
            ),
            conflicting_overwrite,
        )
    if case_id == "retention_lock":

        def blocked_retention() -> None:
            retention_request = RetentionStateReadRequest(
                "request.retention.blocked",
                bundle.ledger_object.object_id,
                bundle.ledger_object.retention_until,
            )
            fault.arm(
                "retention_unavailable",
                retention_request.request_id,
                provider_subject_sha256(bundle.ledger_object),
            )
            try:
                _expect_test_fault(
                    lambda: bundle.ledger_objects.read_retention_state(
                        retention_request
                    ),
                    retention_request,
                    bundle.ledger_object,
                    "retention_unavailable",
                )
            finally:
                fault.clear()

        def verified_retention() -> None:
            put_request = LedgerObjectPutRequest(
                "request.retention.create", bundle.ledger_object, bundle.ledger_payload
            )
            _validated_receipt(
                bundle.ledger_objects.put_if_absent(put_request),
                LedgerObjectPutReceipt,
                request_id=put_request.request_id,
                object=put_request.object,
                write_status="created",
            )
            read_request = LedgerObjectReadRequest(
                "request.retention.read",
                bundle.ledger_object.object_id,
                bundle.ledger_object.sha256,
            )
            _validated_receipt(
                bundle.ledger_objects.read_verified(read_request),
                LedgerObjectReadReceipt,
                request_id=read_request.request_id,
                object=bundle.ledger_object,
                payload=bundle.ledger_payload,
            )
            retention_request = RetentionStateReadRequest(
                "request.retention.verify",
                bundle.ledger_object.object_id,
                bundle.ledger_object.retention_until,
            )
            _validated_receipt(
                bundle.ledger_objects.read_retention_state(retention_request),
                RetentionStateReadReceipt,
                request_id=retention_request.request_id,
                object=bundle.ledger_object,
            )

        return (verified_retention, blocked_retention)
    if case_id == "conditional_head_cas_race":
        initial_digest = _head_digest(bundle.initial_head)
        contender = LedgerHeadDescriptor(
            bundle.successor_head.deployment_id,
            2,
            "entry.contender",
            "sha256:" + "c" * 64,
            initial_digest,
        )
        initial_request = LedgerHeadCompareAndSwapRequest(
            "request.head.initial", None, bundle.initial_head
        )
        winner_request = LedgerHeadCompareAndSwapRequest(
            "request.head.winner", initial_digest, bundle.successor_head
        )

        def initial_head() -> None:
            read_request = LedgerHeadReadRequest(
                "request.head.read_empty",
                bundle.initial_head.deployment_id,
            )
            _validated_receipt(
                bundle.ledger_heads.read_head(read_request),
                LedgerHeadReadReceipt,
                request_id=read_request.request_id,
                head=None,
            )
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(initial_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=initial_request.request_id,
                head=initial_request.proposed_head,
                compare_and_swap_status="advanced",
            )

        def race_winner() -> None:
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(winner_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=winner_request.request_id,
                head=winner_request.proposed_head,
                compare_and_swap_status="advanced",
            )
            read_request = LedgerHeadReadRequest(
                "request.head.read_current",
                bundle.successor_head.deployment_id,
            )
            _validated_receipt(
                bundle.ledger_heads.read_head(read_request),
                LedgerHeadReadReceipt,
                request_id=read_request.request_id,
                head=bundle.successor_head,
            )

        def stale_contender() -> None:
            stale_request = LedgerHeadCompareAndSwapRequest(
                "request.head.stale", initial_digest, contender
            )
            _expect_provider_rejection(
                lambda: bundle.ledger_heads.compare_and_swap_head(stale_request),
                stale_request,
                contender,
                "ledger_head_conflict",
            )

        return (
            initial_head,
            race_winner,
            stale_contender,
        )
    if case_id == "ledger_lineage_integrity":
        initial_digest = _head_digest(bundle.initial_head)

        def valid() -> None:
            initial_request = LedgerHeadCompareAndSwapRequest(
                "request.lineage.initial", None, bundle.initial_head
            )
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(initial_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=initial_request.request_id,
                head=initial_request.proposed_head,
                compare_and_swap_status="advanced",
            )
            successor_request = LedgerHeadCompareAndSwapRequest(
                "request.lineage.successor", initial_digest, bundle.successor_head
            )
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(successor_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=successor_request.request_id,
                head=successor_request.proposed_head,
                compare_and_swap_status="advanced",
            )

        def gap() -> None:
            gap_head = LedgerHeadDescriptor(
                bundle.initial_head.deployment_id,
                4,
                "entry.gap",
                "sha256:" + "d" * 64,
                _head_digest(bundle.successor_head),
            )
            gap_request = LedgerHeadCompareAndSwapRequest(
                "request.lineage.gap",
                _head_digest(bundle.successor_head),
                gap_head,
            )
            _expect_provider_rejection(
                lambda: bundle.ledger_heads.compare_and_swap_head(gap_request),
                gap_request,
                gap_head,
                "ledger_sequence_gap",
            )

        def fork() -> None:
            fork_head = LedgerHeadDescriptor(
                bundle.initial_head.deployment_id,
                2,
                "entry.fork",
                "sha256:" + "e" * 64,
                initial_digest,
            )
            fork_request = LedgerHeadCompareAndSwapRequest(
                "request.lineage.fork", initial_digest, fork_head
            )
            _expect_provider_rejection(
                lambda: bundle.ledger_heads.compare_and_swap_head(fork_request),
                fork_request,
                fork_head,
                "ledger_head_conflict",
            )

        return (valid, gap, fork)
    if case_id == "immutable_catalog_objects":
        conflict_payload = b"conflicting-catalog-object"
        conflict = CatalogObjectDescriptor(
            bundle.catalog_object.object_id,
            _bytes_digest(conflict_payload),
            len(conflict_payload),
            bundle.catalog_object.namespace_id,
            bundle.catalog_object.failure_domain_id,
        )
        create_request = CatalogObjectPutRequest(
            "request.catalog.create", bundle.catalog_object, bundle.catalog_payload
        )
        read_request = CatalogObjectReadRequest(
            "request.catalog.read",
            bundle.catalog_object.object_id,
            bundle.catalog_object.sha256,
        )

        def catalog_overwrite() -> None:
            conflict_request = CatalogObjectPutRequest(
                "request.catalog.conflict", conflict, conflict_payload
            )
            _expect_provider_rejection(
                lambda: bundle.catalog_objects.put_sha256_object(
                    conflict_request
                ),
                conflict_request,
                conflict,
                "immutable_catalog_overwrite",
            )

        return (
            lambda: _validated_receipt(
                bundle.catalog_objects.put_sha256_object(create_request),
                CatalogObjectPutReceipt,
                request_id=create_request.request_id,
                object=create_request.object,
                write_status="created",
            ),
            catalog_overwrite,
            lambda: _validated_receipt(
                bundle.catalog_objects.read_sha256_object(read_request),
                CatalogObjectReadReceipt,
                request_id=read_request.request_id,
                object=bundle.catalog_object,
                payload=bundle.catalog_payload,
            ),
        )
    if case_id == "custody_separation":
        snapshot: dict[str, str] = {}

        def separated() -> None:
            snapshot.update(fault.separation_snapshot(bundle))
            fault.assert_separation(snapshot)
            _record_control_assertion(snapshot, {"separation_verified": True})

        def collapsed() -> None:
            collapsed_snapshot = dict(snapshot or fault.separation_snapshot(bundle))
            collapsed_snapshot["catalog_namespace_id"] = collapsed_snapshot["ledger_namespace_id"]
            collapsed_snapshot["catalog_failure_domain_id"] = collapsed_snapshot[
                "ledger_failure_domain_id"
            ]
            _expect_control_rejection(
                lambda: fault.assert_separation(collapsed_snapshot),
                {"control_id": "custody_separation"},
                collapsed_snapshot,
                "custody_separation_collapsed",
            )

        return (separated, collapsed)
    if case_id == "workload_identity_lifecycle":
        request = bundle.workload_request

        def alternate_identity(**overrides: Any) -> WorkloadIdentityDescriptor:
            identity = request.identity
            values = {
                "provider_id": identity.provider_id,
                "identity_id": identity.identity_id,
                "audience": identity.audience,
                "scope_ids": identity.scope_ids,
                "issued_at": identity.issued_at,
                "expires_at": identity.expires_at,
                "rotation_id": identity.rotation_id,
                "rotation_state": identity.rotation_state,
            }
            values.update(overrides)
            return WorkloadIdentityDescriptor(**values)

        def current() -> None:
            for receipt in (
                bundle.workload_identity.verify_identity(request),
                bundle.workload_identity.verify_scope(request),
                bundle.workload_identity.verify_freshness(request),
            ):
                _validated_receipt(
                    receipt,
                    WorkloadIdentityVerificationReceipt,
                    request_id=request.request_id,
                    identity=request.identity,
                )

        def provider_mismatch() -> None:
            alternate = alternate_identity(provider_id="provider.wrong")
            mismatched = WorkloadIdentityVerificationRequest(
                "request.identity.provider",
                alternate,
                "provider.wrong",
                request.required_scope_ids,
                request.required_rotation_id,
                request.required_rotation_state,
                request.verified_at,
            )
            _expect_provider_rejection(
                lambda: bundle.workload_identity.verify_identity(mismatched),
                mismatched,
                alternate,
                "provider_mismatch",
            )

        def stale() -> None:
            alternate = alternate_identity(expires_at="2026-09-20T00:40:00Z")
            stale_request = WorkloadIdentityVerificationRequest(
                "request.identity.stale",
                alternate,
                request.required_provider_id,
                request.required_scope_ids,
                request.required_rotation_id,
                request.required_rotation_state,
                request.verified_at,
            )
            _expect_provider_rejection(
                lambda: bundle.workload_identity.verify_freshness(stale_request),
                stale_request,
                alternate,
                "freshness_policy_mismatch",
            )

        def scope() -> None:
            alternate = alternate_identity(scope_ids=("scope.ungranted",))
            mismatched = WorkloadIdentityVerificationRequest(
                "request.identity.scope",
                alternate,
                request.required_provider_id,
                ("scope.ungranted",),
                request.required_rotation_id,
                request.required_rotation_state,
                request.verified_at,
            )
            _expect_provider_rejection(
                lambda: bundle.workload_identity.verify_scope(mismatched),
                mismatched,
                alternate,
                "scope_policy_mismatch",
            )

        def rotation() -> None:
            alternate = alternate_identity(rotation_id="rotation.alternate.1")
            mismatched = WorkloadIdentityVerificationRequest(
                "request.identity.rotation",
                alternate,
                request.required_provider_id,
                request.required_scope_ids,
                "rotation.alternate.1",
                "current",
                request.verified_at,
            )
            _expect_provider_rejection(
                lambda: bundle.workload_identity.verify_identity(mismatched),
                mismatched,
                alternate,
                "rotation_policy_mismatch",
            )

        return (current, provider_mismatch, stale, scope, rotation)
    if case_id == "signed_head_verification":
        signed: dict[str, SignedReleaseHeadDescriptor] = {}

        def valid() -> None:
            receipt = _validated_signing_receipt(
                signer.sign_head(bundle.signing_request),
                bundle.signing_request,
            )
            signed["head"] = receipt.signed_head
            verification_request = ReleaseHeadVerificationRequest(
                "request.verify.valid",
                receipt.signed_head,
                bundle.signing_request.offline_root_authorization_sha256,
                bundle.signing_request.head.previous_head_sha256,
                bundle.signing_request.requested_at,
            )
            _validated_verification_receipt(
                bundle.release_verifier.verify_signed_head(verification_request),
                verification_request,
            )

        def tampered() -> None:
            item = signed["head"]
            altered = SignedReleaseHeadDescriptor(
                item.head,
                item.signer_key_id,
                item.offline_root_authorization_sha256,
                item.signing_algorithm,
                item.signature + b"x",
                item.signed_at,
            )
            verification_request = ReleaseHeadVerificationRequest(
                "request.verify.tampered",
                altered,
                item.offline_root_authorization_sha256,
                item.head.previous_head_sha256,
                bundle.signing_request.requested_at,
            )
            _expect_provider_rejection(
                lambda: bundle.release_verifier.verify_signed_head(
                    verification_request
                ),
                verification_request,
                altered.head,
                "signature_mismatch",
            )

        def wrong_root() -> None:
            alternate_signing = ReleaseHeadSigningRequest(
                "request.sign.wrong_root",
                bundle.signing_request.head,
                bundle.signing_request.signer_key_id,
                "sha256:" + "f" * 64,
                bundle.signing_request.signing_algorithm,
                bundle.signing_request.requested_at,
            )
            alternate_receipt = _validated_signing_receipt(
                signer.sign_head(alternate_signing),
                alternate_signing,
            )
            verification_request = ReleaseHeadVerificationRequest(
                "request.verify.root",
                alternate_receipt.signed_head,
                "sha256:" + "f" * 64,
                alternate_receipt.signed_head.head.previous_head_sha256,
                bundle.signing_request.requested_at,
            )
            _expect_provider_rejection(
                lambda: bundle.release_verifier.verify_signed_head(
                    verification_request
                ),
                verification_request,
                alternate_receipt.signed_head.head,
                "root_authorization_mismatch",
            )

        def wrong_predecessor() -> None:
            alternate_head = LedgerHeadDescriptor(
                bundle.signing_request.head.deployment_id,
                2,
                "entry.alternate.predecessor",
                "sha256:" + "c" * 64,
                "sha256:" + "d" * 64,
            )
            alternate_signing = ReleaseHeadSigningRequest(
                "request.sign.wrong_predecessor",
                alternate_head,
                bundle.signing_request.signer_key_id,
                bundle.signing_request.offline_root_authorization_sha256,
                bundle.signing_request.signing_algorithm,
                bundle.signing_request.requested_at,
            )
            alternate_receipt = _validated_signing_receipt(
                signer.sign_head(alternate_signing),
                alternate_signing,
            )
            verification_request = ReleaseHeadVerificationRequest(
                "request.verify.predecessor",
                alternate_receipt.signed_head,
                alternate_receipt.signed_head.offline_root_authorization_sha256,
                "sha256:" + "d" * 64,
                bundle.signing_request.requested_at,
            )
            _expect_provider_rejection(
                lambda: bundle.release_verifier.verify_signed_head(
                    verification_request
                ),
                verification_request,
                alternate_head,
                "predecessor_policy_mismatch",
            )

        return (valid, tampered, wrong_root, wrong_predecessor)
    if case_id == "audit_append_blocks_release":

        def accepted() -> None:
            audit_request = ReleaseAuditAppendRequest(
                "request.audit.accepted", bundle.audit_event
            )
            _validated_receipt(
                bundle.release_audit.append_audit_event(audit_request),
                ReleaseAuditAppendReceipt,
                request_id=audit_request.request_id,
                event=audit_request.event,
                append_status="appended",
            )
            _validated_signing_receipt(
                signer.sign_head(bundle.signing_request),
                bundle.signing_request,
            )

        def blocked() -> None:
            signer_calls_before = signer.call_count
            audit_request = ReleaseAuditAppendRequest(
                "request.audit.blocked", bundle.audit_event
            )
            fault.arm(
                "audit_append",
                audit_request.request_id,
                provider_subject_sha256(bundle.audit_event),
            )
            try:
                try:
                    _expect_test_fault(
                        lambda: bundle.release_audit.append_audit_event(
                            audit_request
                        ),
                        audit_request,
                        bundle.audit_event,
                        "audit_append",
                    )
                except _ExpectedBlocked as exc:
                    signer_calls_after = signer.call_count
                    _record_runner_counter(signer_calls_before, signer_calls_after)
                    if signer_calls_after != signer_calls_before:
                        raise RuntimeError(
                            "Signing occurred after a failed audit append"
                        ) from exc
                    raise
            finally:
                fault.clear()

        return (accepted, blocked)
    if case_id == "partial_release_recovery":

        def partial() -> None:
            ledger_request = LedgerObjectPutRequest(
                "request.partial.ledger", bundle.ledger_object, bundle.ledger_payload
            )
            _validated_receipt(
                bundle.ledger_objects.put_if_absent(ledger_request),
                LedgerObjectPutReceipt,
                request_id=ledger_request.request_id,
                object=ledger_request.object,
                write_status="created",
            )
            head_request = LedgerHeadCompareAndSwapRequest(
                "request.partial.head", None, bundle.initial_head
            )
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(head_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=head_request.request_id,
                head=head_request.proposed_head,
                compare_and_swap_status="advanced",
            )
            catalog_request = CatalogObjectPutRequest(
                "request.partial.catalog", bundle.catalog_object, bundle.catalog_payload
            )
            fault.arm(
                "catalog_put",
                catalog_request.request_id,
                provider_subject_sha256(bundle.catalog_object),
            )
            try:
                _expect_test_fault(
                    lambda: bundle.catalog_objects.put_sha256_object(
                        catalog_request
                    ),
                    catalog_request,
                    bundle.catalog_object,
                    "catalog_put",
                )
            finally:
                fault.clear()

        def recovered() -> None:
            ledger_request = LedgerObjectPutRequest(
                "request.recover.ledger", bundle.ledger_object, bundle.ledger_payload
            )
            _validated_receipt(
                bundle.ledger_objects.put_if_absent(ledger_request),
                LedgerObjectPutReceipt,
                request_id=ledger_request.request_id,
                object=ledger_request.object,
                write_status="already_present_same_digest",
            )
            head_request = LedgerHeadCompareAndSwapRequest(
                "request.recover.head", None, bundle.initial_head
            )
            _validated_receipt(
                bundle.ledger_heads.compare_and_swap_head(head_request),
                LedgerHeadCompareAndSwapReceipt,
                request_id=head_request.request_id,
                head=head_request.proposed_head,
                compare_and_swap_status="already_current_same_digest",
            )
            catalog_request = CatalogObjectPutRequest(
                "request.recover.catalog", bundle.catalog_object, bundle.catalog_payload
            )
            _validated_receipt(
                bundle.catalog_objects.put_sha256_object(catalog_request),
                CatalogObjectPutReceipt,
                request_id=catalog_request.request_id,
                object=catalog_request.object,
                write_status="created",
            )
            audit_request = ReleaseAuditAppendRequest(
                "request.recover.audit", bundle.audit_event
            )
            _validated_receipt(
                bundle.release_audit.append_audit_event(audit_request),
                ReleaseAuditAppendReceipt,
                request_id=audit_request.request_id,
                event=audit_request.event,
                append_status="appended",
            )
            signing_receipt = _validated_signing_receipt(
                signer.sign_head(bundle.signing_request),
                bundle.signing_request,
            )
            verification_request = ReleaseHeadVerificationRequest(
                "request.recover.verify",
                signing_receipt.signed_head,
                bundle.signing_request.offline_root_authorization_sha256,
                bundle.signing_request.head.previous_head_sha256,
                bundle.signing_request.requested_at,
            )
            _validated_verification_receipt(
                bundle.release_verifier.verify_signed_head(verification_request),
                verification_request,
            )

        return (partial, recovered)
    raise QualificationError("Unknown production custody conformance case")


def _validate_bundle_protocols(bundle: ProductionCustodyAdapterBundle) -> None:
    components = (
        ("checkpoint_access", bundle.checkpoint_access, NativeCheckpointAccessProvider),
        (
            "ledger_objects",
            bundle.ledger_objects,
            RetentionLockedLedgerObjectProvider,
        ),
        ("ledger_heads", bundle.ledger_heads, ConditionalLedgerHeadProvider),
        ("catalog_objects", bundle.catalog_objects, ImmutableCatalogObjectProvider),
        ("workload_identity", bundle.workload_identity, WorkloadIdentityVerifier),
        ("release_signer", bundle.release_signer, ReleaseHeadSigner),
        ("release_verifier", bundle.release_verifier, ReleaseHeadVerifier),
        ("release_audit", bundle.release_audit, ReleaseAuditSink),
    )
    for label, provider, protocol in components:
        if not isinstance(provider, protocol):
            raise QualificationError(
                f"Adapter bundle {label} does not implement its provider protocol"
            )


def run_production_custody_conformance(
    contract: ProductionCustodyProviderContract,
    suite: ProductionCustodyConformanceSuite,
    adapter_factory: ProductionCustodyAdapterFactory,
    fault_injector_factory: TestOnlyProductionCustodyFaultInjectorFactory,
    *,
    environment_class: str = REFERENCE_ENVIRONMENT,
) -> ProductionCustodyConformanceReport:
    verified_contract = ProductionCustodyProviderContract.from_dict(contract.to_dict())
    _validate_required_operation_coverage(verified_contract)
    verified_suite = ProductionCustodyConformanceSuite.from_dict(suite.to_dict())
    if (verified_suite.contract_id, verified_suite.contract_sha256) != (
        verified_contract.contract_id,
        verified_contract.contract_sha256,
    ):
        raise QualificationError("Conformance suite contract binding is invalid")
    if environment_class not in {REFERENCE_ENVIRONMENT, EXTERNAL_ENVIRONMENT}:
        raise QualificationError("Conformance environment class is invalid")
    factory_environment = getattr(adapter_factory, "environment_class", None)
    if factory_environment != environment_class:
        raise QualificationError(
            "Adapter factory provenance does not match the report environment"
        )
    observations: list[CaseObservation] = []
    provider_descriptor: dict[str, str] | None = None
    for case in verified_suite.cases:
        fault = fault_injector_factory.create_fault_injector(case.case_id)
        bundle = adapter_factory.create_bundle(case.case_id, fault)
        if bundle.environment_class != factory_environment:
            raise QualificationError(
                "Adapter bundle provenance does not match its factory"
            )
        _validate_bundle_protocols(bundle)
        descriptor = _validate_provider_descriptor(bundle.provider_descriptor)
        if provider_descriptor is None:
            provider_descriptor = descriptor
        elif descriptor != provider_descriptor:
            raise QualificationError("Provider descriptor changed across isolated cases")
        observations.append(_run_case(case, bundle, fault))
    if provider_descriptor is None:
        raise QualificationError("Conformance suite contains no cases")
    body = {
        "schema_version": SCHEMA_VERSION,
        "contract_id": verified_contract.contract_id,
        "contract_sha256": verified_contract.contract_sha256,
        "suite_id": verified_suite.suite_id,
        "suite_sha256": verified_suite.suite_sha256,
        "provider_descriptor": provider_descriptor,
        "environment_class": environment_class,
        "case_observations": [item.to_dict() for item in observations],
        "overall_outcome": "conformant"
        if all(item.outcome == "pass" for item in observations)
        else "nonconformant",
        "independent_review_required": True,
        "provider_selection_effect": "none",
        "qualification_effect": "none",
        "deployment_effect": "none",
        "catalog_publication_effect": "none",
        "enrollment_effect": "none",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
    return ProductionCustodyConformanceReport.from_dict(
        {
            **body,
            "report_id": "PCF-" + digest.removeprefix("sha256:")[:32].upper(),
            "report_sha256": digest,
        }
    )


__all__ = [
    "CASE_DEFINITIONS",
    "CONFORMANCE_OPERATION_COVERAGE",
    "CheckpointConformanceFixture",
    "ConformanceControlRejection",
    "ConformanceCase",
    "ConformanceVariant",
    "EXTERNAL_ENVIRONMENT",
    "ProductionCustodyAdapterBundle",
    "ProductionCustodyAdapterFactory",
    "ProductionCustodyConformanceReport",
    "ProductionCustodyConformanceSuite",
    "REFERENCE_ENVIRONMENT",
    "TestOnlyProductionCustodyFaultInjector",
    "TestOnlyProductionCustodyFaultInjectorFactory",
    "TestFaultAcknowledgement",
    "build_production_custody_conformance_suite",
    "run_production_custody_conformance",
]

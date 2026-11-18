"""Repository-only contracts for cryptography and PKI specialists.

The records in this module describe bounded analysis of sanitized or synthetic
cryptographic evidence. The module contains no network client, scanner,
command runner, key generator, keystore client, secret resolver, credential
handler, or target implementation. A caller-supplied adapter can receive only
validated metadata and digests after exact authorization, context, time,
replay, provenance, and budget checks succeed.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

SCHEMA_VERSION = 1
MAX_WINDOW_SECONDS = 86_400
MAX_EVIDENCE_ITEMS = 10_000
MAX_FINDINGS = 10_000
MAX_OBSERVED_BYTES = 1_000_000_000

BOUNDARY_EFFECTS = MappingProxyType(
    {
        "builtin_network": "none",
        "builtin_scanner": "none",
        "builtin_command_execution": "none",
        "builtin_key_generation": "none",
        "builtin_key_access": "none",
        "builtin_secret_access": "none",
        "builtin_credential_handling": "none",
        "builtin_target_interaction": "none",
        "injected_adapter_invocation": "caller_supplied_repository_only",
    }
)

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|contextref|scoperef|authorizationref|admissionref|"
    r"evidenceplanref|policyref|trustref|budgetref|capabilityref|evidenceref|"
    r"collectorref|ruleref|remediationref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
SECRET_MATERIAL_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{4,}|"
    r"\b(?:password|passwd|secret|private_key|api_key|client_secret|"
    r"access_token|refresh_token)\s*[:=]\s*[^,}\s]+|"
    r"\bAKIA[0-9A-Z]{16}\b|\bgh[oprsu]_[A-Za-z0-9]{20,}\b)",
    re.IGNORECASE,
)


class CryptoPKISpecialistContractError(ValueError):
    """Raised when a cryptography or PKI specialist contract fails closed."""


class SpecialistFamily(StrEnum):
    CRYPTOGRAPHIC_PROTOCOLS = "cryptographic_protocols"
    PKI_TRUST = "pki_trust"
    TLS_MTLS = "tls_mtls"
    CERTIFICATE_LIFECYCLE = "certificate_lifecycle"
    SECRETS_KEY_MANAGEMENT = "secrets_key_management"
    SIGNING_VERIFICATION = "signing_verification"
    TOKEN_IDENTITY_PROTOCOLS = "token_identity_protocols"
    CRYPTOGRAPHIC_MISUSE = "cryptographic_misuse"


class AssessmentCheck(StrEnum):
    PROTOCOL_VERSION_POLICY = "protocol_version_policy"
    CIPHER_SUITE_POLICY = "cipher_suite_policy"
    TRUST_PATH_POLICY = "trust_path_policy"
    REVOCATION_STATUS_POLICY = "revocation_status_policy"
    TLS_ENDPOINT_CONFIGURATION = "tls_endpoint_configuration"
    MTLS_IDENTITY_BINDING = "mtls_identity_binding"
    CERTIFICATE_ISSUANCE = "certificate_issuance"
    CERTIFICATE_RENEWAL_ROTATION = "certificate_renewal_rotation"
    SECRET_INVENTORY_HYGIENE = "secret_inventory_hygiene"
    KEY_CUSTODY_ROTATION = "key_custody_rotation"
    SIGNATURE_VERIFICATION = "signature_verification"
    TOKEN_VALIDATION = "token_validation"
    IDENTITY_PROTOCOL_BINDING = "identity_protocol_binding"
    ALGORITHM_PARAMETER_MISUSE = "algorithm_parameter_misuse"
    NONCE_IV_REUSE_POLICY = "nonce_iv_reuse_policy"
    KEY_USAGE_SEPARATION = "key_usage_separation"


class EvidenceKind(StrEnum):
    SYNTHETIC_CERTIFICATE_MANIFEST = "synthetic_certificate_manifest"
    SANITIZED_TLS_CONFIGURATION = "sanitized_tls_configuration"
    SANITIZED_HANDSHAKE_SUMMARY = "sanitized_handshake_summary"
    SANITIZED_TRUST_PATH_SUMMARY = "sanitized_trust_path_summary"
    SANITIZED_REVOCATION_SUMMARY = "sanitized_revocation_summary"
    SANITIZED_KEY_LIFECYCLE_METADATA = "sanitized_key_lifecycle_metadata"
    SANITIZED_SECRET_INVENTORY_SUMMARY = "sanitized_secret_inventory_summary"
    SANITIZED_SIGNATURE_POLICY = "sanitized_signature_policy"
    SANITIZED_TOKEN_CLAIMS_SCHEMA = "sanitized_token_claims_schema"
    SANITIZED_IDENTITY_PROTOCOL_METADATA = "sanitized_identity_protocol_metadata"
    SANITIZED_SOURCE_ANALYSIS_FINDING = "sanitized_source_analysis_finding"


class FindingCategory(StrEnum):
    DEPRECATED_ALGORITHM = "deprecated_algorithm"
    WEAK_PARAMETER_POLICY = "weak_parameter_policy"
    PROTOCOL_DOWNGRADE_POLICY = "protocol_downgrade_policy"
    TRUST_PATH_GAP = "trust_path_gap"
    REVOCATION_GAP = "revocation_gap"
    HOST_IDENTITY_GAP = "host_identity_gap"
    MTLS_BINDING_GAP = "mtls_binding_gap"
    CERTIFICATE_LIFECYCLE_GAP = "certificate_lifecycle_gap"
    SECRET_CUSTODY_GAP = "secret_custody_gap"
    KEY_LIFECYCLE_GAP = "key_lifecycle_gap"
    SIGNATURE_VALIDATION_GAP = "signature_validation_gap"
    TOKEN_VALIDATION_GAP = "token_validation_gap"
    IDENTITY_PROTOCOL_GAP = "identity_protocol_gap"
    NONCE_IV_POLICY_GAP = "nonce_iv_policy_gap"
    KEY_USAGE_SEPARATION_GAP = "key_usage_separation_gap"


class FindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceBasis(StrEnum):
    DETERMINISTIC_POLICY_MATCH = "deterministic_policy_match"
    PROVENANCE_BOUNDED_INFERENCE = "provenance_bounded_inference"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class AdapterDisposition(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


class AssessmentOutcome(StrEnum):
    PASS = "pass"
    CONTROL_GAP = "control_gap"
    INCONCLUSIVE = "inconclusive"


class ReceiptStatus(StrEnum):
    COMPLETED = "completed"
    DENIED = "denied"
    FAILED = "failed"


FAMILY_CHECKS = MappingProxyType(
    {
        SpecialistFamily.CRYPTOGRAPHIC_PROTOCOLS: frozenset(
            {
                AssessmentCheck.PROTOCOL_VERSION_POLICY,
                AssessmentCheck.CIPHER_SUITE_POLICY,
                AssessmentCheck.ALGORITHM_PARAMETER_MISUSE,
            }
        ),
        SpecialistFamily.PKI_TRUST: frozenset(
            {
                AssessmentCheck.TRUST_PATH_POLICY,
                AssessmentCheck.REVOCATION_STATUS_POLICY,
                AssessmentCheck.KEY_USAGE_SEPARATION,
            }
        ),
        SpecialistFamily.TLS_MTLS: frozenset(
            {
                AssessmentCheck.PROTOCOL_VERSION_POLICY,
                AssessmentCheck.CIPHER_SUITE_POLICY,
                AssessmentCheck.TLS_ENDPOINT_CONFIGURATION,
                AssessmentCheck.MTLS_IDENTITY_BINDING,
            }
        ),
        SpecialistFamily.CERTIFICATE_LIFECYCLE: frozenset(
            {
                AssessmentCheck.CERTIFICATE_ISSUANCE,
                AssessmentCheck.CERTIFICATE_RENEWAL_ROTATION,
                AssessmentCheck.REVOCATION_STATUS_POLICY,
            }
        ),
        SpecialistFamily.SECRETS_KEY_MANAGEMENT: frozenset(
            {
                AssessmentCheck.SECRET_INVENTORY_HYGIENE,
                AssessmentCheck.KEY_CUSTODY_ROTATION,
                AssessmentCheck.KEY_USAGE_SEPARATION,
            }
        ),
        SpecialistFamily.SIGNING_VERIFICATION: frozenset(
            {
                AssessmentCheck.SIGNATURE_VERIFICATION,
                AssessmentCheck.KEY_USAGE_SEPARATION,
                AssessmentCheck.ALGORITHM_PARAMETER_MISUSE,
            }
        ),
        SpecialistFamily.TOKEN_IDENTITY_PROTOCOLS: frozenset(
            {
                AssessmentCheck.TOKEN_VALIDATION,
                AssessmentCheck.IDENTITY_PROTOCOL_BINDING,
                AssessmentCheck.SIGNATURE_VERIFICATION,
            }
        ),
        SpecialistFamily.CRYPTOGRAPHIC_MISUSE: frozenset(
            {
                AssessmentCheck.ALGORITHM_PARAMETER_MISUSE,
                AssessmentCheck.NONCE_IV_REUSE_POLICY,
                AssessmentCheck.KEY_USAGE_SEPARATION,
            }
        ),
    }
)

CHECK_FINDINGS = MappingProxyType(
    {
        AssessmentCheck.PROTOCOL_VERSION_POLICY: frozenset(
            {FindingCategory.PROTOCOL_DOWNGRADE_POLICY}
        ),
        AssessmentCheck.CIPHER_SUITE_POLICY: frozenset(
            {FindingCategory.DEPRECATED_ALGORITHM, FindingCategory.WEAK_PARAMETER_POLICY}
        ),
        AssessmentCheck.TRUST_PATH_POLICY: frozenset({FindingCategory.TRUST_PATH_GAP}),
        AssessmentCheck.REVOCATION_STATUS_POLICY: frozenset({FindingCategory.REVOCATION_GAP}),
        AssessmentCheck.TLS_ENDPOINT_CONFIGURATION: frozenset(
            {
                FindingCategory.HOST_IDENTITY_GAP,
                FindingCategory.PROTOCOL_DOWNGRADE_POLICY,
                FindingCategory.DEPRECATED_ALGORITHM,
                FindingCategory.WEAK_PARAMETER_POLICY,
            }
        ),
        AssessmentCheck.MTLS_IDENTITY_BINDING: frozenset(
            {
                FindingCategory.MTLS_BINDING_GAP,
                FindingCategory.TRUST_PATH_GAP,
                FindingCategory.KEY_USAGE_SEPARATION_GAP,
            }
        ),
        AssessmentCheck.CERTIFICATE_ISSUANCE: frozenset(
            {
                FindingCategory.CERTIFICATE_LIFECYCLE_GAP,
                FindingCategory.TRUST_PATH_GAP,
                FindingCategory.KEY_USAGE_SEPARATION_GAP,
            }
        ),
        AssessmentCheck.CERTIFICATE_RENEWAL_ROTATION: frozenset(
            {
                FindingCategory.CERTIFICATE_LIFECYCLE_GAP,
                FindingCategory.REVOCATION_GAP,
            }
        ),
        AssessmentCheck.SECRET_INVENTORY_HYGIENE: frozenset({FindingCategory.SECRET_CUSTODY_GAP}),
        AssessmentCheck.KEY_CUSTODY_ROTATION: frozenset(
            {
                FindingCategory.KEY_LIFECYCLE_GAP,
                FindingCategory.SECRET_CUSTODY_GAP,
                FindingCategory.KEY_USAGE_SEPARATION_GAP,
            }
        ),
        AssessmentCheck.SIGNATURE_VERIFICATION: frozenset(
            {
                FindingCategory.SIGNATURE_VALIDATION_GAP,
                FindingCategory.DEPRECATED_ALGORITHM,
                FindingCategory.WEAK_PARAMETER_POLICY,
                FindingCategory.KEY_USAGE_SEPARATION_GAP,
            }
        ),
        AssessmentCheck.TOKEN_VALIDATION: frozenset(
            {
                FindingCategory.TOKEN_VALIDATION_GAP,
                FindingCategory.SIGNATURE_VALIDATION_GAP,
                FindingCategory.DEPRECATED_ALGORITHM,
            }
        ),
        AssessmentCheck.IDENTITY_PROTOCOL_BINDING: frozenset(
            {
                FindingCategory.IDENTITY_PROTOCOL_GAP,
                FindingCategory.TOKEN_VALIDATION_GAP,
                FindingCategory.MTLS_BINDING_GAP,
            }
        ),
        AssessmentCheck.ALGORITHM_PARAMETER_MISUSE: frozenset(
            {FindingCategory.DEPRECATED_ALGORITHM, FindingCategory.WEAK_PARAMETER_POLICY}
        ),
        AssessmentCheck.NONCE_IV_REUSE_POLICY: frozenset({FindingCategory.NONCE_IV_POLICY_GAP}),
        AssessmentCheck.KEY_USAGE_SEPARATION: frozenset({FindingCategory.KEY_USAGE_SEPARATION_GAP}),
    }
)


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret scanning."""

    _validate_json(value, "value")
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if SECRET_MATERIAL_RE.search(encoded):
        raise CryptoPKISpecialistContractError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise CryptoPKISpecialistContractError(f"{label} exceeds the nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CryptoPKISpecialistContractError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise CryptoPKISpecialistContractError(f"{label} has an unsupported value")


def _reference(value: Any, label: str, namespace: str) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise CryptoPKISpecialistContractError(f"{label} must be an opaque reference")
    if not value.startswith(namespace + ":"):
        raise CryptoPKISpecialistContractError(f"{label} must use the {namespace} namespace")
    if SECRET_MATERIAL_RE.search(value):
        raise CryptoPKISpecialistContractError(f"{label} contains secret material")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CryptoPKISpecialistContractError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CryptoPKISpecialistContractError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CryptoPKISpecialistContractError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _evaluated_at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CryptoPKISpecialistContractError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _positive(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise CryptoPKISpecialistContractError(f"{label} is invalid")
    return value


def _nonnegative(value: Any, label: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise CryptoPKISpecialistContractError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class SpecialistCapabilityDeclaration:
    family: SpecialistFamily
    capability_ref: str
    checks: tuple[AssessmentCheck, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        checks = tuple(AssessmentCheck(item) for item in self.checks)
        if not checks or len(checks) != len(set(checks)):
            raise CryptoPKISpecialistContractError("checks are invalid")
        if not set(checks).issubset(FAMILY_CHECKS[self.family]):
            raise CryptoPKISpecialistContractError("check is outside the specialist family")
        object.__setattr__(self, "checks", tuple(sorted(checks, key=str)))

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "crypto_pki_specialist_capability_declaration",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "checks": [item.value for item in self.checks],
            "evidence_policy": "sanitized_or_synthetic_digest_only",
            "qualification_effect": "none",
        }

    @property
    def declaration_id(self) -> str:
        return _identity("CPD", "crypto-pki-specialist-declaration-v1", self._body())[0]

    @property
    def declaration_sha256(self) -> str:
        return _identity("CPD", "crypto-pki-specialist-declaration-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class AssessmentBudget:
    budget_ref: str
    maximum_evidence_items: int
    maximum_findings: int
    maximum_observed_bytes: int
    maximum_duration_seconds: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "budget_ref", _reference(self.budget_ref, "budget_ref", "budgetref")
        )
        object.__setattr__(
            self,
            "maximum_evidence_items",
            _positive(self.maximum_evidence_items, "maximum_evidence_items", MAX_EVIDENCE_ITEMS),
        )
        object.__setattr__(
            self,
            "maximum_findings",
            _positive(self.maximum_findings, "maximum_findings", MAX_FINDINGS),
        )
        object.__setattr__(
            self,
            "maximum_observed_bytes",
            _positive(self.maximum_observed_bytes, "maximum_observed_bytes", MAX_OBSERVED_BYTES),
        )
        object.__setattr__(
            self,
            "maximum_duration_seconds",
            _positive(
                self.maximum_duration_seconds,
                "maximum_duration_seconds",
                MAX_WINDOW_SECONDS,
            ),
        )

    @property
    def budget_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget_ref": self.budget_ref,
            "maximum_evidence_items": self.maximum_evidence_items,
            "maximum_findings": self.maximum_findings,
            "maximum_observed_bytes": self.maximum_observed_bytes,
            "maximum_duration_seconds": self.maximum_duration_seconds,
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentContext:
    tenant_ref: str
    context_ref: str
    context_binding_sha256: str
    scope_ref: str
    scope_sha256: str
    authorization_ref: str
    authorization_sha256: str
    action_admission_ref: str
    action_admission_sha256: str
    evidence_plan_ref: str
    evidence_plan_sha256: str
    cryptographic_policy_ref: str
    cryptographic_policy_sha256: str
    trust_policy_ref: str
    trust_policy_sha256: str
    authorized_at: str
    authorization_expires_at: str
    repository_assessment_authorized: bool
    target_interaction_authorized: bool
    budget: AssessmentBudget

    def __post_init__(self) -> None:
        references = (
            ("tenant_ref", "tenantref"),
            ("context_ref", "contextref"),
            ("scope_ref", "scoperef"),
            ("authorization_ref", "authorizationref"),
            ("action_admission_ref", "admissionref"),
            ("evidence_plan_ref", "evidenceplanref"),
            ("cryptographic_policy_ref", "policyref"),
            ("trust_policy_ref", "trustref"),
        )
        for field_name, namespace in references:
            object.__setattr__(
                self,
                field_name,
                _reference(getattr(self, field_name), field_name, namespace),
            )
        for field_name in (
            "context_binding_sha256",
            "scope_sha256",
            "authorization_sha256",
            "action_admission_sha256",
            "evidence_plan_sha256",
            "cryptographic_policy_sha256",
            "trust_policy_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        authorized = _instant(_timestamp(self.authorized_at, "authorized_at"))
        expires = _instant(_timestamp(self.authorization_expires_at, "authorization_expires_at"))
        if not 0 < (expires - authorized).total_seconds() <= MAX_WINDOW_SECONDS:
            raise CryptoPKISpecialistContractError("authorization window is invalid")
        if self.repository_assessment_authorized is not True:
            raise CryptoPKISpecialistContractError("explicit repository authorization is required")
        if self.target_interaction_authorized is not False:
            raise CryptoPKISpecialistContractError("target interaction must remain unauthorized")
        if not isinstance(self.budget, AssessmentBudget):
            raise CryptoPKISpecialistContractError("budget is invalid")

    @property
    def assessment_context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_ref": self.tenant_ref,
            "context_ref": self.context_ref,
            "context_binding_sha256": self.context_binding_sha256,
            "scope_ref": self.scope_ref,
            "scope_sha256": self.scope_sha256,
            "authorization_ref": self.authorization_ref,
            "authorization_sha256": self.authorization_sha256,
            "action_admission_ref": self.action_admission_ref,
            "action_admission_sha256": self.action_admission_sha256,
            "evidence_plan_ref": self.evidence_plan_ref,
            "evidence_plan_sha256": self.evidence_plan_sha256,
            "cryptographic_policy_ref": self.cryptographic_policy_ref,
            "cryptographic_policy_sha256": self.cryptographic_policy_sha256,
            "trust_policy_ref": self.trust_policy_ref,
            "trust_policy_sha256": self.trust_policy_sha256,
            "authorized_at": self.authorized_at,
            "authorization_expires_at": self.authorization_expires_at,
            "repository_assessment_authorized": self.repository_assessment_authorized,
            "target_interaction_authorized": self.target_interaction_authorized,
            "budget": self.budget.to_dict(),
            "budget_sha256": self.budget.budget_sha256,
        }


@dataclass(frozen=True, slots=True)
class EvidenceProvenance:
    evidence_ref: str
    evidence_kind: EvidenceKind
    content_sha256: str
    source_manifest_sha256: str
    collector_ref: str
    collected_at: str
    observed_bytes: int
    provenance_chain: tuple[str, ...]
    sanitized: bool = True
    contains_private_key: bool = False
    contains_secret_value: bool = False
    contains_credential: bool = False
    contains_live_target_capture: bool = False
    includes_executable_material: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_ref", _reference(self.evidence_ref, "evidence_ref", "evidenceref")
        )
        object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        object.__setattr__(self, "content_sha256", _digest(self.content_sha256, "content_sha256"))
        object.__setattr__(
            self,
            "source_manifest_sha256",
            _digest(self.source_manifest_sha256, "source_manifest_sha256"),
        )
        object.__setattr__(
            self, "collector_ref", _reference(self.collector_ref, "collector_ref", "collectorref")
        )
        object.__setattr__(self, "collected_at", _timestamp(self.collected_at, "collected_at"))
        object.__setattr__(
            self,
            "observed_bytes",
            _positive(self.observed_bytes, "observed_bytes", MAX_OBSERVED_BYTES),
        )
        chain = tuple(_digest(item, "provenance_chain") for item in self.provenance_chain)
        if not chain or len(chain) != len(set(chain)):
            raise CryptoPKISpecialistContractError("provenance_chain is invalid")
        object.__setattr__(self, "provenance_chain", chain)
        if self.sanitized is not True:
            raise CryptoPKISpecialistContractError("evidence must be sanitized")
        if any(
            value is not False
            for value in (
                self.contains_private_key,
                self.contains_secret_value,
                self.contains_credential,
                self.contains_live_target_capture,
                self.includes_executable_material,
            )
        ):
            raise CryptoPKISpecialistContractError("evidence crosses the repository-only boundary")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "crypto_pki_evidence_provenance",
            "schema_version": SCHEMA_VERSION,
            "evidence_ref": self.evidence_ref,
            "evidence_kind": self.evidence_kind.value,
            "content_sha256": self.content_sha256,
            "source_manifest_sha256": self.source_manifest_sha256,
            "collector_ref": self.collector_ref,
            "collected_at": self.collected_at,
            "observed_bytes": self.observed_bytes,
            "provenance_chain": list(self.provenance_chain),
            "sanitized": self.sanitized,
            "contains_private_key": self.contains_private_key,
            "contains_secret_value": self.contains_secret_value,
            "contains_credential": self.contains_credential,
            "contains_live_target_capture": self.contains_live_target_capture,
            "includes_executable_material": self.includes_executable_material,
            "qualification_effect": "none",
        }

    @property
    def evidence_id(self) -> str:
        return _identity("CPE", "crypto-pki-evidence-provenance-v1", self._body())[0]

    @property
    def evidence_sha256(self) -> str:
        return _identity("CPE", "crypto-pki-evidence-provenance-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentRequest:
    declaration_id: str
    declaration_sha256: str
    family: SpecialistFamily
    capability_ref: str
    check: AssessmentCheck
    context: SpecialistAssessmentContext
    evidence: tuple[EvidenceProvenance, ...]
    expected_policy_sha256: str
    estimated_evidence_items: int
    estimated_findings: int
    estimated_observed_bytes: int
    estimated_duration_seconds: int
    idempotency_sha256: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.declaration_id, str)
            or re.fullmatch(r"CPD-[0-9A-F]{32}", self.declaration_id) is None
        ):
            raise CryptoPKISpecialistContractError("declaration_id is invalid")
        object.__setattr__(
            self,
            "declaration_sha256",
            _digest(self.declaration_sha256, "declaration_sha256"),
        )
        object.__setattr__(self, "family", SpecialistFamily(self.family))
        object.__setattr__(
            self,
            "capability_ref",
            _reference(self.capability_ref, "capability_ref", "capabilityref"),
        )
        object.__setattr__(self, "check", AssessmentCheck(self.check))
        if self.check not in FAMILY_CHECKS[self.family]:
            raise CryptoPKISpecialistContractError("check is outside the specialist family")
        if not isinstance(self.context, SpecialistAssessmentContext):
            raise CryptoPKISpecialistContractError("context is invalid")
        evidence = tuple(self.evidence)
        if not evidence or any(not isinstance(item, EvidenceProvenance) for item in evidence):
            raise CryptoPKISpecialistContractError("evidence is invalid")
        evidence = tuple(sorted(evidence, key=lambda item: item.evidence_id))
        if len({item.evidence_ref for item in evidence}) != len(evidence):
            raise CryptoPKISpecialistContractError("evidence_ref values must be unique")
        if len({item.evidence_sha256 for item in evidence}) != len(evidence):
            raise CryptoPKISpecialistContractError("evidence records must be unique")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(
            self,
            "expected_policy_sha256",
            _digest(self.expected_policy_sha256, "expected_policy_sha256"),
        )
        object.__setattr__(
            self,
            "idempotency_sha256",
            _digest(self.idempotency_sha256, "idempotency_sha256"),
        )
        budget = self.context.budget
        estimates = (
            ("estimated_evidence_items", budget.maximum_evidence_items),
            ("estimated_findings", budget.maximum_findings),
            ("estimated_observed_bytes", budget.maximum_observed_bytes),
            ("estimated_duration_seconds", budget.maximum_duration_seconds),
        )
        for field_name, maximum in estimates:
            object.__setattr__(
                self,
                field_name,
                _positive(getattr(self, field_name), field_name, maximum),
            )
        if len(evidence) > self.estimated_evidence_items:
            raise CryptoPKISpecialistContractError("evidence exceeds the request estimate")
        if sum(item.observed_bytes for item in evidence) > self.estimated_observed_bytes:
            raise CryptoPKISpecialistContractError("evidence bytes exceed the request estimate")
        issued = _instant(_timestamp(self.issued_at, "issued_at"))
        expires = _instant(_timestamp(self.expires_at, "expires_at"))
        authorized = _instant(self.context.authorized_at)
        authorization_expires = _instant(self.context.authorization_expires_at)
        if not 0 < (expires - issued).total_seconds() <= MAX_WINDOW_SECONDS:
            raise CryptoPKISpecialistContractError("request window is invalid")
        if issued < authorized or expires > authorization_expires:
            raise CryptoPKISpecialistContractError("request is outside the authorization window")

    @property
    def evidence_set_sha256(self) -> str:
        return canonical_sha256([item.to_dict() for item in self.evidence])

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "crypto_pki_specialist_assessment_request",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "declaration_id": self.declaration_id,
            "declaration_sha256": self.declaration_sha256,
            "family": self.family.value,
            "capability_ref": self.capability_ref,
            "check": self.check.value,
            "context": self.context.to_dict(),
            "assessment_context_sha256": self.context.assessment_context_sha256,
            "evidence": [item.to_dict() for item in self.evidence],
            "evidence_set_sha256": self.evidence_set_sha256,
            "expected_policy_sha256": self.expected_policy_sha256,
            "estimated_evidence_items": self.estimated_evidence_items,
            "estimated_findings": self.estimated_findings,
            "estimated_observed_bytes": self.estimated_observed_bytes,
            "estimated_duration_seconds": self.estimated_duration_seconds,
            "idempotency_sha256": self.idempotency_sha256,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "qualification_effect": "none",
        }

    @property
    def request_id(self) -> str:
        return _identity("CPR", "crypto-pki-specialist-request-v1", self._body())[0]

    @property
    def request_sha256(self) -> str:
        return _identity("CPR", "crypto-pki-specialist-request-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class AssessmentFinding:
    category: FindingCategory
    severity: FindingSeverity
    rule_ref: str
    evidence_refs: tuple[str, ...]
    remediation_ref: str
    confidence_basis: ConfidenceBasis

    def __post_init__(self) -> None:
        object.__setattr__(self, "category", FindingCategory(self.category))
        object.__setattr__(self, "severity", FindingSeverity(self.severity))
        object.__setattr__(self, "rule_ref", _reference(self.rule_ref, "rule_ref", "ruleref"))
        evidence_refs = tuple(
            _reference(item, "evidence_refs", "evidenceref") for item in self.evidence_refs
        )
        if not evidence_refs or len(evidence_refs) != len(set(evidence_refs)):
            raise CryptoPKISpecialistContractError("finding evidence_refs are invalid")
        object.__setattr__(self, "evidence_refs", tuple(sorted(evidence_refs)))
        object.__setattr__(
            self,
            "remediation_ref",
            _reference(self.remediation_ref, "remediation_ref", "remediationref"),
        )
        object.__setattr__(self, "confidence_basis", ConfidenceBasis(self.confidence_basis))

    def _body(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "rule_ref": self.rule_ref,
            "evidence_refs": list(self.evidence_refs),
            "remediation_ref": self.remediation_ref,
            "confidence_basis": self.confidence_basis.value,
        }

    @property
    def finding_id(self) -> str:
        return _identity("CPF", "crypto-pki-specialist-finding-v1", self._body())[0]

    @property
    def finding_sha256(self) -> str:
        return _identity("CPF", "crypto-pki-specialist-finding-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "finding_sha256": self.finding_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentObservation:
    request_id: str
    request_sha256: str
    assessment_context_sha256: str
    evidence_set_sha256: str
    disposition: AdapterDisposition
    outcome: AssessmentOutcome
    findings: tuple[AssessmentFinding, ...]
    analysis_evidence_sha256: str
    actual_evidence_items: int
    actual_findings: int
    actual_observed_bytes: int
    actual_duration_seconds: int
    network_call_performed: bool
    scanner_execution_performed: bool
    command_execution_performed: bool
    key_generation_performed: bool
    key_access_performed: bool
    secret_access_performed: bool
    credential_handling_performed: bool
    target_interaction_performed: bool
    started_at: str
    completed_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_id, str)
            or re.fullmatch(r"CPR-[0-9A-F]{32}", self.request_id) is None
        ):
            raise CryptoPKISpecialistContractError("request_id is invalid")
        for field_name in (
            "request_sha256",
            "assessment_context_sha256",
            "evidence_set_sha256",
            "analysis_evidence_sha256",
        ):
            object.__setattr__(self, field_name, _digest(getattr(self, field_name), field_name))
        object.__setattr__(self, "disposition", AdapterDisposition(self.disposition))
        object.__setattr__(self, "outcome", AssessmentOutcome(self.outcome))
        findings = tuple(self.findings)
        if any(not isinstance(item, AssessmentFinding) for item in findings):
            raise CryptoPKISpecialistContractError("findings are invalid")
        findings = tuple(sorted(findings, key=lambda item: item.finding_id))
        if len({item.finding_id for item in findings}) != len(findings):
            raise CryptoPKISpecialistContractError("findings must be unique")
        object.__setattr__(self, "findings", findings)
        counters = (
            ("actual_evidence_items", MAX_EVIDENCE_ITEMS),
            ("actual_findings", MAX_FINDINGS),
            ("actual_observed_bytes", MAX_OBSERVED_BYTES),
            ("actual_duration_seconds", MAX_WINDOW_SECONDS),
        )
        for field_name, maximum in counters:
            object.__setattr__(
                self,
                field_name,
                _nonnegative(getattr(self, field_name), field_name, maximum),
            )
        if self.actual_findings != len(findings):
            raise CryptoPKISpecialistContractError("actual_findings does not match findings")
        if self.disposition is AdapterDisposition.COMPLETED and self.actual_evidence_items == 0:
            raise CryptoPKISpecialistContractError("completed observation requires evidence")
        if self.outcome is AssessmentOutcome.PASS and findings:
            raise CryptoPKISpecialistContractError("pass outcome cannot include findings")
        if self.outcome is AssessmentOutcome.CONTROL_GAP and not findings:
            raise CryptoPKISpecialistContractError("control_gap outcome requires findings")
        if self.disposition is not AdapterDisposition.COMPLETED and (
            self.outcome is not AssessmentOutcome.INCONCLUSIVE or findings
        ):
            raise CryptoPKISpecialistContractError(
                "denied or failed observations must be inconclusive without findings"
            )
        started = _instant(_timestamp(self.started_at, "started_at"))
        completed = _instant(_timestamp(self.completed_at, "completed_at"))
        if completed < started:
            raise CryptoPKISpecialistContractError("observation window is invalid")
        if any(
            value is not False
            for value in (
                self.network_call_performed,
                self.scanner_execution_performed,
                self.command_execution_performed,
                self.key_generation_performed,
                self.key_access_performed,
                self.secret_access_performed,
                self.credential_handling_performed,
                self.target_interaction_performed,
            )
        ):
            raise CryptoPKISpecialistContractError("adapter crossed the repository-only boundary")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "assessment_context_sha256": self.assessment_context_sha256,
            "evidence_set_sha256": self.evidence_set_sha256,
            "disposition": self.disposition.value,
            "outcome": self.outcome.value,
            "findings": [item.to_dict() for item in self.findings],
            "analysis_evidence_sha256": self.analysis_evidence_sha256,
            "actual_evidence_items": self.actual_evidence_items,
            "actual_findings": self.actual_findings,
            "actual_observed_bytes": self.actual_observed_bytes,
            "actual_duration_seconds": self.actual_duration_seconds,
            "network_call_performed": self.network_call_performed,
            "scanner_execution_performed": self.scanner_execution_performed,
            "command_execution_performed": self.command_execution_performed,
            "key_generation_performed": self.key_generation_performed,
            "key_access_performed": self.key_access_performed,
            "secret_access_performed": self.secret_access_performed,
            "credential_handling_performed": self.credential_handling_performed,
            "target_interaction_performed": self.target_interaction_performed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


class SpecialistAssessmentAdapter(Protocol):
    """Caller-supplied adapter for repository-safe metadata assessment."""

    def assess(self, request: SpecialistAssessmentRequest) -> SpecialistAssessmentObservation:
        """Assess sanitized evidence without interacting with keys, secrets, or targets."""


@dataclass(frozen=True, slots=True)
class SpecialistAssessmentReceipt:
    request: SpecialistAssessmentRequest
    observation: SpecialistAssessmentObservation
    status: ReceiptStatus

    def __post_init__(self) -> None:
        if not isinstance(self.request, SpecialistAssessmentRequest):
            raise CryptoPKISpecialistContractError("request is invalid")
        if not isinstance(self.observation, SpecialistAssessmentObservation):
            raise CryptoPKISpecialistContractError("observation is invalid")
        object.__setattr__(self, "status", ReceiptStatus(self.status))
        observation = self.observation
        request = self.request
        if (
            observation.request_id != request.request_id
            or observation.request_sha256 != request.request_sha256
            or observation.assessment_context_sha256 != request.context.assessment_context_sha256
            or observation.evidence_set_sha256 != request.evidence_set_sha256
        ):
            raise CryptoPKISpecialistContractError("receipt observation binding mismatch")
        expected_status = {
            AdapterDisposition.COMPLETED: ReceiptStatus.COMPLETED,
            AdapterDisposition.DENIED: ReceiptStatus.DENIED,
            AdapterDisposition.FAILED: ReceiptStatus.FAILED,
        }[observation.disposition]
        if self.status is not expected_status:
            raise CryptoPKISpecialistContractError("receipt status is inconsistent")
        valid_evidence_refs = {item.evidence_ref for item in request.evidence}
        if any(
            not set(finding.evidence_refs).issubset(valid_evidence_refs)
            for finding in observation.findings
        ):
            raise CryptoPKISpecialistContractError("receipt finding cites unbound evidence")
        if any(
            finding.category not in CHECK_FINDINGS[request.check]
            for finding in observation.findings
        ):
            raise CryptoPKISpecialistContractError("receipt finding is outside the requested check")
        budget = request.context.budget
        actuals = (
            (observation.actual_evidence_items, request.estimated_evidence_items),
            (observation.actual_findings, request.estimated_findings),
            (observation.actual_observed_bytes, request.estimated_observed_bytes),
            (observation.actual_duration_seconds, request.estimated_duration_seconds),
            (observation.actual_evidence_items, budget.maximum_evidence_items),
            (observation.actual_findings, budget.maximum_findings),
            (observation.actual_observed_bytes, budget.maximum_observed_bytes),
            (observation.actual_duration_seconds, budget.maximum_duration_seconds),
        )
        if any(actual > maximum for actual, maximum in actuals):
            raise CryptoPKISpecialistContractError("receipt observation exceeded its budget")
        if observation.actual_evidence_items > len(request.evidence):
            raise CryptoPKISpecialistContractError("receipt contains unbound evidence items")
        if _instant(observation.started_at) < _instant(request.issued_at) or _instant(
            observation.completed_at
        ) > _instant(request.expires_at):
            raise CryptoPKISpecialistContractError("receipt observation window is invalid")

    def _body(self) -> dict[str, Any]:
        return {
            "kind": "crypto_pki_specialist_assessment_receipt",
            "schema_version": SCHEMA_VERSION,
            "boundary_effects": dict(BOUNDARY_EFFECTS),
            "request": self.request.to_dict(),
            "observation": self.observation.to_dict(),
            "status": self.status.value,
            "qualification_effect": "none",
        }

    @property
    def receipt_id(self) -> str:
        return _identity("CPC", "crypto-pki-specialist-receipt-v1", self._body())[0]

    @property
    def receipt_sha256(self) -> str:
        return _identity("CPC", "crypto-pki-specialist-receipt-v1", self._body())[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


def recommended_capability_declarations() -> tuple[SpecialistCapabilityDeclaration, ...]:
    """Return deterministic declarations for all repository-only specialist families."""

    return tuple(
        SpecialistCapabilityDeclaration(
            family=family,
            capability_ref=f"capabilityref:crypto-pki/{family.value}",
            checks=tuple(sorted(checks, key=str)),
        )
        for family, checks in FAMILY_CHECKS.items()
    )


def dispatch_specialist_assessment(
    request: SpecialistAssessmentRequest,
    declaration: SpecialistCapabilityDeclaration,
    expected_context: SpecialistAssessmentContext,
    adapter: SpecialistAssessmentAdapter,
    *,
    evaluated_at: datetime,
    seen_request_ids: Iterable[str] = (),
    seen_idempotency_sha256: Iterable[str] = (),
) -> SpecialistAssessmentReceipt:
    """Validate exact bindings and invoke one repository-only adapter once."""

    if not isinstance(request, SpecialistAssessmentRequest):
        raise CryptoPKISpecialistContractError("request is invalid")
    if not isinstance(declaration, SpecialistCapabilityDeclaration):
        raise CryptoPKISpecialistContractError("declaration is invalid")
    if not isinstance(expected_context, SpecialistAssessmentContext):
        raise CryptoPKISpecialistContractError("expected_context is invalid")
    if (
        request.declaration_id != declaration.declaration_id
        or request.declaration_sha256 != declaration.declaration_sha256
        or request.family is not declaration.family
        or request.capability_ref != declaration.capability_ref
        or request.check not in declaration.checks
    ):
        raise CryptoPKISpecialistContractError("declaration binding mismatch")
    if request.context != expected_context:
        raise CryptoPKISpecialistContractError("assessment context mismatch")
    now = _evaluated_at(evaluated_at)
    if not _instant(request.issued_at) <= now <= _instant(request.expires_at):
        raise CryptoPKISpecialistContractError("request is not active")
    if (
        not _instant(request.context.authorized_at)
        <= now
        <= _instant(request.context.authorization_expires_at)
    ):
        raise CryptoPKISpecialistContractError("authorization is not active")
    if request.request_id in set(seen_request_ids):
        raise CryptoPKISpecialistContractError("request replay is forbidden")
    if request.idempotency_sha256 in set(seen_idempotency_sha256):
        raise CryptoPKISpecialistContractError("idempotency replay is forbidden")

    observation = adapter.assess(request)
    if not isinstance(observation, SpecialistAssessmentObservation):
        raise CryptoPKISpecialistContractError("adapter returned an invalid observation")
    if (
        observation.request_id != request.request_id
        or observation.request_sha256 != request.request_sha256
        or observation.assessment_context_sha256 != request.context.assessment_context_sha256
        or observation.evidence_set_sha256 != request.evidence_set_sha256
    ):
        raise CryptoPKISpecialistContractError("observation binding mismatch")
    valid_evidence_refs = {item.evidence_ref for item in request.evidence}
    if any(
        not set(finding.evidence_refs).issubset(valid_evidence_refs)
        for finding in observation.findings
    ):
        raise CryptoPKISpecialistContractError("finding cites evidence outside the request")
    if any(
        finding.category not in CHECK_FINDINGS[request.check] for finding in observation.findings
    ):
        raise CryptoPKISpecialistContractError("finding is outside the requested check")
    budget = request.context.budget
    actuals = (
        (observation.actual_evidence_items, request.estimated_evidence_items),
        (observation.actual_findings, request.estimated_findings),
        (observation.actual_observed_bytes, request.estimated_observed_bytes),
        (observation.actual_duration_seconds, request.estimated_duration_seconds),
        (observation.actual_evidence_items, budget.maximum_evidence_items),
        (observation.actual_findings, budget.maximum_findings),
        (observation.actual_observed_bytes, budget.maximum_observed_bytes),
        (observation.actual_duration_seconds, budget.maximum_duration_seconds),
    )
    if any(actual > maximum for actual, maximum in actuals):
        raise CryptoPKISpecialistContractError("adapter exceeded the bound budget")
    if observation.actual_evidence_items > len(request.evidence):
        raise CryptoPKISpecialistContractError("adapter reported unbound evidence items")
    if _instant(observation.completed_at) > now:
        raise CryptoPKISpecialistContractError("adapter observation is from the future")
    status = {
        AdapterDisposition.COMPLETED: ReceiptStatus.COMPLETED,
        AdapterDisposition.DENIED: ReceiptStatus.DENIED,
        AdapterDisposition.FAILED: ReceiptStatus.FAILED,
    }[observation.disposition]
    return SpecialistAssessmentReceipt(request=request, observation=observation, status=status)


def parse_contract(value: Mapping[str, Any]) -> dict[str, Any]:
    """Reconstruct a wire record and reject altered identities or content."""

    if not isinstance(value, Mapping):
        raise CryptoPKISpecialistContractError("contract must be an object")
    try:
        kind = value.get("kind")
        if kind == "crypto_pki_specialist_capability_declaration":
            expected = SpecialistCapabilityDeclaration(
                family=SpecialistFamily(value["family"]),
                capability_ref=value["capability_ref"],
                checks=tuple(AssessmentCheck(item) for item in value["checks"]),
            ).to_dict()
        elif kind == "crypto_pki_evidence_provenance":
            expected = _evidence_from_dict(value).to_dict()
        elif kind == "crypto_pki_specialist_assessment_request":
            expected = _request_from_dict(value).to_dict()
        elif kind == "crypto_pki_specialist_assessment_receipt":
            request = _request_from_dict(value["request"])
            observation = _observation_from_dict(value["observation"])
            expected = SpecialistAssessmentReceipt(
                request=request,
                observation=observation,
                status=ReceiptStatus(value["status"]),
            ).to_dict()
        else:
            raise CryptoPKISpecialistContractError("contract kind is unsupported")
    except CryptoPKISpecialistContractError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise CryptoPKISpecialistContractError("contract structure is invalid") from exc
    if canonical_json(dict(value)) != canonical_json(expected):
        raise CryptoPKISpecialistContractError("contract identity or content is invalid")
    return expected


def _context_from_dict(value: Mapping[str, Any]) -> SpecialistAssessmentContext:
    budget_value = value["budget"]
    budget = AssessmentBudget(
        budget_ref=budget_value["budget_ref"],
        maximum_evidence_items=budget_value["maximum_evidence_items"],
        maximum_findings=budget_value["maximum_findings"],
        maximum_observed_bytes=budget_value["maximum_observed_bytes"],
        maximum_duration_seconds=budget_value["maximum_duration_seconds"],
    )
    return SpecialistAssessmentContext(
        tenant_ref=value["tenant_ref"],
        context_ref=value["context_ref"],
        context_binding_sha256=value["context_binding_sha256"],
        scope_ref=value["scope_ref"],
        scope_sha256=value["scope_sha256"],
        authorization_ref=value["authorization_ref"],
        authorization_sha256=value["authorization_sha256"],
        action_admission_ref=value["action_admission_ref"],
        action_admission_sha256=value["action_admission_sha256"],
        evidence_plan_ref=value["evidence_plan_ref"],
        evidence_plan_sha256=value["evidence_plan_sha256"],
        cryptographic_policy_ref=value["cryptographic_policy_ref"],
        cryptographic_policy_sha256=value["cryptographic_policy_sha256"],
        trust_policy_ref=value["trust_policy_ref"],
        trust_policy_sha256=value["trust_policy_sha256"],
        authorized_at=value["authorized_at"],
        authorization_expires_at=value["authorization_expires_at"],
        repository_assessment_authorized=value["repository_assessment_authorized"],
        target_interaction_authorized=value["target_interaction_authorized"],
        budget=budget,
    )


def _evidence_from_dict(value: Mapping[str, Any]) -> EvidenceProvenance:
    return EvidenceProvenance(
        evidence_ref=value["evidence_ref"],
        evidence_kind=EvidenceKind(value["evidence_kind"]),
        content_sha256=value["content_sha256"],
        source_manifest_sha256=value["source_manifest_sha256"],
        collector_ref=value["collector_ref"],
        collected_at=value["collected_at"],
        observed_bytes=value["observed_bytes"],
        provenance_chain=tuple(value["provenance_chain"]),
        sanitized=value["sanitized"],
        contains_private_key=value["contains_private_key"],
        contains_secret_value=value["contains_secret_value"],
        contains_credential=value["contains_credential"],
        contains_live_target_capture=value["contains_live_target_capture"],
        includes_executable_material=value["includes_executable_material"],
    )


def _request_from_dict(value: Mapping[str, Any]) -> SpecialistAssessmentRequest:
    return SpecialistAssessmentRequest(
        declaration_id=value["declaration_id"],
        declaration_sha256=value["declaration_sha256"],
        family=SpecialistFamily(value["family"]),
        capability_ref=value["capability_ref"],
        check=AssessmentCheck(value["check"]),
        context=_context_from_dict(value["context"]),
        evidence=tuple(_evidence_from_dict(item) for item in value["evidence"]),
        expected_policy_sha256=value["expected_policy_sha256"],
        estimated_evidence_items=value["estimated_evidence_items"],
        estimated_findings=value["estimated_findings"],
        estimated_observed_bytes=value["estimated_observed_bytes"],
        estimated_duration_seconds=value["estimated_duration_seconds"],
        idempotency_sha256=value["idempotency_sha256"],
        issued_at=value["issued_at"],
        expires_at=value["expires_at"],
    )


def _finding_from_dict(value: Mapping[str, Any]) -> AssessmentFinding:
    return AssessmentFinding(
        category=FindingCategory(value["category"]),
        severity=FindingSeverity(value["severity"]),
        rule_ref=value["rule_ref"],
        evidence_refs=tuple(value["evidence_refs"]),
        remediation_ref=value["remediation_ref"],
        confidence_basis=ConfidenceBasis(value["confidence_basis"]),
    )


def _observation_from_dict(value: Mapping[str, Any]) -> SpecialistAssessmentObservation:
    return SpecialistAssessmentObservation(
        request_id=value["request_id"],
        request_sha256=value["request_sha256"],
        assessment_context_sha256=value["assessment_context_sha256"],
        evidence_set_sha256=value["evidence_set_sha256"],
        disposition=AdapterDisposition(value["disposition"]),
        outcome=AssessmentOutcome(value["outcome"]),
        findings=tuple(_finding_from_dict(item) for item in value["findings"]),
        analysis_evidence_sha256=value["analysis_evidence_sha256"],
        actual_evidence_items=value["actual_evidence_items"],
        actual_findings=value["actual_findings"],
        actual_observed_bytes=value["actual_observed_bytes"],
        actual_duration_seconds=value["actual_duration_seconds"],
        network_call_performed=value["network_call_performed"],
        scanner_execution_performed=value["scanner_execution_performed"],
        command_execution_performed=value["command_execution_performed"],
        key_generation_performed=value["key_generation_performed"],
        key_access_performed=value["key_access_performed"],
        secret_access_performed=value["secret_access_performed"],
        credential_handling_performed=value["credential_handling_performed"],
        target_interaction_performed=value["target_interaction_performed"],
        started_at=value["started_at"],
        completed_at=value["completed_at"],
    )

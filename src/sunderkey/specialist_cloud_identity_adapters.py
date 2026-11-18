"""Fail-closed specialist adapter contracts for cloud and identity surfaces.

This repository-only module defines provider-neutral requests, fixed provider
profiles, injected adapter observations, and content-addressed receipts for
roadmap packages C4.3 through C4.8. It has no cloud SDK, identity client,
credential resolver, network transport, or remote execution implementation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .types import ActionTier

SCHEMA_VERSION = 1
MAX_WINDOW_SECONDS = 86_400
MAX_OPERATIONS = 64
MAX_RESOURCES = 10_000
MAX_EVIDENCE_ITEMS = 256

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
UTC_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
REFERENCE_RE = re.compile(
    r"(?:tenantref|accountref|projectref|subscriptionref|clusterref|scoperef|"
    r"missionref|workerref|actionref|approvalref|sessionref|principalref|"
    r"evidenceref|adapterref|attestationref):"
    r"[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z"
)
IDEMPOTENCY_RE = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._/-]{7,190}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|"
    r"\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|authorization|cookie)\s*[\"']?\s*[:=]|"
    r"\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

REPOSITORY_ONLY_EFFECTS = MappingProxyType(
    {
        "authority_grant": "none",
        "credential_resolution": "none",
        "network_client": "not_included",
        "qualification": "none",
        "remote_execution": "injected_adapter_only",
        "provider_sdk": "not_included",
    }
)


class CloudIdentityAdapterError(ValueError):
    """Raised when a cloud or identity adapter contract fails closed."""


class ProviderKind(StrEnum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"
    ENTRA_ID = "entra_id"
    OKTA_FEDERATION = "okta_federation"
    SAAS_TENANCY = "saas_tenancy"
    SERVERLESS_CONTAINER = "serverless_container"


class CapabilityFamily(StrEnum):
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_CONTROL_PLANE = "cloud_control_plane"
    WORKLOAD_IDENTITY = "workload_identity"
    CLOUD_IAM = "cloud_iam"
    CONTAINER_ORCHESTRATION = "container_orchestration"
    DATA_PLATFORM = "data_platform"


class MutationClass(StrEnum):
    READ_ONLY = "read_only"
    VALIDATION = "validation"
    REVERSIBLE_MUTATION = "reversible_mutation"


class SpecialistOperation(StrEnum):
    INVENTORY_READ = "inventory_read"
    IDENTITY_POLICY_READ = "identity_policy_read"
    FEDERATION_TRUST_READ = "federation_trust_read"
    KUBERNETES_RBAC_READ = "kubernetes_rbac_read"
    WORKLOAD_BINDING_READ = "workload_binding_read"
    DATA_ACCESS_METADATA_READ = "data_access_metadata_read"
    ROLE_SESSION_VALIDATE = "role_session_validate"
    FEDERATION_EXCHANGE_VALIDATE = "federation_exchange_validate"
    WORKLOAD_IDENTITY_VALIDATE = "workload_identity_validate"
    RESOURCE_ACCESS_SAFE_PROOF = "resource_access_safe_proof"
    TEMPORARY_ROLE_BINDING = "temporary_role_binding"
    EPHEMERAL_WORKLOAD_IDENTITY = "ephemeral_workload_identity"
    REVERSIBLE_CONFIGURATION_PROBE = "reversible_configuration_probe"


class ResultState(StrEnum):
    COMPLETED = "completed"
    BLOCKED = "blocked"
    STOPPED = "stopped"


@dataclass(frozen=True, slots=True)
class OperationPolicy:
    family: CapabilityFamily
    package_id: str
    mutation_class: MutationClass
    minimum_tier: ActionTier

    def to_dict(self) -> dict[str, str]:
        return {
            "family": self.family.value,
            "package_id": self.package_id,
            "mutation_class": self.mutation_class.value,
            "minimum_tier": self.minimum_tier.value,
        }


OPERATION_POLICIES = MappingProxyType(
    {
        SpecialistOperation.INVENTORY_READ: OperationPolicy(
            CapabilityFamily.CLOUD_CONTROL_PLANE, "C4.4", MutationClass.READ_ONLY, ActionTier.R1
        ),
        SpecialistOperation.IDENTITY_POLICY_READ: OperationPolicy(
            CapabilityFamily.IDENTITY_PROVIDER, "C4.3", MutationClass.READ_ONLY, ActionTier.R1
        ),
        SpecialistOperation.FEDERATION_TRUST_READ: OperationPolicy(
            CapabilityFamily.IDENTITY_PROVIDER, "C4.3", MutationClass.READ_ONLY, ActionTier.R1
        ),
        SpecialistOperation.KUBERNETES_RBAC_READ: OperationPolicy(
            CapabilityFamily.CONTAINER_ORCHESTRATION,
            "C4.7",
            MutationClass.READ_ONLY,
            ActionTier.R1,
        ),
        SpecialistOperation.WORKLOAD_BINDING_READ: OperationPolicy(
            CapabilityFamily.WORKLOAD_IDENTITY, "C4.5", MutationClass.READ_ONLY, ActionTier.R1
        ),
        SpecialistOperation.DATA_ACCESS_METADATA_READ: OperationPolicy(
            CapabilityFamily.DATA_PLATFORM, "C4.8", MutationClass.READ_ONLY, ActionTier.R1
        ),
        SpecialistOperation.ROLE_SESSION_VALIDATE: OperationPolicy(
            CapabilityFamily.CLOUD_IAM, "C4.6", MutationClass.VALIDATION, ActionTier.R2
        ),
        SpecialistOperation.FEDERATION_EXCHANGE_VALIDATE: OperationPolicy(
            CapabilityFamily.IDENTITY_PROVIDER, "C4.3", MutationClass.VALIDATION, ActionTier.R2
        ),
        SpecialistOperation.WORKLOAD_IDENTITY_VALIDATE: OperationPolicy(
            CapabilityFamily.WORKLOAD_IDENTITY, "C4.5", MutationClass.VALIDATION, ActionTier.R2
        ),
        SpecialistOperation.RESOURCE_ACCESS_SAFE_PROOF: OperationPolicy(
            CapabilityFamily.DATA_PLATFORM, "C4.8", MutationClass.VALIDATION, ActionTier.R2
        ),
        SpecialistOperation.TEMPORARY_ROLE_BINDING: OperationPolicy(
            CapabilityFamily.CLOUD_IAM,
            "C4.6",
            MutationClass.REVERSIBLE_MUTATION,
            ActionTier.R3,
        ),
        SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY: OperationPolicy(
            CapabilityFamily.WORKLOAD_IDENTITY,
            "C4.5",
            MutationClass.REVERSIBLE_MUTATION,
            ActionTier.R3,
        ),
        SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE: OperationPolicy(
            CapabilityFamily.CLOUD_CONTROL_PLANE,
            "C4.4",
            MutationClass.REVERSIBLE_MUTATION,
            ActionTier.R3,
        ),
    }
)


def canonical_json(value: Any) -> str:
    _validate_json(value, "value")
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    if SECRET_RE.search(encoded):
        raise CloudIdentityAdapterError("secret material is forbidden")
    return encoded


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": dict(body), "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _validate_json(value: Any, label: str, *, depth: int = 0) -> None:
    if depth > 12:
        raise CloudIdentityAdapterError(f"{label} exceeds nesting limit")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json(item, f"{label}[{index}]", depth=depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CloudIdentityAdapterError(f"{label} has a non-string key")
            _validate_json(item, f"{label}.{key}", depth=depth + 1)
        return
    raise CloudIdentityAdapterError(f"{label} has unsupported content")


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise CloudIdentityAdapterError(f"{label} must be a SHA-256 digest")
    return value


def _reference(value: Any, label: str, namespace: str) -> str:
    if not isinstance(value, str) or REFERENCE_RE.fullmatch(value) is None:
        raise CloudIdentityAdapterError(f"{label} must be an opaque reference")
    if not value.startswith(namespace + ":"):
        raise CloudIdentityAdapterError(f"{label} must use the {namespace} namespace")
    if SECRET_RE.search(value):
        raise CloudIdentityAdapterError(f"{label} contains secret material")
    return value


def _references(
    values: Sequence[str], label: str, namespace: str, maximum: int = 64
) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise CloudIdentityAdapterError(f"{label} must be a sequence")
    result = tuple(_reference(item, f"{label} item", namespace) for item in values)
    if len(result) > maximum or len(result) != len(set(result)):
        raise CloudIdentityAdapterError(f"{label} count or uniqueness is invalid")
    return tuple(sorted(result))


def _digests(values: Sequence[str], label: str, maximum: int = 256) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise CloudIdentityAdapterError(f"{label} must be a sequence")
    result = tuple(_digest(item, f"{label} item") for item in values)
    if not 1 <= len(result) <= maximum or len(result) != len(set(result)):
        raise CloudIdentityAdapterError(f"{label} count or uniqueness is invalid")
    return tuple(sorted(result))


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise CloudIdentityAdapterError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise CloudIdentityAdapterError(f"{label} must be valid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _window(issued_at: str, expires_at: str, label: str) -> None:
    seconds = (
        _instant(_timestamp(expires_at, f"{label} expires_at"))
        - _instant(_timestamp(issued_at, f"{label} issued_at"))
    ).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS:
        raise CloudIdentityAdapterError(f"{label} window is invalid")


def _at(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CloudIdentityAdapterError("evaluated_at must be timezone aware")
    return value.astimezone(UTC).replace(microsecond=0)


def _bounded(value: Any, label: str, *, minimum: int = 0, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise CloudIdentityAdapterError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    provider: ProviderKind
    profile_id: str
    supported_operations: tuple[SpecialistOperation, ...]
    required_scope_dimensions: tuple[str, ...]
    dry_run_operations: tuple[SpecialistOperation, ...]

    def __post_init__(self) -> None:
        if not self.profile_id.startswith("profile:"):
            raise CloudIdentityAdapterError("profile_id is invalid")
        if not self.supported_operations or len(set(self.supported_operations)) != len(
            self.supported_operations
        ):
            raise CloudIdentityAdapterError("supported_operations are invalid")
        allowed = {"account", "project", "subscription", "cluster"}
        if not set(self.required_scope_dimensions) <= allowed:
            raise CloudIdentityAdapterError("required_scope_dimensions are invalid")
        if not set(self.dry_run_operations) <= set(self.supported_operations):
            raise CloudIdentityAdapterError("dry_run_operations exceed profile support")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider.value,
            "profile_id": self.profile_id,
            "supported_operations": sorted(item.value for item in self.supported_operations),
            "required_scope_dimensions": sorted(self.required_scope_dimensions),
            "dry_run_operations": sorted(item.value for item in self.dry_run_operations),
            "repository_only": True,
            "qualification_status": "not_qualified",
        }


READS = (
    SpecialistOperation.INVENTORY_READ,
    SpecialistOperation.IDENTITY_POLICY_READ,
    SpecialistOperation.FEDERATION_TRUST_READ,
    SpecialistOperation.WORKLOAD_BINDING_READ,
    SpecialistOperation.DATA_ACCESS_METADATA_READ,
)
VALIDATIONS = (
    SpecialistOperation.ROLE_SESSION_VALIDATE,
    SpecialistOperation.FEDERATION_EXCHANGE_VALIDATE,
    SpecialistOperation.WORKLOAD_IDENTITY_VALIDATE,
    SpecialistOperation.RESOURCE_ACCESS_SAFE_PROOF,
)
MUTATIONS = (
    SpecialistOperation.TEMPORARY_ROLE_BINDING,
    SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY,
    SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE,
)

PROVIDER_PROFILES = MappingProxyType(
    {
        ProviderKind.AWS: ProviderProfile(
            ProviderKind.AWS,
            "profile:aws-control-plane-v1",
            READS + VALIDATIONS + MUTATIONS,
            ("account",),
            MUTATIONS,
        ),
        ProviderKind.AZURE: ProviderProfile(
            ProviderKind.AZURE,
            "profile:azure-control-plane-v1",
            READS + VALIDATIONS + MUTATIONS,
            ("subscription",),
            MUTATIONS,
        ),
        ProviderKind.GCP: ProviderProfile(
            ProviderKind.GCP,
            "profile:gcp-control-plane-v1",
            READS + VALIDATIONS + MUTATIONS,
            ("project",),
            MUTATIONS,
        ),
        ProviderKind.KUBERNETES: ProviderProfile(
            ProviderKind.KUBERNETES,
            "profile:kubernetes-control-plane-v1",
            (
                SpecialistOperation.KUBERNETES_RBAC_READ,
                SpecialistOperation.WORKLOAD_BINDING_READ,
                SpecialistOperation.WORKLOAD_IDENTITY_VALIDATE,
                SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY,
                SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE,
            ),
            ("cluster",),
            (
                SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY,
                SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE,
            ),
        ),
        ProviderKind.ENTRA_ID: ProviderProfile(
            ProviderKind.ENTRA_ID,
            "profile:entra-id-v1",
            (
                SpecialistOperation.IDENTITY_POLICY_READ,
                SpecialistOperation.FEDERATION_TRUST_READ,
                SpecialistOperation.ROLE_SESSION_VALIDATE,
                SpecialistOperation.FEDERATION_EXCHANGE_VALIDATE,
                SpecialistOperation.TEMPORARY_ROLE_BINDING,
            ),
            (),
            (SpecialistOperation.TEMPORARY_ROLE_BINDING,),
        ),
        ProviderKind.OKTA_FEDERATION: ProviderProfile(
            ProviderKind.OKTA_FEDERATION,
            "profile:okta-style-federation-v1",
            (
                SpecialistOperation.IDENTITY_POLICY_READ,
                SpecialistOperation.FEDERATION_TRUST_READ,
                SpecialistOperation.FEDERATION_EXCHANGE_VALIDATE,
                SpecialistOperation.TEMPORARY_ROLE_BINDING,
            ),
            (),
            (SpecialistOperation.TEMPORARY_ROLE_BINDING,),
        ),
        ProviderKind.SAAS_TENANCY: ProviderProfile(
            ProviderKind.SAAS_TENANCY,
            "profile:saas-tenancy-v1",
            (
                SpecialistOperation.INVENTORY_READ,
                SpecialistOperation.IDENTITY_POLICY_READ,
                SpecialistOperation.DATA_ACCESS_METADATA_READ,
                SpecialistOperation.ROLE_SESSION_VALIDATE,
                SpecialistOperation.RESOURCE_ACCESS_SAFE_PROOF,
            ),
            (),
            (),
        ),
        ProviderKind.SERVERLESS_CONTAINER: ProviderProfile(
            ProviderKind.SERVERLESS_CONTAINER,
            "profile:serverless-container-v1",
            (
                SpecialistOperation.INVENTORY_READ,
                SpecialistOperation.WORKLOAD_BINDING_READ,
                SpecialistOperation.WORKLOAD_IDENTITY_VALIDATE,
                SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY,
                SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE,
            ),
            (),
            (
                SpecialistOperation.EPHEMERAL_WORKLOAD_IDENTITY,
                SpecialistOperation.REVERSIBLE_CONFIGURATION_PROBE,
            ),
        ),
    }
)


def provider_profile_declarations() -> tuple[ProviderProfile, ...]:
    """Return fixed repository-only provider profiles in provider order."""

    return tuple(PROVIDER_PROFILES[item] for item in ProviderKind)


@dataclass(frozen=True, slots=True)
class CapabilityDeclaration:
    package_id: str
    family: CapabilityFamily
    operations: tuple[SpecialistOperation, ...]
    repository_only: bool = True
    qualification_status: str = "not_qualified"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "family": self.family.value,
            "operations": sorted(item.value for item in self.operations),
            "repository_only": self.repository_only,
            "qualification_status": self.qualification_status,
        }


def capability_declarations() -> tuple[CapabilityDeclaration, ...]:
    result = []
    for family in CapabilityFamily:
        policies = [
            operation for operation, policy in OPERATION_POLICIES.items() if policy.family is family
        ]
        package_ids = {OPERATION_POLICIES[item].package_id for item in policies}
        if len(package_ids) != 1:
            raise CloudIdentityAdapterError("capability policy has inconsistent package binding")
        result.append(CapabilityDeclaration(package_ids.pop(), family, tuple(policies)))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class ScopeBinding:
    tenant_ref: str
    scope_ref: str
    account_refs: tuple[str, ...] = ()
    project_refs: tuple[str, ...] = ()
    subscription_refs: tuple[str, ...] = ()
    cluster_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_ref", _reference(self.tenant_ref, "tenant_ref", "tenantref")
        )
        object.__setattr__(self, "scope_ref", _reference(self.scope_ref, "scope_ref", "scoperef"))
        for field, namespace in (
            ("account_refs", "accountref"),
            ("project_refs", "projectref"),
            ("subscription_refs", "subscriptionref"),
            ("cluster_refs", "clusterref"),
        ):
            object.__setattr__(self, field, _references(getattr(self, field), field, namespace, 32))

    @property
    def binding_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_ref": self.tenant_ref,
            "scope_ref": self.scope_ref,
            "account_refs": list(self.account_refs),
            "project_refs": list(self.project_refs),
            "subscription_refs": list(self.subscription_refs),
            "cluster_refs": list(self.cluster_refs),
        }


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    mission_ref: str
    worker_ref: str
    action_ref: str
    action_admission_sha256: str
    scope: ScopeBinding

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "mission_ref", _reference(self.mission_ref, "mission_ref", "missionref")
        )
        object.__setattr__(
            self, "worker_ref", _reference(self.worker_ref, "worker_ref", "workerref")
        )
        object.__setattr__(
            self, "action_ref", _reference(self.action_ref, "action_ref", "actionref")
        )
        object.__setattr__(
            self,
            "action_admission_sha256",
            _digest(self.action_admission_sha256, "action_admission_sha256"),
        )
        if not isinstance(self.scope, ScopeBinding):
            raise CloudIdentityAdapterError("scope must be a ScopeBinding")

    @property
    def context_sha256(self) -> str:
        return canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_ref": self.mission_ref,
            "worker_ref": self.worker_ref,
            "action_ref": self.action_ref,
            "action_admission_sha256": self.action_admission_sha256,
            "scope": self.scope.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    approval_ref: str
    approval_sha256: str
    context_sha256: str
    provider: ProviderKind
    operation: SpecialistOperation
    maximum_tier: ActionTier
    allow_mutation: bool
    require_dry_run: bool
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "approval_ref", _reference(self.approval_ref, "approval_ref", "approvalref")
        )
        object.__setattr__(
            self, "approval_sha256", _digest(self.approval_sha256, "approval_sha256")
        )
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        if not isinstance(self.provider, ProviderKind) or not isinstance(
            self.operation, SpecialistOperation
        ):
            raise CloudIdentityAdapterError("approval provider or operation is invalid")
        if not isinstance(self.maximum_tier, ActionTier):
            raise CloudIdentityAdapterError("approval maximum_tier is invalid")
        if not isinstance(self.allow_mutation, bool) or not isinstance(self.require_dry_run, bool):
            raise CloudIdentityAdapterError("approval flags must be boolean")
        _window(self.issued_at, self.expires_at, "approval")

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_ref": self.approval_ref,
            "approval_sha256": self.approval_sha256,
            "context_sha256": self.context_sha256,
            "provider": self.provider.value,
            "operation": self.operation.value,
            "maximum_tier": self.maximum_tier.value,
            "allow_mutation": self.allow_mutation,
            "require_dry_run": self.require_dry_run,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class SessionBinding:
    session_ref: str
    principal_ref: str
    session_sha256: str
    context_sha256: str
    provider: ProviderKind
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "session_ref", _reference(self.session_ref, "session_ref", "sessionref")
        )
        object.__setattr__(
            self, "principal_ref", _reference(self.principal_ref, "principal_ref", "principalref")
        )
        object.__setattr__(self, "session_sha256", _digest(self.session_sha256, "session_sha256"))
        object.__setattr__(self, "context_sha256", _digest(self.context_sha256, "context_sha256"))
        if not isinstance(self.provider, ProviderKind):
            raise CloudIdentityAdapterError("session provider is invalid")
        _window(self.issued_at, self.expires_at, "session")

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_ref": self.session_ref,
            "principal_ref": self.principal_ref,
            "session_sha256": self.session_sha256,
            "context_sha256": self.context_sha256,
            "provider": self.provider.value,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True, slots=True)
class ExecutionBudget:
    max_operations: int
    max_resources: int
    max_mutations: int
    max_evidence_items: int

    def __post_init__(self) -> None:
        _bounded(self.max_operations, "max_operations", minimum=1, maximum=MAX_OPERATIONS)
        _bounded(self.max_resources, "max_resources", minimum=1, maximum=MAX_RESOURCES)
        _bounded(self.max_mutations, "max_mutations", maximum=16)
        _bounded(
            self.max_evidence_items, "max_evidence_items", minimum=1, maximum=MAX_EVIDENCE_ITEMS
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "max_operations": self.max_operations,
            "max_resources": self.max_resources,
            "max_mutations": self.max_mutations,
            "max_evidence_items": self.max_evidence_items,
        }


@dataclass(frozen=True, slots=True)
class SpecialistActionRequest:
    context: ExecutionContext
    provider: ProviderKind
    operation: SpecialistOperation
    requested_tier: ActionTier
    approval: ApprovalBinding
    session: SessionBinding
    evidence_refs: tuple[str, ...]
    evidence_sha256: tuple[str, ...]
    idempotency_key: str
    dry_run: bool
    budget: ExecutionBudget
    issued_at: str
    expires_at: str
    request_id: str = ""
    request_sha256: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.context, ExecutionContext) or not isinstance(
            self.provider, ProviderKind
        ):
            raise CloudIdentityAdapterError("request context or provider is invalid")
        if not isinstance(self.operation, SpecialistOperation) or not isinstance(
            self.requested_tier, ActionTier
        ):
            raise CloudIdentityAdapterError("request operation or tier is invalid")
        profile = PROVIDER_PROFILES[self.provider]
        if self.operation not in profile.supported_operations:
            raise CloudIdentityAdapterError("provider profile does not support operation")
        policy = OPERATION_POLICIES[self.operation]
        if self.requested_tier.rank < policy.minimum_tier.rank:
            raise CloudIdentityAdapterError("requested tier is below the operation minimum")
        self._validate_scope(profile)
        if not isinstance(self.approval, ApprovalBinding) or not isinstance(
            self.session, SessionBinding
        ):
            raise CloudIdentityAdapterError("approval and session bindings are required")
        if self.approval.context_sha256 != self.context.context_sha256:
            raise CloudIdentityAdapterError("approval context does not match request")
        if (
            self.approval.provider is not self.provider
            or self.approval.operation is not self.operation
        ):
            raise CloudIdentityAdapterError("approval provider or operation does not match request")
        if not self.approval.maximum_tier.allows(self.requested_tier):
            raise CloudIdentityAdapterError("approval tier does not allow request")
        if (
            self.session.context_sha256 != self.context.context_sha256
            or self.session.provider is not self.provider
        ):
            raise CloudIdentityAdapterError("session context or provider does not match request")
        if policy.mutation_class is MutationClass.REVERSIBLE_MUTATION:
            if not self.approval.allow_mutation:
                raise CloudIdentityAdapterError("R3 mutation requires explicit mutation approval")
            if self.approval.require_dry_run and not self.dry_run:
                raise CloudIdentityAdapterError("approval requires dry-run execution")
            if self.dry_run and self.operation not in profile.dry_run_operations:
                raise CloudIdentityAdapterError(
                    "provider profile does not support dry-run operation"
                )
            if self.budget.max_mutations < 1:
                raise CloudIdentityAdapterError("mutation budget must permit one mutation")
        elif self.budget.max_mutations != 0:
            raise CloudIdentityAdapterError(
                "read and validation requests require zero mutation budget"
            )
        if not isinstance(self.dry_run, bool):
            raise CloudIdentityAdapterError("dry_run must be boolean")
        refs = _references(self.evidence_refs, "evidence_refs", "evidenceref", MAX_EVIDENCE_ITEMS)
        digests = _digests(self.evidence_sha256, "evidence_sha256")
        if not refs or len(refs) != len(digests):
            raise CloudIdentityAdapterError("evidence references and digests must align")
        object.__setattr__(self, "evidence_refs", refs)
        object.__setattr__(self, "evidence_sha256", digests)
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise CloudIdentityAdapterError("idempotency_key is invalid")
        if not isinstance(self.budget, ExecutionBudget):
            raise CloudIdentityAdapterError("budget is invalid")
        _window(self.issued_at, self.expires_at, "request")
        body = self._body()
        expected_id, expected_sha = _identity("CIR", "cloud-identity-request.v1", body)
        if self.request_id and self.request_id != expected_id:
            raise CloudIdentityAdapterError("request_id integrity check failed")
        if self.request_sha256 and self.request_sha256 != expected_sha:
            raise CloudIdentityAdapterError("request_sha256 integrity check failed")
        object.__setattr__(self, "request_id", expected_id)
        object.__setattr__(self, "request_sha256", expected_sha)

    def _validate_scope(self, profile: ProviderProfile) -> None:
        dimensions = {
            "account": self.context.scope.account_refs,
            "project": self.context.scope.project_refs,
            "subscription": self.context.scope.subscription_refs,
            "cluster": self.context.scope.cluster_refs,
        }
        missing = [item for item in profile.required_scope_dimensions if not dimensions[item]]
        if missing:
            raise CloudIdentityAdapterError("provider profile required scope dimension is missing")

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "cloud_identity_action_request",
            "effects": dict(REPOSITORY_ONLY_EFFECTS),
            "context": self.context.to_dict(),
            "provider": self.provider.value,
            "profile": PROVIDER_PROFILES[self.provider].to_dict(),
            "operation": self.operation.value,
            "policy": OPERATION_POLICIES[self.operation].to_dict(),
            "requested_tier": self.requested_tier.value,
            "approval": self.approval.to_dict(),
            "session": self.session.to_dict(),
            "evidence_refs": list(self.evidence_refs),
            "evidence_sha256": list(self.evidence_sha256),
            "idempotency_key": self.idempotency_key,
            "dry_run": self.dry_run,
            "budget": self.budget.to_dict(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            **self._body(),
        }


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    adapter_ref: str
    version: str
    provider: ProviderKind
    supported_operations: tuple[SpecialistOperation, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "adapter_ref", _reference(self.adapter_ref, "adapter_ref", "adapterref")
        )
        if not isinstance(self.version, str) or VERSION_RE.fullmatch(self.version) is None:
            raise CloudIdentityAdapterError("adapter version is invalid")
        if not isinstance(self.provider, ProviderKind):
            raise CloudIdentityAdapterError("adapter provider is invalid")
        if not self.supported_operations or len(set(self.supported_operations)) != len(
            self.supported_operations
        ):
            raise CloudIdentityAdapterError("adapter supported_operations are invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter_ref": self.adapter_ref,
            "version": self.version,
            "provider": self.provider.value,
            "supported_operations": sorted(item.value for item in self.supported_operations),
        }


@dataclass(frozen=True, slots=True)
class AdapterObservation:
    request_id: str
    request_sha256: str
    context_sha256: str
    scope_binding_sha256: str
    approval_sha256: str
    session_sha256: str
    idempotency_key: str
    state: ResultState
    operations_performed: int
    resources_observed: int
    mutations_performed: int
    evidence_refs: tuple[str, ...]
    evidence_sha256: tuple[str, ...]
    result_attestation_ref: str
    result_attestation_sha256: str
    restoration_evidence_refs: tuple[str, ...]
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.state, ResultState):
            raise CloudIdentityAdapterError("observation state is invalid")
        for field in (
            "request_sha256",
            "context_sha256",
            "scope_binding_sha256",
            "approval_sha256",
            "session_sha256",
            "result_attestation_sha256",
        ):
            object.__setattr__(self, field, _digest(getattr(self, field), field))
        if not self.request_id.startswith("CIR-"):
            raise CloudIdentityAdapterError("observation request_id is invalid")
        if (
            not isinstance(self.idempotency_key, str)
            or IDEMPOTENCY_RE.fullmatch(self.idempotency_key) is None
        ):
            raise CloudIdentityAdapterError("observation idempotency_key is invalid")
        _bounded(self.operations_performed, "operations_performed", maximum=MAX_OPERATIONS)
        _bounded(self.resources_observed, "resources_observed", maximum=MAX_RESOURCES)
        _bounded(self.mutations_performed, "mutations_performed", maximum=16)
        object.__setattr__(
            self,
            "evidence_refs",
            _references(self.evidence_refs, "evidence_refs", "evidenceref", MAX_EVIDENCE_ITEMS),
        )
        object.__setattr__(
            self, "evidence_sha256", _digests(self.evidence_sha256, "evidence_sha256")
        )
        object.__setattr__(
            self,
            "result_attestation_ref",
            _reference(self.result_attestation_ref, "result_attestation_ref", "attestationref"),
        )
        object.__setattr__(
            self,
            "restoration_evidence_refs",
            _references(
                self.restoration_evidence_refs, "restoration_evidence_refs", "evidenceref", 32
            ),
        )
        _timestamp(self.observed_at, "observed_at")


@runtime_checkable
class CloudIdentityExecutionAdapter(Protocol):
    identity: AdapterIdentity

    def execute(self, request: SpecialistActionRequest) -> AdapterObservation:
        """Execute one already admitted request and return a bound observation."""


class SpecialistReplayGuard:
    """Process-local fail-closed replay guard for repository tests."""

    def __init__(self) -> None:
        self._reserved: set[str] = set()

    def reserve(self, idempotency_key: str) -> None:
        if idempotency_key in self._reserved:
            raise CloudIdentityAdapterError("idempotency key has already been used")
        self._reserved.add(idempotency_key)


@dataclass(frozen=True, slots=True)
class SpecialistActionReceipt:
    request_id: str
    request_sha256: str
    context_sha256: str
    scope_binding_sha256: str
    provider: ProviderKind
    operation: SpecialistOperation
    mutation_class: MutationClass
    adapter: AdapterIdentity
    state: ResultState
    operations_performed: int
    resources_observed: int
    mutations_performed: int
    evidence_refs: tuple[str, ...]
    evidence_sha256: tuple[str, ...]
    result_attestation_ref: str
    result_attestation_sha256: str
    restoration_evidence_refs: tuple[str, ...]
    observed_at: str
    receipt_id: str = ""
    receipt_sha256: str = ""

    def __post_init__(self) -> None:
        body = self._body()
        expected_id, expected_sha = _identity("CIO", "cloud-identity-receipt.v1", body)
        if self.receipt_id and self.receipt_id != expected_id:
            raise CloudIdentityAdapterError("receipt_id integrity check failed")
        if self.receipt_sha256 and self.receipt_sha256 != expected_sha:
            raise CloudIdentityAdapterError("receipt_sha256 integrity check failed")
        object.__setattr__(self, "receipt_id", expected_id)
        object.__setattr__(self, "receipt_sha256", expected_sha)

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "cloud_identity_action_receipt",
            "effects": dict(REPOSITORY_ONLY_EFFECTS),
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "context_sha256": self.context_sha256,
            "scope_binding_sha256": self.scope_binding_sha256,
            "provider": self.provider.value,
            "operation": self.operation.value,
            "mutation_class": self.mutation_class.value,
            "adapter": self.adapter.to_dict(),
            "state": self.state.value,
            "operations_performed": self.operations_performed,
            "resources_observed": self.resources_observed,
            "mutations_performed": self.mutations_performed,
            "evidence_refs": list(self.evidence_refs),
            "evidence_sha256": list(self.evidence_sha256),
            "result_attestation_ref": self.result_attestation_ref,
            "result_attestation_sha256": self.result_attestation_sha256,
            "restoration_evidence_refs": list(self.restoration_evidence_refs),
            "observed_at": self.observed_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            **self._body(),
        }


def execute_specialist_action(
    request: SpecialistActionRequest,
    *,
    expected_context: ExecutionContext,
    adapter: CloudIdentityExecutionAdapter,
    replay_guard: SpecialistReplayGuard,
    evaluated_at: datetime,
) -> SpecialistActionReceipt:
    """Validate, reserve, call one injected adapter, and attest its observation."""

    if request.context.context_sha256 != expected_context.context_sha256:
        raise CloudIdentityAdapterError("request context does not match expected context")
    now = _at(evaluated_at)
    for binding, label in (
        (request, "request"),
        (request.approval, "approval"),
        (request.session, "session"),
    ):
        if not _instant(binding.issued_at) <= now <= _instant(binding.expires_at):
            raise CloudIdentityAdapterError(f"{label} is not current")
    if not isinstance(adapter, CloudIdentityExecutionAdapter):
        raise CloudIdentityAdapterError("adapter does not implement the execution protocol")
    identity = adapter.identity
    if (
        identity.provider is not request.provider
        or request.operation not in identity.supported_operations
    ):
        raise CloudIdentityAdapterError("adapter identity does not support request")
    replay_guard.reserve(request.idempotency_key)
    observation = adapter.execute(request)
    expected = {
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "context_sha256": request.context.context_sha256,
        "scope_binding_sha256": request.context.scope.binding_sha256,
        "approval_sha256": request.approval.approval_sha256,
        "session_sha256": request.session.session_sha256,
        "idempotency_key": request.idempotency_key,
    }
    for field, value in expected.items():
        if getattr(observation, field) != value:
            raise CloudIdentityAdapterError(f"observation {field} does not match request")
    if observation.operations_performed > request.budget.max_operations:
        raise CloudIdentityAdapterError("observation exceeds operation budget")
    if observation.resources_observed > request.budget.max_resources:
        raise CloudIdentityAdapterError("observation exceeds resource budget")
    if observation.mutations_performed > request.budget.max_mutations:
        raise CloudIdentityAdapterError("observation exceeds mutation budget")
    if len(observation.evidence_refs) > request.budget.max_evidence_items:
        raise CloudIdentityAdapterError("observation exceeds evidence budget")
    if not set(request.evidence_refs) <= set(observation.evidence_refs):
        raise CloudIdentityAdapterError("observation omitted required evidence")
    policy = OPERATION_POLICIES[request.operation]
    if policy.mutation_class is MutationClass.REVERSIBLE_MUTATION:
        if observation.mutations_performed and not observation.restoration_evidence_refs:
            raise CloudIdentityAdapterError("mutation result requires restoration evidence")
    elif observation.mutations_performed:
        raise CloudIdentityAdapterError("non-mutation operation reported a mutation")
    if _instant(observation.observed_at) > now:
        raise CloudIdentityAdapterError("observation is from the future")
    return SpecialistActionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        context_sha256=request.context.context_sha256,
        scope_binding_sha256=request.context.scope.binding_sha256,
        provider=request.provider,
        operation=request.operation,
        mutation_class=policy.mutation_class,
        adapter=identity,
        state=observation.state,
        operations_performed=observation.operations_performed,
        resources_observed=observation.resources_observed,
        mutations_performed=observation.mutations_performed,
        evidence_refs=observation.evidence_refs,
        evidence_sha256=observation.evidence_sha256,
        result_attestation_ref=observation.result_attestation_ref,
        result_attestation_sha256=observation.result_attestation_sha256,
        restoration_evidence_refs=observation.restoration_evidence_refs,
        observed_at=observation.observed_at,
    )

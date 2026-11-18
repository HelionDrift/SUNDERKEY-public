"""Pure GCP acceptance planning composed from existing offline prerequisites."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .assessment_transport_contracts import BrowserAction
from .authorized_browser_runtime import AuthorizedBrowserPolicy
from .candidate_adapter_runner import ContainmentBackendAttestation
from .candidate_backend_conformance import (
    ContainmentConformanceSuiteCatalog,
    build_containment_conformance_suite_catalog,
)
from .candidate_backend_host_preflight import (
    CLASS_REQUIREMENTS,
    COMMON_REQUIREMENTS,
    ContainmentBackendDeploymentBinding,
)
from .deployment_manifests import EXTERNAL_EVIDENCE, DeploymentManifest
from .deployment_profile_contracts import (
    Capability,
    CredentialConstraints,
    CredentialDeliveryMode,
    DeploymentKind,
    DeploymentProfile,
    EgressMode,
    EvidenceCustodyPolicy,
    IngressMode,
    StopCleanupPolicy,
    TrustRootPin,
    UpdateChannel,
    VersionPin,
)
from .enterprise_identity_contracts import SsoTrustPolicy
from .execution_control_runtime import ExecutionBinding
from .gcp_resource_bindings import (
    PRIMARY_REGION,
    GcpResourceBindingPlan,
    verify_gcp_resource_binding_plan,
)
from .health_state_contracts import HealthContext, ProbeDefinition, ProbeKind
from .persistence_port_contracts import (
    BackendKind,
    BackendCapabilityDeclaration,
    DeploymentClass,
    IsolationLevel,
    postgresql_production_capabilities,
)
from .production_deployment_decision_dossier import ProductionDeploymentDecisionDossier
from .regional_custody_contracts import TenantRegionBinding

DOMAIN = "sunderkey.gcp-acceptance-checklist.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_HEALTH_DEFINITIONS = 64
SERVICES = ("oci_container", "microvm", "browser", "postgresql", "identity", "health")
QUEUE_ORDER = ("WQ-016", "WQ-017", "WQ-018", "WQ-019")
_QUEUE_EVIDENCE = (
    "source_bound_read_only_host_preflight_reports",
    "signed_complete_oci_and_microvm_dynamic_conformance",
    "signed_execution_evidence_for_six_reference_candidates",
    "distinct_domain_commander_control_and_assurance_qualification_decisions",
)
HOST_FIELDS = (
    "project_id",
    "instance_name",
    "zone",
    "machine_type",
    "os_image",
    "os_image_sha256",
    "architecture",
    "host_id",
    "service_identity_id",
    "service_account_ref",
    "kernel_image_sha256",
    "rootfs_image_sha256",
)
_EFFECTS = dict.fromkeys(
    (
        "authorization",
        "credential_access",
        "deployment",
        "network",
        "qualification",
        "runtime_execution",
        "signature_generation",
        "storage_mutation",
        "target_action",
    ),
    "none",
)
_SOURCE_NAMES = {
    "resource_plan",
    "deployment_manifest",
    "containment_catalog",
    "postgresql",
    "browser",
    "identity",
    "health",
    "containment_bindings",
}
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_POSITIVE = {
    "browser": (
        "scope_admission_and_policy_binding",
        "pinned_driver_attestation",
        "same_origin_navigation",
        "opaque_credential_reference",
        "bounded_action_output",
        "content_addressed_browser_evidence",
    ),
    "postgresql": (
        "atomic_transaction_and_outbox",
        "isolation_and_fencing",
        "idempotency_and_tenant_isolation",
        *EXTERNAL_EVIDENCE,
    ),
    "identity": (
        "authenticated_pinned_rs256_keyset",
        "issuer_audience_tenant_binding",
        "mfa_assurance_and_time_binding",
        "nonce_and_replay_binding",
    ),
    "health": (
        "required_probe_observations",
        "contiguous_recovery_hysteresis",
        "content_addressed_health_provenance",
    ),
}
_NEGATIVE = {
    "oci_container": (
        "metadata_endpoint_denied",
        "host_credentials_denied",
        "network_and_egress_denied",
        "deadline_and_cancel_stop",
        "output_limit_fail_closed",
        "workspace_and_container_residual_scan",
    ),
    "microvm": (
        "metadata_endpoint_denied",
        "host_credentials_denied",
        "network_and_egress_denied",
        "deadline_and_cancel_stop",
        "output_limit_fail_closed",
        "jailer_overlay_and_vm_residual_scan",
    ),
    "browser": (
        "foreign_origin_or_scope_denied",
        "expired_admission_denied",
        "cancel_and_emergency_stop",
        "budget_overrun_denied",
        "file_download_and_script_denied",
        "credential_body_not_exposed",
        "browser_session_cleanup_and_residual_scan",
    ),
    "postgresql": (
        "failed_batch_atomic_rollback",
        "stale_fence_and_conflict_denied",
        "cross_tenant_access_denied",
        "migration_mismatch_denied",
        "failed_restore_and_rollback_fail_closed",
    ),
    "identity": (
        "unknown_key_or_algorithm_denied",
        "discovery_or_embedded_key_denied",
        "issuer_audience_tenant_mismatch_denied",
        "expired_or_future_token_denied",
        "missing_mfa_or_nonce_denied",
        "replayed_session_denied",
        "authentication_does_not_grant_operator_authority",
    ),
    "health": (
        "missing_stale_future_or_conflicting_observation_pauses",
        "required_dependency_unhealthy_pauses",
        "recovery_does_not_resume_authority",
    ),
}


class GcpAcceptanceChecklistError(ValueError):
    """Invalid, unsupported or stale acceptance-planning inputs."""


def _canonical(value: Any) -> str:
    nodes = 0
    serialized_bytes = 0

    def charge(amount: int) -> None:
        nonlocal serialized_bytes
        serialized_bytes += amount
        if serialized_bytes > MAX_DOCUMENT_BYTES:
            raise GcpAcceptanceChecklistError(
                "Checklist exceeds its aggregate serialized-byte bound"
            )

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 24 or nodes > 50_000:
            raise GcpAcceptanceChecklistError("Checklist structure exceeds its bound")
        kind = type(item)
        if kind is dict:
            if len(item) > 4096 or any(type(key) is not str for key in item):
                raise GcpAcceptanceChecklistError("Native bounded object keys are required")
            charge(2 + len(item) + max(0, len(item) - 1))
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif kind is list:
            if len(item) > 4096:
                raise GcpAcceptanceChecklistError("Checklist list exceeds its bound")
            charge(2 + max(0, len(item) - 1))
            for child in item:
                visit(child, depth + 1)
        elif kind is str:
            if len(item) > 8192:
                raise GcpAcceptanceChecklistError("Bounded printable ASCII strings are required")
            charge(len(item) + 2)
            if not item.isascii():
                raise GcpAcceptanceChecklistError("Bounded printable ASCII strings are required")
            for char in item:
                if ord(char) < 32 or ord(char) > 126:
                    raise GcpAcceptanceChecklistError(
                        "Bounded printable ASCII strings are required"
                    )
                if char in {'"', "\\"}:
                    charge(1)
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise GcpAcceptanceChecklistError("Native signed 64-bit integers are required")
            charge(len(str(item)))
        elif kind is bool:
            charge(4 if item else 5)
        elif kind is type(None):
            charge(4)
        elif kind not in (bool, type(None)):
            raise GcpAcceptanceChecklistError("Native JSON values are required")

    visit(value, 0)
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(text.encode("ascii")) > MAX_DOCUMENT_BYTES:
        raise GcpAcceptanceChecklistError("Checklist exceeds its byte bound")
    return text


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise GcpAcceptanceChecklistError(f"{label} requires exact native fields")
    return value


def _replayed(raw: dict[str, Any], expected: dict[str, Any], label: str) -> dict[str, Any]:
    if _canonical(raw) != _canonical(expected):
        raise GcpAcceptanceChecklistError(f"{label} does not reproduce its source")
    return raw


def _reference(raw: dict[str, Any], source_id: str) -> dict[str, Any]:
    if type(source_id) is not str or not source_id:
        raise GcpAcceptanceChecklistError("Native source identifiers are required")
    return {"source_id": source_id, "document_sha256": _digest(raw), "document": raw}


def _snapshot(source: Any) -> dict[str, Any]:
    if hasattr(source, "document_json") and (
        type(source.document_json) is not str or len(source.document_json) > MAX_DOCUMENT_BYTES
    ):
        raise GcpAcceptanceChecklistError("Source JSON must be native and bounded before parsing")
    raw = source.to_dict()
    _canonical(raw)
    if "schema_version" in raw and (
        type(raw["schema_version"]) is not int or raw["schema_version"] != 1
    ):
        raise GcpAcceptanceChecklistError("Source schema version must be the native integer one")
    return raw


def _native_fields(raw: dict, fields: tuple[str, ...], kind: type) -> None:
    if any(type(raw[key]) is not kind for key in fields):
        raise GcpAcceptanceChecklistError("Source scalar types must be exact before replay")


def _typed_tuple(value: Any, kind: type, label: str) -> None:
    if (
        type(value) is not tuple
        or len(value) > 4096
        or any(type(item) is not kind for item in value)
    ):
        raise GcpAcceptanceChecklistError(f"{label} must contain exact bounded source types")


def _planning_context_sources(
    deployment_profile: DeploymentProfile, regional_binding: TenantRegionBinding
) -> tuple[DeploymentProfile, TenantRegionBinding]:
    if (
        type(deployment_profile) is not DeploymentProfile
        or type(regional_binding) is not TenantRegionBinding
    ):
        raise GcpAcceptanceChecklistError(
            "Exact profile and regional planning sources are required"
        )
    for field, kind in (
        ("deployment_kind", DeploymentKind),
        ("ingress_mode", IngressMode),
        ("egress_mode", EgressMode),
        ("update_channel", UpdateChannel),
        ("credential_constraints", CredentialConstraints),
        ("custody_policy", EvidenceCustodyPolicy),
        ("stop_cleanup_policy", StopCleanupPolicy),
    ):
        if type(getattr(deployment_profile, field)) is not kind:
            raise GcpAcceptanceChecklistError("Profile source types must be exact before replay")
    for field, kind in (
        ("supported_capabilities", Capability),
        ("trust_roots", TrustRootPin),
        ("version_pins", VersionPin),
        ("tool_allowlist", str),
    ):
        _typed_tuple(getattr(deployment_profile, field), kind, field)
    _typed_tuple(
        deployment_profile.credential_constraints.allowed_modes,
        CredentialDeliveryMode,
        "Credential delivery modes",
    )
    for root in deployment_profile.trust_roots:
        _typed_tuple(root.purposes, str, "Trust root purposes")
    for field in ("allowed_storage_regions", "allowed_processing_regions"):
        _typed_tuple(getattr(regional_binding, field), str, field)
    profile_raw, regional_raw = _snapshot(deployment_profile), _snapshot(regional_binding)
    profile = DeploymentProfile.from_dict(profile_raw)
    region = TenantRegionBinding.from_dict(regional_raw)
    _replayed(profile_raw, profile.to_dict(), "Deployment profile")
    _replayed(regional_raw, region.to_dict(), "Tenant region binding")
    return profile, region


@dataclass(frozen=True)
class GcpContainmentPrerequisite:
    """Declared exact backend and host binding, not a host observation."""

    attestation: ContainmentBackendAttestation
    binding: ContainmentBackendDeploymentBinding


@dataclass(frozen=True)
class GcpAcceptancePrerequisites:
    """All prerequisites are explicitly supplied; missing hosts have no fallback."""

    deployment_manifest: DeploymentManifest
    containment_catalog: ContainmentConformanceSuiteCatalog
    containment_bindings: tuple[GcpContainmentPrerequisite, ...]
    postgres_capabilities: BackendCapabilityDeclaration
    browser_policy: AuthorizedBrowserPolicy
    oidc_policy: SsoTrustPolicy
    health_definitions: tuple[ProbeDefinition, ...]


def _sources(plan: GcpResourceBindingPlan, prerequisites: GcpAcceptancePrerequisites) -> dict:
    if type(prerequisites) is not GcpAcceptancePrerequisites:
        raise GcpAcceptanceChecklistError("Exact acceptance prerequisites are required")
    required = (
        ("deployment_manifest", DeploymentManifest),
        ("containment_catalog", ContainmentConformanceSuiteCatalog),
        ("postgres_capabilities", BackendCapabilityDeclaration),
        ("browser_policy", AuthorizedBrowserPolicy),
        ("oidc_policy", SsoTrustPolicy),
    )
    if any(type(getattr(prerequisites, key)) is not cls for key, cls in required):
        raise GcpAcceptanceChecklistError("Exact supported prerequisite source types are required")
    if (
        type(prerequisites.containment_bindings) is not tuple
        or len(prerequisites.containment_bindings) > 2
    ):
        raise GcpAcceptanceChecklistError("At most two exact containment bindings are supported")
    if (
        type(prerequisites.health_definitions) is not tuple
        or not 1 <= len(prerequisites.health_definitions) <= MAX_HEALTH_DEFINITIONS
        or any(
            type(item) is not ProbeDefinition
            or type(item.context) is not HealthContext
            or type(item.kind) is not ProbeKind
            for item in prerequisites.health_definitions
        )
    ):
        raise GcpAcceptanceChecklistError("Explicit bounded exact health definitions are required")
    manifest = prerequisites.deployment_manifest
    raw = _snapshot(manifest)
    _replayed(raw, DeploymentManifest.build(raw["profile_type"]).to_dict(), "Deployment manifest")
    parsed = DeploymentManifest.from_dict(raw)
    if parsed.profile_type not in {"single_node_postgresql", "high_availability_postgresql"}:
        raise GcpAcceptanceChecklistError("An existing PostgreSQL deployment manifest is required")
    _canonical([manifest.profile_id, manifest.profile_sha256, manifest.profile_type])
    if (manifest.profile_id, manifest.profile_sha256, manifest.profile_type) != (
        parsed.profile_id,
        parsed.profile_sha256,
        parsed.profile_type,
    ):
        raise GcpAcceptanceChecklistError("Deployment manifest wrapper is stale")
    catalog = prerequisites.containment_catalog
    catalog_raw = _snapshot(catalog)
    _replayed(
        catalog_raw, build_containment_conformance_suite_catalog().to_dict(), "Containment catalog"
    )
    parsed_catalog = ContainmentConformanceSuiteCatalog.from_dict(catalog_raw)
    if (
        type(catalog.catalog_sha256) is not str
        or catalog.catalog_sha256 != parsed_catalog.catalog_sha256
        or type(catalog.suites) is not tuple
        or _canonical(list(catalog.suites)) != _canonical(catalog_raw["suites"])
    ):
        raise GcpAcceptanceChecklistError("Containment catalog wrapper is stale")
    postgres = prerequisites.postgres_capabilities
    if type(postgres.backend) is not BackendKind:
        raise GcpAcceptanceChecklistError("PostgreSQL backend must be an exact source enum")
    _typed_tuple(postgres.deployment_classes, DeploymentClass, "Persistence deployment classes")
    _typed_tuple(postgres.isolation_levels, IsolationLevel, "Persistence isolation levels")
    postgres_raw = _snapshot(postgres)
    _replayed(
        postgres_raw, postgresql_production_capabilities().to_dict(), "PostgreSQL declaration"
    )
    BackendCapabilityDeclaration.from_dict(postgres_raw)
    browser = prerequisites.browser_policy
    if (
        type(browser.binding) is not ExecutionBinding
        or type(browser.allowed_actions) is not tuple
        or any(type(action) is not BrowserAction for action in browser.allowed_actions)
    ):
        raise GcpAcceptanceChecklistError("Exact browser binding and actions are required")
    browser_raw = {
        "body": browser.body(),
        "policy_id": browser.policy_id,
        "policy_sha256": browser.policy_sha256,
    }
    _canonical(browser_raw)
    body = browser_raw["body"]
    _native_fields(
        body,
        (
            "max_actions",
            "max_navigations",
            "max_total_bytes",
            "max_screenshots",
            "max_action_milliseconds",
            "max_session_milliseconds",
            "max_selector_length",
        ),
        int,
    )
    _native_fields(body["binding"], ("fence_epoch",), int)
    browser_replay = AuthorizedBrowserPolicy(
        **{key: value for key, value in body.items() if key not in {"binding", "allowed_actions"}},
        binding=ExecutionBinding(**body["binding"]),
        allowed_actions=tuple(BrowserAction(value) for value in body["allowed_actions"]),
        policy_id=browser.policy_id,
        policy_sha256=browser.policy_sha256,
    )
    _replayed(
        browser_raw,
        {
            "body": browser_replay.body(),
            "policy_id": browser_replay.policy_id,
            "policy_sha256": browser_replay.policy_sha256,
        },
        "Browser policy",
    )
    _typed_tuple(
        prerequisites.oidc_policy.accepted_assurance_contexts, str, "SSO assurance contexts"
    )
    oidc_raw = _snapshot(prerequisites.oidc_policy)
    _native_fields(oidc_raw, ("require_mfa",), bool)
    _native_fields(
        oidc_raw, ("maximum_auth_age_seconds", "maximum_session_seconds", "clock_skew_seconds"), int
    )
    oidc_replay = SsoTrustPolicy(
        **{
            key: oidc_raw[key]
            for key in (
                "tenant_id",
                "issuer",
                "audience",
                "require_mfa",
                "maximum_auth_age_seconds",
                "maximum_session_seconds",
                "clock_skew_seconds",
            )
        },
        accepted_assurance_contexts=tuple(oidc_raw["accepted_assurance_contexts"]),
    )
    _replayed(oidc_raw, oidc_replay.to_dict(), "OIDC trust policy")
    health = []
    for definition in prerequisites.health_definitions:
        definition_raw = _snapshot(definition)
        _native_fields(definition_raw, ("required",), bool)
        _native_fields(
            definition_raw,
            ("failure_threshold", "recovery_threshold", "interval_seconds", "max_age_seconds"),
            int,
        )
        _replayed(
            definition_raw, ProbeDefinition.from_dict(definition_raw).to_dict(), "Health definition"
        )
        health.append(_reference(definition_raw, definition_raw["definition_id"]))
    if len({row["source_id"] for row in health}) != len(health):
        raise GcpAcceptanceChecklistError("Health definitions must be unique")
    if len({_canonical(row["document"]["context"]) for row in health}) != 1:
        raise GcpAcceptanceChecklistError("Health definitions must bind one exact context")
    bindings = []
    for row in prerequisites.containment_bindings:
        if (
            type(row) is not GcpContainmentPrerequisite
            or type(row.attestation) is not ContainmentBackendAttestation
            or type(row.binding) is not ContainmentBackendDeploymentBinding
        ):
            raise GcpAcceptanceChecklistError("Exact containment prerequisite pairs are required")
        attestation_raw, binding_raw = _snapshot(row.attestation), _snapshot(row.binding)
        attestation = ContainmentBackendAttestation.from_dict(attestation_raw)
        binding = ContainmentBackendDeploymentBinding.from_dict(
            binding_raw, parsed_catalog, attestation
        )
        actual = [
            row.attestation.backend_id,
            row.attestation.attestation_sha256,
            row.attestation.isolation_class,
            row.binding.binding_id,
            row.binding.binding_sha256,
            row.binding.isolation_class,
        ]
        expected = [
            attestation.backend_id,
            attestation.attestation_sha256,
            attestation.isolation_class,
            binding.binding_id,
            binding.binding_sha256,
            binding.isolation_class,
        ]
        if _canonical(actual) != _canonical(expected):
            raise GcpAcceptanceChecklistError("Containment prerequisite wrapper is stale")
        _replayed(attestation_raw, attestation.to_dict(), "Backend attestation")
        _replayed(binding_raw, binding.to_dict(), "Host deployment binding")
        bindings.append(
            {
                "isolation_class": binding.isolation_class,
                "attestation": _reference(attestation_raw, attestation.backend_id),
                "binding": _reference(binding_raw, binding.binding_id),
            }
        )
    if len({row["isolation_class"] for row in bindings}) != len(bindings):
        raise GcpAcceptanceChecklistError("Containment classes must be unique")
    return {
        "resource_plan": _reference(plan.to_dict(), plan.to_dict()["plan_id"]),
        "deployment_manifest": _reference(raw, parsed.profile_id),
        "containment_catalog": _reference(catalog_raw, catalog_raw["catalog_id"]),
        "postgresql": _reference(postgres_raw, postgres_raw["declaration_id"]),
        "browser": _reference(browser_raw, browser.policy_id),
        "identity": _reference(oidc_raw, oidc_raw["record_id"]),
        "health": sorted(health, key=lambda row: row["source_id"]),
        "containment_bindings": sorted(bindings, key=lambda row: row["isolation_class"]),
    }


def _hosts(host_declarations: Any, sources: dict) -> tuple[dict, list[str]]:
    _canonical(host_declarations)
    hosts = _exact(host_declarations, {"oci_container", "microvm"}, "Host declarations")
    plan = sources["resource_plan"]["document"]
    projects = {row["project_id"] for row in plan["projects"]}
    service_accounts = {row["service_identity_ref"] for row in plan["service_accounts"]}
    bindings = {
        row["isolation_class"]: row["binding"]["document"]
        for row in sources["containment_bindings"]
    }
    blockers = []
    for isolation_class, row in hosts.items():
        if row is None:
            blockers.append(f"{isolation_class}_host_declaration_missing")
            continue
        _exact(row, set(HOST_FIELDS), "Host declaration")
        for key, value in row.items():
            if value is None:
                if (
                    key not in {"kernel_image_sha256", "rootfs_image_sha256"}
                    or isolation_class == "microvm"
                ):
                    blockers.append(f"{isolation_class}_{key}_missing")
                continue
            if type(value) is not str or not 1 <= len(value) <= 256:
                raise GcpAcceptanceChecklistError(
                    "Host coordinates must be native bounded strings or null"
                )
            if key.endswith("sha256") and _DIGEST.fullmatch(value) is None:
                raise GcpAcceptanceChecklistError("Host image digests must be exact SHA-256 values")
        if row["project_id"] is not None and row["project_id"] not in projects:
            raise GcpAcceptanceChecklistError("Host project is not declared by the resource plan")
        if row["zone"] is not None and row["zone"] not in {
            f"{PRIMARY_REGION}-{letter}" for letter in "abc"
        }:
            raise GcpAcceptanceChecklistError(
                "Host zone must remain within the declared primary region"
            )
        if row["architecture"] is not None and row["architecture"] not in {"x86_64", "aarch64"}:
            raise GcpAcceptanceChecklistError("Unsupported declared host architecture")
        if (
            row["service_account_ref"] is not None
            and row["service_account_ref"] not in service_accounts
        ):
            raise GcpAcceptanceChecklistError(
                "Host service account is not declared by the resource plan"
            )
        if (
            row["os_image"] is not None
            and re.fullmatch(
                r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z][a-z0-9-]{0,62}",
                row["os_image"],
            )
            is None
        ):
            raise GcpAcceptanceChecklistError(
                "Host OS image must be an exact declared image resource, not a family"
            )
        binding = bindings.get(isolation_class)
        if binding is not None and any(
            row[key] is not None and row[key] != binding[key]
            for key in ("host_id", "architecture", "service_identity_id")
        ):
            raise GcpAcceptanceChecklistError(
                "Host declaration differs from its deployment binding"
            )
        if isolation_class == "oci_container" and any(
            row[key] is not None for key in ("kernel_image_sha256", "rootfs_image_sha256")
        ):
            raise GcpAcceptanceChecklistError(
                "OCI declarations cannot substitute microVM image fields"
            )
    return json.loads(_canonical(hosts)), blockers


def _rows(sources: dict) -> list[dict[str, Any]]:
    catalog_raw = sources["containment_catalog"]["document"]
    _replayed(
        catalog_raw, build_containment_conformance_suite_catalog().to_dict(), "Checklist catalog"
    )
    suites = {row["isolation_class"]: row for row in catalog_raw["suites"]}
    rows = []
    for service in SERVICES:
        checks = (
            list(COMMON_REQUIREMENTS + CLASS_REQUIREMENTS[service])
            if service in CLASS_REQUIREMENTS
            else []
        )
        positive = (
            list(suites[service]["probe_ids"]) if service in suites else list(_POSITIVE[service])
        )
        rows.append(
            {
                "service": service,
                "required_host_preflight_checks": checks,
                "required_positive_evidence": positive,
                "required_negative_evidence": list(_NEGATIVE[service]),
                "required_outputs": [
                    "content_addressed_receipts",
                    "bounded_redacted_runtime_outputs",
                    "stop_outcome",
                    "cleanup_and_residual_evidence",
                ],
                "status": "required_not_observed",
                "observed_acceptance": False,
            }
        )
    return rows


def _validate_references(sources: dict) -> None:
    def reference(row: Any) -> None:
        _exact(row, {"source_id", "document_sha256", "document"}, "Source reference")
        if (
            type(row["source_id"]) is not str
            or not 1 <= len(row["source_id"]) <= 256
            or type(row["document"]) is not dict
            or row["document_sha256"] != _digest(row["document"])
        ):
            raise GcpAcceptanceChecklistError("Source reference does not bind its embedded bytes")

    for key in _SOURCE_NAMES - {"health", "containment_bindings"}:
        reference(sources[key])
    health = sources["health"]
    bindings = sources["containment_bindings"]
    if type(health) is not list or not 1 <= len(health) <= MAX_HEALTH_DEFINITIONS:
        raise GcpAcceptanceChecklistError("Checklist health references are invalid")
    if type(bindings) is not list or len(bindings) > 2:
        raise GcpAcceptanceChecklistError("Checklist containment references are invalid")
    for row in health:
        reference(row)
    for row in bindings:
        _exact(row, {"isolation_class", "attestation", "binding"}, "Containment reference")
        if row["isolation_class"] not in SERVICES[:2]:
            raise GcpAcceptanceChecklistError("Unsupported containment class")
        reference(row["attestation"])
        reference(row["binding"])


def _dependencies() -> list[dict]:
    return [
        {
            "queue_id": queue,
            "requires": ["WQ-015" if index == 0 else QUEUE_ORDER[index - 1]],
            "required_evidence": _QUEUE_EVIDENCE[index],
            "status": "blocked_external_evidence",
            "gate_completed": False,
        }
        for index, queue in enumerate(QUEUE_ORDER)
    ]


def _compose(
    plan: GcpResourceBindingPlan,
    *,
    prerequisites: GcpAcceptancePrerequisites,
    host_declarations: dict,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> dict:
    _canonical(host_declarations)
    deployment_profile, regional_binding = _planning_context_sources(
        deployment_profile, regional_binding
    )
    report = verify_gcp_resource_binding_plan(
        plan,
        dossier=dossier,
        deployment_profile=deployment_profile,
        regional_binding=regional_binding,
    )
    sources = _sources(plan, prerequisites)
    if sources["identity"]["document"]["tenant_id"] != regional_binding.tenant_ref:
        raise GcpAcceptanceChecklistError("SSO tenant differs from the declared regional tenant")
    browser_tenant = sources["browser"]["document"]["body"]["binding"]["tenant_id"]
    if browser_tenant != regional_binding.tenant_ref:
        raise GcpAcceptanceChecklistError(
            "Browser tenant differs from the declared regional tenant"
        )
    context = sources["health"][0]["document"]["context"]
    if context["tenant_ref"] != regional_binding.tenant_ref:
        raise GcpAcceptanceChecklistError("Health tenant differs from the declared regional tenant")
    if context["worker_ref"] != deployment_profile.worker_ref:
        raise GcpAcceptanceChecklistError("Health worker differs from the declared profile worker")
    hosts, host_blockers = _hosts(host_declarations, sources)
    blockers = (
        set(report["blocker_codes"])
        | set(host_blockers)
        | {
            "provider_host_capabilities_unverified",
            "host_preflight_observations_missing",
            "dynamic_containment_evidence_missing",
            "browser_runtime_evidence_missing",
            "postgresql_runtime_evidence_missing",
            "oidc_authenticated_keyset_and_runtime_evidence_missing",
            "health_observations_missing",
            "reference_candidate_execution_evidence_missing",
            "independent_qualification_required",
        }
    )
    present = {row["isolation_class"] for row in sources["containment_bindings"]}
    blockers.update(
        f"{name}_deployment_binding_missing" for name in SERVICES[:2] if name not in present
    )
    kinds = {
        row["document"]["probe_kind"] for row in sources["health"] if row["document"]["required"]
    }
    blockers.update(
        f"health_required_{kind.value}_definition_missing"
        for kind in ProbeKind
        if kind.value not in kinds
    )
    if not sources["identity"]["document"]["require_mfa"]:
        blockers.add("identity_mfa_requirement_missing")
    body = {
        "schema_version": 1,
        "kind": DOMAIN,
        "status": "unsigned_offline_acceptance_checklist",
        "identity_assurance": "operator_asserted_unsigned",
        "parsing_scope": "content_integrity_only",
        "source_integrity": "supplied_records_revalidated_not_authenticated",
        "source_bindings": sources,
        "host_declarations": hosts,
        "services": _rows(sources),
        "dependency_order": _dependencies(),
        "blocker_codes": sorted(blockers),
        "observed_live_acceptance": False,
        "qualified_readiness": False,
        "effects": dict(_EFFECTS),
    }
    digest = _digest({"domain": DOMAIN, "checklist": body})
    return {**body, "checklist_id": "GAC-" + digest[7:39].upper(), "checklist_sha256": digest}


@dataclass(frozen=True)
class GcpAcceptanceChecklist:
    """Canonical immutable unsigned checklist; parsing is not current-source verification."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, raw: Any) -> GcpAcceptanceChecklist:
        try:
            return cls(_canonical(raw))
        except GcpAcceptanceChecklistError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise GcpAcceptanceChecklistError("Checklist content parsing failed") from exc

    def to_dict(self) -> dict[str, Any]:
        if type(self.document_json) is not str or len(self.document_json) > MAX_DOCUMENT_BYTES:
            raise GcpAcceptanceChecklistError("A bounded native canonical checklist is required")
        try:
            raw = json.loads(self.document_json)
        except (ValueError, RecursionError) as exc:
            raise GcpAcceptanceChecklistError("Checklist JSON is invalid") from exc
        fields = {
            "schema_version",
            "kind",
            "status",
            "identity_assurance",
            "parsing_scope",
            "source_integrity",
            "source_bindings",
            "host_declarations",
            "services",
            "dependency_order",
            "blocker_codes",
            "observed_live_acceptance",
            "qualified_readiness",
            "effects",
            "checklist_id",
            "checklist_sha256",
        }
        _exact(raw, fields, "Checklist")
        _canonical(raw)
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["kind"] != DOMAIN
            or raw["status"] != "unsigned_offline_acceptance_checklist"
            or raw["identity_assurance"] != "operator_asserted_unsigned"
            or raw["parsing_scope"] != "content_integrity_only"
            or raw["source_integrity"] != "supplied_records_revalidated_not_authenticated"
            or type(raw["observed_live_acceptance"]) is not bool
            or raw["observed_live_acceptance"]
            or type(raw["qualified_readiness"]) is not bool
            or raw["qualified_readiness"]
            or raw["effects"] != _EFFECTS
        ):
            raise GcpAcceptanceChecklistError(
                "Checklist cannot imply authority or observed acceptance"
            )
        _exact(raw["source_bindings"], _SOURCE_NAMES, "Checklist source bindings")
        _validate_references(raw["source_bindings"])
        _exact(
            raw["host_declarations"], {"oci_container", "microvm"}, "Checklist host declarations"
        )
        if _canonical(raw["services"]) != _canonical(_rows(raw["source_bindings"])):
            raise GcpAcceptanceChecklistError("Checklist evidence requirements do not reproduce")
        if _canonical(raw["dependency_order"]) != _canonical(_dependencies()):
            raise GcpAcceptanceChecklistError("Checklist cannot bypass WQ-016 through WQ-019 gates")
        blockers = raw["blocker_codes"]
        if (
            type(blockers) is not list
            or not blockers
            or any(type(code) is not str for code in blockers)
            or blockers != sorted(set(blockers))
            or "authenticated_d014_selection_required" not in blockers
            or "independent_qualification_required" not in blockers
        ):
            raise GcpAcceptanceChecklistError(
                "Checklist must preserve explicit acceptance blockers"
            )
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"checklist_id", "checklist_sha256"}
        }
        digest = _digest({"domain": DOMAIN, "checklist": body})
        if (
            raw["checklist_sha256"] != digest
            or raw["checklist_id"] != "GAC-" + digest[7:39].upper()
            or _canonical(raw) != self.document_json
        ):
            raise GcpAcceptanceChecklistError("Checklist content address does not match")
        return raw


def build_gcp_acceptance_checklist(
    plan: GcpResourceBindingPlan,
    *,
    prerequisites: GcpAcceptancePrerequisites,
    host_declarations: dict,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> GcpAcceptanceChecklist:
    """Compose declarations and required evidence, without collecting or accepting evidence."""
    try:
        return GcpAcceptanceChecklist.from_dict(
            _compose(
                plan,
                prerequisites=prerequisites,
                host_declarations=host_declarations,
                dossier=dossier,
                deployment_profile=deployment_profile,
                regional_binding=regional_binding,
            )
        )
    except GcpAcceptanceChecklistError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise GcpAcceptanceChecklistError("Acceptance prerequisite replay failed") from exc


def verify_gcp_acceptance_checklist(
    checklist: GcpAcceptanceChecklist,
    plan: GcpResourceBindingPlan,
    *,
    prerequisites: GcpAcceptancePrerequisites,
    host_declarations: dict,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> dict[str, Any]:
    """Require exact supplied-source replay, never authenticate D014 or observe a runtime."""
    if type(checklist) is not GcpAcceptanceChecklist:
        raise GcpAcceptanceChecklistError("An exact checklist record is required")
    expected = build_gcp_acceptance_checklist(
        plan,
        prerequisites=prerequisites,
        host_declarations=host_declarations,
        dossier=dossier,
        deployment_profile=deployment_profile,
        regional_binding=regional_binding,
    ).to_dict()
    _replayed(checklist.to_dict(), expected, "Acceptance checklist")
    return {
        "status": "valid_unsigned_offline_checklist",
        "checklist_id": expected["checklist_id"],
        "checklist_sha256": expected["checklist_sha256"],
        "blocker_codes": expected["blocker_codes"],
        "observed_live_acceptance": False,
        "qualified_readiness": False,
        "effects": dict(_EFFECTS),
    }

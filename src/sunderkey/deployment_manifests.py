"""Deterministic repository-only deployment manifest publication.

This module builds exact local, single-node, and high-availability deployment
descriptions. It does not inspect a host, access credentials, connect to a
database, run a process, contact a network, deploy services, or qualify an
environment.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .deployment_profile_contracts import (
    DeploymentKind,
    build_standard_profile,
)
from .egress_proxy_contracts import (
    SCHEMA_VERSION as EGRESS_SCHEMA_VERSION,
)
from .egress_proxy_contracts import (
    canonical_sha256 as egress_contract_sha256,
)
from .ha_coordination_contracts import (
    SCHEMA_VERSION as HA_SCHEMA_VERSION,
)
from .ha_coordination_contracts import (
    canonical_sha256 as ha_contract_sha256,
)
from .health_state_contracts import (
    SCHEMA_VERSION as HEALTH_SCHEMA_VERSION,
)
from .health_state_contracts import (
    canonical_sha256 as health_contract_sha256,
)
from .persistence_port_contracts import (
    postgresql_production_capabilities,
    sqlite_development_capabilities,
)
from .postgresql_runtime_adapter import (
    POSTGRESQL_MIGRATION_ID,
    POSTGRESQL_MIGRATION_SHA256,
    POSTGRESQL_MIGRATION_VERSION,
)
from .regional_custody_contracts import (
    SCHEMA_VERSION as CUSTODY_SCHEMA_VERSION,
)
from .regional_custody_contracts import (
    canonical_sha256 as custody_contract_sha256,
)

SCHEMA_VERSION = 1
PROFILE_DOMAIN = "sunderkey.deployment-manifest.v1"
BUNDLE_DOMAIN = "sunderkey.deployment-manifest-bundle.v1"
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE_RE = re.compile(
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]{1,5})?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}\Z"
)
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.]+)?\Z")
SECRET_REF_RE = re.compile(r"secretref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
SERVICE_ID_RE = re.compile(r"service:[a-z][a-z0-9-]{1,62}\Z")
SECRET_VALUE_RE = re.compile(
    r"(?:-----BEGIN [A-Z0-9 ]*(?:PRIVATE|SECRET) KEY-----|"
    r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|private[_-]?key)\s*[:=]|"
    r"\bbearer\s+[A-Za-z0-9._~+/-]{8,}|\bAKIA[0-9A-Z]{16}\b|"
    r"\bgh[oprsu]_[A-Za-z0-9]{20,}|[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@)",
    re.IGNORECASE,
)

BOUNDARY_EFFECTS = {
    "credential_access": "none",
    "deployment": "none",
    "filesystem_discovery": "none",
    "network": "none",
    "process_execution": "none",
    "qualification": "none",
    "target_action": "none",
}

EXTERNAL_EVIDENCE = (
    "backup_restore_drill_receipt",
    "capacity_load_test_receipt",
    "cleanup_residual_scan_receipt",
    "egress_enforcement_observation",
    "health_probe_observation_set",
    "migration_execution_receipt",
    "regional_custody_attestation",
    "rollback_drill_receipt",
    "runtime_image_signature_verification",
    "tls_handshake_observation",
)

_DIGESTS = {
    "api": "sha256:" + "a" * 64,
    "backup": "sha256:" + "b" * 64,
    "egress": "sha256:" + "c" * 64,
    "ingress": "sha256:" + "d" * 64,
    "migrator": "sha256:" + "e" * 64,
    "postgresql": "sha256:" + "f" * 64,
    "scheduler": "sha256:" + "1" * 64,
    "worker": "sha256:" + "2" * 64,
}


class DeploymentManifestError(ValueError):
    """Raised when a deployment manifest fails closed."""


def canonical_json(value: Any) -> str:
    """Return deterministic printable ASCII JSON after secret screening."""

    try:
        document = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise DeploymentManifestError("value cannot be serialized") from exc
    if SECRET_VALUE_RE.search(document):
        raise DeploymentManifestError("raw secret or credential material is forbidden")
    return document


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _identity(prefix: str, domain: str, body: dict[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"content": body, "domain": domain})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _image(name: str, version: str) -> dict[str, str]:
    digest = _DIGESTS[name]
    return {
        "component": name,
        "exact_version": version,
        "image_digest": digest,
        "image_reference": f"registry.sunderkey.invalid/sunderkey/{name}@{digest}",
    }


def _service(name: str, replicas: int, image: str, role: str) -> dict[str, Any]:
    return {
        "image_component": image,
        "replicas": replicas,
        "role": role,
        "run_as_non_root": True,
        "service_identity": f"service:{name}",
        "writable_root_filesystem": False,
    }


def _contract_bindings() -> list[dict[str, Any]]:
    deployment = build_standard_profile(DeploymentKind.CUSTOMER_HOSTED_WORKER)
    sqlite = sqlite_development_capabilities()
    postgres = postgresql_production_capabilities()
    simple = (
        (
            "sunderkey.egress_proxy_contracts",
            EGRESS_SCHEMA_VERSION,
            egress_contract_sha256,
        ),
        (
            "sunderkey.ha_coordination_contracts",
            HA_SCHEMA_VERSION,
            ha_contract_sha256,
        ),
        (
            "sunderkey.health_state_contracts",
            HEALTH_SCHEMA_VERSION,
            health_contract_sha256,
        ),
        (
            "sunderkey.regional_custody_contracts",
            CUSTODY_SCHEMA_VERSION,
            custody_contract_sha256,
        ),
    )
    bindings = [
        {
            "contract_id": deployment.profile_id,
            "contract_sha256": deployment.profile_sha256,
            "module": "sunderkey.deployment_profile_contracts",
            "schema_version": 1,
        },
        {
            "contract_id": sqlite.declaration_id,
            "contract_sha256": sqlite.declaration_sha256,
            "module": "sunderkey.persistence_port_contracts.sqlite",
            "schema_version": 1,
        },
        {
            "contract_id": postgres.declaration_id,
            "contract_sha256": postgres.declaration_sha256,
            "module": "sunderkey.persistence_port_contracts.postgresql",
            "schema_version": 1,
        },
        {
            "contract_id": POSTGRESQL_MIGRATION_ID,
            "contract_sha256": POSTGRESQL_MIGRATION_SHA256,
            "module": "sunderkey.postgresql_runtime_adapter",
            "schema_version": 1,
        },
    ]
    for module, schema_version, hasher in simple:
        source = {"module": module, "schema_version": schema_version}
        bindings.append(
            {
                "contract_id": "contract:" + module.removeprefix("sunderkey."),
                "contract_sha256": hasher(source),
                "module": module,
                "schema_version": schema_version,
            }
        )
    return sorted(bindings, key=lambda item: item["module"])


def _common_network(profile_type: str) -> dict[str, Any]:
    if profile_type == "local_sqlite_asgi":
        return {
            "egress_mode": "deny_all",
            "egress_proxy_required": False,
            "ingress_mode": "loopback_only",
            "internal_service_tls": "not_required_loopback_only",
            "ports": [
                {
                    "container_port": 8080,
                    "exposure": "127.0.0.1_only",
                    "service": "api",
                    "transport": "tcp",
                }
            ],
            "public_ingress": False,
            "tls_mode": "not_terminated_local_only",
        }
    return {
        "egress_mode": "default_deny_allowlist_proxy",
        "egress_proxy_required": True,
        "ingress_mode": "tls_only",
        "internal_service_tls": "mutual_tls_required",
        "ports": [
            {
                "container_port": 8443,
                "exposure": "ingress_proxy_only",
                "service": "api",
                "transport": "tcp",
            },
            {
                "container_port": 5432,
                "exposure": "cluster_internal_only",
                "service": "postgresql",
                "transport": "tcp",
            },
            {
                "container_port": 15001,
                "exposure": "cluster_internal_only",
                "service": "egress",
                "transport": "tcp",
            },
        ],
        "public_ingress": False,
        "tls_mode": "operator_certificate_reference_required",
    }


def _runtime(profile_type: str) -> dict[str, Any]:
    if profile_type == "local_sqlite_asgi":
        return {
            "api_adapter": "in_process_asgi",
            "outbox_delivery": "single_process",
            "scheduler_mode": "single_process_durable",
            "worker_concurrency": 1,
        }
    if profile_type == "single_node_postgresql":
        return {
            "api_adapter": "asgi_server_injected",
            "outbox_delivery": "single_claimant_with_fence",
            "scheduler_mode": "single_active_with_durable_lease",
            "worker_concurrency": 4,
        }
    return {
        "api_adapter": "asgi_server_injected",
        "outbox_delivery": "multi_claimant_skip_locked_with_fence",
        "scheduler_mode": "quorum_guarded_single_active_with_durable_lease",
        "worker_concurrency": 16,
    }


def _storage(profile_type: str) -> dict[str, Any]:
    if profile_type == "local_sqlite_asgi":
        declaration = sqlite_development_capabilities()
        return {
            "artifact_store": "local_content_addressed_directory",
            "backend": "sqlite",
            "backend_capability_id": declaration.declaration_id,
            "backend_capability_sha256": declaration.declaration_sha256,
            "database_volume": "local_operator_managed",
            "encryption_at_rest": "host_responsibility_external_evidence_required",
            "persistent_volume_count": 1,
        }
    declaration = postgresql_production_capabilities()
    return {
        "artifact_store": "external_content_addressed_store_reference",
        "backend": "postgresql",
        "backend_capability_id": declaration.declaration_id,
        "backend_capability_sha256": declaration.declaration_sha256,
        "database_volume": "encrypted_durable_volume_required",
        "encryption_at_rest": "required_external_evidence",
        "persistent_volume_count": 1 if profile_type == "single_node_postgresql" else 3,
    }


def _profile_body(profile_type: str) -> dict[str, Any]:
    if profile_type not in {
        "local_sqlite_asgi",
        "single_node_postgresql",
        "high_availability_postgresql",
    }:
        raise DeploymentManifestError("profile_type is unsupported")
    local = profile_type == "local_sqlite_asgi"
    ha = profile_type == "high_availability_postgresql"
    images = [_image("api", "1.0.0"), _image("scheduler", "1.0.0"), _image("worker", "1.0.0")]
    services = [
        _service("api", 3 if ha else 1, "api", "control_plane_api"),
        _service("scheduler", 3 if ha else 1, "scheduler", "durable_scheduler"),
        _service("worker", 4 if ha else 1, "worker", "restricted_execution_worker"),
    ]
    if not local:
        images.extend(
            [
                _image("backup", "1.0.0"),
                _image("egress", "1.35.3"),
                _image("ingress", "1.35.3"),
                _image("migrator", "1.0.0"),
                _image("postgresql", "17.6.0"),
            ]
        )
        services.extend(
            [
                _service("backup", 1, "backup", "database_backup"),
                _service("egress", 2 if ha else 1, "egress", "default_deny_egress_proxy"),
                _service("ingress", 2 if ha else 1, "ingress", "tls_ingress_proxy"),
                _service("migrator", 0, "migrator", "operator_invoked_migration_job"),
                _service("postgresql", 3 if ha else 1, "postgresql", "durable_database"),
            ]
        )
    required_evidence = list(EXTERNAL_EVIDENCE)
    if local:
        required_evidence = [
            "cleanup_residual_scan_receipt",
            "health_probe_observation_set",
            "migration_execution_receipt",
            "rollback_drill_receipt",
            "runtime_image_signature_verification",
        ]
    return {
        "backup": {
            "continuous_archiving": not local,
            "encrypted_backup_reference_required": not local,
            "point_in_time_recovery_required": not local,
            "restore_drill_required": True,
            "status": "external_execution_required",
        },
        "capacity": {
            "api_replicas": 3 if ha else 1,
            "database_replicas": 3 if ha else (0 if local else 1),
            "maximum_inflight_actions": 256 if ha else (8 if local else 64),
            "maximum_worker_concurrency": 16 if ha else (1 if local else 4),
            "scheduler_replicas": 3 if ha else 1,
            "worker_replicas": 4 if ha else 1,
        },
        "cleanup": {
            "artifact_retention_policy_required": True,
            "database_drop_forbidden": True,
            "external_residual_scan_required": True,
            "mission_cleanup_receipt_required": True,
            "temporary_volume_removal_required": True,
        },
        "contract_bindings": _contract_bindings(),
        "effects": dict(BOUNDARY_EFFECTS),
        "fencing": {
            "coordination_mode": "quorum_epoch_and_fencing_token" if ha else "durable_lease_fence",
            "fail_closed_on_ambiguity": True,
            "ha_coordination_required": ha,
            "minimum_voters": 3 if ha else 1,
            "stale_writer_rejection_required": True,
        },
        "health": {
            "dependency_probes_required": True,
            "fail_closed_on_unknown": True,
            "integrity_probes_required": True,
            "liveness_path": "/health/live",
            "readiness_path": "/health/ready",
            "recovery_requires_separate_admission": True,
        },
        "images": sorted(images, key=lambda item: item["component"]),
        "migration": {
            "automatic_migration": False,
            "execution_mode": "operator_invoked_offline"
            if local
            else "operator_invoked_expand_contract",
            "migration_id": POSTGRESQL_MIGRATION_ID,
            "migration_sha256": POSTGRESQL_MIGRATION_SHA256,
            "migration_version": POSTGRESQL_MIGRATION_VERSION,
            "preflight_and_backup_required": True,
        },
        "network": _common_network(profile_type),
        "profile_type": profile_type,
        "regional_custody": {
            "cross_region_transfer_default": "deny",
            "data_region": "operator_selected_pinned_region",
            "key_region": "same_region_required",
            "regional_replication": "same_region_only" if ha else "disabled",
            "retention_schedule_required": True,
        },
        "required_external_evidence": required_evidence,
        "rollback": {
            "automatic_rollback": False,
            "database_restore_requires_approval": True,
            "image_digest_reversion_supported": True,
            "previous_manifest_reference_required": True,
            "rollback_drill_required": True,
        },
        "runtime": _runtime(profile_type),
        "secrets": [
            "secretref:artifact-store-credential",
            "secretref:database-credential",
            "secretref:egress-proxy-client-identity",
            "secretref:ingress-tls-identity",
        ]
        if not local
        else [],
        "services": sorted(services, key=lambda item: item["service_identity"]),
        "status": "repository_manifest_complete_infrastructure_blocked",
        "storage": _storage(profile_type),
    }


@dataclass(frozen=True, slots=True)
class DeploymentManifest:
    profile_id: str
    profile_sha256: str
    profile_type: str
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def build(cls, profile_type: str) -> DeploymentManifest:
        body = _profile_body(profile_type)
        profile_id, profile_sha256 = _identity("DMF", PROFILE_DOMAIN, body)
        raw = {"profile_id": profile_id, "profile_sha256": profile_sha256, **body}
        return cls(profile_id, profile_sha256, profile_type, canonical_json(raw))

    @classmethod
    def from_dict(cls, raw: Any) -> DeploymentManifest:
        if not isinstance(raw, dict):
            raise DeploymentManifestError("deployment profile must be an object")
        profile_type = raw.get("profile_type")
        expected_body = _profile_body(profile_type)
        expected_fields = {"profile_id", "profile_sha256", *expected_body}
        if set(raw) != expected_fields:
            raise DeploymentManifestError("deployment profile fields are invalid")
        body = {key: raw[key] for key in expected_body}
        if canonical_json(body) != canonical_json(expected_body):
            raise DeploymentManifestError("deployment profile differs from the checked template")
        expected_id, expected_sha256 = _identity("DMF", PROFILE_DOMAIN, body)
        if raw["profile_id"] != expected_id or raw["profile_sha256"] != expected_sha256:
            raise DeploymentManifestError("deployment profile content address is invalid")
        for image in body["images"]:
            if (
                IMAGE_RE.fullmatch(image["image_reference"]) is None
                or image["image_reference"].rsplit("@", 1)[1] != image["image_digest"]
                or VERSION_RE.fullmatch(image["exact_version"]) is None
            ):
                raise DeploymentManifestError("deployment image pin is invalid")
        if any(SECRET_REF_RE.fullmatch(value) is None for value in body["secrets"]):
            raise DeploymentManifestError("deployment secret reference is invalid")
        if any(
            SERVICE_ID_RE.fullmatch(value["service_identity"]) is None for value in body["services"]
        ):
            raise DeploymentManifestError("deployment service identity is invalid")
        return cls(expected_id, expected_sha256, profile_type, canonical_json(raw))


@dataclass(frozen=True, slots=True)
class DeploymentManifestBundle:
    bundle_id: str
    bundle_sha256: str
    profiles: tuple[DeploymentManifest, ...]
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @classmethod
    def from_dict(cls, raw: Any) -> DeploymentManifestBundle:
        expected_fields = {
            "bundle_id",
            "bundle_sha256",
            "effects",
            "external_qualification_complete",
            "kind",
            "live_deployment_performed",
            "profiles",
            "repository_manifest_publication_complete",
            "required_external_evidence",
            "schema_version",
            "status",
        }
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise DeploymentManifestError("deployment manifest bundle fields are invalid")
        profiles = tuple(DeploymentManifest.from_dict(item) for item in raw["profiles"])
        expected = build_deployment_manifest_bundle()
        if canonical_json(raw) != expected.document_json:
            raise DeploymentManifestError("deployment manifest bundle differs from checked content")
        return cls(
            raw["bundle_id"],
            raw["bundle_sha256"],
            profiles,
            canonical_json(raw),
        )


def build_deployment_manifest_bundle() -> DeploymentManifestBundle:
    """Build the fixed nonqualifying manifest bundle without external effects."""

    profiles = tuple(
        DeploymentManifest.build(profile_type)
        for profile_type in (
            "high_availability_postgresql",
            "local_sqlite_asgi",
            "single_node_postgresql",
        )
    )
    body = {
        "effects": dict(BOUNDARY_EFFECTS),
        "external_qualification_complete": False,
        "kind": "deployment_manifest_bundle",
        "live_deployment_performed": False,
        "profiles": [profile.to_dict() for profile in profiles],
        "repository_manifest_publication_complete": True,
        "required_external_evidence": list(EXTERNAL_EVIDENCE),
        "schema_version": SCHEMA_VERSION,
        "status": "repository_complete_infrastructure_blocked",
    }
    bundle_id, bundle_sha256 = _identity("DMB", BUNDLE_DOMAIN, body)
    raw = {"bundle_id": bundle_id, "bundle_sha256": bundle_sha256, **body}
    return DeploymentManifestBundle(bundle_id, bundle_sha256, profiles, canonical_json(raw))


def parse_deployment_manifest_bundle(document: str) -> DeploymentManifestBundle:
    """Parse and verify an exact canonical deployment manifest bundle."""

    if not isinstance(document, str):
        raise DeploymentManifestError("deployment manifest document must be text")
    try:
        raw = json.loads(document)
    except json.JSONDecodeError as exc:
        raise DeploymentManifestError("deployment manifest document is invalid JSON") from exc
    result = DeploymentManifestBundle.from_dict(raw)
    if document != result.document_json:
        raise DeploymentManifestError("deployment manifest document is not canonical JSON")
    return result

"""Review declared GCP service boundaries without IAM changes or network activity."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .candidate_enrollment_production_custody_contract import PROVIDER_INTERFACE_DESCRIPTORS
from .deployment_profile_contracts import DeploymentProfile, EgressMode
from .egress_proxy_contracts import EgressPolicy
from .gcp_resource_bindings import (
    GcpResourceBindingPlan,
    parse_gcp_planning_json,
    verify_gcp_resource_binding_plan,
)
from .production_deployment_decision_dossier import ProductionDeploymentDecisionDossier
from .regional_custody_contracts import TenantRegionBinding

DOMAIN = "sunderkey.gcp-service-boundary-review.v1"
MAX_ITEMS = 128
MAX_REVIEW_BYTES = 262_144
_INPUT_FIELDS = {
    "service_assignments",
    "application_network_edges",
    "host_resolver_policy",
    "stop_binding",
}
_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "credential_access": "none",
        "deployment": "none",
        "iam_mutation": "none",
        "network": "none",
        "qualification": "none",
        "signature_generation": "none",
        "storage_mutation": "none",
        "target_action": "none",
    }
)
_SERVICE_ROLES = frozenset(
    {
        "control_plane_api",
        "durable_scheduler",
        "restricted_execution_worker",
        "database_backup",
        "default_deny_egress_proxy",
        "tls_ingress_proxy",
        "operator_invoked_migration_job",
        "durable_database",
    }
)
_CUSTODY_RESOURCE_TYPES = MappingProxyType(
    {
        "retention_locked_ledger_objects": "storeref",
        "conditional_ledger_head": "storeref",
        "immutable_catalog_objects": "storeref",
        "release_head_signing": "keyref",
        "release_head_verification": "keyref",
        "release_audit": "storeref",
    }
)
_ROLE_OPERATIONS = MappingProxyType(
    {
        descriptor["interface_id"]: frozenset(descriptor["required_operations"])
        for descriptor in PROVIDER_INTERFACE_DESCRIPTORS
        if descriptor["interface_id"] in _CUSTODY_RESOURCE_TYPES
    }
)
_PERMANENT_BLOCKERS = frozenset(
    {
        "authenticated_d014_selection_required",
        "effective_iam_and_federation_policy_required",
        "incident_owner_and_stop_enforcement_required",
        "network_enforcement_and_dns_owner_policy_required",
        "provider_configuration_unverified",
        "production_go_no_go_required",
        "resource_namespace_and_effective_scope_policy_required",
        "worker_containment_unverified",
    }
)
_PLAN_BLOCKERS = frozenset(
    {
        "authenticated_d014_selection_required",
        "provider_configuration_unverified",
        "organization_folder_billing_unbound",
        "recovery_region_unselected",
        "worker_containment_unverified",
        "production_go_no_go_required",
        "service_identity_coordinates_missing",
        "profile_evidence_store_coordinates_missing",
        "tenant_encryption_coordinates_missing",
        "database_coordinates_missing",
        "managed_sql_manifest_mapping_required",
    }
)
_OWNER_BLOCKERS = frozenset(
    {
        "worker_service_assignment_required",
        "custody_service_assignment_required",
        "custody_operation_scope_required",
        "egress_proxy_service_assignment_required",
        "worker_application_network_edge_required",
        "host_resolver_policy_required",
        "worker_resolver_binding_required",
        "exact_stop_cleanup_restoration_binding_required",
    }
)
_REFERENCE = re.compile(r"[a-z][a-z0-9_-]{1,63}:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_METADATA_HOSTS = frozenset({"metadata", "metadata.google.internal", "metadata.goog"})
_METADATA_NETWORKS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("fd20:ce::254/128"),
    ipaddress.ip_network("::ffff:169.254.169.254/128"),
)


class GcpServiceBoundaryError(ValueError):
    """Invalid declarations or evidence that does not bind the supplied sources."""


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or len(value) != len(fields)
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise GcpServiceBoundaryError(f"{label} fields are invalid")
    return value


class _JsonBudget:
    """Bound expanded native JSON before walking or allocating encoded text."""

    def __init__(self) -> None:
        self.bytes_left = MAX_REVIEW_BYTES
        self.nodes_left = MAX_REVIEW_BYTES

    def take(self, size: int) -> None:
        self.bytes_left -= size
        if self.bytes_left < 0:
            raise GcpServiceBoundaryError("Review exceeds its aggregate byte bound")

    def node(self) -> None:
        self.nodes_left -= 1
        if self.nodes_left < 0:
            raise GcpServiceBoundaryError("Review exceeds its aggregate node bound")

    def integer(self, value: int) -> None:
        # A lower decimal-digit bound checks huge ints without an unsafe conversion.
        # The generic byte bound remains the ceiling, not a new source-family limit.
        sign = int(value < 0)
        digits = 1 if value == 0 else ((value.bit_length() - 1) * 30102) // 100000 + 1
        self.take(sign + digits)
        try:
            encoded_size = len(str(value))
        except ValueError as exc:
            raise GcpServiceBoundaryError("Review integer encoding exceeds its bounds") from exc
        self.take(encoded_size - sign - digits)


def _native(
    value: Any,
    depth: int = 0,
    *,
    bounded_lists: bool = True,
    _budget: _JsonBudget | None = None,
) -> None:
    if depth > 12:
        raise GcpServiceBoundaryError("Review nesting exceeds its bound")
    budget = _JsonBudget() if _budget is None else _budget
    budget.node()
    if value is None:
        budget.take(4)
        return
    if type(value) is bool:
        budget.take(4 if value else 5)
        return
    if type(value) is int:
        budget.integer(value)
        return
    if type(value) is str:
        # Account for quotes and reject oversize text before any character scan.
        budget.take(len(value) + 2)
        if not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise GcpServiceBoundaryError("Review strings must be printable ASCII")
        budget.take(value.count('"') + value.count("\\"))
        return
    if type(value) is list:
        if bounded_lists and len(value) > MAX_ITEMS:
            raise GcpServiceBoundaryError("Review array exceeds its bound")
        budget.take(2 + max(0, len(value) - 1))
        for item in value:
            _native(item, depth + 1, bounded_lists=bounded_lists, _budget=budget)
        return
    if type(value) is dict:
        if len(value) > MAX_ITEMS:
            raise GcpServiceBoundaryError("Review object exceeds its field bound")
        budget.take(2 + max(0, len(value) - 1) + len(value))
        for key, item in value.items():
            if type(key) is not str:
                raise GcpServiceBoundaryError("Review keys must be native strings")
            _native(key, depth + 1, bounded_lists=bounded_lists, _budget=budget)
            _native(item, depth + 1, bounded_lists=bounded_lists, _budget=budget)
        return
    raise GcpServiceBoundaryError("Review contains an unsupported primitive")


def _canonical(value: Any, *, bounded_lists: bool = True) -> str:
    _native(value, bounded_lists=bounded_lists)
    try:
        text = json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (ValueError, RecursionError) as exc:
        raise GcpServiceBoundaryError("Review JSON encoding exceeds its bounds") from exc
    if len(text.encode("ascii")) > MAX_REVIEW_BYTES:
        raise GcpServiceBoundaryError("Review exceeds its byte bound")
    return text


def _ref(value: Any, namespace: str) -> str:
    if (
        type(value) is not str
        or _REFERENCE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise GcpServiceBoundaryError(f"{namespace} reference is invalid")
    return value


def _rows(value: Any, fields: set[str], label: str) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_ITEMS:
        raise GcpServiceBoundaryError(f"{label} must be a bounded native array")
    return [_exact(item, fields, label) for item in value]


def _codes(value: Any, allowed: frozenset[str], label: str) -> list[str]:
    if (
        type(value) is not list
        or len(value) > len(allowed)
        or any(type(item) is not str or item not in allowed for item in value)
        or value != sorted(set(value))
    ):
        raise GcpServiceBoundaryError(f"{label} must be a sorted unique allowed array")
    return value


def _reference(value: Any, prefix: str) -> dict[str, str]:
    raw = _exact(value, {"id", "sha256"}, "source reference")
    if (
        type(raw["sha256"]) is not str
        or _DIGEST.fullmatch(raw["sha256"]) is None
        or type(raw["id"]) is not str
        or raw["id"] != prefix + "-" + raw["sha256"][7:39].upper()
    ):
        raise GcpServiceBoundaryError("Source identity and digest do not agree")
    return raw


def _validate_inputs(value: Any) -> dict[str, Any]:
    raw = _exact(value, _INPUT_FIELDS, "service boundary input")
    _canonical(raw)
    assignments = _rows(
        raw["service_assignments"],
        {"service_ref", "role", "service_identity_ref", "operations"},
        "service assignments",
    )
    seen: set[str] = set()
    for item in assignments:
        service = _ref(item["service_ref"], "componentref")
        if service in seen:
            raise GcpServiceBoundaryError("Service references must be unique")
        seen.add(service)
        _ref(item["service_identity_ref"], "principalref")
        role = item["role"]
        if type(role) is not str or role not in _SERVICE_ROLES | _ROLE_OPERATIONS.keys():
            raise GcpServiceBoundaryError("Service role is unsupported")
        operations = _rows(item["operations"], {"operation", "resource_ref"}, "role operations")
        pairs: set[tuple[str, str]] = set()
        for operation in operations:
            name = operation["operation"]
            if type(name) is not str or name not in _ROLE_OPERATIONS.get(role, frozenset()):
                raise GcpServiceBoundaryError("Operation is outside the role allowlist")
            resource = _ref(operation["resource_ref"], _CUSTODY_RESOURCE_TYPES[role])
            if (name, resource) in pairs:
                raise GcpServiceBoundaryError("Role operation scopes must be unique")
            pairs.add((name, resource))
        item["operations"] = sorted(
            operations, key=lambda row: (row["operation"], row["resource_ref"])
        )
    assignments.sort(key=lambda item: item["service_ref"])
    raw["service_assignments"] = assignments
    edges = _rows(
        raw["application_network_edges"],
        {
            "worker_service_ref",
            "worker_ref",
            "proxy_service_ref",
            "policy_id",
            "policy_sha256",
            "resolver_ref",
            "proxy_only",
        },
        "application network edges",
    )
    seen_edges: set[tuple[str, str]] = set()
    for edge in edges:
        _ref(edge["worker_service_ref"], "componentref")
        _ref(edge["worker_ref"], "workerref")
        _ref(edge["proxy_service_ref"], "componentref")
        _reference({"id": edge["policy_id"], "sha256": edge["policy_sha256"]}, "EGP")
        if edge["resolver_ref"] is not None:
            _ref(edge["resolver_ref"], "resolver")
        if edge["proxy_only"] is not True:
            raise GcpServiceBoundaryError("Worker application traffic must be proxy-only")
        key = (edge["worker_service_ref"], edge["policy_id"])
        if key in seen_edges:
            raise GcpServiceBoundaryError("Worker policy edges must be unique")
        seen_edges.add(key)
    edges.sort(key=lambda item: (item["worker_service_ref"], item["policy_id"]))
    raw["application_network_edges"] = edges
    resolver = raw["host_resolver_policy"]
    if resolver is not None:
        _exact(
            resolver,
            {
                "resolver_ref",
                "proxy_service_ref",
                "addresses",
                "port",
                "transports",
                "worker_direct_dns",
            },
            "host resolver policy",
        )
        _ref(resolver["resolver_ref"], "resolver")
        _ref(resolver["proxy_service_ref"], "componentref")
        if type(resolver["port"]) is not int or resolver["port"] != 53:
            raise GcpServiceBoundaryError("Host resolver policy is limited to DNS port 53")
        if resolver["worker_direct_dns"] is not False:
            raise GcpServiceBoundaryError("Workers must not bypass proxy DNS")
        addresses = resolver["addresses"]
        if type(addresses) is not list or not addresses or len(addresses) > MAX_ITEMS:
            raise GcpServiceBoundaryError("Resolver addresses must be a bounded nonempty array")
        for address in addresses:
            try:
                if type(address) is not str or str(ipaddress.ip_address(address)) != address:
                    raise ValueError
            except ValueError as exc:
                raise GcpServiceBoundaryError("Resolver address is not canonical") from exc
        if len(addresses) != len(set(addresses)):
            raise GcpServiceBoundaryError("Resolver addresses must be unique")
        resolver["addresses"] = sorted(addresses)
        transports = resolver["transports"]
        if (
            type(transports) is not list
            or not transports
            or len(transports) > 2
            or any(type(item) is not str or item not in {"tcp", "udp"} for item in transports)
            or len(transports) != len(set(transports))
        ):
            raise GcpServiceBoundaryError("Resolver transports must be explicit DNS transports")
        resolver["transports"] = sorted(transports)
    stop = raw["stop_binding"]
    if stop is not None:
        _exact(
            stop,
            {
                "stop_contract_ref",
                "cleanup_contract_ref",
                "restoration_contract_ref",
                "maximum_stop_ack_seconds",
                "stop_supported",
                "cleanup_required",
                "restoration_required",
            },
            "stop binding",
        )
        for name, namespace in (
            ("stop_contract_ref", "stopref"),
            ("cleanup_contract_ref", "cleanupref"),
            ("restoration_contract_ref", "restorationref"),
        ):
            _ref(stop[name], namespace)
        if (
            type(stop["maximum_stop_ack_seconds"]) is not int
            or not 1 <= stop["maximum_stop_ack_seconds"] <= 300
        ):
            raise GcpServiceBoundaryError("Stop acknowledgement bound is invalid")
        if any(
            stop[name] is not True
            for name in ("stop_supported", "cleanup_required", "restoration_required")
        ):
            raise GcpServiceBoundaryError("Stop, cleanup and restoration are mandatory")
    return raw


def _owned_policy(policy: Any) -> EgressPolicy:
    if type(policy) is not EgressPolicy:
        raise GcpServiceBoundaryError("Exact typed egress policies are required")
    try:
        raw = policy.to_dict()
        _canonical(raw)
        for field in ("schema_version", "policy_version", "maximum_resolution_age_seconds"):
            if type(raw[field]) is not int:
                raise GcpServiceBoundaryError("Egress integer metadata must be native")
        if type(raw["redirects_allowed"]) is not bool:
            raise GcpServiceBoundaryError("Egress redirect metadata must be native")
        for rule in raw["endpoint_rules"]:
            for field in ("port", "max_request_bytes", "max_response_bytes"):
                if type(rule[field]) is not int:
                    raise GcpServiceBoundaryError("Egress rule quantities must be native integers")
        owned = EgressPolicy.from_dict(raw)
        if _canonical(owned.to_dict()) != _canonical(raw):
            raise GcpServiceBoundaryError("Egress source does not replay exactly")
        return owned
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise GcpServiceBoundaryError("Egress source revalidation failed") from exc


def _metadata_rule(policy: EgressPolicy) -> None:
    for rule in policy.endpoint_rules:
        if rule.host.rstrip(".").lower() in _METADATA_HOSTS:
            raise GcpServiceBoundaryError("Worker application egress permits a metadata hostname")
        for cidr in rule.allowed_ip_networks:
            network = ipaddress.ip_network(cidr)
            if any(
                network.version == reserved.version and network.overlaps(reserved)
                for reserved in _METADATA_NETWORKS
            ):
                raise GcpServiceBoundaryError(
                    "Worker application egress overlaps metadata addresses"
                )


def _owner_blockers(inputs: dict[str, Any]) -> list[str]:
    assignments = inputs["service_assignments"]
    roles = {item["role"] for item in assignments}
    blockers: set[str] = set()
    if "restricted_execution_worker" not in roles:
        blockers.add("worker_service_assignment_required")
    if not roles.intersection(_CUSTODY_RESOURCE_TYPES):
        blockers.add("custody_service_assignment_required")
    if any(
        item["role"] in _CUSTODY_RESOURCE_TYPES and not item["operations"] for item in assignments
    ):
        blockers.add("custody_operation_scope_required")
    if "default_deny_egress_proxy" not in roles:
        blockers.add("egress_proxy_service_assignment_required")
    edged = {item["worker_service_ref"] for item in inputs["application_network_edges"]}
    if any(
        item["role"] == "restricted_execution_worker" and item["service_ref"] not in edged
        for item in assignments
    ):
        blockers.add("worker_application_network_edge_required")
    if inputs["host_resolver_policy"] is None:
        blockers.add("host_resolver_policy_required")
    if any(edge["resolver_ref"] is None for edge in inputs["application_network_edges"]):
        blockers.add("worker_resolver_binding_required")
    if inputs["stop_binding"] is None:
        blockers.add("exact_stop_cleanup_restoration_binding_required")
    return sorted(blockers)


def _address(body: dict[str, Any]) -> tuple[str, str]:
    digest = (
        "sha256:"
        + hashlib.sha256(_canonical({"domain": DOMAIN, "review": body}).encode("ascii")).hexdigest()
    )
    return "GSB-" + digest[7:39].upper(), digest


@dataclass(frozen=True, slots=True)
class GcpServiceBoundaryReview:
    """Owned canonical planning record. Content integrity is not source authentication."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, raw: Any) -> GcpServiceBoundaryReview:
        return cls(_canonical(raw))

    @classmethod
    def from_json(cls, text: str) -> GcpServiceBoundaryReview:
        try:
            return cls.from_dict(parse_gcp_planning_json(text))
        except ValueError as exc:
            raise GcpServiceBoundaryError("Service review JSON is invalid") from exc

    def to_dict(self) -> dict[str, Any]:
        try:
            raw = parse_gcp_planning_json(self.document_json)
        except ValueError as exc:
            raise GcpServiceBoundaryError("Service review wrapper is invalid") from exc
        _exact(
            raw,
            _INPUT_FIELDS
            | {
                "kind",
                "schema_version",
                "primary_region",
                "source_bindings",
                "status",
                "validation_scope",
                "identity_assurance",
                "effects",
                "resource_plan_blocker_codes",
                "owner_input_blocker_codes",
                "permanent_blocker_codes",
                "review_id",
                "review_sha256",
            },
            "service review",
        )
        inputs = {key: raw[key] for key in _INPUT_FIELDS}
        if _canonical(_validate_inputs(json.loads(_canonical(inputs)))) != _canonical(inputs):
            raise GcpServiceBoundaryError("Service review declarations must be canonical")
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["kind"] != DOMAIN
            or raw["primary_region"] != "us-west3"
            or raw["status"] != "valid_for_offline_planning_only"
            or raw["validation_scope"] != "declared_service_and_application_network_boundaries"
            or raw["identity_assurance"] != "operator_asserted_unsigned"
            or raw["effects"] != dict(_EFFECTS)
        ):
            raise GcpServiceBoundaryError("Service review metadata or effects are invalid")
        sources = _exact(
            raw["source_bindings"],
            {
                "resource_plan",
                "d014_dossier",
                "deployment_profile",
                "regional_binding",
                "egress_policies",
            },
            "source bindings",
        )
        for name, prefix in (
            ("resource_plan", "GRP"),
            ("d014_dossier", "PDD"),
            ("deployment_profile", "DPC"),
            ("regional_binding", "TRB"),
        ):
            _reference(sources[name], prefix)
        policies = _rows(sources["egress_policies"], {"id", "sha256"}, "policy source bindings")
        for reference in policies:
            _reference(reference, "EGP")
        if policies != sorted(policies, key=lambda item: item["id"]) or len(
            {item["id"] for item in policies}
        ) != len(policies):
            raise GcpServiceBoundaryError("Policy source bindings must be sorted and unique")
        _codes(raw["resource_plan_blocker_codes"], _PLAN_BLOCKERS, "resource plan blockers")
        _codes(raw["owner_input_blocker_codes"], _OWNER_BLOCKERS, "owner input blockers")
        if raw["owner_input_blocker_codes"] != _owner_blockers(inputs):
            raise GcpServiceBoundaryError("Owner input blockers must be derived")
        if raw["permanent_blocker_codes"] != sorted(_PERMANENT_BLOCKERS):
            raise GcpServiceBoundaryError("Permanent acceptance blockers must not be removed")
        body = {key: item for key, item in raw.items() if key not in {"review_id", "review_sha256"}}
        if (raw["review_id"], raw["review_sha256"]) != _address(body) or _canonical(
            raw
        ) != self.document_json:
            raise GcpServiceBoundaryError(
                "Service review identity does not match its canonical contents"
            )
        return raw


def review_gcp_service_boundaries(
    inputs: dict[str, Any],
    *,
    resource_plan: GcpResourceBindingPlan,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
    egress_policies: tuple[EgressPolicy, ...],
) -> GcpServiceBoundaryReview:
    """Review explicit declarations, never effective IAM, enforcement or live admission."""
    owned_inputs = _validate_inputs(json.loads(_canonical(inputs)))
    try:
        plan_result = verify_gcp_resource_binding_plan(
            resource_plan,
            dossier=dossier,
            deployment_profile=deployment_profile,
            regional_binding=regional_binding,
        )
        plan = resource_plan.to_dict()
        profile = DeploymentProfile.from_dict(deployment_profile.to_dict())
        region = TenantRegionBinding.from_dict(regional_binding.to_dict())
    except (ValueError, TypeError, AttributeError) as exc:
        raise GcpServiceBoundaryError("Resource planning source verification failed") from exc
    if type(egress_policies) is not tuple or len(egress_policies) > MAX_ITEMS:
        raise GcpServiceBoundaryError("Egress sources must be a bounded native tuple")
    policies = [_owned_policy(policy) for policy in egress_policies]
    policy_by_id = {policy.to_dict()["policy_id"]: policy for policy in policies}
    if len(policy_by_id) != len(policies):
        raise GcpServiceBoundaryError("Egress policy sources must be unique")
    accounts = {
        item["service_identity_ref"]: item["unique_id"] for item in plan["service_accounts"]
    }
    storage_refs = {item["storage_ref"] for item in plan["gcs_buckets"]}
    signing_refs = {
        item["key_ref"] for item in plan["kms_key_versions"] if item["purpose"] == "ASYMMETRIC_SIGN"
    }
    assignments = {item["service_ref"]: item for item in owned_inputs["service_assignments"]}
    custody_accounts: set[str] = set()
    worker_accounts: set[str] = set()
    execution_accounts: set[str] = set()
    trusted_accounts: set[str] = set()
    role_accounts: dict[str, set[str]] = {}
    for item in assignments.values():
        if item["service_identity_ref"] not in accounts:
            raise GcpServiceBoundaryError("Service account is not declared in the resource plan")
        identity = accounts[item["service_identity_ref"]]
        role = item["role"]
        role_accounts.setdefault(role, set()).add(identity)
        if role == "restricted_execution_worker":
            execution_accounts.add(identity)
        else:
            trusted_accounts.add(identity)
        if role in _CUSTODY_RESOURCE_TYPES:
            custody_accounts.add(identity)
            valid_refs = signing_refs if _CUSTODY_RESOURCE_TYPES[role] == "keyref" else storage_refs
            if any(operation["resource_ref"] not in valid_refs for operation in item["operations"]):
                raise GcpServiceBoundaryError(
                    "Custody operation resource is not explicitly declared for that purpose"
                )
        if role in {"restricted_execution_worker", "default_deny_egress_proxy"}:
            worker_accounts.add(identity)
    if custody_accounts.intersection(worker_accounts):
        raise GcpServiceBoundaryError("Worker or proxy identity aliases a custody identity")
    if execution_accounts.intersection(trusted_accounts):
        raise GcpServiceBoundaryError("Worker identity aliases a trusted service identity")
    if role_accounts.get("release_head_signing", set()).intersection(
        role_accounts.get("release_head_verification", set())
    ):
        raise GcpServiceBoundaryError(
            "Release signing and verification identities must be independent"
        )
    resolver = owned_inputs["host_resolver_policy"]
    if (
        resolver is not None
        and assignments.get(resolver["proxy_service_ref"], {}).get("role")
        != "default_deny_egress_proxy"
    ):
        raise GcpServiceBoundaryError("Host resolver must bind a declared egress proxy")
    used_policies: set[str] = set()
    if (
        owned_inputs["application_network_edges"]
        and profile.egress_mode is EgressMode.EVIDENCE_REMOVABLE_MEDIA
    ):
        raise GcpServiceBoundaryError(
            "Disconnected profiles cannot declare application network edges"
        )
    for edge in owned_inputs["application_network_edges"]:
        if (
            assignments.get(edge["worker_service_ref"], {}).get("role")
            != "restricted_execution_worker"
        ):
            raise GcpServiceBoundaryError("Application edge must bind a declared worker")
        if (
            assignments.get(edge["proxy_service_ref"], {}).get("role")
            != "default_deny_egress_proxy"
        ):
            raise GcpServiceBoundaryError("Application edge must bind a declared egress proxy")
        policy = policy_by_id.get(edge["policy_id"])
        if policy is None or policy.to_dict()["policy_sha256"] != edge["policy_sha256"]:
            raise GcpServiceBoundaryError(
                "Application edge does not bind an exact supplied egress policy"
            )
        if (
            policy.worker_ref != edge["worker_ref"]
            or policy.worker_ref != profile.worker_ref
            or policy.tenant_ref != region.tenant_ref
        ):
            raise GcpServiceBoundaryError(
                "Application egress context differs from its worker or tenant sources"
            )
        if (
            resolver is not None
            and edge["resolver_ref"] is not None
            and (
                edge["resolver_ref"] != resolver["resolver_ref"]
                or edge["proxy_service_ref"] != resolver["proxy_service_ref"]
            )
        ):
            raise GcpServiceBoundaryError(
                "Application edge resolver binding differs from the host policy"
            )
        _metadata_rule(policy)
        used_policies.add(edge["policy_id"])
    if used_policies != set(policy_by_id):
        raise GcpServiceBoundaryError("Every supplied policy must bind an explicit worker edge")
    stop = owned_inputs["stop_binding"]
    if stop is not None and _canonical(stop) != _canonical(profile.stop_cleanup_policy.to_dict()):
        raise GcpServiceBoundaryError("Stop binding differs from the exact deployment profile")
    body = {
        **owned_inputs,
        "kind": DOMAIN,
        "schema_version": 1,
        "primary_region": "us-west3",
        "source_bindings": {
            **plan["source_bindings"],
            "resource_plan": {"id": plan["plan_id"], "sha256": plan["plan_sha256"]},
            "egress_policies": sorted(
                [
                    {
                        "id": policy.to_dict()["policy_id"],
                        "sha256": policy.to_dict()["policy_sha256"],
                    }
                    for policy in policies
                ],
                key=lambda item: item["id"],
            ),
        },
        "status": "valid_for_offline_planning_only",
        "validation_scope": "declared_service_and_application_network_boundaries",
        "identity_assurance": "operator_asserted_unsigned",
        "resource_plan_blocker_codes": sorted(plan_result["blocker_codes"]),
        "owner_input_blocker_codes": _owner_blockers(owned_inputs),
        "permanent_blocker_codes": sorted(_PERMANENT_BLOCKERS),
        "effects": dict(_EFFECTS),
    }
    identity, digest = _address(body)
    return GcpServiceBoundaryReview.from_dict(
        {**body, "review_id": identity, "review_sha256": digest}
    )


def verify_gcp_service_boundary_review(
    review: GcpServiceBoundaryReview,
    *,
    resource_plan: GcpResourceBindingPlan,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
    egress_policies: tuple[EgressPolicy, ...],
) -> GcpServiceBoundaryReview:
    """Replay exact supplied sources. This is not a positive runtime-use gate."""
    if type(review) is not GcpServiceBoundaryReview:
        raise GcpServiceBoundaryError("An exact typed service review is required")
    raw = review.to_dict()
    expected = review_gcp_service_boundaries(
        {key: raw[key] for key in _INPUT_FIELDS},
        resource_plan=resource_plan,
        dossier=dossier,
        deployment_profile=deployment_profile,
        regional_binding=regional_binding,
        egress_policies=egress_policies,
    )
    if expected.document_json != review.document_json:
        raise GcpServiceBoundaryError(
            "Service review does not bind the exact supplied source replay"
        )
    return expected

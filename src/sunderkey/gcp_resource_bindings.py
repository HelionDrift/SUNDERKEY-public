"""Validate declared GCP coordinates without cloud access or deployment authority."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .deployment_profile_contracts import DeploymentProfile
from .production_deployment_decision_dossier import ProductionDeploymentDecisionDossier
from .regional_custody_contracts import TenantRegionBinding

DOMAIN = "sunderkey.gcp-resource-binding-plan.v1"
PRIMARY_REGION = "us-west3"
MAX_PLAN_BYTES = 262_144
MAX_ITEMS = 128
_INPUT_FIELDS = {
    "provider",
    "primary_region",
    "recovery_region",
    "projects",
    "service_accounts",
    "kms_key_versions",
    "gcs_buckets",
    "cloud_sql_instances",
}
_EFFECTS = {
    "authorization": "none",
    "credential_access": "none",
    "deployment": "none",
    "network": "none",
    "qualification": "none",
    "signature_generation": "none",
    "storage_mutation": "none",
    "target_action": "none",
}
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,29}\Z")
_ACCOUNT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]\Z")
_BUCKET = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]\Z")
_INSTANCE = re.compile(r"[a-z][a-z0-9-]{0,95}[a-z0-9]\Z|[a-z]\Z")
_REFERENCE = re.compile(r"[a-z]+ref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY = re.compile(
    r"projects/(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])/locations/us-west3/"
    r"keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}/"
    r"cryptoKeyVersions/[1-9][0-9]{0,29}\Z"
)


class GcpResourceBindingError(ValueError):
    """Invalid declared coordinates or unverified source substitution."""


def _exact(raw: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (
        type(raw) is not dict
        or len(raw) != len(fields)
        or any(type(key) is not str for key in raw)
        or set(raw) != fields
    ):
        raise GcpResourceBindingError(f"{label} fields are invalid")
    return raw


class _JsonBudget:
    """Account for expanded JSON bytes and visits before allocating encoded text."""

    def __init__(self) -> None:
        self.bytes_left = MAX_PLAN_BYTES
        self.nodes_left = MAX_PLAN_BYTES

    def take(self, size: int) -> None:
        self.bytes_left -= size
        if self.bytes_left < 0:
            raise GcpResourceBindingError("Planning input exceeds the aggregate byte limit")

    def node(self) -> None:
        self.nodes_left -= 1
        if self.nodes_left < 0:
            raise GcpResourceBindingError("Planning input exceeds the aggregate node limit")

    def integer(self, value: int) -> None:
        # This lower decimal-digit bound avoids converting an oversized native int.
        # No new integer-family ceiling is imposed: the existing byte limit applies.
        sign = int(value < 0)
        digits = 1 if value == 0 else ((value.bit_length() - 1) * 30102) // 100000 + 1
        self.take(sign + digits)
        try:
            encoded_size = len(str(value))
        except ValueError as exc:
            raise GcpResourceBindingError("Planning integer encoding exceeds its bounds") from exc
        self.take(encoded_size - sign - digits)


def _json_values(
    value: Any,
    depth: int = 0,
    *,
    max_items: int | None = MAX_ITEMS,
    _budget: _JsonBudget | None = None,
) -> None:
    if depth > 12:
        raise GcpResourceBindingError("Planning input exceeds the nesting limit")
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
        # Check the minimum encoded size before scanning characters or escapes.
        budget.take(len(value) + 2)
        if not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise GcpResourceBindingError("Planning strings must be printable ASCII")
        budget.take(value.count('"') + value.count("\\"))
        return
    if type(value) is list:
        if max_items is not None and len(value) > max_items:
            raise GcpResourceBindingError("Planning array exceeds the item limit")
        budget.take(2 + max(0, len(value) - 1))
        for item in value:
            _json_values(item, depth + 1, max_items=max_items, _budget=budget)
        return
    if type(value) is dict:
        # Braces, commas and colons; keys account for their own quoted bytes.
        budget.take(2 + max(0, len(value) - 1) + len(value))
        for key, item in value.items():
            if type(key) is not str:
                raise GcpResourceBindingError("Planning keys must be native strings")
            _json_values(key, depth + 1, max_items=max_items, _budget=budget)
            _json_values(item, depth + 1, max_items=max_items, _budget=budget)
        return
    raise GcpResourceBindingError("Planning input contains an unsupported primitive")


def _canonical(value: Any, *, max_items: int | None = MAX_ITEMS) -> str:
    _json_values(value, max_items=max_items)
    try:
        text = json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        )
    except (ValueError, RecursionError) as exc:
        raise GcpResourceBindingError("Planning JSON encoding exceeds its bounds") from exc
    if len(text.encode("ascii")) > MAX_PLAN_BYTES:
        raise GcpResourceBindingError("Planning input exceeds the byte limit")
    return text


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GcpResourceBindingError("Planning JSON contains duplicate keys")
        result[key] = value
    return result


def _parse_json(text: str, *, max_items: int | None) -> dict[str, Any]:
    if type(text) is not str:
        raise GcpResourceBindingError("Planning JSON must be native text")
    try:
        if len(text) > MAX_PLAN_BYTES or len(text.encode("utf-8")) > MAX_PLAN_BYTES:
            raise GcpResourceBindingError("Planning JSON exceeds the byte limit")
        raw = json.loads(text, object_pairs_hook=_object_pairs)
        _canonical(raw, max_items=max_items)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise GcpResourceBindingError("Planning JSON is invalid or exceeds its bounds") from exc
    if type(raw) is not dict:
        raise GcpResourceBindingError("Planning JSON must contain an object")
    return raw


def parse_gcp_planning_json(text: str) -> dict[str, Any]:
    """Decode bounded coordinates, never credentials or provider observations."""
    return _parse_json(text, max_items=MAX_ITEMS)


def parse_gcp_source_json(text: str) -> dict[str, Any]:
    """Preserve native source metadata before an existing source parser normalizes it.

    Source contracts enforce their own collection limits. The coordinate-specific
    128-row limit does not apply, while primitive, depth, and byte bounds still do.
    This parser does not authenticate or replace the source contract's validation.
    """
    raw = _parse_json(text, max_items=None)
    if type(raw.get("schema_version")) is not int or raw["schema_version"] != 1:
        raise GcpResourceBindingError("Planning source schema metadata is invalid")
    return raw


def _match(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise GcpResourceBindingError(f"{label} is invalid")
    return value


def _ref(value: Any, namespace: str) -> str:
    text = _match(value, _REFERENCE, namespace)
    if not text.startswith(namespace + ":"):
        raise GcpResourceBindingError(f"{namespace} namespace is invalid")
    return text


def _rows(raw: Any, fields: set[str], label: str) -> list[dict[str, Any]]:
    if type(raw) is not list or len(raw) > MAX_ITEMS:
        raise GcpResourceBindingError(f"{label} must be a bounded native array")
    return [_exact(item, fields, label) for item in raw]


def _unique(values: list[str], label: str) -> None:
    if len(values) != len(set(values)):
        raise GcpResourceBindingError(f"{label} must be unique")


def _validate_inputs(raw: Any) -> dict[str, Any]:
    value = _exact(raw, _INPUT_FIELDS, "GCP coordinate input")
    _canonical(value)
    if value["provider"] != "gcp" or value["primary_region"] != PRIMARY_REGION:
        raise GcpResourceBindingError(
            "Only the owner-directed GCP us-west3 planning region is allowed"
        )
    if value["recovery_region"] is not None:
        raise GcpResourceBindingError(
            "No recovery region has been selected for this planning version"
        )
    projects = _rows(value["projects"], {"project_id", "project_number"}, "projects")
    if not projects:
        raise GcpResourceBindingError("At least one explicitly supplied project is required")
    for project in projects:
        project_name = _match(project["project_id"], _PROJECT, "project ID")
        if any(reserved in project_name for reserved in ("google", "ssl", "null", "undefined")):
            raise GcpResourceBindingError("Reserved project-name forms are unsupported")
        _match(project["project_number"], _NUMBER, "project number")
    _unique([item["project_id"] for item in projects], "project IDs")
    _unique([item["project_number"] for item in projects], "project numbers")
    project_ids = {item["project_id"] for item in projects}

    def project_id(item: dict[str, Any]) -> str:
        candidate = _match(item["project_id"], _PROJECT, "resource project ID")
        if candidate not in project_ids:
            raise GcpResourceBindingError("Resource project is not explicitly declared")
        return candidate

    accounts = _rows(
        value["service_accounts"],
        {"service_identity_ref", "project_id", "account_id", "unique_id"},
        "service accounts",
    )
    for account in accounts:
        project_id(account)
        _ref(account["service_identity_ref"], "principalref")
        _match(account["account_id"], _ACCOUNT, "user-managed account ID")
        _match(account["unique_id"], _NUMBER, "service account unique ID")
    _unique([item["service_identity_ref"] for item in accounts], "service identity references")
    _unique([item["unique_id"] for item in accounts], "service account unique IDs")
    _unique(
        [f"{item['project_id']}/{item['account_id']}" for item in accounts], "account coordinates"
    )

    keys = _rows(
        value["kms_key_versions"],
        {"key_ref", "resource_name", "purpose", "algorithm", "protection_level"},
        "key versions",
    )
    key_profiles: dict[str, tuple[str, str]] = {}
    for key in keys:
        _ref(key["key_ref"], "keyref")
        match = _KEY.fullmatch(_match(key["resource_name"], _KEY, "pinned KMS version"))
        if match is None or match["project"] not in project_ids:
            raise GcpResourceBindingError("KMS project is not explicitly declared")
        purpose = _match(
            key["purpose"], re.compile(r"ENCRYPT_DECRYPT|ASYMMETRIC_SIGN"), "key purpose"
        )
        algorithm = _match(key["algorithm"], re.compile(r"[A-Z0-9_]+"), "key algorithm")
        protection = _match(key["protection_level"], re.compile(r"SOFTWARE|HSM"), "key protection")
        expected = {
            "ENCRYPT_DECRYPT": ("GOOGLE_SYMMETRIC_ENCRYPTION", {"SOFTWARE", "HSM"}),
            "ASYMMETRIC_SIGN": ("EC_SIGN_ED25519", {"SOFTWARE"}),
        }.get(purpose)
        if expected is None or algorithm != expected[0] or protection not in expected[1]:
            raise GcpResourceBindingError(
                "KMS purpose, algorithm, or protection profile is unsupported"
            )
        crypto_key = key["resource_name"].rsplit("/cryptoKeyVersions/", 1)[0]
        key_profile = (purpose, protection)
        if crypto_key in key_profiles and key_profiles[crypto_key] != key_profile:
            raise GcpResourceBindingError("Versions of one CryptoKey cannot mix immutable profiles")
        key_profiles[crypto_key] = key_profile
    _unique([item["key_ref"] for item in keys], "key references")
    _unique([item["resource_name"] for item in keys], "key version coordinates")
    encryption_keys = {item["key_ref"] for item in keys if item["purpose"] == "ENCRYPT_DECRYPT"}

    buckets = _rows(
        value["gcs_buckets"],
        {"storage_ref", "project_id", "bucket_name", "location", "encryption_key_ref"},
        "buckets",
    )
    for bucket in buckets:
        project_id(bucket)
        _ref(bucket["storage_ref"], "storeref")
        name = _match(bucket["bucket_name"], _BUCKET, "supported bucket name")
        if name.startswith("goog") or "google" in name or "g00gle" in name:
            raise GcpResourceBindingError("Reserved bucket-name forms are unsupported")
        if bucket["location"] != PRIMARY_REGION:
            raise GcpResourceBindingError("Bucket location must be exactly us-west3")
        if _ref(bucket["encryption_key_ref"], "keyref") not in encryption_keys:
            raise GcpResourceBindingError(
                "Bucket must reference a declared regional encryption version"
            )
    _unique([item["storage_ref"] for item in buckets], "storage references")
    _unique([item["bucket_name"] for item in buckets], "bucket coordinates")

    databases = _rows(
        value["cloud_sql_instances"],
        {"database_ref", "project_id", "instance_id", "region", "primary_zone", "secondary_zone"},
        "Cloud SQL instances",
    )
    for database in databases:
        project = project_id(database)
        _ref(database["database_ref"], "componentref")
        instance = _match(database["instance_id"], _INSTANCE, "SQL instance ID")
        if len(project + ":" + instance) > 98 or database["region"] != PRIMARY_REGION:
            raise GcpResourceBindingError(
                "SQL instance coordinates are outside the supported profile"
            )
        zones = {"us-west3-a", "us-west3-b", "us-west3-c"}
        if type(database["primary_zone"]) is not str or database["primary_zone"] not in zones:
            raise GcpResourceBindingError("SQL primary zone must be explicit and regional")
        secondary = database["secondary_zone"]
        if secondary is not None and (
            type(secondary) is not str
            or secondary not in zones
            or secondary == database["primary_zone"]
        ):
            raise GcpResourceBindingError("SQL secondary zone must be a distinct regional zone")
    _unique([item["database_ref"] for item in databases], "database references")
    _unique(
        [f"{item['project_id']}/{item['instance_id']}" for item in databases], "SQL coordinates"
    )
    return value


def _sources(
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> dict[str, Any]:
    if (
        type(dossier) is not ProductionDeploymentDecisionDossier
        or type(deployment_profile) is not DeploymentProfile
        or type(regional_binding) is not TenantRegionBinding
    ):
        raise GcpResourceBindingError("Exact typed planning sources are required")
    try:
        snapshots = (dossier.to_dict(), deployment_profile.to_dict(), regional_binding.to_dict())
        for snapshot in snapshots:
            _canonical(snapshot, max_items=None)
            if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
                raise GcpResourceBindingError("Planning source schema metadata is invalid")
        dossier = ProductionDeploymentDecisionDossier.from_dict(snapshots[0])
        deployment_profile = DeploymentProfile.from_dict(snapshots[1])
        regional_binding = TenantRegionBinding.from_dict(snapshots[2])
    except (ValueError, TypeError, AttributeError) as exc:
        raise GcpResourceBindingError("Planning source revalidation failed") from exc
    if (
        regional_binding.home_region != PRIMARY_REGION
        or PRIMARY_REGION not in regional_binding.allowed_storage_regions
        or PRIMARY_REGION not in regional_binding.allowed_processing_regions
    ):
        raise GcpResourceBindingError(
            "Tenant region policy does not contain the selected primary region"
        )
    return {
        "d014_dossier": {"id": dossier.dossier_id, "sha256": dossier.dossier_sha256},
        "deployment_profile": {
            "id": deployment_profile.profile_id,
            "sha256": deployment_profile.profile_sha256,
        },
        "regional_binding": {
            "id": regional_binding.binding_id,
            "sha256": regional_binding.binding_sha256,
        },
    }


def _address(body: dict[str, Any]) -> tuple[str, str]:
    digest = (
        "sha256:"
        + hashlib.sha256(_canonical({"domain": DOMAIN, "plan": body}).encode("ascii")).hexdigest()
    )
    return "GRP-" + digest[7:39].upper(), digest


@dataclass(frozen=True)
class GcpResourceBindingPlan:
    """Immutable coordinate intent, not configuration observation or authenticated authority."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, raw: Any) -> GcpResourceBindingPlan:
        return cls(_canonical(raw))

    @classmethod
    def from_json(cls, text: str) -> GcpResourceBindingPlan:
        return cls.from_dict(parse_gcp_planning_json(text))

    def to_dict(self) -> dict[str, Any]:
        raw = parse_gcp_planning_json(self.document_json)
        _exact(
            raw,
            _INPUT_FIELDS
            | {
                "kind",
                "schema_version",
                "source_bindings",
                "validation_scope",
                "identity_assurance",
                "effects",
                "plan_id",
                "plan_sha256",
            },
            "GCP binding plan",
        )
        _validate_inputs({key: raw[key] for key in _INPUT_FIELDS})
        if (
            raw["kind"] != DOMAIN
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["effects"] != _EFFECTS
            or raw["validation_scope"] != "declared_coordinates_only"
            or raw["identity_assurance"] != "operator_asserted_unsigned"
        ):
            raise GcpResourceBindingError("GCP plan metadata or effect boundary is invalid")
        sources = _exact(
            raw["source_bindings"],
            {"d014_dossier", "deployment_profile", "regional_binding"},
            "source bindings",
        )
        for name, prefix in (
            ("d014_dossier", "PDD"),
            ("deployment_profile", "DPC"),
            ("regional_binding", "TRB"),
        ):
            reference = _exact(sources[name], {"id", "sha256"}, "source reference")
            _match(reference["sha256"], _DIGEST, "source digest")
            if reference["id"] != prefix + "-" + reference["sha256"][7:39].upper():
                raise GcpResourceBindingError("Source identifier and digest do not agree")
        body = {key: value for key, value in raw.items() if key not in {"plan_id", "plan_sha256"}}
        if (raw["plan_id"], raw["plan_sha256"]) != _address(body):
            raise GcpResourceBindingError("GCP plan identity does not match its contents")
        if _canonical(raw) != self.document_json:
            raise GcpResourceBindingError("GCP plan wrapper must contain canonical JSON")
        return raw


def build_gcp_resource_binding_plan(
    inputs: dict[str, Any],
    *,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> GcpResourceBindingPlan:
    """Bind explicit coordinates to revalidated planning sources without signing or cloud access."""
    coordinates = _validate_inputs(inputs)
    body = {
        **coordinates,
        "kind": DOMAIN,
        "schema_version": 1,
        "source_bindings": _sources(dossier, deployment_profile, regional_binding),
        "validation_scope": "declared_coordinates_only",
        "identity_assurance": "operator_asserted_unsigned",
        "effects": dict(_EFFECTS),
    }
    plan_id, plan_sha256 = _address(body)
    plan = GcpResourceBindingPlan.from_dict(
        {**body, "plan_id": plan_id, "plan_sha256": plan_sha256}
    )
    verify_gcp_resource_binding_plan(
        plan,
        dossier=dossier,
        deployment_profile=deployment_profile,
        regional_binding=regional_binding,
    )
    return plan


def verify_gcp_resource_binding_plan(
    plan: GcpResourceBindingPlan,
    *,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> dict[str, Any]:
    """Check exact supplied sources and return planning-only blockers, never runtime admission."""
    if type(plan) is not GcpResourceBindingPlan:
        raise GcpResourceBindingError("An exact GCP planning record is required")
    raw = plan.to_dict()
    if raw["source_bindings"] != _sources(dossier, deployment_profile, regional_binding):
        raise GcpResourceBindingError("GCP plan does not bind the exact supplied source records")
    profile = DeploymentProfile.from_dict(deployment_profile.to_dict())
    region = TenantRegionBinding.from_dict(regional_binding.to_dict())
    blockers = {
        "authenticated_d014_selection_required",
        "provider_configuration_unverified",
        "organization_folder_billing_unbound",
        "recovery_region_unselected",
        "worker_containment_unverified",
        "production_go_no_go_required",
    }
    if not raw["service_accounts"]:
        blockers.add("service_identity_coordinates_missing")
    stores = {item["storage_ref"] for item in raw["gcs_buckets"]}
    if profile.custody_policy.evidence_store_ref not in stores:
        blockers.add("profile_evidence_store_coordinates_missing")
    encryption = {
        item["key_ref"] for item in raw["kms_key_versions"] if item["purpose"] == "ENCRYPT_DECRYPT"
    }
    if region.encryption_key_ref not in encryption:
        blockers.add("tenant_encryption_coordinates_missing")
    for bucket in raw["gcs_buckets"]:
        if bucket["encryption_key_ref"] != region.encryption_key_ref:
            raise GcpResourceBindingError(
                "Bucket encryption reference differs from the tenant binding"
            )
    if not raw["cloud_sql_instances"]:
        blockers.add("database_coordinates_missing")
    else:
        blockers.add("managed_sql_manifest_mapping_required")
    return {
        "status": "valid_for_offline_planning_only",
        "plan_id": raw["plan_id"],
        "plan_sha256": raw["plan_sha256"],
        "primary_region": PRIMARY_REGION,
        "source_integrity": "supplied_records_revalidated_not_authenticated",
        "validation_scope": "declared_coordinates_only",
        "blocker_codes": sorted(blockers),
        "effects": dict(_EFFECTS),
        "network_call_performed": False,
    }

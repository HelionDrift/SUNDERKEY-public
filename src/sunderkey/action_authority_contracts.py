"""Portable source contracts for authenticated action authority.

These records describe exact authority inputs. They do not authenticate a
principal, authorize an action, reserve budget, or dispatch an adapter.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, ClassVar

from .expert_runtime import WorkProduct, content_address_work_product
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 262_144
MAX_ACTIONS = 512
MAX_TEXT_ITEMS = 128
MAX_TEXT_LENGTH = 2_048
ACTION_TIERS = ("R0", "R1", "R2", "R3", "R4")
TIER_ORDER = MappingProxyType({tier: index for index, tier in enumerate(ACTION_TIERS)})
TARGET_ENVIRONMENTS = ("sandbox", "replica", "live")
ADAPTER_KINDS = ("http", "browser", "session", "specialist")
RESOURCE_FIELDS = (
    "money_microunits",
    "rate_units",
    "request_bytes",
    "response_bytes",
    "duration_ms",
    "impact_events",
)
MAX_SIGNED_SQLITE_INTEGER = 2**63 - 1
MAX_COMBINABLE_BYTE_AXIS = MAX_SIGNED_SQLITE_INTEGER // 2
NO_EFFECTS = MappingProxyType(
    {
        "authorization_effect": "none",
        "model_call_performed": False,
        "network_call_performed": False,
        "qualification_effect": "none",
        "target_action_performed": False,
        "tool_effect": "none",
    }
)

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/@+\-]{0,255}\Z")
_ACTION_TYPE = re.compile(r"[a-z][a-z0-9_.:\-]{0,127}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[+\-][A-Za-z0-9.\-]+)?\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_PRODUCT_ID = re.compile(r"EWP-[0-9A-F]{32}\Z")
_RUNTIME_PACK_ID = re.compile(r"ERP-[0-9A-F]{32}\Z")
_ENVELOPE_ID = re.compile(r"EEE-[0-9A-F]{32}\Z")
_PROFILE_ID = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})\Z")


class ActionAuthorityContractError(ValueError):
    """Raised when an action-authority source record is invalid."""


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _external_document(raw: Any, label: str) -> dict[str, Any]:
    if isinstance(raw, bytes):
        if len(raw) > MAX_RECORD_BYTES:
            raise ActionAuthorityContractError(f"{label} exceeds the byte ceiling")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ActionAuthorityContractError(f"{label} is not UTF-8") from exc
        return _external_document(text, label)
    if isinstance(raw, str):
        if len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise ActionAuthorityContractError(f"{label} exceeds the byte ceiling")
        try:
            raw = loads_json_without_duplicate_keys(raw)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise ActionAuthorityContractError(f"{label} is not canonical JSON") from exc
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError(f"{label} must be an object")
    value = _deep_copy(dict(raw), label)
    if len(_canonical_json(value).encode("ascii")) > MAX_RECORD_BYTES:
        raise ActionAuthorityContractError(f"{label} exceeds the byte ceiling")
    return value


def _deep_copy(value: Any, label: str) -> Any:
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is str:
        _safe_text(value, label, allow_empty=True)
        return value
    if type(value) is list:
        return [_deep_copy(item, f"{label} item") for item in value]
    if type(value) is dict:
        result: dict[str, Any] = {}
        for key, item in value.items():
            _safe_text(key, f"{label} key")
            result[key] = _deep_copy(item, f"{label}.{key}")
        return result
    raise ActionAuthorityContractError(f"{label} contains an unsupported value")


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ActionAuthorityContractError(f"{label} fields are invalid")


def _safe_text(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or len(value) > MAX_TEXT_LENGTH:
        raise ActionAuthorityContractError(f"{label} must be an exact string")
    if not value and not allow_empty:
        raise ActionAuthorityContractError(f"{label} must not be empty")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ActionAuthorityContractError(f"{label} contains a control character")
    if unicodedata.normalize("NFC", value) != value:
        raise ActionAuthorityContractError(f"{label} is not NFC normalized")
    return value


def _identifier(value: Any, label: str) -> str:
    value = _safe_text(value, label)
    if _IDENTIFIER.fullmatch(value) is None:
        raise ActionAuthorityContractError(f"{label} is not an identifier")
    return value


def _action_type(value: Any, label: str = "action_type") -> str:
    value = _safe_text(value, label)
    if _ACTION_TYPE.fullmatch(value) is None:
        raise ActionAuthorityContractError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ActionAuthorityContractError(f"{label} must be a SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise ActionAuthorityContractError(f"{label} must be a UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ActionAuthorityContractError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC:
        raise ActionAuthorityContractError(f"{label} must be UTC")
    return value


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ActionAuthorityContractError(f"{label} is outside its allowed range")
    return value


def _tier(value: Any, label: str) -> str:
    if type(value) is not str or value not in ACTION_TIERS:
        raise ActionAuthorityContractError(f"{label} must be R0 through R4")
    return value


def _version(value: Any, label: str) -> str:
    value = _safe_text(value, label)
    if _VERSION.fullmatch(value) is None:
        raise ActionAuthorityContractError(f"{label} must be an exact version")
    return value


def _strings(
    raw: Any,
    label: str,
    *,
    item_validator: Any = _safe_text,
    maximum: int = MAX_TEXT_ITEMS,
) -> tuple[str, ...]:
    if type(raw) is not list or not 1 <= len(raw) <= maximum:
        raise ActionAuthorityContractError(f"{label} must be a bounded nonempty list")
    values = tuple(item_validator(item, f"{label} item") for item in raw)
    if values != tuple(sorted(values)) or len(set(values)) != len(values):
        raise ActionAuthorityContractError(f"{label} must be sorted and unique")
    return values


def _effects(value: Any) -> None:
    if type(value) is not dict or value != dict(NO_EFFECTS):
        raise ActionAuthorityContractError("effects must declare no authority or runtime effects")
    if any(type(value[key]) is not type(expected) for key, expected in NO_EFFECTS.items()):
        raise ActionAuthorityContractError("effect value types are invalid")


def _window(value: Mapping[str, Any]) -> None:
    effective = _timestamp(value["effective_at"], "effective_at")
    expires = _timestamp(value["expires_at"], "expires_at")
    if _instant(effective) >= _instant(expires):
        raise ActionAuthorityContractError("authority expiry must follow its effective time")


def _revision(value: Mapping[str, Any]) -> None:
    revision = _integer(value["revision"], "revision", 1)
    previous = value["previous_revision_sha256"]
    if revision == 1:
        if previous is not None:
            raise ActionAuthorityContractError("initial revision must not name a predecessor")
    else:
        _sha256(previous, "previous_revision_sha256")


def _assignment(raw: Any, expected_role: str, label: str) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError(f"{label} must be an object")
    value = dict(raw)
    _exact(
        value,
        {"assertion_issuer", "principal_profile_id", "principal_subject", "role"},
        label,
    )
    if value["role"] != expected_role:
        raise ActionAuthorityContractError(f"{label} role is invalid")
    for field in ("assertion_issuer", "principal_profile_id", "principal_subject"):
        _identifier(value[field], f"{label}.{field}")
    if value["assertion_issuer"] == value["principal_subject"]:
        raise ActionAuthorityContractError(f"{label} issuer and subject must differ")
    return value


def _resources(raw: Any, label: str) -> dict[str, int]:
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError(f"{label} must be an object")
    value = dict(raw)
    _exact(value, set(RESOURCE_FIELDS), label)
    for field in RESOURCE_FIELDS:
        maximum = (
            MAX_COMBINABLE_BYTE_AXIS
            if field in {"request_bytes", "response_bytes"}
            else MAX_SIGNED_SQLITE_INTEGER
        )
        _integer(value[field], f"{label}.{field}", 1, maximum)
    return value


def _content_hash(kind: str, body: Mapping[str, Any]) -> str:
    material = _canonical_json({"domain": f"sunderkey.{kind}.v1", "record": dict(body)}).encode(
        "ascii"
    )
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _address(
    kind: str,
    body: Mapping[str, Any],
    *,
    id_field: str,
    hash_field: str,
    prefix: str,
) -> dict[str, Any]:
    clean_body = _deep_copy(dict(body), kind)
    digest = _content_hash(kind, clean_body)
    return {
        **clean_body,
        id_field: prefix + digest.removeprefix("sha256:")[:32].upper(),
        hash_field: digest,
    }


def _require_address(
    value: Mapping[str, Any],
    *,
    kind: str,
    id_field: str,
    hash_field: str,
    prefix: str,
) -> None:
    _identifier(value[id_field], id_field)
    _sha256(value[hash_field], hash_field)
    body = {key: item for key, item in value.items() if key not in {id_field, hash_field}}
    expected = _address(kind, body, id_field=id_field, hash_field=hash_field, prefix=prefix)
    if value[id_field] != expected[id_field] or value[hash_field] != expected[hash_field]:
        raise ActionAuthorityContractError(f"{kind} content address is invalid")


@dataclass(frozen=True, slots=True)
class _PortableRecord:
    document_json: str

    KIND: ClassVar[str]
    ID_FIELD: ClassVar[str]
    HASH_FIELD: ClassVar[str]
    PREFIX: ClassVar[str]

    def to_dict(self) -> dict[str, Any]:
        try:
            value = loads_json_without_duplicate_keys(self.document_json)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise ActionAuthorityContractError("stored record JSON is invalid") from exc
        if not isinstance(value, dict):
            raise ActionAuthorityContractError("stored record must be an object")
        return value

    @property
    def record_id(self) -> str:
        return self.to_dict()[self.ID_FIELD]

    @property
    def content_sha256(self) -> str:
        return self.to_dict()[self.HASH_FIELD]


@dataclass(frozen=True, slots=True)
class ActionAuthorityPolicyRevision(_PortableRecord):
    KIND: ClassVar[str] = "action_authority_policy_revision"
    ID_FIELD: ClassVar[str] = "policy_revision_id"
    HASH_FIELD: ClassVar[str] = "policy_revision_sha256"
    PREFIX: ClassVar[str] = "AAP-"

    @property
    def policy_revision_id(self) -> str:
        return self.record_id

    @property
    def policy_revision_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> ActionAuthorityPolicyRevision:
        return cls(_canonical_json(_parse_policy(raw)))


@dataclass(frozen=True, slots=True)
class AuthoritativeActionCatalogRevision(_PortableRecord):
    KIND: ClassVar[str] = "authoritative_action_catalog_revision"
    ID_FIELD: ClassVar[str] = "catalog_revision_id"
    HASH_FIELD: ClassVar[str] = "catalog_revision_sha256"
    PREFIX: ClassVar[str] = "ACR-"

    @property
    def catalog_revision_id(self) -> str:
        return self.record_id

    @property
    def catalog_revision_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> AuthoritativeActionCatalogRevision:
        return cls(_canonical_json(_parse_catalog(raw)))


@dataclass(frozen=True, slots=True)
class AuthoritativeTargetDescriptorRevision(_PortableRecord):
    KIND: ClassVar[str] = "authoritative_target_descriptor_revision"
    ID_FIELD: ClassVar[str] = "target_revision_id"
    HASH_FIELD: ClassVar[str] = "target_revision_sha256"
    PREFIX: ClassVar[str] = "ATR-"

    @property
    def target_revision_id(self) -> str:
        return self.record_id

    @property
    def target_revision_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> AuthoritativeTargetDescriptorRevision:
        return cls(_canonical_json(_parse_target(raw)))


@dataclass(frozen=True, slots=True)
class ActionBudgetPolicyRevision(_PortableRecord):
    KIND: ClassVar[str] = "action_budget_policy_revision"
    ID_FIELD: ClassVar[str] = "budget_revision_id"
    HASH_FIELD: ClassVar[str] = "budget_revision_sha256"
    PREFIX: ClassVar[str] = "ABP-"

    @property
    def budget_revision_id(self) -> str:
        return self.record_id

    @property
    def budget_revision_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> ActionBudgetPolicyRevision:
        return cls(_canonical_json(_parse_budget(raw)))


@dataclass(frozen=True, slots=True)
class ActionSafetyPolicyRevision(_PortableRecord):
    KIND: ClassVar[str] = "action_safety_policy_revision"
    ID_FIELD: ClassVar[str] = "safety_revision_id"
    HASH_FIELD: ClassVar[str] = "safety_revision_sha256"
    PREFIX: ClassVar[str] = "ASP-"

    @property
    def safety_revision_id(self) -> str:
        return self.record_id

    @property
    def safety_revision_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> ActionSafetyPolicyRevision:
        return cls(_canonical_json(_parse_safety(raw)))


@dataclass(frozen=True, slots=True)
class AuthenticatedProposalMaterialImport(_PortableRecord):
    KIND: ClassVar[str] = "authenticated_proposal_material_import"
    ID_FIELD: ClassVar[str] = "proposal_import_id"
    HASH_FIELD: ClassVar[str] = "proposal_import_sha256"
    PREFIX: ClassVar[str] = "APM-"

    @property
    def proposal_import_id(self) -> str:
        return self.record_id

    @property
    def proposal_import_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> AuthenticatedProposalMaterialImport:
        return cls(_canonical_json(_parse_proposal_import(raw)))


@dataclass(frozen=True, slots=True)
class ExactActionSourceHeadBundle(_PortableRecord):
    KIND: ClassVar[str] = "exact_action_source_head_bundle"
    ID_FIELD: ClassVar[str] = "source_bundle_id"
    HASH_FIELD: ClassVar[str] = "source_bundle_sha256"
    PREFIX: ClassVar[str] = "ASH-"

    @property
    def source_bundle_id(self) -> str:
        return self.record_id

    @property
    def source_bundle_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def from_dict(cls, raw: Any) -> ExactActionSourceHeadBundle:
        return cls(_canonical_json(_parse_source_bundle(raw)))


def _common_revision(value: Mapping[str, Any], kind: str) -> None:
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise ActionAuthorityContractError(f"{kind} schema version is invalid")
    if value["kind"] != kind:
        raise ActionAuthorityContractError(f"{kind} kind is invalid")
    for field in ("tenant_id", "mission_id", "plan_id"):
        _identifier(value[field], field)
    _revision(value)
    _window(value)
    _sha256(value["revocation_policy_sha256"], "revocation_policy_sha256")
    _effects(value["effects"])


def _parse_policy(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "action authority policy revision")
    fields = {
        "schema_version",
        "kind",
        "policy_revision_id",
        "policy_revision_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "policy_id",
        "revision",
        "previous_revision_sha256",
        "typed_resolver",
        "admission_control",
        "revocation_control",
        "effective_at",
        "expires_at",
        "revocation_policy_sha256",
        "effects",
    }
    _exact(value, fields, "action authority policy revision")
    _common_revision(value, ActionAuthorityPolicyRevision.KIND)
    _identifier(value["policy_id"], "policy_id")
    assignments = (
        _assignment(value["typed_resolver"], "typed_resolver", "typed_resolver"),
        _assignment(value["admission_control"], "admission_control", "admission_control"),
        _assignment(value["revocation_control"], "independent_control", "revocation_control"),
    )
    for field in ("principal_profile_id", "principal_subject"):
        identities = [item[field] for item in assignments]
        if len(set(identities)) != len(identities):
            raise ActionAuthorityContractError(f"authority assignments reuse {field}")
    issuers = {item["assertion_issuer"] for item in assignments}
    if any(item["principal_subject"] in issuers for item in assignments):
        raise ActionAuthorityContractError("authority assignment subject is also an issuer")
    _require_address(
        value,
        kind=ActionAuthorityPolicyRevision.KIND,
        id_field=ActionAuthorityPolicyRevision.ID_FIELD,
        hash_field=ActionAuthorityPolicyRevision.HASH_FIELD,
        prefix=ActionAuthorityPolicyRevision.PREFIX,
    )
    return value


def _catalog_entry(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError("catalog entry must be an object")
    value = dict(raw)
    fields = {
        "action_type",
        "maximum_action_tier",
        "target_kinds",
        "supported_environments",
        "parameter_schema_sha256",
        "tool_artifact_ref",
        "tool_artifact_sha256",
        "tool_exact_version",
        "adapter_kind",
        "r4_executor_supported",
    }
    _exact(value, fields, "catalog entry")
    _action_type(value["action_type"])
    maximum = _tier(value["maximum_action_tier"], "maximum_action_tier")
    _strings(value["target_kinds"], "target_kinds", item_validator=_identifier)
    environments = _strings(value["supported_environments"], "supported_environments")
    if any(item not in TARGET_ENVIRONMENTS for item in environments):
        raise ActionAuthorityContractError("catalog environment is invalid")
    _sha256(value["parameter_schema_sha256"], "parameter_schema_sha256")
    _safe_text(value["tool_artifact_ref"], "tool_artifact_ref")
    _sha256(value["tool_artifact_sha256"], "tool_artifact_sha256")
    _version(value["tool_exact_version"], "tool_exact_version")
    if value["adapter_kind"] not in ADAPTER_KINDS:
        raise ActionAuthorityContractError("adapter_kind is invalid")
    if type(value["r4_executor_supported"]) is not bool:
        raise ActionAuthorityContractError("r4_executor_supported must be boolean")
    if maximum == "R4" and not value["r4_executor_supported"]:
        raise ActionAuthorityContractError("R4 catalog entry requires explicit executor support")
    return value


def _parse_catalog(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "authoritative action catalog revision")
    fields = {
        "schema_version",
        "kind",
        "catalog_revision_id",
        "catalog_revision_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "catalog_id",
        "catalog_version",
        "registry_sha256",
        "revision",
        "previous_revision_sha256",
        "entries",
        "effective_at",
        "expires_at",
        "revocation_policy_sha256",
        "effects",
    }
    _exact(value, fields, "authoritative action catalog revision")
    _common_revision(value, AuthoritativeActionCatalogRevision.KIND)
    _identifier(value["catalog_id"], "catalog_id")
    _version(value["catalog_version"], "catalog_version")
    _sha256(value["registry_sha256"], "registry_sha256")
    entries = value["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= MAX_ACTIONS:
        raise ActionAuthorityContractError("catalog entries are invalid")
    checked = [_catalog_entry(item) for item in entries]
    keys = [item["action_type"] for item in checked]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ActionAuthorityContractError("catalog entries must be sorted and unique")
    _require_address(
        value,
        kind=AuthoritativeActionCatalogRevision.KIND,
        id_field=AuthoritativeActionCatalogRevision.ID_FIELD,
        hash_field=AuthoritativeActionCatalogRevision.HASH_FIELD,
        prefix=AuthoritativeActionCatalogRevision.PREFIX,
    )
    return value


def _parse_target(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "authoritative target descriptor revision")
    fields = {
        "schema_version",
        "kind",
        "target_revision_id",
        "target_revision_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "target_descriptor_id",
        "target_id",
        "target_sha256",
        "target_kind",
        "environment",
        "scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "allowed_action_types",
        "maximum_action_tier",
        "revision",
        "previous_revision_sha256",
        "effective_at",
        "expires_at",
        "revocation_policy_sha256",
        "effects",
    }
    _exact(value, fields, "authoritative target descriptor revision")
    _common_revision(value, AuthoritativeTargetDescriptorRevision.KIND)
    for field in ("target_descriptor_id", "target_id", "target_kind"):
        _identifier(value[field], field)
    for field in (
        "target_sha256",
        "scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
    ):
        _sha256(value[field], field)
    if value["environment"] not in TARGET_ENVIRONMENTS:
        raise ActionAuthorityContractError("target environment is invalid")
    _strings(value["allowed_action_types"], "allowed_action_types", item_validator=_action_type)
    _tier(value["maximum_action_tier"], "maximum_action_tier")
    _require_address(
        value,
        kind=AuthoritativeTargetDescriptorRevision.KIND,
        id_field=AuthoritativeTargetDescriptorRevision.ID_FIELD,
        hash_field=AuthoritativeTargetDescriptorRevision.HASH_FIELD,
        prefix=AuthoritativeTargetDescriptorRevision.PREFIX,
    )
    return value


def _parse_budget(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "action budget policy revision")
    fields = {
        "schema_version",
        "kind",
        "budget_revision_id",
        "budget_revision_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "budget_id",
        "scope_sha256",
        "limits",
        "per_action_ceiling",
        "revision",
        "previous_revision_sha256",
        "effective_at",
        "expires_at",
        "revocation_policy_sha256",
        "effects",
    }
    _exact(value, fields, "action budget policy revision")
    _common_revision(value, ActionBudgetPolicyRevision.KIND)
    _identifier(value["budget_id"], "budget_id")
    _sha256(value["scope_sha256"], "scope_sha256")
    limits = _resources(value["limits"], "limits")
    ceiling = _resources(value["per_action_ceiling"], "per_action_ceiling")
    if any(ceiling[field] > limits[field] for field in RESOURCE_FIELDS):
        raise ActionAuthorityContractError("per-action ceiling exceeds the stable budget")
    _require_address(
        value,
        kind=ActionBudgetPolicyRevision.KIND,
        id_field=ActionBudgetPolicyRevision.ID_FIELD,
        hash_field=ActionBudgetPolicyRevision.HASH_FIELD,
        prefix=ActionBudgetPolicyRevision.PREFIX,
    )
    return value


def _parse_safety(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "action safety policy revision")
    fields = {
        "schema_version",
        "kind",
        "safety_revision_id",
        "safety_revision_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "safety_policy_id",
        "scope_sha256",
        "target_sha256",
        "action_types",
        "maximum_action_tier",
        "stop_conditions",
        "impact_limits",
        "monitor",
        "deadline",
        "restoration",
        "revision",
        "previous_revision_sha256",
        "effective_at",
        "expires_at",
        "revocation_policy_sha256",
        "effects",
    }
    _exact(value, fields, "action safety policy revision")
    _common_revision(value, ActionSafetyPolicyRevision.KIND)
    _identifier(value["safety_policy_id"], "safety_policy_id")
    _sha256(value["scope_sha256"], "scope_sha256")
    _sha256(value["target_sha256"], "target_sha256")
    _strings(value["action_types"], "action_types", item_validator=_action_type)
    _tier(value["maximum_action_tier"], "maximum_action_tier")
    _strings(value["stop_conditions"], "stop_conditions")
    impact = value["impact_limits"]
    if not isinstance(impact, Mapping):
        raise ActionAuthorityContractError("impact_limits must be an object")
    impact = dict(impact)
    _exact(
        impact,
        {
            "maximum_duration_ms",
            "maximum_impact_events",
            "maximum_request_bytes",
            "maximum_response_bytes",
        },
        "impact_limits",
    )
    for field in impact:
        _integer(impact[field], f"impact_limits.{field}", 1)
    monitor = value["monitor"]
    if not isinstance(monitor, Mapping):
        raise ActionAuthorityContractError("monitor must be an object")
    monitor = dict(monitor)
    _exact(
        monitor,
        {
            "heartbeat_timeout_seconds",
            "monitor_id",
            "principal_profile_id",
            "principal_subject",
            "required",
        },
        "monitor",
    )
    for field in ("monitor_id", "principal_profile_id", "principal_subject"):
        _identifier(monitor[field], f"monitor.{field}")
    _integer(monitor["heartbeat_timeout_seconds"], "monitor.heartbeat_timeout_seconds", 1)
    if monitor["required"] is not True:
        raise ActionAuthorityContractError("a live stop monitor is required")
    deadline = value["deadline"]
    if not isinstance(deadline, Mapping):
        raise ActionAuthorityContractError("deadline must be an object")
    deadline = dict(deadline)
    _exact(deadline, {"hard_deadline_required", "maximum_duration_ms"}, "deadline")
    if deadline["hard_deadline_required"] is not True:
        raise ActionAuthorityContractError("a hard action deadline is required")
    _integer(deadline["maximum_duration_ms"], "deadline.maximum_duration_ms", 1)
    if deadline["maximum_duration_ms"] != impact["maximum_duration_ms"]:
        raise ActionAuthorityContractError("deadline and impact duration limits differ")
    restoration = value["restoration"]
    if not isinstance(restoration, Mapping):
        raise ActionAuthorityContractError("restoration must be an object")
    restoration = dict(restoration)
    _exact(
        restoration,
        {
            "completion_evidence_required",
            "owner_profile_id",
            "owner_subject",
            "required",
            "restoration_plan_sha256",
            "verifier_profile_id",
            "verifier_subject",
        },
        "restoration",
    )
    if (
        restoration["required"] is not True
        or restoration["completion_evidence_required"] is not True
    ):
        raise ActionAuthorityContractError("restoration and its evidence are required")
    _sha256(restoration["restoration_plan_sha256"], "restoration_plan_sha256")
    for field in ("owner_profile_id", "owner_subject", "verifier_profile_id", "verifier_subject"):
        _identifier(restoration[field], f"restoration.{field}")
    if (
        restoration["owner_profile_id"] == restoration["verifier_profile_id"]
        or restoration["owner_subject"] == restoration["verifier_subject"]
    ):
        raise ActionAuthorityContractError("restoration owner and verifier must be independent")
    _require_address(
        value,
        kind=ActionSafetyPolicyRevision.KIND,
        id_field=ActionSafetyPolicyRevision.ID_FIELD,
        hash_field=ActionSafetyPolicyRevision.HASH_FIELD,
        prefix=ActionSafetyPolicyRevision.PREFIX,
    )
    return value


_PRODUCT_FIELDS = {
    "schema_version",
    "product_id",
    "product_sha256",
    "product_type",
    "runtime_pack_id",
    "runtime_catalog_sha256",
    "runtime_pack_sha256",
    "producer_profile_id",
    "execution_envelope_id",
    "execution_envelope_sha256",
    "mission_id",
    "plan_id",
    "work_id",
    "summary",
    "confidence",
    "uncertainty",
    "evidence_refs",
    "lineage_product_ids",
    "independent_review",
    "payload",
    "model_output_effect",
    "tool_effect",
    "authorization_effect",
}
_PROPOSAL_PAYLOAD_FIELDS = {
    "target_scope_sha256",
    "authority_snapshot_sha256",
    "evidence_snapshot_sha256",
    "mission_id",
    "plan_id",
    "work_id",
    "requested_action_tier",
    "proposed_actions",
    "evidence_requirement_ids",
    "cleanup_requirement_ids",
    "approval_requirement_ids",
    "stop_conditions",
}


def _validated_phase188_product(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError("reviewed product must be an object")
    value = _deep_copy(dict(raw), "reviewed product")
    _exact(value, _PRODUCT_FIELDS, "reviewed product")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ActionAuthorityContractError("reviewed product schema version is invalid")
    if value["product_type"] != "action_proposal":
        raise ActionAuthorityContractError("reviewed product is not an action proposal")
    expected_patterns = {
        "product_id": _PRODUCT_ID,
        "runtime_pack_id": _RUNTIME_PACK_ID,
        "producer_profile_id": _PROFILE_ID,
        "execution_envelope_id": _ENVELOPE_ID,
    }
    for field, pattern in expected_patterns.items():
        if type(value[field]) is not str or pattern.fullmatch(value[field]) is None:
            raise ActionAuthorityContractError(f"reviewed product {field} is invalid")
    for field in ("mission_id", "plan_id", "work_id"):
        _identifier(value[field], field)
    for field in (
        "product_sha256",
        "runtime_catalog_sha256",
        "runtime_pack_sha256",
        "execution_envelope_sha256",
    ):
        _sha256(value[field], field)
    for field in ("summary", "confidence", "uncertainty"):
        _safe_text(value[field], field)
    if value["confidence"] not in {"unknown", "low", "moderate", "high"}:
        raise ActionAuthorityContractError("reviewed product confidence is invalid")
    if type(value["evidence_refs"]) is not list:
        raise ActionAuthorityContractError("evidence_refs must be a list")
    if len(value["evidence_refs"]) > 256:
        raise ActionAuthorityContractError("evidence_refs exceeds its item ceiling")
    for item in value["evidence_refs"]:
        _sha256(item, "evidence_refs item")
    if type(value["lineage_product_ids"]) is not list:
        raise ActionAuthorityContractError("lineage_product_ids must be a list")
    if len(value["lineage_product_ids"]) > 256:
        raise ActionAuthorityContractError("lineage_product_ids exceeds its item ceiling")
    for item in value["lineage_product_ids"]:
        if type(item) is not str or re.fullmatch(r"EWP-[0-9A-F]{32}", item) is None:
            raise ActionAuthorityContractError("lineage product ID is invalid")
    if len(set(value["evidence_refs"])) != len(value["evidence_refs"]):
        raise ActionAuthorityContractError("evidence_refs must be unique")
    if len(set(value["lineage_product_ids"])) != len(value["lineage_product_ids"]):
        raise ActionAuthorityContractError("lineage_product_ids must be unique")
    if type(value["independent_review"]) is not dict:
        raise ActionAuthorityContractError("independent_review must be an object")
    review = value["independent_review"]
    _exact(
        review,
        {"producer_excluded", "required", "reviewer_profile_ids", "status"},
        "independent_review",
    )
    if (
        type(review["required"]) is not bool
        or review["status"] != "not_reviewed"
        or review["reviewer_profile_ids"] != []
        or review["producer_excluded"] is not True
    ):
        raise ActionAuthorityContractError(
            "Phase188 product must retain its nonauthoritative review marker"
        )
    if (
        value["model_output_effect"] != "advisory_only"
        or value["tool_effect"] != "none"
        or value["authorization_effect"] != "none"
    ):
        raise ActionAuthorityContractError("reviewed product claims an executable effect")
    payload = value["payload"]
    if not isinstance(payload, Mapping):
        raise ActionAuthorityContractError("action proposal payload must be an object")
    payload = dict(payload)
    _exact(payload, _PROPOSAL_PAYLOAD_FIELDS, "action proposal payload")
    for field in ("target_scope_sha256", "authority_snapshot_sha256", "evidence_snapshot_sha256"):
        _sha256(payload[field], field)
    for field in ("mission_id", "plan_id", "work_id"):
        _identifier(payload[field], field)
        if payload[field] != value[field]:
            raise ActionAuthorityContractError(f"action proposal {field} binding is invalid")
    _tier(payload["requested_action_tier"], "requested_action_tier")
    for field in (
        "proposed_actions",
        "evidence_requirement_ids",
        "cleanup_requirement_ids",
        "approval_requirement_ids",
        "stop_conditions",
    ):
        if type(payload[field]) is not list or not payload[field]:
            raise ActionAuthorityContractError(f"{field} must be a nonempty list")
        if len(payload[field]) > MAX_TEXT_ITEMS:
            raise ActionAuthorityContractError(f"{field} exceeds its item ceiling")
        for item in payload[field]:
            if field == "proposed_actions":
                _action_type(item, f"{field} item")
            else:
                _safe_text(item, f"{field} item")
        if len(set(payload[field])) != len(payload[field]):
            raise ActionAuthorityContractError(f"{field} must not contain duplicates")
    body = {key: item for key, item in value.items() if key not in {"product_id", "product_sha256"}}
    try:
        expected = content_address_work_product(body)
    except Exception as exc:
        raise ActionAuthorityContractError("reviewed product address is invalid") from exc
    if (
        expected["product_id"] != value["product_id"]
        or expected["product_sha256"] != value["product_sha256"]
    ):
        raise ActionAuthorityContractError("reviewed product content address is invalid")
    return value


def _binding(raw: Any, label: str, fields: tuple[str, str]) -> dict[str, str]:
    if not isinstance(raw, Mapping):
        raise ActionAuthorityContractError(f"{label} must be an object")
    value = dict(raw)
    _exact(value, set(fields), label)
    _identifier(value[fields[0]], fields[0])
    _sha256(value[fields[1]], fields[1])
    return value


def _parse_proposal_import(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "authenticated proposal material import")
    fields = {
        "schema_version",
        "kind",
        "proposal_import_id",
        "proposal_import_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "workspace_id",
        "review_snapshot_id",
        "review_snapshot_sha256",
        "review_closure_id",
        "review_closure_sha256",
        "review_disposition",
        "reviewed_product",
        "catalog_binding",
        "target_binding",
        "parameter_set_id",
        "parameter_set_sha256",
        "parameter_schema_sha256",
        "selected_action_type",
        "requested_action_tier",
        "imported_at",
        "effects",
    }
    _exact(value, fields, "authenticated proposal material import")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ActionAuthorityContractError("proposal import schema version is invalid")
    if value["kind"] != AuthenticatedProposalMaterialImport.KIND:
        raise ActionAuthorityContractError("proposal import kind is invalid")
    for field in (
        "tenant_id",
        "mission_id",
        "plan_id",
        "workspace_id",
        "review_snapshot_id",
        "review_closure_id",
        "parameter_set_id",
    ):
        _identifier(value[field], field)
    for field in (
        "review_snapshot_sha256",
        "review_closure_sha256",
        "parameter_set_sha256",
        "parameter_schema_sha256",
    ):
        _sha256(value[field], field)
    if value["review_disposition"] != "accepted":
        raise ActionAuthorityContractError("proposal material requires an accepted review")
    product = _validated_phase188_product(value["reviewed_product"])
    if any(product[field] != value[field] for field in ("mission_id", "plan_id")):
        raise ActionAuthorityContractError("reviewed product mission binding is invalid")
    catalog = _binding(
        value["catalog_binding"],
        "catalog_binding",
        ("catalog_revision_id", "catalog_revision_sha256"),
    )
    target = _binding(
        value["target_binding"],
        "target_binding",
        ("target_revision_id", "target_revision_sha256"),
    )
    del catalog, target
    selected = _action_type(value["selected_action_type"], "selected_action_type")
    payload = product["payload"]
    if selected not in payload["proposed_actions"]:
        raise ActionAuthorityContractError("selected action type is absent from reviewed proposals")
    tier = _tier(value["requested_action_tier"], "requested_action_tier")
    if tier != payload["requested_action_tier"]:
        raise ActionAuthorityContractError("requested tier differs from the reviewed proposal")
    _timestamp(value["imported_at"], "imported_at")
    _effects(value["effects"])
    _require_address(
        value,
        kind=AuthenticatedProposalMaterialImport.KIND,
        id_field=AuthenticatedProposalMaterialImport.ID_FIELD,
        hash_field=AuthenticatedProposalMaterialImport.HASH_FIELD,
        prefix=AuthenticatedProposalMaterialImport.PREFIX,
    )
    return value


_SOURCE_BINDINGS = (
    ("action_authority_policy_revision_id", "action_authority_policy_revision_sha256"),
    ("catalog_revision_id", "catalog_revision_sha256"),
    ("target_revision_id", "target_revision_sha256"),
    ("budget_revision_id", "budget_revision_sha256"),
    ("safety_revision_id", "safety_revision_sha256"),
    ("proposal_import_id", "proposal_import_sha256"),
    ("session_authority_id", "session_authority_sha256"),
    ("execution_session_id", "execution_session_sha256"),
)


def _parse_source_bundle(raw: Any) -> dict[str, Any]:
    value = _external_document(raw, "exact action source-head bundle")
    fields = {
        "schema_version",
        "kind",
        "source_bundle_id",
        "source_bundle_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "active_plan_sha256",
        "active_plan_version",
        "mission_revision",
        "mission_policy_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "scope_revocation_head_sha256",
        "workspace_high_water_sha256",
        "review_closure_projection_sha256",
        "review_revocation_head_sha256",
        "budget_policy_binding_sequence",
        "budget_policy_binding_sha256",
        "budget_ledger_head_sha256",
        "action_authority_policy_revision_id",
        "action_authority_policy_revision_sha256",
        "catalog_revision_id",
        "catalog_revision_sha256",
        "target_revision_id",
        "target_revision_sha256",
        "budget_revision_id",
        "budget_revision_sha256",
        "safety_revision_id",
        "safety_revision_sha256",
        "proposal_import_id",
        "proposal_import_sha256",
        "session_authority_id",
        "session_authority_sha256",
        "execution_session_id",
        "execution_session_sha256",
        "owner_epoch",
        "fence_generation",
        "credential_lease_sha256",
        "health_observation_sha256",
        "executor_deployment_sha256",
        "monitor_observation_sha256",
        "observed_at",
        "valid_until",
        "effects",
    }
    _exact(value, fields, "exact action source-head bundle")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ActionAuthorityContractError("source bundle schema version is invalid")
    if value["kind"] != ExactActionSourceHeadBundle.KIND:
        raise ActionAuthorityContractError("source bundle kind is invalid")
    for field in ("tenant_id", "mission_id", "plan_id"):
        _identifier(value[field], field)
    for id_field, hash_field in _SOURCE_BINDINGS:
        _identifier(value[id_field], id_field)
        _sha256(value[hash_field], hash_field)
    for field in (
        "active_plan_sha256",
        "mission_policy_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "scope_revocation_head_sha256",
        "workspace_high_water_sha256",
        "review_closure_projection_sha256",
        "review_revocation_head_sha256",
        "budget_policy_binding_sha256",
        "budget_ledger_head_sha256",
        "credential_lease_sha256",
        "health_observation_sha256",
        "executor_deployment_sha256",
        "monitor_observation_sha256",
    ):
        _sha256(value[field], field)
    _integer(value["active_plan_version"], "active_plan_version", 1)
    _integer(value["mission_revision"], "mission_revision", 0)
    _integer(
        value["budget_policy_binding_sequence"],
        "budget_policy_binding_sequence",
        1,
    )
    _integer(value["owner_epoch"], "owner_epoch", 1)
    _integer(value["fence_generation"], "fence_generation", 1)
    observed = _timestamp(value["observed_at"], "observed_at")
    valid_until = _timestamp(value["valid_until"], "valid_until")
    if _instant(observed) >= _instant(valid_until):
        raise ActionAuthorityContractError("source bundle validity window is invalid")
    _effects(value["effects"])
    _require_address(
        value,
        kind=ExactActionSourceHeadBundle.KIND,
        id_field=ExactActionSourceHeadBundle.ID_FIELD,
        hash_field=ExactActionSourceHeadBundle.HASH_FIELD,
        prefix=ExactActionSourceHeadBundle.PREFIX,
    )
    return value


def _revision_body(
    *,
    kind: str,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    revision: int,
    previous_revision_sha256: str | None,
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "plan_id": plan_id,
        "revision": revision,
        "previous_revision_sha256": previous_revision_sha256,
        "effective_at": effective_at,
        "expires_at": expires_at,
        "revocation_policy_sha256": revocation_policy_sha256,
        "effects": dict(NO_EFFECTS),
    }


def build_action_authority_policy_revision(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    policy_id: str,
    revision: int,
    previous_revision_sha256: str | None,
    typed_resolver: Mapping[str, Any],
    admission_control: Mapping[str, Any],
    revocation_control: Mapping[str, Any],
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> ActionAuthorityPolicyRevision:
    body = {
        **_revision_body(
            kind=ActionAuthorityPolicyRevision.KIND,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            revision=revision,
            previous_revision_sha256=previous_revision_sha256,
            effective_at=effective_at,
            expires_at=expires_at,
            revocation_policy_sha256=revocation_policy_sha256,
        ),
        "policy_id": policy_id,
        "typed_resolver": dict(typed_resolver),
        "admission_control": dict(admission_control),
        "revocation_control": dict(revocation_control),
    }
    return ActionAuthorityPolicyRevision.from_dict(
        _address(
            ActionAuthorityPolicyRevision.KIND,
            body,
            id_field=ActionAuthorityPolicyRevision.ID_FIELD,
            hash_field=ActionAuthorityPolicyRevision.HASH_FIELD,
            prefix=ActionAuthorityPolicyRevision.PREFIX,
        )
    )


def build_authoritative_action_catalog_revision(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    catalog_id: str,
    catalog_version: str,
    registry_sha256: str,
    entries: Sequence[Mapping[str, Any]],
    revision: int,
    previous_revision_sha256: str | None,
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> AuthoritativeActionCatalogRevision:
    body = {
        **_revision_body(
            kind=AuthoritativeActionCatalogRevision.KIND,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            revision=revision,
            previous_revision_sha256=previous_revision_sha256,
            effective_at=effective_at,
            expires_at=expires_at,
            revocation_policy_sha256=revocation_policy_sha256,
        ),
        "catalog_id": catalog_id,
        "catalog_version": catalog_version,
        "registry_sha256": registry_sha256,
        "entries": [dict(item) for item in entries],
    }
    return AuthoritativeActionCatalogRevision.from_dict(
        _address(
            AuthoritativeActionCatalogRevision.KIND,
            body,
            id_field=AuthoritativeActionCatalogRevision.ID_FIELD,
            hash_field=AuthoritativeActionCatalogRevision.HASH_FIELD,
            prefix=AuthoritativeActionCatalogRevision.PREFIX,
        )
    )


def build_authoritative_target_descriptor_revision(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    target_descriptor_id: str,
    target_id: str,
    target_sha256: str,
    target_kind: str,
    environment: str,
    scope_sha256: str,
    authority_snapshot_sha256: str,
    evidence_snapshot_sha256: str,
    allowed_action_types: Sequence[str],
    maximum_action_tier: str,
    revision: int,
    previous_revision_sha256: str | None,
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> AuthoritativeTargetDescriptorRevision:
    body = {
        **_revision_body(
            kind=AuthoritativeTargetDescriptorRevision.KIND,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            revision=revision,
            previous_revision_sha256=previous_revision_sha256,
            effective_at=effective_at,
            expires_at=expires_at,
            revocation_policy_sha256=revocation_policy_sha256,
        ),
        "target_descriptor_id": target_descriptor_id,
        "target_id": target_id,
        "target_sha256": target_sha256,
        "target_kind": target_kind,
        "environment": environment,
        "scope_sha256": scope_sha256,
        "authority_snapshot_sha256": authority_snapshot_sha256,
        "evidence_snapshot_sha256": evidence_snapshot_sha256,
        "allowed_action_types": list(allowed_action_types),
        "maximum_action_tier": maximum_action_tier,
    }
    return AuthoritativeTargetDescriptorRevision.from_dict(
        _address(
            AuthoritativeTargetDescriptorRevision.KIND,
            body,
            id_field=AuthoritativeTargetDescriptorRevision.ID_FIELD,
            hash_field=AuthoritativeTargetDescriptorRevision.HASH_FIELD,
            prefix=AuthoritativeTargetDescriptorRevision.PREFIX,
        )
    )


def build_action_budget_policy_revision(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    budget_id: str,
    scope_sha256: str,
    limits: Mapping[str, int],
    per_action_ceiling: Mapping[str, int],
    revision: int,
    previous_revision_sha256: str | None,
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> ActionBudgetPolicyRevision:
    body = {
        **_revision_body(
            kind=ActionBudgetPolicyRevision.KIND,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            revision=revision,
            previous_revision_sha256=previous_revision_sha256,
            effective_at=effective_at,
            expires_at=expires_at,
            revocation_policy_sha256=revocation_policy_sha256,
        ),
        "budget_id": budget_id,
        "scope_sha256": scope_sha256,
        "limits": dict(limits),
        "per_action_ceiling": dict(per_action_ceiling),
    }
    return ActionBudgetPolicyRevision.from_dict(
        _address(
            ActionBudgetPolicyRevision.KIND,
            body,
            id_field=ActionBudgetPolicyRevision.ID_FIELD,
            hash_field=ActionBudgetPolicyRevision.HASH_FIELD,
            prefix=ActionBudgetPolicyRevision.PREFIX,
        )
    )


def build_action_safety_policy_revision(
    *,
    tenant_id: str,
    mission_id: str,
    plan_id: str,
    safety_policy_id: str,
    scope_sha256: str,
    target_sha256: str,
    action_types: Sequence[str],
    maximum_action_tier: str,
    stop_conditions: Sequence[str],
    impact_limits: Mapping[str, int],
    monitor: Mapping[str, Any],
    deadline: Mapping[str, Any],
    restoration: Mapping[str, Any],
    revision: int,
    previous_revision_sha256: str | None,
    effective_at: str,
    expires_at: str,
    revocation_policy_sha256: str,
) -> ActionSafetyPolicyRevision:
    body = {
        **_revision_body(
            kind=ActionSafetyPolicyRevision.KIND,
            tenant_id=tenant_id,
            mission_id=mission_id,
            plan_id=plan_id,
            revision=revision,
            previous_revision_sha256=previous_revision_sha256,
            effective_at=effective_at,
            expires_at=expires_at,
            revocation_policy_sha256=revocation_policy_sha256,
        ),
        "safety_policy_id": safety_policy_id,
        "scope_sha256": scope_sha256,
        "target_sha256": target_sha256,
        "action_types": list(action_types),
        "maximum_action_tier": maximum_action_tier,
        "stop_conditions": list(stop_conditions),
        "impact_limits": dict(impact_limits),
        "monitor": dict(monitor),
        "deadline": dict(deadline),
        "restoration": dict(restoration),
    }
    return ActionSafetyPolicyRevision.from_dict(
        _address(
            ActionSafetyPolicyRevision.KIND,
            body,
            id_field=ActionSafetyPolicyRevision.ID_FIELD,
            hash_field=ActionSafetyPolicyRevision.HASH_FIELD,
            prefix=ActionSafetyPolicyRevision.PREFIX,
        )
    )


def build_authenticated_proposal_material_import(
    *,
    product: WorkProduct,
    tenant_id: str,
    workspace_id: str,
    review_snapshot_id: str,
    review_snapshot_sha256: str,
    review_closure_id: str,
    review_closure_sha256: str,
    catalog: AuthoritativeActionCatalogRevision,
    target: AuthoritativeTargetDescriptorRevision,
    parameter_set_id: str,
    parameter_set_sha256: str,
    selected_action_type: str,
    requested_action_tier: str,
    imported_at: str,
) -> AuthenticatedProposalMaterialImport:
    if type(product) is not WorkProduct:
        raise ActionAuthorityContractError("a validated Phase188 WorkProduct is required")
    if type(catalog) is not AuthoritativeActionCatalogRevision:
        raise ActionAuthorityContractError("an authoritative catalog revision is required")
    if type(target) is not AuthoritativeTargetDescriptorRevision:
        raise ActionAuthorityContractError("an authoritative target revision is required")
    product_doc = _validated_phase188_product(product.to_dict())
    catalog_doc = catalog.to_dict()
    target_doc = target.to_dict()
    expected = {
        "tenant_id": tenant_id,
        "mission_id": product_doc["mission_id"],
        "plan_id": product_doc["plan_id"],
    }
    if any(
        catalog_doc[field] != item or target_doc[field] != item for field, item in expected.items()
    ):
        raise ActionAuthorityContractError("proposal source records cross an authority boundary")
    entry = next(
        (item for item in catalog_doc["entries"] if item["action_type"] == selected_action_type),
        None,
    )
    if entry is None or selected_action_type not in target_doc["allowed_action_types"]:
        raise ActionAuthorityContractError(
            "selected action is absent from catalog or target authority"
        )
    if target_doc["target_kind"] not in entry["target_kinds"]:
        raise ActionAuthorityContractError("catalog entry does not support the target kind")
    if target_doc["environment"] not in entry["supported_environments"]:
        raise ActionAuthorityContractError("catalog entry does not support the target environment")
    tier = _tier(requested_action_tier, "requested_action_tier")
    if (
        TIER_ORDER[tier] > TIER_ORDER[entry["maximum_action_tier"]]
        or TIER_ORDER[tier] > TIER_ORDER[target_doc["maximum_action_tier"]]
    ):
        raise ActionAuthorityContractError("requested tier exceeds catalog or target authority")
    payload = product_doc["payload"]
    if (
        payload["target_scope_sha256"] != target_doc["scope_sha256"]
        or payload["authority_snapshot_sha256"] != target_doc["authority_snapshot_sha256"]
        or payload["evidence_snapshot_sha256"] != target_doc["evidence_snapshot_sha256"]
    ):
        raise ActionAuthorityContractError("reviewed proposal target lineage is stale")
    imported = _timestamp(imported_at, "imported_at")
    for source in (catalog_doc, target_doc):
        if not (
            _instant(source["effective_at"]) <= _instant(imported) < _instant(source["expires_at"])
        ):
            raise ActionAuthorityContractError(
                "proposal import does not fall within its source authority window"
            )
    body = {
        "schema_version": 1,
        "kind": AuthenticatedProposalMaterialImport.KIND,
        "tenant_id": tenant_id,
        "mission_id": product_doc["mission_id"],
        "plan_id": product_doc["plan_id"],
        "workspace_id": workspace_id,
        "review_snapshot_id": review_snapshot_id,
        "review_snapshot_sha256": review_snapshot_sha256,
        "review_closure_id": review_closure_id,
        "review_closure_sha256": review_closure_sha256,
        "review_disposition": "accepted",
        "reviewed_product": product_doc,
        "catalog_binding": {
            "catalog_revision_id": catalog.catalog_revision_id,
            "catalog_revision_sha256": catalog.catalog_revision_sha256,
        },
        "target_binding": {
            "target_revision_id": target.target_revision_id,
            "target_revision_sha256": target.target_revision_sha256,
        },
        "parameter_set_id": parameter_set_id,
        "parameter_set_sha256": parameter_set_sha256,
        "parameter_schema_sha256": entry["parameter_schema_sha256"],
        "selected_action_type": selected_action_type,
        "requested_action_tier": tier,
        "imported_at": imported,
        "effects": dict(NO_EFFECTS),
    }
    return AuthenticatedProposalMaterialImport.from_dict(
        _address(
            AuthenticatedProposalMaterialImport.KIND,
            body,
            id_field=AuthenticatedProposalMaterialImport.ID_FIELD,
            hash_field=AuthenticatedProposalMaterialImport.HASH_FIELD,
            prefix=AuthenticatedProposalMaterialImport.PREFIX,
        )
    )


def build_exact_action_source_head_bundle(
    *,
    policy: ActionAuthorityPolicyRevision,
    catalog: AuthoritativeActionCatalogRevision,
    target: AuthoritativeTargetDescriptorRevision,
    budget: ActionBudgetPolicyRevision,
    safety: ActionSafetyPolicyRevision,
    proposal: AuthenticatedProposalMaterialImport,
    active_plan_sha256: str,
    active_plan_version: int,
    mission_revision: int,
    mission_policy_sha256: str,
    trust_policy_sha256: str,
    scope_grant_sha256: str,
    scope_revocation_head_sha256: str,
    workspace_high_water_sha256: str,
    review_closure_projection_sha256: str,
    review_revocation_head_sha256: str,
    budget_policy_binding_sequence: int,
    budget_policy_binding_sha256: str,
    budget_ledger_head_sha256: str,
    session_authority_id: str,
    session_authority_sha256: str,
    execution_session_id: str,
    execution_session_sha256: str,
    owner_epoch: int,
    fence_generation: int,
    credential_lease_sha256: str,
    health_observation_sha256: str,
    executor_deployment_sha256: str,
    monitor_observation_sha256: str,
    observed_at: str,
    valid_until: str,
) -> ExactActionSourceHeadBundle:
    records = (policy, catalog, target, budget, safety)
    expected_types = (
        ActionAuthorityPolicyRevision,
        AuthoritativeActionCatalogRevision,
        AuthoritativeTargetDescriptorRevision,
        ActionBudgetPolicyRevision,
        ActionSafetyPolicyRevision,
    )
    if any(
        type(record) is not expected
        for record, expected in zip(records, expected_types, strict=True)
    ):
        raise ActionAuthorityContractError("source bundle contains a noncanonical revision")
    if type(proposal) is not AuthenticatedProposalMaterialImport:
        raise ActionAuthorityContractError("source bundle proposal import is invalid")
    documents = [record.to_dict() for record in records]
    proposal_doc = proposal.to_dict()
    boundary = {
        "tenant_id": documents[0]["tenant_id"],
        "mission_id": documents[0]["mission_id"],
        "plan_id": documents[0]["plan_id"],
    }
    if any(
        any(document[field] != item for field, item in boundary.items())
        for document in documents[1:]
    ):
        raise ActionAuthorityContractError("source revisions cross an authority boundary")
    if any(proposal_doc[field] != item for field, item in boundary.items()):
        raise ActionAuthorityContractError("proposal import crosses the source boundary")
    if (
        proposal_doc["catalog_binding"]["catalog_revision_id"] != catalog.catalog_revision_id
        or proposal_doc["target_binding"]["target_revision_id"] != target.target_revision_id
        or proposal_doc["catalog_binding"]["catalog_revision_sha256"]
        != catalog.catalog_revision_sha256
        or proposal_doc["target_binding"]["target_revision_sha256"] != target.target_revision_sha256
    ):
        raise ActionAuthorityContractError("proposal import uses stale catalog or target authority")
    action_type = proposal_doc["selected_action_type"]
    tier = proposal_doc["requested_action_tier"]
    catalog_doc, target_doc, budget_doc, safety_doc = (
        catalog.to_dict(),
        target.to_dict(),
        budget.to_dict(),
        safety.to_dict(),
    )
    entry = next(
        (item for item in catalog_doc["entries"] if item["action_type"] == action_type),
        None,
    )
    if entry is None or action_type not in target_doc["allowed_action_types"]:
        raise ActionAuthorityContractError(
            "selected action lacks current catalog or target authority"
        )
    if (
        target_doc["target_kind"] not in entry["target_kinds"]
        or target_doc["environment"] not in entry["supported_environments"]
    ):
        raise ActionAuthorityContractError("catalog entry does not cover the current target")
    if action_type not in safety_doc["action_types"]:
        raise ActionAuthorityContractError("safety policy does not cover the selected action")
    if any(
        TIER_ORDER[tier] > TIER_ORDER[maximum]
        for maximum in (
            entry["maximum_action_tier"],
            target_doc["maximum_action_tier"],
            safety_doc["maximum_action_tier"],
        )
    ):
        raise ActionAuthorityContractError("selected tier exceeds a current source policy")
    if (
        budget_doc["scope_sha256"] != target_doc["scope_sha256"]
        or safety_doc["scope_sha256"] != target_doc["scope_sha256"]
        or safety_doc["target_sha256"] != target_doc["target_sha256"]
    ):
        raise ActionAuthorityContractError("budget or safety policy crosses the target boundary")
    observed = _timestamp(observed_at, "observed_at")
    valid = _timestamp(valid_until, "valid_until")
    if _instant(observed) >= _instant(valid):
        raise ActionAuthorityContractError("source bundle validity window is invalid")
    if _instant(proposal_doc["imported_at"]) > _instant(observed):
        raise ActionAuthorityContractError("proposal import occurs after source observation")
    for document in documents:
        if not (
            _instant(document["effective_at"])
            <= _instant(observed)
            < _instant(document["expires_at"])
        ):
            raise ActionAuthorityContractError("a source revision is not current at observation")
        if _instant(valid) > _instant(document["expires_at"]):
            raise ActionAuthorityContractError("source bundle outlives a source revision")
    body = {
        "schema_version": 1,
        "kind": ExactActionSourceHeadBundle.KIND,
        **boundary,
        "active_plan_sha256": active_plan_sha256,
        "active_plan_version": active_plan_version,
        "mission_revision": mission_revision,
        "mission_policy_sha256": mission_policy_sha256,
        "trust_policy_sha256": trust_policy_sha256,
        "scope_grant_sha256": scope_grant_sha256,
        "scope_revocation_head_sha256": scope_revocation_head_sha256,
        "workspace_high_water_sha256": workspace_high_water_sha256,
        "review_closure_projection_sha256": review_closure_projection_sha256,
        "review_revocation_head_sha256": review_revocation_head_sha256,
        "budget_policy_binding_sequence": budget_policy_binding_sequence,
        "budget_policy_binding_sha256": budget_policy_binding_sha256,
        "budget_ledger_head_sha256": budget_ledger_head_sha256,
        "action_authority_policy_revision_id": policy.policy_revision_id,
        "action_authority_policy_revision_sha256": policy.policy_revision_sha256,
        "catalog_revision_id": catalog.catalog_revision_id,
        "catalog_revision_sha256": catalog.catalog_revision_sha256,
        "target_revision_id": target.target_revision_id,
        "target_revision_sha256": target.target_revision_sha256,
        "budget_revision_id": budget.budget_revision_id,
        "budget_revision_sha256": budget.budget_revision_sha256,
        "safety_revision_id": safety.safety_revision_id,
        "safety_revision_sha256": safety.safety_revision_sha256,
        "proposal_import_id": proposal.proposal_import_id,
        "proposal_import_sha256": proposal.proposal_import_sha256,
        "session_authority_id": session_authority_id,
        "session_authority_sha256": session_authority_sha256,
        "execution_session_id": execution_session_id,
        "execution_session_sha256": execution_session_sha256,
        "owner_epoch": owner_epoch,
        "fence_generation": fence_generation,
        "credential_lease_sha256": credential_lease_sha256,
        "health_observation_sha256": health_observation_sha256,
        "executor_deployment_sha256": executor_deployment_sha256,
        "monitor_observation_sha256": monitor_observation_sha256,
        "observed_at": observed,
        "valid_until": valid,
        "effects": dict(NO_EFFECTS),
    }
    return ExactActionSourceHeadBundle.from_dict(
        _address(
            ExactActionSourceHeadBundle.KIND,
            body,
            id_field=ExactActionSourceHeadBundle.ID_FIELD,
            hash_field=ExactActionSourceHeadBundle.HASH_FIELD,
            prefix=ExactActionSourceHeadBundle.PREFIX,
        )
    )


RECORD_TYPES = MappingProxyType(
    {
        ActionAuthorityPolicyRevision.KIND: ActionAuthorityPolicyRevision,
        AuthoritativeActionCatalogRevision.KIND: AuthoritativeActionCatalogRevision,
        AuthoritativeTargetDescriptorRevision.KIND: AuthoritativeTargetDescriptorRevision,
        ActionBudgetPolicyRevision.KIND: ActionBudgetPolicyRevision,
        ActionSafetyPolicyRevision.KIND: ActionSafetyPolicyRevision,
        AuthenticatedProposalMaterialImport.KIND: AuthenticatedProposalMaterialImport,
        ExactActionSourceHeadBundle.KIND: ExactActionSourceHeadBundle,
    }
)


def parse_action_authority_contract(raw: Any) -> _PortableRecord:
    value = _external_document(raw, "action authority contract")
    record_type = RECORD_TYPES.get(value.get("kind"))
    if record_type is None:
        raise ActionAuthorityContractError("action authority contract kind is invalid")
    return record_type.from_dict(value)


def _object_schema(properties: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(properties),
        "properties": dict(properties),
    }


def _base_revision_schema(kind: str, id_field: str, hash_field: str) -> dict[str, Any]:
    return {
        "schema_version": {"const": 1},
        "kind": {"const": kind},
        id_field: {"$ref": "#/$defs/identifier"},
        hash_field: {"$ref": "#/$defs/sha256"},
        "tenant_id": {"$ref": "#/$defs/identifier"},
        "mission_id": {"$ref": "#/$defs/identifier"},
        "plan_id": {"$ref": "#/$defs/identifier"},
        "revision": {"type": "integer", "minimum": 1},
        "previous_revision_sha256": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/sha256"}]},
        "effective_at": {"$ref": "#/$defs/timestamp"},
        "expires_at": {"$ref": "#/$defs/timestamp"},
        "revocation_policy_sha256": {"$ref": "#/$defs/sha256"},
        "effects": {"$ref": "#/$defs/effects"},
    }


def _binding_schema(id_field: str, hash_field: str) -> dict[str, Any]:
    return _object_schema(
        {
            id_field: {"$ref": "#/$defs/identifier"},
            hash_field: {"$ref": "#/$defs/sha256"},
        }
    )


def action_authority_contracts_schema() -> dict[str, Any]:
    string_array = {
        "type": "array",
        "minItems": 1,
        "maxItems": MAX_TEXT_ITEMS,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/text"},
    }
    action_array = {
        **string_array,
        "items": {"$ref": "#/$defs/action_type"},
    }

    def assignment(role: str) -> dict[str, Any]:
        return _object_schema(
            {
                "role": {"const": role},
                "principal_profile_id": {"$ref": "#/$defs/identifier"},
                "principal_subject": {"$ref": "#/$defs/identifier"},
                "assertion_issuer": {"$ref": "#/$defs/identifier"},
            }
        )

    resources = _object_schema(
        {
            field: {
                "type": "integer",
                "minimum": 1,
                "maximum": (
                    MAX_COMBINABLE_BYTE_AXIS
                    if field in {"request_bytes", "response_bytes"}
                    else MAX_SIGNED_SQLITE_INTEGER
                ),
            }
            for field in RESOURCE_FIELDS
        }
    )
    policy = _object_schema(
        {
            **_base_revision_schema(
                ActionAuthorityPolicyRevision.KIND,
                ActionAuthorityPolicyRevision.ID_FIELD,
                ActionAuthorityPolicyRevision.HASH_FIELD,
            ),
            "policy_id": {"$ref": "#/$defs/identifier"},
            "typed_resolver": assignment("typed_resolver"),
            "admission_control": assignment("admission_control"),
            "revocation_control": assignment("independent_control"),
        }
    )
    entry = _object_schema(
        {
            "action_type": {"$ref": "#/$defs/action_type"},
            "maximum_action_tier": {"$ref": "#/$defs/tier"},
            "target_kinds": string_array,
            "supported_environments": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"enum": list(TARGET_ENVIRONMENTS)},
            },
            "parameter_schema_sha256": {"$ref": "#/$defs/sha256"},
            "tool_artifact_ref": {"$ref": "#/$defs/text"},
            "tool_artifact_sha256": {"$ref": "#/$defs/sha256"},
            "tool_exact_version": {"$ref": "#/$defs/version"},
            "adapter_kind": {"enum": list(ADAPTER_KINDS)},
            "r4_executor_supported": {"type": "boolean"},
        }
    )
    catalog = _object_schema(
        {
            **_base_revision_schema(
                AuthoritativeActionCatalogRevision.KIND,
                AuthoritativeActionCatalogRevision.ID_FIELD,
                AuthoritativeActionCatalogRevision.HASH_FIELD,
            ),
            "catalog_id": {"$ref": "#/$defs/identifier"},
            "catalog_version": {"$ref": "#/$defs/version"},
            "registry_sha256": {"$ref": "#/$defs/sha256"},
            "entries": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_ACTIONS,
                "items": entry,
            },
        }
    )
    target = _object_schema(
        {
            **_base_revision_schema(
                AuthoritativeTargetDescriptorRevision.KIND,
                AuthoritativeTargetDescriptorRevision.ID_FIELD,
                AuthoritativeTargetDescriptorRevision.HASH_FIELD,
            ),
            "target_descriptor_id": {"$ref": "#/$defs/identifier"},
            "target_id": {"$ref": "#/$defs/identifier"},
            "target_sha256": {"$ref": "#/$defs/sha256"},
            "target_kind": {"$ref": "#/$defs/identifier"},
            "environment": {"enum": list(TARGET_ENVIRONMENTS)},
            "scope_sha256": {"$ref": "#/$defs/sha256"},
            "authority_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "evidence_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "allowed_action_types": action_array,
            "maximum_action_tier": {"$ref": "#/$defs/tier"},
        }
    )
    budget = _object_schema(
        {
            **_base_revision_schema(
                ActionBudgetPolicyRevision.KIND,
                ActionBudgetPolicyRevision.ID_FIELD,
                ActionBudgetPolicyRevision.HASH_FIELD,
            ),
            "budget_id": {"$ref": "#/$defs/identifier"},
            "scope_sha256": {"$ref": "#/$defs/sha256"},
            "limits": resources,
            "per_action_ceiling": resources,
        }
    )
    monitor = _object_schema(
        {
            "monitor_id": {"$ref": "#/$defs/identifier"},
            "principal_profile_id": {"$ref": "#/$defs/identifier"},
            "principal_subject": {"$ref": "#/$defs/identifier"},
            "heartbeat_timeout_seconds": {"type": "integer", "minimum": 1},
            "required": {"const": True},
        }
    )
    deadline = _object_schema(
        {
            "hard_deadline_required": {"const": True},
            "maximum_duration_ms": {"type": "integer", "minimum": 1},
        }
    )
    restoration = _object_schema(
        {
            "required": {"const": True},
            "restoration_plan_sha256": {"$ref": "#/$defs/sha256"},
            "owner_profile_id": {"$ref": "#/$defs/identifier"},
            "owner_subject": {"$ref": "#/$defs/identifier"},
            "verifier_profile_id": {"$ref": "#/$defs/identifier"},
            "verifier_subject": {"$ref": "#/$defs/identifier"},
            "completion_evidence_required": {"const": True},
        }
    )
    safety = _object_schema(
        {
            **_base_revision_schema(
                ActionSafetyPolicyRevision.KIND,
                ActionSafetyPolicyRevision.ID_FIELD,
                ActionSafetyPolicyRevision.HASH_FIELD,
            ),
            "safety_policy_id": {"$ref": "#/$defs/identifier"},
            "scope_sha256": {"$ref": "#/$defs/sha256"},
            "target_sha256": {"$ref": "#/$defs/sha256"},
            "action_types": action_array,
            "maximum_action_tier": {"$ref": "#/$defs/tier"},
            "stop_conditions": string_array,
            "impact_limits": _object_schema(
                {
                    "maximum_duration_ms": {"type": "integer", "minimum": 1},
                    "maximum_impact_events": {"type": "integer", "minimum": 1},
                    "maximum_request_bytes": {"type": "integer", "minimum": 1},
                    "maximum_response_bytes": {"type": "integer", "minimum": 1},
                }
            ),
            "monitor": monitor,
            "deadline": deadline,
            "restoration": restoration,
        }
    )
    product_payload = _object_schema(
        {
            "target_scope_sha256": {"$ref": "#/$defs/sha256"},
            "authority_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "evidence_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "mission_id": {"$ref": "#/$defs/identifier"},
            "plan_id": {"$ref": "#/$defs/identifier"},
            "work_id": {"$ref": "#/$defs/identifier"},
            "requested_action_tier": {"$ref": "#/$defs/tier"},
            "proposed_actions": action_array,
            "evidence_requirement_ids": string_array,
            "cleanup_requirement_ids": string_array,
            "approval_requirement_ids": string_array,
            "stop_conditions": string_array,
        }
    )
    product = _object_schema(
        {
            "schema_version": {"const": 1},
            "product_id": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
            "product_sha256": {"$ref": "#/$defs/sha256"},
            "product_type": {"const": "action_proposal"},
            "runtime_pack_id": {"type": "string", "pattern": r"^ERP-[0-9A-F]{32}$"},
            "runtime_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "runtime_pack_sha256": {"$ref": "#/$defs/sha256"},
            "producer_profile_id": {
                "type": "string",
                "pattern": r"^AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})$",
            },
            "execution_envelope_id": {
                "type": "string",
                "pattern": r"^EEE-[0-9A-F]{32}$",
            },
            "execution_envelope_sha256": {"$ref": "#/$defs/sha256"},
            "mission_id": {"$ref": "#/$defs/identifier"},
            "plan_id": {"$ref": "#/$defs/identifier"},
            "work_id": {"$ref": "#/$defs/identifier"},
            "summary": {"$ref": "#/$defs/text"},
            "confidence": {"enum": ["unknown", "low", "moderate", "high"]},
            "uncertainty": {"$ref": "#/$defs/text"},
            "evidence_refs": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/sha256"},
            },
            "lineage_product_ids": {
                "type": "array",
                "maxItems": 256,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
            },
            "independent_review": _object_schema(
                {
                    "required": {"type": "boolean"},
                    "status": {"const": "not_reviewed"},
                    "reviewer_profile_ids": {"const": []},
                    "producer_excluded": {"const": True},
                }
            ),
            "payload": product_payload,
            "model_output_effect": {"const": "advisory_only"},
            "tool_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
        }
    )
    proposal_import = _object_schema(
        {
            "schema_version": {"const": 1},
            "kind": {"const": AuthenticatedProposalMaterialImport.KIND},
            "proposal_import_id": {"$ref": "#/$defs/identifier"},
            "proposal_import_sha256": {"$ref": "#/$defs/sha256"},
            "tenant_id": {"$ref": "#/$defs/identifier"},
            "mission_id": {"$ref": "#/$defs/identifier"},
            "plan_id": {"$ref": "#/$defs/identifier"},
            "workspace_id": {"$ref": "#/$defs/identifier"},
            "review_snapshot_id": {"$ref": "#/$defs/identifier"},
            "review_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "review_closure_id": {"$ref": "#/$defs/identifier"},
            "review_closure_sha256": {"$ref": "#/$defs/sha256"},
            "review_disposition": {"const": "accepted"},
            "reviewed_product": product,
            "catalog_binding": _binding_schema("catalog_revision_id", "catalog_revision_sha256"),
            "target_binding": _binding_schema("target_revision_id", "target_revision_sha256"),
            "parameter_set_id": {"$ref": "#/$defs/identifier"},
            "parameter_set_sha256": {"$ref": "#/$defs/sha256"},
            "parameter_schema_sha256": {"$ref": "#/$defs/sha256"},
            "selected_action_type": {"$ref": "#/$defs/action_type"},
            "requested_action_tier": {"$ref": "#/$defs/tier"},
            "imported_at": {"$ref": "#/$defs/timestamp"},
            "effects": {"$ref": "#/$defs/effects"},
        }
    )
    source_properties: dict[str, Any] = {
        "schema_version": {"const": 1},
        "kind": {"const": ExactActionSourceHeadBundle.KIND},
        "source_bundle_id": {"$ref": "#/$defs/identifier"},
        "source_bundle_sha256": {"$ref": "#/$defs/sha256"},
        "tenant_id": {"$ref": "#/$defs/identifier"},
        "mission_id": {"$ref": "#/$defs/identifier"},
        "plan_id": {"$ref": "#/$defs/identifier"},
        "active_plan_sha256": {"$ref": "#/$defs/sha256"},
        "active_plan_version": {"type": "integer", "minimum": 1},
        "mission_revision": {"type": "integer", "minimum": 0},
        "owner_epoch": {"type": "integer", "minimum": 1},
        "fence_generation": {"type": "integer", "minimum": 1},
        "observed_at": {"$ref": "#/$defs/timestamp"},
        "valid_until": {"$ref": "#/$defs/timestamp"},
        "effects": {"$ref": "#/$defs/effects"},
    }
    for id_field, hash_field in _SOURCE_BINDINGS:
        source_properties[id_field] = {"$ref": "#/$defs/identifier"}
        source_properties[hash_field] = {"$ref": "#/$defs/sha256"}
    for field in (
        "mission_policy_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "scope_revocation_head_sha256",
        "workspace_high_water_sha256",
        "review_closure_projection_sha256",
        "review_revocation_head_sha256",
        "budget_policy_binding_sha256",
        "budget_ledger_head_sha256",
        "credential_lease_sha256",
        "health_observation_sha256",
        "executor_deployment_sha256",
        "monitor_observation_sha256",
    ):
        source_properties[field] = {"$ref": "#/$defs/sha256"}
    source_properties["budget_policy_binding_sequence"] = {
        "type": "integer",
        "minimum": 1,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.local/schemas/action-authority-contracts-v1.schema.json",
        "title": "SUNDERKEY action authority source contracts",
        "$defs": {
            "sha256": {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"},
            "identifier": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9:._/@+\-]{0,255}$"},
            "action_type": {"type": "string", "pattern": r"^[a-z][a-z0-9_.:\-]{0,127}$"},
            "version": {
                "type": "string",
                "pattern": r"^[0-9]+\.[0-9]+\.[0-9]+(?:[+\-][A-Za-z0-9.\-]+)?$",
            },
            "timestamp": {
                "type": "string",
                "pattern": r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
            },
            "tier": {"type": "string", "enum": list(ACTION_TIERS)},
            "text": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_LENGTH},
            "effects": _object_schema(
                {
                    "authorization_effect": {"const": "none"},
                    "model_call_performed": {"const": False},
                    "network_call_performed": {"const": False},
                    "qualification_effect": {"const": "none"},
                    "target_action_performed": {"const": False},
                    "tool_effect": {"const": "none"},
                }
            ),
        },
        "oneOf": [
            policy,
            catalog,
            target,
            budget,
            safety,
            proposal_import,
            _object_schema(source_properties),
        ],
    }


def record_schema(kind: str) -> dict[str, Any]:
    schema = action_authority_contracts_schema()
    for variant in schema["oneOf"]:
        if variant["properties"]["kind"].get("const") == kind:
            return {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                **variant,
            }
    raise ActionAuthorityContractError("schema kind is invalid")


__all__ = [
    "ACTION_TIERS",
    "RESOURCE_FIELDS",
    "ActionAuthorityContractError",
    "ActionAuthorityPolicyRevision",
    "ActionBudgetPolicyRevision",
    "ActionSafetyPolicyRevision",
    "AuthenticatedProposalMaterialImport",
    "AuthoritativeActionCatalogRevision",
    "AuthoritativeTargetDescriptorRevision",
    "ExactActionSourceHeadBundle",
    "action_authority_contracts_schema",
    "build_action_authority_policy_revision",
    "build_action_budget_policy_revision",
    "build_action_safety_policy_revision",
    "build_authenticated_proposal_material_import",
    "build_authoritative_action_catalog_revision",
    "build_authoritative_target_descriptor_revision",
    "build_exact_action_source_head_bundle",
    "parse_action_authority_contract",
    "record_schema",
]

"""Portable typed action resolution and admission evidence records.

Model-authored proposal prose is evidence for review only. This module never
interprets that prose as an action, parameter, target, approval, or authority.
It resolves only independently supplied typed records against an immutable
executable-action catalog and reconstructs the Phase 165 admission request.
Portable records never establish current authority. Durable authenticated
admission is available only through ``AuthenticatedActionAdmissionService``.
No function in this module dispatches, executes, contacts, or changes a target.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Protocol

from .action_admission_contracts import (
    ActionAdmissionRequest,
    AdmissionStatus,
    ApprovalBinding,
    ArtifactBinding,
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    EvidenceObligation,
    HealthEvidence,
    RequestedAction,
    RestorationDuties,
    StopConditions,
    TargetBinding,
    TargetEnvironment,
    WorkerSession,
    evaluate_action_admission,
)
from .action_admission_contracts import ActionTier as LegacyActionTier
from .errors import StoreError
from .expert_review import (
    ClosureDisposition,
    ExpertReviewRecordSet,
    verify_expert_review_record_set,
)
from .qualification import _canonical_json, _canonical_sha256
from .registry import ExpertRegistry
from .validation import DuplicateJsonKeyError, loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 8_388_608
MAX_ACTIONS = 4096
MAX_PARAMETERS = 128
MAX_TEXT_LENGTH = 16_384

CATALOG_DOMAIN = "sunderkey.executable-action-catalog.v1"
PARAMETER_SET_DOMAIN = "sunderkey.action-parameter-set.v1"
TARGET_DOMAIN = "sunderkey.target-action-descriptor.v1"
RESOLUTION_DOMAIN = "sunderkey.action-proposal-resolution.v1"
QUORUM_DOMAIN = "sunderkey.action-authorization-quorum.v1"
RECEIPT_DOMAIN = "sunderkey.authenticated-action-admission-receipt.v1"
REVOCATION_DOMAIN = "sunderkey.action-admission-revocation.v1"
ACTION_DOMAIN = "sunderkey.resolved-action.v1"
PARAMETER_CONTRACT_DOMAIN = "sunderkey.action-parameter-contract.v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_MOVING_VERSIONS = frozenset({"auto", "current", "default", "latest", "stable"})


class ActionResolutionError(StoreError):
    """Raised when a typed action-resolution record fails closed validation."""


class ActionTier(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


class ParameterValueType(StrEnum):
    STRING = "string"
    IDENTIFIER = "identifier"
    SHA256 = "sha256"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    STRING_ARRAY = "string_array"


class AuthorizationRole(StrEnum):
    TYPED_RESOLVER = "typed_resolver"
    MISSION_OWNER = "mission_owner"
    INDEPENDENT_CONTROL = "independent_control"
    ADMISSION_CONTROL = "admission_control"


class AdmissionReceiptStatus(StrEnum):
    ADMITTED_CONTRACT_ONLY = "admitted_contract_only"


_TIER_ORDER = {tier: index for index, tier in enumerate(ActionTier)}

NO_EFFECTS = MappingProxyType(
    {
        "authorization_effect": "none",
        "dispatch_performed": False,
        "model_call_performed": False,
        "network_call_performed": False,
        "qualification_effect": "none",
        "target_action_performed": False,
        "tool_effect": "none",
    }
)

_PREFIXES = {
    "executable_action_catalog": "EAC",
    "action_parameter_set": "APS",
    "target_action_descriptor": "TAD",
    "action_proposal_resolution": "APR",
    "action_authorization_quorum": "AAQ",
    "authenticated_action_admission_receipt": "AARX",
    "action_admission_revocation": "AARV",
}
_DOMAINS = {
    "executable_action_catalog": CATALOG_DOMAIN,
    "action_parameter_set": PARAMETER_SET_DOMAIN,
    "target_action_descriptor": TARGET_DOMAIN,
    "action_proposal_resolution": RESOLUTION_DOMAIN,
    "action_authorization_quorum": QUORUM_DOMAIN,
    "authenticated_action_admission_receipt": RECEIPT_DOMAIN,
    "action_admission_revocation": REVOCATION_DOMAIN,
}
_ID_FIELDS = {
    "executable_action_catalog": "catalog_id",
    "action_parameter_set": "parameter_set_id",
    "target_action_descriptor": "descriptor_id",
    "action_proposal_resolution": "resolution_id",
    "action_authorization_quorum": "quorum_id",
    "authenticated_action_admission_receipt": "receipt_id",
    "action_admission_revocation": "revocation_id",
}
_HASH_FIELDS = {
    "executable_action_catalog": "catalog_sha256",
    "action_parameter_set": "parameter_set_sha256",
    "target_action_descriptor": "descriptor_sha256",
    "action_proposal_resolution": "resolution_sha256",
    "action_authorization_quorum": "quorum_sha256",
    "authenticated_action_admission_receipt": "receipt_sha256",
    "action_admission_revocation": "revocation_sha256",
}


def _strict_json(value: Any, label: str, depth: int = 0) -> None:
    if depth > 32:
        raise ActionResolutionError(f"{label} exceeds the nesting limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ActionResolutionError(f"{label} integer is outside the signed 64-bit range")
        return
    if isinstance(value, float):
        raise ActionResolutionError(f"{label} cannot contain floating-point values")
    if isinstance(value, str):
        if (
            not value.isascii()
            or len(value) > MAX_TEXT_LENGTH
            or any(ord(character) < 0x20 and character not in "\t\n\r" for character in value)
        ):
            raise ActionResolutionError(f"{label} contains invalid text")
        return
    if isinstance(value, list):
        if len(value) > MAX_ACTIONS:
            raise ActionResolutionError(f"{label} contains too many values")
        for index, item in enumerate(value):
            _strict_json(item, f"{label}[{index}]", depth + 1)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key or not key.isascii():
                raise ActionResolutionError(f"{label} contains an invalid key")
            _strict_json(item, f"{label}.{key}", depth + 1)
        return
    raise ActionResolutionError(f"{label} contains an unsupported value")


def _mapping(raw: Any, label: str) -> dict[str, Any]:
    if isinstance(raw, str):
        if not raw or len(raw.encode("utf-8")) > MAX_RECORD_BYTES:
            raise ActionResolutionError(f"{label} exceeds the JSON byte ceiling")
        try:
            value = loads_json_without_duplicate_keys(raw)
        except (json.JSONDecodeError, DuplicateJsonKeyError) as exc:
            raise ActionResolutionError(f"{label} JSON is invalid") from exc
        if _canonical_json(value) != raw:
            raise ActionResolutionError(f"{label} JSON is not canonical")
        raw = value
    if not isinstance(raw, Mapping):
        raise ActionResolutionError(f"{label} must be an object")
    value = dict(raw)
    _strict_json(value, label)
    if len(_canonical_json(value).encode("ascii")) > MAX_RECORD_BYTES:
        raise ActionResolutionError(f"{label} exceeds the JSON byte ceiling")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    if set(value) != fields:
        raise ActionResolutionError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ActionResolutionError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ActionResolutionError(f"{label} is invalid")
    return value


def _version(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _VERSION.fullmatch(value) is None
        or value.lower() in _MOVING_VERSIONS
        or not any(character.isdigit() for character in value)
    ):
        raise ActionResolutionError(f"{label} must be an exact nonmoving version")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ActionResolutionError(f"{label} is invalid")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ActionResolutionError(f"{label} is invalid")
    return value


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise ActionResolutionError(f"{label} is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ActionResolutionError(f"{label} is invalid") from exc
    return value


def _enum(enum_type: type[StrEnum], value: Any, label: str) -> StrEnum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ActionResolutionError(f"{label} is invalid") from exc


def _address_record(kind: str, body: Mapping[str, Any]) -> dict[str, Any]:
    digest = _canonical_sha256({"domain": _DOMAINS[kind], "record": dict(body)})
    record_id = f"{_PREFIXES[kind]}-{digest.removeprefix('sha256:')[:32].upper()}"
    return {**dict(body), _ID_FIELDS[kind]: record_id, _HASH_FIELDS[kind]: digest}


def _validate_addressed_record(value: Mapping[str, Any], kind: str) -> None:
    if type(value.get("schema_version")) is not int or value.get("schema_version") != 1:
        raise ActionResolutionError(f"{kind} schema version is invalid")
    if type(value.get("kind")) is not str or value.get("kind") != kind:
        raise ActionResolutionError(f"{kind} kind is invalid")
    effects = value.get("effects")
    if not isinstance(effects, Mapping) or set(effects) != set(NO_EFFECTS):
        raise ActionResolutionError(f"{kind} claims a prohibited effect")
    for field, expected in NO_EFFECTS.items():
        if type(effects[field]) is not type(expected) or effects[field] != expected:
            raise ActionResolutionError(f"{kind} claims a prohibited effect")
    record_id = _identifier(value.get(_ID_FIELDS[kind]), f"{kind} ID")
    digest = _sha256(value.get(_HASH_FIELDS[kind]), f"{kind} hash")
    body = {
        key: item
        for key, item in value.items()
        if key not in {_ID_FIELDS[kind], _HASH_FIELDS[kind]}
    }
    expected = _address_record(kind, body)
    if record_id != expected[_ID_FIELDS[kind]] or digest != expected[_HASH_FIELDS[kind]]:
        raise ActionResolutionError(f"{kind} content address is invalid")


@dataclass(frozen=True)
class _PortableRecord:
    document_json: str

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def kind(self) -> str:
        return str(self.to_dict()["kind"])

    @property
    def record_id(self) -> str:
        return str(self.to_dict()[_ID_FIELDS[self.kind]])

    @property
    def content_sha256(self) -> str:
        return str(self.to_dict()[_HASH_FIELDS[self.kind]])


@dataclass(frozen=True)
class ExecutableActionCatalog(_PortableRecord):
    @property
    def catalog_id(self) -> str:
        return self.record_id

    @property
    def catalog_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ActionParameterSet(_PortableRecord):
    @property
    def parameter_set_id(self) -> str:
        return self.record_id

    @property
    def parameter_set_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class TargetActionDescriptor(_PortableRecord):
    @property
    def descriptor_id(self) -> str:
        return self.record_id

    @property
    def descriptor_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ActionProposalResolution(_PortableRecord):
    _proof: bytes = dataclass_field(default=b"", repr=False, compare=False)

    @property
    def resolution_id(self) -> str:
        return self.record_id

    @property
    def resolution_sha256(self) -> str:
        return self.content_sha256

    @classmethod
    def _seal(cls, record: ActionProposalResolution) -> ActionProposalResolution:
        proof = hmac.new(
            _RESOLUTION_PROOF_KEY,
            record.document_json.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return cls(record.document_json, proof)

    def _proof_is_valid(self) -> bool:
        expected = hmac.new(
            _RESOLUTION_PROOF_KEY,
            self.document_json.encode("ascii"),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(self._proof, expected)


@dataclass(frozen=True)
class ActionAuthorizationQuorum(_PortableRecord):
    @property
    def quorum_id(self) -> str:
        return self.record_id

    @property
    def quorum_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class AuthenticatedActionAdmissionReceipt(_PortableRecord):
    @property
    def receipt_id(self) -> str:
        return self.record_id

    @property
    def receipt_sha256(self) -> str:
        return self.content_sha256


@dataclass(frozen=True)
class ActionAdmissionRevocation(_PortableRecord):
    @property
    def revocation_id(self) -> str:
        return self.record_id

    @property
    def revocation_sha256(self) -> str:
        return self.content_sha256


_CURRENT_REVIEW_PROOF_KEY = secrets.token_bytes(32)
_CURRENT_AUTHORIZATION_PROOF_KEY = secrets.token_bytes(32)
_RESOLUTION_PROOF_KEY = secrets.token_bytes(32)


def _current_review_proof_material(records: ExpertReviewRecordSet) -> bytes:
    return _canonical_json(
        {
            "closure": records.closure.to_dict(),
            "closure_request": records.closure_request.to_dict(),
            "receipts": [item.to_dict() for item in records.receipts],
            "revocation": (
                None if records.revocation is None else records.revocation.to_dict()
            ),
            "snapshot": records.snapshot.to_dict(),
        }
    ).encode("ascii")


class CurrentExpertReviewClosure:
    """Opaque process-sealed result from a current authoritative-state check."""

    __slots__ = ("_frozen", "_proof", "_records")

    def __init__(self, records: ExpertReviewRecordSet, proof: bytes) -> None:
        if not isinstance(proof, bytes):
            raise ActionResolutionError(
                "Current expert review closure must come from the authoritative verifier"
            )
        object.__setattr__(self, "_records", records)
        object.__setattr__(self, "_proof", proof)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        if getattr(self, "_frozen", False):
            raise AttributeError("Current expert review closure is immutable")
        raise AttributeError("Current expert review closure fields are private")

    def _proof_is_valid(self) -> bool:
        expected = hmac.new(
            _CURRENT_REVIEW_PROOF_KEY,
            _current_review_proof_material(self._records),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(self._proof, expected)


class ExpertReviewClosureVerifier(Protocol):
    """Point-of-use bridge to authoritative Phase194 closure state."""

    def verify_current(
        self,
        records: ExpertReviewRecordSet,
        registry: ExpertRegistry,
    ) -> CurrentExpertReviewClosure:
        """Check exact current state, including revocation, and return a process seal."""


class CurrentPrincipalAuthorization:
    """Opaque process-sealed result from principal assertion verification."""

    __slots__ = ("_authorization", "_frozen", "_proof")

    def __init__(self, authorization: Mapping[str, Any], proof: bytes) -> None:
        if not isinstance(proof, bytes):
            raise ActionResolutionError(
                "Current authorization must come from the authoritative verifier"
            )
        object.__setattr__(self, "_authorization", MappingProxyType(dict(authorization)))
        object.__setattr__(self, "_proof", proof)
        object.__setattr__(self, "_frozen", True)

    def __setattr__(self, name: str, value: Any) -> None:
        del name, value
        if getattr(self, "_frozen", False):
            raise AttributeError("Current principal authorization is immutable")
        raise AttributeError("Current principal authorization fields are private")

    def _proof_is_valid(self) -> bool:
        expected = hmac.new(
            _CURRENT_AUTHORIZATION_PROOF_KEY,
            _canonical_json(dict(self._authorization)).encode("ascii"),
            hashlib.sha256,
        ).digest()
        return hmac.compare_digest(self._proof, expected)


class PrincipalAuthorizationVerifier(Protocol):
    """Point-of-use bridge to trusted principal assertion and replay custody."""

    def verify_current(
        self,
        authorization: Mapping[str, Any],
    ) -> CurrentPrincipalAuthorization:
        """Verify trust, scope, revocation, operation intent, and replay custody."""


def _seal_current_principal_authorization(
    authorization: Mapping[str, Any],
) -> CurrentPrincipalAuthorization:
    parsed = _authorization(authorization, "principal authorization")
    proof = hmac.new(
        _CURRENT_AUTHORIZATION_PROOF_KEY,
        _canonical_json(parsed).encode("ascii"),
        hashlib.sha256,
    ).digest()
    return CurrentPrincipalAuthorization(parsed, proof)


def _verify_current_principal_authorization(
    verifier: PrincipalAuthorizationVerifier,
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    parsed = _authorization(authorization, "principal authorization")
    method = getattr(verifier, "verify_current", None)
    if not callable(method):
        raise ActionResolutionError("A point-of-use principal authorization verifier is required")
    sealed = method(parsed)
    if (
        type(sealed) is not CurrentPrincipalAuthorization
        or not sealed._proof_is_valid()
        or sealed._authorization != parsed
    ):
        raise ActionResolutionError("Principal authorization verifier returned an invalid seal")
    return parsed


def _seal_current_expert_review_closure(
    records: ExpertReviewRecordSet,
) -> CurrentExpertReviewClosure:
    """Seal a result after an authoritative Phase194 verifier completes its check."""

    proof = hmac.new(
        _CURRENT_REVIEW_PROOF_KEY,
        _current_review_proof_material(records),
        hashlib.sha256,
    ).digest()
    return CurrentExpertReviewClosure(records, proof)


def _verify_current_expert_review_closure(
    verifier: ExpertReviewClosureVerifier,
    records: ExpertReviewRecordSet,
    registry: ExpertRegistry,
) -> ExpertReviewRecordSet:
    method = getattr(verifier, "verify_current", None)
    if not callable(method):
        raise ActionResolutionError("A point-of-use expert review verifier is required")
    sealed = method(records, registry)
    if type(sealed) is not CurrentExpertReviewClosure or not sealed._proof_is_valid():
        raise ActionResolutionError("Expert review verifier did not return a valid process seal")
    verified = verify_expert_review_record_set(sealed._records, registry)
    if verified.revocation is not None:
        raise ActionResolutionError("A revoked expert review closure is not current")
    if verified.closure.to_dict()["disposition"] != ClosureDisposition.ACCEPTED.value:
        raise ActionResolutionError("Expert review closure is not accepted")
    return verified


def parameter_contract_sha256(contract: Sequence[Mapping[str, Any]]) -> str:
    parsed = _parameter_contract(list(contract), "parameter contract")
    return _canonical_sha256(
        {"domain": PARAMETER_CONTRACT_DOMAIN, "parameter_contract": parsed}
    )


def _parameter_contract(raw: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > MAX_PARAMETERS:
        raise ActionResolutionError(f"{label} is invalid")
    parsed: list[dict[str, Any]] = []
    for index, item_raw in enumerate(raw):
        item = _mapping(item_raw, f"{label}[{index}]")
        _exact(item, {"name", "required", "value_type"}, f"{label}[{index}]")
        name = _identifier(item["name"], "parameter name")
        value_type = _enum(ParameterValueType, item["value_type"], "parameter value type")
        parsed.append(
            {
                "name": name,
                "required": _boolean(item["required"], "parameter required flag"),
                "value_type": value_type.value,
            }
        )
    if parsed != sorted(parsed, key=lambda item: item["name"]):
        raise ActionResolutionError(f"{label} must be ordered")
    names = [item["name"] for item in parsed]
    if len(names) != len(set(names)):
        raise ActionResolutionError(f"{label} names must be unique")
    return parsed


def _catalog_entry(raw: Any) -> dict[str, Any]:
    value = _mapping(raw, "catalog entry")
    fields = {
        "action_type",
        "executor_supported",
        "maximum_action_tier",
        "parameter_contract",
        "parameter_contract_sha256",
        "r4_executor_supported",
        "supported_environments",
        "tool_artifact_ref",
        "tool_artifact_sha256",
        "tool_exact_version",
    }
    _exact(value, fields, "catalog entry")
    _identifier(value["action_type"], "action type")
    maximum = _enum(ActionTier, value["maximum_action_tier"], "maximum action tier")
    if maximum is ActionTier.R5:
        raise ActionResolutionError("R5 cannot be an executable catalog ceiling")
    contract = _parameter_contract(value["parameter_contract"], "parameter contract")
    if value["parameter_contract_sha256"] != parameter_contract_sha256(contract):
        raise ActionResolutionError("Catalog parameter contract hash is invalid")
    executor_supported = _boolean(value["executor_supported"], "executor support")
    r4_supported = _boolean(value["r4_executor_supported"], "R4 executor support")
    if r4_supported and (
        not executor_supported or _TIER_ORDER[maximum] < _TIER_ORDER[ActionTier.R4]
    ):
        raise ActionResolutionError("R4 executor support is inconsistent")
    environments = value["supported_environments"]
    if not isinstance(environments, list) or not environments:
        raise ActionResolutionError("Supported environments are invalid")
    parsed_environments = [
        _enum(TargetEnvironment, item, "supported environment").value for item in environments
    ]
    if parsed_environments != sorted(set(parsed_environments)):
        raise ActionResolutionError("Supported environments must be unique and ordered")
    _identifier(value["tool_artifact_ref"], "tool artifact reference")
    _sha256(value["tool_artifact_sha256"], "tool artifact hash")
    _version(value["tool_exact_version"], "tool version")
    return {
        **value,
        "maximum_action_tier": maximum.value,
        "parameter_contract": contract,
        "supported_environments": parsed_environments,
    }


def parse_executable_action_catalog(raw: Any) -> ExecutableActionCatalog:
    value = _mapping(raw, "executable action catalog")
    fields = {
        "schema_version",
        "kind",
        "catalog_id",
        "catalog_sha256",
        "catalog_name",
        "catalog_version",
        "registry_sha256",
        "entries",
        "effects",
    }
    _exact(value, fields, "executable action catalog")
    _identifier(value["catalog_name"], "catalog name")
    _version(value["catalog_version"], "catalog version")
    _sha256(value["registry_sha256"], "registry hash")
    entries = value["entries"]
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ACTIONS:
        raise ActionResolutionError("Catalog entries are invalid")
    parsed = [_catalog_entry(item) for item in entries]
    if parsed != sorted(parsed, key=lambda item: item["action_type"]):
        raise ActionResolutionError("Catalog entries must be ordered")
    action_types = [item["action_type"] for item in parsed]
    if len(action_types) != len(set(action_types)):
        raise ActionResolutionError("Catalog action types must be unique")
    value["entries"] = parsed
    _validate_addressed_record(value, "executable_action_catalog")
    return ExecutableActionCatalog(_canonical_json(value))


def build_executable_action_catalog(
    *,
    catalog_name: str,
    catalog_version: str,
    registry_sha256: str,
    entries: Sequence[Mapping[str, Any]],
) -> ExecutableActionCatalog:
    parsed_entries = sorted(
        (_catalog_entry(item) for item in entries),
        key=lambda item: item["action_type"],
    )
    body = {
        "schema_version": 1,
        "kind": "executable_action_catalog",
        "catalog_name": catalog_name,
        "catalog_version": catalog_version,
        "registry_sha256": registry_sha256,
        "entries": parsed_entries,
        "effects": dict(NO_EFFECTS),
    }
    return parse_executable_action_catalog(_address_record("executable_action_catalog", body))


def _catalog_action(catalog: ExecutableActionCatalog, action_type: str) -> dict[str, Any]:
    action_type = _identifier(action_type, "action type")
    entry = next(
        (item for item in catalog.to_dict()["entries"] if item["action_type"] == action_type),
        None,
    )
    if entry is None:
        raise ActionResolutionError("Action type is absent from the executable catalog")
    return entry


def _validate_parameter_value(value: Any, value_type: str, label: str) -> None:
    parsed_type = ParameterValueType(value_type)
    if parsed_type is ParameterValueType.STRING:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_TEXT_LENGTH
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ActionResolutionError(f"{label} is not an exact string")
    elif parsed_type is ParameterValueType.IDENTIFIER:
        _identifier(value, label)
    elif parsed_type is ParameterValueType.SHA256:
        _sha256(value, label)
    elif parsed_type is ParameterValueType.INTEGER:
        _integer(value, label)
    elif parsed_type is ParameterValueType.BOOLEAN:
        _boolean(value, label)
    elif parsed_type is ParameterValueType.STRING_ARRAY:
        if not isinstance(value, list) or len(value) > MAX_PARAMETERS:
            raise ActionResolutionError(f"{label} is not a string array")
        if any(
            not isinstance(item, str)
            or not item
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
            for item in value
        ):
            raise ActionResolutionError(f"{label} is not a string array")
        if value != sorted(set(value)):
            raise ActionResolutionError(f"{label} must be unique and ordered")


def parse_action_parameter_set(
    raw: Any,
    catalog: ExecutableActionCatalog,
) -> ActionParameterSet:
    catalog = parse_executable_action_catalog(catalog.to_dict())
    value = _mapping(raw, "action parameter set")
    fields = {
        "schema_version",
        "kind",
        "parameter_set_id",
        "parameter_set_sha256",
        "catalog_id",
        "catalog_sha256",
        "catalog_version",
        "action_type",
        "parameter_contract_sha256",
        "parameters",
        "effects",
    }
    _exact(value, fields, "action parameter set")
    catalog_document = catalog.to_dict()
    if (
        value["catalog_id"] != catalog.catalog_id
        or value["catalog_sha256"] != catalog.catalog_sha256
        or value["catalog_version"] != catalog_document["catalog_version"]
    ):
        raise ActionResolutionError("Parameter set catalog binding is invalid")
    entry = _catalog_action(catalog, value["action_type"])
    if value["parameter_contract_sha256"] != entry["parameter_contract_sha256"]:
        raise ActionResolutionError("Parameter set contract binding is invalid")
    parameters = _mapping(value["parameters"], "typed parameters")
    contract = {item["name"]: item for item in entry["parameter_contract"]}
    required = {name for name, item in contract.items() if item["required"]}
    if not required.issubset(parameters) or not set(parameters).issubset(contract):
        raise ActionResolutionError("Typed parameter names do not match the contract")
    for name, parameter in parameters.items():
        _validate_parameter_value(parameter, contract[name]["value_type"], f"parameter {name}")
    _validate_addressed_record(value, "action_parameter_set")
    return ActionParameterSet(_canonical_json(value))


def build_action_parameter_set(
    catalog: ExecutableActionCatalog,
    *,
    action_type: str,
    parameters: Mapping[str, Any],
) -> ActionParameterSet:
    catalog = parse_executable_action_catalog(catalog.to_dict())
    entry = _catalog_action(catalog, action_type)
    catalog_document = catalog.to_dict()
    body = {
        "schema_version": 1,
        "kind": "action_parameter_set",
        "catalog_id": catalog.catalog_id,
        "catalog_sha256": catalog.catalog_sha256,
        "catalog_version": catalog_document["catalog_version"],
        "action_type": action_type,
        "parameter_contract_sha256": entry["parameter_contract_sha256"],
        "parameters": dict(parameters),
        "effects": dict(NO_EFFECTS),
    }
    return parse_action_parameter_set(_address_record("action_parameter_set", body), catalog)


def parse_target_action_descriptor(raw: Any) -> TargetActionDescriptor:
    value = _mapping(raw, "target action descriptor")
    fields = {
        "schema_version",
        "kind",
        "descriptor_id",
        "descriptor_sha256",
        "tenant_id",
        "mission_id",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "target_id",
        "target_sha256",
        "environment",
        "effects",
    }
    _exact(value, fields, "target action descriptor")
    for field in ("tenant_id", "mission_id", "target_id"):
        _identifier(value[field], field)
    for field in ("target_scope_sha256", "authority_snapshot_sha256", "target_sha256"):
        _sha256(value[field], field)
    _enum(TargetEnvironment, value["environment"], "target environment")
    _validate_addressed_record(value, "target_action_descriptor")
    return TargetActionDescriptor(_canonical_json(value))


def build_target_action_descriptor(
    *,
    tenant_id: str,
    mission_id: str,
    target_scope_sha256: str,
    authority_snapshot_sha256: str,
    target_id: str,
    target_sha256: str,
    environment: TargetEnvironment | str,
) -> TargetActionDescriptor:
    body = {
        "schema_version": 1,
        "kind": "target_action_descriptor",
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "target_scope_sha256": target_scope_sha256,
        "authority_snapshot_sha256": authority_snapshot_sha256,
        "target_id": target_id,
        "target_sha256": target_sha256,
        "environment": TargetEnvironment(environment).value,
        "effects": dict(NO_EFFECTS),
    }
    return parse_target_action_descriptor(_address_record("target_action_descriptor", body))


_AUTHORIZATION_FIELDS = {
    "role",
    "principal_profile_id",
    "principal_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "tenant_id",
    "mission_id",
    "scope_sha256",
    "target_sha256",
    "action_sha256",
    "resolution_sha256",
    "authorized_tier",
    "decision",
    "issued_at",
    "expires_at",
}


def _authorization(raw: Any, label: str) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact(value, _AUTHORIZATION_FIELDS, label)
    role = _enum(AuthorizationRole, value["role"], "authorization role")
    for field in (
        "principal_profile_id",
        "principal_subject",
        "assertion_issuer",
        "assertion_id",
        "tenant_id",
        "mission_id",
    ):
        _identifier(value[field], field)
    if value["principal_subject"] == value["assertion_issuer"]:
        raise ActionResolutionError("Assertion issuer and subject must differ")
    for field in (
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "resolution_sha256",
    ):
        _sha256(value[field], field)
    tier = _enum(ActionTier, value["authorized_tier"], "authorized tier")
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 cannot be authorized")
    if value["decision"] != "approved":
        raise ActionResolutionError("Authorization decision must be approved")
    issued_at = _timestamp(value["issued_at"], "authorization issued_at")
    expires_at = _timestamp(value["expires_at"], "authorization expires_at")
    if issued_at >= expires_at:
        raise ActionResolutionError("Authorization expiry must follow issuance")
    return {**value, "role": role.value, "authorized_tier": tier.value}


def _assert_authorization_binding(
    authorization: Mapping[str, Any],
    *,
    role: AuthorizationRole,
    tenant_id: str,
    mission_id: str,
    scope_sha256: str,
    target_sha256: str,
    action_sha256: str,
    resolution_sha256: str,
    action_tier: ActionTier,
) -> None:
    if authorization["role"] != role.value:
        raise ActionResolutionError(f"{role.value} authorization role is invalid")
    expected = {
        "tenant_id": tenant_id,
        "mission_id": mission_id,
        "scope_sha256": scope_sha256,
        "target_sha256": target_sha256,
        "action_sha256": action_sha256,
        "resolution_sha256": resolution_sha256,
    }
    if any(authorization[field] != value for field, value in expected.items()):
        raise ActionResolutionError(f"{role.value} authorization binding is invalid")
    authorized_tier = ActionTier(authorization["authorized_tier"])
    if _TIER_ORDER[authorized_tier] < _TIER_ORDER[action_tier]:
        raise ActionResolutionError(f"{role.value} authorization tier is insufficient")


def _assert_authorization_current_at(
    authorization: Mapping[str, Any],
    at: str,
    label: str,
) -> None:
    instant = _timestamp(at, label)
    if not authorization["issued_at"] <= instant < authorization["expires_at"]:
        raise ActionResolutionError(f"{label} is outside the authorization window")


def _resolved_action_sha256(
    *,
    catalog: ExecutableActionCatalog,
    entry: Mapping[str, Any],
    parameters: ActionParameterSet,
    target: TargetActionDescriptor,
    action_tier: ActionTier,
) -> str:
    return _canonical_sha256(
        {
            "domain": ACTION_DOMAIN,
            "catalog_id": catalog.catalog_id,
            "catalog_sha256": catalog.catalog_sha256,
            "action_type": entry["action_type"],
            "action_tier": action_tier.value,
            "parameter_set_id": parameters.parameter_set_id,
            "parameter_set_sha256": parameters.parameter_set_sha256,
            "target_descriptor_id": target.descriptor_id,
            "target_descriptor_sha256": target.descriptor_sha256,
            "tool_artifact_ref": entry["tool_artifact_ref"],
            "tool_artifact_sha256": entry["tool_artifact_sha256"],
            "tool_exact_version": entry["tool_exact_version"],
        }
    )


def parse_action_proposal_resolution(raw: Any) -> ActionProposalResolution:
    value = _mapping(raw, "action proposal resolution")
    fields = {
        "schema_version",
        "kind",
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "proposal_work_id",
        "proposal_product_id",
        "proposal_product_sha256",
        "proposal_producer_profile_id",
        "review_snapshot_id",
        "review_snapshot_sha256",
        "review_closure_id",
        "review_closure_sha256",
        "catalog_id",
        "catalog_sha256",
        "catalog_version",
        "parameter_set_id",
        "parameter_set_sha256",
        "target_descriptor_id",
        "target_descriptor_sha256",
        "target_scope_sha256",
        "target_id",
        "target_sha256",
        "target_authority_sha256",
        "target_environment",
        "action_type",
        "action_tier",
        "action_sha256",
        "idempotency_key_sha256",
        "tool_artifact_ref",
        "tool_artifact_sha256",
        "tool_exact_version",
        "resolver_profile_id",
        "resolver_subject",
        "resolved_at",
        "resolution_status",
        "effects",
    }
    _exact(value, fields, "action proposal resolution")
    for field in (
        "tenant_id",
        "mission_id",
        "plan_id",
        "proposal_work_id",
        "proposal_product_id",
        "proposal_producer_profile_id",
        "review_snapshot_id",
        "review_closure_id",
        "catalog_id",
        "parameter_set_id",
        "target_descriptor_id",
        "target_id",
        "action_type",
        "tool_artifact_ref",
    ):
        _identifier(value[field], field)
    for field in (
        "proposal_product_sha256",
        "review_snapshot_sha256",
        "review_closure_sha256",
        "catalog_sha256",
        "parameter_set_sha256",
        "target_descriptor_sha256",
        "target_scope_sha256",
        "target_sha256",
        "target_authority_sha256",
        "action_sha256",
        "idempotency_key_sha256",
        "tool_artifact_sha256",
    ):
        _sha256(value[field], field)
    _version(value["catalog_version"], "catalog version")
    _version(value["tool_exact_version"], "tool version")
    tier = _enum(ActionTier, value["action_tier"], "action tier")
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 actions cannot be resolved")
    _enum(TargetEnvironment, value["target_environment"], "target environment")
    _identifier(value["resolver_profile_id"], "resolver profile ID")
    _identifier(value["resolver_subject"], "resolver subject")
    if value["resolver_profile_id"] == value["proposal_producer_profile_id"]:
        raise ActionResolutionError("Typed resolver must be independent from the proposal producer")
    _timestamp(value["resolved_at"], "resolved_at")
    if value["resolution_status"] != "typed_resolved_pending_authorization":
        raise ActionResolutionError("Resolution status is invalid")
    _validate_addressed_record(value, "action_proposal_resolution")
    return ActionProposalResolution(_canonical_json(value))


def _verified_resolution(
    resolution: ActionProposalResolution,
) -> tuple[ActionProposalResolution, dict[str, Any]]:
    if type(resolution) is not ActionProposalResolution or not resolution._proof_is_valid():
        raise ActionResolutionError(
            "A process-local proof-sealed typed action resolution is required"
        )
    parsed = parse_action_proposal_resolution(resolution.to_dict())
    return resolution, parsed.to_dict()


def resolve_action_proposal(
    records: ExpertReviewRecordSet,
    registry: ExpertRegistry,
    review_verifier: ExpertReviewClosureVerifier,
    catalog: ExecutableActionCatalog,
    parameters: ActionParameterSet,
    target: TargetActionDescriptor,
    *,
    proposal_product_id: str,
    action_type: str,
    action_tier: ActionTier | str,
    idempotency_key_sha256: str,
    resolver_profile_id: str,
    resolver_subject: str,
    resolved_at: str,
) -> ActionProposalResolution:
    verified = _verify_current_expert_review_closure(
        review_verifier, records, registry
    )
    closure = verified.closure.to_dict()
    snapshot = verified.snapshot.to_dict()
    if (
        closure["snapshot_id"] != verified.snapshot.snapshot_id
        or closure["snapshot_sha256"] != verified.snapshot.snapshot_sha256
    ):
        raise ActionResolutionError("Expert review closure snapshot binding is invalid")
    proposal = next(
        (item for item in snapshot["products"] if item["product_id"] == proposal_product_id),
        None,
    )
    if proposal is None or proposal["product_type"] != "action_proposal":
        raise ActionResolutionError("Selected reviewed product is not an action proposal")
    catalog = parse_executable_action_catalog(catalog.to_dict())
    parameters = parse_action_parameter_set(parameters.to_dict(), catalog)
    target = parse_target_action_descriptor(target.to_dict())
    catalog_document = catalog.to_dict()
    parameter_document = parameters.to_dict()
    target_document = target.to_dict()
    if parameter_document["action_type"] != action_type:
        raise ActionResolutionError("Parameter set action type is inconsistent")
    if (
        target_document["tenant_id"] != snapshot["tenant_id"]
        or target_document["mission_id"] != snapshot["mission_id"]
        or target_document["target_scope_sha256"] != snapshot["target_scope_sha256"]
        or target_document["authority_snapshot_sha256"]
        != snapshot["authority_snapshot_sha256"]
    ):
        raise ActionResolutionError("Target descriptor is outside the reviewed proposal scope")
    if catalog_document["registry_sha256"] != snapshot["registry_sha256"]:
        raise ActionResolutionError("Executable catalog registry binding is invalid")
    entry = _catalog_action(catalog, action_type)
    tier = ActionTier(action_tier)
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 actions are categorically rejected")
    if _TIER_ORDER[tier] > _TIER_ORDER[ActionTier(entry["maximum_action_tier"])]:
        raise ActionResolutionError("Requested action tier exceeds the catalog ceiling")
    if not entry["executor_supported"]:
        raise ActionResolutionError("Action has no qualified executor support")
    if tier is ActionTier.R4 and not entry["r4_executor_supported"]:
        raise ActionResolutionError("R4 action lacks explicit executor support")
    if target_document["environment"] not in entry["supported_environments"]:
        raise ActionResolutionError("Target environment is unsupported for the action")
    action_sha256 = _resolved_action_sha256(
        catalog=catalog,
        entry=entry,
        parameters=parameters,
        target=target,
        action_tier=tier,
    )
    _sha256(idempotency_key_sha256, "idempotency key hash")
    body = {
        "schema_version": 1,
        "kind": "action_proposal_resolution",
        "tenant_id": snapshot["tenant_id"],
        "mission_id": snapshot["mission_id"],
        "plan_id": snapshot["plan_id"],
        "proposal_work_id": proposal["work_id"],
        "proposal_product_id": proposal["product_id"],
        "proposal_product_sha256": proposal["product_sha256"],
        "proposal_producer_profile_id": proposal["producer_profile_id"],
        "review_snapshot_id": verified.snapshot.snapshot_id,
        "review_snapshot_sha256": verified.snapshot.snapshot_sha256,
        "review_closure_id": verified.closure.closure_id,
        "review_closure_sha256": verified.closure.closure_sha256,
        "catalog_id": catalog.catalog_id,
        "catalog_sha256": catalog.catalog_sha256,
        "catalog_version": catalog_document["catalog_version"],
        "parameter_set_id": parameters.parameter_set_id,
        "parameter_set_sha256": parameters.parameter_set_sha256,
        "target_descriptor_id": target.descriptor_id,
        "target_descriptor_sha256": target.descriptor_sha256,
        "target_scope_sha256": target_document["target_scope_sha256"],
        "target_id": target_document["target_id"],
        "target_sha256": target_document["target_sha256"],
        "target_authority_sha256": target_document["authority_snapshot_sha256"],
        "target_environment": target_document["environment"],
        "action_type": action_type,
        "action_tier": tier.value,
        "action_sha256": action_sha256,
        "idempotency_key_sha256": idempotency_key_sha256,
        "tool_artifact_ref": entry["tool_artifact_ref"],
        "tool_artifact_sha256": entry["tool_artifact_sha256"],
        "tool_exact_version": entry["tool_exact_version"],
        "resolver_profile_id": resolver_profile_id,
        "resolver_subject": resolver_subject,
        "resolved_at": resolved_at,
        "resolution_status": "typed_resolved_pending_authorization",
        "effects": dict(NO_EFFECTS),
    }
    return ActionProposalResolution._seal(
        parse_action_proposal_resolution(
            _address_record("action_proposal_resolution", body)
        )
    )


def parse_action_authorization_quorum(raw: Any) -> ActionAuthorizationQuorum:
    value = _mapping(raw, "action authorization quorum")
    fields = {
        "schema_version",
        "kind",
        "quorum_id",
        "quorum_sha256",
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "approvals",
        "approved_at",
        "expires_at",
        "quorum_status",
        "effects",
    }
    _exact(value, fields, "action authorization quorum")
    for field in ("resolution_id", "tenant_id", "mission_id"):
        _identifier(value[field], field)
    for field in (
        "resolution_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
    ):
        _sha256(value[field], field)
    tier = _enum(ActionTier, value["action_tier"], "action tier")
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 actions cannot receive an authorization quorum")
    approvals_raw = value["approvals"]
    if not isinstance(approvals_raw, list) or not approvals_raw:
        raise ActionResolutionError("Authorization approvals are invalid")
    approvals = [_authorization(item, "authorization approval") for item in approvals_raw]
    expected_roles = [AuthorizationRole.MISSION_OWNER.value]
    if tier in {ActionTier.R3, ActionTier.R4}:
        expected_roles.append(AuthorizationRole.INDEPENDENT_CONTROL.value)
    if [item["role"] for item in approvals] != expected_roles:
        raise ActionResolutionError("Authorization quorum roles are incomplete or noncanonical")
    for approval in approvals:
        _assert_authorization_binding(
            approval,
            role=AuthorizationRole(approval["role"]),
            tenant_id=value["tenant_id"],
            mission_id=value["mission_id"],
            scope_sha256=value["scope_sha256"],
            target_sha256=value["target_sha256"],
            action_sha256=value["action_sha256"],
            resolution_sha256=value["resolution_sha256"],
            action_tier=tier,
        )
    uniqueness_fields = (
        "principal_profile_id",
        "principal_subject",
        "canonical_replay_key_sha256",
        "assertion_sha256",
    )
    for field in uniqueness_fields:
        items = [item[field] for item in approvals]
        if len(items) != len(set(items)):
            raise ActionResolutionError(f"Authorization quorum reuses {field}")
    approved_at = _timestamp(value["approved_at"], "approved_at")
    expires_at = _timestamp(value["expires_at"], "expires_at")
    if approved_at >= expires_at:
        raise ActionResolutionError("Authorization quorum expiry must follow approval")
    if any(not (item["issued_at"] <= approved_at < item["expires_at"]) for item in approvals):
        raise ActionResolutionError("Authorization approval is not current at quorum approval")
    if expires_at > min(item["expires_at"] for item in approvals):
        raise ActionResolutionError("Authorization quorum outlives an approval")
    if value["quorum_status"] != "approved_for_contract_admission":
        raise ActionResolutionError("Authorization quorum status is invalid")
    value["approvals"] = approvals
    _validate_addressed_record(value, "action_authorization_quorum")
    return ActionAuthorizationQuorum(_canonical_json(value))


def build_action_authorization_quorum(
    resolution: ActionProposalResolution,
    authorization_verifier: PrincipalAuthorizationVerifier,
    *,
    approvals: Sequence[Mapping[str, Any]],
    approved_at: str,
    expires_at: str,
) -> ActionAuthorizationQuorum:
    resolution, document = _verified_resolution(resolution)
    parsed = [
        _verify_current_principal_authorization(authorization_verifier, item)
        for item in approvals
    ]
    if _timestamp(approved_at, "approved_at") < document["resolved_at"]:
        raise ActionResolutionError("Authorization quorum cannot predate the resolution")
    profiles = {document["proposal_producer_profile_id"], document["resolver_profile_id"]}
    if any(
        item["principal_profile_id"] in profiles
        or item["principal_subject"] == document["resolver_subject"]
        for item in parsed
    ):
        raise ActionResolutionError(
            "Authorization approvers must be independent from production and resolution"
        )
    body = {
        "schema_version": 1,
        "kind": "action_authorization_quorum",
        "resolution_id": resolution.resolution_id,
        "resolution_sha256": resolution.resolution_sha256,
        "tenant_id": document["tenant_id"],
        "mission_id": document["mission_id"],
        "scope_sha256": document["target_scope_sha256"],
        "target_sha256": document["target_sha256"],
        "action_sha256": document["action_sha256"],
        "action_tier": document["action_tier"],
        "approvals": parsed,
        "approved_at": approved_at,
        "expires_at": expires_at,
        "quorum_status": "approved_for_contract_admission",
        "effects": dict(NO_EFFECTS),
    }
    return parse_action_authorization_quorum(
        _address_record("action_authorization_quorum", body)
    )


def _verify_resolution_quorum_binding(
    resolution: ActionProposalResolution,
    quorum: ActionAuthorizationQuorum,
) -> tuple[dict[str, Any], dict[str, Any]]:
    resolution, resolution_document = _verified_resolution(resolution)
    quorum = parse_action_authorization_quorum(quorum.to_dict())
    quorum_document = quorum.to_dict()
    expected = {
        "resolution_id": resolution.resolution_id,
        "resolution_sha256": resolution.resolution_sha256,
        "tenant_id": resolution_document["tenant_id"],
        "mission_id": resolution_document["mission_id"],
        "scope_sha256": resolution_document["target_scope_sha256"],
        "target_sha256": resolution_document["target_sha256"],
        "action_sha256": resolution_document["action_sha256"],
        "action_tier": resolution_document["action_tier"],
    }
    if any(quorum_document[field] != item for field, item in expected.items()):
        raise ActionResolutionError("Authorization quorum resolution binding is invalid")
    if quorum_document["approved_at"] < resolution_document["resolved_at"]:
        raise ActionResolutionError("Authorization quorum predates the resolution")
    excluded = {
        resolution_document["proposal_producer_profile_id"],
        resolution_document["resolver_profile_id"],
    }
    if any(
        item["principal_profile_id"] in excluded
        or item["principal_subject"] == resolution_document["resolver_subject"]
        for item in quorum_document["approvals"]
    ):
        raise ActionResolutionError("Authorization quorum independence is invalid")
    return resolution_document, quorum_document


def reconstruct_action_admission_request(
    resolution: ActionProposalResolution,
    quorum: ActionAuthorizationQuorum,
    *,
    context: ContextBinding,
    worker_session: WorkerSession,
    credential_lease: CredentialLease,
    health: HealthEvidence,
    budget: BudgetBinding,
    evidence_obligations: Sequence[EvidenceObligation],
    stop_conditions: StopConditions,
    restoration_duties: RestorationDuties,
    requested_at: str,
    expires_at: str,
) -> ActionAdmissionRequest:
    resolution_document, quorum_document = _verify_resolution_quorum_binding(
        resolution, quorum
    )
    if (
        context.tenant_id != resolution_document["tenant_id"]
        or context.mission_id != resolution_document["mission_id"]
        or context.scope_sha256 != resolution_document["target_scope_sha256"]
    ):
        raise ActionResolutionError("Phase 165 context is outside the typed resolution")
    target_descriptor = resolution_document
    owner = quorum_document["approvals"][0]
    try:
        legacy_tier = LegacyActionTier(resolution_document["action_tier"])
    except ValueError as exc:
        raise ActionResolutionError("Resolved action tier is unsupported by Phase 165") from exc
    target = TargetBinding(
        target_id=target_descriptor["target_id"],
        target_sha256=target_descriptor["target_sha256"],
        authority_sha256=resolution_document["target_authority_sha256"],
        tenant_id=resolution_document["tenant_id"],
        mission_id=resolution_document["mission_id"],
        scope_sha256=resolution_document["target_scope_sha256"],
        environment=TargetEnvironment(resolution_document["target_environment"]),
    )
    action = RequestedAction(
        action_id=resolution.resolution_id,
        action_type=resolution_document["action_type"],
        action_tier=legacy_tier,
        action_sha256=resolution_document["action_sha256"],
        target_sha256=resolution_document["target_sha256"],
        parameters_sha256=resolution_document["parameter_set_sha256"],
        tool=ArtifactBinding(
            artifact_ref=resolution_document["tool_artifact_ref"],
            artifact_sha256=resolution_document["tool_artifact_sha256"],
            exact_version=resolution_document["tool_exact_version"],
        ),
        idempotency_key_sha256=resolution_document["idempotency_key_sha256"],
    )
    approval = ApprovalBinding(
        approval_id=quorum.quorum_id,
        approval_sha256=quorum.quorum_sha256,
        tenant_id=resolution_document["tenant_id"],
        mission_id=resolution_document["mission_id"],
        scope_sha256=resolution_document["target_scope_sha256"],
        target_sha256=resolution_document["target_sha256"],
        action_sha256=resolution_document["action_sha256"],
        worker_id=worker_session.worker_id,
        session_id=worker_session.session_id,
        fence_token_sha256=worker_session.fence_token_sha256,
        leader_epoch=worker_session.leader_epoch,
        authorized_tier=legacy_tier,
        approver_id=owner["principal_profile_id"],
        decision="approved",
        issued_at=quorum_document["approved_at"],
        expires_at=quorum_document["expires_at"],
    )
    request = ActionAdmissionRequest(
        context=context,
        worker_session=worker_session,
        approval=approval,
        credential_lease=credential_lease,
        health=health,
        budget=budget,
        target=target,
        action=action,
        evidence_obligations=tuple(evidence_obligations),
        stop_conditions=stop_conditions,
        restoration_duties=restoration_duties,
        requested_at=requested_at,
        expires_at=expires_at,
    )
    if (
        credential_lease.permitted_action_sha256 != action.action_sha256
        or stop_conditions.action_sha256 != action.action_sha256
        or restoration_duties.action_sha256 != action.action_sha256
        or any(item.action_sha256 != action.action_sha256 for item in evidence_obligations)
    ):
        raise ActionResolutionError("Phase 165 prerequisites are not bound to the resolved action")
    return request


def parse_authenticated_action_admission_receipt(
    raw: Any,
) -> AuthenticatedActionAdmissionReceipt:
    value = _mapping(raw, "authenticated action admission receipt")
    fields = {
        "schema_version",
        "kind",
        "receipt_id",
        "receipt_sha256",
        "resolution_id",
        "resolution_sha256",
        "quorum_id",
        "quorum_sha256",
        "request_id",
        "request_sha256",
        "decision_id",
        "decision_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "evaluated_at",
        "status",
        "admission_authorization",
        "identity_assurance",
        "effects",
    }
    _exact(value, fields, "authenticated action admission receipt")
    for field in (
        "resolution_id",
        "quorum_id",
        "request_id",
        "decision_id",
        "tenant_id",
        "mission_id",
    ):
        _identifier(value[field], field)
    for field in (
        "resolution_sha256",
        "quorum_sha256",
        "request_sha256",
        "decision_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
    ):
        _sha256(value[field], field)
    tier = _enum(ActionTier, value["action_tier"], "action tier")
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 actions cannot receive an admission receipt")
    _timestamp(value["evaluated_at"], "evaluated_at")
    if value["status"] != AdmissionReceiptStatus.ADMITTED_CONTRACT_ONLY.value:
        raise ActionResolutionError("Admission receipt status is invalid")
    authorization = _authorization(
        value["admission_authorization"], "admission authorization"
    )
    _assert_authorization_binding(
        authorization,
        role=AuthorizationRole.ADMISSION_CONTROL,
        tenant_id=value["tenant_id"],
        mission_id=value["mission_id"],
        scope_sha256=value["scope_sha256"],
        target_sha256=value["target_sha256"],
        action_sha256=value["action_sha256"],
        resolution_sha256=value["resolution_sha256"],
        action_tier=tier,
    )
    _assert_authorization_current_at(authorization, value["evaluated_at"], "evaluated_at")
    if value["identity_assurance"] != "mission_store_principal_assertion":
        raise ActionResolutionError("Admission receipt identity assurance is invalid")
    value["admission_authorization"] = authorization
    _validate_addressed_record(value, "authenticated_action_admission_receipt")
    return AuthenticatedActionAdmissionReceipt(_canonical_json(value))


def authenticate_action_admission(
    resolution: ActionProposalResolution,
    quorum: ActionAuthorizationQuorum,
    request: ActionAdmissionRequest,
    records: ExpertReviewRecordSet,
    registry: ExpertRegistry,
    review_verifier: ExpertReviewClosureVerifier,
    authorization_verifier: PrincipalAuthorizationVerifier,
    *,
    evaluated_at: str,
    admission_authorization: Mapping[str, Any],
) -> AuthenticatedActionAdmissionReceipt:
    raise ActionResolutionError(
        "Portable admission is disabled; use AuthenticatedActionAdmissionService"
    )
    resolution_document, quorum_document = _verify_resolution_quorum_binding(
        resolution, quorum
    )
    current_review = _verify_current_expert_review_closure(
        review_verifier, records, registry
    )
    if (
        current_review.snapshot.snapshot_id != resolution_document["review_snapshot_id"]
        or current_review.snapshot.snapshot_sha256
        != resolution_document["review_snapshot_sha256"]
        or current_review.closure.closure_id != resolution_document["review_closure_id"]
        or current_review.closure.closure_sha256
        != resolution_document["review_closure_sha256"]
    ):
        raise ActionResolutionError("Current expert review closure differs from the resolution")
    for approval in quorum_document["approvals"]:
        _verify_current_principal_authorization(authorization_verifier, approval)
    decision = evaluate_action_admission(request, evaluated_at=evaluated_at)
    if decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY:
        reasons = ",".join(item.value for item in decision.denial_reasons)
        raise ActionResolutionError(f"Phase 165 action admission denied: {reasons}")
    if (
        request.context.tenant_id != resolution_document["tenant_id"]
        or request.context.mission_id != resolution_document["mission_id"]
        or request.context.scope_sha256 != resolution_document["target_scope_sha256"]
        or request.target.target_sha256 != resolution_document["target_sha256"]
        or request.action.action_sha256 != resolution_document["action_sha256"]
        or request.action.parameters_sha256 != resolution_document["parameter_set_sha256"]
        or request.approval.approval_sha256 != quorum.quorum_sha256
        or request.approval.approval_id != quorum.quorum_id
    ):
        raise ActionResolutionError("Phase 165 request is not the resolved authorized action")
    authorization = _verify_current_principal_authorization(
        authorization_verifier, admission_authorization
    )
    tier = ActionTier(resolution_document["action_tier"])
    _assert_authorization_binding(
        authorization,
        role=AuthorizationRole.ADMISSION_CONTROL,
        tenant_id=resolution_document["tenant_id"],
        mission_id=resolution_document["mission_id"],
        scope_sha256=resolution_document["target_scope_sha256"],
        target_sha256=resolution_document["target_sha256"],
        action_sha256=resolution_document["action_sha256"],
        resolution_sha256=resolution.resolution_sha256,
        action_tier=tier,
    )
    _assert_authorization_current_at(authorization, evaluated_at, "evaluated_at")
    if authorization["principal_profile_id"] in {
        resolution_document["proposal_producer_profile_id"],
        resolution_document["resolver_profile_id"],
        *(item["principal_profile_id"] for item in quorum_document["approvals"]),
    } or authorization["principal_subject"] in {
        resolution_document["resolver_subject"],
        *(item["principal_subject"] for item in quorum_document["approvals"]),
    }:
        raise ActionResolutionError("Admission Control must be independent")
    replay_keys = {
        item["canonical_replay_key_sha256"] for item in quorum_document["approvals"]
    }
    assertion_hashes = {item["assertion_sha256"] for item in quorum_document["approvals"]}
    if (
        authorization["canonical_replay_key_sha256"] in replay_keys
        or authorization["assertion_sha256"] in assertion_hashes
    ):
        raise ActionResolutionError("Admission authorization reuses quorum authentication")
    body = {
        "schema_version": 1,
        "kind": "authenticated_action_admission_receipt",
        "resolution_id": resolution.resolution_id,
        "resolution_sha256": resolution.resolution_sha256,
        "quorum_id": quorum.quorum_id,
        "quorum_sha256": quorum.quorum_sha256,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "decision_id": decision.decision_id,
        "decision_sha256": decision.decision_sha256,
        "tenant_id": resolution_document["tenant_id"],
        "mission_id": resolution_document["mission_id"],
        "scope_sha256": resolution_document["target_scope_sha256"],
        "target_sha256": resolution_document["target_sha256"],
        "action_sha256": resolution_document["action_sha256"],
        "action_tier": resolution_document["action_tier"],
        "evaluated_at": evaluated_at,
        "status": AdmissionReceiptStatus.ADMITTED_CONTRACT_ONLY.value,
        "admission_authorization": authorization,
        "identity_assurance": "mission_store_principal_assertion",
        "effects": dict(NO_EFFECTS),
    }
    return parse_authenticated_action_admission_receipt(
        _address_record("authenticated_action_admission_receipt", body)
    )


def parse_action_admission_revocation(raw: Any) -> ActionAdmissionRevocation:
    value = _mapping(raw, "action admission revocation")
    fields = {
        "schema_version",
        "kind",
        "revocation_id",
        "revocation_sha256",
        "receipt_id",
        "receipt_sha256",
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "reason_code",
        "control_authorization",
        "revoked_at",
        "identity_assurance",
        "effects",
    }
    _exact(value, fields, "action admission revocation")
    for field in ("receipt_id", "resolution_id", "tenant_id", "mission_id", "reason_code"):
        _identifier(value[field], field)
    for field in (
        "receipt_sha256",
        "resolution_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
    ):
        _sha256(value[field], field)
    tier = _enum(ActionTier, value["action_tier"], "action tier")
    if tier is ActionTier.R5:
        raise ActionResolutionError("R5 revocation binding is invalid")
    authorization = _authorization(
        value["control_authorization"], "revocation Control authorization"
    )
    _assert_authorization_binding(
        authorization,
        role=AuthorizationRole.INDEPENDENT_CONTROL,
        tenant_id=value["tenant_id"],
        mission_id=value["mission_id"],
        scope_sha256=value["scope_sha256"],
        target_sha256=value["target_sha256"],
        action_sha256=value["action_sha256"],
        resolution_sha256=value["resolution_sha256"],
        action_tier=tier,
    )
    _assert_authorization_current_at(authorization, value["revoked_at"], "revoked_at")
    if value["identity_assurance"] != "mission_store_principal_assertion":
        raise ActionResolutionError("Revocation identity assurance is invalid")
    value["control_authorization"] = authorization
    _validate_addressed_record(value, "action_admission_revocation")
    return ActionAdmissionRevocation(_canonical_json(value))


def build_action_admission_revocation(
    receipt: AuthenticatedActionAdmissionReceipt,
    authorization_verifier: PrincipalAuthorizationVerifier,
    *,
    reason_code: str,
    control_authorization: Mapping[str, Any],
    revoked_at: str,
) -> ActionAdmissionRevocation:
    raise ActionResolutionError(
        "Portable revocation is disabled; use AuthenticatedActionAdmissionService"
    )
    receipt = parse_authenticated_action_admission_receipt(receipt.to_dict())
    document = receipt.to_dict()
    if _timestamp(revoked_at, "revoked_at") < document["evaluated_at"]:
        raise ActionResolutionError("Revocation cannot predate admission")
    authorization = _verify_current_principal_authorization(
        authorization_verifier, control_authorization
    )
    admission = document["admission_authorization"]
    if (
        authorization["principal_profile_id"] == admission["principal_profile_id"]
        or authorization["principal_subject"] == admission["principal_subject"]
        or authorization["canonical_replay_key_sha256"]
        == admission["canonical_replay_key_sha256"]
        or authorization["assertion_sha256"] == admission["assertion_sha256"]
    ):
        raise ActionResolutionError("Revocation Control must be independently authenticated")
    body = {
        "schema_version": 1,
        "kind": "action_admission_revocation",
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt.receipt_sha256,
        "resolution_id": document["resolution_id"],
        "resolution_sha256": document["resolution_sha256"],
        "tenant_id": document["tenant_id"],
        "mission_id": document["mission_id"],
        "scope_sha256": document["scope_sha256"],
        "target_sha256": document["target_sha256"],
        "action_sha256": document["action_sha256"],
        "action_tier": document["action_tier"],
        "reason_code": reason_code,
        "control_authorization": authorization,
        "revoked_at": revoked_at,
        "identity_assurance": "mission_store_principal_assertion",
        "effects": dict(NO_EFFECTS),
    }
    return parse_action_admission_revocation(
        _address_record("action_admission_revocation", body)
    )


def verify_authenticated_action_admission(
    resolution: ActionProposalResolution,
    quorum: ActionAuthorizationQuorum,
    request: ActionAdmissionRequest,
    receipt: AuthenticatedActionAdmissionReceipt,
    records: ExpertReviewRecordSet,
    registry: ExpertRegistry,
    review_verifier: ExpertReviewClosureVerifier,
    authorization_verifier: PrincipalAuthorizationVerifier,
    *,
    revocation: ActionAdmissionRevocation | None = None,
) -> bool:
    raise ActionResolutionError(
        "Portable verification cannot establish authority; use service verify_current"
    )
    resolution_document, _ = _verify_resolution_quorum_binding(resolution, quorum)
    current_review = _verify_current_expert_review_closure(
        review_verifier, records, registry
    )
    if (
        current_review.snapshot.snapshot_id != resolution_document["review_snapshot_id"]
        or current_review.snapshot.snapshot_sha256
        != resolution_document["review_snapshot_sha256"]
        or current_review.closure.closure_id != resolution_document["review_closure_id"]
        or current_review.closure.closure_sha256
        != resolution_document["review_closure_sha256"]
    ):
        raise ActionResolutionError("Current expert review closure differs from the receipt chain")
    quorum_document = quorum.to_dict()
    for approval in quorum_document["approvals"]:
        _verify_current_principal_authorization(authorization_verifier, approval)
    receipt = parse_authenticated_action_admission_receipt(receipt.to_dict())
    document = receipt.to_dict()
    _verify_current_principal_authorization(
        authorization_verifier, document["admission_authorization"]
    )
    decision = evaluate_action_admission(request, evaluated_at=document["evaluated_at"])
    expected = {
        "resolution_id": resolution.resolution_id,
        "resolution_sha256": resolution.resolution_sha256,
        "quorum_id": quorum.quorum_id,
        "quorum_sha256": quorum.quorum_sha256,
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "decision_id": decision.decision_id,
        "decision_sha256": decision.decision_sha256,
        "tenant_id": resolution_document["tenant_id"],
        "mission_id": resolution_document["mission_id"],
        "scope_sha256": resolution_document["target_scope_sha256"],
        "target_sha256": resolution_document["target_sha256"],
        "action_sha256": resolution_document["action_sha256"],
        "action_tier": resolution_document["action_tier"],
    }
    if decision.status is not AdmissionStatus.ADMITTED_CONTRACT_ONLY or any(
        document[field] != value for field, value in expected.items()
    ):
        raise ActionResolutionError("Authenticated admission receipt chain is invalid")
    if revocation is None:
        return True
    revocation = parse_action_admission_revocation(revocation.to_dict())
    revoked = revocation.to_dict()
    _verify_current_principal_authorization(
        authorization_verifier, revoked["control_authorization"]
    )
    bindings = {
        "receipt_id": receipt.receipt_id,
        "receipt_sha256": receipt.receipt_sha256,
        "resolution_id": resolution.resolution_id,
        "resolution_sha256": resolution.resolution_sha256,
        "tenant_id": document["tenant_id"],
        "mission_id": document["mission_id"],
        "scope_sha256": document["scope_sha256"],
        "target_sha256": document["target_sha256"],
        "action_sha256": document["action_sha256"],
        "action_tier": document["action_tier"],
    }
    if any(revoked[field] != value for field, value in bindings.items()):
        raise ActionResolutionError("Action admission revocation binding is invalid")
    if revoked["revoked_at"] < document["evaluated_at"]:
        raise ActionResolutionError("Action admission revocation predates admission")
    return False


__all__ = [
    "ACTION_DOMAIN",
    "ActionAdmissionRevocation",
    "ActionAuthorizationQuorum",
    "ActionParameterSet",
    "ActionProposalResolution",
    "ActionResolutionError",
    "ActionTier",
    "AdmissionReceiptStatus",
    "AuthenticatedActionAdmissionReceipt",
    "AuthorizationRole",
    "ExecutableActionCatalog",
    "NO_EFFECTS",
    "ParameterValueType",
    "TargetActionDescriptor",
    "build_action_authorization_quorum",
    "build_action_parameter_set",
    "build_executable_action_catalog",
    "build_target_action_descriptor",
    "parameter_contract_sha256",
    "parse_action_admission_revocation",
    "parse_action_authorization_quorum",
    "parse_action_parameter_set",
    "parse_action_proposal_resolution",
    "parse_authenticated_action_admission_receipt",
    "parse_executable_action_catalog",
    "parse_target_action_descriptor",
    "reconstruct_action_admission_request",
    "resolve_action_proposal",
]

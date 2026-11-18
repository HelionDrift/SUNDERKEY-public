"""Inert supplied partner connector identity, scope and transfer projection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "api_supplied_partner_connector_trust_projection"
PROFILE_ID = "AOE-GB-D06-S16"
CAPABILITY_ID = "army.gb.d06.s16"
VECTOR_ID = "AV-GB-D06-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D06-S16"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GB-D06-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:5533b9ea8b0f65cd868a92f8d752db6093a6f6840ace1941b7fadd818a9c2425"
DOMAIN = "sunderkey.offline-partner-connector-trust.v1"
MODEL_DOMAIN = "sunderkey.offline-partner-connector-trust-model.v1"
SEMANTICS_PROFILE = "declared-exact-identity-scope-partner-class.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_CONNECTORS = 64
MAX_TRANSFERS = 128
MAX_SCOPES = 64
MAX_DATA_CLASSES = 32
MAX_WORK = 2_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "partner_identity_verified",
        "connector_configuration_verified",
        "scope_grant_verified",
        "transfer_observed",
        "destination_verified",
        "data_classification_verified",
        "policy_enforcement_verified",
        "exfiltration_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "connectors": MAX_CONNECTORS,
    "transfers": MAX_TRANSFERS,
    "scopes_per_connector": MAX_SCOPES,
    "data_classes_per_connector": MAX_DATA_CLASSES,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Connector ownership, identity, grants, data classes and transfers are caller declarations.",
    "Only complete exact outbound identity, partner, scope and data-class rules are modeled.",
    "Disabled, unknown or incomplete connector semantics cannot yield a candidate.",
    "A candidate is a supplied policy contradiction, not observed unauthorized data transfer.",
    "Delegation, token exchange, transforms, fan-out and inbound flows are not modeled.",
    "No partner system, low-code runtime, credential, network or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
)


class PartnerConnectorTrustAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied connector model/report."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise PartnerConnectorTrustAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise PartnerConnectorTrustAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(c) <= 126 for c in item):
                raise PartnerConnectorTrustAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise PartnerConnectorTrustAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise PartnerConnectorTrustAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise PartnerConnectorTrustAnalysisError(
                                "Exact native string keys required"
                            )
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise PartnerConnectorTrustAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise PartnerConnectorTrustAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise PartnerConnectorTrustAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise PartnerConnectorTrustAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise PartnerConnectorTrustAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise PartnerConnectorTrustAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise PartnerConnectorTrustAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise PartnerConnectorTrustAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, PartnerConnectorTrustAnalysisError):
            raise
        raise PartnerConnectorTrustAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise PartnerConnectorTrustAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise PartnerConnectorTrustAnalysisError("Bounded exact identity required")
    return value


def _sorted_rows(rows: Any, field: str, limit: int, label: str) -> list:
    if type(rows) is not list or not 1 <= len(rows) <= limit:
        raise PartnerConnectorTrustAnalysisError(f"Bounded nonempty {label} required")
    ids = [_identity(row[field]) for row in rows if type(row) is dict and field in row]
    if len(ids) != len(rows) or ids != sorted(set(ids)):
        raise PartnerConnectorTrustAnalysisError(f"Sorted unique {label} identities required")
    return rows


def _id_list(value: Any, limit: int, label: str) -> list[str]:
    if type(value) is not list or len(value) > limit:
        raise PartnerConnectorTrustAnalysisError(f"Bounded {label} list required")
    for item in value:
        _identity(item)
    if value != sorted(set(value)):
        raise PartnerConnectorTrustAnalysisError(f"Sorted unique {label} list required")
    return value


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    _exact(owned, {"schema_version", "connectors", "transfers"}, "model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise PartnerConnectorTrustAnalysisError("Exact schema version 1 required")
    connectors = _sorted_rows(owned["connectors"], "connector_id", MAX_CONNECTORS, "connector")
    transfers = _sorted_rows(owned["transfers"], "transfer_id", MAX_TRANSFERS, "transfer")
    connector_ids: set[str] = set()
    for item in connectors:
        work.charge(16)
        _exact(
            item,
            {
                "connector_id",
                "connector_kind",
                "partner_id",
                "bound_identity",
                "allowed_scopes",
                "allowed_data_classes",
                "enabled",
                "policy_complete",
            },
            "connector",
        )
        if item["connector_kind"] not in ("partner_api", "b2b_exchange", "low_code"):
            raise PartnerConnectorTrustAnalysisError("Supported connector kind required")
        _identity(item["partner_id"])
        _identity(item["bound_identity"])
        _id_list(item["allowed_scopes"], MAX_SCOPES, "scope")
        _id_list(item["allowed_data_classes"], MAX_DATA_CLASSES, "data class")
        if type(item["enabled"]) is not bool or type(item["policy_complete"]) is not bool:
            raise PartnerConnectorTrustAnalysisError("Exact connector booleans required")
        connector_ids.add(item["connector_id"])
    for item in transfers:
        work.charge(16)
        _exact(
            item,
            {
                "transfer_id",
                "connector_id",
                "direction",
                "presented_identity",
                "destination_partner_id",
                "required_scope",
                "data_class",
                "context_complete",
                "observed_outcome",
                "observation_complete",
            },
            "transfer",
        )
        if _identity(item["connector_id"]) not in connector_ids:
            raise PartnerConnectorTrustAnalysisError("Unknown transfer connector")
        if item["direction"] not in ("outbound", "unknown"):
            raise PartnerConnectorTrustAnalysisError("Only outbound direction is modeled")
        for field in (
            "presented_identity",
            "destination_partner_id",
            "required_scope",
            "data_class",
        ):
            if item[field] != "unknown":
                _identity(item[field])
        if item["observed_outcome"] not in ("allowed", "denied", "unknown"):
            raise PartnerConnectorTrustAnalysisError("Supported supplied outcome required")
        if (
            type(item["context_complete"]) is not bool
            or type(item["observation_complete"]) is not bool
        ):
            raise PartnerConnectorTrustAnalysisError("Exact transfer booleans required")
    return owned, source_text


def _observe(transfer: dict, connector: dict) -> dict:
    reasons: list[str] = []
    if transfer["direction"] != "outbound":
        reasons.append("transfer_direction_unknown")
    if not connector["enabled"]:
        reasons.append("connector_disabled")
    if not connector["policy_complete"]:
        reasons.append("connector_policy_incomplete")
    if not transfer["context_complete"]:
        reasons.append("transfer_context_incomplete")
    if not transfer["observation_complete"] or transfer["observed_outcome"] == "unknown":
        reasons.append("transfer_observation_incomplete")
    for field in ("presented_identity", "destination_partner_id", "required_scope", "data_class"):
        if transfer[field] == "unknown":
            reasons.append(field + "_unknown")
    expected = None
    violated: list[str] = []
    if not reasons:
        if transfer["presented_identity"] != connector["bound_identity"]:
            violated.append("identity_mismatch")
        if transfer["destination_partner_id"] != connector["partner_id"]:
            violated.append("partner_mismatch")
        if transfer["required_scope"] not in connector["allowed_scopes"]:
            violated.append("scope_not_granted")
        if transfer["data_class"] not in connector["allowed_data_classes"]:
            violated.append("data_class_not_allowed")
        expected = "deny" if violated else "allow"
    if reasons:
        outcome = "unknown"
    elif expected == "deny" and transfer["observed_outcome"] == "allowed":
        outcome = "candidate_declared_deny_allowed_contradiction"
    elif expected == "allow" and transfer["observed_outcome"] == "denied":
        outcome = "declared_allow_denied_contradiction"
    else:
        outcome = "matches_declared_policy"
    return {
        "transfer_id": transfer["transfer_id"],
        "connector_id": transfer["connector_id"],
        "connector_kind": connector["connector_kind"],
        "expected_outcome": expected,
        "supplied_outcome": transfer["observed_outcome"],
        "outcome": outcome,
        "violated_declarations": violated,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    connectors = {row["connector_id"]: row for row in owned["connectors"]}
    observations = [_observe(row, connectors[row["connector_id"]]) for row in owned["transfers"]]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _address(MODEL_DOMAIN, source_text),
        "transfer_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_deny_allowed_contradiction"
            for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "transfer_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "PCT-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise PartnerConnectorTrustAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise PartnerConnectorTrustAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class PartnerConnectorTrustAnalysis:
    """Detached supplied-data comparison, not live connector evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> PartnerConnectorTrustAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> PartnerConnectorTrustAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_partner_connector_trust(model: Any) -> PartnerConnectorTrustAnalysis:
    """Compare only supplied connector policy and transfer declarations."""
    return PartnerConnectorTrustAnalysis(_derive(model))


def analyze_supplied_partner_connector_trust_bytes(
    *, model_bytes: Any
) -> PartnerConnectorTrustAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise PartnerConnectorTrustAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PartnerConnectorTrustAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_partner_connector_trust(_decode(text))


def verify_supplied_partner_connector_trust_analysis(
    report: Any, *, model: Any
) -> PartnerConnectorTrustAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not PartnerConnectorTrustAnalysis:
        raise PartnerConnectorTrustAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise PartnerConnectorTrustAnalysisError(
            "Report differs from separately supplied originals"
        )
    return PartnerConnectorTrustAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic partner policy contradiction, match and unknown transfer."""
    return {
        "schema_version": 1,
        "connectors": [
            {
                "connector_id": "b2b-orders",
                "connector_kind": "b2b_exchange",
                "partner_id": "partner-a",
                "bound_identity": "connector-orders",
                "allowed_scopes": ["orders.read"],
                "allowed_data_classes": ["internal"],
                "enabled": True,
                "policy_complete": True,
            }
        ],
        "transfers": [
            {
                "transfer_id": "allowed-contradiction",
                "connector_id": "b2b-orders",
                "direction": "outbound",
                "presented_identity": "connector-orders",
                "destination_partner_id": "partner-b",
                "required_scope": "orders.read",
                "data_class": "internal",
                "context_complete": True,
                "observed_outcome": "allowed",
                "observation_complete": True,
            },
            {
                "transfer_id": "exact-match",
                "connector_id": "b2b-orders",
                "direction": "outbound",
                "presented_identity": "connector-orders",
                "destination_partner_id": "partner-a",
                "required_scope": "orders.read",
                "data_class": "internal",
                "context_complete": True,
                "observed_outcome": "allowed",
                "observation_complete": True,
            },
            {
                "transfer_id": "unknown-context",
                "connector_id": "b2b-orders",
                "direction": "outbound",
                "presented_identity": "unknown",
                "destination_partner_id": "partner-a",
                "required_scope": "orders.read",
                "data_class": "internal",
                "context_complete": False,
                "observed_outcome": "unknown",
                "observation_complete": False,
            },
        ],
    }


__all__ = [
    "PartnerConnectorTrustAnalysisError",
    "PartnerConnectorTrustAnalysis",
    "analyze_supplied_partner_connector_trust",
    "analyze_supplied_partner_connector_trust_bytes",
    "verify_supplied_partner_connector_trust_analysis",
    "component_fixture",
]

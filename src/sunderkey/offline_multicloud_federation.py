"""Inert comparison of supplied cross-cloud federation trust declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "cloud_supplied_multicloud_federation_projection"
PROFILE_ID = "AOE-GC-D14-S09"
CAPABILITY_ID = "army.gc.d14.s09"
VECTOR_ID = "AV-GC-D14-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S09"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GC-D14-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f4bc312d47ac1303787d572089d10804ec4befb3662ad63a8b8d398eb9fcb290"
DOMAIN = "sunderkey.offline-multicloud-federation.v1"
MODEL_DOMAIN = "sunderkey.offline-multicloud-federation-model.v1"
SEMANTICS_PROFILE = "declared-exact-cross-provider-trust-exchange.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_TRUSTS = 64
MAX_EXCHANGES = 128
MAX_WORK = 2_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_PROVIDERS = ("aws", "azure", "gcp")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "provider_configuration_verified",
        "assertion_signature_verified",
        "issuer_verified",
        "audience_verified",
        "subject_verified",
        "role_mapping_verified",
        "exchange_observed",
        "token_issued_verified",
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
    "trusts": MAX_TRUSTS,
    "exchanges": MAX_EXCHANGES,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Trusts, issuer, audience, subject, role, disposition and outcomes are caller declarations.",
    "Only exact cross-provider labels and one-to-one trust mappings are modeled.",
    "Unknown assertion or incomplete trust context cannot yield a candidate.",
    "A candidate is a supplied deny-versus-issued mismatch, not a verified token exchange.",
    "Provider policy languages, token claims, cryptography and transitive trust are not modeled.",
    "No cloud tenant, provider, credential, network, process or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
)


class MulticloudFederationAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied federation model/report."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise MulticloudFederationAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise MulticloudFederationAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(c) <= 126 for c in item):
                raise MulticloudFederationAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise MulticloudFederationAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise MulticloudFederationAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise MulticloudFederationAnalysisError(
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
            raise MulticloudFederationAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise MulticloudFederationAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise MulticloudFederationAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise MulticloudFederationAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise MulticloudFederationAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise MulticloudFederationAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise MulticloudFederationAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise MulticloudFederationAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, MulticloudFederationAnalysisError):
            raise
        raise MulticloudFederationAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise MulticloudFederationAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise MulticloudFederationAnalysisError("Bounded exact identity required")
    return value


def _provider(value: Any) -> str:
    if type(value) is not str or value not in _PROVIDERS:
        raise MulticloudFederationAnalysisError("Supported provider label required")
    return value


def _rows(rows: Any, field: str, limit: int, label: str) -> list:
    if type(rows) is not list or not 1 <= len(rows) <= limit:
        raise MulticloudFederationAnalysisError(f"Bounded nonempty {label} required")
    names = [_identity(item[field]) for item in rows if type(item) is dict and field in item]
    if len(names) != len(rows) or names != sorted(set(names)):
        raise MulticloudFederationAnalysisError(f"Sorted unique {label} identities required")
    return rows


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    _exact(owned, {"schema_version", "trusts", "exchanges"}, "model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise MulticloudFederationAnalysisError("Exact schema version 1 required")
    trusts = _rows(owned["trusts"], "trust_id", MAX_TRUSTS, "trust")
    exchanges = _rows(owned["exchanges"], "exchange_id", MAX_EXCHANGES, "exchange")
    trust_ids = set()
    trust_fields = {
        "trust_id",
        "source_provider",
        "source_tenant",
        "target_provider",
        "target_tenant",
        "issuer_id",
        "audience_id",
        "subject_id",
        "role_id",
        "enabled",
        "contract_complete",
    }
    exchange_fields = {
        "exchange_id",
        "trust_id",
        "source_provider",
        "source_tenant",
        "target_provider",
        "target_tenant",
        "issuer_id",
        "audience_id",
        "subject_id",
        "role_id",
        "assertion_disposition",
        "context_complete",
        "supplied_outcome",
        "observation_complete",
    }
    for item in trusts:
        work.charge(16)
        _exact(item, trust_fields, "trust")
        source = _provider(item["source_provider"])
        target = _provider(item["target_provider"])
        if source == target:
            raise MulticloudFederationAnalysisError("Cross-provider trust required")
        for key in (
            "source_tenant",
            "target_tenant",
            "issuer_id",
            "audience_id",
            "subject_id",
            "role_id",
        ):
            _identity(item[key])
        if type(item["enabled"]) is not bool or type(item["contract_complete"]) is not bool:
            raise MulticloudFederationAnalysisError("Exact trust booleans required")
        trust_ids.add(item["trust_id"])
    for item in exchanges:
        work.charge(16)
        _exact(item, exchange_fields, "exchange")
        if _identity(item["trust_id"]) not in trust_ids:
            raise MulticloudFederationAnalysisError("Unknown trust reference")
        source = _provider(item["source_provider"])
        target = _provider(item["target_provider"])
        if source == target:
            raise MulticloudFederationAnalysisError("Cross-provider exchange required")
        for key in (
            "source_tenant",
            "target_tenant",
            "issuer_id",
            "audience_id",
            "subject_id",
            "role_id",
        ):
            if item[key] != "unknown":
                _identity(item[key])
        if item["assertion_disposition"] not in ("declared_verified", "failed", "unknown"):
            raise MulticloudFederationAnalysisError("Supported assertion disposition required")
        if item["supplied_outcome"] not in ("issued", "denied", "unknown"):
            raise MulticloudFederationAnalysisError("Supported supplied outcome required")
        if (
            type(item["context_complete"]) is not bool
            or type(item["observation_complete"]) is not bool
        ):
            raise MulticloudFederationAnalysisError("Exact exchange booleans required")
    return owned, source_text


def _observe(exchange: dict, trust: dict) -> dict:
    reasons: list[str] = []
    if not trust["contract_complete"]:
        reasons.append("trust_contract_incomplete")
    if not exchange["context_complete"]:
        reasons.append("exchange_context_incomplete")
    if not exchange["observation_complete"] or exchange["supplied_outcome"] == "unknown":
        reasons.append("exchange_observation_incomplete")
    if exchange["assertion_disposition"] == "unknown":
        reasons.append("assertion_disposition_unknown")
    keys = (
        "source_provider",
        "source_tenant",
        "target_provider",
        "target_tenant",
        "issuer_id",
        "audience_id",
        "subject_id",
        "role_id",
    )
    for key in keys:
        if exchange[key] == "unknown":
            reasons.append(key + "_unknown")
    mismatches = []
    expected = None
    if not reasons:
        mismatches = [key for key in keys if exchange[key] != trust[key]]
        if not trust["enabled"]:
            mismatches.append("trust_disabled")
        if exchange["assertion_disposition"] == "failed":
            mismatches.append("assertion_failed")
        if mismatches:
            expected = "deny"
        else:
            reasons.append("unmodeled_issuance_conditions")
    if reasons:
        outcome = "unknown"
    elif expected == "deny" and exchange["supplied_outcome"] == "issued":
        outcome = "candidate_declared_deny_issued_contradiction"
    else:
        outcome = "matches_declared_trust"
    return {
        "exchange_id": exchange["exchange_id"],
        "trust_id": exchange["trust_id"],
        "expected_outcome": expected,
        "supplied_outcome": exchange["supplied_outcome"],
        "outcome": outcome,
        "mismatched_declarations": mismatches,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    trusts = {item["trust_id"]: item for item in owned["trusts"]}
    observations = [_observe(row, trusts[row["trust_id"]]) for row in owned["exchanges"]]
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
        "exchange_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_deny_issued_contradiction" for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "exchange_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "MCF-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise MulticloudFederationAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise MulticloudFederationAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class MulticloudFederationAnalysis:
    """Detached supplied-data comparison, not live federation evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> MulticloudFederationAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> MulticloudFederationAnalysis:
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


def analyze_supplied_multicloud_federation(model: Any) -> MulticloudFederationAnalysis:
    """Compare finite supplied cross-provider trust/exchange declarations."""
    return MulticloudFederationAnalysis(_derive(model))


def analyze_supplied_multicloud_federation_bytes(
    *, model_bytes: Any
) -> MulticloudFederationAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise MulticloudFederationAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MulticloudFederationAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_multicloud_federation(_decode(text))


def verify_supplied_multicloud_federation_analysis(
    report: Any, *, model: Any
) -> MulticloudFederationAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not MulticloudFederationAnalysis:
        raise MulticloudFederationAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise MulticloudFederationAnalysisError("Report differs from separately supplied originals")
    return MulticloudFederationAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic cross-cloud matching, mismatch and uncertain exchanges."""
    return {
        "schema_version": 1,
        "trusts": [
            {
                "trust_id": "aws-to-gcp",
                "source_provider": "aws",
                "source_tenant": "aws-account-a",
                "target_provider": "gcp",
                "target_tenant": "gcp-project-b",
                "issuer_id": "issuer-a",
                "audience_id": "audience-b",
                "subject_id": "workload-a",
                "role_id": "reader",
                "enabled": True,
                "contract_complete": True,
            }
        ],
        "exchanges": [
            {
                "exchange_id": "deny-issued",
                "trust_id": "aws-to-gcp",
                "source_provider": "aws",
                "source_tenant": "aws-account-a",
                "target_provider": "gcp",
                "target_tenant": "gcp-project-b",
                "issuer_id": "issuer-a",
                "audience_id": "audience-other",
                "subject_id": "workload-a",
                "role_id": "reader",
                "assertion_disposition": "declared_verified",
                "context_complete": True,
                "supplied_outcome": "issued",
                "observation_complete": True,
            },
            {
                "exchange_id": "exact-match",
                "trust_id": "aws-to-gcp",
                "source_provider": "aws",
                "source_tenant": "aws-account-a",
                "target_provider": "gcp",
                "target_tenant": "gcp-project-b",
                "issuer_id": "issuer-a",
                "audience_id": "audience-b",
                "subject_id": "workload-a",
                "role_id": "reader",
                "assertion_disposition": "declared_verified",
                "context_complete": True,
                "supplied_outcome": "issued",
                "observation_complete": True,
            },
            {
                "exchange_id": "unknown-context",
                "trust_id": "aws-to-gcp",
                "source_provider": "aws",
                "source_tenant": "aws-account-a",
                "target_provider": "gcp",
                "target_tenant": "gcp-project-b",
                "issuer_id": "issuer-a",
                "audience_id": "audience-b",
                "subject_id": "workload-a",
                "role_id": "reader",
                "assertion_disposition": "unknown",
                "context_complete": False,
                "supplied_outcome": "unknown",
                "observation_complete": False,
            },
        ],
    }


__all__ = [
    "MulticloudFederationAnalysisError",
    "MulticloudFederationAnalysis",
    "analyze_supplied_multicloud_federation",
    "analyze_supplied_multicloud_federation_bytes",
    "verify_supplied_multicloud_federation_analysis",
    "component_fixture",
]

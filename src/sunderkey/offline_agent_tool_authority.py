"""Inert comparison of supplied agent tool-use and authority declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "agent_supplied_tool_authority_projection"
PROFILE_ID = "AOE-GD-D20-S14"
CAPABILITY_ID = "army.gd.d20.s14"
VECTOR_ID = "AV-GD-D20-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S14"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:deb46b9f30d5238f754c4a5fae7b1e3901de55d510501df5c6490b85873e4579"
DOMAIN = "sunderkey.offline-agent-tool-authority.v1"
ANALYSIS_PROFILE = "supplied-exact-tool-tier-resource-admission-v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DEPTH = 12
MAX_NATIVE_NODES = 8_192
MAX_SOURCES = 16
MAX_TOOLS = 64
MAX_RESOURCES = 64
MAX_USES = 64
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_TIERS = {"R0": 0, "R1": 1, "R2": 2}
_PROVENANCE_KINDS = frozenset(("synthetic_fixture", "operator_supplied"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "filesystem": "none",
    "network": "none",
    "process": "none",
    "provider": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class AgentToolAuthorityError(ValueError):
    """Invalid, unsupported, or over-budget supplied tool-use model."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise AgentToolAuthorityError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AgentToolAuthorityError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    seen = estimated = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_NATIVE_NODES or depth > MAX_DEPTH:
            raise AgentToolAuthorityError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if seen + len(stack) + 2 * len(item) > MAX_NATIVE_NODES:
                raise AgentToolAuthorityError("Native node limit exceeded")
            estimated += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise AgentToolAuthorityError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if seen + len(stack) + len(item) > MAX_NATIVE_NODES:
                raise AgentToolAuthorityError("Native node limit exceeded")
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise AgentToolAuthorityError("Invalid Unicode scalar text") from exc
            if len(encoded) > maximum:
                raise AgentToolAuthorityError("Native string exceeds bound")
            estimated += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise AgentToolAuthorityError("Native integer exceeds 64 bits")
            estimated += len(str(item))
        elif kind is bool:
            estimated += 5
        elif item is None:
            estimated += 4
        else:
            raise AgentToolAuthorityError("Unsupported native primitive")
        if estimated > 12 * maximum:
            raise AgentToolAuthorityError("Native serialized size limit exceeded")
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > maximum:
        raise AgentToolAuthorityError("Canonical byte limit exceeded")
    return text


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise AgentToolAuthorityError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise AgentToolAuthorityError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise AgentToolAuthorityError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise AgentToolAuthorityError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise AgentToolAuthorityError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise AgentToolAuthorityError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise AgentToolAuthorityError(f"{label} exceeds byte limit")
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise AgentToolAuthorityError("JSON depth limit exceeded")
        elif character in "]}":
            depth -= 1
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_json_integer,
            parse_float=_unsupported_number,
            parse_constant=_unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, AgentToolAuthorityError):
            raise
        raise AgentToolAuthorityError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _id_list(value: Any, limit: int, label: str) -> list[str]:
    if type(value) is not list or len(value) > limit:
        raise AgentToolAuthorityError(f"{label} must be a bounded native list")
    for item in value:
        _identifier(item, label)
        if item == "unknown":
            raise AgentToolAuthorityError(f"{label} cannot grant the unknown sentinel")
    if value != sorted(set(value)):
        raise AgentToolAuthorityError(f"{label} must be sorted and unique")
    return value


def _validate_model(model: Any) -> tuple[dict[str, Any], str, dict[str, Any]]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "evidence_sources", "policy", "tool_uses"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AgentToolAuthorityError("Unsupported schema version")
    model_source = _identifier(document["source_id"], "model source ID")
    sources = document["evidence_sources"]
    uses = document["tool_uses"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise AgentToolAuthorityError("Evidence sources must be nonempty and bounded")
    if type(uses) is not list or not 1 <= len(uses) <= MAX_USES:
        raise AgentToolAuthorityError("Tool uses must be nonempty and bounded")
    source_ids = set()
    for raw in sources:
        source = _exact(raw, {"source_id", "provenance_kind"}, "evidence source")
        source_id = _identifier(source["source_id"], "evidence source ID")
        if source_id == model_source or source_id in source_ids:
            raise AgentToolAuthorityError("Evidence source IDs must be distinct")
        if (
            type(source["provenance_kind"]) is not str
            or source["provenance_kind"] not in _PROVENANCE_KINDS
        ):
            raise AgentToolAuthorityError("Unsupported provenance kind")
        source_ids.add(source_id)
    policy = _exact(
        document["policy"],
        {"source_id", "complete", "maximum_tier", "allowed_tool_ids", "allowed_resource_ids"},
        "policy",
    )
    if _identifier(policy["source_id"], "policy source ID") not in source_ids:
        raise AgentToolAuthorityError("Missing policy provenance")
    if type(policy["complete"]) is not bool:
        raise AgentToolAuthorityError("Policy completeness must be a native boolean")
    if type(policy["maximum_tier"]) is not str or policy["maximum_tier"] not in _TIERS:
        raise AgentToolAuthorityError("Unsupported maximum action tier")
    _id_list(policy["allowed_tool_ids"], MAX_TOOLS, "allowed tool IDs")
    _id_list(policy["allowed_resource_ids"], MAX_RESOURCES, "allowed resource IDs")
    use_ids = set()
    for raw in uses:
        use = _exact(
            raw,
            {
                "use_id",
                "tool_id",
                "resource_id",
                "requested_tier",
                "approval_state",
                "context_complete",
                "observed_admission",
                "observation_complete",
                "source_id",
            },
            "tool use",
        )
        use_id = _identifier(use["use_id"], "use ID")
        _identifier(use["tool_id"], "tool ID")
        _identifier(use["resource_id"], "resource ID")
        if use_id in use_ids:
            raise AgentToolAuthorityError("Duplicate tool use ID")
        use_ids.add(use_id)
        if _identifier(use["source_id"], "use source ID") not in source_ids:
            raise AgentToolAuthorityError("Missing tool-use provenance")
        if type(use["requested_tier"]) is not str or use["requested_tier"] not in _TIERS:
            raise AgentToolAuthorityError("Unsupported requested tier")
        if type(use["approval_state"]) is not str or use["approval_state"] not in {
            "approved",
            "denied",
            "unknown",
        }:
            raise AgentToolAuthorityError("Unsupported approval state")
        if type(use["observed_admission"]) is not str or use["observed_admission"] not in {
            "admitted",
            "rejected",
            "unknown",
        }:
            raise AgentToolAuthorityError("Unsupported supplied admission")
        if (
            type(use["context_complete"]) is not bool
            or type(use["observation_complete"]) is not bool
        ):
            raise AgentToolAuthorityError("Completeness fields must be native booleans")
    return document, model_text, policy


def _observe(use: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    unknowns = []
    if not policy["complete"]:
        unknowns.append("policy_incomplete")
    if not use["context_complete"]:
        unknowns.append("use_context_incomplete")
    if not use["observation_complete"] or use["observed_admission"] == "unknown":
        unknowns.append("admission_observation_incomplete")
    if use["approval_state"] == "unknown":
        unknowns.append("approval_unknown")
    if use["tool_id"] == "unknown":
        unknowns.append("tool_unknown")
    if use["resource_id"] == "unknown":
        unknowns.append("resource_unknown")
    violations = []
    expected = None
    if not unknowns:
        if use["tool_id"] not in policy["allowed_tool_ids"]:
            violations.append("tool_not_allowed")
        if use["resource_id"] not in policy["allowed_resource_ids"]:
            violations.append("resource_not_allowed")
        if _TIERS[use["requested_tier"]] > _TIERS[policy["maximum_tier"]]:
            violations.append("tier_exceeded")
        if use["approval_state"] == "denied":
            violations.append("approval_denied")
        expected = "reject" if violations else "admit"
    if unknowns:
        disposition = "unknown"
    elif expected == "reject" and use["observed_admission"] == "admitted":
        disposition = "candidate_declared_overreach"
    elif expected == "admit" and use["observed_admission"] == "rejected":
        disposition = "declared_allow_rejected_contradiction"
    else:
        disposition = "matches_declared_policy"
    return {
        "use_id": use["use_id"],
        "expected_admission": expected,
        "supplied_admission": use["observed_admission"],
        "disposition": disposition,
        "violated_declarations": violations,
        "unknowns": unknowns,
    }


def _projection(model: Any) -> dict[str, Any]:
    document, model_text, policy = _validate_model(model)
    observations = [
        _observe(use, policy)
        for use in sorted(document["tool_uses"], key=lambda item: item["use_id"])
    ]
    report = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "scheduled_wave_id": WAVE_ID,
        "commander_profile_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source": {
            "source_id": document["source_id"],
            "model_sha256": _sha(model_text),
            "evidence_source_ids": sorted(
                source["source_id"] for source in document["evidence_sources"]
            ),
        },
        "supplied_model": model,
        "tool_use_projections": observations,
        "candidate_count": sum(
            row["disposition"] == "candidate_declared_overreach" for row in observations
        ),
        "unknown_count": sum(row["disposition"] == "unknown" for row in observations),
        "uncertainty": [
            "Policy, approval, admission, and provenance values are supplied declarations.",
            "A contradiction does not establish actual authority, tool use, or excessive agency.",
            "Neither matching policy nor approval state proves safe or authorized execution.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "ATA-" + digest[:32].upper()
    report["report_sha256"] = "sha256:" + digest
    _canonical(report, maximum=MAX_REPORT_BYTES)
    return report


_REPORT_FIELDS = {
    "schema_version",
    "component_id",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "work_package_id",
    "scheduled_wave_id",
    "commander_profile_id",
    "independent_validator_id",
    "blueprint_sha256",
    "source",
    "supplied_model",
    "tool_use_projections",
    "candidate_count",
    "unknown_count",
    "uncertainty",
    "offline_only",
    "target_behavior_verified",
    "live_vulnerability_verdict",
    "effects",
    "report_id",
    "report_sha256",
}


def _replay(document: Any) -> str:
    _exact(document, _REPORT_FIELDS, "report")
    expected = _projection(document["supplied_model"])
    if document != expected:
        raise AgentToolAuthorityError("Report does not replay retained model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> AgentToolAuthorityReport:
    report = object.__new__(AgentToolAuthorityReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class AgentToolAuthorityReport:
    """Detached unsigned projection, requiring separate original-source replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not AgentToolAuthorityReport:
            raise AgentToolAuthorityError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> AgentToolAuthorityReport:
        if cls is not AgentToolAuthorityReport:
            raise AgentToolAuthorityError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> AgentToolAuthorityReport:
        if cls is not AgentToolAuthorityReport or type(value) is not str:
            raise AgentToolAuthorityError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise AgentToolAuthorityError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not AgentToolAuthorityReport or type(self.document_json) is not str:
            raise AgentToolAuthorityError("Exact native report wrapper required")
        return AgentToolAuthorityReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_agent_tool_authority(model: Any) -> AgentToolAuthorityReport:
    """Compare supplied policy and admission only; never call a tool."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_agent_tool_authority_bytes(*, model_bytes: Any) -> AgentToolAuthorityReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise AgentToolAuthorityError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentToolAuthorityError("Model bytes must be UTF-8") from exc
    return analyze_supplied_agent_tool_authority(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_agent_tool_authority(report: Any, *, model: Any) -> AgentToolAuthorityReport:
    """Rebuild against an independently supplied original model."""
    if type(report) is not AgentToolAuthorityReport:
        raise AgentToolAuthorityError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise AgentToolAuthorityError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic authority declarations with opaque tool IDs."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-tool-authority-model",
        "evidence_sources": [
            {"source_id": "synthetic-policy", "provenance_kind": "synthetic_fixture"},
            {"source_id": "synthetic-admissions", "provenance_kind": "synthetic_fixture"},
        ],
        "policy": {
            "source_id": "synthetic-policy",
            "complete": True,
            "maximum_tier": "R1",
            "allowed_tool_ids": ["tool-read"],
            "allowed_resource_ids": ["resource-a"],
        },
        "tool_uses": [
            {
                "use_id": "use-overreach",
                "tool_id": "tool-read",
                "resource_id": "resource-a",
                "requested_tier": "R2",
                "approval_state": "approved",
                "context_complete": True,
                "observed_admission": "admitted",
                "observation_complete": True,
                "source_id": "synthetic-admissions",
            },
            {
                "use_id": "use-match",
                "tool_id": "tool-read",
                "resource_id": "resource-a",
                "requested_tier": "R0",
                "approval_state": "approved",
                "context_complete": True,
                "observed_admission": "admitted",
                "observation_complete": True,
                "source_id": "synthetic-admissions",
            },
            {
                "use_id": "use-unknown",
                "tool_id": "unknown",
                "resource_id": "resource-a",
                "requested_tier": "R1",
                "approval_state": "unknown",
                "context_complete": False,
                "observed_admission": "unknown",
                "observation_complete": False,
                "source_id": "synthetic-admissions",
            },
        ],
    }


__all__ = [
    "AgentToolAuthorityError",
    "AgentToolAuthorityReport",
    "analyze_supplied_agent_tool_authority",
    "analyze_supplied_agent_tool_authority_bytes",
    "verify_supplied_agent_tool_authority",
    "component_fixture",
]

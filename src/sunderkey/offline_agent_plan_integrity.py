"""Inert comparison of supplied agent plan revisions with a declared baseline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "agent_supplied_plan_revision_integrity"
PROFILE_ID = "AOE-GD-D20-S19"
CAPABILITY_ID = "army.gd.d20.s19"
VECTOR_ID = "AV-GD-D20-S19-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S19"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:2a48fbecd6a0d2771fc461bee8285a459c04e0aeaf7c12425956abac56454187"
DOMAIN = "sunderkey.offline-agent-plan-integrity.v1"
ANALYSIS_PROFILE = "supplied-single-hop-baseline-plan-revision-v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DEPTH = 12
MAX_NATIVE_NODES = 8_192
MAX_SOURCES = 16
MAX_STEPS = 64
MAX_REVISIONS = 64
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_PROVENANCE_KINDS = frozenset(("synthetic_fixture", "operator_supplied"))
_ORIGINS = frozenset(("owner", "agent", "external", "unknown"))
_APPROVALS = frozenset(("approved", "denied", "unknown"))
_APPLICATIONS = frozenset(("applied", "rejected", "unknown"))
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


class AgentPlanIntegrityError(ValueError):
    """Invalid, unsupported, or over-budget supplied plan model."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise AgentPlanIntegrityError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AgentPlanIntegrityError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    seen = estimated = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_NATIVE_NODES or depth > MAX_DEPTH:
            raise AgentPlanIntegrityError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if seen + len(stack) + 2 * len(item) > MAX_NATIVE_NODES:
                raise AgentPlanIntegrityError("Native node limit exceeded")
            estimated += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise AgentPlanIntegrityError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if seen + len(stack) + len(item) > MAX_NATIVE_NODES:
                raise AgentPlanIntegrityError("Native node limit exceeded")
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise AgentPlanIntegrityError("Invalid Unicode scalar text") from exc
            if len(encoded) > maximum:
                raise AgentPlanIntegrityError("Native string exceeds bound")
            estimated += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise AgentPlanIntegrityError("Native integer exceeds 64 bits")
            estimated += len(str(item))
        elif kind is bool:
            estimated += 5
        elif item is None:
            estimated += 4
        else:
            raise AgentPlanIntegrityError("Unsupported native primitive")
        if estimated > 12 * maximum:
            raise AgentPlanIntegrityError("Native serialized size limit exceeded")
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > maximum:
        raise AgentPlanIntegrityError("Canonical byte limit exceeded")
    return text


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise AgentPlanIntegrityError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise AgentPlanIntegrityError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise AgentPlanIntegrityError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise AgentPlanIntegrityError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise AgentPlanIntegrityError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise AgentPlanIntegrityError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise AgentPlanIntegrityError(f"{label} exceeds byte limit")
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
                raise AgentPlanIntegrityError("JSON depth limit exceeded")
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
        if isinstance(exc, AgentPlanIntegrityError):
            raise
        raise AgentPlanIntegrityError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _steps(value: Any, label: str) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= MAX_STEPS:
        raise AgentPlanIntegrityError(f"{label} must be a nonempty bounded list")
    for step in value:
        _identifier(step, label)
        if step == "unknown":
            raise AgentPlanIntegrityError("Unknown sentinel cannot be a plan step")
    if len(set(value)) != len(value):
        raise AgentPlanIntegrityError("Plan steps must be unique")
    return value


def _validate_model(model: Any) -> tuple[dict[str, Any], str, dict[str, Any]]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "evidence_sources", "baseline", "revisions"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AgentPlanIntegrityError("Unsupported schema version")
    model_source = _identifier(document["source_id"], "model source ID")
    sources = document["evidence_sources"]
    revisions = document["revisions"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise AgentPlanIntegrityError("Evidence sources must be nonempty and bounded")
    if type(revisions) is not list or not 1 <= len(revisions) <= MAX_REVISIONS:
        raise AgentPlanIntegrityError("Revisions must be nonempty and bounded")
    source_ids = set()
    for raw in sources:
        source = _exact(raw, {"source_id", "provenance_kind"}, "evidence source")
        source_id = _identifier(source["source_id"], "evidence source ID")
        if source_id == model_source or source_id in source_ids:
            raise AgentPlanIntegrityError("Evidence source IDs must be distinct")
        if (
            type(source["provenance_kind"]) is not str
            or source["provenance_kind"] not in _PROVENANCE_KINDS
        ):
            raise AgentPlanIntegrityError("Unsupported provenance kind")
        source_ids.add(source_id)
    baseline = _exact(document["baseline"], {"source_id", "goal_id", "step_ids"}, "baseline")
    if _identifier(baseline["source_id"], "baseline source ID") not in source_ids:
        raise AgentPlanIntegrityError("Missing baseline provenance")
    if _identifier(baseline["goal_id"], "baseline goal ID") == "unknown":
        raise AgentPlanIntegrityError("Unknown sentinel cannot be baseline goal")
    _steps(baseline["step_ids"], "baseline steps")
    revision_ids = set()
    for raw in revisions:
        revision = _exact(
            raw,
            {
                "revision_id",
                "previous_goal_id",
                "previous_step_ids",
                "proposed_goal_id",
                "proposed_step_ids",
                "origin",
                "approval_state",
                "application_state",
                "context_complete",
                "observation_complete",
                "source_id",
            },
            "revision",
        )
        revision_id = _identifier(revision["revision_id"], "revision ID")
        if revision_id in revision_ids:
            raise AgentPlanIntegrityError("Duplicate revision ID")
        revision_ids.add(revision_id)
        for field in ("previous_goal_id", "proposed_goal_id"):
            if _identifier(revision[field], field) == "unknown":
                raise AgentPlanIntegrityError("Unknown sentinel cannot be a goal ID")
        _steps(revision["previous_step_ids"], "previous steps")
        _steps(revision["proposed_step_ids"], "proposed steps")
        if _identifier(revision["source_id"], "revision source ID") not in source_ids:
            raise AgentPlanIntegrityError("Missing revision provenance")
        if type(revision["origin"]) is not str or revision["origin"] not in _ORIGINS:
            raise AgentPlanIntegrityError("Unsupported revision origin")
        if (
            type(revision["approval_state"]) is not str
            or revision["approval_state"] not in _APPROVALS
        ):
            raise AgentPlanIntegrityError("Unsupported approval state")
        if (
            type(revision["application_state"]) is not str
            or revision["application_state"] not in _APPLICATIONS
        ):
            raise AgentPlanIntegrityError("Unsupported application state")
        if (
            type(revision["context_complete"]) is not bool
            or type(revision["observation_complete"]) is not bool
        ):
            raise AgentPlanIntegrityError("Completeness fields must be native booleans")
    return document, model_text, baseline


def _observe(revision: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    unknowns = []
    if (
        revision["previous_goal_id"] != baseline["goal_id"]
        or revision["previous_step_ids"] != baseline["step_ids"]
    ):
        unknowns.append("previous_snapshot_not_baseline")
    if not revision["context_complete"]:
        unknowns.append("revision_context_incomplete")
    if not revision["observation_complete"] or revision["application_state"] == "unknown":
        unknowns.append("application_observation_incomplete")
    if revision["origin"] == "unknown":
        unknowns.append("origin_unknown")
    if revision["approval_state"] == "unknown":
        unknowns.append("approval_unknown")
    changed = (
        revision["proposed_goal_id"] != baseline["goal_id"]
        or revision["proposed_step_ids"] != baseline["step_ids"]
    )
    if unknowns:
        disposition = "unknown"
    elif not changed:
        disposition = "declared_unchanged_plan"
    elif revision["application_state"] == "rejected":
        disposition = "declared_change_not_applied"
    elif revision["origin"] == "owner" and revision["approval_state"] == "denied":
        disposition = "unknown_owner_approval_conflict"
        unknowns.append("owner_approval_conflict")
    elif revision["approval_state"] == "denied":
        disposition = "candidate_declared_denied_change_applied"
    else:
        disposition = "declared_approved_change_unverified"
    return {
        "revision_id": revision["revision_id"],
        "origin": revision["origin"],
        "approval_state": revision["approval_state"],
        "application_state": revision["application_state"],
        "goal_changed": revision["proposed_goal_id"] != baseline["goal_id"],
        "step_sequence_changed": revision["proposed_step_ids"] != baseline["step_ids"],
        "disposition": disposition,
        "unknowns": unknowns,
    }


def _projection(model: Any) -> dict[str, Any]:
    document, model_text, baseline = _validate_model(model)
    observations = [
        _observe(revision, baseline)
        for revision in sorted(document["revisions"], key=lambda item: item["revision_id"])
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
        "revision_projections": observations,
        "candidate_count": sum(
            row["disposition"] == "candidate_declared_denied_change_applied" for row in observations
        ),
        "unknown_count": sum(row["disposition"].startswith("unknown") for row in observations),
        "uncertainty": [
            "Baseline, revision origin, approval, application, and provenance are supplied claims.",
            "Each proposal is compared only to the declared baseline, not a live plan history.",
            "A candidate contradiction does not prove prompt injection, hijacking, or execution.",
            "An approval declaration is not authenticated action authority.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "APL-" + digest[:32].upper()
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
    "revision_projections",
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
        raise AgentPlanIntegrityError("Report does not replay retained model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> AgentPlanIntegrityReport:
    report = object.__new__(AgentPlanIntegrityReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class AgentPlanIntegrityReport:
    """Detached unsigned projection, requiring separate original-source replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not AgentPlanIntegrityReport:
            raise AgentPlanIntegrityError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> AgentPlanIntegrityReport:
        if cls is not AgentPlanIntegrityReport:
            raise AgentPlanIntegrityError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> AgentPlanIntegrityReport:
        if cls is not AgentPlanIntegrityReport or type(value) is not str:
            raise AgentPlanIntegrityError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise AgentPlanIntegrityError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not AgentPlanIntegrityReport or type(self.document_json) is not str:
            raise AgentPlanIntegrityError("Exact native report wrapper required")
        return AgentPlanIntegrityReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_agent_plan_integrity(model: Any) -> AgentPlanIntegrityReport:
    """Compare supplied revision metadata only; never run an agent or plan."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_agent_plan_integrity_bytes(*, model_bytes: Any) -> AgentPlanIntegrityReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise AgentPlanIntegrityError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentPlanIntegrityError("Model bytes must be UTF-8") from exc
    return analyze_supplied_agent_plan_integrity(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_agent_plan_integrity(report: Any, *, model: Any) -> AgentPlanIntegrityReport:
    """Rebuild against an independently supplied original model."""
    if type(report) is not AgentPlanIntegrityReport:
        raise AgentPlanIntegrityError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise AgentPlanIntegrityError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic plan metadata without instructions or prompt text."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-plan-model",
        "evidence_sources": [
            {"source_id": "synthetic-baseline", "provenance_kind": "synthetic_fixture"},
            {"source_id": "synthetic-revisions", "provenance_kind": "synthetic_fixture"},
        ],
        "baseline": {
            "source_id": "synthetic-baseline",
            "goal_id": "goal-review",
            "step_ids": ["step-inventory", "step-summarize"],
        },
        "revisions": [
            {
                "revision_id": "revision-denied-applied",
                "previous_goal_id": "goal-review",
                "previous_step_ids": ["step-inventory", "step-summarize"],
                "proposed_goal_id": "goal-expand",
                "proposed_step_ids": ["step-inventory", "step-expand"],
                "origin": "external",
                "approval_state": "denied",
                "application_state": "applied",
                "context_complete": True,
                "observation_complete": True,
                "source_id": "synthetic-revisions",
            },
            {
                "revision_id": "revision-rejected",
                "previous_goal_id": "goal-review",
                "previous_step_ids": ["step-inventory", "step-summarize"],
                "proposed_goal_id": "goal-expand",
                "proposed_step_ids": ["step-inventory", "step-expand"],
                "origin": "agent",
                "approval_state": "denied",
                "application_state": "rejected",
                "context_complete": True,
                "observation_complete": True,
                "source_id": "synthetic-revisions",
            },
            {
                "revision_id": "revision-unknown",
                "previous_goal_id": "goal-review",
                "previous_step_ids": ["step-inventory", "step-summarize"],
                "proposed_goal_id": "goal-expand",
                "proposed_step_ids": ["step-inventory", "step-expand"],
                "origin": "unknown",
                "approval_state": "unknown",
                "application_state": "unknown",
                "context_complete": False,
                "observation_complete": False,
                "source_id": "synthetic-revisions",
            },
        ],
    }


__all__ = [
    "AgentPlanIntegrityError",
    "AgentPlanIntegrityReport",
    "analyze_supplied_agent_plan_integrity",
    "analyze_supplied_agent_plan_integrity_bytes",
    "verify_supplied_agent_plan_integrity",
    "component_fixture",
]

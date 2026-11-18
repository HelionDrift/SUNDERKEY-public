"""Bounded offline projection of supplied API response data flow."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S15"
CAPABILITY_ID = "army.gb.d06.s15"
VECTOR_ID = "AV-GB-D06-S15-01"
DOMAIN = "sunderkey.offline-api-downstream-trust.v1"
ANALYSIS_PROFILE = "supplied-field-step-sink-dataflow-v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 524_288
MAX_DEPTH = 24
MAX_NODES = 32_768
MAX_FIELDS = 32
MAX_STEPS = 64
MAX_SINKS = 32
MAX_EDGES = 256
MAX_WORK = 200_000
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_SENSITIVE_KINDS = ("command_argument", "html_render", "sql_query", "url_fetch")
_SINK_KINDS = frozenset((*_SENSITIVE_KINDS, "telemetry"))
_STEP_KINDS = frozenset(("identity_transform", "validation", "opaque_transform"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "network": "none",
    "payload_generation": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class ApiDownstreamTrustError(ValueError):
    """Invalid, unsupported, or over-budget supplied data-flow model."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(key) is not str for key in value):
        raise ApiDownstreamTrustError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ApiDownstreamTrustError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ApiDownstreamTrustError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(stack) + 2 * len(item) > MAX_NODES:
                raise ApiDownstreamTrustError("Native node limit exceeded")
            size += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise ApiDownstreamTrustError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise ApiDownstreamTrustError("Native node limit exceeded")
            size += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise ApiDownstreamTrustError("Invalid Unicode scalar text") from exc
            if len(encoded) > MAX_MODEL_BYTES:
                raise ApiDownstreamTrustError("Native string exceeds bound")
            size += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise ApiDownstreamTrustError("Native integer exceeds 64 bits")
            size += len(str(item))
        elif kind is bool:
            size += 5
        elif item is None:
            size += 4
        else:
            raise ApiDownstreamTrustError("Unsupported native primitive")
        if size > 12 * maximum:
            raise ApiDownstreamTrustError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise ApiDownstreamTrustError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise ApiDownstreamTrustError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise ApiDownstreamTrustError("JSON integer exceeds bound")
    result = int(text)
    if result.bit_length() > 63:
        raise ApiDownstreamTrustError("JSON integer exceeds bound")
    return result


def _unsupported_number(_text: str) -> None:
    raise ApiDownstreamTrustError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise ApiDownstreamTrustError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise ApiDownstreamTrustError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise ApiDownstreamTrustError(f"{label} exceeds byte limit")
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
                raise ApiDownstreamTrustError("JSON depth limit exceeded")
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
        if isinstance(exc, ApiDownstreamTrustError):
            raise
        raise ApiDownstreamTrustError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _producer(value: Any) -> tuple[str, dict[str, str]]:
    producer = _exact(value, {"source_id", "response_fields"}, "producer")
    source_id = _identifier(producer["source_id"], "producer source_id")
    fields = producer["response_fields"]
    if type(fields) is not list or len(fields) > MAX_FIELDS:
        raise ApiDownstreamTrustError("Response fields must be a bounded list")
    result = {}
    for raw in fields:
        field = _exact(raw, {"field_id", "trust"}, "response field")
        field_id = _identifier(field["field_id"], "field_id")
        if (
            field_id in result
            or type(field["trust"]) is not str
            or field["trust"] not in {"trusted", "untrusted"}
        ):
            raise ApiDownstreamTrustError("Duplicate field or unsupported trust declaration")
        result[field_id] = field["trust"]
    return source_id, result


def _flow(
    value: Any, fields: dict[str, str]
) -> tuple[str, dict[str, dict[str, Any]], dict[str, str], dict[str, list[str]], set[str], int]:
    flow = _exact(value, {"source_id", "steps", "sinks", "edges"}, "flow")
    source_id = _identifier(flow["source_id"], "flow source_id")
    raw_steps = flow["steps"]
    raw_sinks = flow["sinks"]
    raw_edges = flow["edges"]
    if type(raw_steps) is not list or len(raw_steps) > MAX_STEPS:
        raise ApiDownstreamTrustError("Steps must be a bounded list")
    if type(raw_sinks) is not list or len(raw_sinks) > MAX_SINKS:
        raise ApiDownstreamTrustError("Sinks must be a bounded list")
    if type(raw_edges) is not list or len(raw_edges) > MAX_EDGES:
        raise ApiDownstreamTrustError("Edges must be a bounded list")
    steps: dict[str, dict[str, Any]] = {}
    sinks: dict[str, str] = {}
    for raw in raw_steps:
        step = _exact(raw, {"step_id", "kind", "protected_sink_kinds"}, "step")
        step_id = _identifier(step["step_id"], "step_id")
        kind = step["kind"]
        if (
            step_id in fields
            or step_id in steps
            or type(kind) is not str
            or kind not in _STEP_KINDS
        ):
            raise ApiDownstreamTrustError("Duplicate step or unsupported step kind")
        protections = step["protected_sink_kinds"]
        if type(protections) is not list or len(protections) > len(_SENSITIVE_KINDS):
            raise ApiDownstreamTrustError("Step protections must be bounded")
        if any(type(item) is not str or item not in _SENSITIVE_KINDS for item in protections):
            raise ApiDownstreamTrustError("Unsupported protected sink kind")
        if len(set(protections)) != len(protections):
            raise ApiDownstreamTrustError("Duplicate protection kind")
        if kind != "validation" and protections:
            raise ApiDownstreamTrustError("Non-validation step cannot declare protection")
        steps[step_id] = step
    for raw in raw_sinks:
        sink = _exact(raw, {"sink_id", "sink_kind"}, "sink")
        sink_id = _identifier(sink["sink_id"], "sink_id")
        kind = sink["sink_kind"]
        if (
            sink_id in fields
            or sink_id in steps
            or sink_id in sinks
            or type(kind) is not str
            or kind not in _SINK_KINDS
        ):
            raise ApiDownstreamTrustError("Duplicate sink or unsupported sink kind")
        sinks[sink_id] = kind
    outgoing: dict[str, list[str]] = {node: [] for node in (*fields, *steps, *sinks)}
    edge_pairs = set()
    for raw in raw_edges:
        edge = _exact(raw, {"from_id", "to_id"}, "edge")
        from_id = _identifier(edge["from_id"], "edge from_id")
        to_id = _identifier(edge["to_id"], "edge to_id")
        pair = (from_id, to_id)
        if (
            from_id not in outgoing
            or to_id not in outgoing
            or from_id in sinks
            or to_id in fields
            or pair in edge_pairs
        ):
            raise ApiDownstreamTrustError("Unknown or unsupported edge identity")
        edge_pairs.add(pair)
        outgoing[from_id].append(to_id)
    for children in outgoing.values():
        children.sort()
    cyclic_nodes, cycle_work = _cycle_nodes(outgoing, steps)
    return source_id, steps, sinks, outgoing, cyclic_nodes, cycle_work


def _cycle_nodes(
    outgoing: dict[str, list[str]], steps: dict[str, dict[str, Any]]
) -> tuple[set[str], int]:
    """Find only step nodes that can return to themselves within the finite graph."""
    cyclic = set()
    work = 0
    for start in sorted(steps):
        ready = deque(outgoing[start])
        seen = set()
        while ready:
            node = ready.popleft()
            work += 1
            if work > MAX_WORK:
                raise ApiDownstreamTrustError("Cycle analysis work limit exceeded")
            if node == start:
                cyclic.add(start)
                break
            if node in seen:
                continue
            seen.add(node)
            ready.extend(outgoing[node])
    return cyclic, work


def _reachable(field_id: str, outgoing: dict[str, list[str]], sinks: dict[str, str]) -> list[str]:
    ready = deque((field_id,))
    visited = {field_id}
    result = set()
    while ready:
        node = ready.popleft()
        for child in outgoing[node]:
            if child in visited:
                continue
            visited.add(child)
            if child in sinks and sinks[child] in _SENSITIVE_KINDS:
                result.add(child)
            else:
                ready.append(child)
    return sorted(result)


def _paths(
    field_id: str,
    steps: dict[str, dict[str, Any]],
    sinks: dict[str, str],
    outgoing: dict[str, list[str]],
    cyclic_nodes: set[str],
    work: list[int],
) -> dict[str, dict[str, tuple[str, ...]]]:
    ready = deque(((field_id, 0, False, False, (field_id,)),))
    visited = {(field_id, 0, False, False)}
    results: dict[str, dict[str, tuple[str, ...]]] = {}
    kind_bits = {kind: 1 << index for index, kind in enumerate(_SENSITIVE_KINDS)}
    while ready:
        node, mask, opaque, cyclic, path = ready.popleft()
        work[0] += 1
        if work[0] > MAX_WORK:
            raise ApiDownstreamTrustError("Data-flow work limit exceeded")
        for child in outgoing[node]:
            next_mask = mask
            next_opaque = opaque
            next_cyclic = cyclic or child in cyclic_nodes
            if child in steps:
                step = steps[child]
                if step["kind"] == "opaque_transform":
                    next_opaque = True
                elif step["kind"] == "validation":
                    for kind in step["protected_sink_kinds"]:
                        next_mask |= kind_bits[kind]
            next_path = (*path, child)
            if child in sinks:
                kind = sinks[child]
                if kind not in kind_bits:
                    continue
                if next_cyclic:
                    status = "unsupported_cycle"
                elif next_opaque:
                    status = "opaque_transform"
                elif next_mask & kind_bits[kind]:
                    status = "declared_protection_unverified"
                else:
                    status = "candidate"
                results.setdefault(child, {}).setdefault(status, next_path)
                continue
            state = (child, next_mask, next_opaque, next_cyclic)
            if state not in visited:
                visited.add(state)
                ready.append((child, next_mask, next_opaque, next_cyclic, next_path))
    return results


def _projection(model: Any) -> dict[str, Any]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "graph_complete", "producer", "flow"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ApiDownstreamTrustError("Unsupported schema version")
    source_id = _identifier(document["source_id"], "model source_id")
    complete = document["graph_complete"]
    if type(complete) is not bool:
        raise ApiDownstreamTrustError("Graph completeness must be a native boolean")
    producer_id, fields = _producer(document["producer"])
    flow_id, steps, sinks, outgoing, cyclic_nodes, cycle_work = _flow(document["flow"], fields)
    if len({source_id, producer_id, flow_id}) != 3:
        raise ApiDownstreamTrustError("Source identifiers must be distinct")
    candidates = []
    unknowns = []
    work = [cycle_work]
    for field_id in sorted(fields):
        if fields[field_id] != "untrusted":
            continue
        if not complete:
            for sink_id in _reachable(field_id, outgoing, sinks):
                unknowns.append(
                    {
                        "field_id": field_id,
                        "sink_id": sink_id,
                        "reason": "incomplete_graph",
                    }
                )
            continue
        results = _paths(field_id, steps, sinks, outgoing, cyclic_nodes, work)
        for sink_id in sorted(results):
            statuses = results[sink_id]
            if "candidate" in statuses:
                candidates.append(
                    {
                        "field_id": field_id,
                        "sink_id": sink_id,
                        "sink_kind": sinks[sink_id],
                        "path": list(statuses["candidate"]),
                    }
                )
            if "unsupported_cycle" in statuses:
                unknowns.append(
                    {
                        "field_id": field_id,
                        "sink_id": sink_id,
                        "reason": "unsupported_cycle",
                        "path": list(statuses["unsupported_cycle"]),
                    }
                )
            elif "candidate" not in statuses:
                reason = (
                    "opaque_transform"
                    if "opaque_transform" in statuses
                    else "declared_protection_unverified"
                )
                unknowns.append(
                    {
                        "field_id": field_id,
                        "sink_id": sink_id,
                        "reason": reason,
                    }
                )
    if not complete and not unknowns:
        unknowns.append(
            {
                "field_id": None,
                "sink_id": None,
                "reason": "incomplete_graph",
            }
        )
    if (
        complete
        and cyclic_nodes
        and not any(row["reason"] == "unsupported_cycle" for row in unknowns)
    ):
        unknowns.append(
            {
                "field_id": None,
                "sink_id": None,
                "reason": "unsupported_cycle",
            }
        )
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": source_id,
            "model_sha256": _sha(model_text),
            "producer": {
                "source_id": producer_id,
                "sha256": _sha(_canonical(document["producer"], maximum=MAX_MODEL_BYTES)),
            },
            "flow": {
                "source_id": flow_id,
                "sha256": _sha(_canonical(document["flow"], maximum=MAX_MODEL_BYTES)),
            },
        },
        "supplied_model": model,
        "analysis_status": (
            "unknown_incomplete_graph"
            if not complete
            else "partial_unsupported_cycle_projection"
            if cyclic_nodes
            else "complete_acyclic_projection"
        ),
        "candidate_paths": candidates,
        "unknowns": unknowns,
        "uncertainty": [
            "Field trust, graph completeness, step meaning, and sink labels are supplied premises.",
            "Declared validation is not proof of effective sanitization or authorization.",
            "Opaque transforms and cycles are not interpreted as safe data flow.",
            "A candidate path is not payload execution, exploitability, or a live vulnerability.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "ADT-" + digest[:32].upper()
    report["report_sha256"] = "sha256:" + digest
    _canonical(report, maximum=MAX_REPORT_BYTES)
    return report


_REPORT_FIELDS = {
    "schema_version",
    "analysis_profile",
    "profile_id",
    "capability_id",
    "vector_id",
    "source",
    "supplied_model",
    "analysis_status",
    "candidate_paths",
    "unknowns",
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
        raise ApiDownstreamTrustError("Report does not replay supplied model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> ApiDownstreamTrustReport:
    report = object.__new__(ApiDownstreamTrustReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class ApiDownstreamTrustReport:
    """Detached unsigned data-flow projection retaining its supplied model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not ApiDownstreamTrustReport:
            raise ApiDownstreamTrustError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> ApiDownstreamTrustReport:
        if cls is not ApiDownstreamTrustReport:
            raise ApiDownstreamTrustError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> ApiDownstreamTrustReport:
        if cls is not ApiDownstreamTrustReport or type(value) is not str:
            raise ApiDownstreamTrustError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise ApiDownstreamTrustError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not ApiDownstreamTrustReport or type(self.document_json) is not str:
            raise ApiDownstreamTrustError("Exact native report wrapper required")
        return ApiDownstreamTrustReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_api_downstream_trust(model: Any) -> ApiDownstreamTrustReport:
    """Project only supplied producer fields, steps, edges, and sinks."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_api_downstream_trust_bytes(*, model_bytes: Any) -> ApiDownstreamTrustReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise ApiDownstreamTrustError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiDownstreamTrustError("Model bytes must be UTF-8") from exc
    return analyze_supplied_api_downstream_trust(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_api_downstream_trust(report: Any, *, model: Any) -> ApiDownstreamTrustReport:
    if type(report) is not ApiDownstreamTrustReport:
        raise ApiDownstreamTrustError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise ApiDownstreamTrustError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return a fresh synthetic graph without response values or destinations."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-downstream-model",
        "graph_complete": True,
        "producer": {
            "source_id": "synthetic-producer",
            "response_fields": [
                {"field_id": "title-field", "trust": "untrusted"},
                {"field_id": "query-field", "trust": "untrusted"},
                {"field_id": "token-field", "trust": "untrusted"},
                {"field_id": "stable-field", "trust": "trusted"},
            ],
        },
        "flow": {
            "source_id": "synthetic-flow",
            "steps": [
                {
                    "step_id": "pass-title",
                    "kind": "identity_transform",
                    "protected_sink_kinds": [],
                },
                {
                    "step_id": "check-query",
                    "kind": "validation",
                    "protected_sink_kinds": ["sql_query"],
                },
                {
                    "step_id": "opaque-token",
                    "kind": "opaque_transform",
                    "protected_sink_kinds": [],
                },
            ],
            "sinks": [
                {"sink_id": "render-sink", "sink_kind": "html_render"},
                {"sink_id": "sql-sink", "sink_kind": "sql_query"},
                {"sink_id": "command-sink", "sink_kind": "command_argument"},
            ],
            "edges": [
                {"from_id": "title-field", "to_id": "pass-title"},
                {"from_id": "pass-title", "to_id": "render-sink"},
                {"from_id": "query-field", "to_id": "check-query"},
                {"from_id": "check-query", "to_id": "sql-sink"},
                {"from_id": "token-field", "to_id": "opaque-token"},
                {"from_id": "opaque-token", "to_id": "command-sink"},
                {"from_id": "stable-field", "to_id": "render-sink"},
            ],
        },
    }


__all__ = [
    "ApiDownstreamTrustError",
    "ApiDownstreamTrustReport",
    "analyze_supplied_api_downstream_trust",
    "analyze_supplied_api_downstream_trust_bytes",
    "verify_supplied_api_downstream_trust",
    "component_fixture",
]

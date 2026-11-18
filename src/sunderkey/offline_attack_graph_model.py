"""Finite offline reachability projection over a supplied abstract graph."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GA-D01-S11"
CAPABILITY_ID = "army.ga.d01.s11"
VECTOR_ID = "AV-GA-D01-S11-01"
DOMAIN = "sunderkey.offline-attack-graph-model.v1"
ANALYSIS_PROFILE = "supplied-abstract-graph-reachability-v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DEPTH = 12
MAX_NATIVE_NODES = 8_192
MAX_SOURCES = 32
MAX_NODES = 64
MAX_EDGES = 256
MAX_ENTRIES = 16
MAX_OBJECTIVES = 16
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_NODE_KINDS = frozenset(("entry", "intermediate", "objective"))
_RELATIONS = frozenset(("declared_access", "declared_dependency", "declared_trust"))
_EDGE_STATUSES = frozenset(("supported", "hypothesized", "blocked"))
_PROVENANCE_KINDS = frozenset(("synthetic_fixture", "operator_supplied"))
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


class AttackGraphModelError(ValueError):
    """Invalid, unsupported, or over-budget supplied abstract graph."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise AttackGraphModelError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise AttackGraphModelError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    seen = 0
    estimated = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_NATIVE_NODES or depth > MAX_DEPTH:
            raise AttackGraphModelError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if seen + len(stack) + 2 * len(item) > MAX_NATIVE_NODES:
                raise AttackGraphModelError("Native node limit exceeded")
            estimated += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise AttackGraphModelError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if seen + len(stack) + len(item) > MAX_NATIVE_NODES:
                raise AttackGraphModelError("Native node limit exceeded")
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise AttackGraphModelError("Invalid Unicode scalar text") from exc
            if len(encoded) > maximum:
                raise AttackGraphModelError("Native string exceeds bound")
            estimated += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise AttackGraphModelError("Native integer exceeds 64 bits")
            estimated += len(str(item))
        elif kind is bool:
            estimated += 5
        elif item is None:
            estimated += 4
        else:
            raise AttackGraphModelError("Unsupported native primitive")
        if estimated > 12 * maximum:
            raise AttackGraphModelError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise AttackGraphModelError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise AttackGraphModelError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise AttackGraphModelError("JSON integer exceeds bound")
    value = int(text)
    if value.bit_length() > 63:
        raise AttackGraphModelError("JSON integer exceeds bound")
    return value


def _unsupported_number(_text: str) -> None:
    raise AttackGraphModelError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise AttackGraphModelError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise AttackGraphModelError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise AttackGraphModelError(f"{label} exceeds byte limit")
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
                raise AttackGraphModelError("JSON depth limit exceeded")
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
        if isinstance(exc, AttackGraphModelError):
            raise
        raise AttackGraphModelError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _validate_model(
    model: Any,
) -> tuple[dict[str, Any], str, list[str], list[str], dict[str, list[dict[str, Any]]]]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "graph_complete", "evidence_sources", "nodes", "edges"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise AttackGraphModelError("Unsupported schema version")
    source_id = _identifier(document["source_id"], "model source_id")
    if type(document["graph_complete"]) is not bool:
        raise AttackGraphModelError("Graph completeness must be a native boolean")
    sources = document["evidence_sources"]
    nodes = document["nodes"]
    edges = document["edges"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise AttackGraphModelError("Evidence sources must be a nonempty bounded list")
    if type(nodes) is not list or len(nodes) > MAX_NODES:
        raise AttackGraphModelError("Nodes must be a bounded list")
    if type(edges) is not list or len(edges) > MAX_EDGES:
        raise AttackGraphModelError("Edges must be a bounded list")
    source_ids = set()
    for raw in sources:
        source = _exact(raw, {"source_id", "provenance_kind"}, "evidence source")
        item_id = _identifier(source["source_id"], "evidence source ID")
        if item_id == source_id or item_id in source_ids:
            raise AttackGraphModelError("Evidence source IDs must be distinct from model source")
        if (
            type(source["provenance_kind"]) is not str
            or source["provenance_kind"] not in _PROVENANCE_KINDS
        ):
            raise AttackGraphModelError("Unsupported provenance kind")
        source_ids.add(item_id)
    node_kinds = {}
    entries = []
    objectives = []
    for raw in nodes:
        node = _exact(raw, {"node_id", "kind", "source_id"}, "node")
        node_id = _identifier(node["node_id"], "node ID")
        kind = node["kind"]
        provenance = _identifier(node["source_id"], "node source ID")
        if node_id in node_kinds or node_id in source_ids or node_id == source_id:
            raise AttackGraphModelError("Node ID must be unique across identities")
        if type(kind) is not str or kind not in _NODE_KINDS or provenance not in source_ids:
            raise AttackGraphModelError("Unsupported node kind or missing node provenance")
        node_kinds[node_id] = kind
        if kind == "entry":
            entries.append(node_id)
        elif kind == "objective":
            objectives.append(node_id)
    if (
        not entries
        or not objectives
        or len(entries) > MAX_ENTRIES
        or len(objectives) > MAX_OBJECTIVES
    ):
        raise AttackGraphModelError("Entry and objective counts must be nonempty and bounded")
    outgoing: dict[str, list[dict[str, Any]]] = {node_id: [] for node_id in node_kinds}
    edge_ids = set()
    edge_pairs = set()
    for raw in edges:
        edge = _exact(
            raw,
            {"edge_id", "from_id", "to_id", "relation", "status", "source_id"},
            "edge",
        )
        edge_id = _identifier(edge["edge_id"], "edge ID")
        from_id = _identifier(edge["from_id"], "edge from ID")
        to_id = _identifier(edge["to_id"], "edge to ID")
        provenance = _identifier(edge["source_id"], "edge source ID")
        pair = (from_id, to_id)
        if (
            edge_id in edge_ids
            or edge_id in node_kinds
            or edge_id in source_ids
            or edge_id == source_id
        ):
            raise AttackGraphModelError("Edge ID must be unique across identities")
        if (
            from_id not in node_kinds
            or to_id not in node_kinds
            or from_id == to_id
            or node_kinds[from_id] == "objective"
            or node_kinds[to_id] == "entry"
            or pair in edge_pairs
        ):
            raise AttackGraphModelError("Invalid, duplicate, or unsupported edge endpoints")
        if provenance not in source_ids:
            raise AttackGraphModelError("Missing edge provenance")
        if type(edge["relation"]) is not str or edge["relation"] not in _RELATIONS:
            raise AttackGraphModelError("Unsupported abstract relation")
        if type(edge["status"]) is not str or edge["status"] not in _EDGE_STATUSES:
            raise AttackGraphModelError("Unsupported edge status")
        edge_ids.add(edge_id)
        edge_pairs.add(pair)
        outgoing[from_id].append(edge)
    for children in outgoing.values():
        children.sort(key=lambda edge: (edge["to_id"], edge["edge_id"]))
    return document, model_text, sorted(entries), sorted(objectives), outgoing


def _shortest_path(
    start: str,
    finish: str,
    outgoing: dict[str, list[dict[str, Any]]],
    *,
    include_hypotheses: bool,
) -> tuple[list[str], list[str]] | None:
    ready = deque(((start, (start,), ()),))
    visited = {start}
    while ready:
        node, path_nodes, path_edges = ready.popleft()
        for edge in outgoing[node]:
            if edge["status"] == "blocked" or (
                edge["status"] == "hypothesized" and not include_hypotheses
            ):
                continue
            child = edge["to_id"]
            if child in visited:
                continue
            next_nodes = (*path_nodes, child)
            next_edges = (*path_edges, edge["edge_id"])
            if child == finish:
                return list(next_nodes), list(next_edges)
            visited.add(child)
            ready.append((child, next_nodes, next_edges))
    return None


def _projection(model: Any) -> dict[str, Any]:
    document, model_text, entries, objectives, outgoing = _validate_model(model)
    complete = document["graph_complete"]
    pairs = []
    for entry in entries:
        for objective in objectives:
            supported = _shortest_path(entry, objective, outgoing, include_hypotheses=False)
            possible = None
            if supported is None:
                possible = _shortest_path(entry, objective, outgoing, include_hypotheses=True)
            if supported is not None:
                disposition = "supplied_supported_reachability"
                path = supported
            elif possible is not None:
                disposition = "unknown_hypothesized_edge"
                path = possible
            else:
                disposition = "no_supplied_path" if complete else "unknown_incomplete_graph"
                path = None
            pairs.append(
                {
                    "entry_id": entry,
                    "objective_id": objective,
                    "disposition": disposition,
                    "node_path": None if path is None else path[0],
                    "edge_path": None if path is None else path[1],
                }
            )
    report = {
        "schema_version": 1,
        "analysis_profile": ANALYSIS_PROFILE,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "source": {
            "source_id": document["source_id"],
            "model_sha256": _sha(model_text),
            "evidence_source_ids": sorted(
                source["source_id"] for source in document["evidence_sources"]
            ),
        },
        "supplied_model": model,
        "analysis_status": "complete_supplied_graph" if complete else "incomplete_supplied_graph",
        "pair_projections": pairs,
        "uncertainty": [
            "Nodes, edges, relationship status, completeness, and provenance labels "
            "are supplied claims.",
            "Provenance IDs identify caller declarations and do not authenticate evidence.",
            "A supported path is reachability in the supplied graph, not exploitability "
            "or target behavior.",
            "Hypothesized edges and incomplete graphs do not establish a negative "
            "or positive live verdict.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "AGM-" + digest[:32].upper()
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
    "pair_projections",
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
        raise AttackGraphModelError("Report does not replay retained model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> AttackGraphModelReport:
    report = object.__new__(AttackGraphModelReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class AttackGraphModelReport:
    """Detached unsigned projection, valid only after original-source replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not AttackGraphModelReport:
            raise AttackGraphModelError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> AttackGraphModelReport:
        if cls is not AttackGraphModelReport:
            raise AttackGraphModelError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> AttackGraphModelReport:
        if cls is not AttackGraphModelReport or type(value) is not str:
            raise AttackGraphModelError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise AttackGraphModelError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not AttackGraphModelReport or type(self.document_json) is not str:
            raise AttackGraphModelError("Exact native report wrapper required")
        return AttackGraphModelReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_attack_graph(model: Any) -> AttackGraphModelReport:
    """Project reachability only; never resolve a target or execute an edge."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_attack_graph_bytes(*, model_bytes: Any) -> AttackGraphModelReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise AttackGraphModelError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AttackGraphModelError("Model bytes must be UTF-8") from exc
    return analyze_supplied_attack_graph(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_attack_graph(report: Any, *, model: Any) -> AttackGraphModelReport:
    """Rebuild the report against an independently supplied original model."""
    if type(report) is not AttackGraphModelReport:
        raise AttackGraphModelError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise AttackGraphModelError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return a fresh synthetic abstract graph with no target identifiers."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-graph-model",
        "graph_complete": True,
        "evidence_sources": [
            {"source_id": "synthetic-inventory", "provenance_kind": "synthetic_fixture"},
            {"source_id": "synthetic-relationships", "provenance_kind": "synthetic_fixture"},
        ],
        "nodes": [
            {"node_id": "entry-a", "kind": "entry", "source_id": "synthetic-inventory"},
            {"node_id": "boundary-b", "kind": "intermediate", "source_id": "synthetic-inventory"},
            {"node_id": "boundary-c", "kind": "intermediate", "source_id": "synthetic-inventory"},
            {"node_id": "objective-d", "kind": "objective", "source_id": "synthetic-inventory"},
            {"node_id": "objective-e", "kind": "objective", "source_id": "synthetic-inventory"},
        ],
        "edges": [
            {
                "edge_id": "edge-ab",
                "from_id": "entry-a",
                "to_id": "boundary-b",
                "relation": "declared_access",
                "status": "supported",
                "source_id": "synthetic-relationships",
            },
            {
                "edge_id": "edge-bd",
                "from_id": "boundary-b",
                "to_id": "objective-d",
                "relation": "declared_trust",
                "status": "supported",
                "source_id": "synthetic-relationships",
            },
            {
                "edge_id": "edge-bc",
                "from_id": "boundary-b",
                "to_id": "boundary-c",
                "relation": "declared_dependency",
                "status": "hypothesized",
                "source_id": "synthetic-relationships",
            },
            {
                "edge_id": "edge-ce",
                "from_id": "boundary-c",
                "to_id": "objective-e",
                "relation": "declared_access",
                "status": "supported",
                "source_id": "synthetic-relationships",
            },
        ],
    }


__all__ = [
    "AttackGraphModelError",
    "AttackGraphModelReport",
    "analyze_supplied_attack_graph",
    "analyze_supplied_attack_graph_bytes",
    "verify_supplied_attack_graph",
    "component_fixture",
]

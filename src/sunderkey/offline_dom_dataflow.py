"""Bounded declared DOM source-to-sink paths without browser execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "dom_supplied_dataflow_projection"
PROFILE_ID = "AOE-GB-D05-S13"
CAPABILITY_ID = "army.gb.d05.s13"
VECTOR_ID = "AV-GB-D05-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S13"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:0d57624319de8c260db498e1501885c1d8b3633e5fc9f92cd5c6f31dfc2ead0e"
DOMAIN = "sunderkey.offline-dom-dataflow.v1"
MODEL_DOMAIN = "sunderkey.offline-dom-dataflow-model.v1"
SEMANTICS_PROFILE = "declared-context-protection-paths.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_SOURCES = 8
MAX_TRANSFORMS = 32
MAX_SINKS = 16
MAX_EDGES = 256
MAX_WORK = 4_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_CONTEXTS = ("html_attribute", "html_markup", "javascript_string", "url_attribute")
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "dom_graph_verified",
        "browser_executed",
        "javascript_executed",
        "sanitizer_behavior_verified",
        "sink_behavior_verified",
        "xss_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "browser",
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
    "sources": MAX_SOURCES,
    "transforms": MAX_TRANSFORMS,
    "sinks": MAX_SINKS,
    "edges": MAX_EDGES,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Sources, trust, graph edges, sink contexts and protection claims are caller declarations.",
    "A context match is a supplied protection label, not verified sanitizer correctness.",
    "Declared pass-through transforms preserve protection only within this model.",
    "Unknown transform or sink semantics and incomplete graphs do not support a candidate.",
    "A candidate is an unprotected supplied path, not live XSS or exploitability evidence.",
    "No payload, browser, JavaScript, URL, target, network, process or credential is used.",
    "No authority, qualification, positive use or live finding is established.",
)


class DomDataflowAnalysisError(ValueError):
    """A supplied model or report is outside the exact bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise DomDataflowAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise DomDataflowAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise DomDataflowAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise DomDataflowAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise DomDataflowAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not -(2**63) <= item < 2**63:
                raise DomDataflowAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise DomDataflowAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise DomDataflowAnalysisError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise DomDataflowAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise DomDataflowAnalysisError("Only exact native JSON primitives are supported")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)
    return size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    return _canonical(value)


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return json.loads(text), text


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise DomDataflowAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise DomDataflowAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Bound raw tokens, escapes and duplicate members before decoding."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise DomDataflowAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise DomDataflowAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise DomDataflowAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise DomDataflowAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            d not in "0123456789abcdefABCDEF" for d in digits
                        ):
                            raise DomDataflowAnalysisError("Malformed raw Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise DomDataflowAnalysisError("Printable ASCII escapes required")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise DomDataflowAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise DomDataflowAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise DomDataflowAnalysisError("Raw string bound exhausted")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise DomDataflowAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise DomDataflowAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise DomDataflowAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise DomDataflowAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise DomDataflowAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise DomDataflowAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, DomDataflowAnalysisError):
            raise
        raise DomDataflowAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DomDataflowAnalysisError("Bounded exact node identity required")
    return value


def _id_list(value: Any, limit: int, *, nonempty: bool = False) -> list[str]:
    if type(value) is not list or len(value) > limit or (nonempty and not value):
        raise DomDataflowAnalysisError("Bounded exact identity list required")
    for item in value:
        _identity(item)
    if len(set(value)) != len(value) or value != sorted(value):
        raise DomDataflowAnalysisError("Sorted unique identity list required")
    return value


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "graph_complete",
        "sources",
        "transforms",
        "sinks",
        "edges",
        "source_ids",
    }:
        raise DomDataflowAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise DomDataflowAnalysisError("Exact native schema version 1 required")
    if type(owned["graph_complete"]) is not bool:
        raise DomDataflowAnalysisError("Exact graph completeness boolean required")
    sources, transforms, sinks, edges = (
        owned["sources"],
        owned["transforms"],
        owned["sinks"],
        owned["edges"],
    )
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise DomDataflowAnalysisError("Bounded nonempty sources required")
    if type(transforms) is not list or len(transforms) > MAX_TRANSFORMS:
        raise DomDataflowAnalysisError("Bounded transforms required")
    if type(sinks) is not list or not 1 <= len(sinks) <= MAX_SINKS:
        raise DomDataflowAnalysisError("Bounded nonempty sinks required")
    if type(edges) is not list or len(edges) > MAX_EDGES:
        raise DomDataflowAnalysisError("Bounded edges required")
    ids: set[str] = set()
    source_ids: set[str] = set()
    transform_ids: set[str] = set()
    sink_ids: set[str] = set()
    for source in sources:
        work.charge(5)
        if type(source) is not dict or source.keys() != {"source_id", "trust"}:
            raise DomDataflowAnalysisError("Exact closed source fields required")
        identity = _identity(source["source_id"])
        if identity in ids:
            raise DomDataflowAnalysisError("Duplicate global node identity")
        ids.add(identity)
        source_ids.add(identity)
        if type(source["trust"]) is not str or source["trust"] not in {
            "untrusted",
            "trusted",
            "unknown",
        }:
            raise DomDataflowAnalysisError("Declared source trust required")
    for transform in transforms:
        work.charge(7)
        if type(transform) is not dict or transform.keys() != {
            "transform_id",
            "kind",
            "protects_contexts",
            "semantics_complete",
        }:
            raise DomDataflowAnalysisError("Exact closed transform fields required")
        identity = _identity(transform["transform_id"])
        if identity in ids:
            raise DomDataflowAnalysisError("Duplicate global node identity")
        ids.add(identity)
        transform_ids.add(identity)
        if type(transform["kind"]) is not str or transform["kind"] not in {
            "passthrough",
            "sanitizer",
            "encoder",
            "unsupported",
        }:
            raise DomDataflowAnalysisError("Declared transform kind required")
        contexts = transform["protects_contexts"]
        if type(contexts) is not list or len(contexts) > len(_CONTEXTS):
            raise DomDataflowAnalysisError("Bounded context declarations required")
        if any(type(context) is not str or context not in _CONTEXTS for context in contexts):
            raise DomDataflowAnalysisError("Known context declarations required")
        if contexts != sorted(set(contexts)):
            raise DomDataflowAnalysisError("Sorted unique context declarations required")
        if transform["kind"] in {"passthrough", "unsupported"} and contexts:
            raise DomDataflowAnalysisError("Nonprotective transform must declare no contexts")
        if type(transform["semantics_complete"]) is not bool:
            raise DomDataflowAnalysisError("Exact transform completeness boolean required")
    for sink in sinks:
        work.charge(6)
        if type(sink) is not dict or sink.keys() != {
            "sink_id",
            "context",
            "sensitive",
            "semantics_complete",
        }:
            raise DomDataflowAnalysisError("Exact closed sink fields required")
        identity = _identity(sink["sink_id"])
        if identity in ids:
            raise DomDataflowAnalysisError("Duplicate global node identity")
        ids.add(identity)
        sink_ids.add(identity)
        if type(sink["context"]) is not str or sink["context"] not in {*_CONTEXTS, "unsupported"}:
            raise DomDataflowAnalysisError("Declared sink context required")
        if type(sink["sensitive"]) is not bool or type(sink["semantics_complete"]) is not bool:
            raise DomDataflowAnalysisError("Exact sink booleans required")
    selected = _id_list(owned["source_ids"], MAX_SOURCES, nonempty=True)
    if any(identity not in source_ids for identity in selected):
        raise DomDataflowAnalysisError("Selected source identity is not declared")
    seen_edges: set[tuple[str, str]] = set()
    for edge in edges:
        work.charge(4)
        if type(edge) is not dict or edge.keys() != {"from_id", "to_id"}:
            raise DomDataflowAnalysisError("Exact closed edge fields required")
        start, end = edge["from_id"], edge["to_id"]
        if type(start) is not str or type(end) is not str or start not in ids or end not in ids:
            raise DomDataflowAnalysisError("Exact known edge endpoint required")
        if start in sink_ids or end in source_ids or start == end:
            raise DomDataflowAnalysisError("Unsupported edge direction or self loop")
        pair = (start, end)
        if pair in seen_edges:
            raise DomDataflowAnalysisError("Duplicate declared edge")
        seen_edges.add(pair)
    if [(edge["from_id"], edge["to_id"]) for edge in edges] != sorted(seen_edges):
        raise DomDataflowAnalysisError("Sorted unique edges required")
    return owned, text


def _graph(model: dict, work: _Work) -> dict[str, list[str]]:
    ids = [source["source_id"] for source in model["sources"]]
    ids.extend(transform["transform_id"] for transform in model["transforms"])
    ids.extend(sink["sink_id"] for sink in model["sinks"])
    graph: dict[str, list[str]] = {identity: [] for identity in ids}
    for edge in model["edges"]:
        graph[edge["from_id"]].append(edge["to_id"])
        work.charge(1)
    for targets in graph.values():
        targets.sort()
    return graph


def _walk(
    source_id: str, sink: dict, graph: dict, transforms: dict, work: _Work
) -> tuple[dict[str, list[str]], bool]:
    """Retain one shortest path per endpoint and protection/unknown state."""
    context = sink["context"]
    start = (source_id, False, False)
    paths: dict[tuple[str, bool, bool], list[str]] = {start: [source_id]}
    pending = deque([start])
    while pending:
        node, protected, uncertain = pending.popleft()
        for target in graph[node]:
            work.charge(1)
            next_protected, next_uncertain = protected, uncertain
            transform = transforms.get(target)
            if transform is not None:
                if not transform["semantics_complete"] or transform["kind"] == "unsupported":
                    next_uncertain = True
                elif transform["kind"] == "passthrough":
                    next_protected = protected
                else:
                    next_protected = context in transform["protects_contexts"]
            state = (target, next_protected, next_uncertain)
            if state not in paths:
                paths[state] = [*paths[(node, protected, uncertain)], target]
                pending.append(state)
    found: dict[str, list[str]] = {}
    for (node, protected, uncertain), path in paths.items():
        if node != sink["sink_id"]:
            continue
        label = "unknown" if uncertain else "protected" if protected else "unprotected"
        previous = found.get(label)
        if previous is None or (len(path), path) < (len(previous), previous):
            found[label] = path
    return found, any(node == sink["sink_id"] for node, _, _ in paths)


def _observe(model: dict, work: _Work) -> list[dict]:
    graph = _graph(model, work)
    sources = {source["source_id"]: source for source in model["sources"]}
    transforms = {transform["transform_id"]: transform for transform in model["transforms"]}
    sinks = {sink["sink_id"]: sink for sink in model["sinks"]}
    rows: list[dict] = []
    for source_id in model["source_ids"]:
        for sink_id in sorted(sinks):
            work.charge(20)
            sink = sinks[sink_id]
            paths, reachable = _walk(source_id, sink, graph, transforms, work)
            reasons: list[str] = []
            if not model["graph_complete"]:
                reasons.append("graph_incomplete")
            if sources[source_id]["trust"] == "unknown":
                reasons.append("source_trust_unknown")
            if sink["context"] == "unsupported":
                reasons.append("sink_context_unsupported")
            if not sink["semantics_complete"]:
                reasons.append("sink_semantics_incomplete")
            if reasons:
                outcome = "unknown"
                witness = min(paths.values(), key=lambda path: (len(path), path)) if paths else None
            elif not reachable:
                outcome, witness = "not_reachable_under_supplied_graph", None
            elif (
                sources[source_id]["trust"] == "untrusted"
                and sink["sensitive"]
                and "unprotected" in paths
            ):
                outcome, witness = "candidate_unprotected_path", paths["unprotected"]
            elif "unknown" in paths:
                outcome, witness = "unknown", paths["unknown"]
            elif sources[source_id]["trust"] == "trusted":
                outcome = "declared_trusted_source"
                witness = min(paths.values(), key=lambda path: (len(path), path))
            elif not sink["sensitive"]:
                outcome = "declared_nonsensitive_sink"
                witness = min(paths.values(), key=lambda path: (len(path), path))
            else:
                outcome, witness = "protected_under_supplied_declarations", paths["protected"]
            if "unknown" in paths:
                reasons.append("path_transform_semantics_unknown")
            rows.append(
                {
                    "source_id": source_id,
                    "sink_id": sink_id,
                    "declared_source_trust": sources[source_id]["trust"],
                    "declared_sink_context": sink["context"],
                    "declared_sink_sensitive": sink["sensitive"],
                    "reachable": reachable,
                    "witness_node_ids": witness,
                    "outcome": outcome,
                    "uncertainty": reasons,
                }
            )
    return rows


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    rows = _observe(owned, work)
    candidate_count = sum(row["outcome"] == "candidate_unprotected_path" for row in rows)
    unknown_count = sum(row["outcome"] == "unknown" for row in rows)
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
        "source_model_sha256": _PLACEHOLDER,
        "observation_count": len(rows),
        "candidate_path_count": candidate_count,
        "unknown_count": unknown_count,
        "sink_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "DDF-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    report_size, report_nodes = _measure(body, work)
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + len(DOMAIN) + len(source_text) + hash_size + 2)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "DDF-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise DomDataflowAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise DomDataflowAnalysisError("Report does not exactly replay its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class DomDataflowAnalysis:
    """Detached supplied-graph projection, never live DOM or XSS evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> DomDataflowAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> DomDataflowAnalysis:
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


def analyze_supplied_dom_dataflow(model: Any) -> DomDataflowAnalysis:
    """Compare finite supplied paths and context protection declarations only."""
    return DomDataflowAnalysis(_derive(model))


def analyze_supplied_dom_dataflow_bytes(*, model_bytes: Any) -> DomDataflowAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise DomDataflowAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DomDataflowAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_dom_dataflow(_decode(text))


def verify_supplied_dom_dataflow_analysis(report: Any, *, model: Any) -> DomDataflowAnalysis:
    """Check a report against separately supplied original graph premises."""
    if type(report) is not DomDataflowAnalysis:
        raise DomDataflowAnalysisError("Exact native DOM analysis family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise DomDataflowAnalysisError("Report differs from separately supplied originals")
    return DomDataflowAnalysis(expected)


def component_fixture() -> dict:
    """Return a fresh synthetic unprotected path and a protected path."""
    return {
        "schema_version": 1,
        "graph_complete": True,
        "sources": [{"source_id": "location-fragment", "trust": "untrusted"}],
        "transforms": [
            {
                "transform_id": "html-encode",
                "kind": "encoder",
                "protects_contexts": ["html_markup"],
                "semantics_complete": True,
            },
            {
                "transform_id": "passthrough",
                "kind": "passthrough",
                "protects_contexts": [],
                "semantics_complete": True,
            },
        ],
        "sinks": [
            {
                "sink_id": "markup-sink",
                "context": "html_markup",
                "sensitive": True,
                "semantics_complete": True,
            },
            {
                "sink_id": "script-sink",
                "context": "javascript_string",
                "sensitive": True,
                "semantics_complete": True,
            },
        ],
        "edges": [
            {"from_id": "html-encode", "to_id": "markup-sink"},
            {"from_id": "location-fragment", "to_id": "html-encode"},
            {"from_id": "location-fragment", "to_id": "passthrough"},
            {"from_id": "passthrough", "to_id": "script-sink"},
        ],
        "source_ids": ["location-fragment"],
    }


__all__ = [
    "DomDataflowAnalysisError",
    "DomDataflowAnalysis",
    "analyze_supplied_dom_dataflow",
    "analyze_supplied_dom_dataflow_bytes",
    "verify_supplied_dom_dataflow_analysis",
    "component_fixture",
]

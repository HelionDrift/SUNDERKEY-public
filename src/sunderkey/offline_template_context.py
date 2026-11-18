"""Inert projection of supplied template slot and escaping declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D05-S09"
CAPABILITY_ID = "army.gb.d05.s09"
VECTOR_ID = "AV-GB-D05-S09-01"
DOMAIN = "sunderkey.offline-template-context.v1"
ANALYSIS_PROFILE = "supplied-slot-context-escape-v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DEPTH = 12
MAX_NATIVE_NODES = 8_192
MAX_SOURCES = 16
MAX_SLOTS = 64
MAX_BINDINGS = 64
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_CONTEXTS = frozenset(("html_text", "html_attribute", "script_string"))
_ESCAPES = _CONTEXTS | frozenset(("none", "opaque"))
_ORIGINS = frozenset(("trusted", "untrusted", "unknown"))
_AUTOESCAPE = frozenset(("off", "contextual", "unknown"))
_PROVENANCE_KINDS = frozenset(("synthetic_fixture", "operator_supplied"))
_EFFECTS = {
    "authority": "none",
    "credential_resolution": "none",
    "execution": "none",
    "filesystem": "none",
    "network": "none",
    "payload_generation": "none",
    "target_interaction": "none",
    "finding_publication": "none",
    "qualification": "none",
}


class TemplateContextError(ValueError):
    """Invalid, unsupported, or over-budget supplied template model."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise TemplateContextError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise TemplateContextError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    seen = estimated = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_NATIVE_NODES or depth > MAX_DEPTH:
            raise TemplateContextError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if seen + len(stack) + 2 * len(item) > MAX_NATIVE_NODES:
                raise TemplateContextError("Native node limit exceeded")
            estimated += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise TemplateContextError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if seen + len(stack) + len(item) > MAX_NATIVE_NODES:
                raise TemplateContextError("Native node limit exceeded")
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise TemplateContextError("Invalid Unicode scalar text") from exc
            if len(encoded) > maximum:
                raise TemplateContextError("Native string exceeds bound")
            estimated += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise TemplateContextError("Native integer exceeds 64 bits")
            estimated += len(str(item))
        elif kind is bool:
            estimated += 5
        elif item is None:
            estimated += 4
        else:
            raise TemplateContextError("Unsupported native primitive")
        if estimated > 12 * maximum:
            raise TemplateContextError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise TemplateContextError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise TemplateContextError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise TemplateContextError("JSON integer exceeds bound")
    value = int(text)
    if value.bit_length() > 63:
        raise TemplateContextError("JSON integer exceeds bound")
    return value


def _unsupported_number(_text: str) -> None:
    raise TemplateContextError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise TemplateContextError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise TemplateContextError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise TemplateContextError(f"{label} exceeds byte limit")
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
                raise TemplateContextError("JSON depth limit exceeded")
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
        if isinstance(exc, TemplateContextError):
            raise
        raise TemplateContextError(f"{label} is malformed JSON") from exc
    _canonical(value, maximum=maximum)
    return value


def _sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def _validate_model(
    model: Any,
) -> tuple[dict[str, Any], str, dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    model_text = _canonical(model, maximum=MAX_MODEL_BYTES)
    document = _exact(
        model,
        {"schema_version", "source_id", "evidence_sources", "engine", "slots", "bindings"},
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise TemplateContextError("Unsupported schema version")
    model_source_id = _identifier(document["source_id"], "model source ID")
    sources = document["evidence_sources"]
    slots = document["slots"]
    bindings = document["bindings"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise TemplateContextError("Evidence sources must be nonempty and bounded")
    if type(slots) is not list or not 1 <= len(slots) <= MAX_SLOTS:
        raise TemplateContextError("Slots must be nonempty and bounded")
    if type(bindings) is not list or len(bindings) > MAX_BINDINGS:
        raise TemplateContextError("Bindings must be bounded")
    source_ids = set()
    for raw in sources:
        source = _exact(raw, {"source_id", "provenance_kind"}, "evidence source")
        source_id = _identifier(source["source_id"], "evidence source ID")
        if source_id == model_source_id or source_id in source_ids:
            raise TemplateContextError("Evidence source IDs must be distinct")
        if (
            type(source["provenance_kind"]) is not str
            or source["provenance_kind"] not in _PROVENANCE_KINDS
        ):
            raise TemplateContextError("Unsupported provenance kind")
        source_ids.add(source_id)
    engine = _exact(document["engine"], {"autoescape", "source_id"}, "engine")
    if type(engine["autoescape"]) is not str or engine["autoescape"] not in _AUTOESCAPE:
        raise TemplateContextError("Unsupported engine autoescape declaration")
    if _identifier(engine["source_id"], "engine source ID") not in source_ids:
        raise TemplateContextError("Missing engine provenance")
    slot_map: dict[str, dict[str, Any]] = {}
    binding_map: dict[str, dict[str, Any]] = {}
    for raw in slots:
        slot = _exact(raw, {"slot_id", "context", "source_id"}, "slot")
        slot_id = _identifier(slot["slot_id"], "slot ID")
        provenance = _identifier(slot["source_id"], "slot source ID")
        if slot_id in slot_map or provenance not in source_ids:
            raise TemplateContextError("Duplicate slot or missing provenance")
        if type(slot["context"]) is not str or slot["context"] not in _CONTEXTS:
            raise TemplateContextError("Unsupported rendering context")
        slot_map[slot_id] = slot
    for raw in bindings:
        binding = _exact(
            raw,
            {"slot_id", "origin", "explicit_escape", "source_id"},
            "binding",
        )
        slot_id = _identifier(binding["slot_id"], "binding slot ID")
        provenance = _identifier(binding["source_id"], "binding source ID")
        if slot_id not in slot_map or slot_id in binding_map or provenance not in source_ids:
            raise TemplateContextError("Unknown or duplicate binding, or missing provenance")
        if type(binding["origin"]) is not str or binding["origin"] not in _ORIGINS:
            raise TemplateContextError("Unsupported binding origin")
        if (
            type(binding["explicit_escape"]) is not str
            or binding["explicit_escape"] not in _ESCAPES
        ):
            raise TemplateContextError("Unsupported explicit escape")
        binding_map[slot_id] = binding
    return document, model_text, slot_map, binding_map


def _disposition(context: str, autoescape: str, binding: dict[str, Any] | None) -> str:
    if binding is None:
        return "unknown_unbound_slot"
    origin = binding["origin"]
    escape = binding["explicit_escape"]
    if origin == "unknown":
        return "unknown_origin"
    if origin == "trusted":
        return "declared_trusted_origin_unverified"
    if escape == context:
        return "declared_matching_escape_unverified"
    if escape == "opaque":
        return "unknown_opaque_escape"
    if autoescape == "contextual":
        if escape == "none":
            return "declared_engine_autoescape_unverified"
        return "unknown_contextual_engine_effect"
    if autoescape == "unknown":
        return "unknown_engine_escape"
    if escape == "none":
        return "candidate_declared_unescaped_flow"
    return "candidate_declared_escape_mismatch"


def _projection(model: Any) -> dict[str, Any]:
    document, model_text, slots, bindings = _validate_model(model)
    autoescape = document["engine"]["autoescape"]
    projections = []
    for slot_id in sorted(slots):
        slot = slots[slot_id]
        binding = bindings.get(slot_id)
        projections.append(
            {
                "slot_id": slot_id,
                "context": slot["context"],
                "origin": None if binding is None else binding["origin"],
                "explicit_escape": None if binding is None else binding["explicit_escape"],
                "disposition": _disposition(slot["context"], autoescape, binding),
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
        "slot_projections": projections,
        "uncertainty": [
            "Contexts, origins, escapes, engine settings, and provenance are supplied claims.",
            "Matching or engine-declared escaping is not verified effective protection.",
            "Opaque escaping and unknown engine behavior cannot establish a safe outcome.",
            "Candidates are declaration mismatches, not rendering or live vulnerabilities.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "TCX-" + digest[:32].upper()
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
    "slot_projections",
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
        raise TemplateContextError("Report does not replay retained model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> TemplateContextReport:
    report = object.__new__(TemplateContextReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class TemplateContextReport:
    """Detached unsigned projection, requiring independent original-model replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not TemplateContextReport:
            raise TemplateContextError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> TemplateContextReport:
        if cls is not TemplateContextReport:
            raise TemplateContextError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> TemplateContextReport:
        if cls is not TemplateContextReport or type(value) is not str:
            raise TemplateContextError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise TemplateContextError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not TemplateContextReport or type(self.document_json) is not str:
            raise TemplateContextError("Exact native report wrapper required")
        return TemplateContextReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_template_context(model: Any) -> TemplateContextReport:
    """Project declarations only; never render or evaluate a template."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_template_context_bytes(*, model_bytes: Any) -> TemplateContextReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise TemplateContextError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TemplateContextError("Model bytes must be UTF-8") from exc
    return analyze_supplied_template_context(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_template_context(report: Any, *, model: Any) -> TemplateContextReport:
    """Rebuild against an independently supplied original model."""
    if type(report) is not TemplateContextReport:
        raise TemplateContextError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise TemplateContextError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic declarations without template text or payloads."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-template-model",
        "evidence_sources": [
            {"source_id": "synthetic-template", "provenance_kind": "synthetic_fixture"},
            {"source_id": "synthetic-bindings", "provenance_kind": "synthetic_fixture"},
        ],
        "engine": {"autoescape": "off", "source_id": "synthetic-template"},
        "slots": [
            {"slot_id": "slot-title", "context": "html_text", "source_id": "synthetic-template"},
            {
                "slot_id": "slot-attribute",
                "context": "html_attribute",
                "source_id": "synthetic-template",
            },
            {
                "slot_id": "slot-script",
                "context": "script_string",
                "source_id": "synthetic-template",
            },
            {"slot_id": "slot-trusted", "context": "html_text", "source_id": "synthetic-template"},
            {"slot_id": "slot-unbound", "context": "html_text", "source_id": "synthetic-template"},
        ],
        "bindings": [
            {
                "slot_id": "slot-title",
                "origin": "untrusted",
                "explicit_escape": "html_text",
                "source_id": "synthetic-bindings",
            },
            {
                "slot_id": "slot-attribute",
                "origin": "untrusted",
                "explicit_escape": "html_text",
                "source_id": "synthetic-bindings",
            },
            {
                "slot_id": "slot-script",
                "origin": "untrusted",
                "explicit_escape": "none",
                "source_id": "synthetic-bindings",
            },
            {
                "slot_id": "slot-trusted",
                "origin": "trusted",
                "explicit_escape": "none",
                "source_id": "synthetic-bindings",
            },
        ],
    }


__all__ = [
    "TemplateContextError",
    "TemplateContextReport",
    "analyze_supplied_template_context",
    "analyze_supplied_template_context_bytes",
    "verify_supplied_template_context",
    "component_fixture",
]

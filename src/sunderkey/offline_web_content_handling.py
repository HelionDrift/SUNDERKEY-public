"""Offline comparison of supplied extension and media-type gate declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D05-S10"
CAPABILITY_ID = "army.gb.d05.s10"
VECTOR_ID = "AV-GB-D05-S10-01"
DOMAIN = "sunderkey.offline-web-content-handling.v1"
ANALYSIS_PROFILE = "supplied-extension-media-gate-differential-v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_DEPTH = 12
MAX_NATIVE_NODES = 8_192
MAX_SOURCES = 16
MAX_EXTENSION_RULES = 32
MAX_MEDIA_RULES = 32
MAX_CASES = 64
_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_GATE_DISPOSITIONS = frozenset(("allow", "deny"))
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


class WebContentHandlingError(ValueError):
    """Invalid, unsupported, or over-budget supplied gate model."""


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or any(type(k) is not str for k in value):
        raise WebContentHandlingError(f"{label} must have exact native fields")
    return value


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise WebContentHandlingError(f"{label} must be a bounded native identifier")
    return value


def _canonical(value: Any, *, maximum: int) -> str:
    stack = [(value, 1)]
    seen = estimated = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_NATIVE_NODES or depth > MAX_DEPTH:
            raise WebContentHandlingError("Native node or depth limit exceeded")
        kind = type(item)
        if kind is dict:
            if seen + len(stack) + 2 * len(item) > MAX_NATIVE_NODES:
                raise WebContentHandlingError("Native node limit exceeded")
            estimated += 2 + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise WebContentHandlingError("Native mapping keys must be strings")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if seen + len(stack) + len(item) > MAX_NATIVE_NODES:
                raise WebContentHandlingError("Native node limit exceeded")
            estimated += 2 + len(item)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            try:
                encoded = item.encode("utf-8")
            except UnicodeError as exc:
                raise WebContentHandlingError("Invalid Unicode scalar text") from exc
            if len(encoded) > maximum:
                raise WebContentHandlingError("Native string exceeds bound")
            estimated += 2 + 12 * len(item)
        elif kind is int:
            if item.bit_length() > 63:
                raise WebContentHandlingError("Native integer exceeds 64 bits")
            estimated += len(str(item))
        elif kind is bool:
            estimated += 5
        elif item is None:
            estimated += 4
        else:
            raise WebContentHandlingError("Unsupported native primitive")
        if estimated > 12 * maximum:
            raise WebContentHandlingError("Native serialized size limit exceeded")
    result = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(result) > maximum:
        raise WebContentHandlingError("Canonical byte limit exceeded")
    return result


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise WebContentHandlingError("JSON duplicate key rejected")
        result[key] = value
    return result


def _json_integer(text: str) -> int:
    if len(text.lstrip("-")) > 19:
        raise WebContentHandlingError("JSON integer exceeds bound")
    value = int(text)
    if value.bit_length() > 63:
        raise WebContentHandlingError("JSON integer exceeds bound")
    return value


def _unsupported_number(_text: str) -> None:
    raise WebContentHandlingError("JSON float or nonfinite number is unsupported")


def _decode(text: Any, label: str, maximum: int) -> Any:
    if type(text) is not str or not text:
        raise WebContentHandlingError(f"{label} must be nonempty native JSON text")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError as exc:
        raise WebContentHandlingError(f"{label} contains invalid Unicode") from exc
    if length > maximum:
        raise WebContentHandlingError(f"{label} exceeds byte limit")
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
                raise WebContentHandlingError("JSON depth limit exceeded")
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
        if isinstance(exc, WebContentHandlingError):
            raise
        raise WebContentHandlingError(f"{label} is malformed JSON") from exc
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
        {
            "schema_version",
            "source_id",
            "evidence_sources",
            "extension_rules",
            "media_rules",
            "cases",
        },
        "model",
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise WebContentHandlingError("Unsupported schema version")
    model_source_id = _identifier(document["source_id"], "model source ID")
    sources = document["evidence_sources"]
    extensions = document["extension_rules"]
    media = document["media_rules"]
    cases = document["cases"]
    if type(sources) is not list or not 1 <= len(sources) <= MAX_SOURCES:
        raise WebContentHandlingError("Evidence sources must be nonempty and bounded")
    if type(extensions) is not list or len(extensions) > MAX_EXTENSION_RULES:
        raise WebContentHandlingError("Extension rules must be bounded")
    if type(media) is not list or len(media) > MAX_MEDIA_RULES:
        raise WebContentHandlingError("Media rules must be bounded")
    if type(cases) is not list or not 1 <= len(cases) <= MAX_CASES:
        raise WebContentHandlingError("Cases must be nonempty and bounded")
    source_ids = set()
    for raw in sources:
        source = _exact(raw, {"source_id", "provenance_kind"}, "evidence source")
        source_id = _identifier(source["source_id"], "evidence source ID")
        if source_id == model_source_id or source_id in source_ids:
            raise WebContentHandlingError("Evidence source IDs must be distinct")
        if (
            type(source["provenance_kind"]) is not str
            or source["provenance_kind"] not in _PROVENANCE_KINDS
        ):
            raise WebContentHandlingError("Unsupported provenance kind")
        source_ids.add(source_id)
    extension_rules: dict[str, dict[str, Any]] = {}
    media_rules: dict[str, dict[str, Any]] = {}
    for raw in extensions:
        rule = _exact(
            raw,
            {"extension_token", "expected_media_token", "disposition", "source_id"},
            "extension rule",
        )
        token = _identifier(rule["extension_token"], "extension token")
        _identifier(rule["expected_media_token"], "expected media token")
        source_id = _identifier(rule["source_id"], "extension rule source ID")
        if token in extension_rules or source_id not in source_ids:
            raise WebContentHandlingError("Duplicate extension rule or missing provenance")
        if type(rule["disposition"]) is not str or rule["disposition"] not in _GATE_DISPOSITIONS:
            raise WebContentHandlingError("Unsupported extension gate disposition")
        extension_rules[token] = rule
    for raw in media:
        rule = _exact(raw, {"media_token", "disposition", "source_id"}, "media rule")
        token = _identifier(rule["media_token"], "media token")
        source_id = _identifier(rule["source_id"], "media rule source ID")
        if token in media_rules or source_id not in source_ids:
            raise WebContentHandlingError("Duplicate media rule or missing provenance")
        if type(rule["disposition"]) is not str or rule["disposition"] not in _GATE_DISPOSITIONS:
            raise WebContentHandlingError("Unsupported media gate disposition")
        media_rules[token] = rule
    case_ids = set()
    for raw in cases:
        case = _exact(
            raw,
            {"case_id", "extension_token", "declared_media_token", "source_id"},
            "case",
        )
        case_id = _identifier(case["case_id"], "case ID")
        _identifier(case["extension_token"], "case extension token")
        _identifier(case["declared_media_token"], "case media token")
        source_id = _identifier(case["source_id"], "case source ID")
        if case_id in case_ids or source_id not in source_ids:
            raise WebContentHandlingError("Duplicate case or missing provenance")
        case_ids.add(case_id)
    return document, model_text, extension_rules, media_rules


def _projection(model: Any) -> dict[str, Any]:
    document, model_text, extension_rules, media_rules = _validate_model(model)
    projections = []
    for case in sorted(document["cases"], key=lambda item: item["case_id"]):
        extension = extension_rules.get(case["extension_token"])
        media = media_rules.get(case["declared_media_token"])
        extension_gate = None if extension is None else extension["disposition"]
        media_gate = None if media is None else media["disposition"]
        expected_media = None if extension is None else extension["expected_media_token"]
        mismatch = None if extension is None else expected_media != case["declared_media_token"]
        if extension_gate is None or media_gate is None:
            disposition = "unknown_missing_gate_rule"
        elif mismatch:
            disposition = "unknown_media_extension_mismatch_policy"
        elif extension_gate != media_gate:
            disposition = "candidate_declared_gate_differential"
        elif extension_gate == "allow":
            disposition = "declared_gate_agreement_allow"
        else:
            disposition = "declared_gate_agreement_deny"
        projections.append(
            {
                "case_id": case["case_id"],
                "extension_token": case["extension_token"],
                "declared_media_token": case["declared_media_token"],
                "expected_media_token": expected_media,
                "extension_gate": extension_gate,
                "media_gate": media_gate,
                "media_extension_mismatch": mismatch,
                "disposition": disposition,
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
        "case_projections": projections,
        "uncertainty": [
            "All gate decisions and provenance labels are caller-supplied declarations.",
            "Opaque tokens do not contain file bytes, names, paths, or actual media values.",
            "Gate disagreement is not proof of server behavior, bypass, or exploitability.",
            "A missing rule or media-extension mismatch has no inferred processing outcome.",
        ],
        "offline_only": True,
        "target_behavior_verified": False,
        "live_vulnerability_verdict": None,
        "effects": dict(_EFFECTS),
    }
    digest = hashlib.sha256(
        _canonical({"domain": DOMAIN, "report": report}, maximum=MAX_REPORT_BYTES).encode("ascii")
    ).hexdigest()
    report["report_id"] = "WCH-" + digest[:32].upper()
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
    "case_projections",
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
        raise WebContentHandlingError("Report does not replay retained model")
    return _canonical(expected, maximum=MAX_REPORT_BYTES)


def _owned(text: str) -> WebContentHandlingReport:
    report = object.__new__(WebContentHandlingReport)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class WebContentHandlingReport:
    """Detached unsigned declaration comparison, requiring original-model replay."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not WebContentHandlingReport:
            raise WebContentHandlingError("Exact report family required")
        self.to_dict()

    @classmethod
    def from_dict(cls, value: Any) -> WebContentHandlingReport:
        if cls is not WebContentHandlingReport:
            raise WebContentHandlingError("Exact report family required")
        return _owned(_replay(value))

    @classmethod
    def from_json(cls, value: Any) -> WebContentHandlingReport:
        if cls is not WebContentHandlingReport or type(value) is not str:
            raise WebContentHandlingError("Exact native report JSON required")
        document = _decode(value, "report", MAX_REPORT_BYTES)
        canonical = _replay(document)
        if value != canonical:
            raise WebContentHandlingError("Canonical report JSON required")
        return _owned(canonical)

    def to_dict(self) -> dict[str, Any]:
        if type(self) is not WebContentHandlingReport or type(self.document_json) is not str:
            raise WebContentHandlingError("Exact native report wrapper required")
        return WebContentHandlingReport.from_json(self.document_json)._document()

    def _document(self) -> dict[str, Any]:
        return _decode(self.document_json, "report", MAX_REPORT_BYTES)

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json


def analyze_supplied_web_content_handling(model: Any) -> WebContentHandlingReport:
    """Compare declared gates only, without reading or creating content."""
    return _owned(_canonical(_projection(model), maximum=MAX_REPORT_BYTES))


def analyze_supplied_web_content_handling_bytes(*, model_bytes: Any) -> WebContentHandlingReport:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise WebContentHandlingError("Bounded native model bytes required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebContentHandlingError("Model bytes must be UTF-8") from exc
    return analyze_supplied_web_content_handling(_decode(text, "model", MAX_MODEL_BYTES))


def verify_supplied_web_content_handling(report: Any, *, model: Any) -> WebContentHandlingReport:
    """Rebuild against an independently supplied original model."""
    if type(report) is not WebContentHandlingReport:
        raise WebContentHandlingError("Exact native report wrapper required")
    retained = report.to_json()
    expected = _canonical(_projection(model), maximum=MAX_REPORT_BYTES)
    if retained != expected:
        raise WebContentHandlingError("Report differs from separately supplied model")
    return _owned(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic opaque tokens without file names or bytes."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-content-model",
        "evidence_sources": [
            {"source_id": "synthetic-policy", "provenance_kind": "synthetic_fixture"},
            {"source_id": "synthetic-cases", "provenance_kind": "synthetic_fixture"},
        ],
        "extension_rules": [
            {
                "extension_token": "extension-a",
                "expected_media_token": "media-a",
                "disposition": "allow",
                "source_id": "synthetic-policy",
            },
            {
                "extension_token": "extension-b",
                "expected_media_token": "media-b",
                "disposition": "deny",
                "source_id": "synthetic-policy",
            },
            {
                "extension_token": "extension-c",
                "expected_media_token": "media-b",
                "disposition": "allow",
                "source_id": "synthetic-policy",
            },
        ],
        "media_rules": [
            {"media_token": "media-a", "disposition": "allow", "source_id": "synthetic-policy"},
            {"media_token": "media-b", "disposition": "deny", "source_id": "synthetic-policy"},
        ],
        "cases": [
            {
                "case_id": "case-agree",
                "extension_token": "extension-a",
                "declared_media_token": "media-a",
                "source_id": "synthetic-cases",
            },
            {
                "case_id": "case-differential",
                "extension_token": "extension-c",
                "declared_media_token": "media-b",
                "source_id": "synthetic-cases",
            },
            {
                "case_id": "case-missing",
                "extension_token": "extension-b",
                "declared_media_token": "media-unknown",
                "source_id": "synthetic-cases",
            },
        ],
    }


__all__ = [
    "WebContentHandlingError",
    "WebContentHandlingReport",
    "analyze_supplied_web_content_handling",
    "analyze_supplied_web_content_handling_bytes",
    "verify_supplied_web_content_handling",
    "component_fixture",
]

"""Unsigned supplied HTTP entity-tag precondition arithmetic."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "http_supplied_etag_precondition_order"
PROFILE_ID = "AOE-GB-D05-S01"
CAPABILITY_ID = "army.gb.d05.s01"
VECTOR_ID = "AV-GB-D05-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:fa6415a05aa9b97e2ca9fa46194d2adc43bb4aabd2a4cfe3b171215d52b18532"
SEMANTICS_PROFILE = "supplied-origin-etag-preconditions-rfc9110-subset.v1"
DOMAIN = "sunderkey.offline-http-etag-preconditions.v1"
MODEL_DOMAIN = "sunderkey.offline-http-etag-model.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 16_384
MAX_DEPTH = 12
MAX_TAG_BYTES = 512
MAX_TAGS_PER_CLAUSE = 16
MAX_WORK = 16_777_216
MAX_TEXT = 1_024
_DECLARED_BOUNDS = {
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "native_depth": MAX_DEPTH,
    "opaque_tag_bytes": MAX_TAG_BYTES,
    "tags_per_clause": MAX_TAGS_PER_CLAUSE,
    "cumulative_work": MAX_WORK,
}
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "HEP-" + "0" * 32
_FLAGS = {
    "offline_only": True,
    "origin_state_authenticated": False,
    "actual_http_response_observed": False,
    "method_executed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = {
    "authority": "none",
    "target": "none",
    "execution": "none",
    "routing": "none",
    "qualification": "none",
    "deployment": "none",
    "provider_requests": "none",
}
_LIMITATIONS = [
    "All origin role, selected representation and eligibility facts are caller declarations.",
    "Only structured If-Match and If-None-Match entity-tag conditions are evaluated.",
    "Date validators, If-Range, raw field parsing and extension preconditions are not evaluated.",
    "A conditional status label is not a response sent by any server or cache.",
    "The unsafe If-Match already-applied success exception is retained as uncertainty.",
    "No cache, Range, method execution, state/currentness or authority is established.",
]


class HttpEtagPreconditionsError(ValueError):
    """Closed input, unsupported arithmetic, cost or replay refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise HttpEtagPreconditionsError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise HttpEtagPreconditionsError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise HttpEtagPreconditionsError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT:
                raise HttpEtagPreconditionsError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise HttpEtagPreconditionsError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise HttpEtagPreconditionsError("Exact native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise HttpEtagPreconditionsError("Cyclic native document")
            queued = len(item) * (2 if kind is dict else 1)
            if queued > node_limit - nodes:
                raise HttpEtagPreconditionsError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise HttpEtagPreconditionsError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise HttpEtagPreconditionsError("Exact native integer-only JSON families required")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _clone(value), size, nodes


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise HttpEtagPreconditionsError("Raw bounded integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) > 19 or (len(digits) == 19 and digits > limit):
        raise HttpEtagPreconditionsError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise HttpEtagPreconditionsError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise HttpEtagPreconditionsError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise HttpEtagPreconditionsError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise HttpEtagPreconditionsError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise HttpEtagPreconditionsError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise HttpEtagPreconditionsError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise HttpEtagPreconditionsError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise HttpEtagPreconditionsError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_TEXT:
                    raise HttpEtagPreconditionsError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise HttpEtagPreconditionsError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise HttpEtagPreconditionsError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise HttpEtagPreconditionsError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise HttpEtagPreconditionsError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise HttpEtagPreconditionsError("Integer-only raw JSON required")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise HttpEtagPreconditionsError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _tag(value: Any, budget: _Budget) -> tuple[bool, bytes]:
    if type(value) is not dict or set(value) != {"weak", "opaque_tag_base64"}:
        raise HttpEtagPreconditionsError("Exact closed entity-tag fields required")
    if type(value["weak"]) is not bool or type(value["opaque_tag_base64"]) is not str:
        raise HttpEtagPreconditionsError("Exact native entity-tag values required")
    encoded = value["opaque_tag_base64"]
    if len(encoded) > 4 * ((MAX_TAG_BYTES + 2) // 3):
        raise HttpEtagPreconditionsError("Entity-tag base64 ceiling exhausted")
    budget.charge(4 * len(encoded) + MAX_TAG_BYTES)
    try:
        opaque = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HttpEtagPreconditionsError("Entity-tag is not canonical base64") from exc
    if len(opaque) > MAX_TAG_BYTES or base64.b64encode(opaque).decode("ascii") != encoded:
        raise HttpEtagPreconditionsError("Entity-tag byte bound or base64 is invalid")
    if any(not (byte == 0x21 or 0x23 <= byte <= 0x7E or 0x80 <= byte <= 0xFF) for byte in opaque):
        raise HttpEtagPreconditionsError("Entity-tag opaque bytes exceed RFC 9110 subset")
    return value["weak"], opaque


def _clause(value: Any, budget: _Budget) -> tuple[str, list[tuple[bool, bytes]]] | None:
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"mode", "tags"}:
        raise HttpEtagPreconditionsError("Exact closed precondition fields required")
    mode, rows = value["mode"], value["tags"]
    if type(mode) is not str or mode not in {"any", "tags"} or type(rows) is not list:
        raise HttpEtagPreconditionsError("Exact precondition mode and native array required")
    if (mode == "any" and rows) or (mode == "tags" and not 1 <= len(rows) <= MAX_TAGS_PER_CLAUSE):
        raise HttpEtagPreconditionsError("Wildcard and entity-tag list forms are exclusive")
    return mode, [_tag(row, budget) for row in rows]


def _predicate(
    label: str,
    clause: tuple[str, list[tuple[bool, bytes]]],
    target_has_current_representation: bool,
    selected: tuple[bool, bytes] | None,
    budget: _Budget,
) -> dict:
    mode, tags = clause
    budget.charge(32 + 8 * len(tags))
    if mode == "any":
        matched = target_has_current_representation
        comparison = "target_has_current_representation"
    elif selected is None:
        matched = False
        comparison = "strong" if label == "if_match" else "weak"
    elif label == "if_match":
        matched = any(
            not selected[0] and not weak and selected[1] == opaque for weak, opaque in tags
        )
        comparison = "strong"
    else:
        matched = any(selected[1] == opaque for _weak, opaque in tags)
        comparison = "weak"
    return {
        "field": label,
        "comparison": comparison,
        "predicate_true": matched if label == "if_match" else not matched,
    }


def _bounds() -> dict:
    return dict(_DECLARED_BOUNDS)


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise HttpEtagPreconditionsError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    if set(source) != {
        "schema_version",
        "source_id",
        "recipient_role",
        "baseline_preconditions_eligible",
        "method",
        "target_has_current_representation",
        "selected_representation_exists",
        "selected_entity_tag",
        "if_match",
        "if_none_match",
    }:
        raise HttpEtagPreconditionsError("Closed source model fields required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise HttpEtagPreconditionsError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _SOURCE.fullmatch(source["source_id"]) is None:
        raise HttpEtagPreconditionsError("Bounded source identifier required")
    if source["recipient_role"] != "origin" or type(source["recipient_role"]) is not str:
        raise HttpEtagPreconditionsError("Only declared origin recipient is supported")
    eligible = source["baseline_preconditions_eligible"]
    target_has_current_representation = source["target_has_current_representation"]
    exists = source["selected_representation_exists"]
    if (
        type(eligible) is not bool
        or type(target_has_current_representation) is not bool
        or type(exists) is not bool
    ):
        raise HttpEtagPreconditionsError("Exact native eligibility and existence booleans required")
    if exists and not target_has_current_representation:
        raise HttpEtagPreconditionsError(
            "Selected representation implies target has a current representation"
        )
    method = source["method"]
    if type(method) is not str or method not in {"GET", "HEAD", "PUT"}:
        raise HttpEtagPreconditionsError("Only GET, HEAD and PUT are supported")
    selected = (
        None
        if source["selected_entity_tag"] is None
        else _tag(source["selected_entity_tag"], budget)
    )
    if not exists and selected is not None:
        raise HttpEtagPreconditionsError("Absent representation cannot have a selected entity tag")
    if_match = _clause(source["if_match"], budget)
    if_none_match = _clause(source["if_none_match"], budget)
    observations: list[dict] = []
    outcome = "preconditions_not_evaluated" if not eligible else "preconditions_pass"
    if eligible:
        if if_match is not None:
            row = _predicate(
                "if_match", if_match, target_has_current_representation, selected, budget
            )
            observations.append(row)
            if not row["predicate_true"]:
                outcome = (
                    "put_if_match_false_new_mutation_blocked_status_unassessed"
                    if method == "PUT"
                    else "conditional_412_predicate"
                )
        if outcome == "preconditions_pass" and if_none_match is not None:
            row = _predicate(
                "if_none_match", if_none_match, target_has_current_representation, selected, budget
            )
            observations.append(row)
            if not row["predicate_true"]:
                outcome = (
                    "conditional_412_predicate" if method == "PUT" else "conditional_304_predicate"
                )
    document = {
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
        "roadmap_package_ids": ["A7.4"],
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "precondition_observations": observations,
        "analysis_status": outcome,
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(18 * size + 8 * source_size + 8 * nodes + len(DOMAIN) + len(MODEL_DOMAIN) + 2)
    return _Plan(document, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "HEP-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise HttpEtagPreconditionsError("Exact native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise HttpEtagPreconditionsError("Report requires complete original source model")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise HttpEtagPreconditionsError("Exact SHA256 report address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "HEP-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise HttpEtagPreconditionsError("Exact report ID/address join required")
    budget.charge(12 * size + 4 * expected.size + 8 * nodes)
    placeholder = {
        **owned,
        "source_model_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    if _canonical(placeholder) != _canonical(expected.document):
        raise HttpEtagPreconditionsError("Report metadata does not replay supplied preconditions")
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise HttpEtagPreconditionsError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise HttpEtagPreconditionsError("Report addresses do not replay original model")
    return document


def _stored(report: Any) -> str:
    if type(report) is not HttpEtagPreconditionsAnalysis:
        raise HttpEtagPreconditionsError("Exact native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise HttpEtagPreconditionsError("Exact native retained report text required")
    return text


def _owned(text: str) -> HttpEtagPreconditionsAnalysis:
    report = object.__new__(HttpEtagPreconditionsAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class HttpEtagPreconditionsAnalysis:
    """Detached unsigned predicate report retaining its complete original model."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not HttpEtagPreconditionsAnalysis:
            raise HttpEtagPreconditionsError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> HttpEtagPreconditionsAnalysis:
        if cls is not HttpEtagPreconditionsAnalysis:
            raise HttpEtagPreconditionsError("Exact native report family required")
        budget = _Budget()
        _document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise HttpEtagPreconditionsError("Report addresses do not replay source")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> HttpEtagPreconditionsAnalysis:
        if cls is not HttpEtagPreconditionsAnalysis:
            raise HttpEtagPreconditionsError("Exact native report family required")
        _replay_text(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay_text(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay_text(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_http_etag_preconditions(model: Any) -> HttpEtagPreconditionsAnalysis:
    """Evaluate declared origin ETag predicates, never a live HTTP method."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_http_etag_preconditions_bytes(
    *, model_bytes: Any
) -> HttpEtagPreconditionsAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise HttpEtagPreconditionsError("Bounded exact native model JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HttpEtagPreconditionsError("ASCII source JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_http_etag_preconditions_analysis(
    report: Any, *, model: Any
) -> HttpEtagPreconditionsAnalysis:
    """Replay embedded and separately supplied originals within one work budget."""
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    if text != canonical:
        raise HttpEtagPreconditionsError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise HttpEtagPreconditionsError(
            "Report differs from embedded or separately original source"
        )
    return _owned(separate)


def component_fixture() -> dict:
    """Return a fresh, inert, declared conditional GET example."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-etag-preconditions",
        "recipient_role": "origin",
        "baseline_preconditions_eligible": True,
        "method": "GET",
        "target_has_current_representation": True,
        "selected_representation_exists": True,
        "selected_entity_tag": {"weak": False, "opaque_tag_base64": "djE="},
        "if_match": None,
        "if_none_match": {
            "mode": "tags",
            "tags": [{"weak": True, "opaque_tag_base64": "djE="}],
        },
    }


__all__ = [
    "HttpEtagPreconditionsAnalysis",
    "HttpEtagPreconditionsError",
    "analyze_supplied_http_etag_preconditions",
    "analyze_supplied_http_etag_preconditions_bytes",
    "verify_supplied_http_etag_preconditions_analysis",
    "component_fixture",
]

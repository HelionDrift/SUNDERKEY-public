"""Finite arithmetic for one caller-supplied HTTP bytes Range field value."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "http_supplied_byte_range_arithmetic"
PROFILE_ID = "AOE-GB-D05-S01"
CAPABILITY_ID = "army.gb.d05.s01"
VECTOR_ID = "AV-GB-D05-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:fa6415a05aa9b97e2ca9fa46194d2adc43bb4aabd2a4cfe3b171215d52b18532"
DOMAIN = "sunderkey.offline-http-byte-range-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-http-byte-range-model.v1"
SEMANTICS_PROFILE = "rfc9110-supplied-bytes-range-arithmetic.v1"
MAX_FIELD_BYTES = 8192
MAX_MEMBERS = 128
MAX_EMPTY_ELEMENTS = 128
MAX_OVERLAPS = 256
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 256
MAX_REPORT_NODES = 4096
MAX_DEPTH = 12
MAX_WORK = 8_388_608
MAX_INTEGER = 2**63 - 1
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_FIELDS = {"schema_version", "source_id", "range_field_value_base64", "representation_length"}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "execution",
        "network",
        "provider",
        "credential",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "server_response_verified",
        "range_honored_verified",
        "representation_identity_verified",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_BOUNDS = {
    "field_bytes": MAX_FIELD_BYTES,
    "members": MAX_MEMBERS,
    "empty_list_elements": MAX_EMPTY_ELEMENTS,
    "retained_overlap_pairs": MAX_OVERLAPS,
    "model_bytes": MAX_MODEL_BYTES,
    "report_bytes": MAX_REPORT_BYTES,
    "model_nodes": MAX_MODEL_NODES,
    "report_nodes": MAX_REPORT_NODES,
    "native_depth": MAX_DEPTH,
    "signed_integer_maximum": MAX_INTEGER,
    "cumulative_work_per_public_operation": MAX_WORK,
}
_LIMITATIONS = (
    "The Range field value and representation length are unauthenticated caller declarations.",
    "Only RFC 9110 bytes-range syntax, selected spans and GET satisfiability are computed.",
    "A nonzero suffix is RFC-satisfiable for a zero-length representation but selects no octets.",
    "No method, If-Range, precondition, response status or multipart body is supplied.",
    "A server can ignore Range or reject a request with many or overlapping ranges.",
    "Finite software numeric, list and byte ceilings are not HTTP protocol limits.",
    "No source authenticity, live use, qualification or response behavior is established.",
)


class HttpByteRangeAnalysisError(ValueError):
    """Closed native input, software cost or semantic replay failed."""


@dataclass
class _Budget:
    work: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.work:
            raise HttpByteRangeAnalysisError("Cumulative operation work budget exceeded")
        self.work += amount


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    """Detach exact native JSON with bounded escaped size, nodes and repeated subtrees."""
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    active: set[int] = set()
    nodes = size = 0

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise HttpByteRangeAnalysisError("Escaped native document byte budget exceeded")
        size += amount
        budget.charge(amount + 1)

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > node_limit or depth > MAX_DEPTH:
            raise HttpByteRangeAnalysisError("Native node or depth budget exceeded")
        kind = type(item)
        if kind is str:
            if len(item) > byte_limit:
                raise HttpByteRangeAnalysisError("Native text exceeds the software limit")
            if not item.isascii() or any(ord(char) < 32 or ord(char) > 126 for char in item):
                raise HttpByteRangeAnalysisError("Printable ASCII native text is required")
            add(len(item) + 2 + item.count('"') + item.count("\\"))
            return item
        if kind is int:
            if not -MAX_INTEGER - 1 <= item <= MAX_INTEGER:
                raise HttpByteRangeAnalysisError("Signed64 native integers are required")
            add(len(str(item)))
            return item
        if kind is bool:
            add(4 if item else 5)
            return item
        if item is None:
            add(4)
            return None
        if kind not in (list, dict):
            raise HttpByteRangeAnalysisError("Exact native JSON families are required")
        if id(item) in active:
            raise HttpByteRangeAnalysisError("Cyclic native input is rejected")
        count = len(item)
        if count * (2 if kind is dict else 1) > node_limit - nodes:
            raise HttpByteRangeAnalysisError("Collection exceeds remaining native node budget")
        add(2 + max(0, count - 1) + (count if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise HttpByteRangeAnalysisError("Exact native string keys are required")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 1), size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _raw_integer(token: str) -> int:
    minus = token.startswith("-")
    digits = token[1:] if minus else token
    if (
        not digits
        or len(digits) > 19
        or any(char not in "0123456789" for char in digits)
        or (len(digits) > 1 and digits[0] == "0")
    ):
        raise HttpByteRangeAnalysisError("Bounded JSON integer grammar is required")
    limit = "9223372036854775808" if minus else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise HttpByteRangeAnalysisError("Raw signed64 integer limit exceeded")
    return int(token)


def _raw_string(text: str, start: int, byte_limit: int) -> int:
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise HttpByteRangeAnalysisError("Incomplete raw JSON escape")
            escaped = text[index]
            if escaped == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise HttpByteRangeAnalysisError("Malformed raw Unicode escape")
                if not 32 <= int(digits, 16) <= 126:
                    raise HttpByteRangeAnalysisError("Raw escaped text exceeds ASCII subset")
                index += 4
            elif escaped not in '\\"/':
                raise HttpByteRangeAnalysisError("Raw escaped text exceeds ASCII subset")
        elif not 32 <= ord(char) <= 126:
            raise HttpByteRangeAnalysisError("Raw JSON text exceeds printable ASCII subset")
        index += 1
        if index - start > byte_limit:
            raise HttpByteRangeAnalysisError("Raw string software limit exceeded")
    raise HttpByteRangeAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit or not text.isascii():
        raise HttpByteRangeAnalysisError("Bounded exact native ASCII JSON text is required")
    budget.charge(len(text))
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise HttpByteRangeAnalysisError("Malformed raw JSON container")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise HttpByteRangeAnalysisError("Raw JSON node/depth budget exceeded")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index, byte_limit)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise HttpByteRangeAnalysisError("Raw integer lexical budget exceeded")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _raw_integer(token)
    if stack:
        raise HttpByteRangeAnalysisError("Unterminated raw JSON container")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in rows:
            if key in result:
                raise HttpByteRangeAnalysisError("Duplicate raw JSON member")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_raw_integer,
            parse_float=lambda _: (_ for _ in ()).throw(
                HttpByteRangeAnalysisError("Float JSON values are unsupported")
            ),
        )
    except (ValueError, RecursionError, OverflowError) as exc:
        raise HttpByteRangeAnalysisError("Invalid bounded JSON document") from exc
    owned, size, _ = _capture(decoded, budget, report=report)
    return owned, size


def _fields(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or value.keys() != fields:
        raise HttpByteRangeAnalysisError(f"{label} requires its exact closed fields")
    return value


def _decimal(text: bytes) -> int:
    if not text or len(text) > 19 or any(char < 48 or char > 57 for char in text):
        raise HttpByteRangeAnalysisError("Bounded decimal range position is required")
    digits = text.decode("ascii")
    if len(digits) == 19 and digits > "9223372036854775807":
        raise HttpByteRangeAnalysisError("Range position exceeds software signed64 limit")
    return int(digits)


def _field(model: dict, budget: _Budget) -> bytes:
    _fields(model, _MODEL_FIELDS, "Model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HttpByteRangeAnalysisError("Exact native schema version 1 is required")
    source_id = model["source_id"]
    if (
        type(source_id) is not str
        or not 1 <= len(source_id) <= 64
        or any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for char in source_id
        )
    ):
        raise HttpByteRangeAnalysisError("Bounded source ID grammar is required")
    length = model["representation_length"]
    if type(length) is not int or not 0 <= length <= MAX_INTEGER:
        raise HttpByteRangeAnalysisError("Nonnegative native signed64 length is required")
    encoded = model["range_field_value_base64"]
    if type(encoded) is not str or len(encoded) > 4 * ((MAX_FIELD_BYTES + 2) // 3):
        raise HttpByteRangeAnalysisError("Bounded canonical base64 field text is required")
    budget.charge(len(encoded) + MAX_FIELD_BYTES + 1)
    try:
        field = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HttpByteRangeAnalysisError("Invalid base64 field text") from exc
    if (
        not field
        or len(field) > MAX_FIELD_BYTES
        or base64.b64encode(field).decode("ascii") != encoded
    ):
        raise HttpByteRangeAnalysisError("Canonical nonempty bounded base64 field is required")
    if any(char != 9 and (char < 32 or char > 126) for char in field):
        raise HttpByteRangeAnalysisError("Printable ASCII or HTAB Range bytes are required")
    return field


def _parse_members(
    field: bytes, length: int, budget: _Budget
) -> tuple[list[dict], list[dict], bool, int]:
    equal = field.find(b"=")
    if equal < 0 or field[:equal].lower() != b"bytes":
        raise HttpByteRangeAnalysisError("Only exact bytes range-unit syntax is supported")
    raw_members = field[equal + 1 :].split(b",")
    if len(raw_members) > MAX_MEMBERS + MAX_EMPTY_ELEMENTS:
        raise HttpByteRangeAnalysisError("Range list exceeds finite member budget")
    budget.charge(8 * len(raw_members) + len(field))
    members: list[dict] = []
    empty_count = 0
    for raw in raw_members:
        part = raw.strip(b" \t")
        if not part:
            empty_count += 1
            if empty_count > MAX_EMPTY_ELEMENTS:
                raise HttpByteRangeAnalysisError("Empty list elements exceed software budget")
            continue
        if len(members) >= MAX_MEMBERS:
            raise HttpByteRangeAnalysisError("Range members exceed software budget")
        if any(char in (9, 32) for char in part):
            raise HttpByteRangeAnalysisError("Whitespace inside a bytes-range member is invalid")
        if part.count(b"-") != 1:
            raise HttpByteRangeAnalysisError("Each bytes-range member requires one hyphen")
        left, right = part.split(b"-")
        index = len(members)
        if not left:
            suffix = _decimal(right)
            satisfiable = suffix > 0
            first = max(0, length - suffix) if satisfiable and length else None
            last = length - 1 if satisfiable and length else None
            kind = "suffix"
            declared_first = None
            declared_last = None
        else:
            declared_first = _decimal(left)
            declared_last = _decimal(right) if right else None
            if declared_last is not None and declared_last < declared_first:
                raise HttpByteRangeAnalysisError("Last byte position precedes first")
            satisfiable = declared_first < length
            first = declared_first if satisfiable else None
            last = (
                min(declared_last, length - 1)
                if (satisfiable and declared_last is not None)
                else (length - 1 if satisfiable else None)
            )
            kind = "closed" if right else "open"
            suffix = None
        members.append(
            {
                "index": index,
                "raw_member": part.decode("ascii"),
                "kind": kind,
                "declared_first": declared_first,
                "declared_last": declared_last,
                "declared_suffix_length": suffix,
                "rfc_satisfiable": satisfiable,
                "selected_first": first,
                "selected_last": last,
                "selected_octets": 0 if first is None else last - first + 1,
            }
        )
    if not members:
        raise HttpByteRangeAnalysisError("Range set requires a nonempty range member")
    overlaps: list[dict] = []
    for i, left in enumerate(members):
        if left["selected_first"] is None:
            continue
        for right in members[i + 1 :]:
            if right["selected_first"] is None:
                continue
            budget.charge(1)
            first = max(left["selected_first"], right["selected_first"])
            last = min(left["selected_last"], right["selected_last"])
            if first <= last:
                if len(overlaps) >= MAX_OVERLAPS:
                    raise HttpByteRangeAnalysisError("Retained overlap pair budget exceeded")
                overlaps.append(
                    {
                        "left_index": left["index"],
                        "right_index": right["index"],
                        "selected_first": first,
                        "selected_last": last,
                    }
                )
    return members, overlaps, any(row["rfc_satisfiable"] for row in members), empty_count


@dataclass(slots=True)
class _Plan:
    source: dict
    field: bytes
    owned: dict
    addressed: dict
    report_size: int


def _prepare_derive(model: Any, budget: _Budget) -> _Plan:
    source, model_size, _ = _capture(model, budget)
    field = _field(source, budget)
    members, overlaps, satisfiable, empty_count = _parse_members(
        field, source["representation_length"], budget
    )
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
        "independent_validator_id": VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "caller_supplied_unverified",
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "field_sha256": _PLACEHOLDER,
        "members": members,
        "overlap_pairs": overlaps,
        "rfc_get_satisfiable_predicate": satisfiable,
        "empty_list_elements_ignored": empty_count,
        "server_behavior_unassessed": True,
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": dict(_BOUNDS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "HBR-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    owned, report_size, _ = _capture(body, budget, report=True)
    addressed = {
        key: value for key, value in owned.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    _, addressed_size, _ = _capture(addressed, budget, report=True)
    model_preimage = len(MODEL_DOMAIN) + 1 + model_size
    analysis_preimage = len(DOMAIN) + 1 + addressed_size
    budget.charge(model_size + addressed_size + report_size)
    budget.charge(2 * (model_preimage + analysis_preimage + len(field)))
    budget.charge(len(owned) + len(addressed))
    # No digest is computed until every plan for the public operation is funded.
    return _Plan(source, field, owned, addressed, report_size)


def _finish_derive(plan: _Plan) -> tuple[dict, str]:
    model_digest = (
        "sha256:"
        + hashlib.sha256(
            MODEL_DOMAIN.encode("ascii") + b"\n" + _canonical(plan.source).encode("ascii")
        ).hexdigest()
    )
    field_digest = "sha256:" + hashlib.sha256(plan.field).hexdigest()
    plan.addressed["source_model_sha256"] = model_digest
    plan.addressed["field_sha256"] = field_digest
    digest = (
        "sha256:"
        + hashlib.sha256(
            DOMAIN.encode("ascii") + b"\n" + _canonical(plan.addressed).encode("ascii")
        ).hexdigest()
    )
    plan.owned["source_model_sha256"] = model_digest
    plan.owned["field_sha256"] = field_digest
    plan.owned["analysis_id"] = "HBR-" + digest[7:39].upper()
    plan.owned["analysis_sha256"] = digest
    text = _canonical(plan.owned)
    if len(text) != plan.report_size:
        raise HttpByteRangeAnalysisError("Fixed-width report differs from its reservation")
    return plan.owned, text


def _derive(model: Any, budget: _Budget) -> tuple[dict, str]:
    return _finish_derive(_prepare_derive(model, budget))


def _prepare_replay(document: Any, size: int, budget: _Budget) -> tuple[str, _Plan]:
    if type(document) is not dict or "source_model" not in document:
        raise HttpByteRangeAnalysisError("An exact source-bearing report is required")
    budget.charge(2 * size)
    supplied = _canonical(document)
    return supplied, _prepare_derive(document["source_model"], budget)


def _replay(document: Any, size: int, budget: _Budget) -> tuple[dict, str]:
    supplied, plan = _prepare_replay(document, size, budget)
    expected, text = _finish_derive(plan)
    if supplied != text:
        raise HttpByteRangeAnalysisError("Report differs from full embedded-source replay")
    return expected, text


def _freeze(text: str) -> HttpByteRangeAnalysis:
    result = object.__new__(HttpByteRangeAnalysis)
    object.__setattr__(result, "_document_json", text)
    return result


@dataclass(frozen=True, slots=True, init=False)
class HttpByteRangeAnalysis:
    """Unsigned arithmetic over one declared field value and representation length."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(self) is not HttpByteRangeAnalysis:
            raise HttpByteRangeAnalysisError("Exact report family is required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        _, text = _replay(owned, size, budget)
        object.__setattr__(self, "_document_json", text)

    @classmethod
    def from_dict(cls, document: Any) -> HttpByteRangeAnalysis:
        if cls is not HttpByteRangeAnalysis:
            raise HttpByteRangeAnalysisError("Exact report family is required")
        return cls(document)

    @classmethod
    def from_json(cls, document_json: Any) -> HttpByteRangeAnalysis:
        if cls is not HttpByteRangeAnalysis:
            raise HttpByteRangeAnalysisError("Exact report family is required")
        budget = _Budget()
        owned, size = _decode(document_json, budget, report=True)
        _, text = _replay(owned, size, budget)
        return _freeze(text)

    def to_dict(self) -> dict:
        return _capture_report(self, _Budget())[0]

    def to_json(self) -> str:
        return _capture_report(self, _Budget())[1]

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _capture_report(report: Any, budget: _Budget) -> tuple[dict, str]:
    if type(report) is not HttpByteRangeAnalysis:
        raise HttpByteRangeAnalysisError("Exact report family is required")
    owned, size = _decode(getattr(report, "_document_json", None), budget, report=True)
    return _replay(owned, size, budget)


def analyze_supplied_http_byte_ranges(model: Any) -> HttpByteRangeAnalysis:
    _, text = _derive(model, _Budget())
    return _freeze(text)


def analyze_supplied_http_byte_ranges_bytes(*, model_bytes: Any) -> HttpByteRangeAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise HttpByteRangeAnalysisError("Bounded exact native JSON model bytes are required")
    budget = _Budget()
    budget.charge(len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HttpByteRangeAnalysisError("Model bytes exceed ASCII subset") from exc
    source, _ = _decode(text, budget)
    _, report = _derive(source, budget)
    return _freeze(report)


def verify_supplied_http_byte_range_analysis(report: Any, *, model: Any) -> HttpByteRangeAnalysis:
    budget = _Budget()
    if type(report) is not HttpByteRangeAnalysis:
        raise HttpByteRangeAnalysisError("Exact report family is required")
    document, size = _decode(getattr(report, "_document_json", None), budget, report=True)
    supplied, embedded_plan = _prepare_replay(document, size, budget)
    original_plan = _prepare_derive(model, budget)
    budget.charge(2 * len(supplied) + original_plan.report_size)
    _, embedded = _finish_derive(embedded_plan)
    if supplied != embedded:
        raise HttpByteRangeAnalysisError("Report differs from full embedded-source replay")
    _, expected = _finish_derive(original_plan)
    if supplied != expected:
        raise HttpByteRangeAnalysisError("Report differs from separately supplied original model")
    return _freeze(expected)


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic declarations, not a server response or source proof."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-range",
        "range_field_value_base64": base64.b64encode(b"bytes=0-4, 10-, -3").decode("ascii"),
        "representation_length": 20,
    }


__all__ = [
    "HttpByteRangeAnalysis",
    "HttpByteRangeAnalysisError",
    "analyze_supplied_http_byte_ranges",
    "analyze_supplied_http_byte_ranges_bytes",
    "verify_supplied_http_byte_range_analysis",
    "component_fixture",
]

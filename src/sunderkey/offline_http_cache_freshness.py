"""Bounded RFC 9111 arithmetic over declared valid cache metadata, without I/O."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "http_supplied_cache_freshness_arithmetic"
PROFILE_ID = "AOE-GB-D05-S02"
CAPABILITY_ID = "army.gb.d05.s02"
VECTOR_ID = "AV-GB-D05-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:03c71eef405c080e094fbab91db4a0b25fe141cf3e581a81c62a51cf2db4da4a"
DOMAIN = "sunderkey.offline-http-cache-freshness.v1"
MODEL_DOMAIN = "sunderkey.offline-http-cache-freshness-model.v1"
SEMANTICS_PROFILE = "rfc9111-conservative-declared-freshness.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_CASES = 128
MAX_WORK = 4_000_000
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_INSTANTS = (
    "request_time_seconds",
    "response_time_seconds",
    "evaluated_at_seconds",
    "date_value_seconds",
    "expires_value_seconds",
)
_DELTAS = ("age_value_seconds", "max_age_seconds", "s_maxage_seconds")
_CASE_FIELDS = {"case_id", "cache_kind", *_INSTANTS, *_DELTAS}
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "header_projection_verified",
        "clock_truth_verified",
        "date_header_append_observed",
        "cacheability_verified",
        "storage_approved",
        "reuse_approved",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "cache_read",
        "cache_write",
        "credential",
        "execution",
        "header_generation",
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
    "cases": MAX_CASES,
    "work_steps": MAX_WORK,
    "integer_minimum": MIN_INTEGER,
    "integer_maximum": MAX_INTEGER,
}
_LIMITATIONS = (
    "Header integers are caller-declared valid projected values; null headers mean absence only.",
    "Null clocks are unavailable premises, not readings of any actual or trusted clock.",
    "Absent Date substitutes declared receipt time for arithmetic, not observed header insertion.",
    "The conservative max age branch is selected, not every cache's permitted implementation.",
    "Freshness arithmetic does not establish cacheability, storage or response reuse permission.",
    "No HTTP parsing, duplicate directives, no-cache, no-store, Vary or heuristics are evaluated.",
    "Signed 64-bit intermediate overflow is unassessed, not full HTTP overflow conformance.",
    "No network, provider, target, credentials, current authority or qualification is established.",
)


class HttpCacheFreshnessAnalysisError(ValueError):
    """A supplied model or report is outside the exact bounded software contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise HttpCacheFreshnessAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    """Reject aliases and charge repeated graphs and escaped bytes before serialization."""
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise HttpCacheFreshnessAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise HttpCacheFreshnessAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise HttpCacheFreshnessAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise HttpCacheFreshnessAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise HttpCacheFreshnessAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise HttpCacheFreshnessAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise HttpCacheFreshnessAnalysisError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise HttpCacheFreshnessAnalysisError(
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
            raise HttpCacheFreshnessAnalysisError("Only exact native JSON primitives are supported")

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
        raise HttpCacheFreshnessAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not MIN_INTEGER <= number <= MAX_INTEGER:
        raise HttpCacheFreshnessAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Bound raw structures, scalar tokens and escapes before the JSON decoder."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise HttpCacheFreshnessAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise HttpCacheFreshnessAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise HttpCacheFreshnessAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise HttpCacheFreshnessAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            digit not in "0123456789abcdefABCDEF" for digit in digits
                        ):
                            raise HttpCacheFreshnessAnalysisError("Malformed raw Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise HttpCacheFreshnessAnalysisError(
                                "Printable ASCII escapes required"
                            )
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise HttpCacheFreshnessAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise HttpCacheFreshnessAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise HttpCacheFreshnessAnalysisError("Raw string bound exhausted")
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
                raise HttpCacheFreshnessAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise HttpCacheFreshnessAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise HttpCacheFreshnessAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise HttpCacheFreshnessAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise HttpCacheFreshnessAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise HttpCacheFreshnessAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, HttpCacheFreshnessAnalysisError):
            raise
        raise HttpCacheFreshnessAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {"schema_version", "cases"}:
        raise HttpCacheFreshnessAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise HttpCacheFreshnessAnalysisError("Exact native schema version 1 required")
    cases = owned["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= MAX_CASES:
        raise HttpCacheFreshnessAnalysisError("Bounded nonempty native cases required")
    identities: set[str] = set()
    for case in cases:
        work.charge(1 + len(_CASE_FIELDS))
        if type(case) is not dict or case.keys() != _CASE_FIELDS:
            raise HttpCacheFreshnessAnalysisError("Exact closed case fields required")
        identifier = case["case_id"]
        if type(identifier) is not str or _ID.fullmatch(identifier) is None:
            raise HttpCacheFreshnessAnalysisError("Bounded native case identity required")
        if identifier in identities:
            raise HttpCacheFreshnessAnalysisError("Duplicate declared case identity")
        identities.add(identifier)
        kind = case["cache_kind"]
        if type(kind) is not str or kind not in {"shared", "private"}:
            raise HttpCacheFreshnessAnalysisError("Declared shared or private cache kind required")
        for name in (*_INSTANTS, *_DELTAS):
            number = case[name]
            if number is not None and type(number) is not int:
                raise HttpCacheFreshnessAnalysisError(
                    "Exact native integer or null premise required"
                )
            if name in _DELTAS and number is not None and number < 0:
                raise HttpCacheFreshnessAnalysisError("Declared delta seconds must be nonnegative")
    return owned, text


class _ArithmeticOutsideSubset(Exception):
    pass


def _checked(number: int) -> int:
    if not MIN_INTEGER <= number <= MAX_INTEGER:
        raise _ArithmeticOutsideSubset
    return number


def _case_observation(case: dict, work: _Work) -> dict:
    work.charge(40)
    request = case["request_time_seconds"]
    response = case["response_time_seconds"]
    evaluated = case["evaluated_at_seconds"]
    date = case["date_value_seconds"]
    effective_date = date if date is not None else response
    age = case["age_value_seconds"]
    reasons: list[str] = []
    row = {
        "case_id": case["case_id"],
        "cache_kind": case["cache_kind"],
        "effective_date_seconds": effective_date,
        "effective_date_source": "declared_date"
        if date is not None
        else "declared_response_time_for_absent_date",
        "effective_age_seconds": age if age is not None else 0,
        "age_value_source": "declared_age" if age is not None else "declared_absent_age_zero",
        "lifetime_source": "no_explicit_lifetime",
        "freshness_lifetime_seconds": None,
        "apparent_age_seconds": None,
        "response_delay_seconds": None,
        "corrected_age_value_seconds": None,
        "corrected_initial_age_seconds": None,
        "resident_time_seconds": None,
        "current_age_seconds": None,
        "freshness_comparison": None,
        "outcome": "unassessed",
        "unassessed_reasons": reasons,
    }
    for value, code in (
        (request, "request_time_unavailable"),
        (response, "response_time_unavailable"),
        (evaluated, "evaluation_time_unavailable"),
    ):
        if value is None:
            reasons.append(code)
    if request is not None and response is not None and request > response:
        reasons.append("declared_request_response_order_inconsistent")
    if response is not None and evaluated is not None and response > evaluated:
        reasons.append("declared_response_evaluation_order_inconsistent")
    if case["cache_kind"] == "shared" and case["s_maxage_seconds"] is not None:
        row["lifetime_source"] = "shared_s_maxage"
        row["freshness_lifetime_seconds"] = case["s_maxage_seconds"]
    elif case["max_age_seconds"] is not None:
        row["lifetime_source"] = "max_age"
        row["freshness_lifetime_seconds"] = case["max_age_seconds"]
    elif case["expires_value_seconds"] is not None:
        row["lifetime_source"] = "expires_minus_effective_date"
        if effective_date is not None:
            try:
                row["freshness_lifetime_seconds"] = _checked(
                    case["expires_value_seconds"] - effective_date
                )
            except _ArithmeticOutsideSubset:
                reasons.append("lifetime_arithmetic_outside_signed64")
    else:
        reasons.append("no_explicit_lifetime_heuristics_unassessed")
    # The request, receipt and evaluation clocks must be available and ordered.
    clock_ready = request is not None and response is not None and evaluated is not None
    if clock_ready and request <= response <= evaluated:
        try:
            row["apparent_age_seconds"] = max(0, _checked(response - effective_date))
            row["response_delay_seconds"] = _checked(response - request)
            row["corrected_age_value_seconds"] = _checked(
                row["effective_age_seconds"] + row["response_delay_seconds"]
            )
            row["corrected_initial_age_seconds"] = max(
                row["apparent_age_seconds"], row["corrected_age_value_seconds"]
            )
            row["resident_time_seconds"] = _checked(evaluated - response)
            row["current_age_seconds"] = _checked(
                row["corrected_initial_age_seconds"] + row["resident_time_seconds"]
            )
        except _ArithmeticOutsideSubset:
            reasons.append("age_arithmetic_outside_signed64")
    if not reasons:
        fresh = row["freshness_lifetime_seconds"] > row["current_age_seconds"]
        row["freshness_comparison"] = fresh
        row["outcome"] = (
            "fresh_under_supplied_arithmetic" if fresh else "not_fresh_under_supplied_arithmetic"
        )
    return row


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    rows: list[dict] = []
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
        "standard": "RFC9111-sections-4.2-4.2.1-4.2.3",
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "case_count": len(owned["cases"]),
        "case_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "HCF-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(body, work)
    for case in owned["cases"]:
        row = _case_observation(case, work)
        row_size, row_nodes = _measure(row, work)
        row_size += 1 if rows else 0
        if size + row_size > MAX_DOCUMENT_BYTES or nodes + row_nodes > MAX_NATIVE_NODES:
            raise HttpCacheFreshnessAnalysisError("Cumulative report bound before retention")
        size += row_size
        nodes += row_nodes
        rows.append(row)
    report_size, report_nodes = _measure(body, work)
    # Reserve full replay/export passes and final digest inputs before the first hash.
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + 1 + len(source_text) + len(DOMAIN) + 1 + hash_size)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "HCF-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise HttpCacheFreshnessAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise HttpCacheFreshnessAnalysisError("Report does not exactly replay its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class HttpCacheFreshnessAnalysis:
    """Detached arithmetic only, not an HTTP cache, trusted clock or reuse grant."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> HttpCacheFreshnessAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> HttpCacheFreshnessAnalysis:
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


def analyze_supplied_http_cache_freshness(model: Any) -> HttpCacheFreshnessAnalysis:
    """Evaluate only declared integer arithmetic, without any external operations."""
    return HttpCacheFreshnessAnalysis(_derive(model))


def analyze_supplied_http_cache_freshness_bytes(*, model_bytes: Any) -> HttpCacheFreshnessAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise HttpCacheFreshnessAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HttpCacheFreshnessAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_http_cache_freshness(_decode(text))


def verify_supplied_http_cache_freshness_analysis(
    report: Any, *, model: Any
) -> HttpCacheFreshnessAnalysis:
    """Check separately supplied original premises, not actual cache state or authority."""
    if type(report) is not HttpCacheFreshnessAnalysis:
        raise HttpCacheFreshnessAnalysisError("Exact native cache analysis family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise HttpCacheFreshnessAnalysisError("Report differs from separately supplied originals")
    return HttpCacheFreshnessAnalysis(expected)


def component_fixture() -> dict:
    """Return fresh wholly synthetic shared, private and unassessed arithmetic cases."""
    case = {
        "case_id": "synthetic-shared-equality",
        "cache_kind": "shared",
        "request_time_seconds": 1000,
        "response_time_seconds": 1005,
        "evaluated_at_seconds": 1020,
        "date_value_seconds": 998,
        "age_value_seconds": 3,
        "max_age_seconds": 60,
        "s_maxage_seconds": 23,
        "expires_value_seconds": 1100,
    }
    return {
        "schema_version": 1,
        "cases": [
            case,
            {**case, "case_id": "synthetic-private", "cache_kind": "private"},
            {
                **case,
                "case_id": "synthetic-no-explicit-lifetime",
                "max_age_seconds": None,
                "s_maxage_seconds": None,
                "expires_value_seconds": None,
            },
        ],
    }


__all__ = [
    "HttpCacheFreshnessAnalysisError",
    "HttpCacheFreshnessAnalysis",
    "analyze_supplied_http_cache_freshness",
    "analyze_supplied_http_cache_freshness_bytes",
    "verify_supplied_http_cache_freshness_analysis",
    "component_fixture",
]

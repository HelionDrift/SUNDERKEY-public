"""Finite CORS checks on supplied parsed metadata, with original-model replay."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "cors_supplied_negotiation_and_exposure"
PROFILE_ID = "AOE-GB-D05-S14"
CAPABILITY_ID = "army.gb.d05.s14"
VECTOR_ID = "AV-GB-D05-S14-01"
STANDARD_COMMIT = "357bd98924d94b81fbe8608192a2ee1f123b82f4"
ANALYSIS_PROFILE = "supplied-fetch-cors-negotiation-exposure.v1"
DOMAIN = "sunderkey.offline-cors-analysis.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_NODES = 32_768
MAX_STRING_BYTES = 4_096
MAX_CASES = 64
MAX_FIELDS_PER_RESPONSE = 32
MAX_FIELD_INSTANCES = 4_096
MAX_NAME_BYTES = 128
MAX_UNSAFE_NAMES_PER_CASE = 32
MAX_RESPONSE_NAMES_PER_CASE = 64
MAX_PARSED_TOKENS = 4_096
MAX_EXPOSED_NAMES = 4_096
MAX_WORK = 1_000_000
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_JSON_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_POLICY_FIELDS = frozenset(
    (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
    )
)
_SAFE_METHODS = frozenset(("GET", "HEAD", "POST"))
_NORMALIZED_METHODS = frozenset(("DELETE", "GET", "HEAD", "OPTIONS", "POST", "PUT"))
_SAFE_RESPONSE_NAMES = frozenset(
    (
        "cache-control",
        "content-language",
        "content-length",
        "content-type",
        "expires",
        "last-modified",
        "pragma",
    )
)
_FORBIDDEN_RESPONSE_NAMES = frozenset(("set-cookie", "set-cookie2"))
_PASS = "passes_supplied_check"
_FAIL = "fails_supplied_check"
_UNKNOWN = "unassessed"
_LIMITS = {
    "max_document_bytes": MAX_DOCUMENT_BYTES,
    "max_depth": MAX_DEPTH,
    "max_nodes": MAX_NODES,
    "max_string_bytes": MAX_STRING_BYTES,
    "max_cases": MAX_CASES,
    "max_fields_per_response": MAX_FIELDS_PER_RESPONSE,
    "max_field_instances": MAX_FIELD_INSTANCES,
    "max_name_bytes": MAX_NAME_BYTES,
    "max_unsafe_names_per_case": MAX_UNSAFE_NAMES_PER_CASE,
    "max_response_names_per_case": MAX_RESPONSE_NAMES_PER_CASE,
    "max_parsed_tokens": MAX_PARSED_TOKENS,
    "max_exposed_names": MAX_EXPOSED_NAMES,
    "max_work": MAX_WORK,
}
_LIMITATIONS = (
    "request_origin_normalization_and_header_value_classification_are_not_verified",
    "metadata_completeness_and_preflight_requirement_are_supplied_premises",
    "no_browser_fetch_eligibility_cache_redirect_or_service_worker_conclusion",
    "no_sop_csp_server_authorization_vulnerability_or_live_access_conclusion",
    "no_response_body_or_credential_values_are_consumed_or_reported",
    "no_source_authentication_or_observed_network_exchange_is_proven",
)
_EFFECTS = {
    name: "none"
    for name in (
        "authority",
        "credential_resolution",
        "execution",
        "finding_publication",
        "network",
        "qualification",
        "target_interaction",
    )
}


class CorsAnalysisError(ValueError):
    """Malformed, unsupported or over-budget supplied metadata."""


@dataclass
class _Cost:
    work: int = 0
    fields: int = 0
    tokens: int = 0
    exposed: int = 0

    def charge(self, units: int) -> None:
        if self.work + units > MAX_WORK:
            raise CorsAnalysisError("Software work limit exceeded")
        self.work += units

    def token(self) -> None:
        if self.tokens >= MAX_PARSED_TOKENS:
            raise CorsAnalysisError("Parsed token limit exceeded")
        self.tokens += 1


def _text(value: Any, maximum: int = MAX_STRING_BYTES, *, empty: bool = False) -> str:
    if type(value) is not str or len(value) > maximum or (not value and not empty):
        raise CorsAnalysisError("Bounded native text is required")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise CorsAnalysisError("Text byte limit exceeded")
    except UnicodeError as exc:
        raise CorsAnalysisError("Unicode scalar text is required") from exc
    return value


def _character_cost(code: int) -> int:
    if code in {34, 92, 8, 9, 10, 12, 13}:
        return 2
    if code < 32 or 126 < code <= 65535:
        return 6
    return 12 if code > 65535 else 1


def _native(value: Any, cost: _Cost | None = None) -> str:
    """Bound every repeated subtree and its escaped serialization before dumps."""
    stack = [(value, 1)]
    nodes = size = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise CorsAnalysisError("Native node/depth limit exceeded")
        kind = type(item)
        if kind is dict:
            count = 2 * len(item)
            if nodes + len(stack) + count > MAX_NODES:
                raise CorsAnalysisError("Native queued-node limit exceeded")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise CorsAnalysisError("Native mapping keys are required")
                stack.append((child, depth + 1))
                stack.append((key, depth + 1))
        elif kind is list:
            if nodes + len(stack) + len(item) > MAX_NODES:
                raise CorsAnalysisError("Native queued-node limit exceeded")
            size += 2 + max(0, len(item) - 1)
            stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            _text(item, empty=True)
            size += 2
            for character in item:
                size += _character_cost(ord(character))
                if size > MAX_DOCUMENT_BYTES:
                    raise CorsAnalysisError("Escaped document byte limit exceeded")
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise CorsAnalysisError("Signed 64-bit integer is required")
            size += len(str(item))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise CorsAnalysisError("Exact native JSON values are required")
        if size > MAX_DOCUMENT_BYTES:
            raise CorsAnalysisError("Document byte limit exceeded")
    if cost is not None:
        cost.charge(size + nodes)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _raw_string(text: str, start: int) -> int:
    index = start + 1
    byte_size = escaped_size = 0
    while index < len(text):
        character = text[index]
        if character == '"':
            return index + 1
        code = ord(character)
        if character == "\\":
            index += 1
            if index >= len(text):
                raise CorsAnalysisError("Unterminated JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
                    raise CorsAnalysisError("Invalid Unicode escape")
                code = int(digits, 16)
                index += 4
                if 0xD800 <= code <= 0xDBFF:
                    if text[index + 1 : index + 3] != "\\u":
                        raise CorsAnalysisError("Unpaired Unicode surrogate")
                    low_digits = text[index + 3 : index + 7]
                    if len(low_digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", low_digits) is None:
                        raise CorsAnalysisError("Invalid Unicode surrogate")
                    low = int(low_digits, 16)
                    if not 0xDC00 <= low <= 0xDFFF:
                        raise CorsAnalysisError("Unpaired Unicode surrogate")
                    code = 0x10000 + ((code - 0xD800) << 10) + low - 0xDC00
                    index += 6
                elif 0xDC00 <= code <= 0xDFFF:
                    raise CorsAnalysisError("Unpaired Unicode surrogate")
            else:
                escaped = {'"': 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}
                if escape not in escaped:
                    raise CorsAnalysisError("Invalid JSON escape")
                code = escaped[escape]
        elif code < 32 or 0xD800 <= code <= 0xDFFF:
            raise CorsAnalysisError("Invalid JSON string scalar")
        byte_size += 1 if code < 128 else 2 if code < 2048 else 3 if code < 65536 else 4
        escaped_size += _character_cost(code)
        if byte_size > MAX_STRING_BYTES or escaped_size > MAX_DOCUMENT_BYTES:
            raise CorsAnalysisError("Raw string budget exceeded")
        index += 1
    raise CorsAnalysisError("Unterminated JSON string")


def _parse_integer(text: str) -> int:
    if _JSON_INTEGER.fullmatch(text) is None:
        raise CorsAnalysisError("Bounded integer JSON grammar is required")
    negative = text.startswith("-")
    magnitude = text[1:] if negative else text
    ceiling = "9223372036854775808" if negative else "9223372036854775807"
    if len(magnitude) == 19 and magnitude > ceiling:
        raise CorsAnalysisError("Signed 64-bit integer limit exceeded")
    return int(text)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorsAnalysisError("Duplicate JSON key")
        result[key] = value
    return result


def _decode(text: Any) -> Any:
    if type(text) is not str or len(text) > MAX_DOCUMENT_BYTES:
        raise CorsAnalysisError("Bounded native JSON text is required")
    try:
        if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise CorsAnalysisError("Raw document byte limit exceeded")
    except UnicodeError as exc:
        raise CorsAnalysisError("UTF-8 scalar text is required") from exc
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n:,":
            index += 1
            continue
        if char in "}]":
            if not stack or stack.pop() != ("{" if char == "}" else "["):
                raise CorsAnalysisError("Malformed JSON container")
            index += 1
            continue
        nodes += 1
        if nodes > MAX_NODES or len(stack) + 1 > MAX_DEPTH:
            raise CorsAnalysisError("Raw node/depth limit exceeded")
        if char in "{[":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index)
        else:
            end = index
            while end < len(text) and text[end] not in " \t\r\n,}:]":
                end += 1
                if end - index > 20:
                    raise CorsAnalysisError("Raw scalar lexical limit exceeded")
            token = text[index:end]
            if token not in {"true", "false", "null"}:
                _parse_integer(token)
            index = end
    if stack:
        raise CorsAnalysisError("Unterminated JSON container")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_parse_integer)
    except (ValueError, RecursionError) as exc:
        raise CorsAnalysisError("Invalid bounded JSON document") from exc
    _native(value)
    return value


def _bytes_json(raw: Any) -> Any:
    if type(raw) is not bytes or len(raw) > MAX_DOCUMENT_BYTES:
        raise CorsAnalysisError("Bounded native bytes are required")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise CorsAnalysisError("UTF-8 JSON bytes are required") from exc
    return _decode(text)


def _exact(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CorsAnalysisError("Exact closed object fields are required")
    return value


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise CorsAnalysisError("Native boolean is required")
    return value


def _reference(value: Any) -> str:
    text = _text(value, MAX_NAME_BYTES)
    if _REF.fullmatch(text) is None:
        raise CorsAnalysisError("Bounded source/case identifier is required")
    return text


def _name(value: Any) -> str:
    text = _text(value, MAX_NAME_BYTES)
    if _TOKEN.fullmatch(text) is None:
        raise CorsAnalysisError("ASCII HTTP token is required")
    return text


def _names(value: Any, ceiling: int) -> list[str]:
    if type(value) is not list or len(value) > ceiling:
        raise CorsAnalysisError("Bounded native header-name array is required")
    result = [_name(name).lower() for name in value]
    if len(result) != len(set(result)):
        raise CorsAnalysisError("Header-name projection must be unique ignoring case")
    return result


def _request(value: Any) -> dict[str, Any]:
    request = _exact(
        value,
        {
            "source_id",
            "serialized_origin",
            "credentials_mode",
            "method",
            "unsafe_header_names",
            "preflight_required",
            "use_cors_preflight",
            "projection_complete",
        },
    )
    _reference(request["source_id"])
    origin = _text(request["serialized_origin"], 1_024)
    if origin == "*" or any(ord(char) < 33 or ord(char) > 126 or char == "," for char in origin):
        raise CorsAnalysisError("A non-wildcard serialized-origin premise is required")
    if type(request["credentials_mode"]) is not str or request["credentials_mode"] not in {
        "omit",
        "same-origin",
        "include",
    }:
        raise CorsAnalysisError("Unsupported credentials-mode premise")
    method = _name(request["method"])
    if method.upper() in _NORMALIZED_METHODS and method != method.upper():
        raise CorsAnalysisError("Known Fetch method must already be normalized")
    _names(request["unsafe_header_names"], MAX_UNSAFE_NAMES_PER_CASE)
    required = _boolean(request["preflight_required"])
    forced = _boolean(request["use_cors_preflight"])
    _boolean(request["projection_complete"])
    if forced and not required:
        raise CorsAnalysisError("Forced preflight contradicts the required-preflight premise")
    return request


def _response(value: Any, cost: _Cost, *, actual: bool) -> dict[str, Any] | None:
    if value is None:
        return None
    fields = {"source_id", "status", "cors_fields", "headers_complete"}
    if actual:
        fields.add("response_header_names")
    response = _exact(value, fields)
    _reference(response["source_id"])
    status = response["status"]
    if type(status) is not int or not 200 <= status <= 599:
        raise CorsAnalysisError("Native final response status 200 through 599 is required")
    _boolean(response["headers_complete"])
    headers = response["cors_fields"]
    if type(headers) is not list or len(headers) > MAX_FIELDS_PER_RESPONSE:
        raise CorsAnalysisError("Bounded ordered policy fields are required")
    if cost.fields + len(headers) > MAX_FIELD_INSTANCES:
        raise CorsAnalysisError("Aggregate field-instance limit exceeded")
    cost.fields += len(headers)
    supplied_names = set()
    for field in headers:
        _exact(field, {"name", "value"})
        name = _name(field["name"]).lower()
        if name not in _POLICY_FIELDS:
            raise CorsAnalysisError("Only selected CORS policy-field values are supported")
        text = _text(field["value"], empty=True)
        if any(ord(char) > 126 or ord(char) < 32 and char != "\t" for char in text):
            raise CorsAnalysisError("Parsed ASCII policy metadata is required")
        supplied_names.add(name)
    if actual:
        inventory = set(_names(response["response_header_names"], MAX_RESPONSE_NAMES_PER_CASE))
        if not supplied_names <= inventory:
            raise CorsAnalysisError("Policy fields contradict the supplied header-name inventory")
        if response["headers_complete"] and inventory & _POLICY_FIELDS != supplied_names:
            raise CorsAnalysisError("Complete inventory lacks selected policy-field values")
    return response


def _indexed(response: dict[str, Any], cost: _Cost) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    cost.charge(len(response["cors_fields"]))
    for field in response["cors_fields"]:
        result.setdefault(field["name"].lower(), []).append(field["value"])
    return result


def _cors_check(request: dict[str, Any], headers: dict[str, list[str]]) -> tuple[str, list[str]]:
    origins = headers.get("access-control-allow-origin", [])
    if not origins:
        return _FAIL, ["allow_origin_absent"]
    if len(origins) != 1:
        return _FAIL, ["allow_origin_singleton_duplicated"]
    included = request["credentials_mode"] == "include"
    if not included and origins[0] == "*":
        return _PASS, []
    if origins[0] != request["serialized_origin"]:
        return _FAIL, ["allow_origin_mismatch"]
    if included:
        credentials = headers.get("access-control-allow-credentials", [])
        if len(credentials) != 1 or credentials[0] != "true":
            return _FAIL, ["allow_credentials_not_exact_true"]
    return _PASS, []


def _list_tokens(values: list[str] | None, cost: _Cost) -> list[str] | None:
    if values is None:
        return None
    result = []
    for value in values:
        cost.charge(len(value) + 1)
        start = 0
        while True:
            comma = value.find(",", start)
            end = len(value) if comma < 0 else comma
            cost.charge(1)
            left, right = start, end
            while left < right and value[left] in " \t":
                left += 1
            while right > left and value[right - 1] in " \t":
                right -= 1
            if left < right:
                if right - left > MAX_NAME_BYTES:
                    raise CorsAnalysisError("Parsed token name byte limit exceeded")
                token = value[left:right]
                if _TOKEN.fullmatch(token) is None:
                    raise _InvalidList
                cost.token()
                result.append(token)
            if comma < 0:
                break
            start = comma + 1
    return result


class _InvalidList(Exception):
    """A supplied policy list does not match the finite HTTP token grammar."""


def _preflight(
    request: dict[str, Any], response: dict[str, Any] | None, cost: _Cost
) -> dict[str, Any]:
    if not request["projection_complete"]:
        return {"outcome": _UNKNOWN, "issues": ["request_projection_incomplete"]}
    if not request["preflight_required"]:
        return {"outcome": "not_required_by_supplied_premise", "issues": []}
    if response is None or not response["headers_complete"]:
        return {"outcome": _UNKNOWN, "issues": ["preflight_metadata_unavailable"]}
    headers = _indexed(response, cost)
    check, issues = _cors_check(request, headers)
    if check != _PASS:
        return {"outcome": check, "issues": issues}
    if not 200 <= response["status"] <= 299:
        return {"outcome": _FAIL, "issues": ["preflight_status_not_ok"]}
    try:
        methods = _list_tokens(headers.get("access-control-allow-methods"), cost)
        names = _list_tokens(headers.get("access-control-allow-headers"), cost)
    except _InvalidList:
        return {"outcome": _FAIL, "issues": ["preflight_allow_list_invalid"]}
    if methods is None and request["use_cors_preflight"]:
        methods = [request["method"]]
    method_set = set(methods or [])
    names_set = {name.lower() for name in names or []}
    included = request["credentials_mode"] == "include"
    cost.charge(len(method_set) + len(names_set) + len(request["unsafe_header_names"]) + 1)
    if (
        request["method"] not in method_set
        and request["method"] not in _SAFE_METHODS
        and (included or "*" not in method_set)
    ):
        return {"outcome": _FAIL, "issues": ["request_method_not_allowed"]}
    for name in request["unsafe_header_names"]:
        normalized = name.lower()
        if normalized == "authorization" and normalized not in names_set:
            return {"outcome": _FAIL, "issues": ["authorization_not_explicitly_allowed"]}
        if normalized not in names_set and (included or "*" not in names_set):
            return {"outcome": _FAIL, "issues": ["unsafe_request_header_not_allowed"]}
    return {"outcome": _PASS, "issues": []}


def _actual(
    request: dict[str, Any], response: dict[str, Any] | None, cost: _Cost
) -> tuple[dict[str, Any], list[str]]:
    if not request["projection_complete"]:
        return {"outcome": _UNKNOWN, "issues": ["request_projection_incomplete"]}, []
    if response is None or not response["headers_complete"]:
        return {"outcome": _UNKNOWN, "issues": ["actual_metadata_unavailable"]}, []
    headers = _indexed(response, cost)
    check, issues = _cors_check(request, headers)
    if check != _PASS:
        return {"outcome": check, "issues": issues}, []
    invalid_expose = False
    try:
        exposed = _list_tokens(headers.get("access-control-expose-headers"), cost) or []
    except _InvalidList:
        exposed = []
        invalid_expose = True
    inventory = set(name.lower() for name in response["response_header_names"])
    explicit = {name.lower() for name in exposed}
    cost.charge(len(inventory) + len(explicit) + 1)
    if "*" in explicit and request["credentials_mode"] != "include":
        selected = inventory - _FORBIDDEN_RESPONSE_NAMES
    else:
        selected = inventory & (_SAFE_RESPONSE_NAMES | explicit) - _FORBIDDEN_RESPONSE_NAMES
    if cost.exposed + len(selected) > MAX_EXPOSED_NAMES:
        raise CorsAnalysisError("Aggregate exposed-name limit exceeded")
    cost.exposed += len(selected)
    cost.charge(len(selected) * MAX_NAME_BYTES)
    names = sorted(selected)
    return {
        "outcome": _PASS,
        "issues": ["optional_expose_list_invalid_safelist_only"] if invalid_expose else [],
    }, names


def _hash(text: str, cost: _Cost) -> str:
    cost.charge(len(text))
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _derive(model: Any) -> dict[str, Any]:
    cost = _Cost()
    model_json = _native(model, cost)
    owned = json.loads(model_json)
    _exact(owned, {"schema_version", "cases"})
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise CorsAnalysisError("Native model schema version 1 is required")
    cases = owned["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= MAX_CASES:
        raise CorsAnalysisError("A bounded nonempty case array is required")
    seen = set()
    validated = []
    for case in cases:
        _exact(case, {"case_id", "request", "preflight_response", "actual_response"})
        case_id = _reference(case["case_id"])
        if case_id in seen:
            raise CorsAnalysisError("Duplicate case identifier")
        seen.add(case_id)
        request = _request(case["request"])
        preflight = _response(case["preflight_response"], cost, actual=False)
        actual = _response(case["actual_response"], cost, actual=True)
        validated.append((case_id, request, preflight, actual))
    rows = []
    for case_id, request, preflight, actual in validated:
        before = _preflight(request, preflight, cost)
        response_check, exposed = _actual(request, actual, cost)
        outcomes = (before["outcome"], response_check["outcome"])
        if _UNKNOWN in outcomes:
            overall = _UNKNOWN
        elif _FAIL in outcomes:
            overall = "fails_supplied_checks"
        else:
            overall = "passes_supplied_checks"
        cost.charge(1)
        rows.append(
            {
                "case_id": case_id,
                "request_source_id": request["source_id"],
                "preflight_source_id": preflight["source_id"] if preflight else None,
                "actual_source_id": actual["source_id"] if actual else None,
                "preflight_check": before,
                "actual_response_check": response_check,
                "exposed_header_names": exposed,
                "comprehensive_share_result": overall,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "analysis_profile": ANALYSIS_PROFILE,
        "standard_commit": STANDARD_COMMIT,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "model": owned,
        "source": {"model_sha256": "sha256:" + "0" * 64},
        "limits": dict(_LIMITS),
        "case_count": len(rows),
        "cases": rows,
        "limitations": list(_LIMITATIONS),
        "offline_only": True,
        "supplied_metadata_only": True,
        "positive_use_approved": False,
        "browser_fetch_eligibility_verified": False,
        "server_authorization_verified": False,
        "source_authentication_verified": False,
        "vulnerability_claimed": False,
        "qualification_claimed": False,
        "effects": dict(_EFFECTS),
    }
    result = {
        **body,
        "report_id": "CRA-" + "0" * 32,
        "report_sha256": "sha256:" + "0" * 64,
    }
    # Fixed-width addresses reserve the complete report before the first digest.
    _native(result, cost)
    body["source"]["model_sha256"] = "sha256:" + _hash(model_json, cost)
    digest = _hash(_native({"domain": DOMAIN, "analysis": body}, cost), cost)
    result["report_id"] = "CRA-" + digest[:32].upper()
    result["report_sha256"] = "sha256:" + digest
    return result


def _replay(document: Any) -> dict[str, Any]:
    original_json = _native(document)
    if type(document) is not dict or "model" not in document:
        raise CorsAnalysisError("An exact source-bearing CORS report is required")
    expected = _derive(document["model"])
    if original_json != _native(expected):
        raise CorsAnalysisError("Report differs from exact original-model reconstruction")
    return expected


@dataclass(frozen=True, slots=True)
class CorsAnalysis:
    """Detached unsigned report, not a grant or authenticated source assertion."""

    document_json: str

    def __post_init__(self) -> None:
        expected = _replay(_decode(self.document_json))
        object.__setattr__(self, "document_json", _native(expected))

    def to_dict(self) -> dict[str, Any]:
        return _capture_report(self)

    def to_json(self) -> str:
        return _native(_capture_report(self))

    @classmethod
    def from_dict(cls, document: Any) -> CorsAnalysis:
        return cls(_native(document))

    @classmethod
    def from_json(cls, document_json: Any) -> CorsAnalysis:
        return cls(document_json)


def _capture_report(report: Any) -> dict[str, Any]:
    if type(report) is not CorsAnalysis:
        raise CorsAnalysisError("The exact native report family is required")
    try:
        text = report.document_json
    except AttributeError as exc:
        raise CorsAnalysisError("Incomplete native report") from exc
    return _replay(_decode(text))


def analyze_supplied_cors(model: Any) -> CorsAnalysis:
    """Evaluate only the supplied finite CORS premises and parsed metadata."""
    return CorsAnalysis(_native(_derive(model)))


def analyze_supplied_cors_bytes(*, model_json: bytes) -> CorsAnalysis:
    """Read bounded UTF-8 JSON bytes, without any acquisition or callback."""
    return analyze_supplied_cors(_bytes_json(model_json))


def verify_supplied_cors_analysis(report: CorsAnalysis, *, model: Any) -> CorsAnalysis:
    """Recompute against the separately supplied original model, without authority."""
    supplied = _capture_report(report)
    expected = _derive(model)
    if _native(supplied) != _native(expected):
        raise CorsAnalysisError("Report is not bound to the separately supplied model")
    return CorsAnalysis(_native(expected))


def component_fixture() -> dict[str, Any]:
    """Return a fresh wholly synthetic model, not an observed HTTP exchange."""
    return {
        "schema_version": 1,
        "cases": [
            {
                "case_id": "synthetic-cors",
                "request": {
                    "source_id": "synthetic-request",
                    "serialized_origin": "https://client.invalid",
                    "credentials_mode": "omit",
                    "method": "PUT",
                    "unsafe_header_names": ["X-Synthetic"],
                    "preflight_required": True,
                    "use_cors_preflight": False,
                    "projection_complete": True,
                },
                "preflight_response": {
                    "source_id": "synthetic-preflight",
                    "status": 204,
                    "cors_fields": [
                        {"name": "Access-Control-Allow-Origin", "value": "*"},
                        {"name": "Access-Control-Allow-Methods", "value": "PUT"},
                        {"name": "Access-Control-Allow-Headers", "value": "X-Synthetic"},
                    ],
                    "headers_complete": True,
                },
                "actual_response": {
                    "source_id": "synthetic-actual",
                    "status": 403,
                    "cors_fields": [
                        {"name": "Access-Control-Allow-Origin", "value": "*"},
                        {"name": "Access-Control-Expose-Headers", "value": "X-Synthetic-Result"},
                    ],
                    "response_header_names": [
                        "Access-Control-Allow-Origin",
                        "Access-Control-Expose-Headers",
                        "Content-Type",
                        "X-Synthetic-Result",
                        "Set-Cookie",
                    ],
                    "headers_complete": True,
                },
            }
        ],
    }


__all__ = [
    "CorsAnalysis",
    "CorsAnalysisError",
    "analyze_supplied_cors",
    "analyze_supplied_cors_bytes",
    "component_fixture",
    "verify_supplied_cors_analysis",
]

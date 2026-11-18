"""Bounded offline differentials over synthetic declared cache-key inputs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "http_supplied_cache_key_differential"
PROFILE_ID = "AOE-GB-D05-S04"
CAPABILITY_ID = "army.gb.d05.s04"
VECTOR_ID = "AV-GB-D05-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:cdb8afff324d5ddfa9b1f50430202be5b311115836320a0e0747f0e34a0c4ec1"
DOMAIN = "sunderkey.offline-cache-key-differential.v1"
MODEL_DOMAIN = "sunderkey.offline-cache-key-differential-model.v1"
SEMANTICS_PROFILE = "declared-cache-key-and-vary-exact-octets.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 256
MAX_PAIRS = 64
MAX_HEADERS = 32
MAX_VARY_FIELDS = 16
MAX_WORK = 4_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEADER = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_REQUEST_FIELDS = {"method", "scheme", "host", "path", "query", "headers"}
_RESPONSE_FIELDS = {"signature", "vary", "no_store"}
_SIDE_FIELDS = {"request", "response"}
_PAIR_FIELDS = {"pair_id", "left", "right"}
_RULE_FIELDS = {
    "include_method",
    "include_scheme",
    "include_host",
    "include_path",
    "include_query",
    "header_names",
}
_PLACEHOLDER = "sha256:" + "0" * 64
_SENSITIVE = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "cache_configuration_verified",
        "actual_request_observed",
        "actual_response_observed",
        "storage_verified",
        "reuse_verified",
        "poisoning_verified",
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
    "pairs": MAX_PAIRS,
    "request_headers": MAX_HEADERS,
    "vary_fields": MAX_VARY_FIELDS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "All requests, responses, signatures, key rules, Vary lists and no-store values are "
    "caller-supplied synthetic premises.",
    "Key fields and Vary request-header values are compared as exact ASCII strings, "
    "without HTTP parsing or normalization.",
    "Null Vary or no-store means undeclared, not absence; wildcard Vary cannot "
    "establish a reusable match.",
    "A declared no-store value is a reason to withhold a candidate signal, not "
    "proof of actual cache compliance.",
    "Other cache directives, status, method eligibility, authorization, freshness, "
    "storage and reuse are unassessed.",
    "A candidate signal is not evidence of live cache poisoning, deception, "
    "exploitability or impact.",
    "No network, process, credentials, provider, target, authority or "
    "qualification is established.",
)


class CacheKeyDifferentialAnalysisError(ValueError):
    """A supplied model or report is outside the exact bounded contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise CacheKeyDifferentialAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise CacheKeyDifferentialAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CacheKeyDifferentialAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise CacheKeyDifferentialAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise CacheKeyDifferentialAnalysisError(
                        "Printable native ASCII strings required"
                    )
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not -(2**63) <= item < 2**63:
                raise CacheKeyDifferentialAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise CacheKeyDifferentialAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise CacheKeyDifferentialAnalysisError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise CacheKeyDifferentialAnalysisError(
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
            raise CacheKeyDifferentialAnalysisError(
                "Only exact native JSON primitives are supported"
            )

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
        raise CacheKeyDifferentialAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise CacheKeyDifferentialAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Limit raw tokens, escapes, graph size and duplicate members before decoding."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise CacheKeyDifferentialAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise CacheKeyDifferentialAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise CacheKeyDifferentialAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise CacheKeyDifferentialAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            d not in "0123456789abcdefABCDEF" for d in digits
                        ):
                            raise CacheKeyDifferentialAnalysisError("Malformed raw Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise CacheKeyDifferentialAnalysisError(
                                "Printable ASCII escapes required"
                            )
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise CacheKeyDifferentialAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise CacheKeyDifferentialAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise CacheKeyDifferentialAnalysisError("Raw string bound exhausted")
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
                raise CacheKeyDifferentialAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise CacheKeyDifferentialAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CacheKeyDifferentialAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise CacheKeyDifferentialAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise CacheKeyDifferentialAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise CacheKeyDifferentialAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CacheKeyDifferentialAnalysisError):
            raise
        raise CacheKeyDifferentialAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _header_names(value: Any, limit: int) -> None:
    if type(value) is not list or len(value) > limit:
        raise CacheKeyDifferentialAnalysisError("Bounded declared header-name list required")
    if any(
        type(name) is not str or _HEADER.fullmatch(name) is None or name in _SENSITIVE
        for name in value
    ):
        raise CacheKeyDifferentialAnalysisError("Lowercase nonsensitive header names required")
    if len(set(value)) != len(value) or value != sorted(value):
        raise CacheKeyDifferentialAnalysisError("Sorted unique header names required")


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {"schema_version", "key_rule", "pairs"}:
        raise CacheKeyDifferentialAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise CacheKeyDifferentialAnalysisError("Exact native schema version 1 required")
    rule = owned["key_rule"]
    if type(rule) is not dict or rule.keys() != _RULE_FIELDS:
        raise CacheKeyDifferentialAnalysisError("Exact closed key rule required")
    for name in _RULE_FIELDS - {"header_names"}:
        if type(rule[name]) is not bool:
            raise CacheKeyDifferentialAnalysisError("Exact declared key-field booleans required")
    _header_names(rule["header_names"], MAX_HEADERS)
    cases = owned["pairs"]
    if type(cases) is not list or not 1 <= len(cases) <= MAX_PAIRS:
        raise CacheKeyDifferentialAnalysisError("Bounded nonempty pairs required")
    identities: set[str] = set()
    for pair in cases:
        work.charge(20)
        if type(pair) is not dict or pair.keys() != _PAIR_FIELDS:
            raise CacheKeyDifferentialAnalysisError("Exact closed pair fields required")
        identifier = pair["pair_id"]
        if (
            type(identifier) is not str
            or _ID.fullmatch(identifier) is None
            or identifier in identities
        ):
            raise CacheKeyDifferentialAnalysisError("Unique bounded pair identity required")
        identities.add(identifier)
        for label in ("left", "right"):
            side = pair[label]
            if type(side) is not dict or side.keys() != _SIDE_FIELDS:
                raise CacheKeyDifferentialAnalysisError("Exact closed side fields required")
            request, response = side["request"], side["response"]
            if type(request) is not dict or request.keys() != _REQUEST_FIELDS:
                raise CacheKeyDifferentialAnalysisError("Exact closed request fields required")
            for field in _REQUEST_FIELDS - {"headers"}:
                if type(request[field]) is not str or (field != "query" and not request[field]):
                    raise CacheKeyDifferentialAnalysisError("Exact request strings required")
            headers = request["headers"]
            if type(headers) is not dict or len(headers) > MAX_HEADERS:
                raise CacheKeyDifferentialAnalysisError("Bounded request header map required")
            for name, header_value in headers.items():
                if (
                    _HEADER.fullmatch(name) is None
                    or name in _SENSITIVE
                    or type(header_value) is not str
                ):
                    raise CacheKeyDifferentialAnalysisError(
                        "Lowercase nonsensitive single-value headers required"
                    )
            if type(response) is not dict or response.keys() != _RESPONSE_FIELDS:
                raise CacheKeyDifferentialAnalysisError("Exact closed response fields required")
            if (
                type(response["signature"]) is not str
                or _SHA.fullmatch(response["signature"]) is None
            ):
                raise CacheKeyDifferentialAnalysisError("Response SHA-256 signature required")
            vary = response["vary"]
            if vary is not None and vary != "*":
                _header_names(vary, MAX_VARY_FIELDS)
            if response["no_store"] is not None and type(response["no_store"]) is not bool:
                raise CacheKeyDifferentialAnalysisError(
                    "Declared no-store boolean or null required"
                )
    return owned, text


def _base_projection(request: dict, rule: dict) -> list:
    projection = [
        [name, request[name]]
        for name in ("method", "scheme", "host", "path", "query")
        if rule["include_" + name]
    ]
    projection.extend(
        ["header:" + name, request["headers"].get(name)] for name in rule["header_names"]
    )
    return projection


def _observe(pair: dict, rule: dict, work: _Work) -> dict:
    work.charge(64 + len(rule["header_names"]) * 2)
    left, right = pair["left"], pair["right"]
    base_equal = _base_projection(left["request"], rule) == _base_projection(right["request"], rule)
    signatures_distinct = left["response"]["signature"] != right["response"]["signature"]
    left_vary, right_vary = left["response"]["vary"], right["response"]["vary"]
    reasons: list[str] = []
    vary_equal: bool | None = None
    collision: bool | None = False if not base_equal else None
    if base_equal:
        if left_vary is None or right_vary is None:
            reasons.append("vary_undeclared")
        elif left_vary == "*" or right_vary == "*":
            reasons.append("vary_wildcard")
        elif left_vary != right_vary:
            reasons.append("vary_declarations_differ")
        else:
            work.charge(2 * len(left_vary))
            vary_equal = all(
                left["request"]["headers"].get(name) == right["request"]["headers"].get(name)
                for name in left_vary
            )
            collision = vary_equal
    for response in (left["response"], right["response"]):
        if response["no_store"] is True and "declared_no_store" not in reasons:
            reasons.append("declared_no_store")
        elif response["no_store"] is None and "no_store_undeclared" not in reasons:
            reasons.append("no_store_undeclared")
    candidate = collision is True and not reasons and signatures_distinct
    if not base_equal or collision is False:
        outcome = "distinct_declared_keys"
    elif reasons:
        outcome = "unassessed"
    elif signatures_distinct:
        outcome = "candidate_key_collision_with_distinct_signatures"
    else:
        outcome = "declared_key_collision_same_signature"
    return {
        "pair_id": pair["pair_id"],
        "base_key_equal": base_equal,
        "vary_values_equal": vary_equal,
        "declared_key_collision": collision,
        "response_signatures_distinct": signatures_distinct,
        "candidate_deception_signal": candidate,
        "outcome": outcome,
        "uncertainty": reasons,
    }


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
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "pair_count": len(owned["pairs"]),
        "candidate_signal_count": 0,
        "pair_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "CKD-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(body, work)
    for pair in owned["pairs"]:
        row = _observe(pair, owned["key_rule"], work)
        row_size, row_nodes = _measure(row, work)
        if size + row_size + 1 > MAX_DOCUMENT_BYTES or nodes + row_nodes > MAX_NATIVE_NODES:
            raise CacheKeyDifferentialAnalysisError("Cumulative report bound before retention")
        size += row_size + 1
        nodes += row_nodes
        rows.append(row)
        body["candidate_signal_count"] += int(row["candidate_deception_signal"])
    report_size, report_nodes = _measure(body, work)
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + len(DOMAIN) + len(source_text) + hash_size + 2)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "CKD-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise CacheKeyDifferentialAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise CacheKeyDifferentialAnalysisError(
            "Report does not exactly replay its embedded source"
        )
    return expected


@dataclass(frozen=True, slots=True, init=False)
class CacheKeyDifferentialAnalysis:
    """Detached declared-model observation, never live cache evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> CacheKeyDifferentialAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> CacheKeyDifferentialAnalysis:
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


def analyze_supplied_cache_key_differential(model: Any) -> CacheKeyDifferentialAnalysis:
    """Compare only synthetic request pairs under one explicitly supplied key rule."""
    return CacheKeyDifferentialAnalysis(_derive(model))


def analyze_supplied_cache_key_differential_bytes(
    *, model_bytes: Any
) -> CacheKeyDifferentialAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise CacheKeyDifferentialAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CacheKeyDifferentialAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_cache_key_differential(_decode(text))


def verify_supplied_cache_key_differential_analysis(
    report: Any, *, model: Any
) -> CacheKeyDifferentialAnalysis:
    """Check a report against separately supplied original synthetic premises."""
    if type(report) is not CacheKeyDifferentialAnalysis:
        raise CacheKeyDifferentialAnalysisError("Exact native cache analysis family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise CacheKeyDifferentialAnalysisError("Report differs from separately supplied originals")
    return CacheKeyDifferentialAnalysis(expected)


def component_fixture() -> dict:
    """Return a fresh synthetic collision and a Vary-separated negative pair."""

    def side(agent: str, signature: str, vary: list[str]) -> dict:
        return {
            "request": {
                "method": "GET",
                "scheme": "https",
                "host": "example.invalid",
                "path": "/item",
                "query": "id=1",
                "headers": {"accept-language": agent},
            },
            "response": {"signature": "sha256:" + signature * 64, "vary": vary, "no_store": False},
        }

    return {
        "schema_version": 1,
        "key_rule": {
            "include_method": True,
            "include_scheme": True,
            "include_host": True,
            "include_path": True,
            "include_query": False,
            "header_names": [],
        },
        "pairs": [
            {
                "pair_id": "synthetic-candidate",
                "left": side("en", "a", []),
                "right": side("fr", "b", []),
            },
            {
                "pair_id": "synthetic-vary-negative",
                "left": side("en", "a", ["accept-language"]),
                "right": side("fr", "b", ["accept-language"]),
            },
        ],
    }


__all__ = [
    "CacheKeyDifferentialAnalysisError",
    "CacheKeyDifferentialAnalysis",
    "analyze_supplied_cache_key_differential",
    "analyze_supplied_cache_key_differential_bytes",
    "verify_supplied_cache_key_differential_analysis",
    "component_fixture",
]

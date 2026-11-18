"""Finite retained-cookie candidate predicates over explicitly supplied metadata."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "retained_cookie_candidate_predicates"
PROFILE_ID = "AOE-GB-D05-S11"
CAPABILITY_ID = "web.browser-auth-session"
VECTOR_ID = "AV-GB-D05-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:b83a03607604ae4f7f4edf728b5a6baed306bddbf63bd5a372c7c2b15e0c79f8"
SEMANTICS_PROFILE = "rfc6265-supplied-retained-candidate-predicates.v1"
DOMAIN = "sunderkey.offline-cookie-selection.v1"
MODEL_DOMAIN = "sunderkey.offline-cookie-selection-model.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 1_024
MAX_COOKIES = 128
MAX_REQUESTS = 64
MAX_HOST_BYTES = 253
MAX_PATH_BYTES = 1_024
MAX_NAME_BYTES = 128
MAX_PAIRS = 8_192
MAX_WORK = 4_000_000
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_IPV4_SPELLING = re.compile(r"[0-9]+(?:\.[0-9]+){3}\Z")
_PATH = re.compile(r"(?:[A-Za-z0-9\-._~!$&'()*+,;=:@/]|%[0-9A-Fa-f]{2})+\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "native_depth_including_scalars": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "cookies": MAX_COOKIES,
    "requests": MAX_REQUESTS,
    "host_bytes": MAX_HOST_BYTES,
    "path_bytes": MAX_PATH_BYTES,
    "cookie_name_bytes": MAX_NAME_BYTES,
    "pairs": MAX_PAIRS,
    "work_steps": MAX_WORK,
}
_FLAGS = {
    "source_authenticated": False,
    "cookie_retention_or_acceptance_proven": False,
    "browser_transmission_proven": False,
    "secure_transport_verified": False,
    "http_api_classification_verified": False,
    "idna_conversion_verified": False,
    "server_authorization_verified": False,
    "vulnerability_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "browser",
        "cookie_storage",
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
_LIMITATIONS = (
    "Retention, canonical source spelling, transport security and HTTP-API status are premises.",
    "Matches describe supplied predicates, not cookie acceptance or actual browser transmission.",
    "Cookie values, Cookie headers and Set-Cookie parsing or acceptance are excluded.",
    "Expiry, eviction, storage, creation or access times and transmission ordering are excluded.",
    "SameSite, public suffixes, IDNA conversion, partitioning and cookie prefixes are excluded.",
    "Punycode-looking LDH labels are supplied ASCII, not independently validated IDNA labels.",
    "Duplicate name/domain/path denial is a closed retained-model constraint, not storage proof.",
    "Paths are supplied literal URI-path spellings, without decoding or normalization.",
    "No browser-specific behavior, live access, vulnerability or qualification is established.",
)


class CookieSelectionError(ValueError):
    """The supplied subset is malformed, over-budget or fails exact reconstruction."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise CookieSelectionError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    """Charge repeated native subtrees and escaped bytes before copying or serialization."""
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise CookieSelectionError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CookieSelectionError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise CookieSelectionError("Native string byte bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise CookieSelectionError("Native strings must be printable ASCII")
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise CookieSelectionError("Native integer is outside signed 64-bit")
            charge(len(str(item)))
        elif kind is dict or kind is list:
            if id(item) in active:
                raise CookieSelectionError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise CookieSelectionError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise CookieSelectionError("Exact native string keys are required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise CookieSelectionError("Only exact native JSON values are supported")

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
        raise CookieSelectionError("Raw integer lexical bound or grammar failed")
    value = int(text)
    if not MIN_INTEGER <= value <= MAX_INTEGER:
        raise CookieSelectionError("Raw integer is outside signed 64-bit")
    return value


def _decode(text: Any) -> Any:
    """Bound raw ASCII nodes, scalar depth, escapes and integers before json.loads."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise CookieSelectionError("Bounded native ASCII JSON is required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise CookieSelectionError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise CookieSelectionError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise CookieSelectionError("Unterminated raw JSON escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            digit not in "0123456789abcdefABCDEF" for digit in digits
                        ):
                            raise CookieSelectionError("Malformed raw JSON Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise CookieSelectionError("Raw string is outside printable ASCII")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise CookieSelectionError("Raw string escape is outside the subset")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise CookieSelectionError("Raw string is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise CookieSelectionError("Raw string byte bound exhausted")
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
                raise CookieSelectionError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise CookieSelectionError("Raw scalar lexical bound exhausted")
            token = text[start:index]
            nodes += 1
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise CookieSelectionError("Raw node/depth bound exhausted")
    if depth:
        raise CookieSelectionError("Unterminated raw JSON structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise CookieSelectionError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise CookieSelectionError("Fractional and nonfinite JSON numbers are unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CookieSelectionError):
            raise
        raise CookieSelectionError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _fields(value: Any, expected: set[str]) -> dict:
    if type(value) is not dict or value.keys() != expected:
        raise CookieSelectionError("Missing or unsupported native document fields")
    return value


def _collection(value: Any, maximum: int, *, nonempty: bool = False) -> list:
    if type(value) is not list or len(value) > maximum or nonempty and not value:
        raise CookieSelectionError("Native collection is outside the supported bound")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise CookieSelectionError("A bounded native source identity is required")
    return value


def _host_kind(value: Any, work: _Work) -> str:
    if type(value) is not str or not value or len(value) > MAX_HOST_BYTES:
        raise CookieSelectionError("Bounded canonical ASCII host metadata is required")
    work.charge(len(value) + 1)
    if ":" in value or _IPV4_SPELLING.fullmatch(value) is not None:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise CookieSelectionError("Canonical IP spelling is required") from exc
        if str(address) != value or "%" in value:
            raise CookieSelectionError("Canonical unbracketed unscoped IP spelling is required")
        return "ipv4" if address.version == 4 else "ipv6"
    if any(_LABEL.fullmatch(label) is None for label in value.split(".")):
        raise CookieSelectionError("Lowercase ASCII LDH host labels are required")
    return "hostname"


def _path(value: Any, work: _Work) -> None:
    if type(value) is not str or not value or len(value) > MAX_PATH_BYTES:
        raise CookieSelectionError("A bounded literal absolute path is required")
    work.charge(len(value) + 1)
    if not value.startswith("/") or _PATH.fullmatch(value) is None:
        raise CookieSelectionError("Path is outside the supplied ASCII URI-path subset")


def _validate_model(value: Any, work: _Work) -> tuple[dict, str, dict[str, str]]:
    owned, text = _capture(value, work)
    _fields(owned, {"schema_version", "cookies", "requests"})
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise CookieSelectionError("Exact native schema version 1 is required")
    cookies = _collection(owned["cookies"], MAX_COOKIES)
    requests = _collection(owned["requests"], MAX_REQUESTS, nonempty=True)
    if len(cookies) * len(requests) > MAX_PAIRS:
        raise CookieSelectionError("Declared pair bound exhausted")
    kinds: dict[str, str] = {}
    cookie_ids: set[str] = set()
    retained_identities: set[tuple[str, str, str]] = set()
    for cookie in cookies:
        _fields(cookie, {"cookie_id", "name", "domain", "path", "host_only", "secure", "http_only"})
        identifier = _identity(cookie["cookie_id"])
        if identifier in cookie_ids:
            raise CookieSelectionError("Duplicate retained cookie identity")
        cookie_ids.add(identifier)
        name = cookie["name"]
        if type(name) is not str or not 1 <= len(name) <= MAX_NAME_BYTES:
            raise CookieSelectionError("Cookie name byte bound failed")
        work.charge(len(name) + 1)
        if _NAME.fullmatch(name) is None:
            raise CookieSelectionError("Cookie name is outside the ASCII token subset")
        domain = cookie["domain"]
        if type(domain) is not str:
            raise CookieSelectionError("Exact native domain text is required")
        if domain not in kinds:
            kinds[domain] = _host_kind(domain, work)
        _path(cookie["path"], work)
        for flag in ("host_only", "secure", "http_only"):
            if type(cookie[flag]) is not bool:
                raise CookieSelectionError("Exact native cookie flags are required")
        retained = (name, domain, cookie["path"])
        if retained in retained_identities:
            raise CookieSelectionError("Duplicate name/domain/path in declared retained model")
        retained_identities.add(retained)
    request_ids: set[str] = set()
    for request in requests:
        _fields(request, {"request_id", "host", "path", "secure_transport", "http_api"})
        identifier = _identity(request["request_id"])
        if identifier in request_ids:
            raise CookieSelectionError("Duplicate declared request identity")
        request_ids.add(identifier)
        host = request["host"]
        if type(host) is not str:
            raise CookieSelectionError("Exact native host text is required")
        if host not in kinds:
            kinds[host] = _host_kind(host, work)
        _path(request["path"], work)
        for flag in ("secure_transport", "http_api"):
            if type(request[flag]) is not bool:
                raise CookieSelectionError("Exact native request flags are required")
    return owned, text, kinds


class _OutputBudget:
    def __init__(self, base: dict, work: _Work) -> None:
        self.size, self.nodes = _measure(base, work)
        self.rows = 0
        self.work = work

    def retain(self, row: dict, rows: list[dict]) -> None:
        size, nodes = _measure(row, self.work)
        size += 1 if self.rows else 0
        if self.size + size > MAX_DOCUMENT_BYTES or self.nodes + nodes > MAX_NATIVE_NODES:
            raise CookieSelectionError(
                "Cumulative report byte/node bound exhausted before retention"
            )
        if self.rows >= MAX_PAIRS:
            raise CookieSelectionError("Cumulative pair bound exhausted before retention")
        self.size += size
        self.nodes += nodes
        self.rows += 1
        rows.append(row)


def _pair(cookie: dict, request: dict, kind: str, work: _Work) -> dict:
    host, domain = request["host"], cookie["domain"]
    requested_path, cookie_path = request["path"], cookie["path"]
    work.charge(1 + len(host) + len(domain) + len(requested_path) + len(cookie_path))
    if cookie["host_only"]:
        domain_matches = host == domain
        domain_basis = "host_only_equal" if domain_matches else "host_only_different"
    elif host == domain:
        domain_matches, domain_basis = True, "exact_domain"
    elif kind != "hostname":
        domain_matches, domain_basis = False, "request_ip_suffix_excluded"
    else:
        domain_matches = host.endswith("." + domain)
        domain_basis = "label_boundary_suffix" if domain_matches else "domain_mismatch"
    if requested_path == cookie_path:
        path_matches, path_basis = True, "exact_path"
    elif requested_path.startswith(cookie_path) and cookie_path.endswith("/"):
        path_matches, path_basis = True, "prefix_ending_slash"
    elif (
        requested_path.startswith(cookie_path)
        and len(requested_path) > len(cookie_path)
        and requested_path[len(cookie_path)] == "/"
    ):
        path_matches, path_basis = True, "prefix_next_slash"
    else:
        path_matches, path_basis = False, "path_mismatch"
    secure_matches = not cookie["secure"] or request["secure_transport"]
    http_only_matches = not cookie["http_only"] or request["http_api"]
    matches = domain_matches and path_matches and secure_matches and http_only_matches
    return {
        "cookie_id": cookie["cookie_id"],
        "request_id": request["request_id"],
        "domain_matches": domain_matches,
        "domain_basis": domain_basis,
        "path_matches": path_matches,
        "path_basis": path_basis,
        "secure_matches": secure_matches,
        "http_only_matches": http_only_matches,
        "outcome": "matches_supplied_predicates"
        if matches
        else "does_not_match_supplied_predicates",
    }


def _hash(domain: str, text: str) -> str:
    """Hash only after the caller has reserved both digest input costs."""
    return (
        "sha256:"
        + hashlib.sha256(domain.encode("ascii") + b"\n" + text.encode("ascii")).hexdigest()
    )


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text, kinds = _validate_model(model, work)
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
        "standard": "RFC6265-sections-5.1.3-5.1.4-5.4",
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _PLACEHOLDER,
        "cookie_count": len(owned["cookies"]),
        "request_count": len(owned["requests"]),
        "pair_count": len(owned["cookies"]) * len(owned["requests"]),
        "pair_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "CKS-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    output = _OutputBudget(body, work)
    for request in owned["requests"]:
        for cookie in owned["cookies"]:
            output.retain(_pair(cookie, request, kinds[request["host"]], work), rows)
    # All source and row costs, including final address widths, precede any digest.
    report_size, report_nodes = _measure(body, work)
    # Reserve complete report passes for raw checking, ownership capture,
    # canonical comparison and final export. These allowances also apply to
    # to_json replay, so no later output pass introduces a new work rejection.
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_body_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + 1 + len(source_text) + len(DOMAIN) + 1 + hash_body_size)
    # Source digests replace a fixed-width printable placeholder: serialized
    # size and traversal costs are unchanged. All remaining work is reserved.
    body["source_model_sha256"] = _hash(MODEL_DOMAIN, source_text)
    digest = _hash(DOMAIN, _canonical(body))
    body["analysis_id"] = "CKS-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise CookieSelectionError("A source-bearing native cookie analysis is required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise CookieSelectionError("Analysis does not exactly replay from its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class CookieSelectionAnalysis:
    """Detached unsigned supplied-predicate results, not a cookie header or permission."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> CookieSelectionAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> CookieSelectionAnalysis:
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


def analyze_supplied_cookie_selection(model: Any) -> CookieSelectionAnalysis:
    """Derive only the four supplied retained-cookie candidate predicates, without I/O."""
    return CookieSelectionAnalysis(_derive(model))


def analyze_supplied_cookie_selection_bytes(*, model_bytes: Any) -> CookieSelectionAnalysis:
    """Accept bounded native ASCII JSON bytes, without reading any resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise CookieSelectionError("Model input must be bounded exact native bytes")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CookieSelectionError("Model bytes must contain ASCII JSON") from exc
    return analyze_supplied_cookie_selection(_decode(text))


def verify_supplied_cookie_selection(report: Any, *, model: Any) -> CookieSelectionAnalysis:
    """Reconstruct against separately supplied originals, not authenticated browser state."""
    if type(report) is not CookieSelectionAnalysis:
        raise CookieSelectionError("Exact native cookie analysis family is required")
    original = _derive(model)
    if _serialize(report.to_dict()) != _serialize(original):
        raise CookieSelectionError(
            "Analysis is not bound to the separately supplied original model"
        )
    return CookieSelectionAnalysis(original)


def component_fixture() -> dict:
    """Return a fresh wholly synthetic retained-metadata/request projection."""
    return {
        "schema_version": 1,
        "cookies": [
            {
                "cookie_id": "synthetic-domain",
                "name": "SID",
                "domain": "example.invalid",
                "path": "/app",
                "host_only": False,
                "secure": True,
                "http_only": True,
            },
            {
                "cookie_id": "synthetic-host",
                "name": "PREF",
                "domain": "api.example.invalid",
                "path": "/",
                "host_only": True,
                "secure": False,
                "http_only": False,
            },
        ],
        "requests": [
            {
                "request_id": "synthetic-https-http",
                "host": "api.example.invalid",
                "path": "/app/item",
                "secure_transport": True,
                "http_api": True,
            },
            {
                "request_id": "synthetic-insecure-script",
                "host": "api.example.invalid",
                "path": "/application",
                "secure_transport": False,
                "http_api": False,
            },
        ],
    }


__all__ = [
    "CookieSelectionError",
    "CookieSelectionAnalysis",
    "analyze_supplied_cookie_selection",
    "analyze_supplied_cookie_selection_bytes",
    "verify_supplied_cookie_selection",
    "component_fixture",
]

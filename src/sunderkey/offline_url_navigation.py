"""Bounded supplied HTTPS URL navigation projection without external operations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

COMPONENT_ID = "https_supplied_url_navigation_projection"
PROFILE_ID = "AOE-GB-D05-S05"
CAPABILITY_ID = "army.gb.d05.s05"
VECTOR_ID = "AV-GB-D05-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:346a1080e1b6406901f0c125b44979087cf7dd1c655459f8552cd203277d06de"
DOMAIN = "sunderkey.offline-url-navigation.v1"
MODEL_DOMAIN = "sunderkey.offline-url-navigation-model.v1"
SEMANTICS_PROFILE = "supplied-ascii-https-rfc3986-subset.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 32_768
MAX_NATIVE_DEPTH = 16
MAX_STRING_BYTES = 1_024
MAX_URL_BYTES = 1_024
MAX_HOPS = 32
MAX_WORK = 4_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_URL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/?:#&=+._~-!$'()*,-"
)
_PLACEHOLDER = "sha256:" + "0" * 64
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "browser_parser_verified",
        "server_parser_verified",
        "redirect_observed",
        "navigation_executed",
        "target_reached",
        "open_redirect_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "navigation",
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
    "url_bytes": MAX_URL_BYTES,
    "hops": MAX_HOPS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Base URL and hop locations are caller-supplied synthetic strings, not observed redirects.",
    "Only ASCII HTTPS DNS-name URLs are projected; no browser or server parser is run.",
    "Host case and explicit port 443 are normalized for declared origin comparison.",
    "Unicode, IDNA labels, IP literals, userinfo, backslashes and all percent escapes are refused.",
    "Fragments are excluded from projected fetch URLs but their presence is reported.",
    "A refused hop stops projection; subsequent supplied hops are not evaluated.",
    "Origin transitions are not proof of open redirects, reachability, exploitability or impact.",
    "No network, process, credentials, provider, target, authority or "
    "qualification is established.",
)


class UrlNavigationAnalysisError(ValueError):
    """A model or report is outside the exact bounded software contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise UrlNavigationAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> tuple[int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise UrlNavigationAnalysisError("Document byte bound exhausted")

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise UrlNavigationAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise UrlNavigationAnalysisError("Native string bound exhausted")
            charge(2 + len(item))
            for char in item:
                if not 32 <= ord(char) <= 126:
                    raise UrlNavigationAnalysisError("Printable native ASCII strings required")
                if char in '\\"':
                    charge(1)
        elif kind is bool:
            charge(4 if item else 5)
        elif item is None:
            charge(4)
        elif kind is int:
            if item.bit_length() > 64 or not -(2**63) <= item < 2**63:
                raise UrlNavigationAnalysisError("Native integer exceeds signed 64-bit")
            charge(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise UrlNavigationAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NATIVE_NODES - nodes:
                raise UrlNavigationAnalysisError("Native collection node bound exhausted")
            charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise UrlNavigationAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise UrlNavigationAnalysisError("Only exact native JSON primitives are supported")

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
        raise UrlNavigationAnalysisError("Raw integer grammar or lexical bound failed")
    number = int(text)
    if not -(2**63) <= number < 2**63:
        raise UrlNavigationAnalysisError("Raw integer exceeds signed 64-bit")
    return number


def _decode(text: Any) -> Any:
    """Bound raw JSON tokens and duplicate members before materializing a model."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise UrlNavigationAnalysisError("Bounded native ASCII JSON required")
    index = depth = nodes = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise UrlNavigationAnalysisError("Raw scalar depth bound exhausted")
            nodes += 1
            index += 1
            length = 0
            while True:
                if index >= len(text):
                    raise UrlNavigationAnalysisError("Unterminated raw JSON string")
                char = text[index]
                if char == '"':
                    index += 1
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise UrlNavigationAnalysisError("Unterminated raw escape")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            d not in "0123456789abcdefABCDEF" for d in digits
                        ):
                            raise UrlNavigationAnalysisError("Malformed raw Unicode escape")
                        if not 32 <= int(digits, 16) <= 126:
                            raise UrlNavigationAnalysisError("Printable ASCII escapes required")
                        index += 5
                    elif escape in '\\"/':
                        index += 1
                    else:
                        raise UrlNavigationAnalysisError("Unsupported raw string escape")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise UrlNavigationAnalysisError("Printable ASCII strings required")
                    index += 1
                length += 1
                if length > MAX_STRING_BYTES:
                    raise UrlNavigationAnalysisError("Raw string bound exhausted")
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
                raise UrlNavigationAnalysisError("Raw scalar depth bound exhausted")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
                if index - start > 20:
                    raise UrlNavigationAnalysisError("Raw scalar lexical bound exhausted")
            nodes += 1
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _integer(token)
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise UrlNavigationAnalysisError("Raw node/depth bound exhausted")
    if depth:
        raise UrlNavigationAnalysisError("Unterminated raw structure")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise UrlNavigationAnalysisError("Duplicate JSON object member")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise UrlNavigationAnalysisError("Fractional/nonfinite JSON numbers unsupported")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, UrlNavigationAnalysisError):
            raise
        raise UrlNavigationAnalysisError("Malformed supplied JSON") from exc
    _measure(document)
    return document


def _validate_model(value: Any, work: _Work) -> tuple[dict, str]:
    owned, text = _capture(value, work)
    if type(owned) is not dict or owned.keys() != {"schema_version", "base_url", "hops"}:
        raise UrlNavigationAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise UrlNavigationAnalysisError("Exact native schema version 1 required")
    base = owned["base_url"]
    if type(base) is not str or not base or len(base) > MAX_URL_BYTES:
        raise UrlNavigationAnalysisError("Bounded base URL string required")
    hops = owned["hops"]
    if type(hops) is not list or not 1 <= len(hops) <= MAX_HOPS:
        raise UrlNavigationAnalysisError("Bounded nonempty hop list required")
    identities: set[str] = set()
    for hop in hops:
        work.charge(4)
        if type(hop) is not dict or hop.keys() != {"hop_id", "location"}:
            raise UrlNavigationAnalysisError("Exact closed hop fields required")
        identity, location = hop["hop_id"], hop["location"]
        if type(identity) is not str or _ID.fullmatch(identity) is None or identity in identities:
            raise UrlNavigationAnalysisError("Unique bounded hop identity required")
        if type(location) is not str or not location or len(location) > MAX_URL_BYTES:
            raise UrlNavigationAnalysisError("Bounded nonempty location string required")
        identities.add(identity)
    return owned, text


class _Refusal(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


def _lexical_check(raw: str) -> None:
    if any(ord(char) > 127 for char in raw):
        raise _Refusal("non_ascii_or_idna_ambiguous")
    if any(char not in _URL_CHARS for char in raw):
        if "\\" in raw:
            raise _Refusal("backslash_ambiguous")
        if "%" in raw:
            raise _Refusal("percent_encoding_ambiguous")
        if "@" in raw:
            raise _Refusal("userinfo_or_at_sign_ambiguous")
        raise _Refusal("unsupported_url_character")
    if raw.startswith("///"):
        raise _Refusal("ambiguous_leading_slashes")
    if raw.count("#") > 1:
        raise _Refusal("ambiguous_fragment_delimiter")


def _authority(netloc: str) -> tuple[str, int, str]:
    if not netloc or "@" in netloc:
        raise _Refusal("userinfo_or_empty_authority")
    if any(char in netloc for char in "[]%\\"):
        raise _Refusal("ip_literal_or_encoded_authority")
    if netloc.count(":") > 1:
        raise _Refusal("ambiguous_authority_colons")
    if ":" in netloc:
        host, port_text = netloc.split(":", 1)
        if not port_text or not port_text.isascii() or not port_text.isdecimal():
            raise _Refusal("invalid_port")
        if len(port_text) > 1 and port_text[0] == "0":
            raise _Refusal("noncanonical_port")
        if len(port_text) > 5 or not 1 <= int(port_text) <= 65535:
            raise _Refusal("invalid_port")
        port = int(port_text)
    else:
        host, port = netloc, 443
    if host.endswith(".") or ".." in host or len(host) > 253:
        raise _Refusal("ambiguous_host")
    labels = host.split(".")
    if len(labels) < 2 or any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise _Refusal("unsupported_host")
    if any(label.lower().startswith("xn--") for label in labels):
        raise _Refusal("idna_label_ambiguous")
    if not labels[-1].isalpha() or len(labels[-1]) < 2:
        raise _Refusal("numeric_or_ambiguous_host")
    normalized_host = host.lower()
    normalized_authority = normalized_host if port == 443 else f"{normalized_host}:{port}"
    return normalized_host, port, normalized_authority


def _project(raw: str, prior_url: str | None) -> dict:
    _lexical_check(raw)
    if prior_url is None:
        if not raw.lower().startswith("https://"):
            raise _Refusal("base_not_absolute_https")
        resolved = raw
    else:
        parsed_raw = urlsplit(raw)
        if parsed_raw.scheme and parsed_raw.scheme.lower() != "https":
            raise _Refusal("scheme_not_https")
        if parsed_raw.scheme and not raw.lower().startswith("https://"):
            raise _Refusal("ambiguous_scheme_form")
        if raw.startswith("//") and raw[2:3] == "/":
            raise _Refusal("ambiguous_leading_slashes")
        resolved = urljoin(prior_url, raw)
    if len(resolved) > MAX_URL_BYTES:
        raise _Refusal("resolved_url_bound_exhausted")
    parts = urlsplit(resolved)
    if parts.scheme.lower() != "https":
        raise _Refusal("scheme_not_https")
    if not parts.netloc:
        raise _Refusal("empty_authority")
    _host, _port, authority = _authority(parts.netloc)
    path = parts.path or "/"
    if path.startswith("//"):
        raise _Refusal("ambiguous_path_slashes")
    origin = "https://" + authority
    fetch_url = urlunsplit(("https", authority, path, parts.query, ""))
    return {"url": fetch_url, "origin": origin, "authority": authority}


def _location_kind(raw: str) -> str:
    if raw.startswith("//"):
        return "scheme_relative"
    if raw.lower().startswith("https://") or re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", raw):
        return "absolute_or_scheme"
    if raw.startswith("/"):
        return "root_relative"
    if raw.startswith("?"):
        return "query_relative"
    if raw.startswith("#"):
        return "fragment_relative"
    return "path_relative"


def _observe(hop: dict, prior: dict, work: _Work) -> tuple[dict, dict | None]:
    raw = hop["location"]
    work.charge(32 + len(raw) * 3 + len(prior["url"]))
    row = {
        "hop_id": hop["hop_id"],
        "location_kind": _location_kind(raw),
        "fragment_present": "#" in raw,
        "from_url": prior["url"],
        "from_origin": prior["origin"],
        "from_authority": prior["authority"],
        "to_url": None,
        "to_origin": None,
        "to_authority": None,
        "origin_changed": None,
        "authority_changed": None,
        "status": "refused",
        "refusal_reason": None,
    }
    try:
        target = _project(raw, prior["url"])
    except _Refusal as exc:
        row["refusal_reason"] = exc.reason
        return row, None
    row.update(
        to_url=target["url"],
        to_origin=target["origin"],
        to_authority=target["authority"],
        origin_changed=target["origin"] != prior["origin"],
        authority_changed=target["authority"] != prior["authority"],
        status="projected",
    )
    return row, target


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    try:
        base = _project(owned["base_url"], None)
    except _Refusal as exc:
        raise UrlNavigationAnalysisError("Base URL refused: " + exc.reason) from exc
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
        "base_projection": base,
        "hop_count": len(owned["hops"]),
        "projected_hop_count": 0,
        "refused_hop_count": 0,
        "unprocessed_hop_count": 0,
        "hop_observations": rows,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "HNP-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(body, work)
    prior = base
    for hop in owned["hops"]:
        row, target = _observe(hop, prior, work)
        row_size, row_nodes = _measure(row, work)
        if size + row_size + 1 > MAX_DOCUMENT_BYTES or nodes + row_nodes > MAX_NATIVE_NODES:
            raise UrlNavigationAnalysisError("Cumulative report bound before retention")
        size += row_size + 1
        nodes += row_nodes
        rows.append(row)
        if target is None:
            body["refused_hop_count"] = 1
            break
        body["projected_hop_count"] += 1
        prior = target
    body["unprocessed_hop_count"] = len(owned["hops"]) - len(rows)
    report_size, report_nodes = _measure(body, work)
    work.charge(4 * (report_size + report_nodes))
    del body["analysis_id"]
    del body["analysis_sha256"]
    hash_size, _ = _measure(body, work)
    work.charge(len(MODEL_DOMAIN) + len(DOMAIN) + len(source_text) + hash_size + 2)
    body["source_model_sha256"] = _address(MODEL_DOMAIN, source_text)
    digest = _address(DOMAIN, _canonical(body))
    body["analysis_id"] = "HNP-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise UrlNavigationAnalysisError("Source-bearing native analysis required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise UrlNavigationAnalysisError("Report does not exactly replay its embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class UrlNavigationAnalysis:
    """Detached synthetic projection, never evidence of live navigation."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> UrlNavigationAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> UrlNavigationAnalysis:
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


def analyze_supplied_url_navigation(model: Any) -> UrlNavigationAnalysis:
    """Project a bounded supplied HTTPS base and synthetic location sequence."""
    return UrlNavigationAnalysis(_derive(model))


def analyze_supplied_url_navigation_bytes(*, model_bytes: Any) -> UrlNavigationAnalysis:
    """Accept exact bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise UrlNavigationAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise UrlNavigationAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_url_navigation(_decode(text))


def verify_supplied_url_navigation_analysis(report: Any, *, model: Any) -> UrlNavigationAnalysis:
    """Check a report against separately supplied original synthetic premises."""
    if type(report) is not UrlNavigationAnalysis:
        raise UrlNavigationAnalysisError("Exact native navigation analysis family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise UrlNavigationAnalysisError("Report differs from separately supplied originals")
    return UrlNavigationAnalysis(expected)


def component_fixture() -> dict:
    """Return a fresh synthetic same-origin, cross-origin and fragment sequence."""
    return {
        "schema_version": 1,
        "base_url": "https://App.Example.invalid:443/start/index#old",
        "hops": [
            {"hop_id": "synthetic-relative", "location": "../next?x=1"},
            {
                "hop_id": "synthetic-cross-origin",
                "location": "//cdn.example.invalid:8443/view#part",
            },
            {"hop_id": "synthetic-fragment", "location": "#other"},
        ],
    }


__all__ = [
    "UrlNavigationAnalysisError",
    "UrlNavigationAnalysis",
    "analyze_supplied_url_navigation",
    "analyze_supplied_url_navigation_bytes",
    "verify_supplied_url_navigation_analysis",
    "component_fixture",
]

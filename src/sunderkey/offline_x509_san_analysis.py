"""Bounded, unsigned comparison of supplied X.509 SANs and one reference ID."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID

COMPONENT_ID = "x509_supplied_san_reference_match"
PROFILE_ID = "AOE-GE-D22-S03"
CAPABILITY_ID = "crypto.pki-x509-validation"
VECTOR_ID = "AV-GE-D22-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S03"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GE-D22-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:72a694de93739620178883eb4744577c819660d619bcb1db1a0c4f1eb4e3cfd0"
SEMANTICS_PROFILE = "supplied-x509-san-dns-ip-reference-subset.v1"
DOMAIN = "sunderkey.offline-x509-san-analysis.v1"
MODEL_DOMAIN = "sunderkey.offline-x509-san-model.v1"
MAX_CERTIFICATE_BYTES = 65_536
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 16_384
MAX_DEPTH = 12
MAX_SAN_ENTRIES = 128
MAX_EXTENSIONS = 128
MAX_WORK = 33_554_432
MAX_TEXT = 4 * ((MAX_CERTIFICATE_BYTES + 2) // 3)
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "XSA-" + "0" * 32
_FLAGS = {
    "offline_only": True,
    "certificate_signature_verified": False,
    "chain_validated": False,
    "trust_established": False,
    "service_authenticated": False,
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
    "The certificate and reference identifier are caller-supplied unverified bytes and metadata.",
    "Only preferred-syntax ASCII non-IDN DNS-ID and exact IPv4/IPv6 IP-ID SAN arithmetic "
    "is assessed.",
    "Wildcards require caller permission and match exactly one complete leftmost DNS label.",
    "Common Name, URI-ID, SRV-ID, IDNA conversion and public-suffix policy are not assessed.",
    "No signature, chain, root, EKU, name constraints, validity, revocation or service trust "
    "is assessed.",
    "A SAN arithmetic match never grants TLS admission, current authority or qualification.",
]


class X509SanAnalysisError(ValueError):
    """Closed source, DER, cost or replay refusal for this supplied-data subset."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise X509SanAnalysisError("Cumulative software work ceiling exhausted")
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
            raise X509SanAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise X509SanAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT:
                raise X509SanAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise X509SanAnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise X509SanAnalysisError("Native signed64 integer ceiling exhausted")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise X509SanAnalysisError("Cyclic native document")
            queued = len(item) * (2 if kind is dict else 1)
            if queued > node_limit - nodes:
                raise X509SanAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise X509SanAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise X509SanAnalysisError("Exact native integer-only JSON families required")

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
        raise X509SanAnalysisError("Raw bounded integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise X509SanAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise X509SanAnalysisError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise X509SanAnalysisError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise X509SanAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise X509SanAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                        raise X509SanAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise X509SanAnalysisError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise X509SanAnalysisError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise X509SanAnalysisError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_TEXT:
                    raise X509SanAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise X509SanAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise X509SanAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise X509SanAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise X509SanAnalysisError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise X509SanAnalysisError("Integer-only raw JSON required")

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
        raise X509SanAnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _name(value: str, *, wildcard: bool = False) -> bool:
    if not value.isascii() or not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    minimum_labels = 2
    if wildcard and labels[0] == "*" and len(labels) >= 2:
        labels = labels[1:]
        minimum_labels = 1
    elif "*" in value:
        return False
    return len(labels) >= minimum_labels and all(
        _DNS_LABEL.fullmatch(label) is not None and not label.lower().startswith("xn--")
        for label in labels
    )


def _reference(kind: Any, value: Any) -> bytes | tuple[str, ...]:
    if type(kind) is not str or kind not in {"dns_id", "ip_id"}:
        raise X509SanAnalysisError("Only declared DNS-ID and IP-ID references are supported")
    if type(value) is not str:
        raise X509SanAnalysisError("Exact native reference text required")
    if kind == "dns_id":
        if not _name(value):
            raise X509SanAnalysisError("Reference is outside non-IDN preferred-name subset")
        return tuple(label.lower() for label in value.split("."))
    if "%" in value:
        raise X509SanAnalysisError("Scoped IP text is not an IP-ID address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise X509SanAnalysisError("Reference is not one IP address") from exc
    if str(address) != value:
        raise X509SanAnalysisError("Canonical IP address text required")
    return address.packed


def _certificate(source: dict, budget: _Budget) -> tuple[bytes, x509.Certificate]:
    encoded = source["certificate_der_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_TEXT:
        raise X509SanAnalysisError("Bounded exact native certificate base64 required")
    budget.charge(4 * len(encoded))
    try:
        der = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise X509SanAnalysisError("Certificate is not canonical base64") from exc
    if (
        not der
        or len(der) > MAX_CERTIFICATE_BYTES
        or base64.b64encode(der).decode("ascii") != encoded
    ):
        raise X509SanAnalysisError("Certificate base64 or DER byte bound is invalid")
    budget.charge(16 * len(der) + 4 * MAX_SAN_ENTRIES)
    try:
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(serialization.Encoding.DER) != der:
            raise X509SanAnalysisError("Noncanonical or trailing certificate DER")
    except (ValueError, TypeError, UnsupportedAlgorithm, x509.UnsupportedGeneralNameType) as exc:
        raise X509SanAnalysisError("One supported exact DER certificate is required") from exc
    return der, certificate


def _observations(
    certificate: x509.Certificate,
    kind: str,
    reference: bytes | tuple[str, ...],
    wildcard: bool,
    budget: _Budget,
) -> tuple[list[dict], list[str]]:
    try:
        extensions = certificate.extensions
        if len(extensions) > MAX_EXTENSIONS:
            raise X509SanAnalysisError("Certificate extension count exceeds software ceiling")
        try:
            san = extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        except x509.ExtensionNotFound:
            return [], []
        if len(san) > MAX_SAN_ENTRIES:
            raise X509SanAnalysisError("SAN entry count exceeds software ceiling")
        rows: list[dict] = []
        unknown: set[str] = set()
        for index, entry in enumerate(san):
            budget.charge(256)
            if isinstance(entry, x509.DNSName):
                name = entry.value
                if type(name) is not str or len(name) > 253 or not name.isascii():
                    status = "unassessed"
                    unknown.add("dns_name_outside_supported_subset")
                    displayed = None
                elif "*" in name and not _name(name, wildcard=True):
                    status = "ignored_invalid_wildcard"
                    displayed = name
                elif not _name(name, wildcard=True):
                    status = "unassessed"
                    unknown.add("dns_name_outside_supported_subset")
                    displayed = None
                else:
                    displayed = name
                    labels = tuple(label.lower() for label in name.split("."))
                    if kind != "dns_id":
                        status = "different_identifier_kind"
                    elif labels[0] == "*":
                        status = (
                            "match"
                            if wildcard
                            and len(reference) == len(labels)
                            and reference[1:] == labels[1:]
                            else "no_match"
                        )
                    else:
                        status = "match" if reference == labels else "no_match"
                row_kind = "dns_id"
            elif isinstance(entry, x509.IPAddress):
                address = entry.value
                if type(address) not in (ipaddress.IPv4Address, ipaddress.IPv6Address):
                    raise X509SanAnalysisError(
                        "SAN iPAddress is not four or sixteen address octets"
                    )
                else:
                    displayed = str(address)
                    status = (
                        "different_identifier_kind"
                        if kind != "ip_id"
                        else "match"
                        if reference == address.packed
                        else "no_match"
                    )
                row_kind = "ip_id"
            else:
                row_kind, displayed, status = "other", None, "unassessed"
                unknown.add("other_general_name_not_evaluated")
            rows.append(
                {
                    "index": index,
                    "kind": row_kind,
                    "presented_value": displayed,
                    "comparison": status,
                }
            )
        return rows, sorted(unknown)
    except (
        ValueError,
        TypeError,
        UnsupportedAlgorithm,
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
    ) as exc:
        raise X509SanAnalysisError("SAN extension cannot be safely decoded") from exc


def _bounds() -> dict:
    return {
        "certificate_bytes": MAX_CERTIFICATE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "native_depth": MAX_DEPTH,
        "san_entries": MAX_SAN_ENTRIES,
        "extensions": MAX_EXTENSIONS,
        "cumulative_work": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    der: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise X509SanAnalysisError("Exact native source model required")
    source, source_size, _ = _capture(model, budget)
    if set(source) != {
        "schema_version",
        "source_id",
        "certificate_der_base64",
        "reference_kind",
        "reference_value",
        "wildcard_matching_permitted",
    }:
        raise X509SanAnalysisError("Closed source model fields required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise X509SanAnalysisError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _SOURCE.fullmatch(source["source_id"]) is None:
        raise X509SanAnalysisError("Bounded source identifier required")
    if type(source["wildcard_matching_permitted"]) is not bool:
        raise X509SanAnalysisError("Exact native wildcard policy boolean required")
    reference = _reference(source["reference_kind"], source["reference_value"])
    der, certificate = _certificate(source, budget)
    rows, unknown = _observations(
        certificate,
        source["reference_kind"],
        reference,
        source["wildcard_matching_permitted"],
        budget,
    )
    comparisons = {row["comparison"] for row in rows}
    outcome = (
        "match_observed"
        if "match" in comparisons
        else "unassessed"
        if "unassessed" in comparisons
        else "no_supported_match_observed"
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
        "source_certificate_sha256": _PLACEHOLDER,
        "source_certificate_bytes": len(der),
        "san_observations": rows,
        "unassessed_reasons": unknown,
        "analysis_status": outcome,
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        18 * size + 8 * source_size + 6 * len(der) + 8 * nodes + len(DOMAIN) + len(MODEL_DOMAIN) + 2
    )
    return _Plan(document, der, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:" + hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_certificate_sha256"] = "sha256:" + hashlib.sha256(plan.der).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_id"] = "XSA-" + digest[7:39].upper()
    document["analysis_sha256"] = digest
    return _canonical(document)


def _report_plan(document: Any, budget: _Budget) -> tuple[dict, str, _Plan]:
    if type(document) is not dict:
        raise X509SanAnalysisError("Exact native report object required")
    owned, size, nodes = _capture(document, budget, report=True)
    if "source_model" not in owned:
        raise X509SanAnalysisError("Report requires complete original source model")
    expected = _plan(owned["source_model"], budget)
    for field in ("source_model_sha256", "source_certificate_sha256", "analysis_sha256"):
        if type(owned.get(field)) is not str or _SHA.fullmatch(owned[field]) is None:
            raise X509SanAnalysisError("Exact SHA256 report address required")
    if (
        type(owned.get("analysis_id")) is not str
        or owned["analysis_id"] != "XSA-" + owned["analysis_sha256"][7:39].upper()
    ):
        raise X509SanAnalysisError("Exact report ID/address join required")
    budget.charge(12 * size + 4 * expected.size + 8 * nodes)
    placeholder = {
        **owned,
        "source_model_sha256": _PLACEHOLDER,
        "source_certificate_sha256": _PLACEHOLDER,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _PLACEHOLDER,
    }
    if _canonical(placeholder) != _canonical(expected.document):
        raise X509SanAnalysisError("Report metadata does not replay original SAN arithmetic")
    return owned, _canonical(owned), expected


def _replay_text(text: Any, budget: _Budget) -> dict:
    document, canonical, plan = _report_plan(_decode(text, budget, report=True), budget)
    if text != canonical:
        raise X509SanAnalysisError("Exact canonical retained report JSON required")
    if _materialize(plan) != canonical:
        raise X509SanAnalysisError("Report addresses do not replay original certificate")
    return document


def _stored(report: Any) -> str:
    if type(report) is not X509SanAnalysis:
        raise X509SanAnalysisError("Exact native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise X509SanAnalysisError("Exact native retained report text required")
    return text


def _owned(text: str) -> X509SanAnalysis:
    report = object.__new__(X509SanAnalysis)
    object.__setattr__(report, "document_json", text)
    return report


@dataclass(frozen=True, slots=True)
class X509SanAnalysis:
    """Detached unsigned SAN arithmetic with complete embedded original DER."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not X509SanAnalysis:
            raise X509SanAnalysisError("Exact native report family required")
        _replay_text(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> X509SanAnalysis:
        if cls is not X509SanAnalysis:
            raise X509SanAnalysisError("Exact native report family required")
        budget = _Budget()
        _document, text, plan = _report_plan(document, budget)
        if _materialize(plan) != text:
            raise X509SanAnalysisError("Report addresses do not replay source")
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> X509SanAnalysis:
        if cls is not X509SanAnalysis:
            raise X509SanAnalysisError("Exact native report family required")
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


def analyze_supplied_x509_san(model: Any) -> X509SanAnalysis:
    """Compare one declared reference to SANs in an exact supplied certificate."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_x509_san_bytes(*, model_bytes: Any) -> X509SanAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise X509SanAnalysisError("Bounded exact native source JSON bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise X509SanAnalysisError("ASCII source JSON bytes required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_x509_san_analysis(report: Any, *, model: Any) -> X509SanAnalysis:
    """Replay embedded and separately supplied originals within one work budget."""
    budget = _Budget()
    text = _stored(report)
    _document, canonical, embedded = _report_plan(_decode(text, budget, report=True), budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    if text != canonical:
        raise X509SanAnalysisError("Exact canonical retained report JSON required")
    expected = _materialize(embedded)
    separate = _materialize(original)
    if expected != text or expected != separate:
        raise X509SanAnalysisError("Report differs from embedded or separately original source")
    return _owned(separate)


__all__ = [
    "X509SanAnalysis",
    "X509SanAnalysisError",
    "analyze_supplied_x509_san",
    "analyze_supplied_x509_san_bytes",
    "verify_supplied_x509_san_analysis",
]

"""Partial structural and signature analysis of an explicitly supplied DER chain."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID

PROFILE_ID = "AOE-GE-D22-S03"
CAPABILITY_ID = "crypto.pki-x509-validation"
VECTOR_ID = "AV-GE-D22-S03-01"
DOMAIN = "sunderkey.offline-x509-chain-analysis.v1"
SEMANTICS_PROFILE = "ordered-supplied-x509-structural-subset-v1"
MAX_CERTIFICATES = 16
MAX_CERTIFICATE_BYTES = 65_536
MAX_TOTAL_DER_BYTES = 524_288
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NODES = 8192
MAX_DEPTH = 12
MAX_EXTENSIONS = 128
MAX_PUBLIC_KEY_BITS = 8192
_MAX_BASE64 = 4 * ((MAX_CERTIFICATE_BYTES + 2) // 3)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_OID = re.compile(r"[0-2](?:\.[0-9]+)+\Z")
_HANDLED_CRITICAL = {
    ExtensionOID.BASIC_CONSTRAINTS.dotted_string,
    ExtensionOID.KEY_USAGE.dotted_string,
}
_KEY_USAGE = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)
_BOUNDS = {
    "maximum_certificates": MAX_CERTIFICATES,
    "maximum_certificate_bytes": MAX_CERTIFICATE_BYTES,
    "maximum_total_der_bytes": MAX_TOTAL_DER_BYTES,
    "maximum_public_key_bits": MAX_PUBLIC_KEY_BITS,
    "maximum_extensions_per_certificate": MAX_EXTENSIONS,
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
_LIMITATIONS = (
    "Supplied certificates, terminal selection and evaluation time are unverified declarations.",
    "This is not complete PKIX, WebPKI, application-purpose or trust validation.",
    "No revocation, hostname, EKU, policy tree, name constraints or root store is evaluated.",
    "Distinguished-name comparisons use the pinned library, not a complete RFC 5280 name profile.",
    "Only BasicConstraints and KeyUsage critical extensions are processed in this subset.",
    "Terminal validity and extensions are observations, not mandatory path constraints.",
    "No algorithm-strength approval, current authority, containment or qualification is granted.",
)
_MODEL_FIELDS = {"schema_version", "chain_der_base64", "declared_terminal_sha256", "evaluated_at"}
_OBSERVATION_FIELDS = {
    "index",
    "role",
    "not_valid_before",
    "not_valid_after",
    "valid_at_supplied_instant",
    "self_issued",
    "basic_constraints",
    "key_usage",
    "critical_extension_oids",
    "unsupported_critical_extension_oids",
}
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "profile_id",
    "capability_id",
    "vector_id",
    "semantics_profile",
    "source",
    "bounds",
    "certificate_observations",
    "issuer_links",
    "violations",
    "incomplete_reasons",
    "supported_checks_outcome",
    "input_provenance",
    "terminal_selection",
    "evaluation_time_basis",
    "offline_only",
    "full_pkix_validated",
    "trust_established",
    "positive_use_approved",
    "qualification_claimed",
    "effects",
    "limitations",
}


class X509ChainAnalysisError(ValueError):
    """A native input, DER encoding, software bound or source replay was rejected."""


def _capture(value: Any) -> Any:
    """Own bounded native JSON before hashing, serialization or general copying."""
    nodes = 0
    size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise X509ChainAnalysisError("native JSON exceeds the aggregate byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise X509ChainAnalysisError("native JSON exceeds the depth or node budget")
        kind = type(item)
        if kind is str:
            if len(item) > _MAX_BASE64:
                raise X509ChainAnalysisError("native text exceeds the supported length")
            charge(len(item) + 2)
            if not item.isascii() or any(not 32 <= ord(char) <= 126 for char in item):
                raise X509ChainAnalysisError("native text must be printable ASCII")
            charge(item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if not -(2**63) <= item < 2**63:
                raise X509ChainAnalysisError("native integer exceeds the signed64 subset")
            charge(len(str(item)))
            return item
        if kind not in (dict, list):
            raise X509ChainAnalysisError("only exact native JSON families are supported")
        needed = len(item) * (2 if kind is dict else 1)
        if needed > MAX_NODES - nodes or id(item) in active:
            raise X509ChainAnalysisError("native JSON is oversized or cyclic")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise X509ChainAnalysisError("native object keys must be exact text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _sha(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _sha(DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii"))
    return {"analysis_id": "XCA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise X509ChainAnalysisError(f"{label} has unsupported or missing fields")
    return value


def _integer(value: Any, maximum: int, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise X509ChainAnalysisError(f"{label} must be a bounded native integer")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise X509ChainAnalysisError(f"{label} must be a native boolean")
    return value


def _digest(value: Any) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise X509ChainAnalysisError("source digest must be canonical SHA-256")
    return value


def _instant(value: Any) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise X509ChainAnalysisError("instant must be native canonical whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise X509ChainAnalysisError("instant is not a valid UTC date") from exc


def _time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _json(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise X509ChainAnalysisError("JSON must be bounded native ASCII text")
    quoted = escaped = False
    depth = 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise X509ChainAnalysisError("JSON exceeds the depth budget before decoding")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise X509ChainAnalysisError("duplicate JSON field")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise X509ChainAnalysisError("JSON floats and nonfinite numbers are unsupported")

    def integer(value: str) -> int:
        if len(value) > 20:
            raise X509ChainAnalysisError("JSON integer exceeds the signed64 subset")
        return int(value)

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise X509ChainAnalysisError("invalid bounded native JSON") from exc
    return _capture(decoded)


def _model(value: Any) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    owned = _exact(_capture(value), _MODEL_FIELDS, "chain model")
    _integer(owned["schema_version"], 1, "schema_version", minimum=1)
    _instant(owned["evaluated_at"])
    _digest(owned["declared_terminal_sha256"])
    encoded = owned["chain_der_base64"]
    if type(encoded) is not list or not 1 <= len(encoded) <= MAX_CERTIFICATES:
        raise X509ChainAnalysisError("chain must be a bounded nonempty native array")
    total = 0
    decoded = []
    for item in encoded:
        if type(item) is not str or not item or len(item) > _MAX_BASE64:
            raise X509ChainAnalysisError("DER must use bounded native canonical base64")
        try:
            der = base64.b64decode(item, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise X509ChainAnalysisError("DER is not canonical base64") from exc
        if (
            not der
            or len(der) > MAX_CERTIFICATE_BYTES
            or base64.b64encode(der).decode("ascii") != item
        ):
            raise X509ChainAnalysisError("DER is empty, oversized or noncanonical base64")
        total += len(der)
        if total > MAX_TOTAL_DER_BYTES:
            raise X509ChainAnalysisError("chain exceeds the aggregate DER byte budget")
        decoded.append(der)
    if len(set(decoded)) != len(decoded):
        raise X509ChainAnalysisError("duplicate certificates are not a supplied path")
    if _sha(decoded[-1]) != owned["declared_terminal_sha256"]:
        raise X509ChainAnalysisError(
            "declared terminal does not match the supplied last certificate"
        )
    return owned, tuple(decoded)


def _observation(cert: x509.Certificate, index: int, count: int, at: datetime) -> dict[str, Any]:
    try:
        extensions = cert.extensions
        if len(extensions) > MAX_EXTENSIONS:
            raise X509ChainAnalysisError("certificate extension count exceeds the supported bound")
        critical = sorted(ext.oid.dotted_string for ext in extensions if ext.critical)
        if any(len(oid) > 128 for oid in critical):
            raise X509ChainAnalysisError("certificate extension OID exceeds the supported bound")
        bc = ku = None
        for ext in extensions:
            if ext.oid == ExtensionOID.BASIC_CONSTRAINTS:
                path_length = ext.value.path_length
                if path_length is not None:
                    _integer(path_length, 2**63 - 1, "path_length")
                bc = {"critical": ext.critical, "ca": ext.value.ca, "path_length": path_length}
            elif ext.oid == ExtensionOID.KEY_USAGE:
                ku = {"critical": ext.critical}
                for field in _KEY_USAGE:
                    ku[field] = (
                        None
                        if field in {"encipher_only", "decipher_only"}
                        and not ext.value.key_agreement
                        else getattr(ext.value, field)
                    )
        before, after = cert.not_valid_before_utc, cert.not_valid_after_utc
        if before > after or before.microsecond or after.microsecond:
            raise X509ChainAnalysisError(
                "certificate validity is outside the supported time subset"
            )
        return {
            "index": index,
            "role": "declared_terminal"
            if index == count - 1
            else "leaf"
            if index == 0
            else "intermediate",
            "not_valid_before": _time(before),
            "not_valid_after": _time(after),
            "valid_at_supplied_instant": before <= at <= after,
            "self_issued": cert.subject == cert.issuer,
            "basic_constraints": bc,
            "key_usage": ku,
            "critical_extension_oids": critical,
            "unsupported_critical_extension_oids": sorted(set(critical) - _HANDLED_CRITICAL),
        }
    except (
        ValueError,
        TypeError,
        UnsupportedAlgorithm,
        x509.DuplicateExtension,
        x509.UnsupportedGeneralNameType,
    ) as exc:
        raise X509ChainAnalysisError("certificate extensions or validity are malformed") from exc


def _key_kind(key: Any) -> str:
    for family, label in (
        (rsa.RSAPublicKey, "rsa"),
        (ec.EllipticCurvePublicKey, "ecdsa"),
        (dsa.DSAPublicKey, "dsa"),
        (ed25519.Ed25519PublicKey, "ed25519"),
        (ed448.Ed448PublicKey, "ed448"),
    ):
        if isinstance(key, family):
            if hasattr(key, "key_size") and key.key_size > MAX_PUBLIC_KEY_BITS:
                return "unsupported"
            return label
    return "unsupported"


def _link(subject: x509.Certificate, issuer: x509.Certificate, index: int) -> dict[str, Any]:
    matches = subject.issuer == issuer.subject
    status, key_kind = "not_checked", "unsupported"
    try:
        key_kind = _key_kind(issuer.public_key())
        if matches:
            if key_kind == "unsupported":
                status = "unsupported"
            else:
                subject.verify_directly_issued_by(issuer)
                status = "verified"
    except InvalidSignature:
        status = "invalid"
    except (ValueError, TypeError, UnsupportedAlgorithm):
        status = "unsupported" if matches else "not_checked"
    return {
        "subject_index": index,
        "issuer_index": index + 1,
        "issuer_name_matches": matches,
        "signature_status": status,
        "issuer_key_kind": key_kind,
    }


def _conclusions(
    observations: list[dict[str, Any]], links: list[dict[str, Any]]
) -> tuple[list, list]:
    violations, incomplete = [], []

    def note(target: list, code: str, index: int, related: int | None = None) -> None:
        target.append(
            {"code": code, "certificate_index": index, "related_certificate_index": related}
        )

    if len(observations) == 1:
        note(incomplete, "no_issuer_link_supplied", 0)
    for item in observations[:-1]:
        index = item["index"]
        bc, ku = item["basic_constraints"], item["key_usage"]
        if not item["valid_at_supplied_instant"]:
            note(violations, "outside_certificate_validity", index)
        if item["unsupported_critical_extension_oids"]:
            note(incomplete, "unsupported_critical_extension", index)
        if ku is not None:
            if not any(ku[key] is True for key in _KEY_USAGE):
                note(violations, "empty_key_usage", index)
            if ku["key_cert_sign"] and (bc is None or not bc["ca"]):
                note(violations, "key_cert_sign_without_ca", index)
            if bc is not None and bc["path_length"] is not None and not ku["key_cert_sign"]:
                note(violations, "path_length_without_key_cert_sign", index)
        if item["role"] == "intermediate":
            if bc is None or not bc["ca"]:
                note(violations, "intermediate_not_ca", index)
            if ku is not None and not ku["key_cert_sign"]:
                note(violations, "intermediate_key_cert_sign_denied", index)
            if bc is not None and bc["ca"] and bc["path_length"] is not None:
                below = sum(not lower["self_issued"] for lower in observations[1:index])
                if below > bc["path_length"]:
                    note(violations, "intermediate_path_length_exceeded", index)
    for link in links:
        index, issuer = link["subject_index"], link["issuer_index"]
        if not link["issuer_name_matches"]:
            note(violations, "issuer_name_mismatch", index, issuer)
        elif link["signature_status"] == "invalid":
            note(violations, "certificate_signature_invalid", index, issuer)
        elif link["signature_status"] == "unsupported":
            note(incomplete, "unsupported_signature_or_issuer_key", index, issuer)
    return violations, incomplete


def _validate_report(value: Any) -> dict[str, Any]:
    raw = _exact(_capture(value), _REPORT_FIELDS, "analysis")
    _integer(raw["schema_version"], 1, "schema_version", minimum=1)
    for field, expected in {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "operator_supplied_unverified",
        "terminal_selection": "caller_declared_untrusted",
        "evaluation_time_basis": "caller_supplied",
        "effects": _EFFECTS,
        "limitations": list(_LIMITATIONS),
    }.items():
        if raw[field] != expected:
            raise X509ChainAnalysisError("analysis widens or changes the fixed partial profile")
    for field in (
        "offline_only",
        "full_pkix_validated",
        "trust_established",
        "positive_use_approved",
        "qualification_claimed",
    ):
        if raw[field] is not (field == "offline_only"):
            raise X509ChainAnalysisError("analysis effects and approval flags are fixed")
    bounds = _exact(raw["bounds"], set(_BOUNDS), "bounds")
    for field, expected in _BOUNDS.items():
        if type(bounds[field]) is not int or bounds[field] != expected:
            raise X509ChainAnalysisError("analysis software bounds are fixed native integers")
    source = _exact(
        raw["source"],
        {"model_sha256", "evaluated_at", "declared_terminal_sha256", "certificates"},
        "source",
    )
    _digest(source["model_sha256"])
    _digest(source["declared_terminal_sha256"])
    at = _instant(source["evaluated_at"])
    certificates = source["certificates"]
    if type(certificates) is not list or not 1 <= len(certificates) <= MAX_CERTIFICATES:
        raise X509ChainAnalysisError("analysis source certificate count is invalid")
    total = 0
    for index, cert in enumerate(certificates):
        _exact(cert, {"index", "der_sha256", "byte_count"}, "certificate source")
        if _integer(cert["index"], MAX_CERTIFICATES - 1, "source index") != index:
            raise X509ChainAnalysisError("source indexes are not contiguous")
        _digest(cert["der_sha256"])
        total += _integer(cert["byte_count"], MAX_CERTIFICATE_BYTES, "DER byte count", minimum=1)
    if total > MAX_TOTAL_DER_BYTES or len({cert["der_sha256"] for cert in certificates}) != len(
        certificates
    ):
        raise X509ChainAnalysisError("analysis DER sources exceed bounds or repeat")
    if certificates[-1]["der_sha256"] != source["declared_terminal_sha256"]:
        raise X509ChainAnalysisError("analysis terminal source is inconsistent")
    observations = raw["certificate_observations"]
    if type(observations) is not list or len(observations) != len(certificates):
        raise X509ChainAnalysisError("analysis observations do not cover the exact source order")
    for index, item in enumerate(observations):
        _exact(item, _OBSERVATION_FIELDS, "certificate observation")
        role = (
            "declared_terminal"
            if index == len(certificates) - 1
            else "leaf"
            if index == 0
            else "intermediate"
        )
        if (
            _integer(item["index"], MAX_CERTIFICATES - 1, "observation index") != index
            or item["role"] != role
        ):
            raise X509ChainAnalysisError("analysis certificate role or index is inconsistent")
        before, after = _instant(item["not_valid_before"]), _instant(item["not_valid_after"])
        if before > after or _boolean(item["valid_at_supplied_instant"], "validity") != (
            before <= at <= after
        ):
            raise X509ChainAnalysisError("analysis validity observation is inconsistent")
        _boolean(item["self_issued"], "self_issued")
        bc, ku = item["basic_constraints"], item["key_usage"]
        if bc is not None:
            _exact(bc, {"critical", "ca", "path_length"}, "basic constraints")
            _boolean(bc["critical"], "basic constraints critical")
            _boolean(bc["ca"], "basic constraints ca")
            if bc["path_length"] is not None:
                _integer(bc["path_length"], 2**63 - 1, "path length")
                if not bc["ca"]:
                    raise X509ChainAnalysisError(
                        "analysis path length requires CA basic constraints"
                    )
        if ku is not None:
            _exact(ku, {"critical", *_KEY_USAGE}, "key usage")
            _boolean(ku["critical"], "key usage critical")
            for key in _KEY_USAGE:
                if key in {"encipher_only", "decipher_only"} and not ku["key_agreement"]:
                    if ku[key] is not None:
                        raise X509ChainAnalysisError(
                            "analysis conditional key usage is inconsistent"
                        )
                else:
                    _boolean(ku[key], "key usage bit")
        critical = item["critical_extension_oids"]
        if type(critical) is not list or len(critical) > MAX_EXTENSIONS:
            raise X509ChainAnalysisError("analysis critical extension count is invalid")
        if any(
            type(oid) is not str or len(oid) > 128 or _OID.fullmatch(oid) is None
            for oid in critical
        ):
            raise X509ChainAnalysisError("analysis critical extension OID is invalid")
        if critical != sorted(set(critical)) or item[
            "unsupported_critical_extension_oids"
        ] != sorted(set(critical) - _HANDLED_CRITICAL):
            raise X509ChainAnalysisError(
                "analysis unsupported critical extension accounting is inconsistent"
            )
        for extension, oid in (
            (bc, ExtensionOID.BASIC_CONSTRAINTS.dotted_string),
            (ku, ExtensionOID.KEY_USAGE.dotted_string),
        ):
            if (oid in critical) != (extension is not None and extension["critical"]):
                raise X509ChainAnalysisError(
                    "analysis handled critical extension accounting is inconsistent"
                )
    links = raw["issuer_links"]
    if type(links) is not list or len(links) != len(certificates) - 1:
        raise X509ChainAnalysisError("analysis issuer links do not cover the exact source order")
    for index, link in enumerate(links):
        _exact(
            link,
            {
                "subject_index",
                "issuer_index",
                "issuer_name_matches",
                "signature_status",
                "issuer_key_kind",
            },
            "issuer link",
        )
        if (
            _integer(link["subject_index"], MAX_CERTIFICATES - 1, "link subject") != index
            or _integer(link["issuer_index"], MAX_CERTIFICATES - 1, "link issuer") != index + 1
        ):
            raise X509ChainAnalysisError("analysis issuer indexes are inconsistent")
        matches = _boolean(link["issuer_name_matches"], "issuer name match")
        if type(link["issuer_key_kind"]) is not str or link["issuer_key_kind"] not in {
            "rsa",
            "ecdsa",
            "dsa",
            "ed25519",
            "ed448",
            "unsupported",
        }:
            raise X509ChainAnalysisError("analysis issuer key kind is unsupported")
        if type(link["signature_status"]) is not str or link["signature_status"] not in (
            {"verified", "invalid", "unsupported"} if matches else {"not_checked"}
        ):
            raise X509ChainAnalysisError(
                "analysis signature and name observations are inconsistent"
            )
        if (
            matches
            and link["issuer_key_kind"] == "unsupported"
            and link["signature_status"] != "unsupported"
        ):
            raise X509ChainAnalysisError("analysis unsupported key cannot verify a signature")
    violations, incomplete = _conclusions(observations, links)
    outcome = "incomplete" if incomplete else "violations" if violations else "pass"
    if (
        _canonical(raw["violations"]) != _canonical(violations)
        or _canonical(raw["incomplete_reasons"]) != _canonical(incomplete)
        or raw["supported_checks_outcome"] != outcome
    ):
        raise X509ChainAnalysisError(
            "analysis conclusions do not reconstruct declared observations"
        )
    body = {
        key: child for key, child in raw.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    if _canonical(raw) != _canonical(_address(body)):
        raise X509ChainAnalysisError("analysis content address is invalid")
    return raw


@dataclass(frozen=True, slots=True)
class X509ChainAnalysis:
    """Owned unsigned metadata; supplied-source replay does not establish trust."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise X509ChainAnalysisError("analysis has incomplete native slots") from exc
        return _validate_report(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> X509ChainAnalysis:
        return cls(_canonical(_validate_report(document)))

    @classmethod
    def from_json(cls, document: str) -> X509ChainAnalysis:
        return cls(document)


def analyze_supplied_x509_chain(model: dict[str, Any]) -> X509ChainAnalysis:
    """Inspect an ordered supplied chain without selecting trust or fetching sources."""
    owned, sources = _model(model)
    certificates = []
    for der in sources:
        try:
            certificate = x509.load_der_x509_certificate(der)
            if certificate.public_bytes(serialization.Encoding.DER) != der:
                raise X509ChainAnalysisError("certificate DER is noncanonical or has trailing data")
            certificates.append(certificate)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise X509ChainAnalysisError(
                "source is not one supported canonical DER certificate"
            ) from exc
    at = _instant(owned["evaluated_at"])
    observations = [
        _observation(cert, index, len(certificates), at) for index, cert in enumerate(certificates)
    ]
    links = [
        _link(certificates[index], certificates[index + 1], index)
        for index in range(len(certificates) - 1)
    ]
    violations, incomplete = _conclusions(observations, links)
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "source": {
            "model_sha256": _sha(_canonical(owned).encode("ascii")),
            "evaluated_at": owned["evaluated_at"],
            "declared_terminal_sha256": owned["declared_terminal_sha256"],
            "certificates": [
                {"index": index, "der_sha256": _sha(der), "byte_count": len(der)}
                for index, der in enumerate(sources)
            ],
        },
        "bounds": dict(_BOUNDS),
        "certificate_observations": observations,
        "issuer_links": links,
        "violations": violations,
        "incomplete_reasons": incomplete,
        "supported_checks_outcome": "incomplete"
        if incomplete
        else "violations"
        if violations
        else "pass",
        "input_provenance": "operator_supplied_unverified",
        "terminal_selection": "caller_declared_untrusted",
        "evaluation_time_basis": "caller_supplied",
        "offline_only": True,
        "full_pkix_validated": False,
        "trust_established": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    return X509ChainAnalysis.from_dict(_address(body))


def verify_supplied_x509_chain_analysis(
    report: X509ChainAnalysis, *, model: dict[str, Any]
) -> X509ChainAnalysis:
    """Recompute every declared observation from exact original supplied sources."""
    if type(report) is not X509ChainAnalysis:
        raise X509ChainAnalysisError("report must be the exact X509ChainAnalysis family")
    observed = report.to_json()
    expected = analyze_supplied_x509_chain(model)
    if observed != expected.to_json():
        raise X509ChainAnalysisError(
            "analysis does not reproduce the supplied original source model"
        )
    return X509ChainAnalysis.from_json(expected.to_json())


__all__ = [
    "CAPABILITY_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "X509ChainAnalysis",
    "X509ChainAnalysisError",
    "analyze_supplied_x509_chain",
    "verify_supplied_x509_chain_analysis",
]

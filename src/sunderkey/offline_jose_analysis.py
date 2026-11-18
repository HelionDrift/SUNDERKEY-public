"""Bounded supplied-public-key compact JWS observations, never admission."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

DOMAIN = "sunderkey.offline-jose-analysis.v1"
PROFILE_ID = "AOE-GA-D03-S05"
CAPABILITY_ID = "army.ga.d03.s05"
VECTOR_ID = "AV-GA-D03-S05-01"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_NODES = 4096
MAX_NATIVE_DEPTH = 12
MAX_TEXT_BYTES = 65_536
MAX_COMPACT_BYTES = 65_536
MAX_HEADER_BYTES = 4096
MAX_CLAIMS_BYTES = 32_768
MAX_EPOCH = 253_402_300_799
_ALGORITHMS = {"ES256", "RS256"}
_B64 = re.compile(r"[A-Za-z0-9_-]+\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MODEL_FIELDS = {
    "schema_version",
    "compact_jws",
    "public_jwk",
    "expected_algorithm",
    "expected_issuer",
    "expected_audience",
    "evaluated_at",
}
_EFFECTS = {
    name: "none"
    for name in ("authority", "deployment", "execution", "qualification", "routing", "target")
}
_FLAGS = {
    "offline_only": True,
    "issuer_authenticated": False,
    "key_origin_authenticated": False,
    "key_currentness_verified": False,
    "live_use_approved": False,
    "replay_prevention_verified": False,
    "qualification_claimed": False,
}
_CHECK_VALUES = {
    "signature": {"valid", "invalid"},
    "issuer": {"match", "mismatch", "missing", "invalid_type"},
    "audience": {"match", "mismatch", "missing", "invalid_type"},
    "expiration": {"before_expiration", "expired", "missing"},
    "not_before": {"reached", "not_reached", "not_present"},
    "issued_at": {"not_future", "future", "not_present"},
    "date_order": {"consistent", "contradictory", "not_assessed"},
}
_NEGATIVE = {
    "invalid",
    "mismatch",
    "invalid_type",
    "expired",
    "not_reached",
    "future",
    "contradictory",
}


class JoseAnalysisError(ValueError):
    """Supplied input is outside this finite nonauthoritative profile."""


def _capture(value: Any) -> Any:
    """Own exact native input while charging repeated nodes and JSON bytes."""
    nodes = 0
    size = 0

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise JoseAnalysisError("Native document exceeds its canonical byte budget")

    def string(item: Any) -> str:
        if type(item) is not str or len(item) > MAX_TEXT_BYTES:
            raise JoseAnalysisError("Native string is outside the supported bound")
        try:
            if len(item.encode("utf-8")) > MAX_TEXT_BYTES:
                raise JoseAnalysisError("Native string is outside the supported bound")
        except UnicodeError as exc:
            raise JoseAnalysisError("Native string is not valid Unicode") from exc
        charge(2)
        for char in item:
            number = ord(char)
            charge(
                2
                if char in '"\\\b\f\n\r\t'
                else 6
                if number < 32 or 127 <= number <= 65535
                else 12
                if number > 65535
                else 1
            )
        return item

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise JoseAnalysisError("Native document exceeds its node or depth budget")
        family = type(item)
        if family is dict:
            if len(item) > MAX_NATIVE_NODES:
                raise JoseAnalysisError("Native dictionary exceeds its node budget")
            charge(2 + max(0, len(item) - 1))
            result = {}
            for key, child in item.items():
                captured_key = string(key)
                charge(1)
                result[captured_key] = visit(child, depth + 1)
            return result
        if family is list:
            if len(item) > MAX_NATIVE_NODES:
                raise JoseAnalysisError("Native list exceeds its node budget")
            charge(2 + max(0, len(item) - 1))
            return [visit(child, depth + 1) for child in item]
        if family is str:
            return string(item)
        if item is None:
            charge(4)
            return None
        if family is bool:
            charge(4 if item else 5)
            return item
        if family is int:
            if item.bit_length() > 63:
                raise JoseAnalysisError("Native integer exceeds its finite magnitude")
            charge(len(str(item)))
            return item
        raise JoseAnalysisError("Only exact native JSON families are supported")

    try:
        return visit(value, 0)
    except (RuntimeError, RecursionError) as exc:
        raise JoseAnalysisError("Native document cannot be captured") from exc


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _bytes_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json(raw: Any, *, maximum: int) -> Any:
    if type(raw) is not bytes or len(raw) > maximum or not raw:
        raise JoseAnalysisError("JSON input is outside its native byte bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise JoseAnalysisError("JSON input must be UTF-8") from exc
    depth = nodes = index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            nodes += 1
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == '"':
                    index += 1
                    break
                else:
                    index += 1
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
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                index += 1
            if index == start:
                index += 1
            nodes += 1
            lexical = text[start:index]
            if lexical.lstrip("-").isdigit() and len(lexical.lstrip("-")) > 19:
                raise JoseAnalysisError("JSON integer exceeds its pre-decoder bound")
        if depth < 0 or depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise JoseAnalysisError("JSON exceeds its pre-decoder node or depth budget")
    if depth != 0:
        raise JoseAnalysisError("JSON structure is incomplete")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise JoseAnalysisError("JSON contains a duplicate member")
            result[key] = value
        return result

    def integer(lexical: str) -> int:
        if len(lexical.lstrip("-")) > 19:
            raise JoseAnalysisError("JSON integer exceeds its finite magnitude")
        value = int(lexical)
        if value.bit_length() > 63:
            raise JoseAnalysisError("JSON integer exceeds its finite magnitude")
        return value

    def unsupported_number(_: str) -> None:
        raise JoseAnalysisError("Fractional or nonfinite numbers are outside this supported subset")

    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported_number,
            parse_constant=unsupported_number,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, JoseAnalysisError):
            raise
        raise JoseAnalysisError("JSON input is malformed") from exc
    return _capture(document)


def _text(value: Any, label: str, maximum: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise JoseAnalysisError(f"{label} must be a bounded native string")
    try:
        if len(value.encode("utf-8")) > maximum:
            raise JoseAnalysisError(f"{label} exceeds its byte bound")
    except UnicodeError as exc:
        raise JoseAnalysisError(f"{label} must be valid Unicode") from exc
    return value


def _decode(value: Any, maximum: int) -> bytes:
    if type(value) is not str or len(value) > (maximum * 4 + 2) // 3:
        raise JoseAnalysisError("Base64url value exceeds its encoded bound")
    if _B64.fullmatch(value) is None:
        raise JoseAnalysisError("Base64url must be nonempty and unpadded")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise JoseAnalysisError("Base64url value is malformed") from exc
    if len(raw) > maximum or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise JoseAnalysisError("Base64url value is not the canonical supported encoding")
    return raw


def _model(value: Any) -> tuple[dict[str, Any], int]:
    model = _capture(value)
    if type(model) is not dict or set(model) != _MODEL_FIELDS:
        raise JoseAnalysisError("JOSE model has an unsupported closed shape")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise JoseAnalysisError("JOSE model schema version must be native integer one")
    algorithm = model["expected_algorithm"]
    if type(algorithm) is not str or algorithm not in _ALGORITHMS:
        raise JoseAnalysisError("Expected algorithm must be explicitly ES256 or RS256")
    token = model["compact_jws"]
    if type(token) is not str or not token.isascii() or not 1 <= len(token) <= MAX_COMPACT_BYTES:
        raise JoseAnalysisError("Compact JWS must be bounded native ASCII")
    _text(model["expected_issuer"], "Expected issuer")
    _text(model["expected_audience"], "Expected audience")
    instant = model["evaluated_at"]
    if type(instant) is not str or _UTC.fullmatch(instant) is None:
        raise JoseAnalysisError("Evaluation instant must be declared canonical UTC")
    try:
        parsed = datetime.strptime(instant, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise JoseAnalysisError("Evaluation instant is invalid") from exc
    epoch = (parsed - datetime(1970, 1, 1, tzinfo=UTC)).days * 86400
    epoch += parsed.hour * 3600 + parsed.minute * 60 + parsed.second
    if not 0 <= epoch <= MAX_EPOCH:
        raise JoseAnalysisError("Evaluation instant is outside the integer epoch subset")
    return model, epoch


def _public_key(jwk: Any, algorithm: str, header: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    if type(jwk) is not dict:
        raise JoseAnalysisError("Public JWK must be an exact native dictionary")
    core = {"kty", "crv", "x", "y"} if algorithm == "ES256" else {"kty", "n", "e"}
    if not core <= set(jwk) or set(jwk) - core - {"alg", "use", "key_ops", "kid"}:
        raise JoseAnalysisError("Only the closed public JWK subset is supported")
    if "alg" in jwk and (type(jwk["alg"]) is not str or jwk["alg"] != algorithm):
        raise JoseAnalysisError("JWK algorithm does not match the explicit algorithm")
    if "use" in jwk and (type(jwk["use"]) is not str or jwk["use"] != "sig"):
        raise JoseAnalysisError("JWK use must be signature verification")
    if "key_ops" in jwk and _canonical(jwk["key_ops"]) != '["verify"]':
        raise JoseAnalysisError("JWK key operations must be exactly verify")
    if "kid" in jwk:
        _text(jwk["kid"], "JWK key ID")
    if "kid" in header and jwk.get("kid") != header["kid"]:
        raise JoseAnalysisError("Declared header key ID does not match the supplied JWK")
    try:
        if algorithm == "ES256":
            if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
                raise JoseAnalysisError("ES256 requires an EC P-256 public JWK")
            x, y = _decode(jwk["x"], 32), _decode(jwk["y"], 32)
            if len(x) != 32 or len(y) != 32:
                raise JoseAnalysisError("P-256 coordinates must each contain exactly 32 octets")
            key = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
            ).public_key()
            return key, {"kty": "EC", "curve": "P-256", "bits": 256}
        if jwk["kty"] != "RSA":
            raise JoseAnalysisError("RS256 requires an RSA public JWK")
        modulus, exponent = _decode(jwk["n"], 512), _decode(jwk["e"], 4)
        if not modulus or modulus[0] == 0 or not exponent or exponent[0] == 0:
            raise JoseAnalysisError("RSA integers require minimal positive Base64urlUInt")
        n, e = int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")
        if not 2048 <= n.bit_length() <= 4096 or n % 2 == 0 or not 3 <= e < n or e % 2 == 0:
            raise JoseAnalysisError("RSA public numbers are outside the supported bound")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        return key, {"kty": "RSA", "curve": None, "bits": key.key_size}
    except (ValueError, UnsupportedAlgorithm) as exc:
        if isinstance(exc, JoseAnalysisError):
            raise
        raise JoseAnalysisError("Supplied public key is invalid or unsupported") from exc


def _claims(claims: dict[str, Any], model: dict[str, Any], now: int) -> dict[str, str]:
    for name in ("exp", "nbf", "iat"):
        if name in claims and (type(claims[name]) is not int or not 0 <= claims[name] <= MAX_EPOCH):
            raise JoseAnalysisError("NumericDate is outside the exact integer epoch subset")

    def claimed_string(value: Any) -> bool:
        return (
            type(value) is str
            and 0 < len(value) <= 512
            and len(value.encode("utf-8")) <= 512
            and not any(ord(char) < 32 or ord(char) == 127 for char in value)
        )

    issuer = (
        "missing"
        if "iss" not in claims
        else "invalid_type"
        if not claimed_string(claims["iss"])
        else "match"
        if claims["iss"] == model["expected_issuer"]
        else "mismatch"
    )
    audience = "missing"
    if "aud" in claims:
        value = claims["aud"]
        audiences = [value] if type(value) is str else value
        if (
            type(audiences) is not list
            or not 1 <= len(audiences) <= 32
            or not all(claimed_string(item) for item in audiences)
            or len(audiences) != len(set(audiences))
        ):
            audience = "invalid_type"
        else:
            audience = "match" if model["expected_audience"] in audiences else "mismatch"
    date_order = "not_assessed"
    if "exp" in claims:
        date_order = (
            "contradictory"
            if any(claims[name] >= claims["exp"] for name in ("nbf", "iat") if name in claims)
            else "consistent"
        )
    return {
        "issuer": issuer,
        "audience": audience,
        "expiration": "missing"
        if "exp" not in claims
        else "before_expiration"
        if now < claims["exp"]
        else "expired",
        "not_before": "not_present"
        if "nbf" not in claims
        else "reached"
        if now >= claims["nbf"]
        else "not_reached",
        "issued_at": "not_present"
        if "iat" not in claims
        else "not_future"
        if now >= claims["iat"]
        else "future",
        "date_order": date_order,
    }


def _observations(checks: dict[str, str]) -> tuple[str, list[str]]:
    negative = sorted(name + "_" + value for name, value in checks.items() if value in _NEGATIVE)
    missing = sorted(name + "_missing" for name, value in checks.items() if value == "missing")
    return (
        "mismatch" if negative else "incomplete" if missing else "consistent_with_supplied_checks",
        sorted(negative + missing),
    )


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _hash({"domain": DOMAIN, "analysis": body})
    return {**body, "analysis_id": "JSA-" + digest[7:39].upper(), "analysis_sha256": digest}


def _report(value: Any) -> dict[str, Any]:
    document = _capture(value)
    expected = {
        "schema_version",
        "profile_id",
        "capability_id",
        "vector_id",
        "algorithm",
        "key",
        "sources",
        "statistics",
        "checks",
        "observations",
        "analysis_status",
        "operational_effects",
        "analysis_id",
        "analysis_sha256",
        *_FLAGS,
    }
    if type(document) is not dict or set(document) != expected:
        raise JoseAnalysisError("JOSE analysis has an unsupported closed shape")
    fixed = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "operational_effects": _EFFECTS,
        **_FLAGS,
    }
    for name, value in fixed.items():
        if _canonical(document[name]) != _canonical(value):
            raise JoseAnalysisError("JOSE analysis changed its fixed nonauthoritative profile")
    algorithm = document["algorithm"]
    if type(algorithm) is not str or algorithm not in _ALGORITHMS:
        raise JoseAnalysisError("JOSE analysis algorithm is unsupported")
    key = document["key"]
    if (
        type(key) is not dict
        or set(key) != {"kty", "curve", "bits"}
        or type(key["bits"]) is not int
    ):
        raise JoseAnalysisError("JOSE analysis key projection is invalid")
    if algorithm == "ES256":
        if _canonical(key) != '{"bits":256,"curve":"P-256","kty":"EC"}':
            raise JoseAnalysisError("JOSE analysis EC projection is invalid")
    elif key["kty"] != "RSA" or key["curve"] is not None or not 2048 <= key["bits"] <= 4096:
        raise JoseAnalysisError("JOSE analysis RSA projection is invalid")
    sources = document["sources"]
    if type(sources) is not dict or set(sources) != {
        "model_sha256",
        "compact_jws_sha256",
        "public_jwk_sha256",
        "compact_jws_bytes",
    }:
        raise JoseAnalysisError("JOSE analysis sources are invalid")
    for name in ("model_sha256", "compact_jws_sha256", "public_jwk_sha256"):
        if type(sources[name]) is not str or _DIGEST.fullmatch(sources[name]) is None:
            raise JoseAnalysisError("JOSE analysis source digest is invalid")
    if (
        type(sources["compact_jws_bytes"]) is not int
        or not 1 <= sources["compact_jws_bytes"] <= MAX_COMPACT_BYTES
    ):
        raise JoseAnalysisError("JOSE analysis source byte count is invalid")
    statistics = document["statistics"]
    ceilings = {
        "protected_header_bytes": MAX_HEADER_BYTES,
        "claims_bytes": MAX_CLAIMS_BYTES,
        "signature_bytes": 512,
        "claim_members": 64,
    }
    if type(statistics) is not dict or set(statistics) != set(ceilings):
        raise JoseAnalysisError("JOSE analysis statistics are invalid")
    for name, ceiling in ceilings.items():
        if type(statistics[name]) is not int or not 0 <= statistics[name] <= ceiling:
            raise JoseAnalysisError("JOSE analysis statistic is outside its native bound")
    expected_signature = 64 if algorithm == "ES256" else (key["bits"] + 7) // 8
    if statistics["signature_bytes"] != expected_signature:
        raise JoseAnalysisError("JOSE analysis signature size contradicts its key")
    checks = document["checks"]
    if type(checks) is not dict or set(checks) != set(_CHECK_VALUES):
        raise JoseAnalysisError("JOSE analysis checks are invalid")
    for name, values in _CHECK_VALUES.items():
        if type(checks[name]) is not str or checks[name] not in values:
            raise JoseAnalysisError("JOSE analysis check is outside its closed vocabulary")
    status, observations = _observations(checks)
    if document["analysis_status"] != status or _canonical(document["observations"]) != _canonical(
        observations
    ):
        raise JoseAnalysisError("JOSE analysis conclusions are internally inconsistent")
    body = {
        name: value
        for name, value in document.items()
        if name not in {"analysis_id", "analysis_sha256"}
    }
    if _canonical(_address(body)) != _canonical(document):
        raise JoseAnalysisError("JOSE analysis content address does not reproduce")
    return document


@dataclass(frozen=True, slots=True)
class JoseAnalysis:
    """Detached unsigned metadata; only supplied-source replay proves conclusions."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    def to_dict(self) -> dict[str, Any]:
        text = self.document_json
        if type(text) is not str or len(text) > MAX_DOCUMENT_BYTES:
            raise JoseAnalysisError("JOSE analysis text is outside its native bound")
        try:
            raw = text.encode("ascii")
        except UnicodeError as exc:
            raise JoseAnalysisError("JOSE analysis text must be canonical ASCII") from exc
        document = _report(_json(raw, maximum=MAX_DOCUMENT_BYTES))
        if _canonical(document) != text:
            raise JoseAnalysisError("JOSE analysis text is not canonical")
        return document

    def to_json(self) -> str:
        self.to_dict()
        return self.document_json

    @classmethod
    def from_dict(cls, document: Any) -> JoseAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: Any) -> JoseAnalysis:
        if type(document) is not str or len(document) > MAX_DOCUMENT_BYTES:
            raise JoseAnalysisError("JOSE analysis input text is outside its native bound")
        try:
            raw = document.encode("utf-8")
        except UnicodeError as exc:
            raise JoseAnalysisError("JOSE analysis input text must be UTF-8") from exc
        return cls.from_dict(_json(raw, maximum=MAX_DOCUMENT_BYTES))


def analyze_supplied_jose(model: Any) -> JoseAnalysis:
    """Observe supplied signature mathematics and explicit declared checks only."""
    captured, now = _model(model)
    token = captured["compact_jws"]
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseAnalysisError("Only compact JWS with three nonempty segments is supported")
    protected, payload, encoded_signature = parts
    header_bytes = _decode(protected, MAX_HEADER_BYTES)
    claims_bytes = _decode(payload, MAX_CLAIMS_BYTES)
    signature = _decode(encoded_signature, 512)
    header = _json(header_bytes, maximum=MAX_HEADER_BYTES)
    claims = _json(claims_bytes, maximum=MAX_CLAIMS_BYTES)
    if (
        type(header) is not dict
        or not {"alg"} <= set(header)
        or set(header) - {"alg", "kid", "typ"}
    ):
        raise JoseAnalysisError("Protected header is outside the supported closed shape")
    algorithm = captured["expected_algorithm"]
    if type(header["alg"]) is not str or header["alg"] != algorithm:
        raise JoseAnalysisError("Protected algorithm does not match the explicit algorithm")
    if "typ" in header and (type(header["typ"]) is not str or header["typ"] != "JWT"):
        raise JoseAnalysisError("Protected type is outside this JWT-claims subset")
    if "kid" in header:
        _text(header["kid"], "Protected key ID")
    if type(claims) is not dict or len(claims) > 64:
        raise JoseAnalysisError("Claims must be a bounded JSON object")
    checks = _claims(claims, captured, now)
    key, dimensions = _public_key(captured["public_jwk"], algorithm, header)
    expected_size = 64 if algorithm == "ES256" else (key.key_size + 7) // 8
    if len(signature) != expected_size:
        raise JoseAnalysisError("Signature length does not match the selected JOSE algorithm")
    signing_input = (protected + "." + payload).encode("ascii")
    checks["signature"] = "invalid"
    try:
        if algorithm == "ES256":
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            order = ec.SECP256R1().group_order
            if 1 <= r < order and 1 <= s < order:
                key.verify(
                    utils.encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256())
                )
                checks["signature"] = "valid"
        else:
            key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            checks["signature"] = "valid"
    except InvalidSignature:
        pass
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise JoseAnalysisError("Signature operation is outside the supported profile") from exc
    status, observations = _observations(checks)
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "algorithm": algorithm,
        "key": dimensions,
        "sources": {
            "model_sha256": _hash(captured),
            "compact_jws_sha256": _bytes_hash(token.encode("ascii")),
            "compact_jws_bytes": len(token),
            "public_jwk_sha256": _hash(captured["public_jwk"]),
        },
        "statistics": {
            "protected_header_bytes": len(header_bytes),
            "claims_bytes": len(claims_bytes),
            "signature_bytes": len(signature),
            "claim_members": len(claims),
        },
        "checks": checks,
        "observations": observations,
        "analysis_status": status,
        "operational_effects": dict(_EFFECTS),
        **_FLAGS,
    }
    owned_body = _capture(body)
    return JoseAnalysis.from_dict(_address(owned_body))


def verify_supplied_jose_analysis(report: Any, *, model: Any) -> JoseAnalysis:
    """Reproduce conclusions from exact supplied sources, never grant their use."""
    if type(report) is not JoseAnalysis:
        raise JoseAnalysisError("JOSE analysis must be an exact owned wrapper")
    try:
        document = report.to_dict()
    except AttributeError as exc:
        raise JoseAnalysisError("JOSE analysis wrapper is incomplete") from exc
    fresh = analyze_supplied_jose(model)
    if fresh.to_json() != _canonical(document):
        raise JoseAnalysisError("JOSE analysis does not reproduce from the supplied sources")
    return fresh

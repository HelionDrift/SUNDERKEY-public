"""Bounded supplied WebAuthn assertion/context arithmetic, not authentication."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "webauthn_supplied_assertion_context_arithmetic"
PROFILE_ID = "AOE-GA-D03-S08"
CAPABILITY_ID = "army.ga.d03.s08"
VECTOR_ID = "AV-GA-D03-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S08"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GA-D03-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b3ed2155fb5865d00f551b389cfb9ba83d411c57361a208e51cb69ae7273bf79"
SEMANTICS_PROFILE = "webauthn-rec-20260825-supplied-unextended-assertion-context.v1"
MODEL_DOMAIN = "sunderkey.offline-webauthn-assertion-model.v1"
DOMAIN = "sunderkey.offline-webauthn-assertion-analysis.v1"
MAX_AUTHENTICATOR_BYTES = 4_096
MAX_CLIENT_BYTES = 16_384
MAX_CHALLENGE_BYTES = 1_024
MAX_RP_ID_BYTES = 253
MAX_ORIGIN_BYTES = 2_048
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 4_096
MAX_CLIENT_NODES = 4_096
MAX_REPORT_NODES = 16_384
MAX_DEPTH = 16
MAX_CLIENT_NUMBER_BYTES = 128
MAX_OBSERVATIONS = 32
MAX_WORK = 67_108_864
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_MODEL_KEYS = {
    "schema_version",
    "source_id",
    "authenticator_data_base64",
    "client_data_json_base64",
    "context",
}
_CONTEXT_KEYS = {
    "rp_id",
    "challenge_base64",
    "origin",
    "cross_origin",
    "top_origin",
    "user_verification_required",
    "previous_sign_count",
}
_CLIENT_KEYS = {"type", "challenge", "origin", "crossOrigin", "topOrigin"}
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "credential_validated",
        "signature_verified",
        "user_authenticated",
        "user_presence_verified",
        "user_verification_verified",
        "origin_ownership_verified",
        "origin_syntax_validated",
        "rp_id_syntax_validated",
        "challenge_quality_verified",
        "cloned_authenticator_proven",
        "counter_state_updated",
        "current_permission_verified",
        "full_webauthn_validity_verified",
        "vulnerability_claimed",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "file_acquisition",
        "network",
        "credential",
        "authenticator",
        "provider",
        "process",
        "execution",
        "authority",
        "qualification",
        "deployment",
    ),
    "none",
)
_LIMITATIONS = (
    "Supplied source bytes and context are unsigned premises, not credential or origin evidence.",
    "Only the fixed assertion prefix and known unextended flags are assessed.",
    "AT, ED and reserved bits leave suffix/extension semantics unassessed, "
    "not valid or invalid CBOR.",
    "UP/UV/BE/BS are observed bits, not independently verified user or authenticator properties.",
    "The complete original client JSON bytes, including a BOM if present, are hashed unchanged.",
    "Unknown client JSON members/order are tolerated within software bounds and not interpreted.",
    "Declared top-origin absence/value is compared, not a universal requirement for optional data.",
    "Counter comparison is arithmetic only; "
    "nonincrease is not clone proof or a rejection decision.",
    "No registration, userHandle, signature, AppID, "
    "credential/CBOR or origin-authorization analysis.",
    "No URL/PSL lookup, challenge randomness/freshness, counter custody or current-use permission.",
    "Embedded base64 retains unsanitized source bytes; metadata is not a redaction guarantee.",
    "Exact replay proves this computation, "
    "not source authenticity, authentication or qualification.",
    "Budgets are local weighted software-cost ceilings; simultaneous maxima need not fit a pass.",
)


class WebAuthnAssertionAnalysisError(ValueError):
    """Closed intake, exact replay or a local software-cost ceiling was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise WebAuthnAssertionAnalysisError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise WebAuthnAssertionAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise WebAuthnAssertionAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > byte_limit:
                raise WebAuthnAssertionAnalysisError("Native string ceiling exhausted")
            add(2)
            for char in item:
                budget.charge(1)
                code = ord(char)
                if char in '\\"\b\f\n\r\t':
                    add(2)
                elif code < 32 or code >= 127:
                    add(6 if code <= 65535 else 12)
                else:
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise WebAuthnAssertionAnalysisError("Exact native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise WebAuthnAssertionAnalysisError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise WebAuthnAssertionAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise WebAuthnAssertionAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise WebAuthnAssertionAnalysisError("Exact integer-only native JSON families required")

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
        raise WebAuthnAssertionAnalysisError("Bounded raw integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    ceiling = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > ceiling:
        raise WebAuthnAssertionAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


@dataclass(frozen=True, slots=True)
class _NumberToken:
    lexical: str


def _number_token(text: str) -> _NumberToken:
    if len(text) > MAX_CLIENT_NUMBER_BYTES or _NUMBER.fullmatch(text) is None:
        raise WebAuthnAssertionAnalysisError("Bounded client JSON number grammar required")
    return _NumberToken(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False, client: bool = False) -> Any:
    byte_limit = MAX_CLIENT_BYTES if client else (MAX_REPORT_BYTES if report else MAX_MODEL_BYTES)
    node_limit = MAX_CLIENT_NODES if client else (MAX_REPORT_NODES if report else MAX_MODEL_NODES)
    if type(text) is not str or not text or len(text) > byte_limit:
        raise WebAuthnAssertionAnalysisError("Bounded exact native JSON text required")
    if not client and not text.isascii():
        raise WebAuthnAssertionAnalysisError("ASCII outer JSON metadata required")
    budget.charge(4 * len(text))
    stack: list[str] = []
    index = nodes = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise WebAuthnAssertionAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise WebAuthnAssertionAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            string_size = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                if ord(text[index]) < 32:
                    raise WebAuthnAssertionAnalysisError("Unescaped JSON control character")
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise WebAuthnAssertionAnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise WebAuthnAssertionAnalysisError("Malformed JSON Unicode escape")
                        index += 4
                    elif text[index] not in '\\"/bfnrt':
                        raise WebAuthnAssertionAnalysisError("Malformed JSON escape")
                string_size += 1
                if string_size > byte_limit:
                    raise WebAuthnAssertionAnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise WebAuthnAssertionAnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            maximum = MAX_CLIENT_NUMBER_BYTES if client else 20
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > maximum:
                    raise WebAuthnAssertionAnalysisError(
                        "Pre-decoder scalar lexical ceiling exhausted"
                    )
            token = text[start:index]
            if token not in ("true", "false", "null"):
                if client:
                    _number_token(token)
                else:
                    _integer(token)
    if stack:
        raise WebAuthnAssertionAnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in items:
            if key in owned:
                raise WebAuthnAssertionAnalysisError("Duplicate raw JSON key")
            owned[key] = child
        return owned

    def unsupported(_: str) -> None:
        raise WebAuthnAssertionAnalysisError("Integer-only outer JSON required")

    budget.charge(8 * len(text) + 64 * nodes)
    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_number_token if client else _integer,
            parse_float=_number_token if client else unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise WebAuthnAssertionAnalysisError("Malformed bounded JSON document") from exc


def _base64_bytes(value: Any, maximum: int, minimum: int, budget: _Budget) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise WebAuthnAssertionAnalysisError("Bounded exact native base64 required")
    budget.charge(4 * len(value))
    if len(value) % 4 or _BASE64.fullmatch(value) is None:
        raise WebAuthnAssertionAnalysisError("Canonical padded base64 required")
    padding = len(value) - len(value.rstrip("="))
    length = len(value) // 4 * 3 - padding
    if not minimum <= length <= maximum:
        raise WebAuthnAssertionAnalysisError("Supplied byte ceiling or prefix truncation")
    budget.charge(4 * len(value) + 8 * length)
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WebAuthnAssertionAnalysisError("Malformed canonical base64") from exc
    if len(data) != length or base64.b64encode(data).decode("ascii") != value:
        raise WebAuthnAssertionAnalysisError("Noncanonical base64 padding bits")
    return data


def _text(value: Any, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise WebAuthnAssertionAnalysisError("Bounded exact context text required")
    if any(not 32 <= ord(char) <= 126 for char in value):
        raise WebAuthnAssertionAnalysisError("Printable ASCII supplied context required")
    return value


def _context(value: Any, budget: _Budget) -> tuple[dict, bytes]:
    if type(value) is not dict or value.keys() != _CONTEXT_KEYS:
        raise WebAuthnAssertionAnalysisError("Exact closed supplied context required")
    _text(value["rp_id"], MAX_RP_ID_BYTES)
    _text(value["origin"], MAX_ORIGIN_BYTES)
    for name in ("cross_origin", "user_verification_required"):
        if type(value[name]) is not bool:
            raise WebAuthnAssertionAnalysisError("Exact context booleans required")
    top = value["top_origin"]
    if top is not None:
        _text(top, MAX_ORIGIN_BYTES)
        if not value["cross_origin"]:
            raise WebAuthnAssertionAnalysisError(
                "Top-origin expectation requires cross-origin context"
            )
    previous = value["previous_sign_count"]
    if previous is not None and (type(previous) is not int or not 0 <= previous <= 0xFFFFFFFF):
        raise WebAuthnAssertionAnalysisError("Nullable exact native uint32 counter required")
    challenge = _base64_bytes(value["challenge_base64"], MAX_CHALLENGE_BYTES, 0, budget)
    return value, challenge


def _client(data: bytes, budget: _Budget) -> dict:
    budget.charge(4 * len(data))
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise WebAuthnAssertionAnalysisError("Well-formed UTF8 client JSON required") from exc
    value = _decode(text, budget, client=True)
    if type(value) is not dict:
        raise WebAuthnAssertionAnalysisError("Client JSON object required")
    for name in ("type", "challenge", "origin"):
        if name not in value or type(value[name]) is not str:
            raise WebAuthnAssertionAnalysisError("Required client-data text fields are malformed")
    cross_present = "crossOrigin" in value
    if cross_present and type(value["crossOrigin"]) is not bool:
        raise WebAuthnAssertionAnalysisError("Client crossOrigin requires an exact boolean")
    top_present = "topOrigin" in value
    if top_present and type(value["topOrigin"]) is not str:
        raise WebAuthnAssertionAnalysisError("Client topOrigin requires text when present")
    budget.charge(4 * len(data) + 64 * len(value))
    return {
        "type": value["type"],
        "challenge": value["challenge"],
        "origin": value["origin"],
        "cross_origin_present": cross_present,
        "cross_origin": value["crossOrigin"] if cross_present else False,
        "top_origin_present": top_present,
        "top_origin": value["topOrigin"] if top_present else None,
        "unknown_member_count": sum(key not in _CLIENT_KEYS for key in value),
        "leading_bom_present": data.startswith(b"\xef\xbb\xbf"),
    }


def _bounds() -> dict:
    return {
        "authenticator_bytes": MAX_AUTHENTICATOR_BYTES,
        "client_json_bytes": MAX_CLIENT_BYTES,
        "challenge_bytes": MAX_CHALLENGE_BYTES,
        "rp_id_bytes": MAX_RP_ID_BYTES,
        "origin_bytes": MAX_ORIGIN_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "client_json_nodes": MAX_CLIENT_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "client_number_lexical_bytes": MAX_CLIENT_NUMBER_BYTES,
        "observations": MAX_OBSERVATIONS,
        "cumulative_work_per_public_operation": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    authenticator: bytes
    client: bytes
    maximum_report_size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size, _ = _capture(model, budget)
    if type(source) is not dict or source.keys() != _MODEL_KEYS:
        raise WebAuthnAssertionAnalysisError("Exact closed source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise WebAuthnAssertionAnalysisError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _IDENTITY.fullmatch(source["source_id"]) is None:
        raise WebAuthnAssertionAnalysisError("Bounded native source identity required")
    context, challenge = _context(source["context"], budget)
    auth = _base64_bytes(source["authenticator_data_base64"], MAX_AUTHENTICATOR_BYTES, 37, budget)
    raw_client = _base64_bytes(source["client_data_json_base64"], MAX_CLIENT_BYTES, 2, budget)
    client = _client(raw_client, budget)
    budget.charge(8 * len(challenge) + 128)
    challenge_text = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii")
    bits, count = auth[32], int.from_bytes(auth[33:37], "big")
    flags = {
        "user_present": bool(bits & 1),
        "reserved_bit_1": bool(bits & 2),
        "user_verified": bool(bits & 4),
        "backup_eligible": bool(bits & 8),
        "backup_state": bool(bits & 16),
        "reserved_bit_5": bool(bits & 32),
        "attested_data_included": bool(bits & 64),
        "extension_data_included": bool(bits & 128),
    }
    unsupported = []
    if bits & 0x22:
        unsupported.append("reserved_flags_unassessed")
    if bits & 0x40:
        unsupported.append("attested_credential_data_unassessed")
    if bits & 0x80:
        unsupported.append("authenticator_extensions_unassessed")
    previous = context["previous_sign_count"]
    if previous is None:
        relation = "prior_unavailable"
    elif previous == count == 0:
        relation = "both_zero"
    elif count > previous:
        relation = "increased"
    else:
        relation = "nonincreasing_signal"
    checks = {
        "client_type_matches": client["type"] == "webauthn.get",
        "challenge_matches": client["challenge"] == challenge_text,
        "origin_matches": client["origin"] == context["origin"],
        "cross_origin_matches": client["cross_origin"] == context["cross_origin"],
        "top_origin_presence_matches": client["top_origin_present"]
        == (context["top_origin"] is not None),
        "top_origin_value_matches": client["top_origin"] == context["top_origin"],
        "top_origin_cross_origin_consistent": not client["top_origin_present"]
        or client["cross_origin"],
        "user_present_bit_set": flags["user_present"],
        "user_verification_requirement_satisfied": not context["user_verification_required"]
        or flags["user_verified"],
        "backup_flags_consistent": not flags["backup_state"] or flags["backup_eligible"],
        "fixed_layout_length_matches": None if unsupported else len(auth) == 37,
        # False has maximal boolean encoded length; its actual value is not yet known.
        "rp_id_hash_matches": False,
    }
    if len(checks) + len(unsupported) + 1 > MAX_OBSERVATIONS:
        raise WebAuthnAssertionAnalysisError("Observation ceiling exhausted")
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
        "source_model": source,
        "source_model_sha256": _PLACEHOLDER,
        "authenticator_data_sha256": _PLACEHOLDER,
        "client_data_json_sha256": _PLACEHOLDER,
        "expected_rp_id_sha256": _PLACEHOLDER,
        "signature_input_sha256": _PLACEHOLDER,
        "authenticator_data_bytes": len(auth),
        "client_data_json_bytes": len(raw_client),
        "signature_input_bytes": len(auth) + 32,
        "authenticator_prefix": {
            "rp_id_hash": "sha256:" + auth[:32].hex(),
            "flags_byte": bits,
            "flags": flags,
            "sign_count": count,
            "unparsed_suffix_bytes": len(auth) - 37,
        },
        "client_data": client,
        "checks": checks,
        "counter_relation": relation,
        "unsupported_reasons": unsupported,
        # All eventual enum values fit 64 ASCII characters. This conservative
        # reservation covers hash-dependent final status without hashing first.
        "analysis_status": "x" * 64,
        "claims": _CLAIMS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "WAA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    document, size, nodes = _capture(document, budget, report=True)
    # Conservatively fund all subsequent materialization, six digests, preimage,
    # sorted encodings, body copies and result/equality buffers. The plan includes
    # the longest boolean, 64-byte status, final identity fields and all source.
    # There are no cost charges or newly discovered output bounds after hashing.
    budget.charge(
        32 * size
        + 16 * source_size
        + 32 * (len(auth) + len(raw_client) + len(challenge))
        + 32 * nodes
        + 16 * MAX_RP_ID_BYTES
        + 1_024
        + len(MODEL_DOMAIN)
        + len(DOMAIN)
    )
    return _Plan(document, auth, raw_client, size)


def _digest(domain: str, value: dict) -> str:
    payload = domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _materialize(plan: _Plan) -> str:
    document = plan.document
    rp_digest = hashlib.sha256(
        document["source_model"]["context"]["rp_id"].encode("ascii")
    ).digest()
    client_digest = hashlib.sha256(plan.client).digest()
    document["checks"]["rp_id_hash_matches"] = plan.authenticator[:32] == rp_digest
    if any(value is False for value in document["checks"].values()):
        status = "contradictory_supplied_checks"
    elif document["unsupported_reasons"]:
        status = "unassessed_supported_profile"
    else:
        status = "consistent_with_supplied_checks"
    document["analysis_status"] = status
    document["expected_rp_id_sha256"] = "sha256:" + rp_digest.hex()
    document["client_data_json_sha256"] = "sha256:" + client_digest.hex()
    document["authenticator_data_sha256"] = (
        "sha256:" + hashlib.sha256(plan.authenticator).hexdigest()
    )
    document["signature_input_sha256"] = (
        "sha256:" + hashlib.sha256(plan.authenticator + client_digest).hexdigest()
    )
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: child
        for key, child in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "WAA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise WebAuthnAssertionAnalysisError("Report requires complete embedded source")
    size, nodes = _measure(document, budget, report=True)
    plan = _plan(document["source_model"], budget)
    budget.charge(8 * size + 4 * plan.maximum_report_size + 8 * nodes)
    return document, plan


def _compare(text: str, document: dict, expected: str) -> None:
    canonical = _canonical(document)
    if text != canonical or canonical != expected:
        raise WebAuthnAssertionAnalysisError(
            "Canonical report does not completely replay its source"
        )


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not WebAuthnAssertionAnalysis:
        raise WebAuthnAssertionAnalysisError("Exact native report wrapper required")
    try:
        text = report.document_json
    except AttributeError as exc:
        raise WebAuthnAssertionAnalysisError("Complete native report wrapper required") from exc
    if type(text) is not str:
        raise WebAuthnAssertionAnalysisError("Exact native report text required")
    return text


@dataclass(frozen=True, slots=True)
class WebAuthnAssertionAnalysis:
    """Unsigned owned metadata; every public export fully replays embedded source."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not WebAuthnAssertionAnalysis:
            raise WebAuthnAssertionAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> WebAuthnAssertionAnalysis:
        if cls is not WebAuthnAssertionAnalysis:
            raise WebAuthnAssertionAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> WebAuthnAssertionAnalysis:
        if cls is not WebAuthnAssertionAnalysis:
            raise WebAuthnAssertionAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def _owned(text: str) -> WebAuthnAssertionAnalysis:
    result = object.__new__(WebAuthnAssertionAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_webauthn_assertion(model: Any) -> WebAuthnAssertionAnalysis:
    """Compare supplied bytes/context without credential or authentication validation."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_webauthn_assertion_bytes(*, model_bytes: Any) -> WebAuthnAssertionAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise WebAuthnAssertionAnalysisError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(4 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebAuthnAssertionAnalysisError("ASCII outer JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_webauthn_assertion_analysis(
    report: Any, *, model: Any
) -> WebAuthnAssertionAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(8 * (embedded.maximum_report_size + original.maximum_report_size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise WebAuthnAssertionAnalysisError(
            "Report contradicts the separately supplied original model"
        )
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh synthetic context; literal benign byte fixtures are pinned by owned tests."""
    return {
        "schema_version": 1,
        "source_id": "fixture-assertion-01",
        "authenticator_data_base64": "JnieIDZhHoSuxlBFqFBiSKiV5H+n3+pQ5K0QyFXL8rkFAAAAAQ==",
        "client_data_json_base64": (
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9E"
            "eEFSRWhNVUZSWVhHQmthR3h3ZEhoOCIsIm9yaWdpbiI6Imh0dHBzOi8vbG9naW4uZXhhbXBsZS5p"
            "bnZhbGlkIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
        ),
        "context": {
            "rp_id": "example.invalid",
            "challenge_base64": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            "origin": "https://login.example.invalid",
            "cross_origin": False,
            "top_origin": None,
            "user_verification_required": True,
            "previous_sign_count": 0,
        },
    }


__all__ = [
    "WebAuthnAssertionAnalysis",
    "WebAuthnAssertionAnalysisError",
    "analyze_supplied_webauthn_assertion",
    "analyze_supplied_webauthn_assertion_bytes",
    "verify_supplied_webauthn_assertion_analysis",
    "component_fixture",
]

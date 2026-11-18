"""Bounded RFC7252 supplied CON-GET/piggyback-ACK byte structure arithmetic."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "coap_supplied_get_piggyback_structure"
PROFILE_ID = "AOE-GD-D18-S15"
CAPABILITY_ID = "army.gd.d18.s15"
VECTOR_ID = "AV-GD-D18-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S15"
WAVE_ID = "IW2-019"
BLUEPRINT_SHA256 = "sha256:a3e9ff84eaf62017510d6009eb674c0e8790538e96ad8a9bd86a99b0c4c9af3b"
SEMANTICS_PROFILE = "rfc7252-supplied-con-get-piggyback-structure.v1"
MODEL_DOMAIN = "sunderkey.offline-coap-model.v1"
DOMAIN = "sunderkey.offline-coap-analysis.v1"
MAX_DATAGRAM_BYTES = 8_192
MAX_MODEL_BYTES = 32_768
MAX_REPORT_BYTES = 262_144
MAX_NODES = 16_384
MAX_DEPTH = 16
MAX_STRING_BYTES = 16_384
MAX_OPTIONS = 128
MAX_REASONS = 64
MAX_WORK = 16_777_216
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_MODEL_FIELDS = {
    "schema_version",
    "request_source_id",
    "response_source_id",
    "request_base64",
    "response_base64",
}
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "CPA-" + "0" * 32
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "network",
        "target",
        "provider",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "publication",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "endpoint_identity_proven",
        "shared_exchange_proven",
        "delivery_proven",
        "response_content_truth_proven",
        "resource_access_proven",
        "full_protocol_conformance_proven",
        "security_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Two supplied datagrams and source labels are unauthenticated declarations.",
    "Only RFC7252 version-one byte geometry and selected CON-GET/ACK predicates are projected.",
    "MID/token equality does not prove endpoints, shared traffic, delivery or resource access.",
    "An Empty ACK is not a response; separate and other exchanges remain unassessed.",
    "Option lengths/repetition/applicability are not URI, UTF8, proxy, cache "
    "or content validation.",
    "Unknown, inapplicable and supernumerary options retain explicit uncertainty.",
    "Integer option leading zeros are accepted; byte spelling is never normalized.",
    "Payload bytes are opaque; neither error nor success codes establish actual outcomes.",
    "No UDP, DTLS, TCP, retransmission, discovery, multicast or endpoint operation occurs.",
    "Canonical parsed model provenance is distinct from original raw JSON byte provenance.",
    "Software ceilings are narrower than protocol possibilities; simultaneous maxima may not fit.",
    "No full specialist, qualification, routing or deployment approval follows.",
)
# Independently transcribed RFC7252 Table 4 geometry, not an endpoint option registry.
# name, value format, minimum length, maximum length, ordinarily repeatable
_OPTIONS = {
    1: ("If-Match", "opaque", 0, 8, True),
    3: ("Uri-Host", "string", 1, 255, False),
    4: ("ETag", "opaque", 1, 8, True),
    5: ("If-None-Match", "empty", 0, 0, False),
    7: ("Uri-Port", "uint", 0, 2, False),
    8: ("Location-Path", "string", 0, 255, True),
    11: ("Uri-Path", "string", 0, 255, True),
    12: ("Content-Format", "uint", 0, 2, False),
    14: ("Max-Age", "uint", 0, 4, False),
    15: ("Uri-Query", "string", 0, 255, True),
    17: ("Accept", "uint", 0, 2, False),
    20: ("Location-Query", "string", 0, 255, True),
    35: ("Proxy-Uri", "string", 1, 1034, False),
    39: ("Proxy-Scheme", "string", 1, 255, False),
    60: ("Size1", "uint", 0, 4, False),
}
_GET_RESPONSE_CODES = {
    67,
    69,
    128,
    129,
    130,
    131,
    132,
    133,
    134,
    140,
    141,
    143,
    160,
    161,
    162,
    163,
    164,
    165,
}


class CoapAnalysisError(ValueError):
    """An exact contract, finite software ceiling or full replay was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise CoapAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > limit - size:
            raise CoapAnalysisError("Escaped canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise CoapAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise CoapAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise CoapAnalysisError("Closed metadata requires ASCII strings")
                if char in '\\"\b\t\n\f\r':
                    add(1)
                elif code < 32 or code == 127:
                    add(5)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise CoapAnalysisError("Exact native signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise CoapAnalysisError("Cyclic native documents are rejected")
            children = len(item) * (2 if kind is dict else 1)
            if children > MAX_NODES - nodes:
                raise CoapAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise CoapAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise CoapAnalysisError("Exact native integer-only JSON families required")

    visit(value, 1)
    return size, nodes


def _clone(value: Any) -> Any:
    if type(value) is dict:
        return {key: _clone(child) for key, child in value.items()}
    if type(value) is list:
        return [_clone(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _clone(value), size


def _integer(text: str) -> int:
    if len(text) > 20 or _INTEGER.fullmatch(text) is None:
        raise CoapAnalysisError("Bounded raw integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    maximum = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise CoapAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _raw_string(text: str, start: int, budget: _Budget) -> int:
    index, count = start + 1, 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1
        budget.charge(1)
        if char == "\\":
            index += 1
            if index >= len(text):
                raise CoapAnalysisError("Incomplete raw JSON escape")
            if text[index] == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise CoapAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise CoapAnalysisError("Closed metadata requires ASCII strings")
                index += 4
            elif text[index] not in '\\"/bfnrt':
                raise CoapAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise CoapAnalysisError("Invalid raw JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise CoapAnalysisError("Pre-decoder string ceiling exhausted")
        index += 1
    raise CoapAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    if type(text) is not str or not text or len(text) > limit or not text.isascii():
        raise CoapAnalysisError("Bounded exact native ASCII JSON text required")
    budget.charge(2 * len(text))
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise CoapAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > MAX_NODES or len(stack) + 1 > MAX_DEPTH:
            raise CoapAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index = _raw_string(text, index, budget)
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise CoapAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise CoapAnalysisError("Unterminated raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in items:
            if key in owned:
                raise CoapAnalysisError("Duplicate raw JSON key")
            owned[key] = child
        return owned

    def unsupported(_: str) -> None:
        raise CoapAnalysisError("Raw floating/nonfinite numbers are unsupported")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CoapAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_DATAGRAM_BYTES + 2) // 3):
        raise CoapAnalysisError("Bounded exact native canonical base64 required")
    budget.charge(3 * len(text))
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise CoapAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 0 <= length <= MAX_DATAGRAM_BYTES:
        raise CoapAnalysisError("Datagram software byte ceiling exhausted")
    budget.charge(4 * len(text) + 4 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CoapAnalysisError("Malformed supplied base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise CoapAnalysisError("Noncanonical base64 spelling/padding bits")
    return raw


def _reason(rows: list[str], text: str, budget: _Budget) -> None:
    budget.charge(1 + sum(len(row) + len(text) for row in rows))
    if text not in rows:
        if len(rows) >= MAX_REASONS:
            raise CoapAnalysisError("Reason software ceiling exhausted")
        budget.charge(1 + len(text))
        rows.append(text)


def _applicability(number: int, code: int) -> str:
    if code == 1:
        if number in {1, 3, 4, 5, 7, 11, 15, 17, 35, 39}:
            return "applicable_to_get_projection"
        if number == 60:
            return "unassessed_applicability"
        return "unrecognized_method_code"
    if code in _GET_RESPONSE_CODES:
        if number == 4:
            return (
                "applicable_to_response_projection"
                if code in {67, 69}
                else (
                    "unassessed_applicability"
                    if code not in {128, 132}
                    else "unrecognized_method_code"
                )
            )
        if number == 12:
            return (
                "unrecognized_method_code"
                if code in {67, 134}
                else ("applicable_to_response_projection")
            )
        if number == 14:
            return "applicable_to_response_projection"
        if number == 60:
            return (
                "applicable_to_response_projection" if code == 141 else ("unrecognized_method_code")
            )
        return "unrecognized_method_code"
    return "unassessed_applicability"


def _option(number: int, value: bytes, occurrence: int, code: int, budget: _Budget) -> dict:
    budget.charge(128 + 4 * len(value))
    definition = _OPTIONS.get(number)
    result = {
        "number": number,
        "occurrence": occurrence,
        "critical": bool(number & 1),
        "unsafe_to_forward": bool(number & 2),
        "no_cache_key_bits": (number & 0x1E) == 0x1C,
        "name": None,
        "format": "unassessed",
        "length_within_definition": None,
        "value_hex": value.hex(),
        "uint_value": None,
        "recognition": "unrecognized_option_number",
        "value_semantics": "unassessed",
    }
    if definition is None:
        return result
    name, form, minimum, maximum, repeatable = definition
    length_ok = minimum <= len(value) <= maximum
    result.update(name=name, format=form, length_within_definition=length_ok)
    if not length_ok:
        result["recognition"] = "unrecognized_option_length"
    elif occurrence > 1 and (not repeatable or (number == 4 and code >> 5 != 0)):
        result["recognition"] = "unrecognized_supernumerary_option"
    else:
        result["recognition"] = _applicability(number, code)
    if form == "uint" and length_ok:
        result["uint_value"] = int.from_bytes(value, "big")
        result["value_semantics"] = "unsigned_integer_bytes_checked"
    elif form in {"opaque", "empty"} and length_ok:
        result["value_semantics"] = "opaque_or_empty_length_only"
    elif form == "string":
        result["value_semantics"] = "string_bytes_not_normalized_or_validated"
    return result


def _extended(raw: bytes, position: int, nibble: int, budget: _Budget) -> tuple[int, int] | None:
    budget.charge(8)
    width = 0 if nibble < 13 else 1 if nibble == 13 else 2
    if width > len(raw) - position:
        return None
    if width == 0:
        return nibble, position
    # Geometry is independently written arithmetic over network-order unsigned bytes.
    value = raw[position] if width == 1 else raw[position] * 256 + raw[position + 1]
    return value + (13 if width == 1 else 269), position + width


def _message(
    raw: bytes, side: str, budget: _Budget, contradictions: list[str], unknown: list[str]
) -> dict:
    budget.charge(256 + 4 * len(raw))
    result = {
        "byte_length": len(raw),
        "header_complete": len(raw) >= 4,
        "version": None,
        "type": None,
        "code": None,
        "code_class": None,
        "code_detail": None,
        "message_id": None,
        "token_length": None,
        "token_hex": None,
        "framing_complete": False,
        "options": [],
        "payload_marker_offset": None,
        "payload_hex": "",
        "payload_bytes": 0,
    }
    if len(raw) < 4:
        _reason(unknown, side + "_truncated_header", budget)
        return result
    version, kind, token_length = raw[0] >> 6, (raw[0] >> 4) & 3, raw[0] & 15
    code = raw[1]
    result.update(
        version=version,
        type=kind,
        code=code,
        code_class=code >> 5,
        code_detail=code & 31,
        message_id=raw[2] * 256 + raw[3],
        token_length=token_length,
    )
    if version != 1:
        _reason(unknown, side + "_version_outside_rfc7252", budget)
        return result
    if token_length > 8:
        _reason(contradictions, side + "_reserved_token_length", budget)
        return result
    if code == 0 and (token_length or len(raw) != 4):
        _reason(contradictions, side + "_nonempty_empty_message", budget)
        return result
    if token_length > len(raw) - 4:
        _reason(unknown, side + "_truncated_token", budget)
        return result
    result["token_hex"] = raw[4 : 4 + token_length].hex()
    position = 4 + token_length
    number = 0
    occurrences: dict[int, int] = {}
    retained_size = retained_nodes = 0
    while position < len(raw):
        budget.charge(32)
        begin = position
        first = raw[position]
        position += 1
        if first == 255:
            result["payload_marker_offset"] = begin
            if position == len(raw):
                _reason(contradictions, side + "_marker_without_payload", budget)
                return result
            budget.charge(4 * (len(raw) - position))
            result["payload_hex"] = raw[position:].hex()
            result["payload_bytes"] = len(raw) - position
            result["framing_complete"] = True
            return result
        delta_nibble, length_nibble = first >> 4, first & 15
        if delta_nibble == 15 or length_nibble == 15:
            _reason(contradictions, side + "_reserved_option_nibble", budget)
            return result
        delta = _extended(raw, position, delta_nibble, budget)
        if delta is None:
            _reason(unknown, side + "_truncated_option_delta", budget)
            return result
        delta_value, position = delta
        length = _extended(raw, position, length_nibble, budget)
        if length is None:
            _reason(unknown, side + "_truncated_option_length", budget)
            return result
        length_value, position = length
        if length_value > len(raw) - position:
            _reason(unknown, side + "_truncated_option_value", budget)
            return result
        if len(result["options"]) >= MAX_OPTIONS:
            raise CoapAnalysisError("Options-per-datagram software ceiling exhausted")
        number += delta_value
        occurrences[number] = occurrences.get(number, 0) + 1
        budget.charge(4 * length_value + 128)
        row = _option(
            number, raw[position : position + length_value], occurrences[number], code, budget
        )
        row.update(
            index=len(result["options"]),
            header_offset=begin,
            value_offset=position,
            value_length=length_value,
            end_offset=position + length_value,
            delta=delta_value,
        )
        if row["recognition"].startswith("unrecognized"):
            _reason(unknown, side + "_unrecognized_options", budget)
        if row["recognition"] == "unassessed_applicability":
            _reason(unknown, side + "_option_applicability_unassessed", budget)
        if row["format"] == "string":
            _reason(unknown, side + "_string_option_semantics_unassessed", budget)
        if number in {1, 5, 35, 39}:
            _reason(unknown, side + "_conditional_or_proxy_semantics_unassessed", budget)
        size, nodes = _measure(row, budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - retained_size or nodes > MAX_NODES - retained_nodes:
            raise CoapAnalysisError("Cumulative option output retention ceiling exhausted")
        budget.charge(4 * (size + nodes))
        retained_size += size + 1
        retained_nodes += nodes
        result["options"].append(row)
        position += length_value
    result["framing_complete"] = True
    return result


def _relations(request: bytes, response: bytes, budget: _Budget) -> dict:
    budget.charge(512)
    contradictions: list[str] = []
    unknown: list[str] = []
    req = _message(request, "request", budget, contradictions, unknown)
    rsp = _message(response, "response", budget, contradictions, unknown)
    checks = {"message_ids_equal": None, "tokens_equal": None, "piggyback_relation_assessed": False}
    eligible_request = req["framing_complete"] and req["type"] == 0 and req["code"] == 1
    if req["header_complete"] and req["version"] == 1:
        if req["type"] != 0 or req["code"] != 1:
            _reason(unknown, "request_outside_con_get_projection", budget)
        if req["code"] == 1 and req["payload_bytes"]:
            _reason(unknown, "get_payload_semantics_unassessed", budget)
    response_kind = "unassessed"
    if rsp["header_complete"] and rsp["version"] == 1:
        if rsp["type"] == 2 and rsp["code"] == 0:
            response_kind = "empty_ack"
            _reason(unknown, "empty_ack_separate_response_not_supplied", budget)
        elif rsp["type"] == 2 and rsp["code"] in _GET_RESPONSE_CODES:
            response_kind = "piggyback_candidate"
        else:
            _reason(unknown, "response_outside_piggyback_code_projection", budget)
            if rsp["type"] in {0, 1} and rsp["code_class"] in {2, 4, 5}:
                response_kind = "separate_response_unassessed"
        if rsp["type"] == 2 and rsp["code_class"] == 0 and rsp["code"]:
            _reason(contradictions, "ack_carries_request_code", budget)
        if rsp["type"] == 3 and rsp["code"]:
            _reason(contradictions, "nonempty_reset_message", budget)
    eligible_response = rsp["framing_complete"] and response_kind == "piggyback_candidate"
    if eligible_request and rsp["framing_complete"] and rsp["type"] == 2:
        checks["message_ids_equal"] = req["message_id"] == rsp["message_id"]
        if not checks["message_ids_equal"]:
            _reason(contradictions, "ack_message_id_mismatch", budget)
    if eligible_request and eligible_response:
        checks["piggyback_relation_assessed"] = True
        checks["tokens_equal"] = req["token_hex"] == rsp["token_hex"]
        if not checks["tokens_equal"]:
            _reason(contradictions, "piggyback_token_mismatch", budget)
        if rsp["code"] == 67:
            budget.charge(32 * len(rsp["options"]))
            etags = [
                row
                for row in rsp["options"]
                if row["number"] == 4 and row["recognition"].startswith("applicable")
            ]
            if not etags:
                _reason(contradictions, "valid_response_without_recognized_etag", budget)
            if rsp["payload_bytes"]:
                _reason(contradictions, "valid_response_has_payload", budget)
            _reason(unknown, "representation_validation_facts_unassessed", budget)
        if rsp["code"] == 134 and rsp["payload_bytes"]:
            _reason(unknown, "not_acceptable_payload_semantics_unassessed", budget)
    complete = eligible_request and eligible_response and not unknown and not contradictions
    outcome = (
        "consistent_supported_piggyback_structure"
        if complete
        else (
            "structural_contradictions_observed" if contradictions else "incomplete_or_unassessed"
        )
    )
    budget.charge(4 * sum(len(row) for row in contradictions + unknown))
    return {
        "request": req,
        "response": rsp,
        "correlation_checks": checks,
        "response_kind": response_kind,
        "outcome": outcome,
        "selected_checks_complete": bool(complete),
        "contradictions": sorted(contradictions),
        "unassessed_reasons": sorted(unknown),
    }


@dataclass(frozen=True)
class _Plan:
    document: dict
    size: int
    request: bytes
    response: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size = _capture(model, budget)
    if type(source) is not dict or source.keys() != _MODEL_FIELDS:
        raise CoapAnalysisError("Exact closed five-field source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise CoapAnalysisError("Exact native schema version one required")
    for key in ("request_source_id", "response_source_id"):
        if type(source[key]) is not str or _SOURCE_ID.fullmatch(source[key]) is None:
            raise CoapAnalysisError("Bounded exact native source label required")
    request = _wire(source["request_base64"], budget)
    response = _wire(source["response_base64"], budget)
    relations = _relations(request, response, budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GD-D18-CMD",
        "group_commander_profile_id": "AOE-HQ-06",
        "independent_validator_id": "AOE-HQ-33",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": source,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "source_bytes": {
            "request_sha256": _SHA_PLACEHOLDER,
            "response_sha256": _SHA_PLACEHOLDER,
            "request_length": len(request),
            "response_length": len(response),
        },
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": {
            "maximum_datagram_bytes": MAX_DATAGRAM_BYTES,
            "maximum_model_bytes": MAX_MODEL_BYTES,
            "maximum_report_bytes": MAX_REPORT_BYTES,
            "maximum_native_nodes": MAX_NODES,
            "scalar_inclusive_depth": MAX_DEPTH,
            "maximum_string_bytes": MAX_STRING_BYTES,
            "maximum_options_per_message": MAX_OPTIONS,
            "maximum_reason_codes": MAX_REASONS,
            "maximum_cumulative_work": MAX_WORK,
        },
        **relations,
    }
    # Complete retained output/copy, byte hashes and final address/encoding passes are
    # funded before any content/address digest, including a later replay comparison.
    document, size = _capture(document, budget, report=True)
    budget.charge(
        8 * size
        + 4 * source_size
        + 4 * (len(request) + len(response))
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, size, request, response)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    for side, data in (("request", plan.request), ("response", plan.response)):
        document["source_bytes"][side + "_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "CPA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise CoapAnalysisError("Report requires its complete embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size)
    return document, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise CoapAnalysisError("Canonical report does not replay its complete embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not CoapAnalysis or not hasattr(report, "document_json"):
        raise CoapAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise CoapAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class CoapAnalysis:
    """Owned unsigned byte observations, rederived at every public export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not CoapAnalysis:
            raise CoapAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> CoapAnalysis:
        if cls is not CoapAnalysis:
            raise CoapAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> CoapAnalysis:
        if cls is not CoapAnalysis:
            raise CoapAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> CoapAnalysis:
    result = object.__new__(CoapAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_coap(model: Any) -> CoapAnalysis:
    """Observe a finite supplied pair, without network or endpoint effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_coap_bytes(*, model_bytes: Any) -> CoapAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise CoapAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CoapAnalysisError("Closed JSON metadata requires ASCII encoding") from exc
    source, _ = _decode(text, budget)
    return _owned(_materialize(_plan(source, budget)))


def verify_supplied_coap_analysis(report: Any, *, model: Any) -> CoapAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, expected)
    if expected != separate:
        raise CoapAnalysisError("Report differs from the separately supplied original model")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh inert CON-GET/2.05 ACK bytes; no acquired traffic or authenticated endpoints."""
    return {
        "schema_version": 1,
        "request_source_id": "synthetic-get",
        "response_source_id": "synthetic-ack",
        "request_base64": base64.b64encode(b"\x41\x01\x12\x34\xaa\xd0\x04").decode("ascii"),
        "response_base64": base64.b64encode(b"\x61\x45\x12\x34\xaa\xc0\xffok").decode("ascii"),
    }


__all__ = [
    "CoapAnalysis",
    "CoapAnalysisError",
    "analyze_supplied_coap",
    "analyze_supplied_coap_bytes",
    "verify_supplied_coap_analysis",
    "component_fixture",
]

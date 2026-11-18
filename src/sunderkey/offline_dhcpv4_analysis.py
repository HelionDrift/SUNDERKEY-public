"""Inert DHCPv4 packet structure and declared DISCOVER/OFFER or REQUEST/ACK joins.

This is byte arithmetic, not a DHCP agent, lease verifier or network observation.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "dhcpv4_supplied_offer_ack_structure"
PROFILE_ID = "AOE-GC-D13-S03"
CAPABILITY_ID = "army.gc.d13.s03"
VECTOR_ID = "AV-GC-D13-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S03"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7ad8506c3f311239fe02108aa7905a21c74afb845bdc6594307294824b0b6bba"
SEMANTICS_PROFILE = "rfc2131-2132-3396-supplied-offer-ack-structure.v1"
MODEL_DOMAIN = "sunderkey.offline-dhcpv4-model.v1"
DOMAIN = "sunderkey.offline-dhcpv4-analysis.v1"
MAX_PACKET_BYTES = 8192
MAX_MODEL_BYTES = 32_768
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 1024
MAX_REPORT_NODES = 32_768
MAX_DEPTH = 16
MAX_FRAGMENTS = 256
MAX_OPTION_DATA_BYTES = 8192
MAX_OBSERVATIONS = 256
MAX_STRING_BYTES = 16_384
MAX_WORK = 67_108_864
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_COOKIE = b"\x63\x82\x53\x63"
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_SHA = "sha256:" + "0" * 64
_FIELDS = {
    "schema_version",
    "request_source_id",
    "response_source_id",
    "request_base64",
    "response_base64",
}
_KNOWN_LENGTHS = {50: 4, 51: 4, 52: 1, 53: 1, 54: 4}
_EFFECTS = dict.fromkeys(
    (
        "packet_acquisition",
        "network",
        "provider",
        "credential",
        "process",
        "execution",
        "address_allocation",
        "lease",
        "authority",
        "routing",
        "deployment",
        "qualification",
    ),
    "none",
)
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "endpoint_identity_verified",
        "lease_validity_verified",
        "address_availability_verified",
        "server_selection_verified",
        "delivery_verified",
        "full_dhcp_validity_verified",
        "rogue_server_claimed",
        "vulnerability_claimed",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Both packets and source labels are supplied, not acquired or authenticated.",
    "Only fixed BOOTP layout, DHCP option framing and the declared pair subset are checked.",
    "All sixteen chaddr bytes are an opaque copied field, not an authenticated client identity.",
    "Unknown cookie, message types, options and ambiguous overload remain unassessed.",
    "Overload is activated only from primary options; "
    "secondary declarations cannot reactivate fields.",
    "Repeated option data is concatenated in options, file, sname order before interpretation.",
    "Client identifiers remain opaque; no equivalence with chaddr or echo obligation is inferred.",
    "Requested-address/server selection, client state, topology and IPAM context are not inferred.",
    "siaddr names the next bootstrap server field, not the DHCP server identifier.",
    "Lease integers are wire quantities, including 0xffffffff; "
    "no clock or lease permission is inferred.",
    "No complete DHCP, BOOTP, transport, later-option or client/server implementation is claimed.",
    "Canonical model identity does not preserve raw JSON spelling; decoded packet identities do.",
    "Retained packet bytes and opaque data are not redacted or approved for publication.",
    "Ceilings are software contracts; simultaneous maxima need not fit all replay passes.",
)


class Dhcpv4AnalysisError(ValueError):
    """An exact input, source replay or finite software ceiling was refused."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise Dhcpv4AnalysisError("Cumulative software work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_cap = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_cap = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > byte_cap - size:
            raise Dhcpv4AnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def walk(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_cap or depth > MAX_DEPTH:
            raise Dhcpv4AnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise Dhcpv4AnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise Dhcpv4AnalysisError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise Dhcpv4AnalysisError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (list, dict):
            if id(item) in active:
                raise Dhcpv4AnalysisError("Cyclic native document")
            if len(item) * (2 if kind is dict else 1) > node_cap - nodes:
                raise Dhcpv4AnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        walk(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise Dhcpv4AnalysisError("Exact native text keys required")
                        walk(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        walk(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise Dhcpv4AnalysisError("Exact integer-only native JSON families required")

    walk(value, 1)
    return size, nodes


def _copy(value: Any) -> Any:
    if type(value) is dict:
        return {key: _copy(child) for key, child in value.items()}
    if type(value) is list:
        return [_copy(child) for child in value]
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _copy(value), size, nodes


def _integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise Dhcpv4AnalysisError("Bounded raw integer grammar required")
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    maximum = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise Dhcpv4AnalysisError("Raw signed64 integer ceiling exhausted")
    return int(token)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    cap = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_cap = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > cap or not text.isascii():
        raise Dhcpv4AnalysisError("Bounded exact ASCII JSON text required")
    budget.charge(2 * len(text))
    stack: list[str] = []
    index = nodes = 0
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise Dhcpv4AnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_cap or len(stack) + 1 > MAX_DEPTH:
            raise Dhcpv4AnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                        raise Dhcpv4AnalysisError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            digit not in "0123456789abcdefABCDEF" for digit in digits
                        ):
                            raise Dhcpv4AnalysisError("Malformed Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise Dhcpv4AnalysisError("Unsupported JSON escape")
                if not 32 <= code <= 126:
                    raise Dhcpv4AnalysisError("Printable ASCII JSON strings required")
                length += 1
                if length > MAX_STRING_BYTES:
                    raise Dhcpv4AnalysisError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise Dhcpv4AnalysisError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise Dhcpv4AnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise Dhcpv4AnalysisError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise Dhcpv4AnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def fractional(_: str) -> None:
        raise Dhcpv4AnalysisError("Integer-only raw JSON required")

    budget.charge(4 * len(text) + 32 * nodes)
    try:
        document = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer,
            parse_float=fractional,
            parse_constant=fractional,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise Dhcpv4AnalysisError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _packet_bytes(value: Any, budget: _Budget) -> bytes:
    encoded_cap = 4 * ((MAX_PACKET_BYTES + 2) // 3)
    if type(value) is not str or not value or len(value) > encoded_cap:
        raise Dhcpv4AnalysisError("Bounded nonempty canonical packet base64 required")
    budget.charge(4 * len(value))
    if len(value) % 4 or _BASE64.fullmatch(value) is None:
        raise Dhcpv4AnalysisError("Canonical standard base64 grammar required")
    decoded_size = len(value) // 4 * 3 - (2 if value.endswith("==") else int(value.endswith("=")))
    if not 1 <= decoded_size <= MAX_PACKET_BYTES:
        raise Dhcpv4AnalysisError("Decoded packet byte ceiling exhausted")
    budget.charge(8 * decoded_size)
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Dhcpv4AnalysisError("Malformed base64 packet") from exc
    if base64.b64encode(data).decode("ascii") != value:
        raise Dhcpv4AnalysisError("Noncanonical base64 pad bits")
    return data


@dataclass(slots=True)
class _Retention:
    budget: _Budget
    size: int = 0
    nodes: int = 0

    def retain(self, row: Any, target: list) -> None:
        size, nodes = _measure(row, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise Dhcpv4AnalysisError("Cumulative retained report ceiling exhausted")
        self.budget.charge(4 * (size + nodes + 1))
        self.size += size + 1
        self.nodes += nodes
        target.append(row)


def _observe(
    retention: _Retention,
    observations: list,
    packet: str,
    category: str,
    code: str,
    field: str,
    offset: int | None,
) -> None:
    if len(observations) >= MAX_OBSERVATIONS:
        raise Dhcpv4AnalysisError("Observation software ceiling exhausted")
    retention.retain(
        {"packet": packet, "category": category, "code": code, "field": field, "offset": offset},
        observations,
    )


def _parse_packet(
    data: bytes,
    side: str,
    retention: _Retention,
    observations: list,
) -> dict:
    budget = retention.budget
    budget.charge(128 + 4 * len(data))
    result = {
        "byte_count": len(data),
        "header": None,
        "cookie_state": "not_examined",
        "fields": [],
        "fragments": [],
        "logical_options": [],
        "message_type": None,
        "options_complete": False,
    }

    def note(category: str, code: str, field: str, offset: int | None) -> None:
        _observe(retention, observations, side, category, code, field, offset)

    if len(data) < 236:
        note("truncated_prefix", "fixed_header_truncated", "header", len(data))
        return result
    op, htype, hlen, hops, xid, secs, flags = struct.unpack_from("!BBBBIHH", data)
    result["header"] = {
        "op": op,
        "htype": htype,
        "hlen": hlen,
        "hops": hops,
        "xid": xid,
        "secs": secs,
        "flags": flags,
        "broadcast_bit": bool(flags & 0x8000),
        "ciaddr_hex": data[12:16].hex(),
        "yiaddr_hex": data[16:20].hex(),
        "siaddr_hex": data[20:24].hex(),
        "giaddr_hex": data[24:28].hex(),
        "chaddr_hex": data[28:44].hex(),
        "sname_hex": data[44:108].hex(),
        "file_hex": data[108:236].hex(),
    }
    if hlen > 16:
        note("contradiction", "hlen_exceeds_chaddr_field", "hlen", 2)
    elif hlen == 0:
        note("unassessed", "zero_hardware_length_unassessed", "hlen", 2)
    if op not in (1, 2):
        note("unassessed", "bootp_op_unassessed", "op", 0)
    if len(data) < 240:
        result["cookie_state"] = "absent_or_truncated"
        note("truncated_prefix", "cookie_absent_or_truncated", "cookie", len(data))
        return result
    if data[236:240] != _COOKIE:
        result["cookie_state"] = "unknown_bootp_vendor_format"
        note("unassessed", "unknown_cookie_or_bootp_vendor_format", "cookie", 236)
        return result
    result["cookie_state"] = "dhcp_cookie"
    assembled: dict[int, bytearray] = {}
    sources: dict[int, list[int]] = {}
    total_data = 0

    def field(name: str, start: int, end: int) -> bool:
        nonlocal total_data
        position = start
        pads = 0
        end_offset = None
        complete = False
        while position < end:
            budget.charge(16)
            code = data[position]
            if code == 0:
                pads += 1
                position += 1
                continue
            if code == 255:
                end_offset = position
                position += 1
                complete = True
                break
            if len(result["fragments"]) >= MAX_FRAGMENTS:
                raise Dhcpv4AnalysisError("Option fragment software ceiling exhausted")
            if position + 1 >= end:
                note(
                    "truncated_prefix" if name == "options" else "contradiction",
                    "option_length_truncated"
                    if name == "options"
                    else "option_crosses_fixed_field",
                    name,
                    position,
                )
                break
            length = data[position + 1]
            finish = position + 2 + length
            if finish > end:
                note(
                    "truncated_prefix" if name == "options" else "contradiction",
                    "option_data_truncated" if name == "options" else "option_crosses_fixed_field",
                    name,
                    position,
                )
                break
            if length > MAX_OPTION_DATA_BYTES - total_data:
                raise Dhcpv4AnalysisError("Aggregate logical option data ceiling exhausted")
            budget.charge(64 + 12 * length)
            value = data[position + 2 : finish]
            retention.retain(
                {
                    "field": name,
                    "offset": position,
                    "code": code,
                    "length": length,
                    "data_hex": value.hex(),
                },
                result["fragments"],
            )
            assembled.setdefault(code, bytearray()).extend(value)
            sources.setdefault(code, []).append(len(result["fragments"]) - 1)
            total_data += length
            position = finish
        if end_offset is None and position == end:
            note(
                "truncated_prefix" if name == "options" else "contradiction",
                "end_option_missing",
                name,
                end,
            )
        remainder = data[position:end] if complete else b""
        budget.charge(4 * len(remainder))
        trailing_pads = remainder.count(0)
        nonpads = len(remainder) - trailing_pads
        if nonpads:
            note(
                "unassessed" if name == "options" else "contradiction",
                "nonpad_after_end",
                name,
                position,
            )
        retention.retain(
            {
                "field": name,
                "start_offset": start,
                "end_offset": end,
                "end_marker_offset": end_offset,
                "end_seen": complete,
                "pad_octets": pads,
                "trailing_pad_octets": trailing_pads,
                "trailing_nonpad_octets": nonpads,
            },
            result["fields"],
        )
        return complete

    all_complete = field("options", 240, len(data))
    activation = bytes(assembled.get(52, b""))
    overload = 0
    if 52 in assembled:
        if len(activation) == 1 and activation[0] in (1, 2, 3):
            overload = activation[0]
        elif not activation:
            note("unassessed", "overload_activation_unavailable", "options", 240)
            all_complete = False
        else:
            note("contradiction", "overload_primary_value_invalid", "options", 240)
            all_complete = False
    if overload & 1:
        all_complete = field("file", 108, 236) and all_complete
    if overload & 2:
        all_complete = field("sname", 44, 108) and all_complete
    for code in sorted(assembled):
        budget.charge(64 + 8 * len(assembled[code]) + 4 * len(sources[code]))
        value = bytes(assembled[code])
        status = "opaque_unassessed"
        number = None
        if code == 52 and value != activation:
            note("unassessed", "secondary_overload_not_reactivated", "option", code)
        elif code in _KNOWN_LENGTHS:
            if all_complete and len(value) != _KNOWN_LENGTHS[code]:
                note("contradiction", "logical_option_length_invalid", "option", code)
                status = "length_contradiction"
            elif len(value) == _KNOWN_LENGTHS[code] and all_complete:
                number = int.from_bytes(value, "big")
                status = "fixed_wire_quantity"
                if code == 53:
                    result["message_type"] = number
                    if not 1 <= number <= 8:
                        note("unassessed", "message_type_unassessed", "option", 53)
                if code == 52 and number not in (1, 2, 3):
                    status = "value_contradiction"
            else:
                status = "incomplete_option_aggregate"
        elif code == 61:
            status = "opaque_client_identifier"
            if all_complete and len(value) < 2:
                note("contradiction", "client_identifier_too_short", "option", 61)
        else:
            note("unassessed", "option_semantics_unassessed", "option", code)
        retention.retain(
            {
                "code": code,
                "length": len(value),
                "data_hex": value.hex(),
                "fragment_indices": sources[code],
                "semantic_status": status,
                "wire_integer": number,
            },
            result["logical_options"],
        )
    result["options_complete"] = all_complete
    if 53 not in assembled and all_complete:
        note("unassessed", "dhcp_type_absent_bootp_unassessed", "option", 53)
    return result


def _pair(request: dict, response: dict, retention: _Retention, observations: list) -> dict:
    result = {"selected_exchange": None, "checks": [], "copied_header_fields_match": None}
    types = (request["message_type"], response["message_type"])
    if types not in ((1, 2), (3, 5)):
        _observe(
            retention, observations, "pair", "unassessed", "exchange_outside_subset", "type", None
        )
        return result
    result["selected_exchange"] = "discover_offer" if types == (1, 2) else "request_ack"
    first, second = request["header"], response["header"]
    retention.budget.charge(512)
    checks = [("request_op", first["op"] == 1), ("response_op", second["op"] == 2)]
    checks += [
        (name, first[name] == second[name])
        for name in ("xid", "htype", "hlen", "flags", "giaddr_hex", "chaddr_hex")
    ]
    checks += [("response_hops", second["hops"] == 0), ("response_secs", second["secs"] == 0)]
    checks.append(("request_reserved_flags", first["flags"] & 0x7FFF == 0))
    if types == (1, 2):
        checks.append(("response_ciaddr", second["ciaddr_hex"] == "00000000"))
    else:
        checks.append(
            ("response_ciaddr", second["ciaddr_hex"] in ("00000000", first["ciaddr_hex"]))
        )
    for name, matches in checks:
        retention.retain({"field": name, "matches": matches}, result["checks"])
        if not matches:
            _observe(
                retention,
                observations,
                "pair",
                "contradiction",
                "declared_pair_field_mismatch",
                name,
                None,
            )
    result["copied_header_fields_match"] = all(value for _, value in checks)
    codes = {row["code"] for row in response["logical_options"]}
    for code in (51, 54):
        if code not in codes:
            _observe(
                retention,
                observations,
                "response",
                "contradiction",
                "required_response_option_absent",
                "option",
                code,
            )
    # Table 3 forbids these response options for the selected two exchanges.
    for code in (50, 55, 57):
        if code in codes:
            _observe(
                retention,
                observations,
                "response",
                "contradiction",
                "option_forbidden_in_selected_response",
                "option",
                code,
            )
    return result


def _bounds() -> dict:
    return {
        "packet_bytes_each": MAX_PACKET_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "fragments_each": MAX_FRAGMENTS,
        "option_data_bytes_each": MAX_OPTION_DATA_BYTES,
        "observations": MAX_OBSERVATIONS,
        "string_bytes": MAX_STRING_BYTES,
        "cumulative_work_per_public_operation": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    request: bytes
    response: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size, _ = _capture(model, budget)
    if type(source) is not dict or source.keys() != _FIELDS:
        raise Dhcpv4AnalysisError("Exact closed supplied pair model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise Dhcpv4AnalysisError("Exact native integer schema version one required")
    for name in ("request_source_id", "response_source_id"):
        if type(source[name]) is not str or _SOURCE_ID.fullmatch(source[name]) is None:
            raise Dhcpv4AnalysisError("Bounded native source identity required")
    request = _packet_bytes(source["request_base64"], budget)
    response = _packet_bytes(source["response_base64"], budget)
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
        "source_model_sha256": _SHA,
        "request_packet_sha256": _SHA,
        "response_packet_sha256": _SHA,
        "request": {},
        "response": {},
        "pair": {},
        "observations": [],
        "supported_checks_outcome": "consistent_supplied_subset",
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "D4A-" + "0" * 32,
        "analysis_sha256": _SHA,
    }
    size, nodes = _measure(document, budget, report=True)
    # Fixed per-packet headers and container punctuation are reserved before parsing.
    retention = _Retention(budget, size + 4096, nodes + 256)
    budget.charge(4096)
    observations = document["observations"]
    document["request"] = _parse_packet(request, "request", retention, observations)
    document["response"] = _parse_packet(response, "response", retention, observations)
    document["pair"] = _pair(document["request"], document["response"], retention, observations)
    if any(row["category"] == "contradiction" for row in observations):
        document["supported_checks_outcome"] = "contradictions"
    elif observations:
        document["supported_checks_outcome"] = "incomplete"
    document, size, nodes = _capture(document, budget, report=True)
    # Fund every future serialization, digest buffer, detached export and equality
    # before the first own digest. Materialization performs no further charge.
    budget.charge(
        12 * size
        + 6 * source_size
        + 4 * nodes
        + 8 * (len(request) + len(response))
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, request, response, size)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["request_packet_sha256"] = "sha256:" + hashlib.sha256(plan.request).hexdigest()
    document["response_packet_sha256"] = "sha256:" + hashlib.sha256(plan.response).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in ("analysis_id", "analysis_sha256")
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "D4A-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise Dhcpv4AnalysisError("Report requires its complete source model")
    size, nodes = _measure(document, budget, report=True)
    plan = _plan(document["source_model"], budget)
    budget.charge(4 * size + nodes + plan.size)
    return document, plan


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise Dhcpv4AnalysisError("Canonical report does not fully replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not Dhcpv4Analysis or not hasattr(report, "document_json"):
        raise Dhcpv4AnalysisError("Complete exact native report wrapper required")
    if type(report.document_json) is not str:
        raise Dhcpv4AnalysisError("Exact native canonical report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class Dhcpv4Analysis:
    """Owned unsigned metadata that fully replays the embedded pair on every export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not Dhcpv4Analysis:
            raise Dhcpv4AnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> Dhcpv4Analysis:
        if cls is not Dhcpv4Analysis:
            raise Dhcpv4AnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, _ = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> Dhcpv4Analysis:
        if cls is not Dhcpv4Analysis:
            raise Dhcpv4AnalysisError("Exact native report family required")
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


def _owned(text: str) -> Dhcpv4Analysis:
    result = object.__new__(Dhcpv4Analysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_dhcpv4(model: Any) -> Dhcpv4Analysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_dhcpv4_bytes(*, model_bytes: Any) -> Dhcpv4Analysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise Dhcpv4AnalysisError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Dhcpv4AnalysisError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_dhcpv4_analysis(report: Any, *, model: Any) -> Dhcpv4Analysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise Dhcpv4AnalysisError("Report does not replay the separately supplied original pair")
    return _owned(separate)


_FIXTURE_REQUEST = (
    "AQEGABI0VngAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjglNj"
    "NQEB/w=="
)
_FIXTURE_RESPONSE = (
    "AgEGABI0VngAAAAAAAAAAMAAAgoAAAAAAAAAAAIAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjglNj"
    "NQECNgTAAAIBMwQAAA4Q/w=="
)


def component_fixture() -> dict:
    """Fresh literal synthetic DISCOVER/OFFER bytes, with no network acquisition."""
    return {
        "schema_version": 1,
        "request_source_id": "synthetic-discover",
        "response_source_id": "synthetic-offer",
        "request_base64": _FIXTURE_REQUEST,
        "response_base64": _FIXTURE_RESPONSE,
    }


__all__ = [
    "Dhcpv4Analysis",
    "Dhcpv4AnalysisError",
    "analyze_supplied_dhcpv4",
    "analyze_supplied_dhcpv4_bytes",
    "verify_supplied_dhcpv4_analysis",
    "component_fixture",
]

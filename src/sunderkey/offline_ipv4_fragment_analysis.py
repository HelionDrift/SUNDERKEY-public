"""Finite supplied IPv4 header and fragment-comparison octet arithmetic."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "ipv4_supplied_fragment_relations_and_header_checksums"
PROFILE_ID = "AOE-GC-D13-S01"
CAPABILITY_ID = "army.gc.d13.s01"
VECTOR_ID = "AV-GC-D13-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S01"
WAVE_ID = "IW2-004"
BLUEPRINT_SHA256 = "sha256:566fbac84eb4d1b27b0c94dfd8cc04d5da90239b3b49645784ef54646c9bcdb6"
SEMANTICS_PROFILE = "rfc791-6864-supplied-ipv4-fragment-arithmetic.v1"
MODEL_DOMAIN = "sunderkey.offline-ipv4-fragment-model.v1"
DOMAIN = "sunderkey.offline-ipv4-fragment-analysis.v1"
MAX_SETS = 16
MAX_PACKETS_PER_SET = 64
MAX_PACKETS = 128
MAX_PACKET_BYTES = 65_535
MAX_TOTAL_PACKET_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_DEPTH = 16
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 262_144
MAX_PAIRS = 2_048
MAX_OBSERVATIONS = 2_048
MAX_OVERLAP_BYTES = 8_388_608
MAX_WORK = 134_217_728
MAX_STRING_BYTES = 4 * ((MAX_PACKET_BYTES + 2) // 3)
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "fragment_sets"}
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "IPFA-" + "0" * 32
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
        "capture_membership_proven",
        "endpoint_identity_proven",
        "identification_uniqueness_proven",
        "one_real_datagram_proven",
        "receiver_reassembly_proven",
        "receiver_overlap_rule_proven",
        "delivery_proven",
        "transport_semantics_proven",
        "full_ipv4_validity_proven",
        "vulnerability_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Sets and source labels are unsigned caller-selected octet comparison groups.",
    "Inputs start at IPv4 byte zero; complete exact-length nonempty payloads are required.",
    "Checksums are header equations, not authenticity, actual transmission or payload integrity.",
    "Atomic IPv4 identification values have no grouping or duplicate-detection meaning.",
    "Even equal non-atomic tuples do not establish one actual datagram or ID uniqueness.",
    "All pair extents, equality, union and gaps are literal supplied-byte arithmetic.",
    "Terminal interpretation is conditional on the declared single non-atomic tuple only.",
    "Missing initial or terminal fragments and gaps are incomplete supplied evidence.",
    "Overlaps never imply an IPv4 discard, first-wins, last-wins or filtering rule.",
    "Received DF fragments are not universally invalid; "
    "no further-fragmentation simulation occurs.",
    "Unknown option semantics are withheld; option, TTL and IHL equality is not assumed.",
    "The DS octet is opaque; historical TOS reserved-bit rules are not applied.",
    "RFC5722 is IPv6-specific and supplies no IPv4 overlap-discard rule here.",
    "No payload is reassembled, decoded as transport data, transmitted or acquired.",
    "Embedded original bytes are unsanitized retained source, not safe or redacted content.",
    "Canonical model identity differs from original raw JSON spelling identity.",
    "Software ceilings are local cost bounds; simultaneous maxima may not fit.",
    "No specialist completion, authority, qualification, parity or operational approval follows.",
)


class IPv4FragmentAnalysisError(ValueError):
    """The exact inert profile, finite software costs or semantic replay was refused."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, units: int) -> None:
        if units < 0 or units > MAX_WORK - self.used:
            raise IPv4FragmentAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += units


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    ancestors: set[int] = set()

    def reserve(amount: int) -> None:
        nonlocal size
        if amount > byte_limit - size:
            raise IPv4FragmentAnalysisError("Canonical escaped document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        budget.charge(1)
        if nodes > node_limit or depth > MAX_DEPTH:
            raise IPv4FragmentAnalysisError("Native node or scalar-inclusive depth exhausted")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_BYTES:
                raise IPv4FragmentAnalysisError("Native string ceiling exhausted")
            reserve(2 + len(item))
            for character in item:
                budget.charge(1)
                code = ord(character)
                if code > 127:
                    raise IPv4FragmentAnalysisError("Closed metadata requires native ASCII text")
                if character in '\\"\b\f\n\r\t':
                    reserve(1)
                elif code < 32 or code == 127:
                    reserve(5)
        elif family is bool:
            reserve(4 if item else 5)
        elif item is None:
            reserve(4)
        elif family is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise IPv4FragmentAnalysisError("Native signed64 integer required")
            budget.charge(20)
            reserve(len(str(item)))
        elif family in (dict, list):
            if id(item) in ancestors:
                raise IPv4FragmentAnalysisError("Cyclic native documents are refused")
            pending = len(item) * (2 if family is dict else 1)
            if pending > node_limit - nodes:
                raise IPv4FragmentAnalysisError("Queued native node ceiling exhausted")
            reserve(2 + max(0, len(item) - 1) + (len(item) if family is dict else 0))
            ancestors.add(id(item))
            try:
                if family is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise IPv4FragmentAnalysisError("Native text object keys required")
                        budget.charge((len(item).bit_length() + 1) * len(key))
                        visit(key, depth + 1)
                        visit(child, depth + 1)
            finally:
                ancestors.remove(id(item))
        else:
            raise IPv4FragmentAnalysisError("Exact native integer-only JSON families required")

    visit(value, 1)
    return size, nodes


def _copy(value: Any) -> Any:
    if type(value) is list:
        return [_copy(child) for child in value]
    if type(value) is dict:
        return {key: _copy(child) for key, child in value.items()}
    return value


def _capture(value: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    size, nodes = _measure(value, budget, report=report)
    budget.charge(4 * (size + nodes))
    return _copy(value), size, nodes


def _integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise IPv4FragmentAnalysisError("Bounded raw signed-integer grammar required")
    digits = token[1:] if token.startswith("-") else token
    maximum = "9223372036854775808" if token.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise IPv4FragmentAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(token)


def _string_end(text: str, position: int, budget: _Budget) -> int:
    cursor = position + 1
    count = 0
    while cursor < len(text):
        character = text[cursor]
        budget.charge(1)
        if character == '"':
            return cursor + 1
        if character == "\\":
            cursor += 1
            if cursor >= len(text):
                raise IPv4FragmentAnalysisError("Incomplete raw string escape")
            escaped = text[cursor]
            if escaped == "u":
                digits = text[cursor + 1 : cursor + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise IPv4FragmentAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise IPv4FragmentAnalysisError("Closed metadata requires ASCII text")
                cursor += 4
            elif escaped not in '\\"/bfnrt':
                raise IPv4FragmentAnalysisError("Malformed raw string escape")
        elif ord(character) < 32:
            raise IPv4FragmentAnalysisError("Invalid raw string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise IPv4FragmentAnalysisError("Pre-decoder string ceiling exhausted")
        cursor += 1
    raise IPv4FragmentAnalysisError("Unterminated raw string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit or not text.isascii():
        raise IPv4FragmentAnalysisError("Bounded native ASCII JSON text required")
    budget.charge(3 * len(text))
    frames: list[str] = []
    cursor = nodes = 0
    while cursor < len(text):
        character = text[cursor]
        if character in " \t\r\n,:":
            cursor += 1
            continue
        if character in "]}":
            if not frames or frames.pop() != ("[" if character == "]" else "{"):
                raise IPv4FragmentAnalysisError("Mismatched raw JSON containers")
            cursor += 1
            continue
        nodes += 1
        if nodes > node_limit or len(frames) + 1 > MAX_DEPTH:
            raise IPv4FragmentAnalysisError("Pre-decoder node or scalar depth exhausted")
        if character in "[{":
            frames.append(character)
            cursor += 1
        elif character == '"':
            cursor = _string_end(text, cursor, budget)
        else:
            start = cursor
            while cursor < len(text) and text[cursor] not in ' \t\r\n,:]}[{"':
                cursor += 1
                if cursor - start > 20:
                    raise IPv4FragmentAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:cursor]
            if token not in ("true", "false", "null"):
                _integer(token)
    if frames:
        raise IPv4FragmentAnalysisError("Unterminated raw JSON containers")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict:
        owned = {}
        for key, child in pairs:
            if key in owned:
                raise IPv4FragmentAnalysisError("Duplicate raw JSON object key")
            owned[key] = child
        return owned

    def fractional(_: str) -> None:
        raise IPv4FragmentAnalysisError("Raw fractional or nonfinite scalars are unsupported")

    budget.charge(6 * len(text) + 32 * nodes)
    try:
        value = json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_int=_integer,
            parse_float=fractional,
            parse_constant=fractional,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise IPv4FragmentAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)[0]


def _label(value: Any) -> str:
    if type(value) is not str or _LABEL.fullmatch(value) is None:
        raise IPv4FragmentAnalysisError("Bounded native ASCII source label required")
    return value


def _wire_length(text: Any) -> int:
    if type(text) is not str or len(text) > MAX_STRING_BYTES:
        raise IPv4FragmentAnalysisError("Bounded native canonical base64 required")
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise IPv4FragmentAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 0 < length <= MAX_PACKET_BYTES:
        raise IPv4FragmentAnalysisError("Packet software byte ceiling or empty input refused")
    return length


def _wire(text: str, length: int, budget: _Budget) -> bytes:
    budget.charge(8 * len(text) + 8 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise IPv4FragmentAnalysisError("Malformed supplied base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != text:
        raise IPv4FragmentAnalysisError("Noncanonical base64 spelling or padding bits")
    return raw


@dataclass(slots=True)
class _Retention:
    budget: _Budget
    bytes: int = 0
    nodes: int = 0
    observations: int = 0
    pairs: int = 0
    overlap_bytes: int = 0

    def append(self, row: Any, rows: list) -> None:
        size, nodes = _measure(row, self.budget, report=True)
        if size + 1 > MAX_REPORT_BYTES - self.bytes or nodes > MAX_REPORT_NODES - self.nodes:
            raise IPv4FragmentAnalysisError("Cumulative retained row ceiling exhausted")
        self.budget.charge(4 * (size + nodes))
        self.bytes += size + 1
        self.nodes += nodes
        rows.append(row)

    def note(
        self,
        rows: list,
        set_id: str,
        code: str,
        packet_id: str | None = None,
        offset: int | None = None,
    ) -> None:
        if self.observations >= MAX_OBSERVATIONS:
            raise IPv4FragmentAnalysisError("Explicit observation ceiling exhausted")
        self.observations += 1
        self.append(
            {"set_id": set_id, "packet_id": packet_id, "code": code, "offset": offset}, rows
        )


def _folded_header_sum(raw: bytes, header_length: int, *, clear_checksum: bool) -> int:
    total = 0
    for index in range(0, header_length, 2):
        if index != 10 or not clear_checksum:
            total += 256 * raw[index] + raw[index + 1]
    while total > 65_535:
        total = (total & 65_535) + (total >> 16)
    return total


@dataclass(frozen=True)
class _Packet:
    row: dict
    raw: bytes
    payload: memoryview


def _packet(
    set_id: str,
    packet_id: str,
    raw: bytes,
    retained: _Retention,
    contradictions: list,
    unknown: list,
) -> _Packet:
    budget = retained.budget
    budget.charge(256 + 4 * len(raw))
    if len(raw) < 20 or raw[0] >> 4 != 4:
        raise IPv4FragmentAnalysisError("Complete IPv4-at-byte-zero header profile required")
    ihl = raw[0] & 15
    header_length = 4 * ihl
    total_length = 256 * raw[2] + raw[3]
    if ihl < 5 or header_length > len(raw):
        raise IPv4FragmentAnalysisError("Complete IHL five-through-fifteen header required")
    if total_length != len(raw) or total_length <= header_length:
        raise IPv4FragmentAnalysisError("Exact IPv4 total length and nonempty payload required")
    flags_offset = 256 * raw[6] + raw[7]
    mf, df = bool(flags_offset & 0x2000), bool(flags_offset & 0x4000)
    offset_units = flags_offset & 0x1FFF
    start = 8 * offset_units
    payload_length = total_length - header_length
    budget.charge(16 * header_length + 128)
    observed_sum = _folded_header_sum(raw, header_length, clear_checksum=False)
    canonical_checksum = 65_535 ^ _folded_header_sum(raw, header_length, clear_checksum=True)
    stored_checksum = 256 * raw[10] + raw[11]
    if observed_sum != 65_535:
        retained.note(contradictions, set_id, "header_checksum_equation_failed", packet_id, 10)
    if flags_offset & 0x8000:
        retained.note(contradictions, set_id, "reserved_header_flag_nonzero", packet_id, 6)
    if mf and payload_length % 8:
        retained.note(
            contradictions, set_id, "nonterminal_payload_not_eight_octet_multiple", packet_id
        )
    option_rows: list = []
    cursor = 20
    while cursor < header_length:
        budget.charge(64)
        option_type = raw[cursor]
        row = {
            "offset": cursor,
            "type": option_type,
            "copied_bit": bool(option_type & 128),
            "option_class": (option_type >> 5) & 3,
            "option_number": option_type & 31,
            "length": 1,
            "framing": "nop" if option_type == 1 else "end" if option_type == 0 else "opaque_tlv",
            "bytes_hex": raw[cursor : cursor + 1].hex(),
        }
        if option_type == 0:
            retained.append(row, option_rows)
            padding = raw[cursor + 1 : header_length]
            budget.charge(8 * len(padding))
            if any(padding):
                retained.note(
                    contradictions,
                    set_id,
                    "nonzero_after_end_option_padding",
                    packet_id,
                    cursor + 1,
                )
            break
        if option_type == 1:
            retained.append(row, option_rows)
            cursor += 1
            continue
        retained.note(unknown, set_id, "opaque_option_semantics_unassessed", packet_id, cursor)
        if cursor + 1 == header_length:
            row["framing"] = "missing_tlv_length"
            retained.note(contradictions, set_id, "option_length_octet_missing", packet_id, cursor)
            retained.append(row, option_rows)
            break
        length = raw[cursor + 1]
        row["length"] = length
        if length < 2 or length > header_length - cursor:
            row["framing"] = "invalid_tlv_extent"
            retained.note(
                contradictions, set_id, "option_length_outside_header", packet_id, cursor + 1
            )
            retained.append(row, option_rows)
            break
        budget.charge(4 * length)
        row["bytes_hex"] = raw[cursor : cursor + length].hex()
        retained.append(row, option_rows)
        cursor += length
    row = {
        "packet_id": packet_id,
        "packet_sha256": _SHA_PLACEHOLDER,
        "byte_length": len(raw),
        "version": 4,
        "ihl_words": ihl,
        "header_length": header_length,
        "total_length": total_length,
        "ds_octet": raw[1],
        "identification": 256 * raw[4] + raw[5],
        "reserved_flag": bool(flags_offset & 0x8000),
        "dont_fragment": df,
        "more_fragments": mf,
        "fragment_offset_units": offset_units,
        "fragment_start": start,
        "fragment_end": start + payload_length,
        "payload_length": payload_length,
        "ttl_octet": raw[8],
        "protocol_octet": raw[9],
        "source_address_hex": raw[12:16].hex(),
        "destination_address_hex": raw[16:20].hex(),
        "atomic_fields": df and not mf and offset_units == 0,
        "unfragmented_fields": not mf and offset_units == 0,
        "observed_checksum": stored_checksum,
        "canonical_zeroed_field_checksum": canonical_checksum,
        "checksum_spelling_matches_canonical": stored_checksum == canonical_checksum,
        "header_folded_sum": observed_sum,
        "header_checksum_equation_holds": observed_sum == 65_535,
        "options": option_rows,
    }
    return _Packet(row, raw, memoryview(raw)[header_length:])


def _pair(first: _Packet, second: _Packet, retained: _Retention, pairs: list) -> None:
    if retained.pairs >= MAX_PAIRS:
        raise IPv4FragmentAnalysisError("Cumulative pair-evaluation ceiling exhausted")
    retained.pairs += 1
    a, b = first.row, second.row
    start = max(a["fragment_start"], b["fragment_start"])
    end = min(a["fragment_end"], b["fragment_end"])
    overlap = max(0, end - start)
    if overlap > MAX_OVERLAP_BYTES - retained.overlap_bytes:
        raise IPv4FragmentAnalysisError("Compared overlap octet ceiling exhausted")
    retained.overlap_bytes += overlap
    retained.budget.charge(256 + 8 * overlap + 4 * (len(first.raw) + len(second.raw)))
    difference = None
    if overlap:
        for position in range(start, end):
            if (
                first.payload[position - a["fragment_start"]]
                != second.payload[position - b["fragment_start"]]
            ):
                difference = position
                break
    retained.append(
        {
            "first_packet_id": a["packet_id"],
            "second_packet_id": b["packet_id"],
            "first_extent": [a["fragment_start"], a["fragment_end"]],
            "second_extent": [b["fragment_start"], b["fragment_end"]],
            "equal_extents": a["fragment_start"] == b["fragment_start"]
            and a["fragment_end"] == b["fragment_end"],
            "overlap_extent": [start, end] if overlap else None,
            "overlap_octets": overlap,
            "overlap_octets_equal": difference is None if overlap else None,
            "first_different_octet_offset": difference,
            "exact_supplied_packet_octets_equal": first.raw == second.raw,
        },
        pairs,
    )


def _union(packets: list[_Packet], budget: _Budget) -> list[list[int]]:
    budget.charge(64 * len(packets) * (len(packets).bit_length() + 1))
    intervals = sorted((p.row["fragment_start"], p.row["fragment_end"]) for p in packets)
    merged: list[list[int]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def _set_relations(
    set_id: str,
    packets: list[_Packet],
    retained: _Retention,
    contradictions: list,
    unknown: list,
) -> dict:
    budget = retained.budget
    budget.charge(256 + 64 * len(packets))
    pairs: list = []
    for index, first in enumerate(packets):
        for other_index in range(index + 1, len(packets)):
            _pair(first, packets[other_index], retained, pairs)
    union = _union(packets, budget)
    endpoints = sorted({p.row["fragment_end"] for p in packets if not p.row["more_fragments"]})
    endpoint = endpoints[0] if len(endpoints) == 1 else None
    gaps: list[list[int]] | None = None
    beyond: list[list[int]] | None = None
    if endpoint is not None:
        gaps, beyond = [], []
        covered = 0
        for start, end in union:
            if start > covered and covered < endpoint:
                gaps.append([covered, min(start, endpoint)])
            covered = max(covered, min(end, endpoint))
            if end > endpoint:
                beyond.append([max(start, endpoint), end])
        if covered < endpoint:
            gaps.append([covered, endpoint])
    tuples = {
        (
            p.row["source_address_hex"],
            p.row["destination_address_hex"],
            p.row["protocol_octet"],
            p.row["identification"],
        )
        for p in packets
    }
    atomic = any(p.row["atomic_fields"] for p in packets)
    same_tuple = len(tuples) == 1
    conditional = same_tuple and not atomic
    if atomic:
        retained.note(unknown, set_id, "atomic_identification_cannot_bind_fragment_group")
    if not same_tuple:
        retained.note(unknown, set_id, "different_tuples_single_datagram_interpretation_withheld")
    initial = [p for p in packets if p.row["fragment_start"] == 0]
    if conditional:
        if not initial:
            retained.note(unknown, set_id, "initial_fragment_not_supplied")
        if not endpoints:
            retained.note(unknown, set_id, "terminal_fragment_not_supplied")
        elif len(endpoints) > 1:
            retained.note(contradictions, set_id, "conditional_terminal_extents_disagree")
        if gaps:
            retained.note(unknown, set_id, "supplied_octet_coverage_has_gaps")
        for packet in packets:
            row = packet.row
            if row["fragment_end"] + 20 > 65_535:
                retained.note(
                    contradictions,
                    set_id,
                    "conditional_payload_extent_exceeds_ipv4_capacity",
                    row["packet_id"],
                )
            if endpoint is not None:
                if row["fragment_end"] > endpoint:
                    retained.note(
                        contradictions,
                        set_id,
                        "conditional_payload_past_terminal_extent",
                        row["packet_id"],
                    )
                elif row["more_fragments"] and row["fragment_end"] == endpoint:
                    retained.note(
                        contradictions,
                        set_id,
                        "conditional_nonterminal_reaches_terminal_extent",
                        row["packet_id"],
                    )
                if row["fragment_start"] == 0 and endpoint + row["header_length"] > 65_535:
                    retained.note(
                        contradictions,
                        set_id,
                        "conditional_initial_header_plus_payload_too_large",
                        row["packet_id"],
                    )
    budget.charge(128 * (len(contradictions) + len(unknown) + len(pairs)))
    conflicting = any(row["overlap_octets_equal"] is False for row in pairs)
    overlapping = any(row["overlap_octets"] for row in pairs)
    if conflicting:
        retained.note(unknown, set_id, "conflicting_octets_receiver_resolution_unassessed")
    own_contradictions = any(row["set_id"] == set_id for row in contradictions)
    own_unknown = any(row["set_id"] == set_id for row in unknown)
    conditional_status = (
        "withheld_atomic_or_mixed_tuple"
        if not conditional
        else "observed_arithmetic_contradictions"
        if own_contradictions
        else "incomplete_or_unassessed_supplied_arithmetic"
        if own_unknown
        else "consistent_supplied_arithmetic"
    )
    return {
        "set_id": set_id,
        "packet_ids": [p.row["packet_id"] for p in packets],
        "tuple_relation": "equal_wire_tuple" if same_tuple else "different_wire_tuples",
        "atomic_packet_present": atomic,
        "conditional_nonatomic_tuple_assessed": conditional,
        "conditional_single_tuple_conclusion": conditional_status,
        "initial_packet_ids": [p.row["packet_id"] for p in initial],
        "literal_mf_zero_endpoints": endpoints,
        "literal_unique_mf_zero_endpoint": endpoint,
        "merged_supplied_intervals": union,
        "union_octets": sum(end - start for start, end in union),
        "literal_gaps_to_unique_endpoint": gaps,
        "literal_intervals_past_unique_endpoint": beyond,
        "coverage_relation": "no_unique_literal_terminal_extent"
        if endpoint is None
        else "literal_extent_has_gaps"
        if gaps
        else "literal_extent_covered",
        "overlap_relation": "conflicting_octets"
        if conflicting
        else "equal_octets_only"
        if overlapping
        else "no_overlap",
        "pairs": pairs,
    }


def _bounds() -> dict:
    return {
        "maximum_sets": MAX_SETS,
        "maximum_packets_per_set": MAX_PACKETS_PER_SET,
        "maximum_packets_total": MAX_PACKETS,
        "maximum_packet_bytes": MAX_PACKET_BYTES,
        "maximum_packet_bytes_total": MAX_TOTAL_PACKET_BYTES,
        "maximum_model_bytes": MAX_MODEL_BYTES,
        "maximum_report_bytes": MAX_REPORT_BYTES,
        "maximum_model_nodes": MAX_MODEL_NODES,
        "maximum_report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "maximum_string_bytes": MAX_STRING_BYTES,
        "maximum_pair_evaluations": MAX_PAIRS,
        "maximum_observations_total": MAX_OBSERVATIONS,
        "maximum_compared_overlap_octets": MAX_OVERLAP_BYTES,
        "maximum_cumulative_work": MAX_WORK,
    }


@dataclass(frozen=True)
class _Plan:
    document: dict
    size: int
    packets: tuple[bytes, ...]


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size, _ = _capture(model, budget)
    if type(source) is not dict or source.keys() != _MODEL_FIELDS:
        raise IPv4FragmentAnalysisError("Exact closed three-field source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise IPv4FragmentAnalysisError("Exact native schema version one required")
    _label(source["source_id"])
    sets = source["fragment_sets"]
    if type(sets) is not list or not 1 <= len(sets) <= MAX_SETS:
        raise IPv4FragmentAnalysisError("Bounded nonempty native fragment-set list required")
    set_ids: set[str] = set()
    packet_ids: set[str] = set()
    declared: list[tuple[str, list[tuple[str, str, int]]]] = []
    total_bytes = 0
    for group in sets:
        if type(group) is not dict or group.keys() != {"set_id", "packets"}:
            raise IPv4FragmentAnalysisError("Exact closed set rows required")
        set_id = _label(group["set_id"])
        if set_id in set_ids:
            raise IPv4FragmentAnalysisError("Duplicate supplied set identity")
        set_ids.add(set_id)
        packets = group["packets"]
        if type(packets) is not list or not 1 <= len(packets) <= MAX_PACKETS_PER_SET:
            raise IPv4FragmentAnalysisError("Bounded nonempty native packet list required")
        rows: list[tuple[str, str, int]] = []
        for packet in packets:
            if type(packet) is not dict or packet.keys() != {"packet_id", "packet_base64"}:
                raise IPv4FragmentAnalysisError("Exact closed packet rows required")
            packet_id = _label(packet["packet_id"])
            if packet_id in packet_ids or len(packet_ids) >= MAX_PACKETS:
                raise IPv4FragmentAnalysisError("Packet identity or aggregate count refused")
            packet_ids.add(packet_id)
            budget.charge(
                4 * len(packet["packet_base64"]) if type(packet["packet_base64"]) is str else 1
            )
            length = _wire_length(packet["packet_base64"])
            if length > MAX_TOTAL_PACKET_BYTES - total_bytes:
                raise IPv4FragmentAnalysisError("Aggregate decoded packet byte ceiling exhausted")
            total_bytes += length
            budget.charge(128)
            rows.append((packet_id, packet["packet_base64"], length))
        declared.append((set_id, rows))
    retained = _Retention(budget)
    parsed_rows: list = []
    set_rows: list = []
    contradictions: list = []
    unknown: list = []
    packet_bytes: list[bytes] = []
    for set_id, rows in declared:
        parsed: list[_Packet] = []
        for packet_id, text, length in rows:
            raw = _wire(text, length, budget)
            packet = _packet(set_id, packet_id, raw, retained, contradictions, unknown)
            retained.append({"set_id": set_id, **packet.row}, parsed_rows)
            packet_bytes.append(raw)
            parsed.append(packet)
        relation = _set_relations(set_id, parsed, retained, contradictions, unknown)
        retained.append(relation, set_rows)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GC-D13-CMD",
        "group_commander_profile_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": source,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "packets": parsed_rows,
        "fragment_sets": set_rows,
        "contradictions": contradictions,
        "unassessed_reasons": unknown,
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": _bounds(),
        "accounting": {
            "packet_count": len(packet_bytes),
            "decoded_packet_octets": total_bytes,
            "pair_evaluations": retained.pairs,
            "compared_overlap_octets": retained.overlap_bytes,
            "observation_count": retained.observations,
        },
    }
    # The entire final document, fixed-width identities and all later encodings,
    # hashes, clones and equality passes are reserved before the first SHA.
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        16 * size
        + 8 * source_size
        + 8 * nodes
        + 8 * total_bytes
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, size, tuple(packet_bytes))


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    for row, raw in zip(document["packets"], plan.packets, strict=True):
        row["packet_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "IPFA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    actual = _decode(text, budget, report=True)
    if type(actual) is not dict or "source_model" not in actual:
        raise IPv4FragmentAnalysisError("Complete embedded source model required")
    expected = _plan(actual["source_model"], budget)
    budget.charge(6 * len(text) + 4 * expected.size)
    return actual, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise IPv4FragmentAnalysisError("Canonical report fails complete source reconstruction")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not IPv4FragmentAnalysis:
        raise IPv4FragmentAnalysisError("Exact complete native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise IPv4FragmentAnalysisError("Complete native report text slot required")
    return text


@dataclass(frozen=True, slots=True)
class IPv4FragmentAnalysis:
    """Unsigned owned octet observations rederived on every public export."""

    document_json: str

    def __post_init__(self) -> None:
        _replay(_stored(self), _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> IPv4FragmentAnalysis:
        if cls is not IPv4FragmentAnalysis:
            raise IPv4FragmentAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, nodes = _capture(document, budget, report=True)
        budget.charge(4 * (size + nodes))
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> IPv4FragmentAnalysis:
        if cls is not IPv4FragmentAnalysis:
            raise IPv4FragmentAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> IPv4FragmentAnalysis:
    result = object.__new__(IPv4FragmentAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_ipv4_fragments(model: Any) -> IPv4FragmentAnalysis:
    """Observe bounded supplied IPv4 octets without acquisition or reassembly."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_ipv4_fragments_bytes(*, model_bytes: Any) -> IPv4FragmentAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise IPv4FragmentAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(3 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise IPv4FragmentAnalysisError("Closed JSON metadata requires ASCII encoding") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_ipv4_fragment_analysis(report: Any, *, model: Any) -> IPv4FragmentAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(4 * (embedded.size + original.size))
    reconstructed = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, reconstructed)
    if reconstructed != separate:
        raise IPv4FragmentAnalysisError(
            "Report differs from the separately supplied original model"
        )
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh wholly synthetic literal 16+8-octet comparison set, with no hashing."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-ipv4-fragments",
        "fragment_sets": [
            {
                "set_id": "declared-comparison",
                "packets": [
                    {
                        "packet_id": "first",
                        "packet_base64": "RQAAJBI0IABAEVxewAACAcYzZAJhYmNkZWZnaGlqa2xtbm9w",
                    },
                    {
                        "packet_id": "last",
                        "packet_base64": "RQAAHBI0AAJAEXxkwAACAcYzZAJxcnN0dXZ3eA==",
                    },
                ],
            }
        ],
    }


__all__ = [
    "IPv4FragmentAnalysis",
    "IPv4FragmentAnalysisError",
    "analyze_supplied_ipv4_fragments",
    "analyze_supplied_ipv4_fragments_bytes",
    "verify_supplied_ipv4_fragment_analysis",
    "component_fixture",
]

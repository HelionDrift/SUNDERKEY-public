"""Bounded observations about one supplied BGP-4 UPDATE byte sequence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "bgp_supplied_update_structure"
PROFILE_ID = "AOE-GC-D13-S02"
CAPABILITY_ID = "army.gc.d13.s02"
VECTOR_ID = "AV-GC-D13-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S02"
WAVE_ID = "IW2-005"
COMMANDER_PROFILE_ID = "AOE-GC-D13-CMD"
GROUP_COMMANDER_PROFILE_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ebdc526850dd9d8cd5b2cf3d7242cac1901b88e4d32d5af51f6200f218b0f02c"
SEMANTICS_PROFILE = "rfc4271-6793-supplied-update-octets.v1"
MODEL_DOMAIN = "sunderkey.offline-bgp-update-model.v1"
REPORT_DOMAIN = "sunderkey.offline-bgp-update-analysis.v1"

MAX_UPDATE_BYTES = 4_096
MAX_MODEL_BYTES = 16_384
MAX_REPORT_BYTES = 262_144
MAX_MODEL_NODES = 512
MAX_REPORT_NODES = 16_384
MAX_DEPTH = 16
MAX_STRING_BYTES = 8_192
MAX_ATTRIBUTES = 128
MAX_PREFIXES = 512
MAX_AS_SEGMENTS = 128
MAX_AS_NUMBERS = 512
MAX_OBSERVATIONS = 512
MAX_WORK = 33_554_432
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1

_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "asn_width_octets", "update_base64"}
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "BGPA-" + "0" * 32
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
        "peer_identity_proven",
        "asn_width_negotiated",
        "as4_path_reconstructed",
        "route_accepted",
        "next_hop_reachable",
        "topology_proven",
        "rpki_validated",
        "full_bgp_validity_proven",
        "vulnerability_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "The exact source is one caller-supplied UPDATE frame, not an acquired peer session.",
    "The 2- or 4-octet AS width is a supplied premise, not negotiated evidence.",
    "Unknown attributes and AS4 reconstruction remain unassessed.",
    "Received low attribute-flag bits are retained and ignored, not rejected.",
    "Non-significant prefix fill bits are retained and ignored for prefix comparison.",
    "A prefix in both withdrawal and announcement lists is an advisory, not a denial.",
    "No route acceptance, NEXT_HOP reachability, topology or RPKI claim follows.",
    "Embedded source bytes are unsanitized retained evidence, not redacted content.",
    "Canonical model identity does not preserve raw JSON whitespace or key order.",
    "All ceilings are local software costs; simultaneous maxima may not fit.",
    "No specialist completion, authority, qualification or parity follows.",
)


class BgpUpdateAnalysisError(ValueError):
    """The exact supplied subset, bounded cost or source replay was refused."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise BgpUpdateAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    maximum_size = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > maximum_size - size:
            raise BgpUpdateAnalysisError("Escaped canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > maximum_nodes or depth > MAX_DEPTH:
            raise BgpUpdateAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise BgpUpdateAnalysisError("Native string ceiling exhausted")
            add(2)
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise BgpUpdateAnalysisError("Closed metadata requires ASCII strings")
                if char in '\\"\b\t\n\f\r':
                    add(2)
                elif code < 32 or code == 127:
                    add(6)
                else:
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise BgpUpdateAnalysisError("Exact native signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise BgpUpdateAnalysisError("Cyclic native document refused")
            children = len(item) * (2 if kind is dict else 1)
            if children > maximum_nodes - nodes:
                raise BgpUpdateAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise BgpUpdateAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise BgpUpdateAnalysisError("Exact native integer-only JSON family required")

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


def _integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise BgpUpdateAnalysisError("Bounded raw integer grammar required")
    digits = token[1:] if token.startswith("-") else token
    maximum = "9223372036854775808" if token.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise BgpUpdateAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(token)


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
                raise BgpUpdateAnalysisError("Incomplete raw JSON escape")
            if text[index] == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise BgpUpdateAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise BgpUpdateAnalysisError("Closed metadata requires ASCII strings")
                index += 4
            elif text[index] not in '\\"/bfnrt':
                raise BgpUpdateAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise BgpUpdateAnalysisError("Invalid raw JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise BgpUpdateAnalysisError("Pre-decoder string ceiling exhausted")
        index += 1
    raise BgpUpdateAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    maximum_size = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > maximum_size or not text.isascii():
        raise BgpUpdateAnalysisError("Bounded exact native ASCII JSON text required")
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
                raise BgpUpdateAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > maximum_nodes or len(stack) + 1 > MAX_DEPTH:
            raise BgpUpdateAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                    raise BgpUpdateAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise BgpUpdateAnalysisError("Unterminated raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, child in items:
            if key in result:
                raise BgpUpdateAnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise BgpUpdateAnalysisError("Raw floating/nonfinite numbers are unsupported")

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
        raise BgpUpdateAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _label(value: Any) -> str:
    if type(value) is not str or _LABEL.fullmatch(value) is None:
        raise BgpUpdateAnalysisError("Bounded exact native source label required")
    return value


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_UPDATE_BYTES + 2) // 3):
        raise BgpUpdateAnalysisError("Bounded exact native UPDATE base64 required")
    budget.charge(3 * len(text))
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise BgpUpdateAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 23 <= length <= MAX_UPDATE_BYTES:
        raise BgpUpdateAnalysisError("Exact 23..4096-octet UPDATE required")
    budget.charge(8 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise BgpUpdateAnalysisError("Invalid supplied UPDATE base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != text:
        raise BgpUpdateAnalysisError("Noncanonical supplied UPDATE base64")
    return raw


@dataclass(slots=True)
class _Observations:
    contradictions: list[str]
    unassessed: list[str]
    advisories: list[str]
    budget: _Budget
    count: int = 0

    def add(self, channel: str, detail: str) -> None:
        rows = getattr(self, channel)
        if self.count >= MAX_OBSERVATIONS:
            raise BgpUpdateAnalysisError("Retained observation ceiling exhausted")
        self.budget.charge(4 * len(detail) + 32)
        rows.append(detail)
        self.count += 1


def _ipv4(raw: bytes) -> str:
    return ".".join(str(octet) for octet in raw)


def _prefixes(
    raw: bytes,
    begin: int,
    end: int,
    kind: str,
    observations: _Observations,
    budget: _Budget,
    existing_count: int,
) -> tuple[list[dict], list[tuple[int, int]]]:
    rows: list[dict] = []
    identities: list[tuple[int, int]] = []
    index = begin
    while index < end:
        if existing_count + len(rows) >= MAX_PREFIXES:
            raise BgpUpdateAnalysisError("Aggregate local prefix-row ceiling exhausted")
        width = raw[index]
        length = (width + 7) // 8
        index += 1
        if index + length > end:
            raise BgpUpdateAnalysisError("Truncated bounded prefix field")
        source = raw[index : index + length]
        index += length
        budget.charge(64 + 8 * length)
        row: dict[str, Any] = {
            "kind": kind,
            "prefix_length": width,
            "raw_prefix_hex": source.hex().upper(),
            "canonical_prefix": None,
            "nonzero_ignored_fill_bits": False,
        }
        if width > 32:
            observations.add("contradictions", f"{kind}_prefix_length_above_ipv4_32")
        else:
            complete = source + b"\x00" * (4 - len(source))
            mask = (0xFFFFFFFF << (32 - width)) & 0xFFFFFFFF if width else 0
            network = int.from_bytes(complete, "big") & mask
            row["canonical_prefix"] = f"{_ipv4(network.to_bytes(4, 'big'))}/{width}"
            if width % 8 and source[-1] & ((1 << (8 - width % 8)) - 1):
                row["nonzero_ignored_fill_bits"] = True
                observations.add("advisories", f"{kind}_nonzero_fill_bits_ignored")
            identities.append((network, width))
        rows.append(row)
    return rows, identities


def _as_path(
    value: bytes,
    width: int,
    observations: _Observations,
    budget: _Budget,
) -> list[dict]:
    rows: list[dict] = []
    index = numbers = 0
    while index < len(value):
        if len(rows) >= MAX_AS_SEGMENTS or index + 2 > len(value):
            raise BgpUpdateAnalysisError("Bounded AS_PATH segment header required")
        segment_type, count = value[index], value[index + 1]
        index += 2
        if count > MAX_AS_NUMBERS - numbers:
            raise BgpUpdateAnalysisError("Local AS-number ceiling exhausted")
        numbers += count
        length = count * width
        if index + length > len(value):
            observations.add("contradictions", "as_path_segment_length_exceeds_attribute")
            rows.append({"segment_type": segment_type, "count": count, "as_numbers": None})
            break
        data = value[index : index + length]
        index += length
        budget.charge(32 + 12 * count)
        values = [int.from_bytes(data[i : i + width], "big") for i in range(0, length, width)]
        if segment_type not in (1, 2):
            observations.add("unassessed", "as_path_segment_type_outside_set_sequence")
        if count == 0:
            observations.add("contradictions", "as_path_empty_segment")
        rows.append({"segment_type": segment_type, "count": count, "as_numbers": values})
    return rows


def _attributes(
    raw: bytes,
    begin: int,
    end: int,
    width: int,
    observations: _Observations,
    budget: _Budget,
) -> tuple[list[dict], set[int]]:
    rows: list[dict] = []
    types: set[int] = set()
    index = begin
    while index < end:
        if len(rows) >= MAX_ATTRIBUTES or index + 3 > end:
            raise BgpUpdateAnalysisError("Bounded attribute header required")
        flags, code = raw[index], raw[index + 1]
        extended = bool(flags & 0x10)
        header_size = 4 if extended else 3
        if index + header_size > end:
            raise BgpUpdateAnalysisError("Truncated extended attribute header")
        length = int.from_bytes(raw[index + 2 : index + header_size], "big")
        index += header_size
        if index + length > end:
            raise BgpUpdateAnalysisError("Attribute length exceeds declared attribute section")
        value = raw[index : index + length]
        index += length
        budget.charge(64 + 8 * length)
        row: dict[str, Any] = {
            "flags_octet": flags,
            "type_code": code,
            "extended_length": extended,
            "value_length": length,
            "raw_value_hex": value.hex().upper(),
            "known_value": None,
        }
        if code in types:
            observations.add("contradictions", "duplicate_attribute_type")
        types.add(code)
        if flags & 0x0F:
            observations.add("advisories", "received_reserved_low_attribute_flag_bits_ignored")
        if code in (1, 2, 3):
            if flags & 0xE0 != 0x40:
                observations.add("contradictions", "mandatory_attribute_flags_mismatch")
            if code == 1:
                if length != 1 or value[0] not in (0, 1, 2):
                    observations.add("contradictions", "origin_length_or_value_invalid")
                else:
                    row["known_value"] = {"origin": value[0]}
            elif code == 2:
                row["known_value"] = {
                    "as_path_segments": _as_path(value, width, observations, budget)
                }
            elif length != 4:
                observations.add("contradictions", "next_hop_length_not_four")
            else:
                row["known_value"] = {"next_hop_ipv4": _ipv4(value)}
        elif code in (17, 18):
            observations.add("unassessed", "as4_attribute_reconstruction_not_attempted")
        else:
            observations.add("unassessed", "uninterpreted_path_attribute_type")
        rows.append(row)
    return rows, types


def _bounds() -> dict:
    return {
        "maximum_update_octets": MAX_UPDATE_BYTES,
        "maximum_model_bytes": MAX_MODEL_BYTES,
        "maximum_report_bytes": MAX_REPORT_BYTES,
        "maximum_model_nodes": MAX_MODEL_NODES,
        "maximum_report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "maximum_string_bytes": MAX_STRING_BYTES,
        "maximum_attributes": MAX_ATTRIBUTES,
        "maximum_prefixes_total": MAX_PREFIXES,
        "maximum_as_segments": MAX_AS_SEGMENTS,
        "maximum_as_numbers": MAX_AS_NUMBERS,
        "maximum_observations": MAX_OBSERVATIONS,
        "maximum_cumulative_work": MAX_WORK,
    }


@dataclass(frozen=True, slots=True)
class _Plan:
    document: dict
    size: int
    nodes: int
    raw: bytes


def _plan(model: Any, budget: _Budget) -> _Plan:
    source, source_size, _ = _capture(model, budget)
    if type(source) is not dict or source.keys() != _MODEL_FIELDS:
        raise BgpUpdateAnalysisError("Exact closed four-field source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise BgpUpdateAnalysisError("Exact native schema version one required")
    _label(source["source_id"])
    width = source["asn_width_octets"]
    if type(width) is not int or width not in (2, 4):
        raise BgpUpdateAnalysisError("Supplied exact 2/4-octet AS width premise required")
    raw = _wire(source["update_base64"], budget)
    if raw[:16] != b"\xff" * 16 or raw[18] != 2:
        raise BgpUpdateAnalysisError("Exact BGP-4 UPDATE header required")
    if int.from_bytes(raw[16:18], "big") != len(raw):
        raise BgpUpdateAnalysisError("Declared UPDATE length must equal exact supplied bytes")
    withdrawn_length = int.from_bytes(raw[19:21], "big")
    withdrawn_end = 21 + withdrawn_length
    if withdrawn_end + 2 > len(raw):
        raise BgpUpdateAnalysisError("Withdrawn section exceeds exact UPDATE frame")
    attribute_length = int.from_bytes(raw[withdrawn_end : withdrawn_end + 2], "big")
    attribute_begin = withdrawn_end + 2
    attribute_end = attribute_begin + attribute_length
    if attribute_end > len(raw):
        raise BgpUpdateAnalysisError("Attribute section exceeds exact UPDATE frame")
    observations = _Observations([], [], [], budget)
    withdrawn, withdrawn_ids = _prefixes(
        raw, 21, withdrawn_end, "withdrawn", observations, budget, 0
    )
    attributes, types = _attributes(
        raw, attribute_begin, attribute_end, width, observations, budget
    )
    announced, announced_ids = _prefixes(
        raw, attribute_end, len(raw), "announced", observations, budget, len(withdrawn)
    )
    if len(withdrawn) + len(announced) > MAX_PREFIXES:
        raise BgpUpdateAnalysisError("Aggregate local prefix-row ceiling exhausted")
    if announced:
        for code, name in ((1, "origin"), (2, "as_path"), (3, "next_hop")):
            if code not in types:
                observations.add("contradictions", f"missing_mandatory_{name}_with_nlri")
    budget.charge(32 * (len(withdrawn_ids) + len(announced_ids)))
    if set(withdrawn_ids) & set(announced_ids):
        observations.add("advisories", "same_prefix_withdrawn_and_announced_permitted")
    if len(set(withdrawn_ids)) < len(withdrawn_ids):
        observations.add("advisories", "repeated_withdrawn_prefix")
    if len(set(announced_ids)) < len(announced_ids):
        observations.add("advisories", "repeated_announced_prefix")
    status = (
        "contradicts_declared_subset"
        if observations.contradictions
        else "unassessed"
        if observations.unassessed
        else "consistent_with_supported_subset"
    )
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": COMMANDER_PROFILE_ID,
        "group_commander_profile_id": GROUP_COMMANDER_PROFILE_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "source_model": source,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "update_sha256": _SHA_PLACEHOLDER,
        "analysis_status": status,
        "header": {
            "message_octets": len(raw),
            "withdrawn_section_octets": withdrawn_length,
            "attribute_section_octets": attribute_length,
            "announced_section_octets": len(raw) - attribute_end,
            "asn_width_octets_premise": width,
        },
        "withdrawn_prefixes": withdrawn,
        "path_attributes": attributes,
        "announced_prefixes": announced,
        "known_contradictions": observations.contradictions,
        "unassessed_reasons": observations.unassessed,
        "advisories": observations.advisories,
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": _bounds(),
        "accounting": {
            "update_octets": len(raw),
            "withdrawn_count": len(withdrawn),
            "attribute_count": len(attributes),
            "announced_count": len(announced),
            "observation_count": observations.count,
        },
    }
    document, size, nodes = _capture(document, budget, report=True)
    # Every later digest, encoding, replay, equality and export is prefunded.
    budget.charge(
        20 * size
        + 12 * source_size
        + 12 * nodes
        + 16 * len(raw)
        + 4 * len(MODEL_DOMAIN)
        + 4 * len(REPORT_DOMAIN)
        + 1_024
    )
    return _Plan(document, size, nodes, raw)


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
    document["update_sha256"] = "sha256:" + hashlib.sha256(plan.raw).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(REPORT_DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "BGPA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    actual, size, nodes = _decode(text, budget, report=True)
    if type(actual) is not dict or "source_model" not in actual:
        raise BgpUpdateAnalysisError("Complete embedded source model required")
    expected = _plan(actual["source_model"], budget)
    budget.charge(8 * size + 8 * nodes + 6 * expected.size)
    return actual, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise BgpUpdateAnalysisError("Canonical report fails complete source reconstruction")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not BgpUpdateAnalysis:
        raise BgpUpdateAnalysisError("Exact complete native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise BgpUpdateAnalysisError("Complete native report text slot required")
    return text


@dataclass(frozen=True, slots=True)
class BgpUpdateAnalysis:
    """Unsigned, source-replaying observation of one supplied UPDATE."""

    document_json: str

    def __post_init__(self) -> None:
        _replay(_stored(self), _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> BgpUpdateAnalysis:
        if cls is not BgpUpdateAnalysis:
            raise BgpUpdateAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, nodes = _capture(document, budget, report=True)
        budget.charge(8 * (size + nodes))
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> BgpUpdateAnalysis:
        if cls is not BgpUpdateAnalysis:
            raise BgpUpdateAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> BgpUpdateAnalysis:
    result = object.__new__(BgpUpdateAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_bgp_update(model: Any) -> BgpUpdateAnalysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_bgp_update_bytes(*, model_bytes: Any) -> BgpUpdateAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise BgpUpdateAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(4 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BgpUpdateAnalysisError("Closed JSON metadata requires ASCII") from exc
    source, _, _ = _decode(text, budget)
    return _owned(_materialize(_plan(source, budget)))


def verify_supplied_bgp_update_analysis(report: Any, *, model: Any) -> BgpUpdateAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(8 * (embedded.size + original.size + embedded.nodes + original.nodes))
    reconstructed = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, reconstructed)
    if reconstructed != separate:
        raise BgpUpdateAnalysisError("Report differs from separately supplied original model")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh synthetic 45-octet UPDATE; no digest or source acquisition."""
    raw = bytes.fromhex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF002D0200000012400101004002040201FC00400304C000020118CB0071"
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-bgp-update",
        "asn_width_octets": 2,
        "update_base64": base64.b64encode(raw).decode("ascii"),
    }


__all__ = [
    "BgpUpdateAnalysis",
    "BgpUpdateAnalysisError",
    "analyze_supplied_bgp_update",
    "analyze_supplied_bgp_update_bytes",
    "verify_supplied_bgp_update_analysis",
    "component_fixture",
]

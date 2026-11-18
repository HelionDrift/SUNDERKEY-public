"""Finite supplied SHA1 PACK base-object and backward OFS_DELTA reconstruction."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import zlib
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "git_supplied_pack_ofs_delta_reconstruction"
PROFILE_ID = "AOE-GC-D17-S01"
CAPABILITY_ID = "army.gc.d17.s01"
VECTOR_ID = "AV-GC-D17-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S01"
WAVE_ID = "IW2-013"
BLUEPRINT_SHA256 = "sha256:a9bc1a2fbb55b2917d9bfd1cfafade6c599bc01a0fb47961f3ebfc79b3bab1c4"
SEMANTICS_PROFILE = "git-2.54-supplied-sha1-pack-ofs-reconstruction.v1"
MODEL_DOMAIN = "sunderkey.offline-git-pack-model.v1"
DOMAIN = "sunderkey.offline-git-pack-analysis.v1"
MAX_PACK_BYTES = 524_288
MAX_MODEL_BYTES = 1_048_576
MAX_REPORT_BYTES = 2_097_152
MAX_OBJECTS = 256
MAX_OBJECT_BYTES = 524_288
MAX_TOTAL_INFLATED_BYTES = 2_097_152
MAX_TOTAL_RECONSTRUCTED_BYTES = 2_097_152
MAX_DELTA_DEPTH = 32
MAX_DELTA_INSTRUCTIONS = 8_192
MAX_INFLATE_CALLS = 4_096
INFLATE_CHUNK_BYTES = 4_096
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 262_144
MAX_DEPTH = 16
MAX_STRING_BYTES = 699_052
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "object_format", "pack_base64"}
_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
_SHA256_PLACEHOLDER = "sha256:" + "0" * 64
_SHA1_PLACEHOLDER = "sha1:" + "0" * 40
_ID_PLACEHOLDER = "GPA-" + "0" * 32
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
        "checkout",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "sha1_security_recommended",
        "repository_validity_proven",
        "object_content_validity_proven",
        "reachable_refs_proven",
        "signature_verified",
        "content_safety_proven",
        "full_pack_format_coverage",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Only supplied SHA1 PACK versions two/three, base types and backward OFS_DELTA are supported.",
    "REF_DELTA, thin packs, SHA256 format and preset zlib dictionaries are outside this subset.",
    "SHA1 is a mechanical format identity/checksum, "
    "not authentication or a security recommendation.",
    "Commit/tree/tag bodies are opaque reconstructed bytes, not validated repository content.",
    "Reconstruction proves no refs, checkout, signature, provenance, "
    "safety or live repository facts.",
    "Canonical parsed model provenance is distinct from original raw JSON byte provenance.",
    "Checksum mismatch is an adverse consistency observation, "
    "not an authenticated provider result.",
    "Independent software ceilings apply; "
    "not every simultaneous maximum fits retained output/work.",
    "No full specialist, qualification, routing or deployment approval follows.",
)


class GitPackAnalysisError(ValueError):
    """An exact contract, supported geometry, software ceiling or replay was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0
    inflate_calls: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise GitPackAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += amount

    def inflate(self, input_size: int, output_cap: int) -> None:
        if self.inflate_calls >= MAX_INFLATE_CALLS:
            raise GitPackAnalysisError("Cumulative bounded inflate-call ceiling exhausted")
        # Fund the compressed slice, both possible input-tail views and bounded
        # returned output plus destination retention BEFORE invoking the C decoder.
        self.charge(128 + 6 * input_size + 3 * output_cap)
        self.inflate_calls += 1


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > limit - size:
            raise GitPackAnalysisError("Escaped canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > MAX_DEPTH:
            raise GitPackAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise GitPackAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise GitPackAnalysisError("Closed metadata requires ASCII strings")
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
                raise GitPackAnalysisError("Exact native signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise GitPackAnalysisError("Cyclic native documents are rejected")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise GitPackAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise GitPackAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise GitPackAnalysisError("Exact native integer-only JSON families required")

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
        raise GitPackAnalysisError("Bounded raw integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    maximum = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise GitPackAnalysisError("Raw signed64 integer ceiling exhausted")
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
                raise GitPackAnalysisError("Incomplete raw JSON escape")
            if text[index] == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise GitPackAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise GitPackAnalysisError("Closed metadata requires ASCII strings")
                index += 4
            elif text[index] not in '\\"/bfnrt':
                raise GitPackAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise GitPackAnalysisError("Invalid raw JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise GitPackAnalysisError("Pre-decoder string ceiling exhausted")
        index += 1
    raise GitPackAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > limit or not text.isascii():
        raise GitPackAnalysisError("Bounded exact native ASCII JSON text required")
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
                raise GitPackAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise GitPackAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                    raise GitPackAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise GitPackAnalysisError("Unterminated raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise GitPackAnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise GitPackAnalysisError("Raw floating/nonfinite numbers are unsupported")

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
        raise GitPackAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_PACK_BYTES + 2) // 3):
        raise GitPackAnalysisError("Bounded exact native canonical base64 required")
    budget.charge(3 * len(text))
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise GitPackAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 0 <= length <= MAX_PACK_BYTES:
        raise GitPackAnalysisError("PACK software byte ceiling exhausted")
    budget.charge(4 * len(text) + 4 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise GitPackAnalysisError("Malformed supplied base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise GitPackAnalysisError("Noncanonical base64 spelling/padding bits")
    return raw


def _byte(raw: bytes, position: int, end: int, budget: _Budget) -> tuple[int, int]:
    budget.charge(4)
    if position >= end:
        raise GitPackAnalysisError("Truncated supported PACK field")
    return raw[position], position + 1


def _entry_header(raw: bytes, position: int, end: int, budget: _Budget) -> tuple[int, int, int]:
    first, position = _byte(raw, position, end, budget)
    kind, size, shift = (first >> 4) & 7, first & 15, 4
    current = first
    while current & 128:
        current, position = _byte(raw, position, end, budget)
        if shift >= 63 or (current & 127) > (MAX_INTEGER - size) >> shift:
            raise GitPackAnalysisError("PACK entry-size integer ceiling exhausted")
        size += (current & 127) << shift
        shift += 7
    if kind == 0:
        raise GitPackAnalysisError("Invalid zero PACK object type")
    if kind not in {*_TYPES, 6}:
        raise GitPackAnalysisError("Unsupported subset: reserved type or REF_DELTA")
    if size > MAX_OBJECT_BYTES:
        raise GitPackAnalysisError("Inflated entry software byte ceiling exhausted")
    return kind, size, position


def _ofs(raw: bytes, position: int, end: int, budget: _Budget) -> tuple[int, int]:
    current, position = _byte(raw, position, end, budget)
    distance = current & 127
    while current & 128:
        current, position = _byte(raw, position, end, budget)
        if distance + 1 > (MAX_INTEGER - (current & 127)) // 128:
            raise GitPackAnalysisError("OFS distance integer ceiling exhausted")
        distance = (distance + 1) * 128 + (current & 127)
    return distance, position


def _delta_size(data: bytes, position: int, budget: _Budget) -> tuple[int, int]:
    result = shift = 0
    while True:
        current, position = _byte(data, position, len(data), budget)
        if shift >= 63 or (current & 127) > (MAX_INTEGER - result) >> shift:
            raise GitPackAnalysisError("Delta-size integer ceiling exhausted")
        result += (current & 127) << shift
        if not current & 128:
            return result, position
        shift += 7


def _inflate(
    raw: bytes, start: int, end: int, expected: int, budget: _Budget
) -> tuple[bytes, int, int]:
    if end - start < 2:
        raise GitPackAnalysisError("Truncated zlib header")
    cmf, flg = raw[start], raw[start + 1]
    if cmf & 15 != 8 or cmf >> 4 > 7 or (cmf * 256 + flg) % 31:
        raise GitPackAnalysisError("Malformed supported zlib CM/window/FCHECK header")
    if flg & 32:
        raise GitPackAnalysisError("Unsupported subset: preset zlib dictionary")
    budget.charge(32_768 + 256)
    decoder = zlib.decompressobj(wbits=15)
    output = bytearray()
    position, calls = start, 0
    while not decoder.eof:
        if position >= end:
            raise GitPackAnalysisError("Truncated zlib stream or checksum")
        input_size = min(INFLATE_CHUNK_BYTES, end - position)
        output_cap = min(INFLATE_CHUNK_BYTES, expected - len(output) + 1)
        budget.inflate(input_size, output_cap)
        chunk = raw[position : position + input_size]
        try:
            expanded = decoder.decompress(chunk, max_length=output_cap)
        except zlib.error as exc:
            raise GitPackAnalysisError("Malformed supported zlib stream/checksum") from exc
        calls += 1
        # EOF unused_data and non-EOF unconsumed_tail are alternative next-byte
        # calculations, not two disjoint suffixes to subtract from the same input.
        tail = decoder.unused_data if decoder.eof else decoder.unconsumed_tail
        if len(tail) > input_size:
            raise GitPackAnalysisError("Invalid bounded zlib consumption result")
        consumed = input_size - len(tail)
        if len(expanded) > expected - len(output):
            raise GitPackAnalysisError("Inflated output exceeds declared entry size")
        output.extend(expanded)
        position += consumed
        if not consumed and not expanded and not decoder.eof:
            raise GitPackAnalysisError("Bounded zlib decoder made no progress")
    if len(output) != expected:
        raise GitPackAnalysisError("Inflated output differs from declared entry size")
    budget.charge(2 * len(output))
    return bytes(output), position, calls


@dataclass(slots=True)
class _Totals:
    inflated: int = 0
    reconstructed: int = 0
    instructions: int = 0
    inflate_calls: int = 0

    def retain(self, size: int, budget: _Budget) -> None:
        if size > MAX_OBJECT_BYTES or size > MAX_TOTAL_RECONSTRUCTED_BYTES - self.reconstructed:
            raise GitPackAnalysisError("Aggregate reconstructed-byte ceiling exhausted")
        budget.charge(4 * size + 32)
        self.reconstructed += size


@dataclass(frozen=True)
class _Object:
    offset: int
    kind: int
    data: bytes
    depth: int


def _delta(
    instructions: bytes, base: bytes, totals: _Totals, budget: _Budget
) -> tuple[bytes, int, int]:
    base_size, position = _delta_size(instructions, 0, budget)
    result_size, position = _delta_size(instructions, position, budget)
    if base_size != len(base):
        raise GitPackAnalysisError("Delta declared base size differs from retained base")
    totals.retain(result_size, budget)
    result = bytearray()
    copies = inserts = 0
    while position < len(instructions):
        if totals.instructions >= MAX_DELTA_INSTRUCTIONS:
            raise GitPackAnalysisError("Cumulative delta instruction ceiling exhausted")
        budget.charge(64)
        totals.instructions += 1
        command, position = _byte(instructions, position, len(instructions), budget)
        if command & 128:
            offset = size = 0
            for index in range(7):
                if command & (1 << index):
                    operand, position = _byte(instructions, position, len(instructions), budget)
                    if index < 4:
                        offset += operand << (8 * index)
                    else:
                        size += operand << (8 * (index - 4))
            size = size or 65_536
            if offset > len(base) or size > len(base) - offset:
                raise GitPackAnalysisError("Delta copy source exceeds retained base")
            if size > result_size - len(result):
                raise GitPackAnalysisError("Delta copy exceeds declared reconstructed size")
            budget.charge(4 * size)
            result.extend(base[offset : offset + size])
            copies += 1
        else:
            size = command
            if not size:
                raise GitPackAnalysisError("Reserved zero delta instruction")
            if size > len(instructions) - position or size > result_size - len(result):
                raise GitPackAnalysisError("Delta insert exceeds instruction/result bounds")
            budget.charge(4 * size)
            result.extend(instructions[position : position + size])
            position += size
            inserts += 1
    if len(result) != result_size:
        raise GitPackAnalysisError("Delta result differs from declared reconstructed size")
    budget.charge(2 * result_size)
    return bytes(result), copies, inserts


def _pack(raw: bytes, budget: _Budget) -> tuple[dict, list[_Object]]:
    budget.charge(512 + 4 * len(raw))
    if len(raw) < 32 or raw[:4] != b"PACK":
        raise GitPackAnalysisError("Truncated or missing supported PACK header/trailer")
    version = int.from_bytes(raw[4:8], "big")
    count = int.from_bytes(raw[8:12], "big")
    if version not in (2, 3):
        raise GitPackAnalysisError("Unsupported subset: PACK version outside two/three")
    if count > MAX_OBJECTS:
        raise GitPackAnalysisError("PACK object-count software ceiling exhausted")
    position, end = 12, len(raw) - 20
    objects: list[_Object] = []
    by_offset: dict[int, _Object] = {}
    rows = []
    totals = _Totals()
    retained_size = retained_nodes = 0
    for index in range(count):
        budget.charge(256)
        begin = position
        kind, size, position = _entry_header(raw, position, end, budget)
        base = None
        distance = None
        depth = 0
        if kind == 6:
            distance, position = _ofs(raw, position, end, budget)
            if not distance or distance > begin - 12 or begin - distance not in by_offset:
                raise GitPackAnalysisError("OFS base is not an earlier proven entry boundary")
            base = by_offset[begin - distance]
            depth = base.depth + 1
            if depth > MAX_DELTA_DEPTH:
                raise GitPackAnalysisError("Per-edge delta-depth software ceiling exhausted")
        if size > MAX_TOTAL_INFLATED_BYTES - totals.inflated:
            raise GitPackAnalysisError("Aggregate inflated-entry byte ceiling exhausted")
        budget.charge(2 * size)
        totals.inflated += size
        if base is None:
            totals.retain(size, budget)
        zlib_start = position
        inflated, position, calls = _inflate(raw, position, end, size, budget)
        totals.inflate_calls += calls
        copies = inserts = 0
        if base is None:
            data, resolved_kind = inflated, kind
        else:
            data, copies, inserts = _delta(inflated, base.data, totals, budget)
            resolved_kind = base.kind
        budget.charge(256 + 4 * len(data) + 4 * ((len(data) + 2) // 3))
        row = {
            "index": index,
            "entry_offset": begin,
            "end_offset": position,
            "packed_type": kind,
            "inflated_entry_bytes": size,
            "zlib_start_offset": zlib_start,
            "compressed_bytes_consumed": position - zlib_start,
            "inflate_calls": calls,
            "base_entry_offset": None if base is None else base.offset,
            "ofs_distance": distance,
            "resolved_type": _TYPES[resolved_kind],
            "reconstructed_bytes": len(data),
            "reconstructed_base64": base64.b64encode(data).decode("ascii"),
            "mechanical_object_sha1": _SHA1_PLACEHOLDER,
            "delta_depth": depth,
            "copy_instructions": copies,
            "insert_instructions": inserts,
        }
        row_size, row_nodes = _measure(row, budget, report=True)
        if row_size + 1 > MAX_REPORT_BYTES - retained_size:
            raise GitPackAnalysisError("Cumulative reconstructed output byte ceiling exhausted")
        if row_nodes > MAX_REPORT_NODES - retained_nodes:
            raise GitPackAnalysisError("Cumulative reconstructed output node ceiling exhausted")
        budget.charge(4 * (row_size + row_nodes))
        retained_size += row_size + 1
        retained_nodes += row_nodes
        stored = _Object(begin, resolved_kind, data, depth)
        objects.append(stored)
        by_offset[begin] = stored
        rows.append(row)
    if position != end:
        raise GitPackAnalysisError("Counted objects do not exactly consume the PACK body")
    budget.charge(80)
    return {
        "version": version,
        "object_count": count,
        "trailer_offset": end,
        "declared_pack_sha1": "sha1:" + raw[end:].hex(),
        "computed_pack_sha1": _SHA1_PLACEHOLDER,
        "checksum_matches": False,
        "outcome": "supported_pack_reconstruction_consistent",
        "total_inflated_entry_bytes": totals.inflated,
        "total_reconstructed_bytes": totals.reconstructed,
        "total_delta_instructions": totals.instructions,
        "total_inflate_calls": totals.inflate_calls,
        "entries": rows,
    }, objects


@dataclass(frozen=True)
class _Plan:
    document: dict
    size: int
    raw: bytes
    objects: list[_Object]


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise GitPackAnalysisError("Exact native closed source dictionary required")
    source, source_size = _capture(model, budget)
    if source.keys() != _MODEL_FIELDS:
        raise GitPackAnalysisError("Exact closed four-field source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise GitPackAnalysisError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _SOURCE_ID.fullmatch(source["source_id"]) is None:
        raise GitPackAnalysisError("Bounded exact native source label required")
    if source["object_format"] != "sha1" or type(source["object_format"]) is not str:
        raise GitPackAnalysisError("Unsupported subset: only explicit sha1 object format")
    raw = _wire(source["pack_base64"], budget)
    pack, objects = _pack(raw, budget)
    document = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_profile_id": "AOE-GC-D17-CMD",
        "group_commander_profile_id": "AOE-HQ-05",
        "independent_validator_id": "AOE-HQ-19",
        "blueprint_sha256": BLUEPRINT_SHA256,
        "roadmap_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA256_PLACEHOLDER,
        "source_model": source,
        "source_model_sha256": _SHA256_PLACEHOLDER,
        "source_pack_sha256": _SHA256_PLACEHOLDER,
        "source_pack_bytes": len(raw),
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": {
            "maximum_pack_bytes": MAX_PACK_BYTES,
            "maximum_model_bytes": MAX_MODEL_BYTES,
            "maximum_report_bytes": MAX_REPORT_BYTES,
            "maximum_objects": MAX_OBJECTS,
            "maximum_inflated_entry_or_object_bytes": MAX_OBJECT_BYTES,
            "maximum_total_inflated_bytes": MAX_TOTAL_INFLATED_BYTES,
            "maximum_total_reconstructed_bytes": MAX_TOTAL_RECONSTRUCTED_BYTES,
            "maximum_delta_depth": MAX_DELTA_DEPTH,
            "maximum_delta_instructions": MAX_DELTA_INSTRUCTIONS,
            "maximum_inflate_calls_per_public_operation": MAX_INFLATE_CALLS,
            "maximum_compressed_input_chunk_bytes": INFLATE_CHUNK_BYTES,
            "maximum_model_nodes": MAX_MODEL_NODES,
            "maximum_report_nodes": MAX_REPORT_NODES,
            "scalar_inclusive_depth": MAX_DEPTH,
            "maximum_string_bytes": MAX_STRING_BYTES,
            "maximum_cumulative_work": MAX_WORK,
        },
        "pack": pack,
    }
    document, size = _capture(document, budget, report=True)
    # All later hashes/loose-object header construction/output encodings are
    # funded here. The longest outcome and False placeholder reserve both checksum
    # branches before any SHA. Replay/final comparison adds its reservation first.
    budget.charge(
        10 * size
        + 4 * source_size
        + 4 * len(raw)
        + sum(4 * len(obj.data) + 128 for obj in objects)
        + len(DOMAIN)
        + len(MODEL_DOMAIN)
        + 2
    )
    return _Plan(document, size, raw, objects)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    pack = document["pack"]
    computed = "sha1:" + hashlib.sha1(plan.raw[: pack["trailer_offset"]]).hexdigest()
    pack["computed_pack_sha1"] = computed
    matches = computed == pack["declared_pack_sha1"]
    pack["checksum_matches"] = matches
    if not matches:
        pack["outcome"] = "declared_pack_checksum_mismatch"
    for row, obj in zip(pack["entries"], plan.objects, strict=True):
        loose = _TYPES[obj.kind].encode("ascii") + b" " + str(len(obj.data)).encode("ascii") + b"\0"
        row["mechanical_object_sha1"] = "sha1:" + hashlib.sha1(loose + obj.data).hexdigest()
    document["source_pack_sha256"] = "sha256:" + hashlib.sha256(plan.raw).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "GPA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise GitPackAnalysisError("Report requires its complete embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size)
    return document, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise GitPackAnalysisError("Canonical report does not replay its complete embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not GitPackAnalysis or not hasattr(report, "document_json"):
        raise GitPackAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise GitPackAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class GitPackAnalysis:
    """Owned unsigned reconstructed bytes, fully rederived at every public export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not GitPackAnalysis:
            raise GitPackAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> GitPackAnalysis:
        if cls is not GitPackAnalysis:
            raise GitPackAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> GitPackAnalysis:
        if cls is not GitPackAnalysis:
            raise GitPackAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> GitPackAnalysis:
    result = object.__new__(GitPackAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_git_pack(model: Any) -> GitPackAnalysis:
    """Reconstruct bounded supplied bytes, without repository or external effects."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_git_pack_bytes(*, model_bytes: Any) -> GitPackAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise GitPackAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GitPackAnalysisError("Closed JSON metadata requires ASCII encoding") from exc
    source, _ = _decode(text, budget)
    return _owned(_materialize(_plan(source, budget)))


def verify_supplied_git_pack_analysis(report: Any, *, model: Any) -> GitPackAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, expected)
    if expected != separate:
        raise GitPackAnalysisError("Report differs from the separately supplied original model")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh inert base blob plus OFS delta, with no acquired repository contents."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-pack",
        "object_format": "sha1",
        "pack_base64": (
            "UEFDSwAAAAIAAAACNngBAQYA+f9hYmNkZWYIHgJWahJ4AQEKAPX/BgaQAgJYWZEE"
            "AgnvAenosoLsqXI0DNXDgVVqlnLWhv/yZw=="
        ),
    }


__all__ = [
    "GitPackAnalysis",
    "GitPackAnalysisError",
    "analyze_supplied_git_pack",
    "analyze_supplied_git_pack_bytes",
    "verify_supplied_git_pack_analysis",
    "component_fixture",
]

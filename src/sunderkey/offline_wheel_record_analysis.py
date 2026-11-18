"""Bounded, non-extracting integrity analysis of supplied Wheel ZIP bytes."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import re
import struct
import zlib
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "wheel_supplied_zip_record_integrity"
PROFILE_ID = "AOE-GC-D17-S05"
CAPABILITY_ID = "army.gc.d17.s05"
VECTOR_ID = "AV-GC-D17-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S05"
WAVE_ID = "IW2-017"
BLUEPRINT_SHA256 = "sha256:99ab56523d8c7702e8ffd8d5000755f794c03ed5e353113fb582539f787dfb20"
SEMANTICS_PROFILE = "pypa-wheel-zip-record-supplied-sha256-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-wheel-record-model.v1"
DOMAIN = "sunderkey.offline-wheel-record-analysis.v1"
MAX_WHEEL_BYTES = 524_288
MAX_MODEL_BYTES = 786_432
MAX_REPORT_BYTES = 2_097_152
MAX_MEMBER_BYTES = 524_288
MAX_EXPANDED_BYTES = 2_097_152
MAX_MEMBERS = 256
MAX_RECORD_BYTES = 262_144
MAX_NAME_BYTES = 255
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 65_536
MAX_DEPTH = 16
MAX_WORK = 134_217_728
MAX_INFLATE_CALLS = 4_096
INFLATE_CHUNK_BYTES = 4_096
INFLATE_OUTPUT_BYTES = 32_768
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_DIST = re.compile(r"[a-z][a-z0-9_]*\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)*\Z")
_TAG = re.compile(r"[A-Za-z0-9_.]+\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "wheel_filename", "wheel_base64"}
_EMPTY_SHA = "sha256:" + "0" * 64
_EMPTY_ID = "WRA-" + "0" * 32
_EFFECTS = dict.fromkeys(
    (
        "network",
        "target",
        "provider",
        "credential",
        "process",
        "execution",
        "installation",
        "publication",
        "authority",
        "qualification",
        "routing",
        "deployment",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "wheel_authenticated",
        "publisher_authenticated",
        "signature_verified",
        "safe_to_install",
        "installed",
        "metadata_semantics_verified",
        "full_wheel_coverage",
        "current_source_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Only supplied single-disk stored/deflate ZIP members with bounded ASCII names are analyzed.",
    (
        "ZIP64, encryption, alternate compression, Unicode-path overrides, "
        "and installation are unsupported."
    ),
    (
        "Only SHA-256 RECORD hashes and exact sizes are supported; "
        "stronger valid algorithms are unassessed."
    ),
    "Legacy RECORD.jws and RECORD.p7s are retained as unverified exempt bytes.",
    "ZIP CRC-32 is a transport consistency check, not the RECORD SHA-256 digest.",
    (
        "Coherent replacement of payload and RECORD can pass; "
        "no publisher or source authenticity follows."
    ),
    "No extraction, package execution, metadata compatibility, or safe-install conclusion follows.",
    "Independent software ceilings may refuse otherwise valid wheels.",
)


class WheelRecordAnalysisError(ValueError):
    """Closed input, unsupported subset, bounded work, or replay was refused."""


@dataclass(slots=True)
class _Budget:
    used: int = 0
    inflate_calls: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise WheelRecordAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += amount


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _measure(value: Any, budget: _Budget, *, report: bool = False) -> tuple[int, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    size = nodes = 0
    active: set[int] = set()

    def add(amount: int) -> None:
        nonlocal size
        if amount > limit - size:
            raise WheelRecordAnalysisError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > MAX_DEPTH:
            raise WheelRecordAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > limit:
                raise WheelRecordAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise WheelRecordAnalysisError("Closed metadata requires ASCII strings")
                if char in '\\"\b\t\n\f\r':
                    add(1)
                elif code < 32 or code == 127:
                    add(5)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise WheelRecordAnalysisError("Exact signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise WheelRecordAnalysisError("Cyclic native document")
            if len(item) * (2 if kind is dict else 1) > node_limit - nodes:
                raise WheelRecordAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise WheelRecordAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise WheelRecordAnalysisError("Exact native JSON scalar families required")

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
        raise WheelRecordAnalysisError("Bounded raw integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    maximum = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise WheelRecordAnalysisError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _raw_string(text: str, start: int, budget: _Budget) -> int:
    position = start + 1
    count = 0
    while position < len(text):
        char = text[position]
        if char == '"':
            return position + 1
        budget.charge(1)
        if char == "\\":
            position += 1
            if position >= len(text):
                raise WheelRecordAnalysisError("Incomplete raw escape")
            if text[position] == "u":
                digits = text[position + 1 : position + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise WheelRecordAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise WheelRecordAnalysisError("Closed metadata requires ASCII")
                position += 4
            elif text[position] not in '\\"/bfnrt':
                raise WheelRecordAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise WheelRecordAnalysisError("Invalid raw JSON control")
        count += 1
        if count > (MAX_REPORT_BYTES if len(text) > MAX_MODEL_BYTES else MAX_MODEL_BYTES):
            raise WheelRecordAnalysisError("Raw string ceiling exhausted")
        position += 1
    raise WheelRecordAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > limit or not text.isascii():
        raise WheelRecordAnalysisError("Bounded exact native ASCII JSON text required")
    budget.charge(2 * len(text))
    position = nodes = 0
    stack: list[str] = []
    while position < len(text):
        char = text[position]
        if char in " \t\r\n,:":
            position += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise WheelRecordAnalysisError("Malformed raw JSON container")
            position += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise WheelRecordAnalysisError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            position += 1
        elif char == '"':
            position = _raw_string(text, position, budget)
        else:
            start = position
            while position < len(text) and text[position] not in ' \t\r\n,:]}[{"':
                position += 1
                if position - start > 20:
                    raise WheelRecordAnalysisError("Pre-decoder scalar ceiling exhausted")
            token = text[start:position]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise WheelRecordAnalysisError("Unterminated raw JSON container")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise WheelRecordAnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise WheelRecordAnalysisError("Raw float/nonfinite values unsupported")

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
        raise WheelRecordAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(value: Any, budget: _Budget) -> bytes:
    if type(value) is not str or len(value) > 4 * ((MAX_WHEEL_BYTES + 2) // 3):
        raise WheelRecordAnalysisError("Bounded native wheel base64 required")
    budget.charge(3 * len(value))
    if len(value) % 4 or _B64.fullmatch(value) is None:
        raise WheelRecordAnalysisError("Canonical padded standard base64 required")
    length = len(value) // 4 * 3 - (len(value) - len(value.rstrip("=")))
    if not 0 <= length <= MAX_WHEEL_BYTES:
        raise WheelRecordAnalysisError("Wheel byte ceiling exhausted")
    budget.charge(4 * len(value) + 4 * length)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WheelRecordAnalysisError("Malformed wheel base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise WheelRecordAnalysisError("Noncanonical wheel base64")
    return raw


@dataclass(slots=True)
class _Member:
    name: str
    data: bytes
    compressed_size: int
    declared_crc: int
    crc_matches: bool
    method: int
    local_offset: int
    data_offset: int
    end_offset: int
    descriptor: str


def _name(raw: bytes) -> str:
    if not raw or len(raw) > MAX_NAME_BYTES or any(c < 33 or c > 126 for c in raw):
        raise WheelRecordAnalysisError("Unsupported subset: bounded printable ASCII names")
    name = raw.decode("ascii")
    parts = name.split("/")
    if (
        name.startswith("/")
        or name.endswith("/")
        or "\\" in name
        or ":" in name
        or any(part in ("", ".", "..") for part in parts)
    ):
        raise WheelRecordAnalysisError("Ambiguous or nonregular archive path")
    return name


def _inflate(data: bytes, maximum: int, budget: _Budget) -> bytes:
    decoder = zlib.decompressobj(-15)
    output = bytearray()
    position = 0
    while position < len(data):
        pending = data[position : position + INFLATE_CHUNK_BYTES]
        position += len(pending)
        while pending:
            if budget.inflate_calls >= MAX_INFLATE_CALLS:
                raise WheelRecordAnalysisError("Inflate call ceiling exhausted")
            remaining = min(maximum - len(output) + 1, INFLATE_OUTPUT_BYTES)
            if remaining <= 0:
                raise WheelRecordAnalysisError("Expanded wheel byte ceiling exhausted")
            budget.charge(128 + 6 * len(pending) + 4 * remaining)
            budget.inflate_calls += 1
            previous = len(pending)
            try:
                part = decoder.decompress(pending, remaining)
            except zlib.error as exc:
                raise WheelRecordAnalysisError("Malformed raw DEFLATE stream") from exc
            if len(part) > maximum - len(output):
                raise WheelRecordAnalysisError("Expanded wheel byte ceiling exhausted")
            output.extend(part)
            pending = decoder.unconsumed_tail
            if decoder.unused_data or (pending and len(pending) == previous and not part):
                raise WheelRecordAnalysisError("Ambiguous or non-progressing DEFLATE stream")
    budget.charge(128 + 4 * min(maximum - len(output) + 1, INFLATE_OUTPUT_BYTES))
    try:
        tail = decoder.flush(min(maximum - len(output) + 1, INFLATE_OUTPUT_BYTES))
    except zlib.error as exc:
        raise WheelRecordAnalysisError("Malformed DEFLATE termination") from exc
    if len(tail) > maximum - len(output) or not decoder.eof or decoder.unused_data:
        raise WheelRecordAnalysisError("Incomplete or oversized DEFLATE member")
    output.extend(tail)
    return bytes(output)


def _zip(raw: bytes, budget: _Budget) -> list[_Member]:
    if len(raw) < 22:
        raise WheelRecordAnalysisError("Truncated ZIP end record")
    budget.charge(8 * len(raw))
    candidates = []
    for position in range(max(0, len(raw) - 65_557), len(raw) - 21):
        if raw[position : position + 4] == b"PK\x05\x06":
            comment = int.from_bytes(raw[position + 20 : position + 22], "little")
            if position + 22 + comment == len(raw):
                candidates.append(position)
    if len(candidates) != 1:
        raise WheelRecordAnalysisError("One exact ZIP end record required")
    end = candidates[0]
    _, disk, central_disk, on_disk, count, central_size, central_start, _ = struct.unpack_from(
        "<IHHHHIIH", raw, end
    )
    if disk or central_disk or on_disk != count or count > MAX_MEMBERS:
        raise WheelRecordAnalysisError("Unsupported subset: single disk and bounded member count")
    if count == 0 or count == 65535 or central_size == 0xFFFFFFFF or central_start == 0xFFFFFFFF:
        raise WheelRecordAnalysisError("Unsupported subset: empty or ZIP64 directory")
    if central_start + central_size != end:
        raise WheelRecordAnalysisError("ZIP central extent mismatch")
    central = []
    position = central_start
    names: set[str] = set()
    folded: set[str] = set()
    for _ in range(count):
        budget.charge(256)
        if position + 46 > end or raw[position : position + 4] != b"PK\x01\x02":
            raise WheelRecordAnalysisError("Truncated ZIP central member")
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", raw, position)
        (
            _,
            made,
            needed,
            flags,
            method,
            _time,
            _date,
            crc,
            compressed,
            expanded,
            name_len,
            extra_len,
            comment_len,
            disk_start,
            _internal,
            external,
            local,
        ) = fields
        next_position = position + 46 + name_len + extra_len + comment_len
        if next_position > end:
            raise WheelRecordAnalysisError("Central member extent exceeds directory")
        if (
            extra_len
            or comment_len
            or disk_start
            or compressed == 0xFFFFFFFF
            or expanded == 0xFFFFFFFF
        ):
            raise WheelRecordAnalysisError(
                "Unsupported subset: extra, comment, disk or ZIP64 member"
            )
        if flags & ~(0x0008 | 0x0800) or method not in (0, 8):
            raise WheelRecordAnalysisError("Unsupported subset: flags or compression method")
        if (external & 0x10) or ((external >> 16) & 0xF000) not in (0, 0x8000):
            raise WheelRecordAnalysisError("Unsupported subset: nonregular archive member")
        name_raw = raw[position + 46 : position + 46 + name_len]
        name = _name(name_raw)
        if name in names or name.lower() in folded:
            raise WheelRecordAnalysisError("Duplicate or case-aliased archive member")
        names.add(name)
        folded.add(name.lower())
        if expanded > MAX_MEMBER_BYTES:
            raise WheelRecordAnalysisError("Per-member expanded byte ceiling exhausted")
        central.append((name, name_raw, needed, flags, method, crc, compressed, expanded, local))
        position = next_position
    if position != end:
        raise WheelRecordAnalysisError("Central directory count/extent mismatch")
    members = []
    ranges = []
    total_expanded = 0
    for name, name_raw, needed, flags, method, crc, compressed, expanded, local in central:
        budget.charge(256 + 4 * compressed)
        if local + 30 > central_start or raw[local : local + 4] != b"PK\x03\x04":
            raise WheelRecordAnalysisError("Missing addressed local member")
        (
            signature,
            local_needed,
            local_flags,
            local_method,
            _time,
            _date,
            local_crc,
            local_compressed,
            local_expanded,
            local_name_len,
            local_extra_len,
        ) = struct.unpack_from("<IHHHHHIIIHH", raw, local)
        if (
            signature != 0x04034B50
            or local_needed != needed
            or local_flags != flags
            or local_method != method
        ):
            raise WheelRecordAnalysisError("Local/central ZIP header disagreement")
        if local_extra_len or local_name_len != len(name_raw):
            raise WheelRecordAnalysisError("Unsupported subset: local extra or name mismatch")
        if raw[local + 30 : local + 30 + local_name_len] != name_raw:
            raise WheelRecordAnalysisError("Local/central ZIP filename disagreement")
        if flags & 0x0008:
            if local_crc or local_compressed or local_expanded:
                raise WheelRecordAnalysisError("Nonzero streaming local placeholders")
        elif (local_crc, local_compressed, local_expanded) != (crc, compressed, expanded):
            raise WheelRecordAnalysisError("Local/central ZIP CRC or size disagreement")
        data_start = local + 30 + local_name_len
        data_end = data_start + compressed
        if data_end > central_start:
            raise WheelRecordAnalysisError("Compressed member crosses central directory")
        descriptor = "none"
        member_end = data_end
        if flags & 0x0008:
            possibilities = []
            if data_end + 12 <= central_start:
                if struct.unpack_from("<III", raw, data_end) == (crc, compressed, expanded):
                    possibilities.append(("without_signature", data_end + 12))
            if data_end + 16 <= central_start and raw[data_end : data_end + 4] == b"PK\x07\x08":
                if struct.unpack_from("<III", raw, data_end + 4) == (crc, compressed, expanded):
                    possibilities.append(("with_signature", data_end + 16))
            if len(possibilities) != 1:
                raise WheelRecordAnalysisError("Missing or ambiguous ZIP data descriptor")
            descriptor, member_end = possibilities[0]
        ranges.append((local, member_end))
        maximum = min(MAX_MEMBER_BYTES, MAX_EXPANDED_BYTES - total_expanded)
        if expanded > maximum:
            raise WheelRecordAnalysisError("Aggregate expanded byte ceiling exhausted")
        wire_data = raw[data_start:data_end]
        if method == 0:
            budget.charge(4 * len(wire_data))
            data = wire_data
        else:
            data = _inflate(wire_data, maximum, budget)
        if len(data) != expanded:
            raise WheelRecordAnalysisError("ZIP declared expanded size mismatch")
        total_expanded += len(data)
        computed_crc = zlib.crc32(data) & 0xFFFFFFFF
        members.append(
            _Member(
                name,
                data,
                compressed,
                crc,
                computed_crc == crc,
                method,
                local,
                data_start,
                member_end,
                descriptor,
            )
        )
    ranges.sort()
    position = 0
    for start, end_offset in ranges:
        if start != position or end_offset <= start:
            raise WheelRecordAnalysisError("ZIP local ranges overlap or leave hidden bytes")
        position = end_offset
    if position != central_start:
        raise WheelRecordAnalysisError("Unaddressed bytes before ZIP central directory")
    return members


def _record(
    members: list[_Member], prefix: str, budget: _Budget
) -> dict[str, tuple[str | None, int | None]]:
    by_name = {member.name: member for member in members}
    required = (prefix + "METADATA", prefix + "WHEEL", prefix + "RECORD")
    if any(name not in by_name for name in required):
        raise WheelRecordAnalysisError("One complete declared dist-info trio required")
    record = by_name[required[2]].data
    if len(record) > MAX_RECORD_BYTES:
        raise WheelRecordAnalysisError("RECORD byte ceiling exhausted")
    budget.charge(8 * len(record))
    try:
        text = record.decode("utf-8")
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise WheelRecordAnalysisError("Malformed UTF-8 CSV RECORD") from exc
    found: dict[str, tuple[str | None, int | None]] = {}
    signatures = {prefix + "RECORD.jws", prefix + "RECORD.p7s"}
    try:
        for row_number, row in enumerate(rows, 1):
            budget.charge(1)
            if row_number > MAX_MEMBERS:
                raise WheelRecordAnalysisError("RECORD row ceiling exhausted")
            budget.charge(128 + sum(4 * len(cell) for cell in row))
            if len(row) != 3 or row[0] != _name(row[0].encode("utf-8")):
                raise WheelRecordAnalysisError("Exact three-field relative RECORD path required")
            name, digest, size = row
            if name in found or name in signatures or name not in by_name:
                raise WheelRecordAnalysisError("Duplicate, exempt or unknown RECORD path")
            if name == required[2]:
                if digest or size:
                    raise WheelRecordAnalysisError("RECORD cannot record its own digest or size")
                found[name] = (None, None)
                continue
            if not digest.startswith("sha256=") or _B64URL.fullmatch(digest[7:]) is None:
                raise WheelRecordAnalysisError(
                    "Unsupported subset: canonical SHA-256 RECORD digest"
                )
            try:
                digest_bytes = base64.urlsafe_b64decode(digest[7:] + "=")
            except (ValueError, binascii.Error) as exc:
                raise WheelRecordAnalysisError("Malformed RECORD digest") from exc
            if (
                len(digest_bytes) != 32
                or base64.urlsafe_b64encode(digest_bytes).rstrip(b"=").decode() != digest[7:]
            ):
                raise WheelRecordAnalysisError("Noncanonical RECORD URL-safe SHA-256")
            if not re.fullmatch(r"(?:0|[1-9][0-9]{0,6})", size):
                raise WheelRecordAnalysisError("Unsupported subset: exact bounded RECORD size")
            found[name] = ("sha256:" + digest_bytes.hex(), int(size))
    except csv.Error as exc:
        raise WheelRecordAnalysisError("Malformed UTF-8 CSV RECORD") from exc
    if set(found) != set(by_name) - signatures:
        raise WheelRecordAnalysisError("RECORD and archive ordinary member coverage differ")
    return found


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int
    raw: bytes
    members: list[_Member]
    recorded: dict[str, tuple[str | None, int | None]]


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise WheelRecordAnalysisError("Exact native closed source dictionary required")
    source, source_size = _capture(model, budget)
    if (
        source.keys() != _MODEL_FIELDS
        or type(source["schema_version"]) is not int
        or source["schema_version"] != 1
    ):
        raise WheelRecordAnalysisError("Exact closed schema-one source required")
    if type(source["source_id"]) is not str or _SOURCE.fullmatch(source["source_id"]) is None:
        raise WheelRecordAnalysisError("Bounded exact source label required")
    filename = source["wheel_filename"]
    if type(filename) is not str or not filename.endswith(".whl"):
        raise WheelRecordAnalysisError("Exact subset wheel filename required")
    pieces = filename[:-4].split("-")
    if (
        len(pieces) != 5
        or _DIST.fullmatch(pieces[0]) is None
        or _VERSION.fullmatch(pieces[1]) is None
        or any(_TAG.fullmatch(piece) is None for piece in pieces[2:])
    ):
        raise WheelRecordAnalysisError("Unsupported subset: simple five-field wheel filename")
    prefix = f"{pieces[0]}-{pieces[1]}.dist-info/"
    raw = _wire(source["wheel_base64"], budget)
    members = _zip(raw, budget)
    if any(
        member.name.split("/", 1)[0].lower().endswith(".dist-info")
        and not member.name.startswith(prefix)
        for member in members
    ):
        raise WheelRecordAnalysisError("Multiple or foreign dist-info directories")
    recorded = _record(members, prefix, budget)
    rows = []
    for member in members:
        declared, size = recorded.get(member.name, (None, None))
        rows.append(
            {
                "name": member.name,
                "compression_method": member.method,
                "compressed_size": member.compressed_size,
                "expanded_size": len(member.data),
                "local_header_offset": member.local_offset,
                "file_data_offset": member.data_offset,
                "member_end_offset": member.end_offset,
                "data_descriptor": member.descriptor,
                "zip_crc32_declared": f"{member.declared_crc:08x}",
                "zip_crc32_matches": member.crc_matches,
                "record_sha256_declared": declared,
                "record_size_declared": size,
                "computed_sha256": _EMPTY_SHA,
                "record_digest_matches": False if declared is not None else None,
                "record_size_matches": (size == len(member.data)) if size is not None else None,
                "record_exempt": member.name
                in {prefix + "RECORD", prefix + "RECORD.jws", prefix + "RECORD.p7s"},
            }
        )
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
        "analysis_id": _EMPTY_ID,
        "analysis_sha256": _EMPTY_SHA,
        "source_model": source,
        "source_model_sha256": _EMPTY_SHA,
        "source_wheel_sha256": _EMPTY_SHA,
        "source_wheel_bytes": len(raw),
        "record_path": prefix + "RECORD",
        "outcome": "internal_integrity_mismatch",
        "member_count": len(members),
        "members": rows,
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": {
            "maximum_wheel_bytes": MAX_WHEEL_BYTES,
            "maximum_model_bytes": MAX_MODEL_BYTES,
            "maximum_report_bytes": MAX_REPORT_BYTES,
            "maximum_member_bytes": MAX_MEMBER_BYTES,
            "maximum_aggregate_expanded_bytes": MAX_EXPANDED_BYTES,
            "maximum_members_and_record_rows": MAX_MEMBERS,
            "maximum_record_bytes": MAX_RECORD_BYTES,
            "maximum_name_bytes": MAX_NAME_BYTES,
            "maximum_model_nodes": MAX_MODEL_NODES,
            "maximum_report_nodes": MAX_REPORT_NODES,
            "scalar_inclusive_depth": MAX_DEPTH,
            "maximum_cumulative_work": MAX_WORK,
        },
    }
    document, size = _capture(document, budget, report=True)
    budget.charge(
        12 * size
        + 6 * source_size
        + 6 * len(raw)
        + 4 * sum(len(member.data) for member in members)
        + 2_048
    )
    return _Plan(document, size, raw, members, recorded)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    good = True
    for row, member in zip(document["members"], plan.members, strict=True):
        actual = "sha256:" + hashlib.sha256(member.data).hexdigest()
        row["computed_sha256"] = actual
        declared, size = plan.recorded.get(member.name, (None, None))
        if declared is not None:
            row["record_digest_matches"] = actual == declared
            good = good and actual == declared and size == len(member.data)
        good = good and member.crc_matches
    document["outcome"] = "internal_integrity_matches" if good else "internal_integrity_mismatch"
    document["source_wheel_sha256"] = "sha256:" + hashlib.sha256(plan.raw).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    address = _digest(DOMAIN, body)
    document["analysis_sha256"] = address
    document["analysis_id"] = "WRA-" + address[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    actual, size = _decode(text, budget, report=True)
    if type(actual) is not dict or "source_model" not in actual:
        raise WheelRecordAnalysisError("Full embedded source required")
    plan = _plan(actual["source_model"], budget)
    budget.charge(4 * size + plan.size)
    return actual, plan


def _compare(text: str, actual: dict, expected: str) -> None:
    if text != _canonical(actual) or text != expected:
        raise WheelRecordAnalysisError("Complete canonical source/report replay mismatch")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if (
        type(report) is not WheelRecordAnalysis
        or not hasattr(report, "document_json")
        or type(report.document_json) is not str
    ):
        raise WheelRecordAnalysisError("Exact native complete report wrapper required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class WheelRecordAnalysis:
    """Unsigned supplied ZIP/RECORD observations, not provenance or install authority."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not WheelRecordAnalysis:
            raise WheelRecordAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> WheelRecordAnalysis:
        if cls is not WheelRecordAnalysis:
            raise WheelRecordAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> WheelRecordAnalysis:
        if cls is not WheelRecordAnalysis:
            raise WheelRecordAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> WheelRecordAnalysis:
    result = object.__new__(WheelRecordAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_wheel_record(model: Any) -> WheelRecordAnalysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_wheel_record_bytes(*, model_bytes: Any) -> WheelRecordAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise WheelRecordAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WheelRecordAnalysisError("Closed model requires ASCII JSON") from exc
    model, _ = _decode(text, budget)
    return _owned(_materialize(_plan(model, budget)))


def verify_supplied_wheel_record_analysis(report: Any, *, model: Any) -> WheelRecordAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    separate = _plan(model, budget)
    budget.charge(2 * (embedded.size + separate.size))
    expected = _materialize(embedded)
    original = _materialize(separate)
    _compare(text, actual, expected)
    if expected != original:
        raise WheelRecordAnalysisError("Separately supplied original wheel differs")
    return _owned(original)


def component_fixture() -> dict:
    """Return a fresh entirely synthetic four-file stored wheel model."""
    prefix = "sample_pkg-1.0.dist-info/"
    files = [
        ("sample_pkg/__init__.py", b"value = 7\n"),
        (prefix + "METADATA", b"Metadata-Version: 2.1\nName: sample-pkg\nVersion: 1.0\n"),
        (prefix + "WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
    ]
    record_rows = []
    for name, data in files:
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        )
        record_rows.append(f"{name},sha256={digest},{len(data)}\n")
    record_rows.append(f"{prefix}RECORD,,\n")
    files.append((prefix + "RECORD", "".join(record_rows).encode("ascii")))
    local = bytearray()
    central = bytearray()
    for name, data in files:
        encoded = name.encode("ascii")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        offset = len(local)
        local.extend(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(encoded),
                0,
            )
        )
        local.extend(encoded)
        local.extend(data)
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                0,
                0,
                0,
                crc,
                len(data),
                len(data),
                len(encoded),
                0,
                0,
                0,
                0,
                0,
                offset,
            )
        )
        central.extend(encoded)
    central_offset = len(local)
    local.extend(central)
    local.extend(
        struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), central_offset, 0
        )
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-wheel",
        "wheel_filename": "sample_pkg-1.0-py3-none-any.whl",
        "wheel_base64": base64.b64encode(bytes(local)).decode("ascii"),
    }


__all__ = [
    "WheelRecordAnalysis",
    "WheelRecordAnalysisError",
    "analyze_supplied_wheel_record",
    "analyze_supplied_wheel_record_bytes",
    "verify_supplied_wheel_record_analysis",
    "component_fixture",
]

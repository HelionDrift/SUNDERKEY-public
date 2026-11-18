"""Supplied numeric Wasm framing and stack types, not execution or full validation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "wasm_supplied_numeric_stack_and_interfaces"
PROFILE_ID = "AOE-GE-D21-S19"
CAPABILITY_ID = "army.ge.d21.s19"
VECTOR_ID = "AV-GE-D21-S19-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S19"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:5d56faef4e97aed134752503f33bf183368ef7c4d19189bcb1d69b524acc962d"
SEMANTICS_PROFILE = "wasm-w3c-wd-20220419-numeric-linear-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-wasm-numeric-stack-model.v1"
DOMAIN = "sunderkey.offline-wasm-numeric-stack-analysis.v1"
MAX_MODULE_BYTES = 262_144
MAX_MODEL_BYTES = 393_216
MAX_REPORT_BYTES = 2_097_152
MAX_SECTIONS = 256
MAX_TYPES = 128
MAX_IMPORTS = 128
MAX_EXPORTS = 128
MAX_FUNCTIONS = 128
MAX_PARAMETERS = 64
MAX_FRAMED_RESULTS = 64
MAX_EXPANDED_LOCALS = 16_384
MAX_INSTRUCTIONS = 65_536
MAX_STACK = 4_096
MAX_OBSERVATIONS = 1_024
MAX_NAME_BYTES = 128
MAX_TOTAL_NAME_BYTES = 16_384
MAX_DEPTH = 16
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 262_144
MAX_WORK = 134_217_728
MAX_BASE64_BYTES = 4 * ((MAX_MODULE_BYTES + 2) // 3)
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "module_base64"}
_PLACEHOLDER = "sha256:" + "0" * 64
_MAGIC = b"\x00asm\x01\x00\x00\x00"
_ORDER = {value: index for index, value in enumerate((1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 10, 11))}
_VALUE_TYPES = {
    0x7F: "i32",
    0x7E: "i64",
    0x7D: "f32",
    0x7C: "f64",
    0x7B: "v128",
    0x70: "funcref",
    0x6F: "externref",
}
_NUMERIC = {"i32", "i64", "f32", "f64"}
_BINOPS = {
    0x6A: "i32",
    0x6B: "i32",
    0x6C: "i32",
    0x7C: "i64",
    0x7D: "i64",
    0x7E: "i64",
    0x92: "f32",
    0x93: "f32",
    0x94: "f32",
    0xA0: "f64",
    0xA1: "f64",
    0xA2: "f64",
}
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "full_wasm_validation",
        "current_spec_conformance",
        "function_execution",
        "host_permissions_verified",
        "host_safety_verified",
        "exploit_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "network",
        "credential",
        "provider",
        "process",
        "filesystem",
        "execution",
        "authority",
        "deployment",
    ),
    "none",
)
_LIMITATIONS = (
    "An older April 2022 W3C Working Draft numeric-linear software subset is pinned.",
    "Binary version one is not a claim of complete current Wasm conformance.",
    "Only function interfaces and selected straight-line operand types are computed.",
    "Parameters are locals; the initial operand stack is empty.",
    "Calls apply declared types without executing, expanding or interpreting functions.",
    "Unsupported opcodes stop that body's semantic scan before guessing immediates.",
    "Known earlier contradictions remain adverse even when later semantics are unassessed.",
    "Deferred standard sections retain only extents, not validation of omitted internals.",
    "Multivalue and reference/vector signatures are framed but not resolved as numeric interfaces.",
    "Nonfunction import/export descriptors and unknown type constructors are refused "
    "as unsupported.",
    "Custom payloads are opaque after their bounded valid UTF8 names.",
    "Names retain exact bytes; no Unicode normalization, host linkage or permission claim occurs.",
    "Floating constants retain little-endian bits, not JSON floating-point values.",
    "Known stack contradictions are observations, not execution, safety or exploit proofs.",
    "Reports embed all supplied module bytes and are not sanitized publication artifacts.",
    "Joint maxima need not fit the cumulative output, node or work ceilings.",
)


class WasmNumericStackError(ValueError):
    """Closed-input, malformed framing, unsupported-subset, replay or cost refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise WasmNumericStackError("Cumulative software work ceiling exhausted")
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
            raise WasmNumericStackError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise WasmNumericStackError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES:
                raise WasmNumericStackError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise WasmNumericStackError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise WasmNumericStackError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise WasmNumericStackError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise WasmNumericStackError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise WasmNumericStackError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise WasmNumericStackError("Exact integer-only native JSON families required")

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
        raise WasmNumericStackError("Raw bounded integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    limit = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise WasmNumericStackError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise WasmNumericStackError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise WasmNumericStackError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise WasmNumericStackError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise WasmNumericStackError("Pre-decoder node/depth ceiling exhausted")
        if char in "[{":
            stack.append(char)
            index += 1
        elif char == '"':
            index += 1
            count = 0
            while index < len(text) and text[index] != '"':
                budget.charge(1)
                code = ord(text[index])
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise WasmNumericStackError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise WasmNumericStackError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise WasmNumericStackError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise WasmNumericStackError("Printable ASCII JSON strings required")
                count += 1
                if count > MAX_BASE64_BYTES:
                    raise WasmNumericStackError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise WasmNumericStackError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise WasmNumericStackError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise WasmNumericStackError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise WasmNumericStackError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise WasmNumericStackError("Integer-only raw JSON required")

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
        raise WasmNumericStackError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _source_shape(model: Any, budget: _Budget) -> None:
    if (
        type(model) is not dict
        or len(model) != 3
        or any(type(key) is not str for key in model)
        or model.keys() != _MODEL_FIELDS
    ):
        raise WasmNumericStackError("Exact closed native source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WasmNumericStackError("Exact native schema version one required")
    identity, encoded = model["source_id"], model["module_base64"]
    if type(identity) is not str or len(identity) > 64:
        raise WasmNumericStackError("Bounded native source identity required")
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise WasmNumericStackError("Bounded native module base64 required")
    budget.charge(256 + 2 * len(identity) + 2 * len(encoded))
    if _ID.fullmatch(identity) is None:
        raise WasmNumericStackError("Bounded ASCII source identity required")


def _module(model: dict, budget: _Budget) -> bytes:
    encoded = model["module_base64"]
    budget.charge(8 * len(encoded))
    if not encoded.isascii():
        raise WasmNumericStackError("ASCII module base64 required")
    raw = encoded.encode("ascii")
    if len(raw) % 4 or _BASE64.fullmatch(raw) is None:
        raise WasmNumericStackError("Canonical padded module base64 required")
    try:
        data = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WasmNumericStackError("Malformed module base64") from exc
    if len(data) < 8 or len(data) > MAX_MODULE_BYTES or base64.b64encode(data) != raw:
        raise WasmNumericStackError("Canonical bounded complete module bytes required")
    if data[:8] != _MAGIC:
        raise WasmNumericStackError("Supported binary magic and version one required")
    return data


@dataclass(slots=True)
class _Reader:
    data: bytes
    pos: int
    end: int
    budget: _Budget

    def byte(self) -> int:
        if self.pos >= self.end:
            raise WasmNumericStackError("Truncated known binary encoding")
        self.budget.charge(8)
        value = self.data[self.pos]
        self.pos += 1
        return value

    def take(self, size: int) -> bytes:
        if size > self.end - self.pos:
            raise WasmNumericStackError("Known binary extent overruns its container")
        self.budget.charge(4 * size + 16)
        value = self.data[self.pos : self.pos + size]
        self.pos += size
        return value

    def leb(self, bits: int = 32, *, signed: bool = False) -> int:
        value = 0
        maximum = (bits + 6) // 7
        for index in range(maximum):
            byte = self.byte()
            payload = byte & 0x7F
            value |= payload << (7 * index)
            if not byte & 0x80:
                if index == maximum - 1:
                    remaining = bits - 7 * index
                    mask = 0x7F ^ ((1 << remaining) - 1)
                    if signed:
                        upper = mask if payload & (1 << (remaining - 1)) else 0
                        if payload & mask != upper:
                            raise WasmNumericStackError("Malformed signed LEB terminal unused bits")
                    elif payload & mask:
                        raise WasmNumericStackError("Malformed unsigned LEB terminal unused bits")
                if signed and byte & 0x40:
                    value -= 1 << (7 * (index + 1))
                low = -(1 << (bits - 1)) if signed else 0
                high = (1 << (bits - (1 if signed else 0))) - 1
                if not low <= value <= high:
                    raise WasmNumericStackError("Known LEB value outside declared width")
                return value
        raise WasmNumericStackError("Known LEB encoding exceeds declared width")

    def count(self, maximum: int, *, unit: int = 128) -> int:
        count = self.leb()
        if count > maximum:
            raise WasmNumericStackError("Binary vector software ceiling exhausted")
        self.budget.charge(unit * count + 32)
        return count

    def exact_end(self) -> None:
        if self.pos != self.end:
            raise WasmNumericStackError("Known binary container has trailing contents")


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int

    def reserve(self, size: int, nodes: int, budget: _Budget) -> None:
        if size > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise WasmNumericStackError("Retained report byte/node ceiling exhausted")
        budget.charge(4 * (size + nodes))
        self.size += size
        self.nodes += nodes


class _Analyzer:
    def __init__(self, data: bytes, document: dict, budget: _Budget, retained: _Retained):
        self.data = data
        self.document = document
        self.budget = budget
        self.retained = retained
        self.names = self.locals = self.instructions = 0
        self.types: list[dict] = []
        self.function_types: list[int] = []
        self.defined_types: list[int] = []
        self.bodies: list[tuple[int, int]] = []
        self.contradictions = 0

    def reason(self, code: str) -> None:
        reasons = self.document["unassessed_reasons"]
        self.budget.charge(128 * (len(reasons) + 1))
        if code not in reasons:
            self.retained.reserve(256, 2, self.budget)
            reasons.append(code)

    def observe(
        self,
        kind: str,
        offset: int,
        *,
        function: int | None = None,
        opcode: int | None = None,
        index: int | None = None,
        signed: int | None = None,
        bits: str | None = None,
        inputs: list[str] | None = None,
        outputs: list[str] | None = None,
        observed: list[str] | None = None,
        expected: list[str] | None = None,
        code: str | None = None,
    ) -> None:
        rows = self.document["semantic_observations"]
        if len(rows) >= MAX_OBSERVATIONS:
            raise WasmNumericStackError("Semantic observation ceiling exhausted")
        arrays = (inputs or [], outputs or [], observed or [], expected or [])
        count = sum(len(value) for value in arrays)
        self.retained.reserve(768 + 16 * count, 40 + count, self.budget)
        rows.append(
            {
                "kind": kind,
                "function_index": function,
                "byte_offset": offset,
                "opcode": opcode,
                "index": index,
                "signed_value": signed,
                "float_bits_base64": bits,
                "input_types": list(arrays[0]),
                "output_types": list(arrays[1]),
                "observed_types": list(arrays[2]),
                "expected_types": list(arrays[3]),
                "code": code,
            }
        )
        if kind == "contradiction":
            self.contradictions += 1

    def name(self, reader: _Reader) -> tuple[bytes, dict]:
        size = reader.leb()
        if size > MAX_NAME_BYTES or size > MAX_TOTAL_NAME_BYTES - self.names:
            raise WasmNumericStackError("UTF8 name byte ceiling exhausted")
        self.budget.charge(16 * size + 128)
        raw = reader.take(size)
        try:
            raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise WasmNumericStackError("Malformed UTF8 binary name") from exc
        self.names += size
        return raw, {"name_base64": base64.b64encode(raw).decode("ascii"), "name_bytes": size}

    def value_type(self, reader: _Reader) -> str:
        byte = reader.byte()
        if byte not in _VALUE_TYPES:
            raise WasmNumericStackError("Unsupported value-type constructor in closed subset")
        return _VALUE_TYPES[byte]

    def type_section(self, reader: _Reader) -> None:
        count = reader.count(MAX_TYPES, unit=1024)
        for index in range(count):
            if reader.byte() != 0x60:
                raise WasmNumericStackError("Unsupported function-type constructor")
            parameters = reader.count(MAX_PARAMETERS)
            self.retained.reserve(512 + 24 * parameters, 20 + parameters, self.budget)
            params = [self.value_type(reader) for _ in range(parameters)]
            results = reader.count(MAX_FRAMED_RESULTS)
            self.retained.reserve(24 * results, results, self.budget)
            result = [self.value_type(reader) for _ in range(results)]
            supported = len(result) <= 1 and all(value in _NUMERIC for value in params + result)
            if not supported:
                self.reason("deferred_function_signature")
            row = {
                "type_index": index,
                "parameter_types": params,
                "result_types": result,
                "numeric_subset_supported": supported,
            }
            self.types.append(row)
            self.document["types"].append(row)
        reader.exact_end()

    def import_section(self, reader: _Reader) -> None:
        count = reader.count(MAX_IMPORTS, unit=1024)
        for index in range(count):
            self.retained.reserve(1536, 48, self.budget)
            _, module = self.name(reader)
            _, name = self.name(reader)
            if reader.byte() != 0:
                raise WasmNumericStackError("Nonfunction import descriptor is unsupported")
            at = reader.pos
            type_index = reader.leb()
            supported = (
                type_index < len(self.types) and self.types[type_index]["numeric_subset_supported"]
            )
            if type_index >= len(self.types):
                self.observe(
                    "contradiction",
                    at,
                    function=index,
                    index=type_index,
                    code="import_type_index_out_of_range",
                )
            self.function_types.append(type_index)
            self.document["imports"].append(
                {
                    "import_index": index,
                    "function_index": index,
                    "module_name": module,
                    "field_name": name,
                    "type_index": type_index,
                    "numeric_interface_resolved": supported,
                }
            )
        reader.exact_end()

    def function_section(self, reader: _Reader) -> None:
        count = reader.count(MAX_FUNCTIONS)
        for _ in range(count):
            at = reader.pos
            type_index = reader.leb()
            function = len(self.function_types)
            if type_index >= len(self.types):
                self.observe(
                    "contradiction",
                    at,
                    function=function,
                    index=type_index,
                    code="defined_type_index_out_of_range",
                )
            self.defined_types.append(type_index)
            self.function_types.append(type_index)
        reader.exact_end()

    def export_section(self, reader: _Reader) -> None:
        count = reader.count(MAX_EXPORTS, unit=1024)
        names: set[bytes] = set()
        for index in range(count):
            self.retained.reserve(1024, 36, self.budget)
            at = reader.pos
            raw, name = self.name(reader)
            if raw in names:
                self.observe("contradiction", at, code="duplicate_export_name")
            names.add(raw)
            if reader.byte() != 0:
                raise WasmNumericStackError("Nonfunction export descriptor is unsupported")
            at = reader.pos
            function = reader.leb()
            type_index = (
                self.function_types[function] if function < len(self.function_types) else None
            )
            supported = (
                type_index is not None
                and type_index < len(self.types)
                and self.types[type_index]["numeric_subset_supported"]
            )
            if type_index is None:
                self.observe(
                    "contradiction", at, index=function, code="export_function_index_out_of_range"
                )
            self.document["exports"].append(
                {
                    "export_index": index,
                    "name": name,
                    "function_index": function,
                    "type_index": type_index,
                    "numeric_interface_resolved": supported,
                }
            )
        reader.exact_end()

    def code_section(self, reader: _Reader) -> None:
        count = reader.count(MAX_FUNCTIONS)
        if count != len(self.defined_types):
            raise WasmNumericStackError("Function and code vector counts disagree")
        for _ in range(count):
            size = reader.leb()
            start = reader.pos
            if size > reader.end - start:
                raise WasmNumericStackError("Code body extent overruns code section")
            self.budget.charge(64 + 8 * size)
            self.bodies.append((start, start + size))
            reader.pos += size
        reader.exact_end()

    def sections(self) -> None:
        reader = _Reader(self.data, 8, len(self.data), self.budget)
        seen: set[int] = set()
        previous = -1
        while reader.pos < reader.end:
            if len(self.document["sections"]) >= MAX_SECTIONS:
                raise WasmNumericStackError("Section-row ceiling exhausted")
            self.retained.reserve(1024, 36, self.budget)
            start = reader.pos
            section = reader.byte()
            size = reader.leb()
            begin = reader.pos
            if size > reader.end - begin:
                raise WasmNumericStackError("Section extent overruns module")
            end = begin + size
            content = _Reader(self.data, begin, end, self.budget)
            name = None
            mode = "selected_numeric_framing"
            if section == 0:
                _, name = self.name(content)
                mode = "custom_name_and_opaque_payload"
            else:
                if section not in _ORDER:
                    raise WasmNumericStackError("Unsupported section id in pinned binary subset")
                if section in seen or _ORDER[section] <= previous:
                    raise WasmNumericStackError("Duplicate or out-of-order standard section")
                seen.add(section)
                previous = _ORDER[section]
                if section == 1:
                    self.type_section(content)
                elif section == 2:
                    self.import_section(content)
                elif section == 3:
                    self.function_section(content)
                elif section == 7:
                    self.export_section(content)
                elif section == 10:
                    self.code_section(content)
                else:
                    mode = "deferred_opaque_extent"
                    self.reason("deferred_standard_section_" + str(section))
            self.document["sections"].append(
                {
                    "section_index": len(self.document["sections"]),
                    "section_id": section,
                    "section_start": start,
                    "payload_start": begin,
                    "payload_end": end,
                    "payload_bytes": size,
                    "assessment": mode,
                    "custom_name": name,
                }
            )
            reader.pos = end
        if len(self.bodies) != len(self.defined_types):
            raise WasmNumericStackError("Function and code vector counts disagree")

    def body(self, defined: int, start: int, end: int) -> None:
        function = len(self.document["imports"]) + defined
        type_index = self.defined_types[defined]
        signature = self.types[type_index] if type_index < len(self.types) else None
        params = signature["parameter_types"] if signature is not None else []
        results = signature["result_types"] if signature is not None else []
        reader = _Reader(self.data, start, end, self.budget)
        groups = reader.count(MAX_EXPANDED_LOCALS, unit=64)
        if len(params) > MAX_EXPANDED_LOCALS - self.locals:
            raise WasmNumericStackError("Expanded locals including parameters ceiling exhausted")
        self.budget.charge(64 + 32 * len(params))
        locals_ = list(params)
        self.locals += len(params)
        for _ in range(groups):
            count = reader.leb()
            value = self.value_type(reader)
            if count > MAX_EXPANDED_LOCALS - self.locals:
                raise WasmNumericStackError(
                    "Expanded locals including parameters ceiling exhausted"
                )
            self.budget.charge(64 + 32 * count)
            locals_.extend([value] * count)
            self.locals += count
        instruction_start = reader.pos
        checking = (
            signature is not None
            and signature["numeric_subset_supported"]
            and all(value in _NUMERIC for value in locals_)
        )
        before = self.contradictions
        if signature is None:
            # The declaration's known index contradiction was already retained.
            checking = False
        if signature is not None and not checking:
            self.reason("deferred_body_local_or_signature_type")
        stack: list[str] = []
        known = checking
        maximum_stack = scanned = 0
        ended = complete = stopped_unsupported = False
        final: list[str] | None = None

        def contradiction(
            code: str,
            at: int,
            opcode: int,
            *,
            index: int | None = None,
            observed: list[str] | None = None,
            expected: list[str] | None = None,
        ) -> None:
            nonlocal known
            self.observe(
                "contradiction",
                at,
                function=function,
                opcode=opcode,
                index=index,
                observed=observed,
                expected=expected,
                code=code,
            )
            known = False

        def pop(expected: list[str] | None, at: int, opcode: int) -> None:
            nonlocal known
            if not known:
                return
            count = len(expected) if expected is not None else 1
            self.budget.charge(32 + 16 * count)
            if len(stack) < count:
                contradiction(
                    "operand_stack_underflow", at, opcode, observed=list(stack), expected=expected
                )
            elif expected is not None and stack[len(stack) - count :] != expected:
                contradiction(
                    "operand_type_mismatch",
                    at,
                    opcode,
                    observed=stack[len(stack) - count :],
                    expected=expected,
                )
            elif count:
                del stack[-count:]

        def push(values: list[str]) -> None:
            nonlocal maximum_stack
            if not known:
                return
            if len(values) > MAX_STACK - len(stack):
                raise WasmNumericStackError("Operand stack software ceiling exhausted")
            self.budget.charge(32 + 16 * len(values))
            stack.extend(values)
            maximum_stack = max(maximum_stack, len(stack))

        while reader.pos < end:
            if self.instructions >= MAX_INSTRUCTIONS:
                raise WasmNumericStackError("Scanned instruction ceiling exhausted")
            self.budget.charge(256)
            at = reader.pos
            opcode = reader.byte()
            self.instructions += 1
            scanned += 1
            if opcode == 0x0B:
                reader.exact_end()
                ended = complete = True
                if known:
                    self.budget.charge(64 + 32 * (len(stack) + len(results)))
                    final = list(stack)
                    if stack != results:
                        contradiction(
                            "terminal_result_stack_mismatch",
                            at,
                            opcode,
                            observed=stack,
                            expected=results,
                        )
                break
            if opcode == 0x01:
                continue
            if opcode == 0x1A:
                pop(None, at, opcode)
            elif opcode in (0x20, 0x21, 0x22):
                index = reader.leb()
                if index >= len(locals_):
                    contradiction("local_index_out_of_range", at, opcode, index=index)
                elif opcode == 0x20:
                    push([locals_[index]])
                else:
                    pop([locals_[index]], at, opcode)
                    if opcode == 0x22:
                        push([locals_[index]])
            elif opcode in (0x41, 0x42, 0x43, 0x44):
                value_type = _VALUE_TYPES[0x7F - (opcode - 0x41)]
                signed = (
                    reader.leb(32 if opcode == 0x41 else 64, signed=True) if opcode < 0x43 else None
                )
                bits = (
                    base64.b64encode(reader.take(4 if opcode == 0x43 else 8)).decode("ascii")
                    if opcode >= 0x43
                    else None
                )
                self.observe(
                    "constant",
                    at,
                    function=function,
                    opcode=opcode,
                    signed=signed,
                    bits=bits,
                    outputs=[value_type],
                )
                push([value_type])
            elif opcode in _BINOPS:
                value_type = _BINOPS[opcode]
                pop([value_type, value_type], at, opcode)
                push([value_type])
            elif opcode == 0x10:
                index = reader.leb()
                if index >= len(self.function_types):
                    contradiction("call_function_index_out_of_range", at, opcode, index=index)
                    continue
                called = self.function_types[index]
                if called >= len(self.types):
                    contradiction("call_type_index_out_of_range", at, opcode, index=called)
                    continue
                target = self.types[called]
                self.observe(
                    "direct_call",
                    at,
                    function=function,
                    opcode=opcode,
                    index=index,
                    inputs=target["parameter_types"],
                    outputs=target["result_types"],
                )
                if not target["numeric_subset_supported"]:
                    self.reason("deferred_call_signature")
                    stopped_unsupported = True
                    break
                pop(target["parameter_types"], at, opcode)
                push(target["result_types"])
            else:
                self.observe(
                    "unassessed_opcode",
                    at,
                    function=function,
                    opcode=opcode,
                    code="deferred_or_unknown_opcode",
                )
                self.reason("deferred_or_unknown_opcode")
                stopped_unsupported = True
                break
        if not ended and reader.pos == end and not stopped_unsupported:
            raise WasmNumericStackError("Known straight-line body has no terminal end")
        adverse = self.contradictions > before or signature is None
        conclusion = "adverse" if adverse else "consistent" if complete and known else "unassessed"
        if not complete or not checking:
            self.reason("terminal_stack_conclusion_withheld")
        self.retained.reserve(
            1024 + 16 * (len(locals_) + (len(final) if final is not None else 0)),
            64 + len(locals_) + (len(final) if final is not None else 0),
            self.budget,
        )
        self.document["functions"].append(
            {
                "defined_function_index": defined,
                "function_index": function,
                "type_index": type_index,
                "body_start": start,
                "body_end": end,
                "instruction_start": instruction_start,
                "parameter_count": len(params),
                "expanded_local_count": len(locals_),
                "local_types": list(locals_),
                "scanned_instruction_count": scanned,
                "maximum_operand_stack": maximum_stack,
                "terminal_end_observed": ended,
                "terminal_result_types": final,
                "selected_stack_conclusion": conclusion,
                "unscanned_instruction_bytes": end - reader.pos,
            }
        )

    def run(self) -> None:
        self.budget.charge(16 * len(self.data) + 8192)
        self.sections()
        for index, (start, end) in enumerate(self.bodies):
            self.body(index, start, end)
        self.document["expanded_locals_including_parameters"] = self.locals
        self.document["scanned_instruction_count"] = self.instructions
        self.document["total_name_bytes"] = self.names
        self.document["known_contradiction_count"] = self.contradictions
        self.document["selected_subset_status"] = (
            "adverse"
            if self.contradictions
            else "unassessed"
            if self.document["unassessed_reasons"]
            else "consistent"
        )


def _bounds() -> dict:
    return {
        "module_bytes": MAX_MODULE_BYTES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "sections": MAX_SECTIONS,
        "types": MAX_TYPES,
        "imports": MAX_IMPORTS,
        "exports": MAX_EXPORTS,
        "defined_functions": MAX_FUNCTIONS,
        "parameters_per_type": MAX_PARAMETERS,
        "framed_results_per_type": MAX_FRAMED_RESULTS,
        "supported_results_per_type": 1,
        "expanded_locals_including_parameters": MAX_EXPANDED_LOCALS,
        "scanned_instructions": MAX_INSTRUCTIONS,
        "operand_stack": MAX_STACK,
        "semantic_observations": MAX_OBSERVATIONS,
        "name_bytes": MAX_NAME_BYTES,
        "total_name_bytes": MAX_TOTAL_NAME_BYTES,
        "depth": MAX_DEPTH,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "whole_operation_work": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    module: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    _source_shape(model, budget)
    source, source_size, _ = _capture(model, budget)
    module = _module(source, budget)
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
        "source_file_sha256": _PLACEHOLDER,
        "source_file_bytes": len(module),
        "sections": [],
        "types": [],
        "imports": [],
        "exports": [],
        "functions": [],
        "semantic_observations": [],
        "expanded_locals_including_parameters": 0,
        "scanned_instruction_count": 0,
        "total_name_bytes": 0,
        "known_contradiction_count": 0,
        "selected_subset_status": "consistent",
        "unassessed_reasons": [],
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "WSA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    size, nodes = _measure(document, budget, report=True)
    analyzer = _Analyzer(module, document, budget, _Retained(size, nodes))
    analyzer.run()
    document, size, nodes = _capture(document, budget, report=True)
    # All content hashing, source/report encoding, equality and final serialization
    # are reserved before _materialize can perform the operation's first digest.
    budget.charge(
        12 * size
        + 4 * source_size
        + 8 * len(module)
        + 8 * nodes
        + len(MODEL_DOMAIN)
        + len(DOMAIN)
        + 2
    )
    return _Plan(document, module, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["source_file_sha256"] = "sha256:" + hashlib.sha256(plan.module).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "WSA-" + digest[7:39].upper()
    return _canonical(document)


def _report_shape(document: Any, budget: _Budget) -> None:
    scalar_text = {
        "component_id",
        "profile_id",
        "capability_id",
        "vector_id",
        "work_package_id",
        "wave_id",
        "commander_id",
        "group_owner_id",
        "independent_validator_id",
        "blueprint_sha256",
        "semantics_profile",
        "source_model_sha256",
        "source_file_sha256",
        "analysis_id",
        "analysis_sha256",
        "selected_subset_status",
    }
    scalar_counts = {
        "schema_version",
        "source_file_bytes",
        "expanded_locals_including_parameters",
        "scanned_instruction_count",
        "total_name_bytes",
        "known_contradiction_count",
    }
    arrays = {
        "sections",
        "types",
        "imports",
        "exports",
        "functions",
        "semantic_observations",
        "unassessed_reasons",
        "limitations",
    }
    fields = scalar_text | scalar_counts | arrays | {"source_model", "flags", "effects", "bounds"}
    if type(document) is not dict or document.keys() != fields:
        raise WasmNumericStackError("Exact closed report object required")
    budget.charge(8192)

    def text(value: Any, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if type(value) is not str:
            raise WasmNumericStackError("Exact native report text required")

    def integer(value: Any, *, nullable: bool = False, signed: bool = False) -> None:
        if value is None and nullable:
            return
        if type(value) is not int or not (MIN_INTEGER if signed else 0) <= value <= MAX_INTEGER:
            raise WasmNumericStackError("Exact bounded native report integer required")

    def boolean(value: Any) -> None:
        if type(value) is not bool:
            raise WasmNumericStackError("Exact native report boolean required")

    def types(value: Any, *, nullable: bool = False, maximum: int = MAX_EXPANDED_LOCALS) -> None:
        if value is None and nullable:
            return
        if type(value) is not list or len(value) > maximum:
            raise WasmNumericStackError("Bounded exact native type array required")
        for item in value:
            if type(item) is not str or item not in _VALUE_TYPES.values():
                raise WasmNumericStackError("Declared native value type required")

    def name(value: Any, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if type(value) is not dict or value.keys() != {"name_base64", "name_bytes"}:
            raise WasmNumericStackError("Exact closed name observation required")
        text(value["name_base64"])
        integer(value["name_bytes"])

    for key in scalar_text:
        text(document[key])
    for key in scalar_counts:
        integer(document[key])
    if document["schema_version"] != 1:
        raise WasmNumericStackError("Native report schema version one required")
    _source_shape(document["source_model"], budget)
    if (
        type(document["flags"]) is not dict
        or document["flags"].keys() != _FLAGS.keys()
        or any(type(value) is not bool or value for value in document["flags"].values())
    ):
        raise WasmNumericStackError("Exact nonpromoting report flags required")
    if (
        type(document["effects"]) is not dict
        or document["effects"].keys() != _EFFECTS.keys()
        or any(type(value) is not str or value != "none" for value in document["effects"].values())
    ):
        raise WasmNumericStackError("Exact no-effect report declarations required")
    if type(document["bounds"]) is not dict or document["bounds"].keys() != _bounds().keys():
        raise WasmNumericStackError("Exact bound projection required")
    for value in document["bounds"].values():
        integer(value)
    for key in ("unassessed_reasons", "limitations"):
        if type(document[key]) is not list or len(document[key]) > 128:
            raise WasmNumericStackError("Bounded exact native text array required")
        for value in document[key]:
            text(value)
    specifications = (
        (
            "sections",
            MAX_SECTIONS,
            {
                "section_index",
                "section_id",
                "section_start",
                "payload_start",
                "payload_end",
                "payload_bytes",
                "assessment",
                "custom_name",
            },
        ),
        (
            "types",
            MAX_TYPES,
            {"type_index", "parameter_types", "result_types", "numeric_subset_supported"},
        ),
        (
            "imports",
            MAX_IMPORTS,
            {
                "import_index",
                "function_index",
                "module_name",
                "field_name",
                "type_index",
                "numeric_interface_resolved",
            },
        ),
        (
            "exports",
            MAX_EXPORTS,
            {"export_index", "name", "function_index", "type_index", "numeric_interface_resolved"},
        ),
        (
            "functions",
            MAX_FUNCTIONS,
            {
                "defined_function_index",
                "function_index",
                "type_index",
                "body_start",
                "body_end",
                "instruction_start",
                "parameter_count",
                "expanded_local_count",
                "local_types",
                "scanned_instruction_count",
                "maximum_operand_stack",
                "terminal_end_observed",
                "terminal_result_types",
                "selected_stack_conclusion",
                "unscanned_instruction_bytes",
            },
        ),
        (
            "semantic_observations",
            MAX_OBSERVATIONS,
            {
                "kind",
                "function_index",
                "byte_offset",
                "opcode",
                "index",
                "signed_value",
                "float_bits_base64",
                "input_types",
                "output_types",
                "observed_types",
                "expected_types",
                "code",
            },
        ),
    )
    for key, maximum, row_fields in specifications:
        rows = document[key]
        if type(rows) is not list or len(rows) > maximum:
            raise WasmNumericStackError("Bounded exact native observation array required")
        budget.charge(512 * len(rows))
        for row in rows:
            if type(row) is not dict or row.keys() != row_fields:
                raise WasmNumericStackError("Exact closed observation row required")
            for field, value in row.items():
                if field in {"module_name", "field_name", "name", "custom_name"}:
                    name(value, nullable=field == "custom_name")
                elif field in {
                    "numeric_subset_supported",
                    "numeric_interface_resolved",
                    "terminal_end_observed",
                }:
                    boolean(value)
                elif field in {
                    "parameter_types",
                    "result_types",
                    "local_types",
                    "terminal_result_types",
                    "input_types",
                    "output_types",
                    "observed_types",
                    "expected_types",
                }:
                    types(value, nullable=field == "terminal_result_types")
                elif field in {
                    "assessment",
                    "selected_stack_conclusion",
                    "kind",
                    "code",
                    "float_bits_base64",
                }:
                    text(value, nullable=field in {"code", "float_bits_base64"})
                else:
                    integer(
                        value,
                        nullable=field
                        in {"function_index", "type_index", "opcode", "index", "signed_value"},
                        signed=field == "signed_value",
                    )


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document = _decode(text, budget, report=True)
    _report_shape(document, budget)
    size, nodes = _measure(document, budget, report=True)
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size + nodes)
    return document, expected


def _compare(text: str, document: dict, expected: str) -> None:
    actual = _canonical(document)
    if text != actual or actual != expected:
        raise WasmNumericStackError("Canonical report does not fully replay its embedded source")


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not WasmNumericStackAnalysis or not hasattr(report, "document_json"):
        raise WasmNumericStackError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise WasmNumericStackError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class WasmNumericStackAnalysis:
    """Owned unsigned metadata; exports replay the complete embedded original bytes."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not WasmNumericStackAnalysis:
            raise WasmNumericStackError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> WasmNumericStackAnalysis:
        if cls is not WasmNumericStackAnalysis or type(document) is not dict:
            raise WasmNumericStackError("Exact native report object and family required")
        budget = _Budget()
        size, nodes = _measure(document, budget, report=True)
        _report_shape(document, budget)
        budget.charge(4 * (size + nodes))
        owned = _clone(document)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> WasmNumericStackAnalysis:
        if cls is not WasmNumericStackAnalysis:
            raise WasmNumericStackError("Exact native report family required")
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


def _owned(text: str) -> WasmNumericStackAnalysis:
    result = object.__new__(WasmNumericStackAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_wasm_numeric_stack(model: Any) -> WasmNumericStackAnalysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_wasm_numeric_stack_bytes(*, model_bytes: Any) -> WasmNumericStackAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise WasmNumericStackError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WasmNumericStackError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_wasm_numeric_stack_analysis(
    report: Any, *, model: Any
) -> WasmNumericStackAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise WasmNumericStackError("Report does not replay the separately supplied original")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh synthetic module; imports are declarations, never host callbacks."""
    module = (
        b"\x00asm\x01\x00\x00\x00"
        b"\x01\x09\x02\x60\x01\x7f\x01\x7f\x60\x00\x00"
        b"\x02\x17\x02\x03env\x04same\x00\x00\x03env\x04same\x00\x00"
        b"\x03\x02\x01\x00"
        b"\x07\x07\x01\x03inc\x00\x02"
        b"\x0a\x0b\x01\x09\x00\x20\x00\x10\x00\x41\x01\x6a\x0b"
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-numeric-wasm",
        "module_base64": base64.b64encode(module).decode("ascii"),
    }


__all__ = [
    "WasmNumericStackAnalysis",
    "WasmNumericStackError",
    "analyze_supplied_wasm_numeric_stack",
    "analyze_supplied_wasm_numeric_stack_bytes",
    "verify_supplied_wasm_numeric_stack_analysis",
    "component_fixture",
]

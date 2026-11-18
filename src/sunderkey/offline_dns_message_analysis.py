"""Bounded structural observations of one supplied DNS message, without I/O."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "dns_supplied_wire_structure"
PROFILE_ID = "AOE-GC-D13-S03"
CAPABILITY_ID = "army.gc.d13.s03"
VECTOR_ID = "AV-GC-D13-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S03"
WAVE_ID = "IW2-006"
BLUEPRINT_SHA256 = "sha256:7ad8506c3f311239fe02108aa7905a21c74afb845bdc6594307294824b0b6bba"
DOMAIN = "sunderkey.offline-dns-message-analysis.v1"
SEMANTICS_PROFILE = "supplied-dns-known-name-boundaries-v1"
MAX_MESSAGE_BYTES = 65_535
MAX_MODEL_BYTES = 131_072
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NODES = 32_768
MAX_DEPTH = 16
MAX_QUESTIONS = 64
MAX_RECORDS = 256
MAX_NAMES = 832
MAX_POINTER_HOPS = 32
MAX_PROVEN_BOUNDARIES = 4096
MAX_EXPANDED_NAME_BYTES = 131_072
MAX_WORK = 262_144
MAX_TXT_STRINGS = 1024
MAX_OBSERVATIONS = 512
_MAX_BASE64 = 4 * ((MAX_MESSAGE_BYTES + 2) // 3)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_TYPES = {1: "a", 2: "ns", 5: "cname", 6: "soa", 12: "ptr", 15: "mx", 16: "txt", 28: "aaaa"}
_BOUNDS = {
    "maximum_message_bytes": MAX_MESSAGE_BYTES,
    "maximum_model_bytes": MAX_MODEL_BYTES,
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_native_nodes": MAX_NODES,
    "maximum_native_depth": MAX_DEPTH,
    "maximum_questions": MAX_QUESTIONS,
    "maximum_total_records": MAX_RECORDS,
    "maximum_names": MAX_NAMES,
    "maximum_pointer_hops_per_name": MAX_POINTER_HOPS,
    "maximum_proven_boundaries": MAX_PROVEN_BOUNDARIES,
    "maximum_total_expanded_name_bytes": MAX_EXPANDED_NAME_BYTES,
    "maximum_parser_work": MAX_WORK,
    "maximum_total_txt_strings": MAX_TXT_STRINGS,
    "maximum_observations": MAX_OBSERVATIONS,
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "execution",
        "target",
        "provider_requests",
        "routing",
        "qualification",
        "deployment",
    ),
    "none",
)
_LIMITATIONS = (
    "Supplied bytes and their provenance are unauthenticated declarations.",
    "Only one message and the declared finite IN record subset are analyzed.",
    "Prior proven name boundaries are required; opaque RDATA does not prove names.",
    "Unknown classes, types, opcodes, extensions, truncation and suffixes withhold completeness.",
    "Labels remain binary and case preserving; no hostname or Unicode normalization is performed.",
    "Unsigned flag and TTL values are observations, not timestamp, cache or authority evidence.",
    "No transport, resolver, EDNS, DNSSEC, delegation, bailiwick or cache behavior is validated.",
    "No vulnerability, current authority, complete specialist or qualification is established.",
)
_FIXED = {
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
    "input_provenance": "operator_supplied_unverified",
    "offline_only": True,
    "comprehensive_dns_validity_verified": False,
    "message_authenticity_verified": False,
    "vulnerability_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
    "effects": _EFFECTS,
    "limitations": list(_LIMITATIONS),
    "bounds": _BOUNDS,
}
_REPORT_FIELDS = set(_FIXED) | {
    "analysis_id",
    "analysis_sha256",
    "model",
    "source",
    "header",
    "sections",
    "confirmed_prefix_end",
    "counted_sections_complete",
    "unconsumed_bytes",
    "observations",
    "supported_checks_outcome",
    "costs",
}
_INTEGER_FIELDS = {
    "schema_version",
    "byte_count",
    "transaction_id",
    "raw_flags",
    "opcode",
    "response_code",
    "question_count",
    "answer_count",
    "authority_count",
    "additional_count",
    "index",
    "start",
    "end",
    "encoded_bytes",
    "expanded_wire_bytes",
    "type",
    "class",
    "ttl",
    "rdlength",
    "rdata_start",
    "preference",
    "serial",
    "refresh",
    "retry",
    "expire",
    "minimum",
    "confirmed_prefix_end",
    "unconsumed_bytes",
    "parser_work",
    "total_expanded_name_bytes",
    "names",
    "proven_boundaries",
    "txt_strings",
    "retained_fragment_bytes",
    "retained_fragment_nodes",
} | set(_BOUNDS)
_BOOLEAN_FIELDS = {
    "offline_only",
    "comprehensive_dns_validity_verified",
    "message_authenticity_verified",
    "vulnerability_proven",
    "live_use_approved",
    "qualification_claimed",
    "qr",
    "authoritative_answer",
    "truncated",
    "recursion_desired",
    "recursion_available",
    "reserved_z",
    "authenticated_data",
    "checking_disabled",
    "counted_sections_complete",
}


class DnsMessageAnalysisError(ValueError):
    """Intake, finite software costs or exact source replay failed."""


def _capture(
    value: Any, *, maximum_bytes: int = MAX_DOCUMENT_BYTES, maximum_nodes: int = MAX_NODES
) -> tuple[Any, int, int]:
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > maximum_bytes:
            raise DnsMessageAnalysisError("native JSON exceeds its aggregate byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > maximum_nodes:
            raise DnsMessageAnalysisError("native JSON exceeds its depth or node budget")
        kind = type(item)
        if kind is str:
            if len(item) > _MAX_BASE64:
                raise DnsMessageAnalysisError("native text exceeds the supported length")
            charge(len(item) + 2)
            if not item.isascii() or any(not 32 <= ord(char) <= 126 for char in item):
                raise DnsMessageAnalysisError("native text must be printable ASCII")
            charge(item.count('"') + item.count("\\"))
            return item
        if kind is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise DnsMessageAnalysisError("native integers must fit signed64")
            charge(len(str(item)))
            return item
        if kind is bool or item is None:
            charge(4 if item is True or item is None else 5)
            return item
        if kind not in (dict, list):
            raise DnsMessageAnalysisError("only exact native JSON families are supported")
        if id(item) in active or len(item) * (2 if kind is dict else 1) > maximum_nodes - nodes:
            raise DnsMessageAnalysisError("native JSON is cyclic or exceeds its node budget")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise DnsMessageAnalysisError("object keys must be exact native text")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 0), size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _sha(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _integer_token(token: str) -> int:
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    ceiling = "9223372036854775808" if negative else "9223372036854775807"
    if (
        len(token) > 20
        or _INTEGER.fullmatch(token) is None
        or len(digits) > 19
        or (len(digits) == 19 and digits > ceiling)
    ):
        raise DnsMessageAnalysisError("JSON integer is outside the signed64 lexical subset")
    return int(token)


def _json(text: Any, *, maximum_bytes: int = MAX_DOCUMENT_BYTES) -> Any:
    if type(text) is bytes:
        if not text or len(text) > maximum_bytes or not text.isascii():
            raise DnsMessageAnalysisError("JSON bytes must be bounded native ASCII")
        text = text.decode("ascii")
    if type(text) is not str or not text or len(text) > maximum_bytes or not text.isascii():
        raise DnsMessageAnalysisError("JSON must be bounded native ASCII text or bytes")
    position = nodes = depth = 0
    while position < len(text):
        char = text[position]
        if char in " \r\n\t,:]}":
            if char in "]}":
                depth -= 1
            position += 1
            continue
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise DnsMessageAnalysisError("raw JSON exceeds node or depth budget before decoding")
        if char in "[{":
            depth += 1
            position += 1
        elif char == '"':
            position += 1
            while position < len(text):
                char = text[position]
                position += 1
                if char == "\\":
                    position += 1
                elif char == '"':
                    break
        else:
            start = position
            while position < len(text) and text[position] not in ' \r\n\t,:[]{}"':
                position += 1
            token = text[start:position]
            if token.startswith("-") or token[:1].isdigit():
                _integer_token(token)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise DnsMessageAnalysisError("duplicate JSON object key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise DnsMessageAnalysisError("JSON floats and nonfinite numbers are unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer_token,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise DnsMessageAnalysisError("invalid bounded JSON") from exc
    return _capture(value, maximum_bytes=maximum_bytes)[0]


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise DnsMessageAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _model(value: Any) -> tuple[dict[str, Any], bytes]:
    model = _exact(
        _capture(value, maximum_bytes=MAX_MODEL_BYTES)[0],
        {"schema_version", "message_base64"},
        "DNS model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DnsMessageAnalysisError("schema_version must be native integer1")
    text = model["message_base64"]
    if type(text) is not str or not text or len(text) > _MAX_BASE64:
        raise DnsMessageAnalysisError("message must be bounded native canonical base64")
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DnsMessageAnalysisError("message base64 is malformed") from exc
    if not raw or len(raw) > MAX_MESSAGE_BYTES or base64.b64encode(raw).decode("ascii") != text:
        raise DnsMessageAnalysisError("message is empty, oversized or noncanonical base64")
    return model, raw


class _StopParsing(Exception):
    pass


class _Budget:
    def __init__(self) -> None:
        self.work = self.expanded = self.names = self.txt_strings = 0
        self.retained_bytes = self.retained_nodes = 0

    def charge(self, amount: int) -> None:
        self.work += amount
        if self.work > MAX_WORK:
            raise DnsMessageAnalysisError("parser work exceeds the supported budget")

    def retain(self, value: Any) -> Any:
        # Fragments are conservatively charged again when retained inside a parent.
        owned, size, nodes = _capture(
            value,
            maximum_bytes=MAX_DOCUMENT_BYTES - self.retained_bytes,
            maximum_nodes=MAX_NODES - self.retained_nodes,
        )
        self.retained_bytes += size
        self.retained_nodes += nodes
        return owned

    def encoded(self, raw: bytes) -> str:
        size = 4 * ((len(raw) + 2) // 3)
        if size + 2 > MAX_DOCUMENT_BYTES - self.retained_bytes:
            raise DnsMessageAnalysisError("encoded fragment exceeds retained output budget")
        self.charge(len(raw))
        return base64.b64encode(raw).decode("ascii")


class _Parser:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.budget = _Budget()
        self.header: dict[str, Any] | None = None
        self.sections: dict[str, list[dict[str, Any]]] = {
            "questions": [],
            "answers": [],
            "authority": [],
            "additional": [],
        }
        self.observations: list[dict[str, Any]] = []
        self.proven: set[int] = set()
        self.nonname: set[int] = set()
        self.prefix_end = 0
        self.complete = False

    def note(self, kind: str, code: str, start: int, end: int) -> None:
        if len(self.observations) >= MAX_OBSERVATIONS:
            raise DnsMessageAnalysisError("observations exceed the supported count")
        self.observations.append(
            self.budget.retain({"kind": kind, "code": code, "start": start, "end": end})
        )

    def stop(self, kind: str, code: str, start: int, end: int) -> None:
        self.note(kind, code, start, end)
        raise _StopParsing

    def need(self, start: int, count: int, code: str) -> None:
        self.budget.charge(count)
        if start + count > len(self.raw):
            self.stop("truncated", code, start, len(self.raw))

    def mark_nonname(self, start: int, end: int) -> None:
        self.budget.charge(end - start)
        self.nonname.update(range(start, end))

    def uint(self, start: int, count: int) -> int:
        self.budget.charge(count)
        return int.from_bytes(self.raw[start : start + count], "big")

    def name(self, start: int, field_end: int, *, rdata: bool = False) -> dict[str, Any]:
        if self.budget.names >= MAX_NAMES or self.budget.expanded >= MAX_EXPANDED_NAME_BYTES:
            raise DnsMessageAnalysisError("names exceed the aggregate expansion or count budget")
        position = start
        encoded_end: int | None = None
        labels: list[str] = []
        pointers: list[dict[str, int]] = []
        visited: set[int] = set()
        boundaries: set[int] = set()
        nonname: list[tuple[int, int]] = []
        expanded = 1
        while True:
            self.budget.charge(1)
            limit = field_end if encoded_end is None else len(self.raw)
            if position >= limit:
                self.stop(
                    "contradiction" if rdata and encoded_end is None else "truncated",
                    "name_exceeds_rdata" if rdata and encoded_end is None else "name_truncated",
                    position,
                    limit,
                )
            if position in visited:
                self.stop("contradiction", "compression_cycle", position, position + 1)
            visited.add(position)
            boundaries.add(position)
            length = self.raw[position]
            if length == 0:
                if encoded_end is None:
                    encoded_end = position + 1
                break
            if length & 0xC0 == 0xC0:
                if position + 2 > limit:
                    self.stop(
                        "contradiction" if rdata and encoded_end is None else "truncated",
                        "name_exceeds_rdata"
                        if rdata and encoded_end is None
                        else "compression_pointer_truncated",
                        position,
                        limit,
                    )
                self.budget.charge(1)
                target = ((length & 0x3F) << 8) | self.raw[position + 1]
                if target >= len(self.raw):
                    self.stop(
                        "contradiction",
                        "compression_target_outside_message",
                        position,
                        position + 2,
                    )
                if target >= position:
                    self.stop(
                        "contradiction", "compression_target_not_prior", position, position + 2
                    )
                if target in visited:
                    self.stop("contradiction", "compression_cycle", position, position + 2)
                if target < 12 or target in self.nonname:
                    self.stop(
                        "contradiction",
                        "compression_target_not_name_boundary",
                        position,
                        position + 2,
                    )
                if target not in self.proven:
                    self.stop("unassessed", "compression_target_not_proven", position, position + 2)
                if len(pointers) >= MAX_POINTER_HOPS:
                    raise DnsMessageAnalysisError("name exceeds the pointer-hop budget")
                pointers.append(self.budget.retain({"start": position, "target": target}))
                nonname.append((position + 1, position + 2))
                if encoded_end is None:
                    encoded_end = position + 2
                position = target
                continue
            if length & 0xC0:
                self.stop(
                    "unassessed", "extended_label_encoding_unassessed", position, position + 1
                )
            label_end = position + length + 1
            if label_end > limit:
                self.stop(
                    "contradiction" if rdata and encoded_end is None else "truncated",
                    "name_exceeds_rdata" if rdata and encoded_end is None else "label_truncated",
                    position,
                    limit,
                )
            expanded += length + 1
            if expanded > 255:
                self.stop(
                    "contradiction",
                    "expanded_name_exceeds_255_octets",
                    start,
                    encoded_end if encoded_end is not None else label_end,
                )
            if expanded > MAX_EXPANDED_NAME_BYTES - self.budget.expanded:
                raise DnsMessageAnalysisError("names exceed the aggregate expansion budget")
            self.budget.charge(length)
            label = self.budget.encoded(self.raw[position + 1 : label_end])
            labels.append(self.budget.retain(label))
            nonname.append((position + 1, label_end))
            position = label_end
        if (
            self.budget.names >= MAX_NAMES
            or expanded > MAX_EXPANDED_NAME_BYTES - self.budget.expanded
        ):
            raise DnsMessageAnalysisError("names exceed the aggregate expansion or count budget")
        additions = boundaries - self.proven
        if len(additions) > MAX_PROVEN_BOUNDARIES - len(self.proven):
            raise DnsMessageAnalysisError("proven name boundaries exceed the cache budget")
        self.budget.charge(len(boundaries))
        self.proven.update(additions)
        for left, right in nonname:
            self.mark_nonname(left, right)
        self.budget.expanded += expanded
        self.budget.names += 1
        return self.budget.retain(
            {
                "start": start,
                "end": encoded_end,
                "encoded_bytes": encoded_end - start,
                "expanded_wire_bytes": expanded,
                "labels_base64": labels,
                "pointer_chain": pointers,
            }
        )

    def rdata(self, rr_type: int, rr_class: int, start: int, end: int) -> dict[str, Any]:
        if rr_class != 1 or rr_type not in _TYPES:
            self.note("unassessed", "record_type_or_class_unassessed", start, end)
            return {
                "kind": "opaque_unassessed",
                "octets_base64": self.budget.encoded(self.raw[start:end]),
            }
        kind = _TYPES[rr_type]
        if kind in ("a", "aaaa"):
            if end - start != (4 if kind == "a" else 16):
                self.stop("contradiction", "rdata_size_mismatch", start, end)
            self.mark_nonname(start, end)
            return {"kind": kind, "address_octets_base64": self.budget.encoded(self.raw[start:end])}
        if kind == "txt":
            if start == end:
                self.stop("contradiction", "txt_requires_one_string", start, end)
            strings: list[str] = []
            position = start
            while position < end:
                if self.budget.txt_strings >= MAX_TXT_STRINGS:
                    raise DnsMessageAnalysisError("TXT strings exceed the aggregate count budget")
                self.budget.charge(1)
                string_end = position + 1 + self.raw[position]
                if string_end > end:
                    self.stop("contradiction", "txt_string_exceeds_rdata", position, end)
                strings.append(
                    self.budget.retain(self.budget.encoded(self.raw[position + 1 : string_end]))
                )
                self.budget.txt_strings += 1
                position = string_end
            self.mark_nonname(start, end)
            return {"kind": kind, "strings_base64": strings}
        position = start
        result: dict[str, Any] = {"kind": kind}
        if kind == "mx":
            if end - start < 2:
                self.stop("contradiction", "rdata_size_mismatch", start, end)
            result["preference"] = self.uint(position, 2)
            self.mark_nonname(position, position + 2)
            position += 2
        result["mname" if kind == "soa" else "name"] = self.name(position, end, rdata=True)
        position = result["mname" if kind == "soa" else "name"]["end"]
        if kind == "soa":
            result["rname"] = self.name(position, end, rdata=True)
            position = result["rname"]["end"]
            if end - position != 20:
                self.stop("contradiction", "rdata_size_mismatch", position, end)
            for field in ("serial", "refresh", "retry", "expire", "minimum"):
                result[field] = self.uint(position, 4)
                position += 4
            self.mark_nonname(position - 20, position)
        if position != end:
            self.stop("contradiction", "rdata_has_unconsumed_octets", position, end)
        return result

    def parse(self) -> None:
        try:
            self.need(0, 12, "header_truncated")
            values = [self.uint(index, 2) for index in range(0, 12, 2)]
            identifier, flags, questions, answers, authority, additional = values
            if questions > MAX_QUESTIONS or answers + authority + additional > MAX_RECORDS:
                raise DnsMessageAnalysisError("declared section counts exceed the software subset")
            self.header = self.budget.retain(
                {
                    "transaction_id": identifier,
                    "raw_flags": flags,
                    "qr": bool(flags & 0x8000),
                    "opcode": (flags >> 11) & 15,
                    "authoritative_answer": bool(flags & 0x0400),
                    "truncated": bool(flags & 0x0200),
                    "recursion_desired": bool(flags & 0x0100),
                    "recursion_available": bool(flags & 0x0080),
                    "reserved_z": bool(flags & 0x0040),
                    "authenticated_data": bool(flags & 0x0020),
                    "checking_disabled": bool(flags & 0x0010),
                    "response_code": flags & 15,
                    "question_count": questions,
                    "answer_count": answers,
                    "authority_count": authority,
                    "additional_count": additional,
                }
            )
            self.mark_nonname(0, 12)
            self.prefix_end = position = 12
            if self.header["opcode"]:
                self.stop("unassessed", "opcode_unassessed", 2, 4)
            if self.header["reserved_z"]:
                self.note("contradiction", "reserved_header_bit_set", 2, 4)
            if self.header["authenticated_data"] or self.header["checking_disabled"]:
                self.note("unassessed", "extension_flags_unassessed", 2, 4)
            if self.header["truncated"]:
                self.note("unassessed", "truncation_flag_set", 2, 4)
            for index in range(questions):
                start = position
                name = self.name(position, len(self.raw))
                position = name["end"]
                self.need(position, 4, "question_fields_truncated")
                rr_type, rr_class = self.uint(position, 2), self.uint(position + 2, 2)
                self.mark_nonname(position, position + 4)
                position += 4
                record = {
                    "index": index,
                    "start": start,
                    "end": position,
                    "name": name,
                    "type": rr_type,
                    "class": rr_class,
                }
                if rr_class != 1 or rr_type not in _TYPES:
                    self.note("unassessed", "question_type_or_class_unassessed", start, position)
                self.sections["questions"].append(self.budget.retain(record))
                self.prefix_end = position
            for section, count in (
                ("answers", answers),
                ("authority", authority),
                ("additional", additional),
            ):
                for index in range(count):
                    start = position
                    name = self.name(position, len(self.raw))
                    position = name["end"]
                    self.need(position, 10, "record_fields_truncated")
                    rr_type, rr_class = self.uint(position, 2), self.uint(position + 2, 2)
                    ttl, rdlength = self.uint(position + 4, 4), self.uint(position + 8, 2)
                    self.mark_nonname(position, position + 10)
                    rdata_start = position + 10
                    end = rdata_start + rdlength
                    self.need(rdata_start, rdlength, "rdata_truncated")
                    data = self.rdata(rr_type, rr_class, rdata_start, end)
                    record = {
                        "index": index,
                        "start": start,
                        "end": end,
                        "name": name,
                        "type": rr_type,
                        "class": rr_class,
                        "ttl": ttl,
                        "rdlength": rdlength,
                        "rdata_start": rdata_start,
                        "rdata": data,
                    }
                    self.sections[section].append(self.budget.retain(record))
                    self.prefix_end = position = end
            self.complete = True
            if position != len(self.raw):
                self.note("unassessed", "trailing_octets_unassessed", position, len(self.raw))
        except _StopParsing:
            return


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _sha(DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii"))
    return {"analysis_id": "DNS-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def _build(model: dict[str, Any], raw: bytes) -> dict[str, Any]:
    parser = _Parser(raw)
    parser.parse()
    budget = parser.budget
    outcome = (
        "contradictions"
        if any(note["kind"] == "contradiction" for note in parser.observations)
        else "incomplete"
        if parser.observations
        else "consistent_supplied_subset"
    )
    body = {
        **_FIXED,
        "model": model,
        "source": {
            "model_sha256": "sha256:" + "0" * 64,
            "message_sha256": "sha256:" + "0" * 64,
            "byte_count": len(raw),
        },
        "header": parser.header,
        "sections": parser.sections,
        "confirmed_prefix_end": parser.prefix_end,
        "counted_sections_complete": parser.complete,
        "unconsumed_bytes": len(raw) - parser.prefix_end,
        "observations": parser.observations,
        "supported_checks_outcome": outcome,
        "costs": {
            "parser_work": budget.work,
            "total_expanded_name_bytes": budget.expanded,
            "names": budget.names,
            "proven_boundaries": len(parser.proven),
            "txt_strings": budget.txt_strings,
            "retained_fragment_bytes": budget.retained_bytes,
            "retained_fragment_nodes": budget.retained_nodes,
        },
    }
    # Whole output (including original source and fixed-width addresses) is owned and
    # bounded before the first source or report hash, not after JSON allocation.
    document, _, _ = _capture(
        {"analysis_id": "DNS-" + "0" * 32, "analysis_sha256": "sha256:" + "0" * 64, **body},
        maximum_bytes=MAX_DOCUMENT_BYTES,
        maximum_nodes=MAX_NODES,
    )
    body = {
        key: child
        for key, child in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    body["source"]["model_sha256"] = _sha(_canonical(model).encode("ascii"))
    body["source"]["message_sha256"] = _sha(raw)
    return _address(body)


def _validate(document: Any) -> dict[str, Any]:
    owned = _exact(_capture(document)[0], _REPORT_FIELDS, "DNS analysis")
    for field, expected in _FIXED.items():
        if _canonical(owned[field]) != _canonical(expected):
            raise DnsMessageAnalysisError("analysis changes the fixed nonauthorizing profile")
    pending = [owned]
    while pending:
        value = pending.pop()
        if type(value) is dict:
            if set(value) == {"start", "target"} and type(value["target"]) is not int:
                raise DnsMessageAnalysisError("compression targets must be exact native integers")
            for key, child in value.items():
                if key in _INTEGER_FIELDS and type(child) is not int:
                    raise DnsMessageAnalysisError("integer metadata must be exact native integers")
                if key in _BOOLEAN_FIELDS and type(child) is not bool:
                    raise DnsMessageAnalysisError("boolean metadata must be exact native booleans")
                pending.append(child)
        elif type(value) is list:
            pending.extend(value)
    for field in ("analysis_sha256",):
        if type(owned[field]) is not str or _DIGEST.fullmatch(owned[field]) is None:
            raise DnsMessageAnalysisError("analysis digest is not canonical SHA-256")
    model, raw = _model(owned["model"])
    expected = _build(model, raw)
    if _canonical(owned) != _canonical(expected):
        raise DnsMessageAnalysisError("analysis does not replay its exact embedded message source")
    return expected


@dataclass(frozen=True, slots=True)
class DnsMessageAnalysis:
    """Detached replayable supplied-data observations, never authenticated DNS evidence."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise DnsMessageAnalysisError("analysis native slots are incomplete") from exc
        if type(text) is not str:
            raise DnsMessageAnalysisError("analysis document_json must be exact native text")
        return _validate(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> DnsMessageAnalysis:
        return cls(_canonical(_validate(document)))

    @classmethod
    def from_json(cls, document: str) -> DnsMessageAnalysis:
        return cls(document)


def analyze_supplied_dns_message(model: dict[str, Any]) -> DnsMessageAnalysis:
    """Observe one supplied message; no source acquisition or protocol execution occurs."""
    owned, raw = _model(model)
    return DnsMessageAnalysis(_canonical(_build(owned, raw)))


def analyze_supplied_dns_message_bytes(*, model_json: bytes | str) -> DnsMessageAnalysis:
    """Parse bounded duplicate-safe model JSON; raw JSON spelling is not provenance."""
    return analyze_supplied_dns_message(_json(model_json, maximum_bytes=MAX_MODEL_BYTES))


def verify_supplied_dns_message_analysis(
    report: DnsMessageAnalysis, *, model: dict[str, Any]
) -> DnsMessageAnalysis:
    """Replay against separately supplied original source, without conferring authority."""
    if type(report) is not DnsMessageAnalysis:
        raise DnsMessageAnalysisError("report must be the exact native DnsMessageAnalysis family")
    observed = report.to_json()
    expected = analyze_supplied_dns_message(model)
    if observed != expected.to_json():
        raise DnsMessageAnalysisError(
            "analysis does not replay the separately supplied original source"
        )
    return DnsMessageAnalysis.from_json(expected.to_json())


__all__ = [
    "BLUEPRINT_SHA256",
    "CAPABILITY_ID",
    "COMPONENT_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "WAVE_ID",
    "WORK_PACKAGE_ID",
    "DnsMessageAnalysis",
    "DnsMessageAnalysisError",
    "analyze_supplied_dns_message",
    "analyze_supplied_dns_message_bytes",
    "verify_supplied_dns_message_analysis",
]

"""Finite, passive framing analysis of one explicitly supplied HTTP/1.1 prefix."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D05-S03"
CAPABILITY_ID = "army.gb.d05.s03"
VECTOR_ID = "AV-GB-D05-S03-01"
WAVE_ID = "IW2-003"
DOMAIN = "sunderkey.offline-http-request-framing.v1"
SEMANTICS_PROFILE = "strict-crlf-supplied-http11-prefix-v1"
MAX_REQUEST_BYTES = 262_144
MAX_HEADER_BYTES = 65_536
MAX_LINE_BYTES = 8192
MAX_HEADERS = 256
MAX_CHUNKS = 1024
MAX_TRAILERS = 128
MAX_CODINGS = 32
MAX_LENGTH_VALUES = 256
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NODES = 65_536
MAX_DEPTH = 12
_MAX_BASE64 = 4 * ((MAX_REQUEST_BYTES + 2) // 3)
_MAX_INTEGER = 2**63 - 1
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_DECIMAL = re.compile(rb"[0-9]+\Z")
_HEX = re.compile(rb"[0-9A-Fa-f]+\Z")
_CATEGORIES = {
    b"host": "host",
    b"content-length": "content_length",
    b"transfer-encoding": "transfer_encoding",
    b"upgrade": "upgrade",
}
_FORBIDDEN_TRAILERS = {
    b"content-length",
    b"transfer-encoding",
    b"host",
    b"authorization",
    b"proxy-authorization",
    b"cookie",
    b"connection",
    b"upgrade",
    b"content-type",
    b"content-encoding",
    b"trailer",
}
_BOUNDS = {
    "maximum_request_bytes": MAX_REQUEST_BYTES,
    "maximum_header_bytes": MAX_HEADER_BYTES,
    "maximum_line_bytes": MAX_LINE_BYTES,
    "maximum_headers": MAX_HEADERS,
    "maximum_chunks": MAX_CHUNKS,
    "maximum_trailers": MAX_TRAILERS,
    "maximum_transfer_codings": MAX_CODINGS,
    "maximum_content_length_values": MAX_LENGTH_VALUES,
}
_EFFECTS = {
    "authority": "none",
    "target": "none",
    "execution": "none",
    "routing": "none",
    "qualification": "none",
    "deployment": "none",
    "provider_requests": "none",
}
_LIMITATIONS = (
    "The supplied bytes and their provenance are unverified declarations.",
    "Strict CRLF is this software subset, not every recipient's parsing behavior.",
    "Only one origin-form HTTP/1.1 request prefix is structurally analyzed.",
    "No target URI, application, authentication or general trailer semantics are validated.",
    "Other transfer codings, chunk extensions and protocol transitions are incomplete.",
    "Unconsumed suffix bytes are not parsed as another request or generated as a payload.",
    "No server behavior, parser disagreement, vulnerability, "
    "live authority or qualification is proved.",
    "No raw target, header value or body is emitted; this is not certified secret sanitization.",
)
_VIOLATIONS = {
    "line_ending_not_crlf": "strict_profile",
    "request_line_invalid": "strict_profile",
    "header_line_invalid": "protocol",
    "whitespace_before_colon": "protocol",
    "obsolete_line_folding": "strict_profile",
    "field_value_control_octet": "protocol",
    "host_field_count_invalid": "protocol",
    "host_field_empty": "protocol",
    "content_length_invalid": "protocol",
    "content_length_conflicting": "protocol",
    "transfer_coding_invalid": "protocol",
    "transfer_coding_empty": "strict_profile",
    "chunked_parameters": "strict_profile",
    "chunked_repeated": "protocol",
    "chunked_not_final": "protocol",
    "chunk_size_invalid": "protocol",
    "chunk_data_terminator_invalid": "strict_profile",
    "forbidden_trailer_field": "protocol",
}
_WARNINGS = {
    "content_length_repetition",
    "content_length_with_transfer_encoding",
    "unconsumed_suffix_not_parsed",
    "trailer_field_semantics_unverified",
}
_INCOMPLETE = {
    "line_terminator_missing",
    "line_length_outside_subset",
    "header_bytes_outside_subset",
    "field_count_outside_subset",
    "http_version_outside_subset",
    "request_target_outside_subset",
    "protocol_transition_outside_subset",
    "numeric_size_outside_subset",
    "content_length_list_outside_subset",
    "content_length_count_outside_subset",
    "transfer_coding_count_outside_subset",
    "transfer_parameters_outside_subset",
    "unsupported_transfer_coding",
    "chunk_extensions_outside_subset",
    "chunk_count_outside_subset",
    "chunk_data_incomplete",
    "content_length_body_incomplete",
}
_FRAMING_FIELDS = {
    "request_line_end",
    "header_start",
    "header_end",
    "body_start",
    "body_end",
    "body_framing",
    "body_complete",
    "body_payload_bytes",
    "headers",
    "content_length_values",
    "transfer_codings",
    "chunks",
    "trailers",
    "unconsumed_bytes",
}
_FIELD_FIELDS = {"index", "category", "line_start", "line_end", "value_start", "value_end"}
_CHUNK_FIELDS = {
    "index",
    "line_start",
    "line_end",
    "data_start",
    "data_end",
    "ending_end",
    "size",
    "is_last",
}
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "semantics_profile",
    "source",
    "bounds",
    "framing",
    "violations",
    "warnings",
    "incomplete_reasons",
    "supported_checks_outcome",
    "input_provenance",
    "offline_only",
    "server_vulnerability_proven",
    "live_use_approved",
    "qualification_claimed",
    "effects",
    "limitations",
}


class HttpRequestFramingError(ValueError):
    """Native intake, software costs, metadata integrity or source replay failed."""


def _capture(value: Any) -> Any:
    nodes = size = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_DOCUMENT_BYTES:
            raise HttpRequestFramingError("native JSON exceeds the aggregate byte budget")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise HttpRequestFramingError("native JSON exceeds depth or node budget")
        kind = type(item)
        if kind is str:
            if len(item) > _MAX_BASE64:
                raise HttpRequestFramingError("native text exceeds the supported length")
            charge(len(item) + 2)
            if not item.isascii() or any(not 32 <= ord(char) <= 126 for char in item):
                raise HttpRequestFramingError("native text must be printable ASCII")
            charge(item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if not -(2**63) <= item <= _MAX_INTEGER:
                raise HttpRequestFramingError("native integer exceeds signed64 subset")
            charge(len(str(item)))
            return item
        if kind not in (dict, list):
            raise HttpRequestFramingError("only exact native JSON families are supported")
        if len(item) * (2 if kind is dict else 1) > MAX_NODES - nodes or id(item) in active:
            raise HttpRequestFramingError("native JSON is oversized or cyclic")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise HttpRequestFramingError("native object keys must be exact text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _address(body: dict[str, Any]) -> dict[str, Any]:
    digest = _sha(DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii"))
    return {"analysis_id": "HFA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise HttpRequestFramingError(f"{label} has missing or unsupported fields")
    return value


def _integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise HttpRequestFramingError(f"{label} must be a bounded native integer")
    return value


def _json(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise HttpRequestFramingError("JSON must be bounded exact native ASCII text")
    quoted = escaped = False
    depth = 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise HttpRequestFramingError("JSON exceeds depth budget before decoding")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise HttpRequestFramingError("duplicate JSON field")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise HttpRequestFramingError("JSON floats and nonfinite numbers are unsupported")

    def integer(value: str) -> int:
        if len(value) > 20:
            raise HttpRequestFramingError("JSON integer exceeds signed64 subset")
        return int(value)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise HttpRequestFramingError("invalid bounded JSON") from exc
    return _capture(value)


def _model(model: Any) -> tuple[dict[str, Any], bytes]:
    owned = _exact(_capture(model), {"schema_version", "request_base64"}, "request model")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise HttpRequestFramingError("model schema_version must be native integer1")
    encoded = owned["request_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > _MAX_BASE64:
        raise HttpRequestFramingError("request must use bounded native canonical base64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HttpRequestFramingError("request base64 is malformed") from exc
    if not raw or len(raw) > MAX_REQUEST_BYTES or base64.b64encode(raw).decode("ascii") != encoded:
        raise HttpRequestFramingError("request is empty, oversized or noncanonical base64")
    return owned, raw


class _StopParsing(Exception):
    pass


class _Parser:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.violations: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []
        self.incomplete: list[dict[str, Any]] = []
        self.framing: dict[str, Any] = {
            "request_line_end": None,
            "header_start": None,
            "header_end": None,
            "body_start": None,
            "body_end": None,
            "body_framing": "undetermined",
            "body_complete": False,
            "body_payload_bytes": None,
            "headers": [],
            "content_length_values": [],
            "transfer_codings": [],
            "chunks": [],
            "trailers": [],
            "unconsumed_bytes": None,
        }

    def note(self, kind: str, code: str, start: int, end: int) -> None:
        entry = {"code": code, "start": start, "end": end}
        if kind == "violation":
            entry["basis"] = _VIOLATIONS[code]
        target = {
            "violation": self.violations,
            "warning": self.warnings,
            "incomplete": self.incomplete,
        }[kind]
        if entry not in target:
            target.append(entry)

    def stop(self, kind: str, code: str, start: int, end: int) -> None:
        self.note(kind, code, start, end)
        raise _StopParsing

    def line(self, start: int) -> tuple[bytes, int]:
        end = self.raw.find(b"\r\n", start, min(len(self.raw), start + MAX_LINE_BYTES + 2))
        scan_end = min(len(self.raw), start + MAX_LINE_BYTES + 1) if end < 0 else end
        candidate = self.raw[start:scan_end]
        if b"\r" in candidate or b"\n" in candidate:
            self.stop("violation", "line_ending_not_crlf", start, scan_end)
        if end < 0:
            code = (
                "line_length_outside_subset"
                if len(self.raw) - start > MAX_LINE_BYTES
                else "line_terminator_missing"
            )
            self.stop("incomplete", code, start, scan_end)
        return candidate, end

    def fields(
        self, start: int, *, trailer: bool
    ) -> tuple[list[tuple[bytes, bytes, int, int]], int]:
        position = start
        result = []
        records = self.framing["trailers" if trailer else "headers"]
        maximum = MAX_TRAILERS if trailer else MAX_HEADERS
        while True:
            line, end = self.line(position)
            if end + 2 - start > MAX_HEADER_BYTES:
                self.stop("incomplete", "header_bytes_outside_subset", start, end)
            if not line:
                return result, end + 2
            if len(records) >= maximum:
                self.stop("incomplete", "field_count_outside_subset", position, end)
            if line[:1] in (b" ", b"\t"):
                self.stop("violation", "obsolete_line_folding", position, end)
            colon = line.find(b":")
            if colon <= 0:
                self.stop("violation", "header_line_invalid", position, end)
            name = line[:colon]
            if name[-1:] in (b" ", b"\t"):
                self.stop("violation", "whitespace_before_colon", position, end)
            if _TOKEN.fullmatch(name) is None:
                self.stop("violation", "header_line_invalid", position, end)
            value = line[colon + 1 :]
            if any((byte < 32 and byte != 9) or byte == 127 for byte in value):
                self.stop("violation", "field_value_control_octet", position, end)
            left = len(value) - len(value.lstrip(b" \t"))
            trimmed = value.strip(b" \t")
            value_start = position + colon + 1 + left
            lowered = name.lower()
            records.append(
                {
                    "index": len(records),
                    "category": _CATEGORIES.get(lowered, "other"),
                    "line_start": position,
                    "line_end": end,
                    "value_start": value_start,
                    "value_end": value_start + len(trimmed),
                }
            )
            result.append((lowered, trimmed, position, end))
            if trailer:
                self.note(
                    "violation" if lowered in _FORBIDDEN_TRAILERS else "warning",
                    "forbidden_trailer_field"
                    if lowered in _FORBIDDEN_TRAILERS
                    else "trailer_field_semantics_unverified",
                    position,
                    end,
                )
            position = end + 2

    def number(self, value: bytes, *, hexadecimal: bool, start: int, end: int) -> int | None:
        grammar = _HEX if hexadecimal else _DECIMAL
        if grammar.fullmatch(value) is None:
            self.note(
                "violation",
                "chunk_size_invalid" if hexadecimal else "content_length_invalid",
                start,
                end,
            )
            return None
        trimmed = value.lstrip(b"0") or b"0"
        maximum = b"7fffffffffffffff" if hexadecimal else b"9223372036854775807"
        lowered = trimmed.lower()
        if len(lowered) > len(maximum) or (len(lowered) == len(maximum) and lowered > maximum):
            self.note("incomplete", "numeric_size_outside_subset", start, end)
            return None
        return int(trimmed, 16 if hexadecimal else 10)

    def lengths(self, fields: list[tuple[bytes, bytes, int, int]]) -> int | None:
        values = self.framing["content_length_values"]
        valid = True
        count = 0
        for name, value, start, end in fields:
            if name != b"content-length":
                continue
            for item in value.split(b","):
                count += 1
                if count > MAX_LENGTH_VALUES:
                    self.stop("incomplete", "content_length_count_outside_subset", start, end)
                item = item.strip(b" \t")
                if not item:
                    self.note("incomplete", "content_length_list_outside_subset", start, end)
                    valid = False
                    continue
                number = self.number(item, hexadecimal=False, start=start, end=end)
                if number is None:
                    valid = False
                else:
                    values.append(number)
        if len(set(values)) > 1:
            self.note(
                "violation",
                "content_length_conflicting",
                self.framing["header_start"],
                self.framing["header_end"],
            )
            valid = False
        if count > 1:
            self.note(
                "warning",
                "content_length_repetition",
                self.framing["header_start"],
                self.framing["header_end"],
            )
        return values[0] if valid and values else None

    def coding_items(self, value: bytes, start: int, end: int) -> list[bytes]:
        # Delimit only outside quoted strings; parameter semantics remain unsupported.
        items = []
        item_start = 0
        quoted = escaped = False
        for index, byte in enumerate(value):
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte == 44:
                if len(items) + 1 >= MAX_CODINGS:
                    self.stop("incomplete", "transfer_coding_count_outside_subset", start, end)
                items.append(value[item_start:index])
                item_start = index + 1
        if quoted:
            self.stop("incomplete", "transfer_parameters_outside_subset", start, end)
        items.append(value[item_start:])
        return items

    def codings(self, fields: list[tuple[bytes, bytes, int, int]]) -> bool:
        codings = self.framing["transfer_codings"]
        valid = True
        for name, value, start, end in fields:
            if name != b"transfer-encoding":
                continue
            for item in self.coding_items(value, start, end):
                if len(codings) >= MAX_CODINGS:
                    self.stop("incomplete", "transfer_coding_count_outside_subset", start, end)
                item = item.strip(b" \t")
                if not item:
                    self.note("violation", "transfer_coding_empty", start, end)
                    valid = False
                    continue
                token, separator, _parameters = item.partition(b";")
                token = token.strip(b" \t").lower()
                if _TOKEN.fullmatch(token) is None:
                    self.note("violation", "transfer_coding_invalid", start, end)
                    valid = False
                    continue
                codings.append("chunked" if token == b"chunked" else "other")
                if token != b"chunked":
                    self.note("incomplete", "unsupported_transfer_coding", start, end)
                elif separator:
                    self.note("violation", "chunked_parameters", start, end)
                    valid = False
        if codings.count("chunked") > 1:
            self.note(
                "violation",
                "chunked_repeated",
                self.framing["header_start"],
                self.framing["header_end"],
            )
            valid = False
        if not codings or codings[-1] != "chunked":
            self.note(
                "violation",
                "chunked_not_final",
                self.framing["header_start"],
                self.framing["header_end"],
            )
            valid = False
        return valid

    def finish(self, end: int, decoded: int) -> None:
        self.framing.update(
            body_end=end,
            body_complete=True,
            body_payload_bytes=decoded,
            unconsumed_bytes=len(self.raw) - end,
        )
        if end < len(self.raw):
            self.note("warning", "unconsumed_suffix_not_parsed", end, len(self.raw))

    def chunked(self, start: int) -> None:
        position, decoded = start, 0
        chunks = self.framing["chunks"]
        while True:
            if len(chunks) >= MAX_CHUNKS:
                self.stop("incomplete", "chunk_count_outside_subset", position, position)
            line, end = self.line(position)
            if b";" in line:
                self.stop("incomplete", "chunk_extensions_outside_subset", position, end)
            number = self.number(line, hexadecimal=True, start=position, end=end)
            if number is None:
                raise _StopParsing
            data_start = end + 2
            data_end = data_start + number
            if data_end > len(self.raw) or (number and data_end + 2 > len(self.raw)):
                self.stop("incomplete", "chunk_data_incomplete", data_start, len(self.raw))
            ending_end = data_end + 2 if number else data_end
            if number and self.raw[data_end:ending_end] != b"\r\n":
                self.stop("violation", "chunk_data_terminator_invalid", data_end, ending_end)
            chunks.append(
                {
                    "index": len(chunks),
                    "line_start": position,
                    "line_end": end,
                    "data_start": data_start,
                    "data_end": data_end,
                    "ending_end": ending_end,
                    "size": number,
                    "is_last": number == 0,
                }
            )
            if number == 0:
                _, body_end = self.fields(data_start, trailer=True)
                self.finish(body_end, decoded)
                return
            decoded += number
            position = ending_end

    def parse(self) -> None:
        try:
            line, end = self.line(0)
            parts = line.split(b" ")
            if len(parts) != 3 or _TOKEN.fullmatch(parts[0]) is None or not parts[1]:
                self.stop("violation", "request_line_invalid", 0, end)
            if any(not 33 <= byte <= 126 for byte in parts[1]):
                self.stop("violation", "request_line_invalid", 0, end)
            self.framing.update(request_line_end=end, header_start=end + 2)
            if parts[2] != b"HTTP/1.1":
                self.stop("incomplete", "http_version_outside_subset", 0, end)
            if not parts[1].startswith(b"/"):
                self.note("incomplete", "request_target_outside_subset", 0, end)
            if parts[0] == b"CONNECT":
                self.note("incomplete", "protocol_transition_outside_subset", 0, end)
            fields, header_end = self.fields(end + 2, trailer=False)
            self.framing.update(header_end=header_end, body_start=header_end)
            hosts = [value for name, value, _, _ in fields if name == b"host"]
            if len(hosts) != 1:
                self.note("violation", "host_field_count_invalid", end + 2, header_end)
            elif not hosts[0]:
                self.note("violation", "host_field_empty", end + 2, header_end)
            if any(name == b"upgrade" for name, _, _, _ in fields):
                self.note("incomplete", "protocol_transition_outside_subset", end + 2, header_end)
            length = self.lengths(fields)
            has_length = any(name == b"content-length" for name, _, _, _ in fields)
            has_coding = any(name == b"transfer-encoding" for name, _, _, _ in fields)
            if has_coding:
                if has_length:
                    self.note(
                        "warning", "content_length_with_transfer_encoding", end + 2, header_end
                    )
                if self.codings(fields):
                    self.framing["body_framing"] = "chunked"
                    self.chunked(header_end)
            elif has_length:
                self.framing["body_framing"] = "content_length"
                if length is not None:
                    if length > len(self.raw) - header_end:
                        self.note(
                            "incomplete",
                            "content_length_body_incomplete",
                            header_end,
                            len(self.raw),
                        )
                    else:
                        self.finish(header_end + length, length)
            else:
                self.framing["body_framing"] = "none"
                self.finish(header_end, 0)
        except _StopParsing:
            return


def _outcome(violations: list, warnings: list, incomplete: list) -> str:
    return (
        "incomplete"
        if incomplete
        else "violations"
        if violations
        else "warnings"
        if warnings
        else "pass"
    )


def _validate_framing(framing: Any, byte_count: int) -> None:
    value = _exact(framing, _FRAMING_FIELDS, "framing")
    for field in (
        "request_line_end",
        "header_start",
        "header_end",
        "body_start",
        "body_end",
        "unconsumed_bytes",
    ):
        if value[field] is not None:
            _integer(value[field], byte_count, field)
    if type(value["body_complete"]) is not bool:
        raise HttpRequestFramingError("body completeness must be an exact native boolean")
    if type(value["body_framing"]) is not str or value["body_framing"] not in {
        "undetermined",
        "none",
        "content_length",
        "chunked",
    }:
        raise HttpRequestFramingError("framing mode is unsupported")
    if value["body_payload_bytes"] is not None:
        _integer(value["body_payload_bytes"], byte_count, "body payload bytes")
    if (value["request_line_end"] is None) != (value["header_start"] is None):
        raise HttpRequestFramingError("request line and header start disagree")
    if value["header_start"] is not None and value["header_start"] != value["request_line_end"] + 2:
        raise HttpRequestFramingError("header start does not follow the request line")
    if value["header_end"] != value["body_start"]:
        raise HttpRequestFramingError("body does not follow the header section")
    for label, maximum in (("headers", MAX_HEADERS), ("trailers", MAX_TRAILERS)):
        records = value[label]
        if type(records) is not list or len(records) > maximum:
            raise HttpRequestFramingError("field metadata exceeds the supported count")
        previous = value["header_start"] if label == "headers" else None
        for index, record in enumerate(records):
            _exact(record, _FIELD_FIELDS, "field metadata")
            for field in ("index", "line_start", "line_end", "value_start", "value_end"):
                _integer(record[field], byte_count, field)
            if (
                record["index"] != index
                or type(record["category"]) is not str
                or record["category"] not in {*_CATEGORIES.values(), "other"}
                or not record["line_start"]
                < record["value_start"]
                <= record["value_end"]
                <= record["line_end"]
                or record["line_end"] - record["line_start"] > MAX_LINE_BYTES
                or record["line_end"] + 2 > byte_count
                or (previous is not None and record["line_start"] != previous)
            ):
                raise HttpRequestFramingError("field ranges, category or indexes disagree")
            previous = record["line_end"] + 2
        if (
            label == "headers"
            and value["header_end"] is not None
            and (
                previous is None
                or value["header_end"] != previous + 2
                or value["header_end"] - value["header_start"] > MAX_HEADER_BYTES
            )
        ):
            raise HttpRequestFramingError("header section does not close the exact fields")
    for field, maximum in (
        ("content_length_values", MAX_LENGTH_VALUES),
        ("transfer_codings", MAX_CODINGS),
        ("chunks", MAX_CHUNKS),
    ):
        if type(value[field]) is not list or len(value[field]) > maximum:
            raise HttpRequestFramingError("framing facts exceed the supported count")
    for item in value["content_length_values"]:
        _integer(item, _MAX_INTEGER, "declared content length")
    if any(
        type(item) is not str or item not in {"chunked", "other"}
        for item in value["transfer_codings"]
    ):
        raise HttpRequestFramingError("transfer coding metadata is unsupported")
    categories = [field["category"] for field in value["headers"]]
    has_length = "content_length" in categories
    has_coding = "transfer_encoding" in categories
    if (
        (value["content_length_values"] and not has_length)
        or (value["transfer_codings"] and not has_coding)
        or (value["body_framing"] == "content_length" and (not has_length or has_coding))
        or (
            value["body_framing"] == "chunked"
            and (
                not has_coding
                or not value["transfer_codings"]
                or value["transfer_codings"][-1] != "chunked"
                or value["transfer_codings"].count("chunked") != 1
            )
        )
        or (value["body_framing"] == "none" and (has_length or has_coding))
    ):
        raise HttpRequestFramingError("framing mode and declared field categories disagree")
    previous = value["body_start"]
    for index, chunk in enumerate(value["chunks"]):
        _exact(chunk, _CHUNK_FIELDS, "chunk metadata")
        for field in _CHUNK_FIELDS - {"is_last"}:
            _integer(chunk[field], byte_count, field)
        if (
            type(chunk["is_last"]) is not bool
            or chunk["index"] != index
            or chunk["line_start"] != previous
            or chunk["line_end"] <= chunk["line_start"]
            or chunk["line_end"] - chunk["line_start"] > MAX_LINE_BYTES
            or chunk["data_start"] != chunk["line_end"] + 2
            or chunk["data_end"] != chunk["data_start"] + chunk["size"]
            or chunk["is_last"] != (chunk["size"] == 0)
            or chunk["ending_end"] != chunk["data_end"] + (0 if chunk["is_last"] else 2)
            or (chunk["is_last"] and index != len(value["chunks"]) - 1)
        ):
            raise HttpRequestFramingError("chunk metadata does not reconstruct exact boundaries")
        previous = chunk["ending_end"]
    trailers = value["trailers"]
    if trailers and (
        not value["chunks"]
        or not value["chunks"][-1]["is_last"]
        or trailers[0]["line_start"] != previous
    ):
        raise HttpRequestFramingError("trailers do not follow the terminal chunk")
    if trailers and trailers[-1]["line_end"] + 2 - trailers[0]["line_start"] > MAX_HEADER_BYTES:
        raise HttpRequestFramingError("trailer section exceeds the supported byte bound")
    if value["body_complete"]:
        start, end = value["body_start"], value["body_end"]
        if (
            start is None
            or end is None
            or start > end
            or value["body_payload_bytes"] is None
            or value["unconsumed_bytes"] != byte_count - end
        ):
            raise HttpRequestFramingError("complete body and suffix accounting disagree")
        if value["body_framing"] == "none":
            if end != start or value["body_payload_bytes"] != 0:
                raise HttpRequestFramingError("unframed requests must have zero body")
        elif value["body_framing"] == "content_length":
            lengths = value["content_length_values"]
            if (
                not lengths
                or len(set(lengths)) != 1
                or end - start != lengths[0]
                or value["body_payload_bytes"] != lengths[0]
            ):
                raise HttpRequestFramingError("body does not match declared content length")
        elif value["body_framing"] == "chunked":
            chunks = value["chunks"]
            trailer_end = trailers[-1]["line_end"] + 2 if trailers else previous
            if (
                not chunks
                or not chunks[-1]["is_last"]
                or end != trailer_end + 2
                or value["body_payload_bytes"] != sum(chunk["size"] for chunk in chunks)
            ):
                raise HttpRequestFramingError("complete chunked body does not reconstruct")
        else:
            raise HttpRequestFramingError("undetermined body cannot be complete")
    elif any(
        value[field] is not None for field in ("body_end", "body_payload_bytes", "unconsumed_bytes")
    ):
        raise HttpRequestFramingError("incomplete body cannot declare completion accounting")
    if value["body_framing"] != "chunked" and (value["chunks"] or trailers):
        raise HttpRequestFramingError("nonchunked body cannot declare chunk or trailer metadata")


def _validate_report(document: Any) -> dict[str, Any]:
    raw = _exact(_capture(document), _REPORT_FIELDS, "analysis")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise HttpRequestFramingError("analysis schema_version must be native integer1")
    expected = {
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "operator_supplied_unverified",
        "effects": _EFFECTS,
        "limitations": list(_LIMITATIONS),
    }
    for field, value in expected.items():
        if _canonical(raw[field]) != _canonical(value):
            raise HttpRequestFramingError("analysis changes the fixed nonauthorizing profile")
    for field in (
        "offline_only",
        "server_vulnerability_proven",
        "live_use_approved",
        "qualification_claimed",
    ):
        if raw[field] is not (field == "offline_only"):
            raise HttpRequestFramingError(
                "analysis flags must remain exact nonauthorizing booleans"
            )
    bounds = _exact(raw["bounds"], set(_BOUNDS), "software bounds")
    if _canonical(bounds) != _canonical(_BOUNDS):
        raise HttpRequestFramingError("analysis changes the exact supported software bounds")
    source = _exact(raw["source"], {"model_sha256", "request_sha256", "byte_count"}, "source")
    for field in ("model_sha256", "request_sha256"):
        if type(source[field]) is not str or _DIGEST.fullmatch(source[field]) is None:
            raise HttpRequestFramingError("source must use canonical SHA-256")
    byte_count = _integer(source["byte_count"], MAX_REQUEST_BYTES, "request bytes")
    if not byte_count:
        raise HttpRequestFramingError("source cannot be empty")
    _validate_framing(raw["framing"], byte_count)
    for label, codes in (
        ("violations", _VIOLATIONS),
        ("warnings", _WARNINGS),
        ("incomplete_reasons", _INCOMPLETE),
    ):
        entries = raw[label]
        if type(entries) is not list or len(entries) > MAX_HEADERS + MAX_CHUNKS + MAX_TRAILERS:
            raise HttpRequestFramingError("analysis finding count exceeds supported bounds")
        seen = set()
        for item in entries:
            _exact(
                item,
                {"code", "start", "end", "basis"}
                if label == "violations"
                else {"code", "start", "end"},
                "finding",
            )
            if type(item["code"]) is not str or item["code"] not in codes:
                raise HttpRequestFramingError("analysis finding code is unsupported")
            start = _integer(item["start"], byte_count, "finding start")
            end = _integer(item["end"], byte_count, "finding end")
            if start > end or (
                label == "violations" and item["basis"] != _VIOLATIONS[item["code"]]
            ):
                raise HttpRequestFramingError("analysis finding range or basis is inconsistent")
            encoded = _canonical(item)
            if encoded in seen:
                raise HttpRequestFramingError("analysis finding repeats")
            seen.add(encoded)
    if raw["supported_checks_outcome"] != _outcome(
        raw["violations"], raw["warnings"], raw["incomplete_reasons"]
    ):
        raise HttpRequestFramingError("analysis outcome does not reflect declared findings")
    body = {
        key: value for key, value in raw.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    if _canonical(raw) != _canonical(_address(body)):
        raise HttpRequestFramingError("analysis content address is invalid")
    return raw


@dataclass(frozen=True, slots=True)
class HttpRequestFramingAnalysis:
    """Detached unsigned metadata, never proof of a remote parser or vulnerability."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise HttpRequestFramingError("analysis native slots are incomplete") from exc
        return _validate_report(_json(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> HttpRequestFramingAnalysis:
        return cls(_canonical(_validate_report(document)))

    @classmethod
    def from_json(cls, document: str) -> HttpRequestFramingAnalysis:
        return cls(document)


def analyze_supplied_http_request_framing(model: dict[str, Any]) -> HttpRequestFramingAnalysis:
    """Analyze supplied octets without sending, normalizing or generating any request."""
    owned, raw = _model(model)
    parser = _Parser(raw)
    parser.parse()
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "source": {
            "model_sha256": _sha(_canonical(owned).encode("ascii")),
            "request_sha256": _sha(raw),
            "byte_count": len(raw),
        },
        "bounds": dict(_BOUNDS),
        "framing": parser.framing,
        "violations": parser.violations,
        "warnings": parser.warnings,
        "incomplete_reasons": parser.incomplete,
        "supported_checks_outcome": _outcome(parser.violations, parser.warnings, parser.incomplete),
        "input_provenance": "operator_supplied_unverified",
        "offline_only": True,
        "server_vulnerability_proven": False,
        "live_use_approved": False,
        "qualification_claimed": False,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    return HttpRequestFramingAnalysis.from_dict(_address(body))


def verify_supplied_http_request_framing(
    report: HttpRequestFramingAnalysis, *, model: dict[str, Any]
) -> HttpRequestFramingAnalysis:
    """Reconstruct exact original-source facts separately from content-only parsing."""
    if type(report) is not HttpRequestFramingAnalysis:
        raise HttpRequestFramingError("report must be the exact native analysis family")
    observed = report.to_json()
    expected = analyze_supplied_http_request_framing(model)
    if observed != expected.to_json():
        raise HttpRequestFramingError("analysis does not replay the exact supplied original bytes")
    return HttpRequestFramingAnalysis.from_json(expected.to_json())


__all__ = [
    "CAPABILITY_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "WAVE_ID",
    "HttpRequestFramingAnalysis",
    "HttpRequestFramingError",
    "analyze_supplied_http_request_framing",
    "verify_supplied_http_request_framing",
]

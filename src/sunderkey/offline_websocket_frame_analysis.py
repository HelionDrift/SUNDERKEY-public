"""Bounded passive analysis of a supplied unextended WebSocket frame prefix."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GB-D06-S05"
CAPABILITY_ID = "army.gb.d06.s05"
VECTOR_ID = "AV-GB-D06-S05-01"
WAVE_ID = "IW2-012"
COMPONENT_ID = "websocket_supplied_frame_state"
DOMAIN = "sunderkey.offline-websocket-frame-analysis.v1"
SEMANTICS_PROFILE = "rfc6455-unextended-message-boundary-prefix-v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_STREAM_BYTES = 262_144
MAX_FRAME_PAYLOAD_BYTES = 131_072
MAX_MESSAGE_BYTES = 262_144
MAX_FRAMES = 2048
MAX_MESSAGES = 1024
MAX_OBSERVATIONS = 256
MAX_NATIVE_DEPTH = 16
MAX_NATIVE_NODES = 32_768
MAX_PARSER_WORK = 1_000_000
MAX_SOURCE_ID_LENGTH = 128
_MAX_BASE64 = 4 * ((MAX_STREAM_BYTES + 2) // 3)
_INT_MIN = -(2**63)
_INT_MAX = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OPCODES = {0: "continuation", 1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}
_KNOWN_CLOSE_CODES = frozenset({1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011})
_FORBIDDEN_CLOSE_CODES = frozenset({1004, 1005, 1006, 1015})
_MODEL_FIELDS = {
    "schema_version",
    "semantics_profile",
    "source_id",
    "sender_role",
    "initial_state",
    "stream_base64",
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
_BOUNDS = {
    "maximum_document_bytes": MAX_DOCUMENT_BYTES,
    "maximum_stream_bytes": MAX_STREAM_BYTES,
    "maximum_frame_payload_bytes": MAX_FRAME_PAYLOAD_BYTES,
    "maximum_message_bytes": MAX_MESSAGE_BYTES,
    "maximum_frames": MAX_FRAMES,
    "maximum_messages": MAX_MESSAGES,
    "maximum_observations": MAX_OBSERVATIONS,
    "maximum_native_depth": MAX_NATIVE_DEPTH,
    "maximum_native_nodes": MAX_NATIVE_NODES,
    "maximum_parser_work_per_reconstruction": MAX_PARSER_WORK,
}
_LIMITATIONS = (
    "Sender role, an initial message boundary and unextended post-handshake framing "
    "are caller premises.",
    "No handshake, Origin, authentication, authorization, endpoint or source truth is verified.",
    "A single sender prefix cannot prove peer responses, timing or a completed closing handshake.",
    "Extensions, reserved opcodes and later or application Close-code semantics remain unassessed.",
    "Binary application data is not interpreted.",
    "Known Close-code classification does not verify appropriateness, role-specific "
    "initiation or a peer echo.",
    "Mask-key presence is checked, not entropy, unpredictability or negotiated connection state.",
    "The embedded source is inert supplied base64, not certified sanitized or safe to publish.",
    "No transport, generated traffic, server vulnerability, live permission or "
    "qualification is provided.",
)
_REPORT_FIELDS = {
    "analysis_id",
    "analysis_sha256",
    "schema_version",
    "profile_id",
    "capability_id",
    "vector_id",
    "wave_id",
    "semantics_profile",
    "source_model",
    "source",
    "bounds",
    "frames",
    "messages",
    "observations",
    "summary",
    "analysis_status",
    "input_provenance",
    "offline_only",
    "server_vulnerability_proven",
    "live_use_approved",
    "qualification_claimed",
    "effects",
    "limitations",
}


class WebSocketFrameAnalysisError(ValueError):
    """Exact-native intake, a software budget or source replay failed."""


def _capture(value: Any) -> tuple[Any, int, int]:
    """Detach exact JSON, charging repeated occurrences before allocation/dumps."""
    size = nodes = 0
    active: set[int] = set()

    def charge(amount: int) -> None:
        nonlocal size
        if amount > MAX_DOCUMENT_BYTES - size:
            raise WebSocketFrameAnalysisError("software budget: aggregate JSON bytes")
        size += amount

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise WebSocketFrameAnalysisError("software budget: native depth or nodes")
        kind = type(item)
        if kind is str:
            if len(item) > _MAX_BASE64:
                raise WebSocketFrameAnalysisError("software budget: native string")
            charge(len(item) + 2)
            if not item.isascii() or any(not 32 <= ord(char) <= 126 for char in item):
                raise WebSocketFrameAnalysisError("native text must be printable ASCII")
            charge(item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            charge(4 if item else 5)
            return item
        if item is None:
            charge(4)
            return None
        if kind is int:
            if not _INT_MIN <= item <= _INT_MAX:
                raise WebSocketFrameAnalysisError("native integer exceeds signed64")
            charge(len(str(item)))
            return item
        if kind not in (dict, list):
            raise WebSocketFrameAnalysisError("only exact native JSON families are supported")
        if id(item) in active or len(item) * (2 if kind is dict else 1) > MAX_NATIVE_NODES - nodes:
            raise WebSocketFrameAnalysisError("software budget: cyclic or queued native nodes")
        charge(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
        active.add(id(item))
        try:
            if kind is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise WebSocketFrameAnalysisError("native object keys must be exact text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    owned = visit(value, 1)
    return owned, size, nodes


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _sha(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _integer_token(token: str) -> int:
    if _INTEGER.fullmatch(token) is None:
        raise WebSocketFrameAnalysisError("JSON integer grammar or signed64 bound is invalid")
    value = int(token)
    if not _INT_MIN <= value <= _INT_MAX:
        raise WebSocketFrameAnalysisError("JSON integer exceeds signed64")
    return value


def _decode(text: Any) -> Any:
    """Bound every raw value, including keys/scalars, before the JSON decoder."""
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise WebSocketFrameAnalysisError("JSON must be bounded exact ASCII text")
    index = nodes = 0
    stack: list[str] = []

    def value_node() -> None:
        nonlocal nodes
        nodes += 1
        if len(stack) + 1 > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise WebSocketFrameAnalysisError("software budget: raw JSON depth or nodes")

    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "[{":
            value_node()
            stack.append(char)
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise WebSocketFrameAnalysisError("JSON container grammar is invalid")
            index += 1
            continue
        value_node()
        if char == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                current = text[index]
                if current == "\\":
                    index += 1
                    if index >= len(text):
                        raise WebSocketFrameAnalysisError("JSON escape is incomplete")
                    escape = text[index]
                    if escape == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise WebSocketFrameAnalysisError("JSON Unicode escape is invalid")
                        index += 4
                    elif escape not in '"\\/bfnrt':
                        raise WebSocketFrameAnalysisError("JSON escape is invalid")
                elif ord(current) < 32:
                    raise WebSocketFrameAnalysisError("JSON string contains a control")
                length += 1
                if length > _MAX_BASE64:
                    raise WebSocketFrameAnalysisError("software budget: raw JSON string")
                index += 1
            if index >= len(text):
                raise WebSocketFrameAnalysisError("JSON string is incomplete")
            index += 1
            continue
        start = index
        while index < len(text) and text[index] not in ' \t\r\n,:{}[]"':
            index += 1
        token = text[start:index]
        if token not in {"true", "false", "null"}:
            _integer_token(token)

    if stack:
        raise WebSocketFrameAnalysisError("JSON containers are incomplete")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, child in items:
            if key in result:
                raise WebSocketFrameAnalysisError("duplicate JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise WebSocketFrameAnalysisError("JSON floats and nonfinite values are unsupported")

    try:
        result = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_integer_token,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise WebSocketFrameAnalysisError("invalid bounded JSON") from exc
    return _capture(result)[0]


def _model(model: Any) -> tuple[dict[str, Any], bytes]:
    owned = _capture(model)[0]
    if type(owned) is not dict or set(owned) != _MODEL_FIELDS:
        raise WebSocketFrameAnalysisError("frame model has missing or unsupported fields")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise WebSocketFrameAnalysisError("schema_version must be native integer1")
    for field, expected in (
        ("semantics_profile", SEMANTICS_PROFILE),
        ("initial_state", "message_boundary"),
    ):
        if type(owned[field]) is not str or owned[field] != expected:
            raise WebSocketFrameAnalysisError("unsupported declared framing premise")
    if type(owned["sender_role"]) is not str or owned["sender_role"] not in {"client", "server"}:
        raise WebSocketFrameAnalysisError("sender_role must be exact client or server text")
    if type(owned["source_id"]) is not str or _SOURCE_ID.fullmatch(owned["source_id"]) is None:
        raise WebSocketFrameAnalysisError("source_id must be a bounded native identifier")
    encoded = owned["stream_base64"]
    if type(encoded) is not str or len(encoded) > _MAX_BASE64 or len(encoded) % 4:
        raise WebSocketFrameAnalysisError("software budget or shape: canonical base64")
    padding = len(encoded) - len(encoded.rstrip("="))
    if padding > 2 or 3 * (len(encoded) // 4) - padding > MAX_STREAM_BYTES:
        raise WebSocketFrameAnalysisError("software budget: decoded stream bytes")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise WebSocketFrameAnalysisError("stream base64 is malformed") from exc
    if len(raw) > MAX_STREAM_BYTES or base64.b64encode(raw).decode("ascii") != encoded:
        raise WebSocketFrameAnalysisError("stream base64 is oversized or noncanonical")
    return owned, raw


def parse_supplied_websocket_frame_model(model_bytes: bytes) -> dict[str, Any]:
    """Decode only bounded supplied JSON bytes; this function performs no file access."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise WebSocketFrameAnalysisError("model_bytes must be bounded exact native bytes")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebSocketFrameAnalysisError("model bytes must contain ASCII JSON") from exc
    return _model(_decode(text))[0]


class _Work:
    def __init__(self) -> None:
        self.used = 0

    def charge(self, amount: int) -> None:
        if amount > MAX_PARSER_WORK - self.used:
            raise WebSocketFrameAnalysisError("software budget: parser work")
        self.used += amount


class _Retained:
    def __init__(self, skeleton: dict[str, Any]) -> None:
        _, self.size, self.nodes = _capture(skeleton)
        # Reserve fixed identity fields and final bounded counters before retaining rows.
        self.size += 512
        self.nodes += 64
        self._check(0, 0)

    def _check(self, size: int, nodes: int) -> None:
        if size > MAX_DOCUMENT_BYTES - self.size or nodes > MAX_NATIVE_NODES - self.nodes:
            raise WebSocketFrameAnalysisError("software budget: retained report")

    def append(
        self, target: list[dict[str, Any]], row: dict[str, Any], ceiling: int
    ) -> dict[str, Any]:
        if len(target) >= ceiling:
            raise WebSocketFrameAnalysisError("software budget: retained record count")
        owned, size, nodes = _capture(row)
        self._check(size + 1, nodes)
        self.size += size + 1
        self.nodes += nodes
        target.append(owned)
        return owned


class _Parser:
    def __init__(self, raw: bytes, sender_role: str, body: dict[str, Any]):
        self.raw, self.role, self.body = raw, sender_role, body
        self.work = _Work()
        self.retained = _Retained(body)
        self.frames = body["frames"]
        self.messages = body["messages"]
        self.observations = body["observations"]
        self.offset = 0
        self.closed = False
        self.active: dict[str, Any] | None = None
        self.terminal = "source_exhausted"

    def note(self, category: str, code: str, start: int, end: int) -> None:
        self.work.charge(1)
        self.retained.append(
            self.observations,
            {
                "category": category,
                "code": code,
                "start": start,
                "end": end,
            },
            MAX_OBSERVATIONS,
        )

    def digest(self, raw: bytes) -> str:
        self.work.charge(len(raw))
        return _sha(raw)

    def finish_message(self, complete: bool, termination: str, invalid: bool = False) -> None:
        assert self.active is not None
        active = self.active
        active["row"].update(
            {
                "index": active["row"]["index"],
                "first_frame_index": active["first"],
                "last_frame_index": active["last"],
                "message_type": _OPCODES[active["opcode"]],
                "fragment_count": active["count"],
                "payload_bytes": active["size"],
                "payload_sha256": "sha256:" + active["hash"].hexdigest(),
                "complete": complete,
                "utf8_status": ("invalid" if invalid else "valid" if complete else "valid_prefix")
                if active["opcode"] == 1
                else "not_applicable",
                "termination": termination,
            }
        )
        self.active = None

    def data(self, opcode: int, fin: bool, payload: bytes, frame: dict[str, Any]) -> bool:
        if self.closed:
            self.note("violation", "data_after_sender_close", frame["start"], frame["end"])
            return False
        if opcode == 0 and self.active is None:
            self.note(
                "violation", "continuation_without_open_message", frame["start"], frame["end"]
            )
            return False
        if opcode in (1, 2):
            if self.active is not None:
                self.note(
                    "violation", "new_data_during_fragmented_message", frame["start"], frame["end"]
                )
                return False
            if len(self.messages) >= MAX_MESSAGES:
                raise WebSocketFrameAnalysisError("software budget: message count")
            row = self.retained.append(
                self.messages,
                {
                    "index": len(self.messages),
                    "first_frame_index": frame["index"],
                    "last_frame_index": MAX_FRAMES,
                    "message_type": _OPCODES[opcode],
                    "fragment_count": MAX_FRAMES,
                    "payload_bytes": MAX_MESSAGE_BYTES,
                    "payload_sha256": "sha256:" + "0" * 64,
                    "complete": False,
                    "utf8_status": "not_applicable",
                    "termination": "structural_violation",
                },
                MAX_MESSAGES,
            )
            self.active = {
                "first": frame["index"],
                "last": frame["index"],
                "opcode": opcode,
                "count": 0,
                "size": 0,
                "hash": hashlib.sha256(),
                "decoder": codecs.getincrementaldecoder("utf-8")("strict") if opcode == 1 else None,
                "row": row,
            }
        assert self.active is not None
        active = self.active
        if len(payload) > MAX_MESSAGE_BYTES - active["size"]:
            raise WebSocketFrameAnalysisError("software budget: message bytes")
        active["last"] = frame["index"]
        active["count"] += 1
        active["size"] += len(payload)
        invalid = False
        if active["decoder"] is not None:
            self.work.charge(len(payload) + 1)
            try:
                active["decoder"].decode(payload, final=fin)
            except UnicodeDecodeError:
                self.note("violation", "text_message_invalid_utf8", frame["start"], frame["end"])
                invalid = True
        self.work.charge(len(payload))
        active["hash"].update(payload)
        if invalid:
            self.finish_message(fin, "fin" if fin else "structural_violation", invalid=True)
            return False
        if fin:
            self.finish_message(True, "fin")
        return True

    def close(self, payload: bytes, frame: dict[str, Any]) -> bool:
        self.closed = True
        if len(payload) == 1:
            frame["close_code_class"] = "invalid_length"
            self.note("violation", "close_payload_length_one", frame["start"], frame["end"])
            return False
        if not payload:
            frame["close_code_class"] = "absent"
            frame["close_reason_utf8"] = "not_present"
            return True
        code = int.from_bytes(payload[:2], "big")
        frame["close_code"] = code
        valid = True
        if code in _FORBIDDEN_CLOSE_CODES:
            frame["close_code_class"] = "forbidden_on_wire"
            self.note("violation", "close_code_forbidden_on_wire", frame["start"], frame["end"])
            valid = False
        elif not 1000 <= code <= 4999:
            frame["close_code_class"] = "outside_code_range"
            self.note("violation", "close_code_outside_range", frame["start"], frame["end"])
            valid = False
        elif code in _KNOWN_CLOSE_CODES:
            frame["close_code_class"] = "rfc6455_defined"
        else:
            frame["close_code_class"] = (
                "unassessed_private_application"
                if code >= 4000
                else "unassessed_registered_application"
                if code >= 3000
                else "unassessed_later_or_extension"
            )
            self.note(
                "unsupported", "close_code_semantics_unassessed", frame["start"], frame["end"]
            )
        self.work.charge(len(payload) - 2)
        try:
            payload[2:].decode("utf-8", "strict")
            frame["close_reason_utf8"] = "valid"
        except UnicodeDecodeError:
            frame["close_reason_utf8"] = "invalid"
            self.note("violation", "close_reason_invalid_utf8", frame["start"], frame["end"])
            valid = False
        return valid

    def parse(self) -> None:
        raw = self.raw
        if not raw:
            self.note("incomplete", "no_frame_supplied", 0, 0)
        while self.offset < len(raw):
            start = self.offset
            if len(self.frames) >= MAX_FRAMES:
                raise WebSocketFrameAnalysisError("software budget: frame count")
            if len(raw) - start < 2:
                self.note("incomplete", "truncated_base_header", start, len(raw))
                self.terminal = "truncated_base_header"
                break
            self.work.charge(2)
            first, second = raw[start], raw[start + 1]
            fin, rsv, opcode = bool(first & 128), (first >> 4) & 7, first & 15
            masked, marker = bool(second & 128), second & 127
            cursor = start + 2
            width = 2 if marker == 126 else 8 if marker == 127 else 0
            if len(raw) - cursor < width:
                self.note("incomplete", "truncated_extended_length", start, len(raw))
                self.terminal = "truncated_extended_length"
                break
            self.work.charge(width)
            if marker == 127 and raw[cursor] & 128:
                self.note("violation", "payload_length_msb_set", start, cursor + 8)
                self.terminal = "payload_length_msb_set"
                break
            length = int.from_bytes(raw[cursor : cursor + width], "big") if width else marker
            cursor += width
            nonminimal = (marker == 126 and length < 126) or (marker == 127 and length < 65536)
            if nonminimal:
                self.note("violation", "payload_length_not_minimal", start, cursor)
            if masked != (self.role == "client"):
                self.note("violation", "mask_direction_mismatch", start, start + 2)
            if opcode & 8:
                if not fin:
                    self.note("violation", "control_frame_fragmented", start, cursor)
                if length > 125:
                    self.note("violation", "control_payload_exceeds_125", start, cursor)
            if length > MAX_FRAME_PAYLOAD_BYTES:
                raise WebSocketFrameAnalysisError("software budget: declared frame payload bytes")
            if masked:
                if len(raw) - cursor < 4:
                    self.note("incomplete", "truncated_masking_key", start, len(raw))
                    self.terminal = "truncated_masking_key"
                    break
                key = raw[cursor : cursor + 4]
                cursor += 4
                self.work.charge(4)
            else:
                key = b""
            if len(raw) - cursor < length:
                self.note("incomplete", "truncated_frame_payload", start, len(raw))
                self.terminal = "truncated_frame_payload"
                break
            end = cursor + length
            frame = self.retained.append(
                self.frames,
                {
                    "index": len(self.frames),
                    "start": start,
                    "payload_start": cursor,
                    "end": end,
                    "fin": fin,
                    "rsv": rsv,
                    "opcode": opcode,
                    "masked": masked,
                    "length_encoding": 7 if width == 0 else 16 if width == 2 else 64,
                    "payload_length": length,
                    "wire_sha256": "sha256:" + "0" * 64,
                    "decoded_payload_sha256": "sha256:" + "0" * 64,
                    "payload_interpretation": "unextended_continuation",
                    "close_code": 4999,
                    "close_code_class": "unassessed_registered_application",
                    "close_reason_utf8": "not_present",
                },
                MAX_FRAMES,
            )
            # Reserve worst-case row sizes first, then replace only with shorter facts.
            frame.update(
                {
                    "decoded_payload_sha256": None,
                    "payload_interpretation": "unassessed",
                    "close_code": None,
                    "close_code_class": None,
                    "close_reason_utf8": None,
                }
            )
            self.offset = end
            if rsv or opcode not in _OPCODES:
                if rsv:
                    self.note("unsupported", "rsv_extension_semantics_unassessed", start, end)
                if opcode not in _OPCODES:
                    self.note("unsupported", "reserved_opcode_semantics_unassessed", start, end)
                frame["wire_sha256"] = self.digest(raw[start:end])
                self.terminal = "unsupported_frame"
                break
            self.work.charge(length)
            payload = raw[cursor:end]
            if masked:
                self.work.charge(length)
                payload = bytes(value ^ key[index % 4] for index, value in enumerate(payload))
            frame["payload_interpretation"] = "unextended_" + _OPCODES[opcode]
            good = True
            if opcode in (0, 1, 2):
                good = self.data(opcode, fin, payload, frame)
            elif opcode == 8:
                good = self.close(payload, frame)
            frame["wire_sha256"] = self.digest(raw[start:end])
            frame["decoded_payload_sha256"] = self.digest(payload)
            if not good or (opcode & 8 and (not fin or length > 125)):
                self.terminal = "structural_violation"
                break
        if self.active is not None:
            first = self.active["first"]
            self.note(
                "incomplete", "message_not_completed", self.frames[first]["start"], self.offset
            )
            self.finish_message(False, "sender_close" if self.closed else "supplied_prefix_end")
        counts = {
            category: sum(row["category"] == category for row in self.observations)
            for category in ("violation", "incomplete", "unsupported")
        }
        self.body["analysis_status"] = (
            "unsupported"
            if counts["unsupported"]
            else "structural_violation"
            if counts["violation"]
            else "incomplete_supplied_prefix"
            if counts["incomplete"]
            else "consistent_with_supported_subset"
        )
        self.body["summary"] = {
            "frame_count": len(self.frames),
            "message_count": len(self.messages),
            "consumed_bytes": self.offset,
            "unconsumed_bytes": len(raw) - self.offset,
            "prefix_fully_consumed": self.offset == len(raw),
            "sender_close_observed": self.closed,
            "supported_checks_complete": not counts["unsupported"]
            and not counts["incomplete"]
            and self.offset == len(raw),
            "terminal_reason": self.terminal,
            "parser_work_used": self.work.used,
            "violation_count": counts["violation"],
            "incomplete_count": counts["incomplete"],
            "unsupported_count": counts["unsupported"],
        }


def _build(model: Any) -> dict[str, Any]:
    owned, raw = _model(model)
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source": {
            "source_id": owned["source_id"],
            "model_sha256": "sha256:" + "0" * 64,
            "stream_sha256": "sha256:" + "0" * 64,
            "byte_count": len(raw),
        },
        "bounds": dict(_BOUNDS),
        "frames": [],
        "messages": [],
        "observations": [],
        "summary": {
            "frame_count": 0,
            "message_count": 0,
            "consumed_bytes": 0,
            "unconsumed_bytes": 0,
            "prefix_fully_consumed": False,
            "sender_close_observed": False,
            "supported_checks_complete": False,
            "terminal_reason": "source_exhausted",
            "parser_work_used": 0,
            "violation_count": 0,
            "incomplete_count": 0,
            "unsupported_count": 0,
        },
        "analysis_status": "consistent_with_supported_subset",
        "input_provenance": "caller_supplied_unverified",
        "offline_only": True,
        "server_vulnerability_proven": False,
        "live_use_approved": False,
        "qualification_claimed": False,
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    parser = _Parser(raw, owned["sender_role"], body)
    parser.parse()
    # All intake, parser and retained-output bounds precede these source/report hashes.
    body = _capture(body)[0]
    body["source"]["model_sha256"] = _sha(_canonical(owned).encode("ascii"))
    body["source"]["stream_sha256"] = _sha(raw)
    digest = _sha(DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii"))
    document = {"analysis_id": "WFA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}
    return _capture(document)[0]


def _validate_report(document: Any) -> dict[str, Any]:
    owned = _capture(document)[0]
    if type(owned) is not dict or set(owned) != _REPORT_FIELDS:
        raise WebSocketFrameAnalysisError("analysis has missing or unsupported fields")
    expected = _build(owned["source_model"])
    if _canonical(owned) != _canonical(expected):
        raise WebSocketFrameAnalysisError(
            "analysis does not replay its exact embedded source model"
        )
    return expected


@dataclass(frozen=True, slots=True)
class WebSocketFrameAnalysis:
    """Detached, unsigned supplied-source analysis with exact reconstruction."""

    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        if type(self) is not WebSocketFrameAnalysis:
            raise WebSocketFrameAnalysisError("analysis must be the exact owned family")
        try:
            text = self.document_json
        except AttributeError as exc:
            raise WebSocketFrameAnalysisError("analysis slots are incomplete") from exc
        return _validate_report(_decode(text))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: Any) -> WebSocketFrameAnalysis:
        if cls is not WebSocketFrameAnalysis:
            raise WebSocketFrameAnalysisError("analysis must be the exact owned family")
        return cls(_canonical(_validate_report(document)))

    @classmethod
    def from_json(cls, document: str) -> WebSocketFrameAnalysis:
        return cls(document)


def analyze_supplied_websocket_frames(model: dict[str, Any]) -> WebSocketFrameAnalysis:
    """Analyze inert supplied bytes only; no acquisition, emission or callback is available."""
    return WebSocketFrameAnalysis(_canonical(_build(model)))


def verify_supplied_websocket_frame_analysis(
    report: WebSocketFrameAnalysis, *, model: dict[str, Any]
) -> WebSocketFrameAnalysis:
    """Rebuild against the separately supplied original model, not hash equality alone."""
    if type(report) is not WebSocketFrameAnalysis:
        raise WebSocketFrameAnalysisError("report must be the exact owned analysis family")
    owned_model = _model(model)[0]
    observed = report.to_json()
    expected = _build(owned_model)
    if observed != _canonical(expected):
        raise WebSocketFrameAnalysisError("analysis does not replay the supplied original model")
    return WebSocketFrameAnalysis(_canonical(expected))


__all__ = [
    "CAPABILITY_ID",
    "COMPONENT_ID",
    "DOMAIN",
    "PROFILE_ID",
    "SEMANTICS_PROFILE",
    "VECTOR_ID",
    "WAVE_ID",
    "WebSocketFrameAnalysis",
    "WebSocketFrameAnalysisError",
    "analyze_supplied_websocket_frames",
    "parse_supplied_websocket_frame_model",
    "verify_supplied_websocket_frame_analysis",
]

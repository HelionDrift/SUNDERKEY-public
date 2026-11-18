"""Bounded, unsigned AMQP 0-9-1 Basic.Publish content assembly observations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "amqp091_supplied_publish_content_assembly"
PROFILE_ID = "AOE-GB-D07-S07"
CAPABILITY_ID = "army.gb.d07.s07"
VECTOR_ID = "AV-GB-D07-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S07"
WAVE_ID = "IW2-007"
COMMANDER_PROFILE_ID = "AOE-GB-D07-CMD"
GROUP_COMMANDER_PROFILE_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:c10fea2af225753591965ec2de3b8a55cf4d0ed37c1a6048a867022b6e1916e0"
SEMANTICS_PROFILE = "amqp-0-9-1-supplied-basic-publish-content.v1"
MODEL_DOMAIN = "sunderkey.offline-amqp091-content-model.v1"
REPORT_DOMAIN = "sunderkey.offline-amqp091-content-analysis.v1"

MAX_STREAM_BYTES = 262_144
MAX_FRAME_PAYLOAD = 65_536
MAX_BODY_BYTES = 65_536
MAX_MODEL_BYTES = 524_288
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 512
MAX_REPORT_NODES = 65_536
MAX_DEPTH = 16
MAX_STRING_BYTES = 800_000
MAX_FRAMES = 128
MAX_CHANNELS = 16
MAX_PUBLISHES = 64
MAX_OBSERVATIONS = 512
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1

_MODEL_FIELDS = {"schema_version", "source_id", "direction", "frames_base64"}
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "AMQA-" + "0" * 32
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
        "connection_identified",
        "channel_open_proven",
        "exchange_exists",
        "queue_permission_proven",
        "message_routed",
        "message_delivered",
        "full_amqp_validity_proven",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Input is one caller-supplied post-negotiation frame stream, not acquired traffic.",
    "The client-to-server direction is supplied, not observed or authenticated.",
    "Only Basic.Publish with zero Basic property flags has supported content semantics.",
    "Unsupported methods, properties and incomplete prefixes withhold a clean conclusion.",
    "Channel grouping does not prove a connection, peer, frame maximum or open channel.",
    "Exchange existence, permissions, routing and delivery are unassessed.",
    "Embedded raw bytes are retained and not sanitized or redacted.",
    "No authority, specialist qualification or competitive parity follows.",
)


class Amqp091ContentAnalysisError(ValueError):
    """The closed native/wire subset, cost ceiling or source replay was refused."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise Amqp091ContentAnalysisError("Cumulative public-operation work exhausted")
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
            raise Amqp091ContentAnalysisError("Escaped canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > maximum_nodes or depth > MAX_DEPTH:
            raise Amqp091ContentAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise Amqp091ContentAnalysisError("Native string ceiling exhausted")
            add(2)
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise Amqp091ContentAnalysisError("Closed metadata requires ASCII")
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
                raise Amqp091ContentAnalysisError("Exact native signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise Amqp091ContentAnalysisError("Cyclic native document refused")
            children = len(item) * (2 if kind is dict else 1)
            if children > maximum_nodes - nodes:
                raise Amqp091ContentAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise Amqp091ContentAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise Amqp091ContentAnalysisError("Exact native integer-only JSON family required")

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
        raise Amqp091ContentAnalysisError("Bounded raw integer grammar required")
    digits = token[1:] if token.startswith("-") else token
    maximum = "9223372036854775808" if token.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise Amqp091ContentAnalysisError("Raw signed64 integer ceiling exhausted")
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
                raise Amqp091ContentAnalysisError("Incomplete raw JSON escape")
            if text[index] == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise Amqp091ContentAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise Amqp091ContentAnalysisError("Closed metadata requires ASCII")
                index += 4
            elif text[index] not in '\\"/bfnrt':
                raise Amqp091ContentAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise Amqp091ContentAnalysisError("Invalid raw JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise Amqp091ContentAnalysisError("Pre-decoder string ceiling exhausted")
        index += 1
    raise Amqp091ContentAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int, int]:
    maximum_size = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > maximum_size or not text.isascii():
        raise Amqp091ContentAnalysisError("Bounded exact native ASCII JSON text required")
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
                raise Amqp091ContentAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > maximum_nodes or len(stack) + 1 > MAX_DEPTH:
            raise Amqp091ContentAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                    raise Amqp091ContentAnalysisError(
                        "Pre-decoder scalar lexical ceiling exhausted"
                    )
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise Amqp091ContentAnalysisError("Unterminated raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, child in items:
            if key in result:
                raise Amqp091ContentAnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise Amqp091ContentAnalysisError("Raw floating/nonfinite numbers are unsupported")

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
        raise Amqp091ContentAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_STREAM_BYTES + 2) // 3):
        raise Amqp091ContentAnalysisError("Bounded exact native frame-stream base64 required")
    budget.charge(3 * len(text))
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise Amqp091ContentAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 8 <= length <= MAX_STREAM_BYTES:
        raise Amqp091ContentAnalysisError("Bounded nonempty frame stream required")
    budget.charge(8 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except binascii.Error as exc:
        raise Amqp091ContentAnalysisError("Invalid supplied frame-stream base64") from exc
    if len(raw) != length or base64.b64encode(raw).decode("ascii") != text:
        raise Amqp091ContentAnalysisError("Noncanonical supplied frame-stream base64")
    return raw


@dataclass(slots=True)
class _Observations:
    contradictions: list[str]
    unassessed: list[str]
    advisories: list[str]
    budget: _Budget
    count: int = 0

    def add(self, channel: str, detail: str) -> None:
        if self.count >= MAX_OBSERVATIONS:
            raise Amqp091ContentAnalysisError("Retained observation ceiling exhausted")
        self.budget.charge(4 * len(detail) + 32)
        getattr(self, channel).append(detail)
        self.count += 1


def _u16(raw: bytes) -> int:
    return int.from_bytes(raw, "big")


def _parse_publish(payload: bytes, observations: _Observations) -> dict:
    if len(payload) < 8:
        raise Amqp091ContentAnalysisError("Truncated Basic.Publish arguments")
    index = 4
    reserved = _u16(payload[index : index + 2])
    index += 2
    values: list[bytes] = []
    for _ in range(2):
        if index >= len(payload):
            raise Amqp091ContentAnalysisError("Truncated Basic.Publish shortstr")
        length = payload[index]
        index += 1
        if index + length > len(payload):
            raise Amqp091ContentAnalysisError("Basic.Publish shortstr overruns method frame")
        values.append(payload[index : index + length])
        index += length
    if index + 1 != len(payload):
        raise Amqp091ContentAnalysisError("Basic.Publish bit field or trailing bytes malformed")
    bits = payload[index]
    if reserved != 0:
        observations.add("contradictions", "basic_publish_reserved_ticket_not_zero")
    if bits & 0xFC:
        observations.add("unassessed", "basic_publish_unused_bit_positions_nonzero")
    if any(b"\x00" in value for value in values):
        observations.add("contradictions", "basic_publish_shortstr_contains_zero_octet")
    for value in values:
        try:
            value.decode("utf-8")
        except UnicodeDecodeError:
            observations.add("contradictions", "basic_publish_shortstr_not_utf8")
    return {
        "reserved_ticket": reserved,
        "exchange_hex": values[0].hex().upper(),
        "routing_key_hex": values[1].hex().upper(),
        "bits_octet": bits,
        "mandatory": bool(bits & 1),
        "immediate": bool(bits & 2),
    }


def _parse_frames(raw: bytes, budget: _Budget) -> tuple[list[dict], list[dict], _Observations]:
    frames: list[dict] = []
    publications: list[dict] = []
    observations = _Observations([], [], [], budget)
    pending: dict[int, dict] = {}
    unknown_channels: set[int] = set()
    seen_channels: set[int] = set()
    offset = 0
    while offset < len(raw):
        if len(frames) >= MAX_FRAMES:
            raise Amqp091ContentAnalysisError("Frame count ceiling exhausted")
        if len(raw) - offset < 8:
            raise Amqp091ContentAnalysisError("Truncated AMQP frame envelope")
        kind = raw[offset]
        channel = _u16(raw[offset + 1 : offset + 3])
        length = int.from_bytes(raw[offset + 3 : offset + 7], "big")
        if length > MAX_FRAME_PAYLOAD or offset + 8 + length > len(raw):
            raise Amqp091ContentAnalysisError("Bounded frame payload exceeds supplied bytes")
        if raw[offset + 7 + length] != 0xCE:
            raise Amqp091ContentAnalysisError("AMQP frame-end octet mismatch")
        budget.charge(96 + 12 * length)
        payload = raw[offset + 7 : offset + 7 + length]
        frame_index = len(frames)
        frames.append(
            {
                "index": frame_index,
                "offset": offset,
                "type_octet": kind,
                "channel": channel,
                "payload_octets": length,
                "payload_hex": payload.hex().upper(),
            }
        )
        offset += 8 + length
        if channel:
            seen_channels.add(channel)
            if len(seen_channels) > MAX_CHANNELS:
                raise Amqp091ContentAnalysisError("Distinct channel ceiling exhausted")
        if kind == 1:
            if channel in pending:
                pending.pop(channel)["assembly_state"] = "interrupted"
                observations.add("unassessed", "same_channel_method_interrupts_content")
            if length < 4:
                raise Amqp091ContentAnalysisError("Truncated AMQP method identifiers")
            class_id, method_id = _u16(payload[:2]), _u16(payload[2:4])
            if (class_id, method_id) != (60, 40):
                unknown_channels.add(channel)
                observations.add("unassessed", "method_outside_basic_publish_subset")
                continue
            if channel == 0:
                observations.add("contradictions", "basic_publish_uses_connection_channel_zero")
            if len(publications) >= MAX_PUBLISHES:
                raise Amqp091ContentAnalysisError("Basic.Publish count ceiling exhausted")
            method = _parse_publish(payload, observations)
            publication = {
                "channel": channel,
                "method_frame_index": frame_index,
                "header_frame_index": None,
                "body_frame_indices": [],
                "method": method,
                "declared_body_octets": None,
                "body_hex": "",
                "assembly_state": "awaiting_header",
                "header_property_flags_hex": None,
            }
            budget.charge(160)
            publications.append(publication)
            pending[channel] = publication
            unknown_channels.discard(channel)
        elif kind == 2:
            if channel == 0:
                observations.add("contradictions", "content_header_uses_connection_channel_zero")
            publication = pending.get(channel)
            if publication is None:
                observations.add(
                    "unassessed" if channel in unknown_channels else "contradictions",
                    "header_without_supported_pending_method",
                )
                continue
            if publication["assembly_state"] != "awaiting_header":
                observations.add("contradictions", "second_header_before_content_completion")
                continue
            if length < 14:
                raise Amqp091ContentAnalysisError("Truncated content-header fixed fields")
            class_id = _u16(payload[:2])
            weight = _u16(payload[2:4])
            body_size = int.from_bytes(payload[4:12], "big")
            if body_size > MAX_BODY_BYTES:
                raise Amqp091ContentAnalysisError("Local declared body byte ceiling exhausted")
            publication["header_frame_index"] = frame_index
            publication["declared_body_octets"] = body_size
            publication["header_property_flags_hex"] = payload[12:].hex().upper()
            publication["assembly_state"] = "awaiting_body"
            if class_id != 60:
                observations.add("contradictions", "content_header_class_mismatch")
            if weight != 0:
                observations.add("contradictions", "content_header_weight_not_zero")
            if payload[12:] != b"\x00\x00":
                observations.add("unassessed", "basic_properties_outside_zero_flags_subset")
            if body_size == 0:
                publication["assembly_state"] = "complete"
                pending.pop(channel)
        elif kind == 3:
            if channel == 0:
                observations.add("contradictions", "content_body_uses_connection_channel_zero")
            publication = pending.get(channel)
            if publication is None:
                observations.add(
                    "unassessed" if channel in unknown_channels else "contradictions",
                    "body_without_supported_pending_content",
                )
                continue
            if publication["assembly_state"] != "awaiting_body":
                observations.add("contradictions", "body_precedes_content_header")
                continue
            previous = len(publication["body_hex"]) // 2
            if previous + length > publication["declared_body_octets"]:
                observations.add("contradictions", "content_body_exceeds_declared_octets")
                publication["assembly_state"] = "oversized_body"
                pending.pop(channel)
                continue
            budget.charge(2 * previous + 10 * length + 64)
            publication["body_hex"] += payload.hex().upper()
            publication["body_frame_indices"].append(frame_index)
            if previous + length == publication["declared_body_octets"]:
                publication["assembly_state"] = "complete"
                pending.pop(channel)
        else:
            if channel in pending:
                pending.pop(channel)["assembly_state"] = "interrupted"
                observations.add("unassessed", "same_channel_unknown_frame_interrupts_content")
            if channel:
                unknown_channels.add(channel)
            observations.add("unassessed", "frame_type_outside_method_header_body_subset")
    if pending:
        observations.add("unassessed", "supplied_stream_ends_with_pending_content")
    if not publications:
        observations.add("unassessed", "no_supported_basic_publish_method")
    return frames, publications, observations


def _bounds() -> dict:
    return {
        "maximum_stream_octets": MAX_STREAM_BYTES,
        "maximum_frame_payload_octets": MAX_FRAME_PAYLOAD,
        "maximum_body_octets": MAX_BODY_BYTES,
        "maximum_model_bytes": MAX_MODEL_BYTES,
        "maximum_report_bytes": MAX_REPORT_BYTES,
        "maximum_model_nodes": MAX_MODEL_NODES,
        "maximum_report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "maximum_string_bytes": MAX_STRING_BYTES,
        "maximum_frames": MAX_FRAMES,
        "maximum_channels": MAX_CHANNELS,
        "maximum_publishes": MAX_PUBLISHES,
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
        raise Amqp091ContentAnalysisError("Exact closed four-field source model required")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise Amqp091ContentAnalysisError("Exact native schema version one required")
    if type(source["source_id"]) is not str or _LABEL.fullmatch(source["source_id"]) is None:
        raise Amqp091ContentAnalysisError("Bounded exact native source label required")
    if type(source["direction"]) is not str or source["direction"] != "client_to_server":
        raise Amqp091ContentAnalysisError("Explicit client-to-server direction premise required")
    raw = _wire(source["frames_base64"], budget)
    frames, publications, observations = _parse_frames(raw, budget)
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
        "frame_stream_sha256": _SHA_PLACEHOLDER,
        "analysis_status": status,
        "frames": frames,
        "publications": publications,
        "known_contradictions": observations.contradictions,
        "unassessed_reasons": observations.unassessed,
        "advisories": observations.advisories,
        "effects": _EFFECTS,
        "claims": _CLAIMS,
        "limitations": list(_LIMITATIONS),
        "bounds": _bounds(),
        "accounting": {
            "stream_octets": len(raw),
            "frame_count": len(frames),
            "publication_count": len(publications),
            "complete_publication_count": sum(
                item["assembly_state"] == "complete" for item in publications
            ),
            "observation_count": observations.count,
        },
    }
    document, size, nodes = _capture(document, budget, report=True)
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
    document["frame_stream_sha256"] = "sha256:" + hashlib.sha256(plan.raw).hexdigest()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(REPORT_DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "AMQA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    actual, size, nodes = _decode(text, budget, report=True)
    if type(actual) is not dict or "source_model" not in actual:
        raise Amqp091ContentAnalysisError("Complete embedded source model required")
    expected = _plan(actual["source_model"], budget)
    budget.charge(8 * size + 8 * nodes + 6 * expected.size)
    return actual, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise Amqp091ContentAnalysisError("Canonical report fails complete source reconstruction")


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not Amqp091ContentAnalysis:
        raise Amqp091ContentAnalysisError("Exact complete native report wrapper required")
    text = getattr(report, "document_json", None)
    if type(text) is not str:
        raise Amqp091ContentAnalysisError("Complete native report text slot required")
    return text


@dataclass(frozen=True, slots=True)
class Amqp091ContentAnalysis:
    """Unsigned, source-replaying observation of supplied publish-content frames."""

    document_json: str

    def __post_init__(self) -> None:
        _replay(_stored(self), _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> Amqp091ContentAnalysis:
        if cls is not Amqp091ContentAnalysis:
            raise Amqp091ContentAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size, nodes = _capture(document, budget, report=True)
        budget.charge(8 * (size + nodes))
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> Amqp091ContentAnalysis:
        if cls is not Amqp091ContentAnalysis:
            raise Amqp091ContentAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> Amqp091ContentAnalysis:
    result = object.__new__(Amqp091ContentAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_amqp091_content(model: Any) -> Amqp091ContentAnalysis:
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_amqp091_content_bytes(*, model_bytes: Any) -> Amqp091ContentAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise Amqp091ContentAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(4 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Amqp091ContentAnalysisError("Closed JSON metadata requires ASCII") from exc
    source, _, _ = _decode(text, budget)
    return _owned(_materialize(_plan(source, budget)))


def verify_supplied_amqp091_content_analysis(report: Any, *, model: Any) -> Amqp091ContentAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(8 * (embedded.size + original.size + embedded.nodes + original.nodes))
    reconstructed = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, reconstructed)
    if reconstructed != separate:
        raise Amqp091ContentAnalysisError("Report differs from separately supplied original model")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh synthetic two-channel stream; no digest or source acquisition."""

    def frame(kind: int, channel: int, payload: bytes) -> bytes:
        return (
            bytes([kind])
            + channel.to_bytes(2, "big")
            + len(payload).to_bytes(4, "big")
            + payload
            + b"\xce"
        )

    method_a = b"\x00\x3c\x00\x28\x00\x00\x01x\x01a\x00"
    method_b = b"\x00\x3c\x00\x28\x00\x00\x01y\x01b\x01"
    header = b"\x00\x3c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00"
    raw = b"".join(
        (
            frame(1, 1, method_a),
            frame(1, 2, method_b),
            frame(2, 1, header),
            frame(2, 2, header),
            frame(3, 1, b"a"),
            frame(3, 2, b"xyz"),
            frame(3, 1, b"bc"),
        )
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-amqp-publish-content",
        "direction": "client_to_server",
        "frames_base64": base64.b64encode(raw).decode("ascii"),
    }


__all__ = [
    "Amqp091ContentAnalysis",
    "Amqp091ContentAnalysisError",
    "analyze_supplied_amqp091_content",
    "analyze_supplied_amqp091_content_bytes",
    "verify_supplied_amqp091_content_analysis",
    "component_fixture",
]

"""Bounded TLS 1.3 Hello offer-selection arithmetic on supplied bytes."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "tls13_supplied_hello_offer_selection"
PROFILE_ID = "AOE-GE-D22-S02"
CAPABILITY_ID = "army.ge.d22.s02"
VECTOR_ID = "AV-GE-D22-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D22-S02"
WAVE_ID = "IW2-015"
BLUEPRINT_SHA256 = "sha256:74e096e4a79ded22370d7e799d27f894b20a5e49d05046e3c8fc51e34fef1457"
DOMAIN = "sunderkey.offline-tls-hello-analysis.v1"
SEMANTICS_PROFILE = "rfc8446-supplied-ordinary-hello-offer-selection.v1"
MAX_MESSAGE_BYTES = 65_536
MAX_MODEL_BYTES = 262_144
MAX_REPORT_BYTES = 1_048_576
MAX_NODES = 8_192
MAX_DEPTH = 16
MAX_EXTENSIONS = 128
MAX_CIPHER_SUITES = 256
MAX_SUPPORTED_GROUPS = 256
MAX_KEY_SHARES = 64
MAX_OBSERVATIONS = 64
MAX_WORK = 4_194_304
MAX_INTEGER = 2**63 - 1
MIN_INTEGER = -(2**63)
MAX_BASE64_CHARS = 4 * ((MAX_MESSAGE_BYTES + 2) // 3)
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_TLS13_CIPHERS = frozenset(range(0x1301, 0x1306))
_RFC_GROUPS = frozenset((23, 24, 25, 29, 30, 256, 257, 258, 259, 260))
_HANDLED_EXTENSIONS = frozenset((10, 43, 51))
_PSK_EXTENSIONS = frozenset((41, 45))
_MODEL_FIELDS = frozenset(("schema_version", "client_hello_base64", "server_hello_base64"))
_BOUNDS = {
    "maximum_message_bytes": MAX_MESSAGE_BYTES,
    "maximum_model_bytes": MAX_MODEL_BYTES,
    "maximum_report_bytes": MAX_REPORT_BYTES,
    "maximum_native_nodes": MAX_NODES,
    "maximum_native_depth": MAX_DEPTH,
    "maximum_extensions_per_hello": MAX_EXTENSIONS,
    "maximum_cipher_suites": MAX_CIPHER_SUITES,
    "maximum_supported_groups": MAX_SUPPORTED_GROUPS,
    "maximum_key_shares": MAX_KEY_SHARES,
    "maximum_observations": MAX_OBSERVATIONS,
    "maximum_cumulative_work": MAX_WORK,
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
    "Supplied messages and their pairing are unauthenticated declarations.",
    "Only ordinary TLS 1.3 Hello structure and declared offer-selection joins are checked.",
    "HelloRetryRequest, PSK and unhandled extensions do not receive a complete conclusion.",
    "Unknown offered identifiers are preserved and are not violations merely for being unknown.",
    "Key exchange bytes, randomness and cryptographic group validity are not validated.",
    "No records, QUIC, transcript, downgrade protection, certificates, trust or Finished "
    "are checked.",
    "No traffic keys, authentication, live endpoint behavior or vulnerability is established.",
    "No current authority, full specialist completion or qualification follows.",
)
_FIXED = {
    "schema_version": 1,
    "component_id": COMPONENT_ID,
    "profile_id": PROFILE_ID,
    "capability_id": CAPABILITY_ID,
    "vector_id": VECTOR_ID,
    "work_package_id": WORK_PACKAGE_ID,
    "wave_id": WAVE_ID,
    "commander_profile_id": "AOE-GE-D22-CMD",
    "group_commander_profile_id": "AOE-HQ-07",
    "independent_validator_id": "AOE-HQ-19",
    "blueprint_sha256": BLUEPRINT_SHA256,
    "roadmap_package_ids": ["A7.4"],
    "semantics_profile": SEMANTICS_PROFILE,
    "input_provenance": "operator_supplied_unverified",
    "offline_only": True,
    "full_tls_validity_verified": False,
    "message_authenticity_verified": False,
    "cryptographic_validation_performed": False,
    "vulnerability_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
    "effects": _EFFECTS,
    "limitations": list(_LIMITATIONS),
    "bounds": _BOUNDS,
}


class TlsHelloAnalysisError(ValueError):
    """Unsupported intake shape, inconsistent replay or exhausted software budget."""


@dataclass
class _Budget:
    work: int = 0

    def charge(self, amount: int) -> None:
        if self.work + amount > MAX_WORK:
            raise TlsHelloAnalysisError("Cumulative software work limit exceeded")
        self.work += amount


def _escaped_string_size(text: Any, budget: _Budget | None = None) -> int:
    if type(text) is not str or len(text) > MAX_BASE64_CHARS:
        raise TlsHelloAnalysisError("Bounded native string is required")
    size = 2
    if budget is not None:
        budget.charge(2 + len(text))
    for char in text:
        code = ord(char)
        if 0xD800 <= code <= 0xDFFF:
            raise TlsHelloAnalysisError("Unicode scalar strings are required")
        amount = (
            2
            if code in (34, 92, 8, 9, 10, 12, 13)
            else (6 if code < 32 or 126 < code <= 65535 else 12 if code > 65535 else 1)
        )
        if budget is not None:
            budget.charge(amount - 1)
        size += amount
    return size


def _capture(value: Any, maximum: int, budget: _Budget | None = None) -> Any:
    """Capture each repeated occurrence while bounding it before serialization."""
    root: list[Any] = [None]
    tasks: list[tuple[Any, Any, Any, int]] = [(value, root, 0, 1)]
    nodes = size = 0
    while tasks:
        if budget is not None:
            budget.charge(1)
        item, parent, slot, depth = tasks.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise TlsHelloAnalysisError("Native node/depth limit exceeded")
        kind = type(item)
        if kind is dict:
            count = len(item)
            if nodes + len(tasks) + 2 * count > MAX_NODES:
                raise TlsHelloAnalysisError("Native queued-node limit exceeded")
            punctuation = 2 + max(0, count - 1) + count
            if budget is not None:
                budget.charge(punctuation)
            size += punctuation
            owned: Any = {}
            for key, child in item.items():
                if budget is not None:
                    budget.charge(1)
                size += _escaped_string_size(key, budget)
                nodes += 1
                if depth + 1 > MAX_DEPTH or size > maximum:
                    raise TlsHelloAnalysisError("Native key/document limit exceeded")
                tasks.append((child, owned, key, depth + 1))
        elif kind is list:
            count = len(item)
            if nodes + len(tasks) + count > MAX_NODES:
                raise TlsHelloAnalysisError("Native queued-node limit exceeded")
            punctuation = 2 + max(0, count - 1)
            if budget is not None:
                budget.charge(punctuation)
            size += punctuation
            owned = [None] * count
            tasks.extend((child, owned, index, depth + 1) for index, child in enumerate(item))
        elif kind is str:
            size += _escaped_string_size(item, budget)
            owned = item
        elif kind is int:
            if not MIN_INTEGER <= item <= MAX_INTEGER:
                raise TlsHelloAnalysisError("Signed 64-bit native integer is required")
            if budget is not None:
                budget.charge(20)
            size += len(str(item))
            owned = item
        elif kind is bool:
            if budget is not None:
                budget.charge(4 if item else 5)
            size += 4 if item else 5
            owned = item
        elif item is None:
            if budget is not None:
                budget.charge(4)
            size += 4
            owned = None
        else:
            raise TlsHelloAnalysisError("Exact native JSON values are required")
        if size > maximum:
            raise TlsHelloAnalysisError("Escaped document byte limit exceeded")
        parent[slot] = owned
    return root[0]


def _canonical(owned: Any) -> str:
    return json.dumps(owned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _integer(text: str) -> int:
    if _INTEGER.fullmatch(text) is None:
        raise TlsHelloAnalysisError("Bounded JSON integer grammar is required")
    negative = text.startswith("-")
    magnitude = text[1:] if negative else text
    ceiling = "9223372036854775808" if negative else "9223372036854775807"
    if len(magnitude) == 19 and magnitude > ceiling:
        raise TlsHelloAnalysisError("Signed 64-bit JSON integer limit exceeded")
    return int(text)


def _raw_string(text: str, start: int) -> tuple[int, int]:
    index = start + 1
    characters = escaped = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            return index + 1, escaped + 2
        code = ord(char)
        if char == "\\":
            index += 1
            if index >= len(text):
                raise TlsHelloAnalysisError("Unterminated JSON escape")
            escape = text[index]
            if escape == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or re.fullmatch(r"[0-9A-Fa-f]{4}", digits) is None:
                    raise TlsHelloAnalysisError("Invalid Unicode escape")
                code = int(digits, 16)
                index += 4
                if 0xD800 <= code <= 0xDBFF:
                    low = text[index + 3 : index + 7]
                    if (
                        text[index + 1 : index + 3] != "\\u"
                        or len(low) != 4
                        or re.fullmatch(r"[0-9A-Fa-f]{4}", low) is None
                    ):
                        raise TlsHelloAnalysisError("Invalid Unicode surrogate pair")
                    low_code = int(low, 16)
                    if not 0xDC00 <= low_code <= 0xDFFF:
                        raise TlsHelloAnalysisError("Invalid Unicode surrogate pair")
                    code = 0x10000 + ((code - 0xD800) << 10) + low_code - 0xDC00
                    index += 6
                elif 0xDC00 <= code <= 0xDFFF:
                    raise TlsHelloAnalysisError("Unpaired Unicode surrogate")
            else:
                codes = {'"': 34, "\\": 92, "/": 47, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}
                if escape not in codes:
                    raise TlsHelloAnalysisError("Invalid JSON escape")
                code = codes[escape]
        elif code < 32 or 0xD800 <= code <= 0xDFFF:
            raise TlsHelloAnalysisError("Invalid JSON string scalar")
        characters += 1
        escaped += (
            2
            if code in (34, 92, 8, 9, 10, 12, 13)
            else (6 if code < 32 or 126 < code <= 65535 else 12 if code > 65535 else 1)
        )
        if characters > MAX_BASE64_CHARS or escaped > MAX_REPORT_BYTES:
            raise TlsHelloAnalysisError("Raw string budget exceeded")
        index += 1
    raise TlsHelloAnalysisError("Unterminated JSON string")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise TlsHelloAnalysisError("Duplicate JSON key")
        result[key] = value
    return result


def _decode(text: Any, maximum: int) -> Any:
    if type(text) is not str or len(text) > maximum:
        raise TlsHelloAnalysisError("Bounded native JSON text is required")
    try:
        if len(text.encode("utf-8")) > maximum:
            raise TlsHelloAnalysisError("Raw JSON byte limit exceeded")
    except UnicodeError as exc:
        raise TlsHelloAnalysisError("Unicode scalar JSON is required") from exc
    index = nodes = size = 0
    stack = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char in ":,":
            size += 1
            if size > maximum:
                raise TlsHelloAnalysisError("Raw canonical JSON byte limit exceeded")
            index += 1
            continue
        if char in "}]":
            if not stack or stack.pop() != ("{" if char == "}" else "["):
                raise TlsHelloAnalysisError("Malformed JSON container")
            size += 1
            if size > maximum:
                raise TlsHelloAnalysisError("Raw canonical JSON byte limit exceeded")
            index += 1
            continue
        nodes += 1
        if nodes > MAX_NODES or len(stack) + 1 > MAX_DEPTH:
            raise TlsHelloAnalysisError("Raw JSON node/depth limit exceeded")
        if char in "{[":
            stack.append(char)
            size += 1
            index += 1
        elif char == '"':
            index, string_size = _raw_string(text, index)
            size += string_size
        else:
            end = index
            while end < len(text) and text[end] not in " \t\r\n,}:]":
                end += 1
                if end - index > 20:
                    raise TlsHelloAnalysisError("Raw JSON scalar lexical limit exceeded")
            token = text[index:end]
            if token not in ("true", "false", "null"):
                _integer(token)
            size += len(token)
            index = end
        if size > maximum:
            raise TlsHelloAnalysisError("Raw canonical JSON byte limit exceeded")
    if stack:
        raise TlsHelloAnalysisError("Unterminated JSON container")
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer)
    except (ValueError, RecursionError, OverflowError) as exc:
        raise TlsHelloAnalysisError("Invalid bounded JSON document") from exc
    return _capture(value, maximum)


def _wire(text: Any, budget: _Budget) -> bytes:
    if (
        type(text) is not str
        or len(text) > MAX_BASE64_CHARS
        or len(text) % 4
        or _BASE64.fullmatch(text) is None
    ):
        raise TlsHelloAnalysisError("Canonical bounded native base64 is required")
    expected = len(text) // 4 * 3 - (2 if text.endswith("==") else 1 if text.endswith("=") else 0)
    if expected > MAX_MESSAGE_BYTES:
        raise TlsHelloAnalysisError("Supplied message byte limit exceeded")
    budget.charge(len(text) + max(0, expected))
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise TlsHelloAnalysisError("Canonical base64 is required") from exc
    if len(raw) != expected or base64.b64encode(raw).decode("ascii") != text:
        raise TlsHelloAnalysisError("Base64 must have exact canonical padding and bits")
    return raw


class _Truncated(Exception):
    def __init__(self, code: str, offset: int) -> None:
        super().__init__(code)
        self.offset = offset


class _Contradiction(Exception):
    def __init__(self, code: str, offset: int) -> None:
        super().__init__(code)
        self.offset = offset


@dataclass
class _Reader:
    raw: bytes
    offset: int
    end: int
    budget: _Budget

    def take(self, size: int) -> bytes:
        if self.offset + size > self.end:
            raise _Contradiction("encoded_field_exceeds_declared_boundary", self.offset)
        if self.offset + size > len(self.raw):
            raise _Truncated("encoded_field_truncated", self.offset)
        self.budget.charge(size + 1)
        result = self.raw[self.offset : self.offset + size]
        self.offset += size
        return result

    def number(self, width: int) -> int:
        return int.from_bytes(self.take(width), "big")

    def vector(self, width: int, minimum: int, maximum: int) -> _Reader:
        size = self.number(width)
        if not minimum <= size <= maximum:
            raise _Contradiction("vector_length_outside_protocol_range", self.offset)
        if self.offset + size > self.end:
            raise _Contradiction("vector_exceeds_declared_boundary", self.offset)
        if self.offset + size > len(self.raw):
            raise _Truncated("vector_truncated", self.offset)
        start = self.offset
        self.offset += size
        return _Reader(self.raw, start, start + size, self.budget)


def _numbers(vector: _Reader, ceiling: int) -> list[int]:
    length = vector.end - vector.offset
    if length % 2:
        raise _Contradiction("uint16_vector_has_odd_length", vector.offset)
    count = length // 2
    if count > ceiling:
        raise TlsHelloAnalysisError("Identifier vector software limit exceeded")
    vector.budget.charge(count)
    return [vector.number(2) for _ in range(count)]


def _share(reader: _Reader) -> dict[str, int]:
    start = reader.offset
    group = reader.number(2)
    data = reader.vector(2, 1, 65535)
    reader.budget.charge(data.end - data.offset)
    return {"group": group, "key_exchange_bytes": data.end - data.offset, "offset": start}


def _extensions(reader: _Reader, summary: dict[str, Any], *, client: bool) -> None:
    vector = reader.vector(2, 8 if client else 6, 65535)
    seen = set()
    while vector.offset < vector.end:
        if len(summary["extensions"]) >= MAX_EXTENSIONS:
            raise TlsHelloAnalysisError("Extension count software limit exceeded")
        start = vector.offset
        kind = vector.number(2)
        data = vector.vector(2, 0, 65535)
        if kind in seen:
            raise _Contradiction("duplicate_extension_type", start)
        seen.add(kind)
        vector.budget.charge(1)
        summary["extensions"].append(
            {"type": kind, "offset": start, "data_bytes": data.end - data.offset}
        )
        if kind == 43:
            if client:
                summary["supported_versions"] = _numbers(data.vector(1, 2, 254), 127)
            else:
                summary["selected_version"] = data.number(2)
        elif kind == 10 and client:
            summary["supported_groups"] = _numbers(data.vector(2, 2, 65535), MAX_SUPPORTED_GROUPS)
        elif kind == 51:
            if client:
                shares = data.vector(2, 0, 65535)
                summary["key_shares"] = []
                seen_shares = set()
                while shares.offset < shares.end:
                    if len(summary["key_shares"]) >= MAX_KEY_SHARES:
                        raise TlsHelloAnalysisError("Key-share count software limit exceeded")
                    item = _share(shares)
                    if item["group"] in seen_shares:
                        raise _Contradiction("duplicate_client_key_share_group", item["offset"])
                    seen_shares.add(item["group"])
                    summary["key_shares"].append(item)
            else:
                summary["key_share"] = _share(data)
        else:
            data.offset = data.end
        if data.offset != data.end:
            raise _Contradiction("extension_payload_has_trailing_bytes", data.offset)


def _hello(raw: bytes, budget: _Budget, *, client: bool) -> dict[str, Any]:
    result: dict[str, Any] = (
        {
            "parse_status": "unassessed",
            "message_type": None,
            "declared_body_bytes": None,
            "confirmed_prefix_end": 0,
            "trailing_bytes": 0,
            "legacy_version": None,
            "random_hex": None,
            "session_id_hex": None,
            "extensions": [],
            "supported_versions": None,
            "supported_groups": None,
            "key_shares": None,
            "cipher_suites": None,
            "compression_methods": None,
        }
        if client
        else {
            "parse_status": "unassessed",
            "message_type": None,
            "declared_body_bytes": None,
            "confirmed_prefix_end": 0,
            "trailing_bytes": 0,
            "legacy_version": None,
            "random_hex": None,
            "session_id_hex": None,
            "extensions": [],
            "selected_version": None,
            "key_share": None,
            "cipher_suite": None,
            "compression_method": None,
            "hello_retry_request": False,
        }
    )
    header = _Reader(raw, 0, max(4, len(raw)), budget)
    reader = header
    try:
        result["message_type"] = header.number(1)
        result["declared_body_bytes"] = header.number(3)
        if result["message_type"] != (1 if client else 2):
            raise _Contradiction("unexpected_handshake_message_type", 0)
        end = 4 + result["declared_body_bytes"]
        if end > MAX_MESSAGE_BYTES:
            result["issue"] = "declared_message_exceeds_supported_ceiling"
            result["confirmed_prefix_end"] = 4
            return result
        reader = _Reader(raw, 4, end, budget)
        result["legacy_version"] = reader.number(2)
        random = reader.take(32)
        result["random_hex"] = random.hex()
        # HRR's KeyShare payload is a different grammar. Do not parse it as an ordinary share.
        if not client and random == HELLO_RETRY_REQUEST_RANDOM:
            result["hello_retry_request"] = True
            result["issue"] = "hello_retry_request_unassessed"
            result["confirmed_prefix_end"] = reader.offset
            return result
        session = reader.vector(1, 0, 32)
        result["session_id_hex"] = session.take(session.end - session.offset).hex()
        if client:
            result["cipher_suites"] = _numbers(reader.vector(2, 2, 65534), MAX_CIPHER_SUITES)
            compression = reader.vector(1, 1, 255)
            result["compression_methods"] = list(
                compression.take(compression.end - compression.offset)
            )
        else:
            result["cipher_suite"] = reader.number(2)
            result["compression_method"] = reader.number(1)
        if reader.offset == reader.end:
            result["issue"] = "hello_without_extensions_tls13_unestablished"
            result["confirmed_prefix_end"] = reader.offset
            return result
        _extensions(reader, result, client=client)
        if reader.offset != reader.end:
            raise _Contradiction("hello_body_has_trailing_bytes", reader.offset)
        if len(raw) > reader.end:
            result["trailing_bytes"] = len(raw) - reader.end
            raise _Contradiction("bytes_follow_declared_handshake", reader.end)
        result["parse_status"] = "complete"
    except _Truncated as exc:
        result["parse_status"] = "truncated_prefix"
        result["issue"] = str(exc)
        result["confirmed_prefix_end"] = min(exc.offset, len(raw))
        return result
    except _Contradiction as exc:
        result["parse_status"] = "structural_contradiction"
        result["issue"] = str(exc)
        result["confirmed_prefix_end"] = min(exc.offset, len(raw))
        return result
    result["confirmed_prefix_end"] = min(reader.offset, len(raw))
    return result


def _relations(client: dict[str, Any], server: dict[str, Any], budget: _Budget) -> dict[str, Any]:
    violations = []
    unknown = []
    checks = dict.fromkeys(
        (
            "session_id_echo",
            "cipher_suite_membership",
            "version_membership",
            "client_share_order_membership",
            "server_share_membership",
        ),
        "unassessed",
    )

    def violation(code: str, side: str = "pair") -> None:
        if len(violations) + len(unknown) >= MAX_OBSERVATIONS:
            raise TlsHelloAnalysisError("Observation software limit exceeded")
        budget.charge(1)
        violations.append({"code": code, "side": side})

    def unassessed(code: str) -> None:
        if len(violations) + len(unknown) >= MAX_OBSERVATIONS:
            raise TlsHelloAnalysisError("Observation software limit exceeded")
        budget.charge(1)
        unknown.append(code)

    for side, hello in (("client", client), ("server", server)):
        if hello["parse_status"] == "structural_contradiction":
            violation(hello["issue"], side)
        elif hello["parse_status"] != "complete":
            unassessed(side + "_" + hello.get("issue", "incomplete"))
    hrr = server["hello_retry_request"]
    both_complete = client["parse_status"] == server["parse_status"] == "complete"
    ordinary = not hrr and both_complete
    ordinary = ordinary and server["selected_version"] == 0x0304
    if not ordinary and not hrr and client["parse_status"] == server["parse_status"] == "complete":
        unassessed("selected_tls13_context_unestablished")
    if both_complete:
        for side, hello in (("client", client), ("server", server)):
            budget.charge(len(hello["extensions"]))
            kinds = {item["type"] for item in hello["extensions"]}
            if kinds & _PSK_EXTENSIONS:
                unassessed(side + "_psk_feature_unassessed")
            if kinds - _HANDLED_EXTENSIONS - _PSK_EXTENSIONS:
                unassessed(side + "_unhandled_extensions")
        if server["selected_version"] is not None:
            versions = client["supported_versions"] or []
            budget.charge(len(versions))
            if server["selected_version"] in versions:
                checks["version_membership"] = "passes"
            else:
                checks["version_membership"] = "violation"
                violation("selected_version_not_offered")
            if server["selected_version"] in (0x0300, 0x0301, 0x0302, 0x0303):
                violation("server_supported_version_prior_to_tls13", "server")
    if ordinary:
        for side, hello in (("client", client), ("server", server)):
            if hello["legacy_version"] != 0x0303:
                violation("tls13_legacy_version_not_0303", side)
        if client["compression_methods"] != [0]:
            violation("tls13_client_compression_not_single_zero", "client")
        if server["compression_method"] != 0:
            violation("tls13_server_compression_not_zero", "server")
        if client["session_id_hex"] == server["session_id_hex"]:
            checks["session_id_echo"] = "passes"
        else:
            checks["session_id_echo"] = "violation"
            violation("session_id_echo_mismatch")
        budget.charge(len(client["cipher_suites"]))
        if server["cipher_suite"] in client["cipher_suites"]:
            checks["cipher_suite_membership"] = "passes"
        else:
            checks["cipher_suite_membership"] = "violation"
            violation("selected_cipher_not_offered")
        if server["cipher_suite"] not in _TLS13_CIPHERS:
            unassessed("selected_cipher_identifier_unassessed")
        group_ids = client["supported_groups"] or []
        shares = client["key_shares"] or []
        budget.charge(4 * len(group_ids) + 4 * len(shares))
        if len(group_ids) != len(set(group_ids)):
            unassessed("duplicate_supported_groups_order_unassessed")
        else:
            index = {group: position for position, group in enumerate(group_ids)}
            positions = []
            for share in shares:
                budget.charge(1)
                if share["group"] not in index:
                    violation("client_key_share_group_not_supported", "client")
                else:
                    positions.append(index[share["group"]])
            budget.charge(len(positions))
            wrong_order = any(left >= right for left, right in zip(positions, positions[1:]))
            if len(positions) != len(shares) or wrong_order:
                checks["client_share_order_membership"] = "violation"
                if len(positions) == len(shares):
                    violation("client_key_share_order_mismatch", "client")
            elif client["key_shares"] is not None and client["supported_groups"] is not None:
                checks["client_share_order_membership"] = "passes"
        selected = server["key_share"]
        if selected is None:
            budget.charge(len(server["extensions"]))
            if 41 not in {item["type"] for item in server["extensions"]}:
                violation("ordinary_non_psk_server_key_share_absent", "server")
                checks["server_share_membership"] = "violation"
        else:
            budget.charge(len(shares) + len(group_ids))
            offered = {share["group"] for share in shares}
            if selected["group"] in offered and selected["group"] in group_ids:
                checks["server_share_membership"] = "passes"
            else:
                checks["server_share_membership"] = "violation"
                violation("server_key_share_group_not_in_client_share_and_groups")
            if selected["group"] not in _RFC_GROUPS:
                unassessed("selected_group_identifier_unassessed")
        budget.charge(len(client["extensions"]) + len(server["extensions"]))
        client_extensions = {item["type"] for item in client["extensions"]}
        for extension in server["extensions"]:
            kind = extension["type"]
            if kind in (43, 51) and kind not in client_extensions:
                violation("server_checked_extension_not_offered", "server")
            if kind == 10:
                violation("supported_groups_not_permitted_in_server_hello", "server")
    outcome = "unassessed"
    if not hrr and violations:
        outcome = "violations_observed"
    elif ordinary and not unknown:
        outcome = "consistent_with_supported_hello_selection"
    return {
        "outcome": outcome,
        "ordinary_tls13_pair_evaluated": ordinary,
        "supported_checks_complete": ordinary and not unknown,
        "selection_checks": checks,
        "violations": violations,
        "unassessed_reasons": unknown,
    }


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _derive(model: Any) -> dict[str, Any]:
    budget = _Budget()
    owned = _capture(model, MAX_MODEL_BYTES, budget)
    if type(owned) is not dict or set(owned) != _MODEL_FIELDS:
        raise TlsHelloAnalysisError("Exact closed source-model fields are required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise TlsHelloAnalysisError("Native model schema version 1 is required")
    client_raw = _wire(owned["client_hello_base64"], budget)
    server_raw = _wire(owned["server_hello_base64"], budget)
    server = _hello(server_raw, budget, client=False)
    client = _hello(client_raw, budget, client=True)
    relations = _relations(client, server, budget)
    reserved = "sha256:" + "0" * 64
    body = {
        **_FIXED,
        "model": owned,
        "source": {
            "model_sha256": reserved,
            "client_hello_sha256": reserved,
            "server_hello_sha256": reserved,
            "client_hello_bytes": len(client_raw),
            "server_hello_bytes": len(server_raw),
        },
        "client_hello": client,
        "server_hello": server,
        **relations,
    }
    result = {**body, "analysis_id": "THA-" + "0" * 32, "analysis_sha256": reserved}
    # Capture complete fixed-width output before serialization or the first address hash.
    result = _capture(result, MAX_REPORT_BYTES, budget)
    body = {
        key: value for key, value in result.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    addressed = _capture({"domain": DOMAIN, "analysis": body}, MAX_REPORT_BYTES, budget)
    model_json = _canonical(owned).encode("ascii")
    reserved_addressed_json = _canonical(addressed).encode("ascii")
    budget.charge(
        len(model_json) + len(client_raw) + len(server_raw) + len(reserved_addressed_json)
    )
    body["source"]["model_sha256"] = _digest(model_json)
    body["source"]["client_hello_sha256"] = _digest(client_raw)
    body["source"]["server_hello_sha256"] = _digest(server_raw)
    addressed["analysis"]["source"] = body["source"]
    digest = _digest(_canonical(addressed).encode("ascii"))
    result["analysis_sha256"] = digest
    result["analysis_id"] = "THA-" + digest[7:39].upper()
    return result


def _replay(document: Any) -> dict[str, Any]:
    owned = _capture(document, MAX_REPORT_BYTES)
    if type(owned) is not dict or "model" not in owned:
        raise TlsHelloAnalysisError("An exact source-bearing report is required")
    expected = _derive(owned["model"])
    if _canonical(owned) != _canonical(expected):
        raise TlsHelloAnalysisError("Report differs from full embedded-source replay")
    return expected


@dataclass(frozen=True, slots=True)
class TlsHelloAnalysis:
    """Detached unsigned arithmetic, never TLS authentication or an authority grant."""

    document_json: str

    def __post_init__(self) -> None:
        expected = _replay(_decode(self.document_json, MAX_REPORT_BYTES))
        object.__setattr__(self, "document_json", _canonical(expected))

    def to_dict(self) -> dict[str, Any]:
        return _capture_report(self)

    def to_json(self) -> str:
        return _canonical(_capture_report(self))

    @classmethod
    def from_dict(cls, document: Any) -> TlsHelloAnalysis:
        return cls(_canonical(_capture(document, MAX_REPORT_BYTES)))

    @classmethod
    def from_json(cls, document_json: Any) -> TlsHelloAnalysis:
        return cls(document_json)


def _capture_report(report: Any) -> dict[str, Any]:
    if type(report) is not TlsHelloAnalysis:
        raise TlsHelloAnalysisError("The exact native report family is required")
    try:
        text = report.document_json
    except AttributeError as exc:
        raise TlsHelloAnalysisError("Incomplete native report") from exc
    return _replay(_decode(text, MAX_REPORT_BYTES))


def analyze_supplied_tls_hello_pair(model: Any) -> TlsHelloAnalysis:
    """Compare only the supplied ordinary TLS 1.3 offer-selection declarations."""
    return TlsHelloAnalysis(_canonical(_derive(model)))


def analyze_supplied_tls_hello_pair_bytes(*, model_bytes: bytes) -> TlsHelloAnalysis:
    """Consume bounded local UTF-8 JSON bytes without acquiring either message."""
    if type(model_bytes) is not bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise TlsHelloAnalysisError("Bounded native model bytes are required")
    try:
        text = model_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise TlsHelloAnalysisError("UTF-8 model bytes are required") from exc
    return analyze_supplied_tls_hello_pair(_decode(text, MAX_MODEL_BYTES))


def verify_supplied_tls_hello_analysis(report: TlsHelloAnalysis, *, model: Any) -> TlsHelloAnalysis:
    """Replay against separately supplied original bytes, with no authenticity claim."""
    supplied = _capture_report(report)
    expected = _derive(model)
    if _canonical(supplied) != _canonical(expected):
        raise TlsHelloAnalysisError("Report is not bound to the separately supplied original model")
    return TlsHelloAnalysis(_canonical(expected))


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic opaque shares, not generated cryptographic keys."""
    client = bytes.fromhex("0303") + bytes(range(32)) + b"\x02ID\x00\x04\x13\x01\x13\x02\x01\x00"
    client_extensions = (
        b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
        b"\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17"
        b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + b"c" * 32
    )
    client += len(client_extensions).to_bytes(2, "big") + client_extensions
    server = bytes.fromhex("0303") + bytes(range(32, 64)) + b"\x02ID\x13\x01\x00"
    server_extensions = b"\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20" + b"s" * 32
    server += len(server_extensions).to_bytes(2, "big") + server_extensions
    return {
        "schema_version": 1,
        "client_hello_base64": base64.b64encode(
            b"\x01" + len(client).to_bytes(3, "big") + client
        ).decode("ascii"),
        "server_hello_base64": base64.b64encode(
            b"\x02" + len(server).to_bytes(3, "big") + server
        ).decode("ascii"),
    }


__all__ = [
    "TlsHelloAnalysis",
    "TlsHelloAnalysisError",
    "analyze_supplied_tls_hello_pair",
    "analyze_supplied_tls_hello_pair_bytes",
    "component_fixture",
    "verify_supplied_tls_hello_analysis",
]

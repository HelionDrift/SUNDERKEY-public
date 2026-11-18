"""Supplied DKIM byte canonicalization, not signature or domain verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "dkim_supplied_canonicalization_and_body_hash"
PROFILE_ID = "AOE-GC-D13-S14"
CAPABILITY_ID = "army.gc.d13.s14"
VECTOR_ID = "AV-GC-D13-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S14"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6ede9269d562acfd25fa6e2c0dc197ad9fc5b4b450d03fb2f5f3e1c768803e3a"
SEMANTICS_PROFILE = "rfc6376-supplied-simple-relaxed-sha256-arithmetic-subset.v1"
MODEL_DOMAIN = "sunderkey.offline-dkim-canonicalization-model.v1"
DOMAIN = "sunderkey.offline-dkim-canonicalization-analysis.v1"
MAX_MESSAGE_BYTES = 262_144
MAX_HEADER_BYTES = 65_536
MAX_LINE_BYTES = 8_192
MAX_HEADER_FIELDS = 512
MAX_HEADER_SELECTIONS = 512
MAX_TAGS = 64
MAX_BODY_LINES = 32_768
MAX_MODEL_BYTES = 524_288
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 65_536
MAX_DEPTH = 16
MAX_WORK = 67_108_864
MAX_BASE64_BYTES = 4 * ((MAX_MESSAGE_BYTES + 2) // 3)
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}\Z")
_TAG_NAME = re.compile(rb"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_ALGORITHM = re.compile(rb"[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\Z")
_CANONICALIZATION = re.compile(rb"[A-Za-z][A-Za-z0-9-]*(?:/[A-Za-z][A-Za-z0-9-]*)?\Z")
_PLACEHOLDER = "sha256:" + "0" * 64
_HASH_BASE64_PLACEHOLDER = "0" * 43 + "="
_MODEL_FIELDS = {"schema_version", "source_id", "message_base64", "dkim_header_index"}
_REQUIRED_TAGS = {"v", "a", "b", "bh", "d", "h", "s"}
_WSP = b" \t"
_FWS = b" \t\r\n"
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "signature_verified",
        "dns_authenticated",
        "key_currentness_verified",
        "domain_authorized",
        "signed_from_conformance_verified",
        "identity_or_expiry_verified",
        "spf_verified",
        "dmarc_verified",
        "mail_validity_verified",
        "mail_acceptance_approved",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    ("network", "dns", "credential", "provider", "process", "execution", "authority", "deployment"),
    "none",
)
_LIMITATIONS = (
    "Only supplied byte canonicalization and a SHA256 body-hash comparison are computed.",
    "The selected header index is a physical field index, not a line or signing-order assertion.",
    "ASCII headers, paired CRLF and optional before-colon SP/HTAB form a declared "
    "arithmetic subset.",
    "Body octets remain opaque; only SP/HTAB are whitespace, with no MIME or SMTP decoding.",
    "Version one, rsa-sha256 and simple/relaxed modes are the supported arithmetic profile.",
    "Unsupported version, algorithm or canonicalization has null unavailable arithmetic fields.",
    "Unknown tags remain in the preimage but their identity, time, key and query meaning "
    "is unassessed.",
    "The b value is not a verified signature; no DNS, key lookup, RSA or domain "
    "authentication occurs.",
    "No signed-From, mailbox identity, expiry, mail validity, acceptance, SPF or DMARC conclusion.",
    "A zero or partial l value is only declared byte coverage, not safe or authorized "
    "mail acceptance.",
    "An oversized l is a coverage contradiction, never a clamped prefix or body-hash result.",
    "Reports retain complete unsanitized message bytes and are not safe-publication artifacts.",
    "Each public operation funds its own complete replay; simultaneous maxima need not "
    "fit the caps.",
)


class DkimCanonicalizationError(ValueError):
    """A closed-input, declared-grammar, exact-replay or software-cost refusal."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise DkimCanonicalizationError("Cumulative software work ceiling exhausted")
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
            raise DkimCanonicalizationError("Canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if depth > MAX_DEPTH or nodes > node_limit:
            raise DkimCanonicalizationError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_BASE64_BYTES + 4:
                raise DkimCanonicalizationError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                if not 32 <= ord(char) <= 126:
                    raise DkimCanonicalizationError("Printable ASCII metadata required")
                if char in '\\"':
                    add(1)
        elif kind is bool:
            add(4 if item else 5)
        elif item is None:
            add(4)
        elif kind is int:
            if item.bit_length() > 64 or not MIN_INTEGER <= item <= MAX_INTEGER:
                raise DkimCanonicalizationError("Native signed64 integer required")
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise DkimCanonicalizationError("Cyclic native document")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise DkimCanonicalizationError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise DkimCanonicalizationError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise DkimCanonicalizationError("Exact integer-only native JSON families required")

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
        raise DkimCanonicalizationError("Raw bounded integer grammar required")
    digits = text[1:] if text.startswith("-") else text
    limit = "9223372036854775808" if text.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise DkimCanonicalizationError("Raw signed64 integer ceiling exhausted")
    return int(text)


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> Any:
    byte_limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > byte_limit:
        raise DkimCanonicalizationError("Bounded exact native JSON text required")
    budget.charge(2 * len(text))
    if not text.isascii():
        raise DkimCanonicalizationError("ASCII raw JSON metadata required")
    index = nodes = 0
    stack: list[str] = []
    while index < len(text):
        char = text[index]
        if char in " \t\r\n,:":
            index += 1
            continue
        if char in "]}":
            if not stack or stack.pop() != ("[" if char == "]" else "{"):
                raise DkimCanonicalizationError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise DkimCanonicalizationError("Pre-decoder node/depth ceiling exhausted")
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
                        raise DkimCanonicalizationError("Incomplete JSON escape")
                    if text[index] == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise DkimCanonicalizationError("Malformed JSON Unicode escape")
                        code = int(digits, 16)
                        index += 4
                    elif text[index] in '\\"/':
                        code = ord(text[index])
                    else:
                        raise DkimCanonicalizationError("Unsupported JSON string escape")
                if not 32 <= code <= 126:
                    raise DkimCanonicalizationError("Printable ASCII JSON strings required")
                count += 1
                if count > MAX_BASE64_BYTES + 4:
                    raise DkimCanonicalizationError("Pre-decoder string ceiling exhausted")
                index += 1
            if index >= len(text):
                raise DkimCanonicalizationError("Unterminated JSON string")
            index += 1
        else:
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}[{"':
                index += 1
                if index - start > 20:
                    raise DkimCanonicalizationError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise DkimCanonicalizationError("Unterminated JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                raise DkimCanonicalizationError("Duplicate raw JSON key")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise DkimCanonicalizationError("Integer-only raw JSON required")

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
        raise DkimCanonicalizationError("Malformed bounded JSON document") from exc
    _measure(document, budget, report=report)
    return document


def _message(model: dict, budget: _Budget) -> bytes:
    if model.keys() != _MODEL_FIELDS:
        raise DkimCanonicalizationError("Exact closed source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DkimCanonicalizationError("Exact native schema version one required")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise DkimCanonicalizationError("Bounded native source identity required")
    selected = model["dkim_header_index"]
    if type(selected) is not int or not 0 <= selected < MAX_HEADER_FIELDS:
        raise DkimCanonicalizationError("Bounded native physical header index required")
    encoded = model["message_base64"]
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise DkimCanonicalizationError("Bounded complete native message base64 required")
    budget.charge(8 * len(encoded))
    if not encoded.isascii():
        raise DkimCanonicalizationError("ASCII message base64 required")
    raw = encoded.encode("ascii")
    if len(raw) % 4 or _BASE64.fullmatch(raw) is None:
        raise DkimCanonicalizationError("Canonical padded message base64 required")
    try:
        message = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DkimCanonicalizationError("Malformed message base64") from exc
    if not message or len(message) > MAX_MESSAGE_BYTES or base64.b64encode(message) != raw:
        raise DkimCanonicalizationError("Canonical bounded complete message bytes required")
    return message


def _source_shape(model: Any, budget: _Budget) -> None:
    if type(model) is not dict or len(model) != 4 or any(type(key) is not str for key in model):
        raise DkimCanonicalizationError("Exact closed native source model required")
    if model.keys() != _MODEL_FIELDS:
        raise DkimCanonicalizationError("Exact closed native source model required")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DkimCanonicalizationError("Exact native schema version one required")
    if (
        type(model["dkim_header_index"]) is not int
        or not 0 <= model["dkim_header_index"] < MAX_HEADER_FIELDS
    ):
        raise DkimCanonicalizationError("Bounded native physical header index required")
    identity, encoded = model["source_id"], model["message_base64"]
    if type(identity) is not str or len(identity) > 64:
        raise DkimCanonicalizationError("Bounded native source identity required")
    if type(encoded) is not str or not encoded or len(encoded) > MAX_BASE64_BYTES:
        raise DkimCanonicalizationError("Bounded native message base64 required")
    budget.charge(256 + 2 * len(identity) + 2 * len(encoded))
    if _ID.fullmatch(identity) is None:
        raise DkimCanonicalizationError("Bounded ASCII source identity required")


@dataclass(frozen=True, slots=True)
class _Field:
    index: int
    name: str
    start: int
    end: int
    colon: int
    raw: bytes
    before_colon_wsp: bool


@dataclass(frozen=True, slots=True)
class _Tag:
    name: str
    value: bytes
    start: int
    end: int


def _field_name(value: bytes) -> str:
    if (
        not value
        or len(value) > 64
        or any(not (33 <= char <= 57 or 59 <= char <= 126) for char in value)
    ):
        raise DkimCanonicalizationError("Bounded ASCII header field name required")
    return value.decode("ascii")


def _fields(message: bytes, budget: _Budget) -> tuple[list[_Field], int, int]:
    budget.charge(10 * len(message))
    separator = message.find(b"\r\n\r\n")
    if separator < 0 or separator + 4 > MAX_HEADER_BYTES:
        raise DkimCanonicalizationError("Bounded CRLF header/body separator required")
    body_start = separator + 4
    # Validate every CR/LF and line width before any line collection is allocated.
    position = line_start = body_lines = 0
    while position < len(message):
        char = message[position]
        if char == 13:
            if position + 1 >= len(message) or message[position + 1] != 10:
                raise DkimCanonicalizationError("Bare CR is outside the declared byte subset")
            if position - line_start > MAX_LINE_BYTES:
                raise DkimCanonicalizationError("Physical line software ceiling exhausted")
            if position >= body_start:
                body_lines += 1
                if body_lines > MAX_BODY_LINES:
                    raise DkimCanonicalizationError("Physical body-line ceiling exhausted")
            position += 2
            line_start = position
        elif char == 10:
            raise DkimCanonicalizationError("Bare LF is outside the declared byte subset")
        else:
            position += 1
    if len(message) - line_start > MAX_LINE_BYTES:
        raise DkimCanonicalizationError("Physical line software ceiling exhausted")
    if line_start < len(message):
        body_lines += 1
    if body_lines > MAX_BODY_LINES:
        raise DkimCanonicalizationError("Physical body-line ceiling exhausted")

    fields: list[_Field] = []
    start = position = 0
    name = ""
    colon = 0
    before_colon_wsp = False

    def finish(end: int) -> None:
        if len(fields) >= MAX_HEADER_FIELDS:
            raise DkimCanonicalizationError("Physical header-field ceiling exhausted")
        budget.charge(256 + 3 * (end - start))
        fields.append(
            _Field(len(fields), name, start, end, colon, message[start:end], before_colon_wsp)
        )

    while position <= separator:
        end = message.find(b"\r\n", position)
        line = message[position:end]
        if not line or any(char != 9 and not 32 <= char <= 126 for char in line):
            raise DkimCanonicalizationError("ASCII header lines with SP/HTAB FWS required")
        if line[0] in _WSP:
            if not name:
                raise DkimCanonicalizationError("Orphan header continuation")
        else:
            if name:
                finish(position)
            start = position
            colon = line.find(b":")
            if colon < 0:
                raise DkimCanonicalizationError("Header field lacks its colon")
            raw_name = line[:colon]
            stripped = raw_name.rstrip(_WSP)
            name = _field_name(stripped)
            before_colon_wsp = stripped != raw_name
        position = end + 2
    if not name:
        raise DkimCanonicalizationError("At least one physical header field required")
    finish(separator + 2)
    return fields, body_start, body_lines


def _tags(field: _Field, budget: _Budget) -> dict[str, _Tag]:
    budget.charge(12 * len(field.raw) + 256 * MAX_TAGS)
    value = field.raw[field.colon + 1 : -2]
    if value.count(b";") > MAX_TAGS:
        raise DkimCanonicalizationError("Selected tag-count ceiling exhausted")
    tags: dict[str, _Tag] = {}
    start = 0
    while start < len(value):
        delimiter = value.find(b";", start)
        end = len(value) if delimiter < 0 else delimiter
        part = value[start:end]
        if not part.strip(_FWS):
            if delimiter < 0 and start > 0:
                break
            raise DkimCanonicalizationError("Empty declared tag specification")
        equal = part.find(b"=")
        if equal < 0:
            raise DkimCanonicalizationError("Declared tag lacks equals")
        name_bytes = part[:equal].strip(_FWS)
        if _TAG_NAME.fullmatch(name_bytes) is None:
            raise DkimCanonicalizationError("Bounded case-sensitive tag name required")
        name = name_bytes.decode("ascii")
        if name in tags:
            raise DkimCanonicalizationError("Duplicate declared case-sensitive tag")
        if len(tags) >= MAX_TAGS:
            raise DkimCanonicalizationError("Selected tag-count ceiling exhausted")
        raw_start = field.start + field.colon + 1 + start + equal + 1
        raw_end = field.start + field.colon + 1 + end
        tags[name] = _Tag(name, part[equal + 1 :].strip(_FWS), raw_start, raw_end)
        if delimiter < 0:
            break
        start = delimiter + 1
    if not tags.keys() >= _REQUIRED_TAGS:
        raise DkimCanonicalizationError("Selected signature lacks a required declared tag")
    return tags


def _tag_base64(value: bytes, budget: _Budget) -> tuple[bytes, str]:
    budget.charge(8 * len(value))
    compact = bytes(char for char in value if char not in _FWS)
    if not compact or len(compact) % 4 or _BASE64.fullmatch(compact) is None:
        raise DkimCanonicalizationError("Declared base64 tag grammar required")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DkimCanonicalizationError("Malformed declared base64 tag") from exc
    return decoded, compact.decode("ascii")


def _declarations(
    tags: dict[str, _Tag], budget: _Budget
) -> tuple[list[str], str | None, str | None, bytes, str, str | None, list[str]]:
    version = tags["v"].value
    algorithm = tags["a"].value
    canonicalization = tags["c"].value if "c" in tags else b"simple/simple"
    if not version or any(char not in b"0123456789" for char in version):
        raise DkimCanonicalizationError("Declared version decimal grammar required")
    if _ALGORITHM.fullmatch(algorithm) is None:
        raise DkimCanonicalizationError("Declared algorithm token grammar required")
    if _CANONICALIZATION.fullmatch(canonicalization) is None:
        raise DkimCanonicalizationError("Declared canonicalization token grammar required")
    if not tags["d"].value or not tags["s"].value:
        raise DkimCanonicalizationError("Nonempty opaque domain and selector declarations required")
    _tag_base64(tags["b"].value, budget)
    bh, compact_bh = _tag_base64(tags["bh"].value, budget)
    signed = tags["h"].value
    if not signed or signed.count(b":") >= MAX_HEADER_SELECTIONS:
        raise DkimCanonicalizationError("Bounded nonempty h selection list required")
    budget.charge(6 * len(signed) + 256 * (signed.count(b":") + 1))
    names = [_field_name(part.strip(_FWS)) for part in signed.split(b":")]
    declared_l = None
    if "l" in tags:
        length = tags["l"].value
        if not 1 <= len(length) <= 76 or any(char not in b"0123456789" for char in length):
            raise DkimCanonicalizationError("Declared l must contain one to 76 decimal digits")
        declared_l = length.decode("ascii")
    modes = canonicalization.split(b"/")
    header = modes[0]
    body = modes[1] if len(modes) == 2 else b"simple"
    reasons = []
    if version != b"1":
        reasons.append("unsupported_declared_version")
    if algorithm != b"rsa-sha256":
        reasons.append("unsupported_declared_algorithm")
    if header not in (b"simple", b"relaxed"):
        reasons.append("unsupported_header_canonicalization")
    if body not in (b"simple", b"relaxed"):
        reasons.append("unsupported_body_canonicalization")
    if reasons:
        return names, None, None, bh, compact_bh, declared_l, reasons
    if len(bh) != 32:
        raise DkimCanonicalizationError("Supported SHA256 bh must encode exactly 32 bytes")
    return names, header.decode("ascii"), body.decode("ascii"), bh, compact_bh, declared_l, []


def _header(raw: bytes, colon: int, name: str, mode: str, budget: _Budget) -> bytes:
    budget.charge(16 * len(raw) + 256)
    if mode == "simple":
        return raw
    value = raw[colon + 1 : -2]
    output = bytearray()
    pending = False
    position = 0
    while position < len(value):
        char = value[position]
        if char == 13:
            position += 2
            continue
        if char in _WSP:
            pending = True
        else:
            if pending and output:
                output.append(32)
            output.append(char)
            pending = False
        position += 1
    return name.lower().encode("ascii") + b":" + bytes(output) + b"\r\n"


def _body(value: bytes, mode: str, lines: int, budget: _Budget) -> bytes:
    budget.charge(20 * len(value) + 128 * (lines + 1) + 512)
    if mode == "simple":
        # Paired-CRLF intake makes this a linear removal of whole trailing empty lines.
        return value.rstrip(b"\r\n") + b"\r\n"
    output = bytearray()
    line = bytearray()
    empty = 0
    pending = False

    def finish() -> None:
        nonlocal empty
        if line:
            output.extend(b"\r\n" * empty)
            output.extend(line)
            output.extend(b"\r\n")
            empty = 0
            line.clear()
        else:
            empty += 1

    position = 0
    while position < len(value):
        char = value[position]
        if char == 13:
            finish()
            pending = False
            position += 2
            continue
        if char in _WSP:
            pending = True
        else:
            if pending:
                line.append(32)
            line.append(char)
            pending = False
        position += 1
    if line or pending:
        finish()
    return bytes(output)


@dataclass(slots=True)
class _Retained:
    size: int
    nodes: int

    def reserve(self, size: int, nodes: int, budget: _Budget) -> None:
        if size > MAX_REPORT_BYTES - self.size or nodes > MAX_REPORT_NODES - self.nodes:
            raise DkimCanonicalizationError("Cumulative retained report ceiling exhausted")
        budget.charge(5 * (size + nodes))
        self.size += size
        self.nodes += nodes


def _selection(
    fields: list[_Field],
    selected: _Field,
    names: list[str],
    mode: str | None,
    tags: dict[str, _Tag],
    budget: _Budget,
    retained: _Retained,
) -> tuple[list[dict], bytes | None, dict]:
    budget.charge(512 * (len(fields) + len(names)) + 8 * MAX_HEADER_BYTES)
    available: dict[str, list[int]] = {}
    for field in fields:
        if field.index != selected.index:
            available.setdefault(field.name.lower(), []).append(field.index)
    rows: list[dict] = []
    chunks: list[bytes] = []
    position = 0
    for index, name in enumerate(names):
        retained.reserve(640, 32, budget)
        candidates = available.get(name.lower())
        physical = candidates.pop() if candidates else None
        field = fields[physical] if physical is not None else None
        contribution = (
            _header(field.raw, field.colon, field.name, mode, budget)
            if field is not None and mode is not None
            else None
        )
        width = len(contribution) if contribution is not None else (0 if field is None else None)
        rows.append(
            {
                "selection_index": index,
                "requested_name": name,
                "physical_header_index": physical,
                "source_start": field.start if field else None,
                "source_end": field.end if field else None,
                "contribution_start": position if mode is not None else None,
                "contribution_bytes": width,
            }
        )
        if contribution is not None:
            chunks.append(contribution)
            position += len(contribution)
    b_tag = tags["b"]
    signature = None
    if mode is not None:
        before = b_tag.start - selected.start
        after = b_tag.end - selected.start
        budget.charge(5 * len(selected.raw))
        deleted = selected.raw[:before] + selected.raw[after:]
        signature = _header(deleted, selected.colon, selected.name, mode, budget)[:-2]
        chunks.append(signature)
    signature_row = {
        "physical_header_index": selected.index,
        "source_start": selected.start,
        "source_end": selected.end,
        "b_removed_start": b_tag.start,
        "b_removed_end": b_tag.end,
        "contribution_start": position if signature is not None else None,
        "contribution_bytes": len(signature) if signature is not None else None,
        "trailing_crlf_in_preimage": False if signature is not None else None,
    }
    return rows, b"".join(chunks) if mode is not None else None, signature_row


def _bounds() -> dict:
    return {
        "message_bytes": MAX_MESSAGE_BYTES,
        "header_bytes_including_separator": MAX_HEADER_BYTES,
        "physical_line_content_bytes": MAX_LINE_BYTES,
        "physical_header_fields": MAX_HEADER_FIELDS,
        "h_selections": MAX_HEADER_SELECTIONS,
        "selected_tags": MAX_TAGS,
        "physical_body_lines": MAX_BODY_LINES,
        "model_bytes": MAX_MODEL_BYTES,
        "report_bytes": MAX_REPORT_BYTES,
        "model_nodes": MAX_MODEL_NODES,
        "report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "cumulative_work_per_public_operation": MAX_WORK,
    }


@dataclass(slots=True)
class _Plan:
    document: dict
    message: bytes
    body_prefix: bytes | None
    preimage: bytes | None
    bh: bytes
    size: int


def _plan(model: Any, budget: _Budget) -> _Plan:
    _source_shape(model, budget)
    source, source_size, _ = _capture(model, budget)
    message = _message(source, budget)
    fields, body_start, body_lines = _fields(message, budget)
    index = source["dkim_header_index"]
    if index >= len(fields) or fields[index].name.lower() != "dkim-signature":
        raise DkimCanonicalizationError("Selected physical field must be DKIM-Signature")
    selected = fields[index]
    tags = _tags(selected, budget)
    names, header_mode, body_mode, bh, compact_bh, declared_l, reasons = _declarations(tags, budget)
    budget.charge(6 * len(message) + 4 * MAX_HEADER_BYTES)
    canonical_body = (
        _body(message[body_start:], body_mode, body_lines, budget)
        if body_mode is not None
        else None
    )
    coverage = "unassessed"
    covered = uncovered = None
    prefix = None
    violations: list[str] = []
    if canonical_body is not None:
        digits = declared_l.lstrip("0") or "0" if declared_l is not None else None
        actual = str(len(canonical_body))
        if digits is not None and (
            len(digits) > len(actual) or (len(digits) == len(actual) and digits > actual)
        ):
            coverage = "declared_length_exceeds_canonical_body"
            violations.append("declared_body_length_exceeds_canonical_body")
            reasons.append("body_hash_unavailable_for_oversized_l")
        else:
            covered = len(canonical_body) if digits is None else int(digits)
            uncovered = len(canonical_body) - covered
            coverage = "full" if covered == len(canonical_body) else "prefix"
            budget.charge(3 * len(canonical_body))
            prefix = canonical_body[:covered]
            # Fund the larger false-comparison shape before computing its digest.
            violations.append("declared_body_hash_mismatch")
    body_observation = {
        "source_start": body_start,
        "source_bytes": len(message) - body_start,
        "physical_lines": body_lines,
        "canonical_bytes": len(canonical_body) if canonical_body is not None else None,
        "canonical_body_base64": None,
        "declared_l_decimal": declared_l,
        "coverage_state": coverage,
        "covered_bytes": covered,
        "uncovered_bytes": uncovered,
        "computed_body_sha256": _PLACEHOLDER if prefix is not None else None,
        "computed_body_hash_base64": _HASH_BASE64_PLACEHOLDER if prefix is not None else None,
        "supplied_bh_base64_without_fws": compact_bh,
        "body_hash_matches_supplied_bh": False if prefix is not None else None,
    }
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
        "source_message_sha256": _PLACEHOLDER,
        "source_message_bytes": len(message),
        "header_bytes_including_separator": body_start,
        "physical_header_fields": len(fields),
        "before_colon_wsp_field_indices": [],
        "selected_signature_index": index,
        "selected_tag_observations": [],
        "header_algorithm": header_mode,
        "body_algorithm": body_mode,
        "body_observation": body_observation,
        "header_selection_observations": [],
        "selected_signature_contribution": {},
        "header_preimage_base64": None,
        "header_preimage_bytes": None,
        "header_preimage_sha256": _PLACEHOLDER if header_mode is not None else None,
        "declared_arithmetic_violations": violations,
        "unassessed_reasons": reasons,
        "analysis_status": "arithmetic_unassessed" if reasons else "arithmetic_computed",
        "flags": _FLAGS,
        "effects": _EFFECTS,
        "bounds": _bounds(),
        "limitations": list(_LIMITATIONS),
        "analysis_id": "DCA-" + "0" * 32,
        "analysis_sha256": _PLACEHOLDER,
    }
    base_size, base_nodes = _measure(document, budget, report=True)
    retained = _Retained(base_size, base_nodes)
    # Fund bulk output and each retained collection entry before encoding/appending.
    if canonical_body is not None:
        retained.reserve(4 * ((len(canonical_body) + 2) // 3) + 64, 4, budget)
        body_observation["canonical_body_base64"] = base64.b64encode(canonical_body).decode("ascii")
    for field in fields:
        if field.before_colon_wsp:
            retained.reserve(24, 2, budget)
            document["before_colon_wsp_field_indices"].append(field.index)
    # Reserve header/preimage base64 and the fixed signature row before allocation.
    retained.reserve(4 * ((MAX_HEADER_BYTES + 2) // 3) + 1024, 80, budget)
    rows, preimage, signature_row = _selection(
        fields, selected, names, header_mode, tags, budget, retained
    )
    document["header_selection_observations"] = rows
    document["selected_signature_contribution"] = signature_row
    document["header_preimage_base64"] = (
        base64.b64encode(preimage).decode("ascii") if preimage is not None else None
    )
    document["header_preimage_bytes"] = len(preimage) if preimage is not None else None
    for tag in tags.values():
        retained.reserve(384, 16, budget)
        document["selected_tag_observations"].append(
            {
                "name": tag.name,
                "value_start_including_fws": tag.start,
                "value_end_including_fws": tag.end,
                "value_bytes_without_surrounding_fws": len(tag.value),
            }
        )
    document, size, nodes = _capture(document, budget, report=True)
    budget.charge(
        10 * size
        + 4 * source_size
        + 8 * len(message)
        + 4 * nodes
        + (4 * len(prefix) if prefix is not None else 0)
        + (4 * len(preimage) if preimage is not None else 0)
        + len(MODEL_DOMAIN)
        + len(DOMAIN)
        + 2
    )
    return _Plan(document, message, prefix, preimage, bh, size)


def _digest(domain: str, value: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    if plan.body_prefix is not None:
        digest = hashlib.sha256(plan.body_prefix).digest()
        body = document["body_observation"]
        body["computed_body_sha256"] = "sha256:" + digest.hex()
        body["computed_body_hash_base64"] = base64.b64encode(digest).decode("ascii")
        body["body_hash_matches_supplied_bh"] = digest == plan.bh
        if digest == plan.bh:
            document["declared_arithmetic_violations"].remove("declared_body_hash_mismatch")
    if plan.preimage is not None:
        document["header_preimage_sha256"] = "sha256:" + hashlib.sha256(plan.preimage).hexdigest()
    document["source_message_sha256"] = "sha256:" + hashlib.sha256(plan.message).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "DCA-" + digest[7:39].upper()
    return _canonical(document)


def _report_shape(document: Any, budget: _Budget) -> None:
    fields = {
        "schema_version",
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
        "source_model",
        "source_model_sha256",
        "source_message_sha256",
        "source_message_bytes",
        "header_bytes_including_separator",
        "physical_header_fields",
        "before_colon_wsp_field_indices",
        "selected_signature_index",
        "selected_tag_observations",
        "header_algorithm",
        "body_algorithm",
        "body_observation",
        "header_selection_observations",
        "selected_signature_contribution",
        "header_preimage_base64",
        "header_preimage_bytes",
        "header_preimage_sha256",
        "declared_arithmetic_violations",
        "unassessed_reasons",
        "analysis_status",
        "flags",
        "effects",
        "bounds",
        "limitations",
        "analysis_id",
        "analysis_sha256",
    }
    if type(document) is not dict or document.keys() != fields:
        raise DkimCanonicalizationError("Exact closed report object required")
    budget.charge(8192)

    def integer(
        value: Any, *, nullable: bool = False, maximum: int = MAX_MESSAGE_BYTES + 2
    ) -> None:
        if value is None and nullable:
            return
        if type(value) is not int or not 0 <= value <= maximum:
            raise DkimCanonicalizationError("Bounded exact native report counter required")

    def text(value: Any, *, nullable: bool = False) -> None:
        if value is None and nullable:
            return
        if type(value) is not str:
            raise DkimCanonicalizationError("Exact native report text required")

    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise DkimCanonicalizationError("Exact native report schema version one required")
    if type(document["source_model"]) is not dict:
        raise DkimCanonicalizationError("Exact native embedded source model required")
    if (
        type(document["flags"]) is not dict
        or document["flags"].keys() != _FLAGS.keys()
        or any(type(value) is not bool or value for value in document["flags"].values())
    ):
        raise DkimCanonicalizationError("Exact nonpromoting boolean flags required")
    if (
        type(document["effects"]) is not dict
        or document["effects"].keys() != _EFFECTS.keys()
        or any(type(value) is not str or value != "none" for value in document["effects"].values())
    ):
        raise DkimCanonicalizationError("Exact no-effect declarations required")
    if type(document["bounds"]) is not dict or document["bounds"].keys() != _bounds().keys():
        raise DkimCanonicalizationError("Exact closed report bounds required")
    for value in document["bounds"].values():
        integer(value, maximum=MAX_INTEGER)
    for key in (
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
        "source_message_sha256",
        "analysis_status",
        "analysis_id",
        "analysis_sha256",
    ):
        text(document[key])
    for key in (
        "header_algorithm",
        "body_algorithm",
        "header_preimage_base64",
        "header_preimage_sha256",
    ):
        text(document[key], nullable=True)
    for key in (
        "source_message_bytes",
        "header_bytes_including_separator",
        "physical_header_fields",
        "selected_signature_index",
    ):
        integer(document[key])
    integer(document["header_preimage_bytes"], nullable=True)
    for key in ("declared_arithmetic_violations", "unassessed_reasons", "limitations"):
        if type(document[key]) is not list:
            raise DkimCanonicalizationError("Exact native report arrays required")
        for value in document[key]:
            text(value)
    if type(document["before_colon_wsp_field_indices"]) is not list:
        raise DkimCanonicalizationError("Exact native before-colon index array required")
    for value in document["before_colon_wsp_field_indices"]:
        integer(value, maximum=MAX_HEADER_FIELDS - 1)
    body = document["body_observation"]
    if type(body) is not dict or body.keys() != {
        "source_start",
        "source_bytes",
        "physical_lines",
        "canonical_bytes",
        "canonical_body_base64",
        "declared_l_decimal",
        "coverage_state",
        "covered_bytes",
        "uncovered_bytes",
        "computed_body_sha256",
        "computed_body_hash_base64",
        "supplied_bh_base64_without_fws",
        "body_hash_matches_supplied_bh",
    }:
        raise DkimCanonicalizationError("Exact closed body observation required")
    for key in ("source_start", "source_bytes", "physical_lines"):
        integer(body[key])
    for key in ("canonical_bytes", "covered_bytes", "uncovered_bytes"):
        integer(body[key], nullable=True)
    for key in (
        "canonical_body_base64",
        "declared_l_decimal",
        "computed_body_sha256",
        "computed_body_hash_base64",
    ):
        text(body[key], nullable=True)
    text(body["coverage_state"])
    text(body["supplied_bh_base64_without_fws"])
    if (
        body["body_hash_matches_supplied_bh"] is not None
        and type(body["body_hash_matches_supplied_bh"]) is not bool
    ):
        raise DkimCanonicalizationError("Exact nullable native body comparison required")
    arrays = (
        (
            "selected_tag_observations",
            MAX_TAGS,
            {
                "name",
                "value_start_including_fws",
                "value_end_including_fws",
                "value_bytes_without_surrounding_fws",
            },
        ),
        (
            "header_selection_observations",
            MAX_HEADER_SELECTIONS,
            {
                "selection_index",
                "requested_name",
                "physical_header_index",
                "source_start",
                "source_end",
                "contribution_start",
                "contribution_bytes",
            },
        ),
    )
    for key, maximum, row_fields in arrays:
        rows = document[key]
        if type(rows) is not list or len(rows) > maximum:
            raise DkimCanonicalizationError("Bounded exact native observation array required")
        budget.charge(256 * len(rows))
        for row in rows:
            if type(row) is not dict or row.keys() != row_fields:
                raise DkimCanonicalizationError("Exact closed observation row required")
            for name, value in row.items():
                if name in ("name", "requested_name"):
                    text(value)
                else:
                    integer(value, nullable=key == "header_selection_observations")
    signature = document["selected_signature_contribution"]
    if type(signature) is not dict or signature.keys() != {
        "physical_header_index",
        "source_start",
        "source_end",
        "b_removed_start",
        "b_removed_end",
        "contribution_start",
        "contribution_bytes",
        "trailing_crlf_in_preimage",
    }:
        raise DkimCanonicalizationError("Exact closed selected-signature contribution required")
    for key, value in signature.items():
        if key == "trailing_crlf_in_preimage":
            if value is not None and type(value) is not bool:
                raise DkimCanonicalizationError(
                    "Exact nullable signature CRLF declaration required"
                )
        else:
            integer(value, nullable=key in ("contribution_start", "contribution_bytes"))


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
        raise DkimCanonicalizationError(
            "Canonical report does not fully replay its embedded source"
        )


def _replay(text: Any, budget: _Budget) -> dict:
    document, plan = _replay_plan(text, budget)
    _compare(text, document, _materialize(plan))
    return document


def _stored(report: Any) -> str:
    if type(report) is not DkimCanonicalizationAnalysis or not hasattr(report, "document_json"):
        raise DkimCanonicalizationError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise DkimCanonicalizationError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class DkimCanonicalizationAnalysis:
    """Owned unsigned bytes with complete embedded original replay on every export."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not DkimCanonicalizationAnalysis:
            raise DkimCanonicalizationError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> DkimCanonicalizationAnalysis:
        if cls is not DkimCanonicalizationAnalysis or type(document) is not dict:
            raise DkimCanonicalizationError("Exact native report object and family required")
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
    def from_json(cls, document_json: Any) -> DkimCanonicalizationAnalysis:
        if cls is not DkimCanonicalizationAnalysis:
            raise DkimCanonicalizationError("Exact native report family required")
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


def _owned(text: str) -> DkimCanonicalizationAnalysis:
    result = object.__new__(DkimCanonicalizationAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_dkim_canonicalization(model: Any) -> DkimCanonicalizationAnalysis:
    """Compute the closed supplied-byte arithmetic without signature or domain truth."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_dkim_canonicalization_bytes(
    *, model_bytes: Any
) -> DkimCanonicalizationAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise DkimCanonicalizationError("Bounded exact native JSON model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DkimCanonicalizationError("ASCII JSON metadata required") from exc
    return _owned(_materialize(_plan(_decode(text, budget), budget)))


def verify_supplied_dkim_canonicalization_analysis(
    report: Any, *, model: Any
) -> DkimCanonicalizationAnalysis:
    text = _stored(report)
    budget = _Budget()
    document, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, document, expected)
    if expected != separate:
        raise DkimCanonicalizationError("Report does not replay the separately supplied original")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh public-only synthetic byte fixture with no actual RSA signature."""
    message = (
        b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.test; s=offline;\r\n"
        b"\th=from:x-note:x-note:x-missing; "
        b"bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=AQ==;\r\n"
        b"From: sender@example.test\r\n"
        b"X-Note: older\r\n"
        b"X-Note: newer\r\n\r\n"
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-dkim-arithmetic",
        "message_base64": base64.b64encode(message).decode("ascii"),
        "dkim_header_index": 0,
    }


__all__ = [
    "DkimCanonicalizationAnalysis",
    "DkimCanonicalizationError",
    "analyze_supplied_dkim_canonicalization",
    "analyze_supplied_dkim_canonicalization_bytes",
    "verify_supplied_dkim_canonicalization_analysis",
    "component_fixture",
]

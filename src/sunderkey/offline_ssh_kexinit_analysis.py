"""Finite arithmetic over two supplied SSH_MSG_KEXINIT payload declarations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "ssh_supplied_kexinit_selection_arithmetic"
PROFILE_ID = "AOE-GC-D12-S06"
CAPABILITY_ID = "army.gc.d12.s06"
VECTOR_ID = "AV-GC-D12-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GC-D12-CMD"
COMMAND_GROUP_ID = "AOE-HQ-05"
VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:ba3ad230cf7bc5d013136c51fb64bd95c7966f7ee7123a2aa3eb80879ffc1b20"
SEMANTICS_PROFILE = "supplied-rfc4253-kexinit-finite-name-selection.v1"
MODEL_DOMAIN = "sunderkey.offline-ssh-kexinit-model.v1"
DOMAIN = "sunderkey.offline-ssh-kexinit-analysis.v1"
MAX_PAYLOAD_BYTES = 32_768
MAX_LIST_BYTES = 8_192
MAX_NAMES_PER_LIST = 128
MAX_NAME_BYTES = 64
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 1_048_576
MAX_MODEL_NODES = 4_096
MAX_REPORT_NODES = 65_536
MAX_DEPTH = 16
MAX_STRING_BYTES = 43_692
MAX_WORK = 134_217_728
MIN_INTEGER = -(2**63)
MAX_INTEGER = 2**63 - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}\Z")
_MODEL_FIELDS = {"schema_version", "source_id", "client_payload_base64", "server_payload_base64"}
_LIST_FIELDS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)
_KEX = frozenset(
    (
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group15-sha512",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group17-sha512",
        "diffie-hellman-group18-sha512",
    )
)
_SIGNING_HOSTKEYS = frozenset(
    (
        "ssh-dss",
        "ssh-rsa",
        "pgp-sign-rsa",
        "pgp-sign-dss",
        "rsa-sha2-256",
        "rsa-sha2-512",
    )
)
_CIPHERS = frozenset(
    (
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "none",
    )
)
_MACS = frozenset(
    (
        "hmac-sha1",
        "hmac-sha1-96",
        "hmac-md5",
        "hmac-md5-96",
        "none",
        "hmac-sha2-256",
        "hmac-sha2-512",
    )
)
_COMPRESSION = frozenset(("none", "zlib"))
_INDICATORS = frozenset(("ext-info-c", "ext-info-s"))
_SHA_PLACEHOLDER = "sha256:" + "0" * 64
_ID_PLACEHOLDER = "SKA-" + "0" * 32
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
        "packet_discard",
        "session",
    ),
    "none",
)
_CLAIMS = dict.fromkeys(
    (
        "source_authenticated",
        "endpoint_identity_proven",
        "actual_negotiation_proven",
        "guessed_packet_existence_proven",
        "packet_discard_performed",
        "key_exchange_completed",
        "crypto_computed",
        "key_validity_proven",
        "algorithm_strength_assessed",
        "recommended_configuration",
        "full_ssh_protocol_coverage",
        "live_use_approved",
        "qualification_claimed",
    ),
    False,
)
_LIMITATIONS = (
    "Only two explicitly supplied unframed KEXINIT payload declarations are analyzed.",
    "Name equality and finite capability tables do not establish actual negotiation.",
    "Algorithm labels do not prove crypto, valid keys, strength or a recommended configuration.",
    "Unknown common predecessors are not skipped to assert later supported winners.",
    "Unknown or AEAD cipher selection withholds the corresponding MAC semantics.",
    "Only ext-info-c/ext-info-s role indicators are recognized; other extensions are deferred.",
    "Cookie randomness, language tags and received reserved-extension semantics are unassessed.",
    "Optimistic rules are conditional; no following packet or actual discard is observed.",
    "Canonical parsed model provenance is not original raw JSON byte provenance or authenticity.",
    "Independent software ceilings apply; not all simultaneous maxima fit retained output/work.",
    "No endpoint, handshake, authentication, routing, qualification or deployment claim follows.",
)


class SshKexinitAnalysisError(ValueError):
    """A native contract, binary subset, software ceiling or exact replay was rejected."""


@dataclass(slots=True)
class _Budget:
    used: int = 0

    def charge(self, amount: int) -> None:
        if amount < 0 or amount > MAX_WORK - self.used:
            raise SshKexinitAnalysisError("Cumulative public-operation work ceiling exhausted")
        self.used += amount


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
            raise SshKexinitAnalysisError("Escaped canonical document byte ceiling exhausted")
        budget.charge(amount)
        size += amount

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        budget.charge(1)
        nodes += 1
        if nodes > node_limit or depth > MAX_DEPTH:
            raise SshKexinitAnalysisError("Native node/depth ceiling exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES:
                raise SshKexinitAnalysisError("Native string ceiling exhausted")
            add(2 + len(item))
            for char in item:
                budget.charge(1)
                code = ord(char)
                if code > 127:
                    raise SshKexinitAnalysisError("Closed metadata requires ASCII strings")
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
                raise SshKexinitAnalysisError("Exact native signed64 integer required")
            budget.charge(20)
            add(len(str(item)))
        elif kind in (dict, list):
            if id(item) in active:
                raise SshKexinitAnalysisError("Cyclic native documents are rejected")
            children = len(item) * (2 if kind is dict else 1)
            if children > node_limit - nodes:
                raise SshKexinitAnalysisError("Queued native node ceiling exhausted")
            add(2 + max(0, len(item) - 1) + (len(item) if kind is dict else 0))
            active.add(id(item))
            try:
                if kind is list:
                    for child in item:
                        visit(child, depth + 1)
                else:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise SshKexinitAnalysisError("Exact native text keys required")
                        visit(key, depth + 1)
                        budget.charge(len(key) * (len(item).bit_length() + 1))
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise SshKexinitAnalysisError("Exact native integer-only JSON families required")

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
        raise SshKexinitAnalysisError("Bounded raw integer grammar required")
    negative = text.startswith("-")
    digits = text[1:] if negative else text
    maximum = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > maximum:
        raise SshKexinitAnalysisError("Raw signed64 integer ceiling exhausted")
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
                raise SshKexinitAnalysisError("Incomplete raw JSON escape")
            if text[index] == "u":
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
                    raise SshKexinitAnalysisError("Malformed raw Unicode escape")
                if int(digits, 16) > 127:
                    raise SshKexinitAnalysisError("Closed metadata requires ASCII strings")
                index += 4
            elif text[index] not in '\\"/bfnrt':
                raise SshKexinitAnalysisError("Malformed raw JSON escape")
        elif ord(char) < 32:
            raise SshKexinitAnalysisError("Invalid raw JSON string character")
        count += 1
        if count > MAX_STRING_BYTES:
            raise SshKexinitAnalysisError("Pre-decoder string ceiling exhausted")
        index += 1
    raise SshKexinitAnalysisError("Unterminated raw JSON string")


def _decode(text: Any, budget: _Budget, *, report: bool = False) -> tuple[Any, int]:
    limit = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    node_limit = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    if type(text) is not str or not text or len(text) > limit or not text.isascii():
        raise SshKexinitAnalysisError("Bounded exact native ASCII JSON text required")
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
                raise SshKexinitAnalysisError("Malformed raw JSON containers")
            index += 1
            continue
        nodes += 1
        if nodes > node_limit or len(stack) + 1 > MAX_DEPTH:
            raise SshKexinitAnalysisError("Pre-decoder node/depth ceiling exhausted")
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
                    raise SshKexinitAnalysisError("Pre-decoder scalar lexical ceiling exhausted")
            token = text[start:index]
            if token not in ("true", "false", "null"):
                _integer(token)
    if stack:
        raise SshKexinitAnalysisError("Unterminated raw JSON containers")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise SshKexinitAnalysisError("Duplicate raw JSON key")
            result[key] = child
        return result

    def unsupported(_: str) -> None:
        raise SshKexinitAnalysisError("Raw floating/nonfinite numbers are unsupported")

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
        raise SshKexinitAnalysisError("Malformed bounded JSON document") from exc
    return _capture(value, budget, report=report)


def _wire(text: Any, budget: _Budget) -> bytes:
    if type(text) is not str or len(text) > 4 * ((MAX_PAYLOAD_BYTES + 2) // 3):
        raise SshKexinitAnalysisError("Bounded exact native canonical base64 required")
    budget.charge(3 * len(text))
    if len(text) % 4 or _BASE64.fullmatch(text) is None:
        raise SshKexinitAnalysisError("Canonical padded standard base64 required")
    length = len(text) // 4 * 3 - (len(text) - len(text.rstrip("=")))
    if not 0 <= length <= MAX_PAYLOAD_BYTES:
        raise SshKexinitAnalysisError("KEXINIT software payload byte ceiling exhausted")
    budget.charge(4 * len(text) + 4 * length)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SshKexinitAnalysisError("Malformed supplied base64") from exc
    if base64.b64encode(raw).decode("ascii") != text:
        raise SshKexinitAnalysisError("Noncanonical base64 spelling/padding bits")
    return raw


def _payload(raw: bytes, role: str, budget: _Budget) -> tuple[dict, dict[str, list[str]]]:
    budget.charge(3 * len(raw) + 256)
    if len(raw) < 17 or raw[0] != 20:
        raise SshKexinitAnalysisError("Exact SSH_MSG_KEXINIT type and sixteen-byte cookie required")
    position = 17
    rows = []
    lists = {}
    for field in _LIST_FIELDS:
        if len(raw) - position < 4:
            raise SshKexinitAnalysisError("Truncated KEXINIT name-list length")
        start = position
        size = int.from_bytes(raw[position : position + 4], "big")
        position += 4
        if size > MAX_LIST_BYTES:
            raise SshKexinitAnalysisError("Name-list software byte ceiling exhausted")
        if size > len(raw) - position:
            raise SshKexinitAnalysisError("Truncated KEXINIT name-list bytes")
        budget.charge(8 * size + 256)
        names = []
        name_start = position
        end = position + size
        for index in range(position, end + 1):
            if index < end and raw[index] != 44:
                if not 33 <= raw[index] <= 126:
                    raise SshKexinitAnalysisError(
                        "Closed name subset requires printable ASCII entries"
                    )
                if index - name_start >= MAX_NAME_BYTES:
                    raise SshKexinitAnalysisError("Name software byte ceiling exhausted")
                continue
            if size == 0:
                break
            if index == name_start:
                raise SshKexinitAnalysisError(
                    "Nonempty entries required inside a nonempty name-list"
                )
            if len(names) >= MAX_NAMES_PER_LIST:
                raise SshKexinitAnalysisError("Name-list entry ceiling exhausted")
            budget.charge(128 + 4 * (index - name_start))
            names.append(raw[name_start:index].decode("ascii"))
            name_start = index + 1
        position = end
        lists[field] = names
        budget.charge(256 + size + 64 * len(names))
        rows.append(
            {
                "field": field,
                "length_offset": start,
                "data_offset": start + 4,
                "end_offset": end,
                "declared_bytes": size,
                "names": names,
            }
        )
    if len(raw) - position != 5:
        raise SshKexinitAnalysisError("Exact boolean/reserved footer and payload closure required")
    truth = raw[position]
    reserved = int.from_bytes(raw[position + 1 : position + 5], "big")
    return {
        "role": role,
        "payload_bytes": len(raw),
        "cookie_base64": base64.b64encode(raw[1:17]).decode("ascii"),
        "cookie_randomness_assessed": False,
        "name_lists": rows,
        "first_kex_packet_follows_offset": position,
        "first_kex_packet_follows_octet": truth,
        "first_kex_packet_follows": truth != 0,
        "sender_boolean_encoding_is_canonical": truth in (0, 1),
        "reserved_uint32": reserved,
        "reserved_ignored_for_base_selection": True,
        "correct_role_ext_info_indicator_present": (
            ("ext-info-c" if role == "client" else "ext-info-s") in lists["kex_algorithms"]
        ),
        "incorrect_role_ext_info_indicator_present": (
            ("ext-info-s" if role == "client" else "ext-info-c") in lists["kex_algorithms"]
        ),
        "extension_info_messages_observed": False,
    }, lists


def _common(client: list[str], server: list[str], budget: _Budget) -> list[str]:
    budget.charge(128 + 8 * MAX_NAME_BYTES * (len(client) + len(server)))
    available = set(server)
    result = []
    for name in client:
        budget.charge(128 + 4 * len(name))
        if name in available:
            result.append(name)
    return result


def _first(values: list[str]) -> str | None:
    return values[0] if values else None


def _independent_candidate(
    common: list[str],
    table: frozenset[str],
    field: str,
    violations: list[str],
    unassessed: list[str],
) -> dict:
    first = _first(common)
    witness = next((name for name in common if name in table), None)
    if first is None:
        status = "no_common_declaration"
        violations.append(field + ":no_common_name")
    elif first in table:
        status = "supported_literal_candidate"
    else:
        status = "first_common_name_unassessed"
        unassessed.append(field + ":unknown_first_common_name")
    return {
        "status": status,
        "supported_candidate_name": first if first in table else None,
        "known_fallback_witness": witness,
        "literal_first_common_name": first,
    }


def _selection(client: dict, server: dict, budget: _Budget) -> tuple[dict, dict, list, list]:
    violations: list[str] = []
    unassessed: list[str] = []
    for role, lists in (("client", client), ("server", server)):
        for field in _LIST_FIELDS[:8]:
            if not lists[field]:
                violations.append(role + ":" + field + ":empty_required_declaration")
        wrong = "ext-info-s" if role == "client" else "ext-info-c"
        if wrong in lists["kex_algorithms"]:
            violations.append(role + ":incorrect_ext_info_role")
    commons = {field: _common(client[field], server[field], budget) for field in _LIST_FIELDS[:8]}
    literal = {field: _first(names) for field, names in commons.items()}
    budget.charge(64 * sum(len(values) for values in commons.values()) + 4096)
    kex_common = [name for name in commons["kex_algorithms"] if name not in _INDICATORS]
    host_common = commons["server_host_key_algorithms"]
    kex_first = _first(kex_common)
    signing = next((name for name in host_common if name in _SIGNING_HOSTKEYS), None)
    host_unknown = any(name not in _SIGNING_HOSTKEYS for name in host_common)
    known_kex = next((name for name in kex_common if name in _KEX), None)
    kex_witness = known_kex if signing is not None else None
    kex_candidate = None
    if kex_first is None:
        kex_status = "no_common_kex_candidate"
        violations.append("kex_algorithms:no_common_nonindicator_name")
    elif kex_first not in _KEX:
        kex_status = "first_common_kex_unassessed"
        unassessed.append("kex_algorithms:unknown_first_common_name")
    elif signing is not None:
        kex_status = "supported_signature_requiring_candidate"
        kex_candidate = kex_first
    elif host_unknown:
        kex_status = "hostkey_capability_unassessed"
        unassessed.append("kex_algorithms:unknown_common_hostkey_capability")
    else:
        kex_status = "no_common_signature_capable_hostkey"
        violations.append("kex_algorithms:no_common_signature_capable_hostkey")
    semantics = {
        "kex_algorithms": {
            "status": kex_status,
            "first_common_nonindicator_name": kex_first,
            "supported_candidate_name": kex_candidate,
            "known_eligible_fallback_witness": kex_witness,
            "signature_capable_hostkey_witness": signing,
            "required_capability": "signature" if kex_first in _KEX else None,
        }
    }
    host_first = _first(host_common)
    if kex_candidate is None:
        host_status, host_candidate = "kex_capability_not_resolved", None
    elif host_first not in _SIGNING_HOSTKEYS:
        host_status, host_candidate = "earlier_common_hostkey_capability_unassessed", None
        unassessed.append("server_host_key_algorithms:unknown_prior_capability")
    else:
        host_status, host_candidate = "supported_signature_capable_candidate", host_first
    semantics["server_host_key_algorithms"] = {
        "status": host_status,
        "literal_first_common_name": host_first,
        "supported_candidate_name": host_candidate,
        "signature_capable_witness": signing,
        "encryption_capability_inferred": False,
    }
    for direction in ("client_to_server", "server_to_client"):
        cipher_field = "encryption_algorithms_" + direction
        mac_field = "mac_algorithms_" + direction
        compression_field = "compression_algorithms_" + direction
        cipher = _independent_candidate(
            commons[cipher_field], _CIPHERS, cipher_field, violations, unassessed
        )
        semantics[cipher_field] = cipher
        if cipher["supported_candidate_name"] is None:
            semantics[mac_field] = {
                "status": "cipher_semantics_unassessed_or_unavailable",
                "literal_first_common_name": literal[mac_field],
                "supported_candidate_name": None,
                "known_fallback_witness": next(
                    (name for name in commons[mac_field] if name in _MACS), None
                ),
            }
            unassessed.append(mac_field + ":cipher_does_not_establish_independent_mac_rule")
        else:
            semantics[mac_field] = _independent_candidate(
                commons[mac_field], _MACS, mac_field, violations, unassessed
            )
        semantics[compression_field] = _independent_candidate(
            commons[compression_field], _COMPRESSION, compression_field, violations, unassessed
        )
    return literal, semantics, sorted(set(violations)), sorted(set(unassessed))


def _optimistic(
    client: dict, server: dict, observations: tuple[dict, dict], violations: list, unassessed: list
) -> list[dict]:
    client_kex = [name for name in client["kex_algorithms"] if name not in _INDICATORS]
    server_kex = [name for name in server["kex_algorithms"] if name not in _INDICATORS]
    kex_equal = (_first(client_kex) == _first(server_kex)) if client_kex and server_kex else None
    client_host, server_host = (
        client["server_host_key_algorithms"],
        server["server_host_key_algorithms"],
    )
    host_equal = (
        (_first(client_host) == _first(server_host)) if client_host and server_host else None
    )
    if kex_equal is False or host_equal is False:
        condition = "if_a_guessed_packet_follows_the_preference_guess_is_wrong"
    elif violations:
        condition = "if_a_guessed_packet_follows_known_declarations_do_not_agree"
    elif unassessed or kex_equal is None or host_equal is None:
        condition = "conditional_guess_assessment_unassessed"
    else:
        condition = "if_a_guessed_packet_follows_the_supported_base_guess_is_consistent"
    return [
        {
            "role": row["role"],
            "received_truth_octet": row["first_kex_packet_follows_octet"],
            "following_guess_declared": row["first_kex_packet_follows"],
            "preferred_nonindicator_kex_names_equal": kex_equal,
            "preferred_hostkey_names_equal": host_equal,
            "conditional_rule": condition
            if row["first_kex_packet_follows"]
            else "no_following_guess_declared",
            "following_packet_observed": False,
            "packet_discard_performed": False,
        }
        for row in observations
    ]


@dataclass(slots=True)
class _Plan:
    document: dict
    size: int
    client: bytes
    server: bytes


def _limits() -> dict:
    return {
        "maximum_payload_bytes": MAX_PAYLOAD_BYTES,
        "maximum_name_list_bytes": MAX_LIST_BYTES,
        "maximum_names_per_list": MAX_NAMES_PER_LIST,
        "maximum_name_bytes": MAX_NAME_BYTES,
        "maximum_model_bytes": MAX_MODEL_BYTES,
        "maximum_report_bytes": MAX_REPORT_BYTES,
        "maximum_model_nodes": MAX_MODEL_NODES,
        "maximum_report_nodes": MAX_REPORT_NODES,
        "scalar_inclusive_depth": MAX_DEPTH,
        "maximum_string_bytes": MAX_STRING_BYTES,
        "maximum_cumulative_work": MAX_WORK,
    }


def _plan(model: Any, budget: _Budget) -> _Plan:
    if type(model) is not dict:
        raise SshKexinitAnalysisError("Exact native source model object required")
    source, source_size = _capture(model, budget)
    if (
        set(source) != _MODEL_FIELDS
        or type(source["schema_version"]) is not int
        or source["schema_version"] != 1
    ):
        raise SshKexinitAnalysisError("Closed source schema version one required")
    if type(source["source_id"]) is not str or _SOURCE_ID.fullmatch(source["source_id"]) is None:
        raise SshKexinitAnalysisError("Bounded exact native source identity required")
    client_raw = _wire(source["client_payload_base64"], budget)
    server_raw = _wire(source["server_payload_base64"], budget)
    client, client_lists = _payload(client_raw, "client", budget)
    server, server_lists = _payload(server_raw, "server", budget)
    budget.charge(65_536 + 8 * (len(client_raw) + len(server_raw)))
    literal, candidates, violations, unassessed = _selection(client_lists, server_lists, budget)
    guesses = _optimistic(client_lists, server_lists, (client, server), violations, unassessed)
    outcome = (
        "known_declaration_contradictions"
        if violations
        else (
            "unassessed_selection_semantics"
            if unassessed
            else "consistent_supported_selection_declarations"
        )
    )
    document = {
        "schema_version": 1,
        "analysis_id": _ID_PLACEHOLDER,
        "analysis_sha256": _SHA_PLACEHOLDER,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "command_group_id": COMMAND_GROUP_ID,
        "validator_id": VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "evidence_package_ids": ["A7.4"],
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": source,
        "source_model_sha256": _SHA_PLACEHOLDER,
        "client_payload_sha256": _SHA_PLACEHOLDER,
        "server_payload_sha256": _SHA_PLACEHOLDER,
        "client": client,
        "server": server,
        "literal_first_common_names": literal,
        "semantic_candidates": candidates,
        "declaration_violations": violations,
        "unassessed_selection_semantics": unassessed,
        "conditional_optimistic_guesses": guesses,
        "outcome": outcome,
        "claims": dict(_CLAIMS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
        "software_limits": _limits(),
    }
    document, size = _capture(document, budget, report=True)
    # Reserve all remaining digest inputs, body/export serializations and retained
    # result text now. Public replay/original comparison funds its extra passes
    # before materialization. There are no charges after the first SHA.
    budget.charge(
        12 * size
        + 4 * source_size
        + 4 * (len(client_raw) + len(server_raw))
        + len(MODEL_DOMAIN)
        + len(DOMAIN)
        + 2
    )
    return _Plan(document, size, client_raw, server_raw)


def _digest(domain: str, document: dict) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(document).encode("ascii")
        ).hexdigest()
    )


def _materialize(plan: _Plan) -> str:
    document = plan.document
    document["client_payload_sha256"] = "sha256:" + hashlib.sha256(plan.client).hexdigest()
    document["server_payload_sha256"] = "sha256:" + hashlib.sha256(plan.server).hexdigest()
    document["source_model_sha256"] = _digest(MODEL_DOMAIN, document["source_model"])
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, body)
    document["analysis_sha256"] = digest
    document["analysis_id"] = "SKA-" + digest[7:39].upper()
    return _canonical(document)


def _replay_plan(text: Any, budget: _Budget) -> tuple[dict, _Plan]:
    document, size = _decode(text, budget, report=True)
    if type(document) is not dict or "source_model" not in document:
        raise SshKexinitAnalysisError("Report requires its complete embedded source model")
    expected = _plan(document["source_model"], budget)
    budget.charge(4 * size + expected.size)
    return document, expected


def _compare(text: str, actual: dict, expected: str) -> None:
    canonical = _canonical(actual)
    if text != canonical or canonical != expected:
        raise SshKexinitAnalysisError(
            "Canonical report does not replay its complete embedded source"
        )


def _replay(text: Any, budget: _Budget) -> dict:
    actual, plan = _replay_plan(text, budget)
    _compare(text, actual, _materialize(plan))
    return actual


def _stored(report: Any) -> str:
    if type(report) is not SshKexinitAnalysis or not hasattr(report, "document_json"):
        raise SshKexinitAnalysisError("Exact complete native report wrapper required")
    if type(report.document_json) is not str:
        raise SshKexinitAnalysisError("Exact native report text required")
    return report.document_json


@dataclass(frozen=True, slots=True)
class SshKexinitAnalysis:
    """Owned unsigned declarations, fully rederived at every public boundary."""

    document_json: str

    def __post_init__(self) -> None:
        if type(self) is not SshKexinitAnalysis:
            raise SshKexinitAnalysisError("Exact native report family required")
        _replay(self.document_json, _Budget())

    @classmethod
    def from_dict(cls, document: Any) -> SshKexinitAnalysis:
        if cls is not SshKexinitAnalysis:
            raise SshKexinitAnalysisError("Exact native report family required")
        budget = _Budget()
        owned, size = _capture(document, budget, report=True)
        budget.charge(size)
        text = _canonical(owned)
        _replay(text, budget)
        return _owned(text)

    @classmethod
    def from_json(cls, document_json: Any) -> SshKexinitAnalysis:
        if cls is not SshKexinitAnalysis:
            raise SshKexinitAnalysisError("Exact native report family required")
        _replay(document_json, _Budget())
        return _owned(document_json)

    def to_dict(self) -> dict:
        return _replay(_stored(self), _Budget())

    def to_json(self) -> str:
        text = _stored(self)
        _replay(text, _Budget())
        return text


def _owned(text: str) -> SshKexinitAnalysis:
    result = object.__new__(SshKexinitAnalysis)
    object.__setattr__(result, "document_json", text)
    return result


def analyze_supplied_ssh_kexinit_pair(model: Any) -> SshKexinitAnalysis:
    """Analyze supplied declaration bytes without acquiring or running SSH."""
    return _owned(_materialize(_plan(model, _Budget())))


def analyze_supplied_ssh_kexinit_pair_bytes(*, model_bytes: Any) -> SshKexinitAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_MODEL_BYTES:
        raise SshKexinitAnalysisError("Bounded exact native model bytes required")
    budget = _Budget()
    budget.charge(2 * len(model_bytes))
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SshKexinitAnalysisError("Closed JSON metadata requires ASCII encoding") from exc
    source, _ = _decode(text, budget)
    return _owned(_materialize(_plan(source, budget)))


def verify_supplied_ssh_kexinit_analysis(report: Any, *, model: Any) -> SshKexinitAnalysis:
    text = _stored(report)
    budget = _Budget()
    actual, embedded = _replay_plan(text, budget)
    original = _plan(model, budget)
    budget.charge(2 * (embedded.size + original.size))
    expected = _materialize(embedded)
    separate = _materialize(original)
    _compare(text, actual, expected)
    if expected != separate:
        raise SshKexinitAnalysisError("Report differs from the separately supplied original model")
    return _owned(separate)


def component_fixture() -> dict:
    """Fresh synthetic SHA2/AES-CTR name declarations, not security recommendations."""
    names = (
        "diffie-hellman-group14-sha256",
        "rsa-sha2-256",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    )
    fields = b"".join(len(name).to_bytes(4, "big") + name.encode("ascii") for name in names)
    client = b"\x14" + bytes(range(16)) + fields + b"\0" * 5
    server = b"\x14" + bytes(range(16, 32)) + fields + b"\0" * 5
    return {
        "schema_version": 1,
        "source_id": "synthetic-kexinit",
        "client_payload_base64": base64.b64encode(client).decode("ascii"),
        "server_payload_base64": base64.b64encode(server).decode("ascii"),
    }


__all__ = [
    "SshKexinitAnalysis",
    "SshKexinitAnalysisError",
    "analyze_supplied_ssh_kexinit_pair",
    "analyze_supplied_ssh_kexinit_pair_bytes",
    "verify_supplied_ssh_kexinit_analysis",
    "component_fixture",
]

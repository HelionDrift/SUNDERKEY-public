"""Finite supplied Redis ACL key checks, not authentication or effective access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "redis_supplied_acl_key_selectors"
DOMAIN = "sunderkey.offline-redis-acl-analysis.v1"
PROFILE_ID = "AOE-GB-D07-S05"
CAPABILITY_ID = "army.gb.d07.s05"
VECTOR_ID = "AV-GB-D07-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GB-D07-CMD"
GROUP_COMMANDER_ID = "AOE-HQ-04"
VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:300f14cfa8939b3b80c939327fbddacc04740723275f1504223f5996c58134a7"
SEMANTICS = "redis_7_2_5_acl_key_subset"
MAX_MODEL_BYTES = 256 * 1024
MAX_REPORT_BYTES = 1024 * 1024
MAX_MODEL_NODES = 16_384
MAX_REPORT_NODES = 32_768
MAX_MODEL_DEPTH = 16
MAX_REPORT_DEPTH = 20
MAX_TEXT_CHARACTERS = 256
MAX_KEY_CHARACTERS = 128
MAX_SELECTORS = 32
MAX_PATTERNS_PER_SELECTOR = 64
MAX_TOTAL_PATTERNS = 512
MAX_QUERIES = 128
MAX_KEYS_PER_QUERY = 32
MAX_TOTAL_KEYS = 1024
MAX_WORK_STEPS = 2_000_000
MAX_WITNESSES = 4096
MAX_MATCH_CACHE_ENTRIES = 8192
_MIN_INTEGER = -(1 << 63)
_MAX_INTEGER = (1 << 63) - 1
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_COMMANDS = ("get", "mget", "del", "copy", "getdel")
_PERMISSIONS = {"read": 1, "write": 2, "read_write": 3}
_UNSUPPORTED_FEATURES = (
    "command_categories",
    "subcommands",
    "first_argument_rules",
    "module_commands",
    "scripts",
    "transactions",
    "pubsub",
    "connection_authentication",
    "binary_key_semantics",
    "cluster_routing",
    "incremental_acl_rules",
)
_STATUSES = (
    "allowed_by_supplied_acl",
    "not_allowed_by_supplied_acl",
    "inconclusive",
)
_OWNERSHIP = {
    "component_id": COMPONENT_ID,
    "profile_id": PROFILE_ID,
    "capability_id": CAPABILITY_ID,
    "vector_id": VECTOR_ID,
    "work_package_id": WORK_PACKAGE_ID,
    "wave_id": WAVE_ID,
    "commander_id": COMMANDER_ID,
    "group_commander_id": GROUP_COMMANDER_ID,
    "validator_id": VALIDATOR_ID,
    "blueprint_sha256": BLUEPRINT_SHA256,
}
_FLAGS = {
    "offline_only": True,
    "source_authenticated": False,
    "principal_authenticated": False,
    "effective_access_proven": False,
    "live_use_approved": False,
    "qualification_claimed": False,
}
_EFFECTS = {
    name: "none"
    for name in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "provider_requests",
        "credentials",
        "process",
    )
}
_BOUNDS = {
    "maximum_model_bytes": MAX_MODEL_BYTES,
    "maximum_report_bytes": MAX_REPORT_BYTES,
    "maximum_model_nodes": MAX_MODEL_NODES,
    "maximum_report_nodes": MAX_REPORT_NODES,
    "maximum_model_depth": MAX_MODEL_DEPTH,
    "maximum_report_depth": MAX_REPORT_DEPTH,
    "maximum_text_characters": MAX_TEXT_CHARACTERS,
    "maximum_key_characters": MAX_KEY_CHARACTERS,
    "maximum_selectors": MAX_SELECTORS,
    "maximum_patterns_per_selector": MAX_PATTERNS_PER_SELECTOR,
    "maximum_total_patterns": MAX_TOTAL_PATTERNS,
    "maximum_queries": MAX_QUERIES,
    "maximum_keys_per_query": MAX_KEYS_PER_QUERY,
    "maximum_total_keys": MAX_TOTAL_KEYS,
    "maximum_work_steps": MAX_WORK_STEPS,
    "maximum_witnesses": MAX_WITNESSES,
    "maximum_match_cache_entries": MAX_MATCH_CACHE_ENTRIES,
}
_LIMITATIONS = [
    "The model is a supplied normalized Redis 7.2.5 command/key permission projection.",
    "Canonical parsed-model digests are not raw-byte provenance or authenticated ACL capture.",
    "Username, resource identity and selector completeness are unauthenticated declarations.",
    "No authentication, existing connection state, user on/off or effective access is inferred.",
    "Only GET, MGET, DEL, plain COPY and GETDEL positional key checks are computed.",
    "No values, optional command arguments, categories, modules, scripts or PubSub are evaluated.",
    "Keys and well-formed glob patterns are a nonempty printable ASCII subset.",
    "Incomplete selectors or any declared unsupported feature withhold final conclusions.",
    "No command dispatch, data access, currentness, policy safety or qualification is proved.",
]
_MODEL_FIELDS = {
    "schema_version",
    "semantics",
    "resource_ref",
    "username",
    "selectors_complete",
    "unsupported_features",
    "root_selector",
    "selectors",
    "queries",
}
_SELECTOR_FIELDS = {"selector_id", "commands", "key_patterns"}
_QUERY_FIELDS = {"query_id", "command", "keys"}
_RESULT_FIELDS = {
    "query_id",
    "query_sha256",
    "command",
    "required_keys",
    "status",
    "matching_selector_ids",
    "selector_checks",
    "reasons",
}
_CHECK_FIELDS = {
    "selector_id",
    "command_allowed",
    "key_permissions_satisfied",
    "matched",
    "key_witnesses",
    "unmatched_key_indices",
}
_KEY_FIELDS = {"key_index", "key", "permissions"}
_WITNESS_FIELDS = {*_KEY_FIELDS, "pattern", "pattern_permissions"}
_SUMMARY_FIELDS = {"query_count", "selector_count", "pattern_count", "work_steps", *_STATUSES}
_REPORT_FIELDS = {
    "schema_version",
    "analysis_id",
    "analysis_sha256",
    "source_model",
    "source_model_sha256",
    "results",
    "summary",
    "bounds",
    "effects",
    "limitations",
    *_OWNERSHIP,
    *_FLAGS,
}


class RedisAclAnalysisError(ValueError):
    """A supplied shape, finite cost or exact source replay is unsupported."""


class _Budget:
    def __init__(self, maximum_bytes: int, maximum_nodes: int, maximum_depth: int) -> None:
        self.maximum_bytes = maximum_bytes
        self.maximum_nodes = maximum_nodes
        self.maximum_depth = maximum_depth
        self.bytes = 0
        self.nodes = 0

    def charge_bytes(self, amount: int) -> None:
        self.bytes += amount
        if self.bytes > self.maximum_bytes:
            raise RedisAclAnalysisError("Canonical data exceeds its byte budget")

    def node(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > self.maximum_nodes or depth > self.maximum_depth:
            raise RedisAclAnalysisError("Native data exceeds its node or depth budget")


def _capture(value: Any, budget: _Budget, *, depth: int = 1) -> Any:
    active: set[int] = set()

    def visit(item: Any, at: int) -> Any:
        budget.node(at)
        kind = type(item)
        if kind is str:
            if len(item) > MAX_TEXT_CHARACTERS or any(not 32 <= ord(c) <= 126 for c in item):
                raise RedisAclAnalysisError("Text requires bounded printable native ASCII")
            budget.charge_bytes(2 + len(item) + item.count('"') + item.count("\\"))
            return item
        if kind is bool:
            budget.charge_bytes(4 if item else 5)
            return item
        if item is None:
            budget.charge_bytes(4)
            return None
        if kind is int:
            if item.bit_length() > 64 or not _MIN_INTEGER <= item <= _MAX_INTEGER:
                raise RedisAclAnalysisError("Native integer exceeds signed 64-bit bounds")
            budget.charge_bytes(len(str(item)))
            return item
        if kind not in (dict, list):
            raise RedisAclAnalysisError("Only exact native JSON families are supported")
        if id(item) in active:
            raise RedisAclAnalysisError("Cyclic data is unsupported")
        minimum_children = len(item) * (2 if kind is dict else 1)
        if budget.nodes + minimum_children > budget.maximum_nodes:
            raise RedisAclAnalysisError("Queued children exceed the native node budget")
        active.add(id(item))
        budget.charge_bytes(2)
        try:
            if kind is list:
                result = []
                for index, child in enumerate(item):
                    if index:
                        budget.charge_bytes(1)
                    result.append(visit(child, at + 1))
                return result
            result = {}
            for index, (key, child) in enumerate(item.items()):
                if type(key) is not str:
                    raise RedisAclAnalysisError("Object keys require exact native strings")
                if index:
                    budget.charge_bytes(1)
                owned_key = visit(key, at + 1)
                budget.charge_bytes(1)
                result[owned_key] = visit(child, at + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, depth)


def _model_budget() -> _Budget:
    return _Budget(MAX_MODEL_BYTES, MAX_MODEL_NODES, MAX_MODEL_DEPTH)


def _report_budget() -> _Budget:
    return _Budget(MAX_REPORT_BYTES, MAX_REPORT_NODES, MAX_REPORT_DEPTH)


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _sha(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _parse_integer(token: str) -> int:
    if len(token) > 20 or _INTEGER.fullmatch(token) is None:
        raise RedisAclAnalysisError("JSON integer lexical form is unsupported")
    negative = token.startswith("-")
    digits = token[1:] if negative else token
    limit = "9223372036854775808" if negative else "9223372036854775807"
    if len(digits) == 19 and digits > limit:
        raise RedisAclAnalysisError("JSON integer exceeds signed 64-bit bounds")
    return int(token)


def _json(text: Any, *, report: bool = False) -> Any:
    maximum_bytes = MAX_REPORT_BYTES if report else MAX_MODEL_BYTES
    maximum_nodes = MAX_REPORT_NODES if report else MAX_MODEL_NODES
    maximum_depth = MAX_REPORT_DEPTH if report else MAX_MODEL_DEPTH
    if type(text) is not str or not text or len(text) > maximum_bytes or not text.isascii():
        raise RedisAclAnalysisError("JSON requires bounded exact native ASCII text")
    depth = nodes = index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            nodes += 1
            if nodes > maximum_nodes or depth + 1 > maximum_depth:
                raise RedisAclAnalysisError("JSON scalar exceeds its node or depth budget")
            index += 1
            length = 0
            closed = False
            while index < len(text):
                char = text[index]
                if char == '"':
                    index += 1
                    closed = True
                    break
                if char == "\\":
                    index += 1
                    if index >= len(text):
                        raise RedisAclAnalysisError("JSON escape is incomplete")
                    char = text[index]
                    if char == "u":
                        digits = text[index + 1 : index + 5]
                        if len(digits) != 4 or any(
                            c not in "0123456789abcdefABCDEF" for c in digits
                        ):
                            raise RedisAclAnalysisError("JSON Unicode escape is invalid")
                        if not 32 <= int(digits, 16) <= 126:
                            raise RedisAclAnalysisError("JSON string is outside printable ASCII")
                        index += 5
                    elif char in '"\\/':
                        index += 1
                    else:
                        raise RedisAclAnalysisError("JSON escape is outside printable ASCII")
                else:
                    if not 32 <= ord(char) <= 126:
                        raise RedisAclAnalysisError("JSON string is outside printable ASCII")
                    index += 1
                length += 1
                if length > MAX_TEXT_CHARACTERS:
                    raise RedisAclAnalysisError("JSON string exceeds its scalar budget")
            if not closed:
                raise RedisAclAnalysisError("JSON string is incomplete")
        elif char in "[{":
            depth += 1
            nodes += 1
            index += 1
        elif char in "]}":
            depth -= 1
            index += 1
        elif char in " \t\r\n,:":
            index += 1
        else:
            nodes += 1
            if nodes > maximum_nodes or depth + 1 > maximum_depth:
                raise RedisAclAnalysisError("JSON scalar exceeds its node or depth budget")
            start = index
            while index < len(text) and text[index] not in ' \t\r\n,:]}{["':
                if index - start >= 20:
                    raise RedisAclAnalysisError("JSON token exceeds its lexical budget")
                index += 1
            if index == start:
                raise RedisAclAnalysisError("JSON token is malformed")
            token = text[start:index]
            if token not in {"true", "false", "null"}:
                _parse_integer(token)
        if depth < 0 or depth > maximum_depth or nodes > maximum_nodes:
            raise RedisAclAnalysisError("JSON exceeds its pre-decoder structure budgets")
    if depth:
        raise RedisAclAnalysisError("JSON containers are incomplete")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise RedisAclAnalysisError("JSON contains a duplicate field")
            result[key] = value
        return result

    def unsupported(_: str) -> None:
        raise RedisAclAnalysisError("Floating and nonfinite JSON numbers are unsupported")

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=_parse_integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, RedisAclAnalysisError):
            raise
        raise RedisAclAnalysisError("JSON syntax is malformed") from exc
    return _capture(parsed, _report_budget() if report else _model_budget())


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or len(value) != len(fields) or value.keys() != fields:
        raise RedisAclAnalysisError(f"{label} has missing or unsupported fields")
    return value


def _list(value: Any, maximum: int, label: str, *, nonempty: bool = False) -> list[Any]:
    if type(value) is not list or len(value) > maximum or (nonempty and not value):
        raise RedisAclAnalysisError(f"{label} requires a bounded native list")
    return value


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT_CHARACTERS) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise RedisAclAnalysisError(f"{label} requires bounded nonempty native text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise RedisAclAnalysisError(f"{label} requires native bool")
    return value


def _integer(value: Any, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise RedisAclAnalysisError(f"{label} requires a bounded native integer")
    return value


def _permission(value: Any) -> str:
    if type(value) is not str or value not in _PERMISSIONS:
        raise RedisAclAnalysisError("Key permissions require read, write or read_write")
    return value


class _Work:
    def __init__(self) -> None:
        self.steps = 0

    def charge(self, amount: int = 1) -> None:
        self.steps += amount
        if self.steps > MAX_WORK_STEPS:
            raise RedisAclAnalysisError("Compilation or matching exceeds its work budget")


def _compile(pattern: str, work: _Work) -> tuple[tuple[str, Any], ...]:
    """Tokenize a well-formed ASCII subset independently of the Redis code."""
    work.charge(len(pattern) + 1)
    tokens: list[tuple[str, Any]] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 == len(pattern):
                raise RedisAclAnalysisError("Glob has a dangling escape")
            tokens.append(("literal", pattern[index + 1]))
            index += 2
        elif char in "*?":
            tokens.append(("star" if char == "*" else "any", None))
            index += 1
        elif char == "[":
            index += 1
            negated = index < len(pattern) and pattern[index] == "^"
            if negated:
                index += 1
            ranges = []
            while index < len(pattern) and pattern[index] != "]":
                if pattern[index] == "\\":
                    if index + 1 == len(pattern):
                        raise RedisAclAnalysisError("Glob class has a dangling escape")
                    code = ord(pattern[index + 1])
                    ranges.append((code, code))
                    index += 2
                elif index + 1 < len(pattern) and pattern[index + 1] == "-":
                    if index + 2 >= len(pattern) or pattern[index + 2] in "]\\":
                        raise RedisAclAnalysisError("Glob class has an unsupported range end")
                    first, last = ord(pattern[index]), ord(pattern[index + 2])
                    ranges.append((min(first, last), max(first, last)))
                    index += 3
                else:
                    code = ord(pattern[index])
                    ranges.append((code, code))
                    index += 1
            if index == len(pattern) or not ranges:
                raise RedisAclAnalysisError("Glob class is empty or unclosed")
            tokens.append(("class", (negated, tuple(ranges))))
            index += 1
        else:
            tokens.append(("literal", char))
            index += 1
    return tuple(tokens)


def _glob(tokens: tuple[tuple[str, Any], ...], key: str, work: _Work) -> bool:
    """Bounded dynamic programming, with no recursive search or range expansion."""
    work.charge(len(key) + 1)
    previous = [True] + [False] * len(key)
    for kind, payload in tokens:
        work.charge(len(key) + 1)
        current = [False] * (len(key) + 1)
        if kind == "star":
            current[0] = previous[0]
        for index, char in enumerate(key, 1):
            if kind == "star":
                current[index] = previous[index] or current[index - 1]
            elif previous[index - 1]:
                if kind == "any":
                    current[index] = True
                elif kind == "literal":
                    current[index] = char == payload
                else:
                    negated, ranges = payload
                    matched = False
                    for first, last in ranges:
                        work.charge()
                        matched = matched or first <= ord(char) <= last
                    current[index] = not matched if negated else matched
        previous = current
    return previous[-1]


def _model(value: Any, work: _Work) -> tuple[dict[str, Any], dict[str, tuple]]:
    model = _exact(_capture(value, _model_budget()), _MODEL_FIELDS, "Redis ACL model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RedisAclAnalysisError("Model schema requires native integer one")
    if model["semantics"] != SEMANTICS:
        raise RedisAclAnalysisError("Model semantics are unsupported")
    _text(model["resource_ref"], "Resource reference")
    _text(model["username"], "Declared username", maximum=128)
    _boolean(model["selectors_complete"], "Selector completeness")
    unsupported = _list(
        model["unsupported_features"], len(_UNSUPPORTED_FEATURES), "Unsupported features"
    )
    if any(type(item) is not str or item not in _UNSUPPORTED_FEATURES for item in unsupported):
        raise RedisAclAnalysisError("Unsupported feature labels are outside the closed vocabulary")
    if len(set(unsupported)) != len(unsupported):
        raise RedisAclAnalysisError("Unsupported feature labels cannot repeat")
    selectors = [model["root_selector"], *_list(model["selectors"], MAX_SELECTORS - 1, "Selectors")]
    ids: set[str] = set()
    compiled: dict[str, tuple] = {}
    pattern_count = 0
    for selector in selectors:
        work.charge()
        _exact(selector, _SELECTOR_FIELDS, "Selector")
        selector_id = _text(selector["selector_id"], "Selector ID", maximum=128)
        if selector_id in ids:
            raise RedisAclAnalysisError("Selector IDs cannot repeat")
        ids.add(selector_id)
        commands = _list(selector["commands"], len(_COMMANDS), "Normalized commands")
        if any(type(command) is not str or command not in _COMMANDS for command in commands):
            raise RedisAclAnalysisError("Commands require the normalized lowercase subset")
        if len(set(commands)) != len(commands):
            raise RedisAclAnalysisError("Normalized commands cannot repeat")
        work.charge(len(commands))
        patterns = _list(
            selector["key_patterns"], MAX_PATTERNS_PER_SELECTOR, "Normalized key patterns"
        )
        seen: set[str] = set()
        for entry in patterns:
            work.charge()
            pattern_count += 1
            if pattern_count > MAX_TOTAL_PATTERNS:
                raise RedisAclAnalysisError("Aggregate patterns exceed their finite bound")
            _exact(entry, {"pattern", "permissions"}, "Key pattern")
            pattern = _text(entry["pattern"], "Key glob", maximum=MAX_KEY_CHARACTERS)
            _permission(entry["permissions"])
            if pattern in seen:
                raise RedisAclAnalysisError(
                    "Identical key patterns require an already merged snapshot"
                )
            seen.add(pattern)
            # Charge repeated source patterns too, even when compilation is reused.
            if pattern in compiled:
                work.charge(len(pattern) + 1)
            else:
                compiled[pattern] = _compile(pattern, work)
    query_ids: set[str] = set()
    key_count = 0
    for query in _list(model["queries"], MAX_QUERIES, "Queries", nonempty=True):
        work.charge()
        _exact(query, _QUERY_FIELDS, "Query")
        query_id = _text(query["query_id"], "Query ID", maximum=128)
        if query_id in query_ids:
            raise RedisAclAnalysisError("Query IDs cannot repeat")
        query_ids.add(query_id)
        command = _text(query["command"], "Query command", maximum=16).lower()
        if command not in _COMMANDS:
            raise RedisAclAnalysisError("Query command is outside the positional key subset")
        keys = _list(query["keys"], MAX_KEYS_PER_QUERY, "Positional keys", nonempty=True)
        if (command in {"get", "getdel"} and len(keys) != 1) or (
            command == "copy" and len(keys) != 2
        ):
            raise RedisAclAnalysisError("Query has an unsupported positional key count")
        key_count += len(keys)
        if key_count > MAX_TOTAL_KEYS:
            raise RedisAclAnalysisError("Aggregate positional keys exceed their finite bound")
        for key in keys:
            work.charge(len(_text(key, "Positional key", maximum=MAX_KEY_CHARACTERS)) + 1)
    return model, compiled


def _required(command: str, index: int) -> str:
    if command in {"get", "mget"} or (command == "copy" and index == 0):
        return "read"
    return "read_write" if command == "getdel" else "write"


def _append(items: list, value: Any, budget: _Budget, *, depth: int) -> None:
    if items:
        budget.charge_bytes(1)
    owned = _capture(value, budget, depth=depth)
    items.append(owned)


def _derive(value: Any) -> dict[str, Any]:
    work = _Work()
    model, compiled = _model(value, work)
    selector_count = 1 + len(model["selectors"])
    work.charge(selector_count * selector_count.bit_length() * MAX_KEY_CHARACTERS)
    selectors = sorted(
        [model["root_selector"], *model["selectors"]], key=lambda item: item["selector_id"]
    )
    patterns_by_selector = {}
    for selector in selectors:
        count = len(selector["key_patterns"])
        work.charge(count * count.bit_length() * MAX_KEY_CHARACTERS)
        patterns_by_selector[selector["selector_id"]] = sorted(
            selector["key_patterns"], key=lambda item: item["pattern"]
        )
    query_count = len(model["queries"])
    work.charge(query_count * query_count.bit_length() * MAX_KEY_CHARACTERS)
    ordered_queries = sorted(model["queries"], key=lambda item: item["query_id"])
    budget = _report_budget()
    zero_sha = "sha256:" + "0" * 64
    body = _capture(
        {
            "schema_version": 1,
            **_OWNERSHIP,
            **_FLAGS,
            "analysis_id": "RAC-" + "0" * 32,
            "analysis_sha256": zero_sha,
            "source_model": model,
            "source_model_sha256": zero_sha,
            "results": [],
            # Reserve maximum counter width before any retained result insertion.
            "summary": {field: MAX_WORK_STEPS for field in _SUMMARY_FIELDS},
            "bounds": _BOUNDS,
            "effects": _EFFECTS,
            "limitations": _LIMITATIONS,
        },
        budget,
    )
    cache: dict[tuple[str, str], bool] = {}
    witness_count = 0
    for query in ordered_queries:
        work.charge()
        command = query["command"].lower()
        result = {
            "query_id": query["query_id"],
            "query_sha256": zero_sha,
            "command": command,
            "required_keys": [],
            "status": "not_allowed_by_supplied_acl",
            "matching_selector_ids": [],
            "selector_checks": [],
            "reasons": [],
        }
        _append(body["results"], result, budget, depth=3)
        result = body["results"][-1]
        for index, key in enumerate(query["keys"]):
            work.charge()
            _append(
                result["required_keys"],
                {"key_index": index, "key": key, "permissions": _required(command, index)},
                budget,
                depth=5,
            )
        for selector in selectors:
            work.charge(len(selector["commands"]) + 1)
            command_allowed = command in selector["commands"]
            check = {
                "selector_id": selector["selector_id"],
                "command_allowed": command_allowed,
                "key_permissions_satisfied": False if command_allowed else None,
                "matched": False,
                "key_witnesses": [],
                "unmatched_key_indices": [],
            }
            _append(result["selector_checks"], check, budget, depth=5)
            check = result["selector_checks"][-1]
            if not command_allowed:
                continue
            patterns = patterns_by_selector[selector["selector_id"]]
            for index, key in enumerate(query["keys"]):
                work.charge()
                permission = _required(command, index)
                flags = _PERMISSIONS[permission]
                matched = None
                for entry in patterns:
                    work.charge()
                    if _PERMISSIONS[entry["permissions"]] & flags != flags:
                        continue
                    pair = (entry["pattern"], key)
                    work.charge(len(pair[0]) + len(pair[1]) + 1)
                    if pair not in cache:
                        if len(cache) >= MAX_MATCH_CACHE_ENTRIES:
                            raise RedisAclAnalysisError(
                                "Match cache exceeds its finite entry budget"
                            )
                        cache[pair] = _glob(compiled[pair[0]], key, work)
                    if cache[pair]:
                        matched = entry
                        break
                if matched is None:
                    _append(check["unmatched_key_indices"], index, budget, depth=7)
                else:
                    witness_count += 1
                    if witness_count > MAX_WITNESSES:
                        raise RedisAclAnalysisError(
                            "Aggregate key witnesses exceed their finite bound"
                        )
                    _append(
                        check["key_witnesses"],
                        {
                            "key_index": index,
                            "key": key,
                            "permissions": permission,
                            "pattern": matched["pattern"],
                            "pattern_permissions": matched["permissions"],
                        },
                        budget,
                        depth=7,
                    )
            check["key_permissions_satisfied"] = not check["unmatched_key_indices"]
            check["matched"] = check["key_permissions_satisfied"]
            if check["matched"]:
                _append(result["matching_selector_ids"], selector["selector_id"], budget, depth=5)
        reasons = []
        if not model["selectors_complete"]:
            reasons.append("incomplete_selector_inventory")
        reasons.extend("unsupported_feature:" + item for item in model["unsupported_features"])
        if reasons:
            result["status"] = "inconclusive"
            reasons.append("known_witnesses_do_not_resolve_source_uncertainty")
        elif result["matching_selector_ids"]:
            result["status"] = "allowed_by_supplied_acl"
            reasons.append("one_selector_matches_command_and_all_positional_keys")
        else:
            reasons.append("no_selector_matches_command_and_all_positional_keys")
        for reason in sorted(reasons):
            _append(result["reasons"], reason, budget, depth=5)
    # All compilation, matching and cumulative retained-output costs passed.
    body["summary"] = {
        "query_count": len(body["results"]),
        "selector_count": len(selectors),
        "pattern_count": sum(len(selector["key_patterns"]) for selector in selectors),
        "work_steps": work.steps,
        **{status: sum(row["status"] == status for row in body["results"]) for status in _STATUSES},
    }
    body["source_model_sha256"] = _sha("sunderkey.offline-redis-acl-model.v1", model)
    queries = {query["query_id"]: query for query in model["queries"]}
    for result in body["results"]:
        result["query_sha256"] = _sha(
            "sunderkey.offline-redis-acl-query.v1", queries[result["query_id"]]
        )
    unsigned = {
        key: item for key, item in body.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _sha(DOMAIN, unsigned)
    body["analysis_id"] = "RAC-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _digest(value: Any) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise RedisAclAnalysisError("Digest requires exact lowercase SHA256 spelling")


def _report(value: Any) -> dict[str, Any]:
    document = _exact(_capture(value, _report_budget()), _REPORT_FIELDS, "Redis ACL analysis")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise RedisAclAnalysisError("Analysis schema requires native integer one")
    for name, expected in _OWNERSHIP.items():
        if type(document[name]) is not str or document[name] != expected:
            raise RedisAclAnalysisError("Analysis ownership metadata does not match the fixed lane")
    for name, expected in _FLAGS.items():
        if type(document[name]) is not bool or document[name] is not expected:
            raise RedisAclAnalysisError("Analysis flags cannot claim authentication or authority")
    _exact(document["bounds"], set(_BOUNDS), "Analysis bounds")
    for name, expected in _BOUNDS.items():
        if type(document["bounds"][name]) is not int or document["bounds"][name] != expected:
            raise RedisAclAnalysisError("Analysis bounds require the fixed native integers")
    _exact(document["effects"], set(_EFFECTS), "Analysis effects")
    if any(type(item) is not str or item != "none" for item in document["effects"].values()):
        raise RedisAclAnalysisError("Analysis effects must remain none")
    if (
        type(document["analysis_id"]) is not str
        or re.fullmatch(r"RAC-[0-9A-F]{32}", document["analysis_id"]) is None
    ):
        raise RedisAclAnalysisError("Analysis ID has invalid spelling")
    _digest(document["analysis_sha256"])
    _digest(document["source_model_sha256"])
    summary = _exact(document["summary"], _SUMMARY_FIELDS, "Analysis summary")
    for counter in summary.values():
        _integer(counter, MAX_WORK_STEPS, "Summary counter")
    _list(document["limitations"], len(_LIMITATIONS), "Analysis limitations", nonempty=True)
    witnesses = 0
    for result in _list(document["results"], MAX_QUERIES, "Query results", nonempty=True):
        _exact(result, _RESULT_FIELDS, "Query result")
        _text(result["query_id"], "Result query ID", maximum=128)
        _digest(result["query_sha256"])
        if type(result["command"]) is not str or result["command"] not in _COMMANDS:
            raise RedisAclAnalysisError("Result command is unsupported")
        if type(result["status"]) is not str or result["status"] not in _STATUSES:
            raise RedisAclAnalysisError("Result status is unsupported")
        for required in _list(result["required_keys"], MAX_KEYS_PER_QUERY, "Required keys"):
            _exact(required, _KEY_FIELDS, "Required key")
            _integer(required["key_index"], MAX_KEYS_PER_QUERY - 1, "Key index")
            _text(required["key"], "Result key", maximum=MAX_KEY_CHARACTERS)
            _permission(required["permissions"])
        for selector_id in _list(
            result["matching_selector_ids"], MAX_SELECTORS, "Matching selectors"
        ):
            _text(selector_id, "Matching selector ID", maximum=128)
        for reason in _list(result["reasons"], len(_UNSUPPORTED_FEATURES) + 2, "Result reasons"):
            _text(reason, "Result reason")
        for check in _list(result["selector_checks"], MAX_SELECTORS, "Selector checks"):
            _exact(check, _CHECK_FIELDS, "Selector check")
            _text(check["selector_id"], "Checked selector ID", maximum=128)
            _boolean(check["command_allowed"], "Command check")
            _boolean(check["matched"], "Selector match")
            if check["key_permissions_satisfied"] is not None:
                _boolean(check["key_permissions_satisfied"], "Key check")
            for index in _list(
                check["unmatched_key_indices"], MAX_KEYS_PER_QUERY, "Unmatched keys"
            ):
                _integer(index, MAX_KEYS_PER_QUERY - 1, "Unmatched key index")
            for witness in _list(check["key_witnesses"], MAX_KEYS_PER_QUERY, "Key witnesses"):
                witnesses += 1
                if witnesses > MAX_WITNESSES:
                    raise RedisAclAnalysisError("Report witnesses exceed their aggregate bound")
                _exact(witness, _WITNESS_FIELDS, "Key witness")
                _integer(witness["key_index"], MAX_KEYS_PER_QUERY - 1, "Witness key index")
                _text(witness["key"], "Witness key", maximum=MAX_KEY_CHARACTERS)
                _text(witness["pattern"], "Witness pattern", maximum=MAX_KEY_CHARACTERS)
                _permission(witness["permissions"])
                _permission(witness["pattern_permissions"])
    expected = _derive(document["source_model"])
    if _canonical(document) != _canonical(expected):
        raise RedisAclAnalysisError("Analysis does not exactly replay its embedded supplied model")
    return expected


@dataclass(frozen=True, slots=True)
class RedisAclAnalysis:
    document_json: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "document_json", _canonical(self._read()))

    def _read(self) -> dict[str, Any]:
        try:
            text = self.document_json
        except AttributeError as exc:
            raise RedisAclAnalysisError("Analysis wrapper is incomplete") from exc
        return _report(_json(text, report=True))

    def to_dict(self) -> dict[str, Any]:
        return self._read()

    def to_json(self) -> str:
        return _canonical(self._read())

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> RedisAclAnalysis:
        return cls(_canonical(_report(document)))

    @classmethod
    def from_json(cls, document: str) -> RedisAclAnalysis:
        return cls(document)


def analyze_supplied_redis_acl(model: dict[str, Any]) -> RedisAclAnalysis:
    return RedisAclAnalysis(_canonical(_derive(model)))


def analyze_supplied_redis_acl_bytes(*, model_json: bytes) -> RedisAclAnalysis:
    if type(model_json) is not bytes or not model_json or len(model_json) > MAX_MODEL_BYTES:
        raise RedisAclAnalysisError("Model bytes require bounded exact native bytes")
    if not model_json.isascii():
        raise RedisAclAnalysisError("Model bytes require the ASCII JSON subset")
    return analyze_supplied_redis_acl(_json(model_json.decode("ascii")))


def verify_supplied_redis_acl_analysis(
    report: RedisAclAnalysis | dict[str, Any], *, model: dict[str, Any]
) -> RedisAclAnalysis:
    if type(report) is RedisAclAnalysis:
        observed = report.to_dict()
    elif type(report) is dict:
        observed = _report(report)
    else:
        raise RedisAclAnalysisError("Report requires an exact supported native family")
    expected = _derive(model)
    if _canonical(observed) != _canonical(expected):
        raise RedisAclAnalysisError(
            "Analysis does not match the separately supplied original model"
        )
    return RedisAclAnalysis(_canonical(expected))


__all__ = [
    "RedisAclAnalysis",
    "RedisAclAnalysisError",
    "analyze_supplied_redis_acl",
    "analyze_supplied_redis_acl_bytes",
    "verify_supplied_redis_acl_analysis",
]

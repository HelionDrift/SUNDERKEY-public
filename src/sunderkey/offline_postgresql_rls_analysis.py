"""Pure PostgreSQL 18 SELECT-grant and row-filter arithmetic on supplied models."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "postgresql_supplied_select_rls"
PROFILE_ID = "AOE-GB-D07-S14"
CAPABILITY_ID = "army.gb.d07.s14"
VECTOR_ID = "AV-GB-D07-S14-01"
PACKAGE_ID = "IWP2-AOE-GB-D07-S14"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GB-D07-CMD"
GROUP_COMMANDER_ID = "AOE-HQ-04"
VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:145d4df6c5bf3b2b47c52ea75a5aabf866c49c41fb405954914fb3a3feeef431"
SEMANTICS_PROFILE = "postgresql-18-select-rls-subset-v1"
DOMAIN = "sunderkey.postgresql-supplied-select-rls.v1"
MODEL_DOMAIN = "sunderkey.postgresql-supplied-select-rls-model.v1"
MAX_DOCUMENT_BYTES = 1_048_576
MAX_NATIVE_DEPTH = 32
MAX_NATIVE_NODES = 32_768
MAX_STRING_BYTES = 512
MAX_ROLES = 64
MAX_MEMBERSHIPS = 256
MAX_COLUMNS = 32
MAX_POLICIES = 128
MAX_CONTEXTS = 32
MAX_ROWS = 256
MAX_QUERIES = 512
MAX_AST_NODES = 4_096
MAX_AST_DEPTH = 12
MAX_ARGUMENTS = 32
MAX_WORK = 1_000_000
MIN_INT8 = -(2**63)
MAX_INT8 = 2**63 - 1
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
_REF = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]{0,18})\Z")
_TYPES = frozenset({"boolean", "int8", "text_c"})
_COMMANDS = frozenset({"ALL", "SELECT", "INSERT", "UPDATE", "DELETE"})
_MODES = frozenset({"PERMISSIVE", "RESTRICTIVE"})
_UNSUPPORTED = frozenset({"function", "subquery", "cast", "collation", "other"})
_BOUNDS = {
    "max_document_bytes": MAX_DOCUMENT_BYTES,
    "max_native_depth": MAX_NATIVE_DEPTH,
    "max_native_nodes": MAX_NATIVE_NODES,
    "max_string_bytes": MAX_STRING_BYTES,
    "max_roles": MAX_ROLES,
    "max_memberships": MAX_MEMBERSHIPS,
    "max_columns": MAX_COLUMNS,
    "max_policies": MAX_POLICIES,
    "max_contexts": MAX_CONTEXTS,
    "max_rows": MAX_ROWS,
    "max_queries": MAX_QUERIES,
    "max_ast_nodes": MAX_AST_NODES,
    "max_ast_depth": MAX_AST_DEPTH,
    "max_arguments": MAX_ARGUMENTS,
    "max_work": MAX_WORK,
}
_EFFECTS = {
    name: "none"
    for name in (
        "authority",
        "credential_resolution",
        "deployment",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider_requests",
        "qualification",
        "target_interaction",
    )
}
_FLAGS = (
    "snapshot_authenticated",
    "live_database_observed",
    "select_privilege_proven",
    "role_membership_proven",
    "full_postgresql_validation_claimed",
    "positive_use_approved",
    "qualification_claimed",
)


class PostgreSQLRlsAnalysisError(ValueError):
    """Malformed, unsupported or over-budget supplied SELECT/RLS model or report."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )


def _text(value: Any, *, empty: bool = False) -> str:
    if type(value) is not str or len(value) > MAX_STRING_BYTES or (not value and not empty):
        raise PostgreSQLRlsAnalysisError("Bounded native ASCII text is required")
    if any(not 32 <= ord(character) <= 126 for character in value):
        raise PostgreSQLRlsAnalysisError("Only printable ASCII text is supported")
    return value


def _int8(value: Any) -> int:
    if type(value) is not int or value.bit_length() > 64 or not MIN_INT8 <= value <= MAX_INT8:
        raise PostgreSQLRlsAnalysisError("An exact native signed int8 value is required")
    return value


def _measure(value: Any, *, depth: int = 1) -> tuple[int, int]:
    """Charge repeated occurrences and queued children before copying, dumps or hashes."""
    pending = [(value, depth)]
    nodes = size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise PostgreSQLRlsAnalysisError("Native node/depth budget exceeded")
        kind = type(item)
        if kind is dict:
            if nodes + len(pending) + 2 * len(item) > MAX_NATIVE_NODES:
                raise PostgreSQLRlsAnalysisError("Native queued-node budget exceeded")
            size += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                if type(key) is not str:
                    raise PostgreSQLRlsAnalysisError("Exact native text keys are required")
                pending.append((child, depth + 1))
                pending.append((key, depth + 1))
        elif kind is list:
            if nodes + len(pending) + len(item) > MAX_NATIVE_NODES:
                raise PostgreSQLRlsAnalysisError("Native queued-node budget exceeded")
            size += 2 + max(0, len(item) - 1)
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            _text(item, empty=True)
            size += 2 + len(item) + item.count('"') + item.count("\\")
        elif kind is int:
            size += len(str(_int8(item)))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        else:
            raise PostgreSQLRlsAnalysisError("Only exact native JSON subset values are supported")
        if size > MAX_DOCUMENT_BYTES:
            raise PostgreSQLRlsAnalysisError("Native aggregate escaped-byte budget exceeded")
    return nodes, size


def _native(value: Any) -> str:
    _measure(value)
    return _canonical(value)


def _integer_token(token: str) -> int:
    if _NUMBER.fullmatch(token) is None:
        raise PostgreSQLRlsAnalysisError("JSON integer grammar or lexical limit is invalid")
    digits = token[1:] if token.startswith("-") else token
    ceiling = "9223372036854775808" if token.startswith("-") else "9223372036854775807"
    if len(digits) == 19 and digits > ceiling:
        raise PostgreSQLRlsAnalysisError("JSON integer exceeds signed int8")
    return int(token)


def _raw_string(text: str, index: int) -> tuple[int, int]:
    index += 1
    length, cost = 0, 2
    while index < len(text):
        character = text[index]
        if character == '"':
            return index + 1, cost
        if character == "\\":
            index += 1
            if index >= len(text):
                break
            escape = text[index]
            if escape in {'"', "\\", "/"}:
                code = ord(escape)
            elif escape == "u":
                lexical = text[index + 1 : index + 5]
                if len(lexical) != 4 or any(c not in "0123456789abcdefABCDEF" for c in lexical):
                    raise PostgreSQLRlsAnalysisError("Invalid JSON Unicode escape")
                code = int(lexical, 16)
                index += 4
            else:
                raise PostgreSQLRlsAnalysisError("Only printable ASCII JSON strings are supported")
        else:
            code = ord(character)
        if not 32 <= code <= 126:
            raise PostgreSQLRlsAnalysisError("Only printable ASCII JSON strings are supported")
        length += 1
        cost += 2 if code in (34, 92) else 1
        if length > MAX_STRING_BYTES:
            raise PostgreSQLRlsAnalysisError("Raw decoded-string budget exceeded")
        index += 1
    raise PostgreSQLRlsAnalysisError("JSON string is incomplete")


def _raw_preflight(content: Any) -> str:
    if type(content) is not bytes or not content or len(content) > MAX_DOCUMENT_BYTES:
        raise PostgreSQLRlsAnalysisError("Bounded nonempty exact native JSON bytes are required")
    if not content.isascii():
        raise PostgreSQLRlsAnalysisError("JSON bytes must use ASCII UTF-8")
    text = content.decode("ascii")
    index = depth = nodes = size = 0
    while index < len(text):
        character = text[index]
        if character in " \t\r\n":
            index += 1
            continue
        if character in "[{":
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise PostgreSQLRlsAnalysisError("Raw JSON depth budget exceeded")
            depth += 1
            nodes += 1
            size += 1
            index += 1
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise PostgreSQLRlsAnalysisError("Raw JSON nesting is malformed")
            size += 1
            index += 1
        elif character in ",:":
            size += 1
            index += 1
        elif character == '"':
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise PostgreSQLRlsAnalysisError("Raw scalar depth budget exceeded")
            index, cost = _raw_string(text, index)
            size += cost
            nodes += 1
        else:
            if depth + 1 > MAX_NATIVE_DEPTH:
                raise PostgreSQLRlsAnalysisError("Raw scalar depth budget exceeded")
            end = index
            while end < len(text) and text[end] not in ' \t\r\n,:[{}]"':
                end += 1
                if end - index > 20:
                    raise PostgreSQLRlsAnalysisError("Raw scalar lexical budget exceeded")
            token = text[index:end]
            if token not in {"true", "false", "null"}:
                _integer_token(token)
            size += len(token)
            nodes += 1
            index = end
        if nodes > MAX_NATIVE_NODES or size > MAX_DOCUMENT_BYTES:
            raise PostgreSQLRlsAnalysisError("Raw JSON node/escaped-byte budget exceeded")
    if depth:
        raise PostgreSQLRlsAnalysisError("Raw JSON nesting is incomplete")
    return text


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PostgreSQLRlsAnalysisError("Duplicate JSON keys are not supported")
        result[key] = value
    return result


def _reject_number(_token: str) -> Any:
    raise PostgreSQLRlsAnalysisError("JSON floats and nonfinite values are not supported")


def _decode(content: bytes) -> dict[str, Any]:
    text = _raw_preflight(content)
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_integer_token,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (ValueError, RecursionError) as exc:
        raise PostgreSQLRlsAnalysisError("Malformed or unsupported JSON document") from exc
    if type(raw) is not dict:
        raise PostgreSQLRlsAnalysisError("A native document object is required")
    _native(raw)
    return raw


def _capture(value: Any) -> dict[str, Any]:
    text = _native(value)
    if type(value) is not dict:
        raise PostgreSQLRlsAnalysisError("A native model/report object is required")
    return json.loads(text)


def _object(value: Any, fields: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != fields:
        raise PostgreSQLRlsAnalysisError(f"{label} fields are invalid")


def _array(value: Any, ceiling: int, label: str, minimum: int = 0) -> list[Any]:
    if type(value) is not list or not minimum <= len(value) <= ceiling:
        raise PostgreSQLRlsAnalysisError(f"{label} array bounds are invalid")
    return value


def _boolean(value: Any) -> bool:
    if type(value) is not bool:
        raise PostgreSQLRlsAnalysisError("An exact native boolean is required")
    return value


def _name(value: Any) -> str:
    if _NAME.fullmatch(_text(value)) is None:
        raise PostgreSQLRlsAnalysisError("A supported exact ASCII identifier is required")
    return value


def _reference(value: Any) -> str:
    if _REF.fullmatch(_text(value)) is None:
        raise PostgreSQLRlsAnalysisError("A bounded exact inert reference is required")
    return value


def _vocabulary(value: Any, choices: frozenset[str]) -> str:
    if type(value) is not str or value not in choices:
        raise PostgreSQLRlsAnalysisError("Unsupported declared vocabulary")
    return value


def _scalar(value: Any, kind: str) -> Any:
    if value is None:
        return None
    if kind == "boolean":
        return _boolean(value)
    if kind == "int8":
        return _int8(value)
    return _text(value, empty=True)


class _Work:
    def __init__(self) -> None:
        self.units = 0
        self.ast_nodes = 0

    def charge(self, amount: int = 1) -> None:
        if self.units + amount > MAX_WORK:
            raise PostgreSQLRlsAnalysisError("Charged graph/predicate work budget exceeded")
        self.units += amount

    def ast(self, depth: int) -> None:
        self.charge()
        self.ast_nodes += 1
        if self.ast_nodes > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise PostgreSQLRlsAnalysisError("Predicate AST node/depth budget exceeded")


def _selectors(value: Any, roles: dict[str, Any], *, empty: bool) -> list[dict[str, Any]]:
    _array(value, MAX_ROLES, "Role selectors", 0 if empty else 1)
    seen = set()
    for item in value:
        if type(item) is not dict or type(item.get("kind")) is not str:
            raise PostgreSQLRlsAnalysisError("A typed role selector is required")
        if item["kind"] == "public":
            _object(item, {"kind"}, "PUBLIC selector")
            identity = ("public",)
        elif item["kind"] == "role":
            _object(item, {"kind", "name"}, "Role selector")
            name = _name(item["name"])
            if name not in roles:
                raise PostgreSQLRlsAnalysisError("Role selector does not resolve")
            identity = ("role", name)
        else:
            raise PostgreSQLRlsAnalysisError("Role selector kind is unsupported")
        if identity in seen:
            raise PostgreSQLRlsAnalysisError("Duplicate role selector")
        seen.add(identity)
    return value


def _compile_operand(
    raw: Any, columns: dict[str, str], work: _Work, depth: int
) -> tuple[tuple[Any, ...], str]:
    work.ast(depth)
    if type(raw) is not dict or type(raw.get("kind")) is not str:
        raise PostgreSQLRlsAnalysisError("A typed predicate operand is required")
    if raw["kind"] == "column":
        _object(raw, {"kind", "name"}, "Column operand")
        name = _name(raw["name"])
        if name not in columns:
            raise PostgreSQLRlsAnalysisError("Predicate column does not resolve")
        return ("column", name), columns[name]
    if raw["kind"] == "current_user":
        _object(raw, {"kind"}, "CURRENT_USER operand")
        return ("current_user",), "text_c"
    if raw["kind"] == "literal":
        _object(raw, {"kind", "type", "value"}, "Literal operand")
        kind = _vocabulary(raw["type"], _TYPES)
        return ("literal", _scalar(raw["value"], kind)), kind
    raise PostgreSQLRlsAnalysisError("Predicate operand kind is unsupported")


def _compile_predicate(
    raw: Any, columns: dict[str, str], work: _Work, issues: set[str], depth: int = 1
) -> tuple[Any, ...]:
    work.ast(depth)
    if type(raw) is not dict or type(raw.get("op")) is not str:
        raise PostgreSQLRlsAnalysisError("A closed predicate AST is required")
    op = raw["op"]
    if op == "bool":
        _object(raw, {"op", "value"}, "Boolean predicate")
        if raw["value"] is not None:
            _boolean(raw["value"])
        return op, raw["value"]
    if op == "unsupported":
        _object(raw, {"op", "feature"}, "Unassessed predicate")
        feature = _vocabulary(raw["feature"], _UNSUPPORTED)
        issues.add("unsupported_predicate_" + feature)
        return op, feature
    if op in {"and", "or"}:
        _object(raw, {"op", "args"}, "Logical predicate")
        _array(raw["args"], MAX_ARGUMENTS, "Logical arguments", 2)
        return op, tuple(
            _compile_predicate(child, columns, work, issues, depth + 1) for child in raw["args"]
        )
    if op == "not":
        _object(raw, {"op", "arg"}, "NOT predicate")
        return op, _compile_predicate(raw["arg"], columns, work, issues, depth + 1)
    if op in {"is_null", "is_not_null"}:
        _object(raw, {"op", "arg"}, "NULL predicate")
        operand, _kind = _compile_operand(raw["arg"], columns, work, depth + 1)
        return op, operand
    if op in {"eq", "ne", "lt", "le", "gt", "ge"}:
        _object(raw, {"op", "left", "right"}, "Comparison predicate")
        left, left_kind = _compile_operand(raw["left"], columns, work, depth + 1)
        right, right_kind = _compile_operand(raw["right"], columns, work, depth + 1)
        if left_kind != right_kind or (op not in {"eq", "ne"} and left_kind != "int8"):
            raise PostgreSQLRlsAnalysisError(
                "Implicit casts/custom comparison semantics unsupported"
            )
        return op, left, right
    raise PostgreSQLRlsAnalysisError("Predicate operator is outside the closed AST")


def _prepare(model: dict[str, Any], work: _Work) -> tuple[Any, ...]:
    _object(
        model,
        {
            "schema_version",
            "semantics_profile",
            "roles",
            "memberships",
            "role_membership_complete",
            "table",
            "contexts",
            "rows",
            "queries",
        },
        "Model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PostgreSQLRlsAnalysisError("Model schema_version must be native integer 1")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise PostgreSQLRlsAnalysisError("Unsupported semantics profile")
    issues: set[str] = set()
    if not _boolean(model["role_membership_complete"]):
        issues.add("role_membership_incomplete")
    roles = {}
    for role in _array(model["roles"], MAX_ROLES, "Roles", 1):
        work.charge()
        _object(role, {"name", "superuser", "bypass_rls"}, "Role")
        name = _name(role["name"])
        if name in roles:
            raise PostgreSQLRlsAnalysisError("Duplicate role definition")
        _boolean(role["superuser"])
        _boolean(role["bypass_rls"])
        roles[name] = role
    edges = {name: [] for name in roles}
    inherited = {name: [] for name in roles}
    degree = {name: 0 for name in roles}
    seen_edges = set()
    for edge in _array(model["memberships"], MAX_MEMBERSHIPS, "Memberships"):
        work.charge()
        _object(edge, {"member_role", "granted_role", "inherit"}, "Membership")
        member, granted = _name(edge["member_role"]), _name(edge["granted_role"])
        if member not in roles or granted not in roles or member == granted:
            raise PostgreSQLRlsAnalysisError("Membership references/self-membership are invalid")
        if (member, granted) in seen_edges:
            raise PostgreSQLRlsAnalysisError("Duplicate membership edge")
        seen_edges.add((member, granted))
        edges[member].append(granted)
        degree[granted] += 1
        if _boolean(edge["inherit"]):
            inherited[member].append(granted)
    pending = deque(sorted(name for name, count in degree.items() if count == 0))
    visited = 0
    while pending:
        name = pending.popleft()
        work.charge()
        visited += 1
        for target in edges[name]:
            work.charge()
            degree[target] -= 1
            if degree[target] == 0:
                pending.append(target)
    if visited != len(roles):
        raise PostgreSQLRlsAnalysisError("Cyclic membership is not a supported native role graph")
    table = model["table"]
    _object(
        table,
        {
            "table_ref",
            "relation_kind",
            "owner_role",
            "rls_enabled",
            "force_rls",
            "policy_inventory_complete",
            "select_grantees",
            "select_grants_complete",
            "columns",
            "policies",
        },
        "Table",
    )
    _reference(table["table_ref"])
    if table["relation_kind"] != "ordinary_table":
        raise PostgreSQLRlsAnalysisError("Only an ordinary-table SELECT model is supported")
    if _name(table["owner_role"]) not in roles:
        raise PostgreSQLRlsAnalysisError("Table owner role does not resolve")
    for key in ("rls_enabled", "force_rls", "policy_inventory_complete", "select_grants_complete"):
        _boolean(table[key])
    if not table["policy_inventory_complete"]:
        issues.add("policy_inventory_incomplete")
    if not table["select_grants_complete"]:
        issues.add("select_grants_incomplete")
    _selectors(table["select_grantees"], roles, empty=True)
    columns = table["columns"]
    if type(columns) is not dict or not 1 <= len(columns) <= MAX_COLUMNS:
        raise PostgreSQLRlsAnalysisError("Column definitions exceed the closed model")
    for name, kind in columns.items():
        _name(name)
        _vocabulary(kind, _TYPES)
    compiled = []
    policy_ids = set()
    for policy in _array(table["policies"], MAX_POLICIES, "Policies"):
        work.charge()
        _object(policy, {"policy_id", "command", "mode", "to_roles", "using"}, "Policy")
        identifier = _reference(policy["policy_id"])
        if identifier in policy_ids:
            raise PostgreSQLRlsAnalysisError("Duplicate table policy identifier")
        policy_ids.add(identifier)
        _vocabulary(policy["command"], _COMMANDS)
        _vocabulary(policy["mode"], _MODES)
        _selectors(policy["to_roles"], roles, empty=False)
        if policy["command"] == "INSERT" and policy["using"] is not None:
            raise PostgreSQLRlsAnalysisError("An INSERT projection cannot declare USING")
        ast = (
            ("bool", True)
            if policy["using"] is None
            else _compile_predicate(policy["using"], columns, work, issues)
        )
        compiled.append((policy, ast))
    contexts = {}
    for context in _array(model["contexts"], MAX_CONTEXTS, "Contexts"):
        work.charge()
        _object(context, {"context_id", "current_role", "row_security_on"}, "Context")
        identifier = _reference(context["context_id"])
        if identifier in contexts or _name(context["current_role"]) not in roles:
            raise PostgreSQLRlsAnalysisError(
                "Context identity/current role does not resolve uniquely"
            )
        _boolean(context["row_security_on"])
        contexts[identifier] = context
    rows = {}
    for row in _array(model["rows"], MAX_ROWS, "Rows"):
        work.charge()
        _object(row, {"row_id", "values"}, "Row")
        identifier = _reference(row["row_id"])
        if identifier in rows:
            raise PostgreSQLRlsAnalysisError("Duplicate row identity")
        if type(row["values"]) is not dict or row["values"].keys() != columns.keys():
            raise PostgreSQLRlsAnalysisError("Row columns are unavailable or not exactly declared")
        for name, kind in columns.items():
            work.charge()
            _scalar(row["values"][name], kind)
        rows[identifier] = row
    query_ids = set()
    for query in _array(model["queries"], MAX_QUERIES, "Queries"):
        work.charge()
        _object(query, {"query_id", "context_id", "row_id"}, "SELECT query")
        identifier = _reference(query["query_id"])
        if identifier in query_ids:
            raise PostgreSQLRlsAnalysisError("Duplicate query identity")
        query_ids.add(identifier)
        _reference(query["context_id"])
        _reference(query["row_id"])
        if query["context_id"] not in contexts or query["row_id"] not in rows:
            raise PostgreSQLRlsAnalysisError("SELECT context/row does not resolve")
    return roles, inherited, contexts, rows, compiled, issues


def _closure(current: str, inherited: dict[str, list[str]], work: _Work) -> tuple[str, ...]:
    found = {current}
    pending = deque([current])
    while pending:
        name = pending.popleft()
        work.charge()
        for target in inherited[name]:
            work.charge()
            if target not in found:
                found.add(target)
                pending.append(target)
    return tuple(sorted(found))


def _matches(
    selectors: list[dict[str, Any]], effective: tuple[str, ...], work: _Work
) -> list[dict[str, Any]]:
    matched = []
    for selector in selectors:
        work.charge(1 + len(effective))
        if selector["kind"] == "public" or selector["name"] in effective:
            matched.append(dict(selector))
    return matched


def _and(values: list[bool | None]) -> bool | None:
    return False if False in values else None if None in values else True


def _or(values: list[bool | None]) -> bool | None:
    return True if True in values else None if None in values else False


def _operand(compiled: tuple[Any, ...], row: dict[str, Any], current: str, work: _Work) -> Any:
    work.charge()
    if compiled[0] == "column":
        return row[compiled[1]]
    return current if compiled[0] == "current_user" else compiled[1]


def _evaluate(
    compiled: tuple[Any, ...], row: dict[str, Any], current: str, work: _Work
) -> bool | None:
    work.charge()
    op = compiled[0]
    if op == "bool":
        return compiled[1]
    if op in {"and", "or"}:
        values = [_evaluate(child, row, current, work) for child in compiled[1]]
        return _and(values) if op == "and" else _or(values)
    if op == "not":
        value = _evaluate(compiled[1], row, current, work)
        return None if value is None else not value
    if op in {"is_null", "is_not_null"}:
        null = _operand(compiled[1], row, current, work) is None
        return null if op == "is_null" else not null
    left = _operand(compiled[1], row, current, work)
    right = _operand(compiled[2], row, current, work)
    if left is None or right is None:
        return None
    if op == "eq":
        return left == right
    if op == "ne":
        return left != right
    if op == "lt":
        return left < right
    if op == "le":
        return left <= right
    if op == "gt":
        return left > right
    return left >= right


def _truth(value: bool | None) -> str:
    return "sql_null" if value is None else "true" if value else "false"


def _build(model: dict[str, Any]) -> dict[str, Any]:
    work = _Work()
    roles, inherited, contexts, rows, policies, issues = _prepare(model, work)
    table = model["table"]
    closure_cache = {}
    context_results = []
    for context in contexts.values():
        current = context["current_role"]
        if current not in closure_cache:
            closure_cache[current] = _closure(current, inherited, work)
        context_results.append(
            {
                "context_id": context["context_id"],
                "current_role": current,
                "effective_roles": list(closure_cache[current]),
                "own_superuser": roles[current]["superuser"],
                "own_bypass_rls": roles[current]["bypass_rls"],
                "owner_privileges_in_role_closure": table["owner_role"] in closure_cache[current],
            }
        )
    results = []
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "package_id": PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_commander_id": GROUP_COMMANDER_ID,
        "validator_id": VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": model,
        "source_model_sha256": "sha256:" + "0" * 64,
        "bounds": dict(_BOUNDS),
        "context_results": context_results,
        "query_results": results,
        "incomplete_reasons": sorted(issues),
        "analysis_status": "incomplete" if issues else "complete_declared_subset",
        "input_provenance": "supplied_unverified_model",
        "work_units": work.units,
        "effects": dict(_EFFECTS),
        **{flag: False for flag in _FLAGS},
        "analysis_id": "PRL-" + "0" * 32,
        "analysis_sha256": "sha256:" + "0" * 64,
    }
    retained_nodes, retained_bytes = _measure(body)
    for query in model["queries"]:
        work.charge()
        context = contexts[query["context_id"]]
        current = context["current_role"]
        role = roles[current]
        effective = closure_cache[current]
        owner = table["owner_role"] in effective
        grants = _matches(table["select_grantees"], effective, work)
        select_allowed = role["superuser"] or bool(grants)
        select = {
            "allowed": select_allowed,
            "reason": "own_superuser"
            if role["superuser"]
            else "explicit_select_grant"
            if grants
            else "no_explicit_select_grant",
            "grantee_witnesses": grants,
        }
        rls = {
            "mode": "unassessed",
            "applies": None,
            "row_passes": None,
            "permissive_value": None,
            "restrictive_value": None,
            "policy_evaluations": [],
        }
        if issues:
            select = {
                "allowed": None,
                "reason": "incomplete_supplied_model",
                "grantee_witnesses": grants,
            }
            outcome = "unassessed"
        else:
            if not table["rls_enabled"]:
                mode = "disabled"
            elif role["superuser"]:
                mode = "bypass_own_superuser"
            elif role["bypass_rls"]:
                mode = "bypass_own_attribute"
            elif owner and not table["force_rls"]:
                mode = "bypass_owner_privileges"
            elif not context["row_security_on"]:
                mode = "row_security_off_error"
            else:
                mode = "active"
            rls["mode"] = mode
            rls["applies"] = mode in {"active", "row_security_off_error"}
            if mode == "active":
                permissive, restrictive = [], []
                for policy, ast in policies:
                    work.charge()
                    if policy["command"] not in {"ALL", "SELECT"}:
                        continue
                    matches = _matches(policy["to_roles"], effective, work)
                    if not matches:
                        continue
                    value = _evaluate(ast, rows[query["row_id"]]["values"], current, work)
                    (permissive if policy["mode"] == "PERMISSIVE" else restrictive).append(value)
                    rls["policy_evaluations"].append(
                        {
                            "policy_id": policy["policy_id"],
                            "mode": policy["mode"],
                            "role_witnesses": matches,
                            "using_form": "absent_implicit_true"
                            if policy["using"] is None
                            else "explicit_expression",
                            "value": _truth(value),
                        }
                    )
                allow, restrict = _or(permissive), _and(restrictive)
                rls["permissive_value"], rls["restrictive_value"] = _truth(allow), _truth(restrict)
                rls["row_passes"] = _and([allow, restrict]) is True
            elif mode != "row_security_off_error":
                rls["row_passes"] = True
            if not select_allowed:
                outcome = "select_not_granted_in_supplied_model"
            elif mode == "row_security_off_error":
                outcome = "row_security_off_error_in_supplied_model"
            else:
                outcome = (
                    "row_available_in_supplied_select_rls_model"
                    if rls["row_passes"]
                    else "row_filtered_in_supplied_select_rls_model"
                )
        result = {**query, "select_privilege": select, "rls": rls, "outcome": outcome}
        # Reserve the complete retained output before adding this row, without
        # repeatedly serializing prior prefixes. Query rows start at body depth 3.
        row_nodes, row_bytes = _measure(result, depth=3)
        retained_nodes += row_nodes
        retained_bytes += (
            row_bytes + bool(results) + len(str(work.units)) - len(str(body["work_units"]))
        )
        if retained_nodes > MAX_NATIVE_NODES or retained_bytes > MAX_DOCUMENT_BYTES:
            raise PostgreSQLRlsAnalysisError("Derived output node/byte budget exceeded")
        results.append(result)
        body["work_units"] = work.units
    # Reserve exact output including fixed-width addresses before any new hash.
    _native(body)
    body["source_model_sha256"] = _digest(MODEL_DOMAIN, model)
    addressed = {
        key: value for key, value in body.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = _digest(DOMAIN, addressed)
    body["analysis_id"] = "PRL-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    return body


def _digest(domain: str, content: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            _canonical({"domain": domain, "content": content}).encode("ascii")
        ).hexdigest()
    )


def _rebuild(raw: dict[str, Any]) -> dict[str, Any]:
    if type(raw.get("source_model")) is not dict:
        raise PostgreSQLRlsAnalysisError("Report source model is unavailable")
    expected = _build(raw["source_model"])
    if _native(raw) != _native(expected):
        raise PostgreSQLRlsAnalysisError("Report does not reproduce its complete supplied source")
    return expected


def parse_supplied_postgresql_rls_model(content: bytes) -> dict[str, Any]:
    """Bounded exact native bytes intake; validate/detach without hashes or SQL."""
    owned = _decode(content)
    _prepare(owned, _Work())
    return owned


@dataclass(frozen=True, slots=True)
class SuppliedPostgreSQLRlsAnalysis:
    """Owned unsigned report; public exports replay its complete embedded model."""

    document_json: str

    def _document(self) -> dict[str, Any]:
        text = getattr(self, "document_json", None)
        if type(self) is not SuppliedPostgreSQLRlsAnalysis or type(text) is not str:
            raise PostgreSQLRlsAnalysisError("Exact native report wrapper is required")
        if not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
            raise PostgreSQLRlsAnalysisError("Report text is invalid or oversized")
        raw = _decode(text.encode("ascii"))
        expected = _rebuild(raw)
        if _canonical(expected) != text:
            raise PostgreSQLRlsAnalysisError("Report wrapper must contain exact canonical JSON")
        return expected

    def __post_init__(self) -> None:
        self._document()

    def to_dict(self) -> dict[str, Any]:
        return self._document()

    def to_json(self) -> str:
        return _canonical(self._document())

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> SuppliedPostgreSQLRlsAnalysis:
        if cls is not SuppliedPostgreSQLRlsAnalysis:
            raise PostgreSQLRlsAnalysisError("Exact report family is required")
        return cls(_canonical(_rebuild(_capture(raw))))

    @classmethod
    def from_bytes(cls, content: bytes) -> SuppliedPostgreSQLRlsAnalysis:
        if cls is not SuppliedPostgreSQLRlsAnalysis:
            raise PostgreSQLRlsAnalysisError("Exact report family is required")
        return cls(_canonical(_rebuild(_decode(content))))

    @classmethod
    def from_json(cls, text: str) -> SuppliedPostgreSQLRlsAnalysis:
        if (
            type(text) is not str
            or not text
            or len(text) > MAX_DOCUMENT_BYTES
            or not text.isascii()
        ):
            raise PostgreSQLRlsAnalysisError("Bounded native ASCII JSON text is required")
        return cls.from_bytes(text.encode("ascii"))


def analyze_supplied_postgresql_rls(model: dict[str, Any]) -> SuppliedPostgreSQLRlsAnalysis:
    """Analyze only explicitly supplied ordinary-table SELECT declarations and rows."""
    return SuppliedPostgreSQLRlsAnalysis(_canonical(_build(_capture(model))))


def verify_supplied_postgresql_rls_analysis(
    report: SuppliedPostgreSQLRlsAnalysis, *, model: dict[str, Any]
) -> SuppliedPostgreSQLRlsAnalysis:
    """Recompute from a separately original model; content addresses grant no authority."""
    original = _capture(model)
    if type(report) is not SuppliedPostgreSQLRlsAnalysis:
        raise PostgreSQLRlsAnalysisError("Exact report wrapper family is required")
    actual = report.to_dict()
    expected = _build(original)
    if _native(actual) != _native(expected):
        raise PostgreSQLRlsAnalysisError("Report differs from the separately original source model")
    return SuppliedPostgreSQLRlsAnalysis(_canonical(expected))


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "CAPABILITY_ID",
    "VECTOR_ID",
    "PACKAGE_ID",
    "WAVE_ID",
    "SEMANTICS_PROFILE",
    "DOMAIN",
    "PostgreSQLRlsAnalysisError",
    "SuppliedPostgreSQLRlsAnalysis",
    "parse_supplied_postgresql_rls_model",
    "analyze_supplied_postgresql_rls",
    "verify_supplied_postgresql_rls_analysis",
]

"""Finite Azure RBAC permission reasoning over supplied, unauthenticated models."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D14-S04"
CAPABILITY_ID = "army.gc.d14.s04"
VECTOR_ID = "AV-GC-D14-S04-01"
WAVE_ID = "IW2-007"
SEMANTICS_PROFILE = "azure-rbac-supplied-model-subset.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 24
MAX_TEXT = 4096
MAX_SCOPES = 512
MAX_SCOPE_DEPTH = 32
MAX_ROLES = 128
MAX_ASSIGNMENTS = 512
MAX_PERMISSION_BLOCKS = 512
MAX_PATTERNS = 2048
MAX_LOCAL_ITEMS = 128
MAX_QUERIES = 128
MAX_MATCH_WORK = 2_000_000
MAX_WITNESSES = 2048
_OUTCOMES = (
    "matching_supplied_role_grant",
    "no_matching_supplied_role_grant",
    "inconclusive",
)
_PERMISSION_FIELDS = {
    "actions",
    "not_actions",
    "data_actions",
    "not_data_actions",
    "condition",
    "condition_version",
}
_LIMITATIONS = (
    "All tenant, role, assignment, membership, scope and coverage facts are supplied declarations.",
    "Matching supplied roles is not effective Azure permission, access safety or provider truth.",
    "Conditions, deny assignments, eligibility and incomplete sources remain uncertainty.",
    "Operation existence and its control or data plane are not independently verified.",
    "No provider, target, credential, qualification, routing or deployment authority is granted.",
)


class AzureRbacAnalysisError(ValueError):
    """The finite model is malformed, unbounded, contradictory or falsely replayed."""


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _hash(domain: str, value: Any) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            domain.encode("ascii") + b"\n" + _canonical(value).encode("ascii")
        ).hexdigest()
    )


def _capture(value: Any) -> Any:
    """Own exact native JSON, charging repeated containers before serialization."""
    active: set[int] = set()
    nodes = size = 0

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes, size
        nodes += 1
        size += 2
        if depth > MAX_DEPTH or nodes > MAX_NODES or size > MAX_JSON_BYTES:
            raise AzureRbacAnalysisError("JSON structural budget exceeded")
        if type(item) is str:
            if len(item) > MAX_TEXT or not item.isascii():
                raise AzureRbacAnalysisError("JSON text requires bounded native ASCII")
            if any(ord(character) < 32 or ord(character) == 127 for character in item):
                raise AzureRbacAnalysisError("JSON text contains unsupported control characters")
            size += 6 * len(item)
            if size > MAX_JSON_BYTES:
                raise AzureRbacAnalysisError("JSON byte budget exceeded")
            return item
        if item is None or type(item) is bool:
            size += 5
            if size > MAX_JSON_BYTES:
                raise AzureRbacAnalysisError("JSON byte budget exceeded")
            return item
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise AzureRbacAnalysisError("JSON integer is outside signed64")
            size += 20
            if size > MAX_JSON_BYTES:
                raise AzureRbacAnalysisError("JSON byte budget exceeded")
            return item
        if type(item) not in (dict, list):
            raise AzureRbacAnalysisError("Only exact native JSON primitives are accepted")
        if len(item) > MAX_NODES or id(item) in active:
            raise AzureRbacAnalysisError("JSON container is oversized or cyclic")
        active.add(id(item))
        try:
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            result = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise AzureRbacAnalysisError("JSON object keys require native text")
                result[visit(key, depth + 1)] = visit(child, depth + 1)
            return result
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _parse_bytes(content: bytes) -> Any:
    if type(content) is not bytes or not content or len(content) > MAX_JSON_BYTES:
        raise AzureRbacAnalysisError("JSON requires bounded nonempty native UTF-8 bytes")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AzureRbacAnalysisError("JSON is not UTF-8") from exc
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise AzureRbacAnalysisError("JSON depth budget exceeded")
        elif character in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, item in items:
            if key in result:
                raise AzureRbacAnalysisError("Duplicate JSON object key")
            result[key] = item
        return result

    def unsupported(_: str) -> Any:
        raise AzureRbacAnalysisError("JSON floats and nonfinite values are unsupported")

    def integer(text: str) -> int:
        if len(text) > 20:
            raise AzureRbacAnalysisError("JSON integer is outside signed64")
        return int(text)

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, RecursionError) as exc:
        raise AzureRbacAnalysisError("Invalid bounded native JSON") from exc
    return _capture(value)


def _object(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or len(value) != len(fields) or value.keys() != fields:
        raise AzureRbacAnalysisError(f"{label} requires exactly its declared fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise AzureRbacAnalysisError(f"{label} requires bounded nonempty native text")
    return value


def _ref(value: Any, label: str) -> str:
    text = _text(value, label)
    if not re.fullmatch(r"/?[A-Za-z0-9][A-Za-z0-9:._/-]*", text):
        raise AzureRbacAnalysisError(f"{label} is outside the supported identifier subset")
    return text


def _list(value: Any, label: str, *, maximum: int = MAX_LOCAL_ITEMS) -> list:
    if type(value) is not list or len(value) > maximum:
        raise AzureRbacAnalysisError(f"{label} requires a bounded native list")
    return value


def _boolean(value: Any, label: str) -> None:
    if type(value) is not bool:
        raise AzureRbacAnalysisError(f"{label} requires a native boolean")


def _nullable_text(value: Any, label: str) -> None:
    if value is not None:
        _text(value, label, maximum=2048)


def _unique_texts(value: Any, label: str, *, references: bool = False) -> list[str]:
    values = _list(value, label)
    seen = set()
    for item in values:
        (_ref if references else _text)(item, label)
        if item.lower() in seen:
            raise AzureRbacAnalysisError(f"{label} contains duplicate case-insensitive values")
        seen.add(item.lower())
    return values


def _scope_id(value: Any, *, root: bool = False) -> tuple[str, str | None]:
    text = _text(value, "Scope identity")
    if text == "/" and root:
        return "root", None
    if not text.startswith("/") or text.endswith("/"):
        raise AzureRbacAnalysisError("Scope identities require explicit unambiguous ARM paths")
    parts = text.split("/")[1:]
    if any(part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_.()-]+", part) for part in parts):
        raise AzureRbacAnalysisError("Scope path is outside the supported ASCII ARM subset")
    lower = [part.lower() for part in parts]
    if len(parts) == 4 and lower[:3] == ["providers", "microsoft.management", "managementgroups"]:
        return "management_group", None
    if lower[0] != "subscriptions" or len(parts) < 2:
        raise AzureRbacAnalysisError("Only supplied management-group and subscription paths apply")
    if len(parts) == 2:
        return "subscription", None
    if len(parts) == 4 and lower[2] == "resourcegroups":
        return "resource_group", "/" + "/".join(parts[:2])
    base = 4 if len(parts) > 3 and lower[2] == "resourcegroups" else 2
    cursor = base
    last_provider = -1
    while cursor < len(parts):
        if lower[cursor] != "providers" or cursor + 3 >= len(parts):
            raise AzureRbacAnalysisError("Resource scope requires provider/type/name pairs")
        last_provider = cursor
        cursor += 2
        pairs = 0
        while cursor < len(parts) and lower[cursor] != "providers":
            if cursor + 1 >= len(parts):
                raise AzureRbacAnalysisError("Resource scope has an unmatched type/name pair")
            cursor += 2
            pairs += 1
        if not pairs:
            raise AzureRbacAnalysisError("Resource scope requires a resource type/name pair")
    if last_provider < 0:
        raise AzureRbacAnalysisError("Unsupported resource scope")
    parent_end = last_provider if len(parts) - last_provider == 4 else len(parts) - 2
    return "resource", "/" + "/".join(parts[:parent_end])


def _supported_pattern(pattern: str) -> bool:
    # The finite subset implements the documented '*' only, not '?' or expressions.
    return bool(
        pattern == "*"
        or (
            "/" in pattern
            and pattern.count("*") <= 1
            and re.fullmatch(r"[A-Za-z0-9_.*/-]+", pattern)
            and "//" not in pattern
        )
    )


class _Budget:
    def __init__(self) -> None:
        self.work = 0
        self.witnesses = 0
        self.witness_bytes = 0

    def spend(self, count: int = 1) -> None:
        self.work += count
        if self.work > MAX_MATCH_WORK:
            raise AzureRbacAnalysisError("Matching work budget exceeded")

    def witness(self, maximum_bytes: int) -> None:
        self.witnesses += 1
        self.witness_bytes += maximum_bytes
        if self.witnesses > MAX_WITNESSES or self.witness_bytes > MAX_JSON_BYTES:
            raise AzureRbacAnalysisError("Witness count or aggregate byte budget exceeded")


def _matches(pattern: str, operation: str, budget: _Budget) -> bool:
    budget.spend(1 + len(pattern) + len(operation))
    pattern, operation = pattern.lower(), operation.lower()
    if "*" not in pattern:
        return pattern == operation
    prefix, suffix = pattern.split("*")
    return (
        len(operation) >= len(prefix) + len(suffix)
        and operation.startswith(prefix)
        and operation.endswith(suffix)
    )


def _prepare(snapshot: Any, queries: Any) -> tuple[dict, list, dict, dict, dict, list, list]:
    inputs = _capture({"snapshot": snapshot, "queries": queries})
    snapshot, queries = inputs["snapshot"], inputs["queries"]
    _object(
        snapshot,
        {
            "schema_version",
            "tenant_id",
            "scopes",
            "role_definitions",
            "role_assignments",
            "coverage",
        },
        "Snapshot",
    )
    if type(snapshot["schema_version"]) is not int or snapshot["schema_version"] != 1:
        raise AzureRbacAnalysisError("schema_version requires the native integer one")
    _ref(snapshot["tenant_id"], "Tenant identity")
    coverage = _object(
        snapshot["coverage"],
        {"role_assignments_complete", "scope_ancestry_complete", "deny_assignments"},
        "Coverage",
    )
    for field in ("role_assignments_complete", "scope_ancestry_complete"):
        _boolean(coverage[field], field)
    if coverage["deny_assignments"] not in ("none_supplied", "present", "unknown"):
        raise AzureRbacAnalysisError("Deny coverage requires an explicit supported declaration")
    issues: dict[str, dict] = {}

    def issue(reason: str, source_id: str) -> None:
        item = {"reason": reason, "source_id": source_id}
        issues[_canonical(item)] = item

    scopes = {}
    for item in _list(snapshot["scopes"], "Scopes", maximum=MAX_SCOPES):
        _object(item, {"scope_id", "kind", "parent_scope_id"}, "Scope")
        kind, natural_parent = _scope_id(item["scope_id"])
        if item["kind"] != kind:
            raise AzureRbacAnalysisError("Declared scope kind contradicts its ARM path")
        key = item["scope_id"].lower()
        if key in scopes:
            raise AzureRbacAnalysisError("Duplicate or conflicting scope identity")
        parent = item["parent_scope_id"]
        if parent is not None:
            parent_kind, _ = _scope_id(parent)
            if kind in ("management_group", "subscription"):
                if parent_kind != "management_group":
                    raise AzureRbacAnalysisError("Only explicit management-group parents apply")
            elif parent.lower() != natural_parent.lower():
                raise AzureRbacAnalysisError("Scope parent contradicts the resource hierarchy")
        elif natural_parent is not None:
            issue("unresolved_scope_parent", item["scope_id"])
        scopes[key] = item
    chains = {}
    for key in scopes:
        path, seen = [], set()
        cursor: str | None = key
        while cursor is not None:
            if cursor in seen:
                raise AzureRbacAnalysisError("Scope ancestry is cyclic")
            if len(path) >= MAX_SCOPE_DEPTH:
                raise AzureRbacAnalysisError("Scope ancestry depth budget exceeded")
            if cursor not in scopes:
                issue("unresolved_scope_parent", scopes[path[-1]]["scope_id"])
                break
            path.append(cursor)
            seen.add(cursor)
            parent = scopes[cursor]["parent_scope_id"]
            cursor = None if parent is None else parent.lower()
        chains[key] = path
    roles = {}
    blocks = patterns = 0
    for role in _list(snapshot["role_definitions"], "Role definitions", maximum=MAX_ROLES):
        _object(
            role,
            {"role_definition_id", "role_type", "assignable_scopes", "permissions"},
            "Role definition",
        )
        _ref(role["role_definition_id"], "Role definition identity")
        key = role["role_definition_id"].lower()
        if key in roles:
            raise AzureRbacAnalysisError("Duplicate or conflicting role definition identity")
        if role["role_type"] not in ("custom", "built_in"):
            raise AzureRbacAnalysisError("Role type requires an explicit supported declaration")
        available = _unique_texts(role["assignable_scopes"], "Assignable scopes")
        if not available:
            raise AzureRbacAnalysisError("A supplied role requires declared assignable scopes")
        management_groups = 0
        for available_scope in available:
            kind, _ = _scope_id(available_scope, root=True)
            management_groups += kind == "management_group"
            if available_scope != "/" and available_scope.lower() not in scopes:
                issue("unresolved_assignable_scope", role["role_definition_id"])
        if role["role_type"] == "custom" and ("/" in available or management_groups > 1):
            issue("unsupported_custom_role_scope_configuration", role["role_definition_id"])
        seen_permissions = set()
        permissions = _list(role["permissions"], "Permissions", maximum=16)
        if len(permissions) > 1:
            issue("unsupported_multiple_permission_blocks", role["role_definition_id"])
        for permission in permissions:
            _object(permission, _PERMISSION_FIELDS, "Permission block")
            blocks += 1
            if blocks > MAX_PERMISSION_BLOCKS:
                raise AzureRbacAnalysisError("Permission block budget exceeded")
            for field in ("actions", "not_actions", "data_actions", "not_data_actions"):
                values = _unique_texts(permission[field], field)
                patterns += len(values)
                if patterns > MAX_PATTERNS:
                    raise AzureRbacAnalysisError("Permission pattern budget exceeded")
                if any(not _supported_pattern(pattern) for pattern in values):
                    issue("unsupported_permission_pattern", role["role_definition_id"])
            for field in ("condition", "condition_version"):
                _nullable_text(permission[field], field)
            if permission["condition"] is not None or permission["condition_version"] is not None:
                issue("unsupported_role_condition", role["role_definition_id"])
            # All native block fields and local/global counts have been checked first.
            identity = _canonical(permission)
            if identity in seen_permissions:
                raise AzureRbacAnalysisError("Duplicate permission block")
            seen_permissions.add(identity)
        roles[key] = role
    assignments = _list(snapshot["role_assignments"], "Role assignments", maximum=MAX_ASSIGNMENTS)
    seen_assignments = set()
    for assignment in assignments:
        _object(
            assignment,
            {
                "assignment_id",
                "tenant_id",
                "principal_id",
                "role_definition_id",
                "scope_id",
                "state",
                "condition",
                "condition_version",
            },
            "Role assignment",
        )
        for field in ("assignment_id", "tenant_id", "principal_id", "role_definition_id"):
            _ref(assignment[field], field)
        key = assignment["assignment_id"].lower()
        if key in seen_assignments:
            raise AzureRbacAnalysisError("Duplicate or conflicting role assignment identity")
        seen_assignments.add(key)
        if assignment["tenant_id"].lower() != snapshot["tenant_id"].lower():
            raise AzureRbacAnalysisError("Assignment tenant differs from the supplied model")
        kind, _ = _scope_id(assignment["scope_id"])
        if assignment["scope_id"].lower() not in scopes:
            issue("unresolved_assignment_scope", assignment["assignment_id"])
        role = roles.get(assignment["role_definition_id"].lower())
        if role is None:
            issue("unresolved_role_definition", assignment["assignment_id"])
        elif assignment["scope_id"].lower() in chains and not any(
            available == "/" or available.lower() in chains[assignment["scope_id"].lower()]
            for available in role["assignable_scopes"]
        ):
            issue("assignment_outside_declared_assignable_scopes", assignment["assignment_id"])
        if assignment["state"] not in ("active", "eligible", "unknown"):
            raise AzureRbacAnalysisError("Assignment state requires an explicit declaration")
        if assignment["state"] != "active":
            issue("unsupported_assignment_eligibility", assignment["assignment_id"])
        for field in ("condition", "condition_version"):
            _nullable_text(assignment[field], field)
        if assignment["condition"] is not None or assignment["condition_version"] is not None:
            issue("unsupported_assignment_condition", assignment["assignment_id"])
        if role is not None and role["role_type"] == "custom" and kind == "management_group":
            if any(block["data_actions"] for block in role["permissions"]):
                issue(
                    "unsupported_custom_data_management_group_assignment",
                    assignment["assignment_id"],
                )
    _list(queries, "Queries", maximum=MAX_QUERIES)
    if not queries:
        raise AzureRbacAnalysisError("At least one explicit query is required")
    seen_queries = set()
    for query in queries:
        _object(
            query,
            {
                "query_id",
                "tenant_id",
                "principal_id",
                "group_ids",
                "group_membership_complete",
                "scope_id",
                "operation",
                "plane",
            },
            "Query",
        )
        for field in ("query_id", "tenant_id", "principal_id"):
            _ref(query[field], field)
        if query["query_id"] in seen_queries:
            raise AzureRbacAnalysisError("Duplicate query identity")
        seen_queries.add(query["query_id"])
        _unique_texts(query["group_ids"], "Supplied group identities", references=True)
        _boolean(query["group_membership_complete"], "group_membership_complete")
        _scope_id(query["scope_id"])
        operation = _text(query["operation"], "Operation")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){2,}", operation):
            raise AzureRbacAnalysisError("Query operations must be explicit supported action names")
        if query["plane"] not in ("control", "data"):
            raise AzureRbacAnalysisError("Query plane requires exact control or data")
    return (
        snapshot,
        queries,
        scopes,
        chains,
        roles,
        assignments,
        [issues[key] for key in sorted(issues)],
    )


def _build_document(snapshot: Any, queries: Any) -> dict:
    snapshot, queries, scopes, chains, roles, assignments, issues = _prepare(snapshot, queries)
    budget = _Budget()
    results = []
    for query in sorted(queries, key=lambda item: item["query_id"]):
        reasons = {item["reason"] for item in issues}
        coverage = snapshot["coverage"]
        if not coverage["role_assignments_complete"]:
            reasons.add("incomplete_role_assignments")
        if not coverage["scope_ancestry_complete"]:
            reasons.add("incomplete_scope_ancestry")
        if coverage["deny_assignments"] != "none_supplied":
            reasons.add("unsupported_or_unknown_deny_assignments")
        if not query["group_membership_complete"]:
            reasons.add("incomplete_group_membership")
        tenant_matches = query["tenant_id"].lower() == snapshot["tenant_id"].lower()
        if not tenant_matches:
            reasons.add("query_tenant_outside_supplied_model")
        query_scope = query["scope_id"].lower()
        if query_scope not in scopes:
            reasons.add("unresolved_query_scope")
        principals = {query["principal_id"].lower()} | {
            group.lower() for group in query["group_ids"]
        }
        witnesses = {}
        for assignment in assignments:
            budget.spend()
            assignment_scope = assignment["scope_id"].lower()
            if (
                not tenant_matches
                or assignment["principal_id"].lower() not in principals
                or assignment_scope not in chains.get(query_scope, [])
            ):
                continue
            role = roles.get(assignment["role_definition_id"].lower())
            if role is None or assignment["state"] != "active":
                continue
            if len(role["permissions"]) > 1:
                continue
            if assignment["condition"] is not None or assignment["condition_version"] is not None:
                continue
            if role["role_type"] == "custom" and (
                "/" in role["assignable_scopes"]
                or sum(
                    _scope_id(item)[0] == "management_group" for item in role["assignable_scopes"]
                )
                > 1
                or (
                    scopes[assignment_scope]["kind"] == "management_group"
                    and any(block["data_actions"] for block in role["permissions"])
                )
            ):
                continue
            if not any(
                available == "/" or available.lower() in chains[assignment_scope]
                for available in role["assignable_scopes"]
            ):
                reasons.add("assignment_outside_declared_assignable_scopes")
                continue
            include, exclude = (
                ("actions", "not_actions")
                if query["plane"] == "control"
                else ("data_actions", "not_data_actions")
            )
            for permission in role["permissions"]:
                budget.spend()
                if (
                    permission["condition"] is not None
                    or permission["condition_version"] is not None
                ):
                    continue
                if any(
                    not _supported_pattern(pattern)
                    for field in (include, exclude)
                    for pattern in permission[field]
                ):
                    continue
                matches = sorted(
                    pattern
                    for pattern in permission[include]
                    if _matches(pattern, query["operation"], budget)
                )
                removed = any(
                    _matches(pattern, query["operation"], budget) for pattern in permission[exclude]
                )
                if not matches or removed:
                    continue
                distance = chains[query_scope].index(assignment_scope)
                path_keys = list(reversed(chains[query_scope][: distance + 1]))
                # Charge a conservative native JSON size before witness expansion or hashing.
                budget.witness(
                    1024
                    + 6
                    * sum(
                        len(value)
                        for value in (
                            assignment["assignment_id"],
                            role["role_definition_id"],
                            assignment["principal_id"],
                            assignment["scope_id"],
                            *matches,
                            *(scopes[key]["scope_id"] for key in path_keys),
                        )
                    )
                )
                witness = {
                    "assignment_id": assignment["assignment_id"],
                    "role_definition_id": role["role_definition_id"],
                    "permission_sha256": _hash("sunderkey.azure-rbac-permission.v1", permission),
                    "assigned_principal_id": assignment["principal_id"],
                    "principal_match": "direct"
                    if assignment["principal_id"].lower() == query["principal_id"].lower()
                    else "supplied_group",
                    "assignment_scope_id": assignment["scope_id"],
                    "scope_path": [scopes[key]["scope_id"] for key in path_keys],
                    "matching_patterns": matches,
                }
                witness_key = _canonical(witness)
                if witness_key not in witnesses:
                    witnesses[witness_key] = witness
        outcome = (
            "inconclusive"
            if reasons
            else "matching_supplied_role_grant"
            if witnesses
            else "no_matching_supplied_role_grant"
        )
        results.append(
            {
                "query_id": query["query_id"],
                "query_sha256": _hash("sunderkey.azure-rbac-query.v1", query),
                "outcome": outcome,
                "uncertainty_reasons": sorted(reasons),
                "known_grant_witnesses": [witnesses[key] for key in sorted(witnesses)],
            }
        )
    body = {
        "schema_version": 1,
        "kind": "azure_rbac_analysis",
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "operator_supplied_unverified",
        "source_digest_basis": "canonical_parsed_json",
        "snapshot": snapshot,
        "queries": queries,
        "snapshot_sha256": _hash("sunderkey.azure-rbac-snapshot.v1", snapshot),
        "queries_sha256": _hash("sunderkey.azure-rbac-queries.v1", queries),
        "source_issues": issues,
        "results": results,
        "summary": {key: sum(result["outcome"] == key for result in results) for key in _OUTCOMES},
        "matching_work": budget.work,
        "limits": {
            "max_json_bytes": MAX_JSON_BYTES,
            "max_nodes": MAX_NODES,
            "max_depth": MAX_DEPTH,
            "max_scopes": MAX_SCOPES,
            "max_scope_depth": MAX_SCOPE_DEPTH,
            "max_roles": MAX_ROLES,
            "max_assignments": MAX_ASSIGNMENTS,
            "max_permission_blocks": MAX_PERMISSION_BLOCKS,
            "max_patterns": MAX_PATTERNS,
            "max_queries": MAX_QUERIES,
            "max_match_work": MAX_MATCH_WORK,
            "max_witnesses": MAX_WITNESSES,
        },
        "limitations": list(_LIMITATIONS),
        "offline_only": True,
        "effective_access_verified": False,
        "qualification_claimed": False,
        "effects": {
            key: "none"
            for key in (
                "authority",
                "qualification",
                "routing",
                "execution",
                "deployment",
                "provider",
                "target_interaction",
            )
        },
    }
    # Validate the complete native result budget before serialization or addressing.
    body = _capture(body)
    digest = _hash("sunderkey.azure-rbac-analysis.v1", body)
    body.update(analysis_id="ARA-" + digest[7:39].upper(), analysis_sha256=digest)
    _capture(body)
    return body


def _verified_document(value: Any) -> dict:
    document = _capture(value)
    if type(document) is not dict or not {"snapshot", "queries"} <= document.keys():
        raise AzureRbacAnalysisError("Analysis requires its exact embedded supplied inputs")
    expected = _build_document(document["snapshot"], document["queries"])
    if _canonical(document) != _canonical(expected):
        raise AzureRbacAnalysisError("Analysis does not match exact source/query replay")
    return expected


@dataclass(frozen=True, slots=True)
class AzureRbacAnalysis:
    """Detached canonical report; parsing/export repeat the supplied-model algorithm."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, document: dict) -> AzureRbacAnalysis:
        return cls(_canonical(_verified_document(document)))

    @classmethod
    def from_json(cls, content: bytes) -> AzureRbacAnalysis:
        return cls.from_dict(_parse_bytes(content))

    def to_dict(self) -> dict:
        if type(self) is not AzureRbacAnalysis:
            raise AzureRbacAnalysisError("Expected an exact AzureRbacAnalysis record")
        text = getattr(self, "document_json", None)
        if type(text) is not str or not text or len(text) > MAX_JSON_BYTES or not text.isascii():
            raise AzureRbacAnalysisError("Analysis requires bounded native canonical ASCII text")
        expected = _verified_document(_parse_bytes(text.encode("ascii")))
        if text != _canonical(expected):
            raise AzureRbacAnalysisError("Analysis text must be exact canonical JSON")
        return expected

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_azure_rbac(snapshot: dict, queries: list) -> AzureRbacAnalysis:
    """Reason only about supplied role grants, never effective Azure authorization."""
    return AzureRbacAnalysis(_canonical(_build_document(snapshot, queries)))


def analyze_azure_rbac_bytes(*, snapshot_bytes: bytes, queries_bytes: bytes) -> AzureRbacAnalysis:
    return analyze_azure_rbac(_parse_bytes(snapshot_bytes), _parse_bytes(queries_bytes))


def verify_azure_rbac_analysis(
    analysis: AzureRbacAnalysis | dict, *, snapshot: dict, queries: list
) -> AzureRbacAnalysis:
    if type(analysis) is AzureRbacAnalysis:
        document = analysis.to_dict()
    elif type(analysis) is dict:
        document = _verified_document(analysis)
    else:
        raise AzureRbacAnalysisError("Expected an exact record or native analysis document")
    expected = _build_document(snapshot, queries)
    if _canonical(document) != _canonical(expected):
        raise AzureRbacAnalysisError("Analysis is bound to different supplied inputs")
    return AzureRbacAnalysis(_canonical(expected))

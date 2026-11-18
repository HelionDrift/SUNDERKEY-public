"""Finite GCP allow-binding reasoning over supplied, unauthenticated sources."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROFILE_ID = "AOE-GC-D14-S06"
CAPABILITY_ID = "army.gc.d14.s06"
VECTOR_ID = "AV-GC-D14-S06-01"
WAVE_ID = "IW2-009"
BLUEPRINT_SHA256 = "sha256:7fe0632a431d0fb376da9d80f6c16a4f54093c5a99dde97c54b116bf8a20f640"
SEMANTICS_PROFILE = "gcp-iam-supplied-allow-subset.v1"
DOMAIN = "sunderkey.gcp-iam-analysis.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 24
MAX_TEXT = 4096
MAX_RESOURCES = 512
MAX_ANCESTRY = 32
MAX_ROLES = 128
MAX_POLICIES = 512
MAX_BINDINGS = 1024
MAX_PERMISSION_ENTRIES = 8192
MAX_MEMBER_APPEARANCES = 4096
MAX_GROUPS = 128
MAX_QUERIES = 128
MAX_MATCH_WORK = 2_000_000
MAX_WITNESSES = 2048
_OUTCOMES = (
    "matching_supplied_allow_binding",
    "no_matching_supplied_allow_binding",
    "inconclusive",
)
_STAGES = {"ALPHA", "BETA", "GA", "DEPRECATED", "DISABLED", "EAP", "unknown"}
_COVERAGE_STATES = {"none_supplied", "present", "unknown"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
_PERMISSION = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*){2,7}")
_ROLE = re.compile(
    r"(?:roles/[A-Za-z0-9_.]+|(?:organizations/[0-9]+|projects/[A-Za-z0-9-]+)"
    r"/roles/[A-Za-z0-9_.]{1,64})"
)
_LIMITATIONS = (
    "All resource, role, policy, membership and coverage facts are supplied declarations.",
    "Matching allow bindings is not effective GCP access, denial, policy safety or provider truth.",
    "Conditions, projected conditional roles and unsupported principals are not evaluated.",
    "Deny, PAB, organization constraints, service-specific applicability "
    "and propagation are unverified.",
    "No provider, credential, target, qualification, routing or deployment authority is granted.",
)


class GcpIamAnalysisError(ValueError):
    """Sources are malformed, unbounded, contradictory or falsely replayed."""


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
    """Own native JSON and charge every occurrence before serialization or hashing."""
    active: set[int] = set()
    nodes = size = 0

    def charge(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_JSON_BYTES:
            raise GcpIamAnalysisError("JSON byte budget exceeded")

    def visit(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        charge(2)
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise GcpIamAnalysisError("JSON structural budget exceeded")
        if type(item) is str:
            if len(item) > MAX_TEXT or not item.isascii():
                raise GcpIamAnalysisError("JSON text requires bounded native ASCII")
            if any(ord(character) < 32 or ord(character) == 127 for character in item):
                raise GcpIamAnalysisError("JSON text has unsupported control characters")
            charge(6 * len(item))
            return item
        if item is None or type(item) is bool:
            charge(5)
            return item
        if type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise GcpIamAnalysisError("JSON integers require signed64")
            charge(20)
            return item
        if type(item) not in (dict, list):
            raise GcpIamAnalysisError("Only native JSON primitives are accepted")
        remaining = MAX_NODES - nodes
        if len(item) * (2 if type(item) is dict else 1) > remaining or id(item) in active:
            raise GcpIamAnalysisError("JSON container is oversized or cyclic")
        active.add(id(item))
        try:
            if type(item) is list:
                return [visit(child, depth + 1) for child in item]
            owned = {}
            for key, child in item.items():
                if type(key) is not str:
                    raise GcpIamAnalysisError("JSON keys require native text")
                owned[visit(key, depth + 1)] = visit(child, depth + 1)
            return owned
        finally:
            active.remove(id(item))

    return visit(value, 0)


def _parse_bytes(raw: Any) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_BYTES:
        raise GcpIamAnalysisError("JSON requires bounded nonempty native bytes")
    if not raw.isascii():
        raise GcpIamAnalysisError("JSON requires native ASCII encoding")
    text = raw.decode("ascii")

    def integer(value: str) -> int:
        if len(value) > 20:
            raise GcpIamAnalysisError("JSON integer is outside signed64")
        number = int(value)
        if not -(2**63) <= number < 2**63:
            raise GcpIamAnalysisError("JSON integer is outside signed64")
        return number

    # Count containers, keys and scalar occurrences before the decoder allocates them.
    # This scanner budgets a lexical subset; json.loads still validates the full grammar.
    depth = nodes = size = index = 0

    def charge_node() -> None:
        nonlocal nodes, size
        nodes += 1
        size += 2
        if nodes > MAX_NODES:
            raise GcpIamAnalysisError("JSON structural budget exceeded")

    def charge_value(amount: int) -> None:
        nonlocal size
        size += amount
        if size > MAX_JSON_BYTES:
            raise GcpIamAnalysisError("JSON byte budget exceeded")

    while index < len(text):
        character = text[index]
        if character in " \t\r\n,:":
            index += 1
            continue
        if character in "[{":
            charge_node()
            charge_value(0)
            depth += 1
            if depth > MAX_DEPTH:
                raise GcpIamAnalysisError("JSON structural budget exceeded")
            index += 1
            continue
        if character in "]}":
            depth -= 1
            if depth < 0:
                raise GcpIamAnalysisError("Invalid JSON container boundary")
            index += 1
            continue
        charge_node()
        if character == '"':
            index += 1
            length = 0
            while index < len(text) and text[index] != '"':
                if text[index] == "\\":
                    index += 1
                    if index >= len(text):
                        raise GcpIamAnalysisError("Invalid JSON string boundary")
                    if text[index] == "u":
                        if index + 4 >= len(text):
                            raise GcpIamAnalysisError("Invalid JSON unicode escape")
                        index += 4
                length += 1
                if length > MAX_TEXT:
                    raise GcpIamAnalysisError("JSON text requires bounded native ASCII")
                charge_value(6)
                index += 1
            if index >= len(text):
                raise GcpIamAnalysisError("Invalid JSON string boundary")
            charge_value(0)
            index += 1
            continue
        start = index
        while index < len(text) and text[index] not in ' \t\r\n,:{}[]"':
            index += 1
        token = text[start:index]
        if token in {"null", "true", "false"}:
            charge_value(5)
        elif re.fullmatch(r"-?(?:0|[1-9][0-9]*)", token):
            charge_value(20)
            integer(token)
        else:
            raise GcpIamAnalysisError("Invalid or unsupported native JSON scalar")
    if depth:
        raise GcpIamAnalysisError("Invalid JSON container boundary")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, child in items:
            if key in result:
                raise GcpIamAnalysisError("Duplicate JSON object key")
            result[key] = child
        return result

    def unsupported(_: str) -> Any:
        raise GcpIamAnalysisError("JSON floats and nonfinite values are unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=unsupported,
            parse_constant=unsupported,
            parse_int=integer,
        )
    except (ValueError, RecursionError) as exc:
        raise GcpIamAnalysisError("Invalid bounded native JSON") from exc
    return _capture(value)


def _object(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or len(value) != len(fields) or value.keys() != fields:
        raise GcpIamAnalysisError(f"{label} requires exactly its declared fields")
    return value


def _text(value: Any, label: str, *, maximum: int = 1024, empty: bool = False) -> str:
    if type(value) is not str or len(value) > maximum or (not value and not empty):
        raise GcpIamAnalysisError(f"{label} requires bounded native text")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise GcpIamAnalysisError(f"{label} requires a native boolean")
    return value


def _list(value: Any, label: str, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise GcpIamAnalysisError(f"{label} requires a bounded native list")
    return value


def _texts(value: Any, label: str, maximum: int) -> list[str]:
    rows = _list(value, label, maximum)
    for row in rows:
        _text(row, label)
    if len(set(rows)) != len(rows):
        raise GcpIamAnalysisError(f"{label} contains duplicate declarations")
    return rows


def _permission(value: Any) -> str:
    text = _text(value, "permission", maximum=256)
    if _PERMISSION.fullmatch(text) is None:
        raise GcpIamAnalysisError("Permissions require exact names, not wildcard selectors")
    return text


def _role_name(value: Any) -> str:
    text = _text(value, "role name", maximum=256)
    if _ROLE.fullmatch(text) is None:
        raise GcpIamAnalysisError("Role name is outside the exact supported naming subset")
    return text


def _role_owner(name: str) -> str | None:
    return None if name.startswith("roles/") else name.rsplit("/roles/", 1)[0]


def _member_kind(member: str) -> str:
    if member.startswith("deleted:"):
        original, separator, unique_id = member[len("deleted:") :].partition("?uid=")
        if separator and unique_id.isascii() and unique_id.isdecimal() and len(unique_id) <= 128:
            if _member_kind(original) in {"user", "service_account", "group"}:
                return "deleted"
        return "unsupported"
    for prefix, kind in (
        ("user:", "user"),
        ("serviceAccount:", "service_account"),
        ("group:", "group"),
    ):
        if member.startswith(prefix) and _EMAIL.fullmatch(member[len(prefix) :]) is not None:
            return kind
    return "unsupported"


def _condition(value: Any) -> None:
    if value is None:
        return
    raw = _object(value, {"title", "description", "expression"}, "condition")
    _text(raw["title"], "condition title", maximum=MAX_TEXT)
    _text(raw["description"], "condition description", maximum=MAX_TEXT, empty=True)
    _text(raw["expression"], "condition expression", maximum=MAX_TEXT)


def _sources(snapshot: Any, queries: Any) -> tuple[dict, list]:
    combined = _capture({"snapshot": snapshot, "queries": queries})
    model = _object(
        combined["snapshot"],
        {"schema_version", "resources", "roles", "allow_policies", "coverage"},
        "snapshot",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GcpIamAnalysisError("snapshot schema_version must be native integer1")
    coverage = _object(
        model["coverage"],
        {
            "resource_ancestry_complete",
            "allow_policies_complete",
            "deny_policies",
            "principal_access_boundaries",
        },
        "coverage",
    )
    for key in ("resource_ancestry_complete", "allow_policies_complete"):
        _boolean(coverage[key], key)
    for key in ("deny_policies", "principal_access_boundaries"):
        if type(coverage[key]) is not str or coverage[key] not in _COVERAGE_STATES:
            raise GcpIamAnalysisError("Restriction coverage requires an exact declared state")

    resources = _list(model["resources"], "resources", MAX_RESOURCES)
    names = set()
    for row in resources:
        _object(row, {"resource_name", "kind", "parent_resource_name"}, "resource")
        name = _text(row["resource_name"], "resource name")
        if name in names:
            raise GcpIamAnalysisError("Duplicate resource name")
        names.add(name)
        kind = row["kind"]
        if type(kind) is not str or kind not in {"organization", "folder", "project", "resource"}:
            raise GcpIamAnalysisError("Resource kind is outside the declared hierarchy subset")
        if row["parent_resource_name"] is not None:
            _text(row["parent_resource_name"], "parent resource name")
        if kind == "organization" and row["parent_resource_name"] is not None:
            raise GcpIamAnalysisError("Organization roots cannot declare a parent")
        if kind in {"folder", "resource"} and row["parent_resource_name"] is None:
            raise GcpIamAnalysisError("Folders and service resources require a declared parent")
        if kind in {"organization", "folder", "project"}:
            prefix = {
                "organization": "organizations/",
                "folder": "folders/",
                "project": "projects/",
            }[kind]
            if not name.startswith(prefix) or not re.fullmatch(
                r"[A-Za-z0-9-]+", name[len(prefix) :]
            ):
                raise GcpIamAnalysisError("Resource kind and resource name do not join")
        elif name.startswith(("organizations/", "folders/", "projects/")):
            raise GcpIamAnalysisError("Service resource names cannot impersonate hierarchy roots")
    resource_map = {row["resource_name"]: row for row in resources}
    for row in resources:
        parent = resource_map.get(row["parent_resource_name"])
        if parent is not None:
            allowed = {
                "folder": {"organization", "folder"},
                "project": {"organization", "folder"},
                "resource": {"project", "resource"},
            }
            if parent["kind"] not in allowed.get(row["kind"], set()):
                raise GcpIamAnalysisError("Declared parent kind contradicts the hierarchy subset")
        cursor = row["resource_name"]
        visited = set()
        while cursor in resource_map:
            if cursor in visited or len(visited) >= MAX_ANCESTRY:
                raise GcpIamAnalysisError("Resource ancestry is cyclic or outside its finite depth")
            visited.add(cursor)
            cursor = resource_map[cursor]["parent_resource_name"]

    roles = _list(model["roles"], "roles", MAX_ROLES)
    names = set()
    permission_count = 0
    for row in roles:
        _object(
            row,
            {"name", "included_permissions", "stage", "deleted", "permissions_complete"},
            "role",
        )
        name = _role_name(row["name"])
        if name in names:
            raise GcpIamAnalysisError("Duplicate role name")
        names.add(name)
        permissions = _texts(
            row["included_permissions"], "included permissions", MAX_PERMISSION_ENTRIES
        )
        permission_count += len(permissions)
        if permission_count > MAX_PERMISSION_ENTRIES:
            raise GcpIamAnalysisError("Aggregate permission entry budget exceeded")
        for permission in permissions:
            _permission(permission)
        if type(row["stage"]) is not str or row["stage"] not in _STAGES:
            raise GcpIamAnalysisError("Role lifecycle requires a declared supported stage")
        _boolean(row["deleted"], "role deleted state")
        _boolean(row["permissions_complete"], "permission completeness")

    policies = _list(model["allow_policies"], "allow policies", MAX_POLICIES)
    names = set()
    binding_count = member_count = 0
    for row in policies:
        _object(row, {"resource_name", "version", "etag", "bindings"}, "allow policy")
        name = _text(row["resource_name"], "policy resource")
        if name in names:
            raise GcpIamAnalysisError("Each supplied resource can have only one allow policy")
        names.add(name)
        if type(row["version"]) is not int or row["version"] not in {1, 3}:
            raise GcpIamAnalysisError("Allow policy version requires native integer1 or3")
        if row["etag"] is not None:
            _text(row["etag"], "etag")
        bindings = _list(row["bindings"], "bindings", MAX_BINDINGS)
        binding_count += len(bindings)
        if binding_count > MAX_BINDINGS:
            raise GcpIamAnalysisError("Aggregate binding budget exceeded")
        seen_bindings = set()
        for binding in bindings:
            _object(binding, {"role", "members", "condition"}, "binding")
            _role_name(binding["role"])
            members = _texts(binding["members"], "binding members", MAX_MEMBER_APPEARANCES)
            if not members:
                raise GcpIamAnalysisError("Bindings require at least one declared member")
            member_count += len(members)
            if member_count > MAX_MEMBER_APPEARANCES:
                raise GcpIamAnalysisError("Aggregate member appearance budget exceeded")
            _condition(binding["condition"])
            if binding["condition"] is not None and row["version"] != 3:
                raise GcpIamAnalysisError("Explicit conditions require allow policy version3")
            # Every binding is small and bounded before this duplicate identity serialization.
            identity = _canonical(
                {
                    "role": binding["role"],
                    "members": sorted(members),
                    "condition": binding["condition"],
                }
            )
            if identity in seen_bindings:
                raise GcpIamAnalysisError("Duplicate exact role binding")
            seen_bindings.add(identity)

    query_rows = _list(combined["queries"], "queries", MAX_QUERIES)
    names = set()
    for row in query_rows:
        _object(
            row,
            {
                "query_id",
                "resource_name",
                "permission",
                "principal",
                "groups",
                "group_membership_complete",
            },
            "query",
        )
        name = _text(row["query_id"], "query ID", maximum=256)
        if name in names:
            raise GcpIamAnalysisError("Duplicate query ID")
        names.add(name)
        _text(row["resource_name"], "query resource")
        _permission(row["permission"])
        _text(row["principal"], "query principal")
        groups = _texts(row["groups"], "query groups", MAX_GROUPS)
        if any(_member_kind(group) != "group" for group in groups):
            raise GcpIamAnalysisError("Groups require exact active group identifiers")
        _boolean(row["group_membership_complete"], "group membership completeness")
    return model, query_rows


def _ancestry(name: str, resources: dict) -> tuple[list[str], set[str]]:
    path = []
    reasons = set()
    cursor = name
    while cursor is not None:
        row = resources.get(cursor)
        if row is None:
            reasons.add("resource_or_parent_missing")
            break
        path.append(cursor)
        cursor = row["parent_resource_name"]
    path.reverse()
    return path, reasons


class _Work:
    def __init__(self) -> None:
        self.used = 0
        self.witnesses = 0

    def charge(self, amount: int = 1) -> None:
        self.used += amount
        if self.used > MAX_MATCH_WORK:
            raise GcpIamAnalysisError("Matching work budget exceeded")

    def witness(self) -> None:
        if self.witnesses >= MAX_WITNESSES:
            raise GcpIamAnalysisError("Witness count budget exceeded")
        self.witnesses += 1


def _member_matches(
    member: str, query: dict, groups: set[str], work: _Work
) -> tuple[str | None, str | None]:
    work.charge()
    kind = _member_kind(member)
    if kind == "deleted":
        return None, None
    if kind in {"user", "service_account"}:
        return ("direct", None) if member == query["principal"] else (None, None)
    if kind == "group":
        if member in groups:
            return "supplied_group", None
        return (
            (None, None)
            if query["group_membership_complete"]
            else (None, "group_membership_incomplete")
        )
    return None, "unsupported_member_selector"


def _build_document(snapshot: Any, queries: Any) -> dict:
    model, query_rows = _sources(snapshot, queries)
    resources = {row["resource_name"]: row for row in model["resources"]}
    roles = {row["name"]: row for row in model["roles"]}
    policies = {row["resource_name"]: row for row in model["allow_policies"]}
    role_permissions = {name: set(row["included_permissions"]) for name, row in roles.items()}
    role_hashes = {name: _hash("sunderkey.gcp-iam-role.v1", row) for name, row in roles.items()}
    policy_hashes = {
        name: _hash("sunderkey.gcp-iam-allow-policy.v1", row) for name, row in policies.items()
    }
    binding_hashes = {
        id(binding): _hash("sunderkey.gcp-iam-allow-binding.v1", binding)
        for policy in policies.values()
        for binding in policy["bindings"]
    }
    coverage = model["coverage"]
    global_reasons = set()
    if not coverage["resource_ancestry_complete"]:
        global_reasons.add("resource_ancestry_incomplete")
    if not coverage["allow_policies_complete"]:
        global_reasons.add("allow_policy_coverage_incomplete")
    for label in ("deny_policies", "principal_access_boundaries"):
        if coverage[label] != "none_supplied":
            global_reasons.add(label + "_not_evaluated")
    if any(name not in resources for name in policies):
        global_reasons.add("policy_resource_missing")
    work = _Work()
    results = []
    for query in sorted(query_rows, key=lambda row: row["query_id"]):
        work.charge()
        path, path_reasons = _ancestry(query["resource_name"], resources)
        reasons = global_reasons | path_reasons
        if _member_kind(query["principal"]) not in {"user", "service_account"}:
            reasons.add("unsupported_query_principal")
        witnesses = []
        groups = set(query["groups"])
        for resource_name in path:
            work.charge()
            policy = policies.get(resource_name)
            if policy is None:
                reasons.add("ancestor_allow_policy_missing")
                continue
            for binding in policy["bindings"]:
                work.charge()
                matching_members = []
                member_reasons = set()
                for member in binding["members"]:
                    match, reason = _member_matches(member, query, groups, work)
                    if reason is not None:
                        member_reasons.add(reason)
                    if match is not None:
                        matching_members.append((member, match))
                if not matching_members and not member_reasons:
                    continue
                name = binding["role"]
                # A v1 projection can hide a condition even if its exact role name is supplied.
                # Reserve the marker in other versions rather than guessing at its meaning.
                if "_withcond_" in name:
                    reasons.add("projected_conditional_role_unassessed")
                    continue
                role = roles.get(name)
                if role is None:
                    reasons.add("role_definition_missing")
                    continue
                if role["deleted"] or role["stage"] == "DISABLED":
                    continue
                if role["stage"] == "unknown":
                    reasons.add("role_lifecycle_unknown")
                    continue
                if query["permission"] not in role_permissions[name]:
                    if not role["permissions_complete"]:
                        reasons.add("role_permission_coverage_incomplete")
                    continue
                owner = _role_owner(name)
                policy_path, owner_reasons = _ancestry(resource_name, resources)
                if owner is not None and (owner_reasons or owner not in policy_path):
                    reasons.add("custom_role_owner_not_joined")
                    continue
                reasons.update(member_reasons)
                if binding["condition"] is not None:
                    reasons.add("condition_unassessed")
                    continue
                if _member_kind(query["principal"]) not in {"user", "service_account"}:
                    continue
                for member, match in matching_members:
                    work.witness()
                    witnesses.append(
                        {
                            "policy_resource_name": resource_name,
                            "policy_sha256": policy_hashes[resource_name],
                            "binding_sha256": binding_hashes[id(binding)],
                            "role_name": name,
                            "role_sha256": role_hashes[name],
                            "member": member,
                            "member_match": match,
                            "permission": query["permission"],
                            "inherited": resource_name != query["resource_name"],
                        }
                    )
        witnesses.sort(
            key=lambda row: (
                row["policy_resource_name"],
                row["role_name"],
                row["member"],
                row["binding_sha256"],
            )
        )
        outcome = (
            "inconclusive"
            if reasons
            else "matching_supplied_allow_binding"
            if witnesses
            else "no_matching_supplied_allow_binding"
        )
        results.append(
            {
                "query_id": query["query_id"],
                "query_sha256": _hash("sunderkey.gcp-iam-query.v1", query),
                "resource_name": query["resource_name"],
                "principal": query["principal"],
                "permission": query["permission"],
                "ancestry": path,
                "outcome": outcome,
                "known_allow_witnesses": witnesses,
                "uncertainty_reasons": sorted(reasons),
            }
        )
    body = {
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "semantics_profile": SEMANTICS_PROFILE,
        "input_provenance": "operator_supplied_unverified",
        "source_provenance": "canonical_parsed_json_not_raw_bytes",
        "offline_only": True,
        "effective_access_proven": False,
        "policy_safety_proven": False,
        "live_use_approved": False,
        "qualification_claimed": False,
        "bounds": {
            "maximum_json_bytes": MAX_JSON_BYTES,
            "maximum_nodes": MAX_NODES,
            "maximum_depth": MAX_DEPTH,
            "maximum_text": MAX_TEXT,
            "maximum_resources": MAX_RESOURCES,
            "maximum_ancestry": MAX_ANCESTRY,
            "maximum_roles": MAX_ROLES,
            "maximum_policies": MAX_POLICIES,
            "maximum_bindings": MAX_BINDINGS,
            "maximum_permission_entries": MAX_PERMISSION_ENTRIES,
            "maximum_member_appearances": MAX_MEMBER_APPEARANCES,
            "maximum_groups": MAX_GROUPS,
            "maximum_queries": MAX_QUERIES,
            "maximum_match_work": MAX_MATCH_WORK,
            "maximum_witnesses": MAX_WITNESSES,
        },
        "snapshot_sha256": _hash("sunderkey.gcp-iam-snapshot.v1", model),
        "queries_sha256": _hash("sunderkey.gcp-iam-queries.v1", query_rows),
        "snapshot": model,
        "queries": query_rows,
        "summary": {
            outcome: sum(row["outcome"] == outcome for row in results) for outcome in _OUTCOMES
        },
        "results": results,
        "limitations": list(_LIMITATIONS),
        "effects": {
            key: "none"
            for key in (
                "authority",
                "execution",
                "target_interaction",
                "provider",
                "credential",
                "qualification",
                "routing",
                "deployment",
            )
        },
    }
    # Check complete output size, repeated source subtrees and witnesses before report hashing.
    _capture(body)
    digest = _hash(DOMAIN, body)
    body.update(analysis_id="GIA-" + digest[7:39].upper(), analysis_sha256=digest)
    _capture(body)
    return body


def _verified_document(value: Any) -> dict:
    document = _capture(value)
    if type(document) is not dict or "snapshot" not in document or "queries" not in document:
        raise GcpIamAnalysisError("Analysis requires exact embedded original source inputs")
    expected = _build_document(document["snapshot"], document["queries"])
    if _canonical(document) != _canonical(expected):
        raise GcpIamAnalysisError("Analysis does not match exact source/query replay")
    return expected


@dataclass(frozen=True, slots=True)
class GcpIamAnalysis:
    """Owned canonical report; exports repeat exact embedded algorithm replay."""

    document_json: str

    def __post_init__(self) -> None:
        self._document()

    def _document(self) -> dict:
        text = getattr(self, "document_json", None)
        if type(text) is not str or not text or len(text) > MAX_JSON_BYTES or not text.isascii():
            raise GcpIamAnalysisError("Analysis requires bounded native canonical ASCII text")
        expected = _verified_document(_parse_bytes(text.encode("ascii")))
        if text != _canonical(expected):
            raise GcpIamAnalysisError("Analysis text must be exact canonical JSON")
        return expected

    @classmethod
    def from_dict(cls, document: dict) -> GcpIamAnalysis:
        return cls(_canonical(_verified_document(document)))

    @classmethod
    def from_json(cls, raw: bytes) -> GcpIamAnalysis:
        return cls.from_dict(_parse_bytes(raw))

    def to_dict(self) -> dict:
        return self._document()

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_gcp_iam(snapshot: dict, queries: list) -> GcpIamAnalysis:
    """Evaluate only supplied allow declarations, never actual provider access."""
    return GcpIamAnalysis(_canonical(_build_document(snapshot, queries)))


def analyze_gcp_iam_bytes(*, snapshot_bytes: bytes, queries_bytes: bytes) -> GcpIamAnalysis:
    return analyze_gcp_iam(_parse_bytes(snapshot_bytes), _parse_bytes(queries_bytes))


def verify_gcp_iam_analysis(
    analysis: GcpIamAnalysis | dict,
    *,
    snapshot: dict,
    queries: list,
) -> GcpIamAnalysis:
    """Recompute separately supplied original inputs without promoting their authenticity."""
    if type(analysis) is GcpIamAnalysis:
        document = analysis.to_dict()
    elif type(analysis) is dict:
        document = _verified_document(analysis)
    else:
        raise GcpIamAnalysisError("Expected an exact report record or native document")
    expected = _build_document(snapshot, queries)
    if _canonical(document) != _canonical(expected):
        raise GcpIamAnalysisError("Analysis is bound to different original source/query inputs")
    return GcpIamAnalysis(_canonical(expected))

"""Project supplied relational role-to-relation grants without database access."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_relational_grant_path"
PROFILE_ID = "AOE-GB-D07-S01"
CAPABILITY_ID = "data.relational-database"
VECTOR_ID = "AV-GB-D07-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:cffc1fb91d5574a2e55f42086247747c1517129827da70e987f80ad80a7fa5ff"
SEMANTICS_PROFILE = "supplied-relational-grant-path-v1"
DOMAIN = "sunderkey.offline-relational-grant-path.v1"
MAX_ROLES = 64
MAX_MEMBERSHIPS = 256
MAX_GRANTS = 256
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PRINCIPAL = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
_ROLE = re.compile(r"role:sha256:[0-9a-f]{64}\Z")
_RELATION = re.compile(r"relation:sha256:[0-9a-f]{64}\Z")
_PRIVILEGES = frozenset(
    ("declared_select", "declared_insert", "declared_update", "declared_delete")
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "database",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "query",
        "target",
    ),
    "none",
)


class RelationalGrantPathError(ValueError):
    """A supplied relation grant model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise RelationalGrantPathError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise RelationalGrantPathError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise RelationalGrantPathError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise RelationalGrantPathError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise RelationalGrantPathError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise RelationalGrantPathError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise RelationalGrantPathError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise RelationalGrantPathError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise RelationalGrantPathError(f"{label} must be an opaque digest reference")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise RelationalGrantPathError(f"{label} identifier is invalid")
    return value


def _privilege(value: Any) -> str:
    if type(value) is not str or value not in _PRIVILEGES:
        raise RelationalGrantPathError("Declared privilege is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "principal_ref",
            "graph_complete",
            "roles",
            "memberships",
            "grants",
            "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RelationalGrantPathError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise RelationalGrantPathError("Semantics profile is invalid")
    principal = _ref(model["principal_ref"], _PRINCIPAL, "Principal")
    if type(model["graph_complete"]) is not bool:
        raise RelationalGrantPathError("Graph completeness must be an exact boolean")
    roles = model["roles"]
    memberships = model["memberships"]
    grants = model["grants"]
    objectives = model["objectives"]
    if type(roles) is not list or len(roles) > MAX_ROLES:
        raise RelationalGrantPathError("Role count is invalid")
    if type(memberships) is not list or len(memberships) > MAX_MEMBERSHIPS:
        raise RelationalGrantPathError("Membership count is invalid")
    if type(grants) is not list or len(grants) > MAX_GRANTS:
        raise RelationalGrantPathError("Grant count is invalid")
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise RelationalGrantPathError("Objective count is invalid")
    known_roles: set[str] = set()
    for role in roles:
        role = _ref(role, _ROLE, "Role")
        if role in known_roles:
            raise RelationalGrantPathError("Duplicate role reference")
        known_roles.add(role)
    edge_ids: set[str] = set()
    for row in memberships:
        _fields(row, {"edge_id", "member_ref", "role_ref"}, "membership")
        edge = _id(row["edge_id"], "Membership")
        if edge in edge_ids:
            raise RelationalGrantPathError("Duplicate edge identifier")
        edge_ids.add(edge)
        member = row["member_ref"]
        if member != principal:
            member = _ref(member, _ROLE, "Membership member")
            if member not in known_roles:
                raise RelationalGrantPathError("Membership member is undeclared")
        role = _ref(row["role_ref"], _ROLE, "Membership role")
        if role not in known_roles:
            raise RelationalGrantPathError("Membership role is undeclared")
    for row in grants:
        _fields(row, {"edge_id", "grantee_ref", "relation_ref", "privilege"}, "grant")
        edge = _id(row["edge_id"], "Grant")
        if edge in edge_ids:
            raise RelationalGrantPathError("Duplicate edge identifier")
        edge_ids.add(edge)
        grantee = row["grantee_ref"]
        if grantee != principal:
            grantee = _ref(grantee, _ROLE, "Grant grantee")
            if grantee not in known_roles:
                raise RelationalGrantPathError("Grant grantee is undeclared")
        _ref(row["relation_ref"], _RELATION, "Grant relation")
        _privilege(row["privilege"])
    seen_objectives: set[tuple[str, str]] = set()
    for row in objectives:
        _fields(row, {"relation_ref", "privilege"}, "objective")
        pair = (
            _ref(row["relation_ref"], _RELATION, "Objective relation"),
            _privilege(row["privilege"]),
        )
        if pair in seen_objectives:
            raise RelationalGrantPathError("Duplicate objective")
        seen_objectives.add(pair)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    principal = plan["principal_ref"]
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in plan["memberships"]:
        adjacency.setdefault(edge["member_ref"], []).append((edge["edge_id"], edge["role_ref"]))
    paths: dict[str, tuple[str, ...]] = {principal: ()}
    queue = deque([principal])
    while queue:
        member = queue.popleft()
        for edge_id, role in sorted(adjacency.get(member, [])):
            if role not in paths:
                paths[role] = (*paths[member], edge_id)
                queue.append(role)
    grants: dict[tuple[str, str], list[dict]] = {}
    for row in plan["grants"]:
        grants.setdefault((row["relation_ref"], row["privilege"]), []).append(row)
    findings = []
    for objective in plan["objectives"]:
        pair = (objective["relation_ref"], objective["privilege"])
        candidates = [
            (paths[grant["grantee_ref"]], grant["edge_id"])
            for grant in grants.get(pair, [])
            if grant["grantee_ref"] in paths
        ]
        if candidates:
            membership_ids, grant_id = min(
                candidates, key=lambda item: (len(item[0]), item[0], item[1])
            )
            disposition = "supplied_grant_path"
        else:
            membership_ids, grant_id = (), None
            disposition = (
                "no_supplied_path" if plan["graph_complete"] else "unknown_incomplete_graph"
            )
        findings.append(
            {
                "relation_ref": pair[0],
                "privilege": pair[1],
                "disposition": disposition,
                "membership_edge_ids": list(membership_ids),
                "grant_edge_id": grant_id,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "database_state_verified": False,
            "role_membership_verified": False,
            "effective_privilege_proven": False,
            "real_path_absence_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Roles, memberships, grants, and graph completeness are caller-supplied.",
            "Only explicit role edges and four abstract relation privileges are projected.",
            "No ownership, deny, row policy, column, schema, inheritance, "
            "or vendor semantics are evaluated.",
            "A supplied grant path is not proof of live database access or vulnerability.",
            "No SQL, database client, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "RGP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class RelationalGrantPath:
    """Immutable report replayed from supplied roles and grants."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise RelationalGrantPathError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise RelationalGrantPathError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_relational_grants(model: Any) -> RelationalGrantPath:
    """Project explicit supplied role and relation-grant edges only."""
    return RelationalGrantPath(_derive(model))


def verify_supplied_relational_grants(report: Any, *, model: Any) -> RelationalGrantPath:
    if type(report) is not RelationalGrantPath:
        raise RelationalGrantPathError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise RelationalGrantPathError("Report differs from supplied model replay")
    return RelationalGrantPath(expected)

"""Project a supplied directory membership and grant path without directory access."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_directory_entitlement_path"
PROFILE_ID = "AOE-GC-D11-S01"
CAPABILITY_ID = "enterprise.active-directory.path-analysis"
VECTOR_ID = "AV-GC-D11-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:e4afec7d18d1adfa1b21c9586e036283a5fb6cc36c062531699e8294745cc579"
SEMANTICS_PROFILE = "supplied-directory-entitlement-path-v1"
DOMAIN = "sunderkey.offline-directory-entitlement-path.v1"
MAX_GROUPS = 64
MAX_MEMBERSHIPS = 256
MAX_GRANTS = 256
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PRINCIPAL = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
_GROUP = re.compile(r"group:sha256:[0-9a-f]{64}\Z")
_RESOURCE = re.compile(r"resource:sha256:[0-9a-f]{64}\Z")
_RIGHTS = frozenset(("declared_read", "declared_write", "declared_control"))
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class DirectoryEntitlementPathError(ValueError):
    """The supplied directory graph or report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise DirectoryEntitlementPathError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise DirectoryEntitlementPathError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise DirectoryEntitlementPathError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise DirectoryEntitlementPathError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise DirectoryEntitlementPathError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DirectoryEntitlementPathError("Native JSON text keys are required")
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
        raise DirectoryEntitlementPathError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise DirectoryEntitlementPathError(f"{label} fields are invalid")


def _reference(value: Any, expression: re.Pattern, label: str) -> str:
    if type(value) is not str or expression.fullmatch(value) is None:
        raise DirectoryEntitlementPathError(f"{label} must be an opaque digest reference")
    return value


def _id(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise DirectoryEntitlementPathError(f"{label} identifier is invalid")
    return value


def _right(value: Any) -> str:
    if type(value) is not str or value not in _RIGHTS:
        raise DirectoryEntitlementPathError("Declared right label is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "source_principal_ref",
            "graph_complete",
            "groups",
            "memberships",
            "grants",
            "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DirectoryEntitlementPathError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise DirectoryEntitlementPathError("Semantics profile is invalid")
    source = _reference(model["source_principal_ref"], _PRINCIPAL, "Source principal")
    if type(model["graph_complete"]) is not bool:
        raise DirectoryEntitlementPathError("Graph completeness must be an exact boolean")
    groups = model["groups"]
    if type(groups) is not list or len(groups) > MAX_GROUPS:
        raise DirectoryEntitlementPathError("Group count is invalid")
    known_groups: set[str] = set()
    for group in groups:
        group = _reference(group, _GROUP, "Group")
        if group in known_groups:
            raise DirectoryEntitlementPathError("Duplicate group reference")
        known_groups.add(group)
    memberships = model["memberships"]
    if type(memberships) is not list or len(memberships) > MAX_MEMBERSHIPS:
        raise DirectoryEntitlementPathError("Membership count is invalid")
    grants = model["grants"]
    if type(grants) is not list or len(grants) > MAX_GRANTS:
        raise DirectoryEntitlementPathError("Grant count is invalid")
    ids: set[str] = set()
    for membership in memberships:
        _fields(membership, {"edge_id", "member_ref", "group_ref"}, "membership")
        edge_id = _id(membership["edge_id"], "Membership")
        if edge_id in ids:
            raise DirectoryEntitlementPathError("Duplicate edge identifier")
        ids.add(edge_id)
        member = membership["member_ref"]
        if member != source:
            member = _reference(member, _GROUP, "Membership member")
            if member not in known_groups:
                raise DirectoryEntitlementPathError("Membership member is undeclared")
        group = _reference(membership["group_ref"], _GROUP, "Membership group")
        if group not in known_groups:
            raise DirectoryEntitlementPathError("Membership group is undeclared")
    for grant in grants:
        _fields(grant, {"edge_id", "grantee_ref", "resource_ref", "right_label"}, "grant")
        edge_id = _id(grant["edge_id"], "Grant")
        if edge_id in ids:
            raise DirectoryEntitlementPathError("Duplicate edge identifier")
        ids.add(edge_id)
        grantee = grant["grantee_ref"]
        if grantee != source:
            grantee = _reference(grantee, _GROUP, "Grant grantee")
            if grantee not in known_groups:
                raise DirectoryEntitlementPathError("Grant grantee is undeclared")
        _reference(grant["resource_ref"], _RESOURCE, "Resource")
        _right(grant["right_label"])
    objectives = model["objectives"]
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise DirectoryEntitlementPathError("Objective count is invalid")
    seen_objectives: set[tuple[str, str]] = set()
    for objective in objectives:
        _fields(objective, {"resource_ref", "right_label"}, "objective")
        pair = (
            _reference(objective["resource_ref"], _RESOURCE, "Objective resource"),
            _right(objective["right_label"]),
        )
        if pair in seen_objectives:
            raise DirectoryEntitlementPathError("Duplicate objective")
        seen_objectives.add(pair)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    source = plan["source_principal_ref"]
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in plan["memberships"]:
        adjacency.setdefault(edge["member_ref"], []).append((edge["edge_id"], edge["group_ref"]))
    paths: dict[str, tuple[str, ...]] = {source: ()}
    queue = deque([source])
    while queue:
        member = queue.popleft()
        for edge_id, group in sorted(adjacency.get(member, [])):
            candidate = (*paths[member], edge_id)
            if group not in paths:
                paths[group] = candidate
                queue.append(group)
    grants_by_pair: dict[tuple[str, str], list[dict]] = {}
    for grant in plan["grants"]:
        grants_by_pair.setdefault((grant["resource_ref"], grant["right_label"]), []).append(grant)
    rows = []
    for objective in plan["objectives"]:
        pair = (objective["resource_ref"], objective["right_label"])
        candidates = [
            (paths[grant["grantee_ref"]], grant["edge_id"])
            for grant in grants_by_pair.get(pair, [])
            if grant["grantee_ref"] in paths
        ]
        if candidates:
            membership_ids, grant_id = min(
                candidates, key=lambda item: (len(item[0]), item[0], item[1])
            )
            disposition = "supplied_path"
        else:
            membership_ids, grant_id = (), None
            disposition = (
                "no_supplied_path" if plan["graph_complete"] else "unknown_incomplete_graph"
            )
        rows.append(
            {
                "resource_ref": pair[0],
                "right_label": pair[1],
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
        "objectives": rows,
        "flags": {
            "directory_source_authenticated": False,
            "principal_or_group_identity_proven": False,
            "membership_or_grant_proven": False,
            "effective_access_proven": False,
            "real_path_absence_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Principal, group, membership, grant, and completeness assertions are caller-supplied.",
            "Only explicit member-of edges and three abstract right labels are projected.",
            "No deny, token, trust, inheritance, or effective-access semantics are evaluated.",
            "A supplied path is not proof of a live access path or vulnerability.",
            "No directory, credential, network, service, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "DEP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class DirectoryEntitlementPath:
    """Replay-checked local projection of supplied directory edges."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise DirectoryEntitlementPathError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise DirectoryEntitlementPathError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_directory_paths(model: Any) -> DirectoryEntitlementPath:
    """Project only declared membership-to-grant paths."""
    return DirectoryEntitlementPath(_derive(model))


def verify_supplied_directory_paths(report: Any, *, model: Any) -> DirectoryEntitlementPath:
    """Recompute a report from current supplied model bytes."""
    if type(report) is not DirectoryEntitlementPath:
        raise DirectoryEntitlementPathError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise DirectoryEntitlementPathError("Report differs from supplied model replay")
    return DirectoryEntitlementPath(expected)

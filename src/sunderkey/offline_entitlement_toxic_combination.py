"""Offline supplied entitlement-graph and toxic-pair policy projection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sunderkey import offline_framework_declaration_core as core

PROFILE_ID = "AOE-GA-D03-S14"
CAPABILITY_ID = "army.ga.d03.s14"
VECTOR_ID = "AV-GA-D03-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S14"
WAVE_ID = "IW2-015"
BLUEPRINT_SHA256 = "sha256:9c948b7552d0265cd727ecacf94cef63b20c5284e805830a2d97dd1bf2b97486"
COMPONENT_ID = "identity_supplied_entitlement_toxic_combination"
DOMAIN = "sunderkey.offline-entitlement-toxic-combination.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = core.MAX_SOURCE_BYTES
MAX_REPORT_BYTES = core.MAX_REPORT_BYTES
MAX_DEPTH = core.MAX_DEPTH
MAX_ROLES = 64
MAX_PRINCIPALS = 32
MAX_PAIRS = 32
MAX_PERMISSIONS = 64
_ASSESSMENTS = {"candidate_declared_toxic_combination", "declared_pair_not_present", "unknown"}
_BASES = {
    "both_permissions_in_supplied_closure",
    "pair_not_in_supplied_closure",
    "incomplete_premises",
}
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "process",
        "credentials",
        "provider_requests",
    )
}
_FLAGS = {
    "offline_only": True,
    "source_authenticated": False,
    "assignments_authenticated": False,
    "dynamic_grants_observed": False,
    "permission_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Roles, inheritance, grants, assignments and toxic pairs are supplied assertions.",
    "Dynamic grants or incomplete graph, assignments, grants or policy yield unknown.",
    "Only exact role inheritance and exact permission-pair membership are modeled.",
    "A candidate pair is a declared policy conflict, not proven account access or exploitation.",
    "No target, network, process, credential, provider request or live exploit occurs.",
]

EntitlementToxicCombinationError = core.FrameworkDeclarationError


def _ids(value: Any, maximum: int, label: str) -> list[str]:
    result = [core.identifier(item, label) for item in core.bounded_list(value, maximum, label)]
    if len(set(result)) != len(result):
        raise EntitlementToxicCombinationError(f"duplicate {label}")
    return result


def _model(
    document: Any,
) -> tuple[bool, dict[str, dict], dict[str, list[str]], dict[str, tuple[str, str]]]:
    item = core.exact(
        document,
        {
            "schema_version",
            "graph_complete",
            "assignments_complete",
            "grants_complete",
            "toxic_policy_complete",
            "dynamic_entitlements_absent",
            "roles",
            "principals",
            "toxic_pairs",
        },
        "model",
    )
    if type(item["schema_version"]) is not str or item["schema_version"] != SCHEMA_VERSION:
        raise EntitlementToxicCombinationError("unsupported model version")
    premises = [
        core.boolean(item[key], key)
        for key in (
            "graph_complete",
            "assignments_complete",
            "grants_complete",
            "toxic_policy_complete",
            "dynamic_entitlements_absent",
        )
    ]
    complete = all(premises)
    roles: dict[str, dict] = {}
    for raw in core.bounded_list(item["roles"], MAX_ROLES, "roles"):
        role = core.exact(raw, {"role_id", "inherits", "permissions"}, "role")
        identity = core.identifier(role["role_id"], "role ID")
        if identity in roles:
            raise EntitlementToxicCombinationError("duplicate role ID")
        roles[identity] = {
            "inherits": _ids(role["inherits"], MAX_ROLES, "inherited role ID"),
            "permissions": _ids(role["permissions"], MAX_PERMISSIONS, "permission ID"),
        }
    if any(parent not in roles for role in roles.values() for parent in role["inherits"]):
        raise EntitlementToxicCombinationError("unknown inherited role")
    visited: set[str] = set()
    active: set[str] = set()

    def visit(role_id: str) -> None:
        if role_id in active:
            raise EntitlementToxicCombinationError("role inheritance cycle is unsupported")
        if role_id in visited:
            return
        active.add(role_id)
        for parent in roles[role_id]["inherits"]:
            visit(parent)
        active.remove(role_id)
        visited.add(role_id)

    for identity in roles:
        visit(identity)
    principals: dict[str, list[str]] = {}
    for raw in core.bounded_list(item["principals"], MAX_PRINCIPALS, "principals"):
        principal = core.exact(raw, {"principal_id", "role_ids"}, "principal")
        identity = core.identifier(principal["principal_id"], "principal ID")
        if identity in principals:
            raise EntitlementToxicCombinationError("duplicate principal ID")
        role_ids = _ids(principal["role_ids"], MAX_ROLES, "assigned role ID")
        if any(role_id not in roles for role_id in role_ids):
            raise EntitlementToxicCombinationError("unknown assigned role")
        principals[identity] = role_ids
    pairs: dict[str, tuple[str, str]] = {}
    pair_values: set[frozenset[str]] = set()
    for raw in core.bounded_list(item["toxic_pairs"], MAX_PAIRS, "toxic pairs"):
        pair = core.exact(raw, {"pair_id", "permission_a", "permission_b"}, "toxic pair")
        identity = core.identifier(pair["pair_id"], "pair ID")
        first = core.identifier(pair["permission_a"], "permission ID")
        second = core.identifier(pair["permission_b"], "permission ID")
        values = frozenset((first, second))
        if identity in pairs or len(values) != 2 or values in pair_values:
            raise EntitlementToxicCombinationError("duplicate or degenerate toxic pair")
        pair_values.add(values)
        pairs[identity] = (first, second)
    return complete, roles, principals, pairs


def _project(
    complete: bool,
    roles: dict[str, dict],
    principals: dict[str, list[str]],
    pairs: dict[str, tuple[str, str]],
) -> list[dict]:
    cache: dict[str, frozenset[str]] = {}

    def closure(role_id: str) -> frozenset[str]:
        if role_id not in cache:
            permissions = set(roles[role_id]["permissions"])
            for parent in roles[role_id]["inherits"]:
                permissions.update(closure(parent))
            cache[role_id] = frozenset(permissions)
        return cache[role_id]

    projections = []
    for principal_id, role_ids in sorted(principals.items()):
        effective = set().union(*(closure(role_id) for role_id in role_ids))
        for pair_id, (first, second) in sorted(pairs.items()):
            if not complete:
                assessment, basis = "unknown", "incomplete_premises"
            elif first in effective and second in effective:
                assessment, basis = (
                    "candidate_declared_toxic_combination",
                    "both_permissions_in_supplied_closure",
                )
            else:
                assessment, basis = "declared_pair_not_present", "pair_not_in_supplied_closure"
            projections.append(
                {
                    "principal_id": principal_id,
                    "pair_id": pair_id,
                    "permission_a": first,
                    "permission_b": second,
                    "declared_membership": (
                        [first in effective, second in effective] if complete else [None, None]
                    ),
                    "assessment": assessment,
                    "basis": basis,
                }
            )
    return projections


def _validate_report(document: Any) -> None:
    item = core.exact(
        document,
        {
            "schema_version",
            "profile_id",
            "capability_id",
            "vector_id",
            "work_package_id",
            "wave_id",
            "blueprint_sha256",
            "component_id",
            "domain",
            "source",
            "premises_complete",
            "projections",
            "summary",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
            *_FLAGS,
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "component_id": COMPONENT_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise EntitlementToxicCombinationError(f"report {key} is invalid")
    core.validate_source(item["source"])
    core.boolean(item["premises_complete"], "premises complete")
    projections = core.bounded_list(item["projections"], MAX_PRINCIPALS * MAX_PAIRS, "projections")
    keys: list[tuple[str, str]] = []
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    for raw in projections:
        p = core.exact(
            raw,
            {
                "principal_id",
                "pair_id",
                "permission_a",
                "permission_b",
                "declared_membership",
                "assessment",
                "basis",
            },
            "projection",
        )
        keys.append(
            (
                core.identifier(p["principal_id"], "principal ID"),
                core.identifier(p["pair_id"], "pair ID"),
            )
        )
        core.identifier(p["permission_a"], "permission ID")
        core.identifier(p["permission_b"], "permission ID")
        membership = core.bounded_list(p["declared_membership"], 2, "membership")
        if len(membership) != 2 or any(
            value is not None and type(value) is not bool for value in membership
        ):
            raise EntitlementToxicCombinationError("report membership is invalid")
        if not item["premises_complete"] and membership != [None, None]:
            raise EntitlementToxicCombinationError("incomplete report cannot claim membership")
        core.choice(p["basis"], _BASES, "basis")
        assessment = core.choice(p["assessment"], _ASSESSMENTS, "assessment")
        if not item["premises_complete"] and assessment != "unknown":
            raise EntitlementToxicCombinationError("incomplete report cannot claim a pair result")
        counts[assessment] += 1
    if keys != sorted(set(keys)):
        raise EntitlementToxicCombinationError("report principal-pair keys must be sorted unique")
    summary = core.exact(item["summary"], {"projection_count", "assessments"}, "summary")
    reported = core.exact(summary["assessments"], set(counts), "summary assessments")
    if (
        type(summary["projection_count"]) is not int
        or summary["projection_count"] != len(projections)
        or any(
            type(reported[key]) is not int or reported[key] != value
            for key, value in counts.items()
        )
    ):
        raise EntitlementToxicCombinationError("report summary is invalid")
    report_id, sha256 = core.report_address(item, domain=DOMAIN, prefix="ETC-")
    if item["report_id"] != report_id or item["report_sha256"] != sha256:
        raise EntitlementToxicCombinationError("report address is invalid")


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise EntitlementToxicCombinationError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EntitlementToxicCombinationError("report must be UTF-8 JSON text") from exc
    document = core.decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return core.canonical(document)


@dataclass(frozen=True, slots=True)
class EntitlementToxicCombinationReport:
    """Canonical report; exact original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(
            self
        ) is not EntitlementToxicCombinationReport or self._json != _checked_report_json(
            self._json
        ):
            raise EntitlementToxicCombinationError("canonical exact report is required")

    def to_json(self) -> str:
        if type(
            self
        ) is not EntitlementToxicCombinationReport or self._json != _checked_report_json(
            self._json
        ):
            raise EntitlementToxicCombinationError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> EntitlementToxicCombinationReport:
        if cls is not EntitlementToxicCombinationReport:
            raise EntitlementToxicCombinationError("report must be the exact report family")
        return cls(_checked_report_json(content))


def analyze_entitlement_toxic_combination(
    *, source_content: bytes, source_id: str
) -> EntitlementToxicCombinationReport:
    identity = core.identifier(source_id, "source ID")
    source = core.decode(source_content, maximum=MAX_SOURCE_BYTES)
    complete, roles, principals, pairs = _model(source)
    projections = _project(complete, roles, principals, pairs)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "component_id": COMPONENT_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": core.digest(source_content),
            "byte_count": len(source_content),
        },
        "premises_complete": complete,
        "projections": projections,
        "summary": {"projection_count": len(projections), "assessments": counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    document["report_id"], document["report_sha256"] = core.report_address(
        document, domain=DOMAIN, prefix="ETC-"
    )
    core.validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return EntitlementToxicCombinationReport(core.canonical(document))


def analyze_supplied_entitlement_toxic_combination(
    model: dict[str, Any],
) -> EntitlementToxicCombinationReport:
    core.validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = core.exact(model, {"source_id", "source"}, "component model")
    source_id = core.identifier(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_entitlement_toxic_combination(
        source_content=core.canonical(item["source"]).encode("ascii"), source_id=source_id
    )


def verify_entitlement_toxic_combination(
    report: EntitlementToxicCombinationReport, *, source_content: bytes, source_id: str
) -> EntitlementToxicCombinationReport:
    if type(report) is not EntitlementToxicCombinationReport:
        raise EntitlementToxicCombinationError("report must be the exact report family")
    loaded = EntitlementToxicCombinationReport.from_json(report.to_json())
    expected = analyze_entitlement_toxic_combination(
        source_content=source_content, source_id=source_id
    )
    if loaded.to_json() != expected.to_json():
        raise EntitlementToxicCombinationError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "graph_complete": True,
        "assignments_complete": True,
        "grants_complete": True,
        "toxic_policy_complete": True,
        "dynamic_entitlements_absent": True,
        "roles": [
            {"role_id": "approver", "inherits": ["reader"], "permissions": ["payment.approve"]},
            {"role_id": "editor", "inherits": ["reader"], "permissions": ["payment.create"]},
            {"role_id": "reader", "inherits": [], "permissions": ["payment.read"]},
        ],
        "principals": [
            {"principal_id": "alice", "role_ids": ["approver", "editor"]},
            {"principal_id": "bob", "role_ids": ["reader"]},
        ],
        "toxic_pairs": [
            {
                "pair_id": "create-approve",
                "permission_a": "payment.create",
                "permission_b": "payment.approve",
            }
        ],
    }

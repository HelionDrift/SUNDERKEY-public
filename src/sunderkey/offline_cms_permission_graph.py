"""Inert projection of supplied CMS role inheritance and permission checks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "web_supplied_cms_permission_graph_projection"
PROFILE_ID = "AOE-GB-D05-S17"
CAPABILITY_ID = "army.gb.d05.s17"
VECTOR_ID = "AV-GB-D05-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S17"
WAVE_ID = "IW2-017"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:88bf4101f1f46ed7fa6e609a34f38a53cf8ace572f60776dd5c382a7ce479c44"
DOMAIN = "sunderkey.offline-cms-permission-graph.v1"
MODEL_DOMAIN = "sunderkey.offline-cms-permission-graph-model.v1"
SEMANTICS_PROFILE = "declared-exact-role-inheritance-permission.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NODES = 16_384
MAX_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_ROLES = 64
MAX_PRINCIPALS = 64
MAX_RESOURCES = 128
MAX_CHECKS = 256
MAX_PERMISSIONS = 64
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "role_assignments_verified",
        "extension_policy_verified",
        "permission_enforcement_observed",
        "resource_access_verified",
        "exploitability_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "nodes": MAX_NODES,
    "depth": MAX_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "roles": MAX_ROLES,
    "principals": MAX_PRINCIPALS,
    "resources": MAX_RESOURCES,
    "checks": MAX_CHECKS,
    "permissions_per_role": MAX_PERMISSIONS,
}
_LIMITATIONS = [
    "Platform, roles, grants, assignments and outcomes are supplied assertions.",
    "Only exact role inheritance and one required permission per resource are modeled.",
    "Plugin hooks, context, explicit denies, tenants and runtime behavior are not inferred.",
    "Graph, assignments, extensions, resource policy and enforcement scope must be complete.",
    "Declared deny with supplied allow is a candidate, not observed access bypass.",
    "A declared allow paired with supplied deny is not a security-bypass candidate.",
    "No CMS, plugin, low-code runtime, credential, network, process or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
]


class CmsPermissionGraphAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied permission graph/report."""


def _measure(value: Any, depth: int = 1, active: set[int] | None = None) -> int:
    if active is None:
        active = set()
    if depth > MAX_DEPTH:
        raise CmsPermissionGraphAnalysisError("Native depth bound exceeded")
    kind = type(value)
    if kind is str:
        if len(value.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or not all(
            32 <= ord(char) <= 126 for char in value
        ):
            raise CmsPermissionGraphAnalysisError("Bounded printable ASCII text required")
        return 1
    if kind is int:
        if not -(2**63) <= value < 2**63:
            raise CmsPermissionGraphAnalysisError("Signed 64-bit integer required")
        return 1
    if kind in (bool, type(None)):
        return 1
    if kind not in (dict, list) or id(value) in active:
        raise CmsPermissionGraphAnalysisError("Exact acyclic JSON primitives required")
    active.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise CmsPermissionGraphAnalysisError("Native text keys required")
            count = 1 + sum(
                _measure(key, depth + 1, active) + _measure(child, depth + 1, active)
                for key, child in value.items()
            )
        else:
            count = 1 + sum(_measure(child, depth + 1, active) for child in value)
    finally:
        active.remove(id(value))
    if count > MAX_NODES:
        raise CmsPermissionGraphAnalysisError("Native node bound exceeded")
    return count


def _serialize(value: Any) -> str:
    _measure(value)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise CmsPermissionGraphAnalysisError("Document byte bound exceeded")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise CmsPermissionGraphAnalysisError("Bounded ASCII JSON required")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in rows:
            if key in result:
                raise CmsPermissionGraphAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20:
            raise CmsPermissionGraphAnalysisError("Integer bound exceeded")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise CmsPermissionGraphAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_token: str) -> None:
        raise CmsPermissionGraphAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, CmsPermissionGraphAnalysisError):
            raise
        raise CmsPermissionGraphAnalysisError("Malformed supplied JSON") from exc
    _serialize(value)
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise CmsPermissionGraphAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None or value == "unknown":
        raise CmsPermissionGraphAnalysisError("Bounded exact identity required")
    return value


def _rows(value: Any, field: str, limit: int, label: str) -> list:
    if type(value) is not list or not 1 <= len(value) <= limit:
        raise CmsPermissionGraphAnalysisError(f"Bounded nonempty {label} list required")
    ids = [_identity(row[field]) for row in value if type(row) is dict and field in row]
    if len(ids) != len(value) or ids != sorted(set(ids)):
        raise CmsPermissionGraphAnalysisError(f"Sorted unique {label} identities required")
    return value


def _ids(value: Any, limit: int, label: str) -> list[str]:
    if type(value) is not list or len(value) > limit:
        raise CmsPermissionGraphAnalysisError(f"Bounded {label} list required")
    for item in value:
        _identity(item)
    if value != sorted(set(value)):
        raise CmsPermissionGraphAnalysisError(f"Sorted unique {label} values required")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise CmsPermissionGraphAnalysisError(f"Native {label} Boolean required")
    return value


def _validate_model(model: Any) -> dict:
    owned = _decode(_serialize(model))
    _exact(
        owned,
        {
            "schema_version",
            "platform_kind",
            "graph_complete",
            "policy_extensions_complete",
            "roles",
            "principals",
            "resources",
            "checks",
        },
        "model",
    )
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise CmsPermissionGraphAnalysisError("Exact schema version 1 required")
    if type(owned["platform_kind"]) is not str or owned["platform_kind"] not in (
        "cms",
        "plugin",
        "low_code",
    ):
        raise CmsPermissionGraphAnalysisError("Supported platform label required")
    _boolean(owned["graph_complete"], "graph completeness")
    _boolean(owned["policy_extensions_complete"], "extension policy completeness")
    roles = _rows(owned["roles"], "role_id", MAX_ROLES, "role")
    principals = _rows(owned["principals"], "principal_id", MAX_PRINCIPALS, "principal")
    resources = _rows(owned["resources"], "resource_id", MAX_RESOURCES, "resource")
    checks = _rows(owned["checks"], "check_id", MAX_CHECKS, "check")
    role_ids = {row["role_id"] for row in roles}
    principal_ids = {row["principal_id"] for row in principals}
    resource_ids = {row["resource_id"] for row in resources}
    role_by_id = {}
    for role in roles:
        _exact(role, {"role_id", "inherits", "grants"}, "role")
        _ids(role["inherits"], MAX_ROLES, "inheritance")
        _ids(role["grants"], MAX_PERMISSIONS, "permission grant")
        if any(parent not in role_ids for parent in role["inherits"]):
            raise CmsPermissionGraphAnalysisError("Unknown inherited role")
        role_by_id[role["role_id"]] = role
    visited: set[str] = set()
    active: set[str] = set()

    def visit(role_id: str) -> None:
        if role_id in active:
            raise CmsPermissionGraphAnalysisError("Role inheritance cycle unsupported")
        if role_id in visited:
            return
        active.add(role_id)
        for parent in role_by_id[role_id]["inherits"]:
            visit(parent)
        active.remove(role_id)
        visited.add(role_id)

    for role_id in sorted(role_ids):
        visit(role_id)
    for principal in principals:
        _exact(principal, {"principal_id", "roles", "assignments_complete"}, "principal")
        _ids(principal["roles"], MAX_ROLES, "assigned role")
        if any(role_id not in role_ids for role_id in principal["roles"]):
            raise CmsPermissionGraphAnalysisError("Unknown assigned role")
        _boolean(principal["assignments_complete"], "assignment completeness")
    for resource in resources:
        _exact(resource, {"resource_id", "required_permission", "policy_complete"}, "resource")
        _identity(resource["required_permission"])
        _boolean(resource["policy_complete"], "resource policy completeness")
    for check in checks:
        _exact(
            check,
            {
                "check_id",
                "principal_id",
                "resource_id",
                "supplied_outcome",
                "observation_complete",
                "enforcement_scope_complete",
            },
            "check",
        )
        if _identity(check["principal_id"]) not in principal_ids:
            raise CmsPermissionGraphAnalysisError("Unknown check principal")
        if _identity(check["resource_id"]) not in resource_ids:
            raise CmsPermissionGraphAnalysisError("Unknown check resource")
        if type(check["supplied_outcome"]) is not str or check["supplied_outcome"] not in (
            "allowed",
            "denied",
            "unknown",
        ):
            raise CmsPermissionGraphAnalysisError("Supported supplied outcome required")
        _boolean(check["observation_complete"], "observation completeness")
        _boolean(check["enforcement_scope_complete"], "enforcement scope completeness")
    return owned


def _grants(
    role_id: str, roles: dict[str, dict], cache: dict[str, frozenset[str]]
) -> frozenset[str]:
    if role_id not in cache:
        collected = set(roles[role_id]["grants"])
        for parent in roles[role_id]["inherits"]:
            collected.update(_grants(parent, roles, cache))
        cache[role_id] = frozenset(collected)
    return cache[role_id]


def _observe(
    check: dict, principal: dict, resource: dict, model: dict, effective: set[str]
) -> dict:
    reasons = []
    if not model["graph_complete"]:
        reasons.append("role_graph_incomplete")
    if not model["policy_extensions_complete"]:
        reasons.append("extension_policy_incomplete")
    if not principal["assignments_complete"]:
        reasons.append("principal_assignments_incomplete")
    if not resource["policy_complete"]:
        reasons.append("resource_policy_incomplete")
    if not check["enforcement_scope_complete"]:
        reasons.append("enforcement_scope_incomplete")
    if not check["observation_complete"] or check["supplied_outcome"] == "unknown":
        reasons.append("supplied_outcome_unknown")
    expected = (
        None if reasons else ("allow" if resource["required_permission"] in effective else "deny")
    )
    if expected is None:
        outcome = "unknown"
    elif expected == "deny" and check["supplied_outcome"] == "allowed":
        outcome = "candidate_declared_deny_allowed_contradiction"
    elif expected == "allow" and check["supplied_outcome"] == "denied":
        outcome = "declared_allow_denied_contradiction"
    else:
        outcome = "matches_declared_permission_graph"
    return {
        "check_id": check["check_id"],
        "principal_id": check["principal_id"],
        "resource_id": check["resource_id"],
        "required_permission": resource["required_permission"],
        "effective_permissions": sorted(effective),
        "expected_outcome": expected,
        "supplied_outcome": check["supplied_outcome"],
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    owned = _validate_model(model)
    roles = {row["role_id"]: row for row in owned["roles"]}
    principals = {row["principal_id"]: row for row in owned["principals"]}
    resources = {row["resource_id"]: row for row in owned["resources"]}
    cache: dict[str, frozenset[str]] = {}
    effective = {
        principal_id: set().union(*(_grants(role, roles, cache) for role in principal["roles"]))
        for principal_id, principal in principals.items()
    }
    observations = [
        _observe(
            row,
            principals[row["principal_id"]],
            resources[row["resource_id"]],
            owned,
            effective[row["principal_id"]],
        )
        for row in owned["checks"]
    ]
    body = {
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
        "source_model": owned,
        "source_model_sha256": _address(MODEL_DOMAIN, _serialize(owned)),
        "check_count": len(observations),
        "candidate_count": sum(
            row["outcome"] == "candidate_declared_deny_allowed_contradiction"
            for row in observations
        ),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "check_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    digest = _address(DOMAIN, _serialize(body))
    body["analysis_id"] = "CPG-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body)
    return body


def _replay(document: Any) -> dict:
    owned = _decode(_serialize(document))
    if type(owned) is not dict or "source_model" not in owned:
        raise CmsPermissionGraphAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if _serialize(owned) != _serialize(expected):
        raise CmsPermissionGraphAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class CmsPermissionGraphAnalysis:
    """Detached permission-graph comparison, not CMS-runtime evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> CmsPermissionGraphAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> CmsPermissionGraphAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())


def analyze_supplied_cms_permission_graph(model: Any) -> CmsPermissionGraphAnalysis:
    """Compare supplied role-derived grants to supplied resource outcomes."""
    return CmsPermissionGraphAnalysis(_derive(model))


def analyze_supplied_cms_permission_graph_bytes(*, model_bytes: Any) -> CmsPermissionGraphAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise CmsPermissionGraphAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise CmsPermissionGraphAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_cms_permission_graph(_decode(text))


def verify_supplied_cms_permission_graph_analysis(
    report: Any, *, model: Any
) -> CmsPermissionGraphAnalysis:
    if type(report) is not CmsPermissionGraphAnalysis:
        raise CmsPermissionGraphAnalysisError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != _serialize(expected):
        raise CmsPermissionGraphAnalysisError("Report differs from separately supplied originals")
    return CmsPermissionGraphAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic inherited grant, missing grant and incomplete extension."""
    return {
        "schema_version": 1,
        "platform_kind": "cms",
        "graph_complete": True,
        "policy_extensions_complete": True,
        "roles": [
            {"role_id": "editor", "inherits": ["reader"], "grants": ["content.edit"]},
            {"role_id": "reader", "inherits": [], "grants": ["content.read"]},
        ],
        "principals": [
            {"principal_id": "alice", "roles": ["editor"], "assignments_complete": True},
            {"principal_id": "bob", "roles": ["reader"], "assignments_complete": True},
        ],
        "resources": [
            {
                "resource_id": "draft",
                "required_permission": "content.edit",
                "policy_complete": True,
            },
            {
                "resource_id": "index",
                "required_permission": "content.read",
                "policy_complete": True,
            },
        ],
        "checks": [
            {
                "check_id": "alice-inherited",
                "principal_id": "alice",
                "resource_id": "index",
                "supplied_outcome": "allowed",
                "observation_complete": True,
                "enforcement_scope_complete": True,
            },
            {
                "check_id": "bob-edit",
                "principal_id": "bob",
                "resource_id": "draft",
                "supplied_outcome": "allowed",
                "observation_complete": True,
                "enforcement_scope_complete": True,
            },
            {
                "check_id": "bob-unknown",
                "principal_id": "bob",
                "resource_id": "index",
                "supplied_outcome": "unknown",
                "observation_complete": False,
                "enforcement_scope_complete": True,
            },
        ],
    }


__all__ = [
    "CmsPermissionGraphAnalysisError",
    "CmsPermissionGraphAnalysis",
    "analyze_supplied_cms_permission_graph",
    "analyze_supplied_cms_permission_graph_bytes",
    "verify_supplied_cms_permission_graph_analysis",
    "component_fixture",
]

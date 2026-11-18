"""Inert comparison of supplied NoSQL exact grants and admission decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "data_supplied_nosql_access_grants_projection"
PROFILE_ID = "AOE-GB-D07-S02"
CAPABILITY_ID = "army.gb.d07.s02"
VECTOR_ID = "AV-GB-D07-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D07-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:7b513d9c1c6725d032d32152eb4db063f6aee68bbcc8ba34a0b475048421291b"
DOMAIN = "sunderkey.offline-nosql-access-grants.v1"
MODEL_DOMAIN = "sunderkey.offline-nosql-access-grants-model.v1"
SEMANTICS_PROFILE = "declared-exact-principal-role-collection-action.v1"
MAX_DOCUMENT_BYTES = 131_072
MAX_NODES = 16_384
MAX_DEPTH = 14
MAX_STRING_BYTES = 256
MAX_ROLES = 64
MAX_PRINCIPALS = 64
MAX_COLLECTIONS = 64
MAX_GRANTS = 128
MAX_CHECKS = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_ACTIONS = ("read", "write", "delete")
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "role_membership_verified",
        "grant_policy_verified",
        "database_admission_observed",
        "collection_access_verified",
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
    "collections": MAX_COLLECTIONS,
    "grants_per_role_or_principal": MAX_GRANTS,
    "checks": MAX_CHECKS,
}
_LIMITATIONS = [
    "Roles, memberships, direct grants, alternate paths and decisions are caller declarations.",
    "Only exact collection and read, write or delete action pairs are modeled.",
    "Wildcard, dynamic, conditional, inherited and document-level rules are not inferred.",
    "Complete role and direct grants, alternate paths and check premises are required.",
    "A declared deny paired with supplied allow is a candidate, not observed database access.",
    "A declared allow paired with supplied deny is not a bypass candidate.",
    "No database, credential, network, process, provider or target is contacted.",
    "No authority, qualification, positive use or live finding is established.",
]


class NoSqlAccessGrantsAnalysisError(ValueError):
    """Invalid, unsupported or over-budget supplied NoSQL model/report."""


def _measure(value: Any, depth: int = 1, active: set[int] | None = None) -> int:
    if active is None:
        active = set()
    if depth > MAX_DEPTH:
        raise NoSqlAccessGrantsAnalysisError("Native depth bound exceeded")
    kind = type(value)
    if kind is str:
        if len(value.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES or not all(
            32 <= ord(char) <= 126 for char in value
        ):
            raise NoSqlAccessGrantsAnalysisError("Bounded printable ASCII text required")
        return 1
    if kind is int:
        if not -(2**63) <= value < 2**63:
            raise NoSqlAccessGrantsAnalysisError("Signed 64-bit integer required")
        return 1
    if kind in (bool, type(None)):
        return 1
    if kind not in (dict, list) or id(value) in active:
        raise NoSqlAccessGrantsAnalysisError("Exact acyclic JSON primitives required")
    active.add(id(value))
    try:
        if kind is dict:
            if any(type(key) is not str for key in value):
                raise NoSqlAccessGrantsAnalysisError("Native text keys required")
            count = 1 + sum(
                _measure(key, depth + 1, active) + _measure(child, depth + 1, active)
                for key, child in value.items()
            )
        else:
            count = 1 + sum(_measure(child, depth + 1, active) for child in value)
    finally:
        active.remove(id(value))
    if count > MAX_NODES:
        raise NoSqlAccessGrantsAnalysisError("Native node bound exceeded")
    return count


def _serialize(value: Any) -> str:
    _measure(value)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise NoSqlAccessGrantsAnalysisError("Document byte bound exceeded")
    return text


def _decode(text: Any) -> Any:
    if type(text) is not str or not text or len(text) > MAX_DOCUMENT_BYTES or not text.isascii():
        raise NoSqlAccessGrantsAnalysisError("Bounded ASCII JSON required")

    def pairs(rows: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in rows:
            if key in result:
                raise NoSqlAccessGrantsAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20:
            raise NoSqlAccessGrantsAnalysisError("Integer bound exceeded")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise NoSqlAccessGrantsAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_token: str) -> None:
        raise NoSqlAccessGrantsAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, NoSqlAccessGrantsAnalysisError):
            raise
        raise NoSqlAccessGrantsAnalysisError("Malformed supplied JSON") from exc
    _serialize(value)
    return value


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise NoSqlAccessGrantsAnalysisError(f"Exact closed {label} fields required")
    return value


def _identity(value: Any) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None or value == "unknown":
        raise NoSqlAccessGrantsAnalysisError("Bounded exact identity required")
    return value


def _rows(value: Any, field: str, limit: int, label: str) -> list:
    if type(value) is not list or not 1 <= len(value) <= limit:
        raise NoSqlAccessGrantsAnalysisError(f"Bounded nonempty {label} list required")
    ids = [_identity(row[field]) for row in value if type(row) is dict and field in row]
    if len(ids) != len(value) or ids != sorted(set(ids)):
        raise NoSqlAccessGrantsAnalysisError(f"Sorted unique {label} IDs required")
    return value


def _ids(value: Any, limit: int, label: str) -> list[str]:
    if type(value) is not list or len(value) > limit:
        raise NoSqlAccessGrantsAnalysisError(f"Bounded {label} list required")
    for item in value:
        _identity(item)
    if value != sorted(set(value)):
        raise NoSqlAccessGrantsAnalysisError(f"Sorted unique {label} IDs required")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise NoSqlAccessGrantsAnalysisError(f"Native {label} Boolean required")
    return value


def _grant_pairs(value: Any, collections: list[str]) -> set[tuple[str, str]]:
    if type(value) is not list or len(value) > MAX_GRANTS:
        raise NoSqlAccessGrantsAnalysisError("Bounded grant list required")
    pairs = []
    for grant in value:
        _exact(grant, {"collection_id", "action"}, "grant")
        collection_id = _identity(grant["collection_id"])
        if collection_id not in collections:
            raise NoSqlAccessGrantsAnalysisError("Unknown grant collection")
        if type(grant["action"]) is not str or grant["action"] not in _ACTIONS:
            raise NoSqlAccessGrantsAnalysisError("Supported exact action required")
        pairs.append((collection_id, grant["action"]))
    if pairs != sorted(set(pairs)):
        raise NoSqlAccessGrantsAnalysisError("Sorted unique exact grants required")
    return set(pairs)


def _validate_model(model: Any) -> dict:
    owned = _decode(_serialize(model))
    _exact(
        owned,
        {
            "schema_version",
            "grants_complete",
            "alternate_grant_paths_complete",
            "collections_complete",
            "collections",
            "roles",
            "principals",
            "checks",
        },
        "model",
    )
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise NoSqlAccessGrantsAnalysisError("Exact schema version 1 required")
    _boolean(owned["grants_complete"], "grant completeness")
    _boolean(owned["alternate_grant_paths_complete"], "alternate grant path completeness")
    _boolean(owned["collections_complete"], "collection completeness")
    collections = _ids(owned["collections"], MAX_COLLECTIONS, "collection")
    roles = _rows(owned["roles"], "role_id", MAX_ROLES, "role")
    principals = _rows(owned["principals"], "principal_id", MAX_PRINCIPALS, "principal")
    checks = _rows(owned["checks"], "check_id", MAX_CHECKS, "check")
    role_ids = {row["role_id"] for row in roles}
    principal_ids = {row["principal_id"] for row in principals}
    for role in roles:
        _exact(role, {"role_id", "grants", "policy_complete"}, "role")
        _boolean(role["policy_complete"], "role policy completeness")
        _grant_pairs(role["grants"], collections)
    for principal in principals:
        _exact(
            principal,
            {
                "principal_id",
                "role_ids",
                "membership_complete",
                "direct_grants",
                "direct_grants_complete",
            },
            "principal",
        )
        _ids(principal["role_ids"], MAX_ROLES, "principal role")
        if any(role_id not in role_ids for role_id in principal["role_ids"]):
            raise NoSqlAccessGrantsAnalysisError("Unknown principal role")
        _boolean(principal["membership_complete"], "membership completeness")
        _boolean(principal["direct_grants_complete"], "direct grant completeness")
        _grant_pairs(principal["direct_grants"], collections)
    for check in checks:
        _exact(
            check,
            {
                "check_id",
                "principal_id",
                "collection_id",
                "action",
                "policy_mode",
                "supplied_decision",
                "context_complete",
                "observation_complete",
            },
            "check",
        )
        if _identity(check["principal_id"]) not in principal_ids:
            raise NoSqlAccessGrantsAnalysisError("Unknown check principal")
        if _identity(check["collection_id"]) not in collections:
            raise NoSqlAccessGrantsAnalysisError("Unknown check collection")
        if type(check["action"]) is not str or check["action"] not in _ACTIONS:
            raise NoSqlAccessGrantsAnalysisError("Supported exact action required")
        if type(check["policy_mode"]) is not str or check["policy_mode"] not in (
            "exact",
            "wildcard_or_dynamic",
        ):
            raise NoSqlAccessGrantsAnalysisError("Supported policy mode required")
        if type(check["supplied_decision"]) is not str or check["supplied_decision"] not in (
            "allow",
            "deny",
            "unknown",
        ):
            raise NoSqlAccessGrantsAnalysisError("Supported supplied decision required")
        _boolean(check["context_complete"], "check context completeness")
        _boolean(check["observation_complete"], "observation completeness")
    return owned


def _observe(check: dict, principal: dict, roles: dict, model: dict) -> dict:
    reasons = []
    if not model["grants_complete"]:
        reasons.append("grant_inventory_incomplete")
    if not model["alternate_grant_paths_complete"]:
        reasons.append("alternate_grant_paths_incomplete")
    if not model["collections_complete"]:
        reasons.append("collection_inventory_incomplete")
    if not principal["membership_complete"]:
        reasons.append("role_membership_incomplete")
    if not principal["direct_grants_complete"]:
        reasons.append("direct_grants_incomplete")
    if any(not roles[role_id]["policy_complete"] for role_id in principal["role_ids"]):
        reasons.append("assigned_role_policy_incomplete")
    if check["policy_mode"] != "exact":
        reasons.append("wildcard_or_dynamic_policy")
    if not check["context_complete"]:
        reasons.append("check_context_incomplete")
    if not check["observation_complete"] or check["supplied_decision"] == "unknown":
        reasons.append("supplied_decision_unknown")
    pair = (check["collection_id"], check["action"])
    matched = sorted(
        role_id
        for role_id in principal["role_ids"]
        if pair in {(grant["collection_id"], grant["action"]) for grant in roles[role_id]["grants"]}
    )
    direct_matched = pair in {
        (grant["collection_id"], grant["action"]) for grant in principal["direct_grants"]
    }
    expected = None if reasons else ("allow" if matched or direct_matched else "deny")
    if expected is None:
        outcome = "unknown"
    elif expected == "deny" and check["supplied_decision"] == "allow":
        outcome = "candidate_declared_deny_allowed_contradiction"
    elif expected == "allow" and check["supplied_decision"] == "deny":
        outcome = "declared_allow_denied_contradiction"
    else:
        outcome = "matches_declared_grants"
    return {
        "check_id": check["check_id"],
        "principal_id": check["principal_id"],
        "collection_id": check["collection_id"],
        "action": check["action"],
        "matched_role_ids": matched,
        "direct_grant_matched": direct_matched,
        "expected_decision": expected,
        "supplied_decision": check["supplied_decision"],
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    owned = _validate_model(model)
    roles = {row["role_id"]: row for row in owned["roles"]}
    principals = {row["principal_id"]: row for row in owned["principals"]}
    observations = [
        _observe(row, principals[row["principal_id"]], roles, owned) for row in owned["checks"]
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
    body["analysis_id"] = "NAG-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body)
    return body


def _replay(document: Any) -> dict:
    owned = _decode(_serialize(document))
    if type(owned) is not dict or "source_model" not in owned:
        raise NoSqlAccessGrantsAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if _serialize(owned) != _serialize(expected):
        raise NoSqlAccessGrantsAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class NoSqlAccessGrantsAnalysis:
    """Detached grant comparison, not database-admission evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> NoSqlAccessGrantsAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> NoSqlAccessGrantsAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())


def analyze_supplied_nosql_access_grants(model: Any) -> NoSqlAccessGrantsAnalysis:
    """Compare bounded supplied exact collection-action grants and decisions."""
    return NoSqlAccessGrantsAnalysis(_derive(model))


def analyze_supplied_nosql_access_grants_bytes(*, model_bytes: Any) -> NoSqlAccessGrantsAnalysis:
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise NoSqlAccessGrantsAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise NoSqlAccessGrantsAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_nosql_access_grants(_decode(text))


def verify_supplied_nosql_access_grants_analysis(
    report: Any, *, model: Any
) -> NoSqlAccessGrantsAnalysis:
    if type(report) is not NoSqlAccessGrantsAnalysis:
        raise NoSqlAccessGrantsAnalysisError("Exact native report family required")
    expected = _derive(model)
    if report.to_json() != _serialize(expected):
        raise NoSqlAccessGrantsAnalysisError("Report differs from separately supplied originals")
    return NoSqlAccessGrantsAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic exact grant match, contradiction and unknown rule."""
    return {
        "schema_version": 1,
        "grants_complete": True,
        "alternate_grant_paths_complete": True,
        "collections_complete": True,
        "collections": ["accounts", "audit"],
        "roles": [
            {
                "role_id": "reader",
                "grants": [{"collection_id": "accounts", "action": "read"}],
                "policy_complete": True,
            }
        ],
        "principals": [
            {
                "principal_id": "alice",
                "role_ids": ["reader"],
                "membership_complete": True,
                "direct_grants": [],
                "direct_grants_complete": True,
            }
        ],
        "checks": [
            {
                "check_id": "allowed-read",
                "principal_id": "alice",
                "collection_id": "accounts",
                "action": "read",
                "policy_mode": "exact",
                "supplied_decision": "allow",
                "context_complete": True,
                "observation_complete": True,
            },
            {
                "check_id": "candidate-delete",
                "principal_id": "alice",
                "collection_id": "accounts",
                "action": "delete",
                "policy_mode": "exact",
                "supplied_decision": "allow",
                "context_complete": True,
                "observation_complete": True,
            },
            {
                "check_id": "unknown-rule",
                "principal_id": "alice",
                "collection_id": "audit",
                "action": "read",
                "policy_mode": "wildcard_or_dynamic",
                "supplied_decision": "allow",
                "context_complete": True,
                "observation_complete": True,
            },
        ],
    }


__all__ = [
    "NoSqlAccessGrantsAnalysisError",
    "NoSqlAccessGrantsAnalysis",
    "analyze_supplied_nosql_access_grants",
    "analyze_supplied_nosql_access_grants_bytes",
    "verify_supplied_nosql_access_grants_analysis",
    "component_fixture",
]

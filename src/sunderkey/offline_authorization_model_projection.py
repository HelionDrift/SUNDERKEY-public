"""Evaluate declared RBAC, ABAC and ReBAC rules over inert supplied facts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_authorization_model_projection"
PROFILE_ID = "AOE-GA-D03-S13"
CAPABILITY_ID = "identity.authorization.rbac-abac-rebac"
VECTOR_ID = "AV-GA-D03-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S13"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a96131eed00385045b71c23dff36c7d4df3ccfce424b22968e0cc91b2856e95c"
DOMAIN = "sunderkey.offline-authorization-model-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_PRINCIPALS = 64
MAX_RESOURCES = 128
MAX_RELATIONS = 512
MAX_RULES = 256
MAX_OBSERVATIONS = 512
MAX_ATTRIBUTES = 32
MAX_ROLES = 32
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AuthorizationModelProjectionError(ValueError):
    """A supplied policy model or independent replay is invalid."""


def _rows(value: Any, maximum: int, label: str) -> list[dict]:
    return core.bounded_list(value, maximum, label)


def _attributes(value: Any, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _rows(value, MAX_ATTRIBUTES, label):
        row = core.exact(item, {"name", "value"}, label)
        name = core.identifier(row["name"], "attribute name")
        if name in result:
            raise AuthorizationModelProjectionError("Duplicate attribute name")
        result[name] = core.identifier(row["value"], "attribute value")
    return result


def _predicate(value: Any, label: str) -> tuple[str, str] | None:
    if value is None:
        return None
    row = core.exact(value, {"name", "value"}, label)
    return (
        core.identifier(row["name"], "predicate name"),
        core.identifier(row["value"], "predicate value"),
    )


def _model(value: Any) -> tuple[dict, dict, dict, set[tuple[str, str, str]]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "roles_complete",
            "attributes_complete", "relations_complete", "principals", "resources",
            "relations", "rules", "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AuthorizationModelProjectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    for field in (
        "policy_complete", "roles_complete", "attributes_complete", "relations_complete",
    ):
        core.boolean(model[field], field)
    principals: dict[str, dict] = {}
    for item in _rows(model["principals"], MAX_PRINCIPALS, "principals"):
        row = core.exact(item, {"principal_id", "roles", "attributes"}, "principal")
        principal_id = core.identifier(row["principal_id"], "principal ID")
        if principal_id in principals:
            raise AuthorizationModelProjectionError("Duplicate principal ID")
        roles = [
            core.identifier(role, "role")
            for role in _rows(row["roles"], MAX_ROLES, "roles")
        ]
        if len(roles) != len(set(roles)):
            raise AuthorizationModelProjectionError("Duplicate principal role")
        principals[principal_id] = {
            "roles": set(roles),
            "attributes": _attributes(row["attributes"], "principal attributes"),
        }
    resources: dict[str, dict] = {}
    for item in _rows(model["resources"], MAX_RESOURCES, "resources"):
        row = core.exact(item, {"resource_id", "attributes"}, "resource")
        resource_id = core.identifier(row["resource_id"], "resource ID")
        if resource_id in resources:
            raise AuthorizationModelProjectionError("Duplicate resource ID")
        resources[resource_id] = _attributes(row["attributes"], "resource attributes")
    relations: set[tuple[str, str, str]] = set()
    for item in _rows(model["relations"], MAX_RELATIONS, "relations"):
        row = core.exact(item, {"principal_id", "relation", "resource_id"}, "relation")
        edge = (
            core.identifier(row["principal_id"], "relation principal ID"),
            core.identifier(row["relation"], "relation name"),
            core.identifier(row["resource_id"], "relation resource ID"),
        )
        if edge[0] not in principals or edge[2] not in resources or edge in relations:
            raise AuthorizationModelProjectionError("Relation is dangling or duplicated")
        relations.add(edge)
    rule_ids: set[str] = set()
    for item in _rows(model["rules"], MAX_RULES, "rules"):
        row = core.exact(
            item,
            {
                "rule_id", "effect", "action", "role", "principal_attribute",
                "resource_attribute", "relation",
            },
            "rule",
        )
        rule_id = core.identifier(row["rule_id"], "rule ID")
        if rule_id in rule_ids:
            raise AuthorizationModelProjectionError("Duplicate rule ID")
        rule_ids.add(rule_id)
        core.choice(row["effect"], {"allow", "deny"}, "rule effect")
        core.identifier(row["action"], "rule action")
        if row["role"] is not None:
            core.identifier(row["role"], "rule role")
        _predicate(row["principal_attribute"], "principal predicate")
        _predicate(row["resource_attribute"], "resource predicate")
        if row["relation"] is not None:
            core.identifier(row["relation"], "rule relation")
    observation_ids: set[str] = set()
    for item in _rows(model["observations"], MAX_OBSERVATIONS, "observations"):
        row = core.exact(
            item,
            {"observation_id", "principal_id", "resource_id", "action", "reported_outcome"},
            "observation",
        )
        observation_id = core.identifier(row["observation_id"], "observation ID")
        if observation_id in observation_ids:
            raise AuthorizationModelProjectionError("Duplicate observation ID")
        observation_ids.add(observation_id)
        if row["principal_id"] not in principals or row["resource_id"] not in resources:
            raise AuthorizationModelProjectionError("Observation references absent facts")
        core.identifier(row["action"], "observation action")
        core.choice(row["reported_outcome"], {"allowed", "denied", "unknown"}, "reported outcome")
    return model, principals, resources, relations


def _condition(
    expected: str | None, actual: bool, complete: bool,
) -> bool | None:
    if expected is None or actual:
        return True
    return False if complete else None


def _attribute_condition(
    predicate: dict | None, attributes: dict[str, str], complete: bool,
) -> bool | None:
    if predicate is None:
        return True
    actual = attributes.get(predicate["name"])
    if actual is None:
        return False if complete else None
    return actual == predicate["value"]


def _match(
    rule: dict, observation: dict, principal: dict, resource: dict,
    relations: set[tuple[str, str, str]], model: dict,
) -> bool | None:
    if rule["action"] != observation["action"]:
        return False
    conditions = (
        _condition(
            rule["role"],
            rule["role"] in principal["roles"],
            model["roles_complete"],
        ),
        _attribute_condition(
            rule["principal_attribute"], principal["attributes"],
            model["attributes_complete"],
        ),
        _attribute_condition(
            rule["resource_attribute"], resource,
            model["attributes_complete"],
        ),
        _condition(
            rule["relation"],
            (
                observation["principal_id"], rule["relation"], observation["resource_id"]
            ) in relations,
            model["relations_complete"],
        ),
    )
    if False in conditions:
        return False
    return None if None in conditions else True


def _projection(
    observation: dict, model: dict, principals: dict, resources: dict,
    relations: set[tuple[str, str, str]],
) -> dict:
    definite: list[dict] = []
    possible: list[dict] = []
    for rule in model["rules"]:
        match = _match(
            rule, observation, principals[observation["principal_id"]],
            resources[observation["resource_id"]], relations, model,
        )
        if match is True:
            definite.append(rule)
        elif match is None:
            possible.append(rule)
    effects = {rule["effect"] for rule in definite}
    possible_effects = {rule["effect"] for rule in possible}
    if not model["policy_complete"]:
        decision, basis = "unknown", "incomplete_policy"
    elif len(effects) > 1:
        decision, basis = "unknown", "conflicting_rules"
    elif possible_effects - effects:
        decision, basis = "unknown", "unresolved_rule_conditions"
    elif effects:
        decision = next(iter(effects))
        basis = "matched_rule"
    elif possible:
        decision, basis = "unknown", "unresolved_rule_conditions"
    else:
        decision, basis = "deny", "complete_default_deny"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif (decision == "allow") == (reported == "allowed"):
        assessment = "declared_consistent"
    else:
        assessment = "candidate_declared_policy_conflict"
    return {
        "observation_id": observation["observation_id"],
        "principal_id": observation["principal_id"],
        "resource_id": observation["resource_id"],
        "action": observation["action"],
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
        "matching_rule_ids": sorted(rule["rule_id"] for rule in definite),
        "possible_rule_ids": sorted(rule["rule_id"] for rule in possible),
    }


def _derive(value: Any) -> dict:
    model, principals, resources, relations = _model(value)
    projections = [
        _projection(item, model, principals, resources, relations)
        for item in model["observations"]
    ]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "observation_count": len(projections),
            "candidate_count": sum(
                row["assessment"] == "candidate_declared_policy_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "reported_outcomes_authenticated": False,
        "effective_access_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Principals, roles, attributes, relations, rules and outcomes are caller declarations.",
            "Only direct principal-resource relations are evaluated; no graph expansion occurs.",
            "Completeness flags do not authenticate facts or prove deployed policy coverage.",
            "A candidate mismatch is not proof of effective access or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="AMP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AuthorizationModelProjectionReport:
    """Unsigned result that requires independent original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AuthorizationModelProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AuthorizationModelProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_authorization_model(model: Any) -> AuthorizationModelProjectionReport:
    """Project supplied policy facts without executing or authenticating them."""
    try:
        return AuthorizationModelProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise AuthorizationModelProjectionError(str(exc)) from exc


def verify_supplied_authorization_model(
    report: Any, *, model: Any,
) -> AuthorizationModelProjectionReport:
    if type(report) is not AuthorizationModelProjectionReport:
        raise AuthorizationModelProjectionError("Exact report wrapper required")
    expected = analyze_supplied_authorization_model(model)
    if report.to_json() != expected.to_json():
        raise AuthorizationModelProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_authorization_model_bytes(
    report_bytes: bytes, *, model: Any,
) -> AuthorizationModelProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise AuthorizationModelProjectionError(str(exc)) from exc
    expected = analyze_supplied_authorization_model(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise AuthorizationModelProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    """Return a synthetic policy with RBAC, ABAC and direct ReBAC conditions."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-authz-model",
        "policy_complete": True,
        "roles_complete": True,
        "attributes_complete": True,
        "relations_complete": True,
        "principals": [
            {
                "principal_id": "alice", "roles": ["analyst"],
                "attributes": [{"name": "clearance", "value": "internal"}],
            },
            {"principal_id": "bob", "roles": [], "attributes": []},
        ],
        "resources": [
            {"resource_id": "case-one", "attributes": [{"name": "class", "value": "internal"}]},
        ],
        "relations": [
            {"principal_id": "alice", "relation": "owner", "resource_id": "case-one"},
        ],
        "rules": [
            {
                "rule_id": "analyst-owner", "effect": "allow", "action": "read",
                "role": "analyst",
                "principal_attribute": {"name": "clearance", "value": "internal"},
                "resource_attribute": {"name": "class", "value": "internal"},
                "relation": "owner",
            },
        ],
        "observations": [
            {
                "observation_id": "alice-read", "principal_id": "alice",
                "resource_id": "case-one", "action": "read", "reported_outcome": "allowed",
            },
            {
                "observation_id": "bob-read", "principal_id": "bob",
                "resource_id": "case-one", "action": "read", "reported_outcome": "allowed",
            },
        ],
    }


__all__ = [
    "AuthorizationModelProjectionError", "AuthorizationModelProjectionReport",
    "analyze_supplied_authorization_model", "verify_supplied_authorization_model",
    "verify_supplied_authorization_model_bytes", "component_fixture",
]

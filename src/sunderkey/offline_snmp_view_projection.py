"""Project supplied SNMP view declarations without contacting a device."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_snmp_view_projection"
PROFILE_ID = "AOE-GC-D13-S15"
CAPABILITY_ID = "army.gc.d13.s15"
VECTOR_ID = "AV-GC-D13-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S15"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:1ea977fa81cb05827ec630e7a6772a4a42a8150fcddf199db9d91c5d3e345600"
DOMAIN = "sunderkey.offline-snmp-view-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_VIEWS = 128
MAX_RULES = 256
MAX_BINDINGS = 256
MAX_QUERIES = 256
MAX_OID_ARCS = 64
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
OPERATIONS = {"read", "write", "notify"}
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class SnmpViewProjectionError(ValueError):
    """A supplied management view or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise SnmpViewProjectionError(f"{label} must be synthetic")
    return identifier


def _oid_arcs(value: Any, label: str) -> tuple[int, ...]:
    arcs = core.bounded_list(value, MAX_OID_ARCS, label)
    if not arcs:
        raise SnmpViewProjectionError(f"{label} must not be empty")
    if any(type(arc) is not int or not 0 <= arc <= 4_294_967_295 for arc in arcs):
        raise SnmpViewProjectionError(f"{label} contains an invalid arc")
    return tuple(arcs)


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "views_complete",
            "bindings_complete",
            "queries_complete",
            "views",
            "bindings",
            "queries",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SnmpViewProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for name in ("views_complete", "bindings_complete", "queries_complete"):
        core.boolean(model[name], name)
    views = core.bounded_list(model["views"], MAX_VIEWS, "views")
    view_ids: set[str] = set()
    for item in views:
        view = core.exact(item, {"view_id", "rules"}, "view")
        view_id = _synthetic(view["view_id"], "view ID")
        if view_id in view_ids:
            raise SnmpViewProjectionError("Duplicate view ID")
        view_ids.add(view_id)
        rules = core.bounded_list(view["rules"], MAX_RULES, "view rules")
        prefixes: set[tuple[int, ...]] = set()
        for item_rule in rules:
            rule = core.exact(item_rule, {"prefix_arcs", "included"}, "view rule")
            prefix = _oid_arcs(rule["prefix_arcs"], "view prefix")
            if prefix in prefixes:
                raise SnmpViewProjectionError("Duplicate view prefix")
            prefixes.add(prefix)
            core.boolean(rule["included"], "view inclusion")
    bindings = core.bounded_list(model["bindings"], MAX_BINDINGS, "bindings")
    binding_keys: set[tuple[str, str]] = set()
    for item in bindings:
        binding = core.exact(item, {"principal_id", "operation", "view_id"}, "binding")
        principal_id = _synthetic(binding["principal_id"], "principal ID")
        operation = core.choice(binding["operation"], OPERATIONS, "operation")
        if binding["view_id"] not in view_ids:
            raise SnmpViewProjectionError("Binding references an undeclared view")
        key = (principal_id, operation)
        if key in binding_keys:
            raise SnmpViewProjectionError("Duplicate principal-operation binding")
        binding_keys.add(key)
    queries = core.bounded_list(model["queries"], MAX_QUERIES, "queries")
    if not queries:
        raise SnmpViewProjectionError("At least one query is required")
    query_ids: set[str] = set()
    for item in queries:
        query = core.exact(
            item,
            {"query_id", "principal_id", "operation", "oid_arcs", "declared_allowed"},
            "query",
        )
        query_id = _synthetic(query["query_id"], "query ID")
        if query_id in query_ids:
            raise SnmpViewProjectionError("Duplicate query ID")
        query_ids.add(query_id)
        _synthetic(query["principal_id"], "principal ID")
        core.choice(query["operation"], OPERATIONS, "operation")
        _oid_arcs(query["oid_arcs"], "query OID")
        core.boolean(query["declared_allowed"], "declared access")
    return model


def _project(query: dict, views: dict[str, dict], bindings: dict[tuple[str, str], str]) -> bool:
    view_id = bindings.get((query["principal_id"], query["operation"]))
    if view_id is None:
        return False
    oid = tuple(query["oid_arcs"])
    matches = [
        (len(rule["prefix_arcs"]), rule["included"])
        for rule in views[view_id]["rules"]
        if oid[: len(rule["prefix_arcs"])] == tuple(rule["prefix_arcs"])
    ]
    return max(matches)[1] if matches else False


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[name] for name in ("views_complete", "bindings_complete", "queries_complete")
    )
    views = {view["view_id"]: view for view in model["views"]}
    bindings = {
        (binding["principal_id"], binding["operation"]): binding["view_id"]
        for binding in model["bindings"]
    }
    projections: list[dict] = []
    for query in model["queries"]:
        projected = _project(query, views, bindings) if complete else None
        differs = projected is not None and projected != query["declared_allowed"]
        projections.append(
            {
                "query_id": query["query_id"],
                "projected_allowed": projected,
                "issues": ["declared_access_differs_from_policy"] if differs else [],
                "disposition": (
                    "unknown_incomplete_declarations"
                    if not complete
                    else "candidate_declared_policy_difference"
                    if differs
                    else "consistent_under_declared_policy"
                ),
            }
        )
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
            "query_count": len(projections),
            "candidate_count": sum(
                row["disposition"] == "candidate_declared_policy_difference" for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations" for row in projections
            ),
        },
        "source_authenticated": False,
        "device_configuration_observed": False,
        "snmp_request_sent": False,
        "snmp_response_observed": False,
        "authentication_verified": False,
        "access_bypass_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Views, bindings, OIDs and declared access are unauthenticated caller data.",
            "Only unmasked numeric prefixes and one binding per principal-operation are modeled.",
            "Longest matching prefix wins; no match or binding projects deny in this model.",
            "This is not the complete RFC 3415 VACM procedure or a NETCONF model.",
            "No SNMP packet, endpoint, community string, key or credential field is accepted.",
            "Synthetic IDs are caller labels, not proof the source is synthetic.",
            "A declared difference does not prove device behavior or live access.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SVP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SnmpViewProjectionReport:
    """Unsigned view projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SnmpViewProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SnmpViewProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_snmp_view(model: Any) -> SnmpViewProjectionReport:
    try:
        return SnmpViewProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise SnmpViewProjectionError(str(exc)) from exc


def verify_supplied_snmp_view(
    report: Any,
    *,
    model: Any,
) -> SnmpViewProjectionReport:
    if type(report) is not SnmpViewProjectionReport:
        raise SnmpViewProjectionError("Exact report wrapper required")
    expected = analyze_supplied_snmp_view(model)
    if report.to_json() != expected.to_json():
        raise SnmpViewProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_snmp_view_bytes(
    report_bytes: bytes,
    *,
    model: Any,
) -> SnmpViewProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise SnmpViewProjectionError(str(exc)) from exc
    expected = analyze_supplied_snmp_view(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise SnmpViewProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:snmp-source",
        "views_complete": True,
        "bindings_complete": True,
        "queries_complete": True,
        "views": [
            {
                "view_id": "synthetic:read-view",
                "rules": [
                    {"prefix_arcs": [1, 3, 6], "included": True},
                    {"prefix_arcs": [1, 3, 6, 1, 4], "included": False},
                ],
            },
        ],
        "bindings": [
            {
                "principal_id": "synthetic:reader",
                "operation": "read",
                "view_id": "synthetic:read-view",
            },
        ],
        "queries": [
            {
                "query_id": "synthetic:public",
                "principal_id": "synthetic:reader",
                "operation": "read",
                "oid_arcs": [1, 3, 6, 1, 2, 1],
                "declared_allowed": True,
            },
            {
                "query_id": "synthetic:private",
                "principal_id": "synthetic:reader",
                "operation": "read",
                "oid_arcs": [1, 3, 6, 1, 4, 1],
                "declared_allowed": True,
            },
        ],
    }


__all__ = [
    "SnmpViewProjectionError",
    "SnmpViewProjectionReport",
    "analyze_supplied_snmp_view",
    "verify_supplied_snmp_view",
    "verify_supplied_snmp_view_bytes",
    "component_fixture",
]

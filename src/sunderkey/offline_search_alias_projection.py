"""Project supplied search alias and tenant-filter declarations without queries."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_search_alias_projection"
PROFILE_ID = "AOE-GB-D07-S06"
CAPABILITY_ID = "army.gb.d07.s06"
VECTOR_ID = "AV-GB-D07-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:33b2e5beea3a1cf6bd9ff50f29ba7c54ecd4a0464f197c1a6d4e74560cf3d1bb"
SEMANTICS_PROFILE = "supplied-search-alias-v1"
DOMAIN = "sunderkey.offline-search-alias-projection.v1"
MAX_INDEXES = 128
MAX_ROUTES = 256
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_INDEX = re.compile(r"index:sha256:[0-9a-f]{64}\Z")
_ALIAS = re.compile(r"alias:sha256:[0-9a-f]{64}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "index",
        "network",
        "provider",
        "publication",
        "qualification",
        "query",
        "target",
    ),
    "none",
)


class SearchAliasProjectionError(ValueError):
    """A supplied alias model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise SearchAliasProjectionError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise SearchAliasProjectionError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise SearchAliasProjectionError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise SearchAliasProjectionError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise SearchAliasProjectionError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise SearchAliasProjectionError("Native JSON text keys are required")
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
        raise SearchAliasProjectionError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise SearchAliasProjectionError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise SearchAliasProjectionError(f"{label} must be an opaque digest reference")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "indexes", "alias_routes", "objectives"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SearchAliasProjectionError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise SearchAliasProjectionError("Semantics profile is invalid")
    indexes = model["indexes"]
    routes = model["alias_routes"]
    objectives = model["objectives"]
    if type(indexes) is not list or not 1 <= len(indexes) <= MAX_INDEXES:
        raise SearchAliasProjectionError("Index count is invalid")
    if type(routes) is not list or len(routes) > MAX_ROUTES:
        raise SearchAliasProjectionError("Alias route count is invalid")
    if type(objectives) is not list or not 1 <= len(objectives) <= MAX_OBJECTIVES:
        raise SearchAliasProjectionError("Objective count is invalid")
    known_indexes: set[str] = set()
    for index in indexes:
        _fields(index, {"index_ref", "tenant_ref"}, "index")
        index_ref = _ref(index["index_ref"], _INDEX, "Index")
        if index_ref in known_indexes:
            raise SearchAliasProjectionError("Duplicate index reference")
        known_indexes.add(index_ref)
        if index["tenant_ref"] != "shared":
            _ref(index["tenant_ref"], _TENANT, "Index tenant")
    route_ids: set[str] = set()
    route_pairs: set[tuple[str, str, str | None]] = set()
    for route in routes:
        _fields(route, {"route_id", "alias_ref", "index_ref", "filter_tenant_ref"}, "route")
        route_id = route["route_id"]
        if type(route_id) is not str or _ID.fullmatch(route_id) is None:
            raise SearchAliasProjectionError("Route identifier is invalid")
        alias = _ref(route["alias_ref"], _ALIAS, "Alias")
        index = _ref(route["index_ref"], _INDEX, "Route index")
        if index not in known_indexes:
            raise SearchAliasProjectionError("Route index is undeclared")
        filter_tenant = route["filter_tenant_ref"]
        if filter_tenant is not None:
            _ref(filter_tenant, _TENANT, "Filter tenant")
        pair = (alias, index, filter_tenant)
        if route_id in route_ids or pair in route_pairs:
            raise SearchAliasProjectionError("Duplicate alias route")
        route_ids.add(route_id)
        route_pairs.add(pair)
    seen_objectives: set[tuple[str, str]] = set()
    for objective in objectives:
        _fields(objective, {"alias_ref", "expected_tenant_ref"}, "objective")
        pair = (
            _ref(objective["alias_ref"], _ALIAS, "Objective alias"),
            _ref(objective["expected_tenant_ref"], _TENANT, "Expected tenant"),
        )
        if pair in seen_objectives:
            raise SearchAliasProjectionError("Duplicate objective")
        seen_objectives.add(pair)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    indexes = {row["index_ref"]: row for row in plan["indexes"]}
    by_alias: dict[str, list[dict]] = {}
    for route in plan["alias_routes"]:
        by_alias.setdefault(route["alias_ref"], []).append(route)
    findings = []
    for objective in plan["objectives"]:
        alias = objective["alias_ref"]
        expected = objective["expected_tenant_ref"]
        rows = []
        for route in sorted(by_alias.get(alias, []), key=lambda row: row["route_id"]):
            index_tenant = indexes[route["index_ref"]]["tenant_ref"]
            filter_tenant = route["filter_tenant_ref"]
            if filter_tenant is not None and filter_tenant != expected:
                disposition = "declared_excluded_by_filter"
            elif index_tenant != "shared" and index_tenant != expected:
                disposition = "declared_index_tenant_mismatch"
            elif index_tenant == "shared" and filter_tenant is None:
                disposition = "declared_unscoped_shared_index"
            else:
                disposition = "declared_aligned_route"
            rows.append(
                {
                    "route_id": route["route_id"],
                    "index_ref": route["index_ref"],
                    "disposition": disposition,
                }
            )
        findings.append(
            {
                "alias_ref": alias,
                "expected_tenant_ref": expected,
                "route_status": "supplied_routes" if rows else "no_supplied_route",
                "routes": rows,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "index_contents_verified": False,
            "alias_configuration_verified": False,
            "tenant_filter_enforced": False,
            "cross_tenant_exposure_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Index ownership, alias routes, and filter declarations are caller-supplied.",
            "The four route labels are abstract comparisons, not engine query semantics.",
            "A declared mismatch or unscoped route does not prove document exposure.",
            "No index, provider, service, credential, network, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "SAP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class SearchAliasProjection:
    """Immutable report replayed from supplied alias declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise SearchAliasProjectionError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise SearchAliasProjectionError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_search_alias(model: Any) -> SearchAliasProjection:
    """Compare only supplied alias, index, tenant, and filter declarations."""
    return SearchAliasProjection(_derive(model))


def verify_supplied_search_alias(report: Any, *, model: Any) -> SearchAliasProjection:
    if type(report) is not SearchAliasProjection:
        raise SearchAliasProjectionError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise SearchAliasProjectionError("Report differs from supplied model replay")
    return SearchAliasProjection(expected)

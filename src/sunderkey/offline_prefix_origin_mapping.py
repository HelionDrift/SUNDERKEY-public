"""Bounded IP-prefix and origin-ASN matching over one supplied route snapshot."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_prefix_origin_mapping"
PROFILE_ID = "AOE-GA-D01-S04"
CAPABILITY_ID = "army.ga.d01.s04"
VECTOR_ID = "AV-GA-D01-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7894007329fc99967864a8e3c0005ff933f33840d8aa9e67fa32352946f71abe"
SEMANTICS_PROFILE = "supplied-prefix-origin-snapshot-v1"
DOMAIN = "sunderkey.offline-prefix-origin-mapping.v1"
MAX_ROUTES = 512
MAX_QUERIES = 64
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "network",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "publication",
        "deployment",
        "provider",
        "bgp_session",
    ),
    "none",
)


class PrefixOriginMappingError(ValueError):
    """A supplied snapshot, query, or replay packet was refused."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise PrefixOriginMappingError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise PrefixOriginMappingError(f"{label} identifier is invalid")


def _prefix(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if type(value) is not str or not 1 <= len(value) <= 49:
        raise PrefixOriginMappingError("Prefix text is invalid")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise PrefixOriginMappingError("Prefix is not a strict canonical network") from exc
    if str(network) != value:
        raise PrefixOriginMappingError("Prefix is not canonical text")
    return network


def _address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if type(value) is not str or not 1 <= len(value) <= 39:
        raise PrefixOriginMappingError("Address text is invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise PrefixOriginMappingError("Address is invalid") from exc
    if str(address) != value:
        raise PrefixOriginMappingError("Address is not canonical text")
    return address


def _canonical(value: dict) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise PrefixOriginMappingError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise PrefixOriginMappingError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise PrefixOriginMappingError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise PrefixOriginMappingError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise PrefixOriginMappingError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise PrefixOriginMappingError("Native JSON text keys are required")
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
        raise PrefixOriginMappingError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> tuple[dict, list[tuple[dict, Any]], list[tuple[dict, Any]]]:
    _fields(model, {"schema_version", "semantics_profile", "routes", "queries"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PrefixOriginMappingError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise PrefixOriginMappingError("Semantics profile is invalid")
    routes = model["routes"]
    queries = model["queries"]
    if type(routes) is not list or not 1 <= len(routes) <= MAX_ROUTES:
        raise PrefixOriginMappingError("Route count is invalid")
    if type(queries) is not list or not 1 <= len(queries) <= MAX_QUERIES:
        raise PrefixOriginMappingError("Query count is invalid")
    route_ids: set[str] = set()
    route_signatures: set[tuple[str, int, str]] = set()
    selected_routes: list[tuple[dict, Any]] = []
    for route in routes:
        _fields(route, {"route_id", "prefix", "origin_asn", "source_id"}, "route")
        _identifier(route["route_id"], "route")
        _identifier(route["source_id"], "source")
        prefix = _prefix(route["prefix"])
        asn = route["origin_asn"]
        if type(asn) is not int or not 1 <= asn <= 4_294_967_295:
            raise PrefixOriginMappingError("Origin ASN is invalid")
        signature = (route["prefix"], asn, route["source_id"])
        if route["route_id"] in route_ids or signature in route_signatures:
            raise PrefixOriginMappingError("Duplicate route observation refused")
        route_ids.add(route["route_id"])
        route_signatures.add(signature)
        selected_routes.append((route, prefix))
    query_ids: set[str] = set()
    selected_queries: list[tuple[dict, Any]] = []
    for query in queries:
        _fields(query, {"query_id", "address"}, "query")
        _identifier(query["query_id"], "query")
        if query["query_id"] in query_ids:
            raise PrefixOriginMappingError("Duplicate query identifier")
        query_ids.add(query["query_id"])
        selected_queries.append((query, _address(query["address"])))
    copied = json.loads(_canonical(model))
    return copied, selected_routes, selected_queries


def _derive(model: Any) -> dict:
    plan, routes, queries = _plan(model)
    observations = []
    for query, address in sorted(queries, key=lambda row: row[0]["query_id"]):
        matched = [
            (route, prefix)
            for route, prefix in routes
            if prefix.version == address.version and address in prefix
        ]
        if not matched:
            observations.append(
                {
                    "query_id": query["query_id"],
                    "address": query["address"],
                    "status": "not_in_supplied_table",
                    "selected_prefix": None,
                    "origin_asns": [],
                    "route_ids": [],
                    "source_ids": [],
                }
            )
            continue
        longest = max(prefix.prefixlen for _, prefix in matched)
        selected = [row for row in matched if row[1].prefixlen == longest]
        asns = sorted({route["origin_asn"] for route, _ in selected})
        observations.append(
            {
                "query_id": query["query_id"],
                "address": query["address"],
                "status": (
                    "single_supplied_origin" if len(asns) == 1 else "conflicting_supplied_origins"
                ),
                "selected_prefix": selected[0][0]["prefix"],
                "origin_asns": asns,
                "route_ids": sorted(route["route_id"] for route, _ in selected),
                "source_ids": sorted({route["source_id"] for route, _ in selected}),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": observations,
        "flags": {
            "source_authenticated": False,
            "snapshot_completeness_proven": False,
            "asn_ownership_proven": False,
            "bgp_validity_proven": False,
            "rpki_validity_proven": False,
            "actual_route_proven": False,
            "target_existence_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Routes and source labels are caller-supplied, not authenticated observations.",
            "Longest-prefix selection is local table arithmetic, not actual network routing.",
            "A missing row is not proof that an address or route is absent.",
            "No BGP session, RPKI, route policy, ASN ownership or target contact is modeled.",
        ],
    }
    encoded = _canonical(body)
    digest = "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()
    return json.loads(
        _canonical(
            {**body, "analysis_id": "POM-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class PrefixOriginAnalysis:
    """Detached, replayed table observation with no network or authority effect."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise PrefixOriginMappingError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise PrefixOriginMappingError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_prefix_origins(model: Any) -> PrefixOriginAnalysis:
    """Return longest supplied-prefix observations, never actual routing proof."""
    return PrefixOriginAnalysis(_derive(model))


def verify_supplied_prefix_origins(report: Any, *, model: Any) -> PrefixOriginAnalysis:
    """Rebuild the supplied-table result instead of trusting its digest alone."""
    if type(report) is not PrefixOriginAnalysis:
        raise PrefixOriginMappingError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise PrefixOriginMappingError("Report differs from supplied model replay")
    return PrefixOriginAnalysis(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "PrefixOriginAnalysis",
    "PrefixOriginMappingError",
    "analyze_supplied_prefix_origins",
    "verify_supplied_prefix_origins",
]

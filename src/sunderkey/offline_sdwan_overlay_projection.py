"""Project supplied overlay routes and explicit site-pair policy without network access."""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_sdwan_overlay_projection"
PROFILE_ID = "AOE-GC-D13-S21"
CAPABILITY_ID = "army.gc.d13.s21"
VECTOR_ID = "AV-GC-D13-S21-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S21"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3da321fe29d23069ccc606ef143173feb701bec6b57a041fba72f2c49c917dcd"
DOMAIN = "sunderkey.offline-sdwan-overlay-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_SITES = 128
MAX_LINKS = 512
MAX_POLICY_PAIRS = 512
MAX_QUERIES = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
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


class SdwanOverlayProjectionError(ValueError):
    """A supplied overlay model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise SdwanOverlayProjectionError(f"{label} must be synthetic")
    return identifier


def _pair(value: Any, sites: set[str], label: str, *, fields: set[str]) -> tuple[str, str]:
    row = core.exact(value, fields, label)
    source = _synthetic(row["source_site_id"], "source site ID")
    target = _synthetic(row["target_site_id"], "target site ID")
    if source not in sites or target not in sites:
        raise SdwanOverlayProjectionError(f"{label} references an undeclared site")
    if source == target:
        raise SdwanOverlayProjectionError(f"{label} must reference distinct sites")
    return source, target


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "sites_complete",
            "links_complete",
            "policy_complete",
            "queries_complete",
            "sites",
            "links",
            "allowed_pairs",
            "queries",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SdwanOverlayProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for name in ("sites_complete", "links_complete", "policy_complete", "queries_complete"):
        core.boolean(model[name], name)
    site_rows = core.bounded_list(model["sites"], MAX_SITES, "sites")
    if not site_rows:
        raise SdwanOverlayProjectionError("At least one site is required")
    sites: set[str] = set()
    for item in site_rows:
        site = core.exact(item, {"site_id"}, "site")
        site_id = _synthetic(site["site_id"], "site ID")
        if site_id in sites:
            raise SdwanOverlayProjectionError("Duplicate site ID")
        sites.add(site_id)
    link_pairs: set[tuple[str, str]] = set()
    for item in core.bounded_list(model["links"], MAX_LINKS, "links"):
        pair = _pair(item, sites, "link", fields={"source_site_id", "target_site_id", "up"})
        if pair in link_pairs:
            raise SdwanOverlayProjectionError("Duplicate directed link")
        link_pairs.add(pair)
        core.boolean(item["up"], "link state")
    policy_pairs: set[tuple[str, str]] = set()
    for item in core.bounded_list(model["allowed_pairs"], MAX_POLICY_PAIRS, "allowed pairs"):
        pair = _pair(item, sites, "allowed pair", fields={"source_site_id", "target_site_id"})
        if pair in policy_pairs:
            raise SdwanOverlayProjectionError("Duplicate allowed pair")
        policy_pairs.add(pair)
    queries = core.bounded_list(model["queries"], MAX_QUERIES, "queries")
    if not queries:
        raise SdwanOverlayProjectionError("At least one query is required")
    query_ids: set[str] = set()
    for item in queries:
        query = core.exact(
            item,
            {"query_id", "source_site_id", "target_site_id", "declared_reachable"},
            "query",
        )
        query_id = _synthetic(query["query_id"], "query ID")
        if query_id in query_ids:
            raise SdwanOverlayProjectionError("Duplicate query ID")
        query_ids.add(query_id)
        _pair(
            query,
            sites,
            "query",
            fields={"query_id", "source_site_id", "target_site_id", "declared_reachable"},
        )
        core.boolean(query["declared_reachable"], "declared reachability")
    return model


def _shortest_path(source: str, target: str, links: list[dict]) -> list[str]:
    adjacency: dict[str, set[str]] = {}
    for link in links:
        if link["up"]:
            adjacency.setdefault(link["source_site_id"], set()).add(link["target_site_id"])
    queue = deque([source])
    previous: dict[str, str | None] = {source: None}
    while queue:
        current = queue.popleft()
        if current == target:
            path = [current]
            while previous[current] is not None:
                current = previous[current]
                path.append(current)
            return list(reversed(path))
        for neighbor in sorted(adjacency.get(current, ())):
            if neighbor not in previous:
                previous[neighbor] = current
                queue.append(neighbor)
    return []


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[name]
        for name in ("sites_complete", "links_complete", "policy_complete", "queries_complete")
    )
    allowed = {(item["source_site_id"], item["target_site_id"]) for item in model["allowed_pairs"]}
    projections: list[dict] = []
    for query in model["queries"]:
        path = (
            _shortest_path(query["source_site_id"], query["target_site_id"], model["links"])
            if complete
            else []
        )
        route_exists = bool(path) if complete else None
        policy_allows = (
            (query["source_site_id"], query["target_site_id"]) in allowed if complete else None
        )
        projected = route_exists and policy_allows if complete else None
        differs = projected is not None and projected != query["declared_reachable"]
        projections.append(
            {
                "query_id": query["query_id"],
                "route_exists": route_exists,
                "policy_allows": policy_allows,
                "path_site_ids": path,
                "projected_reachable": projected,
                "issues": ["declared_reachability_differs_from_model"] if differs else [],
                "disposition": (
                    "unknown_incomplete_declarations"
                    if not complete
                    else "candidate_declared_model_difference"
                    if differs
                    else "consistent_under_declared_model"
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
                row["disposition"] == "candidate_declared_model_difference" for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations" for row in projections
            ),
        },
        "source_authenticated": False,
        "overlay_state_observed": False,
        "policy_enforcement_observed": False,
        "packet_path_observed": False,
        "live_reachability_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Sites, directed link states, policy pairs and reachability are caller declarations.",
            "Shortest path is computed only over declared up links with deterministic tie order.",
            "A route and a policy allowance are separate local predicates.",
            "No address, tunnel packet, controller, provider or credential field is accepted.",
            "Synthetic IDs are caller labels, not proof the source is synthetic.",
            "No live overlay state, forwarding behavior or policy enforcement is observed.",
            "A declared difference does not prove a reachable live network path.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SOP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class SdwanOverlayProjectionReport:
    """Unsigned overlay projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SdwanOverlayProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SdwanOverlayProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_sdwan_overlay(model: Any) -> SdwanOverlayProjectionReport:
    try:
        return SdwanOverlayProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise SdwanOverlayProjectionError(str(exc)) from exc


def verify_supplied_sdwan_overlay(
    report: Any,
    *,
    model: Any,
) -> SdwanOverlayProjectionReport:
    if type(report) is not SdwanOverlayProjectionReport:
        raise SdwanOverlayProjectionError("Exact report wrapper required")
    expected = analyze_supplied_sdwan_overlay(model)
    if report.to_json() != expected.to_json():
        raise SdwanOverlayProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_sdwan_overlay_bytes(
    report_bytes: bytes,
    *,
    model: Any,
) -> SdwanOverlayProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise SdwanOverlayProjectionError(str(exc)) from exc
    expected = analyze_supplied_sdwan_overlay(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise SdwanOverlayProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:overlay-source",
        "sites_complete": True,
        "links_complete": True,
        "policy_complete": True,
        "queries_complete": True,
        "sites": [
            {"site_id": "synthetic:west"},
            {"site_id": "synthetic:central"},
            {"site_id": "synthetic:east"},
        ],
        "links": [
            {"source_site_id": "synthetic:west", "target_site_id": "synthetic:central", "up": True},
            {
                "source_site_id": "synthetic:central",
                "target_site_id": "synthetic:east",
                "up": False,
            },
        ],
        "allowed_pairs": [
            {"source_site_id": "synthetic:west", "target_site_id": "synthetic:east"},
        ],
        "queries": [
            {
                "query_id": "synthetic:cross-region",
                "source_site_id": "synthetic:west",
                "target_site_id": "synthetic:east",
                "declared_reachable": True,
            },
            {
                "query_id": "synthetic:to-central",
                "source_site_id": "synthetic:west",
                "target_site_id": "synthetic:central",
                "declared_reachable": False,
            },
        ],
    }


__all__ = [
    "SdwanOverlayProjectionError",
    "SdwanOverlayProjectionReport",
    "analyze_supplied_sdwan_overlay",
    "verify_supplied_sdwan_overlay",
    "verify_supplied_sdwan_overlay_bytes",
    "component_fixture",
]

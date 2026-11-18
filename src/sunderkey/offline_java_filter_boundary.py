"""Offline projection of supplied Java servlet-filter route coverage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sunderkey import offline_framework_declaration_core as core

PROFILE_ID = "AOE-GB-D05-S06"
CAPABILITY_ID = "army.gb.d05.s06"
VECTOR_ID = "AV-GB-D05-S06-01"
WAVE_ID = "IW2-006"
DOMAIN = "sunderkey.offline-java-filter-boundary.v1"
SCHEMA_VERSION = "v1"
COMPONENT_ID = "java_supplied_filter_mapping_boundary"
MAX_SOURCE_BYTES = core.MAX_SOURCE_BYTES
MAX_REPORT_BYTES = core.MAX_REPORT_BYTES
MAX_DEPTH = core.MAX_DEPTH
_DISPATCHERS = {"REQUEST", "FORWARD", "INCLUDE", "ERROR", "ASYNC"}
_KINDS = {"authorization_guard", "other"}
_ASSESSMENTS = {
    "candidate_declared_coverage_gap",
    "declared_coverage",
    "not_required",
    "unknown",
}
_BASES = {
    "guard_covered",
    "guard_dispatcher_absent",
    "guard_route_absent",
    "guard_not_required",
    "incomplete_declarations",
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
    "facts_authenticated": False,
    "policy_authenticated": False,
    "filter_execution_observed": False,
    "server_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Filter bindings, dispatcher types and route requirements are supplied assertions.",
    "Exact paths and route IDs are inert labels; servlet URL-pattern resolution does not occur.",
    "Declared guard coverage does not prove filter execution or authorization enforcement.",
    "An incomplete declaration set yields unknown rather than a coverage claim.",
    "A declared gap is a candidate requirement mismatch, not a verified vulnerability.",
    "No target, network, process, credential, provider request or live exploit occurs.",
]

JavaFilterBoundaryError = core.FrameworkDeclarationError


def _model(document: Any) -> tuple[bool, dict[str, dict], dict[str, dict]]:
    item = core.exact(
        document, {"schema_version", "declarations_complete", "filters", "routes"}, "model"
    )
    if item["schema_version"] != SCHEMA_VERSION or type(item["schema_version"]) is not str:
        raise JavaFilterBoundaryError("unsupported model version")
    complete = core.boolean(item["declarations_complete"], "declarations complete")
    raw_routes = core.bounded_list(item["routes"], 512, "routes")
    raw_filters = core.bounded_list(item["filters"], 512, "filters")
    routes: dict[str, dict] = {}
    path_dispatchers: set[tuple[str, str]] = set()
    for raw in raw_routes:
        route = core.exact(raw, {"route_id", "route_path", "dispatcher", "requires_guard"}, "route")
        identity = core.identifier(route["route_id"], "route ID")
        path = core.path(route["route_path"])
        dispatcher = core.choice(route["dispatcher"], _DISPATCHERS, "dispatcher")
        if identity in routes or (path, dispatcher) in path_dispatchers:
            raise JavaFilterBoundaryError("duplicate route ID or path-dispatcher pair")
        path_dispatchers.add((path, dispatcher))
        routes[identity] = {
            "route_path": path,
            "dispatcher": dispatcher,
            "requires_guard": core.boolean(route["requires_guard"], "requires guard"),
        }
    filters: dict[str, dict] = {}
    for raw in raw_filters:
        binding = core.exact(raw, {"filter_id", "kind", "route_ids", "dispatchers"}, "filter")
        identity = core.identifier(binding["filter_id"], "filter ID")
        if identity in filters:
            raise JavaFilterBoundaryError("duplicate filter ID")
        route_ids = [
            core.identifier(value, "route ID")
            for value in core.bounded_list(binding["route_ids"], 512, "filter routes")
        ]
        dispatchers = [
            core.choice(value, _DISPATCHERS, "dispatcher")
            for value in core.bounded_list(binding["dispatchers"], 5, "filter dispatchers")
        ]
        if len(set(route_ids)) != len(route_ids) or len(set(dispatchers)) != len(dispatchers):
            raise JavaFilterBoundaryError("duplicate filter route or dispatcher")
        if any(route_id not in routes for route_id in route_ids):
            raise JavaFilterBoundaryError("filter references an unknown route")
        filters[identity] = {
            "kind": core.choice(binding["kind"], _KINDS, "filter kind"),
            "route_ids": frozenset(route_ids),
            "dispatchers": frozenset(dispatchers),
        }
    return complete, routes, filters


def _project(complete: bool, routes: dict[str, dict], filters: dict[str, dict]) -> list[dict]:
    projections = []
    for identity, route in sorted(routes.items()):
        guards = {
            filter_id: binding
            for filter_id, binding in filters.items()
            if binding["kind"] == "authorization_guard" and identity in binding["route_ids"]
        }
        covering = sorted(
            filter_id
            for filter_id, binding in guards.items()
            if route["dispatcher"] in binding["dispatchers"]
        )
        if not complete:
            assessment, basis = "unknown", "incomplete_declarations"
        elif not route["requires_guard"]:
            assessment, basis = "not_required", "guard_not_required"
        elif covering:
            assessment, basis = "declared_coverage", "guard_covered"
        elif guards:
            assessment, basis = "candidate_declared_coverage_gap", "guard_dispatcher_absent"
        else:
            assessment, basis = "candidate_declared_coverage_gap", "guard_route_absent"
        projections.append(
            {
                "route_id": identity,
                "route_path": route["route_path"],
                "dispatcher": route["dispatcher"],
                "requires_guard": route["requires_guard"],
                "mapped_guard_ids": sorted(guards),
                "covering_guard_ids": covering,
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
            "wave_id",
            "domain",
            "source",
            "declarations_complete",
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
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise JavaFilterBoundaryError(f"report {key} is invalid")
    core.validate_source(item["source"])
    core.boolean(item["declarations_complete"], "report declarations complete")
    projections = core.bounded_list(item["projections"], 512, "projections")
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    ids = []
    for raw in projections:
        p = core.exact(
            raw,
            {
                "route_id",
                "route_path",
                "dispatcher",
                "requires_guard",
                "mapped_guard_ids",
                "covering_guard_ids",
                "assessment",
                "basis",
            },
            "projection",
        )
        ids.append(core.identifier(p["route_id"], "route ID"))
        core.path(p["route_path"])
        core.choice(p["dispatcher"], _DISPATCHERS, "dispatcher")
        core.boolean(p["requires_guard"], "requires guard")
        mapped = [
            core.identifier(value, "filter ID")
            for value in core.bounded_list(p["mapped_guard_ids"], 512, "mapped guards")
        ]
        covering = [
            core.identifier(value, "filter ID")
            for value in core.bounded_list(p["covering_guard_ids"], 512, "covering guards")
        ]
        if (
            mapped != sorted(set(mapped))
            or covering != sorted(set(covering))
            or not set(covering) <= set(mapped)
        ):
            raise JavaFilterBoundaryError("report guard IDs are invalid")
        core.choice(p["basis"], _BASES, "basis")
        counts[core.choice(p["assessment"], _ASSESSMENTS, "assessment")] += 1
    if ids != sorted(set(ids)):
        raise JavaFilterBoundaryError("report route IDs must be sorted unique")
    summary = core.exact(item["summary"], {"route_count", "assessments"}, "summary")
    reported = core.exact(summary["assessments"], set(counts), "summary assessments")
    if (
        type(summary["route_count"]) is not int
        or summary["route_count"] != len(projections)
        or any(
            type(reported[key]) is not int or reported[key] != value
            for key, value in counts.items()
        )
    ):
        raise JavaFilterBoundaryError("report summary is invalid")
    report_id, sha256 = core.report_address(item, domain=DOMAIN, prefix="JFB-")
    if item["report_id"] != report_id or item["report_sha256"] != sha256:
        raise JavaFilterBoundaryError("report address is invalid")


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise JavaFilterBoundaryError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise JavaFilterBoundaryError("report must be UTF-8 JSON text") from exc
    document = core.decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return core.canonical(document)


@dataclass(frozen=True, slots=True)
class JavaFilterBoundaryReport:
    """Canonical report; exact original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not JavaFilterBoundaryReport or self._json != _checked_report_json(
            self._json
        ):
            raise JavaFilterBoundaryError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not JavaFilterBoundaryReport or self._json != _checked_report_json(
            self._json
        ):
            raise JavaFilterBoundaryError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> JavaFilterBoundaryReport:
        if cls is not JavaFilterBoundaryReport:
            raise JavaFilterBoundaryError("report must be the exact report family")
        return cls(_checked_report_json(content))


def analyze_java_filter_boundary(
    *, source_content: bytes, source_id: str
) -> JavaFilterBoundaryReport:
    """Project supplied filter-route and dispatcher declarations without executing them."""
    identity = core.identifier(source_id, "source ID")
    source = core.decode(source_content, maximum=MAX_SOURCE_BYTES)
    complete, routes, filters = _model(source)
    projections = _project(complete, routes, filters)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "wave_id": WAVE_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": core.digest(source_content),
            "byte_count": len(source_content),
        },
        "declarations_complete": complete,
        "projections": projections,
        "summary": {"route_count": len(projections), "assessments": counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    document["report_id"], document["report_sha256"] = core.report_address(
        document, domain=DOMAIN, prefix="JFB-"
    )
    core.validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return JavaFilterBoundaryReport(core.canonical(document))


def analyze_supplied_java_filter_boundary(model: dict[str, Any]) -> JavaFilterBoundaryReport:
    """Canonicalize an exact native source-backed component model."""
    core.validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = core.exact(model, {"source_id", "source"}, "component model")
    source_id = core.identifier(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_java_filter_boundary(
        source_content=core.canonical(item["source"]).encode("ascii"), source_id=source_id
    )


def verify_java_filter_boundary(
    report: JavaFilterBoundaryReport, *, source_content: bytes, source_id: str
) -> JavaFilterBoundaryReport:
    """Rebuild from exact original source bytes and compare the entire report."""
    if type(report) is not JavaFilterBoundaryReport:
        raise JavaFilterBoundaryError("report must be the exact report family")
    loaded = JavaFilterBoundaryReport.from_json(report.to_json())
    expected = analyze_java_filter_boundary(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise JavaFilterBoundaryError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic servlet-filter declarations."""
    return {
        "schema_version": SCHEMA_VERSION,
        "declarations_complete": True,
        "filters": [
            {
                "filter_id": "guard",
                "kind": "authorization_guard",
                "route_ids": ["account", "forwarded"],
                "dispatchers": ["REQUEST"],
            },
            {
                "filter_id": "logger",
                "kind": "other",
                "route_ids": ["account"],
                "dispatchers": ["REQUEST"],
            },
        ],
        "routes": [
            {
                "route_id": "account",
                "route_path": "/account",
                "dispatcher": "REQUEST",
                "requires_guard": True,
            },
            {
                "route_id": "forwarded",
                "route_path": "/account",
                "dispatcher": "FORWARD",
                "requires_guard": True,
            },
            {
                "route_id": "health",
                "route_path": "/health",
                "dispatcher": "REQUEST",
                "requires_guard": False,
            },
        ],
    }

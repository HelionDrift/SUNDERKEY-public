"""Offline projection of supplied .NET endpoint-routing middleware order."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sunderkey import offline_framework_declaration_core as core

PROFILE_ID = "AOE-GB-D05-S07"
CAPABILITY_ID = "army.gb.d05.s07"
VECTOR_ID = "AV-GB-D05-S07-01"
WAVE_ID = "IW2-007"
DOMAIN = "sunderkey.offline-dotnet-middleware-boundary.v1"
SCHEMA_VERSION = "v1"
COMPONENT_ID = "dotnet_supplied_middleware_order_boundary"
MAX_SOURCE_BYTES = core.MAX_SOURCE_BYTES
MAX_REPORT_BYTES = core.MAX_REPORT_BYTES
MAX_DEPTH = core.MAX_DEPTH
_STAGES = {"routing", "authentication", "authorization", "endpoint", "other"}
_ASSESSMENTS = {
    "candidate_declared_order_gap",
    "declared_order_satisfied",
    "not_required",
    "unknown",
}
_BASES = {
    "authorization_between_routing_and_endpoint",
    "authorization_missing",
    "authorization_outside_endpoint_window",
    "not_required",
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
    "middleware_execution_observed": False,
    "server_enforcement_observed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Middleware order, route requirements and pipeline completeness are supplied assertions.",
    "This narrow model covers explicit endpoint routing only; branches and implicit "
    "routing are not modeled.",
    "Exact paths are inert labels; no route matching or request dispatch occurs.",
    "Declared ordering does not prove middleware execution or authorization enforcement.",
    "An incomplete declaration set yields unknown rather than an ordering claim.",
    "A declared gap is a candidate requirement mismatch, not a verified vulnerability.",
    "No target, network, process, credential, provider request or live exploit occurs.",
]

DotnetMiddlewareBoundaryError = core.FrameworkDeclarationError


def _model(document: Any) -> tuple[bool, list[dict], dict[str, dict]]:
    item = core.exact(
        document,
        {"schema_version", "declarations_complete", "pipeline_kind", "middleware", "routes"},
        "model",
    )
    if type(item["schema_version"]) is not str or item["schema_version"] != SCHEMA_VERSION:
        raise DotnetMiddlewareBoundaryError("unsupported model version")
    complete = core.boolean(item["declarations_complete"], "declarations complete")
    if (
        type(item["pipeline_kind"]) is not str
        or item["pipeline_kind"] != "explicit_endpoint_routing"
    ):
        raise DotnetMiddlewareBoundaryError("unsupported pipeline kind")
    raw_middleware = core.bounded_list(item["middleware"], 512, "middleware")
    raw_routes = core.bounded_list(item["routes"], 512, "routes")
    middleware = []
    ids: set[str] = set()
    stage_counts = {stage: 0 for stage in _STAGES if stage != "other"}
    for raw in raw_middleware:
        entry = core.exact(raw, {"middleware_id", "stage"}, "middleware")
        identity = core.identifier(entry["middleware_id"], "middleware ID")
        if identity in ids:
            raise DotnetMiddlewareBoundaryError("duplicate middleware ID")
        ids.add(identity)
        stage = core.choice(entry["stage"], _STAGES, "middleware stage")
        if stage != "other":
            stage_counts[stage] += 1
            if stage_counts[stage] > 1:
                raise DotnetMiddlewareBoundaryError(
                    "multiple modeled middleware stages are unsupported"
                )
        middleware.append({"middleware_id": identity, "stage": stage})
    if not complete and any(stage_counts[stage] == 0 for stage in ("routing", "endpoint")):
        pass
    elif stage_counts["routing"] != 1 or stage_counts["endpoint"] != 1:
        raise DotnetMiddlewareBoundaryError(
            "explicit endpoint routing needs one routing and endpoint stage"
        )
    routes: dict[str, dict] = {}
    paths: set[str] = set()
    for raw in raw_routes:
        route = core.exact(raw, {"route_id", "route_path", "requires_authorization"}, "route")
        identity = core.identifier(route["route_id"], "route ID")
        path = core.path(route["route_path"])
        if identity in routes or path in paths:
            raise DotnetMiddlewareBoundaryError("duplicate route ID or path")
        paths.add(path)
        routes[identity] = {
            "route_path": path,
            "requires_authorization": core.boolean(
                route["requires_authorization"], "requires authorization"
            ),
        }
    return complete, middleware, routes


def _project(complete: bool, middleware: list[dict], routes: dict[str, dict]) -> list[dict]:
    stages = {
        entry["stage"]: index for index, entry in enumerate(middleware) if entry["stage"] != "other"
    }
    window = [
        middleware[stages[stage]]["middleware_id"] if stage in stages else None
        for stage in ("routing", "authorization", "endpoint")
    ]
    projections = []
    for identity, route in sorted(routes.items()):
        if not complete:
            assessment, basis = "unknown", "incomplete_declarations"
        elif not route["requires_authorization"]:
            assessment, basis = "not_required", "not_required"
        elif "authorization" not in stages:
            assessment, basis = "candidate_declared_order_gap", "authorization_missing"
        elif stages["routing"] < stages["authorization"] < stages["endpoint"]:
            assessment, basis = (
                "declared_order_satisfied",
                "authorization_between_routing_and_endpoint",
            )
        else:
            assessment, basis = (
                "candidate_declared_order_gap",
                "authorization_outside_endpoint_window",
            )
        projections.append(
            {
                "route_id": identity,
                "route_path": route["route_path"],
                "requires_authorization": route["requires_authorization"],
                "stage_ids": list(window),
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
            "pipeline_kind",
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
        "pipeline_kind": "explicit_endpoint_routing",
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise DotnetMiddlewareBoundaryError(f"report {key} is invalid")
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
                "requires_authorization",
                "stage_ids",
                "assessment",
                "basis",
            },
            "projection",
        )
        ids.append(core.identifier(p["route_id"], "route ID"))
        core.path(p["route_path"])
        core.boolean(p["requires_authorization"], "requires authorization")
        stage_ids = core.bounded_list(p["stage_ids"], 3, "stage IDs")
        if len(stage_ids) != 3:
            raise DotnetMiddlewareBoundaryError("report stage IDs are invalid")
        for stage_id in stage_ids:
            if stage_id is not None:
                core.identifier(stage_id, "middleware ID")
        core.choice(p["basis"], _BASES, "basis")
        counts[core.choice(p["assessment"], _ASSESSMENTS, "assessment")] += 1
    if ids != sorted(set(ids)):
        raise DotnetMiddlewareBoundaryError("report route IDs must be sorted unique")
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
        raise DotnetMiddlewareBoundaryError("report summary is invalid")
    report_id, sha256 = core.report_address(item, domain=DOMAIN, prefix="DMB-")
    if item["report_id"] != report_id or item["report_sha256"] != sha256:
        raise DotnetMiddlewareBoundaryError("report address is invalid")


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise DotnetMiddlewareBoundaryError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DotnetMiddlewareBoundaryError("report must be UTF-8 JSON text") from exc
    document = core.decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return core.canonical(document)


@dataclass(frozen=True, slots=True)
class DotnetMiddlewareBoundaryReport:
    """Canonical report; exact original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not DotnetMiddlewareBoundaryReport or self._json != _checked_report_json(
            self._json
        ):
            raise DotnetMiddlewareBoundaryError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not DotnetMiddlewareBoundaryReport or self._json != _checked_report_json(
            self._json
        ):
            raise DotnetMiddlewareBoundaryError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> DotnetMiddlewareBoundaryReport:
        if cls is not DotnetMiddlewareBoundaryReport:
            raise DotnetMiddlewareBoundaryError("report must be the exact report family")
        return cls(_checked_report_json(content))


def analyze_dotnet_middleware_boundary(
    *, source_content: bytes, source_id: str
) -> DotnetMiddlewareBoundaryReport:
    """Project supplied middleware order without loading or executing a pipeline."""
    identity = core.identifier(source_id, "source ID")
    source = core.decode(source_content, maximum=MAX_SOURCE_BYTES)
    complete, middleware, routes = _model(source)
    projections = _project(complete, middleware, routes)
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
        "pipeline_kind": "explicit_endpoint_routing",
        "projections": projections,
        "summary": {"route_count": len(projections), "assessments": counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    document["report_id"], document["report_sha256"] = core.report_address(
        document, domain=DOMAIN, prefix="DMB-"
    )
    core.validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return DotnetMiddlewareBoundaryReport(core.canonical(document))


def analyze_supplied_dotnet_middleware_boundary(
    model: dict[str, Any],
) -> DotnetMiddlewareBoundaryReport:
    """Canonicalize an exact native source-backed component model."""
    core.validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = core.exact(model, {"source_id", "source"}, "component model")
    source_id = core.identifier(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_dotnet_middleware_boundary(
        source_content=core.canonical(item["source"]).encode("ascii"), source_id=source_id
    )


def verify_dotnet_middleware_boundary(
    report: DotnetMiddlewareBoundaryReport, *, source_content: bytes, source_id: str
) -> DotnetMiddlewareBoundaryReport:
    """Rebuild from exact original source bytes and compare the entire report."""
    if type(report) is not DotnetMiddlewareBoundaryReport:
        raise DotnetMiddlewareBoundaryError("report must be the exact report family")
    loaded = DotnetMiddlewareBoundaryReport.from_json(report.to_json())
    expected = analyze_dotnet_middleware_boundary(
        source_content=source_content, source_id=source_id
    )
    if loaded.to_json() != expected.to_json():
        raise DotnetMiddlewareBoundaryError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    """Return fresh synthetic explicit endpoint-routing declarations."""
    return {
        "schema_version": SCHEMA_VERSION,
        "declarations_complete": True,
        "pipeline_kind": "explicit_endpoint_routing",
        "middleware": [
            {"middleware_id": "routing", "stage": "routing"},
            {"middleware_id": "authentication", "stage": "authentication"},
            {"middleware_id": "authorization", "stage": "authorization"},
            {"middleware_id": "endpoints", "stage": "endpoint"},
        ],
        "routes": [
            {"route_id": "account", "route_path": "/account", "requires_authorization": True},
            {"route_id": "health", "route_path": "/health", "requires_authorization": False},
        ],
    }

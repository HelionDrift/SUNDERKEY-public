"""Project supplied Linux logging routes against required synthetic streams."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_logging_route_policy_projection"
PROFILE_ID = "AOE-GC-D12-S08"
CAPABILITY_ID = "army.gc.d12.s08"
VECTOR_ID = "AV-GC-D12-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:eb5818ad8bf81c1c8cd75e71d6baca35c8bb32ecc5c4dfa34ddf65800382ab98"
DOMAIN = "sunderkey.offline-linux-logging-routes.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class LinuxLoggingRouteError(ValueError):
    """A supplied logging-route model or replay is invalid."""


def _identifiers(value: Any, *, label: str, limit: int = 64) -> list[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, limit, label)]
    if len(items) != len(set(items)):
        raise LinuxLoggingRouteError(f"Duplicate {label}")
    return items


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "required_stream_ids", "sink_states", "stream_routes",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise LinuxLoggingRouteError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise LinuxLoggingRouteError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    required = set(_identifiers(model["required_stream_ids"], label="required stream ID"))
    sinks = {}
    for item in core.bounded_list(model["sink_states"], 64, "sink states"):
        row = core.exact(item, {"sink_id", "enabled_declared"}, "sink state")
        sink_id = core.identifier(row["sink_id"], "sink ID")
        if sink_id in sinks:
            raise LinuxLoggingRouteError("Duplicate sink ID")
        sinks[sink_id] = core.boolean(row["enabled_declared"], "enabled declaration")
    if not sinks:
        raise LinuxLoggingRouteError("At least one sink is required")
    routes = core.bounded_list(model["stream_routes"], 64, "stream routes")
    if not routes:
        raise LinuxLoggingRouteError("At least one stream route is required")
    rows = []
    seen = set()
    for item in routes:
        row = core.exact(item, {"stream_id", "sink_ids"}, "stream route")
        stream_id = core.identifier(row["stream_id"], "stream ID")
        if stream_id in seen:
            raise LinuxLoggingRouteError("Duplicate stream route")
        seen.add(stream_id)
        sink_ids = _identifiers(row["sink_ids"], label="route sink ID")
        if not set(sink_ids).issubset(sinks):
            raise LinuxLoggingRouteError("Route references an unknown sink")
        enabled_sink_ids = sorted(sink_id for sink_id in sink_ids if sinks[sink_id])
        flags = (
            ["required_stream_without_enabled_sink"]
            if stream_id in required and not enabled_sink_ids else []
        )
        rows.append({
            "stream_id": stream_id,
            "sink_ids": sorted(sink_ids),
            "enabled_sink_ids": enabled_sink_ids,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["stream_id"])
    missing_required = sorted(required - seen)
    deviations = [row["stream_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_logging_route_inventory_incomplete"]
    if missing_required:
        unknown.append("required_stream_absent_from_supplied_routes")
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "stream_projections": rows,
        "missing_required_stream_ids": missing_required,
        "declared_policy_deviation_stream_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_logging_route_projection",
        "source_authenticated": False,
        "host_connected": False,
        "log_record_read": False,
        "sink_connected": False,
        "control_changed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Required streams, routes, sink states, and completeness are assertions.",
            "The model does not read logs or verify effective delivery to any sink.",
            "A missing enabled route is a review signal, not proof of impairment.",
            "No host, log service, credential, sink, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="LLR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class LinuxLoggingRouteReport:
    """Unsigned route projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise LinuxLoggingRouteError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> LinuxLoggingRouteReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_logging_routes(model: Any) -> LinuxLoggingRouteReport:
    return LinuxLoggingRouteReport._owned(_derive(model))


def verify_supplied_logging_routes(
    report: Any, *, model: Any
) -> LinuxLoggingRouteReport:
    if type(report) is not LinuxLoggingRouteReport:
        raise LinuxLoggingRouteError("Exact logging route wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise LinuxLoggingRouteError("Report differs from separate original model")
    return LinuxLoggingRouteReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-logging-routes",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "required_stream_ids": ["security"],
        "sink_states": [{"sink_id": "sink-a", "enabled_declared": False}],
        "stream_routes": [{"stream_id": "security", "sink_ids": ["sink-a"]}],
    }

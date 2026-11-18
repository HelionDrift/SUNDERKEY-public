"""Compare synthetic Windows remote-session routes with supplied scope."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_remote_route_policy_projection"
PROFILE_ID = "AOE-GC-D11-S12"
CAPABILITY_ID = "army.gc.d11.s12"
VECTOR_ID = "AV-GC-D11-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:938ec72b977d2a2d2492c06fb76ad70fcd02e47f47bf1dea468ebe342e4d3528"
DOMAIN = "sunderkey.offline-windows-remote-routes.v1"
CHANNELS = frozenset({"winrm", "wmi", "rdp", "smb"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsRemoteRouteError(ValueError):
    """A supplied remote-route model or replay is invalid."""


def _route(item: Any, *, label: str) -> tuple[str, str, str]:
    row = core.exact(item, {"source_host_id", "destination_host_id", "channel"}, label)
    source = core.identifier(row["source_host_id"], "source host ID")
    destination = core.identifier(row["destination_host_id"], "destination host ID")
    channel = core.identifier(row["channel"], "channel")
    if channel not in CHANNELS:
        raise WindowsRemoteRouteError("Unknown remote channel")
    return source, destination, channel


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_routes", "sessions",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsRemoteRouteError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsRemoteRouteError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        _route(item, label="approved route")
        for item in core.bounded_list(model["approved_routes"], 64, "approved routes")
    ]
    if len(approved) != len(set(approved)):
        raise WindowsRemoteRouteError("Approved routes must be unique")
    sessions = core.bounded_list(model["sessions"], 64, "sessions")
    if not sessions:
        raise WindowsRemoteRouteError("At least one session is required")
    rows = []
    seen = set()
    for item in sessions:
        row = core.exact(item, {
            "session_id", "source_host_id", "destination_host_id", "channel",
            "session_declared",
        }, "session")
        session_id = core.identifier(row["session_id"], "session ID")
        if session_id in seen:
            raise WindowsRemoteRouteError("Duplicate session ID")
        seen.add(session_id)
        route = _route({key: row[key] for key in (
            "source_host_id", "destination_host_id", "channel"
        )}, label="session route")
        declared = core.boolean(row["session_declared"], "session declaration")
        flags = (
            ["session_outside_supplied_route_scope"]
            if declared and route not in approved else []
        )
        rows.append({
            "session_id": session_id,
            "source_host_id": route[0],
            "destination_host_id": route[1],
            "channel": route[2],
            "session_declared": declared,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["session_id"])
    deviations = [row["session_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_remote_session_inventory_incomplete"]
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
        "session_projections": rows,
        "declared_policy_deviation_session_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_remote_route_projection",
        "source_authenticated": False,
        "host_connected": False,
        "remote_session_opened": False,
        "credential_used": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Host IDs, route approvals, sessions, and completeness are assertions.",
            "The model does not establish reachability or authorization to any host.",
            "A route mismatch is a review signal, not proof of lateral movement.",
            "No host, credential, remote session, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WRR-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsRemoteRouteReport:
    """Unsigned route projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsRemoteRouteError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsRemoteRouteReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_remote_routes(model: Any) -> WindowsRemoteRouteReport:
    return WindowsRemoteRouteReport._owned(_derive(model))


def verify_supplied_remote_routes(
    report: Any, *, model: Any
) -> WindowsRemoteRouteReport:
    if type(report) is not WindowsRemoteRouteReport:
        raise WindowsRemoteRouteError("Exact remote route wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsRemoteRouteError("Report differs from separate original model")
    return WindowsRemoteRouteReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-remote-routes",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_routes": [{
            "source_host_id": "host-a", "destination_host_id": "host-b", "channel": "winrm",
        }],
        "sessions": [{
            "session_id": "session-a", "source_host_id": "host-a",
            "destination_host_id": "host-c", "channel": "winrm",
            "session_declared": True,
        }],
    }

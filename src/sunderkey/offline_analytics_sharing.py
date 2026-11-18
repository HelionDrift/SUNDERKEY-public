"""Project supplied managed-analytics sharing without service access."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_analytics_sharing"
PROFILE_ID = "AOE-GB-D07-S12"
CAPABILITY_ID = "army.gb.d07.s12"
VECTOR_ID = "AV-GB-D07-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D07-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GB-D07-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:d806bbeeb04dda64357a6597f497fe6066e29025ec9a7d9655b1cb23bd4c876d"
SEMANTICS_PROFILE = "supplied-analytics-sharing-v1"
DOMAIN = "sunderkey.offline-analytics-sharing.v1"
MAX_PRINCIPALS = 128
MAX_WORKSPACES = 64
MAX_SOURCES = 128
MAX_DASHBOARDS = 128
MAX_SOURCES_PER_DASHBOARD = 32
MAX_SHARES = 256
MAX_OBJECTIVES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_PRINCIPAL = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
_TENANT = re.compile(r"tenant:sha256:[0-9a-f]{64}\Z")
_WORKSPACE = re.compile(r"workspace:sha256:[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"source:sha256:[0-9a-f]{64}\Z")
_DASHBOARD = re.compile(r"dashboard:sha256:[0-9a-f]{64}\Z")
_PERMISSIONS = frozenset(("view", "export"))
_STATES = frozenset(("declared_granted", "declared_denied", "unknown"))
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "dashboard",
        "execution",
        "export",
        "filesystem",
        "network",
        "provider",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class AnalyticsSharingError(ValueError):
    """A supplied analytics model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise AnalyticsSharingError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise AnalyticsSharingError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise AnalyticsSharingError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise AnalyticsSharingError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise AnalyticsSharingError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise AnalyticsSharingError("Native JSON text keys are required")
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
        raise AnalyticsSharingError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise AnalyticsSharingError(f"{label} fields are invalid")


def _ref(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise AnalyticsSharingError(f"{label} must be an opaque digest reference")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version", "semantics_profile", "sharing_complete", "principals",
            "workspaces", "data_sources", "dashboards", "shares", "objectives",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AnalyticsSharingError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise AnalyticsSharingError("Semantics profile is invalid")
    if type(model["sharing_complete"]) is not bool:
        raise AnalyticsSharingError("Sharing completeness must be an exact boolean")
    limits = (
        ("principals", MAX_PRINCIPALS, True),
        ("workspaces", MAX_WORKSPACES, True),
        ("data_sources", MAX_SOURCES, True),
        ("dashboards", MAX_DASHBOARDS, True),
        ("shares", MAX_SHARES, False),
        ("objectives", MAX_OBJECTIVES, True),
    )
    for name, maximum, required in limits:
        value = model[name]
        if type(value) is not list or len(value) > maximum or (required and not value):
            raise AnalyticsSharingError(f"{name} count is invalid")
    principals: set[str] = set()
    for row in model["principals"]:
        _fields(row, {"principal_ref", "tenant_ref"}, "principal")
        principal = _ref(row["principal_ref"], _PRINCIPAL, "Principal")
        if principal in principals:
            raise AnalyticsSharingError("Duplicate principal reference")
        principals.add(principal)
        _ref(row["tenant_ref"], _TENANT, "Principal tenant")
    workspaces: set[str] = set()
    for row in model["workspaces"]:
        _fields(row, {"workspace_ref", "tenant_ref"}, "workspace")
        workspace = _ref(row["workspace_ref"], _WORKSPACE, "Workspace")
        if workspace in workspaces:
            raise AnalyticsSharingError("Duplicate workspace reference")
        workspaces.add(workspace)
        _ref(row["tenant_ref"], _TENANT, "Workspace tenant")
    sources: set[str] = set()
    for row in model["data_sources"]:
        _fields(row, {"source_ref", "tenant_ref"}, "source")
        source = _ref(row["source_ref"], _SOURCE, "Source")
        if source in sources:
            raise AnalyticsSharingError("Duplicate source reference")
        sources.add(source)
        _ref(row["tenant_ref"], _TENANT, "Source tenant")
    dashboards: set[str] = set()
    for row in model["dashboards"]:
        _fields(row, {"dashboard_ref", "workspace_ref", "source_refs"}, "dashboard")
        dashboard = _ref(row["dashboard_ref"], _DASHBOARD, "Dashboard")
        if dashboard in dashboards:
            raise AnalyticsSharingError("Duplicate dashboard reference")
        dashboards.add(dashboard)
        if _ref(row["workspace_ref"], _WORKSPACE, "Dashboard workspace") not in workspaces:
            raise AnalyticsSharingError("Dashboard workspace is undeclared")
        selected = row["source_refs"]
        if type(selected) is not list or not 1 <= len(selected) <= MAX_SOURCES_PER_DASHBOARD:
            raise AnalyticsSharingError("Dashboard source count is invalid")
        checked = []
        for item in selected:
            source = _ref(item, _SOURCE, "Dashboard source")
            if source not in sources:
                raise AnalyticsSharingError("Dashboard source is undeclared")
            checked.append(source)
        if len(set(checked)) != len(checked):
            raise AnalyticsSharingError("Duplicate dashboard source")
    share_ids: set[str] = set()
    share_keys: set[tuple[str, str, str]] = set()
    for row in model["shares"]:
        _fields(
            row,
            {"share_id", "principal_ref", "dashboard_ref", "permission", "state"},
            "share",
        )
        share_id = row["share_id"]
        if type(share_id) is not str or _ID.fullmatch(share_id) is None:
            raise AnalyticsSharingError("Share identifier is invalid")
        permission = row["permission"]
        if type(permission) is not str or permission not in _PERMISSIONS:
            raise AnalyticsSharingError("Share permission is invalid")
        key = (
            _ref(row["principal_ref"], _PRINCIPAL, "Share principal"),
            _ref(row["dashboard_ref"], _DASHBOARD, "Share dashboard"),
            permission,
        )
        if key[0] not in principals or key[1] not in dashboards:
            raise AnalyticsSharingError("Share subject is undeclared")
        if type(row["state"]) is not str or row["state"] not in _STATES:
            raise AnalyticsSharingError("Share state is invalid")
        if share_id in share_ids or key in share_keys:
            raise AnalyticsSharingError("Duplicate or contradictory share")
        share_ids.add(share_id)
        share_keys.add(key)
    seen: set[tuple[str, str, str]] = set()
    for row in model["objectives"]:
        _fields(row, {"principal_ref", "dashboard_ref", "permission"}, "objective")
        permission = row["permission"]
        if type(permission) is not str or permission not in _PERMISSIONS:
            raise AnalyticsSharingError("Objective permission is invalid")
        key = (
            _ref(row["principal_ref"], _PRINCIPAL, "Objective principal"),
            _ref(row["dashboard_ref"], _DASHBOARD, "Objective dashboard"),
            permission,
        )
        if key[0] not in principals or key[1] not in dashboards:
            raise AnalyticsSharingError("Objective subject is undeclared")
        if key in seen:
            raise AnalyticsSharingError("Objective is duplicated")
        seen.add(key)
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    principals = {row["principal_ref"]: row["tenant_ref"] for row in plan["principals"]}
    workspaces = {row["workspace_ref"]: row["tenant_ref"] for row in plan["workspaces"]}
    sources = {row["source_ref"]: row["tenant_ref"] for row in plan["data_sources"]}
    dashboards = {row["dashboard_ref"]: row for row in plan["dashboards"]}
    shares = {
        (row["principal_ref"], row["dashboard_ref"], row["permission"]): row
        for row in plan["shares"]
    }
    findings = []
    for objective in plan["objectives"]:
        key = (
            objective["principal_ref"],
            objective["dashboard_ref"],
            objective["permission"],
        )
        share = shares.get(key)
        workspace_mismatch = False
        cross_tenant_sources: list[str] = []
        if share is None:
            disposition = (
                "no_supplied_share" if plan["sharing_complete"] else "unknown_incomplete_sharing"
            )
        elif share["state"] == "declared_denied":
            disposition = "declared_denied"
        elif share["state"] == "unknown":
            disposition = "unknown_share_state"
        else:
            tenant = principals[key[0]]
            dashboard = dashboards[key[1]]
            workspace_mismatch = workspaces[dashboard["workspace_ref"]] != tenant
            cross_tenant_sources = sorted(
                source for source in dashboard["source_refs"] if sources[source] != tenant
            )
            disposition = (
                "declared_cross_tenant_share"
                if workspace_mismatch or cross_tenant_sources
                else "declared_aligned_share"
            )
        findings.append(
            {
                "principal_ref": key[0],
                "dashboard_ref": key[1],
                "permission": key[2],
                "share_id": share["share_id"] if share is not None else None,
                "disposition": disposition,
                "workspace_tenant_mismatch": workspace_mismatch,
                "cross_tenant_source_refs": cross_tenant_sources,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "findings": findings,
        "flags": {
            "principal_identity_verified": False,
            "dashboard_configuration_verified": False,
            "data_source_contents_verified": False,
            "effective_share_proven": False,
            "exposure_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Principals, tenancy, dashboards, data sources, and shares are caller-supplied.",
            "Only exact declared view and export labels are compared.",
            "A declared cross-tenant share does not prove effective access or exposure.",
            "No dashboard, analytics service, provider, credential, network, "
            "or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "ASH-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class AnalyticsSharing:
    """Immutable report replayed from supplied managed-analytics declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise AnalyticsSharingError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise AnalyticsSharingError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_analytics_sharing(model: Any) -> AnalyticsSharing:
    """Compare declared analytics sharing without target interaction."""
    return AnalyticsSharing(_derive(model))


def verify_supplied_analytics_sharing(report: Any, *, model: Any) -> AnalyticsSharing:
    if type(report) is not AnalyticsSharing:
        raise AnalyticsSharingError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise AnalyticsSharingError("Report differs from supplied model replay")
    return AnalyticsSharing(expected)

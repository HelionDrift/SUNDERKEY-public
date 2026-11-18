"""Compare synthetic Windows administration invocations with supplied approval."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_admin_invocation_policy_projection"
PROFILE_ID = "AOE-GC-D11-S10"
CAPABILITY_ID = "army.gc.d11.s10"
VECTOR_ID = "AV-GC-D11-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:54ecbd4b054263cca039d174986e1f60203f088219f4ae43134c148261e8dc07"
DOMAIN = "sunderkey.offline-windows-admin-invocations.v1"
FAMILIES = frozenset({"powershell", "wmi", "com", "lolbin"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsAdminInvocationError(ValueError):
    """A supplied administration invocation model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_invocation_ids", "invocations",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsAdminInvocationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsAdminInvocationError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved invocation ID")
        for item in core.bounded_list(model["approved_invocation_ids"], 64, "approvals")
    ]
    if len(approved) != len(set(approved)):
        raise WindowsAdminInvocationError("Approved invocation IDs must be unique")
    invocations = core.bounded_list(model["invocations"], 64, "invocations")
    if not invocations:
        raise WindowsAdminInvocationError("At least one invocation is required")
    rows = []
    seen = set()
    for item in invocations:
        row = core.exact(item, {
            "invocation_id", "family", "privileged_context_declared",
        }, "invocation")
        invocation_id = core.identifier(row["invocation_id"], "invocation ID")
        family = core.identifier(row["family"], "family")
        if invocation_id in seen or family not in FAMILIES:
            raise WindowsAdminInvocationError("Duplicate invocation or unknown family")
        seen.add(invocation_id)
        privileged = core.boolean(
            row["privileged_context_declared"], "privileged context declaration"
        )
        flags = (
            ["privileged_invocation_outside_supplied_approval"]
            if privileged and invocation_id not in approved else []
        )
        rows.append({
            "invocation_id": invocation_id,
            "family": family,
            "privileged_context_declared": privileged,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["invocation_id"])
    deviations = [row["invocation_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_admin_invocation_inventory_incomplete"]
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
        "invocation_projections": rows,
        "declared_policy_deviation_invocation_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_admin_invocation_projection",
        "source_authenticated": False,
        "host_connected": False,
        "command_text_read": False,
        "invocation_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Invocation family, context, approval, and completeness are assertions.",
            "The model does not parse commands or prove unauthorized activity.",
            "An approval mismatch is a review signal, not a vulnerability finding.",
            "No command, host, process, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WAI-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsAdminInvocationReport:
    """Unsigned invocation projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsAdminInvocationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsAdminInvocationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_admin_invocations(model: Any) -> WindowsAdminInvocationReport:
    return WindowsAdminInvocationReport._owned(_derive(model))


def verify_supplied_admin_invocations(
    report: Any, *, model: Any
) -> WindowsAdminInvocationReport:
    if type(report) is not WindowsAdminInvocationReport:
        raise WindowsAdminInvocationError("Exact administration invocation wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsAdminInvocationError("Report differs from separate original model")
    return WindowsAdminInvocationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-admin-invocations",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_invocation_ids": ["approved-invocation"],
        "invocations": [{
            "invocation_id": "review-invocation",
            "family": "wmi",
            "privileged_context_declared": True,
        }],
    }

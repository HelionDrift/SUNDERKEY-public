"""Compare synthetic Windows autostart declarations with a supplied allowlist."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_autostart_policy_projection"
PROFILE_ID = "AOE-GC-D11-S09"
CAPABILITY_ID = "army.gc.d11.s09"
VECTOR_ID = "AV-GC-D11-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3aefaacf845b1401214b26d901092c87be3cd7c9982022a1b07aff12450281c4"
DOMAIN = "sunderkey.offline-windows-autostart-policy.v1"
MECHANISMS = frozenset({
    "service", "scheduled_task", "run_key", "startup_folder", "wmi_subscription",
})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsAutostartPolicyError(ValueError):
    """A supplied autostart model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_artifact_ids", "artifacts",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsAutostartPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsAutostartPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved artifact ID")
        for item in core.bounded_list(model["approved_artifact_ids"], 64, "approved artifacts")
    ]
    if len(approved) != len(set(approved)):
        raise WindowsAutostartPolicyError("Approved artifact IDs must be unique")
    artifacts = core.bounded_list(model["artifacts"], 64, "artifacts")
    if not artifacts:
        raise WindowsAutostartPolicyError("At least one artifact is required")
    rows = []
    seen = set()
    for item in artifacts:
        row = core.exact(item, {
            "artifact_id", "mechanism", "enabled_declared",
        }, "artifact")
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        mechanism = core.identifier(row["mechanism"], "mechanism")
        if artifact_id in seen or mechanism not in MECHANISMS:
            raise WindowsAutostartPolicyError("Duplicate artifact or unknown mechanism")
        seen.add(artifact_id)
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = (
            ["enabled_outside_supplied_allowlist"]
            if enabled and artifact_id not in approved else []
        )
        rows.append({
            "artifact_id": artifact_id,
            "mechanism": mechanism,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["artifact_id"])
    deviations = [row["artifact_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_autostart_inventory_incomplete"]
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
        "artifact_projections": rows,
        "declared_policy_deviation_artifact_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_autostart_policy_projection",
        "source_authenticated": False,
        "host_connected": False,
        "autostart_verified": False,
        "artifact_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The artifact inventory, approval list, and completeness are assertions.",
            "The model does not inspect Windows autoruns or prove persistence.",
            "An allowlist mismatch is a review signal, not a vulnerability finding.",
            "No host, process, credential, artifact, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WAP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsAutostartPolicyReport:
    """Unsigned allowlist projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsAutostartPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsAutostartPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_autostarts(model: Any) -> WindowsAutostartPolicyReport:
    return WindowsAutostartPolicyReport._owned(_derive(model))


def verify_supplied_autostarts(
    report: Any, *, model: Any
) -> WindowsAutostartPolicyReport:
    if type(report) is not WindowsAutostartPolicyReport:
        raise WindowsAutostartPolicyError("Exact autostart wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsAutostartPolicyError("Report differs from separate original model")
    return WindowsAutostartPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-autostarts",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_artifact_ids": ["approved-task"],
        "artifacts": [{
            "artifact_id": "unapproved-task",
            "mechanism": "scheduled_task",
            "enabled_declared": True,
        }],
    }

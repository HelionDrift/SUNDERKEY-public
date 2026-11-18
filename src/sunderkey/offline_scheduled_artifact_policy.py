"""Compare synthetic scheduled-artifact declarations with supplied policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "linux_supplied_scheduled_artifact_policy_projection"
PROFILE_ID = "AOE-GC-D12-S04"
CAPABILITY_ID = "army.gc.d12.s04"
VECTOR_ID = "AV-GC-D12-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S04"
WAVE_ID = "IW2-004"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:daeee0d26d9bb2983331493f1c2648271af7fec9b8faecfde97a59a6ce9aef86"
DOMAIN = "sunderkey.offline-scheduled-artifact-policy.v1"
SOURCES = {"systemd_timer", "cron"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class ScheduledArtifactPolicyError(ValueError):
    """A supplied schedule declaration or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "policies", "schedules",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ScheduledArtifactPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise ScheduledArtifactPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    policies = {}
    for item in core.bounded_list(model["policies"], 32, "policies"):
        row = core.exact(item, {
            "policy_id", "allowed_source_ids", "allowed_artifact_ids",
        }, "policy")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if policy_id in policies:
            raise ScheduledArtifactPolicyError("Duplicate policy ID")
        source_ids = [
            core.choice(source, SOURCES, "schedule source")
            for source in core.bounded_list(row["allowed_source_ids"], 2, "sources")
        ]
        artifact_ids = [
            core.identifier(artifact, "artifact ID")
            for artifact in core.bounded_list(
                row["allowed_artifact_ids"], 32, "allowed artifacts"
            )
        ]
        if len(source_ids) != len(set(source_ids)) or len(artifact_ids) != len(set(artifact_ids)):
            raise ScheduledArtifactPolicyError("Duplicate source or artifact in policy")
        policies[policy_id] = {
            "sources": set(source_ids),
            "artifacts": set(artifact_ids),
        }
    if not policies:
        raise ScheduledArtifactPolicyError("At least one policy is required")
    schedules = core.bounded_list(model["schedules"], 64, "schedules")
    if not schedules:
        raise ScheduledArtifactPolicyError("At least one schedule is required")
    rows = []
    seen = set()
    for item in schedules:
        row = core.exact(item, {
            "schedule_id", "policy_id", "source_id", "artifact_id", "enabled_declared",
        }, "schedule")
        schedule_id = core.identifier(row["schedule_id"], "schedule ID")
        policy_id = core.identifier(row["policy_id"], "policy ID")
        if schedule_id in seen or policy_id not in policies:
            raise ScheduledArtifactPolicyError("Duplicate schedule or unknown policy")
        seen.add(schedule_id)
        source_id = core.choice(row["source_id"], SOURCES, "schedule source")
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = []
        if enabled and source_id not in policies[policy_id]["sources"]:
            flags.append("source_outside_supplied_policy")
        if enabled and artifact_id not in policies[policy_id]["artifacts"]:
            flags.append("artifact_outside_supplied_policy")
        rows.append({
            "schedule_id": schedule_id,
            "policy_id": policy_id,
            "source_id": source_id,
            "artifact_id": artifact_id,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["schedule_id"])
    deviations = [row["schedule_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_schedule_inventory_incomplete"]
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
        "schedule_projections": rows,
        "declared_policy_deviation_schedule_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_schedule_projection",
        "source_authenticated": False,
        "host_configuration_read": False,
        "systemd_unit_parsed": False,
        "crontab_parsed": False,
        "service_started": False,
        "persistence_installed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Schedule, source, artifact, policy, and completeness are supplied assertions.",
            "Labels are not parsed systemd units or crontab expressions.",
            "A declared policy mismatch does not prove installed persistence.",
            "No host, service, scheduler, process, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SAP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ScheduledArtifactPolicyReport:
    """Unsigned schedule projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ScheduledArtifactPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ScheduledArtifactPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_schedules(model: Any) -> ScheduledArtifactPolicyReport:
    return ScheduledArtifactPolicyReport._owned(_derive(model))


def verify_supplied_schedules(
    report: Any, *, model: Any
) -> ScheduledArtifactPolicyReport:
    if type(report) is not ScheduledArtifactPolicyReport:
        raise ScheduledArtifactPolicyError("Exact schedule wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ScheduledArtifactPolicyError("Report differs from separate original model")
    return ScheduledArtifactPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-schedules",
        "synthetic_fixture": True, "inventory_complete": True,
        "policies": [{
            "policy_id": "maintenance", "allowed_source_ids": ["systemd_timer"],
            "allowed_artifact_ids": ["approved-job"],
        }],
        "schedules": [{
            "schedule_id": "task-a", "policy_id": "maintenance", "source_id": "cron",
            "artifact_id": "other-job", "enabled_declared": True,
        }],
    }

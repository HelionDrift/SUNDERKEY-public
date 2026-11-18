"""Compare synthetic launchd job declarations with supplied approval."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_launch_job_policy_projection"
PROFILE_ID = "AOE-GC-D12-S11"
CAPABILITY_ID = "army.gc.d12.s11"
VECTOR_ID = "AV-GC-D12-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D12-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GC-D12-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8c4c2b22c982bfc773c13374afc83facdb44c2d84bb6a00a60df8f943703ede0"
DOMAIN = "sunderkey.offline-macos-launch-policy.v1"
JOB_DOMAINS = frozenset({"user", "system"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosLaunchPolicyError(ValueError):
    """A supplied launch job model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "approved_job_ids", "jobs",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosLaunchPolicyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosLaunchPolicyError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    approved = [
        core.identifier(item, "approved job ID")
        for item in core.bounded_list(model["approved_job_ids"], 64, "approved jobs")
    ]
    if len(approved) != len(set(approved)):
        raise MacosLaunchPolicyError("Approved job IDs must be unique")
    jobs = core.bounded_list(model["jobs"], 64, "jobs")
    if not jobs:
        raise MacosLaunchPolicyError("At least one job is required")
    rows = []
    seen = set()
    for item in jobs:
        row = core.exact(item, {"job_id", "job_domain", "enabled_declared"}, "job")
        job_id = core.identifier(row["job_id"], "job ID")
        domain = core.identifier(row["job_domain"], "job domain")
        if job_id in seen or domain not in JOB_DOMAINS:
            raise MacosLaunchPolicyError("Duplicate job or unknown domain")
        seen.add(job_id)
        enabled = core.boolean(row["enabled_declared"], "enabled declaration")
        flags = (
            ["enabled_job_outside_supplied_approval"]
            if enabled and job_id not in approved else []
        )
        rows.append({
            "job_id": job_id,
            "job_domain": domain,
            "enabled_declared": enabled,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["job_id"])
    deviations = [row["job_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_launch_job_inventory_incomplete"]
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
        "job_projections": rows,
        "declared_policy_deviation_job_ids": deviations,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_launch_job_projection",
        "source_authenticated": False,
        "host_connected": False,
        "launchd_queried": False,
        "job_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Launch jobs, approval, enabled state, and completeness are assertions.",
            "The model does not inspect launchd configuration or prove persistence.",
            "An approval mismatch is a review signal, not a finding.",
            "No host, job, process, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MLP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosLaunchPolicyReport:
    """Unsigned launch-job projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosLaunchPolicyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosLaunchPolicyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_launch_jobs(model: Any) -> MacosLaunchPolicyReport:
    return MacosLaunchPolicyReport._owned(_derive(model))


def verify_supplied_launch_jobs(
    report: Any, *, model: Any
) -> MacosLaunchPolicyReport:
    if type(report) is not MacosLaunchPolicyReport:
        raise MacosLaunchPolicyError("Exact launch job wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosLaunchPolicyError("Report differs from separate original model")
    return MacosLaunchPolicyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-launch-jobs",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "approved_job_ids": ["approved-job"],
        "jobs": [{
            "job_id": "review-job", "job_domain": "system", "enabled_declared": True,
        }],
    }

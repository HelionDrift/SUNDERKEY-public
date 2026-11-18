"""Compare supplied HPC scheduler queue and isolation declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "hpc_supplied_queue_posture_projection"
PROFILE_ID = "AOE-GC-D16-S12"
CAPABILITY_ID = "army.gc.d16.s12"
VECTOR_ID = "AV-GC-D16-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S12"
WAVE_ID = "IW2-024"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:441846e26c0d3cc39c1d37adfb99a576a79b17f2bb65fe667566a695e2f7f641"
DOMAIN = "sunderkey.offline-hpc-queue-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_QUEUES = 32
SUBMITTER_SCOPES = {"approved", "public", "unknown"}
ISOLATION = {"isolated", "shared", "unknown"}
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


class HpcQueuePostureError(ValueError):
    """The reduced queue declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "queues"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise HpcQueuePostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["queues"], MAX_QUEUES, "queues"):
        queue = core.exact(
            row,
            {
                "queue_id",
                "submitter_scope",
                "job_isolation",
                "credential_forwarding_allowed",
                "policy_assertions_complete",
            },
            "queue",
        )
        queue_id = core.identifier(queue["queue_id"], "queue ID")
        if queue_id in seen:
            raise HpcQueuePostureError("Duplicate queue ID")
        seen.add(queue_id)
        core.choice(queue["submitter_scope"], SUBMITTER_SCOPES, "submitter scope")
        core.choice(queue["job_isolation"], ISOLATION, "job isolation")
        if queue["credential_forwarding_allowed"] is not None:
            core.boolean(queue["credential_forwarding_allowed"], "credential forwarding")
        core.boolean(queue["policy_assertions_complete"], "policy completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    queues = sorted(model["queues"], key=lambda row: row["queue_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for queue in queues:
        queue_id = queue["queue_id"]
        if not queue["policy_assertions_complete"]:
            uncertainty.append({"issue": "incomplete_declared_queue_policy", "queue_id": queue_id})
            continue
        if queue["submitter_scope"] == "unknown":
            uncertainty.append({"issue": "submitter_scope_unknown", "queue_id": queue_id})
        elif queue["submitter_scope"] == "public":
            signals.append({"issue": "declared_public_job_submission", "queue_id": queue_id})
        if queue["job_isolation"] == "unknown":
            uncertainty.append({"issue": "job_isolation_unknown", "queue_id": queue_id})
        elif queue["job_isolation"] == "shared":
            signals.append({"issue": "declared_shared_job_execution", "queue_id": queue_id})
        if queue["credential_forwarding_allowed"] is None:
            uncertainty.append({"issue": "credential_forwarding_unknown", "queue_id": queue_id})
        elif queue["credential_forwarding_allowed"]:
            signals.append({"issue": "declared_credential_forwarding", "queue_id": queue_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "queue_id": "none"})
    signals.sort(key=lambda row: (row["queue_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["queue_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_hpc_queue_review"
    elif uncertainty or not queues:
        disposition = "unknown"
    else:
        disposition = "no_declared_hpc_queue_review_signal"
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
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "inventory_complete_asserted": model["inventory_complete"],
        "queue_count": len(queues),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not queues),
        "disposition": disposition,
        "source_authenticated": False,
        "scheduler_policy_verified": False,
        "queue_contacted": False,
        "job_submitted": False,
        "credential_accessed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Submitter, isolation and credential-forwarding labels are supplied assertions.",
            "No scheduler, queue policy, job specification or cluster node is parsed.",
            "A declared queue policy difference is a review hypothesis, not job access proof.",
            "No job is submitted and no queue, node, credential or target is contacted.",
            "An absent signal does not establish scheduler or workload safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="HQP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class HpcQueuePostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise HpcQueuePostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> HpcQueuePostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_hpc_queue_posture(model: Any) -> HpcQueuePostureReport:
    return HpcQueuePostureReport._owned(_derive(model))


def verify_supplied_hpc_queue_posture(report: Any, *, model: Any) -> HpcQueuePostureReport:
    if type(report) is not HpcQueuePostureReport:
        raise HpcQueuePostureError("Exact HPC posture wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise HpcQueuePostureError("Report differs from separate original model")
    return HpcQueuePostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-hpc-queue",
        "inventory_complete": True,
        "queues": [
            {
                "queue_id": "queue_a",
                "submitter_scope": "public",
                "job_isolation": "shared",
                "credential_forwarding_allowed": True,
                "policy_assertions_complete": True,
            }
        ],
    }

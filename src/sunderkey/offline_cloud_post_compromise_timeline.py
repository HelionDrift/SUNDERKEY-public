"""Project supplied cloud artifact appearance without inferring compromise."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "cloud_supplied_post_compromise_control_timeline"
PROFILE_ID = "AOE-GC-D14-S18"
CAPABILITY_ID = "army.gc.d14.s18"
VECTOR_ID = "AV-GC-D14-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D14-S18"
WAVE_ID = "IW2-021"
COMMANDER_ID = "AOE-GC-D14-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d9ed08b343ad05c6f60199a46623683a69ed8c0b6393597727309dbc870f13df"
DOMAIN = "sunderkey.offline-cloud-post-compromise-timeline.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
KINDS = {"role_trust", "access_key_metadata", "automation_binding"}
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


class CloudPostCompromiseTimelineError(ValueError):
    """A supplied artifact timeline or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "scope_id",
            "baseline_snapshot_id",
            "later_snapshot_id",
            "artifacts",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CloudPostCompromiseTimelineError("Unsupported model version")
    for key in ("source_id", "scope_id", "baseline_snapshot_id", "later_snapshot_id"):
        core.identifier(model[key], key)
    if model["baseline_snapshot_id"] == model["later_snapshot_id"]:
        raise CloudPostCompromiseTimelineError("Snapshots must be distinct")
    artifacts = core.bounded_list(model["artifacts"], 32, "artifacts")
    if not artifacts:
        raise CloudPostCompromiseTimelineError("At least one artifact is required")
    seen: set[str] = set()
    for item in artifacts:
        artifact = core.exact(
            item,
            {
                "artifact_id",
                "kind",
                "baseline_present",
                "later_present",
                "approved_change",
                "context_complete",
            },
            "artifact",
        )
        artifact_id = core.identifier(artifact["artifact_id"], "artifact ID")
        if artifact_id in seen:
            raise CloudPostCompromiseTimelineError("Duplicate artifact ID")
        seen.add(artifact_id)
        core.choice(artifact["kind"], KINDS, "artifact kind")
        for key in ("baseline_present", "later_present", "approved_change", "context_complete"):
            core.boolean(artifact[key], key)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows = []
    for artifact in model["artifacts"]:
        disposition = (
            "unknown"
            if not artifact["context_complete"]
            else "candidate_declared_unreviewed_artifact_appearance"
            if not artifact["baseline_present"]
            and artifact["later_present"]
            and not artifact["approved_change"]
            else "no_declared_unreviewed_artifact_appearance"
        )
        rows.append(
            {
                "artifact_id": artifact["artifact_id"],
                "kind": artifact["kind"],
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "scope_id": model["scope_id"],
        "baseline_snapshot_id": model["baseline_snapshot_id"],
        "later_snapshot_id": model["later_snapshot_id"],
        "artifact_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "provider_queried": False,
        "artifact_existence_verified": False,
        "compromise_inferred": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Snapshot membership, change approval and artifact kinds are caller-supplied labels.",
            "No cloud provider, credential material, artifact contents or target is accessed.",
            "An unreviewed declared appearance does not establish persistence or compromise.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CPT-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class CloudPostCompromiseTimelineReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CloudPostCompromiseTimelineError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CloudPostCompromiseTimelineReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cloud_post_compromise(model: Any) -> CloudPostCompromiseTimelineReport:
    return CloudPostCompromiseTimelineReport._owned(_derive(model))


def verify_supplied_cloud_post_compromise(
    report: Any, *, model: Any
) -> CloudPostCompromiseTimelineReport:
    if type(report) is not CloudPostCompromiseTimelineReport:
        raise CloudPostCompromiseTimelineError("Exact cloud artifact timeline wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CloudPostCompromiseTimelineError("Report differs from separate original model")
    return CloudPostCompromiseTimelineReport._owned(expected)


def verify_supplied_cloud_post_compromise_bytes(
    report_bytes: bytes, *, model: Any
) -> CloudPostCompromiseTimelineReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise CloudPostCompromiseTimelineError("Exported report differs from original replay")
    return CloudPostCompromiseTimelineReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-cloud-artifacts",
        "scope_id": "account-one",
        "baseline_snapshot_id": "snapshot-one",
        "later_snapshot_id": "snapshot-two",
        "artifacts": [
            {
                "artifact_id": "role-trust-new",
                "kind": "role_trust",
                "baseline_present": False,
                "later_present": True,
                "approved_change": False,
                "context_complete": True,
            },
            {
                "artifact_id": "automation-existing",
                "kind": "automation_binding",
                "baseline_present": True,
                "later_present": True,
                "approved_change": False,
                "context_complete": True,
            },
        ],
    }

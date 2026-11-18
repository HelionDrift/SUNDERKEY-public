"""Project supplied Windows artifact write and execution declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "windows_supplied_privilege_artifact_projection"
PROFILE_ID = "AOE-GC-D11-S08"
CAPABILITY_ID = "army.gc.d11.s08"
VECTOR_ID = "AV-GC-D11-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S08"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GC-D11-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:fe9c4c7933c95d70f21a86b87cf88bfe13a14d2b5373e93ac250a8ff9b3f1439"
DOMAIN = "sunderkey.offline-windows-privilege-artifacts.v1"
ARTIFACT_KINDS = frozenset({"service", "scheduled_task", "startup_artifact"})
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class WindowsPrivilegeArtifactError(ValueError):
    """A supplied privilege artifact model or replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "artifacts",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WindowsPrivilegeArtifactError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise WindowsPrivilegeArtifactError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    artifacts = core.bounded_list(model["artifacts"], 64, "artifacts")
    if not artifacts:
        raise WindowsPrivilegeArtifactError("At least one artifact is required")
    rows = []
    seen = set()
    for item in artifacts:
        row = core.exact(item, {
            "artifact_id", "artifact_kind", "privileged_execution_declared",
            "low_privilege_write_declared",
        }, "artifact")
        artifact_id = core.identifier(row["artifact_id"], "artifact ID")
        kind = core.identifier(row["artifact_kind"], "artifact kind")
        if artifact_id in seen or kind not in ARTIFACT_KINDS:
            raise WindowsPrivilegeArtifactError("Duplicate artifact or unknown kind")
        seen.add(artifact_id)
        privileged = core.boolean(
            row["privileged_execution_declared"], "privileged execution declaration"
        )
        writable = core.boolean(
            row["low_privilege_write_declared"], "low privilege write declaration"
        )
        flags = ["declared_write_execution_overlap"] if privileged and writable else []
        rows.append({
            "artifact_id": artifact_id,
            "artifact_kind": kind,
            "privileged_execution_declared": privileged,
            "low_privilege_write_declared": writable,
            "declared_policy_flags": flags,
        })
    rows.sort(key=lambda row: row["artifact_id"])
    deviations = [row["artifact_id"] for row in rows if row["declared_policy_flags"]]
    unknown = [] if complete else ["supplied_privilege_artifact_inventory_incomplete"]
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
        "disposition": "unknown" if unknown else "supplied_privilege_artifact_projection",
        "source_authenticated": False,
        "host_connected": False,
        "acl_verified": False,
        "artifact_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Artifact kind, write access, execution context, and completeness are assertions.",
            "The model does not inspect Windows ACLs or prove privilege escalation.",
            "A declared overlap is a review signal, not a vulnerability finding.",
            "No host, process, credential, artifact, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WPA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class WindowsPrivilegeArtifactReport:
    """Unsigned declaration projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WindowsPrivilegeArtifactError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WindowsPrivilegeArtifactReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_privilege_artifacts(model: Any) -> WindowsPrivilegeArtifactReport:
    return WindowsPrivilegeArtifactReport._owned(_derive(model))


def verify_supplied_privilege_artifacts(
    report: Any, *, model: Any
) -> WindowsPrivilegeArtifactReport:
    if type(report) is not WindowsPrivilegeArtifactReport:
        raise WindowsPrivilegeArtifactError("Exact privilege artifact wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise WindowsPrivilegeArtifactError("Report differs from separate original model")
    return WindowsPrivilegeArtifactReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-privilege-artifacts",
        "synthetic_fixture": True,
        "inventory_complete": True,
        "artifacts": [{
            "artifact_id": "service-a",
            "artifact_kind": "service",
            "privileged_execution_declared": True,
            "low_privilege_write_declared": True,
        }],
    }

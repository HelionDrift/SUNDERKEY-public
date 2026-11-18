"""Compare caller-supplied engineering project export and review declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ot_supplied_engineering_project_provenance"
PROFILE_ID = "AOE-GD-D19-S04"
CAPABILITY_ID = "army.gd.d19.s04"
VECTOR_ID = "AV-GD-D19-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S04"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:8890df9e0107dafb2b2b06a1f61727ffa01f18f85f36172e40d2108548498a7b"
DOMAIN = "sunderkey.offline-ot-engineering-project-provenance.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class OtEngineeringProjectProvenanceError(ValueError):
    """A project declaration or original-model replay was refused."""


def _digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        raise OtEngineeringProjectProvenanceError(f"{label} must be a SHA-256 digest or null")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise OtEngineeringProjectProvenanceError(f"{label} must be a SHA-256 digest or null")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "project_exports"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtEngineeringProjectProvenanceError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    exports = core.bounded_list(model["project_exports"], 32, "project exports")
    if not exports:
        raise OtEngineeringProjectProvenanceError("At least one project export is required")
    seen: set[str] = set()
    for item in exports:
        export = core.exact(
            item,
            {
                "project_id",
                "reviewed_package_sha256",
                "supplied_package_sha256",
                "review_recorded",
                "context_complete",
            },
            "project export",
        )
        project_id = core.identifier(export["project_id"], "project ID")
        if project_id in seen:
            raise OtEngineeringProjectProvenanceError("Duplicate project ID")
        seen.add(project_id)
        _digest(export["reviewed_package_sha256"], "reviewed package digest")
        _digest(export["supplied_package_sha256"], "supplied package digest")
        if export["review_recorded"] is not None:
            core.boolean(export["review_recorded"], "review recorded")
        core.boolean(export["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows: list[dict] = []
    for export in model["project_exports"]:
        complete = (
            model["inventory_complete"]
            and export["context_complete"]
            and all(
                export[key] is not None
                for key in (
                    "reviewed_package_sha256",
                    "supplied_package_sha256",
                    "review_recorded",
                )
            )
        )
        issues: list[str] = []
        if complete:
            if export["reviewed_package_sha256"] != export["supplied_package_sha256"]:
                issues.append("supplied_package_digest_differs_from_reviewed_digest")
            if not export["review_recorded"]:
                issues.append("review_record_not_declared")
        rows.append(
            {
                "project_id": export["project_id"],
                "issues": issues if complete else None,
                "disposition": (
                    "unknown"
                    if not complete
                    else "candidate_declared_project_provenance_gap"
                    if issues
                    else "no_declared_project_provenance_gap"
                ),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "project_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "workstation_contacted": False,
        "export_authenticity_verified": False,
        "review_authenticity_verified": False,
        "deployment_verified": False,
        "process_safety_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Project inventory, digests, review labels and completeness are caller-supplied.",
            "A declared gap does not establish deployment, compromise or process impact.",
            "No workstation, controller, credential, network or process is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OEP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OtEngineeringProjectProvenanceReport:
    """Unsigned R0 projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtEngineeringProjectProvenanceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtEngineeringProjectProvenanceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_engineering_project_provenance(
    model: Any,
) -> OtEngineeringProjectProvenanceReport:
    return OtEngineeringProjectProvenanceReport._owned(_derive(model))


def verify_supplied_ot_engineering_project_provenance(
    report: Any, *, model: Any
) -> OtEngineeringProjectProvenanceReport:
    if type(report) is not OtEngineeringProjectProvenanceReport:
        raise OtEngineeringProjectProvenanceError("Exact engineering project wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtEngineeringProjectProvenanceError("Report differs from original-model replay")
    return OtEngineeringProjectProvenanceReport._owned(expected)


def verify_supplied_ot_engineering_project_provenance_bytes(
    report_bytes: bytes, *, model: Any
) -> OtEngineeringProjectProvenanceReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise OtEngineeringProjectProvenanceError(
            "Exported report differs from original-model replay"
        )
    return OtEngineeringProjectProvenanceReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-engineering-exports",
        "inventory_complete": True,
        "project_exports": [
            {
                "project_id": "project-a",
                "reviewed_package_sha256": "sha256:" + "a" * 64,
                "supplied_package_sha256": "sha256:" + "b" * 64,
                "review_recorded": False,
                "context_complete": True,
            },
            {
                "project_id": "project-b",
                "reviewed_package_sha256": "sha256:" + "c" * 64,
                "supplied_package_sha256": "sha256:" + "c" * 64,
                "review_recorded": True,
                "context_complete": True,
            },
        ],
    }

"""Compare caller-supplied HMI tag mapping and access-mode declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ot_supplied_hmi_tag_mapping"
PROFILE_ID = "AOE-GD-D19-S03"
CAPABILITY_ID = "army.gd.d19.s03"
VECTOR_ID = "AV-GD-D19-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S03"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:f370dc86fcfe1518eb0ec93d5fc2a4c19b9a8906305974e5da0e221a44698cde"
DOMAIN = "sunderkey.offline-ot-hmi-tag-mapping.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
ACCESS_MODES = {"read_only", "read_write"}
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


class OtHmiTagMappingError(ValueError):
    """An HMI declaration or original-model replay was refused."""


def _optional_identifier(value: Any, label: str) -> str | None:
    return None if value is None else core.identifier(value, label)


def _optional_mode(value: Any, label: str) -> str | None:
    return None if value is None else core.choice(value, ACCESS_MODES, label)


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "tag_bindings"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtHmiTagMappingError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    bindings = core.bounded_list(model["tag_bindings"], 32, "tag bindings")
    if not bindings:
        raise OtHmiTagMappingError("At least one tag binding is required")
    seen: set[str] = set()
    for item in bindings:
        binding = core.exact(
            item,
            {
                "tag_id",
                "baseline_point_ref",
                "project_point_ref",
                "baseline_access_mode",
                "project_access_mode",
                "context_complete",
            },
            "tag binding",
        )
        tag_id = core.identifier(binding["tag_id"], "tag ID")
        if tag_id in seen:
            raise OtHmiTagMappingError("Duplicate tag ID")
        seen.add(tag_id)
        _optional_identifier(binding["baseline_point_ref"], "baseline point reference")
        _optional_identifier(binding["project_point_ref"], "project point reference")
        _optional_mode(binding["baseline_access_mode"], "baseline access mode")
        _optional_mode(binding["project_access_mode"], "project access mode")
        core.boolean(binding["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows: list[dict] = []
    for binding in model["tag_bindings"]:
        complete = (
            model["inventory_complete"]
            and binding["context_complete"]
            and all(
                binding[key] is not None
                for key in (
                    "baseline_point_ref",
                    "project_point_ref",
                    "baseline_access_mode",
                    "project_access_mode",
                )
            )
        )
        issues: list[str] = []
        if complete:
            if binding["baseline_point_ref"] != binding["project_point_ref"]:
                issues.append("supplied_point_reference_differs_from_baseline")
            if binding["baseline_access_mode"] != binding["project_access_mode"]:
                issues.append("supplied_access_mode_differs_from_baseline")
        rows.append(
            {
                "tag_id": binding["tag_id"],
                "issues": issues if complete else None,
                "disposition": (
                    "unknown"
                    if not complete
                    else "candidate_declared_tag_mapping_difference"
                    if issues
                    else "no_declared_tag_mapping_difference"
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
        "tag_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "hmi_or_scada_contacted": False,
        "project_configuration_authenticated": False,
        "effective_write_access_verified": False,
        "point_behavior_verified": False,
        "process_safety_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Tag, point, access-mode, inventory and completeness labels are caller-supplied.",
            "A declared mismatch does not establish HMI behavior, write access or process impact.",
            "No HMI, SCADA, historian, controller, network, credential or process is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OTM-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OtHmiTagMappingReport:
    """Unsigned R0 projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtHmiTagMappingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtHmiTagMappingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_hmi_tag_mapping(model: Any) -> OtHmiTagMappingReport:
    return OtHmiTagMappingReport._owned(_derive(model))


def verify_supplied_ot_hmi_tag_mapping(report: Any, *, model: Any) -> OtHmiTagMappingReport:
    if type(report) is not OtHmiTagMappingReport:
        raise OtHmiTagMappingError("Exact HMI tag mapping wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtHmiTagMappingError("Report differs from original-model replay")
    return OtHmiTagMappingReport._owned(expected)


def verify_supplied_ot_hmi_tag_mapping_bytes(
    report_bytes: bytes, *, model: Any
) -> OtHmiTagMappingReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise OtHmiTagMappingError("Exported report differs from original-model replay")
    return OtHmiTagMappingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-hmi-project",
        "inventory_complete": True,
        "tag_bindings": [
            {
                "tag_id": "tag-a",
                "baseline_point_ref": "point-a",
                "project_point_ref": "point-b",
                "baseline_access_mode": "read_only",
                "project_access_mode": "read_write",
                "context_complete": True,
            },
            {
                "tag_id": "tag-b",
                "baseline_point_ref": "point-c",
                "project_point_ref": "point-c",
                "baseline_access_mode": "read_only",
                "project_access_mode": "read_only",
                "context_complete": True,
            },
        ],
    }

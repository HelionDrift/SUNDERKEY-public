"""Compare caller-supplied OT controller configuration digest declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "ot_supplied_controller_configuration"
PROFILE_ID = "AOE-GD-D19-S02"
CAPABILITY_ID = "army.gd.d19.s02"
VECTOR_ID = "AV-GD-D19-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D19-S02"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GD-D19-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:5d180ac4e0565b5dbb1840eac8c92d23df7ad96bb869bf845c75d6965c86e827"
DOMAIN = "sunderkey.offline-ot-controller-configuration.v1"
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


class OtControllerConfigurationError(ValueError):
    """A controller declaration or original-model replay was refused."""


def _digest(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value.startswith("sha256:") or len(value) != 71:
        raise OtControllerConfigurationError(f"{label} must be a SHA-256 digest or null")
    if any(char not in "0123456789abcdef" for char in value[7:]):
        raise OtControllerConfigurationError(f"{label} must be a SHA-256 digest or null")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "controllers"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OtControllerConfigurationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    controllers = core.bounded_list(model["controllers"], 32, "controllers")
    if not controllers:
        raise OtControllerConfigurationError("At least one controller is required")
    seen: set[str] = set()
    for item in controllers:
        controller = core.exact(
            item,
            {
                "controller_id",
                "baseline_logic_sha256",
                "project_logic_sha256",
                "baseline_io_map_sha256",
                "project_io_map_sha256",
                "context_complete",
            },
            "controller",
        )
        controller_id = core.identifier(controller["controller_id"], "controller ID")
        if controller_id in seen:
            raise OtControllerConfigurationError("Duplicate controller ID")
        seen.add(controller_id)
        for key in (
            "baseline_logic_sha256",
            "project_logic_sha256",
            "baseline_io_map_sha256",
            "project_io_map_sha256",
        ):
            _digest(controller[key], key)
        core.boolean(controller["context_complete"], "context completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    rows: list[dict] = []
    for controller in model["controllers"]:
        complete = (
            model["inventory_complete"]
            and controller["context_complete"]
            and all(
                controller[key] is not None
                for key in (
                    "baseline_logic_sha256",
                    "project_logic_sha256",
                    "baseline_io_map_sha256",
                    "project_io_map_sha256",
                )
            )
        )
        issues: list[str] = []
        if complete:
            if controller["baseline_logic_sha256"] != controller["project_logic_sha256"]:
                issues.append("supplied_logic_digest_differs_from_baseline")
            if controller["baseline_io_map_sha256"] != controller["project_io_map_sha256"]:
                issues.append("supplied_io_map_digest_differs_from_baseline")
        rows.append(
            {
                "controller_id": controller["controller_id"],
                "issues": issues if complete else None,
                "disposition": (
                    "unknown"
                    if not complete
                    else "candidate_declared_configuration_digest_difference"
                    if issues
                    else "no_declared_configuration_digest_difference"
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
        "controller_projections": rows,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in rows),
        "unknown_count": sum(row["disposition"] == "unknown" for row in rows),
        "source_authenticated": False,
        "controller_contacted": False,
        "project_export_authenticated": False,
        "deployed_logic_verified": False,
        "io_behavior_verified": False,
        "process_safety_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Controller inventory, completeness and digest labels are caller-supplied.",
            "Digest differences do not establish deployed logic, I/O behavior or process impact.",
            "No PLC, RTU, PAC, engineering tool, network, credential or process is contacted.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OCC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OtControllerConfigurationReport:
    """Unsigned R0 projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OtControllerConfigurationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OtControllerConfigurationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_ot_controller_configuration(model: Any) -> OtControllerConfigurationReport:
    return OtControllerConfigurationReport._owned(_derive(model))


def verify_supplied_ot_controller_configuration(
    report: Any, *, model: Any
) -> OtControllerConfigurationReport:
    if type(report) is not OtControllerConfigurationReport:
        raise OtControllerConfigurationError("Exact controller configuration wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OtControllerConfigurationError("Report differs from original-model replay")
    return OtControllerConfigurationReport._owned(expected)


def verify_supplied_ot_controller_configuration_bytes(
    report_bytes: bytes, *, model: Any
) -> OtControllerConfigurationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    expected = _derive(model)
    if type(report) is not dict or core.canonical(report) != core.canonical(expected):
        raise OtControllerConfigurationError("Exported report differs from original-model replay")
    return OtControllerConfigurationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-controller-exports",
        "inventory_complete": True,
        "controllers": [
            {
                "controller_id": "controller-a",
                "baseline_logic_sha256": "sha256:" + "a" * 64,
                "project_logic_sha256": "sha256:" + "b" * 64,
                "baseline_io_map_sha256": "sha256:" + "c" * 64,
                "project_io_map_sha256": "sha256:" + "c" * 64,
                "context_complete": True,
            },
            {
                "controller_id": "controller-b",
                "baseline_logic_sha256": "sha256:" + "d" * 64,
                "project_logic_sha256": "sha256:" + "d" * 64,
                "baseline_io_map_sha256": "sha256:" + "e" * 64,
                "project_io_map_sha256": "sha256:" + "e" * 64,
                "context_complete": True,
            },
        ],
    }

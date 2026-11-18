"""Compare caller-supplied RTOS task and isolation declarations offline."""

from __future__ import annotations

from typing import Any

from . import offline_firmware_projection_core as fw
from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_rtos_task_policy_projection"
PROFILE_ID = "AOE-GD-D18-S04"
CAPABILITY_ID = "army.gd.d18.s04"
VECTOR_ID = "AV-GD-D18-S04-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S04"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:052dac0f203d1a4b98cf2888fba72a04b82c8375b3fc308afe0ae4c1985bd300"
DOMAIN = "sunderkey.offline-firmware-rtos-task-policy.v1"


class FirmwareRtosTaskPolicyReport(fw.FirmwareProjectionReport):
    """Unsigned RTOS task-policy declaration projection."""


def _priority(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 255:
        raise fw.FirmwareProjectionError(f"{label} must be an integer from 0 to 255 or null")
    return value


def _derive(value: Any) -> dict:
    model, model_text = fw.model_base(value, collection="tasks")
    seen: set[str] = set()
    rows: list[dict] = []
    for item in model["tasks"]:
        task = core.exact(
            item,
            {
                "task_id", "expected_priority", "declared_priority",
                "isolation_expected", "isolation_declared", "context_complete",
            },
            "RTOS task",
        )
        task_id = fw.unique_id(task["task_id"], seen=seen, label="task ID")
        if _priority(task["expected_priority"], "expected priority") is None:
            raise fw.FirmwareProjectionError("Expected priority must be present")
        _priority(task["declared_priority"], "declared priority")
        core.boolean(task["isolation_expected"], "expected isolation")
        if task["isolation_declared"] is not None:
            core.boolean(task["isolation_declared"], "declared isolation")
        core.boolean(task["context_complete"], "context completeness")
        complete = (
            model["inventory_complete"] and task["context_complete"]
            and task["declared_priority"] is not None
            and task["isolation_declared"] is not None
        )
        issues: list[str] = []
        if complete:
            if task["expected_priority"] != task["declared_priority"]:
                issues.append("declared_priority_differs_from_expected")
            if task["isolation_expected"] != task["isolation_declared"]:
                issues.append("declared_isolation_differs_from_expected")
        rows.append({
            "task_id": task_id,
            "issues": issues if complete else None,
            "disposition": (
                "unknown" if not complete else
                "candidate_declared_task_policy_gap" if issues else
                "no_declared_task_policy_gap"
            ),
        })
    return fw.report_document(
        model_text=model_text, component_id=COMPONENT_ID, profile_id=PROFILE_ID,
        work_package_id=WORK_PACKAGE_ID, blueprint_sha256=BLUEPRINT_SHA256,
        domain=DOMAIN, prefix="RTP-", row_key="task_projections", rows=rows,
        additional_false_flags=("rtos_executed", "scheduler_observed", "isolation_enforced"),
        limitations=[
            "Task inventory, priorities and isolation states are caller-supplied.",
            "Declared mismatch does not establish actual scheduler or memory behavior.",
            "No RTOS image, hardware, process or task is executed.",
        ],
    )


def analyze_supplied_firmware_rtos_task_policy(model: Any) -> FirmwareRtosTaskPolicyReport:
    return FirmwareRtosTaskPolicyReport._owned(_derive(model))


def verify_supplied_firmware_rtos_task_policy(
    report: Any, *, model: Any
) -> FirmwareRtosTaskPolicyReport:
    return fw.verify_report(
        report, model=model, derive=_derive, report_type=FirmwareRtosTaskPolicyReport
    )


def verify_supplied_firmware_rtos_task_policy_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareRtosTaskPolicyReport:
    return fw.verify_report_bytes(
        report_bytes, model=model, derive=_derive, report_type=FirmwareRtosTaskPolicyReport
    )


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-rtos-task-export",
        "inventory_complete": True,
        "tasks": [
            {
                "task_id": "control-loop", "expected_priority": 10,
                "declared_priority": 9, "isolation_expected": True,
                "isolation_declared": False, "context_complete": True,
            },
            {
                "task_id": "status", "expected_priority": 5,
                "declared_priority": 5, "isolation_expected": True,
                "isolation_declared": True, "context_complete": True,
            },
        ],
    }

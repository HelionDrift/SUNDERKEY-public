"""Compare supplied UART, JTAG, and SWD interface policy declarations offline."""

from __future__ import annotations

from typing import Any

from . import offline_firmware_projection_core as fw
from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_debug_interface_inventory_projection"
PROFILE_ID = "AOE-GD-D18-S05"
CAPABILITY_ID = "army.gd.d18.s05"
VECTOR_ID = "AV-GD-D18-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S05"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:9cfc71887e0c753c4888e1d4d237b3cc5564003ca68981c20d57899f011ad49a"
DOMAIN = "sunderkey.offline-firmware-debug-interface-inventory.v1"


class FirmwareDebugInterfaceInventoryReport(fw.FirmwareProjectionReport):
    """Unsigned debug-interface declaration projection."""


def _derive(value: Any) -> dict:
    model, model_text = fw.model_base(value, collection="interfaces")
    seen: set[str] = set()
    rows: list[dict] = []
    for item in model["interfaces"]:
        interface = core.exact(
            item,
            {
                "interface_id", "interface_kind", "expected_enabled",
                "declared_enabled", "context_complete",
            },
            "debug interface",
        )
        interface_id = fw.unique_id(
            interface["interface_id"], seen=seen, label="interface ID"
        )
        core.choice(interface["interface_kind"], {"UART", "JTAG", "SWD"}, "interface kind")
        core.boolean(interface["expected_enabled"], "expected enabled state")
        if interface["declared_enabled"] is not None:
            core.boolean(interface["declared_enabled"], "declared enabled state")
        core.boolean(interface["context_complete"], "context completeness")
        complete = (
            model["inventory_complete"] and interface["context_complete"]
            and interface["declared_enabled"] is not None
        )
        issues = []
        if complete and interface["expected_enabled"] != interface["declared_enabled"]:
            issues.append("declared_enabled_state_differs_from_expected")
        rows.append({
            "interface_id": interface_id,
            "interface_kind": interface["interface_kind"],
            "issues": issues if complete else None,
            "disposition": (
                "unknown" if not complete else
                "candidate_declared_debug_policy_gap" if issues else
                "no_declared_debug_policy_gap"
            ),
        })
    return fw.report_document(
        model_text=model_text, component_id=COMPONENT_ID, profile_id=PROFILE_ID,
        work_package_id=WORK_PACKAGE_ID, blueprint_sha256=BLUEPRINT_SHA256,
        domain=DOMAIN, prefix="FDI-", row_key="interface_projections", rows=rows,
        additional_false_flags=("debug_probe_connected", "interface_state_observed"),
        limitations=[
            "Interface inventory and enabled-state labels are caller-supplied.",
            "A mismatch does not establish reachability, authentication or exploitability.",
            "No UART, JTAG, SWD, device or hardware probe is accessed.",
        ],
    )


def analyze_supplied_firmware_debug_interface_inventory(
    model: Any,
) -> FirmwareDebugInterfaceInventoryReport:
    return FirmwareDebugInterfaceInventoryReport._owned(_derive(model))


def verify_supplied_firmware_debug_interface_inventory(
    report: Any, *, model: Any
) -> FirmwareDebugInterfaceInventoryReport:
    return fw.verify_report(
        report, model=model, derive=_derive, report_type=FirmwareDebugInterfaceInventoryReport
    )


def verify_supplied_firmware_debug_interface_inventory_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareDebugInterfaceInventoryReport:
    return fw.verify_report_bytes(
        report_bytes, model=model, derive=_derive, report_type=FirmwareDebugInterfaceInventoryReport
    )


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-debug-export",
        "inventory_complete": True,
        "interfaces": [
            {
                "interface_id": "board-a-jtag", "interface_kind": "JTAG",
                "expected_enabled": False, "declared_enabled": True,
                "context_complete": True,
            },
            {
                "interface_id": "board-a-uart", "interface_kind": "UART",
                "expected_enabled": False, "declared_enabled": False,
                "context_complete": True,
            },
        ],
    }

"""Compare supplied firmware emulation fixture and trace declarations offline."""

from __future__ import annotations

from typing import Any

from . import offline_firmware_projection_core as fw
from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_emulation_trace_projection"
PROFILE_ID = "AOE-GD-D18-S02"
CAPABILITY_ID = "army.gd.d18.s02"
VECTOR_ID = "AV-GD-D18-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S02"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:b77873cb28f7404638eecf9a681faee1e127db1e919214b5fd2a0ec9845476e2"
DOMAIN = "sunderkey.offline-firmware-emulation-trace.v1"


class FirmwareEmulationTraceReport(fw.FirmwareProjectionReport):
    """Unsigned emulation declaration projection."""


def _derive(value: Any) -> dict:
    model, model_text = fw.model_base(value, collection="emulation_runs")
    seen: set[str] = set()
    rows: list[dict] = []
    for item in model["emulation_runs"]:
        run = core.exact(
            item,
            {
                "image_id", "expected_architecture", "declared_emulator_architecture",
                "baseline_trace_sha256", "declared_trace_sha256", "fixture_complete",
                "trace_complete",
            },
            "emulation run",
        )
        image_id = fw.unique_id(run["image_id"], seen=seen, label="image ID")
        core.identifier(run["expected_architecture"], "expected architecture")
        if run["declared_emulator_architecture"] is not None:
            core.identifier(run["declared_emulator_architecture"], "emulator architecture")
        fw.digest_or_none(run["baseline_trace_sha256"], "baseline trace digest")
        fw.digest_or_none(run["declared_trace_sha256"], "declared trace digest")
        core.boolean(run["fixture_complete"], "fixture completeness")
        core.boolean(run["trace_complete"], "trace completeness")
        complete = (
            model["inventory_complete"] and run["fixture_complete"]
            and run["trace_complete"]
            and all(
                run[field] is not None
                for field in (
                    "declared_emulator_architecture", "baseline_trace_sha256",
                    "declared_trace_sha256",
                )
            )
        )
        issues: list[str] = []
        if complete:
            if run["expected_architecture"] != run["declared_emulator_architecture"]:
                issues.append("declared_emulator_architecture_differs_from_expected")
            if run["baseline_trace_sha256"] != run["declared_trace_sha256"]:
                issues.append("declared_trace_differs_from_supplied_baseline")
        rows.append({
            "image_id": image_id,
            "issues": issues if complete else None,
            "disposition": (
                "unknown" if not complete else
                "candidate_declared_emulation_divergence" if issues else
                "no_declared_emulation_divergence"
            ),
        })
    return fw.report_document(
        model_text=model_text, component_id=COMPONENT_ID, profile_id=PROFILE_ID,
        work_package_id=WORK_PACKAGE_ID, blueprint_sha256=BLUEPRINT_SHA256,
        domain=DOMAIN, prefix="FET-", row_key="emulation_projections", rows=rows,
        additional_false_flags=("emulator_executed", "firmware_executed", "trace_authenticated"),
        limitations=[
            "Image, fixture, architecture and trace labels are caller-supplied.",
            "A digest difference does not establish a firmware defect or exploitability.",
            "No emulator, device or firmware image is opened or executed.",
        ],
    )


def analyze_supplied_firmware_emulation_trace(model: Any) -> FirmwareEmulationTraceReport:
    return FirmwareEmulationTraceReport._owned(_derive(model))


def verify_supplied_firmware_emulation_trace(
    report: Any, *, model: Any
) -> FirmwareEmulationTraceReport:
    return fw.verify_report(
        report, model=model, derive=_derive, report_type=FirmwareEmulationTraceReport
    )


def verify_supplied_firmware_emulation_trace_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareEmulationTraceReport:
    return fw.verify_report_bytes(
        report_bytes, model=model, derive=_derive, report_type=FirmwareEmulationTraceReport
    )


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-emulation-export",
        "inventory_complete": True,
        "emulation_runs": [
            {
                "image_id": "image-a",
                "expected_architecture": "armv7m",
                "declared_emulator_architecture": "armv7m",
                "baseline_trace_sha256": "sha256:" + "a" * 64,
                "declared_trace_sha256": "sha256:" + "b" * 64,
                "fixture_complete": True,
                "trace_complete": True,
            },
            {
                "image_id": "image-b",
                "expected_architecture": "riscv32",
                "declared_emulator_architecture": "riscv32",
                "baseline_trace_sha256": "sha256:" + "c" * 64,
                "declared_trace_sha256": "sha256:" + "c" * 64,
                "fixture_complete": True,
                "trace_complete": True,
            },
        ],
    }

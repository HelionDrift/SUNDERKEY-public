"""Compare supplied hardware tamper and component provenance declarations offline."""

from __future__ import annotations

from typing import Any

from . import offline_firmware_projection_core as fw
from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_tamper_provenance_projection"
PROFILE_ID = "AOE-GD-D18-S16"
CAPABILITY_ID = "army.gd.d18.s16"
VECTOR_ID = "AV-GD-D18-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S16"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:0f6b6bc2563cfd8f03d98b937c33aa1ebced29820bf462670b2527603698e91f"
DOMAIN = "sunderkey.offline-firmware-tamper-provenance.v1"


class FirmwareTamperProvenanceReport(fw.FirmwareProjectionReport):
    """Unsigned tamper and supply-chain declaration projection."""


def _derive(value: Any) -> dict:
    model, model_text = fw.model_base(value, collection="components")
    seen: set[str] = set()
    rows: list[dict] = []
    for item in model["components"]:
        component = core.exact(
            item,
            {
                "component_id", "expected_provenance_sha256", "supplied_provenance_sha256",
                "expected_seal_intact", "declared_seal_state", "context_complete",
            },
            "hardware component",
        )
        component_id = fw.unique_id(
            component["component_id"], seen=seen, label="hardware component ID"
        )
        fw.digest_or_none(component["expected_provenance_sha256"], "expected provenance digest")
        fw.digest_or_none(component["supplied_provenance_sha256"], "supplied provenance digest")
        core.boolean(component["expected_seal_intact"], "expected seal state")
        core.choice(
            component["declared_seal_state"], {"intact", "broken", "unknown"},
            "declared seal state",
        )
        core.boolean(component["context_complete"], "context completeness")
        complete = (
            model["inventory_complete"] and component["context_complete"]
            and component["declared_seal_state"] != "unknown"
            and component["expected_provenance_sha256"] is not None
            and component["supplied_provenance_sha256"] is not None
        )
        issues = []
        if complete:
            if (
                component["expected_provenance_sha256"]
                != component["supplied_provenance_sha256"]
            ):
                issues.append("supplied_provenance_differs_from_expected")
            if component["expected_seal_intact"] != (
                component["declared_seal_state"] == "intact"
            ):
                issues.append("declared_seal_state_differs_from_expected")
        rows.append({
            "component_id": component_id,
            "issues": issues if complete else None,
            "disposition": (
                "unknown" if not complete else
                "candidate_declared_tamper_or_provenance_gap" if issues else
                "no_declared_tamper_or_provenance_gap"
            ),
        })
    return fw.report_document(
        model_text=model_text, component_id=COMPONENT_ID, profile_id=PROFILE_ID,
        work_package_id=WORK_PACKAGE_ID, blueprint_sha256=BLUEPRINT_SHA256,
        domain=DOMAIN, prefix="FTP-", row_key="component_projections", rows=rows,
        additional_false_flags=("physical_inspection_performed", "supply_chain_authenticated"),
        limitations=[
            "Component inventory, provenance digests and seal labels are caller-supplied.",
            "Declared mismatch does not prove tampering, counterfeit origin or impact.",
            "No device, package, component or supply-chain system is accessed.",
        ],
    )


def analyze_supplied_firmware_tamper_provenance(
    model: Any,
) -> FirmwareTamperProvenanceReport:
    return FirmwareTamperProvenanceReport._owned(_derive(model))


def verify_supplied_firmware_tamper_provenance(
    report: Any, *, model: Any
) -> FirmwareTamperProvenanceReport:
    return fw.verify_report(
        report, model=model, derive=_derive, report_type=FirmwareTamperProvenanceReport
    )


def verify_supplied_firmware_tamper_provenance_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareTamperProvenanceReport:
    return fw.verify_report_bytes(
        report_bytes, model=model, derive=_derive, report_type=FirmwareTamperProvenanceReport
    )


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-supply-export",
        "inventory_complete": True,
        "components": [
            {
                "component_id": "board-a-module",
                "expected_provenance_sha256": "sha256:" + "a" * 64,
                "supplied_provenance_sha256": "sha256:" + "b" * 64,
                "expected_seal_intact": True, "declared_seal_state": "broken",
                "context_complete": True,
            },
            {
                "component_id": "board-b-module",
                "expected_provenance_sha256": "sha256:" + "c" * 64,
                "supplied_provenance_sha256": "sha256:" + "c" * 64,
                "expected_seal_intact": True, "declared_seal_state": "intact",
                "context_complete": True,
            },
        ],
    }

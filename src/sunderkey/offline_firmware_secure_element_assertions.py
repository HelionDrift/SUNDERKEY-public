"""Compare supplied TPM, TEE, and secure-element identity declarations offline."""

from __future__ import annotations

from typing import Any

from . import offline_firmware_projection_core as fw
from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_secure_element_assertions_projection"
PROFILE_ID = "AOE-GD-D18-S10"
CAPABILITY_ID = "army.gd.d18.s10"
VECTOR_ID = "AV-GD-D18-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S10"
WAVE_ID = "IW2-014"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:406a9128f980b34efce02004be26b63e4aa715e3906974be8533c63dac0d1d8f"
DOMAIN = "sunderkey.offline-firmware-secure-element-assertions.v1"


class FirmwareSecureElementAssertionsReport(fw.FirmwareProjectionReport):
    """Unsigned secure-element declaration projection."""


def _derive(value: Any) -> dict:
    model, model_text = fw.model_base(value, collection="assets")
    seen: set[str] = set()
    rows: list[dict] = []
    for item in model["assets"]:
        asset = core.exact(
            item,
            {
                "asset_id", "asset_kind", "expected_identity_sha256",
                "supplied_identity_sha256", "hardware_backed_expected",
                "hardware_backed_declared", "context_complete",
            },
            "secure-element asset",
        )
        asset_id = fw.unique_id(asset["asset_id"], seen=seen, label="asset ID")
        core.choice(asset["asset_kind"], {"TPM", "TEE", "secure_element"}, "asset kind")
        fw.digest_or_none(asset["expected_identity_sha256"], "expected identity digest")
        fw.digest_or_none(asset["supplied_identity_sha256"], "supplied identity digest")
        core.boolean(asset["hardware_backed_expected"], "expected hardware backing")
        if asset["hardware_backed_declared"] is not None:
            core.boolean(asset["hardware_backed_declared"], "declared hardware backing")
        core.boolean(asset["context_complete"], "context completeness")
        complete = (
            model["inventory_complete"] and asset["context_complete"]
            and all(
                asset[field] is not None
                for field in (
                    "expected_identity_sha256", "supplied_identity_sha256",
                    "hardware_backed_declared",
                )
            )
        )
        issues = []
        if complete:
            if asset["expected_identity_sha256"] != asset["supplied_identity_sha256"]:
                issues.append("supplied_identity_differs_from_expected")
            if asset["hardware_backed_expected"] != asset["hardware_backed_declared"]:
                issues.append("declared_hardware_backing_differs_from_expected")
        rows.append({
            "asset_id": asset_id,
            "asset_kind": asset["asset_kind"],
            "issues": issues if complete else None,
            "disposition": (
                "unknown" if not complete else
                "candidate_declared_secure_element_gap" if issues else
                "no_declared_secure_element_gap"
            ),
        })
    return fw.report_document(
        model_text=model_text, component_id=COMPONENT_ID, profile_id=PROFILE_ID,
        work_package_id=WORK_PACKAGE_ID, blueprint_sha256=BLUEPRINT_SHA256,
        domain=DOMAIN, prefix="FSE-", row_key="asset_projections", rows=rows,
        additional_false_flags=(
            "attestation_verified", "key_material_accessed", "root_of_trust_proven"
        ),
        limitations=[
            "Asset inventory, identity digests and backing claims are caller-supplied.",
            "Digest comparison is not attestation or proof of hardware-backed keys.",
            "No TPM, TEE, secure element, key material or device is accessed.",
        ],
    )


def analyze_supplied_firmware_secure_element_assertions(
    model: Any,
) -> FirmwareSecureElementAssertionsReport:
    return FirmwareSecureElementAssertionsReport._owned(_derive(model))


def verify_supplied_firmware_secure_element_assertions(
    report: Any, *, model: Any
) -> FirmwareSecureElementAssertionsReport:
    return fw.verify_report(
        report, model=model, derive=_derive, report_type=FirmwareSecureElementAssertionsReport
    )


def verify_supplied_firmware_secure_element_assertions_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareSecureElementAssertionsReport:
    return fw.verify_report_bytes(
        report_bytes, model=model, derive=_derive, report_type=FirmwareSecureElementAssertionsReport
    )


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-root-export",
        "inventory_complete": True,
        "assets": [
            {
                "asset_id": "device-a-tpm", "asset_kind": "TPM",
                "expected_identity_sha256": "sha256:" + "a" * 64,
                "supplied_identity_sha256": "sha256:" + "b" * 64,
                "hardware_backed_expected": True,
                "hardware_backed_declared": False,
                "context_complete": True,
            },
            {
                "asset_id": "device-b-tee", "asset_kind": "TEE",
                "expected_identity_sha256": "sha256:" + "c" * 64,
                "supplied_identity_sha256": "sha256:" + "c" * 64,
                "hardware_backed_expected": True,
                "hardware_backed_declared": True,
                "context_complete": True,
            },
        ],
    }

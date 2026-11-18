"""Reconcile caller-supplied firmware inventory and SBOM claims offline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "firmware_supplied_inventory_sbom_claim_reconciliation"
PROFILE_ID = "AOE-GD-D18-S01"
CAPABILITY_ID = "army.gd.d18.s01"
VECTOR_ID = "AV-GD-D18-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D18-S01"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GD-D18-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:9a591edcc0f7c8052ce9d00e0c6424a8e13370b33bb27f531b095d19f3ead061"
DOMAIN = "sunderkey.offline-firmware-inventory-sbom.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class FirmwareInventorySbomError(ValueError):
    """The supplied claims or an original-model replay are invalid."""


def _claims(value: Any, label: str) -> dict[str, dict]:
    rows = core.bounded_list(value, 128, label)
    claims: dict[str, dict] = {}
    for item in rows:
        row = core.exact(item, {"component_id", "version", "sha256"}, label)
        component_id = core.identifier(row["component_id"], "component ID")
        core.identifier(row["version"], "component version")
        if type(row["sha256"]) is not str or _SHA256.fullmatch(row["sha256"]) is None:
            raise FirmwareInventorySbomError("Component digest must be lowercase sha256")
        if component_id in claims:
            raise FirmwareInventorySbomError(f"Duplicate component ID in {label}")
        claims[component_id] = row
    return claims


def _model(value: Any) -> tuple[dict, str, dict[str, dict], dict[str, dict]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "inventory_source_id", "sbom_source_id",
            "inventory_complete", "sbom_complete", "firmware_inventory", "sbom_claims",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise FirmwareInventorySbomError("Unsupported model version")
    core.identifier(model["inventory_source_id"], "inventory source ID")
    core.identifier(model["sbom_source_id"], "SBOM source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    core.boolean(model["sbom_complete"], "SBOM completeness")
    inventory = _claims(model["firmware_inventory"], "firmware inventory")
    sbom = _claims(model["sbom_claims"], "SBOM claims")
    if (
        not inventory and not sbom
        and model["inventory_complete"] and model["sbom_complete"]
    ):
        raise FirmwareInventorySbomError("Complete empty claim sets are unsupported")
    return model, core.canonical(model), inventory, sbom


def _derive(value: Any) -> dict:
    model, model_text, inventory, sbom = _model(value)
    rows = []
    for component_id in sorted(inventory.keys() | sbom.keys()):
        firmware_row = inventory.get(component_id)
        sbom_row = sbom.get(component_id)
        if firmware_row is None:
            comparison = "sbom_only"
        elif sbom_row is None:
            comparison = "inventory_only"
        else:
            version_matches = firmware_row["version"] == sbom_row["version"]
            digest_matches = firmware_row["sha256"] == sbom_row["sha256"]
            comparison = (
                "matching_claims" if version_matches and digest_matches else
                "version_and_digest_differ" if not version_matches and not digest_matches else
                "version_differs" if not version_matches else "digest_differs"
            )
        rows.append({
            "component_id": component_id,
            "comparison": comparison,
            "inventory_version": firmware_row["version"] if firmware_row else None,
            "sbom_version": sbom_row["version"] if sbom_row else None,
            "inventory_sha256": firmware_row["sha256"] if firmware_row else None,
            "sbom_sha256": sbom_row["sha256"] if sbom_row else None,
        })
    complete = model["inventory_complete"] and model["sbom_complete"]
    differing = sum(row["comparison"] != "matching_claims" for row in rows)
    disposition = (
        "unknown_incomplete_supplied_claims" if not complete else
        "candidate_supplied_claim_mismatch" if differing else "supplied_claims_match"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "inventory_source_id": model["inventory_source_id"],
        "sbom_source_id": model["sbom_source_id"],
        "inventory_complete": model["inventory_complete"],
        "sbom_complete": model["sbom_complete"],
        "inventory_claim_count": len(inventory),
        "sbom_claim_count": len(sbom),
        "rows": rows,
        "disposition": disposition,
        "candidate_count": differing if complete else 0,
        "unknown_count": int(not complete),
        "source_authenticated": False,
        "firmware_acquired": False,
        "firmware_unpacked": False,
        "sbom_parsed": False,
        "component_bytes_hashed": False,
        "device_contacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Inventory and SBOM fields are supplied claims, not authenticated artifacts.",
            "Digest equality compares supplied strings; no component bytes are read or hashed.",
            "A mismatch is an unsigned review candidate only when both sets are declared complete.",
            "Claim matching does not prove composition, integrity, provenance or device state.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="FSB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class FirmwareInventorySbomReport:
    """Unsigned claim reconciliation requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise FirmwareInventorySbomError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> FirmwareInventorySbomReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_firmware_inventory_sbom(model: Any) -> FirmwareInventorySbomReport:
    return FirmwareInventorySbomReport._owned(_derive(model))


def verify_supplied_firmware_inventory_sbom(
    report: Any, *, model: Any
) -> FirmwareInventorySbomReport:
    if type(report) is not FirmwareInventorySbomReport:
        raise FirmwareInventorySbomError("Exact firmware inventory wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise FirmwareInventorySbomError("Report differs from separate original model")
    return FirmwareInventorySbomReport._owned(expected)


def verify_supplied_firmware_inventory_sbom_bytes(
    report_bytes: bytes, *, model: Any
) -> FirmwareInventorySbomReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise FirmwareInventorySbomError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise FirmwareInventorySbomError("Exported report differs from original replay")
    return FirmwareInventorySbomReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "inventory_source_id": "synthetic-firmware-inventory",
        "sbom_source_id": "synthetic-sbom-claims",
        "inventory_complete": True,
        "sbom_complete": True,
        "firmware_inventory": [
            {
                "component_id": "controller-runtime",
                "version": "2.0",
                "sha256": "sha256:" + "1" * 64,
            },
        ],
        "sbom_claims": [
            {
                "component_id": "controller-runtime",
                "version": "1.9",
                "sha256": "sha256:" + "1" * 64,
            },
        ],
    }

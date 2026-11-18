"""Inspect bounded caller-supplied ACPI table bytes without platform access."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "acpi_supplied_table_integrity"
PROFILE_ID = "AOE-GD-D24-S01"
CAPABILITY_ID = "army.gd.d24.s01"
VECTOR_ID = "AV-GD-D24-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:d42c7082450419c7c471aa96405d99d5e68b6a8320a9fd92c023b500624ecfd0"
DOMAIN = "sunderkey.offline-acpi-table-integrity.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_TABLE_BYTES = 4_096
HEADER_BYTES = 36
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AcpiTableIntegrityError(ValueError):
    """A supplied ACPI table model or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "table_complete", "table_bytes"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AcpiTableIntegrityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["table_complete"], "table completeness")
    table = core.bounded_list(model["table_bytes"], MAX_TABLE_BYTES, "table bytes")
    if not table:
        raise AcpiTableIntegrityError("Table bytes must not be empty")
    if any(type(item) is not int or not 0 <= item <= 255 for item in table):
        raise AcpiTableIntegrityError("Table bytes must be native unsigned8 values")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    table = bytes(model["table_bytes"])
    signature = table[:4].decode("ascii", errors="replace") if len(table) >= 4 else None
    common_header_supported = signature != "FACS"
    declared_length = (
        int.from_bytes(table[4:8], "little")
        if common_header_supported and len(table) >= 8
        else None
    )
    issues: list[str] = []
    if common_header_supported and len(table) < HEADER_BYTES:
        issues.append("short_common_header")
    if declared_length is not None and model["table_complete"] and declared_length != len(table):
        issues.append("declared_length_mismatch")
    checksum_valid = None
    if (
        common_header_supported
        and model["table_complete"]
        and declared_length == len(table)
        and len(table) >= HEADER_BYTES
    ):
        checksum_valid = sum(table) % 256 == 0
        if not checksum_valid:
            issues.append("table_checksum_mismatch")
    disposition = (
        "unknown"
        if not model["table_complete"] or not common_header_supported
        else "candidate_supplied_acpi_table_integrity_gap"
        if issues
        else "no_supplied_acpi_table_integrity_gap"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "signature": signature,
        "common_header_supported": common_header_supported,
        "supplied_byte_count": len(table),
        "declared_length": declared_length,
        "checksum_valid": checksum_valid,
        "issues": issues,
        "disposition": disposition,
        "candidate_count": (
            len(issues) if model["table_complete"] and common_header_supported else 0
        ),
        "unknown_count": int(not model["table_complete"] or not common_header_supported),
        "source_authenticated": False,
        "platform_contacted": False,
        "firmware_verified": False,
        "exploit_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "The supplied bytes and completeness declaration are unauthenticated.",
            "Only the common ACPI header length and whole-table checksum are evaluated.",
            "FACS and table-specific fields are not parsed; no platform firmware is read.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ATI-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AcpiTableIntegrityReport:
    """Unsigned ACPI projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AcpiTableIntegrityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AcpiTableIntegrityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_acpi_table(model: Any) -> AcpiTableIntegrityReport:
    return AcpiTableIntegrityReport._owned(_derive(model))


def verify_supplied_acpi_table(report: Any, *, model: Any) -> AcpiTableIntegrityReport:
    if type(report) is not AcpiTableIntegrityReport:
        raise AcpiTableIntegrityError("Exact ACPI table wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AcpiTableIntegrityError("Report differs from separate original model")
    return AcpiTableIntegrityReport._owned(expected)


def verify_supplied_acpi_table_bytes(
    report_bytes: bytes, *, model: Any
) -> AcpiTableIntegrityReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AcpiTableIntegrityError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AcpiTableIntegrityError("Exported report differs from original replay")
    return AcpiTableIntegrityReport._owned(expected)


def component_fixture() -> dict:
    table = [84, 69, 83, 84, 36, 0, 0, 0, 1, 0] + [0] * 26
    return {
        "schema_version": 1,
        "source_id": "synthetic-acpi-table",
        "table_complete": True,
        "table_bytes": table,
    }

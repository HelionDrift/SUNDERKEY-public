"""Compare supplied backup freshness and restore-test declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "backup_supplied_recovery_posture_projection"
PROFILE_ID = "AOE-GC-D16-S08"
CAPABILITY_ID = "army.gc.d16.s08"
VECTOR_ID = "AV-GC-D16-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S08"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:0148a5b642a42026f51e22d4bb88aab51a9174a4f2b385e2e3e7bf4ff7703a6d"
DOMAIN = "sunderkey.offline-backup-recovery-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_ASSETS = 32
MAX_AGE_SECONDS = 315_360_000
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


class BackupRecoveryPostureError(ValueError):
    """The reduced backup declaration or replay is invalid."""


def _age(value: Any, label: str, *, optional: bool = False) -> int | None:
    if optional and value is None:
        return None
    if type(value) is not int or not 0 <= value <= MAX_AGE_SECONDS:
        raise BackupRecoveryPostureError(f"{label} must be a bounded nonnegative integer")
    return value


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "assets"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BackupRecoveryPostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["assets"], MAX_ASSETS, "assets"):
        asset = core.exact(
            row,
            {
                "asset_id",
                "backup_required",
                "backup_enabled",
                "maximum_recovery_point_age_seconds",
                "latest_backup_age_seconds",
                "maximum_restore_test_age_seconds",
                "latest_restore_test_age_seconds",
            },
            "asset",
        )
        asset_id = core.identifier(asset["asset_id"], "asset ID")
        if asset_id in seen:
            raise BackupRecoveryPostureError("Duplicate asset ID")
        seen.add(asset_id)
        core.boolean(asset["backup_required"], "backup requirement")
        if asset["backup_enabled"] is not None:
            core.boolean(asset["backup_enabled"], "backup enabled assertion")
        _age(asset["maximum_recovery_point_age_seconds"], "recovery point limit")
        _age(asset["latest_backup_age_seconds"], "latest backup age", optional=True)
        _age(asset["maximum_restore_test_age_seconds"], "restore test limit")
        _age(asset["latest_restore_test_age_seconds"], "restore test age", optional=True)
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    assets = sorted(model["assets"], key=lambda row: row["asset_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for asset in assets:
        asset_id = asset["asset_id"]
        if not asset["backup_required"]:
            continue
        if asset["backup_enabled"] is False:
            signals.append({"issue": "declared_backup_disabled", "asset_id": asset_id})
        elif asset["backup_enabled"] is None:
            uncertainty.append({"issue": "backup_enablement_not_asserted", "asset_id": asset_id})
        if asset["latest_backup_age_seconds"] is None:
            uncertainty.append({"issue": "latest_backup_age_missing", "asset_id": asset_id})
        elif asset["latest_backup_age_seconds"] > asset["maximum_recovery_point_age_seconds"]:
            signals.append({"issue": "declared_recovery_point_age_exceeded", "asset_id": asset_id})
        if asset["latest_restore_test_age_seconds"] is None:
            uncertainty.append({"issue": "restore_test_age_missing", "asset_id": asset_id})
        elif asset["latest_restore_test_age_seconds"] > asset["maximum_restore_test_age_seconds"]:
            signals.append({"issue": "declared_restore_test_age_exceeded", "asset_id": asset_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "asset_id": "none"})
    signals.sort(key=lambda row: (row["asset_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["asset_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_recovery_review"
    elif uncertainty or not assets:
        disposition = "unknown"
    else:
        disposition = "no_declared_recovery_review_signal"
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "inventory_complete_asserted": model["inventory_complete"],
        "asset_count": len(assets),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not assets),
        "disposition": disposition,
        "source_authenticated": False,
        "backup_verified": False,
        "restore_executed": False,
        "asset_contacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Asset, policy, backup and restore-test ages are supplied assertions.",
            "No clock, backup catalog, recovery point or restore result is independently checked.",
            "A declared policy-age difference is a review hypothesis, not failed recovery proof.",
            "No backup is read, altered or restored and no asset is contacted.",
            "An absent signal does not establish recoverability or resilience.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BRP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class BackupRecoveryPostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BackupRecoveryPostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BackupRecoveryPostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_backup_recovery_posture(model: Any) -> BackupRecoveryPostureReport:
    return BackupRecoveryPostureReport._owned(_derive(model))


def verify_supplied_backup_recovery_posture(
    report: Any, *, model: Any
) -> BackupRecoveryPostureReport:
    if type(report) is not BackupRecoveryPostureReport:
        raise BackupRecoveryPostureError("Exact backup posture wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BackupRecoveryPostureError("Report differs from separate original model")
    return BackupRecoveryPostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-backup-recovery",
        "inventory_complete": True,
        "assets": [
            {
                "asset_id": "asset_a",
                "backup_required": True,
                "backup_enabled": True,
                "maximum_recovery_point_age_seconds": 3600,
                "latest_backup_age_seconds": 7200,
                "maximum_restore_test_age_seconds": 86_400,
                "latest_restore_test_age_seconds": None,
            }
        ],
    }

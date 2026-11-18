"""Compare supplied Citrix, VDI and RDS session policy declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "vdi_supplied_session_posture_projection"
PROFILE_ID = "AOE-GC-D16-S07"
CAPABILITY_ID = "army.gc.d16.s07"
VECTOR_ID = "AV-GC-D16-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S07"
WAVE_ID = "IW2-019"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:6fc6c03225ae864f434f90b6898a01fd5743a5a37ebe37148ece16165fbeed8c"
DOMAIN = "sunderkey.offline-vdi-session-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_POOLS = 32
PLATFORMS = {"citrix", "vdi", "rds"}
ENTRY_SCOPES = {"internal", "partner", "public", "unknown"}
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


class VdiSessionPostureError(ValueError):
    """The reduced session declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "pools"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise VdiSessionPostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["pools"], MAX_POOLS, "pools"):
        pool = core.exact(
            row,
            {
                "pool_id",
                "platform",
                "remote_entry_scope",
                "session_mfa_enforced",
                "sensitive_data_asserted",
                "clipboard_transfer_allowed",
                "policy_assertions_complete",
            },
            "pool",
        )
        pool_id = core.identifier(pool["pool_id"], "pool ID")
        if pool_id in seen:
            raise VdiSessionPostureError("Duplicate pool ID")
        seen.add(pool_id)
        core.choice(pool["platform"], PLATFORMS, "platform")
        core.choice(pool["remote_entry_scope"], ENTRY_SCOPES, "entry scope")
        for field in ("session_mfa_enforced", "clipboard_transfer_allowed"):
            if pool[field] is not None:
                core.boolean(pool[field], field)
        core.boolean(pool["sensitive_data_asserted"], "sensitive data assertion")
        core.boolean(pool["policy_assertions_complete"], "policy completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    pools = sorted(model["pools"], key=lambda row: row["pool_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for pool in pools:
        pool_id = pool["pool_id"]
        if not pool["policy_assertions_complete"]:
            uncertainty.append({"issue": "incomplete_declared_session_policy", "pool_id": pool_id})
            continue
        entry = pool["remote_entry_scope"]
        if entry == "unknown":
            uncertainty.append({"issue": "remote_entry_scope_unknown", "pool_id": pool_id})
        if pool["session_mfa_enforced"] is None:
            uncertainty.append({"issue": "session_mfa_not_asserted", "pool_id": pool_id})
        elif entry == "public" and not pool["session_mfa_enforced"]:
            signals.append({"issue": "declared_public_session_without_mfa", "pool_id": pool_id})
        if pool["clipboard_transfer_allowed"] is None:
            uncertainty.append({"issue": "clipboard_policy_not_asserted", "pool_id": pool_id})
        elif pool["sensitive_data_asserted"] and pool["clipboard_transfer_allowed"]:
            signals.append({"issue": "declared_sensitive_clipboard_transfer", "pool_id": pool_id})
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "pool_id": "none"})
    signals.sort(key=lambda row: (row["pool_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["pool_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_session_review"
    elif uncertainty or not pools:
        disposition = "unknown"
    else:
        disposition = "no_declared_session_review_signal"
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
        "pool_count": len(pools),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not pools),
        "disposition": disposition,
        "source_authenticated": False,
        "remote_entry_verified": False,
        "session_policy_verified": False,
        "session_started": False,
        "data_transferred": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Platform, entry, MFA, sensitivity and clipboard labels are supplied assertions.",
            "No broker, gateway, policy engine or directory configuration is parsed.",
            "A declared policy difference is a review hypothesis, not session access proof.",
            "No remote session is started and no data or credential is transferred.",
            "An absent signal does not establish effective session isolation.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="VSP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class VdiSessionPostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise VdiSessionPostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> VdiSessionPostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_vdi_session_posture(model: Any) -> VdiSessionPostureReport:
    return VdiSessionPostureReport._owned(_derive(model))


def verify_supplied_vdi_session_posture(report: Any, *, model: Any) -> VdiSessionPostureReport:
    if type(report) is not VdiSessionPostureReport:
        raise VdiSessionPostureError("Exact VDI session wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise VdiSessionPostureError("Report differs from separate original model")
    return VdiSessionPostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-vdi-session",
        "inventory_complete": True,
        "pools": [
            {
                "pool_id": "pool_a",
                "platform": "citrix",
                "remote_entry_scope": "public",
                "session_mfa_enforced": False,
                "sensitive_data_asserted": True,
                "clipboard_transfer_allowed": True,
                "policy_assertions_complete": True,
            }
        ],
    }

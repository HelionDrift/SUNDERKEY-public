"""Compare supplied monitoring and RMM remote-control declarations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "rmm_supplied_control_posture_projection"
PROFILE_ID = "AOE-GC-D16-S11"
CAPABILITY_ID = "army.gc.d16.s11"
VECTOR_ID = "AV-GC-D16-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D16-S11"
WAVE_ID = "IW2-023"
COMMANDER_ID = "AOE-GC-D16-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:72a91666878914f524b40723ad9cd26cbdc35e3fadd1c902d42e050b9629b8bf"
DOMAIN = "sunderkey.offline-rmm-control-posture.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_FLEETS = 32
CONTROL_SCOPES = {"restricted", "broad", "unknown"}
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


class RmmControlPostureError(ValueError):
    """The reduced remote-control declaration or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "fleets"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RmmControlPostureError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    seen: set[str] = set()
    for row in core.bounded_list(model["fleets"], MAX_FLEETS, "fleets"):
        fleet = core.exact(
            row,
            {
                "fleet_id",
                "remote_control_enabled",
                "operator_scope",
                "approval_required",
                "agent_inventory_complete",
                "policy_assertions_complete",
            },
            "fleet",
        )
        fleet_id = core.identifier(fleet["fleet_id"], "fleet ID")
        if fleet_id in seen:
            raise RmmControlPostureError("Duplicate fleet ID")
        seen.add(fleet_id)
        for field in ("remote_control_enabled", "approval_required"):
            if fleet[field] is not None:
                core.boolean(fleet[field], field)
        core.choice(fleet["operator_scope"], CONTROL_SCOPES, "operator scope")
        core.boolean(fleet["agent_inventory_complete"], "agent inventory completeness")
        core.boolean(fleet["policy_assertions_complete"], "policy completeness")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    fleets = sorted(model["fleets"], key=lambda row: row["fleet_id"])
    signals: list[dict[str, str]] = []
    uncertainty: list[dict[str, str]] = []
    for fleet in fleets:
        fleet_id = fleet["fleet_id"]
        if not fleet["policy_assertions_complete"]:
            uncertainty.append({"issue": "incomplete_declared_rmm_policy", "fleet_id": fleet_id})
            continue
        if not fleet["agent_inventory_complete"]:
            uncertainty.append(
                {"issue": "incomplete_declared_agent_inventory", "fleet_id": fleet_id}
            )
        if fleet["remote_control_enabled"] is None:
            uncertainty.append({"issue": "remote_control_state_unknown", "fleet_id": fleet_id})
            continue
        if not fleet["remote_control_enabled"]:
            continue
        if fleet["operator_scope"] == "unknown":
            uncertainty.append({"issue": "operator_scope_unknown", "fleet_id": fleet_id})
        elif fleet["operator_scope"] == "broad":
            signals.append({"issue": "declared_broad_remote_control_scope", "fleet_id": fleet_id})
        if fleet["approval_required"] is None:
            uncertainty.append({"issue": "approval_requirement_unknown", "fleet_id": fleet_id})
        elif not fleet["approval_required"]:
            signals.append(
                {"issue": "declared_remote_control_without_approval", "fleet_id": fleet_id}
            )
    if not model["inventory_complete"]:
        uncertainty.append({"issue": "incomplete_supplied_inventory", "fleet_id": "none"})
    signals.sort(key=lambda row: (row["fleet_id"], row["issue"]))
    uncertainty.sort(key=lambda row: (row["fleet_id"], row["issue"]))
    if signals:
        disposition = "candidate_declared_rmm_control_review"
    elif uncertainty or not fleets:
        disposition = "unknown"
    else:
        disposition = "no_declared_rmm_control_review_signal"
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
        "fleet_count": len(fleets),
        "signals": signals,
        "uncertainty": uncertainty,
        "candidate_count": len(signals),
        "unknown_count": len(uncertainty) + int(not fleets),
        "disposition": disposition,
        "source_authenticated": False,
        "operator_authority_verified": False,
        "agent_fleet_contacted": False,
        "remote_command_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Remote-control, scope, approval and inventory labels are supplied assertions.",
            "No RMM product policy, agent, tenant or operator credential is verified.",
            "A declared broad or unapproved scope is a review hypothesis, not access proof.",
            "No remote command runs and no managed endpoint is contacted.",
            "An absent signal does not establish fleet control safety.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RCP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RmmControlPostureReport:
    """Unsigned supplied-metadata projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RmmControlPostureError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RmmControlPostureReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rmm_control_posture(model: Any) -> RmmControlPostureReport:
    return RmmControlPostureReport._owned(_derive(model))


def verify_supplied_rmm_control_posture(report: Any, *, model: Any) -> RmmControlPostureReport:
    if type(report) is not RmmControlPostureReport:
        raise RmmControlPostureError("Exact RMM posture wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RmmControlPostureError("Report differs from separate original model")
    return RmmControlPostureReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-rmm-control",
        "inventory_complete": True,
        "fleets": [
            {
                "fleet_id": "fleet_a",
                "remote_control_enabled": True,
                "operator_scope": "broad",
                "approval_required": False,
                "agent_inventory_complete": False,
                "policy_assertions_complete": True,
            }
        ],
    }

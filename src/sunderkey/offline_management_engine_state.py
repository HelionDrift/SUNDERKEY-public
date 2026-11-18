"""Compare supplied Intel AMT control declarations with an explicit local policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "amt_supplied_control_state_policy"
PROFILE_ID = "AOE-GD-D24-S10"
CAPABILITY_ID = "army.gd.d24.s10"
VECTOR_ID = "AV-GD-D24-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D24-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GD-D24-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-33"
BLUEPRINT_SHA256 = "sha256:c37a9e12066fe826c8edf1b9b4971085afd0cb41e90f58f1ea08e1a1d75fb3a1"
DOMAIN = "sunderkey.offline-management-engine-state.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class ManagementEngineStateError(ValueError):
    """A supplied AMT declaration or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "platforms"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ManagementEngineStateError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    platforms = core.bounded_list(model["platforms"], 64, "platforms")
    if not platforms:
        raise ManagementEngineStateError("At least one platform is required")
    platform_ids: set[str] = set()
    for row in platforms:
        platform = core.exact(
            row,
            {
                "platform_id", "provisioning_state", "control_mode",
                "network_interface_enabled", "tls_enabled", "network_policy",
            },
            "platform",
        )
        platform_id = core.identifier(platform["platform_id"], "platform ID")
        if platform_id in platform_ids:
            raise ManagementEngineStateError("Duplicate platform ID")
        platform_ids.add(platform_id)
        core.choice(
            platform["provisioning_state"], {"unconfigured", "configured"},
            "provisioning state",
        )
        core.choice(platform["control_mode"], {"none", "CCM", "ACM"}, "control mode")
        core.boolean(platform["network_interface_enabled"], "network interface state")
        core.boolean(platform["tls_enabled"], "TLS state")
        core.choice(
            platform["network_policy"], {"disabled", "tls_required", "unrestricted"},
            "network policy",
        )
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    gaps = []
    for platform in sorted(model["platforms"], key=lambda row: row["platform_id"]):
        platform_id = platform["platform_id"]
        state = platform["provisioning_state"]
        mode = platform["control_mode"]
        network_enabled = platform["network_interface_enabled"]
        tls_enabled = platform["tls_enabled"]
        policy = platform["network_policy"]
        if (state == "unconfigured") != (mode == "none"):
            gaps.append({"platform_id": platform_id, "issue": "control_mode_state_mismatch"})
        if network_enabled and policy == "disabled":
            gaps.append({"platform_id": platform_id, "issue": "network_policy_disabled_mismatch"})
        if (
            state == "configured"
            and network_enabled
            and not tls_enabled
            and policy == "tls_required"
        ):
            gaps.append({"platform_id": platform_id, "issue": "network_policy_tls_mismatch"})
    disposition = (
        "unknown"
        if not model["inventory_complete"]
        else "candidate_supplied_amt_control_gap"
        if gaps
        else "no_supplied_amt_control_gap"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "platform_count": len(model["platforms"]),
        "gaps": gaps,
        "disposition": disposition,
        "candidate_count": len(gaps) if model["inventory_complete"] else 0,
        "unknown_count": int(not model["inventory_complete"]),
        "source_authenticated": False,
        "management_engine_contacted": False,
        "network_reachability_verified": False,
        "effective_control_verified": False,
        "exploit_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "AMT states and network policy are caller-supplied, not discovered or authenticated.",
            "No chipset, management engine, host, network endpoint or credentials are used.",
            "This does not prove remote exposure or effective control.",
            "It does not prove firmware state or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MES-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ManagementEngineStateReport:
    """Unsigned AMT policy projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ManagementEngineStateError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ManagementEngineStateReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_management_engine_state(model: Any) -> ManagementEngineStateReport:
    return ManagementEngineStateReport._owned(_derive(model))


def verify_supplied_management_engine_state(
    report: Any, *, model: Any
) -> ManagementEngineStateReport:
    if type(report) is not ManagementEngineStateReport:
        raise ManagementEngineStateError("Exact management-engine wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ManagementEngineStateError("Report differs from separate original model")
    return ManagementEngineStateReport._owned(expected)


def verify_supplied_management_engine_state_bytes(
    report_bytes: bytes, *, model: Any
) -> ManagementEngineStateReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ManagementEngineStateError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ManagementEngineStateError("Exported report differs from original replay")
    return ManagementEngineStateReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-amt-inventory",
        "inventory_complete": True,
        "platforms": [
            {
                "platform_id": "lab-workstation-a",
                "provisioning_state": "configured",
                "control_mode": "CCM",
                "network_interface_enabled": True,
                "tls_enabled": False,
                "network_policy": "tls_required",
            }
        ],
    }

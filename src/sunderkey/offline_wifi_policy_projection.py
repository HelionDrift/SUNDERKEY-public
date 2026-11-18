"""Compare supplied synthetic Wi-Fi declarations against caller policy only."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_wifi_policy_projection"
PROFILE_ID = "AOE-GC-D13-S08"
CAPABILITY_ID = "army.gc.d13.s08"
VECTOR_ID = "AV-GC-D13-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S08"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c0f5b16c691e99e87ada4655ca2fdae16cb1e7458ec55afbde75ab7f0491990b"
DOMAIN = "sunderkey.offline-wifi-policy-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_NETWORKS = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MODES = {
    "open",
    "wpa2_personal",
    "wpa2_enterprise",
    "wpa3_personal",
    "wpa3_enterprise",
    "wpa2_wpa3_transition",
}
PMF_STATES = {"disabled", "capable", "required"}
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


class WifiPolicyProjectionError(ValueError):
    """A supplied Wi-Fi declaration or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise WifiPolicyProjectionError(f"{label} must be synthetic")
    return identifier


def _mode(value: Any, label: str) -> str:
    return core.choice(value, MODES, label)


def _unique_modes(value: Any, label: str) -> list[str]:
    modes = [_mode(item, label) for item in core.bounded_list(value, len(MODES), label)]
    if len(modes) != len(set(modes)):
        raise WifiPolicyProjectionError(f"{label} contains duplicates")
    return modes


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "policy_id",
            "policy_complete",
            "networks_complete",
            "policy",
            "networks",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise WifiPolicyProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    _synthetic(model["policy_id"], "policy ID")
    core.boolean(model["policy_complete"], "policy completeness")
    core.boolean(model["networks_complete"], "network completeness")
    policy = core.exact(
        model["policy"],
        {"allowed_modes", "pmf_required_modes", "guest_isolation_required"},
        "policy",
    )
    allowed = _unique_modes(policy["allowed_modes"], "allowed modes")
    required = _unique_modes(policy["pmf_required_modes"], "PMF-required modes")
    if not set(required) <= set(allowed):
        raise WifiPolicyProjectionError("PMF-required modes must be allowed modes")
    core.boolean(policy["guest_isolation_required"], "guest isolation requirement")
    networks = core.bounded_list(model["networks"], MAX_NETWORKS, "networks")
    if not networks:
        raise WifiPolicyProjectionError("At least one network is required")
    seen: set[str] = set()
    for item in networks:
        network = core.exact(
            item,
            {"network_id", "security_mode", "pmf_state", "guest", "client_isolation"},
            "network",
        )
        network_id = _synthetic(network["network_id"], "network ID")
        if network_id in seen:
            raise WifiPolicyProjectionError("Duplicate network ID")
        seen.add(network_id)
        _mode(network["security_mode"], "security mode")
        core.choice(network["pmf_state"], PMF_STATES, "PMF state")
        core.boolean(network["guest"], "guest flag")
        core.boolean(network["client_isolation"], "client isolation flag")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    complete = model["policy_complete"] and model["networks_complete"]
    allowed = set(policy["allowed_modes"])
    required = set(policy["pmf_required_modes"])
    projections: list[dict] = []
    for network in model["networks"]:
        issues: list[str] = []
        if complete:
            if network["security_mode"] not in allowed:
                issues.append("security_mode_differs_from_policy")
            if network["security_mode"] in required and network["pmf_state"] != "required":
                issues.append("pmf_state_differs_from_policy")
            if (
                network["guest"]
                and policy["guest_isolation_required"]
                and not network["client_isolation"]
            ):
                issues.append("guest_isolation_differs_from_policy")
        projections.append(
            {
                "network_id": network["network_id"],
                "issues": issues,
                "disposition": (
                    "unknown_incomplete_declarations"
                    if not complete
                    else "candidate_declared_policy_difference"
                    if issues
                    else "consistent_under_declared_policy"
                ),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "network_count": len(projections),
            "candidate_count": sum(
                row["disposition"] == "candidate_declared_policy_difference" for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations" for row in projections
            ),
        },
        "source_authenticated": False,
        "radio_observed": False,
        "authentication_observed": False,
        "pmf_behavior_observed": False,
        "client_isolation_observed": False,
        "wireless_exposure_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Network and policy labels are unauthenticated caller declarations.",
            "Mode and PMF comparisons use caller policy, not a universal security baseline.",
            "No SSID, BSSID, access-point, packet, key or credential field is accepted.",
            "Synthetic IDs are caller labels, not proof the supplied data is synthetic.",
            "No radio traffic, association, authentication or isolation is observed.",
            "A declared difference does not prove a live weakness or reachable client.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="WPP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class WifiPolicyProjectionReport:
    """Unsigned declaration projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise WifiPolicyProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> WifiPolicyProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_wifi_policy(model: Any) -> WifiPolicyProjectionReport:
    try:
        return WifiPolicyProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise WifiPolicyProjectionError(str(exc)) from exc


def verify_supplied_wifi_policy(
    report: Any,
    *,
    model: Any,
) -> WifiPolicyProjectionReport:
    if type(report) is not WifiPolicyProjectionReport:
        raise WifiPolicyProjectionError("Exact report wrapper required")
    expected = analyze_supplied_wifi_policy(model)
    if report.to_json() != expected.to_json():
        raise WifiPolicyProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_wifi_policy_bytes(
    report_bytes: bytes,
    *,
    model: Any,
) -> WifiPolicyProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise WifiPolicyProjectionError(str(exc)) from exc
    expected = analyze_supplied_wifi_policy(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise WifiPolicyProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:wifi-source",
        "policy_id": "synthetic:wifi-policy",
        "policy_complete": True,
        "networks_complete": True,
        "policy": {
            "allowed_modes": ["wpa3_personal", "wpa2_wpa3_transition"],
            "pmf_required_modes": ["wpa3_personal"],
            "guest_isolation_required": True,
        },
        "networks": [
            {
                "network_id": "synthetic:staff",
                "security_mode": "wpa3_personal",
                "pmf_state": "required",
                "guest": False,
                "client_isolation": False,
            },
            {
                "network_id": "synthetic:guest",
                "security_mode": "wpa2_wpa3_transition",
                "pmf_state": "capable",
                "guest": True,
                "client_isolation": False,
            },
        ],
    }


__all__ = [
    "WifiPolicyProjectionError",
    "WifiPolicyProjectionReport",
    "analyze_supplied_wifi_policy",
    "verify_supplied_wifi_policy",
    "verify_supplied_wifi_policy_bytes",
    "component_fixture",
]

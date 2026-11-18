"""Compare supplied port-admission and VLAN assertions without network access."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_nac_admission_consistency"
PROFILE_ID = "AOE-GC-D13-S07"
CAPABILITY_ID = "army.gc.d13.s07"
VECTOR_ID = "AV-GC-D13-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S07"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GC-D13-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:bcf8bcbc663819c96cfaf49e64ebc6bfdcf66d846e139917beffef46e04bfeb2"
DOMAIN = "sunderkey.offline-nac-admission-consistency.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_SESSIONS = 256
MAX_VLANS = 256
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class NacAdmissionError(ValueError):
    """A supplied admission model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise NacAdmissionError(f"{label} must be synthetic")
    return identifier


def _vlan(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 4094:
        raise NacAdmissionError(f"{label} must be an integer from 1 to 4094")
    return value


def _optional_vlan(value: Any, label: str) -> int | None:
    return None if value is None else _vlan(value, label)


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_id", "policy_complete",
            "sessions_complete", "configured_vlans_complete", "policy",
            "configured_vlans", "sessions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise NacAdmissionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    _synthetic(model["policy_id"], "policy ID")
    for field in ("policy_complete", "sessions_complete", "configured_vlans_complete"):
        core.boolean(model[field], field)
    policy = core.exact(
        model["policy"],
        {
            "accept_requires_authorized", "reject_requires_unauthorized",
            "accepted_vlan_required",
        },
        "policy",
    )
    for field in policy:
        core.boolean(policy[field], field)
    configured = core.bounded_list(model["configured_vlans"], MAX_VLANS, "configured VLANs")
    configured_ids = [_vlan(item, "configured VLAN") for item in configured]
    if len(set(configured_ids)) != len(configured_ids):
        raise NacAdmissionError("Duplicate configured VLAN")
    sessions = core.bounded_list(model["sessions"], MAX_SESSIONS, "sessions")
    if not sessions:
        raise NacAdmissionError("At least one session is required")
    seen: set[str] = set()
    for item in sessions:
        session = core.exact(
            item,
            {
                "session_id", "port_id", "radius_result", "controlled_port_state",
                "tunnel_type", "tunnel_medium_type", "tunnel_private_group_vlan",
                "declared_assigned_vlan",
            },
            "session",
        )
        session_id = _synthetic(session["session_id"], "session ID")
        if session_id in seen:
            raise NacAdmissionError("Duplicate session ID")
        seen.add(session_id)
        _synthetic(session["port_id"], "port ID")
        core.choice(session["radius_result"], {"accept", "reject"}, "RADIUS result")
        core.choice(
            session["controlled_port_state"],
            {"authorized", "unauthorized"},
            "controlled port state",
        )
        if session["tunnel_type"] not in (None, "vlan"):
            raise NacAdmissionError("Unsupported tunnel type")
        if session["tunnel_medium_type"] not in (None, "ieee802"):
            raise NacAdmissionError("Unsupported tunnel medium type")
        _optional_vlan(session["tunnel_private_group_vlan"], "tunnel VLAN")
        _optional_vlan(session["declared_assigned_vlan"], "assigned VLAN")
    return model


def _issues(session: dict, policy: dict, configured: set[int]) -> list[str]:
    issues: list[str] = []
    if session["radius_result"] == "reject":
        if (
            policy["reject_requires_unauthorized"]
            and session["controlled_port_state"] == "authorized"
        ):
            issues.append("reject_port_state_differs_from_policy")
        return issues
    if (
        policy["accept_requires_authorized"]
        and session["controlled_port_state"] == "unauthorized"
    ):
        issues.append("accept_port_state_differs_from_policy")
    if policy["accepted_vlan_required"]:
        vlan = session["tunnel_private_group_vlan"]
        if (
            session["tunnel_type"] != "vlan"
            or session["tunnel_medium_type"] != "ieee802"
            or vlan is None
        ):
            issues.append("required_vlan_attributes_incomplete")
        else:
            if vlan not in configured:
                issues.append("assigned_vlan_not_declared_configured")
            if session["declared_assigned_vlan"] != vlan:
                issues.append("declared_vlan_assignment_differs")
    return issues


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[field]
        for field in ("policy_complete", "sessions_complete", "configured_vlans_complete")
    )
    configured = set(model["configured_vlans"])
    projections: list[dict] = []
    for session in model["sessions"]:
        issues = _issues(session, model["policy"], configured) if complete else []
        disposition = (
            "unknown_incomplete_declarations" if not complete
            else "candidate_declared_policy_difference" if issues
            else "consistent_under_declared_policy"
        )
        projections.append({
            "session_id": session["session_id"],
            "port_id": session["port_id"],
            "issues": issues,
            "disposition": disposition,
        })
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
            "session_count": len(projections),
            "candidate_count": sum(
                row["disposition"] == "candidate_declared_policy_difference"
                for row in projections
            ),
            "unknown_count": sum(
                row["disposition"] == "unknown_incomplete_declarations"
                for row in projections
            ),
        },
        "source_authenticated": False,
        "radius_exchange_observed": False,
        "controlled_port_observed": False,
        "vlan_assignment_observed": False,
        "device_policy_verified": False,
        "access_bypass_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "RADIUS result, controlled port state and VLAN attributes are caller declarations.",
            "The expected mapping is caller policy, not universal device behavior.",
            "Only numeric VLAN assignment attributes are modeled, not packet encoding.",
            "Fallback modes, multi-host ports, reauthentication and vendor policy are excluded.",
            "A declared difference does not prove a live bypass or reachable segment.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="NAP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class NacAdmissionReport:
    """Unsigned NAC assertion projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise NacAdmissionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> NacAdmissionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_nac_admission(model: Any) -> NacAdmissionReport:
    try:
        return NacAdmissionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise NacAdmissionError(str(exc)) from exc


def verify_supplied_nac_admission(
    report: Any, *, model: Any,
) -> NacAdmissionReport:
    if type(report) is not NacAdmissionReport:
        raise NacAdmissionError("Exact report wrapper required")
    expected = analyze_supplied_nac_admission(model)
    if report.to_json() != expected.to_json():
        raise NacAdmissionError("Report differs from separate original model")
    return expected


def verify_supplied_nac_admission_bytes(
    report_bytes: bytes, *, model: Any,
) -> NacAdmissionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise NacAdmissionError(str(exc)) from exc
    expected = analyze_supplied_nac_admission(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise NacAdmissionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:nac-source",
        "policy_id": "synthetic:nac-policy",
        "policy_complete": True,
        "sessions_complete": True,
        "configured_vlans_complete": True,
        "policy": {
            "accept_requires_authorized": True,
            "reject_requires_unauthorized": True,
            "accepted_vlan_required": True,
        },
        "configured_vlans": [20, 30],
        "sessions": [
            {"session_id": "synthetic:accepted", "port_id": "synthetic:port-one",
             "radius_result": "accept", "controlled_port_state": "authorized",
             "tunnel_type": "vlan", "tunnel_medium_type": "ieee802",
             "tunnel_private_group_vlan": 20, "declared_assigned_vlan": 20},
            {"session_id": "synthetic:rejected", "port_id": "synthetic:port-two",
             "radius_result": "reject", "controlled_port_state": "authorized",
             "tunnel_type": None, "tunnel_medium_type": None,
             "tunnel_private_group_vlan": None, "declared_assigned_vlan": None},
        ],
    }


__all__ = [
    "NacAdmissionError", "NacAdmissionReport",
    "analyze_supplied_nac_admission", "verify_supplied_nac_admission",
    "verify_supplied_nac_admission_bytes", "component_fixture",
]

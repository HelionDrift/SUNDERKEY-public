"""Project direct guest and tenant trust declarations without federation calls."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_guest_trust_projection"
PROFILE_ID = "AOE-GA-D03-S09"
CAPABILITY_ID = "army.ga.d03.s09"
VECTOR_ID = "AV-GA-D03-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S09"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:d6025fce8a67988e012f9604e4cc9e4df3e05f0a51bab867b6bf9e69bf267ea1"
DOMAIN = "sunderkey.offline-guest-trust-projection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_GUESTS = 256
MAX_TRUSTS = 256
MAX_OBSERVATIONS = 512
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class GuestTrustProjectionError(ValueError):
    """A supplied guest-trust model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise GuestTrustProjectionError(f"{label} must be a synthetic label")
    return identifier


def _model(value: Any) -> tuple[dict, dict[str, dict], dict[tuple[str, str], bool]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "guests_complete",
            "trusts_complete", "guests", "trusts", "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GuestTrustProjectionError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in ("policy_complete", "guests_complete", "trusts_complete"):
        core.boolean(model[field], field)
    guests: dict[str, dict] = {}
    for item in core.bounded_list(model["guests"], MAX_GUESTS, "guests"):
        row = core.exact(
            item,
            {"guest_id", "home_tenant", "resource_tenant", "invitation_recorded", "active"},
            "guest",
        )
        guest_id = _synthetic(row["guest_id"], "guest ID")
        if guest_id in guests:
            raise GuestTrustProjectionError("Duplicate guest ID")
        _synthetic(row["home_tenant"], "home tenant ID")
        _synthetic(row["resource_tenant"], "resource tenant ID")
        core.boolean(row["invitation_recorded"], "invitation recorded")
        core.boolean(row["active"], "guest active")
        guests[guest_id] = row
    trusts: dict[tuple[str, str], bool] = {}
    for item in core.bounded_list(model["trusts"], MAX_TRUSTS, "trusts"):
        row = core.exact(
            item, {"home_tenant", "resource_tenant", "enabled"}, "direct trust"
        )
        home = _synthetic(row["home_tenant"], "trust home tenant")
        resource = _synthetic(row["resource_tenant"], "trust resource tenant")
        core.boolean(row["enabled"], "trust enabled")
        edge = (home, resource)
        if edge in trusts:
            raise GuestTrustProjectionError("Duplicate direct trust")
        trusts[edge] = row["enabled"]
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise GuestTrustProjectionError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {"observation_id", "guest_id", "resource_tenant", "reported_outcome"},
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen:
            raise GuestTrustProjectionError("Duplicate observation ID")
        seen.add(observation_id)
        _synthetic(row["guest_id"], "observation guest ID")
        _synthetic(row["resource_tenant"], "observation resource tenant ID")
        core.choice(row["reported_outcome"], {"allowed", "denied", "unknown"}, "outcome")
    return model, guests, trusts


def _project(observation: dict, model: dict, guests: dict, trusts: dict) -> dict:
    guest = guests.get(observation["guest_id"])
    if not model["policy_complete"]:
        decision, basis = "unknown", "incomplete_policy"
    elif guest is None:
        if model["guests_complete"]:
            decision, basis = "deny", "guest_absent_from_complete_inventory"
        else:
            decision, basis = "unknown", "guest_inventory_incomplete"
    elif observation["resource_tenant"] != guest["resource_tenant"]:
        decision, basis = "deny", "different_declared_resource_tenant"
    elif not guest["invitation_recorded"] or not guest["active"]:
        decision, basis = "deny", "invitation_or_guest_inactive"
    else:
        edge = (guest["home_tenant"], guest["resource_tenant"])
        enabled = trusts.get(edge)
        if enabled is False:
            decision, basis = "deny", "direct_trust_disabled"
        elif enabled is None and model["trusts_complete"]:
            decision, basis = "deny", "direct_trust_absent"
        elif enabled is None:
            decision, basis = "unknown", "trust_inventory_incomplete"
        else:
            decision, basis = "unknown", "no_federation_or_access_validation"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif reported == "allowed":
        assessment = "candidate_declared_guest_trust_conflict"
    else:
        assessment = "declared_deny_consistent"
    return {
        "observation_id": observation["observation_id"],
        "guest_id": observation["guest_id"],
        "resource_tenant": observation["resource_tenant"],
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
    }


def _derive(value: Any) -> dict:
    model, guests, trusts = _model(value)
    projections = [
        _project(item, model, guests, trusts) for item in model["observations"]
    ]
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
            "observation_count": len(projections),
            "candidate_count": sum(
                row["assessment"] == "candidate_declared_guest_trust_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "guest_inventory_authenticated": False,
        "trust_policy_authenticated": False,
        "reported_outcomes_authenticated": False,
        "federation_exchange_performed": False,
        "effective_guest_access_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Guests, invitations, direct trust rules, completeness and outcomes are declarations.",
            "Only exact direct home-to-resource trust is modeled; no transitive trust exists.",
            "A declared enabled trust remains unknown without federation and access checks.",
            "A candidate mismatch is not effective guest access or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="GTP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class GuestTrustProjectionReport:
    """Unsigned result wrapper requiring separately retained original input."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise GuestTrustProjectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> GuestTrustProjectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_guest_trust(model: Any) -> GuestTrustProjectionReport:
    try:
        return GuestTrustProjectionReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise GuestTrustProjectionError(str(exc)) from exc


def verify_supplied_guest_trust(
    report: Any, *, model: Any,
) -> GuestTrustProjectionReport:
    if type(report) is not GuestTrustProjectionReport:
        raise GuestTrustProjectionError("Exact report wrapper required")
    expected = analyze_supplied_guest_trust(model)
    if report.to_json() != expected.to_json():
        raise GuestTrustProjectionError("Report differs from separate original model")
    return expected


def verify_supplied_guest_trust_bytes(
    report_bytes: bytes, *, model: Any,
) -> GuestTrustProjectionReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise GuestTrustProjectionError(str(exc)) from exc
    expected = analyze_supplied_guest_trust(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise GuestTrustProjectionError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:guest-trust",
        "policy_complete": True,
        "guests_complete": True,
        "trusts_complete": True,
        "guests": [
            {
                "guest_id": "synthetic:guest-one",
                "home_tenant": "synthetic:tenant-home",
                "resource_tenant": "synthetic:tenant-resource",
                "invitation_recorded": True,
                "active": True,
            },
        ],
        "trusts": [
            {
                "home_tenant": "synthetic:tenant-home",
                "resource_tenant": "synthetic:tenant-resource",
                "enabled": False,
            },
        ],
        "observations": [
            {
                "observation_id": "synthetic:guest-observed",
                "guest_id": "synthetic:guest-one",
                "resource_tenant": "synthetic:tenant-resource",
                "reported_outcome": "allowed",
            },
        ],
    }


__all__ = [
    "GuestTrustProjectionError", "GuestTrustProjectionReport",
    "analyze_supplied_guest_trust", "verify_supplied_guest_trust",
    "verify_supplied_guest_trust_bytes", "component_fixture",
]

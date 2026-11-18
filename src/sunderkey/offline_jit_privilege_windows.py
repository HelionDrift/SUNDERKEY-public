"""Project supplied just-in-time privilege windows without using credentials."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_jit_privilege_windows"
PROFILE_ID = "AOE-GA-D03-S12"
CAPABILITY_ID = "army.ga.d03.s12"
VECTOR_ID = "AV-GA-D03-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S12"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:62e8cf4a3a39ecefe24243f5869af76012d2ce221c845949f2069d648d6bf7e7"
DOMAIN = "sunderkey.offline-jit-privilege-windows.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_GRANTS = 256
MAX_REVOCATIONS = 512
MAX_OBSERVATIONS = 512
MAX_TICK = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class JitPrivilegeWindowError(ValueError):
    """A supplied window model or separately sourced replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise JitPrivilegeWindowError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise JitPrivilegeWindowError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> tuple[dict, dict[str, dict], dict[str, list[int]]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "grants_complete",
            "revocations_complete", "order_complete", "grants", "revocations",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise JitPrivilegeWindowError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in (
        "policy_complete", "grants_complete", "revocations_complete", "order_complete",
    ):
        core.boolean(model[field], field)
    grants: dict[str, dict] = {}
    for item in core.bounded_list(model["grants"], MAX_GRANTS, "grants"):
        row = core.exact(
            item,
            {
                "grant_id", "principal_id", "privilege_id", "starts_at", "ends_at",
                "approval_recorded",
            },
            "grant",
        )
        grant_id = _synthetic(row["grant_id"], "grant ID")
        if grant_id in grants:
            raise JitPrivilegeWindowError("Duplicate grant ID")
        _synthetic(row["principal_id"], "principal ID")
        _synthetic(row["privilege_id"], "privilege ID")
        if _tick(row["starts_at"], "grant start") >= _tick(row["ends_at"], "grant end"):
            raise JitPrivilegeWindowError("Grant window is empty")
        core.boolean(row["approval_recorded"], "approval recorded")
        grants[grant_id] = row
    revocations: dict[str, list[int]] = {}
    seen_revocations: set[str] = set()
    for item in core.bounded_list(model["revocations"], MAX_REVOCATIONS, "revocations"):
        row = core.exact(item, {"revocation_id", "grant_id", "at_tick"}, "revocation")
        revocation_id = _synthetic(row["revocation_id"], "revocation ID")
        grant_id = _synthetic(row["grant_id"], "revocation grant ID")
        if revocation_id in seen_revocations or grant_id not in grants:
            raise JitPrivilegeWindowError("Revocation is duplicated or dangling")
        at_tick = _tick(row["at_tick"], "revocation tick")
        if at_tick < grants[grant_id]["starts_at"]:
            raise JitPrivilegeWindowError("Revocation precedes its grant window")
        seen_revocations.add(revocation_id)
        revocations.setdefault(grant_id, []).append(at_tick)
    seen_observations: set[str] = set()
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise JitPrivilegeWindowError("At least one observation is required")
    for item in observations:
        row = core.exact(
            item,
            {
                "observation_id", "principal_id", "privilege_id", "at_tick",
                "reported_outcome",
            },
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen_observations:
            raise JitPrivilegeWindowError("Duplicate observation ID")
        seen_observations.add(observation_id)
        _synthetic(row["principal_id"], "observation principal ID")
        _synthetic(row["privilege_id"], "observation privilege ID")
        _tick(row["at_tick"], "observation tick")
        core.choice(row["reported_outcome"], {"allowed", "denied", "unknown"}, "outcome")
    return model, grants, revocations


def _project(observation: dict, model: dict, grants: dict, revocations: dict) -> dict:
    matches = [
        grant for grant in grants.values()
        if grant["principal_id"] == observation["principal_id"]
        and grant["privilege_id"] == observation["privilege_id"]
    ]
    tick = observation["at_tick"]
    eligible = [
        grant for grant in matches
        if grant["approval_recorded"] and grant["starts_at"] <= tick < grant["ends_at"]
        and not any(at <= tick for at in revocations.get(grant["grant_id"], ()))
    ]
    if not model["policy_complete"] or not model["order_complete"]:
        decision, basis = "unknown", "incomplete_policy_or_order"
    elif eligible and not model["revocations_complete"]:
        decision, basis = "unknown", "unlisted_revocation_possible"
    elif eligible:
        decision, basis = "allow", "declared_approved_active_grant"
    elif not model["grants_complete"]:
        decision, basis = "unknown", "unlisted_grant_possible"
    else:
        decision, basis = "deny", "no_declared_approved_active_grant"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif (decision == "allow") == (reported == "allowed"):
        assessment = "declared_consistent"
    else:
        assessment = "candidate_declared_window_conflict"
    return {
        "observation_id": observation["observation_id"],
        "principal_id": observation["principal_id"],
        "privilege_id": observation["privilege_id"],
        "at_tick": tick,
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
        "matching_grant_ids": sorted(grant["grant_id"] for grant in matches),
        "eligible_grant_ids": sorted(grant["grant_id"] for grant in eligible),
    }


def _derive(value: Any) -> dict:
    model, grants, revocations = _model(value)
    projections = [
        _project(item, model, grants, revocations) for item in model["observations"]
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
                row["assessment"] == "candidate_declared_window_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "grant_approval_authenticated": False,
        "revocation_authenticated": False,
        "reported_outcomes_authenticated": False,
        "effective_privilege_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Grant, approval, revocation, completeness and outcome records are declarations.",
            "Logical ticks do not prove ordering against a deployed service clock.",
            "Only declared JIT windows are compared; PAM and JEA enforcement is not tested.",
            "A candidate conflict is not effective privilege or a verified vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="JPW-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class JitPrivilegeWindowReport:
    """Unsigned report wrapper that requires separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise JitPrivilegeWindowError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> JitPrivilegeWindowReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_jit_privilege_windows(model: Any) -> JitPrivilegeWindowReport:
    try:
        return JitPrivilegeWindowReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise JitPrivilegeWindowError(str(exc)) from exc


def verify_supplied_jit_privilege_windows(
    report: Any, *, model: Any,
) -> JitPrivilegeWindowReport:
    if type(report) is not JitPrivilegeWindowReport:
        raise JitPrivilegeWindowError("Exact report wrapper required")
    expected = analyze_supplied_jit_privilege_windows(model)
    if report.to_json() != expected.to_json():
        raise JitPrivilegeWindowError("Report differs from separate original model")
    return expected


def verify_supplied_jit_privilege_windows_bytes(
    report_bytes: bytes, *, model: Any,
) -> JitPrivilegeWindowReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise JitPrivilegeWindowError(str(exc)) from exc
    expected = analyze_supplied_jit_privilege_windows(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise JitPrivilegeWindowError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:jit-window",
        "policy_complete": True,
        "grants_complete": True,
        "revocations_complete": True,
        "order_complete": True,
        "grants": [
            {
                "grant_id": "synthetic:grant-one",
                "principal_id": "synthetic:operator-one",
                "privilege_id": "synthetic:review-only",
                "starts_at": 10,
                "ends_at": 30,
                "approval_recorded": True,
            },
        ],
        "revocations": [
            {
                "revocation_id": "synthetic:revoke-one",
                "grant_id": "synthetic:grant-one",
                "at_tick": 20,
            },
        ],
        "observations": [
            {
                "observation_id": "synthetic:before-revoke",
                "principal_id": "synthetic:operator-one",
                "privilege_id": "synthetic:review-only",
                "at_tick": 15,
                "reported_outcome": "allowed",
            },
            {
                "observation_id": "synthetic:after-revoke",
                "principal_id": "synthetic:operator-one",
                "privilege_id": "synthetic:review-only",
                "at_tick": 25,
                "reported_outcome": "allowed",
            },
        ],
    }


__all__ = [
    "JitPrivilegeWindowError", "JitPrivilegeWindowReport",
    "analyze_supplied_jit_privilege_windows", "verify_supplied_jit_privilege_windows",
    "verify_supplied_jit_privilege_windows_bytes", "component_fixture",
]

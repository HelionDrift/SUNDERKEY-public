"""Project negative factor-rebind invariants from a supplied synthetic timeline."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_mfa_factor_rebind"
PROFILE_ID = "AOE-GA-D03-S02"
CAPABILITY_ID = "army.ga.d03.s02"
VECTOR_ID = "AV-GA-D03-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S02"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:61cc5028f573b8ba677f7e5608c3455c5562418c4d91ed375726629105e9e7f4"
DOMAIN = "sunderkey.offline-mfa-factor-rebind.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_FACTORS = 64
MAX_EVENTS = 512
MAX_TICK = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class MfaFactorRebindError(ValueError):
    """A supplied factor timeline or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise MfaFactorRebindError(f"{label} must be a synthetic label")
    return identifier


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "account_id", "policy_complete",
            "events_complete", "order_complete", "approval_required_for_rebind",
            "initial_factor_ids", "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MfaFactorRebindError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    _synthetic(model["account_id"], "account ID")
    for field in (
        "policy_complete", "events_complete", "order_complete",
        "approval_required_for_rebind",
    ):
        core.boolean(model[field], field)
    initial = [
        _synthetic(item, "factor ID")
        for item in core.bounded_list(model["initial_factor_ids"], MAX_FACTORS, "factors")
    ]
    if len(initial) != len(set(initial)):
        raise MfaFactorRebindError("Duplicate initial factor ID")
    events = core.bounded_list(model["events"], MAX_EVENTS, "events")
    if not events:
        raise MfaFactorRebindError("At least one event is required")
    seen: set[str] = set()
    last_tick = -1
    for event in events:
        row = core.exact(
            event,
            {"event_id", "factor_id", "at_tick", "event_type", "reported_outcome"},
            "event",
        )
        event_id = _synthetic(row["event_id"], "event ID")
        if event_id in seen:
            raise MfaFactorRebindError("Duplicate event ID")
        seen.add(event_id)
        _synthetic(row["factor_id"], "event factor ID")
        tick = row["at_tick"]
        if type(tick) is not int or not 0 <= tick <= MAX_TICK or tick <= last_tick:
            raise MfaFactorRebindError("Events require bounded strict logical order")
        last_tick = tick
        kind = core.choice(
            row["event_type"],
            {"recovery_approved", "factor_bound", "factor_revoked", "factor_used"},
            "event type",
        )
        expected = {"accepted", "rejected", "unknown"} if kind == "factor_used" else {"none"}
        core.choice(row["reported_outcome"], expected, "reported outcome")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    complete = all(
        model[field] for field in ("policy_complete", "events_complete", "order_complete")
    )
    enrolled = set(model["initial_factor_ids"])
    approval_for: str | None = None
    projections: list[dict] = []
    for event in model["events"]:
        factor = event["factor_id"]
        kind = event["event_type"]
        flags: list[str] = []
        if complete:
            if kind == "factor_bound":
                if factor in enrolled:
                    flags.append("candidate_duplicate_declared_binding")
                if model["approval_required_for_rebind"] and approval_for != factor:
                    flags.append("candidate_binding_without_declared_approval")
            elif kind == "factor_revoked" and factor not in enrolled:
                flags.append("candidate_revocation_of_unenrolled_factor")
            elif (
                kind == "factor_used"
                and event["reported_outcome"] == "accepted"
                and factor not in enrolled
            ):
                flags.append("candidate_acceptance_without_declared_enrollment")
        disposition = (
            "unknown" if not complete else "candidate" if flags else "no_declared_conflict"
        )
        projections.append({
            "event_id": event["event_id"],
            "factor_id": factor,
            "at_tick": event["at_tick"],
            "event_type": kind,
            "reported_outcome": event["reported_outcome"],
            "disposition": disposition,
            "candidate_flags": flags,
        })
        if kind == "recovery_approved":
            approval_for = factor
        elif kind == "factor_bound":
            enrolled.add(factor)
            approval_for = None
        elif kind == "factor_revoked":
            enrolled.discard(factor)
            if approval_for == factor:
                approval_for = None
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
            "event_count": len(projections),
            "candidate_count": sum(row["disposition"] == "candidate" for row in projections),
            "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "factor_possession_proven": False,
        "recovery_approval_authenticated": False,
        "factor_enrollment_observed": False,
        "authentication_attempt_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Factor labels, approval, enrollment, use and outcome are caller declarations.",
            "Approval events are not evidence of independent approval or authority.",
            "A declared lifecycle conflict is not observed authentication or a finding.",
            "No factor secrets, credentials, target responses or live services are processed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MFR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class MfaFactorRebindReport:
    """Unsigned factor-lifecycle projection with separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MfaFactorRebindError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MfaFactorRebindReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mfa_factor_rebind(model: Any) -> MfaFactorRebindReport:
    try:
        return MfaFactorRebindReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise MfaFactorRebindError(str(exc)) from exc


def verify_supplied_mfa_factor_rebind(
    report: Any, *, model: Any,
) -> MfaFactorRebindReport:
    if type(report) is not MfaFactorRebindReport:
        raise MfaFactorRebindError("Exact report wrapper required")
    expected = analyze_supplied_mfa_factor_rebind(model)
    if report.to_json() != expected.to_json():
        raise MfaFactorRebindError("Report differs from separate original model")
    return expected


def verify_supplied_mfa_factor_rebind_bytes(
    report_bytes: bytes, *, model: Any,
) -> MfaFactorRebindReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise MfaFactorRebindError(str(exc)) from exc
    expected = analyze_supplied_mfa_factor_rebind(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise MfaFactorRebindError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:factor-rebind",
        "account_id": "synthetic:account-one",
        "policy_complete": True,
        "events_complete": True,
        "order_complete": True,
        "approval_required_for_rebind": True,
        "initial_factor_ids": ["synthetic:factor-old"],
        "events": [
            {"event_id": "synthetic:use-old", "factor_id": "synthetic:factor-old",
             "at_tick": 1, "event_type": "factor_used", "reported_outcome": "accepted"},
            {"event_id": "synthetic:bind-new", "factor_id": "synthetic:factor-new",
             "at_tick": 2, "event_type": "factor_bound", "reported_outcome": "none"},
            {"event_id": "synthetic:revoke-old", "factor_id": "synthetic:factor-old",
             "at_tick": 3, "event_type": "factor_revoked", "reported_outcome": "none"},
            {"event_id": "synthetic:use-revoked", "factor_id": "synthetic:factor-old",
             "at_tick": 4, "event_type": "factor_used", "reported_outcome": "accepted"},
        ],
    }


__all__ = [
    "MfaFactorRebindError", "MfaFactorRebindReport",
    "analyze_supplied_mfa_factor_rebind", "verify_supplied_mfa_factor_rebind",
    "verify_supplied_mfa_factor_rebind_bytes", "component_fixture",
]

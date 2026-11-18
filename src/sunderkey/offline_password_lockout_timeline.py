"""Project negative lockout invariants from synthetic authentication outcomes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_password_lockout_timeline"
PROFILE_ID = "AOE-GA-D03-S01"
CAPABILITY_ID = "army.ga.d03.s01"
VECTOR_ID = "AV-GA-D03-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S01"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:0b9d09987bafcdefc99afd9f75a6b4903ad0693563b6b8ac1ca79e9337a36fa9"
DOMAIN = "sunderkey.offline-password-lockout-timeline.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_ACCOUNTS = 64
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


class PasswordLockoutTimelineError(ValueError):
    """A supplied lockout model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise PasswordLockoutTimelineError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise PasswordLockoutTimelineError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> tuple[dict, set[str]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "events_complete",
            "order_complete", "maximum_failures", "lockout_ticks", "accounts", "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PasswordLockoutTimelineError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in ("policy_complete", "events_complete", "order_complete"):
        core.boolean(model[field], field)
    maximum = _tick(model["maximum_failures"], "maximum failures")
    if not 1 <= maximum <= 10:
        raise PasswordLockoutTimelineError("Maximum failures is outside the closed policy range")
    lockout_ticks = _tick(model["lockout_ticks"], "lockout duration")
    if lockout_ticks == 0:
        raise PasswordLockoutTimelineError("Lockout duration must be positive")
    accounts = [
        _synthetic(item, "account ID")
        for item in core.bounded_list(model["accounts"], MAX_ACCOUNTS, "accounts")
    ]
    if len(accounts) != len(set(accounts)):
        raise PasswordLockoutTimelineError("Duplicate account ID")
    events = core.bounded_list(model["events"], MAX_EVENTS, "events")
    if not events:
        raise PasswordLockoutTimelineError("At least one event is required")
    seen: set[str] = set()
    last_tick = -1
    for item in events:
        row = core.exact(
            item, {"event_id", "account_id", "at_tick", "reported_outcome"}, "event"
        )
        event_id = _synthetic(row["event_id"], "event ID")
        if event_id in seen:
            raise PasswordLockoutTimelineError("Duplicate event ID")
        seen.add(event_id)
        if _synthetic(row["account_id"], "event account ID") not in accounts:
            raise PasswordLockoutTimelineError("Event account is absent")
        tick = _tick(row["at_tick"], "event tick")
        if tick <= last_tick:
            raise PasswordLockoutTimelineError("Events require strict supplied order")
        last_tick = tick
        core.choice(row["reported_outcome"], {"failed", "succeeded", "unknown"}, "outcome")
    return model, set(accounts)


def _derive(value: Any) -> dict:
    model, accounts = _model(value)
    state = {
        account_id: {"failures": 0, "locked_until": 0, "ambiguous": False}
        for account_id in accounts
    }
    projections: list[dict] = []
    complete = all(
        model[field] for field in ("policy_complete", "events_complete", "order_complete")
    )
    for event in model["events"]:
        account = state[event["account_id"]]
        tick = event["at_tick"]
        if tick >= account["locked_until"]:
            account["locked_until"] = 0
            if account["failures"] >= model["maximum_failures"]:
                account["failures"] = 0
        locked = tick < account["locked_until"]
        if not complete:
            decision, basis = "unknown", "incomplete_policy_events_or_order"
        elif account["ambiguous"]:
            decision, basis = "unknown", "prior_unknown_outcome"
        elif locked:
            decision, basis = "deny", "inside_declared_lockout"
        else:
            decision, basis = "unknown", "no_negative_lockout_invariant"
        reported = event["reported_outcome"]
        if decision == "unknown" or reported == "unknown":
            assessment = "unknown"
        elif reported == "succeeded":
            assessment = "candidate_declared_lockout_conflict"
        else:
            assessment = "declared_failure_consistent"
        projections.append({
            "event_id": event["event_id"],
            "account_id": event["account_id"],
            "at_tick": tick,
            "reported_outcome": reported,
            "projected_decision": decision,
            "basis": basis,
            "assessment": assessment,
        })
        if reported == "unknown":
            account["ambiguous"] = True
        if not complete or account["ambiguous"] or locked:
            continue
        if reported == "succeeded":
            account["failures"] = 0
        else:
            account["failures"] += 1
            if account["failures"] >= model["maximum_failures"]:
                account["locked_until"] = tick + model["lockout_ticks"]
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
            "candidate_count": sum(
                row["assessment"] == "candidate_declared_lockout_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "policy_authenticated": False,
        "reported_outcomes_authenticated": False,
        "credential_value_processed": False,
        "authentication_attempt_performed": False,
        "effective_lockout_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Policy, event ordering, completeness and outcomes are caller declarations.",
            "No passwords, credentials, hashes or target responses are processed.",
            "This models only a negative lockout invariant, not attack pacing or success.",
            "A candidate mismatch is not observed authentication or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PLT-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class PasswordLockoutTimelineReport:
    """Unsigned result wrapper requiring separately retained original input."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PasswordLockoutTimelineError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PasswordLockoutTimelineReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_password_lockout(model: Any) -> PasswordLockoutTimelineReport:
    try:
        return PasswordLockoutTimelineReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise PasswordLockoutTimelineError(str(exc)) from exc


def verify_supplied_password_lockout(
    report: Any, *, model: Any,
) -> PasswordLockoutTimelineReport:
    if type(report) is not PasswordLockoutTimelineReport:
        raise PasswordLockoutTimelineError("Exact report wrapper required")
    expected = analyze_supplied_password_lockout(model)
    if report.to_json() != expected.to_json():
        raise PasswordLockoutTimelineError("Report differs from separate original model")
    return expected


def verify_supplied_password_lockout_bytes(
    report_bytes: bytes, *, model: Any,
) -> PasswordLockoutTimelineReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise PasswordLockoutTimelineError(str(exc)) from exc
    expected = analyze_supplied_password_lockout(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise PasswordLockoutTimelineError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:lockout-timeline",
        "policy_complete": True,
        "events_complete": True,
        "order_complete": True,
        "maximum_failures": 2,
        "lockout_ticks": 10,
        "accounts": ["synthetic:account-one"],
        "events": [
            {"event_id": "synthetic:first", "account_id": "synthetic:account-one",
             "at_tick": 10, "reported_outcome": "failed"},
            {"event_id": "synthetic:second", "account_id": "synthetic:account-one",
             "at_tick": 11, "reported_outcome": "failed"},
            {"event_id": "synthetic:inside", "account_id": "synthetic:account-one",
             "at_tick": 12, "reported_outcome": "succeeded"},
        ],
    }


__all__ = [
    "PasswordLockoutTimelineError", "PasswordLockoutTimelineReport",
    "analyze_supplied_password_lockout", "verify_supplied_password_lockout",
    "verify_supplied_password_lockout_bytes", "component_fixture",
]

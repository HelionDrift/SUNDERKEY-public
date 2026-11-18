"""Project negative Kerberos realm-path invariants from synthetic ticket metadata."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "identity_supplied_kerberos_realm_path"
PROFILE_ID = "AOE-GA-D03-S06"
CAPABILITY_ID = "army.ga.d03.s06"
VECTOR_ID = "AV-GA-D03-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S06"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GA-D03-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:558262fd4bc84c519423fda718deae8916cb447ed2a158735fbdcf46b754d319"
DOMAIN = "sunderkey.offline-kerberos-realm-path.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_TICKETS = 256
MAX_REALMS = 128
MAX_TRANSITED = 16
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


class KerberosRealmPathError(ValueError):
    """A supplied realm-path model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise KerberosRealmPathError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise KerberosRealmPathError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> tuple[dict, dict[str, dict], set[str]]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "policy_complete", "tickets_complete",
            "realms_complete", "order_complete", "trusted_realms", "tickets",
            "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise KerberosRealmPathError("Unsupported model version")
    _synthetic(model["source_id"], "source ID")
    for field in (
        "policy_complete", "tickets_complete", "realms_complete", "order_complete",
    ):
        core.boolean(model[field], field)
    realms = [
        _synthetic(item, "trusted realm")
        for item in core.bounded_list(model["trusted_realms"], MAX_REALMS, "realms")
    ]
    if len(realms) != len(set(realms)):
        raise KerberosRealmPathError("Duplicate trusted realm")
    tickets: dict[str, dict] = {}
    for item in core.bounded_list(model["tickets"], MAX_TICKETS, "tickets"):
        row = core.exact(
            item,
            {
                "ticket_id", "client_realm", "service_realm", "service_id",
                "transited_realms", "starts_at", "ends_at",
            },
            "ticket metadata",
        )
        ticket_id = _synthetic(row["ticket_id"], "ticket ID")
        if ticket_id in tickets:
            raise KerberosRealmPathError("Duplicate ticket ID")
        _synthetic(row["client_realm"], "client realm")
        _synthetic(row["service_realm"], "service realm")
        _synthetic(row["service_id"], "service ID")
        transited = [
            _synthetic(realm, "transited realm")
            for realm in core.bounded_list(row["transited_realms"], MAX_TRANSITED, "transited")
        ]
        if len(transited) != len(set(transited)):
            raise KerberosRealmPathError("Duplicate transited realm")
        if _tick(row["starts_at"], "ticket start") >= _tick(row["ends_at"], "ticket end"):
            raise KerberosRealmPathError("Ticket window is empty")
        tickets[ticket_id] = row
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise KerberosRealmPathError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {
                "observation_id", "ticket_id", "expected_service_realm",
                "expected_service_id", "at_tick", "reported_outcome",
            },
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen:
            raise KerberosRealmPathError("Duplicate observation ID")
        seen.add(observation_id)
        _synthetic(row["ticket_id"], "observation ticket ID")
        _synthetic(row["expected_service_realm"], "expected service realm")
        _synthetic(row["expected_service_id"], "expected service ID")
        _tick(row["at_tick"], "observation tick")
        core.choice(row["reported_outcome"], {"accepted", "rejected", "unknown"}, "outcome")
    return model, tickets, set(realms)


def _project(observation: dict, model: dict, tickets: dict, realms: set) -> dict:
    ticket = tickets.get(observation["ticket_id"])
    tick = observation["at_tick"]
    if not model["policy_complete"] or not model["order_complete"]:
        decision, basis = "unknown", "incomplete_policy_or_order"
    elif ticket is None:
        if model["tickets_complete"]:
            decision, basis = "deny", "ticket_absent_from_complete_inventory"
        else:
            decision, basis = "unknown", "ticket_inventory_incomplete"
    elif ticket["service_realm"] != observation["expected_service_realm"]:
        decision, basis = "deny", "declared_service_realm_mismatch"
    elif ticket["service_id"] != observation["expected_service_id"]:
        decision, basis = "deny", "declared_service_id_mismatch"
    elif tick < ticket["starts_at"] or tick >= ticket["ends_at"]:
        decision, basis = "deny", "outside_declared_ticket_window"
    elif any(
        realm not in realms
        for realm in (ticket["client_realm"], *ticket["transited_realms"])
    ):
        if model["realms_complete"]:
            decision, basis = "deny", "untrusted_declared_realm_path"
        else:
            decision, basis = "unknown", "realm_policy_incomplete"
    else:
        decision, basis = "unknown", "no_ticket_or_service_validation"
    reported = observation["reported_outcome"]
    if decision == "unknown" or reported == "unknown":
        assessment = "unknown"
    elif reported == "accepted":
        assessment = "candidate_declared_realm_path_conflict"
    else:
        assessment = "declared_rejection_consistent"
    return {
        "observation_id": observation["observation_id"],
        "ticket_id": observation["ticket_id"],
        "at_tick": tick,
        "reported_outcome": reported,
        "projected_decision": decision,
        "basis": basis,
        "assessment": assessment,
    }


def _derive(value: Any) -> dict:
    model, tickets, realms = _model(value)
    projections = [
        _project(item, model, tickets, realms) for item in model["observations"]
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
                row["assessment"] == "candidate_declared_realm_path_conflict"
                for row in projections
            ),
            "unknown_count": sum(row["assessment"] == "unknown" for row in projections),
        },
        "source_authenticated": False,
        "realm_policy_authenticated": False,
        "ticket_metadata_authenticated": False,
        "reported_outcomes_authenticated": False,
        "ticket_crypto_validated": False,
        "service_authorization_validated": False,
        "effective_authentication_observed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Ticket metadata, realm policy, ordering and outcomes are declarations.",
            "A transited-realm list may be fabricated and is not authenticated here.",
            "Trusted realms do not prove ticket validity or application authorization.",
            "A candidate mismatch is not observed authentication or a vulnerability.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="KRP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class KerberosRealmPathReport:
    """Unsigned result wrapper requiring separately retained original input."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise KerberosRealmPathError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> KerberosRealmPathReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_kerberos_realm_path(model: Any) -> KerberosRealmPathReport:
    try:
        return KerberosRealmPathReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise KerberosRealmPathError(str(exc)) from exc


def verify_supplied_kerberos_realm_path(
    report: Any, *, model: Any,
) -> KerberosRealmPathReport:
    if type(report) is not KerberosRealmPathReport:
        raise KerberosRealmPathError("Exact report wrapper required")
    expected = analyze_supplied_kerberos_realm_path(model)
    if report.to_json() != expected.to_json():
        raise KerberosRealmPathError("Report differs from separate original model")
    return expected


def verify_supplied_kerberos_realm_path_bytes(
    report_bytes: bytes, *, model: Any,
) -> KerberosRealmPathReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise KerberosRealmPathError(str(exc)) from exc
    expected = analyze_supplied_kerberos_realm_path(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise KerberosRealmPathError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:kerberos-realm-path",
        "policy_complete": True,
        "tickets_complete": True,
        "realms_complete": True,
        "order_complete": True,
        "trusted_realms": ["synthetic:home-realm"],
        "tickets": [
            {
                "ticket_id": "synthetic:ticket-one",
                "client_realm": "synthetic:home-realm",
                "service_realm": "synthetic:service-realm",
                "service_id": "synthetic:service-one",
                "transited_realms": ["synthetic:transit-realm"],
                "starts_at": 10,
                "ends_at": 40,
            },
        ],
        "observations": [
            {
                "observation_id": "synthetic:ticket-observed",
                "ticket_id": "synthetic:ticket-one",
                "expected_service_realm": "synthetic:service-realm",
                "expected_service_id": "synthetic:service-one",
                "at_tick": 20,
                "reported_outcome": "accepted",
            },
        ],
    }


__all__ = [
    "KerberosRealmPathError", "KerberosRealmPathReport",
    "analyze_supplied_kerberos_realm_path", "verify_supplied_kerberos_realm_path",
    "verify_supplied_kerberos_realm_path_bytes", "component_fixture",
]

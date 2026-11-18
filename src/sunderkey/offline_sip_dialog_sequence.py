"""Project a narrow synthetic SIP single-dialog event sequence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "network_supplied_sip_dialog_sequence_projection"
PROFILE_ID = "AOE-GC-D13-S13"
CAPABILITY_ID = "army.gc.d13.s13"
VECTOR_ID = "AV-GC-D13-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D13-S13"
WAVE_ID = "IW2-016"
COMMANDER_ID = "AOE-GC-D13-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4f6130b715bd8bb5fd2fced1138dae4f468309496c6f4248335226c7e3604455"
DOMAIN = "sunderkey.offline-sip-dialog-sequence.v1"
KINDS = {"INVITE", "1XX_INVITE", "2XX_INVITE", "ACK", "BYE", "2XX_BYE"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class SipDialogSequenceError(ValueError):
    """The supplied sequence or original-model replay is invalid."""


def _cseq(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2_147_483_647:
        raise SipDialogSequenceError("CSeq must be a bounded nonnegative integer")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "single_nonforked_dialog_asserted", "call_id", "events",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise SipDialogSequenceError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise SipDialogSequenceError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    if not core.boolean(
        model["single_nonforked_dialog_asserted"], "single-dialog assertion"
    ):
        raise SipDialogSequenceError("Only the declared single nonforked dialog is modeled")
    core.identifier(model["call_id"], "call ID")
    events = core.bounded_list(model["events"], 64, "events")
    if not events:
        raise SipDialogSequenceError("At least one event is required")
    normalized = []
    seen = set()
    for item in events:
        row = core.exact(item, {"event_id", "kind", "cseq"}, "event")
        event_id = core.identifier(row["event_id"], "event ID")
        if event_id in seen:
            raise SipDialogSequenceError("Duplicate event ID")
        seen.add(event_id)
        normalized.append((
            event_id, core.choice(row["kind"], KINDS, "event kind"), _cseq(row["cseq"])
        ))
    state = "start"
    invite_cseq = bye_cseq = None
    rows = []
    for event_id, kind, cseq in normalized:
        flags = []
        if state == "start" and kind == "INVITE":
            invite_cseq = cseq
            state = "invited"
        elif state == "invited" and kind == "1XX_INVITE":
            if cseq != invite_cseq:
                flags.append("invite_response_cseq_mismatch")
        elif state == "invited" and kind == "2XX_INVITE":
            if cseq != invite_cseq:
                flags.append("invite_response_cseq_mismatch")
            else:
                state = "accepted"
        elif state == "accepted" and kind == "ACK":
            if cseq != invite_cseq:
                flags.append("ack_cseq_mismatch")
            else:
                state = "confirmed"
        elif state == "confirmed" and kind == "BYE":
            if invite_cseq is None or cseq <= invite_cseq:
                flags.append("bye_cseq_not_later_than_invite")
            else:
                bye_cseq = cseq
                state = "terminating"
        elif state == "terminating" and kind == "2XX_BYE":
            if cseq != bye_cseq:
                flags.append("bye_response_cseq_mismatch")
            else:
                state = "terminated"
        else:
            flags.append("event_outside_declared_sequence")
        rows.append({
            "event_id": event_id,
            "kind": kind,
            "state_after_event": state,
            "declared_sequence_flags": flags,
        })
    deviations = sorted(row["event_id"] for row in rows if row["declared_sequence_flags"])
    unknown = [] if complete else ["supplied_sip_trace_incomplete"]
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "single_nonforked_dialog_asserted": True,
        "supplied_event_count": len(normalized),
        "event_projections": rows,
        "declared_sequence_deviation_event_ids": deviations,
        "final_declared_state": state,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_sip_sequence_projection",
        "source_authenticated": False,
        "sip_messages_parsed": False,
        "sip_conformance_verified": False,
        "media_analyzed": False,
        "network_call_performed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Events, ordering, CSeq, dialog shape, and completeness are supplied assertions.",
            "This narrow single-dialog model is not a SIP parser or full RFC 3261 validator.",
            "A model deviation does not prove a protocol flaw or security vulnerability.",
            "No SIP endpoint, media stream, credential, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="SDS-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class SipDialogSequenceReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise SipDialogSequenceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> SipDialogSequenceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_sip_dialog(model: Any) -> SipDialogSequenceReport:
    return SipDialogSequenceReport._owned(_derive(model))


def verify_supplied_sip_dialog(
    report: Any, *, model: Any
) -> SipDialogSequenceReport:
    if type(report) is not SipDialogSequenceReport:
        raise SipDialogSequenceError("Exact SIP wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise SipDialogSequenceError("Report differs from separate original model")
    return SipDialogSequenceReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-sip-dialog",
        "synthetic_fixture": True, "inventory_complete": True,
        "single_nonforked_dialog_asserted": True,
        "call_id": "call-a",
        "events": [
            {"event_id": "e1", "kind": "INVITE", "cseq": 1},
            {"event_id": "e2", "kind": "1XX_INVITE", "cseq": 1},
            {"event_id": "e3", "kind": "2XX_INVITE", "cseq": 1},
            {"event_id": "e4", "kind": "ACK", "cseq": 1},
            {"event_id": "e5", "kind": "BYE", "cseq": 2},
            {"event_id": "e6", "kind": "2XX_BYE", "cseq": 2},
        ],
    }

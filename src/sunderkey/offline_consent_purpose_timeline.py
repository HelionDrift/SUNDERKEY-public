"""Replay caller-supplied purpose-consent events without legal conclusions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_consent_purpose_timeline"
PROFILE_ID = "AOE-GB-D09-S11"
CAPABILITY_ID = "army.gb.d09.s11"
VECTOR_ID = "AV-GB-D09-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4e743d75eb5e4a62b81f9bd053798f73da9155c24643c3538c21237e854cef66"
SEMANTICS_PROFILE = "supplied-consent-purpose-timeline-v1"
DOMAIN = "sunderkey.offline-consent-purpose-timeline.v1"
MAX_PURPOSES = 128
MAX_EVENTS = 512
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SUBJECT = re.compile(r"subject:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "consent_write",
        "credential",
        "execution",
        "filesystem",
        "network",
        "privacy_claim",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class ConsentPurposeTimelineError(ValueError):
    """The supplied purpose timeline or replay document was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ConsentPurposeTimelineError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise ConsentPurposeTimelineError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ConsentPurposeTimelineError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise ConsentPurposeTimelineError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ConsentPurposeTimelineError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ConsentPurposeTimelineError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ConsentPurposeTimelineError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise ConsentPurposeTimelineError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ConsentPurposeTimelineError(f"{label} identifier is invalid")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {"schema_version", "semantics_profile", "subject_ref", "purposes", "events"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ConsentPurposeTimelineError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise ConsentPurposeTimelineError("Semantics profile is invalid")
    if type(model["subject_ref"]) is not str or _SUBJECT.fullmatch(model["subject_ref"]) is None:
        raise ConsentPurposeTimelineError("Opaque subject reference is required")
    purposes = model["purposes"]
    if type(purposes) is not list or not 1 <= len(purposes) <= MAX_PURPOSES:
        raise ConsentPurposeTimelineError("Purpose count is invalid")
    purpose_ids = [_identifier(value, "purpose") for value in purposes]
    if len(set(purpose_ids)) != len(purpose_ids):
        raise ConsentPurposeTimelineError("Duplicate purpose identifier")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise ConsentPurposeTimelineError("Event count is invalid")
    event_ids: set[str] = set()
    for event in events:
        _fields(
            event,
            {"event_id", "purpose_id", "action", "declared_active_after", "source_id"},
            "event",
        )
        event_id = _identifier(event["event_id"], "event")
        if event_id in event_ids:
            raise ConsentPurposeTimelineError("Duplicate event identifier")
        event_ids.add(event_id)
        if _identifier(event["purpose_id"], "event purpose") not in purpose_ids:
            raise ConsentPurposeTimelineError("Event purpose is undeclared")
        _identifier(event["source_id"], "event source")
        if event["action"] not in ("grant", "withdraw", "process"):
            raise ConsentPurposeTimelineError("Event action is invalid")
        if type(event["declared_active_after"]) is not bool:
            raise ConsentPurposeTimelineError("Declared active state is invalid")
    return model


def _derive(model: Any) -> dict:
    plan = _plan(model)
    active: set[str] = set()
    rows = []
    for position, event in enumerate(plan["events"]):
        flags = []
        purpose = event["purpose_id"]
        if event["action"] == "grant":
            if purpose in active:
                flags.append("repeated_declared_grant")
            active.add(purpose)
        elif event["action"] == "withdraw":
            if purpose not in active:
                flags.append("withdrawal_without_local_grant")
            active.discard(purpose)
        elif purpose not in active:
            flags.append("processing_without_local_grant")
        expected = purpose in active
        if event["declared_active_after"] is not expected:
            flags.append("declared_active_state_mismatch")
        rows.append(
            {
                "position": position,
                "event_id": event["event_id"],
                "purpose_id": purpose,
                "source_id": event["source_id"],
                "expected_active_after": expected,
                "anomaly_flags": sorted(flags),
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "events": rows,
        "final_active_purposes": sorted(active),
        "flags": {
            "subject_identity_proven": False,
            "event_source_authenticated": False,
            "event_order_proven": False,
            "consent_validity_proven": False,
            "lawful_basis_assessed": False,
            "processing_observed": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Purposes, subject label, event source, order and outcomes are caller-supplied.",
            "Local grant state does not establish valid consent or a legal basis for processing.",
            "A processing signal without local grant is not proof of a privacy violation.",
            "No subject, consent store, service, credential, or target is contacted or changed.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "CPT-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class ConsentPurposeTimeline:
    """Replay-checked local projection of supplied purpose events."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ConsentPurposeTimelineError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise ConsentPurposeTimelineError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_consent_purposes(model: Any) -> ConsentPurposeTimeline:
    """Derive only a supplied purpose-specific grant timeline."""
    return ConsentPurposeTimeline(_derive(model))


def verify_supplied_consent_purposes(report: Any, *, model: Any) -> ConsentPurposeTimeline:
    """Recompute the report from current supplied model bytes."""
    if type(report) is not ConsentPurposeTimeline:
        raise ConsentPurposeTimelineError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise ConsentPurposeTimelineError("Report differs from supplied model replay")
    return ConsentPurposeTimeline(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "ConsentPurposeTimeline",
    "ConsentPurposeTimelineError",
    "analyze_supplied_consent_purposes",
    "verify_supplied_consent_purposes",
]

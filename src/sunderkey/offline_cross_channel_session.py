"""Project declared cross-channel session revocation without replaying a token."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_cross_channel_session"
PROFILE_ID = "AOE-GE-D23-S08"
CAPABILITY_ID = "army.ge.d23.s08"
VECTOR_ID = "AV-GE-D23-S08-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S08"
WAVE_ID = "IW2-022"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3fc3cada3755371bacdabced078c46d974a9e1928cfd2b7e355d0c7f477ab80c"
SEMANTICS_PROFILE = "supplied-cross-channel-session-revocation-v1"
DOMAIN = "sunderkey.offline-cross-channel-session.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_EVENTS = 128
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_KINDS = frozenset({"issue", "revoke", "observe"})
_OUTCOMES = frozenset({"accepted", "rejected", "unknown"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class CrossChannelSessionError(ValueError):
    """A supplied session model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise CrossChannelSessionError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise CrossChannelSessionError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise CrossChannelSessionError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise CrossChannelSessionError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise CrossChannelSessionError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise CrossChannelSessionError("Native JSON text keys are required")
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
        raise CrossChannelSessionError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise CrossChannelSessionError(f"{label} fields are invalid")


def _reference(value: Any, label: str) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise CrossChannelSessionError(f"{label} must be an opaque reference")
    return value


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(
        model,
        {
            "schema_version", "semantics_profile", "source_id", "events_complete",
            "policy", "events",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CrossChannelSessionError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise CrossChannelSessionError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise CrossChannelSessionError("Source identifier is invalid")
    if type(model["events_complete"]) is not bool:
        raise CrossChannelSessionError("Event-completeness declaration must be boolean")
    policy = model["policy"]
    _fields(policy, {"declaration_complete", "cross_channel_revocation"}, "policy")
    if any(type(policy[field]) is not bool for field in policy):
        raise CrossChannelSessionError("Policy declarations must be boolean")
    events = model["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise CrossChannelSessionError("Event count is invalid")
    identifiers: set[str] = set()
    for event in events:
        _fields(
            event,
            {
                "event_id", "kind", "session_ref", "channel_ref", "declared_outcome",
                "capture_complete", "revocation_effective_before_observation",
            },
            "event",
        )
        identifier = event["event_id"]
        if type(identifier) is not str or _ID.fullmatch(identifier) is None:
            raise CrossChannelSessionError("Event identifier is invalid")
        if identifier in identifiers:
            raise CrossChannelSessionError("Event identifier is repeated")
        identifiers.add(identifier)
        kind = event["kind"]
        if type(kind) is not str or kind not in _KINDS:
            raise CrossChannelSessionError("Event kind is invalid")
        _reference(event["session_ref"], "Session reference")
        _reference(event["channel_ref"], "Channel reference")
        if type(event["capture_complete"]) is not bool:
            raise CrossChannelSessionError("Capture-complete declaration must be boolean")
        effective = event["revocation_effective_before_observation"]
        if effective is not None and type(effective) is not bool:
            raise CrossChannelSessionError("Revocation-effectiveness declaration is invalid")
        if kind == "observe":
            if (
                type(event["declared_outcome"]) is not str
                or event["declared_outcome"] not in _OUTCOMES
            ):
                raise CrossChannelSessionError("Observation outcome is invalid")
        elif (
            event["declared_outcome"] is not None
            or event["capture_complete"]
            or effective is not None
        ):
            raise CrossChannelSessionError("Non-observation event fields are invalid")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    issued: set[str] = set()
    revoked_by: dict[str, str] = {}
    projections = []
    for index, event in enumerate(model["events"]):
        session = event["session_ref"]
        kind = event["kind"]
        if kind == "issue":
            if session in issued:
                raise CrossChannelSessionError("Session reference was issued twice")
            issued.add(session)
        elif kind == "revoke":
            if session not in issued or session in revoked_by:
                raise CrossChannelSessionError("Revocation lacks one preceding issue")
            revoked_by[session] = event["channel_ref"]
        else:
            revoker = revoked_by.get(session)
            negative = (
                policy["cross_channel_revocation"]
                and revoker is not None
                and revoker != event["channel_ref"]
                and event["revocation_effective_before_observation"] is True
            )
            if (
                not model["events_complete"]
                or not policy["declaration_complete"]
                or not event["capture_complete"]
            ):
                disposition = "unresolved_declaration_or_capture"
            elif session not in issued or event["declared_outcome"] == "unknown":
                disposition = "unresolved_session_or_outcome"
            elif (
                policy["cross_channel_revocation"]
                and revoker is not None
                and revoker != event["channel_ref"]
                and event["revocation_effective_before_observation"] is not True
            ):
                disposition = "unresolved_revocation_effect"
            elif not negative:
                disposition = "no_declared_cross_channel_negative_invariant"
            elif event["declared_outcome"] == "accepted":
                disposition = "candidate_declared_cross_channel_conflict"
            else:
                disposition = "declared_reject_consistent"
            projections.append(
                {
                    "event_id": event["event_id"],
                    "event_index": index,
                    "negative_predicate": (
                        "cross_channel_revocation_effective" if negative else None
                    ),
                    "disposition": disposition,
                }
            )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "observation_count": len(projections),
        "projections": projections,
        "flags": {
            "session_runtime_verified": False,
            "revocation_effect_verified": False,
            "token_replay_performed": False,
            "cross_channel_bypass_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Session and channel references are opaque labels, not credentials.",
            "All event order, policy, effectiveness and outcomes are caller assertions.",
            "Only a declared cross-channel negative invariant is compared.",
            "A declared conflict does not prove session replay or target behavior.",
            "No file, credential, network, process, or target is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "CCS-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class CrossChannelSession:
    """Immutable report replayed from a supplied cross-channel timeline."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise CrossChannelSessionError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise CrossChannelSessionError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_cross_channel_session(model: Any) -> CrossChannelSession:
    """Project supplied cross-channel predicates without credential use."""
    return CrossChannelSession(_derive(model))


def verify_supplied_cross_channel_session(
    report: Any, *, model: Any
) -> CrossChannelSession:
    if type(report) is not CrossChannelSession:
        raise CrossChannelSessionError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise CrossChannelSessionError("Report differs from supplied source replay")
    return CrossChannelSession(expected)

"""Offline projection of supplied session invalidation and device-binding timelines."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sunderkey import offline_framework_declaration_core as core

PROFILE_ID = "AOE-GA-D03-S16"
CAPABILITY_ID = "army.ga.d03.s16"
VECTOR_ID = "AV-GA-D03-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D03-S16"
WAVE_ID = "IW2-017"
BLUEPRINT_SHA256 = "sha256:db3b973e3c45b61c3c64e486842b3d8ce25d19e31c786db9c8c9b6385c92b4dd"
COMPONENT_ID = "identity_supplied_session_binding_timeline"
DOMAIN = "sunderkey.offline-session-binding-timeline.v1"
SCHEMA_VERSION = "v1"
MAX_SOURCE_BYTES = core.MAX_SOURCE_BYTES
MAX_REPORT_BYTES = core.MAX_REPORT_BYTES
MAX_DEPTH = core.MAX_DEPTH
MAX_EVENTS = 1024
_KINDS = {"issue", "rotate", "revoke", "observe"}
_SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_OUTCOMES = {"allowed", "denied", "unknown"}
_ASSESSMENTS = {
    "candidate_declared_negative_policy_conflict",
    "declared_deny_consistent",
    "unknown",
}
_BASES = {
    "incomplete_premises",
    "unknown_session",
    "observation_unknown",
    "revoked_session",
    "revocation_effect_unknown",
    "rotated_session",
    "device_mismatch",
    "no_negative_invariant",
}
_EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "target",
        "execution",
        "routing",
        "qualification",
        "deployment",
        "network",
        "process",
        "credentials",
        "provider_requests",
    )
}
_FLAGS = {
    "offline_only": True,
    "source_authenticated": False,
    "credential_use_performed": False,
    "session_runtime_observed": False,
    "device_binding_verified": False,
    "token_replay_performed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}
_LIMITATIONS = [
    "Timeline events, device labels, policy and outcomes are supplied assertions.",
    "Session and device IDs must be synthetic labels, not tokens, cookies or secrets.",
    "Concurrent, partial or ambiguous event ordering yields unknown.",
    "A revoke event alone does not prove that revocation was effective at observation time.",
    "Only declared negative invariants are compared; allowed use is never inferred.",
    "A candidate conflict is not observed token replay or device-binding failure.",
    "No target, network, process, credential, provider request or live exploit occurs.",
]

SessionBindingTimelineError = core.FrameworkDeclarationError


def _nullable_id(value: Any, label: str) -> str | None:
    return None if value is None else _synthetic_id(value, label)


def _synthetic_id(value: Any, label: str) -> str:
    identity = core.identifier(value, label)
    if _SYNTHETIC_ID.fullmatch(identity) is None:
        raise SessionBindingTimelineError(f"{label} must be a synthetic opaque label")
    return identity


def _model(document: Any) -> tuple[bool, dict[str, bool], list[dict]]:
    item = core.exact(
        document,
        {
            "schema_version",
            "events_complete",
            "policy_complete",
            "concurrency_resolved",
            "device_bindings_complete",
            "policy",
            "events",
        },
        "model",
    )
    if type(item["schema_version"]) is not str or item["schema_version"] != SCHEMA_VERSION:
        raise SessionBindingTimelineError("unsupported model version")
    premises = [
        core.boolean(item[key], key)
        for key in (
            "events_complete",
            "policy_complete",
            "concurrency_resolved",
            "device_bindings_complete",
        )
    ]
    complete = all(premises)
    policy = core.exact(
        item["policy"],
        {"invalidate_on_rotation", "invalidate_on_revoke", "device_binding_required"},
        "policy",
    )
    checked_policy = {
        key: core.boolean(policy[key], key)
        for key in ("invalidate_on_rotation", "invalidate_on_revoke", "device_binding_required")
    }
    events = []
    seen: set[str] = set()
    for raw in core.bounded_list(item["events"], MAX_EVENTS, "events"):
        event = core.exact(
            raw,
            {
                "event_id",
                "kind",
                "session_id",
                "replacement_session_id",
                "device_id",
                "supplied_outcome",
                "observation_complete",
                "revocation_effective_before_observation",
            },
            "event",
        )
        identity = core.identifier(event["event_id"], "event ID")
        if identity in seen:
            raise SessionBindingTimelineError("duplicate event ID")
        seen.add(identity)
        kind = core.choice(event["kind"], _KINDS, "event kind")
        session_id = _synthetic_id(event["session_id"], "session ID")
        replacement = _nullable_id(event["replacement_session_id"], "replacement session ID")
        device_id = _nullable_id(event["device_id"], "device ID")
        outcome = event["supplied_outcome"]
        observed = core.boolean(event["observation_complete"], "observation complete")
        revocation_effective = event["revocation_effective_before_observation"]
        if revocation_effective is not None and type(revocation_effective) is not bool:
            raise SessionBindingTimelineError(
                "revocation effectiveness must be native Boolean or null"
            )
        if kind == "issue":
            if (
                replacement is not None
                or device_id is None
                or outcome is not None
                or observed
                or revocation_effective is not None
            ):
                raise SessionBindingTimelineError("issue event fields are invalid")
        elif kind == "rotate":
            if (
                replacement is None
                or replacement == session_id
                or device_id is None
                or outcome is not None
                or observed
                or revocation_effective is not None
            ):
                raise SessionBindingTimelineError("rotate event fields are invalid")
        elif kind == "revoke":
            if (
                replacement is not None
                or device_id is not None
                or outcome is not None
                or observed
                or revocation_effective is not None
            ):
                raise SessionBindingTimelineError("revoke event fields are invalid")
        elif (
            replacement is not None
            or device_id is None
            or type(outcome) is not str
            or outcome not in _OUTCOMES
        ):
            raise SessionBindingTimelineError("observe event fields are invalid")
        events.append(
            {
                "event_id": identity,
                "kind": kind,
                "session_id": session_id,
                "replacement_session_id": replacement,
                "device_id": device_id,
                "supplied_outcome": outcome,
                "observation_complete": observed,
                "revocation_effective_before_observation": revocation_effective,
            }
        )
    return complete, checked_policy, events


def _project(complete: bool, policy: dict[str, bool], events: list[dict]) -> list[dict]:
    if not complete:
        return [
            {
                "event_id": event["event_id"],
                "event_index": index,
                "session_id": event["session_id"],
                "presented_device_id": event["device_id"],
                "supplied_outcome": event["supplied_outcome"],
                "expected_negative_decision": None,
                "basis": "incomplete_premises",
                "assessment": "unknown",
            }
            for index, event in enumerate(events)
            if event["kind"] == "observe"
        ]
    sessions: dict[str, dict] = {}
    projections = []
    for index, event in enumerate(events):
        kind = event["kind"]
        session_id = event["session_id"]
        if kind == "issue":
            if session_id in sessions:
                raise SessionBindingTimelineError("session ID issued more than once")
            sessions[session_id] = {"device_id": event["device_id"], "state": "active"}
        elif kind == "rotate":
            replacement = event["replacement_session_id"]
            if (
                session_id not in sessions
                or replacement in sessions
                or sessions[session_id]["state"] != "active"
            ):
                raise SessionBindingTimelineError("rotation has unsupported lineage")
            sessions[session_id]["state"] = "rotated"
            sessions[replacement] = {"device_id": event["device_id"], "state": "active"}
        elif kind == "revoke":
            if session_id not in sessions or sessions[session_id]["state"] == "revoked":
                raise SessionBindingTimelineError("revocation has unsupported lineage")
            sessions[session_id]["state"] = "revoked"
        else:
            session = sessions.get(session_id)
            if (
                session is not None
                and session["state"] != "revoked"
                and event["revocation_effective_before_observation"] is not None
            ):
                raise SessionBindingTimelineError(
                    "revocation effectiveness premise has no prior revoke"
                )
            if not event["observation_complete"] or event["supplied_outcome"] == "unknown":
                basis = "observation_unknown"
            elif session is None:
                basis = "unknown_session"
            elif session["state"] == "revoked":
                basis = (
                    "revoked_session"
                    if policy["invalidate_on_revoke"]
                    and event["revocation_effective_before_observation"] is True
                    else "revocation_effect_unknown"
                )
            elif session["state"] == "rotated" and policy["invalidate_on_rotation"]:
                basis = "rotated_session"
            elif policy["device_binding_required"] and event["device_id"] != session["device_id"]:
                basis = "device_mismatch"
            else:
                basis = "no_negative_invariant"
            if basis in ("revoked_session", "rotated_session", "device_mismatch"):
                assessment = (
                    "candidate_declared_negative_policy_conflict"
                    if event["supplied_outcome"] == "allowed"
                    else "declared_deny_consistent"
                )
            else:
                assessment = "unknown"
            projections.append(
                {
                    "event_id": event["event_id"],
                    "event_index": index,
                    "session_id": session_id,
                    "presented_device_id": event["device_id"],
                    "supplied_outcome": event["supplied_outcome"],
                    "expected_negative_decision": (
                        True
                        if basis in ("revoked_session", "rotated_session", "device_mismatch")
                        else None
                    ),
                    "basis": basis,
                    "assessment": assessment,
                }
            )
    return projections


def _validate_report(document: Any) -> None:
    item = core.exact(
        document,
        {
            "schema_version",
            "profile_id",
            "capability_id",
            "vector_id",
            "work_package_id",
            "wave_id",
            "blueprint_sha256",
            "component_id",
            "domain",
            "source",
            "premises_complete",
            "projections",
            "summary",
            "effects",
            "limitations",
            "report_id",
            "report_sha256",
            *_FLAGS,
        },
        "report",
    )
    for key, expected in {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "component_id": COMPONENT_ID,
        "domain": DOMAIN,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
        **_FLAGS,
    }.items():
        if type(item[key]) is not type(expected) or item[key] != expected:
            raise SessionBindingTimelineError(f"report {key} is invalid")
    core.validate_source(item["source"])
    core.boolean(item["premises_complete"], "premises complete")
    projections = core.bounded_list(item["projections"], MAX_EVENTS, "projections")
    counts = {assessment: 0 for assessment in sorted(_ASSESSMENTS)}
    event_ids: set[str] = set()
    indices: list[int] = []
    for raw in projections:
        p = core.exact(
            raw,
            {
                "event_id",
                "event_index",
                "session_id",
                "presented_device_id",
                "supplied_outcome",
                "expected_negative_decision",
                "basis",
                "assessment",
            },
            "projection",
        )
        event_id = core.identifier(p["event_id"], "event ID")
        if event_id in event_ids:
            raise SessionBindingTimelineError("duplicate observation event ID")
        event_ids.add(event_id)
        if type(p["event_index"]) is not int or not 0 <= p["event_index"] < MAX_EVENTS:
            raise SessionBindingTimelineError("report event index is invalid")
        indices.append(p["event_index"])
        _synthetic_id(p["session_id"], "session ID")
        _synthetic_id(p["presented_device_id"], "device ID")
        core.choice(p["supplied_outcome"], _OUTCOMES, "supplied outcome")
        if (
            p["expected_negative_decision"] is not None
            and p["expected_negative_decision"] is not True
        ):
            raise SessionBindingTimelineError("report negative decision is invalid")
        core.choice(p["basis"], _BASES, "basis")
        assessment = core.choice(p["assessment"], _ASSESSMENTS, "assessment")
        if not item["premises_complete"] and (
            assessment != "unknown" or p["expected_negative_decision"] is not None
        ):
            raise SessionBindingTimelineError("incomplete report cannot claim a policy decision")
        counts[assessment] += 1
    if indices != sorted(set(indices)):
        raise SessionBindingTimelineError("report event indices must be sorted unique")
    summary = core.exact(item["summary"], {"observation_count", "assessments"}, "summary")
    reported = core.exact(summary["assessments"], set(counts), "summary assessments")
    if (
        type(summary["observation_count"]) is not int
        or summary["observation_count"] != len(projections)
        or any(
            type(reported[key]) is not int or reported[key] != value
            for key, value in counts.items()
        )
    ):
        raise SessionBindingTimelineError("report summary is invalid")
    report_id, sha256 = core.report_address(item, domain=DOMAIN, prefix="SBT-")
    if item["report_id"] != report_id or item["report_sha256"] != sha256:
        raise SessionBindingTimelineError("report address is invalid")


def _checked_report_json(content: Any) -> str:
    if type(content) is not str:
        raise SessionBindingTimelineError("report must be native JSON text")
    try:
        raw = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SessionBindingTimelineError("report must be UTF-8 JSON text") from exc
    document = core.decode(raw, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return core.canonical(document)


@dataclass(frozen=True, slots=True)
class SessionBindingTimelineReport:
    """Canonical report; exact original-source replay proves derivation."""

    _json: str

    def __post_init__(self) -> None:
        if type(self) is not SessionBindingTimelineReport or self._json != _checked_report_json(
            self._json
        ):
            raise SessionBindingTimelineError("canonical exact report is required")

    def to_json(self) -> str:
        if type(self) is not SessionBindingTimelineReport or self._json != _checked_report_json(
            self._json
        ):
            raise SessionBindingTimelineError("canonical exact report is required")
        return self._json

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    @classmethod
    def from_json(cls, content: str) -> SessionBindingTimelineReport:
        if cls is not SessionBindingTimelineReport:
            raise SessionBindingTimelineError("report must be the exact report family")
        return cls(_checked_report_json(content))


def analyze_session_binding_timeline(
    *, source_content: bytes, source_id: str
) -> SessionBindingTimelineReport:
    identity = core.identifier(source_id, "source ID")
    source = core.decode(source_content, maximum=MAX_SOURCE_BYTES)
    complete, policy, events = _model(source)
    projections = _project(complete, policy, events)
    counts = {
        assessment: sum(p["assessment"] == assessment for p in projections)
        for assessment in sorted(_ASSESSMENTS)
    }
    document = {
        "schema_version": SCHEMA_VERSION,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "component_id": COMPONENT_ID,
        "domain": DOMAIN,
        "source": {
            "source_id": identity,
            "sha256": core.digest(source_content),
            "byte_count": len(source_content),
        },
        "premises_complete": complete,
        "projections": projections,
        "summary": {"observation_count": len(projections), "assessments": counts},
        **_FLAGS,
        "effects": _EFFECTS,
        "limitations": _LIMITATIONS,
    }
    document["report_id"], document["report_sha256"] = core.report_address(
        document, domain=DOMAIN, prefix="SBT-"
    )
    core.validate_tree(document, maximum=MAX_REPORT_BYTES)
    _validate_report(document)
    return SessionBindingTimelineReport(core.canonical(document))


def analyze_supplied_session_binding_timeline(
    model: dict[str, Any],
) -> SessionBindingTimelineReport:
    core.validate_tree(model, maximum=MAX_SOURCE_BYTES)
    item = core.exact(model, {"source_id", "source"}, "component model")
    source_id = core.identifier(item["source_id"], "source ID")
    _model(item["source"])
    return analyze_session_binding_timeline(
        source_content=core.canonical(item["source"]).encode("ascii"), source_id=source_id
    )


def verify_session_binding_timeline(
    report: SessionBindingTimelineReport, *, source_content: bytes, source_id: str
) -> SessionBindingTimelineReport:
    if type(report) is not SessionBindingTimelineReport:
        raise SessionBindingTimelineError("report must be the exact report family")
    loaded = SessionBindingTimelineReport.from_json(report.to_json())
    expected = analyze_session_binding_timeline(source_content=source_content, source_id=source_id)
    if loaded.to_json() != expected.to_json():
        raise SessionBindingTimelineError("report does not replay from supplied source")
    return expected


def component_fixture() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "events_complete": True,
        "policy_complete": True,
        "concurrency_resolved": True,
        "device_bindings_complete": True,
        "policy": {
            "invalidate_on_rotation": True,
            "invalidate_on_revoke": True,
            "device_binding_required": True,
        },
        "events": [
            {
                "event_id": "e1",
                "kind": "issue",
                "session_id": "synthetic:s-old",
                "replacement_session_id": None,
                "device_id": "synthetic:device-a",
                "supplied_outcome": None,
                "observation_complete": False,
                "revocation_effective_before_observation": None,
            },
            {
                "event_id": "e2",
                "kind": "rotate",
                "session_id": "synthetic:s-old",
                "replacement_session_id": "synthetic:s-new",
                "device_id": "synthetic:device-a",
                "supplied_outcome": None,
                "observation_complete": False,
                "revocation_effective_before_observation": None,
            },
            {
                "event_id": "e3",
                "kind": "observe",
                "session_id": "synthetic:s-old",
                "replacement_session_id": None,
                "device_id": "synthetic:device-a",
                "supplied_outcome": "allowed",
                "observation_complete": True,
                "revocation_effective_before_observation": None,
            },
            {
                "event_id": "e4",
                "kind": "observe",
                "session_id": "synthetic:s-new",
                "replacement_session_id": None,
                "device_id": "synthetic:device-b",
                "supplied_outcome": "allowed",
                "observation_complete": True,
                "revocation_effective_before_observation": None,
            },
            {
                "event_id": "e5",
                "kind": "revoke",
                "session_id": "synthetic:s-new",
                "replacement_session_id": None,
                "device_id": None,
                "supplied_outcome": None,
                "observation_complete": False,
                "revocation_effective_before_observation": None,
            },
            {
                "event_id": "e6",
                "kind": "observe",
                "session_id": "synthetic:s-new",
                "replacement_session_id": None,
                "device_id": "synthetic:device-a",
                "supplied_outcome": "denied",
                "observation_complete": True,
                "revocation_effective_before_observation": True,
            },
        ],
    }

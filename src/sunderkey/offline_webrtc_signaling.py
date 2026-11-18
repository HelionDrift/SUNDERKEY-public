"""Inert projection of supplied WebRTC signaling membership and owner declarations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "browser_supplied_webrtc_signaling_projection"
PROFILE_ID = "AOE-GB-D05-S18"
CAPABILITY_ID = "army.gb.d05.s18"
VECTOR_ID = "AV-GB-D05-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D05-S18"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GB-D05-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-34"
BLUEPRINT_SHA256 = "sha256:65b6d5d68752bfe25b445e7bccf4d437bc61e455509d29214aee3a074cec2791"
DOMAIN = "sunderkey.offline-webrtc-signaling.v1"
MODEL_DOMAIN = "sunderkey.offline-webrtc-signaling-model.v1"
SEMANTICS_PROFILE = "declared-direct-signaling-membership-owner-projection.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_NATIVE_NODES = 8_192
MAX_NATIVE_DEPTH = 12
MAX_STRING_BYTES = 256
MAX_ROOMS = 32
MAX_PEERS_PER_ROOM = 64
MAX_EVENTS = 128
MAX_WORK = 1_000_000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_KINDS = frozenset(("offer", "answer", "ice_candidate"))
_FLAGS = dict.fromkeys(
    (
        "source_authenticated",
        "signaling_delivered",
        "peer_identity_verified",
        "sdp_parsed",
        "ice_connectivity_verified",
        "webrtc_session_established",
        "browser_executed",
        "exploit_verified",
        "positive_use_approved",
        "qualification_claimed",
    ),
    False,
)
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "browser",
        "credential",
        "execution",
        "network",
        "process",
        "provider",
        "qualification",
        "target",
    ),
    "none",
)
_BOUNDS = {
    "document_bytes": MAX_DOCUMENT_BYTES,
    "native_nodes": MAX_NATIVE_NODES,
    "scalar_inclusive_depth": MAX_NATIVE_DEPTH,
    "string_bytes": MAX_STRING_BYTES,
    "rooms": MAX_ROOMS,
    "peers_per_room": MAX_PEERS_PER_ROOM,
    "events": MAX_EVENTS,
    "work_steps": MAX_WORK,
}
_LIMITATIONS = (
    "Rooms, membership, forwarding, identity and direct-submission are caller declarations.",
    "Offer, answer and ICE-candidate labels identify supplied envelope kinds only.",
    "SDP, ICE candidate text, transport and media behavior are not parsed or validated.",
    "A candidate contradicts supplied direct-signaling policy, not observed delivery.",
    "Unknown or incomplete membership, policy, identity or relay context cannot yield a candidate.",
    "No browser, WebRTC session, payload, target, network, process or credential is used.",
    "No authority, qualification, positive use or live finding is established.",
)


class WebRTCSignalingAnalysisError(ValueError):
    """A supplied model or report is outside the bounded closed contract."""


@dataclass(slots=True)
class _Work:
    count: int = 0

    def charge(self, amount: int) -> None:
        if self.count + amount > MAX_WORK:
            raise WebRTCSignalingAnalysisError("Software work bound exhausted")
        self.count += amount


def _measure(value: Any, work: _Work | None = None) -> None:
    size = nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal size, nodes
        nodes += 1
        if depth > MAX_NATIVE_DEPTH or nodes > MAX_NATIVE_NODES:
            raise WebRTCSignalingAnalysisError("Native node/depth bound exhausted")
        kind = type(item)
        if kind is str:
            if len(item) > MAX_STRING_BYTES or not all(32 <= ord(char) <= 126 for char in item):
                raise WebRTCSignalingAnalysisError("Bounded printable ASCII string required")
            size += len(json.dumps(item, ensure_ascii=True))
        elif kind is bool:
            size += 4 if item else 5
        elif item is None:
            size += 4
        elif kind is int:
            if not -(2**63) <= item < 2**63:
                raise WebRTCSignalingAnalysisError("Signed 64-bit integer required")
            size += len(str(item))
        elif kind in (dict, list):
            if id(item) in active:
                raise WebRTCSignalingAnalysisError("Cyclic native document")
            active.add(id(item))
            size += 2 + len(item) * 2
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise WebRTCSignalingAnalysisError("Exact native string keys required")
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        else:
            raise WebRTCSignalingAnalysisError("Exact native JSON primitives required")
        if size > MAX_DOCUMENT_BYTES:
            raise WebRTCSignalingAnalysisError("Document byte bound exhausted")

    visit(value, 1)
    if work is not None:
        work.charge(size + nodes)


def _serialize(value: Any, work: _Work | None = None) -> str:
    _measure(value, work)
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    if len(text) > MAX_DOCUMENT_BYTES:
        raise WebRTCSignalingAnalysisError("Serialized document byte bound exhausted")
    return text


def _decode(content: Any) -> Any:
    if (
        type(content) is not str
        or not content
        or len(content) > MAX_DOCUMENT_BYTES
        or not content.isascii()
    ):
        raise WebRTCSignalingAnalysisError("Bounded ASCII JSON required")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result: dict = {}
        for key, value in items:
            if key in result:
                raise WebRTCSignalingAnalysisError("Duplicate JSON member")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token) > 20 or re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})", token) is None:
            raise WebRTCSignalingAnalysisError("Raw integer bound failed")
        value = int(token)
        if not -(2**63) <= value < 2**63:
            raise WebRTCSignalingAnalysisError("Signed 64-bit integer required")
        return value

    def unsupported(_: str) -> None:
        raise WebRTCSignalingAnalysisError("Fractional or nonfinite number unsupported")

    try:
        value = json.loads(
            content,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=unsupported,
            parse_constant=unsupported,
        )
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, WebRTCSignalingAnalysisError):
            raise
        raise WebRTCSignalingAnalysisError("Malformed supplied JSON") from exc
    _measure(value)
    return value


def _capture(value: Any, work: _Work | None = None) -> tuple[Any, str]:
    text = _serialize(value, work)
    return _decode(text), text


def _identity(value: Any, *, allow_unknown: bool = False) -> str:
    if (
        type(value) is not str
        or _ID.fullmatch(value) is None
        or (value == "unknown" and not allow_unknown)
    ):
        raise WebRTCSignalingAnalysisError("Bounded identity required")
    return value


def _validate_model(model: Any, work: _Work) -> tuple[dict, str]:
    owned, source_text = _capture(model, work)
    if type(owned) is not dict or owned.keys() != {
        "schema_version",
        "rooms_complete",
        "rooms",
        "events",
    }:
        raise WebRTCSignalingAnalysisError("Exact closed model fields required")
    if type(owned["schema_version"]) is not int or owned["schema_version"] != 1:
        raise WebRTCSignalingAnalysisError("Exact schema version 1 required")
    if type(owned["rooms_complete"]) is not bool:
        raise WebRTCSignalingAnalysisError("Exact room completeness boolean required")
    rooms, events = owned["rooms"], owned["events"]
    if type(rooms) is not list or not 1 <= len(rooms) <= MAX_ROOMS:
        raise WebRTCSignalingAnalysisError("Bounded nonempty rooms required")
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise WebRTCSignalingAnalysisError("Bounded nonempty events required")
    room_ids: set[str] = set()
    for room in rooms:
        work.charge(16)
        if type(room) is not dict or room.keys() != {
            "room_id",
            "member_peer_ids",
            "membership_complete",
            "forwarding_policy_complete",
            "member_only_forwarding_required",
            "sender_owner_match_required",
        }:
            raise WebRTCSignalingAnalysisError("Exact closed room fields required")
        room_id = _identity(room["room_id"])
        if room_id in room_ids:
            raise WebRTCSignalingAnalysisError("Duplicate room identity")
        room_ids.add(room_id)
        members = room["member_peer_ids"]
        if type(members) is not list or not 1 <= len(members) <= MAX_PEERS_PER_ROOM:
            raise WebRTCSignalingAnalysisError("Bounded nonempty room members required")
        for member in members:
            _identity(member)
        if members != sorted(set(members)):
            raise WebRTCSignalingAnalysisError("Sorted unique member identities required")
        if (
            type(room["membership_complete"]) is not bool
            or type(room["forwarding_policy_complete"]) is not bool
            or type(room["member_only_forwarding_required"]) is not bool
            or type(room["sender_owner_match_required"]) is not bool
        ):
            raise WebRTCSignalingAnalysisError("Exact room booleans required")
    event_ids: set[str] = set()
    for event in events:
        work.charge(16)
        if type(event) is not dict or event.keys() != {
            "event_id",
            "room_id",
            "artifact_kind",
            "sender_peer_id",
            "recipient_peer_id",
            "payload_owner_peer_id",
            "forwarding_decision",
            "direct_submission",
            "identity_binding_complete",
            "context_complete",
        }:
            raise WebRTCSignalingAnalysisError("Exact closed event fields required")
        event_id = _identity(event["event_id"])
        if event_id in event_ids:
            raise WebRTCSignalingAnalysisError("Duplicate event identity")
        event_ids.add(event_id)
        if _identity(event["room_id"]) not in room_ids:
            raise WebRTCSignalingAnalysisError("Unknown room identity")
        if type(event["artifact_kind"]) is not str or event["artifact_kind"] not in _KINDS:
            raise WebRTCSignalingAnalysisError("Supported signaling artifact kind required")
        for field in ("sender_peer_id", "recipient_peer_id", "payload_owner_peer_id"):
            _identity(event[field], allow_unknown=True)
        if type(event["forwarding_decision"]) is not str or event["forwarding_decision"] not in (
            "allow",
            "deny",
            "unknown",
        ):
            raise WebRTCSignalingAnalysisError("Supported forwarding decision required")
        for field in ("direct_submission", "identity_binding_complete", "context_complete"):
            if type(event[field]) is not bool:
                raise WebRTCSignalingAnalysisError("Exact event booleans required")
    if [row["room_id"] for row in rooms] != sorted(room_ids) or [
        row["event_id"] for row in events
    ] != sorted(event_ids):
        raise WebRTCSignalingAnalysisError("Sorted rooms and events required")
    return owned, source_text


def _observe(event: dict, room: dict, rooms_complete: bool) -> dict:
    reasons: list[str] = []
    if not rooms_complete:
        reasons.append("rooms_incomplete")
    if not room["membership_complete"]:
        reasons.append("membership_incomplete")
    if not room["forwarding_policy_complete"]:
        reasons.append("forwarding_policy_incomplete")
    if not event["direct_submission"]:
        reasons.append("relay_or_server_submission")
    if not event["identity_binding_complete"]:
        reasons.append("identity_binding_incomplete")
    if not event["context_complete"]:
        reasons.append("event_context_incomplete")
    if event["forwarding_decision"] == "unknown":
        reasons.append("forwarding_decision_unknown")
    for field in ("sender_peer_id", "recipient_peer_id", "payload_owner_peer_id"):
        if event[field] == "unknown":
            reasons.append(field + "_unknown")
    members = room["member_peer_ids"]
    if reasons:
        outcome = "unknown"
    elif event["forwarding_decision"] == "deny":
        outcome = "declared_forwarding_denied"
    elif room["member_only_forwarding_required"] and (
        event["sender_peer_id"] not in members or event["recipient_peer_id"] not in members
    ):
        outcome = "candidate_forwarded_outside_declared_membership"
    elif room["sender_owner_match_required"] and (
        event["payload_owner_peer_id"] != event["sender_peer_id"]
    ):
        outcome = "candidate_forwarded_payload_owner_mismatch"
    else:
        outcome = "consistent_with_declared_signaling_policy"
    return {
        "event_id": event["event_id"],
        "room_id": event["room_id"],
        "artifact_kind": event["artifact_kind"],
        "sender_peer_id": event["sender_peer_id"],
        "recipient_peer_id": event["recipient_peer_id"],
        "payload_owner_peer_id": event["payload_owner_peer_id"],
        "outcome": outcome,
        "uncertainty": reasons,
    }


def _address(domain: str, text: str) -> str:
    return "sha256:" + hashlib.sha256((domain + "\n" + text).encode("ascii")).hexdigest()


def _derive(model: Any) -> dict:
    work = _Work()
    owned, source_text = _validate_model(model, work)
    rooms = {item["room_id"]: item for item in owned["rooms"]}
    observations = [
        _observe(event, rooms[event["room_id"]], owned["rooms_complete"])
        for event in owned["events"]
    ]
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
        "semantics_profile": SEMANTICS_PROFILE,
        "source_model": owned,
        "source_model_sha256": _address(MODEL_DOMAIN, source_text),
        "event_count": len(observations),
        "candidate_count": sum(row["outcome"].startswith("candidate_") for row in observations),
        "unknown_count": sum(row["outcome"] == "unknown" for row in observations),
        "event_observations": observations,
        "bounds": dict(_BOUNDS),
        "flags": dict(_FLAGS),
        "effects": dict(_EFFECTS),
        "limitations": list(_LIMITATIONS),
    }
    body_text = _serialize(body, work)
    work.charge(len(DOMAIN) + len(MODEL_DOMAIN) + len(source_text) + len(body_text))
    digest = _address(DOMAIN, body_text)
    body["analysis_id"] = "WSG-" + digest[7:39].upper()
    body["analysis_sha256"] = digest
    _serialize(body, work)
    return body


def _replay(document: Any) -> dict:
    owned, text = _capture(document)
    if type(owned) is not dict or "source_model" not in owned:
        raise WebRTCSignalingAnalysisError("Source-bearing report required")
    expected = _derive(owned["source_model"])
    if text != _serialize(expected):
        raise WebRTCSignalingAnalysisError("Report does not replay embedded source")
    return expected


@dataclass(frozen=True, slots=True, init=False)
class WebRTCSignalingAnalysis:
    """Detached declaration projection, never live WebRTC evidence."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        object.__setattr__(self, "_document_json", _serialize(_replay(document)))

    @classmethod
    def from_dict(cls, document: Any) -> WebRTCSignalingAnalysis:
        return cls(document)

    @classmethod
    def from_json(cls, content: Any) -> WebRTCSignalingAnalysis:
        return cls(_decode(content))

    def to_dict(self) -> dict:
        return _replay(_decode(getattr(self, "_document_json", None)))

    def to_json(self) -> str:
        return _serialize(self.to_dict())

    @property
    def analysis_id(self) -> str:
        return self.to_dict()["analysis_id"]

    @property
    def analysis_sha256(self) -> str:
        return self.to_dict()["analysis_sha256"]


def analyze_supplied_webrtc_signaling(model: Any) -> WebRTCSignalingAnalysis:
    """Project only supplied direct-signaling policy declarations."""
    return WebRTCSignalingAnalysis(_derive(model))


def analyze_supplied_webrtc_signaling_bytes(*, model_bytes: Any) -> WebRTCSignalingAnalysis:
    """Accept bounded ASCII JSON bytes without reading a resource."""
    if type(model_bytes) is not bytes or not model_bytes or len(model_bytes) > MAX_DOCUMENT_BYTES:
        raise WebRTCSignalingAnalysisError("Bounded exact native model bytes required")
    try:
        text = model_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebRTCSignalingAnalysisError("ASCII model bytes required") from exc
    return analyze_supplied_webrtc_signaling(_decode(text))


def verify_supplied_webrtc_signaling_analysis(
    report: Any, *, model: Any
) -> WebRTCSignalingAnalysis:
    """Replay a report against separately supplied original premises."""
    if type(report) is not WebRTCSignalingAnalysis:
        raise WebRTCSignalingAnalysisError("Exact native report family required")
    expected = _derive(model)
    if _serialize(report.to_dict()) != _serialize(expected):
        raise WebRTCSignalingAnalysisError("Report differs from separately supplied originals")
    return WebRTCSignalingAnalysis(expected)


def component_fixture() -> dict:
    """Fresh synthetic direct-signaling, denial and ambiguous relay cases."""
    return {
        "schema_version": 1,
        "rooms_complete": True,
        "rooms": [
            {
                "room_id": "demo",
                "member_peer_ids": ["alice", "bob"],
                "membership_complete": True,
                "forwarding_policy_complete": True,
                "member_only_forwarding_required": True,
                "sender_owner_match_required": True,
            }
        ],
        "events": [
            {
                "event_id": "candidate-membership",
                "room_id": "demo",
                "artifact_kind": "ice_candidate",
                "sender_peer_id": "mallory",
                "recipient_peer_id": "alice",
                "payload_owner_peer_id": "mallory",
                "forwarding_decision": "allow",
                "direct_submission": True,
                "identity_binding_complete": True,
                "context_complete": True,
            },
            {
                "event_id": "candidate-owner",
                "room_id": "demo",
                "artifact_kind": "offer",
                "sender_peer_id": "alice",
                "recipient_peer_id": "bob",
                "payload_owner_peer_id": "bob",
                "forwarding_decision": "allow",
                "direct_submission": True,
                "identity_binding_complete": True,
                "context_complete": True,
            },
            {
                "event_id": "denied",
                "room_id": "demo",
                "artifact_kind": "offer",
                "sender_peer_id": "mallory",
                "recipient_peer_id": "alice",
                "payload_owner_peer_id": "mallory",
                "forwarding_decision": "deny",
                "direct_submission": True,
                "identity_binding_complete": True,
                "context_complete": True,
            },
            {
                "event_id": "matching",
                "room_id": "demo",
                "artifact_kind": "answer",
                "sender_peer_id": "bob",
                "recipient_peer_id": "alice",
                "payload_owner_peer_id": "bob",
                "forwarding_decision": "allow",
                "direct_submission": True,
                "identity_binding_complete": True,
                "context_complete": True,
            },
            {
                "event_id": "unknown-relay",
                "room_id": "demo",
                "artifact_kind": "ice_candidate",
                "sender_peer_id": "alice",
                "recipient_peer_id": "bob",
                "payload_owner_peer_id": "alice",
                "forwarding_decision": "allow",
                "direct_submission": False,
                "identity_binding_complete": True,
                "context_complete": True,
            },
        ],
    }


__all__ = [
    "WebRTCSignalingAnalysisError",
    "WebRTCSignalingAnalysis",
    "analyze_supplied_webrtc_signaling",
    "analyze_supplied_webrtc_signaling_bytes",
    "verify_supplied_webrtc_signaling_analysis",
    "component_fixture",
]

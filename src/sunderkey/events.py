"""Typed append-only mission events with authorization separation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .errors import EventError
from .mission import MissionRequest
from .types import ActionTier, EventType, EvidenceLevel, MissionEnvironment
from .validation import is_ascii_text

EVENT_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,95}")
MISSION_ID_PATTERN = re.compile(r"[A-Z0-9][A-Z0-9._-]{2,63}")
PROFILE_ID_PATTERN = re.compile(
    r"AOE-(?:G[A-E]-D\d{2}-(?:S\d{2}|CMD)|HQ-\d{2})"
)
ACTION_HASH_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
APPROVAL_ID_PATTERN = re.compile(r"APR-[A-Z0-9][A-Z0-9._-]{2,59}")

DEFAULT_CONTROL_PROFILE_IDS = frozenset({"AOE-HQ-12"})
DEFAULT_ASSURANCE_PROFILE_IDS = frozenset(
    {
        "AOE-HQ-18",
        "AOE-HQ-19",
        "AOE-HQ-20",
        "AOE-HQ-21",
    }
)

REQUIRED_PAYLOAD_FIELDS = {
    EventType.OBSERVATION: {
        "target",
        "evidence_refs",
        "confidence",
        "sensitivity",
    },
    EventType.HYPOTHESIS: {
        "claim",
        "supporting_observations",
        "alternatives",
        "confidence",
    },
    EventType.PROPOSAL: {
        "target",
        "method",
        "action_tier",
        "expected_effect",
        "safeguards",
        "rollback",
    },
    EventType.AUTHORIZATION: {
        "proposal_id",
        "executor_profile_id",
        "authority",
        "scope_token",
        "action_hash",
        "action_tier",
        "expires_at",
        "constraints",
    },
    EventType.RESULT: {
        "authorization_id",
        "action_hash",
        "execution_identity",
        "started_at",
        "ended_at",
        "evidence_refs",
        "cleanup",
    },
    EventType.FINDING: {
        "result_id",
        "root_cause",
        "preconditions",
        "evidence_level",
        "impact",
        "mappings",
        "owner",
    },
    EventType.BLOCKER: {
        "reason",
        "risk",
        "decision_owner",
    },
    EventType.HANDOFF: {
        "from_profile_id",
        "to_profile_id",
        "graph_objects",
        "question",
        "due_state",
    },
}

OPTIONAL_PAYLOAD_FIELDS = {
    EventType.AUTHORIZATION: {
        "approval_id",
        "purpose",
    },
    EventType.FINDING: {
        "independent_reproduction_result_id",
        "counter_evidence_review",
    },
}

STRING_PAYLOAD_FIELDS = {
    EventType.OBSERVATION: {"target", "confidence", "sensitivity"},
    EventType.HYPOTHESIS: {"claim", "confidence"},
    EventType.PROPOSAL: {
        "target",
        "method",
        "expected_effect",
        "rollback",
    },
    EventType.AUTHORIZATION: {
        "proposal_id",
        "executor_profile_id",
        "authority",
        "scope_token",
        "action_hash",
        "expires_at",
        "approval_id",
        "purpose",
    },
    EventType.RESULT: {
        "authorization_id",
        "action_hash",
        "execution_identity",
        "started_at",
        "ended_at",
        "cleanup",
    },
    EventType.FINDING: {
        "result_id",
        "root_cause",
        "impact",
        "owner",
        "independent_reproduction_result_id",
        "counter_evidence_review",
    },
    EventType.BLOCKER: {"reason", "risk", "decision_owner"},
    EventType.HANDOFF: {
        "from_profile_id",
        "to_profile_id",
        "question",
        "due_state",
    },
}

STRING_SEQUENCE_PAYLOAD_FIELDS = {
    EventType.OBSERVATION: {"evidence_refs"},
    EventType.HYPOTHESIS: {"supporting_observations", "alternatives"},
    EventType.PROPOSAL: {"safeguards"},
    EventType.AUTHORIZATION: {"constraints"},
    EventType.RESULT: {"evidence_refs"},
    EventType.FINDING: {"preconditions", "mappings"},
    EventType.HANDOFF: {"graph_objects"},
}

PROPOSAL_ACTION_FIELDS = tuple(sorted(REQUIRED_PAYLOAD_FIELDS[EventType.PROPOSAL]))


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not is_ascii_text(value):
        raise EventError(f"{label} must be an ISO 8601 timestamp string")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise EventError(f"{label} must be an ISO 8601 timestamp string") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EventError(f"{label} must include a timezone")
    return parsed


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def compute_proposal_action_hash(payload: Mapping[str, Any]) -> str:
    try:
        action = {
            field: _thaw(payload[field])
            for field in PROPOSAL_ACTION_FIELDS
        }
    except KeyError as exc:
        raise EventError(
            f"Proposal payload cannot be hashed without {exc.args[0]}"
        ) from exc
    serialized = json.dumps(
        action,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    digest = hashlib.sha256(serialized).hexdigest()
    return f"sha256:{digest}"


def _non_empty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, tuple, list, dict, Mapping)):
        return bool(value)
    return True


def _require_string(value: Any, label: str) -> None:
    if not is_ascii_text(value):
        raise EventError(f"{label} must be non-empty ASCII text")


def _require_string_sequence(value: Any, label: str) -> None:
    if not isinstance(value, (list, tuple)) or not value:
        raise EventError(f"{label} must be a non-empty ASCII text list")
    if not all(is_ascii_text(item) for item in value):
        raise EventError(f"{label} must be a non-empty ASCII text list")


@dataclass(frozen=True)
class MissionEvent:
    schema_version: int
    event_id: str
    mission_id: str
    event_type: EventType
    actor_profile_id: str
    timestamp: str
    payload: Mapping[str, Any]
    references: tuple[str, ...]

    @property
    def grants_permission(self) -> bool:
        return self.event_type is EventType.AUTHORIZATION

    @classmethod
    def from_dict(cls, raw: Any) -> MissionEvent:
        if not isinstance(raw, dict):
            raise EventError("event must be an object")
        allowed = {
            "schema_version",
            "event_id",
            "mission_id",
            "event_type",
            "actor_profile_id",
            "timestamp",
            "payload",
            "references",
        }
        unknown = set(raw) - allowed
        if unknown:
            names = ", ".join(sorted(unknown))
            raise EventError(f"event contains unsupported fields: {names}")
        if raw.get("schema_version") != 1:
            raise EventError("event schema_version must be 1")
        event_id = raw.get("event_id")
        if not isinstance(event_id, str) or EVENT_ID_PATTERN.fullmatch(event_id) is None:
            raise EventError(f"Invalid event_id: {event_id}")
        mission_id = raw.get("mission_id")
        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise EventError(f"Invalid mission_id: {mission_id}")
        actor = raw.get("actor_profile_id")
        if (
            not isinstance(actor, str)
            or PROFILE_ID_PATTERN.fullmatch(actor) is None
        ):
            raise EventError(f"Invalid actor_profile_id: {actor}")
        try:
            event_type = EventType(raw.get("event_type"))
        except (TypeError, ValueError) as exc:
            raise EventError(f"Invalid event_type: {raw.get('event_type')}") from exc
        timestamp = raw.get("timestamp")
        _parse_timestamp(timestamp, "timestamp")
        payload = raw.get("payload")
        if not isinstance(payload, dict):
            raise EventError("payload must be an object")
        if not all(isinstance(key, str) for key in payload):
            raise EventError("payload field names must be strings")
        missing = {
            field
            for field in REQUIRED_PAYLOAD_FIELDS[event_type]
            if field not in payload or not _non_empty(payload[field])
        }
        if missing:
            names = ", ".join(sorted(missing))
            raise EventError(f"{event_type.value} payload is missing: {names}")
        references = raw.get("references", [])
        if not isinstance(references, list) or not all(
            isinstance(item, str) and item.strip() for item in references
        ):
            raise EventError("references must be a list of non-empty strings")
        if len(references) != len(set(references)):
            raise EventError("references contains duplicates")
        invalid_references = [
            reference
            for reference in references
            if EVENT_ID_PATTERN.fullmatch(reference) is None
        ]
        if invalid_references:
            raise EventError("references contains an invalid event ID")
        event = cls(
            schema_version=1,
            event_id=event_id,
            mission_id=mission_id,
            event_type=event_type,
            actor_profile_id=actor,
            timestamp=timestamp,
            payload=_freeze(payload),
            references=tuple(references),
        )
        event.validate_payload_types()
        return event

    def validate_payload_types(self) -> None:
        allowed_fields = REQUIRED_PAYLOAD_FIELDS[self.event_type] | (
            OPTIONAL_PAYLOAD_FIELDS.get(self.event_type, set())
        )
        unknown_fields = set(self.payload) - allowed_fields
        if unknown_fields:
            names = ", ".join(sorted(unknown_fields))
            raise EventError(
                f"{self.event_type.value} payload contains unsupported fields: {names}"
            )
        for field in STRING_PAYLOAD_FIELDS.get(self.event_type, set()):
            if field in self.payload:
                _require_string(
                    self.payload[field],
                    f"payload.{field}",
                )
        for field in STRING_SEQUENCE_PAYLOAD_FIELDS.get(self.event_type, set()):
            _require_string_sequence(
                self.payload[field],
                f"payload.{field}",
            )
        if self.event_type in {EventType.PROPOSAL, EventType.AUTHORIZATION}:
            try:
                ActionTier(self.payload["action_tier"])
            except (TypeError, ValueError) as exc:
                raise EventError("payload.action_tier is invalid") from exc
        if self.event_type is EventType.AUTHORIZATION:
            _parse_timestamp(self.payload["expires_at"], "payload.expires_at")
            executor = self.payload["executor_profile_id"]
            if PROFILE_ID_PATTERN.fullmatch(executor) is None:
                raise EventError("payload.executor_profile_id is invalid")
            if ACTION_HASH_PATTERN.fullmatch(self.payload["action_hash"]) is None:
                raise EventError("payload.action_hash must be a lowercase SHA-256 value")
            has_approval_id = "approval_id" in self.payload
            has_purpose = "purpose" in self.payload
            if has_approval_id != has_purpose:
                raise EventError(
                    "payload.approval_id and payload.purpose must be provided together"
                )
            if has_approval_id:
                approval_id = self.payload["approval_id"]
                if APPROVAL_ID_PATTERN.fullmatch(approval_id) is None:
                    raise EventError("payload.approval_id is invalid")
                if self.payload["purpose"] != "simulation":
                    raise EventError("payload.purpose must be simulation")
        if self.event_type is EventType.RESULT:
            if ACTION_HASH_PATTERN.fullmatch(self.payload["action_hash"]) is None:
                raise EventError("payload.action_hash must be a lowercase SHA-256 value")
            started = _parse_timestamp(self.payload["started_at"], "payload.started_at")
            ended = _parse_timestamp(self.payload["ended_at"], "payload.ended_at")
            if ended < started:
                raise EventError("payload.ended_at cannot precede payload.started_at")
        if self.event_type is EventType.FINDING:
            if EVENT_ID_PATTERN.fullmatch(self.payload["result_id"]) is None:
                raise EventError("payload.result_id is invalid")
            try:
                level = EvidenceLevel(self.payload["evidence_level"])
            except (TypeError, ValueError) as exc:
                raise EventError("payload.evidence_level is invalid") from exc
            if level.rank < EvidenceLevel.E2.rank:
                raise EventError("A finding requires evidence level E2 or higher")
            if level is EvidenceLevel.E4:
                required = {
                    "independent_reproduction_result_id",
                    "counter_evidence_review",
                }
                missing = {
                    field
                    for field in required
                    if field not in self.payload or not _non_empty(self.payload[field])
                }
                if missing:
                    names = ", ".join(sorted(missing))
                    raise EventError(f"E4 finding payload is missing: {names}")
            reproduction_id = self.payload.get("independent_reproduction_result_id")
            if (
                reproduction_id is not None
                and EVENT_ID_PATTERN.fullmatch(reproduction_id) is None
            ):
                raise EventError(
                    "payload.independent_reproduction_result_id is invalid"
                )
        if self.event_type is EventType.HANDOFF:
            for field in ("from_profile_id", "to_profile_id"):
                if PROFILE_ID_PATTERN.fullmatch(self.payload[field]) is None:
                    raise EventError(f"payload.{field} is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "mission_id": self.mission_id,
            "event_type": self.event_type.value,
            "actor_profile_id": self.actor_profile_id,
            "timestamp": self.timestamp,
            "payload": _thaw(self.payload),
            "references": list(self.references),
        }


class EventLedger:
    """Append-only in-memory ledger for one mission."""

    def __init__(
        self,
        mission: MissionRequest,
        *,
        allowed_profile_ids: set[str],
        control_profile_ids: set[str] | None = None,
        assurance_profile_ids: set[str] | None = None,
    ) -> None:
        if not isinstance(mission, MissionRequest):
            raise EventError("mission must be a validated MissionRequest")
        if not isinstance(allowed_profile_ids, set):
            raise EventError("allowed_profile_ids must be a set")
        invalid_allowed = {
            profile_id
            for profile_id in allowed_profile_ids
            if (
                not isinstance(profile_id, str)
                or PROFILE_ID_PATTERN.fullmatch(profile_id) is None
            )
        }
        if invalid_allowed:
            raise EventError("allowed_profile_ids contains an invalid profile ID")

        self._mission = mission
        self._mission_id = mission.mission_id
        self._allowed_profile_ids = frozenset(allowed_profile_ids)

        if control_profile_ids is None:
            control_ids = DEFAULT_CONTROL_PROFILE_IDS & self._allowed_profile_ids
        else:
            control_ids = frozenset(control_profile_ids)
        if assurance_profile_ids is None:
            assurance_ids = DEFAULT_ASSURANCE_PROFILE_IDS & self._allowed_profile_ids
        else:
            assurance_ids = frozenset(assurance_profile_ids)
        if not control_ids.issubset(self._allowed_profile_ids):
            raise EventError("Control profiles must be assigned to this mission")
        if not assurance_ids.issubset(self._allowed_profile_ids):
            raise EventError("Assurance profiles must be assigned to this mission")
        if control_ids & assurance_ids:
            raise EventError("Control and Assurance profile sets must be disjoint")
        self._control_profile_ids = control_ids
        self._assurance_profile_ids = assurance_ids
        self._events: list[MissionEvent] = []
        self._by_id: dict[str, MissionEvent] = {}
        self._consumed_authorization_ids: set[str] = set()

    @property
    def events(self) -> tuple[MissionEvent, ...]:
        return tuple(self._events)

    def get(self, event_id: str) -> MissionEvent:
        try:
            return self._by_id[event_id]
        except KeyError as exc:
            raise EventError(f"Unknown event ID: {event_id}") from exc

    def append(self, event: MissionEvent) -> None:
        if event.mission_id != self._mission_id:
            raise EventError(
                f"Event mission {event.mission_id} does not match {self._mission_id}"
            )
        if event.event_id in self._by_id:
            raise EventError(f"Duplicate event ID: {event.event_id}")
        if event.actor_profile_id not in self._allowed_profile_ids:
            raise EventError(f"Actor is not assigned to this mission: {event.actor_profile_id}")
        missing_references = [
            reference
            for reference in event.references
            if reference not in self._by_id
        ]
        if missing_references:
            names = ", ".join(missing_references)
            raise EventError(f"Event references unknown prior events: {names}")
        if self._events:
            previous_timestamp = _parse_timestamp(
                self._events[-1].timestamp,
                "previous event timestamp",
            )
            event_timestamp = _parse_timestamp(event.timestamp, "timestamp")
            if event_timestamp < previous_timestamp:
                raise EventError("Event timestamp cannot precede the prior event")
        consumed_authorization_id: str | None = None
        if event.event_type is EventType.PROPOSAL:
            self._validate_proposal(event)
        elif event.event_type is EventType.AUTHORIZATION:
            self._validate_authorization(event)
        elif event.event_type is EventType.RESULT:
            consumed_authorization_id = self._validate_result(event)
        elif event.event_type is EventType.FINDING:
            self._validate_finding(event)
        elif event.event_type is EventType.HANDOFF:
            self._validate_handoff(event)
        self._events.append(event)
        self._by_id[event.event_id] = event
        if consumed_authorization_id is not None:
            self._consumed_authorization_ids.add(consumed_authorization_id)

    def _validate_proposal(self, event: MissionEvent) -> None:
        proposed_tier = ActionTier(event.payload["action_tier"])
        if proposed_tier.rank > self._mission.max_action_tier.rank:
            raise EventError(
                f"Proposal tier {proposed_tier.value} exceeds mission maximum "
                f"{self._mission.max_action_tier.value}"
            )
        if proposed_tier is ActionTier.R5 and (
            self._mission.environment is not MissionEnvironment.SYNTHETIC
            or not self._mission.constraints.isolated_research_range
        ):
            raise EventError("R5 proposals require an isolated synthetic range")

    def _validate_authorization(self, event: MissionEvent) -> None:
        if event.actor_profile_id not in self._control_profile_ids:
            raise EventError("Only an independent Control profile can authorize an action")
        proposal = self.get(str(event.payload["proposal_id"]))
        if proposal.event_type is not EventType.PROPOSAL:
            raise EventError("payload.proposal_id must reference a proposal event")
        if proposal.actor_profile_id == event.actor_profile_id:
            raise EventError("An action proposer cannot authorize the same action")
        if proposal.event_id not in event.references:
            raise EventError("Authorization must reference its proposal")
        executor_profile_id = str(event.payload["executor_profile_id"])
        if executor_profile_id not in self._allowed_profile_ids:
            raise EventError("Authorization executor is not assigned to this mission")
        if executor_profile_id == event.actor_profile_id:
            raise EventError("An action authorizer cannot execute the same action")
        if executor_profile_id in self._control_profile_ids:
            raise EventError("Independent Control profiles cannot execute actions")
        proposed_tier = ActionTier(proposal.payload["action_tier"])
        authorized_tier = ActionTier(event.payload["action_tier"])
        if authorized_tier is not proposed_tier:
            raise EventError("Authorization tier must match the proposed action tier")
        if authorized_tier.rank > self._mission.max_action_tier.rank:
            raise EventError("Authorization exceeds the mission action-tier ceiling")
        if event.payload["scope_token"] != self._mission.scope_reference:
            raise EventError("Authorization scope token does not match the mission scope")
        expected_hash = compute_proposal_action_hash(proposal.payload)
        if event.payload["action_hash"] != expected_hash:
            raise EventError("Authorization action hash does not match its proposal")
        issued = _parse_timestamp(event.timestamp, "timestamp")
        expires = _parse_timestamp(event.payload["expires_at"], "payload.expires_at")
        if expires <= issued:
            raise EventError("Authorization expiry must follow its issue time")

    def _validate_result(self, event: MissionEvent) -> str:
        authorization_id = str(event.payload["authorization_id"])
        authorization = self.get(authorization_id)
        if authorization.event_type is not EventType.AUTHORIZATION:
            raise EventError("payload.authorization_id must reference an authorization")
        if authorization.payload.get("purpose") == "simulation":
            raise EventError(
                "A simulation-purpose authorization cannot back a result event"
            )
        if authorization_id in self._consumed_authorization_ids:
            raise EventError("Authorization has already been consumed by a result")
        if authorization.event_id not in event.references:
            raise EventError("Result must reference its authorization")
        if authorization.actor_profile_id == event.actor_profile_id:
            raise EventError("An action authorizer cannot execute the same action")
        if event.actor_profile_id != authorization.payload["executor_profile_id"]:
            raise EventError("Result actor does not match the authorized executor")
        if event.payload["action_hash"] != authorization.payload["action_hash"]:
            raise EventError("Result action hash does not match its authorization")
        issued = _parse_timestamp(
            authorization.timestamp,
            "authorization.timestamp",
        )
        started = _parse_timestamp(event.payload["started_at"], "payload.started_at")
        ended = _parse_timestamp(event.payload["ended_at"], "payload.ended_at")
        recorded = _parse_timestamp(event.timestamp, "timestamp")
        expires = _parse_timestamp(
            authorization.payload["expires_at"],
            "authorization.payload.expires_at",
        )
        if started < issued:
            raise EventError("Result execution began before authorization")
        if started > expires:
            raise EventError("Result execution began after authorization expiry")
        if ended > expires:
            raise EventError("Result execution ended after authorization expiry")
        if recorded < ended:
            raise EventError("Result event timestamp cannot precede execution end")
        return authorization_id

    def _validate_finding(self, event: MissionEvent) -> None:
        if event.actor_profile_id not in self._assurance_profile_ids:
            raise EventError("Only an independent Assurance profile can issue a finding")
        evidence_level = EvidenceLevel(event.payload["evidence_level"])
        if not evidence_level.satisfies(self._mission.required_evidence_level):
            raise EventError(
                f"Finding evidence level {evidence_level.value} does not satisfy "
                f"mission requirement {self._mission.required_evidence_level.value}"
            )

        result_id = str(event.payload["result_id"])
        result = self.get(result_id)
        if result.event_type is not EventType.RESULT:
            raise EventError("payload.result_id must reference a result event")
        if result_id not in event.references:
            raise EventError("Finding must reference payload.result_id")
        if event.actor_profile_id in self._result_participants(result):
            raise EventError(
                "A finding issuer must be independent from the action participants"
            )

        reproduction_id = event.payload.get("independent_reproduction_result_id")
        if reproduction_id is not None:
            self._validate_reproduction(event, result, str(reproduction_id))

    def _validate_handoff(self, event: MissionEvent) -> None:
        if event.payload["from_profile_id"] != event.actor_profile_id:
            raise EventError("A handoff actor must match payload.from_profile_id")
        for field in ("from_profile_id", "to_profile_id"):
            if event.payload[field] not in self._allowed_profile_ids:
                raise EventError(f"Handoff {field} is not assigned to this mission")

    def _result_participants(self, result: MissionEvent) -> set[str]:
        authorization = self.get(str(result.payload["authorization_id"]))
        proposal = self.get(str(authorization.payload["proposal_id"]))
        return {
            proposal.actor_profile_id,
            authorization.actor_profile_id,
            result.actor_profile_id,
        }

    def _validate_reproduction(
        self,
        finding: MissionEvent,
        primary_result: MissionEvent,
        reproduction_id: str,
    ) -> None:
        if reproduction_id == primary_result.event_id:
            raise EventError("Independent reproduction must use a distinct result")
        reproduction = self.get(reproduction_id)
        if reproduction.event_type is not EventType.RESULT:
            raise EventError(
                "payload.independent_reproduction_result_id must reference a result"
            )
        if reproduction_id not in finding.references:
            raise EventError("Finding must reference its independent reproduction result")
        if reproduction.actor_profile_id not in self._assurance_profile_ids:
            raise EventError(
                "Independent reproduction must be performed by an Assurance profile"
            )
        if reproduction.actor_profile_id == primary_result.actor_profile_id:
            raise EventError("Independent reproduction requires a different executor")
        if finding.actor_profile_id in self._result_participants(reproduction):
            raise EventError(
                "A finding issuer must be independent from reproduction participants"
            )
        if (
            reproduction.payload["authorization_id"]
            == primary_result.payload["authorization_id"]
        ):
            raise EventError("Independent reproduction requires a separate authorization")
        if reproduction.payload["action_hash"] != primary_result.payload["action_hash"]:
            raise EventError("Independent reproduction action hash must match the result")

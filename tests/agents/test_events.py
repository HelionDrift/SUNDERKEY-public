from __future__ import annotations

import unittest
from typing import Any

from sunderkey.errors import EventError
from sunderkey.events import (
    EventLedger,
    MissionEvent,
    compute_proposal_action_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.types import EventType

MISSION_ID = "MISSION-UNIT-001"
SCOPE_REFERENCE = "scope://unit/synthetic-api"
SPECIALIST_ID = "AOE-GB-D06-S09"
SECOND_SPECIALIST_ID = "AOE-GB-D06-S10"
CONTROL_ID = "AOE-HQ-12"
ASSURANCE_ID = "AOE-HQ-19"
SECOND_ASSURANCE_ID = "AOE-HQ-18"

ALL_PROFILE_IDS = {
    SPECIALIST_ID,
    SECOND_SPECIALIST_ID,
    CONTROL_ID,
    ASSURANCE_ID,
    SECOND_ASSURANCE_ID,
}

BAD_ACTION_HASH = "sha256:" + ("0" * 64)


def mission_request(
    *,
    max_action_tier: str = "R2",
    required_evidence_level: str = "E2",
    scope_reference: str = SCOPE_REFERENCE,
) -> MissionRequest:
    return MissionRequest.from_dict(
        {
            "schema_version": 1,
            "mission_id": MISSION_ID,
            "objective": "Validate a synthetic API authorization boundary",
            "environment": "test",
            "requested_specialist_ids": [SPECIALIST_ID],
            "max_action_tier": max_action_tier,
            "required_evidence_level": required_evidence_level,
            "scope_reference": scope_reference,
            "constraints": {
                "production": False,
                "third_party": False,
                "synthetic_data_only": True,
                "isolated_research_range": False,
                "max_cell_size": 20,
            },
        }
    )


def proposal_data(
    *,
    event_id: str = "EVT-PROP-001",
    actor: str = SPECIALIST_ID,
    action_tier: Any = "R2",
    timestamp: str = "2026-01-01T10:00:00Z",
    target: str = "synthetic://api/object/fixture",
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": event_id,
        "mission_id": MISSION_ID,
        "event_type": "proposal",
        "actor_profile_id": actor,
        "timestamp": timestamp,
        "payload": {
            "target": target,
            "method": "Read-only authorization boundary validation",
            "action_tier": action_tier,
            "expected_effect": "Return only the assigned synthetic object",
            "safeguards": ["Synthetic data", "Request limit"],
            "rollback": "Stop the validation request",
        },
        "references": [],
    }


def authorization_data(
    *,
    proposal: dict[str, Any] | None = None,
    event_id: str = "EVT-AUTH-001",
    actor: str = CONTROL_ID,
    executor_profile_id: str = SPECIALIST_ID,
    action_tier: Any | None = None,
    action_hash: str | None = None,
    scope_token: str = SCOPE_REFERENCE,
    timestamp: str = "2026-01-01T10:05:00Z",
    expires_at: str = "2026-01-01T11:00:00Z",
) -> dict[str, Any]:
    proposal = proposal or proposal_data()
    proposal_id = proposal["event_id"]
    proposal_payload = proposal["payload"]
    if action_tier is None:
        action_tier = proposal_payload["action_tier"]
    if action_hash is None:
        action_hash = compute_proposal_action_hash(proposal_payload)
    return {
        "schema_version": 1,
        "event_id": event_id,
        "mission_id": MISSION_ID,
        "event_type": "authorization",
        "actor_profile_id": actor,
        "timestamp": timestamp,
        "payload": {
            "proposal_id": proposal_id,
            "authority": "unit-control-policy",
            "scope_token": scope_token,
            "action_hash": action_hash,
            "executor_profile_id": executor_profile_id,
            "action_tier": action_tier,
            "expires_at": expires_at,
            "constraints": ["Synthetic target only"],
        },
        "references": [proposal_id],
    }


def result_data(
    *,
    event_id: str = "EVT-RESULT-001",
    authorization_id: str = "EVT-AUTH-001",
    actor: str = SPECIALIST_ID,
    action_hash: str | None = None,
    timestamp: str = "2026-01-01T10:20:00Z",
    started_at: str = "2026-01-01T10:10:00Z",
    ended_at: str = "2026-01-01T10:20:00Z",
) -> dict[str, Any]:
    if action_hash is None:
        action_hash = compute_proposal_action_hash(proposal_data()["payload"])
    return {
        "schema_version": 1,
        "event_id": event_id,
        "mission_id": MISSION_ID,
        "event_type": "result",
        "actor_profile_id": actor,
        "timestamp": timestamp,
        "payload": {
            "authorization_id": authorization_id,
            "action_hash": action_hash,
            "execution_identity": f"identity://unit/{actor}",
            "started_at": started_at,
            "ended_at": ended_at,
            "evidence_refs": [f"evidence://unit/{event_id.lower()}"],
            "cleanup": "No persistent change was made",
        },
        "references": [authorization_id],
    }


def finding_data(
    evidence_level: Any,
    *,
    event_id: str = "EVT-FINDING-001",
    actor: str = ASSURANCE_ID,
    result_id: str = "EVT-RESULT-001",
    independent_reproduction_result_id: str | None = None,
    counter_evidence_review: str | None = None,
    timestamp: str = "2026-01-01T10:30:00Z",
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "result_id": result_id,
        "root_cause": "Synthetic object authorization is not enforced",
        "preconditions": ["Authenticated synthetic user"],
        "evidence_level": evidence_level,
        "impact": "Synthetic cross-account data exposure",
        "mappings": ["CWE-639"],
        "owner": "owner://unit/api-team",
    }
    references = [result_id]
    if independent_reproduction_result_id is not None:
        payload[
            "independent_reproduction_result_id"
        ] = independent_reproduction_result_id
        if independent_reproduction_result_id not in references:
            references.append(independent_reproduction_result_id)
    if counter_evidence_review is not None:
        payload["counter_evidence_review"] = counter_evidence_review
    return {
        "schema_version": 1,
        "event_id": event_id,
        "mission_id": MISSION_ID,
        "event_type": "finding",
        "actor_profile_id": actor,
        "timestamp": timestamp,
        "payload": payload,
        "references": references,
    }


def append_authorized_result(
    ledger: EventLedger,
    *,
    proposal_id: str = "EVT-PROP-001",
    authorization_id: str = "EVT-AUTH-001",
    result_id: str = "EVT-RESULT-001",
    executor: str = SPECIALIST_ID,
    proposal_timestamp: str = "2026-01-01T10:00:00Z",
    authorization_timestamp: str = "2026-01-01T10:05:00Z",
    started_at: str = "2026-01-01T10:10:00Z",
    ended_at: str = "2026-01-01T10:20:00Z",
    result_timestamp: str = "2026-01-01T10:20:00Z",
    expires_at: str = "2026-01-01T11:00:00Z",
) -> tuple[MissionEvent, MissionEvent, MissionEvent]:
    proposal_raw = proposal_data(
        event_id=proposal_id,
        actor=executor,
        timestamp=proposal_timestamp,
    )
    action_hash = compute_proposal_action_hash(proposal_raw["payload"])
    authorization_raw = authorization_data(
        proposal=proposal_raw,
        event_id=authorization_id,
        executor_profile_id=executor,
        action_hash=action_hash,
        timestamp=authorization_timestamp,
        expires_at=expires_at,
    )
    result_raw = result_data(
        event_id=result_id,
        authorization_id=authorization_id,
        actor=executor,
        action_hash=action_hash,
        timestamp=result_timestamp,
        started_at=started_at,
        ended_at=ended_at,
    )
    events = tuple(
        MissionEvent.from_dict(raw)
        for raw in (proposal_raw, authorization_raw, result_raw)
    )
    for event in events:
        ledger.append(event)
    return events


class EventLedgerTests(unittest.TestCase):
    def test_valid_proposal_authorization_result_lifecycle(self) -> None:
        mission = mission_request()
        ledger = EventLedger(
            mission,
            allowed_profile_ids={SPECIALIST_ID, CONTROL_ID},
        )
        proposal_raw = proposal_data()
        action_hash = compute_proposal_action_hash(proposal_raw["payload"])
        authorization_raw = authorization_data(
            proposal=proposal_raw,
            action_hash=action_hash,
        )
        result_raw = result_data(action_hash=action_hash)
        proposal = MissionEvent.from_dict(proposal_raw)
        authorization = MissionEvent.from_dict(authorization_raw)
        result = MissionEvent.from_dict(result_raw)

        ledger.append(proposal)
        ledger.append(authorization)
        ledger.append(result)

        self.assertFalse(proposal.grants_permission)
        self.assertTrue(authorization.grants_permission)
        self.assertEqual(
            tuple(event.event_type for event in ledger.events),
            (EventType.PROPOSAL, EventType.AUTHORIZATION, EventType.RESULT),
        )
        self.assertEqual(result.to_dict(), result_raw)

    def test_only_independent_control_can_authorize(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        proposal_raw = proposal_data()
        ledger.append(MissionEvent.from_dict(proposal_raw))

        authorization = MissionEvent.from_dict(
            authorization_data(
                proposal=proposal_raw,
                actor=SECOND_SPECIALIST_ID,
            )
        )
        with self.assertRaisesRegex(EventError, "independent Control profile"):
            ledger.append(authorization)

    def test_proposer_cannot_authorize_same_action(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
            control_profile_ids={SPECIALIST_ID},
        )
        proposal_raw = proposal_data()
        ledger.append(MissionEvent.from_dict(proposal_raw))

        authorization = MissionEvent.from_dict(
            authorization_data(
                proposal=proposal_raw,
                actor=SPECIALIST_ID,
            )
        )
        with self.assertRaisesRegex(EventError, "proposer cannot authorize"):
            ledger.append(authorization)

    def test_authorization_cannot_increase_tier_or_expire_at_issue(self) -> None:
        proposal_raw = proposal_data()
        invalid_authorizations = (
            authorization_data(proposal=proposal_raw, action_tier="R3"),
            authorization_data(
                proposal=proposal_raw,
                expires_at="2026-01-01T10:05:00Z",
            ),
        )
        for authorization_raw in invalid_authorizations:
            ledger = EventLedger(
                mission_request(),
                allowed_profile_ids=ALL_PROFILE_IDS,
            )
            ledger.append(MissionEvent.from_dict(proposal_raw))
            with (
                self.subTest(payload=authorization_raw["payload"]),
                self.assertRaises(EventError),
            ):
                ledger.append(MissionEvent.from_dict(authorization_raw))

    def test_mission_action_tier_is_a_hard_ceiling(self) -> None:
        ledger = EventLedger(
            mission_request(max_action_tier="R1"),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        proposal = MissionEvent.from_dict(proposal_data(action_tier="R2"))

        with self.assertRaises(EventError):
            ledger.append(proposal)

    def test_authorization_scope_must_exactly_match_mission_scope(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        proposal_raw = proposal_data()
        ledger.append(MissionEvent.from_dict(proposal_raw))
        authorization = MissionEvent.from_dict(
            authorization_data(
                proposal=proposal_raw,
                scope_token=SCOPE_REFERENCE + "/expanded",
            )
        )

        with self.assertRaises(EventError):
            ledger.append(authorization)

    def test_executor_must_match_authorized_profile(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        proposal_raw = proposal_data()
        action_hash = compute_proposal_action_hash(proposal_raw["payload"])
        ledger.append(MissionEvent.from_dict(proposal_raw))
        ledger.append(
            MissionEvent.from_dict(
                authorization_data(
                    proposal=proposal_raw,
                    executor_profile_id=SPECIALIST_ID,
                    action_hash=action_hash,
                )
            )
        )
        result = MissionEvent.from_dict(
            result_data(
                actor=SECOND_SPECIALIST_ID,
                action_hash=action_hash,
            )
        )

        with self.assertRaises(EventError):
            ledger.append(result)

    def test_authorization_and_result_action_hashes_are_verified(self) -> None:
        proposal_raw = proposal_data()

        authorization_ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        authorization_ledger.append(MissionEvent.from_dict(proposal_raw))
        bad_authorization = MissionEvent.from_dict(
            authorization_data(
                proposal=proposal_raw,
                action_hash=BAD_ACTION_HASH,
            )
        )
        with self.assertRaises(EventError):
            authorization_ledger.append(bad_authorization)

        result_ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        result_ledger.append(MissionEvent.from_dict(proposal_raw))
        result_ledger.append(
            MissionEvent.from_dict(authorization_data(proposal=proposal_raw))
        )
        bad_result = MissionEvent.from_dict(
            result_data(action_hash=BAD_ACTION_HASH)
        )
        with self.assertRaises(EventError):
            result_ledger.append(bad_result)

    def test_authorization_is_single_use(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        _, authorization, result = append_authorized_result(ledger)
        replay_raw = result_data(
            event_id="EVT-RESULT-002",
            authorization_id=authorization.event_id,
            action_hash=str(result.payload["action_hash"]),
            timestamp="2026-01-01T10:21:00Z",
            started_at="2026-01-01T10:20:01Z",
            ended_at="2026-01-01T10:20:02Z",
        )

        with self.assertRaises(EventError):
            ledger.append(MissionEvent.from_dict(replay_raw))

    def test_result_must_stay_within_authorization_window(self) -> None:
        proposal_raw = proposal_data()
        action_hash = compute_proposal_action_hash(proposal_raw["payload"])
        cases = (
            (
                result_data(
                    action_hash=action_hash,
                    started_at="2026-01-01T10:04:59Z",
                    ended_at="2026-01-01T10:20:00Z",
                ),
                "before authorization",
            ),
            (
                result_data(
                    action_hash=action_hash,
                    started_at="2026-01-01T10:10:00Z",
                    ended_at="2026-01-01T11:00:01Z",
                ),
                "ended after authorization expiry",
            ),
            (
                result_data(
                    action_hash=action_hash,
                    timestamp="2026-01-01T11:00:02Z",
                    started_at="2026-01-01T11:00:01Z",
                    ended_at="2026-01-01T11:00:02Z",
                ),
                "began after authorization expiry",
            ),
        )
        for result_raw, message in cases:
            ledger = EventLedger(
                mission_request(),
                allowed_profile_ids=ALL_PROFILE_IDS,
            )
            ledger.append(MissionEvent.from_dict(proposal_raw))
            ledger.append(
                MissionEvent.from_dict(
                    authorization_data(
                        proposal=proposal_raw,
                        action_hash=action_hash,
                    )
                )
            )
            with self.subTest(message=message), self.assertRaisesRegex(
                EventError,
                message,
            ):
                ledger.append(MissionEvent.from_dict(result_raw))

    def test_ledger_requires_prior_references_and_monotonic_time(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        raw = proposal_data()
        raw["references"] = ["EVT-MISSING-001"]
        with self.assertRaisesRegex(EventError, "unknown prior events"):
            ledger.append(MissionEvent.from_dict(raw))

        ledger.append(MissionEvent.from_dict(proposal_data()))
        raw = proposal_data(event_id="EVT-PROP-002")
        raw["timestamp"] = "2026-01-01T09:59:59Z"
        with self.assertRaisesRegex(EventError, "prior event"):
            ledger.append(MissionEvent.from_dict(raw))

    def test_ledger_rejects_unassigned_actor_and_duplicate_event_id(self) -> None:
        restricted = EventLedger(
            mission_request(),
            allowed_profile_ids={CONTROL_ID},
        )
        with self.assertRaisesRegex(EventError, "not assigned"):
            restricted.append(MissionEvent.from_dict(proposal_data()))

        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        event = MissionEvent.from_dict(proposal_data())
        ledger.append(event)
        with self.assertRaisesRegex(EventError, "Duplicate event ID"):
            ledger.append(event)

    def test_explicit_empty_control_and_assurance_sets_stay_empty(self) -> None:
        control_ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
            control_profile_ids=set(),
        )
        proposal_raw = proposal_data()
        control_ledger.append(MissionEvent.from_dict(proposal_raw))
        with self.assertRaises(EventError):
            control_ledger.append(
                MissionEvent.from_dict(
                    authorization_data(proposal=proposal_raw)
                )
            )

        assurance_ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
            assurance_profile_ids=set(),
        )
        append_authorized_result(assurance_ledger)
        finding = MissionEvent.from_dict(finding_data("E2"))
        with self.assertRaises(EventError):
            assurance_ledger.append(finding)


class EvidenceContractTests(unittest.TestCase):
    def test_findings_require_e2_or_higher(self) -> None:
        for level in ("E0", "E1"):
            with self.subTest(level=level), self.assertRaisesRegex(
                EventError,
                "E2 or higher",
            ):
                MissionEvent.from_dict(finding_data(level))

        for level in ("E2", "E3"):
            with self.subTest(level=level):
                event = MissionEvent.from_dict(finding_data(level))
                self.assertEqual(event.payload["evidence_level"], level)

    def test_mission_required_evidence_level_is_enforced(self) -> None:
        ledger = EventLedger(
            mission_request(required_evidence_level="E3"),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        append_authorized_result(ledger)

        with self.assertRaises(EventError):
            ledger.append(MissionEvent.from_dict(finding_data("E2")))

        accepted = MissionEvent.from_dict(
            finding_data(
                "E3",
                event_id="EVT-FINDING-002",
            )
        )
        ledger.append(accepted)
        self.assertEqual(ledger.events[-1], accepted)

    def test_only_assurance_can_issue_a_result_backed_finding(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        append_authorized_result(ledger)

        non_assurance = MissionEvent.from_dict(
            finding_data(
                "E2",
                actor=SECOND_SPECIALIST_ID,
            )
        )
        with self.assertRaisesRegex(EventError, "Assurance profile"):
            ledger.append(non_assurance)

        finding = MissionEvent.from_dict(
            finding_data(
                "E2",
                event_id="EVT-FINDING-002",
            )
        )
        ledger.append(finding)
        self.assertEqual(ledger.events[-1], finding)

    def test_finding_actor_must_be_independent_from_result_actor(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        append_authorized_result(
            ledger,
            executor=ASSURANCE_ID,
        )
        finding = MissionEvent.from_dict(
            finding_data(
                "E2",
                actor=ASSURANCE_ID,
            )
        )

        with self.assertRaises(EventError):
            ledger.append(finding)

    def test_e4_requires_reproduction_result_and_counter_review(self) -> None:
        with self.assertRaisesRegex(EventError, "E4 finding payload is missing"):
            MissionEvent.from_dict(finding_data("E4"))

    def test_e4_requires_distinct_independent_reproduction_result(self) -> None:
        ledger = EventLedger(
            mission_request(required_evidence_level="E4"),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        append_authorized_result(ledger)
        append_authorized_result(
            ledger,
            proposal_id="EVT-PROP-002",
            authorization_id="EVT-AUTH-002",
            result_id="EVT-RESULT-002",
            executor=SECOND_ASSURANCE_ID,
            proposal_timestamp="2026-01-01T10:21:00Z",
            authorization_timestamp="2026-01-01T10:22:00Z",
            started_at="2026-01-01T10:23:00Z",
            ended_at="2026-01-01T10:24:00Z",
            result_timestamp="2026-01-01T10:24:00Z",
            expires_at="2026-01-01T10:50:00Z",
        )

        same_result = MissionEvent.from_dict(
            finding_data(
                "E4",
                event_id="EVT-FINDING-001",
                independent_reproduction_result_id="EVT-RESULT-001",
                counter_evidence_review="review://unit/counter-evidence",
            )
        )
        with self.assertRaises(EventError):
            ledger.append(same_result)

        accepted = MissionEvent.from_dict(
            finding_data(
                "E4",
                event_id="EVT-FINDING-002",
                independent_reproduction_result_id="EVT-RESULT-002",
                counter_evidence_review="review://unit/counter-evidence",
            )
        )
        ledger.append(accepted)
        self.assertEqual(ledger.events[-1], accepted)

    def test_e4_reproduction_actor_must_be_independent(self) -> None:
        ledger = EventLedger(
            mission_request(required_evidence_level="E4"),
            allowed_profile_ids=ALL_PROFILE_IDS,
        )
        append_authorized_result(
            ledger,
            executor=SECOND_ASSURANCE_ID,
        )
        append_authorized_result(
            ledger,
            proposal_id="EVT-PROP-002",
            authorization_id="EVT-AUTH-002",
            result_id="EVT-RESULT-002",
            executor=SECOND_ASSURANCE_ID,
            proposal_timestamp="2026-01-01T10:21:00Z",
            authorization_timestamp="2026-01-01T10:22:00Z",
            started_at="2026-01-01T10:23:00Z",
            ended_at="2026-01-01T10:24:00Z",
            result_timestamp="2026-01-01T10:24:00Z",
            expires_at="2026-01-01T10:50:00Z",
        )
        finding = MissionEvent.from_dict(
            finding_data(
                "E4",
                independent_reproduction_result_id="EVT-RESULT-002",
                counter_evidence_review="review://unit/counter-evidence",
            )
        )

        with self.assertRaises(EventError):
            ledger.append(finding)

    def test_invalid_enum_types_raise_contract_error(self) -> None:
        raw = finding_data({"invalid": "mapping"})
        with self.assertRaises(EventError):
            MissionEvent.from_dict(raw)

    def test_payload_fields_and_types_are_strict(self) -> None:
        raw = proposal_data()
        raw["payload"]["unexpected"] = "value"
        with self.assertRaisesRegex(EventError, "unsupported fields"):
            MissionEvent.from_dict(raw)

        raw = proposal_data()
        raw["payload"]["safeguards"] = "not-a-list"
        with self.assertRaisesRegex(EventError, "non-empty .* list"):
            MissionEvent.from_dict(raw)

    def test_non_ascii_and_format_control_payload_text_is_rejected(self) -> None:
        payloads = (
            "text" + chr(0x2014) + "value",
            "text" + chr(0x200B) + "value",
        )
        for target in payloads:
            raw = proposal_data(target=target)
            with (
                self.subTest(target=target.encode("unicode_escape")),
                self.assertRaises(EventError),
            ):
                MissionEvent.from_dict(raw)


if __name__ == "__main__":
    unittest.main()

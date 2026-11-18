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

MISSION_ID = "MISSION-SIM-001"
SCOPE_REFERENCE = "scope://unit/simulation"
SPECIALIST_ID = "AOE-GB-D06-S09"
CONTROL_ID = "AOE-HQ-12"
PROFILE_IDS = {SPECIALIST_ID, CONTROL_ID}


def mission_request() -> MissionRequest:
    return MissionRequest.from_dict(
        {
            "schema_version": 1,
            "mission_id": MISSION_ID,
            "objective": "Validate the simulation authorization boundary",
            "environment": "synthetic",
            "requested_specialist_ids": [SPECIALIST_ID],
            "max_action_tier": "R2",
            "required_evidence_level": "E2",
            "scope_reference": SCOPE_REFERENCE,
            "constraints": {
                "production": False,
                "third_party": False,
                "synthetic_data_only": True,
                "isolated_research_range": True,
                "max_cell_size": 20,
            },
        }
    )


def proposal_data() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": "EVT-SIM-PROP-001",
        "mission_id": MISSION_ID,
        "event_type": "proposal",
        "actor_profile_id": SPECIALIST_ID,
        "timestamp": "2026-01-01T10:00:00Z",
        "payload": {
            "target": "synthetic://simulation/fixture",
            "method": "Render a policy-only simulation manifest",
            "action_tier": "R2",
            "expected_effect": "Produce no external effect",
            "safeguards": ["No network access", "No subprocess access"],
            "rollback": "No rollback is required",
        },
        "references": [],
    }


def authorization_data(
    *,
    approval_id: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    proposal = proposal_data()
    payload: dict[str, Any] = {
        "proposal_id": proposal["event_id"],
        "authority": "unit-control-policy",
        "scope_token": SCOPE_REFERENCE,
        "action_hash": compute_proposal_action_hash(proposal["payload"]),
        "executor_profile_id": SPECIALIST_ID,
        "action_tier": "R2",
        "expires_at": "2026-01-01T11:00:00Z",
        "constraints": ["Simulation only"],
    }
    if approval_id is not None:
        payload["approval_id"] = approval_id
    if purpose is not None:
        payload["purpose"] = purpose
    return {
        "schema_version": 1,
        "event_id": "EVT-SIM-AUTH-001",
        "mission_id": MISSION_ID,
        "event_type": "authorization",
        "actor_profile_id": CONTROL_ID,
        "timestamp": "2026-01-01T10:05:00Z",
        "payload": payload,
        "references": [proposal["event_id"]],
    }


def result_data() -> dict[str, Any]:
    proposal = proposal_data()
    return {
        "schema_version": 1,
        "event_id": "EVT-SIM-RESULT-001",
        "mission_id": MISSION_ID,
        "event_type": "result",
        "actor_profile_id": SPECIALIST_ID,
        "timestamp": "2026-01-01T10:20:00Z",
        "payload": {
            "authorization_id": "EVT-SIM-AUTH-001",
            "action_hash": compute_proposal_action_hash(proposal["payload"]),
            "execution_identity": "identity://unit/simulation-specialist",
            "started_at": "2026-01-01T10:10:00Z",
            "ended_at": "2026-01-01T10:20:00Z",
            "evidence_refs": ["evidence://unit/simulation-result"],
            "cleanup": "No persistent change was made",
        },
        "references": ["EVT-SIM-AUTH-001"],
    }


class SimulationAuthorizationBoundaryTests(unittest.TestCase):
    def test_legacy_authorization_without_simulation_metadata_remains_valid(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=PROFILE_IDS,
        )
        for raw in (proposal_data(), authorization_data(), result_data()):
            ledger.append(MissionEvent.from_dict(raw))

        self.assertEqual(len(ledger.events), 3)

    def test_simulation_metadata_pair_is_accepted_and_preserved(self) -> None:
        raw = authorization_data(
            approval_id="APR-SIM-001",
            purpose="simulation",
        )

        event = MissionEvent.from_dict(raw)

        self.assertEqual(event.payload["approval_id"], "APR-SIM-001")
        self.assertEqual(event.payload["purpose"], "simulation")
        self.assertEqual(event.to_dict(), raw)

    def test_simulation_metadata_must_be_provided_as_a_pair(self) -> None:
        cases = (
            authorization_data(approval_id="APR-SIM-001"),
            authorization_data(purpose="simulation"),
        )

        for raw in cases:
            with (
                self.subTest(payload=raw["payload"]),
                self.assertRaisesRegex(EventError, "provided together"),
            ):
                MissionEvent.from_dict(raw)

    def test_authorization_allows_only_simulation_purpose(self) -> None:
        raw = authorization_data(
            approval_id="APR-SIM-001",
            purpose="execution",
        )

        with self.assertRaisesRegex(EventError, "must be simulation"):
            MissionEvent.from_dict(raw)

    def test_approval_id_requires_stable_ascii_form(self) -> None:
        invalid_ids = (
            "APP-SIM-001",
            "APR-sim-001",
            "APR-A",
            "APR-SIM" + chr(0x2014) + "001",
            "APR-SIM" + chr(0x200B) + "001",
        )

        for approval_id in invalid_ids:
            raw = authorization_data(
                approval_id=approval_id,
                purpose="simulation",
            )
            with (
                self.subTest(
                    approval_id=approval_id.encode("unicode_escape")
                ),
                self.assertRaises(EventError),
            ):
                MissionEvent.from_dict(raw)

    def test_purpose_requires_ascii_text(self) -> None:
        raw = authorization_data(
            approval_id="APR-SIM-001",
            purpose="sim" + chr(0x200B) + "ulation",
        )

        with self.assertRaisesRegex(EventError, "ASCII"):
            MissionEvent.from_dict(raw)

    def test_result_rejects_simulation_purpose_authorization(self) -> None:
        ledger = EventLedger(
            mission_request(),
            allowed_profile_ids=PROFILE_IDS,
        )
        ledger.append(MissionEvent.from_dict(proposal_data()))
        ledger.append(
            MissionEvent.from_dict(
                authorization_data(
                    approval_id="APR-SIM-001",
                    purpose="simulation",
                )
            )
        )

        with self.assertRaisesRegex(EventError, "simulation-purpose"):
            ledger.append(MissionEvent.from_dict(result_data()))

        self.assertEqual(len(ledger.events), 2)


if __name__ == "__main__":
    unittest.main()

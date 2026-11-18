"""Offline supplied governance outcome reconciliation tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_governance_quorum_reconciliation import (
    GovernanceQuorumReconciliationError,
    analyze_supplied_governance_quorum,
    component_fixture,
    verify_supplied_governance_quorum,
    verify_supplied_governance_quorum_bytes,
)


class GovernanceQuorumReconciliationTests(unittest.TestCase):
    def test_declared_mismatch_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_governance_quorum(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(body["proposal_projections"][0]["computed_passed"], True)
        self.assertEqual(body["proposal_projections"][1]["computed_passed"], False)
        self.assertFalse(body["chain_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_governance_quorum(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_governance_quorum_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_incomplete_snapshot_and_zero_decisive_votes(self) -> None:
        model = component_fixture()
        model["proposals"][0]["snapshot_complete"] = False
        self.assertEqual(analyze_supplied_governance_quorum(model).to_dict()["unknown_count"], 1)
        model = component_fixture()
        proposal = model["proposals"][1]
        proposal["for_votes"] = 0
        proposal["against_votes"] = 0
        self.assertEqual(analyze_supplied_governance_quorum(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_governance_quorum(model)
        changed = copy.deepcopy(model)
        changed["proposals"][0]["declared_passed"] = True
        with self.assertRaises(GovernanceQuorumReconciliationError):
            verify_supplied_governance_quorum(report, model=changed)
        with self.assertRaises(GovernanceQuorumReconciliationError):
            verify_supplied_governance_quorum(report.to_dict(), model=model)
        with self.assertRaises(GovernanceQuorumReconciliationError):
            verify_supplied_governance_quorum_bytes(b"{}", model=model)

    def test_rejects_duplicate_proposal_and_invalid_power(self) -> None:
        model = component_fixture()
        model["proposals"][1]["proposal_id"] = "proposal-one"
        with self.assertRaises(GovernanceQuorumReconciliationError):
            analyze_supplied_governance_quorum(model)
        model = component_fixture()
        model["proposals"][0]["snapshot_voting_power"] = 500
        with self.assertRaises(GovernanceQuorumReconciliationError):
            analyze_supplied_governance_quorum(model)


if __name__ == "__main__":
    unittest.main()

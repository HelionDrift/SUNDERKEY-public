"""Supplied consensus vote grouping and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_consensus_vote_equivocation import (
    ConsensusVoteEquivocationError,
    analyze_supplied_consensus_votes,
    component_fixture,
    verify_supplied_consensus_votes,
    verify_supplied_consensus_votes_bytes,
)


class ConsensusVoteEquivocationTests(unittest.TestCase):
    def test_conflicting_blocks_are_an_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_consensus_votes(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(len(body["coordinate_projections"][0]["block_votes"]), 2)
        self.assertFalse(body["validator_signatures_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_consensus_votes(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_consensus_votes_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_same_block_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["votes"][1]["block_id"] = "block-one"
        self.assertEqual(analyze_supplied_consensus_votes(model).to_dict()["candidate_count"], 0)
        model["context_complete"] = False
        self.assertEqual(analyze_supplied_consensus_votes(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_consensus_votes(model)
        changed = copy.deepcopy(model)
        changed["votes"][1]["block_id"] = "block-three"
        with self.assertRaises(ConsensusVoteEquivocationError):
            verify_supplied_consensus_votes(report, model=changed)
        with self.assertRaises(ConsensusVoteEquivocationError):
            verify_supplied_consensus_votes(report.to_dict(), model=model)
        with self.assertRaises(ConsensusVoteEquivocationError):
            verify_supplied_consensus_votes_bytes(b"{}", model=model)

    def test_rejects_duplicate_vote_and_invalid_coordinate(self) -> None:
        model = component_fixture()
        model["votes"][1]["vote_id"] = "vote-one"
        with self.assertRaises(ConsensusVoteEquivocationError):
            analyze_supplied_consensus_votes(model)
        model = component_fixture()
        model["votes"][1]["height"] = -1
        with self.assertRaises(ConsensusVoteEquivocationError):
            analyze_supplied_consensus_votes(model)


if __name__ == "__main__":
    unittest.main()

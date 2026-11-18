"""Source-bound synthetic path review checkpoint tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_path_review_checkpoint import (
    PathReviewCheckpointError,
    PathReviewCheckpointReport,
    analyze_supplied_path_review,
    component_fixture,
    verify_supplied_path_review,
)


class PathReviewCheckpointTests(unittest.TestCase):
    def test_review_node_covers_declared_routes_without_authority(self) -> None:
        body = analyze_supplied_path_review(component_fixture()).to_dict()
        self.assertEqual(
            [row["disposition"] for row in body["pair_checkpoint_projections"]],
            ["review_on_all_supplied_supported_routes", "unknown"],
        )
        self.assertFalse(body["review_authority_verified"])
        self.assertFalse(body["route_executed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_direct_declared_route_avoids_review(self) -> None:
        model = component_fixture()
        model["graph_model"]["edges"].append({
            "edge_id": "edge-ae", "from_id": "entry-a", "to_id": "objective-e",
            "relation": "declared_access", "status": "supported",
            "source_id": "synthetic-relationships",
        })
        body = analyze_supplied_path_review(model).to_dict()
        row = body["pair_checkpoint_projections"][1]
        self.assertEqual(row["disposition"], "supplied_supported_route_avoids_review")
        self.assertTrue(row["unreviewed_supported_route_declared"])

    def test_hypothesized_avoidance_and_incomplete_graph_stay_uncertain(self) -> None:
        model = component_fixture()
        model["graph_model"]["edges"].append({
            "edge_id": "edge-ae", "from_id": "entry-a", "to_id": "objective-e",
            "relation": "declared_access", "status": "hypothesized",
            "source_id": "synthetic-relationships",
        })
        model["graph_model"]["graph_complete"] = False
        body = analyze_supplied_path_review(model).to_dict()
        row = body["pair_checkpoint_projections"][1]
        self.assertEqual(row["disposition"], "unknown_hypothesized_route_avoids_review")
        self.assertIn("supplied_graph_incomplete", body["uncertainty"])

    def test_nonsynthetic_and_invalid_checkpoints_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PathReviewCheckpointError):
            analyze_supplied_path_review(model)
        model = component_fixture()
        model["review_node_ids"] = ["entry-a"]
        with self.assertRaises(PathReviewCheckpointError):
            analyze_supplied_path_review(model)
        model = component_fixture()
        model["graph_model"]["evidence_sources"][0]["provenance_kind"] = "operator_supplied"
        with self.assertRaises(PathReviewCheckpointError):
            analyze_supplied_path_review(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_path_review(model)
        self.assertEqual(
            verify_supplied_path_review(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["review_node_ids"] = ["boundary-c"]
        with self.assertRaises(PathReviewCheckpointError):
            verify_supplied_path_review(report, model=changed)
        with self.assertRaises(PathReviewCheckpointError):
            PathReviewCheckpointReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

"""Supplied protocol trace differential projections and replay checks."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_protocol_trace_differential import (
    ProtocolTraceDifferentialError,
    ProtocolTraceDifferentialReport,
    analyze_supplied_protocol_trace_differential,
    component_fixture,
    verify_supplied_protocol_trace_differential,
)


class ProtocolTraceDifferentialTests(unittest.TestCase):
    def test_common_prefix_and_divergent_case(self) -> None:
        report = analyze_supplied_protocol_trace_differential(component_fixture()).to_dict()
        self.assertEqual(report["supplied_case_count"], 2)
        self.assertEqual(report["divergent_case_ids"], ["c2"])
        self.assertEqual(report["case_projections"][0]["disposition"], "same_supplied_trace")
        self.assertEqual(report["case_projections"][1]["common_stage_prefix_count"], 1)
        self.assertEqual(report["case_projections"][1]["first_differing_stage_index"], 1)
        self.assertEqual(
            report["case_projections"][1]["disposition"],
            "stage_and_outcome_divergence",
        )
        self.assertFalse(report["trace_origin_verified"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(report["candidate_count"], 0)

    def test_outcome_only_and_stage_only_divergence(self) -> None:
        model = component_fixture()
        model["cases"][0]["traces"]["parser_b"]["outcome"] = "rejected"
        model["cases"][1]["traces"]["parser_b"]["outcome"] = "accepted"
        rows = analyze_supplied_protocol_trace_differential(model).to_dict()["case_projections"]
        self.assertEqual(rows[0]["disposition"], "outcome_divergence")
        self.assertIsNone(rows[0]["first_differing_stage_index"])
        self.assertEqual(rows[1]["disposition"], "stage_divergence")

    def test_rejects_duplicate_digest_and_missing_trace(self) -> None:
        model = component_fixture()
        model["cases"][1]["input_sha256"] = model["cases"][0]["input_sha256"]
        with self.assertRaises(ProtocolTraceDifferentialError):
            analyze_supplied_protocol_trace_differential(model)
        model = component_fixture()
        del model["cases"][0]["traces"]["parser_b"]
        with self.assertRaises(ProtocolTraceDifferentialError):
            analyze_supplied_protocol_trace_differential(model)

    def test_incomplete_inventory_and_original_model_replay(self) -> None:
        model = component_fixture()
        model["case_inventory_complete"] = False
        report = analyze_supplied_protocol_trace_differential(model)
        self.assertEqual(report.to_dict()["disposition"], "unknown")
        self.assertEqual(
            verify_supplied_protocol_trace_differential(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["cases"][1]["traces"]["parser_b"]["outcome"] = "accepted"
        with self.assertRaises(ProtocolTraceDifferentialError):
            verify_supplied_protocol_trace_differential(report, model=changed)
        with self.assertRaises(ProtocolTraceDifferentialError):
            ProtocolTraceDifferentialReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

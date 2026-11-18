"""Inert supplied container-boundary path projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_container_boundary_path_declarations import (
    ContainerBoundaryPathError,
    analyze_supplied_container_boundary_paths,
    analyze_supplied_container_boundary_paths_bytes,
    component_fixture,
    verify_supplied_container_boundary_paths,
    verify_supplied_container_boundary_paths_bytes,
)


class ContainerBoundaryPathTests(unittest.TestCase):
    def test_supplied_mismatch_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_container_boundary_paths(model)
        body = report.to_dict()
        self.assertEqual(body["profile_id"], "AOE-GC-D15-S10")
        self.assertEqual(body["wave_id"], "IW2-012")
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["path_observations"][0]["effective_containment_edge_ids"],
            ["boundary-two"],
        )
        self.assertEqual(
            body["path_observations"][0]["disposition"],
            "candidate_supplied_boundary_mismatch",
        )
        self.assertFalse(body["platform_access_verified"])
        self.assertFalse(body["containment_enforcement_verified"])
        self.assertFalse(body["finding_claimed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_container_boundary_paths(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_container_boundary_paths_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analyze_supplied_container_boundary_paths_bytes(
                model_bytes=json.dumps(model).encode("ascii")
            ).to_json(),
            report.to_json(),
        )

    def test_matching_paths_and_each_incomplete_premise_yield_no_candidate(self) -> None:
        model = component_fixture()
        model["paths"][0]["claimed_reaches_platform"] = False
        body = analyze_supplied_container_boundary_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["path_observations"][0]["disposition"], "matches_supplied_boundaries")

        for field in ("exposure_state", "prerequisite_state", "containment_state"):
            incomplete = component_fixture()
            incomplete["edges"][0][field] = "unknown"
            body = analyze_supplied_container_boundary_paths(incomplete).to_dict()
            self.assertEqual(body["candidate_count"], 0)
            self.assertEqual(body["unknown_count"], 1)
            self.assertIsNone(body["path_observations"][0]["computed_from_declarations"])

        for field in ("inventory_complete", "context_complete"):
            incomplete = component_fixture()
            if field == "inventory_complete":
                incomplete[field] = False
            else:
                incomplete["paths"][0][field] = False
            body = analyze_supplied_container_boundary_paths(incomplete).to_dict()
            self.assertEqual(body["candidate_count"], 0)
            self.assertEqual(body["unknown_count"], 1)

    def test_prerequisites_exposure_and_controls_are_only_declaration_comparisons(self) -> None:
        for field, state, result_field in (
            ("exposure_state", "declared_absent", "absent_exposure_edge_ids"),
            ("prerequisite_state", "declared_unmet", "unmet_prerequisite_edge_ids"),
            ("containment_state", "declared_effective", "effective_containment_edge_ids"),
        ):
            model = component_fixture()
            for edge in model["edges"]:
                edge["containment_state"] = "declared_ineffective"
            model["edges"][0][field] = state
            body = analyze_supplied_container_boundary_paths(model).to_dict()
            self.assertEqual(body["candidate_count"], 1)
            self.assertEqual(body["path_observations"][0][result_field], ["boundary-one"])
            self.assertFalse(body["path_observations"][0]["computed_from_declarations"])

        model = component_fixture()
        for edge in model["edges"]:
            edge["containment_state"] = "declared_ineffective"
        body = analyze_supplied_container_boundary_paths(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["path_observations"][0]["computed_from_declarations"])

    def test_structure_schema_and_exact_native_types_fail_closed(self) -> None:
        cases = []
        disconnected = component_fixture()
        disconnected["paths"][0]["edge_ids"].reverse()
        cases.append(disconnected)
        early_platform = component_fixture()
        early_platform["edges"][0]["to_id"] = "platform-a"
        early_platform["edges"][1]["from_id"] = "platform-a"
        cases.append(early_platform)
        no_boundary = component_fixture()
        no_boundary["nodes"][1]["boundary_label"] = "workload"
        no_boundary["nodes"][2]["boundary_label"] = "workload"
        cases.append(no_boundary)
        duplicate = component_fixture()
        duplicate["edges"].append(copy.deepcopy(duplicate["edges"][0]))
        cases.append(duplicate)
        unsupported = component_fixture()
        unsupported["edges"][0]["containment_state"] = "probably_effective"
        cases.append(unsupported)
        extra = component_fixture()
        extra["nodes"][0]["surprise"] = "not-allowed"
        cases.append(extra)
        non_native = component_fixture()
        non_native["inventory_complete"] = 1
        cases.append(non_native)
        sequence_type = component_fixture()
        sequence_type["paths"][0]["edge_ids"] = tuple(sequence_type["paths"][0]["edge_ids"])
        cases.append(sequence_type)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_container_boundary_paths(model)

    def test_replay_rejects_mutation_forgery_and_wrong_report_type(self) -> None:
        model = component_fixture()
        report = analyze_supplied_container_boundary_paths(model)
        original = copy.deepcopy(model)
        model["edges"][1]["containment_state"] = "declared_ineffective"
        self.assertEqual(report.to_dict()["source_model"], original)
        with self.assertRaises(ContainerBoundaryPathError):
            verify_supplied_container_boundary_paths(report, model=model)
        with self.assertRaises(ContainerBoundaryPathError):
            verify_supplied_container_boundary_paths(report.to_dict(), model=original)
        forged = report.to_dict()
        forged["finding_claimed"] = True
        with self.assertRaises(ContainerBoundaryPathError):
            verify_supplied_container_boundary_paths_bytes(
                json.dumps(forged).encode("ascii"), model=original
            )

    def test_source_and_report_byte_bounds(self) -> None:
        with self.assertRaises(ValueError):
            analyze_supplied_container_boundary_paths_bytes(model_bytes=b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            analyze_supplied_container_boundary_paths_bytes(model_bytes=b"x" * 65_537)
        with self.assertRaises(ValueError):
            verify_supplied_container_boundary_paths_bytes(
                b"x" * 131_073, model=component_fixture()
            )


if __name__ == "__main__":
    unittest.main()

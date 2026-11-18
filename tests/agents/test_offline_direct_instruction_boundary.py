"""Synthetic direct-instruction boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_direct_instruction_boundary import (
    DirectInstructionBoundaryError,
    DirectInstructionBoundaryReport,
    analyze_supplied_direct_instruction_boundary,
    component_fixture,
    verify_supplied_direct_instruction_boundary,
)


class DirectInstructionBoundaryTests(unittest.TestCase):
    def test_declared_conflict_is_not_jailbreak_proof(self) -> None:
        body = analyze_supplied_direct_instruction_boundary(component_fixture()).to_dict()
        self.assertEqual(body["declared_boundary_conflict_attempt_refs"], ["attempt-opaque-a"])
        self.assertFalse(body["prompt_text_processed"])
        self.assertFalse(body["model_called"])
        self.assertFalse(body["jailbreak_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_unknown_outcome_remains_unknown(self) -> None:
        model = component_fixture()
        model["user_attempts"][0]["outcome_declared"] = "unknown"
        body = analyze_supplied_direct_instruction_boundary(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["declared_boundary_conflict_attempt_refs"], [])

    def test_rejects_duplicate_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["user_attempts"].append(copy.deepcopy(model["user_attempts"][0]))
        with self.assertRaises(DirectInstructionBoundaryError):
            analyze_supplied_direct_instruction_boundary(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(DirectInstructionBoundaryError):
            analyze_supplied_direct_instruction_boundary(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_direct_instruction_boundary(model)
        self.assertEqual(
            verify_supplied_direct_instruction_boundary(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["user_attempts"][0]["outcome_declared"] = "declined"
        with self.assertRaises(DirectInstructionBoundaryError):
            verify_supplied_direct_instruction_boundary(report, model=changed)
        with self.assertRaises(DirectInstructionBoundaryError):
            DirectInstructionBoundaryReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

"""Synthetic eBPF helper policy projection boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ebpf_helper_policy import (
    EbpfHelperPolicyError,
    EbpfHelperPolicyReport,
    analyze_supplied_ebpf_helpers,
    component_fixture,
    verify_supplied_ebpf_helpers,
)


class EbpfHelperPolicyTests(unittest.TestCase):
    def test_helper_gap_is_not_execution(self) -> None:
        report = analyze_supplied_ebpf_helpers(component_fixture()).to_dict()
        self.assertEqual(report["declared_policy_deviation_program_ids"], ["program-a"])
        self.assertEqual(
            report["program_projections"][0]["outside_supplied_policy_helper_ids"],
            ["helper-b"],
        )
        self.assertFalse(report["kernel_connected"])
        self.assertFalse(report["bytecode_parsed"])
        self.assertFalse(report["verifier_invoked"])
        self.assertFalse(report["program_loaded"])
        self.assertEqual(report["candidate_count"], 0)

    def test_allowed_helper_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["programs"][0]["declared_helper_ids"] = ["helper-a"]
        report = analyze_supplied_ebpf_helpers(model).to_dict()
        self.assertEqual(report["declared_policy_deviation_program_ids"], [])
        self.assertEqual(report["disposition"], "unknown")

    def test_rejects_duplicate_missing_policy_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["programs"].append(copy.deepcopy(model["programs"][0]))
        with self.assertRaises(EbpfHelperPolicyError):
            analyze_supplied_ebpf_helpers(model)
        model = component_fixture()
        model["programs"][0]["program_type"] = "network"
        with self.assertRaises(EbpfHelperPolicyError):
            analyze_supplied_ebpf_helpers(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(EbpfHelperPolicyError):
            analyze_supplied_ebpf_helpers(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ebpf_helpers(model)
        self.assertEqual(
            verify_supplied_ebpf_helpers(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["programs"][0]["declared_helper_ids"] = ["helper-a"]
        with self.assertRaises(EbpfHelperPolicyError):
            verify_supplied_ebpf_helpers(report, model=changed)
        with self.assertRaises(EbpfHelperPolicyError):
            EbpfHelperPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

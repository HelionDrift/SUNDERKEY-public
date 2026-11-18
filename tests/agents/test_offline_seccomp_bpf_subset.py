"""A synthetic seccomp classic-BPF subset is projected without execution."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_seccomp_bpf_subset import (
    SeccompBpfSubsetError,
    SeccompBpfSubsetReport,
    analyze_supplied_seccomp_bpf_subset,
    component_fixture,
    verify_supplied_seccomp_bpf_subset,
)


class SeccompBpfSubsetTests(unittest.TestCase):
    def test_sample_actions_are_only_offline_projections(self) -> None:
        body = analyze_supplied_seccomp_bpf_subset(component_fixture()).to_dict()
        actions = {row["case_id"]: row["projected_action"] for row in body["cases"]}
        self.assertEqual(actions, {
            "i386-read": "kill_process",
            "x86-execve": "errno",
            "x86-read": "allow",
        })
        self.assertFalse(body["kernel_behavior_verified"])
        self.assertFalse(body["sandbox_escape_verified"])
        self.assertFalse(body["finding_claimed"])

    def test_out_of_range_jump_and_unknown_opcode_reject(self) -> None:
        model = component_fixture()
        model["instructions"][1]["jf"] = 99
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)
        model = component_fixture()
        model["instructions"][0]["code"] = 0xFF
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)

    def test_unreachable_and_unsupported_return_reject(self) -> None:
        model = component_fixture()
        model["instructions"].append({"code": 0x06, "jt": 0, "jf": 0, "k": 0x7FFF0000})
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)
        model = component_fixture()
        model["instructions"][4]["k"] = 0x7FC00000
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)

    def test_nonsynthetic_and_duplicate_case_reject(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)
        model = component_fixture()
        model["cases"][1]["case_id"] = model["cases"][0]["case_id"]
        with self.assertRaises(SeccompBpfSubsetError):
            analyze_supplied_seccomp_bpf_subset(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_seccomp_bpf_subset(model)
        self.assertEqual(
            verify_supplied_seccomp_bpf_subset(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["cases"][0]["syscall_nr"] = 60
        with self.assertRaises(SeccompBpfSubsetError):
            verify_supplied_seccomp_bpf_subset(report, model=changed)
        with self.assertRaises(SeccompBpfSubsetError):
            SeccompBpfSubsetReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

"""Supplied RISC-V PMP interval projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_riscv_pmp_projection import (
    RiscvPmpProjectionError,
    analyze_supplied_riscv_pmp,
    component_fixture,
    verify_supplied_riscv_pmp,
    verify_supplied_riscv_pmp_bytes,
)


class RiscvPmpProjectionTests(unittest.TestCase):
    def test_supplied_mismatch_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_riscv_pmp(model)
        body = report.to_dict()
        self.assertEqual(body["decisions"][0]["computed_decision"], "allow")
        self.assertEqual(body["candidate_count"], 1)
        self.assertFalse(body["soc_contacted"])
        self.assertFalse(body["hardware_decision_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_riscv_pmp(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_riscv_pmp_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_priority_partial_overlap_and_missing_match(self) -> None:
        model = component_fixture()
        model["entries"].append({
            "entry_id": "pmp1", "priority": 1, "range_start": 0,
            "range_end_exclusive": 16_384, "permissions": ["read", "write"],
        })
        model["accesses"] = [
            {
                "access_id": "partial", "address": 8190, "byte_count": 4,
                "mode": "U", "operation": "write", "expected_decision": "deny",
            },
            {
                "access_id": "absent", "address": 20_000, "byte_count": 4,
                "mode": "S", "operation": "read", "expected_decision": "deny",
            },
        ]
        body = analyze_supplied_riscv_pmp(model).to_dict()
        self.assertEqual([row["computed_decision"] for row in body["decisions"]], ["deny", "deny"])
        self.assertEqual(body["decisions"][0]["matched_entry_id"], "pmp0")
        self.assertIsNone(body["decisions"][1]["matched_entry_id"])
        self.assertEqual(body["candidate_count"], 0)
        model["entries_complete"] = False
        self.assertEqual(analyze_supplied_riscv_pmp(model).to_dict()["disposition"], "unknown")

    def test_rejects_invalid_intervals_and_duplicate_priority(self) -> None:
        model = component_fixture()
        model["entries"][0]["range_end_exclusive"] = 4096
        with self.assertRaises(RiscvPmpProjectionError):
            analyze_supplied_riscv_pmp(model)
        model = component_fixture()
        duplicate = copy.deepcopy(model["entries"][0])
        duplicate["entry_id"] = "pmp1"
        model["entries"].append(duplicate)
        with self.assertRaises(RiscvPmpProjectionError):
            analyze_supplied_riscv_pmp(model)

    def test_replay_rejects_changed_model_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_riscv_pmp(model)
        changed = copy.deepcopy(model)
        changed["accesses"][0]["expected_decision"] = "allow"
        with self.assertRaises(RiscvPmpProjectionError):
            verify_supplied_riscv_pmp(report, model=changed)
        with self.assertRaises(RiscvPmpProjectionError):
            verify_supplied_riscv_pmp(report.to_dict(), model=model)
        with self.assertRaises(RiscvPmpProjectionError):
            verify_supplied_riscv_pmp_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

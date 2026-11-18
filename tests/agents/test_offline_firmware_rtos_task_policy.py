"""Firmware RTOS task policy declaration and original-model replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_firmware_rtos_task_policy import (
    FirmwareRtosTaskPolicyReport,
    analyze_supplied_firmware_rtos_task_policy,
    component_fixture,
    verify_supplied_firmware_rtos_task_policy,
    verify_supplied_firmware_rtos_task_policy_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class FirmwareRtosTaskPolicyTests(unittest.TestCase):
    def test_candidate_negative_and_replay(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-firmware-rtos-task-policy-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_firmware_rtos_task_policy(model)
        body = report.to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(len(body["task_projections"][0]["issues"]), 2)
        self.assertEqual(body["task_projections"][1]["issues"], [])
        self.assertFalse(body["rtos_executed"])
        self.assertFalse(body["isolation_enforced"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_firmware_rtos_task_policy(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_firmware_rtos_task_policy_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_missing_and_invalid_data_fail_closed(self) -> None:
        model = component_fixture()
        model["tasks"][0]["isolation_declared"] = None
        body = analyze_supplied_firmware_rtos_task_policy(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["task_projections"][0]["issues"])
        model = component_fixture()
        report = analyze_supplied_firmware_rtos_task_policy(model)
        changed = copy.deepcopy(model)
        changed["tasks"][0]["declared_priority"] = 10
        with self.assertRaises(ValueError):
            verify_supplied_firmware_rtos_task_policy(report, model=changed)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_rtos_task_policy(report.to_dict(), model=model)
        with self.assertRaises(ValueError):
            verify_supplied_firmware_rtos_task_policy_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            FirmwareRtosTaskPolicyReport({})
        invalid = copy.deepcopy(model)
        invalid["tasks"][0]["declared_priority"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_firmware_rtos_task_policy(invalid)


if __name__ == "__main__":
    unittest.main()

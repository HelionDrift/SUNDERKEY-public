"""Supplied ROS 2 security declaration and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ros2_security_declaration import (
    Ros2SecurityDeclarationError,
    analyze_supplied_ros2_security,
    component_fixture,
    verify_supplied_ros2_security,
    verify_supplied_ros2_security_bytes,
)


class Ros2SecurityDeclarationTests(unittest.TestCase):
    def test_declared_control_gap_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ros2_security(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["deployment_projections"][0]["unmet_control_labels"],
            ["strict_enforcement_disabled"],
        )
        self.assertFalse(body["ros_runtime_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_ros2_security(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_ros2_security_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_complete_controls_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["deployments"][0]["strict_enforcement"] = True
        self.assertEqual(analyze_supplied_ros2_security(model).to_dict()["candidate_count"], 0)
        model["deployments"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_ros2_security(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ros2_security(model)
        changed = copy.deepcopy(model)
        changed["deployments"][0]["allow_unauthenticated_participants"] = True
        with self.assertRaises(Ros2SecurityDeclarationError):
            verify_supplied_ros2_security(report, model=changed)
        with self.assertRaises(Ros2SecurityDeclarationError):
            verify_supplied_ros2_security(report.to_dict(), model=model)
        with self.assertRaises(Ros2SecurityDeclarationError):
            verify_supplied_ros2_security_bytes(b"{}", model=model)

    def test_rejects_duplicate_deployment_and_topic(self) -> None:
        model = component_fixture()
        model["deployments"].append(copy.deepcopy(model["deployments"][0]))
        with self.assertRaises(Ros2SecurityDeclarationError):
            analyze_supplied_ros2_security(model)
        model = component_fixture()
        model["deployments"][0]["protected_topic_ids"].append("motion-command")
        with self.assertRaises(Ros2SecurityDeclarationError):
            analyze_supplied_ros2_security(model)


if __name__ == "__main__":
    unittest.main()

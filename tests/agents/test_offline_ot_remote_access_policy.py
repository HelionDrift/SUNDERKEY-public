"""Supplied OT remote-access policy projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ot_remote_access_policy import (
    OtRemoteAccessPolicyError,
    analyze_supplied_ot_remote_access,
    component_fixture,
    verify_supplied_ot_remote_access,
    verify_supplied_ot_remote_access_bytes,
)


class OtRemoteAccessPolicyTests(unittest.TestCase):
    def test_missing_mfa_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ot_remote_access(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["rows"][0]["missing_required_controls"], ["mfa"])
        self.assertFalse(body["ot_network_contacted"])
        self.assertFalse(body["actual_access_or_session_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_ot_remote_access(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_ot_remote_access_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_controls_actor_duration_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["paths"][0]["controls"].append("mfa")
        self.assertEqual(
            analyze_supplied_ot_remote_access(model).to_dict()["candidate_count"], 0
        )
        model["paths"][0]["session_minutes"] = 120
        body = analyze_supplied_ot_remote_access(model).to_dict()
        self.assertFalse(body["rows"][0]["duration_within_limit"])
        self.assertEqual(body["candidate_count"], 1)
        model["paths"][0]["actor_kind"] = "iiot_gateway"
        self.assertFalse(
            analyze_supplied_ot_remote_access(model).to_dict()["rows"][0]["actor_kind_allowed"]
        )
        model["inventory_complete"] = False
        body = analyze_supplied_ot_remote_access(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)

    def test_rejects_weak_policy_and_duplicate_path(self) -> None:
        model = component_fixture()
        model["policy"]["required_controls"].remove("approved_identity")
        with self.assertRaises(OtRemoteAccessPolicyError):
            analyze_supplied_ot_remote_access(model)
        model = component_fixture()
        model["paths"].append(copy.deepcopy(model["paths"][0]))
        with self.assertRaises(OtRemoteAccessPolicyError):
            analyze_supplied_ot_remote_access(model)
        model = component_fixture()
        model["paths"][0]["controls"].append("unknown_control")
        with self.assertRaises(ValueError):
            analyze_supplied_ot_remote_access(model)

    def test_changed_original_and_forged_wrapper_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ot_remote_access(model)
        changed = copy.deepcopy(model)
        changed["paths"][0]["session_minutes"] = 45
        with self.assertRaises(OtRemoteAccessPolicyError):
            verify_supplied_ot_remote_access(report, model=changed)
        with self.assertRaises(OtRemoteAccessPolicyError):
            verify_supplied_ot_remote_access(report.to_dict(), model=model)
        with self.assertRaises(OtRemoteAccessPolicyError):
            verify_supplied_ot_remote_access_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

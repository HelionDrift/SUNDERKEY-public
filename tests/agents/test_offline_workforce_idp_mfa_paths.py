"""Supplied workforce IdP MFA-path policy and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_workforce_idp_mfa_paths import (
    WorkforceIdpMfaPathError,
    analyze_supplied_workforce_idp_mfa_paths,
    component_fixture,
    verify_supplied_workforce_idp_mfa_paths,
    verify_supplied_workforce_idp_mfa_paths_bytes,
)


class WorkforceIdpMfaPathTests(unittest.TestCase):
    def test_privileged_unprotected_path_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_workforce_idp_mfa_paths(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["application_projections"][0]["enabled_without_declared_mfa_path_ids"],
            ["legacy"],
        )
        self.assertFalse(body["idp_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_workforce_idp_mfa_paths(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_workforce_idp_mfa_paths_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_disabled_path_and_incomplete_policy(self) -> None:
        model = component_fixture()
        model["applications"][0]["sign_in_paths"][1]["enabled"] = False
        self.assertEqual(
            analyze_supplied_workforce_idp_mfa_paths(model).to_dict()["candidate_count"], 0
        )
        model["applications"][0]["policy_complete"] = False
        self.assertEqual(
            analyze_supplied_workforce_idp_mfa_paths(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_workforce_idp_mfa_paths(model)
        changed = copy.deepcopy(model)
        changed["applications"][0]["mfa_required"] = False
        with self.assertRaises(WorkforceIdpMfaPathError):
            verify_supplied_workforce_idp_mfa_paths(report, model=changed)
        with self.assertRaises(WorkforceIdpMfaPathError):
            verify_supplied_workforce_idp_mfa_paths(report.to_dict(), model=model)
        with self.assertRaises(WorkforceIdpMfaPathError):
            verify_supplied_workforce_idp_mfa_paths_bytes(b"{}", model=model)

    def test_rejects_duplicate_application_and_path(self) -> None:
        model = component_fixture()
        model["applications"].append(copy.deepcopy(model["applications"][0]))
        with self.assertRaises(WorkforceIdpMfaPathError):
            analyze_supplied_workforce_idp_mfa_paths(model)
        model = component_fixture()
        model["applications"][0]["sign_in_paths"][1]["path_id"] = "standard"
        with self.assertRaises(WorkforceIdpMfaPathError):
            analyze_supplied_workforce_idp_mfa_paths(model)


if __name__ == "__main__":
    unittest.main()

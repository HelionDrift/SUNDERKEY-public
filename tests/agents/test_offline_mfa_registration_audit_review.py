"""Synthetic MFA audit tests retain identity and method-state uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_mfa_registration_audit_review import (
    MfaRegistrationAuditReviewError,
    MfaRegistrationAuditReviewReport,
    analyze_supplied_mfa_registration_audit,
    component_fixture,
    verify_supplied_mfa_registration_audit,
)


class MfaRegistrationAuditReviewTests(unittest.TestCase):
    def test_declared_success_does_not_validate_registration(self) -> None:
        report = analyze_supplied_mfa_registration_audit(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["declared_result"], "success")
        self.assertTrue(body["actor_matches_supplied_expectation"])
        self.assertTrue(body["target_matches_supplied_expectation"])
        self.assertFalse(body["registration_verified"])
        self.assertFalse(body["help_desk_contact_verified"])
        self.assertFalse(body["mfa_method_control_verified"])
        self.assertNotIn("11111111-1111", report.to_json())

    def test_actor_mismatch_remains_uncertain(self) -> None:
        model = component_fixture()
        model["expected_actor_id"] = "33333333-3333-3333-3333-333333333333"
        body = analyze_supplied_mfa_registration_audit(model).to_dict()
        self.assertFalse(body["actor_matches_supplied_expectation"])
        self.assertEqual(body["candidate_count"], 0)

    def test_unknown_activity_duplicate_target_and_invalid_time_reject(self) -> None:
        model = component_fixture()
        model["directory_audit"]["activityDisplayName"] = "Unknown operation"
        with self.assertRaises(MfaRegistrationAuditReviewError):
            analyze_supplied_mfa_registration_audit(model)
        model = component_fixture()
        model["directory_audit"]["targetResources"] *= 2
        with self.assertRaises(MfaRegistrationAuditReviewError):
            analyze_supplied_mfa_registration_audit(model)
        model = component_fixture()
        model["directory_audit"]["activityDateTime"] = "2026-99-01T00:00:00Z"
        with self.assertRaises(MfaRegistrationAuditReviewError):
            analyze_supplied_mfa_registration_audit(model)
        model = component_fixture()
        model["directory_audit"]["result"] = {"unexpected": "shape"}
        with self.assertRaises(MfaRegistrationAuditReviewError):
            analyze_supplied_mfa_registration_audit(model)

    def test_nonsynthetic_source_rejects(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MfaRegistrationAuditReviewError):
            analyze_supplied_mfa_registration_audit(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mfa_registration_audit(model)
        self.assertEqual(
            verify_supplied_mfa_registration_audit(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["directory_audit"]["result"] = "failure"
        with self.assertRaises(MfaRegistrationAuditReviewError):
            verify_supplied_mfa_registration_audit(report, model=changed)
        with self.assertRaises(MfaRegistrationAuditReviewError):
            MfaRegistrationAuditReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

"""Synthetic email header tests do not upgrade declared results to trust."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_email_auth_results_review import (
    EmailAuthResultsReviewError,
    EmailAuthResultsReviewReport,
    analyze_supplied_email_auth_results,
    component_fixture,
    verify_supplied_email_auth_results,
)


class EmailAuthResultsReviewTests(unittest.TestCase):
    def test_declared_passes_are_not_verified_authentication(self) -> None:
        report = analyze_supplied_email_auth_results(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["method_result_count"], 3)
        self.assertTrue(body["authserv_matches_supplied_expectation"])
        self.assertEqual(
            {row["method"] for row in body["declared_results"]},
            {"spf", "dkim", "dmarc"},
        )
        self.assertFalse(body["mail_authentication_verified"])
        self.assertFalse(body["header_trust_verified"])
        self.assertFalse(body["message_delivered"])
        self.assertNotIn("sender.synthetic.example", report.to_json())

    def test_declared_domain_mismatch_is_not_a_finding(self) -> None:
        model = component_fixture()
        model["expected_origin_domain"] = "other.synthetic.example"
        body = analyze_supplied_email_auth_results(model).to_dict()
        self.assertFalse(
            body["declared_results"][0]["domain_matches_supplied_expectation"]
        )
        self.assertEqual(body["candidate_count"], 0)

    def test_duplicate_method_and_header_injection_reject(self) -> None:
        model = component_fixture()
        model["authentication_results_header"] += (
            "; spf=fail smtp.mailfrom=sender.synthetic.example"
        )
        with self.assertRaises(EmailAuthResultsReviewError):
            analyze_supplied_email_auth_results(model)
        model = component_fixture()
        model["authentication_results_header"] += "\r\nInjected: x"
        with self.assertRaises(EmailAuthResultsReviewError):
            analyze_supplied_email_auth_results(model)

    def test_real_domain_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["authentication_results_header"] = model[
            "authentication_results_header"
        ].replace("sender.synthetic.example", "sender.real.test")
        with self.assertRaises(EmailAuthResultsReviewError):
            analyze_supplied_email_auth_results(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(EmailAuthResultsReviewError):
            analyze_supplied_email_auth_results(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_email_auth_results(model)
        self.assertEqual(
            verify_supplied_email_auth_results(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["expected_origin_domain"] = "other.synthetic.example"
        with self.assertRaises(EmailAuthResultsReviewError):
            verify_supplied_email_auth_results(report, model=changed)
        with self.assertRaises(EmailAuthResultsReviewError):
            EmailAuthResultsReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

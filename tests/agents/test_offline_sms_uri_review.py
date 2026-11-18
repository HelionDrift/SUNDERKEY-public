"""Synthetic SMS URI tests preserve delivery uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_sms_uri_review import (
    SmsUriReviewError,
    SmsUriReviewReport,
    analyze_supplied_sms_uri,
    component_fixture,
    verify_supplied_sms_uri,
)


class SmsUriReviewTests(unittest.TestCase):
    def test_supplied_uri_never_claims_message_delivery(self) -> None:
        report = analyze_supplied_sms_uri(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["recipient_count"], 2)
        self.assertTrue(body["recipients_match_supplied_expectation"])
        self.assertTrue(body["body_present"])
        self.assertFalse(body["message_composed"])
        self.assertFalse(body["message_delivered"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertNotIn("+12025550101", report.to_json())
        self.assertNotIn("Exercise metadata", report.to_json())

    def test_order_mismatch_is_not_a_delivery_finding(self) -> None:
        model = component_fixture()
        model["expected_recipients"].reverse()
        body = analyze_supplied_sms_uri(model).to_dict()
        self.assertFalse(body["recipients_match_supplied_expectation"])
        self.assertFalse(body["message_delivered"])

    def test_duplicate_body_real_number_and_bad_scheme_reject(self) -> None:
        model = component_fixture()
        model["sms_uri"] += "&body=second"
        with self.assertRaises(SmsUriReviewError):
            analyze_supplied_sms_uri(model)
        model = component_fixture()
        model["sms_uri"] = model["sms_uri"].replace("+12025550101", "+12025550223")
        with self.assertRaises(SmsUriReviewError):
            analyze_supplied_sms_uri(model)
        model = component_fixture()
        model["sms_uri"] = model["sms_uri"].replace("sms:", "https:")
        with self.assertRaises(SmsUriReviewError):
            analyze_supplied_sms_uri(model)

    def test_malformed_escapes_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["sms_uri"] = model["sms_uri"].replace("%20", "%ZZ")
        with self.assertRaises(SmsUriReviewError):
            analyze_supplied_sms_uri(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SmsUriReviewError):
            analyze_supplied_sms_uri(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_sms_uri(model)
        self.assertEqual(
            verify_supplied_sms_uri(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["sms_uri"] = changed["sms_uri"].replace("Exercise", "Changed")
        with self.assertRaises(SmsUriReviewError):
            verify_supplied_sms_uri(report, model=changed)
        with self.assertRaises(SmsUriReviewError):
            SmsUriReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

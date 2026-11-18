"""Synthetic consent URI review never asserts identity, grant, or delivery."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_oauth_consent_uri_review import (
    OAuthConsentUriReviewError,
    OAuthConsentUriReviewReport,
    analyze_supplied_oauth_consent_uri,
    component_fixture,
    verify_supplied_oauth_consent_uri,
)


class OAuthConsentUriReviewTests(unittest.TestCase):
    def test_consistent_request_is_not_consent_or_delivery(self) -> None:
        report = analyze_supplied_oauth_consent_uri(component_fixture())
        body = report.to_dict()
        self.assertTrue(body["syntax_and_declared_expectations_match"])
        self.assertEqual(body["requested_scope_count"], 2)
        self.assertTrue(body["explicit_consent_prompt"])
        self.assertFalse(body["application_identity_verified"])
        self.assertFalse(body["consent_granted"])
        self.assertFalse(body["lure_delivered"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertNotIn("synthetic-state-1", report.to_json())

    def test_mismatched_expected_client_and_scopes_remain_unknown(self) -> None:
        model = component_fixture()
        model["expected_client_id"] = "33333333-3333-3333-3333-333333333333"
        model["allowed_scopes"] = ["User.Read"]
        body = analyze_supplied_oauth_consent_uri(model).to_dict()
        self.assertFalse(body["client_id_matches_supplied_expectation"])
        self.assertEqual(body["unlisted_scope_count"], 1)
        self.assertEqual(body["disposition"], "unknown")

    def test_duplicate_query_static_mixing_and_live_redirect_rejected(self) -> None:
        for replacement in (
            "&client_id=33333333-3333-3333-3333-333333333333",
            "&scope=Mail.Read",
        ):
            model = component_fixture()
            model["authorization_uri"] += replacement
            with self.subTest(replacement=replacement), self.assertRaises(
                OAuthConsentUriReviewError
            ):
                analyze_supplied_oauth_consent_uri(model)
        model = component_fixture()
        model["authorization_uri"] = model["authorization_uri"].replace(
            "User.Read%20offline_access", "https%3A%2F%2Fgraph.microsoft.com%2F.default%20User.Read"
        )
        with self.assertRaises(OAuthConsentUriReviewError):
            analyze_supplied_oauth_consent_uri(model)
        model = component_fixture()
        model["expected_redirect_uri"] = "https://real.example.org/callback"
        with self.assertRaises(OAuthConsentUriReviewError):
            analyze_supplied_oauth_consent_uri(model)

    def test_nonsynthetic_source_and_bad_authorization_path_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OAuthConsentUriReviewError):
            analyze_supplied_oauth_consent_uri(model)
        model = component_fixture()
        model["authorization_uri"] = model["authorization_uri"].replace(
            "login.microsoftonline.com", "synthetic.example"
        )
        with self.assertRaises(OAuthConsentUriReviewError):
            analyze_supplied_oauth_consent_uri(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_oauth_consent_uri(model)
        self.assertEqual(
            verify_supplied_oauth_consent_uri(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["allowed_scopes"] = ["User.Read"]
        with self.assertRaises(OAuthConsentUriReviewError):
            verify_supplied_oauth_consent_uri(report, model=changed)
        with self.assertRaises(OAuthConsentUriReviewError):
            OAuthConsentUriReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

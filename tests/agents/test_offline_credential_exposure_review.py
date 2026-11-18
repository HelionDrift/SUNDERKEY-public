"""Opaque exposure review never resolves or validates a credential."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_credential_exposure_review import (
    CredentialExposurePartial,
    CredentialExposurePartialError,
    analyze_supplied_credential_exposure,
    verify_supplied_credential_exposure,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
PRINCIPAL = "principal:sha256:" + "c" * 64
CREDENTIAL = "credential:sha256:" + "d" * 64


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-opaque-credential-exposure-v1",
        "tenant_id": "tenant:fixture",
        "scope_sha256": SCOPE,
        "reviewed_at": "2026-09-23T13:00:00Z",
        "signals": [
            {
                "event_id": "event:one",
                "tenant_id": "tenant:fixture",
                "scope_sha256": SCOPE,
                "principal_ref": PRINCIPAL,
                "credential_ref": CREDENTIAL,
                "feed_ref": "feed:fixture",
                "source_sha256": SOURCE,
                "observed_at": "2026-09-23T12:00:00Z",
                "expires_at": "2026-09-24T12:00:00Z",
                "kind": "breach_correlation",
            }
        ],
        "consents": [
            {
                "tenant_id": "tenant:fixture",
                "scope_sha256": SCOPE,
                "principal_ref": PRINCIPAL,
                "allowed_kinds": ["breach_correlation"],
                "issued_at": "2026-09-23T11:00:00Z",
                "expires_at": "2026-09-24T11:00:00Z",
                "source_sha256": SOURCE,
            }
        ],
    }


class CredentialExposurePartialTests(unittest.TestCase):
    def test_matching_supplied_consent_only_yields_human_review_candidate(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_credential_exposure(model)
        body = report.to_dict()
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["review_plan"]["items"][0]["disposition"], "human_review_candidate")
        self.assertFalse(body["flags"]["consent_authenticated"])
        self.assertFalse(body["flags"]["credential_validity_proven"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(verify_supplied_credential_exposure(report, model=model).to_dict(), body)
        self.assertEqual(model, original)

    def test_missing_consent_and_stale_signal_block_review_candidacy(self):
        model = _model()
        model["consents"] = []
        body = analyze_supplied_credential_exposure(model).to_dict()
        self.assertEqual(
            body["review_plan"]["items"][0]["disposition"], "blocked_missing_current_consent"
        )
        model = _model()
        model["signals"][0]["expires_at"] = "2026-09-23T12:30:00Z"
        body = analyze_supplied_credential_exposure(model).to_dict()
        self.assertEqual(body["review_plan"]["items"][0]["disposition"], "stale_signal")

    def test_plaintext_cross_scope_future_and_tampered_reports_are_refused(self):
        model = _model()
        model["signals"][0]["credential_ref"] = "password123"
        with self.assertRaises(ValueError):
            analyze_supplied_credential_exposure(model)
        model = _model()
        model["signals"][0]["scope_sha256"] = "sha256:" + "e" * 64
        with self.assertRaises(ValueError):
            analyze_supplied_credential_exposure(model)
        model = _model()
        model["signals"][0]["observed_at"] = "2026-09-24T12:00:00Z"
        model["signals"][0]["expires_at"] = "2026-09-25T12:00:00Z"
        with self.assertRaises(ValueError):
            analyze_supplied_credential_exposure(model)
        model = _model()
        model["signals"][0]["secret"] = "forbidden"
        with self.assertRaises(CredentialExposurePartialError):
            analyze_supplied_credential_exposure(model)
        body = analyze_supplied_credential_exposure(_model()).to_dict()
        body["flags"]["compromise_proven"] = True
        with self.assertRaises(CredentialExposurePartialError):
            CredentialExposurePartial(body)
        report = analyze_supplied_credential_exposure(_model())
        model = _model()
        model["consents"] = []
        with self.assertRaises(CredentialExposurePartialError):
            verify_supplied_credential_exposure(report, model=model)


if __name__ == "__main__":
    unittest.main()

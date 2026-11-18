"""Consent-screened, metadata-only credential exposure review."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.credential_exposure_triage import (
    CredentialExposureError,
    CredentialExposureSignal,
    ExposureDisposition,
    ExposureReviewConsent,
    plan_credential_exposure_review,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
PRINCIPAL = "principal:sha256:" + "c" * 64
OTHER_PRINCIPAL = "principal:sha256:" + "d" * 64
CREDENTIAL = "credential:sha256:" + "e" * 64
AT = "2026-09-23T13:00:00Z"


def signal(
    event_id="event:one", *, principal=PRINCIPAL,
    credential=CREDENTIAL, tenant="tenant:one", scope=SCOPE,
    kind="breach_correlation", observed_at="2026-09-23T12:00:00Z",
    expires_at="2026-09-24T12:00:00Z",
):
    return CredentialExposureSignal(
        event_id=event_id, tenant_id=tenant, scope_sha256=scope,
        principal_ref=principal, credential_ref=credential,
        feed_ref="feed:approved", source_sha256=SOURCE,
        observed_at=observed_at, expires_at=expires_at, kind=kind,
    )


def consent(
    *, principal=PRINCIPAL, tenant="tenant:one", scope=SCOPE,
    kinds=("breach_correlation",), issued_at="2026-09-23T11:00:00Z",
    expires_at="2026-09-24T11:00:00Z",
):
    return ExposureReviewConsent(
        tenant_id=tenant, scope_sha256=scope, principal_ref=principal,
        allowed_kinds=kinds, issued_at=issued_at, expires_at=expires_at,
        source_sha256=SOURCE,
    )


def review(signals, consents=(), **changes):
    values = {
        "tenant_id": "tenant:one", "scope_sha256": SCOPE,
        "reviewed_at": AT, "signals": tuple(signals), "consents": tuple(consents),
    }
    values.update(changes)
    return plan_credential_exposure_review(**values)


class CredentialExposureTriageTests(unittest.TestCase):
    def test_current_matching_consent_yields_only_review_candidate(self):
        output = review((signal(),), (consent(),))
        item = output.items[0]
        self.assertEqual(item.disposition, ExposureDisposition.REVIEW_CANDIDATE)
        self.assertEqual(item.matching_consent_sha256, (consent().consent_sha256,))
        self.assertEqual(output.to_dict()["effects"]["login"], "none")
        self.assertEqual(output.to_dict()["effects"]["rotation"], "none")
        self.assertEqual(output.to_dict()["effects"]["secret_resolution"], "none")
        self.assertNotIn("password", str(item.to_dict()))
        detached = output.to_dict()
        detached["effects"]["login"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["login"], "none")

    def test_no_current_matching_consent_blocks_review_candidate(self):
        for current in (
            (),
            (consent(principal=OTHER_PRINCIPAL),),
            (consent(kinds=("reuse_indicator",)),),
            (consent(expires_at="2026-09-23T12:30:00Z"),),
        ):
            with self.subTest(consents=current):
                output = review((signal(),), current)
                self.assertEqual(
                    output.items[0].disposition, ExposureDisposition.CONSENT_MISSING,
                )
                self.assertEqual(output.items[0].matching_consent_sha256, ())

    def test_expired_signal_cannot_become_current_candidate(self):
        output = review(
            (signal(expires_at="2026-09-23T12:30:00Z"),), (consent(),),
        )
        self.assertEqual(output.items[0].disposition, ExposureDisposition.STALE)
        self.assertEqual(output.items[0].matching_consent_sha256, ())

    def test_order_and_duplicate_inputs_are_deterministic(self):
        first = signal("event:first")
        second = signal("event:second", kind="reuse_indicator")
        approved = consent(kinds=("breach_correlation", "reuse_indicator"))
        left = review((first, second, first), (approved, approved))
        right = review((second, first), (approved,))
        self.assertEqual(left.to_dict(), right.to_dict())
        self.assertEqual(len(left.items), 2)

    def test_conflicting_event_evidence_and_scope_fail_closed(self):
        with self.assertRaisesRegex(CredentialExposureError, "conflicting evidence"):
            review((signal(), signal(kind="reuse_indicator")))
        for item in (signal(tenant="tenant:two"), signal(scope="sha256:" + "f" * 64)):
            with self.subTest(signal=item), self.assertRaisesRegex(
                CredentialExposureError, "crosses tenant or scope",
            ):
                review((item,))
        with self.assertRaisesRegex(CredentialExposureError, "crosses tenant or scope"):
            review((signal(),), (consent(tenant="tenant:two"),))

    def test_future_timestamps_and_retention_limits_fail_closed(self):
        with self.assertRaisesRegex(CredentialExposureError, "future-dated"):
            review((signal(observed_at="2026-09-23T14:00:00Z",
                           expires_at="2026-09-24T14:00:00Z"),))
        with self.assertRaisesRegex(CredentialExposureError, "future-dated"):
            review((), (consent(issued_at="2026-09-23T14:00:00Z",
                                expires_at="2026-09-24T14:00:00Z"),))
        with self.assertRaisesRegex(CredentialExposureError, "hard limit"):
            signal(expires_at="2026-11-01T12:00:00Z")
        with self.assertRaisesRegex(CredentialExposureError, "hard limit"):
            consent(expires_at="2027-01-01T11:00:00Z")

    def test_plaintext_or_reusable_secret_input_is_rejected(self):
        for invalid in ("hunter2", "sha256:" + "e" * 64, "credential:password:foo"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                CredentialExposureError, "opaque digest reference",
            ):
                signal(credential=invalid)
        with self.assertRaisesRegex(CredentialExposureError, "opaque digest reference"):
            consent(principal="user@example.com")

    def test_tampering_and_noncanonical_plan_fail_closed(self):
        with self.assertRaisesRegex(CredentialExposureError, "signal_sha256"):
            replace(signal(), kind="reuse_indicator")
        with self.assertRaisesRegex(CredentialExposureError, "consent_sha256"):
            replace(consent(), principal_ref=OTHER_PRINCIPAL)
        output = review((signal(),), (consent(),))
        with self.assertRaisesRegex(CredentialExposureError, "plan_sha256"):
            replace(output, reviewed_at="2026-09-23T13:01:00Z")
        with self.assertRaisesRegex(CredentialExposureError, "review items"):
            replace(output, items=(), plan_sha256="")


if __name__ == "__main__":
    unittest.main()

"""Synthetic SHAKEN claim comparison never authenticates a call."""

from __future__ import annotations

import base64
import copy
import json
import unittest

from sunderkey.offline_passport_claim_review import (
    PassportClaimReviewError,
    PassportClaimReviewReport,
    analyze_supplied_passport_claim,
    component_fixture,
    verify_supplied_passport_claim,
)


def replace_payload(model: dict, payload: dict) -> dict:
    changed = copy.deepcopy(model)
    parts = changed["passport_jws"].split(".")
    parts[1] = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    changed["passport_jws"] = ".".join(parts)
    return changed


class PassportClaimReviewTests(unittest.TestCase):
    def test_matching_claims_do_not_authenticate_call_or_deepfake(self) -> None:
        model = component_fixture()
        body = analyze_supplied_passport_claim(model).to_dict()
        self.assertEqual(body["declared_attestation"], "A")
        self.assertTrue(body["origin_matches_supplied_signaling"])
        self.assertTrue(body["destination_matches_supplied_signaling"])
        self.assertFalse(body["signature_verified"])
        self.assertFalse(body["caller_identity_verified"])
        self.assertFalse(body["deepfake_assessed"])
        self.assertNotIn(model["sip_from_tn"], str(body))

    def test_mismatched_signaling_remains_unknown(self) -> None:
        model = component_fixture()
        model["sip_from_tn"] = "12125550102"
        body = analyze_supplied_passport_claim(model).to_dict()
        self.assertFalse(body["origin_matches_supplied_signaling"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["finding_claimed"])

    def test_duplicate_json_key_and_malformed_signature_reject(self) -> None:
        model = component_fixture()
        parts = model["passport_jws"].split(".")
        parts[1] = base64.urlsafe_b64encode(
            b'{"attest":"A","attest":"B"}'
        ).rstrip(b"=").decode()
        model["passport_jws"] = ".".join(parts)
        with self.assertRaises(PassportClaimReviewError):
            analyze_supplied_passport_claim(model)
        model = component_fixture()
        model["passport_jws"] = model["passport_jws"].rsplit(".", 1)[0] + ".AQ"
        with self.assertRaises(PassportClaimReviewError):
            analyze_supplied_passport_claim(model)

    def test_unknown_attestation_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        payload = {
            "attest": "D",
            "dest": {"tn": ["12125550101"]},
            "iat": 1767225600,
            "orig": {"tn": "12125550100"},
            "origid": "123e4567-e89b-12d3-a456-426655440000",
        }
        with self.assertRaises(PassportClaimReviewError):
            analyze_supplied_passport_claim(replace_payload(model, payload))
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PassportClaimReviewError):
            analyze_supplied_passport_claim(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_passport_claim(model)
        self.assertEqual(
            verify_supplied_passport_claim(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["sip_to_tn"] = "12125550102"
        with self.assertRaises(PassportClaimReviewError):
            verify_supplied_passport_claim(report, model=changed)
        with self.assertRaises(PassportClaimReviewError):
            PassportClaimReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

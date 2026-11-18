"""Offline token-payload parser-view comparison and replay coverage."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_token_payload_views import (
    TokenPayloadViewsError,
    TokenPayloadViewsReport,
    analyze_supplied_token_payload_views,
    component_fixture,
    verify_supplied_token_payload_views,
)


class TokenPayloadViewsTests(unittest.TestCase):
    def test_duplicate_key_sample_is_review_only(self) -> None:
        report = analyze_supplied_token_payload_views(component_fixture()).to_dict()
        self.assertFalse(report["strict_local_decode_accepted"])
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual(report["disposition"], "candidate_declared_token_view_review")
        self.assertFalse(report["signature_verified"])
        self.assertFalse(report["token_accepted_by_target"])
        self.assertFalse(report["qualification_claimed"])
        self.assertNotIn("admin", str(report))

    def test_matching_strict_view_has_no_difference(self) -> None:
        model = component_fixture()
        raw = b'{"sub":"reader"}'
        model["payload_b64url"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        model["parser_views"] = [{
            "parser_id": "strict", "claims": {"sub": "reader"},
        }]
        report = analyze_supplied_token_payload_views(model).to_dict()
        self.assertTrue(report["strict_local_decode_accepted"])
        self.assertEqual(report["signals"], [])
        self.assertEqual(report["disposition"], "no_declared_token_view_difference")

    def test_supplied_view_difference_from_strict_decoder(self) -> None:
        model = component_fixture()
        raw = b'{"sub":"reader"}'
        model["payload_b64url"] = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        report = analyze_supplied_token_payload_views(model).to_dict()
        self.assertIn("declared_view_differs_from_strict_decode", report["signals"])

    def test_absent_views_remain_unknown(self) -> None:
        model = component_fixture()
        model["parser_views"] = []
        report = analyze_supplied_token_payload_views(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["signals"], [])

    def test_rejects_duplicate_parser_or_noncanonical_base64url(self) -> None:
        model = component_fixture()
        model["parser_views"].append(copy.deepcopy(model["parser_views"][0]))
        with self.assertRaises(TokenPayloadViewsError):
            analyze_supplied_token_payload_views(model)
        model = component_fixture()
        model["payload_b64url"] += "="
        with self.assertRaises(TokenPayloadViewsError):
            analyze_supplied_token_payload_views(model)

    def test_rejects_extra_fields_and_nonobject_claims(self) -> None:
        model = component_fixture()
        model["parser_views"][0]["claims"] = ["unexpected"]
        with self.assertRaises(TokenPayloadViewsError):
            analyze_supplied_token_payload_views(model)
        model = component_fixture()
        model["accepted_by_target"] = True
        with self.assertRaises(ValueError):
            analyze_supplied_token_payload_views(model)

    def test_replay_requires_exact_original_model(self) -> None:
        model = component_fixture()
        report = analyze_supplied_token_payload_views(model)
        self.assertEqual(
            verify_supplied_token_payload_views(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["parser_views"][0]["claims"]["sub"] = "other"
        with self.assertRaises(TokenPayloadViewsError):
            verify_supplied_token_payload_views(report, model=changed)
        with self.assertRaises(TokenPayloadViewsError):
            TokenPayloadViewsReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

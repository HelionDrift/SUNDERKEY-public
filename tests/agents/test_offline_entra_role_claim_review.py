"""Supplied Entra role labels never authenticate a token or tenant."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_entra_role_claim_review import (
    EntraRoleClaimReview,
    EntraRoleClaimReviewError,
    analyze_supplied_entra_role_claims,
    verify_supplied_entra_role_claims,
)


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def _numbered_ref(kind: str, index: int) -> str:
    return f"{kind}:sha256:{index:064x}"


def _model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-entra-direct-role-claim-review-v1",
        "tenant_ref": _ref("tenant", "a"),
        "assignments": [
            {
                "assignment_id": "a1",
                "subject_ref": _ref("subject", "b"),
                "resource_ref": _ref("resource", "c"),
                "role_ref": _ref("role", "d"),
                "active": True,
            },
            {
                "assignment_id": "a2",
                "subject_ref": _ref("subject", "b"),
                "resource_ref": _ref("resource", "c"),
                "role_ref": _ref("role", "e"),
                "active": False,
            },
        ],
        "observations": [
            {
                "token_ref": _ref("token", "f"),
                "declared_tenant_ref": _ref("tenant", "a"),
                "subject_ref": _ref("subject", "b"),
                "resource_ref": _ref("resource", "c"),
                "role_refs": [_ref("role", "d"), _ref("role", "e")],
            },
            {
                "token_ref": _ref("token", "1"),
                "declared_tenant_ref": _ref("tenant", "2"),
                "subject_ref": _ref("subject", "b"),
                "resource_ref": _ref("resource", "c"),
                "role_refs": [],
            },
            {
                "token_ref": _ref("token", "3"),
                "declared_tenant_ref": _ref("tenant", "a"),
                "subject_ref": _ref("subject", "b"),
                "resource_ref": _ref("resource", "c"),
                "role_refs": [],
            },
        ],
    }


class EntraRoleClaimReviewTests(unittest.TestCase):
    def test_direct_assignment_and_claim_differences_remain_review_signals(self):
        model = _model()
        original = copy.deepcopy(model)
        report = analyze_supplied_entra_role_claims(model)
        rows = report.to_dict()["observations"]
        self.assertEqual(rows[0]["claimed_without_supplied_direct_assignment"], [_ref("role", "e")])
        self.assertEqual(rows[0]["assigned_but_not_claimed"], [])
        self.assertFalse(rows[0]["declared_tenant_mismatch"])
        self.assertEqual(rows[0]["comparison_status"], "compared_supplied_direct_assignments")
        self.assertEqual(rows[1]["assigned_but_not_claimed"], [])
        self.assertTrue(rows[1]["declared_tenant_mismatch"])
        self.assertEqual(rows[1]["comparison_status"], "withheld_tenant_mismatch")
        self.assertEqual(rows[2]["assigned_but_not_claimed"], [_ref("role", "d")])
        self.assertFalse(report.to_dict()["flags"]["token_signature_or_issuer_verified"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_entra_role_claims(report, model=model).to_json(), report.to_json()
        )

    def test_advertised_observation_and_role_bounds_have_bounded_report(self):
        model = _model()
        model["observations"] = [
            {
                **model["observations"][0],
                "token_ref": _numbered_ref("token", index),
                "role_refs": [_numbered_ref("role", role) for role in range(16)],
            }
            for index in range(128)
        ]
        report = analyze_supplied_entra_role_claims(model)
        self.assertEqual(len(report.to_dict()["observations"]), 128)
        self.assertLessEqual(len(report.to_json()), 1_048_576)

    def test_plain_subject_duplicate_assignment_non_native_and_tamper_are_refused(self):
        model = _model()
        model["assignments"][0]["subject_ref"] = "real-user"
        with self.assertRaises(EntraRoleClaimReviewError):
            analyze_supplied_entra_role_claims(model)
        model = _model()
        model["assignments"][0]["active"] = 1
        with self.assertRaises(EntraRoleClaimReviewError):
            analyze_supplied_entra_role_claims(model)
        model = _model()
        model["assignments"][1]["assignment_id"] = "a1"
        with self.assertRaises(EntraRoleClaimReviewError):
            analyze_supplied_entra_role_claims(model)
        model = _model()
        model["observations"][0]["role_refs"][0] = object()
        with self.assertRaises(EntraRoleClaimReviewError):
            analyze_supplied_entra_role_claims(model)
        body = analyze_supplied_entra_role_claims(_model()).to_dict()
        body["flags"]["effective_access_proven"] = True
        with self.assertRaises(EntraRoleClaimReviewError):
            EntraRoleClaimReview(body)
        report = analyze_supplied_entra_role_claims(_model())
        changed = _model()
        changed["assignments"][0]["active"] = False
        with self.assertRaises(EntraRoleClaimReviewError):
            verify_supplied_entra_role_claims(report, model=changed)


if __name__ == "__main__":
    unittest.main()

"""Bounded Kerberos AD declaration comparison tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_kerberos_ad_declarations import (
    KerberosAdDeclarationsError,
    analyze_supplied_kerberos_ad,
    component_fixture,
    verify_supplied_kerberos_ad,
    verify_supplied_kerberos_ad_bytes,
)


class KerberosAdDeclarationsTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_declaration_mismatch(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        report = analyze_supplied_kerberos_ad(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertIn("spn_declared_for_multiple_accounts", body["rows"][0]["policy_issues"])
        self.assertIn(
            "unconstrained_delegation_outside_supplied_policy",
            body["rows"][0]["policy_issues"],
        )
        self.assertFalse(body["ticket_or_authentication_observed"])
        self.assertFalse(body["effective_access_or_exploitability_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        self.assertEqual(
            verify_supplied_kerberos_ad(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_kerberos_ad_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_clean_and_incomplete_models(self) -> None:
        model = component_fixture()
        model["services"][1]["spn_refs"] = ["spn:sha256:" + "f" * 64]
        model["services"][0]["delegation_mode"] = "none"
        model["services"][0]["encryption_labels"] = ["aes256"]
        self.assertEqual(analyze_supplied_kerberos_ad(model).to_dict()["candidate_count"], 0)
        model["inventory_complete"] = False
        model["services"][0]["delegation_mode"] = "unconstrained"
        body = analyze_supplied_kerberos_ad(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 2)
        self.assertIsNone(body["rows"][0]["policy_issues"])

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        model["services"][0]["account_ref"] = "Administrator"
        with self.assertRaises(ValueError):
            analyze_supplied_kerberos_ad(model)
        model = component_fixture()
        model["services"].append(copy.deepcopy(model["services"][0]))
        with self.assertRaises(ValueError):
            analyze_supplied_kerberos_ad(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_kerberos_ad(model)
        model = component_fixture()
        report = analyze_supplied_kerberos_ad(model)
        changed = copy.deepcopy(model)
        changed["policy"]["forbid_unconstrained_delegation"] = False
        with self.assertRaises(KerberosAdDeclarationsError):
            verify_supplied_kerberos_ad(report, model=changed)
        with self.assertRaises(KerberosAdDeclarationsError):
            verify_supplied_kerberos_ad(report.to_dict(), model=model)
        with self.assertRaises(KerberosAdDeclarationsError):
            verify_supplied_kerberos_ad_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_kerberos_ad_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()

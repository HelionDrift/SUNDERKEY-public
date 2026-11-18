"""Supplied EVM principal boundary and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_evm_origin_authorization import (
    EvmOriginAuthorizationError,
    analyze_supplied_evm_origin_authorization,
    component_fixture,
    verify_supplied_evm_origin_authorization,
    verify_supplied_evm_origin_authorization_bytes,
)


class EvmOriginAuthorizationTests(unittest.TestCase):
    def test_origin_gate_with_different_caller_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_evm_origin_authorization(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertTrue(body["check_projections"][0]["origin_differs_from_caller"])
        self.assertFalse(body["solidity_parsed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_evm_origin_authorization(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_evm_origin_authorization_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_same_principal_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["checks"][0]["immediate_caller_id"] = "user-one"
        self.assertEqual(
            analyze_supplied_evm_origin_authorization(model).to_dict()["candidate_count"], 0
        )
        model["checks"][0]["context_complete"] = False
        self.assertEqual(
            analyze_supplied_evm_origin_authorization(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_evm_origin_authorization(model)
        changed = copy.deepcopy(model)
        changed["checks"][0]["authorization_source"] = "immediate_caller"
        with self.assertRaises(EvmOriginAuthorizationError):
            verify_supplied_evm_origin_authorization(report, model=changed)
        with self.assertRaises(EvmOriginAuthorizationError):
            verify_supplied_evm_origin_authorization(report.to_dict(), model=model)
        with self.assertRaises(EvmOriginAuthorizationError):
            verify_supplied_evm_origin_authorization_bytes(b"{}", model=model)

    def test_rejects_duplicate_and_unknown_source(self) -> None:
        model = component_fixture()
        model["checks"][1]["check_id"] = "origin-check"
        with self.assertRaises(EvmOriginAuthorizationError):
            analyze_supplied_evm_origin_authorization(model)
        model = component_fixture()
        model["checks"][0]["authorization_source"] = "untrusted_label"
        with self.assertRaises(ValueError):
            analyze_supplied_evm_origin_authorization(model)


if __name__ == "__main__":
    unittest.main()

"""Supplied managed-service grant scope and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_managed_paas_grant_scope import (
    ManagedPaasGrantScopeError,
    analyze_supplied_managed_paas_grants,
    component_fixture,
    verify_supplied_managed_paas_grants,
    verify_supplied_managed_paas_grants_bytes,
)


class ManagedPaasGrantScopeTests(unittest.TestCase):
    def test_broader_grant_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_managed_paas_grants(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["service_projections"][0]["broader_grant_ids"], ["grant-broad"])
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_managed_paas_grants(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_managed_paas_grants_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_inactive_grant_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["services"][0]["grants"][0]["active"] = False
        self.assertEqual(
            analyze_supplied_managed_paas_grants(model).to_dict()["candidate_count"], 0
        )
        model["services"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_managed_paas_grants(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_managed_paas_grants(model)
        changed = copy.deepcopy(model)
        changed["services"][0]["grants"][0]["granted_scope"] = "resource"
        with self.assertRaises(ManagedPaasGrantScopeError):
            verify_supplied_managed_paas_grants(report, model=changed)
        with self.assertRaises(ManagedPaasGrantScopeError):
            verify_supplied_managed_paas_grants(report.to_dict(), model=model)
        with self.assertRaises(ManagedPaasGrantScopeError):
            verify_supplied_managed_paas_grants_bytes(b"{}", model=model)

    def test_rejects_duplicate_service_and_grant(self) -> None:
        model = component_fixture()
        model["services"].append(copy.deepcopy(model["services"][0]))
        with self.assertRaises(ManagedPaasGrantScopeError):
            analyze_supplied_managed_paas_grants(model)
        model = component_fixture()
        model["services"][0]["grants"][1]["grant_id"] = "grant-broad"
        with self.assertRaises(ManagedPaasGrantScopeError):
            analyze_supplied_managed_paas_grants(model)


if __name__ == "__main__":
    unittest.main()

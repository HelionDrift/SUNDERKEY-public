"""Bounded enterprise SaaS delegation projection and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_enterprise_saas_admin_delegation import (
    EnterpriseSaasAdminError,
    analyze_supplied_enterprise_saas_admin,
    component_fixture,
    verify_supplied_enterprise_saas_admin,
    verify_supplied_enterprise_saas_admin_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class EnterpriseSaasAdminTests(unittest.TestCase):
    def test_candidate_and_inert_fixture(self) -> None:
        model = component_fixture()
        example = json.loads(
            (ROOT / "examples/offline-enterprise-saas-admin-delegation-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_enterprise_saas_admin(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["delegation_projections"][0]["disposition"],
            "candidate_declared_admin_delegation_gap",
        )
        self.assertFalse(body["saas_queried"])
        self.assertFalse(body["effective_access_verified"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_enterprise_saas_admin(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_enterprise_saas_admin_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_unknown(self) -> None:
        model = component_fixture()
        model["external_privileged_delegation_allowed"] = True
        self.assertEqual(
            analyze_supplied_enterprise_saas_admin(model).to_dict()["candidate_count"], 0
        )
        model["external_privileged_delegation_allowed"] = False
        model["delegations"][0]["principal_scope"] = "unknown"
        body = analyze_supplied_enterprise_saas_admin(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        model["delegations"][0]["principal_scope"] = "external"
        model["delegations"][0]["context_complete"] = False
        self.assertEqual(
            analyze_supplied_enterprise_saas_admin(model).to_dict()["unknown_count"], 1
        )
        model["delegations"][0]["context_complete"] = True
        model["delegations"][0]["active"] = False
        self.assertEqual(
            analyze_supplied_enterprise_saas_admin(model).to_dict()["candidate_count"], 0
        )

    def test_malformed_and_replay_refusal(self) -> None:
        model = component_fixture()
        report = analyze_supplied_enterprise_saas_admin(model)
        changed = copy.deepcopy(model)
        changed["external_privileged_delegation_allowed"] = True
        with self.assertRaises(EnterpriseSaasAdminError):
            verify_supplied_enterprise_saas_admin(report, model=changed)
        with self.assertRaises(EnterpriseSaasAdminError):
            verify_supplied_enterprise_saas_admin(report.to_dict(), model=model)
        with self.assertRaises(EnterpriseSaasAdminError):
            verify_supplied_enterprise_saas_admin_bytes(b"{}", model=model)
        duplicate = copy.deepcopy(model)
        duplicate["delegations"][1]["delegation_id"] = duplicate["delegations"][0]["delegation_id"]
        with self.assertRaises(EnterpriseSaasAdminError):
            analyze_supplied_enterprise_saas_admin(duplicate)
        with self.assertRaises(ValueError):
            analyze_supplied_enterprise_saas_admin({**model, "product_family": "unknown-provider"})
        with self.assertRaises(ValueError):
            analyze_supplied_enterprise_saas_admin({**model, "unexpected": True})


if __name__ == "__main__":
    unittest.main()

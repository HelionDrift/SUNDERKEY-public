"""Bounded cloud organization support and billing declaration tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_cloud_org_support_billing_boundary import (
    CloudOrgSupportBillingError,
    analyze_supplied_cloud_org_support_billing,
    component_fixture,
    verify_supplied_cloud_org_support_billing,
    verify_supplied_cloud_org_support_billing_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class CloudOrgSupportBillingTests(unittest.TestCase):
    def test_candidate_and_inert_fixture(self) -> None:
        model = component_fixture()
        example = json.loads(
            (
                ROOT / "examples/offline-cloud-org-support-billing-boundary-component.json"
            ).read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        report = analyze_supplied_cloud_org_support_billing(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["access_path_projections"][0]["disposition"], "candidate_declared_approval_gap"
        )
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["billing_action_performed"])
        self.assertFalse(body["support_action_performed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cloud_org_support_billing(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_cloud_org_support_billing_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_unknown(self) -> None:
        model = component_fixture()
        model["access_paths"][0]["approval_recorded"] = True
        self.assertEqual(
            analyze_supplied_cloud_org_support_billing(model).to_dict()["candidate_count"], 0
        )
        model["access_paths"][0]["approval_recorded"] = False
        model["access_paths"][0]["context_complete"] = False
        body = analyze_supplied_cloud_org_support_billing(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        model["access_paths"][0]["context_complete"] = True
        model["access_paths"][0]["active"] = False
        self.assertEqual(
            analyze_supplied_cloud_org_support_billing(model).to_dict()["candidate_count"], 0
        )

    def test_malformed_and_replay_refusal(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cloud_org_support_billing(model)
        changed = copy.deepcopy(model)
        changed["access_paths"][0]["approval_recorded"] = True
        with self.assertRaises(CloudOrgSupportBillingError):
            verify_supplied_cloud_org_support_billing(report, model=changed)
        with self.assertRaises(CloudOrgSupportBillingError):
            verify_supplied_cloud_org_support_billing(report.to_dict(), model=model)
        with self.assertRaises(CloudOrgSupportBillingError):
            verify_supplied_cloud_org_support_billing_bytes(b"{}", model=model)
        duplicate = copy.deepcopy(model)
        duplicate["access_paths"][1]["path_id"] = duplicate["access_paths"][0]["path_id"]
        with self.assertRaises(CloudOrgSupportBillingError):
            analyze_supplied_cloud_org_support_billing(duplicate)
        with self.assertRaises(ValueError):
            analyze_supplied_cloud_org_support_billing({**model, "access_paths": []})
        with self.assertRaises(ValueError):
            analyze_supplied_cloud_org_support_billing({**model, "organization_id": "bad id"})


if __name__ == "__main__":
    unittest.main()

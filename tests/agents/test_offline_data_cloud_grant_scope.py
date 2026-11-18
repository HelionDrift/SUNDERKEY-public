"""Supplied data-cloud grant scope and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_data_cloud_grant_scope import (
    DataCloudGrantScopeError,
    analyze_supplied_data_cloud_grants,
    component_fixture,
    verify_supplied_data_cloud_grants,
    verify_supplied_data_cloud_grants_bytes,
)


class DataCloudGrantScopeTests(unittest.TestCase):
    def test_external_grant_under_deny_policy_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_data_cloud_grants(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["dataset_projections"][0]["mismatched_grant_ids"], ["external-reader"]
        )
        self.assertFalse(body["data_cloud_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_data_cloud_grants(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_data_cloud_grants_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_inactive_grant_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["datasets"][0]["grants"][0]["active"] = False
        self.assertEqual(analyze_supplied_data_cloud_grants(model).to_dict()["candidate_count"], 0)
        model["datasets"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_data_cloud_grants(model).to_dict()["unknown_count"], 1)

    def test_restricted_public_grant_is_mismatch_even_when_external_allowed(self) -> None:
        model = component_fixture()
        dataset = model["datasets"][0]
        dataset["external_sharing_allowed"] = True
        dataset["grants"][0]["recipient_scope"] = "public"
        self.assertEqual(analyze_supplied_data_cloud_grants(model).to_dict()["candidate_count"], 1)

    def test_public_classification_does_not_override_external_deny_policy(self) -> None:
        model = component_fixture()
        dataset = model["datasets"][0]
        dataset["classification"] = "public"
        self.assertEqual(analyze_supplied_data_cloud_grants(model).to_dict()["candidate_count"], 1)
        dataset["external_sharing_allowed"] = True
        self.assertEqual(analyze_supplied_data_cloud_grants(model).to_dict()["candidate_count"], 0)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_data_cloud_grants(model)
        changed = copy.deepcopy(model)
        changed["datasets"][0]["external_sharing_allowed"] = True
        with self.assertRaises(DataCloudGrantScopeError):
            verify_supplied_data_cloud_grants(report, model=changed)
        with self.assertRaises(DataCloudGrantScopeError):
            verify_supplied_data_cloud_grants(report.to_dict(), model=model)
        with self.assertRaises(DataCloudGrantScopeError):
            verify_supplied_data_cloud_grants_bytes(b"{}", model=model)

    def test_rejects_duplicate_dataset_and_grant(self) -> None:
        model = component_fixture()
        model["datasets"].append(copy.deepcopy(model["datasets"][0]))
        with self.assertRaises(DataCloudGrantScopeError):
            analyze_supplied_data_cloud_grants(model)
        model = component_fixture()
        model["datasets"][0]["grants"][1]["grant_id"] = "external-reader"
        with self.assertRaises(DataCloudGrantScopeError):
            analyze_supplied_data_cloud_grants(model)


if __name__ == "__main__":
    unittest.main()

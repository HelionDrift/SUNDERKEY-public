"""Supplied KMS grant separation and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_kms_grant_separation import (
    KmsGrantSeparationError,
    analyze_supplied_kms_grants,
    component_fixture,
    verify_supplied_kms_grants,
    verify_supplied_kms_grants_bytes,
)


class KmsGrantSeparationTests(unittest.TestCase):
    def test_split_grants_for_one_principal_are_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kms_grants(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["key_projections"][0]["overlapping_principal_ids"], ["principal-a"])
        self.assertFalse(body["kms_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_kms_grants(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_kms_grants_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_inactive_grant_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["keys"][0]["grants"][1]["active"] = False
        self.assertEqual(analyze_supplied_kms_grants(model).to_dict()["candidate_count"], 0)
        model["keys"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_kms_grants(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kms_grants(model)
        changed = copy.deepcopy(model)
        changed["keys"][0]["grants"][1]["principal_id"] = "principal-b"
        with self.assertRaises(KmsGrantSeparationError):
            verify_supplied_kms_grants(report, model=changed)
        with self.assertRaises(KmsGrantSeparationError):
            verify_supplied_kms_grants(report.to_dict(), model=model)
        with self.assertRaises(KmsGrantSeparationError):
            verify_supplied_kms_grants_bytes(b"{}", model=model)

    def test_rejects_duplicate_key_and_duplicate_action(self) -> None:
        model = component_fixture()
        model["keys"].append(copy.deepcopy(model["keys"][0]))
        with self.assertRaises(KmsGrantSeparationError):
            analyze_supplied_kms_grants(model)
        model = component_fixture()
        model["keys"][0]["grants"][0]["actions"].append("decrypt")
        with self.assertRaises(KmsGrantSeparationError):
            analyze_supplied_kms_grants(model)


if __name__ == "__main__":
    unittest.main()

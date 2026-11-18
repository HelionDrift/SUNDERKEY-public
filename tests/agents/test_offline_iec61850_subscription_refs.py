"""Supplied IEC 61850 publication references and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_iec61850_subscription_refs import (
    Iec61850SubscriptionRefError,
    analyze_supplied_iec61850_subscriptions,
    component_fixture,
    verify_supplied_iec61850_subscriptions,
    verify_supplied_iec61850_subscriptions_bytes,
)


class Iec61850SubscriptionRefTests(unittest.TestCase):
    def test_dataset_reference_gap_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iec61850_subscriptions(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["subscription_projections"][0]["mismatch"],
            "dataset_reference_mismatch",
        )
        self.assertFalse(body["ied_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_iec61850_subscriptions(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_iec61850_subscriptions_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_matching_and_missing_publication(self) -> None:
        model = component_fixture()
        model["subscriptions"][0]["dataset_id"] = "set-a"
        self.assertEqual(
            analyze_supplied_iec61850_subscriptions(model).to_dict()["candidate_count"], 0
        )
        model["subscriptions"][0]["publication_id"] = "missing"
        self.assertEqual(
            analyze_supplied_iec61850_subscriptions(model).to_dict()["candidate_count"], 1
        )
        model["context_complete"] = False
        self.assertEqual(
            analyze_supplied_iec61850_subscriptions(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_iec61850_subscriptions(model)
        changed = copy.deepcopy(model)
        changed["station_id"] = "other-station"
        with self.assertRaises(Iec61850SubscriptionRefError):
            verify_supplied_iec61850_subscriptions(report, model=changed)
        with self.assertRaises(Iec61850SubscriptionRefError):
            verify_supplied_iec61850_subscriptions(report.to_dict(), model=model)
        with self.assertRaises(Iec61850SubscriptionRefError):
            verify_supplied_iec61850_subscriptions_bytes(b"{}", model=model)

    def test_rejects_duplicate_publication_and_subscription(self) -> None:
        model = component_fixture()
        model["publications"].append(copy.deepcopy(model["publications"][0]))
        with self.assertRaises(Iec61850SubscriptionRefError):
            analyze_supplied_iec61850_subscriptions(model)
        model = component_fixture()
        model["subscriptions"].append(copy.deepcopy(model["subscriptions"][0]))
        with self.assertRaises(Iec61850SubscriptionRefError):
            analyze_supplied_iec61850_subscriptions(model)


if __name__ == "__main__":
    unittest.main()

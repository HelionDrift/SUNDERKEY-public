"""Supplied logging guardrail event and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_cloud_logging_guardrail_timeline import (
    CloudLoggingGuardrailError,
    analyze_supplied_cloud_logging,
    component_fixture,
    verify_supplied_cloud_logging,
    verify_supplied_cloud_logging_bytes,
)


class CloudLoggingGuardrailTests(unittest.TestCase):
    def test_unalerted_disable_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cloud_logging(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["control_projections"][0]["unalerted_disable_event_ids"], ["event-one"]
        )
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cloud_logging(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_cloud_logging_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_recorded_alert_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["controls"][0]["events"][0]["alert_recorded"] = True
        self.assertEqual(analyze_supplied_cloud_logging(model).to_dict()["candidate_count"], 0)
        model["controls"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_cloud_logging(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_cloud_logging(model)
        changed = copy.deepcopy(model)
        changed["controls"][0]["events"][0]["alert_recorded"] = True
        with self.assertRaises(CloudLoggingGuardrailError):
            verify_supplied_cloud_logging(report, model=changed)
        with self.assertRaises(CloudLoggingGuardrailError):
            verify_supplied_cloud_logging(report.to_dict(), model=model)
        with self.assertRaises(CloudLoggingGuardrailError):
            verify_supplied_cloud_logging_bytes(b"{}", model=model)

    def test_rejects_duplicate_position_and_event_id(self) -> None:
        model = component_fixture()
        model["controls"][0]["events"][1]["position"] = 1
        with self.assertRaises(CloudLoggingGuardrailError):
            analyze_supplied_cloud_logging(model)
        model = component_fixture()
        model["controls"][0]["events"][1]["event_id"] = "event-one"
        with self.assertRaises(CloudLoggingGuardrailError):
            analyze_supplied_cloud_logging(model)


if __name__ == "__main__":
    unittest.main()

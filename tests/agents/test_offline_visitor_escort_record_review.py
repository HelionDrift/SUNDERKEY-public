"""Synthetic visitor records cannot establish tailgating or escort presence."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_visitor_escort_record_review import (
    VisitorEscortRecordReviewError,
    VisitorEscortRecordReviewReport,
    analyze_supplied_visitor_escort_records,
    component_fixture,
    verify_supplied_visitor_escort_records,
)


class VisitorEscortRecordReviewTests(unittest.TestCase):
    def test_declared_record_gaps_do_not_prove_physical_entry(self) -> None:
        report = analyze_supplied_visitor_escort_records(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["visitor_record_count"], 2)
        self.assertEqual(body["declared_escort_gap_count"], 1)
        self.assertEqual(body["missing_exit_record_count"], 1)
        self.assertFalse(body["tailgating_observed"])
        self.assertFalse(body["escort_presence_verified"])
        self.assertFalse(body["physical_entry_verified"])
        self.assertNotIn("visitor-01", report.to_json())

    def test_recorded_escort_changes_only_declared_gap(self) -> None:
        model = component_fixture()
        model["visits"][1]["escort_id"] = "escort-02"
        body = analyze_supplied_visitor_escort_records(model).to_dict()
        self.assertEqual(body["declared_escort_gap_count"], 0)
        self.assertFalse(body["escort_presence_verified"])

    def test_duplicate_visitor_bad_chronology_and_bad_entry_reject(self) -> None:
        model = component_fixture()
        model["visits"][1]["visitor_id"] = "visitor-01"
        with self.assertRaises(VisitorEscortRecordReviewError):
            analyze_supplied_visitor_escort_records(model)
        model = component_fixture()
        model["visits"][0]["exit_time_utc"] = "2026-01-01T09:00:00Z"
        with self.assertRaises(VisitorEscortRecordReviewError):
            analyze_supplied_visitor_escort_records(model)
        model = component_fixture()
        model["visits"][0]["entry_id"] = "door-z"
        with self.assertRaises(VisitorEscortRecordReviewError):
            analyze_supplied_visitor_escort_records(model)

    def test_nonsynthetic_source_rejects(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(VisitorEscortRecordReviewError):
            analyze_supplied_visitor_escort_records(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_visitor_escort_records(model)
        self.assertEqual(
            verify_supplied_visitor_escort_records(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["visits"][1]["escort_id"] = "escort-02"
        with self.assertRaises(VisitorEscortRecordReviewError):
            verify_supplied_visitor_escort_records(report, model=changed)
        with self.assertRaises(VisitorEscortRecordReviewError):
            VisitorEscortRecordReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

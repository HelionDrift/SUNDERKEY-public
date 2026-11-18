"""Offline supplied proxy storage-layout regression tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_proxy_storage_layout import (
    ProxyStorageLayoutError,
    analyze_supplied_proxy_storage_layout,
    component_fixture,
    verify_supplied_proxy_storage_layout,
    verify_supplied_proxy_storage_layout_bytes,
)


class ProxyStorageLayoutTests(unittest.TestCase):
    def test_relocated_field_and_new_overlap_are_distinct_candidates(self) -> None:
        model = component_fixture()
        report = analyze_supplied_proxy_storage_layout(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            {row["disposition"] for row in body["field_projections"]},
            {
                "declared_prior_field_preserved",
                "candidate_declared_prior_field_reinterpreted",
                "candidate_declared_new_field_overlap",
            },
        )
        self.assertFalse(body["contract_executed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(
            verify_supplied_proxy_storage_layout(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_proxy_storage_layout_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_append_only_and_incomplete_layouts(self) -> None:
        model = component_fixture()
        model["next_fields"][1]["slot"] = 1
        model["next_fields"][2]["slot"] = 2
        body = analyze_supplied_proxy_storage_layout(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        model["declaration_complete"] = False
        self.assertEqual(analyze_supplied_proxy_storage_layout(model).to_dict()["unknown_count"], 3)
        model = component_fixture()
        model["next_fields"] = model["next_fields"][:1]
        body = analyze_supplied_proxy_storage_layout(model).to_dict()
        self.assertIn(
            "unknown_removed_prior_field", {row["disposition"] for row in body["field_projections"]}
        )

    def test_replay_rejects_changed_layout_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_proxy_storage_layout(model)
        changed = copy.deepcopy(model)
        changed["next_fields"][1]["slot"] = 3
        with self.assertRaises(ProxyStorageLayoutError):
            verify_supplied_proxy_storage_layout(report, model=changed)
        with self.assertRaises(ProxyStorageLayoutError):
            verify_supplied_proxy_storage_layout(report.to_dict(), model=model)
        with self.assertRaises(ProxyStorageLayoutError):
            verify_supplied_proxy_storage_layout_bytes(b"{}", model=model)

    def test_rejects_overlapping_fields_and_boolean_slot(self) -> None:
        model = component_fixture()
        model["next_fields"][2]["slot"] = 0
        with self.assertRaises(ProxyStorageLayoutError):
            analyze_supplied_proxy_storage_layout(model)
        model = component_fixture()
        model["prior_fields"][0]["slot"] = True
        with self.assertRaises(ProxyStorageLayoutError):
            analyze_supplied_proxy_storage_layout(model)


if __name__ == "__main__":
    unittest.main()

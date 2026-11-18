"""Supplied compute ingress scope and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_compute_ingress_scope import (
    ComputeIngressScopeError,
    analyze_supplied_compute_ingress,
    component_fixture,
    verify_supplied_compute_ingress,
    verify_supplied_compute_ingress_bytes,
)


class ComputeIngressScopeTests(unittest.TestCase):
    def test_private_workload_public_ingress_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_compute_ingress(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["workload_projections"][0]["workload_id"], "function-one")
        self.assertFalse(body["provider_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_compute_ingress(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_compute_ingress_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_private_ingress_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["workloads"][0]["ingress_scope"] = "private"
        self.assertEqual(analyze_supplied_compute_ingress(model).to_dict()["candidate_count"], 0)
        model["workloads"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_compute_ingress(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_compute_ingress(model)
        changed = copy.deepcopy(model)
        changed["workloads"][0]["private_only_required"] = False
        with self.assertRaises(ComputeIngressScopeError):
            verify_supplied_compute_ingress(report, model=changed)
        with self.assertRaises(ComputeIngressScopeError):
            verify_supplied_compute_ingress(report.to_dict(), model=model)
        with self.assertRaises(ComputeIngressScopeError):
            verify_supplied_compute_ingress_bytes(b"{}", model=model)

    def test_rejects_duplicate_workload_and_unknown_kind(self) -> None:
        model = component_fixture()
        model["workloads"].append(copy.deepcopy(model["workloads"][0]))
        with self.assertRaises(ComputeIngressScopeError):
            analyze_supplied_compute_ingress(model)
        model = component_fixture()
        model["workloads"][0]["workload_kind"] = "unsupported"
        with self.assertRaises(ValueError):
            analyze_supplied_compute_ingress(model)


if __name__ == "__main__":
    unittest.main()

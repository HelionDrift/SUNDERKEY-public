"""Supplied Kubernetes runtime reconciliation declaration checks."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_kubernetes_runtime_reconciliation import (
    KubernetesRuntimeReconciliationError,
    analyze_supplied_kubernetes_runtime_reconciliation,
    component_fixture,
    verify_supplied_kubernetes_runtime_reconciliation,
    verify_supplied_kubernetes_runtime_reconciliation_bytes,
)


class KubernetesRuntimeReconciliationTests(unittest.TestCase):
    def test_matching_supplied_rows_are_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_runtime_reconciliation(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "supplied_runtime_consistent")
        self.assertEqual(body["desired_workload_count"], 1)
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["workload_rows"][0]["image_match"])
        self.assertFalse(body["cluster_queried"])
        self.assertFalse(body["helm_rendered"])
        self.assertFalse(body["operator_reconciled"])
        self.assertFalse(body["gitops_reconciled"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_kubernetes_runtime_reconciliation(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_kubernetes_runtime_reconciliation_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_supplied_runtime_conflicts_and_missing_rows(self) -> None:
        model = component_fixture()
        model["runtime"][0]["image_digest"] = "sha256:" + "b" * 64
        model["runtime"][0]["revision"] = "revision-2"
        body = analyze_supplied_kubernetes_runtime_reconciliation(model).to_dict()
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(body["disposition"], "candidate_supplied_runtime_mismatch")
        self.assertEqual(
            {row["issue"] for row in body["mismatches"]},
            {"image_digest_mismatch", "revision_mismatch"},
        )
        model["runtime"] = []
        body = analyze_supplied_kubernetes_runtime_reconciliation(model).to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertIsNone(body["workload_rows"][0]["image_match"])
        self.assertIn("runtime_workload_absent", {row["issue"] for row in body["mismatches"]})

    def test_incomplete_inventory_and_missing_revision_stay_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["runtime"][0]["image_digest"] = "sha256:" + "b" * 64
        body = analyze_supplied_kubernetes_runtime_reconciliation(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["mismatches"], [])
        self.assertIsNone(body["workload_rows"][0]["image_match"])
        self.assertIsNone(body["workload_rows"][0]["revision_match"])
        self.assertEqual(body["workload_rows"][0]["status"], "unknown")
        model = component_fixture()
        model["runtime"][0]["revision"] = None
        body = analyze_supplied_kubernetes_runtime_reconciliation(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertIsNone(body["workload_rows"][0]["revision_match"])

    def test_closed_bounds_and_native_types(self) -> None:
        cases = []
        model = component_fixture()
        model["schema_version"] = True
        cases.append(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        cases.append(model)
        model = component_fixture()
        model["desired"][0]["delivery_kind"] = "shell"
        cases.append(model)
        model = component_fixture()
        model["runtime"][0]["image_digest"] = "sha512:abcd"
        cases.append(model)
        model = component_fixture()
        model["desired"][0]["extra"] = "x"
        cases.append(model)
        model = component_fixture()
        model["desired"] *= 65
        cases.append(model)
        model = component_fixture()
        model["runtime"].append(copy.deepcopy(model["runtime"][0]))
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_kubernetes_runtime_reconciliation(model)

    def test_original_replay_rejects_changes_and_forged_exports(self) -> None:
        model = component_fixture()
        report = analyze_supplied_kubernetes_runtime_reconciliation(model)
        changed = copy.deepcopy(model)
        changed["desired"][0]["revision"] = "revision-2"
        with self.assertRaises(KubernetesRuntimeReconciliationError):
            verify_supplied_kubernetes_runtime_reconciliation(report, model=changed)
        with self.assertRaises(KubernetesRuntimeReconciliationError):
            verify_supplied_kubernetes_runtime_reconciliation(report.to_dict(), model=model)
        tampered = report.to_dict()
        tampered["candidate_count"] = 4
        with self.assertRaises(KubernetesRuntimeReconciliationError):
            verify_supplied_kubernetes_runtime_reconciliation_bytes(
                json.dumps(tampered).encode("ascii"), model=model
            )
        duplicated = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_kubernetes_runtime_reconciliation_bytes(
                duplicated.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()

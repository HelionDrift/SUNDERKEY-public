"""Supplied hybrid key-material lineage projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_hybrid_kem_lineage import (
    HybridKemLineageError,
    HybridKemLineageReport,
    analyze_supplied_hybrid_kem_lineage,
    component_fixture,
    verify_supplied_hybrid_kem_lineage,
)


class HybridKemLineageTests(unittest.TestCase):
    def test_both_declared_kinds_reach_final_without_crypto_claim(self) -> None:
        report = analyze_supplied_hybrid_kem_lineage(component_fixture()).to_dict()
        self.assertEqual(report["final_source_kinds"], ["classical", "post_quantum"])
        self.assertEqual(report["final_source_contribution_ids"], ["new_scheme", "traditional"])
        self.assertEqual(report["missing_hybrid_source_kinds"], [])
        self.assertFalse(report["combiner_security_verified"])
        self.assertEqual(report["candidate_count"], 0)

    def test_indirect_and_single_kind_lineages(self) -> None:
        model = component_fixture()
        model["derivations"] = [
            {"material_id": "intermediate", "input_material_ids": ["traditional"]},
            {"material_id": "session", "input_material_ids": ["intermediate"]},
        ]
        report = analyze_supplied_hybrid_kem_lineage(model).to_dict()
        self.assertEqual(report["final_source_contribution_ids"], ["traditional"])
        self.assertEqual(report["missing_hybrid_source_kinds"], ["post_quantum"])
        self.assertEqual(report["structural_disposition"], "single_kind_declared")

    def test_rejects_cycle_and_unresolved_material(self) -> None:
        model = component_fixture()
        model["derivations"] = [
            {"material_id": "session", "input_material_ids": ["other"]},
            {"material_id": "other", "input_material_ids": ["session"]},
        ]
        with self.assertRaises(HybridKemLineageError):
            analyze_supplied_hybrid_kem_lineage(model)
        model = component_fixture()
        model["derivations"][0]["input_material_ids"] = ["absent"]
        with self.assertRaises(HybridKemLineageError):
            analyze_supplied_hybrid_kem_lineage(model)

    def test_incomplete_inventory_and_original_model_replay(self) -> None:
        model = component_fixture()
        model["material_inventory_complete"] = False
        report = analyze_supplied_hybrid_kem_lineage(model)
        self.assertEqual(report.to_dict()["disposition"], "unknown")
        self.assertEqual(
            verify_supplied_hybrid_kem_lineage(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["derivations"][0]["input_material_ids"] = ["traditional"]
        with self.assertRaises(HybridKemLineageError):
            verify_supplied_hybrid_kem_lineage(report, model=changed)
        with self.assertRaises(HybridKemLineageError):
            HybridKemLineageReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

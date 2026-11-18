"""Warehouse lineage labels remain replayable supplied-data hypotheses."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_warehouse_lineage import (
    WarehouseLineage,
    WarehouseLineageError,
    analyze_supplied_warehouse_lineage,
    verify_supplied_warehouse_lineage,
)

ROOT = Path(__file__).resolve().parents[2]


def _ref(kind: str, letter: str) -> str:
    return f"{kind}:sha256:" + letter * 64


def model() -> dict:
    tenant_a = _ref("tenant", "a")
    tenant_b = _ref("tenant", "b")
    region_a = _ref("region", "c")
    region_b = _ref("region", "d")
    datasets = [_ref("dataset", letter) for letter in "1234567"]
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-warehouse-lineage-v1",
        "lineage_complete": False,
        "datasets": [
            {"dataset_ref": datasets[0], "tenant_ref": tenant_a, "region_ref": region_a},
            {"dataset_ref": datasets[1], "tenant_ref": tenant_a, "region_ref": region_a},
            {"dataset_ref": datasets[2], "tenant_ref": tenant_b, "region_ref": region_b},
            {"dataset_ref": datasets[3], "tenant_ref": tenant_a, "region_ref": region_a},
            {"dataset_ref": datasets[4], "tenant_ref": tenant_b, "region_ref": region_a},
            {"dataset_ref": datasets[5], "tenant_ref": tenant_b, "region_ref": region_b},
            {"dataset_ref": datasets[6], "tenant_ref": tenant_a, "region_ref": region_a},
        ],
        "transfers": [
            {
                "transfer_id": "t1",
                "source_dataset_ref": datasets[1],
                "output_dataset_ref": datasets[0],
                "state": "declared_included",
            },
            {
                "transfer_id": "t2",
                "source_dataset_ref": datasets[2],
                "output_dataset_ref": datasets[1],
                "state": "declared_included",
            },
            {
                "transfer_id": "t3",
                "source_dataset_ref": datasets[4],
                "output_dataset_ref": datasets[3],
                "state": "unknown",
            },
            {
                "transfer_id": "t4",
                "source_dataset_ref": datasets[5],
                "output_dataset_ref": datasets[3],
                "state": "declared_excluded",
            },
        ],
        "objectives": [
            {
                "output_dataset_ref": datasets[index],
                "expected_tenant_ref": tenant_a,
                "expected_region_ref": region_a,
            }
            for index in (0, 3, 6)
        ],
    }


class WarehouseLineageTests(unittest.TestCase):
    def test_declared_unknown_and_incomplete_lineage(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_warehouse_lineage(source)
        self.assertEqual(source, original)
        findings = report.to_dict()["findings"]
        self.assertEqual(
            [row["disposition"] for row in findings],
            [
                "declared_lineage_boundary_mismatch",
                "unknown_transfer_policy",
                "unknown_incomplete_lineage",
            ],
        )
        self.assertEqual(findings[0]["mismatched_dimensions"], ["tenant", "region"])
        self.assertEqual(findings[0]["transfer_ids"], ["t2", "t1"])
        self.assertEqual(findings[1]["unknown_transfer_ids"], ["t3"])
        self.assertIsNone(findings[2]["source_dataset_ref"])
        self.assertFalse(report.to_dict()["flags"]["data_movement_observed"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_warehouse_lineage(report, model=source).to_json(),
            report.to_json(),
        )
        source["lineage_complete"] = True
        self.assertEqual(
            analyze_supplied_warehouse_lineage(source).to_dict()["findings"][2][
                "disposition"
            ],
            "no_supplied_mismatch",
        )

    def test_direct_sink_mismatch_and_refusal(self) -> None:
        source = model()
        source["objectives"][0]["expected_tenant_ref"] = _ref("tenant", "b")
        finding = analyze_supplied_warehouse_lineage(source).to_dict()["findings"][0]
        self.assertEqual(finding["source_dataset_ref"], source["datasets"][0]["dataset_ref"])
        self.assertEqual(finding["transfer_ids"], [])
        source = model()
        source["transfers"][0]["source_dataset_ref"] = _ref("dataset", "9")
        with self.assertRaises(WarehouseLineageError):
            analyze_supplied_warehouse_lineage(source)
        source = model()
        source["transfers"][1]["transfer_id"] = "t1"
        with self.assertRaises(WarehouseLineageError):
            analyze_supplied_warehouse_lineage(source)
        source = model()
        source["transfers"][0]["state"] = "executed"
        with self.assertRaises(WarehouseLineageError):
            analyze_supplied_warehouse_lineage(source)
        source = model()
        source["datasets"][0]["region_ref"] = object()
        with self.assertRaises(WarehouseLineageError):
            analyze_supplied_warehouse_lineage(source)

    def test_tampering_or_changed_source_cannot_replace_replay(self) -> None:
        source = model()
        report = analyze_supplied_warehouse_lineage(source)
        tampered = report.to_dict()
        tampered["flags"]["data_movement_observed"] = True
        with self.assertRaises(WarehouseLineageError):
            WarehouseLineage(tampered)
        source["transfers"][0]["state"] = "declared_excluded"
        with self.assertRaises(WarehouseLineageError):
            verify_supplied_warehouse_lineage(report, model=source)

    def test_closed_component_dispatch_and_resource_denial(self) -> None:
        request = components.load_offline_specialist_component_request(
            ROOT / "examples" / "offline-warehouse-lineage-component.json"
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(
            result["analysis"]["findings"][0]["disposition"],
            "declared_lineage_boundary_mismatch",
        )
        self.assertFalse(result["positive_use_approved"])
        self.assertEqual(
            components.verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        request["resources"]["network"] = ["forbidden"]
        with self.assertRaises(components.OfflineSpecialistComponentError):
            components.run_offline_specialist_component(
                request, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()

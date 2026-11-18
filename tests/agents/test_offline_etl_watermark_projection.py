"""Supplied ETL watermarks do not prove pipeline execution or freshness."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_etl_watermark_projection import (
    EtlWatermarkProjection,
    EtlWatermarkProjectionError,
    analyze_supplied_etl_watermarks,
    verify_supplied_etl_watermarks,
)


def _step(letter: str) -> str:
    return "step:sha256:" + letter * 64


def model() -> dict:
    a, b, c = (_step(letter) for letter in "abc")
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-etl-watermarks-v1",
        "steps": [
            {"step_ref": a, "declared_state": "complete", "output_watermark_tick": 9},
            {"step_ref": b, "declared_state": "complete", "output_watermark_tick": 8},
            {"step_ref": c, "declared_state": "pending", "output_watermark_tick": None},
        ],
        "dependencies": [
            {"dependency_id": "d1", "upstream_step_ref": a, "downstream_step_ref": b},
            {"dependency_id": "d2", "upstream_step_ref": b, "downstream_step_ref": c},
        ],
        "objectives": [
            {"step_ref": b, "required_watermark_tick": 7},
            {"step_ref": c, "required_watermark_tick": 7},
            {"step_ref": a, "required_watermark_tick": 10},
        ],
    }


class EtlWatermarkProjectionTests(unittest.TestCase):
    def test_lineage_replay_separates_ready_stale_and_incomplete(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_etl_watermarks(source)
        findings = report.to_dict()["findings"]
        self.assertEqual(source, original)
        self.assertEqual(findings[0]["disposition"], "within_supplied_watermark")
        self.assertEqual(findings[0]["minimum_declared_watermark_tick"], 8)
        self.assertEqual(findings[1]["disposition"], "declared_incomplete_lineage")
        self.assertEqual(findings[1]["blocking_step_refs"], [_step("c")])
        self.assertEqual(findings[2]["disposition"], "below_supplied_watermark")
        self.assertFalse(report.to_dict()["flags"]["pipeline_execution_verified"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_etl_watermarks(report, model=source).to_json(), report.to_json()
        )

    def test_cycle_missing_step_and_state_watermark_mismatch_refused(self) -> None:
        source = model()
        source["dependencies"].append(
            {
                "dependency_id": "d3",
                "upstream_step_ref": _step("c"),
                "downstream_step_ref": _step("a"),
            }
        )
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)
        source = model()
        source["dependencies"][0]["upstream_step_ref"] = _step("d")
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)
        source = model()
        source["steps"][2]["output_watermark_tick"] = 1
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)
        source = model()
        source["steps"][0]["output_watermark_tick"] = True
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)

    def test_duplicate_and_tampered_replay_refused(self) -> None:
        source = model()
        source["dependencies"][1]["dependency_id"] = "d1"
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)
        source = model()
        report = analyze_supplied_etl_watermarks(source)
        tampered = report.to_dict()
        tampered["flags"]["pipeline_execution_verified"] = True
        with self.assertRaises(EtlWatermarkProjectionError):
            EtlWatermarkProjection(tampered)
        source["steps"][0]["output_watermark_tick"] = 10
        with self.assertRaises(EtlWatermarkProjectionError):
            verify_supplied_etl_watermarks(report, model=source)
        source = model()
        source["steps"][0]["step_ref"] = object()
        with self.assertRaises(EtlWatermarkProjectionError):
            analyze_supplied_etl_watermarks(source)


if __name__ == "__main__":
    unittest.main()

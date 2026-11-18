"""MLOps lineage is a bounded supplied stage graph, not an executed pipeline."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_mlops_lineage as analysis

ROOT = Path(__file__).resolve().parents[2]


class MlopsLineageTests(unittest.TestCase):
    def test_fixture_separates_continuity_conflicts_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_mlops_lineage(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 2)
        self.assertEqual(value["unknown_count"], 2)
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["stage_execution_verified"])
        self.assertFalse(value["artifact_bytes_read"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        rows = {row["release_id"]: row for row in value["release_projections"]}
        self.assertEqual(
            rows["clean"]["stage_path"], ["dataset", "training", "package"]
        )
        self.assertEqual(rows["clean"]["risk_reasons"], [])
        self.assertEqual(rows["changed"]["risk_reasons"], ["declared_digest_discontinuity"])
        self.assertEqual(rows["blocked"]["risk_reasons"], ["declared_unapproved_stage"])
        self.assertEqual(rows["unknown"]["disposition"], "unknown")
        self.assertEqual(rows["incomplete"]["disposition"], "unknown")
        self.assertEqual(
            analysis.verify_supplied_mlops_lineage(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_mlops_lineage_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_conflict_under_unknown_approval_remains_unknown(self) -> None:
        model = analysis.component_fixture()
        model["stages"][3]["approval"] = "unknown"
        value = analysis.analyze_supplied_mlops_lineage(model).to_dict()
        rows = {row["release_id"]: row for row in value["release_projections"]}
        self.assertEqual(rows["changed"]["disposition"], "unknown")
        self.assertEqual(rows["changed"]["risk_reasons"], ["declared_digest_discontinuity"])

    def test_invalid_predecessor_root_digest_and_duplicates_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["stages"][0].update(input_sha256="sha256:" + "a" * 64),
            lambda m: m["stages"][1].update(predecessor_stage_id="package"),
            lambda m: m["stages"][1].update(output_sha256="invalid"),
            lambda m: m["stages"].append(copy.deepcopy(m["stages"][0])),
            lambda m: m["releases"].append(copy.deepcopy(m["releases"][0])),
            lambda m: m["releases"][0].update(terminal_stage_id="missing"),
            lambda m: m["stages"][0].update(approval=True),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_mlops_lineage(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_mlops_lineage(model)
        changed = copy.deepcopy(model)
        changed["stages"][2]["approval"] = "denied"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_mlops_lineage(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_mlops_lineage_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-mlops-lineage-component.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(request["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(request["component_id"], analysis.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(request["payload"]["model"], analysis.component_fixture())


if __name__ == "__main__":
    unittest.main()

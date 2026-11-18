"""Separate supplied SAML, DICOM and OCI observations under one unsigned task."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task

ROOT = Path(__file__).resolve().parents[2]


def supplied_task() -> dict:
    # Input order is intentional: the task sorts job identifiers before dispatch.
    selections = (
        ("z-dicom", "offline-dicom-pdv-component.json"),
        ("a-saml", "offline-saml-conditions-component.json"),
        ("m-oci", "offline-oci-blob-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.separate-assertion-pdu-artifact-review",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in selections
        ],
    }


class OfflineSamlDicomTaskIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )

    def run_task(self, model: dict) -> task.OfflineSpecialistTaskResult:
        return task.run_offline_specialist_task(
            model, catalog=self.catalog, repository_root=ROOT
        )

    def test_three_separate_sources_and_commanders_remain_nonoperational(self) -> None:
        model = supplied_task()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        result = report.to_dict()
        self.assertEqual(result["model"], original)
        self.assertEqual(
            tuple(
                result[field]
                for field in ("job_count", "distinct_component_count", "distinct_profile_count")
            ),
            (3, 3, 3),
        )
        self.assertEqual(
            [row["job_id"] for row in result["jobs"]], ["a-saml", "m-oci", "z-dicom"]
        )
        expected = (
            (
                "AOE-GA-D03-S03",
                "AOE-GA-D03-CMD",
                "AOE-HQ-19",
                "saml_supplied_conditions_audience_restrictions",
            ),
            (
                "AOE-GC-D17-S10",
                "AOE-GC-D17-CMD",
                "AOE-HQ-19",
                "oci_supplied_blob_graph_integrity",
            ),
            (
                "AOE-GD-D25-S12",
                "AOE-GD-D25-CMD",
                "AOE-HQ-33",
                "dicom_supplied_pdata_pdv_structure",
            ),
        )
        requests = {row["job_id"]: row["request"] for row in original["jobs"]}
        source_pins = []
        for row, ownership, identity in zip(
            result["jobs"], result["ownership_index"], expected, strict=True
        ):
            profile, commander, validator, component_id = identity
            self.assertEqual(
                tuple(
                    ownership[key]
                    for key in (
                        "profile_id",
                        "commander_profile_id",
                        "independent_validator_id",
                        "component_id",
                    )
                ),
                (profile, commander, validator, component_id),
            )
            self.assertIs(ownership["independent_review_required"], True)
            request = requests[row["job_id"]]
            self.assertEqual(
                row["result"],
                components.run_offline_specialist_component(
                    request, catalog=self.catalog, repository_root=ROOT
                ),
            )
            analysis = row["result"]["analysis"]
            self.assertEqual(analysis["source_model"], request["payload"]["model"])
            source_pins.append(analysis["source_model_sha256"])
        self.assertEqual(len(set(source_pins)), 3)
        self.assertEqual(
            result["jobs"][0]["result"]["analysis"]["analysis_status"],
            "supported_conditions_satisfied",
        )
        self.assertEqual(
            result["jobs"][2]["result"]["analysis"]["analysis_status"],
            "bounded_structure_observed",
        )
        self.assertEqual(
            result["jobs"][2]["result"]["analysis"]["pdu_header"]["pdv_count"], 2
        )
        self.assertEqual(set(result["operational_effects"].values()), {"none"})
        for field in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            self.assertIs(result[field], False)
        self.assertEqual(
            task.verify_offline_specialist_task(
                report, model=original, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "changed-pdu-source"
        self.assertEqual(report.to_dict()["model"], original)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_later_resource_escalation_denies_before_any_leaf_dispatch(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["resources"]["network"] = ["not-authorized"]
        with (
            patch.object(components, "run_offline_specialist_component") as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError),
        ):
            self.run_task(model)
        dispatch.assert_not_called()

    def test_last_malformed_pdu_cannot_publish_partial_task(self) -> None:
        model = supplied_task()
        model["jobs"][0]["request"]["payload"]["model"]["pdu_base64"] = "Tk9U"
        with (
            patch.object(
                components,
                "run_offline_specialist_component",
                wraps=components.run_offline_specialist_component,
            ) as dispatch,
            self.assertRaises(task.OfflineSpecialistTaskError) as caught,
        ):
            self.run_task(model)
        self.assertEqual(dispatch.call_count, 3)
        self.assertIsInstance(caught.exception.__cause__, ValueError)
        self.assertNotIsInstance(caught.exception.__cause__, TypeError)


if __name__ == "__main__":
    unittest.main()

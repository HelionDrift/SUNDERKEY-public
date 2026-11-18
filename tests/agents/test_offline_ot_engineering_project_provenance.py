"""Bounded engineering project provenance declaration and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_ot_engineering_project_provenance import (
    OtEngineeringProjectProvenanceError,
    analyze_supplied_ot_engineering_project_provenance,
    component_fixture,
    verify_supplied_ot_engineering_project_provenance,
    verify_supplied_ot_engineering_project_provenance_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


class OtEngineeringProjectProvenanceTests(unittest.TestCase):
    def test_candidate_is_only_a_supplied_provenance_gap(self) -> None:
        model = component_fixture()
        original = copy.deepcopy(model)
        example = json.loads(
            (ROOT / "examples/offline-ot-engineering-project-provenance-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"], model)
        body = analyze_supplied_ot_engineering_project_provenance(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (1, 0))
        self.assertEqual(len(body["project_projections"][0]["issues"]), 2)
        self.assertFalse(body["workstation_contacted"])
        self.assertFalse(body["deployment_verified"])
        self.assertFalse(body["process_safety_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(model, original)
        report = analyze_supplied_ot_engineering_project_provenance(model)
        self.assertEqual(
            verify_supplied_ot_engineering_project_provenance(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_ot_engineering_project_provenance_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_negative_and_missing_observations_fail_closed(self) -> None:
        model = component_fixture()
        export = model["project_exports"][0]
        export["supplied_package_sha256"] = export["reviewed_package_sha256"]
        export["review_recorded"] = True
        self.assertEqual(
            analyze_supplied_ot_engineering_project_provenance(model).to_dict()["candidate_count"],
            0,
        )
        export["review_recorded"] = None
        body = analyze_supplied_ot_engineering_project_provenance(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 1))
        self.assertIsNone(body["project_projections"][0]["issues"])
        export["review_recorded"] = False
        export["context_complete"] = False
        self.assertEqual(
            analyze_supplied_ot_engineering_project_provenance(model).to_dict()["candidate_count"],
            0,
        )
        export["context_complete"] = True
        model["inventory_complete"] = False
        body = analyze_supplied_ot_engineering_project_provenance(model).to_dict()
        self.assertEqual((body["candidate_count"], body["unknown_count"]), (0, 2))

    def test_malformed_and_tampered_inputs_fail(self) -> None:
        model = component_fixture()
        with self.assertRaises(ValueError):
            analyze_supplied_ot_engineering_project_provenance(
                {**model, "project_exports": tuple(model["project_exports"])}
            )
        with self.assertRaises(ValueError):
            analyze_supplied_ot_engineering_project_provenance({**model, "source_id": None})
        duplicate = copy.deepcopy(model)
        duplicate["project_exports"][1]["project_id"] = duplicate["project_exports"][0][
            "project_id"
        ]
        with self.assertRaises(OtEngineeringProjectProvenanceError):
            analyze_supplied_ot_engineering_project_provenance(duplicate)
        malformed = copy.deepcopy(model)
        malformed["project_exports"][0]["reviewed_package_sha256"] = "sha256:bad"
        with self.assertRaises(OtEngineeringProjectProvenanceError):
            analyze_supplied_ot_engineering_project_provenance(malformed)
        report = analyze_supplied_ot_engineering_project_provenance(model)
        changed = copy.deepcopy(model)
        changed["project_exports"][0]["review_recorded"] = True
        with self.assertRaises(OtEngineeringProjectProvenanceError):
            verify_supplied_ot_engineering_project_provenance(report, model=changed)
        with self.assertRaises(OtEngineeringProjectProvenanceError):
            verify_supplied_ot_engineering_project_provenance(report.to_dict(), model=model)
        with self.assertRaises(OtEngineeringProjectProvenanceError):
            verify_supplied_ot_engineering_project_provenance_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_ot_engineering_project_provenance_bytes(b'{"x":1,"x":2}', model=model)


if __name__ == "__main__":
    unittest.main()

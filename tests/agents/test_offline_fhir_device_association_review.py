"""Synthetic FHIR device relations do not expose a patient or claim a fault."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_fhir_device_association_review import (
    FhirDeviceAssociationReviewError,
    FhirDeviceAssociationReviewReport,
    analyze_supplied_fhir_device_association,
    component_fixture,
    verify_supplied_fhir_device_association,
)


class FhirDeviceAssociationReviewTests(unittest.TestCase):
    def test_matching_synthetic_relation_is_not_clinical_verification(self) -> None:
        model = component_fixture()
        body = analyze_supplied_fhir_device_association(model).to_dict()
        self.assertTrue(body["device_reference_matches_supplied_device"])
        self.assertEqual(body["declared_association_status"], "implanted")
        self.assertFalse(body["patient_association_verified"])
        self.assertFalse(body["device_security_verified"])
        self.assertFalse(body["finding_claimed"])
        self.assertNotIn("Patient/synthetic-001", str(body))

    def test_mismatched_reference_and_inactive_status_are_only_cues(self) -> None:
        model = component_fixture()
        model["association"]["device"]["reference"] = "Device/device-002"
        model["device"]["status"] = "inactive"
        body = analyze_supplied_fhir_device_association(model).to_dict()
        self.assertFalse(body["device_reference_matches_supplied_device"])
        self.assertTrue(body["inactive_device_with_implanted_association_review_cue"])
        self.assertEqual(body["candidate_count"], 0)

    def test_extra_patient_details_and_unknown_status_reject(self) -> None:
        model = component_fixture()
        model["association"]["subject"]["display"] = "Private name"
        with self.assertRaises(ValueError):
            analyze_supplied_fhir_device_association(model)
        model = component_fixture()
        model["association"]["status"]["coding"][0]["code"] = "other"
        with self.assertRaises(FhirDeviceAssociationReviewError):
            analyze_supplied_fhir_device_association(model)

    def test_nonsynthetic_source_rejects(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(FhirDeviceAssociationReviewError):
            analyze_supplied_fhir_device_association(model)

    def test_replay_requires_separate_original(self) -> None:
        model = component_fixture()
        report = analyze_supplied_fhir_device_association(model)
        self.assertEqual(
            verify_supplied_fhir_device_association(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["device"]["status"] = "inactive"
        with self.assertRaises(FhirDeviceAssociationReviewError):
            verify_supplied_fhir_device_association(report, model=changed)
        with self.assertRaises(FhirDeviceAssociationReviewError):
            FhirDeviceAssociationReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

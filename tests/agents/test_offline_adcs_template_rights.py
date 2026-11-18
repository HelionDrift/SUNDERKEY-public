"""Supplied AD CS template-rights projection and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_adcs_template_rights import (
    AdcsTemplateRightsError,
    analyze_supplied_adcs_template_rights,
    component_fixture,
    verify_supplied_adcs_template_rights,
    verify_supplied_adcs_template_rights_bytes,
)


class AdcsTemplateRightsTests(unittest.TestCase):
    def test_mismatch_is_supplied_only_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_adcs_template_rights(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["rows"][1]["policy_issues"],
            [
                "enrollment_principal_outside_supplied_allowlist",
                "required_read_not_declared",
                "required_enroll_not_declared",
            ],
        )
        self.assertFalse(body["effective_enrollment_access_verified"])
        self.assertFalse(body["certificate_issued"])
        self.assertFalse(body["esc_classification_claimed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_adcs_template_rights(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_adcs_template_rights_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_clean_and_incomplete_models(self) -> None:
        model = component_fixture()
        other = model["templates"][0]["principal_rights"][1]["principal_ref"]
        model["templates"][0]["allowed_enrollment_principal_refs"].append(other)
        model["templates"][0]["principal_rights"][1]["allow_right_labels"] = [
            "read", "enroll", "autoenroll"
        ]
        self.assertEqual(
            analyze_supplied_adcs_template_rights(model).to_dict()["candidate_count"], 0
        )
        model["inventory_complete"] = False
        model["templates"][0]["principal_rights"][1]["allow_right_labels"] = [
            "autoenroll"
        ]
        body = analyze_supplied_adcs_template_rights(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["rows"][1]["policy_issues"])
        self.assertEqual(body["rows"][1]["row_disposition"], "unknown_incomplete_inventory")
        self.assertEqual(body["mismatches"], [])

    def test_rejects_undeclared_shapes_and_duplicates(self) -> None:
        model = component_fixture()
        model["templates"][0]["principal_rights"].append(
            copy.deepcopy(model["templates"][0]["principal_rights"][0])
        )
        with self.assertRaises(AdcsTemplateRightsError):
            analyze_supplied_adcs_template_rights(model)
        model = component_fixture()
        model["templates"][0]["principal_rights"][0]["allow_right_labels"].append(
            "write_owner"
        )
        with self.assertRaises(ValueError):
            analyze_supplied_adcs_template_rights(model)
        model = component_fixture()
        model["templates"][0]["principal_rights"][0]["principal_ref"] = "Administrator"
        with self.assertRaises(AdcsTemplateRightsError):
            analyze_supplied_adcs_template_rights(model)
        model = component_fixture()
        model["policy"]["require_read_with_enrollment"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_adcs_template_rights(model)

    def test_changed_original_and_forged_report_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_adcs_template_rights(model)
        changed = copy.deepcopy(model)
        changed["policy"]["require_read_with_enrollment"] = False
        with self.assertRaises(AdcsTemplateRightsError):
            verify_supplied_adcs_template_rights(report, model=changed)
        with self.assertRaises(AdcsTemplateRightsError):
            verify_supplied_adcs_template_rights(report.to_dict(), model=model)
        with self.assertRaises(AdcsTemplateRightsError):
            verify_supplied_adcs_template_rights_bytes(b"{}", model=model)
        with self.assertRaises(ValueError):
            verify_supplied_adcs_template_rights_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )


if __name__ == "__main__":
    unittest.main()

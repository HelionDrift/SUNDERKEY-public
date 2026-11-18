"""Supplied lifecycle consistency, uncertainty, and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_scim_lifecycle as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ScimLifecycleTests(unittest.TestCase):
    def test_fixture_source_addresses_replay_and_effects(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_scim_lifecycle(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GA-D03-S15")
        self.assertEqual(document["capability_id"], "army.ga.d03.s15")
        self.assertEqual(document["vector_id"], "AV-GA-D03-S15-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-lifecycle-model")
        self.assertEqual(document["source"]["before"]["source_id"], "before-snapshot")
        self.assertTrue(document["report_id"].startswith("SLC-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertFalse(document["provider_behavior_verified"])
        self.assertIsNone(document["effective_access_revoked"])
        self.assertEqual(
            analysis.ScimLifecycleReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.ScimLifecycleReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_scim_lifecycle(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["before"]["users"].clear()
        self.assertNotEqual(model, other)

    def test_complete_fixture_candidates_and_non_claims(self):
        document = analysis.analyze_supplied_scim_lifecycle(analysis.component_fixture()).to_dict()
        self.assertEqual(document["analysis_status"], "complete_snapshot_projection")
        self.assertEqual(
            document["orphan_membership_candidates"],
            [{"group_id": "g-review", "user_id": "u-river"}],
        )
        self.assertEqual(
            [row["operation_id"] for row in document["unreflected_deprovision_candidates"]],
            ["disable-alex", "remove-alex"],
        )
        self.assertEqual(
            [row["disposition"] for row in document["operation_outcomes"]],
            ["unreflected_candidate", "no_unreflected_indicator", "unreflected_candidate"],
        )
        self.assertEqual(document["unknowns"], [])
        self.assertFalse(document["provider_behavior_verified"])

    def test_incomplete_snapshots_emit_unknown_not_candidates(self):
        model = analysis.component_fixture()
        model["snapshots_complete"] = False
        document = analysis.analyze_supplied_scim_lifecycle(model).to_dict()
        self.assertEqual(document["analysis_status"], "unknown_incomplete_snapshots")
        self.assertEqual(document["orphan_membership_candidates"], [])
        self.assertEqual(document["unreflected_deprovision_candidates"], [])
        self.assertEqual(
            [row["disposition"] for row in document["operation_outcomes"]],
            ["unknown", "unknown", "unknown"],
        )
        self.assertEqual(len(document["unknowns"]), 4)
        self.assertEqual(document["unknowns"][0]["kind"], "orphan_membership")

    def test_empty_incomplete_scope_still_explicitly_unknown(self):
        model = analysis.component_fixture()
        model["snapshots_complete"] = False
        model["after"]["groups"] = []
        model["deprovision"]["operations"] = []
        document = analysis.analyze_supplied_scim_lifecycle(model).to_dict()
        self.assertEqual(
            document["unknowns"], [{"kind": "snapshot_scope", "reason": "snapshots_incomplete"}]
        )

    def test_no_unreflected_indicator_and_not_present_before(self):
        model = analysis.component_fixture()
        model["after"]["users"][0]["active"] = False
        model["after"]["groups"][0]["members"] = ["u-river"]
        model["deprovision"]["operations"].append(
            {
                "operation_id": "delete-new",
                "kind": "delete_user",
                "user_id": "u-new",
                "group_id": None,
            }
        )
        document = analysis.analyze_supplied_scim_lifecycle(model).to_dict()
        self.assertEqual(document["unreflected_deprovision_candidates"], [])
        self.assertEqual(
            [row["disposition"] for row in document["operation_outcomes"]],
            ["no_unreflected_indicator"] * 3 + ["not_present_in_before_snapshot"],
        )

    def test_remove_membership_checks_group_and_user_exactly(self):
        model = analysis.component_fixture()
        model["before"]["groups"][0]["members"] = ["u-river"]
        document = analysis.analyze_supplied_scim_lifecycle(model).to_dict()
        self.assertEqual(
            document["operation_outcomes"][2]["disposition"],
            "not_present_in_before_snapshot",
        )
        self.assertEqual(
            [row["operation_id"] for row in document["unreflected_deprovision_candidates"]],
            ["disable-alex"],
        )

    def test_exact_opaque_ids_without_directory_normalization(self):
        model = analysis.component_fixture()
        model["after"]["users"][0]["user_id"] = "U-Alex"
        document = analysis.analyze_supplied_scim_lifecycle(model).to_dict()
        self.assertIn(
            {"group_id": "g-review", "user_id": "u-alex"},
            document["orphan_membership_candidates"],
        )
        self.assertNotIn(
            "disable-alex",
            [row["operation_id"] for row in document["unreflected_deprovision_candidates"]],
        )

    def test_duplicate_keys_rejected_in_model_and_report(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace('"active":true', '"active":true,"active":false', 1)
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_scim_lifecycle(model)
        changed = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.ScimLifecycleReport.from_json(changed)

    def test_duplicate_identities_and_invalid_references_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["after"]["users"].append(copy.deepcopy(model["after"]["users"][0]))
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["after"]["groups"].append(copy.deepcopy(model["after"]["groups"][0]))
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["after"]["groups"][0]["members"].append("u-alex")
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["deprovision"]["operations"][1]["operation_id"] = "disable-alex"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["deprovision"]["operations"].append(
            {
                "operation_id": "second-disable",
                "kind": "disable_user",
                "user_id": "u-alex",
                "group_id": None,
            }
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["after"]["source_id"] = model["before"]["source_id"]
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ScimLifecycleError):
                    analysis.analyze_supplied_scim_lifecycle(model)

    def test_unsupported_operation_and_native_types_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["deprovision"]["operations"][0]["kind"] = "revoke_tokens"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["deprovision"]["operations"][0]["group_id"] = "g-review"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["deprovision"]["operations"][2]["group_id"] = None
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["snapshots_complete"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["before"]["users"][0]["active"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["schema_version"] = True
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["extra"] = "unexpected"
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ScimLifecycleError):
                    analysis.analyze_supplied_scim_lifecycle(model)

    def test_bounds_and_bad_bytes_rejected(self):
        model = analysis.component_fixture()
        model["before"]["users"] *= analysis.MAX_USERS
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle(model)
        model = analysis.component_fixture()
        model["deprovision"]["operations"] *= analysis.MAX_OPERATIONS
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle(model)
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.analyze_supplied_scim_lifecycle_bytes(
                model_bytes=b" " * (analysis.MAX_MODEL_BYTES + 1)
            )

    def test_report_tamper_and_external_source_mismatch(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_scim_lifecycle(model)
        changed = report.to_dict()
        changed["effective_access_revoked"] = True
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.ScimLifecycleReport.from_dict(changed)
        changed = report.to_dict()
        changed["orphan_membership_candidates"] = []
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.ScimLifecycleReport.from_json(canonical(changed))
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.ScimLifecycleReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["after"]["users"][0]["active"] = False
        with self.assertRaises(analysis.ScimLifecycleError):
            analysis.verify_supplied_scim_lifecycle(report, model=other)

    def test_no_network_process_or_credential_effect(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_scim_lifecycle(analysis.component_fixture())
            self.assertEqual(report.to_dict()["effects"]["credential_resolution"], "none")


if __name__ == "__main__":
    unittest.main()

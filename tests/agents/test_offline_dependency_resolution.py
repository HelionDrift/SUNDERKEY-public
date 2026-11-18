"""Bounded supplied dependency resolution and replay tests."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_dependency_resolution as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class DependencyResolutionTests(unittest.TestCase):
    def test_fixture_source_address_replay_and_effects(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_dependency_resolution(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GC-D17-S08")
        self.assertEqual(document["capability_id"], "army.gc.d17.s08")
        self.assertEqual(document["vector_id"], "AV-GC-D17-S08-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-resolution-model")
        self.assertEqual(document["source"]["manifest"]["source_id"], "synthetic-manifest")
        self.assertTrue(document["report_id"].startswith("DCR-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertFalse(document["registry_behavior_verified"])
        self.assertIsNone(document["dependency_confusion_verdict"])
        self.assertEqual(
            analysis.DependencyResolutionReport.from_dict(document).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.DependencyResolutionReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_dependency_resolution(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["manifest"]["requirements"].clear()
        self.assertNotEqual(model, other)

    def test_complete_corroborated_cross_registry_candidate(self):
        document = analysis.analyze_supplied_dependency_resolution(
            analysis.component_fixture()
        ).to_dict()
        self.assertEqual(
            document["requirement_outcomes"],
            [{"requirement_id": "dep-widget", "disposition": "collision_candidate"}],
        )
        self.assertEqual(document["unknowns"], [])
        self.assertEqual(document["source_conflicts"], [])
        candidate = document["collision_candidates"][0]
        self.assertEqual(candidate["name"], "widget-core")
        self.assertEqual(candidate["intended_registry_ref"], "internal")
        self.assertEqual(candidate["selected_registry_ref"], "public")
        self.assertEqual(candidate["selected_version"], "2.0")
        self.assertFalse(document["registry_behavior_verified"])

    def test_same_registry_selected_is_not_a_candidate(self):
        model = analysis.component_fixture()
        lock = model["lockfile"]["entries"][0]
        selected = model["resolution"]["records"][0]["selected"]
        lock["version"] = "1.0"
        lock["registry_ref"] = "internal"
        selected["version"] = "1.0"
        selected["registry_ref"] = "internal"
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(document["collision_candidates"], [])
        self.assertEqual(
            document["requirement_outcomes"][0]["disposition"],
            "no_cross_registry_selection",
        )

    def test_incomplete_evidence_stays_unknown(self):
        model = analysis.component_fixture()
        model["evidence_complete"] = False
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(document["collision_candidates"], [])
        self.assertEqual(
            document["requirement_outcomes"][0]["disposition"],
            "unknown_incomplete_evidence",
        )
        self.assertEqual(document["unknowns"][0]["reason"], "evidence_completeness_not_declared")

    def test_uncorroborated_intended_registry_is_unknown(self):
        model = analysis.component_fixture()
        model["resolution"]["records"][0]["available"] = [
            {"name": "widget-core", "version": "2.0", "registry_ref": "public"}
        ]
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(document["collision_candidates"], [])
        self.assertEqual(
            document["requirement_outcomes"][0]["disposition"],
            "unknown_uncorroborated_registry_pair",
        )

    def test_missing_lock_or_resolution_is_unknown(self):
        model = analysis.component_fixture()
        model["lockfile"]["entries"] = []
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(
            document["requirement_outcomes"][0]["disposition"],
            "unknown_missing_lock_entry",
        )
        self.assertEqual(document["collision_candidates"], [])
        model = analysis.component_fixture()
        model["resolution"]["records"] = []
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(document["requirement_outcomes"][0]["disposition"], "unknown_unresolved")
        self.assertEqual(document["collision_candidates"], [])

    def test_lock_resolution_and_available_conflicts_are_not_candidates(self):
        base = analysis.component_fixture()
        variants = []
        model = copy.deepcopy(base)
        model["lockfile"]["entries"][0]["version"] = "3.0"
        variants.append(model)
        model = copy.deepcopy(base)
        model["resolution"]["records"][0]["selected"]["name"] = "other-core"
        variants.append(model)
        model = copy.deepcopy(base)
        model["resolution"]["records"][0]["available"] = [
            {"name": "widget-core", "version": "1.0", "registry_ref": "internal"}
        ]
        variants.append(model)
        for model in variants:
            with self.subTest(model=model):
                document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
                self.assertEqual(document["collision_candidates"], [])
                self.assertEqual(
                    document["requirement_outcomes"][0]["disposition"],
                    "conflicting_source_evidence",
                )
                self.assertEqual(len(document["source_conflicts"]), 1)

    def test_exact_name_only_not_typosquat_distance(self):
        model = analysis.component_fixture()
        model["resolution"]["records"][0]["available"][0]["name"] = "widqet-core"
        document = analysis.analyze_supplied_dependency_resolution(model).to_dict()
        self.assertEqual(document["collision_candidates"], [])
        self.assertEqual(
            document["requirement_outcomes"][0]["disposition"],
            "unknown_uncorroborated_registry_pair",
        )

    def test_duplicate_json_keys_rejected_at_all_levels(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.analyze_supplied_dependency_resolution_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace('"version":"2.0"', '"version":"2.0","version":"3.0"', 1)
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.analyze_supplied_dependency_resolution_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_dependency_resolution(model)
        changed = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.DependencyResolutionReport.from_json(changed)

    def test_duplicate_and_unknown_identities_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["manifest"]["registries"].append("internal")
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["manifest"]["requirements"].append(
            copy.deepcopy(model["manifest"]["requirements"][0])
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["lockfile"]["entries"].append(copy.deepcopy(model["lockfile"]["entries"][0]))
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["resolution"]["records"].append(copy.deepcopy(model["resolution"]["records"][0]))
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["resolution"]["records"][0]["available"].append(
            copy.deepcopy(model["resolution"]["records"][0]["available"][0])
        )
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["manifest"]["requirements"][0]["intended_registry_ref"] = "unknown"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["resolution"]["source_id"] = model["lockfile"]["source_id"]
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.DependencyResolutionError):
                    analysis.analyze_supplied_dependency_resolution(model)

    def test_closed_native_input_and_bounds(self):
        base = analysis.component_fixture()
        bad_models = []
        model = copy.deepcopy(base)
        model["evidence_complete"] = 1
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["schema_version"] = True
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["manifest"]["requirements"][0]["name"] = "Widget-Core"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["lockfile"]["entries"][0]["artifact_sha256"] = "sha256:bad"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["extra"] = "unsupported"
        bad_models.append(model)
        model = copy.deepcopy(base)
        model["manifest"]["requirements"] *= analysis.MAX_REQUIREMENTS + 1
        bad_models.append(model)
        for model in bad_models:
            with self.subTest(model=model):
                with self.assertRaises(analysis.DependencyResolutionError):
                    analysis.analyze_supplied_dependency_resolution(model)
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.analyze_supplied_dependency_resolution_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.analyze_supplied_dependency_resolution_bytes(
                model_bytes=b" " * (analysis.MAX_MODEL_BYTES + 1)
            )

    def test_report_tamper_and_external_source_mismatch(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_dependency_resolution(model)
        changed = report.to_dict()
        changed["registry_behavior_verified"] = True
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.DependencyResolutionReport.from_dict(changed)
        changed = report.to_dict()
        changed["collision_candidates"] = []
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.DependencyResolutionReport.from_json(canonical(changed))
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.DependencyResolutionReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["manifest"]["requirements"][0]["intended_registry_ref"] = "public"
        with self.assertRaises(analysis.DependencyResolutionError):
            analysis.verify_supplied_dependency_resolution(report, model=other)

    def test_no_network_process_package_or_credential_effect(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_dependency_resolution(analysis.component_fixture())
            effects = report.to_dict()["effects"]
            self.assertEqual(effects["credential_resolution"], "none")
            self.assertEqual(effects["package_download"], "none")


if __name__ == "__main__":
    unittest.main()

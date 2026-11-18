"""Bounded supplied build-metadata projection tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

from sunderkey.offline_build_reproducibility import (
    BuildReproducibilityError,
    analyze_supplied_build_reproducibility,
    component_fixture,
    verify_supplied_build_reproducibility,
)

ROOT = Path(__file__).resolve().parents[2]


class BuildReproducibilityTests(unittest.TestCase):
    def test_divergence_is_only_a_supplied_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_build_reproducibility(model).to_dict()
        self.assertEqual(report["disposition"], "candidate_declared_build_review")
        self.assertEqual(report["candidate_count"], 2)
        self.assertTrue(all(
            row["issue"] == "same_declared_inputs_divergent_artifact"
            for row in report["signals"]
        ))
        self.assertFalse(report["build_executed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_matching_digest_has_no_declared_signal(self) -> None:
        model = component_fixture()
        model["runs"][1]["artifact_sha256"] = model["runs"][0]["artifact_sha256"]
        report = analyze_supplied_build_reproducibility(model).to_dict()
        self.assertEqual(report["disposition"], "no_declared_build_review_signal")
        self.assertEqual(report["candidate_count"], 0)

    def test_incomplete_inputs_preserve_unknown_not_divergence(self) -> None:
        model = component_fixture()
        model["runs"][0]["declared_inputs_complete"] = False
        report = analyze_supplied_build_reproducibility(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["candidate_count"], 0)
        self.assertEqual(report["unknown_count"], 1)

    def test_unsandboxed_and_network_flags_are_declarations(self) -> None:
        model = component_fixture()
        model["runs"][1]["artifact_sha256"] = model["runs"][0]["artifact_sha256"]
        model["runs"][0]["sandboxed"] = False
        model["runs"][1]["network_allowed"] = True
        report = analyze_supplied_build_reproducibility(model).to_dict()
        issues = {row["issue"] for row in report["signals"]}
        self.assertEqual(issues, {
            "declared_unsandboxed_build", "declared_build_network_access",
        })

    def test_closed_model_rejects_commands_and_bad_digest(self) -> None:
        model = component_fixture()
        model["runs"][0]["command"] = "not permitted"
        with self.assertRaises(ValueError):
            analyze_supplied_build_reproducibility(model)
        model = component_fixture()
        model["runs"][0]["artifact_sha256"] = "abc"
        with self.assertRaises(BuildReproducibilityError):
            analyze_supplied_build_reproducibility(model)

    def test_duplicate_run_and_boolean_subclass_rejected(self) -> None:
        model = component_fixture()
        model["runs"][1]["run_id"] = "run_a"
        with self.assertRaises(BuildReproducibilityError):
            analyze_supplied_build_reproducibility(model)
        model = component_fixture()
        model["inventory_complete"] = 1
        with self.assertRaises(ValueError):
            analyze_supplied_build_reproducibility(model)

    def test_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_build_reproducibility(model)
        self.assertEqual(
            verify_supplied_build_reproducibility(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        model["runs"][1]["artifact_sha256"] = model["runs"][0]["artifact_sha256"]
        with self.assertRaises(BuildReproducibilityError):
            verify_supplied_build_reproducibility(report, model=model)
        with self.assertRaises(BuildReproducibilityError):
            verify_supplied_build_reproducibility(report.to_dict(), model=component_fixture())

    def test_catalog_dispatch_is_source_bound_and_nonqualifying(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-build-reproducibility-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S09")
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["full_candidate_assembled"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["runs"][1]["artifact_sha256"] = (
            changed["payload"]["model"]["runs"][0]["artifact_sha256"]
        )
        with self.assertRaises(ValueError):
            verify_offline_specialist_component_result(
                result, request=changed, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()

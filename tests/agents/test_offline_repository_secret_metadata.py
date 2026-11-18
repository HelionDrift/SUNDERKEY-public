"""Metadata-only repository and build-log occurrence tests."""

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

from sunderkey.offline_repository_secret_metadata import (
    RepositorySecretMetadataError,
    analyze_supplied_repository_secret_metadata,
    component_fixture,
    verify_supplied_repository_secret_metadata,
)

ROOT = Path(__file__).resolve().parents[2]


class RepositorySecretMetadataTests(unittest.TestCase):
    def test_cross_surface_and_public_flags_are_only_candidates(self) -> None:
        report = analyze_supplied_repository_secret_metadata(component_fixture()).to_dict()
        self.assertEqual(report["disposition"], "candidate_declared_secret_occurrence_review")
        self.assertEqual(report["candidate_count"], 2)
        self.assertEqual({row["issue"] for row in report["signals"]}, {
            "declared_public_unredacted_occurrence",
            "same_opaque_incident_across_declared_surfaces",
        })
        self.assertFalse(report["secret_bytes_read"])
        self.assertFalse(report["secret_validity_verified"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})

    def test_no_review_signal_is_not_absence_proof(self) -> None:
        model = component_fixture()
        model["occurrences"] = [model["occurrences"][0]]
        model["occurrences"][0]["audience"] = "restricted"
        model["occurrences"][0]["rotation_confirmed"] = True
        model["occurrences"][0]["removal_confirmed"] = True
        report = analyze_supplied_repository_secret_metadata(model).to_dict()
        self.assertEqual(report["disposition"], "no_declared_occurrence_review_signal")
        self.assertEqual(report["candidate_count"], 0)

    def test_incomplete_inventory_is_unknown(self) -> None:
        model = component_fixture()
        model["occurrences"] = []
        model["inventory_complete"] = False
        report = analyze_supplied_repository_secret_metadata(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["unknown_count"], 2)

    def test_raw_content_and_unexpected_fields_rejected(self) -> None:
        model = component_fixture()
        model["occurrences"][0]["secret_value"] = "not permitted"
        with self.assertRaises(ValueError):
            analyze_supplied_repository_secret_metadata(model)
        model = component_fixture()
        model["occurrences"][0]["file_path"] = "not permitted"
        with self.assertRaises(ValueError):
            analyze_supplied_repository_secret_metadata(model)

    def test_bad_enum_and_duplicate_occurrence_rejected(self) -> None:
        model = component_fixture()
        model["occurrences"][0]["surface"] = "unknown"
        with self.assertRaises(RepositorySecretMetadataError):
            analyze_supplied_repository_secret_metadata(model)
        model = component_fixture()
        model["occurrences"][1]["occurrence_id"] = "repo_a"
        with self.assertRaises(RepositorySecretMetadataError):
            analyze_supplied_repository_secret_metadata(model)

    def test_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_repository_secret_metadata(model)
        self.assertEqual(
            verify_supplied_repository_secret_metadata(
                report, model=copy.deepcopy(model)
            ).to_json(),
            report.to_json(),
        )
        model["occurrences"][0]["audience"] = "organization"
        with self.assertRaises(RepositorySecretMetadataError):
            verify_supplied_repository_secret_metadata(report, model=model)
        with self.assertRaises(RepositorySecretMetadataError):
            verify_supplied_repository_secret_metadata(
                report.to_dict(), model=component_fixture()
            )

    def test_catalog_dispatch_is_source_bound_and_nonqualifying(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-repository-secret-metadata-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S11")
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["full_candidate_assembled"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["occurrences"][0]["audience"] = "organization"
        with self.assertRaises(ValueError):
            verify_offline_specialist_component_result(
                result, request=changed, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()

"""Exact supplied decision comparison does not prove a target bypass."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_cross_surface_authorization import (
    CrossSurfaceAuthorization,
    CrossSurfaceAuthorizationError,
    analyze_supplied_cross_surface_authorization,
    verify_supplied_cross_surface_authorization,
)

ROOT = Path(__file__).resolve().parents[2]


def model(*, mapping_complete: bool = True) -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-cross-surface-authorization-decisions-v1",
        "source_id": "source.synthetic-1",
        "identity_mapping_complete": mapping_complete,
        "decisions": [
            {
                "decision_id": "d1", "surface_id": "web",
                "principal_ref": "ref:viewer", "action_ref": "ref:read",
                "resource_ref": "ref:record-1", "outcome": "denied",
            },
            {
                "decision_id": "d2", "surface_id": "api",
                "principal_ref": "ref:viewer", "action_ref": "ref:read",
                "resource_ref": "ref:record-1", "outcome": "allowed",
            },
        ],
    }


class CrossSurfaceAuthorizationTests(unittest.TestCase):
    def test_checked_example_uses_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-cross-surface-authorization-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S07")
        self.assertEqual(
            result["analysis"]["comparisons"][0]["disposition"],
            "candidate_declared_decision_difference",
        )
        self.assertFalse(result["analysis"]["flags"]["authorization_bypass_verified"])

    def test_exact_shared_key_difference_is_only_a_candidate(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_cross_surface_authorization(source)
        body = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(body["exact_shared_key_count"], 1)
        self.assertEqual(body["surface_count"], 2)
        self.assertEqual(
            body["comparisons"][0]["disposition"],
            "candidate_declared_decision_difference",
        )
        self.assertFalse(body["flags"]["identity_mapping_verified"])
        self.assertFalse(body["flags"]["target_authorization_verified"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_cross_surface_authorization(report, model=source).to_json(),
            report.to_json(),
        )

    def test_incomplete_mapping_unknown_and_unshared_keys_do_not_promote(self) -> None:
        body = analyze_supplied_cross_surface_authorization(
            model(mapping_complete=False)
        ).to_dict()
        self.assertEqual(
            body["comparisons"][0]["disposition"], "unresolved_identity_mapping"
        )
        source = model()
        source["decisions"][1]["outcome"] = "unknown"
        body = analyze_supplied_cross_surface_authorization(source).to_dict()
        self.assertEqual(body["comparisons"][0]["disposition"], "unresolved_decision")
        source = model()
        source["decisions"][1]["resource_ref"] = "ref:record-2"
        body = analyze_supplied_cross_surface_authorization(source).to_dict()
        self.assertEqual(body["exact_shared_key_count"], 0)

    def test_duplicate_or_unsafe_input_is_refused(self) -> None:
        source = model()
        source["decisions"][1]["surface_id"] = "web"
        with self.assertRaises(CrossSurfaceAuthorizationError):
            analyze_supplied_cross_surface_authorization(source)
        for bad in ([], {}, 1, None):
            source = model()
            source["decisions"][1]["outcome"] = bad
            with self.subTest(bad=bad):
                with self.assertRaises(CrossSurfaceAuthorizationError):
                    analyze_supplied_cross_surface_authorization(source)
        source = model()
        source["network_permission"] = True
        with self.assertRaises(CrossSurfaceAuthorizationError):
            analyze_supplied_cross_surface_authorization(source)
        source = model()
        source["decisions"][0]["principal_ref"] = "actual-secret"
        with self.assertRaises(CrossSurfaceAuthorizationError):
            analyze_supplied_cross_surface_authorization(source)
        source = model()
        source["cycle"] = source
        with self.assertRaises(CrossSurfaceAuthorizationError):
            analyze_supplied_cross_surface_authorization(source)

    def test_tampering_or_alternate_source_is_refused(self) -> None:
        source = model()
        report = analyze_supplied_cross_surface_authorization(source)
        tampered = report.to_dict()
        tampered["comparisons"][0]["disposition"] = "declared_decision_alignment"
        with self.assertRaises(CrossSurfaceAuthorizationError):
            CrossSurfaceAuthorization(tampered)
        alternate = model(mapping_complete=False)
        with self.assertRaises(CrossSurfaceAuthorizationError):
            verify_supplied_cross_surface_authorization(report, model=alternate)
        with self.assertRaises(CrossSurfaceAuthorizationError):
            verify_supplied_cross_surface_authorization(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

"""Supplied development-container boundary projection tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey.offline_devcontainer_boundary import (
    DevcontainerBoundaryError,
    analyze_supplied_devcontainer_boundary,
    component_fixture,
    verify_supplied_devcontainer_boundary,
)
from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    run_offline_specialist_component,
    verify_offline_specialist_component_result,
)

ROOT = Path(__file__).resolve().parents[2]


class DevcontainerBoundaryTests(unittest.TestCase):
    def test_supplied_source_to_host_link_is_replayable_and_nonqualifying(self) -> None:
        model = component_fixture()
        report = analyze_supplied_devcontainer_boundary(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "candidate_declared_source_to_host_boundary")
        self.assertEqual(body["candidate_count"], 3)
        self.assertEqual(
            {row["source"]["kind"] for row in body["declared_links"]},
            {"tag_based_feature_reference", "unreviewed_feature", "unreviewed_hook"},
        )
        self.assertEqual(
            {row["host_boundary"]["kind"] for row in body["declared_links"]},
            {"writable_host_path"},
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        for key in (
            "configuration_parsed",
            "container_started",
            "hook_executed",
            "host_effect_observed",
            "finding_claimed",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertFalse(body[key])
        self.assertEqual(
            verify_supplied_devcontainer_boundary(report, model=model).to_json(),
            report.to_json(),
        )

    def test_disjoint_signals_and_unknown_inputs_do_not_prove_safety(self) -> None:
        model = component_fixture()
        model["mounts"] = []
        body = analyze_supplied_devcontainer_boundary(model).to_dict()
        self.assertEqual(body["disposition"], "declared_review_signal_without_join")
        self.assertEqual(body["candidate_count"], 0)
        model["features"] = []
        model["hooks"] = []
        model["image"]["reviewed"] = True
        model["image"]["reference_kind"] = "digest"
        body = analyze_supplied_devcontainer_boundary(model).to_dict()
        self.assertEqual(body["disposition"], "no_declared_boundary_signal")
        self.assertFalse(body["source_authenticated"])
        model["inventory_complete"] = False
        body = analyze_supplied_devcontainer_boundary(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertIn("incomplete_supplied_inventory", body["uncertainty"])

    def test_multiple_host_boundaries_and_unknown_scope_are_visible(self) -> None:
        model = component_fixture()
        model["privileged"] = True
        model["mounts"].extend(
            [
                {"mount_id": "socket_a", "source_scope": "host_socket", "writable": False},
                {"mount_id": "unknown_a", "source_scope": "unknown", "writable": True},
            ]
        )
        body = analyze_supplied_devcontainer_boundary(model).to_dict()
        self.assertEqual(body["candidate_count"], 9)
        self.assertIn("unknown_mount_scope", body["uncertainty"])
        self.assertEqual(body["unknown_count"], 1)

    def test_bounded_maximum_projection_and_oversized_input(self) -> None:
        model = component_fixture()
        model["image"] = {"reference_kind": "tag", "reviewed": False}
        model["features"] = [
            {"feature_id": f"feature_{index}", "reference_kind": "tag", "reviewed": False}
            for index in range(16)
        ]
        model["hooks"] = [
            {"phase": phase, "declared": True, "reviewed": False}
            for phase in ("onCreate", "updateContent", "postCreate", "postStart", "postAttach")
        ]
        model["mounts"] = [
            {"mount_id": f"mount_{index}", "source_scope": "host_socket", "writable": True}
            for index in range(16)
        ]
        model["privileged"] = True
        report = analyze_supplied_devcontainer_boundary(model)
        self.assertEqual(report.to_dict()["candidate_count"], 663)
        self.assertLess(len(report.to_json().encode("ascii")), 131_072)
        model["features"].append(
            {"feature_id": "too_many", "reference_kind": "tag", "reviewed": False}
        )
        with self.assertRaises(ValueError):
            analyze_supplied_devcontainer_boundary(model)

    def test_raw_values_duplicate_rows_and_native_type_aliases_are_rejected(self) -> None:
        cases = []
        model = component_fixture()
        model["hooks"][0]["command"] = "not accepted"
        cases.append(model)
        model = component_fixture()
        model["mounts"][0]["source"] = "/host/path"
        cases.append(model)
        model = component_fixture()
        model["features"].append(copy.deepcopy(model["features"][0]))
        cases.append(model)
        model = component_fixture()
        model["hooks"].append(copy.deepcopy(model["hooks"][0]))
        cases.append(model)
        model = component_fixture()
        model["hooks"][0] = {"phase": "postCreate", "declared": False, "reviewed": True}
        cases.append(model)
        model = component_fixture()
        model["privileged"] = 1
        cases.append(model)
        model = component_fixture()
        model["schema_version"] = True
        cases.append(model)
        model = component_fixture()
        model["features"][0]["reference_kind"] = "latest-or-maybe"
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_devcontainer_boundary(model)

    def test_original_source_substitution_and_direct_report_forgery_fail(self) -> None:
        model = component_fixture()
        report = analyze_supplied_devcontainer_boundary(model)
        changed = copy.deepcopy(model)
        changed["mounts"][0]["writable"] = False
        with self.assertRaises(DevcontainerBoundaryError):
            verify_supplied_devcontainer_boundary(report, model=changed)
        with self.assertRaises(DevcontainerBoundaryError):
            verify_supplied_devcontainer_boundary(report.to_dict(), model=model)

    def test_catalog_dispatch_preserves_original_request_and_no_positive_use(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-devcontainer-boundary-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
        self.assertEqual(result["component"]["profile_id"], "AOE-GC-D17-S13")
        self.assertFalse(result["positive_use_approved"])
        self.assertFalse(result["full_candidate_assembled"])
        self.assertEqual(
            verify_offline_specialist_component_result(
                result, request=request, catalog=catalog, repository_root=ROOT
            ),
            result,
        )
        changed = copy.deepcopy(request)
        changed["payload"]["model"]["mounts"][0]["writable"] = False
        with self.assertRaises(ValueError):
            verify_offline_specialist_component_result(
                result, request=changed, catalog=catalog, repository_root=ROOT
            )


if __name__ == "__main__":
    unittest.main()

"""Supplied private endpoint path scope and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_private_endpoint_path import (
    PrivateEndpointPathError,
    analyze_supplied_private_endpoint_paths,
    component_fixture,
    verify_supplied_private_endpoint_paths,
    verify_supplied_private_endpoint_paths_bytes,
)


class PrivateEndpointPathTests(unittest.TestCase):
    def test_public_scope_under_private_rule_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_private_endpoint_paths(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertFalse(body["dns_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_private_endpoint_paths(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_private_endpoint_paths_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_private_and_unknown_scopes(self) -> None:
        model = component_fixture()
        model["paths"][0]["dns_target_scope"] = "private"
        self.assertEqual(
            analyze_supplied_private_endpoint_paths(model).to_dict()["candidate_count"], 0
        )
        model["paths"][0]["route_scope"] = "unknown"
        self.assertEqual(
            analyze_supplied_private_endpoint_paths(model).to_dict()["unknown_count"], 1
        )

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_private_endpoint_paths(model)
        changed = copy.deepcopy(model)
        changed["paths"][0]["private_only_required"] = False
        with self.assertRaises(PrivateEndpointPathError):
            verify_supplied_private_endpoint_paths(report, model=changed)
        with self.assertRaises(PrivateEndpointPathError):
            verify_supplied_private_endpoint_paths(report.to_dict(), model=model)
        with self.assertRaises(PrivateEndpointPathError):
            verify_supplied_private_endpoint_paths_bytes(b"{}", model=model)

    def test_rejects_duplicate_path_and_invalid_scope(self) -> None:
        model = component_fixture()
        model["paths"][1]["path_id"] = "path-one"
        with self.assertRaises(PrivateEndpointPathError):
            analyze_supplied_private_endpoint_paths(model)
        model = component_fixture()
        model["paths"][0]["dns_target_scope"] = "other"
        with self.assertRaises(ValueError):
            analyze_supplied_private_endpoint_paths(model)


if __name__ == "__main__":
    unittest.main()

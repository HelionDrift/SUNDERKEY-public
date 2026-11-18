"""Supplied Workspace external sharing policy and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_workspace_external_sharing import (
    WorkspaceExternalSharingError,
    analyze_supplied_workspace_sharing,
    component_fixture,
    verify_supplied_workspace_sharing,
    verify_supplied_workspace_sharing_bytes,
)


class WorkspaceExternalSharingTests(unittest.TestCase):
    def test_external_grant_under_deny_policy_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_workspace_sharing(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["scope_projections"][0]["active_external_grant_ids"], ["grant-one"])
        self.assertFalse(body["workspace_queried"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_workspace_sharing(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_workspace_sharing_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_inactive_grant_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["scopes"][0]["grants"][0]["active"] = False
        self.assertEqual(analyze_supplied_workspace_sharing(model).to_dict()["candidate_count"], 0)
        model["scopes"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_workspace_sharing(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_workspace_sharing(model)
        changed = copy.deepcopy(model)
        changed["scopes"][0]["external_sharing_allowed"] = True
        with self.assertRaises(WorkspaceExternalSharingError):
            verify_supplied_workspace_sharing(report, model=changed)
        with self.assertRaises(WorkspaceExternalSharingError):
            verify_supplied_workspace_sharing(report.to_dict(), model=model)
        with self.assertRaises(WorkspaceExternalSharingError):
            verify_supplied_workspace_sharing_bytes(b"{}", model=model)

    def test_rejects_duplicate_scope_and_duplicate_grant(self) -> None:
        model = component_fixture()
        model["scopes"].append(copy.deepcopy(model["scopes"][0]))
        with self.assertRaises(WorkspaceExternalSharingError):
            analyze_supplied_workspace_sharing(model)
        model = component_fixture()
        model["scopes"][0]["grants"][1]["grant_id"] = "grant-one"
        with self.assertRaises(WorkspaceExternalSharingError):
            analyze_supplied_workspace_sharing(model)


if __name__ == "__main__":
    unittest.main()

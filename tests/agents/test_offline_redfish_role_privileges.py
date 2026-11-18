"""Supplied Redfish role ceilings and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_redfish_role_privileges import (
    RedfishRolePrivilegesError,
    analyze_supplied_redfish_role_privileges,
    component_fixture,
    verify_supplied_redfish_role_privileges,
    verify_supplied_redfish_role_privileges_bytes,
)


class RedfishRolePrivilegesTests(unittest.TestCase):
    def test_excess_grant_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_redfish_role_privileges(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["gaps"][0]["excess_privileges"], ["ConfigureComponents"])
        self.assertFalse(body["bmc_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_redfish_role_privileges(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_redfish_role_privileges_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_allowed_grant_missing_role_and_incomplete_inventory(self) -> None:
        model = component_fixture()
        model["accounts"][0]["allowed_privileges"].append("ConfigureComponents")
        self.assertEqual(
            analyze_supplied_redfish_role_privileges(model).to_dict()["candidate_count"], 0
        )
        model["accounts"][0]["role_id"] = "missing"
        self.assertEqual(
            analyze_supplied_redfish_role_privileges(model).to_dict()["gaps"][0]["issue"],
            "unresolved_role_reference",
        )
        model["inventory_complete"] = False
        self.assertEqual(
            analyze_supplied_redfish_role_privileges(model).to_dict()["unknown_count"], 1
        )

    def test_rejects_duplicate_roles_accounts_and_grants(self) -> None:
        for collection in ("roles", "accounts"):
            model = component_fixture()
            model[collection].append(copy.deepcopy(model[collection][0]))
            with self.subTest(collection=collection), self.assertRaises(RedfishRolePrivilegesError):
                analyze_supplied_redfish_role_privileges(model)
        model = component_fixture()
        model["roles"][0]["assigned_privileges"].append("Login")
        with self.assertRaises(RedfishRolePrivilegesError):
            analyze_supplied_redfish_role_privileges(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_redfish_role_privileges(model)
        changed = copy.deepcopy(model)
        changed["source_id"] = "other"
        with self.assertRaises(RedfishRolePrivilegesError):
            verify_supplied_redfish_role_privileges(report, model=changed)
        with self.assertRaises(RedfishRolePrivilegesError):
            verify_supplied_redfish_role_privileges(report.to_dict(), model=model)
        with self.assertRaises(RedfishRolePrivilegesError):
            verify_supplied_redfish_role_privileges_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

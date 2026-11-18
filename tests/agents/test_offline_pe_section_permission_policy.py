"""Source-bound synthetic PE section-permission policy tests."""

from __future__ import annotations

import base64
import copy
import struct
import unittest

from sunderkey.offline_pe_section_permission_policy import (
    PeSectionPermissionPolicyError,
    PeSectionPermissionPolicyReport,
    analyze_supplied_pe_section_permissions,
    component_fixture,
    verify_supplied_pe_section_permissions,
)


class PeSectionPermissionPolicyTests(unittest.TestCase):
    def test_static_wx_flags_are_not_exploitability(self) -> None:
        model = component_fixture()
        raw = bytearray(base64.b64decode(model["pe_layout_model"]["pe_file_base64"]))
        struct.pack_into("<I", raw, 392 + 36, 0xE0000040)
        model["pe_layout_model"]["pe_file_base64"] = base64.b64encode(raw).decode("ascii")
        body = analyze_supplied_pe_section_permissions(model).to_dict()
        self.assertEqual(body["outside_supplied_policy_section_indexes"], [1])
        self.assertFalse(body["loader_execution_performed"])
        self.assertFalse(body["runtime_permissions_verified"])
        self.assertFalse(body["exploitability_claimed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_base_fixture_has_no_wx_section(self) -> None:
        body = analyze_supplied_pe_section_permissions(component_fixture()).to_dict()
        self.assertEqual(body["outside_supplied_policy_section_indexes"], [])
        self.assertEqual(body["base_pe_source_file_sha256"][:7], "sha256:")

    def test_rejects_nonsynthetic_and_wrong_policy_type(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PeSectionPermissionPolicyError):
            analyze_supplied_pe_section_permissions(model)
        model = component_fixture()
        model["writable_executable_allowed"] = 0
        with self.assertRaises(ValueError):
            analyze_supplied_pe_section_permissions(model)

    def test_original_model_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_pe_section_permissions(model)
        self.assertEqual(
            verify_supplied_pe_section_permissions(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["writable_executable_allowed"] = True
        with self.assertRaises(PeSectionPermissionPolicyError):
            verify_supplied_pe_section_permissions(report, model=changed)
        with self.assertRaises(PeSectionPermissionPolicyError):
            PeSectionPermissionPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

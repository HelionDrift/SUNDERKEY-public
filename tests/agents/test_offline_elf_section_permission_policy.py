"""Source-bound synthetic AArch64 ELF section-permission policy tests."""

from __future__ import annotations

import base64
import copy
import struct
import unittest

from sunderkey.offline_elf_section_permission_policy import (
    ElfSectionPermissionPolicyError,
    ElfSectionPermissionPolicyReport,
    analyze_supplied_elf_section_permissions,
    component_fixture,
    verify_supplied_elf_section_permissions,
)


class ElfSectionPermissionPolicyTests(unittest.TestCase):
    def test_static_allocated_wx_flags_are_not_exploitability(self) -> None:
        model = component_fixture()
        raw = bytearray(base64.b64decode(model["elf_layout_model"]["elf_file_base64"]))
        section_header_offset = int.from_bytes(raw[40:48], "little")
        section_header_size = int.from_bytes(raw[58:60], "little")
        section_one_flags = section_header_offset + section_header_size + 8
        struct.pack_into("<Q", raw, section_one_flags, 0x7)
        model["elf_layout_model"]["elf_file_base64"] = base64.b64encode(raw).decode("ascii")
        body = analyze_supplied_elf_section_permissions(model).to_dict()
        self.assertEqual(body["outside_supplied_policy_section_indexes"], [1])
        self.assertFalse(body["loader_execution_performed"])
        self.assertFalse(body["runtime_permissions_verified"])
        self.assertFalse(body["exploitability_claimed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_fixture_is_aarch64_and_unflagged(self) -> None:
        body = analyze_supplied_elf_section_permissions(component_fixture()).to_dict()
        self.assertEqual(body["outside_supplied_policy_section_indexes"], [])
        self.assertEqual(body["uncertainty"], [])

    def test_machine_mismatch_remains_unknown(self) -> None:
        model = component_fixture()
        raw = bytearray(base64.b64decode(model["elf_layout_model"]["elf_file_base64"]))
        raw[18:20] = (62).to_bytes(2, "little")
        model["elf_layout_model"]["elf_file_base64"] = base64.b64encode(raw).decode("ascii")
        body = analyze_supplied_elf_section_permissions(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_elf_section_permissions(model)
        self.assertEqual(
            verify_supplied_elf_section_permissions(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["allocated_wx_allowed"] = True
        with self.assertRaises(ElfSectionPermissionPolicyError):
            verify_supplied_elf_section_permissions(report, model=changed)
        with self.assertRaises(ElfSectionPermissionPolicyError):
            ElfSectionPermissionPolicyReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

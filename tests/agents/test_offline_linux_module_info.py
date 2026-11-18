"""Source-bound tests for synthetic Linux module-info tag projection."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_linux_module_info import (
    LinuxModuleInfoError,
    LinuxModuleInfoReport,
    analyze_supplied_linux_module_info,
    component_fixture,
    verify_supplied_linux_module_info,
)


class LinuxModuleInfoTests(unittest.TestCase):
    def test_tag_presence_does_not_claim_module_compatibility(self) -> None:
        body = analyze_supplied_linux_module_info(component_fixture()).to_dict()
        self.assertTrue(body["module_info_section_present"])
        self.assertEqual(body["tag_counts"], {"depends": 1, "license": 1, "vermagic": 1})
        self.assertEqual(body["missing_required_tag_ids"], [])
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["kernel_compatibility_verified"])
        self.assertFalse(body["module_loaded"])
        self.assertFalse(body["kernel_exploitability_claimed"])

    def test_missing_required_tag_is_not_a_finding(self) -> None:
        model = component_fixture()
        model["required_tag_ids"].append("name")
        body = analyze_supplied_linux_module_info(model).to_dict()
        self.assertEqual(body["missing_required_tag_ids"], ["name"])
        self.assertFalse(body["finding_claimed"])

    def test_malformed_tag_and_unterminated_record_rejected(self) -> None:
        end = 0x80 + len(b"license=GPL\x00vermagic=synthetic\x00depends=\x00") - 1
        for offset, replacement in ((0x80, ord("L")), (end, ord("X"))):
            with self.subTest(offset=offset):
                model = component_fixture()
                raw = bytearray(base64.b64decode(model["elf_layout_model"]["elf_file_base64"]))
                raw[offset] = replacement
                model["elf_layout_model"]["elf_file_base64"] = base64.b64encode(
                    raw
                ).decode("ascii")
                with self.assertRaises(LinuxModuleInfoError):
                    analyze_supplied_linux_module_info(model)

    def test_duplicate_tag_requirement_and_nonsynthetic_input_rejected(self) -> None:
        model = component_fixture()
        model["required_tag_ids"].append("license")
        with self.assertRaises(LinuxModuleInfoError):
            analyze_supplied_linux_module_info(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(LinuxModuleInfoError):
            analyze_supplied_linux_module_info(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_linux_module_info(model)
        self.assertEqual(
            verify_supplied_linux_module_info(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["required_tag_ids"].append("name")
        with self.assertRaises(LinuxModuleInfoError):
            verify_supplied_linux_module_info(report, model=changed)
        with self.assertRaises(LinuxModuleInfoError):
            LinuxModuleInfoReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

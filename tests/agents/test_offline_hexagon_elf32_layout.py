"""Synthetic Hexagon ELF32 layout tests preserve firmware uncertainty."""

from __future__ import annotations

import base64
import copy
import struct
import unittest

from sunderkey.offline_hexagon_elf32_layout import (
    HexagonElf32LayoutError,
    HexagonElf32LayoutReport,
    analyze_supplied_hexagon_elf32_layout,
    component_fixture,
    verify_supplied_hexagon_elf32_layout,
)


def altered_file(model: dict, offset: int, fmt: str, value: int) -> dict:
    result = copy.deepcopy(model)
    raw = bytearray(base64.b64decode(result["elf_file_base64"]))
    struct.pack_into(fmt, raw, offset, value)
    result["elf_file_base64"] = base64.b64encode(raw).decode("ascii")
    return result


class HexagonElf32LayoutTests(unittest.TestCase):
    def test_bounded_segment_geometry_is_not_firmware_proof(self) -> None:
        body = analyze_supplied_hexagon_elf32_layout(component_fixture()).to_dict()
        self.assertTrue(body["hexagon_machine_marker"])
        self.assertEqual(body["load_segment_count"], 1)
        self.assertEqual(body["segment_observations"][0]["file_offset_hex"], "0x80")
        self.assertTrue(body["segment_observations"][0]["file_extent_bounded"])
        self.assertEqual(body["candidate_count"], 0)
        self.assertFalse(body["baseband_firmware_identity_verified"])
        self.assertFalse(body["firmware_loadability_verified"])
        self.assertFalse(body["exploitability_claimed"])

    def test_machine_mismatch_preserves_uncertainty(self) -> None:
        model = altered_file(component_fixture(), 18, "<H", 62)
        body = analyze_supplied_hexagon_elf32_layout(model).to_dict()
        self.assertFalse(body["hexagon_machine_marker"])
        self.assertIn("machine_not_hexagon", body["uncertainty"])
        self.assertFalse(body["finding_claimed"])

    def test_truncated_extent_and_invalid_alignment_rejected(self) -> None:
        model = altered_file(component_fixture(), 56, "<I", 252)
        with self.assertRaises(HexagonElf32LayoutError):
            analyze_supplied_hexagon_elf32_layout(model)
        model = altered_file(component_fixture(), 80, "<I", 3)
        with self.assertRaises(HexagonElf32LayoutError):
            analyze_supplied_hexagon_elf32_layout(model)

    def test_wrong_class_and_nonsynthetic_input_rejected(self) -> None:
        model = altered_file(component_fixture(), 4, "<B", 2)
        with self.assertRaises(HexagonElf32LayoutError):
            analyze_supplied_hexagon_elf32_layout(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(HexagonElf32LayoutError):
            analyze_supplied_hexagon_elf32_layout(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_hexagon_elf32_layout(model)
        self.assertEqual(
            verify_supplied_hexagon_elf32_layout(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = altered_file(model, 18, "<H", 62)
        with self.assertRaises(HexagonElf32LayoutError):
            verify_supplied_hexagon_elf32_layout(report, model=changed)
        with self.assertRaises(HexagonElf32LayoutError):
            HexagonElf32LayoutReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

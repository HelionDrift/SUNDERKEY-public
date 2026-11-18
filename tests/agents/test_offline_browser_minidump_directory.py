"""Synthetic minidump geometry tests keep browser and crash claims unknown."""

from __future__ import annotations

import copy
import struct
import unittest

from sunderkey.offline_browser_minidump_directory import (
    BrowserMinidumpDirectoryError,
    BrowserMinidumpDirectoryReport,
    analyze_supplied_browser_minidump_directory,
    component_fixture,
    verify_supplied_browser_minidump_directory,
)


class BrowserMinidumpDirectoryTests(unittest.TestCase):
    def test_synthetic_directory_does_not_claim_crash_or_exploit(self) -> None:
        report = analyze_supplied_browser_minidump_directory(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["stream_count"], 2)
        self.assertEqual([item["name"] for item in body["stream_directory"]],
                         ["exception", "system_info"])
        self.assertTrue(body["directory_geometry_valid"])
        self.assertFalse(body["stream_contents_interpreted"])
        self.assertFalse(body["crash_cause_verified"])
        self.assertFalse(body["exploitability_verified"])
        self.assertNotIn("EXCP", report.to_json())
        self.assertEqual(body["candidate_count"], 0)

    def test_bad_signature_version_and_bounds_rejected(self) -> None:
        for offset, replacement in (
            (0, b"NOPE"),
            (4, struct.pack("<I", 1)),
            (8, struct.pack("<I", 17)),
            (12, struct.pack("<I", 4090)),
            (40, struct.pack("<I", 500)),
            (48, struct.pack("<I", 4090)),
            (52, struct.pack("<I", 4090)),
        ):
            model = component_fixture()
            raw = bytearray.fromhex(model["dump_hex"])
            raw[offset:offset + 4] = replacement
            model["dump_hex"] = raw.hex()
            with self.subTest(offset=offset), self.assertRaises(BrowserMinidumpDirectoryError):
                analyze_supplied_browser_minidump_directory(model)

    def test_overlap_duplicate_and_nonhex_rejected(self) -> None:
        for offset, replacement in (
            (44, struct.pack("<I", 6)),
            (52, struct.pack("<I", 32)),
            (52, struct.pack("<I", 58)),
            (52, struct.pack("<I", 0)),
            (52, struct.pack("<I", 56)),
            (52, struct.pack("<I", 52)),
        ):
            model = component_fixture()
            raw = bytearray.fromhex(model["dump_hex"])
            raw[offset:offset + 4] = replacement
            model["dump_hex"] = raw.hex()
            with (
                self.subTest(replacement=replacement),
                self.assertRaises(BrowserMinidumpDirectoryError),
            ):
                analyze_supplied_browser_minidump_directory(model)
        model = component_fixture()
        model["dump_hex"] = model["dump_hex"].upper()
        with self.assertRaises(BrowserMinidumpDirectoryError):
            analyze_supplied_browser_minidump_directory(model)

    def test_only_synthetic_original_model_replay(self) -> None:
        model = component_fixture()
        report = analyze_supplied_browser_minidump_directory(model)
        self.assertEqual(
            verify_supplied_browser_minidump_directory(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["dump_hex"] = changed["dump_hex"][:-2] + "00"
        with self.assertRaises(BrowserMinidumpDirectoryError):
            verify_supplied_browser_minidump_directory(report, model=changed)
        changed = copy.deepcopy(model)
        changed["synthetic_fixture"] = False
        with self.assertRaises(BrowserMinidumpDirectoryError):
            analyze_supplied_browser_minidump_directory(changed)
        with self.assertRaises(BrowserMinidumpDirectoryError):
            BrowserMinidumpDirectoryReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

"""Synthetic Apple kernel Mach-O marker tests preserve base uncertainty."""

from __future__ import annotations

import base64
import copy
import struct
import unittest

from sunderkey.offline_apple_kernel_macho_markers import (
    AppleKernelMachoMarkerError,
    AppleKernelMachoMarkerReport,
    analyze_supplied_apple_kernel_macho_markers,
    component_fixture,
    verify_supplied_apple_kernel_macho_markers,
)


class AppleKernelMachoMarkerTests(unittest.TestCase):
    def test_markers_are_not_signature_or_kernel_proof(self) -> None:
        body = analyze_supplied_apple_kernel_macho_markers(component_fixture()).to_dict()
        self.assertTrue(body["marker_flags_declared"]["kext_bundle_file_type"])
        self.assertTrue(body["marker_flags_declared"]["code_signature_command"])
        self.assertTrue(body["marker_flags_declared"]["code_signature_extent_bounded"])
        self.assertEqual(body["missing_required_marker_ids"], [])
        self.assertEqual(body["disposition"], "unknown")
        self.assertFalse(body["code_signature_verified"])
        self.assertFalse(body["kernel_loading_verified"])
        self.assertFalse(body["kernel_exploitability_claimed"])
        self.assertEqual(body["candidate_count"], 0)

    def test_missing_required_marker_is_not_a_finding(self) -> None:
        model = component_fixture()
        model["required_marker_ids"].append("arm64_cpu")
        body = analyze_supplied_apple_kernel_macho_markers(model).to_dict()
        self.assertEqual(body["missing_required_marker_ids"], ["arm64_cpu"])
        self.assertFalse(body["finding_claimed"])

    def test_out_of_bounds_signature_extent_is_uncertain_not_verified(self) -> None:
        model = component_fixture()
        raw = bytearray(base64.b64decode(model["macho_layout_model"]["macho_file_base64"]))
        struct.pack_into("<II", raw, 64, 124, 16)
        model["macho_layout_model"]["macho_file_base64"] = base64.b64encode(
            raw
        ).decode("ascii")
        body = analyze_supplied_apple_kernel_macho_markers(model).to_dict()
        self.assertFalse(body["marker_flags_declared"]["code_signature_extent_bounded"])
        self.assertIn("code_signature_extent_not_bounded", body["uncertainty"])

    def test_nonsynthetic_and_duplicate_marker_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(AppleKernelMachoMarkerError):
            analyze_supplied_apple_kernel_macho_markers(model)
        model = component_fixture()
        model["required_marker_ids"].append("x86_64_cpu")
        with self.assertRaises(AppleKernelMachoMarkerError):
            analyze_supplied_apple_kernel_macho_markers(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_apple_kernel_macho_markers(model)
        self.assertEqual(
            verify_supplied_apple_kernel_macho_markers(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["required_marker_ids"].append("arm64_cpu")
        with self.assertRaises(AppleKernelMachoMarkerError):
            verify_supplied_apple_kernel_macho_markers(report, model=changed)
        with self.assertRaises(AppleKernelMachoMarkerError):
            AppleKernelMachoMarkerReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

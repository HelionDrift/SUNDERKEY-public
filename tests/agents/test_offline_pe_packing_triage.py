"""Synthetic PE byte triage does not infer packing or malware behavior."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_pe_packing_triage import (
    PePackingTriageError,
    PePackingTriageReport,
    analyze_supplied_pe_packing_triage,
    component_fixture,
    verify_supplied_pe_packing_triage,
)


class PePackingTriageTests(unittest.TestCase):
    def test_section_distribution_and_trailing_bytes_are_descriptive(self) -> None:
        body = analyze_supplied_pe_packing_triage(component_fixture()).to_dict()
        self.assertEqual(body["section_count"], 1)
        self.assertEqual(body["trailing_file_bytes"], 23)
        self.assertEqual(body["section_byte_distribution"][0]["byte_entropy_millibits"], 78)
        self.assertFalse(body["packed_code_verified"])
        self.assertFalse(body["malware_identity_verified"])
        self.assertFalse(body["configuration_extracted"])
        self.assertEqual(body["candidate_count"], 0)

    def test_distribution_changes_without_behavior_claim(self) -> None:
        model = component_fixture()
        pe_model = model["pe_layout_model"]
        data = bytearray(base64.b64decode(pe_model["pe_file_base64"]))
        data[512:1024] = bytes(range(256)) * 2
        pe_model["pe_file_base64"] = base64.b64encode(data).decode("ascii")
        body = analyze_supplied_pe_packing_triage(model).to_dict()
        self.assertEqual(body["section_byte_distribution"][0]["byte_entropy_millibits"], 8000)
        self.assertFalse(body["packed_code_verified"])
        self.assertEqual(body["disposition"], "unknown")

    def test_invalid_source_and_corrupt_pe_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(PePackingTriageError):
            analyze_supplied_pe_packing_triage(model)
        model = component_fixture()
        model["pe_layout_model"]["pe_file_base64"] = "invalid"
        with self.assertRaises(ValueError):
            analyze_supplied_pe_packing_triage(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_pe_packing_triage(model)
        self.assertEqual(
            verify_supplied_pe_packing_triage(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["source_id"] = "changed-synthetic-pe-triage"
        with self.assertRaises(PePackingTriageError):
            verify_supplied_pe_packing_triage(report, model=changed)
        with self.assertRaises(PePackingTriageError):
            PePackingTriageReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

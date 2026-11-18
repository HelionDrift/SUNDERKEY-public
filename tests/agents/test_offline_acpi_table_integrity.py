"""Supplied ACPI table arithmetic and original-model replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_acpi_table_integrity import (
    AcpiTableIntegrityError,
    analyze_supplied_acpi_table,
    component_fixture,
    verify_supplied_acpi_table,
    verify_supplied_acpi_table_bytes,
)


class AcpiTableIntegrityTests(unittest.TestCase):
    def test_checksum_candidate_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_acpi_table(model)
        body = report.to_dict()
        self.assertEqual(body["issues"], ["table_checksum_mismatch"])
        self.assertEqual(body["candidate_count"], 1)
        self.assertFalse(body["platform_contacted"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_acpi_table(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_acpi_table_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_valid_checksum_and_incomplete_table(self) -> None:
        model = component_fixture()
        table = model["table_bytes"]
        table[9] = (-sum(table)) & 255
        self.assertEqual(analyze_supplied_acpi_table(model).to_dict()["candidate_count"], 0)
        model["table_complete"] = False
        body = analyze_supplied_acpi_table(model).to_dict()
        self.assertEqual(body["unknown_count"], 1)
        self.assertIsNone(body["checksum_valid"])

    def test_short_header_and_length_mismatch(self) -> None:
        model = component_fixture()
        model["table_bytes"] = [84, 69, 83, 84, 36, 0, 0, 0]
        body = analyze_supplied_acpi_table(model).to_dict()
        self.assertEqual(body["issues"], ["short_common_header", "declared_length_mismatch"])

    def test_facs_is_unsupported_not_a_common_header_candidate(self) -> None:
        model = component_fixture()
        model["table_bytes"][:4] = [70, 65, 67, 83]
        body = analyze_supplied_acpi_table(model).to_dict()
        self.assertFalse(body["common_header_supported"])
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertEqual(body["issues"], [])
        self.assertIsNone(body["checksum_valid"])

    def test_rejects_invalid_bytes_and_replay_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_acpi_table(model)
        for invalid in (-1, 256, True):
            changed = copy.deepcopy(model)
            changed["table_bytes"][0] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(AcpiTableIntegrityError):
                analyze_supplied_acpi_table(changed)
        changed = copy.deepcopy(model)
        changed["source_id"] = "changed-source"
        with self.assertRaises(AcpiTableIntegrityError):
            verify_supplied_acpi_table(report, model=changed)
        with self.assertRaises(AcpiTableIntegrityError):
            verify_supplied_acpi_table(report.to_dict(), model=model)
        with self.assertRaises(AcpiTableIntegrityError):
            verify_supplied_acpi_table_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

"""Synthetic AIS position reports retain source and navigation uncertainty."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_ais_position_report import (
    AisPositionReport,
    AisPositionReportError,
    analyze_supplied_ais_position_report,
    component_fixture,
    verify_supplied_ais_position_report,
)


def altered_field(model: dict, offset: int, width: int, value: int) -> dict:
    changed = copy.deepcopy(model)
    raw = base64.b64decode(changed["report_base64"])
    bits = "".join(f"{octet:08b}" for octet in raw)
    bits = bits[:offset] + f"{value:0{width}b}" + bits[offset + width:]
    changed["report_base64"] = base64.b64encode(
        int(bits, 2).to_bytes(21, "big")
    ).decode("ascii")
    return changed


class AisPositionReportTests(unittest.TestCase):
    def test_report_geometry_is_not_vessel_or_position_proof(self) -> None:
        report = analyze_supplied_ais_position_report(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["message_id"], 1)
        self.assertFalse(body["longitude_available"])
        self.assertFalse(body["latitude_available"])
        self.assertFalse(body["vessel_identity_verified"])
        self.assertFalse(body["position_accuracy_verified"])
        self.assertNotIn("123456789", report.to_json())
        self.assertEqual(body["candidate_count"], 0)

    def test_other_message_and_reserved_spare_rejected(self) -> None:
        for offset, width, value in ((0, 6, 4), (145, 2, 1)):
            with self.subTest(offset=offset):
                with self.assertRaises(AisPositionReportError):
                    analyze_supplied_ais_position_report(
                        altered_field(component_fixture(), offset, width, value)
                    )

    def test_out_of_range_coordinates_rejected(self) -> None:
        for offset, width, value in ((61, 28, 108_000_001), (89, 27, 54_000_001)):
            with self.subTest(offset=offset):
                with self.assertRaises(AisPositionReportError):
                    analyze_supplied_ais_position_report(
                        altered_field(component_fixture(), offset, width, value)
                    )

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(AisPositionReportError):
            analyze_supplied_ais_position_report(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ais_position_report(model)
        self.assertEqual(
            verify_supplied_ais_position_report(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        with self.assertRaises(AisPositionReportError):
            verify_supplied_ais_position_report(
                report, model=altered_field(model, 6, 2, 1)
            )
        with self.assertRaises(AisPositionReportError):
            AisPositionReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

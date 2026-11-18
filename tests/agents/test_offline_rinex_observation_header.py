"""Synthetic RINEX header tests preserve GNSS accuracy uncertainty."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_rinex_observation_header import (
    RinexObservationHeaderError,
    RinexObservationHeaderReport,
    analyze_supplied_rinex_observation_header,
    component_fixture,
    verify_supplied_rinex_observation_header,
)


def altered_header(model: dict, index: int, value: str) -> dict:
    changed = copy.deepcopy(model)
    header = bytearray(base64.b64decode(changed["header_base64"]))
    header[index] = ord(value)
    changed["header_base64"] = base64.b64encode(header).decode("ascii")
    return changed


class RinexObservationHeaderTests(unittest.TestCase):
    def test_declarations_are_not_position_or_station_proof(self) -> None:
        body = analyze_supplied_rinex_observation_header(component_fixture()).to_dict()
        self.assertEqual(body["header_line_count"], 5)
        self.assertEqual(body["rinex_version"], "4.02")
        self.assertEqual(body["file_system_scope"], "G")
        self.assertEqual(
            body["observation_declarations"][0]["observation_codes"],
            ["C1C", "L1C", "D1C", "S1C"],
        )
        self.assertFalse(body["position_or_time_accuracy_verified"])
        self.assertFalse(body["station_identity_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_version_label_and_count_mismatch_rejected(self) -> None:
        header = base64.b64decode(component_fixture()["header_base64"])
        fourth = 81 * 3
        for index, value in ((7, "3"), (60, "X"), (fourth + 5, "5")):
            with self.subTest(index=index):
                with self.assertRaises(RinexObservationHeaderError):
                    analyze_supplied_rinex_observation_header(
                        altered_header(component_fixture(), index, value)
                    )
        self.assertEqual(len(header), 404)

    def test_unknown_observation_code_rejected(self) -> None:
        with self.assertRaises(RinexObservationHeaderError):
            analyze_supplied_rinex_observation_header(
                altered_header(component_fixture(), 81 * 3 + 7, "Z")
            )

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(RinexObservationHeaderError):
            analyze_supplied_rinex_observation_header(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_rinex_observation_header(model)
        self.assertEqual(
            verify_supplied_rinex_observation_header(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        with self.assertRaises(RinexObservationHeaderError):
            verify_supplied_rinex_observation_header(
                report, model=altered_header(model, 81, "X")
            )
        with self.assertRaises(RinexObservationHeaderError):
            RinexObservationHeaderReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

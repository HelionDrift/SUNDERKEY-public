"""Synthetic CCSDS packet tests preserve mission identity uncertainty."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_ccsds_space_packet import (
    CcsdsSpacePacketError,
    CcsdsSpacePacketReport,
    analyze_supplied_ccsds_space_packet,
    component_fixture,
    verify_supplied_ccsds_space_packet,
)


def altered_packet(model: dict, index: int, value: int) -> dict:
    changed = copy.deepcopy(model)
    packet = bytearray(base64.b64decode(changed["packet_base64"]))
    packet[index] = value
    changed["packet_base64"] = base64.b64encode(packet).decode("ascii")
    return changed


class CcsdsSpacePacketTests(unittest.TestCase):
    def test_primary_header_geometry_is_not_mission_proof(self) -> None:
        body = analyze_supplied_ccsds_space_packet(component_fixture()).to_dict()
        self.assertEqual(body["packet_length"], 9)
        self.assertEqual(body["packet_version_number"], 0)
        self.assertEqual(body["application_process_id"], 42)
        self.assertEqual(body["sequence_flags"], 3)
        self.assertEqual(body["packet_data_length"], 3)
        self.assertFalse(body["mission_apid_mapping_verified"])
        self.assertFalse(body["mission_identity_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_version_length_and_idle_header_rejected(self) -> None:
        for index, value in ((0, 0x20), (5, 3)):
            with self.subTest(index=index):
                with self.assertRaises(CcsdsSpacePacketError):
                    analyze_supplied_ccsds_space_packet(
                        altered_packet(component_fixture(), index, value)
                    )
        idle_with_secondary = altered_packet(component_fixture(), 0, 0x0F)
        idle_with_secondary = altered_packet(idle_with_secondary, 1, 0xFF)
        with self.assertRaises(CcsdsSpacePacketError):
            analyze_supplied_ccsds_space_packet(idle_with_secondary)

    def test_telecommand_type_not_command_validation(self) -> None:
        body = analyze_supplied_ccsds_space_packet(
            altered_packet(component_fixture(), 0, 0x10)
        ).to_dict()
        self.assertEqual(body["packet_type"], "telecommand")
        self.assertFalse(body["telecommand_meaning_verified"])

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(CcsdsSpacePacketError):
            analyze_supplied_ccsds_space_packet(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ccsds_space_packet(model)
        self.assertEqual(
            verify_supplied_ccsds_space_packet(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        with self.assertRaises(CcsdsSpacePacketError):
            verify_supplied_ccsds_space_packet(
                report, model=altered_packet(model, 8, 4)
            )
        with self.assertRaises(CcsdsSpacePacketError):
            CcsdsSpacePacketReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

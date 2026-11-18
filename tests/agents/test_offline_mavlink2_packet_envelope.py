"""Synthetic MAVLink 2 envelope tests preserve source and aircraft uncertainty."""

from __future__ import annotations

import base64
import copy
import unittest

from sunderkey.offline_mavlink2_packet_envelope import (
    Mavlink2PacketEnvelopeError,
    Mavlink2PacketEnvelopeReport,
    analyze_supplied_mavlink2_packet_envelope,
    component_fixture,
    verify_supplied_mavlink2_packet_envelope,
)


def altered_packet(model: dict, index: int, value: int) -> dict:
    changed = copy.deepcopy(model)
    packet = bytearray(base64.b64decode(changed["packet_base64"]))
    packet[index] = value
    changed["packet_base64"] = base64.b64encode(packet).decode("ascii")
    return changed


class Mavlink2PacketEnvelopeTests(unittest.TestCase):
    def test_geometry_is_not_checksum_or_aircraft_proof(self) -> None:
        body = analyze_supplied_mavlink2_packet_envelope(component_fixture()).to_dict()
        self.assertEqual(body["packet_length"], 14)
        self.assertEqual(body["payload_length"], 2)
        self.assertEqual(body["message_id"], 0)
        self.assertEqual(body["sender_system_id"], 1)
        self.assertFalse(body["checksum_verified"])
        self.assertFalse(body["aircraft_identity_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_magic_length_sender_and_unknown_flag_rejected(self) -> None:
        for index, value in ((0, 0xFE), (1, 3), (2, 2), (5, 0), (6, 0)):
            with self.subTest(index=index, value=value):
                with self.assertRaises(Mavlink2PacketEnvelopeError):
                    analyze_supplied_mavlink2_packet_envelope(
                        altered_packet(component_fixture(), index, value)
                    )

    def test_signed_field_is_detected_but_not_authenticated(self) -> None:
        model = altered_packet(component_fixture(), 2, 1)
        packet = base64.b64decode(model["packet_base64"]) + bytes(13)
        model["packet_base64"] = base64.b64encode(packet).decode("ascii")
        body = analyze_supplied_mavlink2_packet_envelope(model).to_dict()
        self.assertTrue(body["signature_present"])
        self.assertFalse(body["signature_verified"])

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(Mavlink2PacketEnvelopeError):
            analyze_supplied_mavlink2_packet_envelope(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_mavlink2_packet_envelope(model)
        self.assertEqual(
            verify_supplied_mavlink2_packet_envelope(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        with self.assertRaises(Mavlink2PacketEnvelopeError):
            verify_supplied_mavlink2_packet_envelope(
                report, model=altered_packet(model, 4, 8)
            )
        with self.assertRaises(Mavlink2PacketEnvelopeError):
            Mavlink2PacketEnvelopeReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

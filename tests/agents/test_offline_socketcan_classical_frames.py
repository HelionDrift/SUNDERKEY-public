"""Synthetic SocketCAN frame tests preserve vehicle and UDS uncertainty."""

from __future__ import annotations

import base64
import copy
import struct
import unittest

from sunderkey.offline_socketcan_classical_frames import (
    CAN_RTR_FLAG,
    SocketCanClassicalFrameError,
    SocketCanClassicalFrameReport,
    analyze_supplied_socketcan_classical_frames,
    component_fixture,
    verify_supplied_socketcan_classical_frames,
)


def altered_frame(model: dict, offset: int, fmt: str, value: int) -> dict:
    result = copy.deepcopy(model)
    raw = bytearray(base64.b64decode(result["frames_base64"]))
    struct.pack_into(fmt, raw, offset, value)
    result["frames_base64"] = base64.b64encode(raw).decode("ascii")
    return result


class SocketCanClassicalFrameTests(unittest.TestCase):
    def test_frame_geometry_is_not_vehicle_or_uds_proof(self) -> None:
        body = analyze_supplied_socketcan_classical_frames(component_fixture()).to_dict()
        self.assertEqual(body["frame_count"], 2)
        self.assertEqual(body["standard_frame_count"], 1)
        self.assertEqual(body["extended_frame_count"], 1)
        self.assertEqual(body["frame_observations"][0]["identifier_hex"], "0x123")
        self.assertFalse(body["vehicle_identity_verified"])
        self.assertFalse(body["uds_message_interpreted"])
        self.assertFalse(body["vehicle_behavior_verified"])
        self.assertEqual(body["candidate_count"], 0)

    def test_truncated_and_invalid_length_rejected(self) -> None:
        model = component_fixture()
        model["frames_base64"] = base64.b64encode(
            base64.b64decode(model["frames_base64"])[:-1]
        ).decode("ascii")
        with self.assertRaises(SocketCanClassicalFrameError):
            analyze_supplied_socketcan_classical_frames(model)
        model = altered_frame(component_fixture(), 4, "<B", 9)
        with self.assertRaises(SocketCanClassicalFrameError):
            analyze_supplied_socketcan_classical_frames(model)

    def test_remote_and_reserved_bits_rejected(self) -> None:
        model = altered_frame(component_fixture(), 0, "<I", CAN_RTR_FLAG | 0x123)
        with self.assertRaises(SocketCanClassicalFrameError):
            analyze_supplied_socketcan_classical_frames(model)
        model = altered_frame(component_fixture(), 5, "<B", 1)
        with self.assertRaises(SocketCanClassicalFrameError):
            analyze_supplied_socketcan_classical_frames(model)

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(SocketCanClassicalFrameError):
            analyze_supplied_socketcan_classical_frames(model)

    def test_replay_requires_original_model_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_socketcan_classical_frames(model)
        self.assertEqual(
            verify_supplied_socketcan_classical_frames(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = altered_frame(model, 4, "<B", 2)
        with self.assertRaises(SocketCanClassicalFrameError):
            verify_supplied_socketcan_classical_frames(report, model=changed)
        with self.assertRaises(SocketCanClassicalFrameError):
            SocketCanClassicalFrameReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

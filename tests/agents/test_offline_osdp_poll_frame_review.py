"""Synthetic OSDP poll frames do not prove badge or access behavior."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_osdp_poll_frame_review import (
    OsdpPollFrameReviewError,
    OsdpPollFrameReviewReport,
    analyze_supplied_osdp_poll_frame,
    component_fixture,
    verify_supplied_osdp_poll_frame,
)


class OsdpPollFrameReviewTests(unittest.TestCase):
    def test_checksum_consistency_does_not_claim_reader_state(self) -> None:
        report = analyze_supplied_osdp_poll_frame(component_fixture())
        body = report.to_dict()
        self.assertTrue(body["checksum_consistent"])
        self.assertEqual(body["command_code"], "CMD_POLL")
        self.assertTrue(body["address_matches_supplied_expectation"])
        self.assertFalse(body["secure_channel_observed"])
        self.assertFalse(body["badge_read_observed"])
        self.assertFalse(body["access_granted_observed"])
        self.assertFalse(body["frame_transmitted"])

    def test_expected_address_mismatch_remains_uncertain(self) -> None:
        model = component_fixture()
        model["expected_pd_address"] = 2
        body = analyze_supplied_osdp_poll_frame(model).to_dict()
        self.assertFalse(body["address_matches_supplied_expectation"])
        self.assertEqual(body["candidate_count"], 0)

    def test_bad_checksum_length_and_command_reject(self) -> None:
        for frame in ("53010700006044", "53010800006044", "53010700006144"):
            with self.subTest(frame=frame):
                model = component_fixture()
                model["frame_hex"] = frame
                with self.assertRaises(OsdpPollFrameReviewError):
                    analyze_supplied_osdp_poll_frame(model)

    def test_secure_channel_flag_and_nonsynthetic_source_reject(self) -> None:
        model = component_fixture()
        model["frame_hex"] = "5301070008603d"
        with self.assertRaises(OsdpPollFrameReviewError):
            analyze_supplied_osdp_poll_frame(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(OsdpPollFrameReviewError):
            analyze_supplied_osdp_poll_frame(model)

    def test_replay_requires_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_osdp_poll_frame(model)
        self.assertEqual(
            verify_supplied_osdp_poll_frame(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["expected_pd_address"] = 2
        with self.assertRaises(OsdpPollFrameReviewError):
            verify_supplied_osdp_poll_frame(report, model=changed)
        with self.assertRaises(OsdpPollFrameReviewError):
            OsdpPollFrameReviewReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

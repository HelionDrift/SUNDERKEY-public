"""Bounded supplied ESRT device-firmware update metadata tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_firmware_update_metadata import (
    FirmwareUpdateMetadataError,
    analyze_supplied_esrt_update_metadata,
    component_fixture,
    verify_supplied_esrt_update_metadata,
    verify_supplied_esrt_update_metadata_bytes,
)


class FirmwareUpdateMetadataTests(unittest.TestCase):
    def test_below_floor_is_an_inert_candidate_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_esrt_update_metadata(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(body["unknown_count"], 0)
        self.assertEqual(
            body["observations"][0]["disposition"],
            "candidate_below_declared_rollback_floor",
        )
        self.assertEqual(
            body["observations"][0]["direction_from_supplied_current_version"],
            "downgrade",
        )
        self.assertFalse(body["device_contacted"])
        self.assertFalse(body["firmware_update_attempted"])
        self.assertFalse(body["firmware_acceptance_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_esrt_update_metadata(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_esrt_update_metadata_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_floor_boundary_and_current_direction_are_distinct(self) -> None:
        model = component_fixture()
        model["proposed_updates"] = [
            {
                "proposal_id": identifier,
                "target_fw_class": model["resource"]["fw_class"],
                "proposed_version": version,
            }
            for identifier, version in (
                ("floor", 9), ("current", 12), ("upgrade", 13)
            )
        ]
        body = analyze_supplied_esrt_update_metadata(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(
            [row["direction_from_supplied_current_version"] for row in body["observations"]],
            ["downgrade", "same_version", "upgrade"],
        )
        self.assertEqual(
            {row["disposition"] for row in body["observations"]},
            {"not_below_declared_rollback_floor"},
        )

    def test_other_target_is_unknown_not_a_rollback_candidate(self) -> None:
        model = component_fixture()
        model["proposed_updates"][0]["target_fw_class"] = (
            "00000000-0000-0000-0000-000000000001"
        )
        body = analyze_supplied_esrt_update_metadata(model).to_dict()
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["unknown_count"], 1)
        self.assertEqual(
            body["observations"][0]["disposition"],
            "unknown_target_not_in_supplied_resource",
        )

    def test_strict_uint32_guids_and_unique_proposals(self) -> None:
        for field, invalid in (
            ("fw_version", True),
            ("lowest_supported_fw_version", -1),
            ("last_attempt_version", 1 << 32),
            ("fw_type", 1),
        ):
            with self.subTest(field=field):
                model = component_fixture()
                model["resource"][field] = invalid
                with self.assertRaises(FirmwareUpdateMetadataError):
                    analyze_supplied_esrt_update_metadata(model)
        model = component_fixture()
        model["resource"]["fw_class"] = model["resource"]["fw_class"].upper()
        with self.assertRaises(FirmwareUpdateMetadataError):
            analyze_supplied_esrt_update_metadata(model)
        model = component_fixture()
        model["proposed_updates"].append(copy.deepcopy(model["proposed_updates"][0]))
        with self.assertRaises(FirmwareUpdateMetadataError):
            analyze_supplied_esrt_update_metadata(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_esrt_update_metadata(model)
        changed = copy.deepcopy(model)
        changed["resource"]["lowest_supported_fw_version"] = 8
        with self.assertRaises(FirmwareUpdateMetadataError):
            verify_supplied_esrt_update_metadata(report, model=changed)
        with self.assertRaises(FirmwareUpdateMetadataError):
            verify_supplied_esrt_update_metadata(report.to_dict(), model=model)
        with self.assertRaises(FirmwareUpdateMetadataError):
            verify_supplied_esrt_update_metadata_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

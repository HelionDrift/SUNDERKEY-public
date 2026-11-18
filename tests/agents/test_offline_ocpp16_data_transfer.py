"""Synthetic OCPP DataTransfer tests preserve vendor and charging uncertainty."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_ocpp16_data_transfer import (
    Ocpp16DataTransferError,
    Ocpp16DataTransferReport,
    analyze_supplied_ocpp16_data_transfer,
    component_fixture,
    verify_supplied_ocpp16_data_transfer,
)


class Ocpp16DataTransferTests(unittest.TestCase):
    def test_request_shape_is_not_vendor_or_charging_proof(self) -> None:
        report = analyze_supplied_ocpp16_data_transfer(component_fixture())
        body = report.to_dict()
        self.assertEqual(body["call_message_type"], 2)
        self.assertEqual(body["action"], "DataTransfer")
        self.assertTrue(body["message_id_present"])
        self.assertTrue(body["data_present"])
        self.assertFalse(body["vendor_identity_verified"])
        self.assertFalse(body["charging_effect_verified"])
        self.assertNotIn("com.synthetic.example", report.to_json())
        self.assertEqual(body["candidate_count"], 0)

    def test_wrong_message_type_action_and_vendor_rejected(self) -> None:
        for slot, value in ((0, 3), (2, "RemoteStartTransaction")):
            model = component_fixture()
            model["request"][slot] = value
            with self.subTest(slot=slot), self.assertRaises(Ocpp16DataTransferError):
                analyze_supplied_ocpp16_data_transfer(model)
        model = component_fixture()
        model["request"][3]["vendorId"] = "not-a-domain"
        with self.assertRaises(Ocpp16DataTransferError):
            analyze_supplied_ocpp16_data_transfer(model)

    def test_unknown_payload_field_and_nonstring_data_rejected(self) -> None:
        model = component_fixture()
        model["request"][3]["powerLimit"] = 1000
        with self.assertRaises(Ocpp16DataTransferError):
            analyze_supplied_ocpp16_data_transfer(model)
        model = component_fixture()
        model["request"][3]["data"] = {"not": "a string"}
        with self.assertRaises(Ocpp16DataTransferError):
            analyze_supplied_ocpp16_data_transfer(model)

    def test_nonsynthetic_source_rejected(self) -> None:
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(Ocpp16DataTransferError):
            analyze_supplied_ocpp16_data_transfer(model)

    def test_replay_requires_separate_original_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_ocpp16_data_transfer(model)
        self.assertEqual(
            verify_supplied_ocpp16_data_transfer(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["request"][3]["messageId"] = "changed"
        with self.assertRaises(Ocpp16DataTransferError):
            verify_supplied_ocpp16_data_transfer(report, model=changed)
        with self.assertRaises(Ocpp16DataTransferError):
            Ocpp16DataTransferReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

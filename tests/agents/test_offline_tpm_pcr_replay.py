"""Supplied SHA-256 PCR extension arithmetic and replay tests."""

from __future__ import annotations

import copy
import hashlib
import unittest

from sunderkey.offline_tpm_pcr_replay import (
    TpmPcrReplayError,
    analyze_supplied_tpm_pcr,
    component_fixture,
    verify_supplied_tpm_pcr,
    verify_supplied_tpm_pcr_bytes,
)


class TpmPcrReplayTests(unittest.TestCase):
    def test_mismatch_is_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_tpm_pcr(model)
        body = report.to_dict()
        expected = hashlib.sha256(bytes(32) + bytes.fromhex("11" * 32)).hexdigest()
        self.assertEqual(body["computed_pcr_hex"], expected)
        self.assertEqual(body["candidate_count"], 1)
        self.assertFalse(body["tpm_contacted"])
        self.assertFalse(body["quote_verified"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(verify_supplied_tpm_pcr(report, model=model).to_json(), report.to_json())
        self.assertEqual(
            verify_supplied_tpm_pcr_bytes(report.to_json().encode(), model=model).to_json(),
            report.to_json(),
        )

    def test_matching_value_and_incomplete_log(self) -> None:
        model = component_fixture()
        model["expected_pcr_hex"] = hashlib.sha256(
            bytes(32) + bytes.fromhex("11" * 32)
        ).hexdigest()
        self.assertEqual(analyze_supplied_tpm_pcr(model).to_dict()["candidate_count"], 0)
        model["log_complete"] = False
        body = analyze_supplied_tpm_pcr(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["unknown_count"], 1)

    def test_rejects_invalid_digest_and_duplicate_event(self) -> None:
        model = component_fixture()
        model["events"][0]["digest_hex"] = "zz" * 32
        with self.assertRaises(TpmPcrReplayError):
            analyze_supplied_tpm_pcr(model)
        model = component_fixture()
        model["events"].append(copy.deepcopy(model["events"][0]))
        with self.assertRaises(TpmPcrReplayError):
            analyze_supplied_tpm_pcr(model)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_tpm_pcr(model)
        changed = copy.deepcopy(model)
        changed["events"][0]["digest_hex"] = "22" * 32
        with self.assertRaises(TpmPcrReplayError):
            verify_supplied_tpm_pcr(report, model=changed)
        with self.assertRaises(TpmPcrReplayError):
            verify_supplied_tpm_pcr(report.to_dict(), model=model)
        with self.assertRaises(TpmPcrReplayError):
            verify_supplied_tpm_pcr_bytes(b"{}", model=model)


if __name__ == "__main__":
    unittest.main()

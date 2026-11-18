from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import openai_expert_runtime_smoke as smoke
from tests.agents.test_openai_expert_provider_adapter_phase201 import (
    TEST_API_KEY,
    DeterministicOpenAITransport,
)


class OpenAIExpertRuntimeSmokeTests(unittest.TestCase):
    @staticmethod
    def _prepared():
        return smoke._prepare(
            lambda fixture, envelope: DeterministicOpenAITransport(
                fixture._response(envelope)
            )
        )

    def test_offline_preflight_never_calls_transport(self) -> None:
        prepared = self._prepared()
        with patch.object(smoke, "_prepare", return_value=prepared):
            self.assertEqual(smoke.main(["--preflight"]), 0)
        self.assertEqual(prepared[4].call_count, 0)

    def test_confirmed_synthetic_execution_has_one_call_and_receipt(self) -> None:
        prepared = self._prepared()
        plan_sha = prepared[1].invocation_plan.plan_sha256
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
            ):
                exit_code = smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: plan_sha,
                )
            self.assertEqual(exit_code, 0)
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema_version"], 2)
            self.assertEqual(receipt["client_request_id"], prepared[4].client_request_id)
            self.assertIn(
                "X-Client-Request-Id", prepared[4].delegate.header_names
            )
            self.assertEqual(receipt["status"], "completed_settled")
            self.assertEqual(receipt["qualification_effect"], "none")
            self.assertTrue(receipt["network_call_performed"])
            self.assertEqual(receipt["store_integrity"], "valid")
            self.assertTrue(receipt["http_response_received"])
            self.assertEqual(receipt["http_status"], 200)
            self.assertEqual(
                receipt["http_request_id_unverified"], "req_phase201_success"
            )
            self.assertEqual(prepared[4].call_count, 1)
            self.assertIsNotNone(receipt["work_product"])
            self.assertNotIn(TEST_API_KEY, output.read_text(encoding="utf-8"))

    def test_http_error_receipt_exposes_status_without_response_body(self) -> None:
        prepared = self._prepared()
        prepared[4].delegate.status = 429
        prepared[4].delegate.raw_response_body = (
            '{"error":"sensitive provider detail"}'.encode("utf-8")
        )
        plan_sha = prepared[1].invocation_plan.plan_sha256
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
            ):
                exit_code = smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: plan_sha,
                )
            self.assertEqual(exit_code, 1)
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["status"], "indeterminate_quarantined")
            self.assertEqual(receipt["http_status"], 429)
            self.assertTrue(receipt["http_response_received"])
            self.assertEqual(
                receipt["settlement_outcome_reason"], "provider_outcome_indeterminate"
            )
            self.assertEqual(receipt["output_status"], "indeterminate")
            self.assertNotIn("sensitive provider detail", receipt_text)
            self.assertNotIn(TEST_API_KEY, receipt_text)

    def test_transport_failure_records_no_http_response(self) -> None:
        prepared = self._prepared()
        prepared[4].delegate.failure = OSError("sensitive transport detail")
        plan_sha = prepared[1].invocation_plan.plan_sha256
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
            ):
                exit_code = smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: plan_sha,
                )
            self.assertEqual(exit_code, 1)
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["status"], "indeterminate_quarantined")
            self.assertFalse(receipt["http_response_received"])
            self.assertEqual(
                receipt["network_call_performed"], "indeterminate_after_attempt"
            )
            self.assertIsNone(receipt["http_status"])
            self.assertIsNone(receipt["http_request_id_unverified"])
            self.assertNotIn("sensitive transport detail", receipt_text)
            self.assertNotIn(TEST_API_KEY, receipt_text)

    def test_unaccepted_http_200_records_status_without_response_body(self) -> None:
        prepared = self._prepared()
        prepared[4].delegate.raw_response_body = (
            b'{"status":"incomplete","incomplete_details":'
            b'{"reason":"max_output_tokens"},"private":"not for receipt"}'
        )
        plan_sha = prepared[1].invocation_plan.plan_sha256
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
            ):
                exit_code = smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: plan_sha,
                )
            self.assertEqual(exit_code, 1)
            receipt_text = output.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertTrue(receipt["http_response_received"])
            self.assertEqual(receipt["http_status"], 200)
            self.assertEqual(receipt["response_status_unverified"], "incomplete")
            self.assertEqual(receipt["incomplete_reason_unverified"], "max_output_tokens")
            self.assertIsNone(receipt["provider_request_id"])
            self.assertNotIn("not for receipt", receipt_text)

    def test_interrupted_run_preserves_client_request_id_in_reservation(self) -> None:
        prepared = self._prepared()
        plan_sha = prepared[1].invocation_plan.plan_sha256
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
                patch.object(prepared[0].custody, "execute", side_effect=KeyboardInterrupt),
                self.assertRaises(KeyboardInterrupt),
            ):
                smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: plan_sha,
                )
            receipt = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "reserved_no_terminal_result")
            self.assertEqual(receipt["client_request_id"], prepared[4].client_request_id)
            self.assertEqual(receipt["network_call_performed"], "unknown_until_terminal_result")

    def test_wrong_confirmation_does_not_publish_or_call(self) -> None:
        prepared = self._prepared()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "smoke-receipt.json"
            with (
                patch.dict(os.environ, {"OPENAI_API_KEY": TEST_API_KEY}),
                patch.object(smoke, "_prepare", return_value=prepared),
                self.assertRaises(SystemExit),
            ):
                smoke.main(
                    [
                        "--run", "--output", str(output),
                        "--confirm-maximum-requests", "1",
                        "--confirm-token-ceiling", "18000",
                    ],
                    confirmation_input=lambda: "sha256:" + "0" * 64,
                )
            self.assertFalse(output.exists())
            self.assertEqual(prepared[4].call_count, 0)


if __name__ == "__main__":
    unittest.main()

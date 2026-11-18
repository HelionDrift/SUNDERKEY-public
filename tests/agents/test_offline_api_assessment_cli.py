"""Bounded local command tests for the synthetic API assessment seam."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts.run_offline_api_assessment import (
    compare_cases,
    main,
    run_batch,
    run_case,
    verify_batch,
    verify_case,
    verify_comparison,
)
from sunderkey.offline_api_assessment import OfflineApiAssessmentError

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "examples" / "offline-api-assessment" / "corroborated-synthetic-case.json"
RETEST_FIXTURE = ROOT / "examples" / "offline-api-assessment" / "denied-synthetic-retest-case.json"


class OfflineApiAssessmentCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.result = run_case(cls.case)

    def test_example_runs_and_verifies_without_response_body_output(self) -> None:
        self.assertEqual(self.result["disposition"], "corroborated_synthetic_signal")
        self.assertNotIn("synthetic-example-only", json.dumps(self.result))
        self.assertEqual(verify_case(self.case, self.result)["status"], "valid")
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["run", "--input", str(FIXTURE)]), 0)
        self.assertEqual(json.loads(output.getvalue()), self.result)

    def test_changed_result_and_changed_response_fail_verification(self) -> None:
        changed = copy.deepcopy(self.result)
        changed["validator_state"] = "negative"
        with self.assertRaises(OfflineApiAssessmentError):
            verify_case(self.case, changed)
        changed_case = copy.deepcopy(self.case)
        changed_case["responses"][1]["body"] = {"record": "different"}
        with self.assertRaises(OfflineApiAssessmentError):
            verify_case(changed_case, self.result)

    def test_verify_command_reproduces_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            path.write_text(json.dumps(self.result), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(["verify", "--input", str(FIXTURE), "--result", str(path)]), 0
                )
        self.assertEqual(json.loads(output.getvalue())["status"], "valid")

    def test_duplicate_keys_and_oversize_input_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "case.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(main(["run", "--input", str(path)]), 2)
            path.write_bytes(b" " * 262_145)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(["run", "--input", str(path)]), 2)

    def test_nonfinite_body_and_unknown_field_are_rejected(self) -> None:
        malformed = copy.deepcopy(self.case)
        malformed["responses"][0]["body"] = {"number": float("nan")}
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            run_case(malformed)
        extra = copy.deepcopy(self.case)
        extra["network_target"] = "https://example.invalid"
        with self.assertRaisesRegex(ValueError, "case fields"):
            run_case(extra)

    def test_retest_command_compares_and_verifies_without_fix_claim(self) -> None:
        second_case = json.loads(RETEST_FIXTURE.read_text(encoding="utf-8"))
        second_result = run_case(second_case)
        comparison = compare_cases(self.case, self.result, second_case, second_result)
        self.assertEqual(
            comparison["observation_change"],
            "prior_signal_not_observed_in_second_synthetic_case",
        )
        self.assertNotIn("verified_fix", json.dumps(comparison))
        self.assertEqual(
            verify_comparison(self.case, self.result, second_case, second_result, comparison)[
                "status"
            ],
            "valid",
        )
        with tempfile.TemporaryDirectory() as temp:
            prior_path = Path(temp) / "prior-result.json"
            second_path = Path(temp) / "second-result.json"
            comparison_path = Path(temp) / "comparison.json"
            prior_path.write_text(json.dumps(self.result), encoding="utf-8")
            second_path.write_text(json.dumps(second_result), encoding="utf-8")
            comparison_path.write_text(json.dumps(comparison), encoding="utf-8")
            common_args = [
                "--prior-input",
                str(FIXTURE),
                "--prior-result",
                str(prior_path),
                "--second-input",
                str(RETEST_FIXTURE),
                "--second-result",
                str(second_path),
            ]
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["retest", *common_args]), 0)
            self.assertEqual(json.loads(output.getvalue()), comparison)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(["retest-verify", *common_args, "--comparison", str(comparison_path)]),
                    0,
                )
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")

    def test_retest_refuses_changed_target_and_changed_comparison(self) -> None:
        second_case = json.loads(RETEST_FIXTURE.read_text(encoding="utf-8"))
        second_result = run_case(second_case)
        comparison = compare_cases(self.case, self.result, second_case, second_result)
        changed_comparison = copy.deepcopy(comparison)
        changed_comparison["observation_change"] = "no_conclusive_synthetic_transition"
        with self.assertRaises(OfflineApiAssessmentError):
            verify_comparison(
                self.case, self.result, second_case, second_result, changed_comparison
            )
        second_case["target_id"] = "TARGET-SYNTHETIC-EXAMPLE-002"
        changed_second_result = run_case(second_case)
        with self.assertRaisesRegex(OfflineApiAssessmentError, "retest mission"):
            compare_cases(self.case, self.result, second_case, changed_second_result)

    def test_batch_command_rolls_up_reproduced_cases(self) -> None:
        second_case = json.loads(RETEST_FIXTURE.read_text(encoding="utf-8"))
        second_result = run_case(second_case)
        pairs = [(self.case, self.result), (second_case, second_result)]
        batch = run_batch(pairs)
        self.assertEqual(batch, run_batch(pairs[::-1]))
        self.assertEqual(batch["disposition_counts"]["corroborated_synthetic_signal"], 1)
        self.assertEqual(batch["disposition_counts"]["negative_synthetic_result"], 1)
        self.assertEqual(len(batch["mixed_observation_binding_sha256s"]), 1)
        self.assertEqual(verify_batch(pairs, batch)["status"], "valid")
        self.assertNotIn("synthetic-example-only", json.dumps(batch))
        with tempfile.TemporaryDirectory() as temp:
            prior_path = Path(temp) / "prior-result.json"
            second_path = Path(temp) / "second-result.json"
            batch_path = Path(temp) / "batch.json"
            prior_path.write_text(json.dumps(self.result), encoding="utf-8")
            second_path.write_text(json.dumps(second_result), encoding="utf-8")
            batch_path.write_text(json.dumps(batch), encoding="utf-8")
            pair_args = [
                "--case",
                str(FIXTURE),
                str(prior_path),
                "--case",
                str(RETEST_FIXTURE),
                str(second_path),
            ]
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["batch", *pair_args]), 0)
            self.assertEqual(json.loads(output.getvalue()), batch)
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(
                    main(["batch-verify", *pair_args, "--batch-result", str(batch_path)]), 0
                )
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")
        changed = copy.deepcopy(batch)
        changed["review_candidate_case_ids"] = []
        with self.assertRaises(OfflineApiAssessmentError):
            verify_batch(pairs, changed)
        with self.assertRaisesRegex(OfflineApiAssessmentError, "replay"):
            run_batch([pairs[0], pairs[0]])


if __name__ == "__main__":
    unittest.main()

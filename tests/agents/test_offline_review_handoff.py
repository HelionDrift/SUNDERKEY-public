"""Commander handoffs summarize reproduced reviews without new authority."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.offline_review_handoff import (
    MAX_HANDOFF_BYTES,
    OfflineReviewHandoffError,
    _classify,
    build_offline_review_handoff,
    verify_offline_review_handoff,
)
from sunderkey.offline_review_workflow import build_offline_review_bundle
from tests.agents.test_offline_review_workflow import jobs, request


class OfflineReviewHandoffTests(unittest.TestCase):
    def test_all_reproduced_jobs_form_deterministic_minimal_handoff(self):
        raw = request()
        bundle = build_offline_review_bundle(raw)
        output = build_offline_review_handoff(raw, bundle)
        reversed_raw = request(list(reversed(jobs())))
        reversed_bundle = build_offline_review_bundle(reversed_raw)
        self.assertEqual(output, build_offline_review_handoff(reversed_raw, reversed_bundle))
        self.assertEqual(len(output["items"]), len(raw["jobs"]))
        self.assertEqual(
            {item["job_id"] for item in output["items"]},
            {job["job_id"] for job in raw["jobs"]},
        )
        self.assertEqual(output["source_bundle_sha256"], bundle["bundle_sha256"])
        self.assertEqual(output["authority_effect"], "none")
        self.assertEqual(output["qualification_effect"], "none")
        self.assertFalse(output["network_call_performed"])
        self.assertEqual(output["effects"]["assignment"], "none")
        by_kind = {item["kind"]: item for item in output["items"]}
        self.assertEqual(
            by_kind["credential_exposure"]["review_lane"],
            "candidate_for_independent_review",
        )
        self.assertEqual(
            by_kind["metadata_impact"]["review_lane"],
            "attention_for_independent_review",
        )
        self.assertEqual(by_kind["restricted_asset"]["review_lane"], "inconclusive")
        self.assertEqual(by_kind["inert_resilience"]["review_lane"], "inconclusive")
        self.assertNotIn("principal_ref", str(output))
        self.assertNotIn("credential_ref", str(output))
        self.assertNotIn("dataset_ref", str(output))

    def test_handoff_rejects_mutated_bundle_before_publication(self):
        raw = request()
        bundle = build_offline_review_bundle(raw)
        bundle["jobs"][0]["result"]["items"][0]["disposition"] = "compromised"
        with self.assertRaisesRegex(OfflineReviewHandoffError, "not reproducible"):
            build_offline_review_handoff(raw, bundle)

    def test_verifier_rejects_changed_handoff_and_json_type_substitution(self):
        raw = request()
        bundle = build_offline_review_bundle(raw)
        handoff = build_offline_review_handoff(raw, bundle)
        self.assertEqual(
            verify_offline_review_handoff(raw, bundle, handoff)["status"], "valid",
        )
        handoff["items"][0]["review_lane"] = "authorized_to_execute"
        with self.assertRaisesRegex(OfflineReviewHandoffError, "does not reproduce"):
            verify_offline_review_handoff(raw, bundle, handoff)
        handoff = build_offline_review_handoff(raw, bundle)
        handoff["network_call_performed"] = 0
        with self.assertRaisesRegex(OfflineReviewHandoffError, "does not reproduce"):
            verify_offline_review_handoff(raw, bundle, handoff)

    def test_closed_review_lanes_include_stale_attention_and_future_kind_fallback(self):
        for kind, result, expected in (
            ("credential_exposure", {"items": [{"disposition": "stale_signal"}]}, "stale"),
            ("synthetic_scenario", {"items": [{"disposition": "expired_request"}]}, "stale"),
            (
                "restricted_asset",
                {"status": "counterevidence_present", "reasons": ["control_counterevidence"]},
                "attention_for_independent_review",
            ),
            (
                "restricted_asset",
                {
                    "status": "bounded_inference_for_review",
                    "reasons": ["prerequisites_and_control_asserted"],
                },
                "candidate_for_independent_review",
            ),
            (
                "inert_resilience",
                {
                    "status": "readiness_evidence_for_review",
                    "review_reasons": ["all_facets_protected_asserted"],
                },
                "candidate_for_independent_review",
            ),
            (
                "detection_rule",
                {"status": "stale_evidence", "reasons": ["snapshot_expired"]},
                "stale",
            ),
            (
                "email_control",
                {"status": "attention_required", "review_reasons": ["delivery_asserted"]},
                "attention_for_independent_review",
            ),
            ("future_kind", {}, "inconclusive"),
        ):
            with self.subTest(kind=kind, result=result):
                lane, reasons = _classify({"kind": kind, "result": result})
                self.assertEqual(lane, expected)
                self.assertTrue(reasons)

    def test_cli_builds_and_verifies_bounded_handoff(self):
        parser = build_parser()
        raw = request(jobs()[:1])
        bundle = build_offline_review_bundle(raw)
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            bundle_path = Path(directory) / "bundle.json"
            handoff_path = Path(directory) / "handoff.json"
            input_path.write_text(json.dumps(raw), encoding="utf-8")
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            build_args = parser.parse_args([
                "offline-review-handoff", "--input", str(input_path),
                "--bundle", str(bundle_path),
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                build_args.handler(build_args)
            handoff = json.loads(output.getvalue())
            self.assertEqual(len(handoff["items"]), 1)
            handoff_path.write_text(json.dumps(handoff), encoding="utf-8")
            verify_args = parser.parse_args([
                "offline-review-handoff-verify", "--input", str(input_path),
                "--bundle", str(bundle_path), "--handoff", str(handoff_path),
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_args.handler(verify_args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")
            handoff_path.write_text('{"items":[],"items":[]}', encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                verify_args.handler(verify_args)
            handoff_path.write_bytes(b" " * (MAX_HANDOFF_BYTES + 1))
            with self.assertRaisesRegex(SunderkeyError, "size limit"):
                verify_args.handler(verify_args)


if __name__ == "__main__":
    unittest.main()

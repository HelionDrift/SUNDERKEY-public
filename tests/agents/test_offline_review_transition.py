"""Offline review transitions compare declared sources without live verdicts."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.offline_review_handoff import build_offline_review_handoff
from sunderkey.offline_review_transition import (
    MAX_TRANSITION_BYTES,
    OfflineReviewTransitionError,
    build_offline_review_transition,
    verify_offline_review_transition,
)
from sunderkey.offline_review_workflow import build_offline_review_bundle
from tests.agents.test_offline_review_workflow import jobs, request


def snapshot(selected_jobs=None, reviewed_at="2026-09-23T13:00:00Z"):
    raw = request(jobs() if selected_jobs is None else selected_jobs)
    raw["reviewed_at"] = reviewed_at
    bundle = build_offline_review_bundle(raw)
    handoff = build_offline_review_handoff(raw, bundle)
    return raw, bundle, handoff


class OfflineReviewTransitionTests(unittest.TestCase):
    def test_unchanged_declared_sources_do_not_claim_unchanged_target(self):
        prior = snapshot()
        current = snapshot(reviewed_at="2026-09-23T14:00:00Z")
        output = build_offline_review_transition(*prior, *current)
        self.assertEqual(len(output["items"]), len(prior[0]["jobs"]))
        self.assertEqual(
            {item["job_id"] for item in output["items"]},
            {job["job_id"] for job in prior[0]["jobs"]},
        )
        self.assertTrue(all(
            item["change_type"] == "same_declared_sources_same_review"
            for item in output["items"]
        ))
        self.assertTrue(all(not item["verified_fix"] for item in output["items"]))
        self.assertTrue(all(not item["confirmed_regression"] for item in output["items"]))
        self.assertEqual(output["authority_effect"], "none")
        self.assertEqual(output["effects"]["retest_execution"], "none")
        self.assertFalse(output["network_call_performed"])
        self.assertEqual(
            verify_offline_review_transition(*prior, *current, output)["status"],
            "valid",
        )

    def test_time_dependent_and_changed_source_review_transitions(self):
        selected = jobs()[:1]
        prior = snapshot(selected)
        later = snapshot(jobs()[:1], reviewed_at="2026-09-24T13:00:00Z")
        output = build_offline_review_transition(*prior, *later)
        self.assertEqual(
            output["items"][0]["change_type"],
            "same_declared_sources_review_changed",
        )
        self.assertEqual(output["items"][0]["current_review_lane"], "stale")
        changed_jobs = jobs()[:1]
        changed_jobs[0]["payload"]["consents"] = []
        changed = snapshot(changed_jobs, reviewed_at="2026-09-23T14:00:00Z")
        output = build_offline_review_transition(*prior, *changed)
        self.assertEqual(
            output["items"][0]["change_type"],
            "changed_declared_sources_review_changed",
        )

    def test_added_removed_and_cross_scope_fail_closed(self):
        prior = snapshot(jobs()[:1])
        current = snapshot(jobs()[1:2], reviewed_at="2026-09-23T14:00:00Z")
        output = build_offline_review_transition(*prior, *current)
        self.assertEqual(
            {item["change_type"] for item in output["items"]},
            {"added_job", "removed_job"},
        )
        other_request = request([{
            "job_id": "job:impact", "kind": "metadata_impact",
            "payload": {"observations": []},
        }])
        other_request["tenant_id"] = "tenant:other"
        other_request["reviewed_at"] = "2026-09-23T14:00:00Z"
        other_bundle = build_offline_review_bundle(other_request)
        other_handoff = build_offline_review_handoff(other_request, other_bundle)
        with self.assertRaisesRegex(OfflineReviewTransitionError, "cross tenant"):
            build_offline_review_transition(
                *prior, other_request, other_bundle, other_handoff,
            )

    def test_reversed_time_and_tampered_handoff_are_rejected(self):
        prior = snapshot()
        same_time = snapshot()
        with self.assertRaisesRegex(OfflineReviewTransitionError, "strictly ordered"):
            build_offline_review_transition(*prior, *same_time)
        current = snapshot(reviewed_at="2026-09-23T14:00:00Z")
        current[2]["items"][0]["review_lane"] = "authorized_to_execute"
        with self.assertRaisesRegex(OfflineReviewTransitionError, "not reproducible"):
            build_offline_review_transition(*prior, *current)

    def test_transition_verifier_rejects_mutation_and_type_substitution(self):
        prior = snapshot()
        current = snapshot(reviewed_at="2026-09-23T14:00:00Z")
        output = build_offline_review_transition(*prior, *current)
        output["items"][0]["verified_fix"] = True
        with self.assertRaisesRegex(OfflineReviewTransitionError, "does not reproduce"):
            verify_offline_review_transition(*prior, *current, output)
        output = build_offline_review_transition(*prior, *current)
        output["network_call_performed"] = 0
        with self.assertRaisesRegex(OfflineReviewTransitionError, "does not reproduce"):
            verify_offline_review_transition(*prior, *current, output)

    def test_cli_build_and_verify_are_bounded(self):
        parser = build_parser()
        prior = snapshot(jobs()[:1])
        current = snapshot(jobs()[:1], reviewed_at="2026-09-23T14:00:00Z")
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / f"source-{index}.json" for index in range(6)]
            for path, value in zip(paths, (*prior, *current), strict=True):
                path.write_text(json.dumps(value), encoding="utf-8")
            options = [
                "--prior-input", str(paths[0]),
                "--prior-bundle", str(paths[1]),
                "--prior-handoff", str(paths[2]),
                "--current-input", str(paths[3]),
                "--current-bundle", str(paths[4]),
                "--current-handoff", str(paths[5]),
            ]
            args = parser.parse_args(["offline-review-transition", *options])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                args.handler(args)
            transition = json.loads(output.getvalue())
            self.assertEqual(len(transition["items"]), 1)
            transition_path = Path(directory) / "transition.json"
            transition_path.write_text(json.dumps(transition), encoding="utf-8")
            verify_args = parser.parse_args([
                "offline-review-transition-verify", *options,
                "--transition", str(transition_path),
            ])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify_args.handler(verify_args)
            self.assertEqual(json.loads(output.getvalue())["status"], "valid")
            transition_path.write_text('{"items":[],"items":[]}', encoding="utf-8")
            with self.assertRaisesRegex(SunderkeyError, "Could not validate"):
                verify_args.handler(verify_args)
            transition_path.write_bytes(b" " * (MAX_TRANSITION_BYTES + 1))
            with self.assertRaisesRegex(SunderkeyError, "size limit"):
                verify_args.handler(verify_args)


if __name__ == "__main__":
    unittest.main()

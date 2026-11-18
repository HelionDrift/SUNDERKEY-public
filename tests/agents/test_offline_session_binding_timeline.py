"""Tests for inert session invalidation and binding timeline comparisons."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_session_binding_timeline as timeline
from sunderkey.offline_framework_declaration_core import canonical, report_address


def encoded(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class SessionBindingTimelineTests(unittest.TestCase):
    source_id = "synthetic:session-timeline"

    def setUp(self) -> None:
        self.model = timeline.component_fixture()

    def analyze(self, model: dict | None = None) -> timeline.SessionBindingTimelineReport:
        return timeline.analyze_session_binding_timeline(
            source_content=encoded(self.model if model is None else model), source_id=self.source_id
        )

    def test_fixture_negative_invariants_without_runtime_or_token_claim(self) -> None:
        report = self.analyze().to_dict()
        observations = {p["event_id"]: p for p in report["projections"]}
        self.assertEqual(observations["e3"]["basis"], "rotated_session")
        self.assertEqual(observations["e4"]["basis"], "device_mismatch")
        self.assertEqual(observations["e6"]["assessment"], "declared_deny_consistent")
        self.assertEqual(
            report["summary"]["assessments"]["candidate_declared_negative_policy_conflict"], 2
        )
        self.assertFalse(report["token_replay_performed"])
        self.assertFalse(report["session_runtime_observed"])
        self.assertFalse(report["finding_claimed"])
        self.assertEqual(set(report["effects"].values()), {"none"})
        self.assertEqual(report["wave_id"], "IW2-017")

    def test_no_negative_invariant_never_infers_allow(self) -> None:
        model = copy.deepcopy(self.model)
        model["policy"]["invalidate_on_rotation"] = False
        model["policy"]["device_binding_required"] = False
        model["events"] = model["events"][:4]
        projections = self.analyze(model).to_dict()["projections"]
        self.assertEqual([p["assessment"] for p in projections], ["unknown", "unknown"])
        self.assertEqual(
            [p["basis"] for p in projections], ["no_negative_invariant", "no_negative_invariant"]
        )

    def test_revoke_requires_policy_and_effective_before_observation(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"][5]["supplied_outcome"] = "allowed"
        self.assertEqual(
            self.analyze(model).to_dict()["projections"][2]["assessment"],
            "candidate_declared_negative_policy_conflict",
        )
        for effectiveness in (False, None):
            changed = copy.deepcopy(model)
            changed["events"][5]["revocation_effective_before_observation"] = effectiveness
            result = self.analyze(changed).to_dict()["projections"][2]
            self.assertEqual(result["assessment"], "unknown")
            self.assertEqual(result["basis"], "revocation_effect_unknown")
            self.assertIsNone(result["expected_negative_decision"])
        changed = copy.deepcopy(model)
        changed["policy"]["invalidate_on_revoke"] = False
        self.assertEqual(self.analyze(changed).to_dict()["projections"][2]["assessment"], "unknown")
        changed = copy.deepcopy(model)
        changed["concurrency_resolved"] = False
        self.assertEqual(self.analyze(changed).to_dict()["projections"][2]["assessment"], "unknown")

    def test_all_partial_and_concurrency_premises_yield_unknown(self) -> None:
        for field in (
            "events_complete",
            "policy_complete",
            "concurrency_resolved",
            "device_bindings_complete",
        ):
            model = copy.deepcopy(self.model)
            model[field] = False
            with self.subTest(field=field):
                report = self.analyze(model).to_dict()
                self.assertFalse(report["premises_complete"])
                self.assertTrue(all(p["assessment"] == "unknown" for p in report["projections"]))
                self.assertTrue(
                    all(p["expected_negative_decision"] is None for p in report["projections"])
                )
        model = copy.deepcopy(self.model)
        model["events_complete"] = False
        model["events"] = model["events"][1:]
        self.assertTrue(
            all(p["assessment"] == "unknown" for p in self.analyze(model).to_dict()["projections"])
        )
        model = copy.deepcopy(self.model)
        model["policy_complete"] = False
        model["events_complete"] = "true"
        with self.assertRaises(timeline.SessionBindingTimelineError):
            self.analyze(model)

    def test_observation_unknown_and_unknown_session_never_promote(self) -> None:
        model = copy.deepcopy(self.model)
        model["events"][2]["observation_complete"] = False
        model["events"][3]["supplied_outcome"] = "unknown"
        model["events"][5]["session_id"] = "synthetic:unseen"
        projections = self.analyze(model).to_dict()["projections"]
        self.assertEqual([p["assessment"] for p in projections], ["unknown", "unknown", "unknown"])
        self.assertEqual(
            [p["basis"] for p in projections],
            ["observation_unknown", "observation_unknown", "unknown_session"],
        )

    def test_closed_timeline_rejects_unsupported_lineage_and_fields(self) -> None:
        invalid = []
        duplicate_id = copy.deepcopy(self.model)
        duplicate_id["events"][1]["event_id"] = "e1"
        invalid.append(duplicate_id)
        missing_issue = copy.deepcopy(self.model)
        missing_issue["events"] = missing_issue["events"][1:]
        invalid.append(missing_issue)
        duplicate_session = copy.deepcopy(self.model)
        duplicate_session["events"].insert(1, copy.deepcopy(duplicate_session["events"][0]))
        duplicate_session["events"][1]["event_id"] = "e-extra"
        invalid.append(duplicate_session)
        missing_replacement = copy.deepcopy(self.model)
        missing_replacement["events"][1]["replacement_session_id"] = None
        invalid.append(missing_replacement)
        invalid_observe = copy.deepcopy(self.model)
        invalid_observe["events"][2]["device_id"] = None
        invalid.append(invalid_observe)
        invalid_effect_type = copy.deepcopy(self.model)
        invalid_effect_type["events"][5]["revocation_effective_before_observation"] = 1
        invalid.append(invalid_effect_type)
        invalid_issue_effect = copy.deepcopy(self.model)
        invalid_issue_effect["events"][0]["revocation_effective_before_observation"] = True
        invalid.append(invalid_issue_effect)
        invalid_early_effect = copy.deepcopy(self.model)
        invalid_early_effect["events"][3]["revocation_effective_before_observation"] = True
        invalid.append(invalid_early_effect)
        nonsynthetic_session = copy.deepcopy(self.model)
        nonsynthetic_session["events"][0]["session_id"] = "raw-token-label"
        invalid.append(nonsynthetic_session)
        nonsynthetic_device = copy.deepcopy(self.model)
        nonsynthetic_device["events"][0]["device_id"] = "raw-device-label"
        invalid.append(nonsynthetic_device)
        extra = copy.deepcopy(self.model)
        extra["target_url"] = "https://example.invalid"
        invalid.append(extra)
        for model in invalid:
            with self.subTest(model=model), self.assertRaises(timeline.SessionBindingTimelineError):
                self.analyze(model)

    def test_raw_decoder_bounds_and_duplicate_keys(self) -> None:
        invalid = (
            b'{"schema_version":"v1","schema_version":"v1"}',
            b'{"x":NaN}',
            b'{"x":1.2}',
            b'{"x":9223372036854775808}',
            b"\xff",
            b"[" * (timeline.MAX_DEPTH + 1) + b"0" + b"]" * (timeline.MAX_DEPTH + 1),
            b" " * (timeline.MAX_SOURCE_BYTES + 1),
        )
        for raw in invalid:
            with (
                self.subTest(raw=raw[:24]),
                self.assertRaises(timeline.SessionBindingTimelineError),
            ):
                timeline.analyze_session_binding_timeline(
                    source_content=raw, source_id=self.source_id
                )

    def test_exact_replay_rejects_changed_and_readdressed_source(self) -> None:
        report = self.analyze()
        self.assertEqual(
            timeline.verify_session_binding_timeline(
                report, source_content=encoded(self.model), source_id=self.source_id
            ),
            report,
        )
        changed = copy.deepcopy(self.model)
        changed["events"][2]["supplied_outcome"] = "denied"
        with self.assertRaises(timeline.SessionBindingTimelineError):
            timeline.verify_session_binding_timeline(
                report, source_content=encoded(changed), source_id=self.source_id
            )
        forged = report.to_dict()
        forged["projections"][0]["assessment"] = "declared_deny_consistent"
        forged["summary"]["assessments"]["candidate_declared_negative_policy_conflict"] -= 1
        forged["summary"]["assessments"]["declared_deny_consistent"] += 1
        forged["report_id"], forged["report_sha256"] = report_address(
            forged, domain=timeline.DOMAIN, prefix="SBT-"
        )
        parsed = timeline.SessionBindingTimelineReport.from_json(canonical(forged))
        with self.assertRaises(timeline.SessionBindingTimelineError):
            timeline.verify_session_binding_timeline(
                parsed, source_content=encoded(self.model), source_id=self.source_id
            )

    def test_report_claim_tampering_and_adapter_validation(self) -> None:
        report = self.analyze()
        forged = report.to_dict()
        forged["token_replay_performed"] = True
        with self.assertRaises(timeline.SessionBindingTimelineError):
            timeline.SessionBindingTimelineReport.from_json(canonical(forged))
        native = {"source_id": self.source_id, "source": copy.deepcopy(self.model)}
        self.assertEqual(timeline.analyze_supplied_session_binding_timeline(native), report)
        native["source"]["concurrency_resolved"] = False
        self.assertNotEqual(timeline.analyze_supplied_session_binding_timeline(native), report)
        native["extra"] = False
        with self.assertRaises(timeline.SessionBindingTimelineError):
            timeline.analyze_supplied_session_binding_timeline(native)

    def test_example_fixture_and_no_effects(self) -> None:
        root = Path(__file__).resolve().parents[2]
        example = json.loads(
            (root / "examples/offline-session-binding-timeline-component.json").read_text()
        )
        self.assertEqual(example["payload"]["model"]["source"], self.model)
        self.assertEqual(example["profile_id"], timeline.PROFILE_ID)
        self.assertEqual(example["component_id"], timeline.COMPONENT_ID)
        report = self.analyze()
        with patch("socket.create_connection", side_effect=AssertionError("network attempt")):
            with patch("subprocess.run", side_effect=AssertionError("process attempt")):
                self.assertEqual(
                    timeline.verify_session_binding_timeline(
                        report, source_content=encoded(self.model), source_id=self.source_id
                    ),
                    report,
                )


if __name__ == "__main__":
    unittest.main()

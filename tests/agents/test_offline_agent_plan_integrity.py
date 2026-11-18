"""Contracts for supplied agent goal and plan revision comparisons."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_agent_plan_integrity as analysis


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def rows(model: dict) -> dict[str, dict]:
    document = analysis.analyze_supplied_agent_plan_integrity(model).to_dict()
    return {row["revision_id"]: row for row in document["revision_projections"]}


class AgentPlanIntegrityTests(unittest.TestCase):
    def test_fixture_and_original_replay(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_plan_integrity(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["work_package_id"], analysis.WORK_PACKAGE_ID)
        self.assertEqual(document["blueprint_sha256"], analysis.BLUEPRINT_SHA256)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        projected = {row["revision_id"]: row for row in document["revision_projections"]}
        self.assertEqual(
            projected["revision-denied-applied"]["disposition"],
            "candidate_declared_denied_change_applied",
        )
        self.assertTrue(projected["revision-denied-applied"]["goal_changed"])
        self.assertTrue(projected["revision-denied-applied"]["step_sequence_changed"])
        self.assertEqual(
            projected["revision-rejected"]["disposition"], "declared_change_not_applied"
        )
        self.assertEqual(projected["revision-unknown"]["disposition"], "unknown")
        self.assertEqual(
            analysis.AgentPlanIntegrityReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.AgentPlanIntegrityReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.verify_supplied_agent_plan_integrity(report, model=model).to_json(),
            report.to_json(),
        )

    def test_checked_component_example(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "examples"
            / "offline-agent-plan-integrity-component.json"
        )
        request = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(request["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(request["component_id"], analysis.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"], {"network": [], "filesystem": [], "process": [], "credential": []}
        )
        self.assertEqual(request["payload"]["model"], analysis.component_fixture())

    def test_step_reorder_is_a_change(self):
        model = analysis.component_fixture()
        item = model["revisions"][0]
        item["proposed_goal_id"] = model["baseline"]["goal_id"]
        item["proposed_step_ids"] = list(reversed(model["baseline"]["step_ids"]))
        row = rows(model)["revision-denied-applied"]
        self.assertFalse(row["goal_changed"])
        self.assertTrue(row["step_sequence_changed"])
        self.assertEqual(row["disposition"], "candidate_declared_denied_change_applied")

    def test_no_change_cannot_be_a_hijack_candidate(self):
        model = analysis.component_fixture()
        item = model["revisions"][0]
        item["proposed_goal_id"] = model["baseline"]["goal_id"]
        item["proposed_step_ids"] = model["baseline"]["step_ids"].copy()
        row = rows(model)["revision-denied-applied"]
        self.assertEqual(row["disposition"], "declared_unchanged_plan")
        self.assertEqual(
            analysis.analyze_supplied_agent_plan_integrity(model).to_dict()["candidate_count"], 0
        )

    def test_approved_change_is_unverified_not_candidate(self):
        model = analysis.component_fixture()
        model["revisions"][0]["approval_state"] = "approved"
        row = rows(model)["revision-denied-applied"]
        self.assertEqual(row["disposition"], "declared_approved_change_unverified")

    def test_owner_denial_application_conflict_is_unknown(self):
        model = analysis.component_fixture()
        model["revisions"][0]["origin"] = "owner"
        row = rows(model)["revision-denied-applied"]
        self.assertEqual(row["disposition"], "unknown_owner_approval_conflict")
        self.assertEqual(row["unknowns"], ["owner_approval_conflict"])
        self.assertEqual(
            analysis.analyze_supplied_agent_plan_integrity(model).to_dict()["candidate_count"], 0
        )

    def test_incomplete_premises_never_create_candidate(self):
        cases = (
            (
                lambda m: m["revisions"][0].update(previous_goal_id="different-goal"),
                "previous_snapshot_not_baseline",
            ),
            (
                lambda m: m["revisions"][0].update(
                    previous_step_ids=["step-summarize", "step-inventory"]
                ),
                "previous_snapshot_not_baseline",
            ),
            (
                lambda m: m["revisions"][0].update(context_complete=False),
                "revision_context_incomplete",
            ),
            (
                lambda m: m["revisions"][0].update(observation_complete=False),
                "application_observation_incomplete",
            ),
            (
                lambda m: m["revisions"][0].update(application_state="unknown"),
                "application_observation_incomplete",
            ),
            (lambda m: m["revisions"][0].update(origin="unknown"), "origin_unknown"),
            (lambda m: m["revisions"][0].update(approval_state="unknown"), "approval_unknown"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                model = analysis.component_fixture()
                mutate(model)
                row = rows(model)["revision-denied-applied"]
                self.assertEqual(row["disposition"], "unknown")
                self.assertIn(expected, row["unknowns"])

    def test_permutation_preserves_projection_but_not_source_address(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_agent_plan_integrity(model).to_dict()
        model["evidence_sources"].reverse()
        model["revisions"].reverse()
        changed = analysis.analyze_supplied_agent_plan_integrity(model).to_dict()
        self.assertEqual(changed["revision_projections"], original["revision_projections"])
        self.assertNotEqual(changed["source"]["model_sha256"], original["source"]["model_sha256"])

    def test_bad_types_semantics_provenance_and_bounds_rejected(self):
        base = analysis.component_fixture()
        changes = (
            lambda m: m.update(schema_version=True),
            lambda m: m["baseline"].update(goal_id="unknown"),
            lambda m: m["baseline"].update(step_ids=[]),
            lambda m: m["baseline"].update(step_ids=["step-a", "step-a"]),
            lambda m: m["baseline"].update(source_id="absent-source"),
            lambda m: m["revisions"][0].update(origin="model"),
            lambda m: m["revisions"][0].update(approval_state="implicit"),
            lambda m: m["revisions"][0].update(application_state="executed"),
            lambda m: m["revisions"][0].update(context_complete=1),
            lambda m: m["revisions"][0].update(source_id="absent-source"),
            lambda m: m["revisions"][0].update(proposed_goal_id="https://host.example/path"),
            lambda m: m["revisions"].append(copy.deepcopy(m["revisions"][0])),
            lambda m: m["evidence_sources"].append(copy.deepcopy(m["evidence_sources"][0])),
            lambda m: m["revisions"].__imul__(analysis.MAX_REVISIONS),
            lambda m: m.update(extra=True),
        )
        for change in changes:
            model = copy.deepcopy(base)
            change(model)
            with self.subTest(model=model):
                with self.assertRaises(analysis.AgentPlanIntegrityError):
                    analysis.analyze_supplied_agent_plan_integrity(model)

    def test_duplicate_json_keys_and_bad_bytes_rejected(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.analyze_supplied_agent_plan_integrity_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"origin":"external"', '"origin":"external","origin":"owner"', 1
        )
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.analyze_supplied_agent_plan_integrity_bytes(model_bytes=text.encode("ascii"))
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.analyze_supplied_agent_plan_integrity_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.analyze_supplied_agent_plan_integrity_bytes(model_bytes=bytearray(b"{}"))

    def test_forged_report_even_with_recomputed_hash_is_rejected(self):
        report = analysis.analyze_supplied_agent_plan_integrity(analysis.component_fixture())
        forged = report.to_dict()
        forged["candidate_count"] = 0
        unsigned = {k: v for k, v in forged.items() if k not in {"report_id", "report_sha256"}}
        digest = hashlib.sha256(
            canonical({"domain": analysis.DOMAIN, "report": unsigned}).encode("ascii")
        ).hexdigest()
        forged["report_id"] = "APL-" + digest[:32].upper()
        forged["report_sha256"] = "sha256:" + digest
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.AgentPlanIntegrityReport.from_dict(forged)
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.AgentPlanIntegrityReport(canonical(forged))

    def test_retained_model_is_not_original_source_assurance(self):
        original = analysis.component_fixture()
        changed = copy.deepcopy(original)
        changed["revisions"][0]["approval_state"] = "approved"
        changed_report = analysis.analyze_supplied_agent_plan_integrity(changed)
        analysis.AgentPlanIntegrityReport.from_json(changed_report.to_json())
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.verify_supplied_agent_plan_integrity(changed_report, model=original)

    def test_report_duplicate_key_and_noncanonical_text_rejected(self):
        report = analysis.analyze_supplied_agent_plan_integrity(analysis.component_fixture())
        text = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.AgentPlanIntegrityReport.from_json(text)
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.AgentPlanIntegrityReport.from_json(" " + report.to_json())
        with self.assertRaises(analysis.AgentPlanIntegrityError):
            analysis.verify_supplied_agent_plan_integrity(
                report.to_dict(), model=analysis.component_fixture()
            )

    def test_no_agent_execution_network_process_or_file_effect(self):
        with (
            patch("builtins.open", side_effect=AssertionError("file effect")),
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_agent_plan_integrity(analysis.component_fixture())
            document = report.to_dict()
            self.assertTrue(all(value == "none" for value in document["effects"].values()))
            self.assertTrue(document["offline_only"])
            self.assertFalse(document["target_behavior_verified"])
            self.assertIsNone(document["live_vulnerability_verdict"])


if __name__ == "__main__":
    unittest.main()

"""Contracts for supplied agent tool-use authority comparisons."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_agent_tool_authority as analysis


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def rows(model: dict) -> dict[str, dict]:
    document = analysis.analyze_supplied_agent_tool_authority(model).to_dict()
    return {row["use_id"]: row for row in document["tool_use_projections"]}


class AgentToolAuthorityTests(unittest.TestCase):
    def test_fixture_and_original_replay(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_tool_authority(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["work_package_id"], analysis.WORK_PACKAGE_ID)
        self.assertEqual(document["blueprint_sha256"], analysis.BLUEPRINT_SHA256)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        projected = {row["use_id"]: row for row in document["tool_use_projections"]}
        self.assertEqual(projected["use-overreach"]["violated_declarations"], ["tier_exceeded"])
        self.assertEqual(projected["use-overreach"]["disposition"], "candidate_declared_overreach")
        self.assertEqual(projected["use-match"]["disposition"], "matches_declared_policy")
        self.assertEqual(projected["use-unknown"]["disposition"], "unknown")
        self.assertEqual(
            analysis.AgentToolAuthorityReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.AgentToolAuthorityReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.verify_supplied_agent_tool_authority(report, model=model).to_json(),
            report.to_json(),
        )

    def test_checked_component_example(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "examples"
            / "offline-agent-tool-authority-component.json"
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

    def test_exact_tool_resource_tier_and_approval_denials(self):
        base = analysis.component_fixture()
        cases = (
            (
                lambda m: m["tool_uses"][0].update(tool_id="tool-other", requested_tier="R0"),
                "tool_not_allowed",
            ),
            (
                lambda m: m["tool_uses"][0].update(
                    resource_id="resource-other", requested_tier="R0"
                ),
                "resource_not_allowed",
            ),
            (
                lambda m: m["tool_uses"][0].update(approval_state="denied", requested_tier="R0"),
                "approval_denied",
            ),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                model = copy.deepcopy(base)
                mutate(model)
                row = rows(model)["use-overreach"]
                self.assertEqual(row["violated_declarations"], [expected])
                self.assertEqual(row["disposition"], "candidate_declared_overreach")

    def test_multiple_violations_have_stable_order(self):
        model = analysis.component_fixture()
        model["tool_uses"][0].update(
            tool_id="tool-other", resource_id="resource-other", approval_state="denied"
        )
        row = rows(model)["use-overreach"]
        self.assertEqual(
            row["violated_declarations"],
            ["tool_not_allowed", "resource_not_allowed", "tier_exceeded", "approval_denied"],
        )

    def test_declared_allow_rejected_is_not_security_candidate(self):
        model = analysis.component_fixture()
        model["tool_uses"][1]["observed_admission"] = "rejected"
        row = rows(model)["use-match"]
        self.assertEqual(row["disposition"], "declared_allow_rejected_contradiction")
        self.assertEqual(
            analysis.analyze_supplied_agent_tool_authority(model).to_dict()["candidate_count"], 1
        )

    def test_unknowns_never_create_candidate(self):
        cases = (
            (lambda m: m["policy"].update(complete=False), "policy_incomplete"),
            (lambda m: m["tool_uses"][0].update(context_complete=False), "use_context_incomplete"),
            (
                lambda m: m["tool_uses"][0].update(observation_complete=False),
                "admission_observation_incomplete",
            ),
            (
                lambda m: m["tool_uses"][0].update(observed_admission="unknown"),
                "admission_observation_incomplete",
            ),
            (lambda m: m["tool_uses"][0].update(approval_state="unknown"), "approval_unknown"),
            (lambda m: m["tool_uses"][0].update(tool_id="unknown"), "tool_unknown"),
            (lambda m: m["tool_uses"][0].update(resource_id="unknown"), "resource_unknown"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                model = analysis.component_fixture()
                mutate(model)
                row = rows(model)["use-overreach"]
                self.assertEqual(row["disposition"], "unknown")
                self.assertIn(expected, row["unknowns"])
                self.assertIsNone(row["expected_admission"])

    def test_permutation_preserves_projection_but_not_source_address(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_agent_tool_authority(model).to_dict()
        model["evidence_sources"].reverse()
        model["tool_uses"].reverse()
        changed = analysis.analyze_supplied_agent_tool_authority(model).to_dict()
        self.assertEqual(changed["tool_use_projections"], original["tool_use_projections"])
        self.assertNotEqual(changed["source"]["model_sha256"], original["source"]["model_sha256"])

    def test_bad_types_semantics_provenance_and_bounds_rejected(self):
        base = analysis.component_fixture()
        changes = (
            lambda m: m.update(schema_version=True),
            lambda m: m["policy"].update(complete=1),
            lambda m: m["policy"].update(maximum_tier="R3"),
            lambda m: m["policy"].update(allowed_tool_ids=["unknown"]),
            lambda m: m["policy"].update(allowed_tool_ids=["tool-read", "tool-read"]),
            lambda m: m["policy"].update(source_id="absent-source"),
            lambda m: m["tool_uses"][0].update(requested_tier="R3"),
            lambda m: m["tool_uses"][0].update(observed_admission="executed"),
            lambda m: m["tool_uses"][0].update(context_complete=1),
            lambda m: m["tool_uses"][0].update(source_id="absent-source"),
            lambda m: m["tool_uses"][0].update(resource_id="https://host.example/path"),
            lambda m: m["tool_uses"].append(copy.deepcopy(m["tool_uses"][0])),
            lambda m: m["evidence_sources"].append(copy.deepcopy(m["evidence_sources"][0])),
            lambda m: m["tool_uses"].__imul__(analysis.MAX_USES),
            lambda m: m.update(extra=True),
        )
        for change in changes:
            model = copy.deepcopy(base)
            change(model)
            with self.subTest(model=model):
                with self.assertRaises(analysis.AgentToolAuthorityError):
                    analysis.analyze_supplied_agent_tool_authority(model)

    def test_duplicate_json_keys_and_bad_bytes_rejected(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.analyze_supplied_agent_tool_authority_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"approval_state":"approved"',
            '"approval_state":"approved","approval_state":"denied"',
            1,
        )
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.analyze_supplied_agent_tool_authority_bytes(model_bytes=text.encode("ascii"))
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.analyze_supplied_agent_tool_authority_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.analyze_supplied_agent_tool_authority_bytes(model_bytes=bytearray(b"{}"))

    def test_forged_report_even_with_recomputed_hash_is_rejected(self):
        report = analysis.analyze_supplied_agent_tool_authority(analysis.component_fixture())
        forged = report.to_dict()
        forged["candidate_count"] = 0
        unsigned = {k: v for k, v in forged.items() if k not in {"report_id", "report_sha256"}}
        digest = hashlib.sha256(
            canonical({"domain": analysis.DOMAIN, "report": unsigned}).encode("ascii")
        ).hexdigest()
        forged["report_id"] = "ATA-" + digest[:32].upper()
        forged["report_sha256"] = "sha256:" + digest
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.AgentToolAuthorityReport.from_dict(forged)
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.AgentToolAuthorityReport(canonical(forged))

    def test_retained_model_is_not_original_source_assurance(self):
        original = analysis.component_fixture()
        changed = copy.deepcopy(original)
        changed["policy"]["maximum_tier"] = "R2"
        changed_report = analysis.analyze_supplied_agent_tool_authority(changed)
        analysis.AgentToolAuthorityReport.from_json(changed_report.to_json())
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.verify_supplied_agent_tool_authority(changed_report, model=original)

    def test_report_duplicate_key_and_noncanonical_text_rejected(self):
        report = analysis.analyze_supplied_agent_tool_authority(analysis.component_fixture())
        text = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.AgentToolAuthorityReport.from_json(text)
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.AgentToolAuthorityReport.from_json(" " + report.to_json())
        with self.assertRaises(analysis.AgentToolAuthorityError):
            analysis.verify_supplied_agent_tool_authority(
                report.to_dict(), model=analysis.component_fixture()
            )

    def test_no_tool_execution_network_process_or_file_effect(self):
        with (
            patch("builtins.open", side_effect=AssertionError("file effect")),
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_agent_tool_authority(analysis.component_fixture())
            document = report.to_dict()
            self.assertTrue(all(value == "none" for value in document["effects"].values()))
            self.assertTrue(document["offline_only"])
            self.assertFalse(document["target_behavior_verified"])
            self.assertIsNone(document["live_vulnerability_verdict"])


if __name__ == "__main__":
    unittest.main()

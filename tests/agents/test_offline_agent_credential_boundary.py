"""Agent credential references remain inert supplied boundary declarations."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_agent_credential_boundary as analysis

ROOT = Path(__file__).resolve().parents[2]


class AgentCredentialBoundaryTests(unittest.TestCase):
    def test_fixture_projects_four_mismatches_and_one_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_credential_boundary(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 4)
        self.assertEqual(value["unknown_count"], 1)
        self.assertFalse(value["secret_value_decoding_performed"])
        self.assertFalse(value["credential_use_performed"])
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        projections = {row["use_id"]: row for row in value["use_projections"]}
        self.assertEqual(projections["within"]["risk_reasons"], [])
        self.assertEqual(projections["audience-mismatch"]["risk_reasons"], ["audience_not_allowed"])
        self.assertEqual(projections["scope-missing"]["risk_reasons"], ["required_scope_missing"])
        self.assertEqual(projections["agent-mismatch"]["risk_reasons"], ["agent_not_approved"])
        self.assertEqual(projections["expired"]["risk_reasons"], ["declared_expired"])
        self.assertEqual(projections["unknown"]["disposition"], "unknown")
        self.assertEqual(
            analysis.verify_supplied_agent_credential_boundary(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_agent_credential_boundary_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_revoked_and_multiple_mismatch_reasons_are_preserved(self) -> None:
        model = analysis.component_fixture()
        model["credentials"][0]["status"] = "revoked"
        model["uses"] = [copy.deepcopy(model["uses"][1])]
        model["uses"][0]["agent_id"] = "agent-two"
        model["uses"][0]["required_scopes"] = ["admin"]
        model["uses"][0]["invocation_epoch"] = 100
        row = analysis.analyze_supplied_agent_credential_boundary(model).to_dict()[
            "use_projections"
        ][0]
        self.assertEqual(
            row["risk_reasons"],
            [
                "declared_revoked", "agent_not_approved", "audience_not_allowed",
                "required_scope_missing", "declared_expired",
            ],
        )

    def test_missing_context_abstains_even_when_other_labels_conflict(self) -> None:
        model = analysis.component_fixture()
        model["uses"] = [copy.deepcopy(model["uses"][1])]
        model["uses"][0]["context_complete"] = False
        row = analysis.analyze_supplied_agent_credential_boundary(model).to_dict()[
            "use_projections"
        ][0]
        self.assertEqual(row["disposition"], "unknown")
        self.assertEqual(row["risk_reasons"], [])

    def test_invalid_identifiers_timestamps_and_references_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["credentials"][0].update(expires_at_epoch=True),
            lambda m: m["uses"][0].update(invocation_epoch=-1),
            lambda m: m["uses"][0].update(credential_id="missing"),
            lambda m: m["uses"][0].update(required_scopes=["read", "read"]),
            lambda m: m["credentials"].append(copy.deepcopy(m["credentials"][0])),
            lambda m: m["uses"][0].update(context_complete="yes"),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_agent_credential_boundary(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_credential_boundary(model)
        changed = copy.deepcopy(model)
        changed["uses"][0]["audience"] = "service-two"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_agent_credential_boundary(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_agent_credential_boundary_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_contains_no_secret_or_resources(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-agent-credential-boundary-component.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(request["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(request["component_id"], analysis.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(request["payload"]["model"], analysis.component_fixture())


if __name__ == "__main__":
    unittest.main()

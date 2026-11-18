"""Supplied agent resource-budget arithmetic and replay controls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_agent_resource_budget as analysis

ROOT = Path(__file__).resolve().parents[2]


class AgentResourceBudgetTests(unittest.TestCase):
    def test_fixture_separates_budget_rejection_and_unknown_tail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_resource_budget(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 2)
        self.assertFalse(document["source_authenticated"])
        self.assertFalse(document["provider_billing_verified"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        rows = document["event_projections"]
        self.assertEqual(
            [row["disposition"] for row in rows],
            [
                "within_declared_budget",
                "candidate_declared_budget_exceeded",
                "declared_rejected",
                "unknown",
                "unknown",
            ],
        )
        self.assertEqual(rows[0]["cumulative_cost_micro_usd"], 3)
        self.assertEqual(rows[1]["cumulative_cost_micro_usd"], 6)
        self.assertEqual(rows[2]["cumulative_requests"], 2)
        self.assertIsNone(rows[4]["cumulative_cost_micro_usd"])
        self.assertEqual(
            analysis.verify_supplied_agent_resource_budget(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_agent_resource_budget_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_integer_ceil_cost_and_each_ceiling_are_exact(self) -> None:
        model = analysis.component_fixture()
        model["events"] = model["events"][:1]
        model["rates"][0]["input_micro_usd_per_million"] = 1
        model["rates"][0]["output_micro_usd_per_million"] = 0
        row = analysis.analyze_supplied_agent_resource_budget(model).to_dict()[
            "event_projections"
        ][0]
        self.assertEqual(row["cumulative_cost_micro_usd"], 1)
        for field in ("maximum_requests", "maximum_tokens", "maximum_cost_micro_usd"):
            with self.subTest(field=field):
                changed = copy.deepcopy(model)
                changed["budget"][field] = 0
                row = analysis.analyze_supplied_agent_resource_budget(changed).to_dict()[
                    "event_projections"
                ][0]
                self.assertEqual(row["disposition"], "candidate_declared_budget_exceeded")

    def test_changed_original_and_tampered_export_are_rejected(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_resource_budget(model)
        changed = copy.deepcopy(model)
        changed["budget"]["maximum_cost_micro_usd"] = 6
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_agent_resource_budget(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_agent_resource_budget_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_invalid_rate_token_reference_and_duplicate_members_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["rates"][0].update(input_micro_usd_per_million=-1),
            lambda m: m["events"][0].update(input_tokens=True),
            lambda m: m["events"][0].update(input_tokens=10_000_001),
            lambda m: m["events"][0].update(model_id=[]),
            lambda m: m["events"][0].update(model_id="missing"),
            lambda m: m["events"].append(copy.deepcopy(m["events"][0])),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_agent_resource_budget(invalid)
        with self.assertRaises(ValueError):
            analysis.verify_supplied_agent_resource_budget_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-agent-resource-budget-component.json").read_text(
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

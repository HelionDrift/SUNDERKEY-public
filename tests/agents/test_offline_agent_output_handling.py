"""Metadata-only supplied agent-output handling controls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_agent_output_handling as analysis

ROOT = Path(__file__).resolve().parents[2]


def dispositions(model: dict) -> dict[str, str]:
    report = analysis.analyze_supplied_agent_output_handling(model).to_dict()
    return {row["flow_id"]: row["disposition"] for row in report["flow_projections"]}


class AgentOutputHandlingTests(unittest.TestCase):
    def test_fixture_is_replayable_and_unsigned(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_output_handling(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["work_package_id"], analysis.WORK_PACKAGE_ID)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertFalse(document["source_authenticated"])
        self.assertFalse(document["output_content_interpreted"])
        self.assertFalse(document["finding_claimed"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            dispositions(model),
            {
                "raw-query": "candidate_declared_unhandled_output",
                "display-only": "declared_display_only",
                "uncertain-query": "unknown",
            },
        )
        self.assertEqual(
            analysis.verify_supplied_agent_output_handling(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_agent_output_handling_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_declared_controls_and_rejection_are_not_candidates(self) -> None:
        model = analysis.component_fixture()
        model["flows"][0]["handling"] = "schema_validated"
        self.assertEqual(dispositions(model)["raw-query"], "declared_handled_unverified")
        model["flows"][0]["handling"] = "raw"
        model["flows"][0]["delivery"] = "rejected"
        self.assertEqual(dispositions(model)["raw-query"], "declared_rejected")
        model["flows"][0]["delivery"] = "accepted"
        model["outputs"][0]["trust"] = "trusted"
        self.assertEqual(
            dispositions(model)["raw-query"], "declared_trusted_source_unverified"
        )

    def test_incomplete_context_or_unknown_labels_abstain(self) -> None:
        model = analysis.component_fixture()
        model["flows"][0]["context_complete"] = False
        self.assertEqual(dispositions(model)["raw-query"], "unknown")
        model["flows"][0]["context_complete"] = True
        model["flows"][0]["handling"] = "unknown"
        self.assertEqual(dispositions(model)["raw-query"], "unknown")

    def test_changed_original_or_exported_report_is_rejected(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_output_handling(model)
        changed = copy.deepcopy(model)
        changed["flows"][0]["handling"] = "context_encoded"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_agent_output_handling(report, model=changed)
        document = report.to_dict()
        document["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_agent_output_handling_bytes(
                json.dumps(document).encode("utf-8"), model=model
            )

    def test_unbounded_ambiguous_or_content_bearing_models_are_rejected(self) -> None:
        model = analysis.component_fixture()
        for mutation in (
            lambda m: m["outputs"][0].update(content="not accepted"),
            lambda m: m["sinks"][0].update(kind="unknown-sink"),
            lambda m: m["flows"][0].update(output_id=[]),
            lambda m: m["flows"][0].update(sink_id="missing"),
            lambda m: m["flows"][0].update(context_complete=1),
            lambda m: m["flows"].append(copy.deepcopy(m["flows"][0])),
        ):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(model)
                mutation(bad)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_agent_output_handling(bad)
        with self.assertRaises(ValueError):
            analysis.analyze_supplied_agent_output_handling({**model, "flows": model["flows"] * 43})

    def test_exported_duplicate_keys_and_nonfinite_values_are_rejected(self) -> None:
        model = analysis.component_fixture()
        for content in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}'):
            with self.subTest(content=content):
                with self.assertRaises(ValueError):
                    analysis.verify_supplied_agent_output_handling_bytes(content, model=model)

    def test_checked_example_remains_inert(self) -> None:
        path = ROOT / "examples/offline-agent-output-handling-component.json"
        request = json.loads(path.read_text(encoding="utf-8"))
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

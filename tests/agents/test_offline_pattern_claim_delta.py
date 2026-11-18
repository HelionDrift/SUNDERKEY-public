"""Pattern graph comparisons remain unsigned declared-status deltas."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_pattern_claim_delta as delta
from sunderkey import offline_specialist_components as components
from sunderkey.offline_pattern_claim_graph import analyze_supplied_pattern_claim_graph
from tests.agents.test_offline_pattern_claim_graph import context, graph_fixture
from tests.agents.test_offline_pattern_task_relations import (
    expanded_plan_fixture,
    expanded_task_fixture,
    plan_fixture,
    task_fixture,
)

ROOT = Path(__file__).resolve().parents[2]


def delta_fixture() -> dict:
    return {
        "schema_version": 1,
        "comparison_label": "synthetic.pattern-graph-comparison",
        "sources": [{"source_id": "before"}, {"source_id": "after"}],
        "pairs": [
            {
                "pair_id": "synthetic.pair",
                "subject_id": "synthetic.caller-subject",
                "basis": "caller_declared_unverified",
                "before": {
                    "source_id": "before",
                    "hypothesis_id": "synthetic.bounded-conjunction",
                },
                "after": {
                    "source_id": "after",
                    "hypothesis_id": "synthetic.bounded-conjunction",
                },
            }
        ],
    }


class PatternClaimDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )
        cls.graph_model = graph_fixture()
        first = context(cls.catalog, task_fixture(), plan_fixture())
        six = context(cls.catalog, expanded_task_fixture(), expanded_plan_fixture())
        cls.before_sources = {"three": first, "six": six}
        changed_task = expanded_task_fixture()
        changed_task["task_id"] += ".after"
        changed_six = context(cls.catalog, changed_task, expanded_plan_fixture())
        cls.after_sources = {"three": first, "six": changed_six}
        cls.contexts = {
            source_id: {
                "graph_report": analyze_supplied_pattern_claim_graph(
                    cls.graph_model, source_contexts=sources,
                    catalog=cls.catalog, repository_root=ROOT,
                ),
                "graph_model": cls.graph_model,
                "source_contexts": sources,
            }
            for source_id, sources in (
                ("before", cls.before_sources), ("after", cls.after_sources)
            )
        }

    def analyze(self, model=None, *, graph_contexts=None) -> dict:
        return delta.analyze_pattern_claim_delta(
            delta_fixture() if model is None else model,
            graph_contexts=self.contexts if graph_contexts is None else graph_contexts,
            catalog=self.catalog, repository_root=ROOT,
        )

    def test_distinct_graphs_do_not_prove_change_or_time_order(self) -> None:
        model = delta_fixture()
        report = self.analyze(model)
        self.assertEqual(report["pair_observations"][0]["state"], "same_declared_status")
        self.assertFalse(report["flags"]["subject_equivalence_proven"])
        self.assertFalse(report["flags"]["time_order_proven"])
        self.assertFalse(report["flags"]["improvement_claimed"])
        self.assertFalse(report["flags"]["positive_use_approved"])
        self.assertEqual(set(report["operational_effects"].values()), {"none"})
        self.assertEqual(
            delta.verify_pattern_claim_delta(
                report, model=model, graph_contexts=self.contexts,
                catalog=self.catalog, repository_root=ROOT,
            ),
            report,
        )

    def test_repeated_evidence_and_positive_use_forgery_are_refused(self) -> None:
        with self.assertRaises(delta.PatternClaimDeltaError):
            self.analyze(graph_contexts={
                "before": self.contexts["before"],
                "after": self.contexts["before"],
            })
        report = self.analyze()
        forged = copy.deepcopy(report)
        forged["flags"]["positive_use_approved"] = True
        with self.assertRaises(delta.PatternClaimDeltaError):
            delta.verify_pattern_claim_delta(
                forged, model=delta_fixture(), graph_contexts=self.contexts,
                catalog=self.catalog, repository_root=ROOT,
            )
        changed = copy.deepcopy(self.contexts)
        changed["after"]["source_contexts"]["six"]["task_model"]["task_id"] = "forged"
        with self.assertRaises(delta.PatternClaimDeltaError):
            self.analyze(graph_contexts=changed)

    def test_invalid_pair_stops_before_graph_replay(self) -> None:
        wrong = delta_fixture()
        wrong["pairs"][0]["basis"] = "verified"
        with self.assertRaises(delta.PatternClaimDeltaError):
            self.analyze(wrong, graph_contexts=object())


class PatternClaimDeltaPrefilterTests(unittest.TestCase):
    def test_definitive_invalid_context_and_claim_stop_before_replay(self) -> None:
        shared = {}
        with patch(
            "sunderkey.offline_pattern_claim_delta.graph.verify_supplied_pattern_claim_graph",
            side_effect=AssertionError("graph replay must not start"),
        ):
            with self.assertRaisesRegex(delta.PatternClaimDeltaError, "distinct context objects"):
                delta.analyze_pattern_claim_delta(
                    delta_fixture(),
                    graph_contexts={"before": shared, "after": shared},
                    catalog=object(), repository_root=ROOT,
                )
        with patch(
            "sunderkey.offline_pattern_claim_delta.analyze_pattern_claim_delta",
            side_effect=AssertionError("comparison replay must not start"),
        ):
            with self.assertRaisesRegex(delta.PatternClaimDeltaError, "offline boundary"):
                delta.verify_pattern_claim_delta(
                    {"flags": {"positive_use_approved": True}},
                    model=object(), graph_contexts=object(), catalog=object(),
                    repository_root=ROOT,
                )

    def test_valid_shaped_claim_still_invokes_original_replay(self) -> None:
        report = {
            "flags": dict(delta._FLAGS),
            "operational_effects": dict(delta._EFFECTS),
        }
        with patch(
            "sunderkey.offline_pattern_claim_delta.analyze_pattern_claim_delta",
            return_value=report,
        ) as replay:
            self.assertEqual(
                delta.verify_pattern_claim_delta(
                    report, model=object(), graph_contexts=object(),
                    catalog=object(), repository_root=ROOT,
                ),
                report,
            )
            replay.assert_called_once()


if __name__ == "__main__":
    unittest.main()

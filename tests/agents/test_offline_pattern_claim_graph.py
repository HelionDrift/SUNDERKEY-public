"""Separate pattern relation sources cannot self-declare verified scope."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_pattern_claim_graph as graph_module
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey.offline_pattern_claim_graph import (
    PatternClaimGraph,
    PatternClaimGraphError,
    analyze_supplied_pattern_claim_graph,
    verify_supplied_pattern_claim_graph,
    verify_supplied_pattern_claim_graph_bytes,
)
from sunderkey.offline_pattern_task_relations import analyze_supplied_pattern_task_relations
from tests.agents.test_offline_pattern_task_relations import (
    bind_source_hashes,
    expanded_plan_fixture,
    expanded_task_fixture,
    plan_fixture,
    task_fixture,
)

ROOT = Path(__file__).resolve().parents[2]


def graph_fixture() -> dict:
    return json.loads(
        (ROOT / "examples/offline-pattern-claim-graph.json").read_text(encoding="utf-8")
    )


def context(catalog: object, task_model: dict, relation_model: dict) -> dict:
    task_report = task.run_offline_specialist_task(
        task_model, catalog=catalog, repository_root=ROOT
    )
    relation_report = analyze_supplied_pattern_task_relations(
        relation_model, task_report=task_report, task_model=task_model,
        catalog=catalog, repository_root=ROOT,
    )
    return {
        "relation_report": relation_report,
        "relation_model": relation_model,
        "task_report": task_report,
        "task_model": task_model,
    }


class PatternClaimGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(
            repository_root=ROOT
        )
        cls.contexts = {
            "three": context(cls.catalog, task_fixture(), plan_fixture()),
            "six": context(cls.catalog, expanded_task_fixture(), expanded_plan_fixture()),
        }

    def analyze(self, plan: dict, *, source_contexts=None) -> PatternClaimGraph:
        return analyze_supplied_pattern_claim_graph(
            plan,
            source_contexts=self.contexts if source_contexts is None else source_contexts,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_distinct_current_replays_remain_declared_scope_only(self) -> None:
        plan = graph_fixture()
        original = copy.deepcopy(plan)
        report = self.analyze(plan)
        body = report.to_dict()
        self.assertEqual(plan, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(len(body["source_bindings"]), 2)
        self.assertEqual(len(body["claim_observations"]), 2)
        self.assertEqual(
            body["hypothesis_observations"][0]["status"],
            "matches_declared_expectation",
        )
        self.assertFalse(body["flags"]["scope_equivalence_proven"])
        self.assertFalse(body["flags"]["source_authenticated"])
        self.assertFalse(body["flags"]["full_candidate_assembled"])
        self.assertFalse(body["flags"]["positive_use_approved"])
        self.assertFalse(body["flags"]["qualification_claimed"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_pattern_claim_graph(
                report, model=plan, source_contexts=self.contexts,
                catalog=self.catalog, repository_root=ROOT,
            ).to_json(),
            report.to_json(),
        )

    def test_contradiction_then_unresolved_precedence(self) -> None:
        plan = graph_fixture()
        contrary_plan = expanded_plan_fixture()
        contrary_plan["premises"][0]["expected_disposition"] = (
            "declared_required_value_consistent"
        )
        contrary = dict(self.contexts)
        contrary["six"] = context(
            self.catalog, expanded_task_fixture(), contrary_plan
        )
        body = self.analyze(plan, source_contexts=contrary).to_dict()
        self.assertEqual(
            body["hypothesis_observations"][0]["status"],
            "contradicts_declared_expectation",
        )

        unknown_task = expanded_task_fixture()
        unknown_task["jobs"][0]["request"]["payload"]["model"]["observations"][0][
            "declared_effective_value"
        ] = "unknown"
        unknown_plan = expanded_plan_fixture()
        bind_source_hashes(unknown_plan, unknown_task)
        unknown = dict(self.contexts)
        unknown["six"] = context(self.catalog, unknown_task, unknown_plan)
        body = self.analyze(plan, source_contexts=unknown).to_dict()
        self.assertEqual(body["hypothesis_observations"][0]["status"], "unresolved")

    def test_repeated_task_invalid_selector_and_forgery_are_refused(self) -> None:
        plan = graph_fixture()
        repeated = {"three": self.contexts["three"], "six": self.contexts["three"]}
        with self.assertRaises(PatternClaimGraphError):
            self.analyze(plan, source_contexts=repeated)
        wrong = copy.deepcopy(plan)
        wrong["claims"][0]["observation_id"] = "missing"
        with self.assertRaises(PatternClaimGraphError):
            self.analyze(wrong)
        report = self.analyze(plan)
        tampered = report.to_dict()
        tampered["flags"]["positive_use_approved"] = True
        with self.assertRaises(PatternClaimGraphError):
            verify_supplied_pattern_claim_graph(
                PatternClaimGraph._owned(tampered), model=plan,
                source_contexts=self.contexts, catalog=self.catalog,
                repository_root=ROOT,
            )
        with self.assertRaises(PatternClaimGraphError):
            verify_supplied_pattern_claim_graph(
                report.to_dict(), model=plan, source_contexts=self.contexts,
                catalog=self.catalog, repository_root=ROOT,
            )

    def test_invalid_graph_denies_before_source_replay(self) -> None:
        cases = []
        wrong_kind = graph_fixture()
        wrong_kind["claims"][0]["observation_kind"] = "hypothesis"
        cases.append(wrong_kind)
        broken_scope = graph_fixture()
        broken_scope["scope_bindings"][0]["basis"] = "verified"
        cases.append(broken_scope)
        cycle = graph_fixture()
        cycle["hypotheses"][0]["dependencies"].append(
            {"kind": "hypothesis", "id": "synthetic.bounded-conjunction"}
        )
        cases.append(cycle)
        for index, model in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(PatternClaimGraphError):
                    self.analyze(model, source_contexts=object())

    def test_exported_graph_requires_separate_original_replay(self) -> None:
        plan = graph_fixture()
        report = self.analyze(plan)
        exported = json.dumps(report.to_dict(), indent=2).encode("utf-8")
        self.assertEqual(
            verify_supplied_pattern_claim_graph_bytes(
                exported, model=plan, source_contexts=self.contexts,
                catalog=self.catalog, repository_root=ROOT,
            ).to_json(),
            report.to_json(),
        )
        forged = report.to_dict()
        forged["flags"]["positive_use_approved"] = True
        with self.assertRaises(PatternClaimGraphError):
            verify_supplied_pattern_claim_graph_bytes(
                json.dumps(forged).encode("utf-8"), model=plan,
                source_contexts=self.contexts, catalog=self.catalog,
                repository_root=ROOT,
            )
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'NaN',
            b'{' + b' ' * 262_144 + b'}',
        ):
            with self.subTest(raw=raw[:16]):
                with self.assertRaises(PatternClaimGraphError):
                    verify_supplied_pattern_claim_graph_bytes(
                        raw, model=plan, source_contexts=object(),
                        catalog=object(), repository_root=ROOT,
                    )


class PatternClaimGraphPrefilterTests(unittest.TestCase):
    def test_definitive_invalid_sources_and_effects_stop_before_replay(self) -> None:
        shared = {}
        with patch(
            "sunderkey.offline_pattern_claim_graph.pattern.verify_supplied_pattern_task_relations",
            side_effect=AssertionError("relation replay must not start"),
        ):
            with self.assertRaisesRegex(PatternClaimGraphError, "distinct context objects"):
                analyze_supplied_pattern_claim_graph(
                    graph_fixture(),
                    source_contexts={"three": shared, "six": shared},
                    catalog=object(), repository_root=ROOT,
                )
        forged = PatternClaimGraph._owned({"flags": {"positive_use_approved": True}})
        with patch(
            "sunderkey.offline_pattern_claim_graph._derive",
            side_effect=AssertionError("graph replay must not start"),
        ):
            with self.assertRaisesRegex(PatternClaimGraphError, "offline boundary"):
                verify_supplied_pattern_claim_graph(
                    forged, model=object(), source_contexts=object(),
                    catalog=object(), repository_root=ROOT,
                )
            with self.assertRaisesRegex(PatternClaimGraphError, "offline boundary"):
                verify_supplied_pattern_claim_graph_bytes(
                    json.dumps(forged.to_dict()).encode("utf-8"),
                    model=object(), source_contexts=object(),
                    catalog=object(), repository_root=ROOT,
                )

    def test_valid_shaped_claim_still_invokes_original_replay(self) -> None:
        body = {
            "flags": dict(graph_module._FLAGS),
            "operational_effects": dict(graph_module._EFFECTS),
        }
        report = PatternClaimGraph._owned(body)
        with patch("sunderkey.offline_pattern_claim_graph._derive", return_value=body) as replay:
            self.assertEqual(
                verify_supplied_pattern_claim_graph(
                    report, model=object(), source_contexts=object(),
                    catalog=object(), repository_root=ROOT,
                ).to_dict(),
                body,
            )
            replay.assert_called_once()


if __name__ == "__main__":
    unittest.main()

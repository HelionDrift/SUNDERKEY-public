"""Finite supplied grammar planning and original-source replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_grammar_plan import (
    FiniteGrammarPlanError,
    FiniteGrammarPlanReport,
    analyze_supplied_finite_grammar,
    component_fixture,
    verify_supplied_finite_grammar,
)


class FiniteGrammarPlanTests(unittest.TestCase):
    def test_counts_without_emitting_candidates(self) -> None:
        report = analyze_supplied_finite_grammar(component_fixture()).to_dict()
        self.assertEqual(report["derivation_count"], 2)
        self.assertEqual(report["minimum_expansion_bytes"], 5)
        self.assertEqual(report["maximum_expansion_bytes"], 6)
        self.assertEqual(report["candidate_count"], 0)
        self.assertFalse(report["payload_generated"])
        self.assertFalse(report["target_executed"])
        self.assertEqual(report["disposition"], "supplied_finite_grammar_plan")

    def test_incomplete_and_unreachable_are_unknown(self) -> None:
        model = component_fixture()
        model["grammar_complete"] = False
        model["rules"].append({
            "symbol_id": "orphan", "alternatives": [[{"literal": "unused"}]]
        })
        report = analyze_supplied_finite_grammar(model).to_dict()
        self.assertEqual(report["disposition"], "unknown")
        self.assertEqual(report["unreachable_rule_ids"], ["orphan"])
        self.assertEqual(report["reachable_rule_count"], 2)
        self.assertEqual(report["supplied_rule_count"], 3)
        self.assertEqual(report["unknown_count"], 2)

    def test_rejects_recursive_and_unresolved_rules(self) -> None:
        model = component_fixture()
        model["rules"][1]["alternatives"] = [[{"ref": "packet"}]]
        with self.assertRaises(FiniteGrammarPlanError):
            analyze_supplied_finite_grammar(model)
        model = component_fixture()
        model["rules"].append({
            "symbol_id": "orphan", "alternatives": [[{"ref": "orphan"}]]
        })
        with self.assertRaises(FiniteGrammarPlanError):
            analyze_supplied_finite_grammar(model)
        model = component_fixture()
        model["rules"][0]["alternatives"] = [[{"ref": "missing"}]]
        with self.assertRaises(FiniteGrammarPlanError):
            analyze_supplied_finite_grammar(model)

    def test_rejects_noninert_literals_and_expansion_overflow(self) -> None:
        model = component_fixture()
        model["rules"][1]["alternatives"] = [[{"literal": "../../x"}]]
        with self.assertRaises(FiniteGrammarPlanError):
            analyze_supplied_finite_grammar(model)
        model = component_fixture()
        model["rules"][0]["alternatives"] = [
            [{"ref": "body"}] * 8
        ]
        model["rules"][1]["alternatives"] = [
            [{"literal": "x"}] for _ in range(16)
        ]
        with self.assertRaises(FiniteGrammarPlanError):
            analyze_supplied_finite_grammar(model)

    def test_replay_requires_exact_wrapper_and_original_model(self) -> None:
        model = component_fixture()
        report = analyze_supplied_finite_grammar(model)
        self.assertEqual(
            verify_supplied_finite_grammar(report, model=copy.deepcopy(model)).to_json(),
            report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["rules"][1]["alternatives"][0][0]["literal"] = "Z"
        with self.assertRaises(FiniteGrammarPlanError):
            verify_supplied_finite_grammar(report, model=changed)
        with self.assertRaises(FiniteGrammarPlanError):
            FiniteGrammarPlanReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

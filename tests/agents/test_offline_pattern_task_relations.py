"""Explicit pattern hypotheses cannot promote unverified task sources."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_framework_declaration_core as core
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey.offline_pattern_task_relations import (
    PatternTaskRelations,
    PatternTaskRelationsError,
    analyze_supplied_pattern_task_relations,
    verify_supplied_pattern_task_relations,
    verify_supplied_pattern_task_relations_bytes,
)

ROOT = Path(__file__).resolve().parents[2]


def plan_fixture() -> dict:
    return json.loads(
        (ROOT / "examples/offline-pattern-task-relations.json").read_text(encoding="utf-8")
    )


def task_fixture() -> dict:
    filenames = (
        ("query", "offline-query-input-boundary-component.json"),
        ("interpreter", "offline-interpreter-input-boundary-component.json"),
        ("observable", "offline-observable-discrepancy-component.json"),
    )
    return {
        "schema_version": 1,
        "task_id": "synthetic.pattern-relation-task",
        "jobs": [
            {
                "job_id": job_id,
                "request": components.load_offline_specialist_component_request(
                    ROOT / "examples" / filename
                ),
            }
            for job_id, filename in filenames
        ],
    }


def expanded_plan_fixture() -> dict:
    return json.loads(
        (ROOT / "examples/offline-pattern-task-relations-expanded.json").read_text(
            encoding="utf-8"
        )
    )


def expanded_task_fixture() -> dict:
    model = task_fixture()
    filenames = (
        ("configuration", "offline-configuration-defaults-component.json"),
        ("deputy", "offline-confused-deputy-boundary-component.json"),
        ("integrity", "offline-integrity-poisoning-component.json"),
    )
    model["jobs"] = [
        {
            "job_id": job_id,
            "request": components.load_offline_specialist_component_request(
                ROOT / "examples" / filename
            ),
        }
        for job_id, filename in filenames
    ] + model["jobs"]
    return model


def twelve_plan_fixture() -> dict:
    return json.loads(
        (ROOT / "examples/offline-pattern-task-relations-twelve.json").read_text(
            encoding="utf-8"
        )
    )


def twelve_task_fixture() -> dict:
    model = expanded_task_fixture()
    filenames = (
        ("authorization", "offline-cross-surface-authorization-component.json"),
        ("session", "offline-cross-channel-session-component.json"),
        ("origin", "offline-request-origin-trust-component.json"),
        ("schedule", "offline-toctou-state-schedule-component.json"),
        ("budget", "offline-resource-expansion-budget-component.json"),
        ("dependency", "offline-dependency-fail-closed-component.json"),
    )
    model["jobs"] = [
        {
            "job_id": job_id,
            "request": components.load_offline_specialist_component_request(
                ROOT / "examples" / filename
            ),
        }
        for job_id, filename in filenames
    ] + model["jobs"]
    return model


def sixteen_plan_fixture() -> dict:
    return json.loads(
        (ROOT / "examples/offline-pattern-task-relations-sixteen.json").read_text(
            encoding="utf-8"
        )
    )


def sixteen_task_fixture() -> dict:
    model = twelve_task_fixture()
    filenames = (
        ("pickle", "offline-pickle-opcode-component.json"),
        ("json", "offline-json-key-policy-component.json"),
        ("archive", "offline-archive-member-paths-component.json"),
        ("dns", "offline-dns-scope-timeline-component.json"),
    )
    model["jobs"] = [
        {
            "job_id": job_id,
            "request": components.load_offline_specialist_component_request(
                ROOT / "examples" / filename
            ),
        }
        for job_id, filename in filenames
    ] + model["jobs"]
    return model


def bind_source_hashes(plan: dict, task_model: dict) -> None:
    requests = {row["job_id"]: row["request"] for row in task_model["jobs"]}
    for premise in plan["premises"]:
        model = requests[premise["job_id"]]["payload"]["model"]
        premise["source_model_sha256"] = core.digest(core.canonical(model).encode("ascii"))


class PatternTaskRelationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.task_model = task_fixture()
        cls.task_report = task.run_offline_specialist_task(
            cls.task_model, catalog=cls.catalog, repository_root=ROOT
        )

    def analyze(self, plan: dict, *, task_model=None, task_report=None) -> PatternTaskRelations:
        return analyze_supplied_pattern_task_relations(
            plan,
            task_model=self.task_model if task_model is None else task_model,
            task_report=self.task_report if task_report is None else task_report,
            catalog=self.catalog,
            repository_root=ROOT,
        )

    def test_three_distinct_sources_match_without_scope_promotion(self) -> None:
        plan = plan_fixture()
        original = copy.deepcopy(plan)
        report = self.analyze(plan)
        body = report.to_dict()
        self.assertEqual(plan, original)
        self.assertEqual(body["source_model"], original)
        self.assertEqual(body["premise_count"], 3)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertEqual(
            {row["status"] for row in body["premises"]},
            {"matches_declared_expectation"},
        )
        self.assertEqual(
            {row["component_id"] for row in body["premises"]},
            {row["component_id"] for row in plan["premises"]},
        )
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        for flag in (
            "scope_equivalence_proven", "source_authenticated", "full_candidate_assembled",
            "positive_use_approved", "qualification_claimed",
        ):
            self.assertIs(body[flag], False)
        self.assertEqual(
            verify_supplied_pattern_task_relations(
                report, model=plan, task_report=self.task_report,
                task_model=self.task_model, catalog=self.catalog,
                repository_root=ROOT,
            ).to_json(),
            report.to_json(),
        )

    def test_contradiction_and_unknown_precedence(self) -> None:
        plan = plan_fixture()
        plan["premises"][0]["expected_disposition"] = "no_declared_unbound_query_input"
        body = self.analyze(plan).to_dict()
        self.assertEqual(body["hypothesis_status"], "contradicts_declared_expectation")
        changed_task = copy.deepcopy(self.task_model)
        changed_task["jobs"][0]["request"]["payload"]["model"]["queries"][0][
            "inputs"
        ][0]["incorporation"] = "unknown"
        changed_report = task.run_offline_specialist_task(
            changed_task, catalog=self.catalog, repository_root=ROOT
        )
        bind_source_hashes(plan, changed_task)
        body = self.analyze(
            plan, task_model=changed_task, task_report=changed_report
        ).to_dict()
        self.assertEqual(body["hypothesis_status"], "unresolved")
        plan["premises"][1]["expected_disposition"] = (
            "no_declared_interpreted_untrusted_input"
        )
        body = self.analyze(
            plan, task_model=changed_task, task_report=changed_report
        ).to_dict()
        self.assertEqual(body["hypothesis_status"], "contradicts_declared_expectation")

    def test_invalid_plan_refuses_before_parent_replay(self) -> None:
        cases = []
        plan = plan_fixture()
        plan["scope_binding"]["basis"] = "verified"
        cases.append(plan)
        plan = plan_fixture()
        plan["scope_binding"]["job_ids"].remove("observable")
        cases.append(plan)
        plan = plan_fixture()
        plan["premises"][1]["premise_id"] = plan["premises"][0]["premise_id"]
        cases.append(plan)
        plan = plan_fixture()
        plan["premises"][0]["expected_disposition"] = []
        cases.append(plan)
        plan = plan_fixture()
        plan["premises"][0]["source_model_sha256"] = "sha256:invalid"
        cases.append(plan)
        plan = plan_fixture()
        plan["network_permission"] = True
        cases.append(plan)
        plan = plan_fixture()
        plan["cycle"] = plan
        cases.append(plan)
        for index, item in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(PatternTaskRelationsError):
                    self.analyze(item, task_report=object())

    def test_alternate_original_and_tampered_relation_are_refused(self) -> None:
        plan = plan_fixture()
        report = self.analyze(plan)
        alternate = copy.deepcopy(self.task_model)
        alternate["jobs"][0]["request"]["payload"]["model"]["queries"][0][
            "execution_declared"
        ] = False
        with self.assertRaises(PatternTaskRelationsError):
            self.analyze(plan, task_model=alternate)
        changed_plan = copy.deepcopy(plan)
        changed_plan["premises"][0]["projection_id"] = "missing"
        with self.assertRaises(PatternTaskRelationsError):
            self.analyze(changed_plan)
        tampered = report.to_dict()
        tampered["positive_use_approved"] = True
        forged = PatternTaskRelations._owned(tampered)
        with self.assertRaises(PatternTaskRelationsError):
            verify_supplied_pattern_task_relations(
                forged, model=plan, task_report=self.task_report,
                task_model=self.task_model, catalog=self.catalog,
                repository_root=ROOT,
            )
        with self.assertRaises(PatternTaskRelationsError):
            verify_supplied_pattern_task_relations(
                report.to_dict(), model=plan, task_report=self.task_report,
                task_model=self.task_model, catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_exported_json_requires_original_and_current_replay(self) -> None:
        plan = plan_fixture()
        report = self.analyze(plan)
        exported = json.dumps(report.to_dict(), indent=2).encode("utf-8")
        self.assertEqual(
            verify_supplied_pattern_task_relations_bytes(
                exported, model=plan, task_report=self.task_report,
                task_model=self.task_model, catalog=self.catalog,
                repository_root=ROOT,
            ).to_json(),
            report.to_json(),
        )
        tampered = report.to_dict()
        tampered["positive_use_approved"] = True
        with self.assertRaises(PatternTaskRelationsError):
            verify_supplied_pattern_task_relations_bytes(
                core.canonical(tampered).encode("ascii"), model=plan,
                task_report=self.task_report, task_model=self.task_model,
                catalog=self.catalog, repository_root=ROOT,
            )
        for raw in (
            b'{"schema_version":1,"schema_version":1}',
            b'NaN',
            b'{' + b' ' * 131_072 + b'}',
        ):
            with self.subTest(raw=raw[:16]):
                with self.assertRaises(PatternTaskRelationsError):
                    verify_supplied_pattern_task_relations_bytes(
                        raw, model=plan, task_report=object(),
                        task_model=object(), catalog=object(), repository_root=ROOT,
                    )

    def test_six_source_expansion_keeps_scope_unverified(self) -> None:
        task_model = expanded_task_fixture()
        plan = expanded_plan_fixture()
        expected = copy.deepcopy(plan)
        bind_source_hashes(expected, task_model)
        self.assertEqual(plan, expected)
        task_report = task.run_offline_specialist_task(
            task_model, catalog=self.catalog, repository_root=ROOT
        )
        result = self.analyze(plan, task_model=task_model, task_report=task_report)
        body = result.to_dict()
        self.assertEqual(body["premise_count"], 6)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertEqual(
            {row["component_id"] for row in body["premises"]},
            {row["component_id"] for row in plan["premises"]},
        )
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["full_candidate_assembled"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(
            verify_supplied_pattern_task_relations(
                result, model=plan, task_report=task_report,
                task_model=task_model, catalog=self.catalog,
                repository_root=ROOT,
            ).to_json(),
            result.to_json(),
        )

    def test_new_leaf_unknown_and_contradiction_remain_distinct(self) -> None:
        task_model = expanded_task_fixture()
        plan = expanded_plan_fixture()
        task_model["jobs"][0]["request"]["payload"]["model"]["observations"][0][
            "declared_effective_value"
        ] = "unknown"
        bind_source_hashes(plan, task_model)
        task_report = task.run_offline_specialist_task(
            task_model, catalog=self.catalog, repository_root=ROOT
        )
        body = self.analyze(
            plan, task_model=task_model, task_report=task_report
        ).to_dict()
        self.assertEqual(body["hypothesis_status"], "unresolved")
        plan["premises"][1]["expected_disposition"] = (
            "declared_requester_boundary_consistent"
        )
        body = self.analyze(
            plan, task_model=task_model, task_report=task_report
        ).to_dict()
        self.assertEqual(body["hypothesis_status"], "contradicts_declared_expectation")

    def test_twelve_source_relation_replays_composite_authorization_key(self) -> None:
        task_model = twelve_task_fixture()
        plan = twelve_plan_fixture()
        expected = copy.deepcopy(plan)
        bind_source_hashes(expected, task_model)
        self.assertEqual(plan, expected)
        task_report = task.run_offline_specialist_task(
            task_model, catalog=self.catalog, repository_root=ROOT
        )
        result = self.analyze(plan, task_model=task_model, task_report=task_report)
        body = result.to_dict()
        self.assertEqual(body["premise_count"], 12)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertEqual(
            {row["component_id"] for row in body["premises"]},
            {row["component_id"] for row in plan["premises"]},
        )
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_pattern_task_relations(
                result, model=plan, task_report=task_report,
                task_model=task_model, catalog=self.catalog,
                repository_root=ROOT,
            ).to_json(),
            result.to_json(),
        )
        plan["premises"][0]["projection_id"] = "sha256:" + "0" * 64
        with self.assertRaises(PatternTaskRelationsError):
            self.analyze(plan, task_model=task_model, task_report=task_report)

    def test_sixteen_source_relation_covers_distinct_result_shapes(self) -> None:
        task_model = sixteen_task_fixture()
        plan = sixteen_plan_fixture()
        expected = copy.deepcopy(plan)
        bind_source_hashes(expected, task_model)
        self.assertEqual(plan, expected)
        task_report = task.run_offline_specialist_task(
            task_model, catalog=self.catalog, repository_root=ROOT
        )
        result = self.analyze(plan, task_model=task_model, task_report=task_report)
        body = result.to_dict()
        self.assertEqual(body["premise_count"], 16)
        self.assertEqual(body["hypothesis_status"], "matches_declared_expectation")
        self.assertEqual(
            {row["component_id"] for row in body["premises"]},
            {row["component_id"] for row in plan["premises"]},
        )
        self.assertFalse(body["scope_equivalence_proven"])
        self.assertFalse(body["source_authenticated"])
        self.assertFalse(body["full_candidate_assembled"])
        self.assertFalse(body["positive_use_approved"])
        self.assertFalse(body["qualification_claimed"])
        self.assertEqual(
            verify_supplied_pattern_task_relations(
                result, model=plan, task_report=task_report,
                task_model=task_model, catalog=self.catalog,
                repository_root=ROOT,
            ).to_json(),
            result.to_json(),
        )
        plan["premises"][3]["projection_id"] = "sha256:" + "0" * 64
        with self.assertRaises(PatternTaskRelationsError):
            self.analyze(plan, task_model=task_model, task_report=task_report)


if __name__ == "__main__":
    unittest.main()

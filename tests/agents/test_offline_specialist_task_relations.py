"""Genuine task replay, unsigned premise DAGs and bounded metadata/current separation."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_relations as relations

ROOT = Path(__file__).resolve().parents[2]
MATCH = "matches_declared_expectation"
CONTRARY = "contradicts_declared_expectation"
UNKNOWN = "unassessed"
_DEFAULT_MODEL = object()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256((relations.DOMAIN + "\n" + canonical(body)).encode("ascii")).hexdigest()
    document["analysis_id"] = "OTR-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest
    return document


class OfflineSpecialistTaskRelationsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Actual current-source catalog generation is explicit test setup, not import work.
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.catalog_document = cls.catalog.to_dict()
        cls.task_model = relations.task_fixture()
        cls.task_report = task.run_offline_specialist_task(
            cls.task_model, catalog=cls.catalog, repository_root=ROOT
        )
        cls.plan = relations.component_fixture()
        cls.report = relations.analyze_offline_specialist_task_relations(
            cls.plan,
            task_report=cls.task_report,
            task_model=cls.task_model,
            catalog=cls.catalog,
            repository_root=ROOT,
        )

    def context(self, **changes):
        return {
            "task_report": self.task_report,
            "task_model": self.task_model,
            "catalog": self.catalog,
            "repository_root": ROOT,
            **changes,
        }

    def run_relations(self, model=_DEFAULT_MODEL, **changes):
        context = self.context(**changes)
        selected = self.plan if model is _DEFAULT_MODEL else model
        if context["catalog"] is self.catalog and context["repository_root"] == ROOT:
            with patch.object(components, "_catalog_document", return_value=self.catalog_document):
                return relations.analyze_offline_specialist_task_relations(
                    selected, **context
                )
        return relations.analyze_offline_specialist_task_relations(selected, **context)

    def verify(self, report=None, model=None, **changes):
        context = self.context(**changes)
        selected_report = self.report if report is None else report
        selected_model = self.plan if model is None else model
        if context["catalog"] is self.catalog and context["repository_root"] == ROOT:
            with patch.object(components, "_catalog_document", return_value=self.catalog_document):
                return relations.verify_offline_specialist_task_relations(
                    selected_report, model=selected_model, **context
                )
        return relations.verify_offline_specialist_task_relations(
            selected_report, model=selected_model, **context
        )

    def test_helpers_reuse_checked_catalog_without_source_rescan(self):
        with patch.object(components, "_read_source", side_effect=AssertionError):
            report = self.run_relations()
            replay = self.verify()
        self.assertEqual(report.to_json(), self.report.to_json())
        self.assertEqual(replay.to_json(), self.report.to_json())

    def assert_preparent_denial(self, model, **changes):
        with (
            patch.object(task, "verify_offline_specialist_task") as replay,
            patch.object(relations, "_hash") as addressing,
        ):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                self.run_relations(model, **changes)
            replay.assert_not_called()
            addressing.assert_not_called()

    def custom_task(self, model):
        return task.run_offline_specialist_task(model, catalog=self.catalog, repository_root=ROOT)

    def source_pin(self, report, job_id):
        return next(
            row["result"]["analysis"]["source_model_sha256"]
            for row in report.to_dict()["jobs"]
            if row["job_id"] == job_id
        )

    def test_real_fixture_has_exact_leaf_sources_and_separate_task_binding(self):
        result = self.report.to_dict()
        parent = self.task_report.to_dict()
        self.assertEqual(result["source_model"], self.plan)
        self.assertEqual(
            result["task_binding"],
            {
                "task_id": parent["task_id"],
                "task_result_id": parent["task_result_id"],
                "task_result_sha256": parent["task_result_sha256"],
                "task_model_sha256": parent["model_sha256"],
                "catalog_id": parent["catalog_id"],
                "catalog_sha256": parent["catalog_sha256"],
                "job_count": 2,
            },
        )
        jobs = {row["job_id"]: row["result"] for row in parent["jobs"]}
        for row in result["premise_observations"]:
            original = jobs[row["job_id"]]
            analysis = original["analysis"]
            observed = next(
                item for item in analysis["flow_observations"] if item["flow_id"] == row["flow_id"]
            )
            self.assertEqual(row["source_model_sha256"], analysis["source_model_sha256"])
            self.assertEqual(row["leaf_observation"], observed)
            self.assertEqual(row["component_result_sha256"], original["result_sha256"])
            self.assertEqual(row["leaf_analysis_sha256"], analysis["analysis_sha256"])
        self.assertEqual(
            [row["status"] for row in result["hypothesis_observations"]], [MATCH, UNKNOWN, UNKNOWN]
        )
        self.assertEqual(result["evaluation_order"], ["known", "unknown", "overall"])
        self.assertEqual(result["roadmap_package_ids"], ["A2.4", "A2.13", "A7.4"])

    def test_static_model_golden_has_no_dynamic_task_or_catalog_identity(self):
        actual = (
            "sha256:"
            + hashlib.sha256(
                (relations.MODEL_DOMAIN + "\n" + canonical(self.plan)).encode("ascii")
            ).hexdigest()
        )
        self.assertEqual(self.report.to_dict()["source_model_sha256"], actual)
        self.assertEqual(
            actual, "sha256:30b6a4b76313fb945d5e21031cc421400b0f9a666776ddbba4fd6737bc7bd318"
        )
        self.assertNotIn("OST-", canonical(self.plan))
        self.assertNotIn("OSC-", canonical(self.plan))
        self.assertEqual(
            self.plan["premises"][0]["source_model_sha256"],
            "sha256:5c9cfab6bd6d73292c098d1e5440967ac6ff73a48964e9c557c4e8b26e8c9806",
        )
        self.assertEqual(
            self.plan["premises"][1]["source_model_sha256"],
            "sha256:5b86106d482a0ab104104c983cc0554addc26651b8d1d34bd743d3249438cbad",
        )
        self.assertEqual(self.report.to_dict(), readdress(self.report.to_dict()))

    def test_source_replaying_roundtrips_require_all_separate_inputs(self):
        document, text = self.report.to_dict(), self.report.to_json()
        passes = (
            relations.analyze_offline_specialist_task_relations_bytes(
                model_bytes=canonical(self.plan).encode(), **self.context()
            ),
            relations.OfflineSpecialistTaskRelations.from_dict(
                document, model=self.plan, **self.context()
            ),
            relations.OfflineSpecialistTaskRelations.from_json(
                " \n" + text, model=self.plan, **self.context()
            ),
            self.verify(),
        )
        for report in passes:
            self.assertIsNot(report, self.report)
            self.assertEqual(report.to_json(), text)
        with self.assertRaises(TypeError):
            relations.OfflineSpecialistTaskRelations.from_dict(document)
        with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
            relations.OfflineSpecialistTaskRelations(text)

    def test_pure_plan_parser_is_detached_hash_free_and_parent_free(self):
        with (
            patch.object(task, "verify_offline_specialist_task") as replay,
            patch.object(relations, "_hash") as addressing,
            patch.object(components.OfflineSpecialistComponentCatalog, "from_dict") as catalog,
        ):
            original = relations.parse_offline_specialist_task_relations_model(
                canonical(self.plan).encode()
            )
            self.assertEqual(original, self.plan)
            original["premises"].clear()
            self.assertTrue(self.plan["premises"])
            replay.assert_not_called()
            addressing.assert_not_called()
            catalog.assert_not_called()

    def test_three_status_conjunction_grid_and_nested_results(self):
        # Independent truth table: a contrary declaration defeats conjunction;
        # otherwise any unavailable observation prevents a match.
        for choices in itertools.product((MATCH, CONTRARY, UNKNOWN), repeat=3):
            with self.subTest(choices=choices):
                premises = []
                for index, choice in enumerate(choices):
                    premise = copy.deepcopy(self.plan["premises"][0 if choice != UNKNOWN else 2])
                    premise["premise_id"] = f"p{index}"
                    premise["expected_decision"] = (
                        "deny_under_supplied_vpc_predicates"
                        if choice == CONTRARY
                        else "allow_under_supplied_vpc_predicates"
                    )
                    premises.append(premise)
                plan = {
                    "schema_version": 1,
                    "plan_id": "grid",
                    "premises": premises,
                    "hypotheses": [
                        {
                            "hypothesis_id": "nested",
                            "dependencies": [{"kind": "hypothesis", "id": "all"}],
                        },
                        {
                            "hypothesis_id": "all",
                            "dependencies": [{"kind": "premise", "id": f"p{i}"} for i in range(3)],
                        },
                    ],
                }
                expected = (
                    CONTRARY if CONTRARY in choices else UNKNOWN if UNKNOWN in choices else MATCH
                )
                result = self.run_relations(plan).to_dict()
                self.assertEqual(
                    [row["status"] for row in result["premise_observations"]], list(choices)
                )
                self.assertEqual(
                    [row["status"] for row in result["hypothesis_observations"]],
                    [expected, expected],
                )
                self.assertEqual(result["evaluation_order"], ["all", "nested"])

    def test_contradiction_dominates_unknown_without_inferred_target_join(self):
        plan = copy.deepcopy(self.plan)
        plan["premises"][0]["expected_decision"] = "deny_under_supplied_vpc_predicates"
        report = self.run_relations(plan).to_dict()
        by_id = {row["hypothesis_id"]: row for row in report["hypothesis_observations"]}
        self.assertEqual(by_id["overall"]["status"], CONTRARY)
        self.assertEqual(by_id["unknown"]["status"], UNKNOWN)
        self.assertEqual(by_id["overall"]["explanation"], "dependency_contradiction")
        self.assertIs(report["flags"]["shared_target_proven"], False)
        self.assertIs(report["flags"]["network_reachability_proven"], False)

    def test_azure_not_filtered_is_distinct_from_allow(self):
        original = copy.deepcopy(self.task_model)
        source = original["jobs"][1]["request"]["payload"]["model"]
        source["attachments"].update(subnet_nsg_id=None, nic_nsg_id=None)
        parent = self.custom_task(original)
        premise = copy.deepcopy(self.plan["premises"][1])
        premise["source_model_sha256"] = self.source_pin(parent, "azure")
        premise["expected_decision"] = "not_filtered_by_declared_nsgs"
        plan = {
            "schema_version": 1,
            "plan_id": "absence",
            "premises": [premise],
            "hypotheses": [
                {
                    "hypothesis_id": "h",
                    "dependencies": [{"kind": "premise", "id": premise["premise_id"]}],
                }
            ],
        }
        result = self.run_relations(plan, task_model=original, task_report=parent).to_dict()
        self.assertEqual(result["premise_observations"][0]["status"], MATCH)
        premise["expected_decision"] = "allow_under_supplied_nsg_predicates"
        result = self.run_relations(plan, task_model=original, task_report=parent).to_dict()
        self.assertEqual(result["premise_observations"][0]["status"], CONTRARY)

    def test_known_action_can_match_with_retained_witness_uncertainty(self):
        original = copy.deepcopy(self.task_model)
        source = original["jobs"][0]["request"]["payload"]["model"]
        possible = copy.deepcopy(source["rules"][2])
        possible.update(rule_id="possible-ingress", direction="INGRESS", priority=100)
        source["rules"].append(possible)
        parent = self.custom_task(original)
        plan = copy.deepcopy(self.plan)
        pin = self.source_pin(parent, "gcp")
        for premise in plan["premises"]:
            if premise["job_id"] == "gcp":
                premise["source_model_sha256"] = pin
        result = self.run_relations(plan, task_model=original, task_report=parent).to_dict()
        observed = next(
            row for row in result["premise_observations"] if row["premise_id"] == "gcp.ingress"
        )
        self.assertEqual(observed["status"], MATCH)
        self.assertFalse(observed["leaf_observation"]["winning_witnesses_complete"])
        self.assertEqual(
            observed["leaf_observation"]["possible_rules"][0]["rule_id"], "possible-ingress"
        )

    def test_scoped_same_spelling_forward_dependencies_and_shared_children(self):
        premise = copy.deepcopy(self.plan["premises"][0])
        premise["premise_id"] = "same"
        plan = {
            "schema_version": 1,
            "plan_id": "scoped",
            "premises": [premise],
            "hypotheses": [
                {"hypothesis_id": "z", "dependencies": [{"kind": "hypothesis", "id": "same"}]},
                {"hypothesis_id": "same", "dependencies": [{"kind": "premise", "id": "same"}]},
                {"hypothesis_id": "a", "dependencies": [{"kind": "hypothesis", "id": "same"}]},
            ],
        }
        result = self.run_relations(plan).to_dict()
        self.assertEqual(result["evaluation_order"], ["same", "a", "z"])
        self.assertTrue(all(row["status"] == MATCH for row in result["hypothesis_observations"]))

    def test_cycles_missing_scopes_duplicates_and_empty_dependencies_precede_parent(self):
        mutations = (
            lambda p: p["hypotheses"][0]["dependencies"].append(
                {"kind": "hypothesis", "id": "overall"}
            ),
            lambda p: p["hypotheses"][0]["dependencies"].append(
                {"kind": "hypothesis", "id": "known"}
            ),
            lambda p: p["hypotheses"][0]["dependencies"].append({"kind": "premise", "id": "known"}),
            lambda p: p["hypotheses"][0]["dependencies"].append(
                copy.deepcopy(p["hypotheses"][0]["dependencies"][0])
            ),
            lambda p: p["hypotheses"][0].update(dependencies=[]),
            lambda p: p["hypotheses"].append(copy.deepcopy(p["hypotheses"][0])),
            lambda p: p["premises"].append(copy.deepcopy(p["premises"][0])),
        )
        for mutate in mutations:
            plan = copy.deepcopy(self.plan)
            mutate(plan)
            self.assert_preparent_denial(plan)
            with (
                patch.object(task, "verify_offline_specialist_task") as replay,
                self.assertRaises(relations.OfflineSpecialistTaskRelationsError),
            ):
                relations.parse_offline_specialist_task_relations_model(canonical(plan).encode())
            replay.assert_not_called()

    def test_swapped_job_component_source_and_flow_pins_reject_before_parent_replay(self):
        changes = (
            {"job_id": "missing"},
            {"job_id": "azure"},
            {
                "component_id": "azure_supplied_nsg_directional_predicates",
                "expected_decision": "allow_under_supplied_nsg_predicates",
            },
            {"source_model_sha256": self.plan["premises"][1]["source_model_sha256"]},
            {"flow_id": "synthetic-inbound"},
            {"flow_id": "missing"},
            {"component_id": "gcp_iam_supplied_allow_model"},
            {"expected_decision": "unassessed"},
        )
        for change in changes:
            plan = copy.deepcopy(self.plan)
            plan["premises"][0].update(change)
            self.assert_preparent_denial(plan)

    def test_false_captured_leaf_source_and_missing_observation_precede_parent(self):
        for mutation in ("source", "observation", "component"):
            document = self.task_report.to_dict()
            selected = next(row["result"] for row in document["jobs"] if row["job_id"] == "gcp")
            if mutation == "source":
                selected["analysis"]["source_model"]["network_id"] = "unselected"
            elif mutation == "observation":
                selected["analysis"]["flow_observations"].clear()
            else:
                selected["component"]["component_id"] = "unselected"
            # Honest same-process retained wrapper substitution, not a remote/authenticated record.
            altered = task.OfflineSpecialistTaskResult._owned(canonical(document))
            self.assert_preparent_denial(self.plan, task_report=altered)

    def test_each_derivation_has_one_parent_replay_and_exports_have_none(self):
        real = task.verify_offline_specialist_task
        with (
            patch.object(task, "verify_offline_specialist_task", wraps=real) as replay,
            patch.object(
                relations, "_final_catalog_check", wraps=relations._final_catalog_check
            ) as final,
        ):
            produced = self.run_relations()
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(final.call_count, 1)
            produced.to_dict()
            produced.to_json()
            self.assertEqual(replay.call_count, 1)
            self.assertEqual(final.call_count, 1)
            self.verify(produced)
            self.assertEqual(replay.call_count, 2)
            self.assertEqual(final.call_count, 2)

    def test_full_returned_parent_report_not_hash_only_is_compared(self):
        changed = copy.deepcopy(self.task_model)
        changed["task_id"] = "different-valid-task"
        alternate = self.custom_task(changed)
        with (
            patch.object(task, "verify_offline_specialist_task", return_value=alternate) as replay,
            patch.object(relations, "_hash") as hashing,
        ):
            with self.assertRaisesRegex(
                relations.OfflineSpecialistTaskRelationsError, "Full returned"
            ):
                self.run_relations()
            self.assertEqual(replay.call_count, 1)
            hashing.assert_not_called()

    def test_owned_parent_delivery_is_detached_and_late_change_denies(self):
        real = task.verify_offline_specialist_task
        originals = (
            canonical(self.task_model),
            self.task_report.document_json,
            self.catalog.document_json,
        )

        class Text(str):
            pass

        for mutation in ("model", "report", "catalog", "report-alias", "catalog-alias"):

            def changed(report, _mutation=mutation, **kwargs):
                result = real(report, **kwargs)
                if _mutation == "model":
                    kwargs["model"]["task_id"] = "late-native-change"
                elif _mutation.startswith("report"):
                    text = (
                        Text(report.document_json)
                        if _mutation.endswith("alias")
                        else report.document_json + " "
                    )
                    object.__setattr__(report, "document_json", text)
                else:
                    catalog = kwargs["catalog"]
                    text = (
                        Text(catalog.document_json)
                        if _mutation.endswith("alias")
                        else catalog.document_json + " "
                    )
                    object.__setattr__(catalog, "document_json", text)
                return result

            with (
                self.subTest(mutation=mutation),
                patch.object(task, "verify_offline_specialist_task", changed),
                patch.object(relations, "_hash") as hashing,
            ):
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    self.run_relations()
                hashing.assert_not_called()
        self.assertEqual(
            (
                canonical(self.task_model),
                self.task_report.document_json,
                self.catalog.document_json,
            ),
            originals,
        )

    def test_only_domain_failures_are_normalized_not_programming_exceptions(self):
        for failure in (TypeError("inert test"), RuntimeError("inert test")):
            with (
                patch.object(task, "verify_offline_specialist_task", side_effect=failure),
                self.assertRaises(type(failure)),
            ):
                self.run_relations()
        failure = task.OfflineSpecialistTaskError("inert domain denial")
        with patch.object(task, "verify_offline_specialist_task", side_effect=failure):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError) as caught:
                self.run_relations()
            self.assertIs(caught.exception.__cause__, failure)

    def test_input_order_is_bound_while_derived_displays_are_deterministic(self):
        changed = copy.deepcopy(self.plan)
        changed["premises"].reverse()
        changed["hypotheses"].reverse()
        for hypothesis in changed["hypotheses"]:
            hypothesis["dependencies"].reverse()
        result = self.run_relations(changed).to_dict()
        original = self.report.to_dict()
        self.assertEqual(result["source_model"], changed)
        self.assertNotEqual(result["source_model_sha256"], original["source_model_sha256"])
        self.assertEqual(result["premise_observations"], original["premise_observations"])
        self.assertEqual(result["hypothesis_observations"], original["hypothesis_observations"])
        self.assertEqual(result["evaluation_order"], original["evaluation_order"])

    def test_parent_order_and_grouping_are_separately_original_bound(self):
        changed = copy.deepcopy(self.task_model)
        changed["jobs"].reverse()
        self.assert_preparent_denial(self.plan, task_model=changed)
        alternate = self.custom_task(changed)
        result = self.run_relations(task_model=changed, task_report=alternate).to_dict()
        self.assertEqual(
            result["source_model_sha256"], self.report.to_dict()["source_model_sha256"]
        )
        self.assertNotEqual(
            result["task_binding"]["task_model_sha256"],
            self.report.to_dict()["task_binding"]["task_model_sha256"],
        )

    def test_cohashed_status_explanation_dag_effects_and_parent_bindings_reject(self):
        changes = (
            lambda d: d["premise_observations"][0].update(status=CONTRARY),
            lambda d: d["premise_observations"][0].update(explanation="invented"),
            lambda d: d["hypothesis_observations"][0].update(status=UNKNOWN),
            lambda d: d["hypothesis_observations"][0]["dependencies"].clear(),
            lambda d: d["evaluation_order"].reverse(),
            lambda d: d["summary"]["premises"].update(total=True),
            lambda d: d["flags"].update(positive_use_approved=True),
            lambda d: d["effects"].update(execution="performed"),
            lambda d: d["task_binding"].update(task_model_sha256="sha256:" + "a" * 64),
        )
        for change in changes:
            document = self.report.to_dict()
            change(document)
            document = readdress(document)
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                relations.OfflineSpecialistTaskRelations.from_dict(
                    document, model=self.plan, **self.context()
                )
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                relations.OfflineSpecialistTaskRelations.from_json(
                    canonical(document), model=self.plan, **self.context()
                )

    def test_exports_reject_locally_inconsistent_cohashed_metadata(self):
        for mutate in (
            lambda d: d["premise_observations"][0].update(status=CONTRARY),
            lambda d: d["hypothesis_observations"][0].update(explanation="invented"),
            lambda d: d["evaluation_order"].reverse(),
            lambda d: d["summary"]["premises"].update(total=True),
            lambda d: next(
                row for row in d["premise_observations"] if row["premise_id"] == "gcp.ingress"
            )["leaf_observation"]["matched_rules"][0].update(priority=True),
            lambda d: next(row for row in d["premise_observations"] if row["job_id"] == "azure")[
                "leaf_observation"
            ]["layers"][0].update(candidate_priority=True),
        ):
            document = self.report.to_dict()
            mutate(document)
            forged = relations.OfflineSpecialistTaskRelations._owned(canonical(readdress(document)))
            with patch.object(task, "verify_offline_specialist_task") as replay:
                for export in (forged.to_dict, forged.to_json):
                    with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                        export()
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    relations.OfflineSpecialistTaskRelations.from_dict(
                        document, model=self.plan, **self.context()
                    )
                replay.assert_not_called()

    def test_coherent_observation_metadata_is_not_current_leaf_verification(self):
        document = self.report.to_dict()
        row = next(
            row for row in document["premise_observations"] if row["premise_id"] == "gcp.ingress"
        )
        row.update(
            actual_decision="deny_under_supplied_vpc_predicates",
            status=CONTRARY,
            explanation="exact_supported_decision_differs",
        )
        row["leaf_observation"]["decision"] = row["actual_decision"]
        for witness in row["leaf_observation"]["matched_rules"]:
            witness["action"] = "deny"
        # Obtain consistent derived DAG metadata without pretending to reverify a leaf.
        work = relations._Work()
        plan, source_text, order = relations._plan(self.plan, work)
        body = relations._body(
            plan, document["task_binding"], document["premise_observations"], order, work
        )
        _document, text = relations._seal(body, source_text, work)
        forged = relations.OfflineSpecialistTaskRelations._owned(text)
        with patch.object(task, "verify_offline_specialist_task") as replay:
            self.assertEqual(
                next(
                    row
                    for row in forged.to_dict()["premise_observations"]
                    if row["premise_id"] == "gcp.ingress"
                )["status"],
                CONTRARY,
            )
            replay.assert_not_called()
        with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
            self.verify(forged)

    def test_separate_original_plan_cannot_be_replaced_by_rehashed_derivative(self):
        changed = copy.deepcopy(self.plan)
        changed["plan_id"] = "alternate-valid-plan"
        alternate = self.run_relations(changed)
        self.assertEqual(alternate.to_dict()["source_model"], changed)
        with patch.object(task, "verify_offline_specialist_task") as replay:
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                self.verify(alternate, self.plan)
            replay.assert_not_called()

    def test_native_aliases_subclasses_open_fields_and_hooks_precede_parent(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Dictionary(dict):
            pass

        for schema in (True, 1.0, "1", Integer(1), 1 << 10000):
            plan = copy.deepcopy(self.plan)
            plan["schema_version"] = schema
            self.assert_preparent_denial(plan)
        for change in (
            {"unknown": None},
            {"plan_id": Text("plan")},
            {"premises": tuple(self.plan["premises"])},
            {"hypotheses": Dictionary()},
        ):
            plan = copy.deepcopy(self.plan)
            plan.update(change)
            self.assert_preparent_denial(plan)
        for value in (Dictionary(self.plan), object(), None):
            with patch.object(relations, "_dump") as dump:
                self.assert_preparent_denial(value)
                dump.assert_not_called()

    def test_external_task_aliases_open_envelopes_and_wrapper_families_precede_parent(self):
        for mutate in (
            lambda d: d.update(schema_version=True),
            lambda d: d["jobs"][0]["request"].update(dry_run=1),
            lambda d: d["jobs"][0]["request"].update(credential_refs=["forbidden"]),
            lambda d: d["jobs"][0]["request"]["resources"].update(network=["forbidden"]),
            lambda d: d["jobs"][0]["request"].update(callback="forbidden"),
        ):
            original = copy.deepcopy(self.task_model)
            mutate(original)
            self.assert_preparent_denial(self.plan, task_model=original)
        for context in (
            {"task_report": object.__new__(task.OfflineSpecialistTaskResult)},
            {"task_report": {}},
            {"catalog": {}},
            {"catalog": object.__new__(components.OfflineSpecialistComponentCatalog)},
        ):
            self.assert_preparent_denial(self.plan, **context)

    def test_raw_integer_unicode_duplicate_and_scalar_depth_denials_before_parent(self):
        for token in (
            "--1",
            "---1",
            "--0",
            "+1",
            "01",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "9" * 2000,
        ):
            raw = (
                canonical(self.plan)
                .replace('"schema_version":1', '"schema_version":' + token)
                .encode()
            )
            with patch.object(relations.json, "loads") as decoder:
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    relations.parse_offline_specialist_task_relations_model(raw)
                decoder.assert_not_called()
        for content in (
            b"[" * relations.MAX_DEPTH + b"0" + b"]" * relations.MAX_DEPTH,
            b"[" + b"0," * relations.MAX_MODEL_NODES + b"0]",
            b'"\\u007f"',
            b'"\\ud800"',
            b'"\\u00e9"',
            b"\xff",
            bytearray(b"{}"),
        ):
            with patch.object(relations.json, "loads") as decoder:
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    relations.parse_offline_specialist_task_relations_model(content)
                decoder.assert_not_called()
        for raw in (
            canonical(self.plan)[:-1] + ',"schema_version":1}',
            canonical(self.plan)[:-1] + ',"schema_versio\\u006e":1}',
        ):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                relations.parse_offline_specialist_task_relations_model(raw.encode())

    def test_native_dag_cycles_queue_and_escaped_byte_costs_are_early(self):
        cycle = []
        cycle.append(cycle)
        shared = ["x" * 400] * 100
        for value in (
            cycle,
            [shared] * 100,
            [None] * (relations.MAX_MODEL_NODES + 1),
            {"unknown": "\\" * (relations.MAX_STRING_BYTES + 1)},
        ):
            with patch.object(relations, "_dump") as dump:
                self.assert_preparent_denial(value)
                dump.assert_not_called()
        with (
            patch.object(relations, "MAX_MODEL_BYTES", 200),
            patch.object(relations, "_dump") as dump,
        ):
            self.assert_preparent_denial({"unknown": "\\" * 100})
            dump.assert_not_called()

    def test_exact_structural_ceilings_and_one_more_refuse_before_parent(self):
        base = self.plan["premises"][0]
        plan = {
            "schema_version": 1,
            "plan_id": "ceilings",
            "premises": [{**base, "premise_id": f"p{i}"} for i in range(32)],
            "hypotheses": [
                {
                    "hypothesis_id": f"h{i:02}",
                    "dependencies": [{"kind": "premise", "id": f"p{j}"} for j in range(4)],
                }
                for i in range(16)
            ],
        }
        result = self.run_relations(plan).to_dict()
        self.assertEqual(result["summary"]["premises"]["total"], 32)
        self.assertEqual(result["summary"]["hypotheses"]["total"], 16)
        self.assertEqual(result["summary"]["dependency_references"], 64)
        for mutate in (
            lambda p: p["premises"].append({**base, "premise_id": "p32"}),
            lambda p: p["hypotheses"].append(
                {"hypothesis_id": "h16", "dependencies": [{"kind": "premise", "id": "p0"}]}
            ),
            lambda p: p["hypotheses"][0]["dependencies"].append({"kind": "premise", "id": "p4"}),
        ):
            invalid = copy.deepcopy(plan)
            mutate(invalid)
            self.assert_preparent_denial(invalid)

    def test_source_and_export_copies_are_detached_and_fixtures_are_fresh(self):
        plan = copy.deepcopy(self.plan)
        original = copy.deepcopy(self.task_model)
        report = self.run_relations(plan, task_model=original)
        text = report.to_json()
        plan["premises"].clear()
        original["jobs"].clear()
        exported = report.to_dict()
        exported["premise_observations"][0]["leaf_observation"].clear()
        exported["source_model"]["hypotheses"].clear()
        self.assertEqual(report.to_json(), text)
        self.assertIsNot(relations.component_fixture(), relations.component_fixture())
        self.assertIsNot(relations.task_fixture(), relations.task_fixture())

    def test_noncanonical_incomplete_and_subclass_wrappers_deny(self):
        class Derived(relations.OfflineSpecialistTaskRelations):
            pass

        empty = object.__new__(relations.OfflineSpecialistTaskRelations)
        forged = relations.OfflineSpecialistTaskRelations._owned(self.report.document_json + " ")
        for report in (empty, forged, object.__new__(Derived), {}):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                self.verify(report)
        for method in (empty.to_dict, empty.to_json, forged.to_dict, forged.to_json):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                method()
        with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
            Derived.from_dict(self.report.to_dict(), model=self.plan, **self.context())

    def test_real_shared_tie_output_exhaustion_precedes_own_digest(self):
        original = copy.deepcopy(self.task_model)
        original["jobs"] = [original["jobs"][0]]
        source = original["jobs"][0]["request"]["payload"]["model"]
        base = copy.deepcopy(source["rules"][0])
        source["rules"] = [{**copy.deepcopy(base), "rule_id": f"rule.{i:03}"} for i in range(256)]
        parent = self.custom_task(original)
        premise = {
            **self.plan["premises"][0],
            "source_model_sha256": self.source_pin(parent, "gcp"),
        }
        plan = {
            "schema_version": 1,
            "plan_id": "bounded-shared-witnesses",
            "premises": [{**premise, "premise_id": f"p{i:02}"} for i in range(32)],
            "hypotheses": [
                {
                    "hypothesis_id": "h",
                    "dependencies": [{"kind": "premise", "id": f"p{i:02}"} for i in range(32)],
                }
            ],
        }
        with patch.object(relations, "_hash") as hashing:
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                self.run_relations(plan, task_model=original, task_report=parent)
            hashing.assert_not_called()

    def test_complete_report_byte_ceiling_is_checked_before_own_digest(self):
        size = len(self.report.document_json)
        real = relations._limits

        def limited(kind, maximum):
            limits = real(kind)
            return (maximum, *limits[1:]) if kind == "report" else limits

        with (
            patch.object(relations, "_limits", lambda kind: limited(kind, size - 1)),
            patch.object(relations, "_hash") as hashing,
        ):
            with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                self.run_relations()
            hashing.assert_not_called()
        with patch.object(relations, "_limits", lambda kind: limited(kind, size)):
            self.assertEqual(self.run_relations().document_json, self.report.document_json)

    def test_every_public_pass_funds_own_work_before_own_hash_without_counting_inherited_work(self):
        document, text = self.report.to_dict(), self.report.to_json()
        operations = {
            "native": lambda: self.run_relations(),
            "bytes": lambda: relations.analyze_offline_specialist_task_relations_bytes(
                model_bytes=canonical(self.plan).encode(), **self.context()
            ),
            "from_dict": lambda: relations.OfflineSpecialistTaskRelations.from_dict(
                document, model=self.plan, **self.context()
            ),
            "from_json": lambda: relations.OfflineSpecialistTaskRelations.from_json(
                text, model=self.plan, **self.context()
            ),
            "verify": lambda: self.verify(),
            "to_dict": self.report.to_dict,
            "to_json": self.report.to_json,
            "plan_parser": lambda: relations.parse_offline_specialist_task_relations_model(
                canonical(self.plan).encode()
            ),
        }
        real_charge, real_hash = relations._Work.charge, relations._hash
        for name, operation in operations.items():
            with self.subTest(boundary=name):
                meter = {"used": 0, "hashed": False}

                def charged(work, amount, _meter=meter):
                    self.assertFalse(_meter["hashed"], "own work charged after first own digest")
                    _meter["used"] += amount
                    return real_charge(work, amount)

                def addressed(*args, _meter=meter):
                    _meter["hashed"] = True
                    return real_hash(*args)

                with (
                    patch.object(relations._Work, "charge", charged),
                    patch.object(relations, "_hash", addressed),
                ):
                    operation()
                self.assertEqual(meter["hashed"], name != "plan_parser")
                exact = meter["used"]

                def limited(work, amount, ceiling):
                    if amount > ceiling - work.used:
                        raise relations.OfflineSpecialistTaskRelationsError(
                            "Transparent test work ceiling"
                        )
                    return real_charge(work, amount)

                with patch.object(
                    relations._Work,
                    "charge",
                    lambda work, amount, _exact=exact: limited(work, amount, _exact),
                ):
                    operation()
                with (
                    patch.object(
                        relations._Work,
                        "charge",
                        lambda work, amount, _exact=exact: limited(work, amount, _exact - 1),
                    ),
                    patch.object(relations, "_hash") as hashing,
                ):
                    with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                        operation()
                    hashing.assert_not_called()

    def test_current_source_drift_denies_use_but_metadata_export_is_historical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for entry in self.catalog.to_dict()["sources"]:
                destination = root / entry["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / entry["path"], destination)
            catalog = components.build_offline_specialist_component_catalog(repository_root=root)
            parent = task.run_offline_specialist_task(
                self.task_model, catalog=catalog, repository_root=root
            )
            report = self.run_relations(task_report=parent, catalog=catalog, repository_root=root)
            source = root / "src/sunderkey/offline_gcp_firewall_analysis.py"
            source.write_bytes(source.read_bytes() + b"\n# disposable source drift fixture\n")
            with patch.object(task, "verify_offline_specialist_task") as replay:
                self.assertEqual(report.to_dict()["source_model"], self.plan)
                replay.assert_not_called()
            with patch.object(relations, "_hash") as hashing:
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    self.verify(report, task_report=parent, catalog=catalog, repository_root=root)
                hashing.assert_not_called()

    def test_final_catalog_source_drift_denies_before_relations_address(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for entry in self.catalog.to_dict()["sources"]:
                destination = root / entry["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / entry["path"], destination)
            catalog = components.build_offline_specialist_component_catalog(repository_root=root)
            parent = task.run_offline_specialist_task(
                self.task_model, catalog=catalog, repository_root=root
            )
            source = root / "src/sunderkey/offline_gcp_firewall_analysis.py"
            real = relations._final_catalog_check

            def drift(document, repository_root):
                source.write_bytes(source.read_bytes() + b"\n# disposable final source drift\n")
                return real(document, repository_root)

            with (
                patch.object(relations, "_final_catalog_check", drift),
                patch.object(relations, "_hash") as hashing,
                patch.object(
                    task,
                    "verify_offline_specialist_task",
                    wraps=task.verify_offline_specialist_task,
                ) as replay,
            ):
                with self.assertRaises(relations.OfflineSpecialistTaskRelationsError):
                    self.run_relations(task_report=parent, catalog=catalog, repository_root=root)
                self.assertEqual(replay.call_count, 1)
                hashing.assert_not_called()

    def test_all_none_effects_and_false_promotions_remain_unsigned(self):
        document = self.report.to_dict()
        self.assertTrue(
            all(type(value) is bool and value is False for value in document["flags"].values())
        )
        self.assertTrue(
            all(type(value) is str and value == "none" for value in document["effects"].values())
        )
        self.assertEqual(document["bounds"]["maximum_inherited_task_replays"], 1)
        self.assertEqual(
            document["bounds"]["inherited_work_accounting"], "separate_existing_budgets"
        )
        self.assertIn("Metadata exports", canonical(document["limitations"]))
        self.assertNotIn("OST-", canonical(document["source_model"]))


if __name__ == "__main__":
    unittest.main()

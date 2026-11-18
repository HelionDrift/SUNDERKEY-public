"""Genuine heterogeneous composition, original-source replay and cost boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey.candidate_adapter_sdk import REFERENCE_PROFILES

ROOT = Path(__file__).resolve().parents[2]


def canonical(value):
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in ("task_result_id", "task_result_sha256")
    }
    value = digest({"domain": "sunderkey.offline-specialist-task-result.v1", "content": body})
    return {**body, "task_result_id": "OST-" + value[7:39].upper(), "task_result_sha256": value}


class OfflineSpecialistTaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.catalog_document = cls.catalog.to_dict()

    def run_task(self, model=None, **kwargs):
        selected_catalog = kwargs.get("catalog", self.catalog)
        selected_root = kwargs.get("root", ROOT)
        selected_model = task.component_fixture() if model is None else model
        if selected_catalog is self.catalog and selected_root == ROOT:
            with patch.object(components, "_catalog_document", return_value=self.catalog_document):
                return task.run_offline_specialist_task(
                    selected_model, catalog=selected_catalog, repository_root=selected_root
                )
        return task.run_offline_specialist_task(
            selected_model, catalog=selected_catalog, repository_root=selected_root
        )

    def verify(self, report, model):
        with patch.object(components, "_catalog_document", return_value=self.catalog_document):
            return task.verify_offline_specialist_task(
                report, model=model, catalog=self.catalog, repository_root=ROOT
            )

    def test_helpers_reuse_checked_catalog_without_source_rescan(self):
        model = task.component_fixture()
        with patch.object(components, "_read_source", side_effect=AssertionError):
            report = self.run_task(model)
            replay = self.verify(report, model)
        self.assertEqual(replay.to_json(), report.to_json())

    def test_heterogeneous_results_equal_independent_dispatch_and_ownership(self):
        model = task.component_fixture()
        result = self.run_task(model).to_dict()
        by_job = {item["job_id"]: item["request"] for item in model["jobs"]}
        for item, ownership in zip(result["jobs"], result["ownership_index"], strict=True):
            standalone = components.run_offline_specialist_component(
                by_job[item["job_id"]], catalog=self.catalog, repository_root=ROOT
            )
            self.assertEqual(item["result"], standalone)
            for key in (
                "component_id",
                "profile_id",
                "package_id",
                "commander_profile_id",
                "independent_validator_id",
            ):
                self.assertEqual(ownership[key], standalone["component"][key])
            self.assertTrue(ownership["independent_review_required"])
        self.assertEqual(
            (
                result["job_count"],
                result["distinct_component_count"],
                result["distinct_profile_count"],
            ),
            (2, 2, 2),
        )
        self.assertEqual(result["model"], model)
        self.assertEqual([job["job_id"] for job in result["jobs"]], ["cookies", "tls"])

    def test_fixture_model_and_independent_address_control(self):
        model = task.component_fixture()
        report = self.run_task(model).to_dict()
        self.assertEqual(report["model_sha256"], digest(model))
        self.assertEqual(report, readdress(report))
        self.assertRegex(report["task_result_id"], r"^OST-[0-9A-F]{32}$")
        self.assertEqual(len(REFERENCE_PROFILES), 6)
        self.assertEqual(
            report["model_sha256"],
            "sha256:05dc8cf589eec854262ba54ab6a955a0d3a1cc43c7e07e3748d985d69b6a318c",
        )
        self.assertEqual(
            [job["result"]["analysis"]["analysis_id"] for job in report["jobs"]],
            ["CKS-0C48DD34662DCE4EC3766D5134C7227D", "THA-5C4792683DD417BB8537391B63B72DCC"],
        )

    def test_del_escape_byte_ceiling_denies_before_native_dump_or_raw_decoder(self):
        for text in (chr(127) * 100, (chr(127) + "\u00e9") * 30):
            for intake in ("native", "raw"):
                with (
                    self.subTest(text_length=len(text), intake=intake),
                    patch.object(task, "MAX_DOCUMENT_BYTES", 300),
                ):
                    if intake == "native":
                        with patch.object(task, "_dump", wraps=task._dump) as dumping:
                            with self.assertRaises(task.OfflineSpecialistTaskError):
                                self.run_task({"source": text})
                            dumping.assert_not_called()
                    else:
                        raw = json.dumps({"source": text}, ensure_ascii=False).encode("utf-8")
                        self.assertLess(len(raw), 300)
                        with patch.object(task.json, "loads") as loads:
                            with self.assertRaises(task.OfflineSpecialistTaskError):
                                task.parse_offline_specialist_task_model(raw)
                            loads.assert_not_called()

    def test_del_and_unicode_in_valid_supplied_comment_preserve_native_raw_replay(self):
        model = task.component_fixture()
        request = copy.deepcopy(model["jobs"][0]["request"])
        request["profile_id"] = "AOE-GB-D06-S02"
        request["component_id"] = "graphql_query_structure"
        request["payload"] = {
            "schema_content": canonical(
                {
                    "query_type": "Query",
                    "types": [
                        {
                            "name": "Query",
                            "kind": "OBJECT",
                            "fields": [{"name": "id", "type": "ID"}],
                        },
                        {"name": "ID", "kind": "SCALAR", "fields": []},
                    ],
                }
            ),
            "query_content": "# supplied comment " + chr(127) + "\u00e9\n{ id }",
            "schema_source_id": "synthetic.schema",
            "query_source_id": "synthetic.query",
            "operation_name": None,
            "limits": {
                "max_schema_bytes": 4096,
                "max_query_bytes": 4096,
                "max_depth": 8,
                "max_tokens": 128,
                "max_nodes": 128,
                "max_expanded_selections": 128,
            },
        }
        model["jobs"] = [{"job_id": "graphql", "request": request}]
        native = self.run_task(model)
        raw = json.dumps(model, ensure_ascii=False).encode("utf-8")
        self.assertEqual(
            task.run_offline_specialist_task_bytes(
                model_bytes=raw, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            native.to_json(),
        )
        self.assertEqual(self.verify(native, model).to_json(), native.to_json())

    def test_bytes_roundtrip_and_explicit_separate_original_parsers(self):
        model = task.component_fixture()
        report = self.run_task(model)
        raw = canonical(model).encode("ascii")
        self.assertEqual(task.parse_offline_specialist_task_model(raw), model)
        self.assertEqual(
            task.run_offline_specialist_task_bytes(
                model_bytes=raw, catalog=self.catalog, repository_root=ROOT
            ).to_json(),
            report.to_json(),
        )
        for replay in (
            self.verify(report, model),
            task.OfflineSpecialistTaskResult.from_dict(
                report.to_dict(), model=model, catalog=self.catalog, repository_root=ROOT
            ),
            task.OfflineSpecialistTaskResult.from_json(
                " \n" + report.to_json(), model=model, catalog=self.catalog, repository_root=ROOT
            ),
        ):
            self.assertEqual(replay.to_json(), report.to_json())

    def test_original_order_is_source_bound_but_display_order_is_sorted(self):
        first = task.component_fixture()
        second = copy.deepcopy(first)
        second["jobs"].reverse()
        a, b = self.run_task(first), self.run_task(second)
        self.assertEqual(a.to_dict()["jobs"], b.to_dict()["jobs"])
        self.assertNotEqual(a.to_dict()["model_sha256"], b.to_dict()["model_sha256"])
        self.assertNotEqual(a.to_dict()["task_result_id"], b.to_dict()["task_result_id"])
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.verify(a, second)

    def test_omitted_default_selector_is_not_inserted_or_readdressed(self):
        explicit = task.component_fixture()
        implicit = copy.deepcopy(explicit)
        for job in implicit["jobs"]:
            del job["request"]["component_id"]
        a, b = self.run_task(explicit).to_dict(), self.run_task(implicit).to_dict()
        self.assertEqual(b["model"], implicit)
        for left, right in zip(a["jobs"], b["jobs"], strict=True):
            self.assertEqual(left["result"]["analysis"], right["result"]["analysis"])
            self.assertNotEqual(left["result"]["request_sha256"], right["result"]["request_sha256"])

    def test_duplicate_job_ids_are_rejected_before_preparation(self):
        model = task.component_fixture()
        model["jobs"][1]["job_id"] = model["jobs"][0]["job_id"]
        with patch.object(components, "prepare_offline_specialist_component_request") as prepare:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            prepare.assert_not_called()

    def test_task_fields_and_native_integer_aliases_fail_before_preparation(self):
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("task_id", []),
            ("task_id", "bad task"),
            ("jobs", []),
        ):
            with self.subTest(field=field, value=value):
                model = task.component_fixture()
                model[field] = value
                with patch.object(
                    components, "prepare_offline_specialist_component_request"
                ) as prepare:
                    with self.assertRaises(task.OfflineSpecialistTaskError):
                        self.run_task(model)
                    prepare.assert_not_called()
        model = task.component_fixture()
        model["unknown"] = None
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.run_task(model)

    def test_later_resource_or_credential_denial_precedes_all_analysis(self):
        for change in (
            "network",
            "filesystem",
            "process",
            "credential",
            "credential_refs",
            "dry_run",
        ):
            with self.subTest(change=change):
                model = task.component_fixture()
                later = model["jobs"][0]["request"]  # tls sorts after cookies
                if change in later["resources"]:
                    later["resources"][change] = ["forbidden"]
                elif change == "dry_run":
                    later["dry_run"] = False
                else:
                    later[change] = ["forbidden"]
                with patch.object(components, "run_offline_specialist_component") as run:
                    with self.assertRaises(task.OfflineSpecialistTaskError):
                        self.run_task(model)
                    run.assert_not_called()

    def test_later_callback_payload_and_foreign_selector_precede_all_analysis(self):
        for mutate in (
            lambda r: r["payload"].update(callback="forbidden"),
            lambda r: r.update(component_id="retained_cookie_candidate_predicates"),
            lambda r: r.update(action_tier="R1"),
            lambda r: r.update(environment="live"),
        ):
            model = task.component_fixture()
            mutate(model["jobs"][0]["request"])
            with patch.object(components, "run_offline_specialist_component") as run:
                with self.assertRaises(task.OfflineSpecialistTaskError):
                    self.run_task(model)
                run.assert_not_called()

    def test_all_preparations_precede_dispatch_and_once_per_job_per_pass(self):
        events = []
        prepare = components.prepare_offline_specialist_component_request
        run = components.run_offline_specialist_component

        def observed_prepare(request, **kwargs):
            events.append("prepare")
            return prepare(request, **kwargs)

        def observed_run(request, **kwargs):
            events.append("run")
            return run(request, **kwargs)

        with (
            patch.object(
                components, "prepare_offline_specialist_component_request", observed_prepare
            ),
            patch.object(components, "run_offline_specialist_component", observed_run),
        ):
            report = self.run_task()
            self.assertEqual(events, ["prepare", "prepare", "run", "run"])
            events.clear()
            report.to_dict()
            report.to_json()
            self.assertEqual(events, [])
            self.verify(report, task.component_fixture())
            self.assertEqual(events, ["prepare", "prepare", "run", "run"])

    def test_leaf_semantic_denial_has_no_retry_or_partial_result(self):
        model = task.component_fixture()
        model["jobs"][0]["request"]["payload"]["model"]["server_hello_base64"] = "invalid"
        real = components.run_offline_specialist_component
        with patch.object(components, "run_offline_specialist_component", wraps=real) as run:
            with self.assertRaises(ValueError):
                self.run_task(model)
            self.assertEqual(run.call_count, 2)

    def test_known_leaf_failure_is_normalized_on_every_source_replay_entry(self):
        request = json.loads(
            (ROOT / "examples/offline-http-request-framing-component.json").read_text()
        )
        model = {
            "schema_version": 1,
            "task_id": "synthetic.http-validation",
            "jobs": [{"job_id": "http", "request": request}],
        }
        valid = self.run_task(model)
        invalid = copy.deepcopy(model)
        invalid["jobs"][0]["request"]["payload"]["model"]["schema_version"] = True
        document, text = valid.to_dict(), valid.to_json()
        operations = (
            lambda: self.run_task(invalid),
            lambda: task.run_offline_specialist_task_bytes(
                model_bytes=canonical(invalid).encode(), catalog=self.catalog, repository_root=ROOT
            ),
            lambda: task.OfflineSpecialistTaskResult.from_dict(
                document, model=invalid, catalog=self.catalog, repository_root=ROOT
            ),
            lambda: task.OfflineSpecialistTaskResult.from_json(
                text, model=invalid, catalog=self.catalog, repository_root=ROOT
            ),
            lambda: self.verify(valid, invalid),
        )
        real = components.run_offline_specialist_component
        for index, operation in enumerate(operations):
            with (
                self.subTest(entry=index),
                patch.object(components, "run_offline_specialist_component", wraps=real) as run,
            ):
                with self.assertRaises(ValueError) as caught:
                    operation()
                self.assertEqual(run.call_count, 1)
                self.assertIsInstance(caught.exception, task.OfflineSpecialistTaskError)
                self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_same_profile_distinct_algorithms_have_one_profile_count(self):
        names = ("offline-aws-scp-component.json", "offline-aws-identity-policy-component.json")
        model = {
            "schema_version": 1,
            "task_id": "synthetic.two-algorithms",
            "jobs": [
                {
                    "job_id": str(index),
                    "request": json.loads((ROOT / "examples" / name).read_text()),
                }
                for index, name in enumerate(names)
            ],
        }
        result = self.run_task(model).to_dict()
        self.assertEqual(
            (
                result["job_count"],
                result["distinct_component_count"],
                result["distinct_profile_count"],
            ),
            (2, 2, 1),
        )

    def test_cumulative_retained_results_deny_before_a_third_analysis(self):
        model = task.component_fixture()
        model["jobs"].append(
            {"job_id": "tls.again", "request": copy.deepcopy(model["jobs"][0]["request"])}
        )
        valid = self.run_task(model).to_dict()
        first_two = {
            "model": model,
            "jobs": valid["jobs"][:2],
            "ownership_index": valid["ownership_index"][:2],
        }
        ceiling = len(canonical(first_two)) - 1
        first_one = {
            "model": model,
            "jobs": valid["jobs"][:1],
            "ownership_index": valid["ownership_index"][:1],
        }
        self.assertLess(len(canonical(first_one)), ceiling)
        self.assertLess(len(canonical(model)), ceiling)
        self.assertTrue(all(len(canonical(job["result"])) < ceiling for job in valid["jobs"]))
        real = components.run_offline_specialist_component
        with (
            patch.object(task, "MAX_DOCUMENT_BYTES", ceiling),
            patch.object(components, "run_offline_specialist_component", wraps=real) as run,
            patch.object(task, "_digest") as hashing,
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            self.assertEqual(run.call_count, 2)
            hashing.assert_not_called()

    def test_preparation_cannot_change_the_original_envelope(self):
        real = components.prepare_offline_specialist_component_request

        def changed(request, **kwargs):
            selected = real(request, **kwargs)
            selected["environment"] = "supplied_inert_data"
            return selected

        with (
            patch.object(components, "prepare_offline_specialist_component_request", changed),
            patch.object(components, "run_offline_specialist_component") as run,
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task()
            run.assert_not_called()

    def test_task_and_export_inputs_are_detached(self):
        model = task.component_fixture()
        original = copy.deepcopy(model)
        report = self.run_task(model)
        text = report.to_json()
        model["jobs"][0]["request"]["payload"]["model"]["schema_version"] = 9
        exported = report.to_dict()
        exported["model"]["jobs"].clear()
        exported["jobs"][0]["result"]["analysis"].clear()
        self.assertEqual(report.to_json(), text)
        self.assertEqual(report.to_dict()["model"], original)
        self.assertIsNot(task.component_fixture(), task.component_fixture())

    def test_cohashed_false_analysis_and_ownership_fail_original_replay(self):
        model = task.component_fixture()
        valid = self.run_task(model).to_dict()
        changes = (
            lambda d: d["jobs"][0]["result"]["analysis"].update(invented_conclusion=True),
            lambda d: d["ownership_index"][0].update(commander_profile_id="foreign.commander"),
            lambda d: d.update(model_sha256="sha256:" + "a" * 64),
            lambda d: d.update(catalog_sha256="sha256:" + "b" * 64),
        )
        for change in changes:
            document = copy.deepcopy(valid)
            change(document)
            document = readdress(document)
            with self.assertRaises(task.OfflineSpecialistTaskError):
                task.OfflineSpecialistTaskResult.from_dict(
                    document, model=model, catalog=self.catalog, repository_root=ROOT
                )
            with self.assertRaises(task.OfflineSpecialistTaskError):
                task.OfflineSpecialistTaskResult.from_json(
                    canonical(document), model=model, catalog=self.catalog, repository_root=ROOT
                )

    def test_promotions_and_effects_cannot_be_rehashed_into_acceptance(self):
        model = task.component_fixture()
        valid = self.run_task(model).to_dict()
        for field in ("full_candidate_assembled", "positive_use_approved", "qualification_claimed"):
            forged = copy.deepcopy(valid)
            forged[field] = True
            with self.assertRaises(task.OfflineSpecialistTaskError):
                task.OfflineSpecialistTaskResult.from_dict(
                    readdress(forged), model=model, catalog=self.catalog, repository_root=ROOT
                )
        self.assertTrue(all(value == "none" for value in valid["operational_effects"].values()))
        self.assertIn("unsanitized", valid["source_content_warning"])

    def test_result_wrapper_families_incomplete_slots_and_raw_constructor_fail(self):
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.OfflineSpecialistTaskResult("{}")
        empty = object.__new__(task.OfflineSpecialistTaskResult)
        for method in (empty.to_dict, empty.to_json):
            with self.assertRaises(task.OfflineSpecialistTaskError):
                method()
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.verify({}, task.component_fixture())
        valid = self.run_task()
        forged = task.OfflineSpecialistTaskResult._owned(valid.document_json + " ")
        with self.assertRaises(task.OfflineSpecialistTaskError):
            forged.to_dict()

    def test_separate_source_substitutions_and_grouping_changes_reject(self):
        original = task.component_fixture()
        report = self.run_task(original)
        for mutate in (
            lambda m: m.update(task_id="different.task"),
            lambda m: m["jobs"][0].update(job_id="changed.tls"),
            lambda m: m["jobs"][0]["request"].update(environment="supplied_inert_data"),
        ):
            changed = copy.deepcopy(original)
            mutate(changed)
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.verify(report, changed)

    def test_duplicate_json_keys_and_numeric_grammar_reject_before_decoder(self):
        for token in (
            "--1",
            "01",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "9" * 10_000,
        ):
            with self.subTest(token=token[:30]), patch.object(task.json, "loads") as loads:
                with self.assertRaises(task.OfflineSpecialistTaskError):
                    task.parse_offline_specialist_task_model(
                        ('{"schema_version":' + token + "}").encode()
                    )
                loads.assert_not_called()
        with self.assertRaises(task.OfflineSpecialistTaskError):
            task.parse_offline_specialist_task_model(b'{"schema_version":1,"schema_version":1}')

    def test_raw_depth_nodes_and_escaped_bytes_reject_before_decoder_or_hash(self):
        cases = (
            b"[" * 81 + b"0" + b"]" * 81,
            b"[" + b"0," * task.MAX_NATIVE_NODES + b"0]",
            ('"' + "\u00e9" * (task.MAX_DOCUMENT_BYTES // 6 + 1) + '"').encode("utf-8"),
        )
        for content in cases:
            with (
                patch.object(task.json, "loads") as loads,
                patch.object(task, "_digest") as hashing,
            ):
                with self.assertRaises(task.OfflineSpecialistTaskError):
                    task.parse_offline_specialist_task_model(content)
                loads.assert_not_called()
                hashing.assert_not_called()

    def test_raw_scalar_unicode_and_native_bounds_are_explicit(self):
        for content in (
            b'"\\ud800"',
            b'"\\udc00"',
            b'"\\ud800\\u0041"',
            b"\xff",
            b"",
            bytearray(b"{}"),
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError):
                task.parse_offline_specialist_task_model(content)
        for value in (task.MIN_INTEGER, task.MAX_INTEGER):
            with self.assertRaisesRegex(task.OfflineSpecialistTaskError, "fields"):
                task.parse_offline_specialist_task_model(canonical({"value": value}).encode())

    def test_native_subclasses_and_hooks_are_rejected_before_serialization(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Dictionary(dict):
            pass

        for value in (Text("task"), Integer(1), Dictionary(), object(), (1,)):
            with (
                patch.object(task.json, "dumps") as dumps,
                patch.object(task, "_digest") as hashing,
            ):
                with self.assertRaises(task.OfflineSpecialistTaskError):
                    self.run_task({"unsupported": value})
                dumps.assert_not_called()
                hashing.assert_not_called()

    def test_shared_native_graph_is_charged_per_occurrence_before_dump(self):
        shared = ["x" * 4096] * 100
        graph = [shared] * 100
        with patch.object(task.json, "dumps") as dumps, patch.object(task, "_digest") as hashing:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(graph)
            dumps.assert_not_called()
            hashing.assert_not_called()
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(task.OfflineSpecialistTaskError):
            self.run_task(cycle)

    def test_job_ceiling_and_repeated_sources_do_not_imply_independent_evidence(self):
        model = task.component_fixture()
        first = model["jobs"][0]
        model["jobs"] = [
            {"job_id": f"job.{index}", "request": copy.deepcopy(first["request"])}
            for index in range(task.MAX_JOBS)
        ]
        report = self.run_task(model).to_dict()
        self.assertEqual(
            (
                report["job_count"],
                report["distinct_component_count"],
                report["distinct_profile_count"],
            ),
            (16, 1, 1),
        )
        self.assertEqual(len({item["result"]["result_id"] for item in report["jobs"]}), 1)
        model["jobs"].append({"job_id": "too.many", "request": first["request"]})
        with patch.object(components, "run_offline_specialist_component") as run:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            run.assert_not_called()

    def test_complete_final_report_byte_boundary_is_reserved_before_task_digest(self):
        model = task.component_fixture()
        valid = self.run_task(model)
        size = len(valid.to_json())
        self.assertLess(len(canonical(model)), size)
        with (
            patch.object(task, "MAX_DOCUMENT_BYTES", size - 1),
            patch.object(task, "_digest") as hashing,
        ):
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task(model)
            hashing.assert_not_called()
        with patch.object(task, "MAX_DOCUMENT_BYTES", size):
            self.assertEqual(self.run_task(model).document_json, valid.document_json)

    def test_final_serialization_and_hash_work_are_reserved_before_first_digest(self):
        costs = []
        original = task._finalize

        def measured(body, model_json, work):
            result = original(body, model_json, work)
            costs.append(work.used)
            return result

        with patch.object(task, "_finalize", measured):
            valid = self.run_task()
        with patch.object(task, "MAX_WORK", costs[0] - 1), patch.object(task, "_digest") as hashing:
            with self.assertRaises(task.OfflineSpecialistTaskError):
                self.run_task()
            hashing.assert_not_called()
        with patch.object(task, "MAX_WORK", costs[0]):
            self.assertEqual(self.run_task().document_json, valid.document_json)

    def test_current_source_drift_and_final_catalog_check_reject_without_partial_return(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory)
            for entry in self.catalog.to_dict()["sources"]:
                destination = selected / entry["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / entry["path"], destination)
            current = components.build_offline_specialist_component_catalog(
                repository_root=selected
            )
            source = selected / "src/sunderkey/offline_tls_hello_analysis.py"
            original = source.read_bytes()
            source.write_bytes(original + b"\n# bounded disposable source change\n")
            with patch.object(components, "run_offline_specialist_component") as run:
                with self.assertRaises(components.OfflineSpecialistComponentError):
                    self.run_task(catalog=current, root=selected)
                run.assert_not_called()
            source.write_bytes(original)
            genuine = components.run_offline_specialist_component
            calls = []

            def changes_after_last(request, **kwargs):
                result = genuine(request, **kwargs)
                calls.append(result)
                if len(calls) == 2:
                    source.write_bytes(original + b"\n# bounded disposable source change\n")
                return result

            with (
                patch.object(components, "run_offline_specialist_component", changes_after_last),
                patch.object(task, "_digest") as hashing,
            ):
                with self.assertRaises(components.OfflineSpecialistComponentError):
                    self.run_task(catalog=current, root=selected)
                self.assertEqual(len(calls), 2)
                hashing.assert_not_called()

    def test_local_fixture_reader_is_explicit_and_bounded(self):
        model = task.component_fixture()
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "inert.json"
            selected.write_text(canonical(model), encoding="ascii")
            self.assertEqual(task.load_offline_specialist_task_model(selected), model)
            with self.assertRaises(components.OfflineSpecialistComponentError):
                task.load_offline_specialist_task_model(Path(directory))
        for path in ("https://example.invalid/task", "\\\\server\\share\\task"):
            with self.assertRaises(components.OfflineSpecialistComponentError):
                task.load_offline_specialist_task_model(path)


if __name__ == "__main__":
    unittest.main()

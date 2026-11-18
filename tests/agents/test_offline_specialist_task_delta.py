"""Source-replayed task revision rows without inferred target equivalence."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey import offline_specialist_task_delta as delta

ROOT = Path(__file__).resolve().parents[2]
ERROR = delta.OfflineSpecialistTaskDeltaError


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def readdress(document: dict) -> dict:
    body = {
        key: value for key, value in document.items() if key not in ("delta_id", "delta_sha256")
    }
    digest = hashlib.sha256((delta.DOMAIN + "\n" + canonical(body)).encode("ascii")).hexdigest()
    return {**body, "delta_id": "OTD-" + digest[:32].upper(), "delta_sha256": "sha256:" + digest}


def request(filename: str) -> dict:
    return components.load_offline_specialist_component_request(ROOT / "examples" / filename)


def before_model() -> dict:
    return {
        "schema_version": 1,
        "task_id": "synthetic.task-revision",
        "jobs": [
            {"job_id": "a-saml", "request": request("offline-saml-conditions-component.json")},
            {"job_id": "m-oci", "request": request("offline-oci-blob-component.json")},
        ],
    }


def after_model() -> dict:
    model = before_model()
    model["jobs"][0]["request"]["payload"]["model"]["evaluation_context"]["audience"] = (
        "https://other.invalid/sp"
    )
    model["jobs"].append(
        {"job_id": "z-dicom", "request": request("offline-dicom-pdv-component.json")}
    )
    return model


class OfflineSpecialistTaskDeltaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        cls.before = before_model()
        cls.after = after_model()
        cls.before_report = task.run_offline_specialist_task(
            cls.before, catalog=cls.catalog, repository_root=ROOT
        )
        cls.after_report = task.run_offline_specialist_task(
            cls.after, catalog=cls.catalog, repository_root=ROOT
        )
        cls.delta_report = delta.analyze_offline_specialist_task_delta(
            before_report=cls.before_report,
            before_model=cls.before,
            after_report=cls.after_report,
            after_model=cls.after,
            catalog=cls.catalog,
            repository_root=ROOT,
        )

    def kwargs(self, **changes: object) -> dict:
        result = {
            "before_report": self.before_report,
            "before_model": copy.deepcopy(self.before),
            "after_report": self.after_report,
            "after_model": copy.deepcopy(self.after),
            "catalog": self.catalog,
            "repository_root": ROOT,
        }
        result.update(changes)
        return result

    def analyze(self, **changes: object) -> delta.OfflineSpecialistTaskDelta:
        return delta.analyze_offline_specialist_task_delta(**self.kwargs(**changes))

    def test_current_three_row_delta_is_addressed_nonoperational_metadata(self) -> None:
        report = self.delta_report
        document = report.to_dict()
        self.assertRegex(document["delta_id"], r"^OTD-[0-9A-F]{32}$")
        self.assertRegex(document["delta_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            [row["job_id"] for row in document["rows"]], ["a-saml", "m-oci", "z-dicom"]
        )
        self.assertEqual(
            [row["relation"] for row in document["rows"]],
            ["request_changed", "same_request", "added"],
        )
        self.assertEqual(
            document["counts"],
            {
                "added": 1,
                "removed": 0,
                "selector_changed": 0,
                "request_changed": 1,
                "same_request": 1,
            },
        )
        self.assertEqual(
            document["before"]["task_result_id"], self.before_report.to_dict()["task_result_id"]
        )
        self.assertEqual(
            document["after"]["task_result_id"], self.after_report.to_dict()["task_result_id"]
        )
        self.assertEqual(document["before"]["catalog_id"], document["after"]["catalog_id"])
        self.assertEqual(document["join_basis"], "caller_declared_equal_task_and_job_labels_only")
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertIs(document["flags"]["same_target_verified"], False)
        self.assertIs(document["flags"]["positive_use_approved"], False)
        self.assertIs(document["flags"]["qualification_claimed"], False)
        self.assertNotIn("source_model", document)
        self.assertNotIn("assertion_xml_base64", report.to_json())
        self.assertNotIn("pdu_base64", report.to_json())

    def test_seven_public_roundtrips_require_separate_current_originals(self) -> None:
        report = self.delta_report
        native = report.to_dict()
        text = report.to_json()
        self.assertEqual(canonical(native), text)
        self.assertEqual(
            delta.OfflineSpecialistTaskDelta.from_dict(native, **self.kwargs()).to_json(), text
        )
        self.assertEqual(
            delta.OfflineSpecialistTaskDelta.from_json(text, **self.kwargs()).to_json(), text
        )
        self.assertEqual(
            delta.verify_offline_specialist_task_delta(report, **self.kwargs()).to_json(), text
        )
        byte_result = delta.analyze_offline_specialist_task_delta_bytes(
            before_report=self.before_report,
            before_model_bytes=canonical(self.before).encode("ascii"),
            after_report=self.after_report,
            after_model_bytes=canonical(self.after).encode("ascii"),
            catalog=self.catalog,
            repository_root=ROOT,
        )
        self.assertEqual(byte_result.to_json(), text)

    def test_removed_and_same_request_are_distinct(self) -> None:
        result = self.analyze(
            before_report=self.after_report,
            before_model=copy.deepcopy(self.after),
            after_report=self.before_report,
            after_model=copy.deepcopy(self.before),
        ).to_dict()
        self.assertEqual(
            [row["relation"] for row in result["rows"]],
            ["request_changed", "same_request", "removed"],
        )
        self.assertEqual(result["counts"]["removed"], 1)

    def test_original_job_order_changes_address_without_fabricating_row_change(self) -> None:
        reordered = copy.deepcopy(self.before)
        reordered["jobs"].reverse()
        reordered_report = task.run_offline_specialist_task(
            reordered, catalog=self.catalog, repository_root=ROOT
        )
        result = self.analyze(after_report=reordered_report, after_model=reordered).to_dict()
        self.assertNotEqual(result["before"]["task_result_id"], result["after"]["task_result_id"])
        self.assertEqual(
            [row["relation"] for row in result["rows"]], ["same_request", "same_request"]
        )

    def test_omitted_vs_explicit_same_default_selector_is_changed(self) -> None:
        omitted = copy.deepcopy(self.before)
        explicit = copy.deepcopy(self.before)
        del omitted["jobs"][0]["request"]["component_id"]
        explicit_report = task.run_offline_specialist_task(
            explicit, catalog=self.catalog, repository_root=ROOT
        )
        omitted_report = task.run_offline_specialist_task(
            omitted, catalog=self.catalog, repository_root=ROOT
        )
        document = self.analyze(
            before_report=omitted_report,
            before_model=omitted,
            after_report=explicit_report,
            after_model=explicit,
        ).to_dict()
        self.assertEqual(document["rows"][0]["relation"], "selector_changed")
        self.assertIsNone(document["rows"][0]["before"]["selector"])
        self.assertEqual(
            document["rows"][0]["after"]["selector"],
            "saml_supplied_conditions_audience_restrictions",
        )
        self.assertEqual(
            document["rows"][0]["before"]["component_id"],
            document["rows"][0]["after"]["component_id"],
        )

    def test_mismatched_task_label_refuses_before_either_parent_replay(self) -> None:
        changed = copy.deepcopy(self.after)
        changed["task_id"] = "synthetic.different-task"
        with patch.object(task, "verify_offline_specialist_task") as replay:
            with self.assertRaises(ERROR):
                self.analyze(after_model=changed)
            replay.assert_not_called()

    def test_separate_original_model_and_report_substitutions_refuse(self) -> None:
        wrong_model = copy.deepcopy(self.before)
        wrong_model["jobs"][0]["request"]["payload"]["model"]["source_id"] = "other-source"
        for changes in (
            {"before_model": wrong_model},
            {"before_report": self.after_report},
            {"after_report": self.before_report},
        ):
            with self.subTest(changes=tuple(changes)):
                with self.assertRaises(ERROR):
                    self.analyze(**changes)

    def test_coherently_readdressed_false_request_identity_is_not_current_truth(self) -> None:
        original = self.delta_report
        forged = copy.deepcopy(original.to_dict())
        forged["rows"][0]["before"]["request_sha256"] = "sha256:" + "a" * 64
        forged = readdress(forged)
        historical = delta.OfflineSpecialistTaskDelta._owned(canonical(forged))
        self.assertEqual(historical.to_dict(), forged)
        with self.assertRaises(ERROR):
            delta.verify_offline_specialist_task_delta(historical, **self.kwargs())
        with self.assertRaises(ERROR):
            delta.OfflineSpecialistTaskDelta.from_dict(forged, **self.kwargs())

    def test_false_relation_counts_flags_and_result_address_refuse_even_rehashed(self) -> None:
        original = self.delta_report.to_dict()
        cases = (
            ("relation", lambda body: body["rows"][0].update(relation="same_request")),
            ("count_alias", lambda body: body["counts"].update(added=True)),
            ("flag_alias", lambda body: body["flags"].update(same_target_verified=0)),
            (
                "result",
                lambda body: body["rows"][1]["after"].update(result_sha256="sha256:" + "a" * 64),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label):
                changed = copy.deepcopy(original)
                mutate(changed)
                with self.assertRaises(ERROR):
                    delta.OfflineSpecialistTaskDelta._owned(canonical(readdress(changed))).to_dict()

    def test_late_wrapper_and_original_model_mutations_refuse(self) -> None:
        report = self.delta_report
        changed = object.__new__(delta.OfflineSpecialistTaskDelta)
        object.__setattr__(
            changed, "document_json", report.to_json().replace("same_request", "allow")
        )
        with self.assertRaises(ERROR):
            changed.to_dict()
        source = copy.deepcopy(self.before)
        source["jobs"][0]["request"]["payload"]["model"]["source_id"] = "changed-original"
        with self.assertRaises(ERROR):
            delta.verify_offline_specialist_task_delta(report, **self.kwargs(before_model=source))

    def test_nonnative_models_and_cycles_refuse_before_parent_replay(self) -> None:
        bad = copy.deepcopy(self.before)
        bad["schema_version"] = True
        cyclic = copy.deepcopy(self.before)
        cyclic["cycle"] = cyclic
        for source in (None, bad, cyclic, {"schema_version": 1.0}):
            with self.subTest(source=type(source).__name__):
                with patch.object(task, "verify_offline_specialist_task") as replay:
                    with self.assertRaises(ERROR):
                        self.analyze(before_model=source)
                    replay.assert_not_called()

    def test_raw_duplicate_float_and_oversized_integer_refuse(self) -> None:
        report = self.delta_report
        native = report.to_json()
        bad = (
            native.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            native.replace('"schema_version":1', '"schema_version":1.0', 1),
            native.replace('"schema_version":1', '"schema_version":999999999999999999999999999', 1),
        )
        for text in bad:
            with self.assertRaises(ERROR):
                delta.OfflineSpecialistTaskDelta.from_json(text, **self.kwargs())
        with self.assertRaises(ERROR):
            delta.analyze_offline_specialist_task_delta_bytes(
                before_report=self.before_report,
                before_model_bytes=canonical(self.before)
                .replace('"schema_version":1', '"schema_version":1.0', 1)
                .encode("ascii"),
                after_report=self.after_report,
                after_model_bytes=canonical(self.after).encode("ascii"),
                catalog=self.catalog,
                repository_root=ROOT,
            )

    def test_report_byte_ceiling_rejects_exact_one_over_and_native_alias(self) -> None:
        report = self.delta_report
        native = report.to_dict()
        with patch.object(delta, "MAX_REPORT_BYTES", len(report.to_json())):
            self.assertEqual(report.to_dict(), native)
        with patch.object(delta, "MAX_REPORT_BYTES", len(report.to_json()) - 1):
            with self.assertRaises(ERROR):
                report.to_dict()
        with self.assertRaises(ERROR):
            delta.OfflineSpecialistTaskDelta.from_dict(
                {**native, "schema_version": True}, **self.kwargs()
            )

    def test_direct_constructor_and_incomplete_wrapper_refuse(self) -> None:
        with self.assertRaises(ERROR):
            delta.OfflineSpecialistTaskDelta("{}")
        with self.assertRaises(ERROR):
            object.__new__(delta.OfflineSpecialistTaskDelta).to_dict()

    def test_all_seven_public_own_work_boundaries_precede_delta_sha(self) -> None:
        report = self.delta_report
        native = report.to_dict()
        text = report.to_json()
        originals = self.kwargs()
        operations = (
            ("analyze", lambda: delta.analyze_offline_specialist_task_delta(**originals)),
            (
                "bytes",
                lambda: delta.analyze_offline_specialist_task_delta_bytes(
                    before_report=self.before_report,
                    before_model_bytes=canonical(self.before).encode("ascii"),
                    after_report=self.after_report,
                    after_model_bytes=canonical(self.after).encode("ascii"),
                    catalog=self.catalog,
                    repository_root=ROOT,
                ),
            ),
            ("verify", lambda: delta.verify_offline_specialist_task_delta(report, **originals)),
            ("from_dict", lambda: delta.OfflineSpecialistTaskDelta.from_dict(native, **originals)),
            ("from_json", lambda: delta.OfflineSpecialistTaskDelta.from_json(text, **originals)),
            ("to_dict", report.to_dict),
            ("to_json", report.to_json),
        )
        original_charge = delta._Work.charge

        def already_verified(report, *, model, catalog, repository_root):
            if report is self.before_report or report is self.after_report:
                return report
            raise AssertionError("Unexpected parent report")

        # This test isolates the delta's own seven work budgets. Other methods
        # exercise genuine current-source task replay without these inert stubs.
        with (
            patch.object(task, "verify_offline_specialist_task", side_effect=already_verified),
            patch.object(
                components.OfflineSpecialistComponentCatalog,
                "from_dict",
                return_value=self.catalog,
            ),
        ):
            for name, operation in operations:
                with self.subTest(operation=name):
                    totals = []

                    def record(work, amount):
                        original_charge(work, amount)
                        totals.append(work.used)

                    with patch.object(delta._Work, "charge", record):
                        operation()
                    exact = max(totals)
                    with patch.object(delta, "MAX_WORK", exact):
                        operation()
                    with (
                        patch.object(delta, "MAX_WORK", exact - 1),
                        patch.object(
                            delta, "sha256", side_effect=AssertionError("late hash")
                        ) as digest,
                    ):
                        with self.assertRaises(ERROR):
                            operation()
                        digest.assert_not_called()


if __name__ == "__main__":
    unittest.main()

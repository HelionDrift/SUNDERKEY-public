"""WQ-001 versioned evaluation corpus assembly tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.evaluation_corpus_assembly import (
    CORPUS_PARTITIONS,
    NO_EFFECTS,
    CorpusAssemblyBudgets,
    EvaluationCorpusAssemblyError,
    EvaluationCorpusAssemblyReceipt,
    assemble_evaluation_corpus,
    canonical_sha256,
    verify_evaluation_corpus_receipt,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "evaluation-corpus-assembly-v1.schema.json"


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def records() -> list[dict[str, object]]:
    content = {
        "public": "public web authorization negative control case alpha",
        "private_holdout": "private identity boundary holdout case bravo",
        "adversarial_safety": "adversarial instruction isolation safety case charlie",
        "regression": "regression evidence validation control case delta",
        "pilot": "pilot restoration verification control case echo",
    }
    return [
        {
            "record_id": f"case-{partition}",
            "record_version": "1.0.0",
            "partition": partition,
            "source_id": f"source-{partition}",
            "source_version": "1.0.0",
            "source_sha256": digest(f"source-{partition}"),
            "provenance_sha256": digest(f"provenance-{partition}"),
            "content": content[partition],
        }
        for partition in CORPUS_PARTITIONS
    ]


def receipt(**overrides: object) -> EvaluationCorpusAssemblyReceipt:
    arguments: dict[str, object] = {
        "corpus_id": "evaluation-corpus-wq-001",
        "corpus_version": "1.0.0",
        "records": records(),
    }
    arguments.update(overrides)
    return assemble_evaluation_corpus(**arguments)  # type: ignore[arg-type]


def _replay(received: EvaluationCorpusAssemblyReceipt, document: dict[str, object]):
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return (
        ("mapping", lambda: EvaluationCorpusAssemblyReceipt.from_dict(document)),
        ("json", lambda: EvaluationCorpusAssemblyReceipt.from_json(encoded)),
        ("verify_mapping", lambda: verify_evaluation_corpus_receipt(document)),
        ("verify_json", lambda: verify_evaluation_corpus_receipt(encoded)),
        (
            "verify_typed",
            lambda: verify_evaluation_corpus_receipt(replace(received, document_json=encoded)),
        ),
    )


def _derived_integer_paths(value: object, path: tuple[object, ...] = ()):
    if type(value) is int and value in (0, 1):
        yield path
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _derived_integer_paths(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _derived_integer_paths(item, (*path, index))


def _corpus_type_replay_fixtures():
    yield "clean", receipt()
    supplied = records()
    supplied[1]["content"] = supplied[0]["content"]
    yield "exact", receipt(records=supplied)
    supplied = records()
    supplied[1]["source_sha256"] = supplied[0]["source_sha256"]
    supplied[1]["provenance_sha256"] = supplied[0]["provenance_sha256"]
    yield "source_provenance", receipt(records=supplied)
    supplied = records()
    supplied[1]["content"] = "public web authorization negative control case omega"
    yield (
        "near",
        receipt(
            records=supplied,
            budgets=CorpusAssemblyBudgets(near_duplicate_threshold_basis_points=6_000),
        ),
    )
    supplied = records()
    supplied[0]["content"] = "shared one three"
    supplied[1]["content"] = "SHARED ONE THREE"
    yield (
        "single_component",
        receipt(
            records=supplied,
            budgets=CorpusAssemblyBudgets(
                maximum_fingerprint_components=1, near_duplicate_threshold_basis_points=1
            ),
        ),
    )
    supplied = records()
    supplied[0]["content"] = "shared one " + " ".join(f"p{i}" for i in range(2_500))
    supplied[1]["content"] = "shared one " + " ".join(f"v{i}" for i in range(2_500))
    yield (
        "one_basis_point",
        receipt(
            records=supplied,
            budgets=CorpusAssemblyBudgets(
                maximum_fingerprint_components=4_096, near_duplicate_threshold_basis_points=1
            ),
        ),
    )


class EvaluationCorpusAssemblyPhase168Tests(unittest.TestCase):
    def test_derived_boolean_aliases_fail_every_public_replay_path(self) -> None:
        visited = set()
        for fixture, original in _corpus_type_replay_fixtures():
            native = original.to_dict()
            for field in (
                "schema_version",
                "summary",
                "partitions",
                "holdout_separation_checks",
                "near_duplicate_indicators",
            ):
                for path in _derived_integer_paths(native[field], (field,)):
                    changed = copy.deepcopy(native)
                    parent = changed
                    for key in path[:-1]:
                        parent = parent[key]
                    parent[path[-1]] = bool(parent[path[-1]])
                    visited.add(path[-1])
                    body = copy.deepcopy(changed)
                    body.pop("manifest_id")
                    body.pop("manifest_sha256")
                    self.assertNotEqual(
                        changed["manifest_sha256"],
                        canonical_sha256(
                            {"domain": "sunderkey.evaluation-corpus-assembly.v1", "manifest": body}
                        ),
                    )
                    for entry, replay in _replay(original, changed):
                        with self.subTest(fixture=fixture, path=path, entry=entry):
                            with self.assertRaises(EvaluationCorpusAssemblyError):
                                replay()
        self.assertTrue(
            {
                "schema_version",
                "exact_duplicate_count",
                "near_duplicate_count",
                "source_overlap_count",
                "provenance_overlap_count",
                "record_count",
                "matching_component_count",
                "union_component_count",
                "similarity_basis_points",
                "threshold_basis_points",
            }.issubset(visited)
        )

    def test_readdressed_boolean_derivations_are_not_accepted_as_truthful(self) -> None:
        original = receipt()
        changed = original.to_dict()
        changed["summary"]["exact_duplicate_count"] = False
        body = copy.deepcopy(changed)
        body.pop("manifest_id")
        body.pop("manifest_sha256")
        changed["manifest_sha256"] = canonical_sha256(
            {"domain": "sunderkey.evaluation-corpus-assembly.v1", "manifest": body}
        )
        changed["manifest_id"] = f"ECM-{changed['manifest_sha256'][7:39].upper()}"
        for entry, replay in _replay(original, changed):
            with self.subTest(entry=entry):
                with self.assertRaises(EvaluationCorpusAssemblyError):
                    replay()

    def test_equal_float_values_remain_invalid_receipt_json(self) -> None:
        original = receipt()
        for field in ("schema_version", "summary"):
            changed = original.to_dict()
            if field == "schema_version":
                changed[field] = 1.0
            else:
                changed[field]["exact_duplicate_count"] = 0.0
            for entry, replay in _replay(original, changed):
                with self.subTest(field=field, entry=entry):
                    with self.assertRaises(EvaluationCorpusAssemblyError):
                        replay()

    def test_valid_native_receipt_identities_and_entry_paths_are_preserved(self) -> None:
        self.assertEqual(
            receipt().manifest_sha256,
            "sha256:8e5cae6eca10e904962a953eb016957fa79e2bd7765612a4b0ebf48ada837a38",
        )
        for fixture, original in _corpus_type_replay_fixtures():
            for entry, replay in _replay(original, original.to_dict()):
                with self.subTest(fixture=fixture, entry=entry):
                    self.assertEqual(replay(), original)

    def test_clean_assembly_is_deterministic_round_trip_and_schema_valid(self) -> None:
        first = receipt()
        second = receipt(records=list(reversed(records())))
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(first, EvaluationCorpusAssemblyReceipt.from_json(first.document_json))
        self.assertEqual(first, verify_evaluation_corpus_receipt(first.to_dict()))

        document = first.to_dict()
        self.assertEqual(document["assembly_status"], "clean")
        self.assertEqual(document["effects"], NO_EFFECTS)
        self.assertEqual(document["summary"]["pair_comparison_count"], 10)
        self.assertEqual(document["summary"]["holdout_check_count"], 7)
        self.assertTrue(
            all(item["status"] == "clean" for item in document["holdout_separation_checks"])
        )

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(document)

    def test_receipt_omits_caller_content_and_binds_safe_fingerprints(self) -> None:
        document = receipt().to_dict()
        serialized = json.dumps(document)
        self.assertNotIn("public web authorization negative control case alpha", serialized)
        for record in document["records"]:
            self.assertNotIn("content", record)
            self.assertGreaterEqual(len(record["fingerprint_component_sha256s"]), 1)
            self.assertTrue(
                all(
                    component.startswith("sha256:")
                    for component in record["fingerprint_component_sha256s"]
                )
            )
            self.assertEqual(
                record["fingerprint_sha256"],
                canonical_sha256(
                    {
                        "domain": "sunderkey.corpus-fingerprint.v1",
                        "components": record["fingerprint_component_sha256s"],
                    }
                ),
            )

    def test_exact_holdout_duplicate_produces_blocking_finding(self) -> None:
        supplied = records()
        supplied[1]["content"] = supplied[0]["content"]
        document = receipt(records=supplied).to_dict()
        self.assertEqual(document["assembly_status"], "contamination_detected")
        self.assertEqual(document["summary"]["exact_duplicate_count"], 1)
        findings = document["contamination_findings"]
        self.assertEqual([item["finding_kind"] for item in findings], ["exact_content_overlap"])
        self.assertEqual(findings[0]["qualification_effect"], "none")

    def test_near_duplicate_holdout_indicator_is_deterministic(self) -> None:
        supplied = records()
        supplied[1]["content"] = "public web authorization negative control case omega"
        limits = CorpusAssemblyBudgets(near_duplicate_threshold_basis_points=6_000)
        document = receipt(records=supplied, budgets=limits).to_dict()
        self.assertEqual(document["assembly_status"], "contamination_detected")
        self.assertEqual(document["summary"]["near_duplicate_count"], 1)
        indicator = document["near_duplicate_indicators"][0]
        self.assertGreaterEqual(indicator["similarity_basis_points"], 6_000)
        self.assertEqual(
            document["contamination_findings"][0]["finding_kind"],
            "near_content_overlap",
        )

    def test_source_and_provenance_holdout_reuse_are_separate_findings(self) -> None:
        supplied = records()
        supplied[1]["source_sha256"] = supplied[0]["source_sha256"]
        supplied[1]["provenance_sha256"] = supplied[0]["provenance_sha256"]
        document = receipt(records=supplied).to_dict()
        self.assertEqual(
            [item["finding_kind"] for item in document["contamination_findings"]],
            ["source_overlap", "provenance_overlap"],
        )
        affected = next(
            item
            for item in document["holdout_separation_checks"]
            if {item["left_partition"], item["right_partition"]} == {"public", "private_holdout"}
        )
        self.assertEqual(affected["source_overlap_count"], 1)
        self.assertEqual(affected["provenance_overlap_count"], 1)
        self.assertEqual(affected["status"], "contaminated")

    def test_nonholdout_duplicate_is_visible_without_false_holdout_claim(self) -> None:
        supplied = records()
        supplied[3]["content"] = supplied[0]["content"]
        document = receipt(records=supplied).to_dict()
        self.assertEqual(document["summary"]["exact_duplicate_count"], 1)
        self.assertEqual(document["contamination_findings"], [])
        self.assertEqual(document["assembly_status"], "clean")

    def test_missing_partition_duplicate_identifier_and_unknown_input_field_fail(self) -> None:
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "every required partition"):
            receipt(records=records()[:-1])

        supplied = records()
        supplied[1]["record_id"] = supplied[0]["record_id"]
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "record IDs"):
            receipt(records=supplied)

        supplied = records()
        supplied[0]["unexpected"] = "rejected"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "fields"):
            receipt(records=supplied)

    def test_invalid_hash_version_and_content_fail_closed(self) -> None:
        supplied = records()
        supplied[0]["source_sha256"] = "not-a-hash"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "sha256"):
            receipt(records=supplied)

        supplied = records()
        supplied[0]["record_version"] = "latest"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "exact immutable"):
            receipt(records=supplied)

        supplied = records()
        supplied[0]["content"] = "two tokens"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "at least three"):
            receipt(records=supplied)

    def test_all_resource_budgets_fail_closed(self) -> None:
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "record count"):
            receipt(records=records(), budgets=CorpusAssemblyBudgets(maximum_records=4))
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "pair comparisons"):
            receipt(
                records=records(),
                budgets=CorpusAssemblyBudgets(maximum_pair_comparisons=9),
            )
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "per-record byte"):
            receipt(
                records=records(),
                budgets=CorpusAssemblyBudgets(
                    maximum_content_bytes_per_record=8,
                    maximum_total_content_bytes=100,
                ),
            )
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "total byte"):
            receipt(
                records=records(),
                budgets=CorpusAssemblyBudgets(
                    maximum_content_bytes_per_record=100,
                    maximum_total_content_bytes=150,
                ),
            )
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "token budget"):
            receipt(
                records=records(),
                budgets=CorpusAssemblyBudgets(maximum_tokens_per_record=4),
            )
        supplied = records()
        supplied[1]["source_sha256"] = supplied[0]["source_sha256"]
        supplied[1]["provenance_sha256"] = supplied[0]["provenance_sha256"]
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "findings exceed budget"):
            receipt(
                records=supplied,
                budgets=CorpusAssemblyBudgets(maximum_findings=1),
            )

    def test_receipt_tampering_and_unknown_fields_are_rejected(self) -> None:
        document = receipt().to_dict()
        document["records"][0]["source_sha256"] = digest("tampered")
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "content address"):
            verify_evaluation_corpus_receipt(document)

        document = receipt().to_dict()
        document["records"][0]["unexpected"] = "rejected"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "fields"):
            verify_evaluation_corpus_receipt(document)

        document = receipt().to_dict()
        document["effects"]["authority"] = "granted"
        body = copy.deepcopy(document)
        body.pop("manifest_id")
        body.pop("manifest_sha256")
        document["manifest_sha256"] = canonical_sha256(
            {"domain": "sunderkey.evaluation-corpus-assembly.v1", "manifest": body}
        )
        document["manifest_id"] = f"ECM-{document['manifest_sha256'][7:39].upper()}"
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "does not match"):
            verify_evaluation_corpus_receipt(document)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        payload = receipt().document_json
        duplicated = payload.replace(
            '"schema_version":1',
            '"schema_version":1,"schema_version":1',
            1,
        )
        with self.assertRaisesRegex(EvaluationCorpusAssemblyError, "duplicate JSON key"):
            EvaluationCorpusAssemblyReceipt.from_json(duplicated)

    def test_public_package_exports_corpus_assembly(self) -> None:
        import sunderkey

        self.assertIs(
            sunderkey.EvaluationCorpusAssemblyReceipt,
            EvaluationCorpusAssemblyReceipt,
        )
        self.assertIs(sunderkey.assemble_evaluation_corpus, assemble_evaluation_corpus)
        self.assertIs(
            sunderkey.verify_evaluation_corpus_receipt,
            verify_evaluation_corpus_receipt,
        )
        self.assertEqual(
            sunderkey.EvaluationCorpusAssemblyPartitions,
            CORPUS_PARTITIONS,
        )


if __name__ == "__main__":
    unittest.main()

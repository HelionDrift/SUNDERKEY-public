"""Supplied RAG index-provenance discrepancy controls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_rag_provenance as analysis

ROOT = Path(__file__).resolve().parents[2]


def dispositions(model: dict) -> dict[str, str]:
    document = analysis.analyze_supplied_rag_provenance(model).to_dict()
    return {row["use_id"]: row["disposition"] for row in document["use_projections"]}


class RagProvenanceTests(unittest.TestCase):
    def test_fixture_separates_mismatch_denial_nonuse_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_rag_provenance(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["candidate_count"], 2)
        self.assertEqual(document["unknown_count"], 1)
        self.assertFalse(document["document_content_read"])
        self.assertFalse(document["source_authenticated"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            dispositions(model),
            {
                "used-mismatch": "candidate_declared_index_digest_mismatch",
                "used-denied": "candidate_declared_unapproved_retrieval",
                "not-used": "declared_not_incorporated",
                "unknown-use": "unknown",
            },
        )
        self.assertEqual(
            analysis.verify_supplied_rag_provenance(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_rag_provenance_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_matching_approved_document_is_not_candidate(self) -> None:
        model = analysis.component_fixture()
        model["documents"][0]["indexed_sha256"] = model["documents"][0]["expected_sha256"]
        self.assertEqual(
            dispositions(model)["used-mismatch"], "declared_matching_index_unverified"
        )
        model["uses"][0]["context_complete"] = False
        self.assertEqual(dispositions(model)["used-mismatch"], "unknown")

    def test_changed_original_or_export_tamper_is_rejected(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_rag_provenance(model)
        changed = copy.deepcopy(model)
        changed["uses"][0]["incorporated"] = "no"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_rag_provenance(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_rag_provenance_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_invalid_digest_reference_and_inconsistent_use_are_rejected(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["documents"][0].update(indexed_sha256="sha256:bad"),
            lambda m: m["documents"][0].update(content="not accepted"),
            lambda m: m["uses"][0].update(document_id=[]),
            lambda m: m["uses"][0].update(document_id="absent"),
            lambda m: m["uses"][0].update(retrieved="no", incorporated="yes"),
            lambda m: m["uses"].append(copy.deepcopy(m["uses"][0])),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_rag_provenance(invalid)
        with self.assertRaises(ValueError):
            analysis.verify_supplied_rag_provenance_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )

    def test_checked_example_remains_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-rag-provenance-component.json").read_text(
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

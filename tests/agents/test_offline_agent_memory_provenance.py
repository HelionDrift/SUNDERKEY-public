"""Supplied agent-memory provenance and read-context controls."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_agent_memory_provenance as analysis

ROOT = Path(__file__).resolve().parents[2]


def dispositions(model: dict) -> dict[str, str]:
    document = analysis.analyze_supplied_agent_memory_provenance(model).to_dict()
    return {row["read_id"]: row["disposition"] for row in document["read_projections"]}


class AgentMemoryProvenanceTests(unittest.TestCase):
    def test_fixture_separates_denied_changed_data_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_memory_provenance(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["candidate_count"], 2)
        self.assertEqual(document["unknown_count"], 1)
        self.assertFalse(document["memory_content_read"])
        self.assertFalse(document["source_authenticated"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            dispositions(model),
            {
                "denied-read": "candidate_declared_denied_memory_use",
                "changed-read": "candidate_declared_memory_digest_mismatch",
                "data-read": "declared_data_only",
                "unknown-read": "unknown",
            },
        )
        self.assertEqual(
            analysis.verify_supplied_agent_memory_provenance(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_agent_memory_provenance_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_rejected_and_matching_approved_read_are_not_candidates(self) -> None:
        model = analysis.component_fixture()
        model["reads"][0]["admission"] = "rejected"
        self.assertEqual(dispositions(model)["denied-read"], "declared_rejected")
        model["entries"][1]["stored_sha256"] = model["entries"][1]["expected_sha256"]
        self.assertEqual(
            dispositions(model)["changed-read"], "declared_approved_memory_unverified"
        )
        model["reads"][1]["context_complete"] = False
        self.assertEqual(dispositions(model)["changed-read"], "unknown")

    def test_changed_original_and_tampered_export_are_rejected(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_agent_memory_provenance(model)
        changed = copy.deepcopy(model)
        changed["reads"][0]["admission"] = "rejected"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_agent_memory_provenance(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_agent_memory_provenance_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_invalid_digest_reference_and_content_are_rejected(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["entries"][0].update(stored_sha256="sha256:bad"),
            lambda m: m["entries"][0].update(memory_text="not accepted"),
            lambda m: m["reads"][0].update(entry_id=[]),
            lambda m: m["reads"][0].update(entry_id="absent"),
            lambda m: m["reads"][0].update(context_complete=1),
            lambda m: m["reads"].append(copy.deepcopy(m["reads"][0])),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_agent_memory_provenance(invalid)
        with self.assertRaises(ValueError):
            analysis.verify_supplied_agent_memory_provenance_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )

    def test_checked_example_is_metadata_only(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-agent-memory-provenance-component.json").read_text(
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

"""Caller-supplied indirect prompt trust-boundary projections."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_indirect_prompt_boundary as analysis

ROOT = Path(__file__).resolve().parents[2]


def dispositions(model: dict) -> dict[str, str]:
    document = analysis.analyze_supplied_indirect_prompt_boundary(model).to_dict()
    return {
        row["promotion_id"]: row["disposition"]
        for row in document["promotion_projections"]
    }


class IndirectPromptBoundaryTests(unittest.TestCase):
    def test_fixture_replays_without_prompt_content_or_authority(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_indirect_prompt_boundary(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["candidate_count"], 1)
        self.assertEqual(document["unknown_count"], 1)
        self.assertFalse(document["prompt_content_interpreted"])
        self.assertFalse(document["finding_claimed"])
        self.assertFalse(document["positive_use_approved"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            dispositions(model),
            {
                "promoted-one": "candidate_declared_lower_trust_promotion",
                "data-only": "declared_data_context",
                "uncertain-one": "unknown",
            },
        )
        self.assertEqual(
            analysis.verify_supplied_indirect_prompt_boundary(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_indirect_prompt_boundary_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_preserved_rejected_trusted_and_incomplete_cases(self) -> None:
        model = analysis.component_fixture()
        model["promotions"][0]["boundary"] = "preserved"
        self.assertEqual(
            dispositions(model)["promoted-one"], "declared_boundary_preserved_unverified"
        )
        model["promotions"][0]["boundary"] = "promoted"
        model["promotions"][0]["admission"] = "rejected"
        self.assertEqual(dispositions(model)["promoted-one"], "declared_rejected")
        model["promotions"][0]["admission"] = "accepted"
        model["content_sources"][0]["trust"] = "trusted"
        self.assertEqual(
            dispositions(model)["promoted-one"], "declared_trusted_source_unverified"
        )
        model["promotions"][0]["context_complete"] = False
        self.assertEqual(dispositions(model)["promoted-one"], "unknown")

    def test_original_change_or_export_tamper_is_refused(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_indirect_prompt_boundary(model)
        changed = copy.deepcopy(model)
        changed["promotions"][0]["boundary"] = "preserved"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_indirect_prompt_boundary(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_indirect_prompt_boundary_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_extra_content_invalid_references_and_duplicate_members_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["content_sources"][0].update(prompt="not accepted"),
            lambda m: m["contexts"][0].update(role="operator"),
            lambda m: m["promotions"][0].update(content_id=[]),
            lambda m: m["promotions"][0].update(context_id="missing"),
            lambda m: m["promotions"][0].update(context_complete=1),
            lambda m: m["promotions"].append(copy.deepcopy(m["promotions"][0])),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_indirect_prompt_boundary(invalid)
        with self.assertRaises(ValueError):
            analysis.analyze_supplied_indirect_prompt_boundary(
                {**model, "promotions": model["promotions"] * 43}
            )
        with self.assertRaises(ValueError):
            analysis.verify_supplied_indirect_prompt_boundary_bytes(
                b'{"schema_version":1,"schema_version":1}', model=model
            )

    def test_checked_example_is_metadata_only(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-indirect-prompt-boundary-component.json").read_text(
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

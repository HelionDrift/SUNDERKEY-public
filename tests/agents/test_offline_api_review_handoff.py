"""Verified synthetic API cases entering proposal-only human review routing."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from scripts.run_offline_api_assessment import _native_adapter, _prepare_case, run_case
from sunderkey.expert_review import ReviewerRole
from sunderkey.human_escalation_routing import ReviewerRosterEntry
from sunderkey.offline_api_assessment import OfflineApiCaseSource, build_offline_api_batch
from sunderkey.offline_api_review_handoff import (
    OfflineApiReviewHandoffError,
    build_offline_api_review_handoff,
    verify_offline_api_review_handoff,
)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "offline-api-assessment"


class OfflineApiReviewHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()
        cls.sources = []
        for name in (
            "corroborated-synthetic-case.json",
            "denied-synthetic-retest-case.json",
        ):
            raw = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
            result = run_case(raw)
            case_id, invocation, evidence = _prepare_case(raw, cls.adapter)
            cls.sources.append(OfflineApiCaseSource(case_id, invocation, evidence, result))
        cls.sources = tuple(cls.sources)
        cls.batch = build_offline_api_batch(adapter=cls.adapter, sources=cls.sources).to_dict()

    def options(self) -> dict:
        return {
            "adapter": self.adapter,
            "sources": self.sources,
            "batch": self.batch,
            "tenant_id": "tenant.synthetic",
            "scope_binding_sha256": "sha256:" + "a" * 64,
            "originating_principal_id": "principal.synthetic-operator",
            "originating_team_id": "team.synthetic-assessment",
            "opened_at": "2026-09-24T12:00:00Z",
            "response_due_at": "2026-09-25T12:00:00Z",
            "planned_at": "2026-09-24T12:00:01Z",
        }

    def test_only_nonnegative_case_enters_unfilled_independent_review(self) -> None:
        options = self.options()
        handoff = build_offline_api_review_handoff(**options)
        self.assertEqual(handoff["review_case_count"], 1)
        self.assertEqual(handoff["effects"]["assignment"], "none")
        self.assertEqual(handoff["origin_authentication"], "not_verified")
        self.assertEqual(handoff["batch_sha256"], self.batch["batch_sha256"])
        plan = handoff["routing_plan"]
        self.assertEqual(len(plan["cases"]), 1)
        self.assertEqual(len(plan["slots"]), 3)
        self.assertEqual({slot["disposition"] for slot in plan["slots"]}, {"unfilled"})
        self.assertEqual(
            plan["cases"][0]["evidence_sha256"], self.sources[0].result["result_sha256"]
        )
        self.assertEqual(verify_offline_api_review_handoff(handoff=handoff, **options), handoff)

    def test_changed_batch_or_handoff_cannot_be_replayed(self) -> None:
        options = self.options()
        handoff = build_offline_api_review_handoff(**options)
        tampered = copy.deepcopy(handoff)
        tampered["review_case_count"] = True
        with self.assertRaisesRegex(OfflineApiReviewHandoffError, "does not match"):
            verify_offline_api_review_handoff(handoff=tampered, **options)
        changed_batch = copy.deepcopy(self.batch)
        changed_batch["review_candidate_case_ids"] = []
        with self.assertRaisesRegex(OfflineApiReviewHandoffError, "sources"):
            build_offline_api_review_handoff(**{**options, "batch": changed_batch})

    def test_negative_only_batch_has_no_review_handoff(self) -> None:
        source = self.sources[1]
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        with self.assertRaisesRegex(OfflineApiReviewHandoffError, "no review candidates"):
            build_offline_api_review_handoff(
                **{**self.options(), "sources": (source,), "batch": batch}
            )

    def test_origin_team_cannot_fill_independent_review_slots(self) -> None:
        roster = (
            ReviewerRosterEntry(
                reviewer_id="reviewer.same-team",
                tenant_id="tenant.synthetic",
                team_id="team.synthetic-assessment",
                role_capabilities=(
                    ReviewerRole.TECHNICAL_EVALUATOR,
                    ReviewerRole.INDEPENDENT_CONTROL,
                    ReviewerRole.INDEPENDENT_ASSURANCE,
                ),
                expertise_tags=("api_authorization",),
                conflicted_case_ids=(),
                active_case_count=0,
                maximum_case_count=3,
                available_from="2026-09-24T11:00:00Z",
                available_until="2026-09-25T12:00:00Z",
                source_sha256="sha256:" + "b" * 64,
            ),
        )
        handoff = build_offline_api_review_handoff(**{**self.options(), "roster": roster})
        slots = handoff["routing_plan"]["slots"]
        technical = next(slot for slot in slots if slot["role"] == "technical_evaluator")
        self.assertEqual(technical["reviewer_id"], "reviewer.same-team")
        for slot in slots:
            if slot["role"] != "technical_evaluator":
                self.assertEqual(slot["disposition"], "unfilled")


if __name__ == "__main__":
    unittest.main()

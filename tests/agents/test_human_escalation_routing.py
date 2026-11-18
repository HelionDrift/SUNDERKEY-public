"""Proposal-only human reviewer routing and independence tests."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.expert_review import ReviewerRole
from sunderkey.human_escalation_routing import (
    HumanEscalationError,
    HumanReviewCase,
    ReviewerRosterEntry,
    plan_human_review,
)

SHA = "sha256:" + "a" * 64
SCOPE = "sha256:" + "b" * 64
AT = "2026-09-23T13:00:00Z"
ROLES = (
    ReviewerRole.TECHNICAL_EVALUATOR,
    ReviewerRole.INDEPENDENT_CONTROL,
    ReviewerRole.INDEPENDENT_ASSURANCE,
)


def case(case_id="case:one", *, roles=ROLES, priority="high", due="2026-09-23T14:00:00Z"):
    return HumanReviewCase(
        case_id=case_id, tenant_id="tenant:one", subject_kind="api_release_delta",
        evidence_sha256=SHA, scope_binding_sha256=SCOPE,
        originating_principal_id="principal:origin",
        originating_team_id="team:origin",
        required_expertise=("api",), required_roles=roles,
        priority=priority, opened_at="2026-09-23T12:00:00Z",
        response_due_at=due,
    )


def reviewer(
    reviewer_id, *, team="team:independent", roles=ROLES,
    expertise=("api",), active=0, maximum=2, conflicts=(),
    until="2026-09-23T15:00:00Z", tenant="tenant:one",
):
    return ReviewerRosterEntry(
        reviewer_id=reviewer_id, tenant_id=tenant, team_id=team,
        role_capabilities=roles, expertise_tags=expertise,
        conflicted_case_ids=conflicts, active_case_count=active,
        maximum_case_count=maximum,
        available_from="2026-09-23T12:00:00Z",
        available_until=until, source_sha256=SHA,
    )


def plan(cases, roster, **changes):
    values = {
        "tenant_id": "tenant:one", "planned_at": AT,
        "cases": tuple(cases), "roster": tuple(roster),
    }
    values.update(changes)
    return plan_human_review(**values)


class HumanEscalationRoutingTests(unittest.TestCase):
    def test_distinct_reviewers_and_independent_teams_are_proposed_only(self):
        roster = (
            reviewer("principal:technical", team="team:origin"),
            reviewer("principal:control"),
            reviewer("principal:assurance"),
        )
        output = plan((case(),), roster)
        self.assertEqual(len(output.slots), 3)
        self.assertEqual(len({item.reviewer_id for item in output.slots}), 3)
        self.assertTrue(all(item.disposition == "proposed" for item in output.slots))
        independent = [item for item in output.slots if item.role is not ROLES[0]]
        self.assertTrue(all(item.reviewer_id != "principal:technical" for item in independent))
        self.assertEqual(output.to_dict()["effects"]["assignment"], "none")
        self.assertEqual(output.to_dict()["effects"]["review_decision"], "none")

    def test_conflict_expertise_availability_and_capacity_leave_slots_unfilled(self):
        roster = (
            reviewer("principal:origin"),
            reviewer("principal:conflicted", conflicts=("case:one",)),
            reviewer("principal:wrong-skill", expertise=("cloud",)),
            reviewer("principal:busy", active=2, maximum=2),
            reviewer("principal:expired", until=AT),
        )
        output = plan((case(),), roster)
        self.assertEqual({item.disposition for item in output.slots}, {"unfilled"})
        self.assertEqual({item.reason for item in output.slots}, {"no_eligible_reviewer"})

    def test_deadline_expiry_is_explicit(self):
        output = plan((case(due="2026-09-23T12:30:00Z"),),
                      (reviewer("principal:one"),))
        self.assertEqual({item.reason for item in output.slots}, {"deadline_expired"})

    def test_priority_and_capacity_balance_are_deterministic(self):
        low = case("case:low", roles=(ReviewerRole.TECHNICAL_EVALUATOR,), priority="low")
        high = case("case:high", roles=(ReviewerRole.TECHNICAL_EVALUATOR,), priority="high")
        roster = (reviewer("principal:a", maximum=1), reviewer("principal:b", maximum=1))
        output = plan((low, high), roster)
        selected = {item.case_id: item.reviewer_id for item in output.slots}
        self.assertEqual(selected, {"case:high": "principal:a", "case:low": "principal:b"})
        reverse = plan((high, low), tuple(reversed(roster)))
        self.assertEqual(output.to_dict(), reverse.to_dict())

    def test_cross_tenant_duplicate_and_tampered_records_fail_closed(self):
        with self.assertRaisesRegex(HumanEscalationError, "tenant"):
            plan((case(),), (reviewer("principal:other", tenant="tenant:two"),))
        with self.assertRaisesRegex(HumanEscalationError, "unique"):
            plan((case(), case()), ())
        with self.assertRaisesRegex(HumanEscalationError, "case_sha256"):
            replace(case(), priority="critical")
        with self.assertRaisesRegex(HumanEscalationError, "roster_entry_sha256"):
            replace(reviewer("principal:one"), maximum_case_count=3)
        with self.assertRaisesRegex(HumanEscalationError, "plan_sha256"):
            replace(plan((case(),), (reviewer("principal:one"),)), planned_at=(
                "2026-09-23T13:01:00Z"
            ))

    def test_invalid_roles_capacity_and_case_time_fail_closed(self):
        with self.assertRaisesRegex(HumanEscalationError, "required_roles"):
            case(roles=(ReviewerRole.INDEPENDENT_ASSURANCE, ReviewerRole.TECHNICAL_EVALUATOR))
        with self.assertRaisesRegex(HumanEscalationError, "capacity"):
            reviewer("principal:one", active=3, maximum=2)
        with self.assertRaisesRegex(HumanEscalationError, "response_due_at"):
            case(due="2026-09-23T11:00:00Z")


if __name__ == "__main__":
    unittest.main()

"""Offline human-review routing proposals with no assignment or approval effect."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from fractions import Fraction
from types import MappingProxyType
from typing import Any

from .expert_review import ReviewerRole
from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_CASES = 256
MAX_REVIEWERS = 1024
MAX_EXPERTISE_TAGS = 32
NO_EFFECTS = MappingProxyType({
    "assignment": "none",
    "authority": "none",
    "evidence_access": "none",
    "execution": "none",
    "notification": "none",
    "review_decision": "none",
})
ROLE_ORDER = (
    ReviewerRole.TECHNICAL_EVALUATOR,
    ReviewerRole.INDEPENDENT_CONTROL,
    ReviewerRole.INDEPENDENT_ASSURANCE,
)
PRIORITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class HumanEscalationError(ValueError):
    """Review routing input or plan violates a closed constraint."""


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise HumanEscalationError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise HumanEscalationError(f"{label} is invalid") from exc


def _time(value: str, label: str) -> datetime:
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise HumanEscalationError(f"{label} is invalid") from exc


def _ids(values: tuple[str, ...], label: str, *, nonempty: bool = False) -> None:
    if (
        not isinstance(values, tuple)
        or len(values) > MAX_EXPERTISE_TAGS
        or (nonempty and not values)
        or any(not isinstance(value, str) for value in values)
        or values != tuple(sorted(set(values)))
    ):
        raise HumanEscalationError(f"{label} must be a canonical bounded tuple")
    for value in values:
        _id(value, label)


@dataclass(frozen=True, slots=True)
class HumanReviewCase:
    case_id: str
    tenant_id: str
    subject_kind: str
    evidence_sha256: str
    scope_binding_sha256: str
    originating_principal_id: str
    originating_team_id: str
    required_expertise: tuple[str, ...]
    required_roles: tuple[ReviewerRole | str, ...]
    priority: str
    opened_at: str
    response_due_at: str
    case_sha256: str = ""

    def __post_init__(self) -> None:
        for name in (
            "case_id", "tenant_id", "subject_kind", "originating_principal_id",
            "originating_team_id",
        ):
            _id(getattr(self, name), name)
        _sha(self.evidence_sha256, "evidence_sha256")
        _sha(self.scope_binding_sha256, "scope_binding_sha256")
        _ids(self.required_expertise, "required_expertise", nonempty=True)
        try:
            roles = tuple(ReviewerRole(value) for value in self.required_roles)
        except (TypeError, ValueError) as exc:
            raise HumanEscalationError("required_roles is invalid") from exc
        if not roles or roles != tuple(role for role in ROLE_ORDER if role in roles):
            raise HumanEscalationError("required_roles must be unique and ordered")
        object.__setattr__(self, "required_roles", roles)
        if self.priority not in PRIORITY_ORDER:
            raise HumanEscalationError("priority is invalid")
        if _time(self.response_due_at, "response_due_at") <= _time(
            self.opened_at, "opened_at"
        ):
            raise HumanEscalationError("response_due_at must follow opened_at")
        expected = _canonical_sha("sunderkey.human-review-case.v1", self._payload())
        if self.case_sha256 and self.case_sha256 != expected:
            raise HumanEscalationError("case_sha256 does not match content")
        object.__setattr__(self, "case_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id, "tenant_id": self.tenant_id,
            "subject_kind": self.subject_kind, "evidence_sha256": self.evidence_sha256,
            "scope_binding_sha256": self.scope_binding_sha256,
            "originating_principal_id": self.originating_principal_id,
            "originating_team_id": self.originating_team_id,
            "required_expertise": list(self.required_expertise),
            "required_roles": [role.value for role in self.required_roles],
            "priority": self.priority, "opened_at": self.opened_at,
            "response_due_at": self.response_due_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "case_sha256": self.case_sha256}


@dataclass(frozen=True, slots=True)
class ReviewerRosterEntry:
    reviewer_id: str
    tenant_id: str
    team_id: str
    role_capabilities: tuple[ReviewerRole | str, ...]
    expertise_tags: tuple[str, ...]
    conflicted_case_ids: tuple[str, ...]
    active_case_count: int
    maximum_case_count: int
    available_from: str
    available_until: str
    source_sha256: str
    roster_entry_sha256: str = ""

    def __post_init__(self) -> None:
        for name in ("reviewer_id", "tenant_id", "team_id"):
            _id(getattr(self, name), name)
        try:
            roles = tuple(ReviewerRole(value) for value in self.role_capabilities)
        except (TypeError, ValueError) as exc:
            raise HumanEscalationError("role_capabilities is invalid") from exc
        if not roles or roles != tuple(role for role in ROLE_ORDER if role in roles):
            raise HumanEscalationError("role_capabilities must be unique and ordered")
        object.__setattr__(self, "role_capabilities", roles)
        _ids(self.expertise_tags, "expertise_tags", nonempty=True)
        _ids(self.conflicted_case_ids, "conflicted_case_ids")
        if (
            isinstance(self.active_case_count, bool)
            or isinstance(self.maximum_case_count, bool)
            or not isinstance(self.active_case_count, int)
            or not isinstance(self.maximum_case_count, int)
            or not 0 <= self.active_case_count <= self.maximum_case_count <= 64
            or self.maximum_case_count == 0
        ):
            raise HumanEscalationError("reviewer capacity is invalid")
        if _time(self.available_until, "available_until") <= _time(
            self.available_from, "available_from"
        ):
            raise HumanEscalationError("reviewer availability interval is invalid")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.human-review-roster-entry.v1", self._payload())
        if self.roster_entry_sha256 and self.roster_entry_sha256 != expected:
            raise HumanEscalationError("roster_entry_sha256 does not match content")
        object.__setattr__(self, "roster_entry_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "reviewer_id": self.reviewer_id, "tenant_id": self.tenant_id,
            "team_id": self.team_id,
            "role_capabilities": [role.value for role in self.role_capabilities],
            "expertise_tags": list(self.expertise_tags),
            "conflicted_case_ids": list(self.conflicted_case_ids),
            "active_case_count": self.active_case_count,
            "maximum_case_count": self.maximum_case_count,
            "available_from": self.available_from,
            "available_until": self.available_until,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "roster_entry_sha256": self.roster_entry_sha256}


@dataclass(frozen=True, slots=True)
class ReviewRoutingSlot:
    case_id: str
    role: ReviewerRole | str
    reviewer_id: str | None
    disposition: str
    reason: str

    def __post_init__(self) -> None:
        _id(self.case_id, "slot case_id")
        try:
            object.__setattr__(self, "role", ReviewerRole(self.role))
        except (TypeError, ValueError) as exc:
            raise HumanEscalationError("slot role is invalid") from exc
        if self.disposition == "proposed":
            if self.reviewer_id is None or self.reason != "eligible_candidate":
                raise HumanEscalationError("proposed slot requires a reviewer")
            _id(self.reviewer_id, "slot reviewer_id")
        elif self.disposition == "unfilled":
            if self.reviewer_id is not None or self.reason not in {
                "deadline_expired", "no_eligible_reviewer"
            }:
                raise HumanEscalationError("unfilled slot has invalid reason")
        else:
            raise HumanEscalationError("slot disposition is invalid")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "case_id": self.case_id, "role": self.role.value,
            "reviewer_id": self.reviewer_id, "disposition": self.disposition,
            "reason": self.reason,
        }


def _maximum_matching(
    eligible_by_role: dict[ReviewerRole, list[ReviewerRosterEntry]],
    roles: tuple[ReviewerRole, ...],
) -> dict[ReviewerRole, str]:
    reviewer_to_role: dict[str, ReviewerRole] = {}
    role_to_reviewer: dict[ReviewerRole, str] = {}

    def assign(role: ReviewerRole, seen: set[str]) -> bool:
        for reviewer in eligible_by_role[role]:
            reviewer_id = reviewer.reviewer_id
            if reviewer_id in seen:
                continue
            seen.add(reviewer_id)
            displaced = reviewer_to_role.get(reviewer_id)
            if displaced is None or assign(displaced, seen):
                reviewer_to_role[reviewer_id] = role
                role_to_reviewer[role] = reviewer_id
                return True
        return False

    for role in sorted(
        roles, key=lambda value: (len(eligible_by_role[value]), ROLE_ORDER.index(value))
    ):
        assign(role, set())
    return role_to_reviewer


def _route(
    cases: tuple[HumanReviewCase, ...],
    roster: tuple[ReviewerRosterEntry, ...],
    at: str,
) -> tuple[ReviewRoutingSlot, ...]:
    now = _time(at, "planned_at")
    added_load: dict[str, int] = {item.reviewer_id: 0 for item in roster}
    slots: list[ReviewRoutingSlot] = []
    ordered_cases = sorted(cases, key=lambda item: (
        PRIORITY_ORDER[item.priority], item.response_due_at, item.case_id
    ))
    for case in ordered_cases:
        if now >= _time(case.response_due_at, "response_due_at"):
            slots.extend(
                ReviewRoutingSlot(case.case_id, role, None, "unfilled", "deadline_expired")
                for role in case.required_roles
            )
            continue
        eligible_by_role: dict[ReviewerRole, list[ReviewerRosterEntry]] = {}
        for role in case.required_roles:
            eligible = [
                reviewer for reviewer in roster
                if reviewer.tenant_id == case.tenant_id
                and role in reviewer.role_capabilities
                and set(case.required_expertise).issubset(reviewer.expertise_tags)
                and case.case_id not in reviewer.conflicted_case_ids
                and reviewer.reviewer_id != case.originating_principal_id
                and (
                    role is ReviewerRole.TECHNICAL_EVALUATOR
                    or reviewer.team_id != case.originating_team_id
                )
                and _time(reviewer.available_from, "available_from") <= now
                < _time(reviewer.available_until, "available_until")
                and reviewer.active_case_count + added_load[reviewer.reviewer_id]
                < reviewer.maximum_case_count
            ]
            eligible_by_role[role] = sorted(eligible, key=lambda item: (
                Fraction(
                    item.active_case_count + added_load[item.reviewer_id],
                    item.maximum_case_count,
                ),
                item.active_case_count + added_load[item.reviewer_id],
                item.reviewer_id,
            ))
        role_to_reviewer = _maximum_matching(eligible_by_role, case.required_roles)
        for role in case.required_roles:
            reviewer_id = role_to_reviewer.get(role)
            if reviewer_id is None:
                slots.append(ReviewRoutingSlot(
                    case.case_id, role, None, "unfilled", "no_eligible_reviewer",
                ))
            else:
                added_load[reviewer_id] += 1
                slots.append(ReviewRoutingSlot(
                    case.case_id, role, reviewer_id, "proposed", "eligible_candidate",
                ))
    return tuple(sorted(slots, key=lambda item: (item.case_id, ROLE_ORDER.index(item.role))))


@dataclass(frozen=True, slots=True)
class HumanReviewRoutingPlan:
    tenant_id: str
    planned_at: str
    cases: tuple[HumanReviewCase, ...]
    roster: tuple[ReviewerRosterEntry, ...]
    slots: tuple[ReviewRoutingSlot, ...]
    plan_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _time(self.planned_at, "planned_at")
        if (
            not isinstance(self.cases, tuple) or len(self.cases) > MAX_CASES
            or any(not isinstance(item, HumanReviewCase) for item in self.cases)
            or self.cases != tuple(sorted(self.cases, key=lambda item: item.case_id))
            or len({item.case_id for item in self.cases}) != len(self.cases)
        ):
            raise HumanEscalationError("cases must be unique, bounded, and canonical")
        if (
            not isinstance(self.roster, tuple) or len(self.roster) > MAX_REVIEWERS
            or any(not isinstance(item, ReviewerRosterEntry) for item in self.roster)
            or self.roster != tuple(sorted(self.roster, key=lambda item: item.reviewer_id))
            or len({item.reviewer_id for item in self.roster}) != len(self.roster)
        ):
            raise HumanEscalationError("roster must be unique, bounded, and canonical")
        if any(item.tenant_id != self.tenant_id for item in (*self.cases, *self.roster)):
            raise HumanEscalationError("case or roster crosses tenant boundary")
        for item in (*self.cases, *self.roster):
            replace(item)
        if any(_time(item.opened_at, "opened_at") > _time(self.planned_at, "planned_at")
               for item in self.cases):
            raise HumanEscalationError("case is future-dated")
        if not isinstance(self.slots, tuple) or self.slots != _route(
            self.cases, self.roster, self.planned_at
        ):
            raise HumanEscalationError("routing slots do not match eligibility")
        expected = _canonical_sha("sunderkey.human-review-routing-plan.v1", self._payload())
        if self.plan_sha256 and self.plan_sha256 != expected:
            raise HumanEscalationError("plan_sha256 does not match content")
        object.__setattr__(self, "plan_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "planned_at": self.planned_at,
            "cases": [item.to_dict() for item in self.cases],
            "roster": [item.to_dict() for item in self.roster],
            "slots": [item.to_dict() for item in self.slots],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "plan_sha256": self.plan_sha256}


def plan_human_review(
    *, tenant_id: str, planned_at: str,
    cases: tuple[HumanReviewCase, ...],
    roster: tuple[ReviewerRosterEntry, ...],
) -> HumanReviewRoutingPlan:
    """Select deterministic candidate reviewers without assigning any work."""
    if (
        not isinstance(cases, tuple) or len(cases) > MAX_CASES
        or any(not isinstance(item, HumanReviewCase) for item in cases)
        or not isinstance(roster, tuple) or len(roster) > MAX_REVIEWERS
        or any(not isinstance(item, ReviewerRosterEntry) for item in roster)
    ):
        raise HumanEscalationError("cases and roster must be bounded typed tuples")
    ordered_cases = tuple(sorted(cases, key=lambda item: item.case_id))
    ordered_roster = tuple(sorted(roster, key=lambda item: item.reviewer_id))
    return HumanReviewRoutingPlan(
        tenant_id=tenant_id, planned_at=planned_at,
        cases=ordered_cases, roster=ordered_roster,
        slots=_route(ordered_cases, ordered_roster, planned_at),
    )

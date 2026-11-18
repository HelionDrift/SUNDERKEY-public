"""Offline deadline and asserted delivery visibility for an exact remediation plan."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any

from .remediation_validation_contracts import (
    MAX_ITEMS,
    RemediationPlan,
    RemediationValidationError,
    _digest,
    _reference,
    _timestamp,
    canonical_json,
    canonical_sha256,
)

MAX_OBSERVATIONS = 4_096
MAX_OBSERVATION_AGE_SECONDS = 604_800
DELIVERY_STATES = frozenset({"unknown", "pending", "delivered", "failed"})
TICKET_STATES = frozenset({"unknown", "open", "closed"})
LOCAL_REFERENCE_RE = re.compile(r"(?:deliveryref|ticketref):[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
NO_EFFECTS = MappingProxyType(
    dict.fromkeys(
        (
            "authorization",
            "closure",
            "execution",
            "integration",
            "network",
            "notification",
            "persistence",
            "qualification",
            "ticketing",
        ),
        "none",
    )
)


class RemediationWorkflowError(RemediationValidationError):
    """The supplied workflow view is ambiguous or does not match its source plan."""


def _address(domain: str, body: Any) -> str:
    return canonical_sha256({"domain": domain, "content": body})


def _local_reference(value: Any, namespace: str) -> None:
    if (
        not isinstance(value, str)
        or LOCAL_REFERENCE_RE.fullmatch(value) is None
        or not value.startswith(namespace + ":")
    ):
        raise RemediationWorkflowError(f"{namespace} must be an opaque reference")


@dataclass(frozen=True, slots=True)
class RemediationServiceTarget:
    item_ref: str
    owner_ref: str
    policy_sha256: str
    recorded_at: str
    due_at: str
    target_sha256: str = ""

    def __post_init__(self) -> None:
        _reference(self.item_ref, "item_ref", "itemref")
        _reference(self.owner_ref, "owner_ref", "principalref")
        _digest(self.policy_sha256, "policy_sha256")
        if _timestamp(self.due_at, "due_at") <= _timestamp(self.recorded_at, "recorded_at"):
            raise RemediationWorkflowError("due_at must follow recorded_at")
        digest = _address("sunderkey.remediation-service-target.v1", self._body())
        if not isinstance(self.target_sha256, str) or self.target_sha256 not in {"", digest}:
            raise RemediationWorkflowError("service target content address is invalid")
        object.__setattr__(self, "target_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "item_ref": self.item_ref,
            "owner_ref": self.owner_ref,
            "policy_sha256": self.policy_sha256,
            "recorded_at": self.recorded_at,
            "due_at": self.due_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "target_sha256": self.target_sha256}


@dataclass(frozen=True, slots=True)
class RemediationDeliveryObservation:
    observation_ref: str
    item_ref: str
    owner_ref: str
    observer_ref: str
    ticket_ref: str | None
    delivery_state: str
    ticket_state: str
    observed_at: str
    source_sha256: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _local_reference(self.observation_ref, "deliveryref")
        _reference(self.item_ref, "item_ref", "itemref")
        _reference(self.owner_ref, "owner_ref", "principalref")
        _reference(self.observer_ref, "observer_ref", "principalref")
        _digest(self.source_sha256, "source_sha256")
        _timestamp(self.observed_at, "observed_at")
        if (
            not isinstance(self.delivery_state, str)
            or self.delivery_state not in DELIVERY_STATES
            or not isinstance(self.ticket_state, str)
            or self.ticket_state not in TICKET_STATES
        ):
            raise RemediationWorkflowError("delivery or ticket state is invalid")
        if self.ticket_ref is not None:
            _local_reference(self.ticket_ref, "ticketref")
        elif self.ticket_state != "unknown" or self.delivery_state == "delivered":
            raise RemediationWorkflowError("a reported ticket outcome requires a ticket reference")
        digest = _address("sunderkey.remediation-delivery-observation.v1", self._body())
        if not isinstance(self.observation_sha256, str) or self.observation_sha256 not in {
            "",
            digest,
        }:
            raise RemediationWorkflowError("delivery observation content address is invalid")
        object.__setattr__(self, "observation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "observation_ref": self.observation_ref,
            "item_ref": self.item_ref,
            "owner_ref": self.owner_ref,
            "observer_ref": self.observer_ref,
            "ticket_ref": self.ticket_ref,
            "delivery_state": self.delivery_state,
            "ticket_state": self.ticket_state,
            "observed_at": self.observed_at,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "observation_sha256": self.observation_sha256}


def review_remediation_workflow(
    plan: RemediationPlan,
    *,
    targets: tuple[RemediationServiceTarget, ...],
    observations: tuple[RemediationDeliveryObservation, ...],
    as_of: str,
    max_observation_age_seconds: int = 86_400,
) -> dict[str, Any]:
    """Project deadlines and supplied ticket metadata, never a resolution verdict."""

    if not isinstance(plan, RemediationPlan):
        raise RemediationWorkflowError("plan must be a typed remediation plan")
    plan = RemediationPlan.from_dict(plan.to_dict())
    if (
        not isinstance(targets, tuple)
        or len(targets) > MAX_ITEMS
        or any(not isinstance(value, RemediationServiceTarget) for value in targets)
        or not isinstance(observations, tuple)
        or len(observations) > MAX_OBSERVATIONS
        or any(not isinstance(value, RemediationDeliveryObservation) for value in observations)
    ):
        raise RemediationWorkflowError("workflow inputs must be bounded typed tuples")
    targets = tuple(sorted((replace(value) for value in targets), key=lambda value: value.item_ref))
    observations = tuple(
        sorted((replace(value) for value in observations), key=lambda value: value.observation_ref)
    )
    if len({value.item_ref for value in targets}) != len(targets):
        raise RemediationWorkflowError("service targets must be unique by item")
    if len({value.observation_ref for value in observations}) != len(observations):
        raise RemediationWorkflowError("delivery observation references must be unique")
    if (
        type(max_observation_age_seconds) is not int
        or not 1 <= max_observation_age_seconds <= MAX_OBSERVATION_AGE_SECONDS
    ):
        raise RemediationWorkflowError("observation age limit is invalid")
    now = _timestamp(as_of, "as_of")
    created = _timestamp(plan.created_at, "plan created_at")
    if now < created:
        raise RemediationWorkflowError("workflow review predates the source plan")
    items_by_ref = {item.item_ref: item for item in plan.items}
    for value in (*targets, *observations):
        item = items_by_ref.get(value.item_ref)
        if item is None or value.owner_ref != item.owner_ref:
            raise RemediationWorkflowError("workflow item or owner does not match source plan")
        timestamp = (
            value.recorded_at if isinstance(value, RemediationServiceTarget) else value.observed_at
        )
        if not created <= _timestamp(timestamp, "workflow source time") <= now:
            raise RemediationWorkflowError("workflow source time is outside the review window")
    plan_stale = now >= _timestamp(plan.expires_at, "plan expires_at")
    targets_by_item = {value.item_ref: value for value in targets}
    output_items = []
    for item in plan.items:
        target = targets_by_item.get(item.item_ref)
        reasons = set()
        deadline_state = "unknown"
        if target is None:
            reasons.add("service_target_missing")
        else:
            deadline_state = "overdue" if now >= _timestamp(target.due_at, "due_at") else "not_due"
            if deadline_state == "overdue":
                reasons.add("asserted_service_target_overdue")
        if plan_stale:
            reasons.add("source_plan_stale")
        history = tuple(value for value in observations if value.item_ref == item.item_ref)
        fresh = tuple(
            value
            for value in history
            if (now - _timestamp(value.observed_at, "observed_at")).total_seconds()
            <= max_observation_age_seconds
        )
        delivery_state = ticket_state = "unknown"
        latest = ()
        if not history:
            reasons.add("delivery_evidence_missing")
        elif not fresh:
            delivery_state = ticket_state = "stale"
            reasons.add("delivery_evidence_stale")
        else:
            latest_time = max(value.observed_at for value in fresh)
            latest = tuple(value for value in fresh if value.observed_at == latest_time)
            delivery_states = {value.delivery_state for value in latest}
            ticket_states = {value.ticket_state for value in latest}
            ticket_refs = {value.ticket_ref for value in fresh if value.ticket_ref is not None}
            delivery_state = (
                next(iter(delivery_states)) if len(delivery_states) == 1 else "conflict"
            )
            ticket_state = next(iter(ticket_states)) if len(ticket_states) == 1 else "conflict"
            if len(ticket_refs) > 1:
                ticket_state = "conflict"
                reasons.add("ticket_lineage_ambiguous")
            if "conflict" in {delivery_state, ticket_state}:
                reasons.add("delivery_metadata_conflict")
            if delivery_state == "failed":
                reasons.add("reported_delivery_failed")
            if delivery_state in {"unknown", "pending"}:
                reasons.add("delivery_not_reported_complete")
            if any(value.ticket_state == "closed" for value in fresh):
                reasons.add("ticket_closed_is_not_remediation_evidence")
        output_items.append(
            {
                "item_ref": item.item_ref,
                "owner_ref": item.owner_ref,
                "target_sha256": None if target is None else target.target_sha256,
                "due_at": None if target is None else target.due_at,
                "deadline_state": deadline_state,
                "delivery_state": delivery_state,
                "ticket_state": ticket_state,
                "latest_observation_sha256s": [value.observation_sha256 for value in latest],
                "observation_sha256s": [value.observation_sha256 for value in history],
                "remediation_state": "unverified",
                "review_required": True,
                "reason_codes": sorted(reasons),
            }
        )
    body = {
        "schema_version": 1,
        "as_of": as_of,
        "plan_id": plan.plan_id,
        "plan_sha256": plan.plan_sha256,
        "context_sha256": plan.context_sha256,
        "max_observation_age_seconds": max_observation_age_seconds,
        "source_plan_stale": plan_stale,
        "target_set_sha256": _address(
            "sunderkey.remediation-service-target-set.v1", [value.to_dict() for value in targets]
        ),
        "observation_set_sha256": _address(
            "sunderkey.remediation-delivery-observation-set.v1",
            [value.to_dict() for value in observations],
        ),
        "items": output_items,
        "claims": {
            "deadline_enforced": False,
            "delivery_verified": False,
            "owner_authenticated": False,
            "remediation_verified": False,
        },
        "effects": dict(NO_EFFECTS),
    }
    return {**body, "review_sha256": _address("sunderkey.remediation-workflow-review.v1", body)}


def verify_remediation_workflow_review(
    review: Mapping[str, Any],
    plan: RemediationPlan,
    *,
    targets: tuple[RemediationServiceTarget, ...],
    observations: tuple[RemediationDeliveryObservation, ...],
    as_of: str,
    max_observation_age_seconds: int = 86_400,
) -> None:
    """Reproduce the complete advisory view from exact caller-supplied sources."""

    if not isinstance(review, Mapping):
        raise RemediationWorkflowError("review must be a mapping")
    expected = review_remediation_workflow(
        plan,
        targets=targets,
        observations=observations,
        as_of=as_of,
        max_observation_age_seconds=max_observation_age_seconds,
    )
    if canonical_json(dict(review)) != canonical_json(expected):
        raise RemediationWorkflowError("workflow review does not replay from its sources")

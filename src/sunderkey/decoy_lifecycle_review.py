"""Offline review of asserted synthetic decoy lifecycle evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from typing import Any

from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_EVENTS = 1000
MAX_APPROVAL_SECONDS = 30 * 24 * 60 * 60
DECOY_RE = re.compile(r"synthetic-decoy:sha256:[0-9a-f]{64}\Z")
SURFACE_RE = re.compile(r"surface:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "deployment": "none",
    "monitoring": "none",
    "network": "none",
    "removal": "none",
    "token_issuance": "none",
}


class DecoyLifecycleError(ValueError):
    """Decoy metadata or lifecycle transition failed closed."""


class DecoyEventKind(StrEnum):
    PLACEMENT_ASSERTED = "placement_asserted"
    TRIGGER_ASSERTED = "trigger_asserted"
    REVOCATION_ASSERTED = "revocation_asserted"
    REMOVAL_ASSERTED = "removal_asserted"


class DecoyState(StrEnum):
    AWAITING_PLACEMENT = "awaiting_placement"
    PLACED_ASSERTED = "placed_asserted"
    TRIGGERED_ASSERTED = "triggered_asserted"
    REVOKED_ASSERTED = "revoked_asserted"
    REMOVED_ASSERTED = "removed_asserted"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise DecoyLifecycleError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise DecoyLifecycleError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise DecoyLifecycleError(f"{label} is invalid") from exc


def _opaque(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DecoyLifecycleError(f"{label} must be an opaque synthetic reference")


@dataclass(frozen=True, slots=True)
class DecoyPlacementApproval:
    tenant_id: str
    scope_sha256: str
    decoy_ref: str
    surface_ref: str
    owner_id: str
    approved_at: str
    expires_at: str
    source_sha256: str
    approval_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _id(self.owner_id, "owner_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.decoy_ref, "decoy_ref", DECOY_RE)
        _opaque(self.surface_ref, "surface_ref", SURFACE_RE)
        approved = _time(self.approved_at, "approved_at")
        expires = _time(self.expires_at, "expires_at")
        if not approved < expires <= approved + timedelta(seconds=MAX_APPROVAL_SECONDS):
            raise DecoyLifecycleError("approval expiry exceeds its hard limit")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.decoy-placement-approval.v1", self._payload())
        if self.approval_sha256 and self.approval_sha256 != expected:
            raise DecoyLifecycleError("approval_sha256 does not match content")
        object.__setattr__(self, "approval_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "decoy_ref": self.decoy_ref, "surface_ref": self.surface_ref,
            "owner_id": self.owner_id, "approved_at": self.approved_at,
            "expires_at": self.expires_at, "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "approval_sha256": self.approval_sha256}


@dataclass(frozen=True, slots=True)
class DecoyLifecycleEvent:
    event_id: str
    tenant_id: str
    scope_sha256: str
    decoy_ref: str
    approval_sha256: str
    kind: DecoyEventKind | str
    occurred_at: str
    evidence_sha256: str
    event_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.event_id, "event_id")
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.decoy_ref, "decoy_ref", DECOY_RE)
        _sha(self.approval_sha256, "approval_sha256")
        try:
            object.__setattr__(self, "kind", DecoyEventKind(self.kind))
        except (TypeError, ValueError) as exc:
            raise DecoyLifecycleError("event kind is invalid") from exc
        _time(self.occurred_at, "occurred_at")
        _sha(self.evidence_sha256, "evidence_sha256")
        expected = _canonical_sha("sunderkey.decoy-lifecycle-event.v1", self._payload())
        if self.event_sha256 and self.event_sha256 != expected:
            raise DecoyLifecycleError("event_sha256 does not match content")
        object.__setattr__(self, "event_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id, "tenant_id": self.tenant_id,
            "scope_sha256": self.scope_sha256, "decoy_ref": self.decoy_ref,
            "approval_sha256": self.approval_sha256, "kind": self.kind.value,
            "occurred_at": self.occurred_at, "evidence_sha256": self.evidence_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "event_sha256": self.event_sha256}


@dataclass(frozen=True, slots=True)
class DecoyLifecycleReview:
    tenant_id: str
    scope_sha256: str
    decoy_ref: str
    approval_sha256: str
    reviewed_at: str
    event_sha256: tuple[str, ...]
    state: DecoyState | str
    review_flags: tuple[str, ...]
    review_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.decoy_ref, "decoy_ref", DECOY_RE)
        _sha(self.approval_sha256, "approval_sha256")
        _time(self.reviewed_at, "reviewed_at")
        try:
            object.__setattr__(self, "state", DecoyState(self.state))
        except (TypeError, ValueError) as exc:
            raise DecoyLifecycleError("review state is invalid") from exc
        if (
            not isinstance(self.event_sha256, tuple)
            or len(self.event_sha256) > MAX_EVENTS
            or len(set(self.event_sha256)) != len(self.event_sha256)
        ):
            raise DecoyLifecycleError("event digests are not canonical")
        for value in self.event_sha256:
            _sha(value, "event digest")
        valid_flags = {
            "expired_placement_requires_removal",
            "post_expiry_trigger_requires_review",
            "removal_evidence_requires_verification",
            "revoked_placement_requires_removal",
            "trigger_requires_independent_review",
        }
        if (
            not isinstance(self.review_flags, tuple)
            or self.review_flags != tuple(sorted(set(self.review_flags)))
            or any(flag not in valid_flags for flag in self.review_flags)
        ):
            raise DecoyLifecycleError("review flags are not canonical")
        expected = _canonical_sha("sunderkey.decoy-lifecycle-review.v1", self._payload())
        if self.review_sha256 and self.review_sha256 != expected:
            raise DecoyLifecycleError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "decoy_ref": self.decoy_ref, "approval_sha256": self.approval_sha256,
            "reviewed_at": self.reviewed_at,
            "event_sha256": list(self.event_sha256),
            "state": self.state.value, "review_flags": list(self.review_flags),
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}


def review_decoy_lifecycle(
    *, approval: DecoyPlacementApproval,
    events: tuple[DecoyLifecycleEvent, ...], reviewed_at: str,
) -> DecoyLifecycleReview:
    """Validate asserted event order and flag review and cleanup obligations."""
    if not isinstance(approval, DecoyPlacementApproval):
        raise DecoyLifecycleError("approval must be typed")
    replace(approval)
    now = _time(reviewed_at, "reviewed_at")
    approved = _time(approval.approved_at, "approved_at")
    expiry = _time(approval.expires_at, "expires_at")
    if approved > now:
        raise DecoyLifecycleError("approval is future-dated")
    if (
        not isinstance(events, tuple) or len(events) > MAX_EVENTS
        or any(not isinstance(event, DecoyLifecycleEvent) for event in events)
    ):
        raise DecoyLifecycleError("events must be a bounded typed tuple")
    by_id: dict[str, DecoyLifecycleEvent] = {}
    for event in events:
        replace(event)
        if (
            event.tenant_id != approval.tenant_id
            or event.scope_sha256 != approval.scope_sha256
            or event.decoy_ref != approval.decoy_ref
            or event.approval_sha256 != approval.approval_sha256
        ):
            raise DecoyLifecycleError("event crosses approval binding")
        occurred = _time(event.occurred_at, "occurred_at")
        if occurred > now or occurred < approved:
            raise DecoyLifecycleError("event is outside review chronology")
        prior = by_id.setdefault(event.event_id, event)
        if prior.event_sha256 != event.event_sha256:
            raise DecoyLifecycleError("event ID has conflicting evidence")
    ordered = sorted(by_id.values(), key=lambda event: (event.occurred_at, event.event_sha256))
    if len({event.occurred_at for event in ordered}) != len(ordered):
        raise DecoyLifecycleError("event chronology has ambiguous equal timestamps")
    state = DecoyState.AWAITING_PLACEMENT
    flags: set[str] = set()
    for event in ordered:
        occurred = _time(event.occurred_at, "occurred_at")
        if event.kind is DecoyEventKind.PLACEMENT_ASSERTED:
            if state is not DecoyState.AWAITING_PLACEMENT or occurred >= expiry:
                raise DecoyLifecycleError("placement lacks current approval or valid state")
            state = DecoyState.PLACED_ASSERTED
        elif event.kind is DecoyEventKind.TRIGGER_ASSERTED:
            if state not in {DecoyState.PLACED_ASSERTED, DecoyState.TRIGGERED_ASSERTED}:
                raise DecoyLifecycleError("trigger lacks active asserted placement")
            state = DecoyState.TRIGGERED_ASSERTED
            flags.add("trigger_requires_independent_review")
            if occurred >= expiry:
                flags.add("post_expiry_trigger_requires_review")
        elif event.kind is DecoyEventKind.REVOCATION_ASSERTED:
            if state not in {DecoyState.PLACED_ASSERTED, DecoyState.TRIGGERED_ASSERTED}:
                raise DecoyLifecycleError("revocation lacks active asserted placement")
            state = DecoyState.REVOKED_ASSERTED
        elif event.kind is DecoyEventKind.REMOVAL_ASSERTED:
            if state not in {
                DecoyState.PLACED_ASSERTED, DecoyState.TRIGGERED_ASSERTED,
                DecoyState.REVOKED_ASSERTED,
            }:
                raise DecoyLifecycleError("removal lacks asserted placement")
            state = DecoyState.REMOVED_ASSERTED
            flags.add("removal_evidence_requires_verification")
    if state in {DecoyState.PLACED_ASSERTED, DecoyState.TRIGGERED_ASSERTED} and now >= expiry:
        flags.add("expired_placement_requires_removal")
    if state is DecoyState.REVOKED_ASSERTED:
        flags.add("revoked_placement_requires_removal")
    return DecoyLifecycleReview(
        tenant_id=approval.tenant_id, scope_sha256=approval.scope_sha256,
        decoy_ref=approval.decoy_ref, approval_sha256=approval.approval_sha256,
        reviewed_at=reviewed_at,
        event_sha256=tuple(event.event_sha256 for event in ordered),
        state=state, review_flags=tuple(sorted(flags)),
    )

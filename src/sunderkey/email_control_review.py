"""Offline review of inert email-control metadata for approved test mailboxes."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from .traffic_derived_api_inventory import (
    TrafficApiInventoryError,
    _canonical_sha,
    _digest,
    _identifier,
    _timestamp,
)

MAX_TEST_MAILBOXES = 50
MAX_OBSERVATIONS = 150
MAX_CLEANUP_ASSERTIONS = 150
MAX_APPROVAL_SECONDS = 7 * 24 * 60 * 60
MAX_EVIDENCE_SECONDS = 2 * 24 * 60 * 60
TEST_MAILBOX_RE = re.compile(r"test-mailbox:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "delivery": "none",
    "mailbox_access": "none",
    "user_interaction": "none",
    "credential_collection": "none",
    "cleanup": "none",
    "network": "none",
    "target_interaction": "none",
}


class EmailControlReviewError(ValueError):
    """Email-control metadata or review violated the closed contract."""


class ArtifactClass(StrEnum):
    HEADER_ONLY = "header_only"
    INERT_LINK = "inert_link"
    INERT_ATTACHMENT = "inert_attachment"


class GatewayDisposition(StrEnum):
    BLOCKED_ASSERTED = "blocked_asserted"
    QUARANTINED_ASSERTED = "quarantined_asserted"
    DELIVERED_ASSERTED = "delivered_asserted"
    UNKNOWN = "unknown"


class MailboxDisposition(StrEnum):
    NOT_DELIVERED_ASSERTED = "not_delivered_asserted"
    DELIVERED_ASSERTED = "delivered_asserted"
    UNKNOWN = "unknown"


class CleanupState(StrEnum):
    CONFIRMED_ASSERTED = "confirmed_asserted"
    PENDING = "pending"
    UNKNOWN = "unknown"


class EmailControlStatus(StrEnum):
    ASSERTED_PREVENTION_FOR_REVIEW = "asserted_prevention_for_review"
    ATTENTION_REQUIRED = "attention_required"
    INCONCLUSIVE = "inconclusive"
    STALE_EVIDENCE = "stale_evidence"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise EmailControlReviewError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise EmailControlReviewError(f"{label} is invalid") from exc


def _time(value: str, label: str) -> datetime:
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise EmailControlReviewError(f"{label} is invalid") from exc


def _mailbox(value: str) -> None:
    if not isinstance(value, str) or TEST_MAILBOX_RE.fullmatch(value) is None:
        raise EmailControlReviewError("mailbox must be an opaque test-mailbox reference")


@dataclass(frozen=True, slots=True)
class EmailTestApproval:
    tenant_id: str
    scope_sha256: str
    scenario_id: str
    test_mailbox_refs: tuple[str, ...]
    allowed_artifact_classes: tuple[ArtifactClass | str, ...]
    approved_at: str
    expires_at: str
    source_sha256: str
    approval_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _id(self.scenario_id, "scenario_id")
        if (
            not isinstance(self.test_mailbox_refs, tuple)
            or not self.test_mailbox_refs
            or len(self.test_mailbox_refs) > MAX_TEST_MAILBOXES
            or self.test_mailbox_refs != tuple(sorted(set(self.test_mailbox_refs)))
        ):
            raise EmailControlReviewError("test mailbox references are not canonical")
        for value in self.test_mailbox_refs:
            _mailbox(value)
        if not isinstance(self.allowed_artifact_classes, tuple):
            raise EmailControlReviewError("artifact classes must be a tuple")
        try:
            kinds = tuple(ArtifactClass(value) for value in self.allowed_artifact_classes)
        except (TypeError, ValueError) as exc:
            raise EmailControlReviewError("artifact classes are invalid") from exc
        if not kinds or kinds != tuple(sorted(set(kinds))):
            raise EmailControlReviewError("artifact classes are not canonical")
        object.__setattr__(self, "allowed_artifact_classes", kinds)
        approved = _time(self.approved_at, "approved_at")
        expires = _time(self.expires_at, "expires_at")
        if not approved < expires <= approved + timedelta(seconds=MAX_APPROVAL_SECONDS):
            raise EmailControlReviewError("approval expiry exceeds its hard limit")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.email-test-approval.v1", self._payload())
        if self.approval_sha256 and self.approval_sha256 != expected:
            raise EmailControlReviewError("approval_sha256 does not match content")
        object.__setattr__(self, "approval_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "scenario_id": self.scenario_id,
            "test_mailbox_refs": list(self.test_mailbox_refs),
            "allowed_artifact_classes": [item.value for item in self.allowed_artifact_classes],
            "approved_at": self.approved_at, "expires_at": self.expires_at,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "approval_sha256": self.approval_sha256}


@dataclass(frozen=True, slots=True)
class EmailDeliveryObservation:
    tenant_id: str
    scope_sha256: str
    approval_sha256: str
    test_mailbox_ref: str
    artifact_class: ArtifactClass | str
    gateway_disposition: GatewayDisposition | str
    mailbox_disposition: MailboxDisposition | str
    source_sha256: str
    observed_at: str
    expires_at: str
    observation_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.approval_sha256, "approval_sha256")
        _mailbox(self.test_mailbox_ref)
        for name, enum_type in (
            ("artifact_class", ArtifactClass),
            ("gateway_disposition", GatewayDisposition),
            ("mailbox_disposition", MailboxDisposition),
        ):
            try:
                object.__setattr__(self, name, enum_type(getattr(self, name)))
            except (TypeError, ValueError) as exc:
                raise EmailControlReviewError(f"{name} is invalid") from exc
        if (
            self.gateway_disposition in {
                GatewayDisposition.BLOCKED_ASSERTED,
                GatewayDisposition.QUARANTINED_ASSERTED,
            }
            and self.mailbox_disposition is MailboxDisposition.DELIVERED_ASSERTED
        ):
            raise EmailControlReviewError("gateway and mailbox dispositions conflict")
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_EVIDENCE_SECONDS):
            raise EmailControlReviewError("observation expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.email-delivery-observation.v1", self._payload())
        if self.observation_sha256 and self.observation_sha256 != expected:
            raise EmailControlReviewError("observation_sha256 does not match content")
        object.__setattr__(self, "observation_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "approval_sha256": self.approval_sha256,
            "test_mailbox_ref": self.test_mailbox_ref,
            "artifact_class": self.artifact_class.value,
            "gateway_disposition": self.gateway_disposition.value,
            "mailbox_disposition": self.mailbox_disposition.value,
            "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "observation_sha256": self.observation_sha256}


@dataclass(frozen=True, slots=True)
class EmailCleanupAssertion:
    tenant_id: str
    scope_sha256: str
    approval_sha256: str
    observation_sha256: str
    state: CleanupState | str
    source_sha256: str
    observed_at: str
    expires_at: str
    cleanup_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        for label in (
            "scope_sha256", "approval_sha256", "observation_sha256", "source_sha256",
        ):
            _sha(getattr(self, label), label)
        try:
            object.__setattr__(self, "state", CleanupState(self.state))
        except (TypeError, ValueError) as exc:
            raise EmailControlReviewError("cleanup state is invalid") from exc
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_EVIDENCE_SECONDS):
            raise EmailControlReviewError("cleanup expiry exceeds its hard limit")
        expected = _canonical_sha("sunderkey.email-cleanup-assertion.v1", self._payload())
        if self.cleanup_sha256 and self.cleanup_sha256 != expected:
            raise EmailControlReviewError("cleanup_sha256 does not match content")
        object.__setattr__(self, "cleanup_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "approval_sha256": self.approval_sha256,
            "observation_sha256": self.observation_sha256,
            "state": self.state.value, "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "cleanup_sha256": self.cleanup_sha256}


@dataclass(frozen=True, slots=True)
class EmailControlReviewItem:
    observation_sha256: str
    test_mailbox_ref: str
    artifact_class: ArtifactClass
    gateway_disposition: GatewayDisposition
    mailbox_disposition: MailboxDisposition
    cleanup_state: CleanupState | None
    review_reason: str

    def __post_init__(self) -> None:
        _sha(self.observation_sha256, "observation_sha256")
        _mailbox(self.test_mailbox_ref)
        for name, enum_type in (
            ("artifact_class", ArtifactClass),
            ("gateway_disposition", GatewayDisposition),
            ("mailbox_disposition", MailboxDisposition),
        ):
            try:
                object.__setattr__(self, name, enum_type(getattr(self, name)))
            except (TypeError, ValueError) as exc:
                raise EmailControlReviewError(f"item {name} is invalid") from exc
        if self.cleanup_state is not None:
            try:
                object.__setattr__(self, "cleanup_state", CleanupState(self.cleanup_state))
            except (TypeError, ValueError) as exc:
                raise EmailControlReviewError("item cleanup state is invalid") from exc
        if self.review_reason not in {
            "prevention_asserted", "delivery_asserted", "outcome_inconclusive",
        }:
            raise EmailControlReviewError("item review reason is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_sha256": self.observation_sha256,
            "test_mailbox_ref": self.test_mailbox_ref,
            "artifact_class": self.artifact_class.value,
            "gateway_disposition": self.gateway_disposition.value,
            "mailbox_disposition": self.mailbox_disposition.value,
            "cleanup_state": self.cleanup_state.value if self.cleanup_state else None,
            "review_reason": self.review_reason,
        }


@dataclass(frozen=True, slots=True)
class EmailControlReview:
    tenant_id: str
    scope_sha256: str
    approval_sha256: str
    reviewed_at: str
    observation_sha256: tuple[str, ...]
    cleanup_sha256: tuple[str, ...]
    items: tuple[EmailControlReviewItem, ...]
    status: EmailControlStatus
    review_reasons: tuple[str, ...]
    review_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _sha(self.approval_sha256, "approval_sha256")
        _time(self.reviewed_at, "reviewed_at")
        if (
            not isinstance(self.observation_sha256, tuple)
            or len(self.observation_sha256) > MAX_OBSERVATIONS
            or self.observation_sha256 != tuple(sorted(set(self.observation_sha256)))
        ):
            raise EmailControlReviewError("review observations are not canonical")
        if (
            not isinstance(self.cleanup_sha256, tuple)
            or len(self.cleanup_sha256) > MAX_CLEANUP_ASSERTIONS
            or self.cleanup_sha256 != tuple(sorted(set(self.cleanup_sha256)))
        ):
            raise EmailControlReviewError("review cleanup assertions are not canonical")
        for value in (*self.observation_sha256, *self.cleanup_sha256):
            _sha(value, "review evidence digest")
        if (
            not isinstance(self.items, tuple)
            or any(not isinstance(item, EmailControlReviewItem) for item in self.items)
            or tuple(item.observation_sha256 for item in self.items)
            != self.observation_sha256
        ):
            raise EmailControlReviewError("review items do not cover observations")
        try:
            object.__setattr__(self, "status", EmailControlStatus(self.status))
        except (TypeError, ValueError) as exc:
            raise EmailControlReviewError("review status is invalid") from exc
        if (
            not isinstance(self.review_reasons, tuple)
            or not self.review_reasons
            or self.review_reasons != tuple(sorted(set(self.review_reasons)))
        ):
            raise EmailControlReviewError("review reasons are not canonical")
        valid_reasons = {
            "prevention_asserted", "delivery_asserted", "outcome_inconclusive",
            "delivered_cleanup_unverified", "no_observations", "evidence_stale",
            "coverage_incomplete",
        }
        if any(reason not in valid_reasons for reason in self.review_reasons):
            raise EmailControlReviewError("review reason is invalid")
        reasons = set(self.review_reasons)
        if (
            self.status is EmailControlStatus.STALE_EVIDENCE
            and "evidence_stale" not in reasons
            or self.status is EmailControlStatus.ATTENTION_REQUIRED
            and "delivery_asserted" not in reasons
            or self.status is EmailControlStatus.INCONCLUSIVE
            and not reasons.intersection({
                "no_observations", "outcome_inconclusive", "coverage_incomplete",
            })
            or self.status is EmailControlStatus.ASSERTED_PREVENTION_FOR_REVIEW
            and reasons != {"prevention_asserted"}
        ):
            raise EmailControlReviewError("review status conflicts with reasons")
        expected = _canonical_sha("sunderkey.email-control-review.v1", self._payload())
        if self.review_sha256 and self.review_sha256 != expected:
            raise EmailControlReviewError("review_sha256 does not match content")
        object.__setattr__(self, "review_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "approval_sha256": self.approval_sha256,
            "reviewed_at": self.reviewed_at,
            "observation_sha256": list(self.observation_sha256),
            "cleanup_sha256": list(self.cleanup_sha256),
            "items": [item.to_dict() for item in self.items],
            "status": self.status.value, "review_reasons": list(self.review_reasons),
            "control_effectiveness_proven": False,
            "independent_review_required": True,
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "review_sha256": self.review_sha256}


def review_email_control(
    *, approval: EmailTestApproval,
    observations: tuple[EmailDeliveryObservation, ...],
    cleanup_assertions: tuple[EmailCleanupAssertion, ...],
    reviewed_at: str,
) -> EmailControlReview:
    """Correlate asserted gateway, mailbox, and cleanup metadata without sending."""
    if not isinstance(approval, EmailTestApproval):
        raise EmailControlReviewError("approval must be typed")
    replace(approval)
    now = _time(reviewed_at, "reviewed_at")
    if _time(approval.approved_at, "approved_at") > now:
        raise EmailControlReviewError("approval is future-dated")
    if (
        not isinstance(observations, tuple)
        or len(observations) > MAX_OBSERVATIONS
        or any(not isinstance(item, EmailDeliveryObservation) for item in observations)
        or not isinstance(cleanup_assertions, tuple)
        or len(cleanup_assertions) > MAX_CLEANUP_ASSERTIONS
        or any(not isinstance(item, EmailCleanupAssertion) for item in cleanup_assertions)
    ):
        raise EmailControlReviewError("evidence must be bounded typed tuples")
    by_key: dict[tuple[str, ArtifactClass], EmailDeliveryObservation] = {}
    for item in observations:
        replace(item)
        if (
            item.tenant_id != approval.tenant_id
            or item.scope_sha256 != approval.scope_sha256
            or item.approval_sha256 != approval.approval_sha256
            or item.test_mailbox_ref not in approval.test_mailbox_refs
            or item.artifact_class not in approval.allowed_artifact_classes
        ):
            raise EmailControlReviewError("observation crosses approval binding")
        if not (
            _time(approval.approved_at, "approved_at")
            <= _time(item.observed_at, "observed_at")
            < _time(approval.expires_at, "expires_at")
            and _time(item.observed_at, "observed_at") <= now
        ):
            raise EmailControlReviewError("observation is outside approval or future-dated")
        key = (item.test_mailbox_ref, item.artifact_class)
        prior = by_key.setdefault(key, item)
        if prior.observation_sha256 != item.observation_sha256:
            raise EmailControlReviewError("one mailbox and artifact has conflicting evidence")
    by_observation = {item.observation_sha256: item for item in by_key.values()}
    by_cleanup: dict[str, EmailCleanupAssertion] = {}
    for item in cleanup_assertions:
        replace(item)
        if (
            item.tenant_id != approval.tenant_id
            or item.scope_sha256 != approval.scope_sha256
            or item.approval_sha256 != approval.approval_sha256
            or item.observation_sha256 not in by_observation
        ):
            raise EmailControlReviewError("cleanup assertion crosses observation binding")
        delivery_time = _time(
            by_observation[item.observation_sha256].observed_at, "observed_at",
        )
        if not delivery_time <= _time(item.observed_at, "observed_at") <= now:
            raise EmailControlReviewError("cleanup assertion is before delivery or future-dated")
        prior = by_cleanup.setdefault(item.observation_sha256, item)
        if prior.cleanup_sha256 != item.cleanup_sha256:
            raise EmailControlReviewError("one observation has conflicting cleanup evidence")
    stale = _time(approval.expires_at, "expires_at") <= now or any(
        _time(item.expires_at, "expires_at") <= now
        for item in (*by_key.values(), *by_cleanup.values())
    )
    items = []
    reasons: set[str] = set()
    for item in sorted(by_key.values(), key=lambda value: value.observation_sha256):
        cleanup = by_cleanup.get(item.observation_sha256)
        if (
            item.gateway_disposition in {
                GatewayDisposition.BLOCKED_ASSERTED,
                GatewayDisposition.QUARANTINED_ASSERTED,
            }
            and item.mailbox_disposition is MailboxDisposition.NOT_DELIVERED_ASSERTED
        ):
            reason = "prevention_asserted"
        elif item.mailbox_disposition is MailboxDisposition.DELIVERED_ASSERTED:
            reason = "delivery_asserted"
            if cleanup is None or cleanup.state is not CleanupState.CONFIRMED_ASSERTED:
                reasons.add("delivered_cleanup_unverified")
        else:
            reason = "outcome_inconclusive"
        reasons.add(reason)
        items.append(EmailControlReviewItem(
            observation_sha256=item.observation_sha256,
            test_mailbox_ref=item.test_mailbox_ref,
            artifact_class=item.artifact_class,
            gateway_disposition=item.gateway_disposition,
            mailbox_disposition=item.mailbox_disposition,
            cleanup_state=cleanup.state if cleanup else None,
            review_reason=reason,
        ))
    if not items:
        reasons.add("no_observations")
    expected_keys = {
        (mailbox, artifact)
        for mailbox in approval.test_mailbox_refs
        for artifact in approval.allowed_artifact_classes
    }
    if set(by_key) != expected_keys:
        reasons.add("coverage_incomplete")
    if stale:
        reasons.add("evidence_stale")
        status = EmailControlStatus.STALE_EVIDENCE
    elif "delivery_asserted" in reasons or "delivered_cleanup_unverified" in reasons:
        status = EmailControlStatus.ATTENTION_REQUIRED
    elif reasons.intersection({
        "outcome_inconclusive", "no_observations", "coverage_incomplete",
    }):
        status = EmailControlStatus.INCONCLUSIVE
    else:
        status = EmailControlStatus.ASSERTED_PREVENTION_FOR_REVIEW
    return EmailControlReview(
        tenant_id=approval.tenant_id, scope_sha256=approval.scope_sha256,
        approval_sha256=approval.approval_sha256, reviewed_at=reviewed_at,
        observation_sha256=tuple(sorted(by_observation)),
        cleanup_sha256=tuple(sorted(item.cleanup_sha256 for item in by_cleanup.values())),
        items=tuple(items), status=status, review_reasons=tuple(sorted(reasons)),
    )

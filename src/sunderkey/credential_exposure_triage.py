"""Opaque, consent-screened credential exposure review without secret access."""

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

MAX_SIGNALS = 5000
MAX_CONSENTS = 5000
MAX_SIGNAL_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_CONSENT_TTL_SECONDS = 90 * 24 * 60 * 60
OPAQUE_PRINCIPAL_RE = re.compile(r"principal:sha256:[0-9a-f]{64}\Z")
OPAQUE_CREDENTIAL_RE = re.compile(r"credential:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authentication": "none",
    "authority": "none",
    "credential_access": "none",
    "login": "none",
    "network": "none",
    "password_audit": "none",
    "rotation": "none",
    "secret_resolution": "none",
}


class CredentialExposureError(ValueError):
    """Credential exposure metadata or consent review failed closed."""


class ExposureKind(StrEnum):
    BREACH_CORRELATION = "breach_correlation"
    REUSE_INDICATOR = "reuse_indicator"
    WEAK_PASSWORD_AUDIT_INDICATOR = "weak_password_audit_indicator"


class ExposureDisposition(StrEnum):
    REVIEW_CANDIDATE = "human_review_candidate"
    CONSENT_MISSING = "blocked_missing_current_consent"
    STALE = "stale_signal"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise CredentialExposureError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise CredentialExposureError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise CredentialExposureError(f"{label} is invalid") from exc


def _opaque(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CredentialExposureError(f"{label} must be an opaque digest reference")


@dataclass(frozen=True, slots=True)
class ExposureReviewConsent:
    tenant_id: str
    scope_sha256: str
    principal_ref: str
    allowed_kinds: tuple[ExposureKind | str, ...]
    issued_at: str
    expires_at: str
    source_sha256: str
    consent_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.principal_ref, "principal_ref", OPAQUE_PRINCIPAL_RE)
        try:
            kinds = tuple(ExposureKind(value) for value in self.allowed_kinds)
        except (TypeError, ValueError) as exc:
            raise CredentialExposureError("allowed_kinds is invalid") from exc
        if not kinds or kinds != tuple(sorted(set(kinds))):
            raise CredentialExposureError("allowed_kinds must be unique and canonical")
        object.__setattr__(self, "allowed_kinds", kinds)
        issued = _time(self.issued_at, "issued_at")
        expires = _time(self.expires_at, "expires_at")
        if not issued < expires <= issued + timedelta(seconds=MAX_CONSENT_TTL_SECONDS):
            raise CredentialExposureError("consent expiry exceeds its hard limit")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.exposure-review-consent.v1", self._payload())
        if self.consent_sha256 and self.consent_sha256 != expected:
            raise CredentialExposureError("consent_sha256 does not match content")
        object.__setattr__(self, "consent_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "principal_ref": self.principal_ref,
            "allowed_kinds": [kind.value for kind in self.allowed_kinds],
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "consent_sha256": self.consent_sha256}


@dataclass(frozen=True, slots=True)
class CredentialExposureSignal:
    event_id: str
    tenant_id: str
    scope_sha256: str
    principal_ref: str
    credential_ref: str
    feed_ref: str
    source_sha256: str
    observed_at: str
    expires_at: str
    kind: ExposureKind | str
    signal_sha256: str = ""

    def __post_init__(self) -> None:
        for name in ("event_id", "tenant_id", "feed_ref"):
            _id(getattr(self, name), name)
        _sha(self.scope_sha256, "scope_sha256")
        _opaque(self.principal_ref, "principal_ref", OPAQUE_PRINCIPAL_RE)
        _opaque(self.credential_ref, "credential_ref", OPAQUE_CREDENTIAL_RE)
        _sha(self.source_sha256, "source_sha256")
        observed = _time(self.observed_at, "observed_at")
        expires = _time(self.expires_at, "expires_at")
        if not observed < expires <= observed + timedelta(seconds=MAX_SIGNAL_AGE_SECONDS):
            raise CredentialExposureError("signal expiry exceeds its hard limit")
        try:
            object.__setattr__(self, "kind", ExposureKind(self.kind))
        except (TypeError, ValueError) as exc:
            raise CredentialExposureError("signal kind is invalid") from exc
        expected = _canonical_sha("sunderkey.credential-exposure-signal.v1", self._payload())
        if self.signal_sha256 and self.signal_sha256 != expected:
            raise CredentialExposureError("signal_sha256 does not match content")
        object.__setattr__(self, "signal_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id, "tenant_id": self.tenant_id,
            "scope_sha256": self.scope_sha256,
            "principal_ref": self.principal_ref,
            "credential_ref": self.credential_ref,
            "feed_ref": self.feed_ref, "source_sha256": self.source_sha256,
            "observed_at": self.observed_at, "expires_at": self.expires_at,
            "kind": self.kind.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "signal_sha256": self.signal_sha256}


@dataclass(frozen=True, slots=True)
class ExposureReviewItem:
    signal_sha256: str
    principal_ref: str
    credential_ref: str
    kind: ExposureKind | str
    matching_consent_sha256: tuple[str, ...]
    disposition: ExposureDisposition | str

    def __post_init__(self) -> None:
        _sha(self.signal_sha256, "item signal digest")
        _opaque(self.principal_ref, "item principal_ref", OPAQUE_PRINCIPAL_RE)
        _opaque(self.credential_ref, "item credential_ref", OPAQUE_CREDENTIAL_RE)
        try:
            object.__setattr__(self, "kind", ExposureKind(self.kind))
            disposition = ExposureDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise CredentialExposureError("item enum is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        if (
            not isinstance(self.matching_consent_sha256, tuple)
            or self.matching_consent_sha256 != tuple(sorted(set(self.matching_consent_sha256)))
        ):
            raise CredentialExposureError("matching consent digests are not canonical")
        for value in self.matching_consent_sha256:
            _sha(value, "item consent digest")
        if (disposition is ExposureDisposition.REVIEW_CANDIDATE) != bool(
            self.matching_consent_sha256
        ):
            raise CredentialExposureError("review candidate requires matching consent")

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal_sha256": self.signal_sha256,
            "principal_ref": self.principal_ref,
            "credential_ref": self.credential_ref,
            "kind": self.kind.value,
            "matching_consent_sha256": list(self.matching_consent_sha256),
            "disposition": self.disposition.value,
        }


@dataclass(frozen=True, slots=True)
class CredentialExposureReviewPlan:
    tenant_id: str
    scope_sha256: str
    reviewed_at: str
    signal_sha256: tuple[str, ...]
    consent_sha256: tuple[str, ...]
    items: tuple[ExposureReviewItem, ...]
    plan_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _time(self.reviewed_at, "reviewed_at")
        for values, maximum, name in (
            (self.signal_sha256, MAX_SIGNALS, "signal_sha256"),
            (self.consent_sha256, MAX_CONSENTS, "consent_sha256"),
        ):
            if (
                not isinstance(values, tuple) or len(values) > maximum
                or values != tuple(sorted(set(values)))
            ):
                raise CredentialExposureError(f"{name} is not canonical")
            for value in values:
                _sha(value, name)
        if (
            not isinstance(self.items, tuple)
            or any(not isinstance(item, ExposureReviewItem) for item in self.items)
            or self.items != tuple(sorted(self.items, key=lambda item: item.signal_sha256))
            or tuple(item.signal_sha256 for item in self.items) != self.signal_sha256
        ):
            raise CredentialExposureError("review items do not cover signals")
        expected = _canonical_sha("sunderkey.credential-exposure-review-plan.v1", self._payload())
        if self.plan_sha256 and self.plan_sha256 != expected:
            raise CredentialExposureError("plan_sha256 does not match content")
        object.__setattr__(self, "plan_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "reviewed_at": self.reviewed_at,
            "signal_sha256": list(self.signal_sha256),
            "consent_sha256": list(self.consent_sha256),
            "items": [item.to_dict() for item in self.items],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "plan_sha256": self.plan_sha256}


def plan_credential_exposure_review(
    *, tenant_id: str, scope_sha256: str, reviewed_at: str,
    signals: tuple[CredentialExposureSignal, ...],
    consents: tuple[ExposureReviewConsent, ...],
) -> CredentialExposureReviewPlan:
    """Screen opaque exposure signals for review, never secret use or rotation."""
    _id(tenant_id, "tenant_id")
    _sha(scope_sha256, "scope_sha256")
    now = _time(reviewed_at, "reviewed_at")
    if (
        not isinstance(signals, tuple) or len(signals) > MAX_SIGNALS
        or any(not isinstance(item, CredentialExposureSignal) for item in signals)
        or not isinstance(consents, tuple) or len(consents) > MAX_CONSENTS
        or any(not isinstance(item, ExposureReviewConsent) for item in consents)
    ):
        raise CredentialExposureError("signals and consents must be bounded typed tuples")
    for item in (*signals, *consents):
        replace(item)
        if item.tenant_id != tenant_id or item.scope_sha256 != scope_sha256:
            raise CredentialExposureError("signal or consent crosses tenant or scope")
    for consent in consents:
        if _time(consent.issued_at, "issued_at") > now:
            raise CredentialExposureError("consent is future-dated")
    by_event: dict[str, CredentialExposureSignal] = {}
    for signal in signals:
        if _time(signal.observed_at, "observed_at") > now:
            raise CredentialExposureError("signal is future-dated")
        prior = by_event.setdefault(signal.event_id, signal)
        if prior.signal_sha256 != signal.signal_sha256:
            raise CredentialExposureError("exposure event ID has conflicting evidence")
    items: list[ExposureReviewItem] = []
    for signal in sorted(by_event.values(), key=lambda item: item.signal_sha256):
        matching = tuple(sorted({
            consent.consent_sha256 for consent in consents
            if consent.principal_ref == signal.principal_ref
            and signal.kind in consent.allowed_kinds
            and _time(consent.issued_at, "issued_at") <= now
            < _time(consent.expires_at, "expires_at")
        }))
        if _time(signal.expires_at, "expires_at") <= now:
            disposition = ExposureDisposition.STALE
            matching = ()
        elif matching:
            disposition = ExposureDisposition.REVIEW_CANDIDATE
        else:
            disposition = ExposureDisposition.CONSENT_MISSING
        items.append(ExposureReviewItem(
            signal_sha256=signal.signal_sha256,
            principal_ref=signal.principal_ref,
            credential_ref=signal.credential_ref,
            kind=signal.kind,
            matching_consent_sha256=matching,
            disposition=disposition,
        ))
    return CredentialExposureReviewPlan(
        tenant_id=tenant_id, scope_sha256=scope_sha256, reviewed_at=reviewed_at,
        signal_sha256=tuple(item.signal_sha256 for item in items),
        consent_sha256=tuple(sorted({item.consent_sha256 for item in consents})),
        items=tuple(items),
    )

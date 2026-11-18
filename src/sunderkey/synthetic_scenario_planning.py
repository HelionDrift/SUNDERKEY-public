"""Inert consent screening for synthetic phishing and insider scenarios."""

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

MAX_REQUESTS = 1000
MAX_CONSENTS = 1000
MAX_REFERENCES = 100
MAX_CONSENT_SECONDS = 14 * 24 * 60 * 60
MAX_WINDOW_SECONDS = 24 * 60 * 60
SYNTHETIC_PRINCIPAL_RE = re.compile(r"synthetic-principal:sha256:[0-9a-f]{64}\Z")
SURFACE_RE = re.compile(r"surface:sha256:[0-9a-f]{64}\Z")
NO_EFFECTS = {
    "authority": "none",
    "credential_collection": "none",
    "delivery": "none",
    "execution": "none",
    "network": "none",
    "target_interaction": "none",
}
EVIDENCE_OBLIGATIONS = (
    "approved_synthetic_population",
    "exact_scope_and_window",
    "activity_trace",
    "cleanup_receipt",
    "independent_review",
)


class SyntheticScenarioError(ValueError):
    """Synthetic scenario metadata or review plan failed closed."""


class ScenarioKind(StrEnum):
    PHISHING_IMPACT = "synthetic_phishing_impact"
    INSIDER_START_POSITION = "synthetic_insider_start_position"


class ScenarioDisposition(StrEnum):
    REVIEW_CANDIDATE = "human_review_candidate"
    NO_MATCHING_CONSENT = "blocked_no_matching_current_consent"
    EXPIRED_REQUEST = "expired_request"


def _id(value: str, label: str) -> None:
    try:
        _identifier(value, label)
    except TrafficApiInventoryError as exc:
        raise SyntheticScenarioError(f"{label} is invalid") from exc


def _sha(value: str, label: str) -> None:
    try:
        _digest(value, label)
    except TrafficApiInventoryError as exc:
        raise SyntheticScenarioError(f"{label} is invalid") from exc


def _time(value: str, label: str):
    try:
        return _timestamp(value, label)
    except TrafficApiInventoryError as exc:
        raise SyntheticScenarioError(f"{label} is invalid") from exc


def _opaque(value: str, label: str, pattern: re.Pattern[str]) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise SyntheticScenarioError(f"{label} must be an opaque synthetic reference")


def _references(
    values: tuple[str, ...], label: str, pattern: re.Pattern[str],
) -> None:
    if (
        not isinstance(values, tuple) or not values or len(values) > MAX_REFERENCES
        or values != tuple(sorted(set(values)))
    ):
        raise SyntheticScenarioError(f"{label} must be bounded and canonical")
    for value in values:
        _opaque(value, label, pattern)


@dataclass(frozen=True, slots=True)
class SyntheticScenarioConsent:
    tenant_id: str
    scope_sha256: str
    scenario_id: str
    kind: ScenarioKind | str
    synthetic_principal_refs: tuple[str, ...]
    surface_refs: tuple[str, ...]
    issued_at: str
    expires_at: str
    source_sha256: str
    consent_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _id(self.scenario_id, "scenario_id")
        _sha(self.scope_sha256, "scope_sha256")
        try:
            object.__setattr__(self, "kind", ScenarioKind(self.kind))
        except (TypeError, ValueError) as exc:
            raise SyntheticScenarioError("scenario kind is invalid") from exc
        _references(
            self.synthetic_principal_refs, "synthetic_principal_refs", SYNTHETIC_PRINCIPAL_RE,
        )
        _references(self.surface_refs, "surface_refs", SURFACE_RE)
        issued = _time(self.issued_at, "issued_at")
        expires = _time(self.expires_at, "expires_at")
        if not issued < expires <= issued + timedelta(seconds=MAX_CONSENT_SECONDS):
            raise SyntheticScenarioError("consent expiry exceeds its hard limit")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.synthetic-scenario-consent.v1", self._payload())
        if self.consent_sha256 and self.consent_sha256 != expected:
            raise SyntheticScenarioError("consent_sha256 does not match content")
        object.__setattr__(self, "consent_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "scenario_id": self.scenario_id, "kind": self.kind.value,
            "synthetic_principal_refs": list(self.synthetic_principal_refs),
            "surface_refs": list(self.surface_refs),
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "consent_sha256": self.consent_sha256}


@dataclass(frozen=True, slots=True)
class SyntheticScenarioRequest:
    request_id: str
    tenant_id: str
    scope_sha256: str
    scenario_id: str
    kind: ScenarioKind | str
    synthetic_principal_ref: str
    surface_ref: str
    created_at: str
    window_start: str
    window_end: str
    source_sha256: str
    request_sha256: str = ""

    def __post_init__(self) -> None:
        for name in ("request_id", "tenant_id", "scenario_id"):
            _id(getattr(self, name), name)
        _sha(self.scope_sha256, "scope_sha256")
        try:
            object.__setattr__(self, "kind", ScenarioKind(self.kind))
        except (TypeError, ValueError) as exc:
            raise SyntheticScenarioError("scenario kind is invalid") from exc
        _opaque(
            self.synthetic_principal_ref, "synthetic_principal_ref", SYNTHETIC_PRINCIPAL_RE,
        )
        _opaque(self.surface_ref, "surface_ref", SURFACE_RE)
        created = _time(self.created_at, "created_at")
        starts = _time(self.window_start, "window_start")
        ends = _time(self.window_end, "window_end")
        if not created <= starts < ends <= starts + timedelta(seconds=MAX_WINDOW_SECONDS):
            raise SyntheticScenarioError("request window exceeds its hard limit")
        _sha(self.source_sha256, "source_sha256")
        expected = _canonical_sha("sunderkey.synthetic-scenario-request.v1", self._payload())
        if self.request_sha256 and self.request_sha256 != expected:
            raise SyntheticScenarioError("request_sha256 does not match content")
        object.__setattr__(self, "request_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id, "tenant_id": self.tenant_id,
            "scope_sha256": self.scope_sha256, "scenario_id": self.scenario_id,
            "kind": self.kind.value,
            "synthetic_principal_ref": self.synthetic_principal_ref,
            "surface_ref": self.surface_ref, "created_at": self.created_at,
            "window_start": self.window_start, "window_end": self.window_end,
            "source_sha256": self.source_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "request_sha256": self.request_sha256}


@dataclass(frozen=True, slots=True)
class ScenarioReviewItem:
    request_sha256: str
    matching_consent_sha256: tuple[str, ...]
    disposition: ScenarioDisposition | str

    def __post_init__(self) -> None:
        _sha(self.request_sha256, "request_sha256")
        try:
            disposition = ScenarioDisposition(self.disposition)
        except (TypeError, ValueError) as exc:
            raise SyntheticScenarioError("disposition is invalid") from exc
        object.__setattr__(self, "disposition", disposition)
        if (
            not isinstance(self.matching_consent_sha256, tuple)
            or self.matching_consent_sha256
            != tuple(sorted(set(self.matching_consent_sha256)))
        ):
            raise SyntheticScenarioError("matching consent digests are not canonical")
        for value in self.matching_consent_sha256:
            _sha(value, "matching consent digest")
        if (disposition is ScenarioDisposition.REVIEW_CANDIDATE) != bool(
            self.matching_consent_sha256
        ):
            raise SyntheticScenarioError("review candidate requires matching consent")

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_sha256": self.request_sha256,
            "matching_consent_sha256": list(self.matching_consent_sha256),
            "disposition": self.disposition.value,
            "evidence_obligations": list(EVIDENCE_OBLIGATIONS),
        }


@dataclass(frozen=True, slots=True)
class SyntheticScenarioPlan:
    tenant_id: str
    scope_sha256: str
    planned_at: str
    request_sha256: tuple[str, ...]
    consent_sha256: tuple[str, ...]
    items: tuple[ScenarioReviewItem, ...]
    plan_sha256: str = ""

    def __post_init__(self) -> None:
        _id(self.tenant_id, "tenant_id")
        _sha(self.scope_sha256, "scope_sha256")
        _time(self.planned_at, "planned_at")
        for values, maximum, label in (
            (self.request_sha256, MAX_REQUESTS, "request_sha256"),
            (self.consent_sha256, MAX_CONSENTS, "consent_sha256"),
        ):
            if (
                not isinstance(values, tuple) or len(values) > maximum
                or values != tuple(sorted(set(values)))
            ):
                raise SyntheticScenarioError(f"{label} is not canonical")
            for value in values:
                _sha(value, label)
        if (
            not isinstance(self.items, tuple)
            or any(not isinstance(item, ScenarioReviewItem) for item in self.items)
            or tuple(item.request_sha256 for item in self.items) != self.request_sha256
        ):
            raise SyntheticScenarioError("review items do not cover requests")
        expected = _canonical_sha("sunderkey.synthetic-scenario-plan.v1", self._payload())
        if self.plan_sha256 and self.plan_sha256 != expected:
            raise SyntheticScenarioError("plan_sha256 does not match content")
        object.__setattr__(self, "plan_sha256", expected)

    def _payload(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id, "scope_sha256": self.scope_sha256,
            "planned_at": self.planned_at,
            "request_sha256": list(self.request_sha256),
            "consent_sha256": list(self.consent_sha256),
            "items": [item.to_dict() for item in self.items],
            "effects": dict(NO_EFFECTS),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._payload(), "plan_sha256": self.plan_sha256}


def plan_synthetic_scenarios(
    *, tenant_id: str, scope_sha256: str, planned_at: str,
    requests: tuple[SyntheticScenarioRequest, ...],
    consents: tuple[SyntheticScenarioConsent, ...],
) -> SyntheticScenarioPlan:
    """Produce review dispositions, never admission or scenario execution."""
    _id(tenant_id, "tenant_id")
    _sha(scope_sha256, "scope_sha256")
    now = _time(planned_at, "planned_at")
    if (
        not isinstance(requests, tuple) or len(requests) > MAX_REQUESTS
        or any(not isinstance(item, SyntheticScenarioRequest) for item in requests)
        or not isinstance(consents, tuple) or len(consents) > MAX_CONSENTS
        or any(not isinstance(item, SyntheticScenarioConsent) for item in consents)
    ):
        raise SyntheticScenarioError("requests and consents must be bounded typed tuples")
    for item in (*requests, *consents):
        replace(item)
        if item.tenant_id != tenant_id or item.scope_sha256 != scope_sha256:
            raise SyntheticScenarioError("request or consent crosses tenant or scope")
    for consent in consents:
        if _time(consent.issued_at, "issued_at") > now:
            raise SyntheticScenarioError("consent is future-dated")
    by_id: dict[str, SyntheticScenarioRequest] = {}
    for request in requests:
        if _time(request.created_at, "created_at") > now:
            raise SyntheticScenarioError("request is future-dated")
        prior = by_id.setdefault(request.request_id, request)
        if prior.request_sha256 != request.request_sha256:
            raise SyntheticScenarioError("request ID has conflicting evidence")
    items: list[ScenarioReviewItem] = []
    for request in sorted(by_id.values(), key=lambda item: item.request_sha256):
        matching = tuple(sorted({
            consent.consent_sha256 for consent in consents
            if consent.scenario_id == request.scenario_id
            and consent.kind == request.kind
            and request.synthetic_principal_ref in consent.synthetic_principal_refs
            and request.surface_ref in consent.surface_refs
            and _time(consent.issued_at, "issued_at") <= now
            < _time(consent.expires_at, "expires_at")
            and _time(consent.issued_at, "issued_at")
            <= _time(request.window_start, "window_start")
            < _time(request.window_end, "window_end")
            <= _time(consent.expires_at, "expires_at")
        }))
        if _time(request.window_end, "window_end") <= now:
            disposition = ScenarioDisposition.EXPIRED_REQUEST
            matching = ()
        elif matching:
            disposition = ScenarioDisposition.REVIEW_CANDIDATE
        else:
            disposition = ScenarioDisposition.NO_MATCHING_CONSENT
        items.append(ScenarioReviewItem(
            request_sha256=request.request_sha256,
            matching_consent_sha256=matching, disposition=disposition,
        ))
    return SyntheticScenarioPlan(
        tenant_id=tenant_id, scope_sha256=scope_sha256, planned_at=planned_at,
        request_sha256=tuple(item.request_sha256 for item in items),
        consent_sha256=tuple(sorted({item.consent_sha256 for item in consents})),
        items=tuple(items),
    )

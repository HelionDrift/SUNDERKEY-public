"""Fail-closed authorized browser action boundary with no built-in browser.

The boundary accepts only caller-supplied scope, admission, policy, clock,
safety, budget, and driver values. It does not resolve credentials, expose
secrets, evaluate scripts, access files, retry actions, or grant authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, ClassVar, Protocol
from urllib.parse import urlsplit

from .assessment_transport_contracts import BrowserAction, BrowserActionIntent, canonical_json
from .execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
)
from .signed_scope_compiler import ScopeBudgetState, VerifiedAssessmentScope, evaluate_request

SCHEMA_VERSION = 1
NO_BUILTIN_IO = True
ENFORCEMENT_BOUNDARY = "injected_authorized_browser_driver_only"
MAX_BYTES = 100_000_000

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_.-]{1,63}\Z")
_CREDENTIAL_REF = re.compile(r"credref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}\Z")
_EVIDENCE_REF = re.compile(r"(?:evidref:[A-Za-z0-9][A-Za-z0-9._:/-]{0,247}|sha256:[0-9a-f]{64})\Z")
_FORBIDDEN_SELECTOR = re.compile(
    r"(?:javascript:|<script|eval\s*\(|input\s*\[\s*type\s*=\s*['\"]?file|"
    r"file://|download\b|clipboard|chrome-extension:|moz-extension:|window\.open|"
    r"target\s*=\s*['\"]?_blank)",
    re.IGNORECASE,
)


class AuthorizedBrowserRuntimeError(ValueError):
    """Raised when a browser boundary value or receipt is invalid."""


class BrowserActionStatus(StrEnum):
    REJECTED_BEFORE_DRIVER = "rejected_before_driver"
    DRIVER_FAILED = "driver_failed"
    POSTCONDITION_FAILED = "postcondition_failed"
    COMPLETED = "completed"


class BrowserDriverFailure(RuntimeError):
    """A safe, coded failure raised by an injected browser driver."""

    def __init__(self, code: str) -> None:
        _code(code, "driver failure code")
        super().__init__(code)
        self.code = code


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(canonical_json(value).encode("ascii"))


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuthorizedBrowserRuntimeError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise AuthorizedBrowserRuntimeError(f"{label} must be a sha256 digest")
    return value


def _code(value: Any, label: str) -> str:
    if not isinstance(value, str) or _CODE.fullmatch(value) is None:
        raise AuthorizedBrowserRuntimeError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AuthorizedBrowserRuntimeError(f"{label} is invalid")
    return value


def _visible_ascii(value: Any, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or not value.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise AuthorizedBrowserRuntimeError(f"{label} must be visible ASCII")
    return value


def _utc(value: Any, label: str) -> str:
    text = _visible_ascii(value, label, 20)
    if len(text) != 20 or not text.endswith("Z"):
        raise AuthorizedBrowserRuntimeError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorizedBrowserRuntimeError(f"{label} is invalid") from exc
    if parsed.isoformat().replace("+00:00", "Z") != text:
        raise AuthorizedBrowserRuntimeError(f"{label} must be canonical UTC")
    return text


def _origin(value: Any, label: str) -> str:
    text = _visible_ascii(value, label, 2048)
    parsed = urlsplit(text)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise AuthorizedBrowserRuntimeError(f"{label} must be a credential-free HTTPS URL")
    try:
        port = parsed.port
    except ValueError as exc:
        raise AuthorizedBrowserRuntimeError(f"{label} port is invalid") from exc
    host = parsed.hostname.lower()
    return f"https://{host}" if port in (None, 443) else f"https://{host}:{port}"


def _binding_sha(binding: ExecutionBinding) -> str:
    return _canonical_sha(binding.to_dict())


def _selector(value: str | None, action: BrowserAction, maximum: int) -> str | None:
    if action is BrowserAction.NAVIGATE:
        if value is not None:
            raise AuthorizedBrowserRuntimeError("navigate cannot carry a selector")
        return None
    if value is None:
        raise AuthorizedBrowserRuntimeError("browser action requires a selector or condition")
    text = _visible_ascii(value, "selector_or_condition", maximum)
    if _FORBIDDEN_SELECTOR.search(text):
        raise AuthorizedBrowserRuntimeError("selector or condition requests a forbidden capability")
    if action is BrowserAction.WAIT_CONDITION:
        if not text.startswith(("present:", "absent:", "url_equals:")):
            raise AuthorizedBrowserRuntimeError("wait condition syntax is not allowlisted")
        operand = text.split(":", 1)[1]
        if not operand or len(operand) > maximum:
            raise AuthorizedBrowserRuntimeError("wait condition operand is invalid")
        if text.startswith("url_equals:"):
            _origin(operand, "wait condition URL")
    elif any(token in text for token in ("\n", "\r", "\x00")):
        raise AuthorizedBrowserRuntimeError("selector syntax is invalid")
    return text


@dataclass(frozen=True, slots=True)
class BrowserBudgetState:
    actions_completed: int
    navigations_completed: int
    bytes_observed: int
    screenshots_captured: int
    session_elapsed_milliseconds: int

    def __post_init__(self) -> None:
        for value, label, maximum in (
            (self.actions_completed, "actions_completed", 1_000_000),
            (self.navigations_completed, "navigations_completed", 1_000_000),
            (self.bytes_observed, "bytes_observed", MAX_BYTES),
            (self.screenshots_captured, "screenshots_captured", 1_000_000),
            (self.session_elapsed_milliseconds, "session_elapsed_milliseconds", 86_400_000),
        ):
            _integer(value, label, 0, maximum)

    def to_dict(self) -> dict[str, int]:
        return {
            "actions_completed": self.actions_completed,
            "bytes_observed": self.bytes_observed,
            "navigations_completed": self.navigations_completed,
            "screenshots_captured": self.screenshots_captured,
            "session_elapsed_milliseconds": self.session_elapsed_milliseconds,
        }


@dataclass(frozen=True, slots=True)
class BrowserBudgetReservation:
    binding_sha256: str
    session_id: str
    action: BrowserAction
    idempotency_key: str
    state_before: BrowserBudgetState
    state_reserved: BrowserBudgetState
    reserved_observed_bytes: int
    reserved_elapsed_milliseconds: int
    reservation_id: str = ""
    reservation_sha256: str = ""

    KIND: ClassVar[str] = "authorized_browser_budget_reservation"

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "budget reservation binding_sha256")
        _identifier(self.session_id, "budget reservation session_id")
        if not isinstance(self.action, BrowserAction):
            raise AuthorizedBrowserRuntimeError("budget reservation action is invalid")
        _identifier(self.idempotency_key, "budget reservation idempotency_key")
        if not isinstance(self.state_before, BrowserBudgetState) or not isinstance(
            self.state_reserved, BrowserBudgetState
        ):
            raise AuthorizedBrowserRuntimeError("budget reservation states are invalid")
        _integer(self.reserved_observed_bytes, "reserved_observed_bytes", 0, MAX_BYTES)
        _integer(
            self.reserved_elapsed_milliseconds,
            "reserved_elapsed_milliseconds",
            1,
            600_000,
        )
        expected = BrowserBudgetState(
            actions_completed=self.state_before.actions_completed + 1,
            navigations_completed=self.state_before.navigations_completed
            + (1 if self.action is BrowserAction.NAVIGATE else 0),
            bytes_observed=self.state_before.bytes_observed + self.reserved_observed_bytes,
            screenshots_captured=self.state_before.screenshots_captured
            + (1 if self.action is BrowserAction.SCREENSHOT_REFERENCE else 0),
            session_elapsed_milliseconds=self.state_before.session_elapsed_milliseconds
            + self.reserved_elapsed_milliseconds,
        )
        if self.state_reserved != expected:
            raise AuthorizedBrowserRuntimeError("budget reservation transition is invalid")
        digest = _canonical_sha({"body": self.body(), "kind": self.KIND})
        identity = "BBR-" + digest[7:39].upper()
        if self.reservation_id and self.reservation_id != identity:
            raise AuthorizedBrowserRuntimeError("budget reservation_id does not match content")
        if self.reservation_sha256 and not hmac.compare_digest(self.reservation_sha256, digest):
            raise AuthorizedBrowserRuntimeError("budget reservation_sha256 does not match content")
        object.__setattr__(self, "reservation_id", identity)
        object.__setattr__(self, "reservation_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "binding_sha256": self.binding_sha256,
            "idempotency_key": self.idempotency_key,
            "reserved_elapsed_milliseconds": self.reserved_elapsed_milliseconds,
            "reserved_observed_bytes": self.reserved_observed_bytes,
            "session_id": self.session_id,
            "state_before": self.state_before.to_dict(),
            "state_reserved": self.state_reserved.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class BrowserBudgetCompletion:
    reservation_id: str
    reservation_sha256: str
    state_after: BrowserBudgetState
    observed_bytes: int
    screenshots_captured: int
    elapsed_milliseconds: int
    completion_sha256: str = ""

    KIND: ClassVar[str] = "authorized_browser_budget_completion"

    def __post_init__(self) -> None:
        _identifier(self.reservation_id, "budget completion reservation_id")
        _digest(self.reservation_sha256, "budget completion reservation_sha256")
        if not isinstance(self.state_after, BrowserBudgetState):
            raise AuthorizedBrowserRuntimeError("budget completion state is invalid")
        _integer(self.observed_bytes, "completion observed_bytes", 0, MAX_BYTES)
        _integer(self.screenshots_captured, "completion screenshots_captured", 0, 1_000_000)
        _integer(self.elapsed_milliseconds, "completion elapsed_milliseconds", 0, 600_000)
        digest = _canonical_sha({"body": self.body(), "kind": self.KIND})
        if self.completion_sha256 and not hmac.compare_digest(self.completion_sha256, digest):
            raise AuthorizedBrowserRuntimeError("budget completion_sha256 does not match content")
        object.__setattr__(self, "completion_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "elapsed_milliseconds": self.elapsed_milliseconds,
            "observed_bytes": self.observed_bytes,
            "reservation_id": self.reservation_id,
            "reservation_sha256": self.reservation_sha256,
            "screenshots_captured": self.screenshots_captured,
            "state_after": self.state_after.to_dict(),
        }


class BrowserBudgetRepository(Protocol):
    def reserve(
        self,
        binding_sha256: str,
        session_id: str,
        action: BrowserAction,
        idempotency_key: str,
        policy: AuthorizedBrowserPolicy,
    ) -> BrowserBudgetReservation: ...

    def complete(
        self,
        reservation: BrowserBudgetReservation,
        observed_bytes: int,
        screenshots_captured: int,
        elapsed_milliseconds: int,
    ) -> BrowserBudgetCompletion: ...


@dataclass(frozen=True, slots=True)
class AuthorizedBrowserPolicy:
    binding: ExecutionBinding
    execution_policy_id: str
    execution_policy_sha256: str
    session_id: str
    principal_label: str
    allowed_actions: tuple[BrowserAction, ...]
    max_actions: int
    max_navigations: int
    max_total_bytes: int
    max_screenshots: int
    max_action_milliseconds: int
    max_session_milliseconds: int
    max_selector_length: int
    policy_id: str = ""
    policy_sha256: str = ""

    KIND: ClassVar[str] = "authorized_browser_policy"

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ExecutionBinding):
            raise AuthorizedBrowserRuntimeError("policy binding is invalid")
        _identifier(self.execution_policy_id, "execution_policy_id")
        _digest(self.execution_policy_sha256, "execution_policy_sha256")
        _identifier(self.session_id, "session_id")
        _identifier(self.principal_label, "principal_label")
        if not self.allowed_actions or not all(
            isinstance(item, BrowserAction) for item in self.allowed_actions
        ):
            raise AuthorizedBrowserRuntimeError("allowed_actions is invalid")
        ordered = tuple(sorted(set(self.allowed_actions), key=lambda item: item.value))
        object.__setattr__(self, "allowed_actions", ordered)
        for value, label, maximum in (
            (self.max_actions, "max_actions", 100_000),
            (self.max_navigations, "max_navigations", 100_000),
            (self.max_total_bytes, "max_total_bytes", MAX_BYTES),
            (self.max_screenshots, "max_screenshots", 100_000),
            (self.max_action_milliseconds, "max_action_milliseconds", 600_000),
            (self.max_session_milliseconds, "max_session_milliseconds", 86_400_000),
            (self.max_selector_length, "max_selector_length", 1024),
        ):
            _integer(value, label, 1, maximum)
        if self.max_navigations > self.max_actions or self.max_screenshots > self.max_actions:
            raise AuthorizedBrowserRuntimeError("sub-ceilings cannot exceed max_actions")
        body = self.body()
        digest = _canonical_sha({"body": body, "kind": self.KIND})
        identity = "ABP-" + digest[7:39].upper()
        if self.policy_id and self.policy_id != identity:
            raise AuthorizedBrowserRuntimeError("policy_id does not match content")
        if self.policy_sha256 and not hmac.compare_digest(self.policy_sha256, digest):
            raise AuthorizedBrowserRuntimeError("policy_sha256 does not match content")
        object.__setattr__(self, "policy_id", identity)
        object.__setattr__(self, "policy_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "allowed_actions": [item.value for item in self.allowed_actions],
            "binding": self.binding.to_dict(),
            "execution_policy_id": self.execution_policy_id,
            "execution_policy_sha256": self.execution_policy_sha256,
            "max_action_milliseconds": self.max_action_milliseconds,
            "max_actions": self.max_actions,
            "max_navigations": self.max_navigations,
            "max_screenshots": self.max_screenshots,
            "max_selector_length": self.max_selector_length,
            "max_session_milliseconds": self.max_session_milliseconds,
            "max_total_bytes": self.max_total_bytes,
            "principal_label": self.principal_label,
            "session_id": self.session_id,
        }


@dataclass(frozen=True, slots=True)
class BrowserSafetySnapshot:
    binding_sha256: str
    request_sha256: str
    health: HealthState
    canceled: bool
    emergency_stop: bool

    def __post_init__(self) -> None:
        _digest(self.binding_sha256, "safety binding_sha256")
        _digest(self.request_sha256, "safety request_sha256")
        if not isinstance(self.health, HealthState):
            raise AuthorizedBrowserRuntimeError("safety health is invalid")
        if not isinstance(self.canceled, bool) or not isinstance(self.emergency_stop, bool):
            raise AuthorizedBrowserRuntimeError("safety stop flags are invalid")


class BrowserRuntimeClock(Protocol):
    def observe(self) -> ClockObservation: ...


class BrowserSafetyMonitor(Protocol):
    def observe(self) -> BrowserSafetySnapshot: ...


@dataclass(frozen=True, slots=True)
class BrowserDriverCommand:
    action: BrowserAction
    page_url: str
    expected_origin: str
    session_id: str
    principal_label: str
    selector_or_condition: str | None
    value_reference: str | None
    evidence_reference: str | None
    maximum_attempts: int
    max_action_milliseconds: int
    max_observed_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.action, BrowserAction):
            raise AuthorizedBrowserRuntimeError("driver action is invalid")
        if _origin(self.page_url, "driver page_url") != self.expected_origin:
            raise AuthorizedBrowserRuntimeError("driver expected origin mismatch")
        _identifier(self.session_id, "driver session_id")
        _identifier(self.principal_label, "driver principal_label")
        _integer(self.maximum_attempts, "maximum_attempts", 1, 1)
        _integer(self.max_action_milliseconds, "max_action_milliseconds", 1, 600_000)
        _integer(self.max_observed_bytes, "max_observed_bytes", 0, MAX_BYTES)
        if (
            self.value_reference is not None
            and _CREDENTIAL_REF.fullmatch(self.value_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("driver value reference is not opaque")
        if (
            self.evidence_reference is not None
            and _EVIDENCE_REF.fullmatch(self.evidence_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("driver evidence reference is not opaque")


@dataclass(frozen=True, slots=True)
class BrowserDriverResult:
    session_id: str
    principal_label: str
    pre_url: str
    post_url: str
    attempts: int
    elapsed_milliseconds: int
    observed_bytes: int
    screenshots_captured: int
    evidence_reference: str | None
    action_complete: bool
    popup_opened: bool = False
    upload_started: bool = False
    download_started: bool = False
    script_evaluated: bool = False
    arbitrary_file_accessed: bool = False
    clipboard_accessed: bool = False
    extension_used: bool = False

    def __post_init__(self) -> None:
        _identifier(self.session_id, "driver result session_id")
        _identifier(self.principal_label, "driver result principal_label")
        _origin(self.pre_url, "driver result pre_url")
        _origin(self.post_url, "driver result post_url")
        _integer(self.attempts, "driver attempts", 1, 1_000_000)
        _integer(self.elapsed_milliseconds, "driver elapsed_milliseconds", 0, 600_000)
        _integer(self.observed_bytes, "driver observed_bytes", 0, MAX_BYTES)
        _integer(self.screenshots_captured, "driver screenshots_captured", 0, 1_000_000)
        if (
            self.evidence_reference is not None
            and _EVIDENCE_REF.fullmatch(self.evidence_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("driver evidence reference is not opaque")
        for name in (
            "action_complete",
            "popup_opened",
            "upload_started",
            "download_started",
            "script_evaluated",
            "arbitrary_file_accessed",
            "clipboard_accessed",
            "extension_used",
        ):
            if not isinstance(getattr(self, name), bool):
                raise AuthorizedBrowserRuntimeError(f"driver result {name} must be a boolean")


class BrowserDriver(Protocol):
    def perform(self, command: BrowserDriverCommand) -> BrowserDriverResult: ...


@dataclass(frozen=True, slots=True)
class BrowserTranscriptEvent:
    sequence: int
    stage: str
    observed_at: str
    monotonic_tick: int
    detail_sha256: str
    previous_event_sha256: str | None
    event_sha256: str = ""

    def __post_init__(self) -> None:
        _integer(self.sequence, "event sequence", 1, 64)
        _code(self.stage, "event stage")
        _utc(self.observed_at, "event observed_at")
        _integer(self.monotonic_tick, "event monotonic_tick", 1, 2**63 - 1)
        _digest(self.detail_sha256, "event detail_sha256")
        if self.previous_event_sha256 is not None:
            _digest(self.previous_event_sha256, "event previous_event_sha256")
        digest = _canonical_sha(self.body())
        if self.event_sha256 and not hmac.compare_digest(self.event_sha256, digest):
            raise AuthorizedBrowserRuntimeError("event_sha256 does not match content")
        object.__setattr__(self, "event_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "detail_sha256": self.detail_sha256,
            "monotonic_tick": self.monotonic_tick,
            "observed_at": self.observed_at,
            "previous_event_sha256": self.previous_event_sha256,
            "sequence": self.sequence,
            "stage": self.stage,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "event_sha256": self.event_sha256}


@dataclass(slots=True)
class _Evidence:
    events: list[BrowserTranscriptEvent] = field(default_factory=list)
    last_tick: int = 0

    def add(self, stage: str, detail: Any, observation: ClockObservation) -> None:
        if not isinstance(observation, ClockObservation):
            raise AuthorizedBrowserRuntimeError("clock returned an invalid observation")
        if observation.monotonic_tick <= self.last_tick:
            raise AuthorizedBrowserRuntimeError("clock monotonic tick did not advance")
        previous = None if not self.events else self.events[-1].event_sha256
        self.events.append(
            BrowserTranscriptEvent(
                len(self.events) + 1,
                stage,
                observation.observed_at,
                observation.monotonic_tick,
                _canonical_sha(detail),
                previous,
            )
        )
        self.last_tick = observation.monotonic_tick


def _validate_transcript(events: tuple[BrowserTranscriptEvent, ...]) -> None:
    if not isinstance(events, tuple) or not events:
        raise AuthorizedBrowserRuntimeError("transcript must be a non-empty tuple")
    previous: str | None = None
    last_tick = 0
    for index, event in enumerate(events, start=1):
        if not isinstance(event, BrowserTranscriptEvent):
            raise AuthorizedBrowserRuntimeError("transcript contains an invalid event")
        if event.sequence != index or event.previous_event_sha256 != previous:
            raise AuthorizedBrowserRuntimeError("transcript chain is invalid")
        if event.monotonic_tick <= last_tick:
            raise AuthorizedBrowserRuntimeError("transcript clock did not advance")
        previous = event.event_sha256
        last_tick = event.monotonic_tick


@dataclass(frozen=True, slots=True)
class BrowserActionReceipt:
    status: BrowserActionStatus
    reason: str
    scope_id: str
    scope_sha256: str
    intent_sha256: str
    execution_request_id: str
    execution_request_sha256: str
    admission_receipt_id: str
    admission_receipt_sha256: str
    policy_id: str
    policy_sha256: str
    binding: ExecutionBinding
    binding_sha256: str
    action: BrowserAction
    session_id: str
    principal_label: str
    intended_origin: str
    driver_called: bool
    budget_reservation_id: str | None
    budget_reservation_sha256: str | None
    budget_completion_sha256: str | None
    pre_url: str | None
    pre_origin: str | None
    pre_session_attestation_sha256: str | None
    post_url: str | None
    post_origin: str | None
    post_session_attestation_sha256: str | None
    observed_bytes: int
    screenshots_captured: int
    elapsed_milliseconds: int
    evidence_reference: str | None
    transcript: tuple[BrowserTranscriptEvent, ...]
    browser_action_performed: bool
    authority_effect: str = "none"
    qualification_effect: str = "none"
    enforcement_boundary: str = ENFORCEMENT_BOUNDARY
    transcript_id: str = ""
    transcript_sha256: str = ""
    receipt_id: str = ""
    receipt_sha256: str = ""

    KIND: ClassVar[str] = "authorized_browser_action_receipt"

    def __post_init__(self) -> None:
        if not isinstance(self.status, BrowserActionStatus):
            raise AuthorizedBrowserRuntimeError("receipt status is invalid")
        _code(self.reason, "receipt reason")
        if self.status is BrowserActionStatus.COMPLETED and self.reason != "completed":
            raise AuthorizedBrowserRuntimeError("completed receipt reason must be completed")
        for value, label in (
            (self.scope_id, "scope_id"),
            (self.execution_request_id, "execution_request_id"),
            (self.admission_receipt_id, "admission_receipt_id"),
            (self.policy_id, "policy_id"),
            (self.session_id, "session_id"),
            (self.principal_label, "principal_label"),
        ):
            _identifier(value, label)
        for value, label in (
            (self.scope_sha256, "scope_sha256"),
            (self.intent_sha256, "intent_sha256"),
            (self.execution_request_sha256, "execution_request_sha256"),
            (self.admission_receipt_sha256, "admission_receipt_sha256"),
            (self.policy_sha256, "policy_sha256"),
        ):
            _digest(value, label)
        if not isinstance(self.binding, ExecutionBinding) or not isinstance(
            self.action, BrowserAction
        ):
            raise AuthorizedBrowserRuntimeError("receipt binding or action is invalid")
        _digest(self.binding_sha256, "binding_sha256")
        if not hmac.compare_digest(self.binding_sha256, _binding_sha(self.binding)):
            raise AuthorizedBrowserRuntimeError("binding_sha256 does not match binding")
        intended_origin = _origin(self.intended_origin, "intended_origin")
        if intended_origin != self.intended_origin:
            raise AuthorizedBrowserRuntimeError("intended_origin is not canonical")
        reservation_values = (
            self.budget_reservation_id,
            self.budget_reservation_sha256,
        )
        if any(value is None for value in reservation_values) != all(
            value is None for value in reservation_values
        ):
            raise AuthorizedBrowserRuntimeError("budget reservation evidence is incomplete")
        if self.budget_reservation_id is not None:
            _identifier(self.budget_reservation_id, "budget_reservation_id")
            _digest(self.budget_reservation_sha256, "budget_reservation_sha256")
        if self.budget_completion_sha256 is not None:
            _digest(self.budget_completion_sha256, "budget_completion_sha256")
            if self.budget_reservation_id is None:
                raise AuthorizedBrowserRuntimeError("budget completion requires a reservation")
        if self.driver_called and self.budget_reservation_id is None:
            raise AuthorizedBrowserRuntimeError("driver call requires a budget reservation")
        if self.status is BrowserActionStatus.COMPLETED and self.budget_completion_sha256 is None:
            raise AuthorizedBrowserRuntimeError("completed action requires budget completion")
        if self.status is BrowserActionStatus.REJECTED_BEFORE_DRIVER and (
            self.driver_called or self.browser_action_performed
        ):
            raise AuthorizedBrowserRuntimeError("pre-driver rejection cannot report a driver call")
        if self.status is BrowserActionStatus.DRIVER_FAILED and (
            not self.driver_called or self.browser_action_performed
        ):
            raise AuthorizedBrowserRuntimeError("driver failure evidence is inconsistent")
        if self.status in {
            BrowserActionStatus.COMPLETED,
            BrowserActionStatus.POSTCONDITION_FAILED,
        } and (not self.driver_called or not self.browser_action_performed):
            raise AuthorizedBrowserRuntimeError("browser action evidence is inconsistent")
        if self.status is BrowserActionStatus.COMPLETED and not self.driver_called:
            raise AuthorizedBrowserRuntimeError("completed receipt requires a driver call")
        if self.authority_effect != "none" or self.qualification_effect != "none":
            raise AuthorizedBrowserRuntimeError("receipt cannot grant authority or qualification")
        if self.enforcement_boundary != ENFORCEMENT_BOUNDARY:
            raise AuthorizedBrowserRuntimeError("enforcement boundary is invalid")
        values = (
            self.pre_url,
            self.pre_origin,
            self.pre_session_attestation_sha256,
            self.post_url,
            self.post_origin,
            self.post_session_attestation_sha256,
        )
        if self.browser_action_performed and any(value is None for value in values):
            raise AuthorizedBrowserRuntimeError("browser result requires complete attestations")
        if not self.browser_action_performed and any(value is not None for value in values):
            raise AuthorizedBrowserRuntimeError("missing browser result cannot carry attestations")
        for url, origin, phase, digest in (
            (self.pre_url, self.pre_origin, "pre", self.pre_session_attestation_sha256),
            (self.post_url, self.post_origin, "post", self.post_session_attestation_sha256),
        ):
            if url is not None:
                if _origin(url, f"{phase}_url") != origin:
                    raise AuthorizedBrowserRuntimeError(f"{phase} origin does not match URL")
                if origin != self.intended_origin and not (
                    self.status is BrowserActionStatus.POSTCONDITION_FAILED
                    and self.reason == "scope_rejected"
                ):
                    raise AuthorizedBrowserRuntimeError(
                        f"{phase} origin does not match intended origin"
                    )
                expected = _canonical_sha(
                    {
                        "origin": origin,
                        "phase": phase,
                        "principal_label": self.principal_label,
                        "session_id": self.session_id,
                        "url": url,
                    }
                )
                if not hmac.compare_digest(digest or "", expected):
                    raise AuthorizedBrowserRuntimeError(f"{phase} session attestation is invalid")
        _integer(self.observed_bytes, "observed_bytes", 0, MAX_BYTES)
        _integer(self.screenshots_captured, "screenshots_captured", 0, 1_000_000)
        _integer(self.elapsed_milliseconds, "elapsed_milliseconds", 0, 600_000)
        if (
            self.evidence_reference is not None
            and _EVIDENCE_REF.fullmatch(self.evidence_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("receipt evidence reference is not opaque")
        _validate_transcript(self.transcript)
        transcript_body = [event.to_dict() for event in self.transcript]
        transcript_digest = _canonical_sha(transcript_body)
        transcript_identity = "ABT-" + transcript_digest[7:39].upper()
        if self.transcript_id and self.transcript_id != transcript_identity:
            raise AuthorizedBrowserRuntimeError("transcript_id does not match content")
        if self.transcript_sha256 and not hmac.compare_digest(
            self.transcript_sha256, transcript_digest
        ):
            raise AuthorizedBrowserRuntimeError("transcript_sha256 does not match content")
        object.__setattr__(self, "transcript_id", transcript_identity)
        object.__setattr__(self, "transcript_sha256", transcript_digest)
        digest = _canonical_sha({"body": self.body(), "kind": self.KIND})
        identity = "ABR-" + digest[7:39].upper()
        if self.receipt_id and self.receipt_id != identity:
            raise AuthorizedBrowserRuntimeError("receipt_id does not match content")
        if self.receipt_sha256 and not hmac.compare_digest(self.receipt_sha256, digest):
            raise AuthorizedBrowserRuntimeError("receipt_sha256 does not match content")
        object.__setattr__(self, "receipt_id", identity)
        object.__setattr__(self, "receipt_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "admission_receipt_id": self.admission_receipt_id,
            "admission_receipt_sha256": self.admission_receipt_sha256,
            "authority_effect": self.authority_effect,
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "browser_action_performed": self.browser_action_performed,
            "budget_completion_sha256": self.budget_completion_sha256,
            "budget_reservation_id": self.budget_reservation_id,
            "budget_reservation_sha256": self.budget_reservation_sha256,
            "driver_called": self.driver_called,
            "elapsed_milliseconds": self.elapsed_milliseconds,
            "enforcement_boundary": self.enforcement_boundary,
            "evidence_reference": self.evidence_reference,
            "execution_request_id": self.execution_request_id,
            "execution_request_sha256": self.execution_request_sha256,
            "intent_sha256": self.intent_sha256,
            "intended_origin": self.intended_origin,
            "observed_bytes": self.observed_bytes,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "post_origin": self.post_origin,
            "post_session_attestation_sha256": self.post_session_attestation_sha256,
            "post_url": self.post_url,
            "pre_origin": self.pre_origin,
            "pre_session_attestation_sha256": self.pre_session_attestation_sha256,
            "pre_url": self.pre_url,
            "principal_label": self.principal_label,
            "qualification_effect": self.qualification_effect,
            "reason": self.reason,
            "scope_id": self.scope_id,
            "scope_sha256": self.scope_sha256,
            "screenshots_captured": self.screenshots_captured,
            "session_id": self.session_id,
            "status": self.status.value,
            "transcript": [event.to_dict() for event in self.transcript],
            "transcript_id": self.transcript_id,
            "transcript_sha256": self.transcript_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "schema_version": SCHEMA_VERSION,
        }


def _check_admission(
    scope: VerifiedAssessmentScope,
    intent: BrowserActionIntent,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedBrowserPolicy,
) -> None:
    if not isinstance(scope, VerifiedAssessmentScope):
        raise AuthorizedBrowserRuntimeError("scope must be a VerifiedAssessmentScope")
    if not isinstance(intent, BrowserActionIntent):
        raise AuthorizedBrowserRuntimeError("intent must be a BrowserActionIntent")
    if not isinstance(execution_request, ExecutionRequest):
        raise AuthorizedBrowserRuntimeError("execution_request is invalid")
    if (
        not isinstance(admission, AdmissionReceipt)
        or admission.status is not AdmissionStatus.ADMITTED
    ):
        raise AuthorizedBrowserRuntimeError("execution admission is not allowed")
    if not isinstance(policy, AuthorizedBrowserPolicy):
        raise AuthorizedBrowserRuntimeError("authorized browser policy is invalid")
    if (
        scope.scope_id != intent.binding.scope_id
        or scope.content_sha256 != intent.binding.scope_sha256
    ):
        raise AuthorizedBrowserRuntimeError("intent scope binding mismatch")
    if execution_request.binding != policy.binding:
        raise AuthorizedBrowserRuntimeError("execution binding mismatch")
    if (
        execution_request.binding.scope_id != scope.scope_id
        or execution_request.binding.scope_sha256 != scope.content_sha256
    ):
        raise AuthorizedBrowserRuntimeError("execution scope binding mismatch")
    if intent.binding.task_id != execution_request.binding.context_id:
        raise AuthorizedBrowserRuntimeError("intent context binding mismatch")
    if (
        intent.session.session_id != execution_request.binding.session_id
        or intent.session.session_id != policy.session_id
        or intent.session.principal_label != policy.principal_label
    ):
        raise AuthorizedBrowserRuntimeError("isolated session or principal binding mismatch")
    if execution_request.policy_id != policy.execution_policy_id or not hmac.compare_digest(
        execution_request.policy_sha256, policy.execution_policy_sha256
    ):
        raise AuthorizedBrowserRuntimeError("execution policy binding mismatch")
    if (
        admission.request_id != execution_request.request_id
        or not hmac.compare_digest(admission.request_sha256, execution_request.request_sha256)
        or admission.policy_id != execution_request.policy_id
        or not hmac.compare_digest(admission.policy_sha256, execution_request.policy_sha256)
    ):
        raise AuthorizedBrowserRuntimeError("admission receipt binding mismatch")
    if not hmac.compare_digest(execution_request.payload_sha256, intent.intent_sha256):
        raise AuthorizedBrowserRuntimeError("execution request does not bind the browser intent")
    if execution_request.payload_size_bytes != len(
        canonical_json(intent.to_dict()).encode("ascii")
    ):
        raise AuthorizedBrowserRuntimeError("execution request payload size mismatch")
    if (
        execution_request.attempt_number != 1
        or execution_request.prior_execution_sha256 is not None
    ):
        raise AuthorizedBrowserRuntimeError("automatic retries are forbidden")


def _check_current_scope(
    scope: VerifiedAssessmentScope,
    intent: BrowserActionIntent,
    observation: ClockObservation,
) -> str:
    decision = evaluate_request(
        scope,
        url=intent.page_url,
        method="GET",
        technique_id=intent.binding.technique_id,
        impact_tier=intent.binding.impact_tier,
        budget_state=ScopeBudgetState(
            intent.binding.budget.requests_completed,
            intent.binding.budget.requests_active,
            intent.binding.budget.requests_in_current_minute,
        ),
        at=datetime.fromisoformat(observation.observed_at[:-1] + "+00:00"),
    )
    if not decision.allowed:
        raise AuthorizedBrowserRuntimeError(f"scope rejected: {decision.reason}")
    return decision.reason


def _check_safety(
    monitor: BrowserSafetyMonitor, binding: ExecutionBinding, request_sha256: str
) -> BrowserSafetySnapshot:
    snapshot = monitor.observe()
    if not isinstance(snapshot, BrowserSafetySnapshot):
        raise AuthorizedBrowserRuntimeError("safety monitor returned an invalid snapshot")
    if (
        snapshot.binding_sha256 != _binding_sha(binding)
        or snapshot.request_sha256 != request_sha256
    ):
        raise AuthorizedBrowserRuntimeError("safety snapshot binding mismatch")
    if snapshot.canceled:
        raise AuthorizedBrowserRuntimeError("canceled")
    if snapshot.emergency_stop:
        raise AuthorizedBrowserRuntimeError("emergency_stop")
    if snapshot.health is not HealthState.HEALTHY:
        raise AuthorizedBrowserRuntimeError("health_not_healthy")
    return snapshot


def _reason(exc: Exception) -> str:
    message = str(exc)
    if message in {"canceled", "emergency_stop", "health_not_healthy"}:
        return message
    if "scope" in message or "protected" in message or "origin" in message:
        return "scope_rejected"
    if "ceiling" in message or "budget" in message:
        return "budget_rejected"
    if "admission" in message or "binding" in message or "policy" in message:
        return "binding_rejected"
    if "selector" in message or "condition" in message or "forbidden" in message:
        return "action_rejected"
    if "clock" in message:
        return "clock_rejected"
    return "validation_rejected"


def _attestation(phase: str, result: BrowserDriverResult, url: str, origin: str) -> str:
    return _canonical_sha(
        {
            "origin": origin,
            "phase": phase,
            "principal_label": result.principal_label,
            "session_id": result.session_id,
            "url": url,
        }
    )


def _validate_budget_reservation(
    reservation: BrowserBudgetReservation,
    *,
    binding_sha256: str,
    session_id: str,
    action: BrowserAction,
    idempotency_key: str,
    policy: AuthorizedBrowserPolicy,
) -> None:
    if not isinstance(reservation, BrowserBudgetReservation):
        raise AuthorizedBrowserRuntimeError("budget repository returned an invalid reservation")
    if (
        reservation.binding_sha256 != binding_sha256
        or reservation.session_id != session_id
        or reservation.action is not action
        or reservation.idempotency_key != idempotency_key
    ):
        raise AuthorizedBrowserRuntimeError("budget reservation binding mismatch")
    before = reservation.state_before
    after = reservation.state_reserved
    if (
        before.actions_completed >= policy.max_actions
        or after.actions_completed > policy.max_actions
    ):
        raise AuthorizedBrowserRuntimeError("action ceiling reached")
    if (
        before.navigations_completed > policy.max_navigations
        or after.navigations_completed > policy.max_navigations
        or (
            action is BrowserAction.NAVIGATE
            and before.navigations_completed >= policy.max_navigations
        )
    ):
        raise AuthorizedBrowserRuntimeError("navigation ceiling reached")
    if (
        before.screenshots_captured > policy.max_screenshots
        or after.screenshots_captured > policy.max_screenshots
        or (
            action is BrowserAction.SCREENSHOT_REFERENCE
            and before.screenshots_captured >= policy.max_screenshots
        )
    ):
        raise AuthorizedBrowserRuntimeError("screenshot ceiling reached")
    remaining_bytes = policy.max_total_bytes - before.bytes_observed
    remaining_time = policy.max_session_milliseconds - before.session_elapsed_milliseconds
    if remaining_bytes <= 0:
        raise AuthorizedBrowserRuntimeError("byte ceiling reached")
    if remaining_time <= 0:
        raise AuthorizedBrowserRuntimeError("session time ceiling reached")
    if reservation.reserved_observed_bytes != remaining_bytes:
        raise AuthorizedBrowserRuntimeError("budget byte reservation is not exact")
    if reservation.reserved_elapsed_milliseconds != min(
        policy.max_action_milliseconds, remaining_time
    ):
        raise AuthorizedBrowserRuntimeError("budget time reservation is not exact")
    if (
        after.bytes_observed > policy.max_total_bytes
        or after.session_elapsed_milliseconds > policy.max_session_milliseconds
    ):
        raise AuthorizedBrowserRuntimeError("budget reservation exceeds policy")


def _validate_budget_completion(
    completion: BrowserBudgetCompletion,
    reservation: BrowserBudgetReservation,
    *,
    observed_bytes: int,
    screenshots_captured: int,
    elapsed_milliseconds: int,
) -> None:
    if not isinstance(completion, BrowserBudgetCompletion):
        raise AuthorizedBrowserRuntimeError("budget repository returned an invalid completion")
    if (
        completion.reservation_id != reservation.reservation_id
        or not hmac.compare_digest(completion.reservation_sha256, reservation.reservation_sha256)
        or completion.observed_bytes != observed_bytes
        or completion.screenshots_captured != screenshots_captured
        or completion.elapsed_milliseconds != elapsed_milliseconds
    ):
        raise AuthorizedBrowserRuntimeError("budget completion binding mismatch")
    if (
        observed_bytes > reservation.reserved_observed_bytes
        or elapsed_milliseconds > reservation.reserved_elapsed_milliseconds
        or screenshots_captured
        > (1 if reservation.action is BrowserAction.SCREENSHOT_REFERENCE else 0)
    ):
        raise AuthorizedBrowserRuntimeError("budget completion exceeds reservation")
    before = reservation.state_before
    expected = BrowserBudgetState(
        actions_completed=before.actions_completed + 1,
        navigations_completed=before.navigations_completed
        + (1 if reservation.action is BrowserAction.NAVIGATE else 0),
        bytes_observed=before.bytes_observed + observed_bytes,
        screenshots_captured=before.screenshots_captured + screenshots_captured,
        session_elapsed_milliseconds=before.session_elapsed_milliseconds + elapsed_milliseconds,
    )
    if completion.state_after != expected:
        raise AuthorizedBrowserRuntimeError("budget completion transition is invalid")


def execute_authorized_browser_action(
    *,
    scope: VerifiedAssessmentScope,
    intent: BrowserActionIntent,
    execution_request: ExecutionRequest,
    admission: AdmissionReceipt,
    policy: AuthorizedBrowserPolicy,
    budget_repository: BrowserBudgetRepository,
    clock: BrowserRuntimeClock,
    safety_monitor: BrowserSafetyMonitor,
    driver: BrowserDriver,
) -> BrowserActionReceipt:
    """Perform at most one injected browser driver call after exact checks."""

    evidence = _Evidence()
    driver_called = False
    browser_action_performed = False
    attested_session_id = intent.session.session_id
    attested_principal_label = intent.session.principal_label
    pre_url: str | None = None
    post_url: str | None = None
    pre_origin: str | None = None
    post_origin: str | None = None
    pre_attestation: str | None = None
    post_attestation: str | None = None
    observed_bytes = 0
    screenshots = 0
    elapsed = 0
    evidence_reference: str | None = None
    intended_origin = _origin(intent.page_url, "intent page_url")
    reservation: BrowserBudgetReservation | None = None
    completion: BrowserBudgetCompletion | None = None
    reservation_valid = False

    def finish(status: BrowserActionStatus, reason: str) -> BrowserActionReceipt:
        if not evidence.events:
            evidence.add("rejected", {"reason": reason}, clock.observe())
        return BrowserActionReceipt(
            status=status,
            reason=reason,
            scope_id=scope.scope_id,
            scope_sha256=scope.content_sha256,
            intent_sha256=intent.intent_sha256,
            execution_request_id=execution_request.request_id,
            execution_request_sha256=execution_request.request_sha256,
            admission_receipt_id=admission.receipt_id,
            admission_receipt_sha256=admission.receipt_sha256,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            binding=execution_request.binding,
            binding_sha256=_binding_sha(execution_request.binding),
            action=intent.action,
            session_id=attested_session_id,
            principal_label=attested_principal_label,
            intended_origin=intended_origin,
            driver_called=driver_called,
            budget_reservation_id=(None if reservation is None else reservation.reservation_id),
            budget_reservation_sha256=(
                None if reservation is None else reservation.reservation_sha256
            ),
            budget_completion_sha256=(None if completion is None else completion.completion_sha256),
            pre_url=pre_url,
            pre_origin=pre_origin,
            pre_session_attestation_sha256=pre_attestation,
            post_url=post_url,
            post_origin=post_origin,
            post_session_attestation_sha256=post_attestation,
            observed_bytes=observed_bytes,
            screenshots_captured=screenshots,
            elapsed_milliseconds=elapsed,
            evidence_reference=evidence_reference,
            transcript=tuple(evidence.events),
            browser_action_performed=browser_action_performed,
        )

    try:
        _check_admission(scope, intent, execution_request, admission, policy)
        expected_origin = intended_origin
        if intent.action not in policy.allowed_actions:
            raise AuthorizedBrowserRuntimeError("browser action is not allowlisted")
        _selector(intent.selector_or_condition, intent.action, policy.max_selector_length)
        if (
            intent.value_reference is not None
            and _CREDENTIAL_REF.fullmatch(intent.value_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("credential reference is not opaque")
        if (
            intent.evidence_reference is not None
            and _EVIDENCE_REF.fullmatch(intent.evidence_reference) is None
        ):
            raise AuthorizedBrowserRuntimeError("evidence reference is not opaque")
        observation = clock.observe()
        decision_reason = _check_current_scope(scope, intent, observation)
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        evidence.add("validated", {"decision": decision_reason}, observation)
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        command_values = {
            "action": intent.action,
            "page_url": intent.page_url,
            "expected_origin": expected_origin,
            "session_id": intent.session.session_id,
            "principal_label": intent.session.principal_label,
            "selector_or_condition": intent.selector_or_condition,
            "value_reference": intent.value_reference,
            "evidence_reference": intent.evidence_reference,
            "maximum_attempts": 1,
            "max_action_milliseconds": policy.max_action_milliseconds,
        }
        reservation = budget_repository.reserve(
            _binding_sha(execution_request.binding),
            intent.session.session_id,
            intent.action,
            execution_request.idempotency_key,
            policy,
        )
        _validate_budget_reservation(
            reservation,
            binding_sha256=_binding_sha(execution_request.binding),
            session_id=intent.session.session_id,
            action=intent.action,
            idempotency_key=execution_request.idempotency_key,
            policy=policy,
        )
        reservation_valid = True
        evidence.add(
            "budget_reserved",
            {
                "reservation_id": reservation.reservation_id,
                "reservation_sha256": reservation.reservation_sha256,
            },
            clock.observe(),
        )
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        final_observation = clock.observe()
        _check_current_scope(scope, intent, final_observation)
        evidence.add("driver_authorized", {"maximum_attempts": 1}, final_observation)
    except Exception as exc:
        if reservation_valid:
            try:
                completion_candidate = budget_repository.complete(reservation, 0, 0, 0)
                _validate_budget_completion(
                    completion_candidate,
                    reservation,
                    observed_bytes=0,
                    screenshots_captured=0,
                    elapsed_milliseconds=0,
                )
                completion = completion_candidate
            except Exception:
                completion = None
        with suppress(Exception):
            evidence.add("rejected", {"reason": _reason(exc)}, clock.observe())
        return finish(BrowserActionStatus.REJECTED_BEFORE_DRIVER, _reason(exc))

    command = BrowserDriverCommand(
        **command_values,
        max_observed_bytes=reservation.reserved_observed_bytes,
    )
    try:
        driver_called = True
        result = driver.perform(command)
        if not isinstance(result, BrowserDriverResult):
            raise BrowserDriverFailure("invalid_driver_result")
        browser_action_performed = True
    except BrowserDriverFailure as exc:
        reason = exc.code
        try:
            completion = budget_repository.complete(reservation, 0, 0, 0)
            _validate_budget_completion(
                completion,
                reservation,
                observed_bytes=0,
                screenshots_captured=0,
                elapsed_milliseconds=0,
            )
        except Exception:
            completion = None
            reason = "budget_completion_failed"
        with suppress(Exception):
            evidence.add("driver_failed", {"failure_code": reason}, clock.observe())
        return finish(BrowserActionStatus.DRIVER_FAILED, reason)
    except Exception:
        reason = "driver_exception"
        try:
            completion = budget_repository.complete(reservation, 0, 0, 0)
            _validate_budget_completion(
                completion,
                reservation,
                observed_bytes=0,
                screenshots_captured=0,
                elapsed_milliseconds=0,
            )
        except Exception:
            completion = None
            reason = "budget_completion_failed"
        with suppress(Exception):
            evidence.add("driver_failed", {"failure_code": reason}, clock.observe())
        return finish(BrowserActionStatus.DRIVER_FAILED, reason)

    pre_url = result.pre_url
    post_url = result.post_url
    pre_origin = _origin(pre_url, "driver pre_url")
    post_origin = _origin(post_url, "driver post_url")
    pre_attestation = _attestation("pre", result, pre_url, pre_origin)
    post_attestation = _attestation("post", result, post_url, post_origin)
    observed_bytes = result.observed_bytes
    screenshots = result.screenshots_captured
    elapsed = result.elapsed_milliseconds
    evidence_reference = result.evidence_reference
    attested_session_id = result.session_id
    attested_principal_label = result.principal_label
    try:
        completion_candidate = budget_repository.complete(
            reservation,
            observed_bytes,
            screenshots,
            elapsed,
        )
        _validate_budget_completion(
            completion_candidate,
            reservation,
            observed_bytes=observed_bytes,
            screenshots_captured=screenshots,
            elapsed_milliseconds=elapsed,
        )
        completion = completion_candidate
        if result.attempts != 1:
            raise AuthorizedBrowserRuntimeError("driver retry evidence is forbidden")
        if (
            result.session_id != intent.session.session_id
            or result.principal_label != intent.session.principal_label
        ):
            raise AuthorizedBrowserRuntimeError("driver session or principal isolation failed")
        if pre_origin != expected_origin or post_origin != expected_origin:
            raise AuthorizedBrowserRuntimeError("cross-origin browser escape is forbidden")
        if not result.action_complete:
            raise AuthorizedBrowserRuntimeError("driver action did not complete")
        if any(
            (
                result.popup_opened,
                result.upload_started,
                result.download_started,
                result.script_evaluated,
                result.arbitrary_file_accessed,
                result.clipboard_accessed,
                result.extension_used,
            )
        ):
            raise AuthorizedBrowserRuntimeError("driver reported a forbidden capability")
        if elapsed > policy.max_action_milliseconds:
            raise AuthorizedBrowserRuntimeError("action time ceiling exceeded")
        if intent.action is BrowserAction.SCREENSHOT_REFERENCE:
            if screenshots != 1 or evidence_reference != intent.evidence_reference:
                raise AuthorizedBrowserRuntimeError("screenshot evidence postcondition failed")
        elif screenshots or evidence_reference is not None:
            raise AuthorizedBrowserRuntimeError("unexpected screenshot evidence")
        _check_safety(safety_monitor, execution_request.binding, execution_request.request_sha256)
        evidence.add(
            "postconditions_validated",
            {
                "observed_bytes": observed_bytes,
                "post_session_attestation_sha256": post_attestation,
                "pre_session_attestation_sha256": pre_attestation,
                "screenshots_captured": screenshots,
            },
            clock.observe(),
        )
        return finish(BrowserActionStatus.COMPLETED, "completed")
    except Exception as exc:
        with suppress(Exception):
            evidence.add("postcondition_failed", {"reason": _reason(exc)}, clock.observe())
        return finish(BrowserActionStatus.POSTCONDITION_FAILED, _reason(exc))


_RECEIPT_FIELDS = {
    "action",
    "admission_receipt_id",
    "admission_receipt_sha256",
    "authority_effect",
    "binding",
    "binding_sha256",
    "browser_action_performed",
    "budget_completion_sha256",
    "budget_reservation_id",
    "budget_reservation_sha256",
    "driver_called",
    "elapsed_milliseconds",
    "enforcement_boundary",
    "evidence_reference",
    "execution_request_id",
    "execution_request_sha256",
    "intent_sha256",
    "intended_origin",
    "kind",
    "observed_bytes",
    "policy_id",
    "policy_sha256",
    "post_origin",
    "post_session_attestation_sha256",
    "post_url",
    "pre_origin",
    "pre_session_attestation_sha256",
    "pre_url",
    "principal_label",
    "qualification_effect",
    "reason",
    "receipt_id",
    "receipt_sha256",
    "schema_version",
    "scope_id",
    "scope_sha256",
    "screenshots_captured",
    "session_id",
    "status",
    "transcript",
    "transcript_id",
    "transcript_sha256",
}


def verify_browser_action_receipt(raw: bytes | str | dict[str, Any]) -> MappingProxyType:
    """Strictly parse and verify one canonical browser action receipt."""

    if isinstance(raw, bytes):
        try:
            text = raw.decode("ascii", errors="strict")
        except UnicodeDecodeError as exc:
            raise AuthorizedBrowserRuntimeError("receipt must use ASCII JSON") from exc
    elif isinstance(raw, str):
        text = raw
    elif isinstance(raw, dict):
        text = canonical_json(raw)
    else:
        raise AuthorizedBrowserRuntimeError("receipt must be JSON or an object")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AuthorizedBrowserRuntimeError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_float=lambda item: (_ for _ in ()).throw(
                AuthorizedBrowserRuntimeError(f"floating-point value is forbidden: {item}")
            ),
            parse_constant=lambda item: (_ for _ in ()).throw(
                AuthorizedBrowserRuntimeError(f"non-finite value is forbidden: {item}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise AuthorizedBrowserRuntimeError("receipt is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != _RECEIPT_FIELDS:
        raise AuthorizedBrowserRuntimeError("receipt fields are not exact")
    if text != canonical_json(value):
        raise AuthorizedBrowserRuntimeError("receipt JSON is not canonical")
    if value["schema_version"] != SCHEMA_VERSION or value["kind"] != BrowserActionReceipt.KIND:
        raise AuthorizedBrowserRuntimeError("receipt version or kind is invalid")
    transcript = value["transcript"]
    if not isinstance(transcript, list) or not transcript:
        raise AuthorizedBrowserRuntimeError("receipt transcript is invalid")
    previous: str | None = None
    for index, event in enumerate(transcript, start=1):
        fields = {
            "detail_sha256",
            "event_sha256",
            "monotonic_tick",
            "observed_at",
            "previous_event_sha256",
            "sequence",
            "stage",
        }
        if not isinstance(event, dict) or set(event) != fields:
            raise AuthorizedBrowserRuntimeError("transcript event fields are not exact")
        body = {key: item for key, item in event.items() if key != "event_sha256"}
        if event["sequence"] != index or event["previous_event_sha256"] != previous:
            raise AuthorizedBrowserRuntimeError("transcript event chain is invalid")
        if not hmac.compare_digest(event["event_sha256"], _canonical_sha(body)):
            raise AuthorizedBrowserRuntimeError("transcript event hash is invalid")
        previous = event["event_sha256"]
    transcript_digest = _canonical_sha(transcript)
    if value["transcript_sha256"] != transcript_digest:
        raise AuthorizedBrowserRuntimeError("transcript digest is invalid")
    if value["transcript_id"] != "ABT-" + transcript_digest[7:39].upper():
        raise AuthorizedBrowserRuntimeError("transcript identity is invalid")
    receipt_body = {
        key: item
        for key, item in value.items()
        if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
    }
    digest = _canonical_sha({"body": receipt_body, "kind": value["kind"]})
    if value["receipt_sha256"] != digest or value["receipt_id"] != "ABR-" + digest[7:39].upper():
        raise AuthorizedBrowserRuntimeError("receipt content address is invalid")
    try:
        checked = BrowserActionReceipt(
            status=BrowserActionStatus(value["status"]),
            reason=value["reason"],
            scope_id=value["scope_id"],
            scope_sha256=value["scope_sha256"],
            intent_sha256=value["intent_sha256"],
            execution_request_id=value["execution_request_id"],
            execution_request_sha256=value["execution_request_sha256"],
            admission_receipt_id=value["admission_receipt_id"],
            admission_receipt_sha256=value["admission_receipt_sha256"],
            policy_id=value["policy_id"],
            policy_sha256=value["policy_sha256"],
            binding=ExecutionBinding(**value["binding"]),
            binding_sha256=value["binding_sha256"],
            action=BrowserAction(value["action"]),
            session_id=value["session_id"],
            principal_label=value["principal_label"],
            intended_origin=value["intended_origin"],
            driver_called=value["driver_called"],
            budget_reservation_id=value["budget_reservation_id"],
            budget_reservation_sha256=value["budget_reservation_sha256"],
            budget_completion_sha256=value["budget_completion_sha256"],
            pre_url=value["pre_url"],
            pre_origin=value["pre_origin"],
            pre_session_attestation_sha256=value["pre_session_attestation_sha256"],
            post_url=value["post_url"],
            post_origin=value["post_origin"],
            post_session_attestation_sha256=value["post_session_attestation_sha256"],
            observed_bytes=value["observed_bytes"],
            screenshots_captured=value["screenshots_captured"],
            elapsed_milliseconds=value["elapsed_milliseconds"],
            evidence_reference=value["evidence_reference"],
            transcript=tuple(BrowserTranscriptEvent(**event) for event in transcript),
            browser_action_performed=value["browser_action_performed"],
            authority_effect=value["authority_effect"],
            qualification_effect=value["qualification_effect"],
            enforcement_boundary=value["enforcement_boundary"],
            transcript_id=value["transcript_id"],
            transcript_sha256=value["transcript_sha256"],
            receipt_id=value["receipt_id"],
            receipt_sha256=value["receipt_sha256"],
        )
    except (AuthorizedBrowserRuntimeError, TypeError, ValueError) as exc:
        raise AuthorizedBrowserRuntimeError("receipt semantic validation failed") from exc
    if checked.to_dict() != value:
        raise AuthorizedBrowserRuntimeError("receipt canonical object does not round trip")
    return MappingProxyType(value)


__all__ = [
    "ENFORCEMENT_BOUNDARY",
    "NO_BUILTIN_IO",
    "AuthorizedBrowserPolicy",
    "AuthorizedBrowserRuntimeError",
    "BrowserActionReceipt",
    "BrowserActionStatus",
    "BrowserBudgetCompletion",
    "BrowserBudgetRepository",
    "BrowserBudgetReservation",
    "BrowserBudgetState",
    "BrowserDriver",
    "BrowserDriverCommand",
    "BrowserDriverFailure",
    "BrowserDriverResult",
    "BrowserRuntimeClock",
    "BrowserSafetyMonitor",
    "BrowserSafetySnapshot",
    "BrowserTranscriptEvent",
    "execute_authorized_browser_action",
    "verify_browser_action_receipt",
]

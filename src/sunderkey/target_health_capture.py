"""Bounded publication of supplied target-health receipts through injected ports.

This workflow reads no target, owns no keys or store, and performs no probes,
retries, sleeps, execution control, or automatic recovery.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, fields
from datetime import UTC, datetime
from typing import Any, Protocol

from .authorized_target_health_runtime import (
    BoundaryReceiptReference,
    BoundarySourceKind,
    HealthDimension,
    HealthSignalState,
    TargetHealthBudgetState,
    TargetHealthObservation,
    TargetHealthReceipt,
    TargetHealthSafetySnapshot,
    TargetHealthStatus,
    parse_target_health_receipt,
)
from .execution_control_runtime import ExecutionBinding, HealthState, canonical_json
from .target_adapter_conformance import AdapterStopRequested, AdapterStopState
from .target_health_custody import TargetHealthAppendResult
from .target_health_custody_contracts import (
    _NO_EFFECTS,
    MAX_DOCUMENT_BYTES,
    MAX_SEQUENCE,
    MAX_STRING_BYTES,
    SIGNATURE_ALGORITHM,
    SignedTargetHealthCustodyEnvelopeV2,
    TargetHealthCollectorPolicyRevision,
    TargetHealthCustodyEvent,
    TargetHealthCustodyReceipt,
    TargetHealthCustodyVerificationResult,
    TargetHealthSigningContext,
    TargetHealthTrustRoot,
    TargetHealthVerificationMode,
    _verify_envelope_common,
    _verify_evidence_current,
    verify_target_health_collector_policy,
    verify_target_health_custody_envelope_current,
)

MAX_SOURCE_CALLS = 128
MAX_TOTAL_BYTES = MAX_SOURCE_CALLS * MAX_DOCUMENT_BYTES
MAX_DOCUMENT_NODES = 8192
MAX_DOCUMENT_DEPTH = 24

_INTEGER_FIELDS = frozenset(
    {
        "schema_version",
        "trust_root_revision",
        "policy_revision",
        "collector_epoch",
        "maximum_observation_age_seconds",
        "maximum_future_skew_seconds",
        "fence_epoch",
        "sequence",
        "next_sequence",
        "current_head_sequence",
        "event_sequence",
        "monotonic_tick",
        "requests_used",
        "evidence_bytes_used",
        "observations_used",
        "latency_milliseconds",
    }
)
_BOOLEAN_FIELDS = frozenset(
    {
        "revoked",
        "canceled",
        "emergency_stop",
        "source_validation_performed",
        "external_call_performed",
        "network_call_performed",
        "browser_action_performed",
        "authentication_performed",
        "boundary_performed",
        "target_effect_performed",
        "signatures_verified",
        "current_policy_verified",
        "current_head_verified",
        "evidence_current_verified",
    }
)
_WRAPPERS = frozenset(
    {
        TargetHealthTrustRoot,
        TargetHealthCollectorPolicyRevision,
        ExecutionBinding,
        TargetHealthSigningContext,
        TargetHealthReceipt,
        TargetHealthBudgetState,
        TargetHealthSafetySnapshot,
        BoundaryReceiptReference,
        TargetHealthObservation,
        SignedTargetHealthCustodyEnvelopeV2,
        TargetHealthCustodyVerificationResult,
        TargetHealthCustodyReceipt,
        TargetHealthCustodyEvent,
    }
)
_ENUMS = frozenset(
    {
        BoundarySourceKind,
        HealthDimension,
        HealthSignalState,
        TargetHealthStatus,
        HealthState,
        TargetHealthVerificationMode,
    }
)


class TargetHealthCaptureError(ValueError):
    """Invalid configuration or supplied native metadata for this leaf workflow."""


class TargetHealthReceiptSource(Protocol):
    """Caller-supplied receipt bytes, not a target collector or probe."""

    def read_receipt(self, *, maximum_bytes: int) -> bytes | None: ...


class TargetHealthEnvelopeSigner(Protocol):
    """Injected signing capability; the workflow accepts no private key."""

    def sign(self, payload: bytes) -> bytes: ...


class TargetHealthCaptureCustody(Protocol):
    """The unchanged context and atomic-append ports of target-health custody."""

    def prepare_signing_context(
        self, *, tenant_id: str, mission_id: str, collector_id: str, binding_sha256: str
    ) -> TargetHealthSigningContext: ...

    def append_envelope(
        self, envelope: SignedTargetHealthCustodyEnvelopeV2
    ) -> TargetHealthAppendResult: ...


@dataclass(frozen=True, slots=True)
class TargetHealthCapturePublication:
    """Validated acknowledgement from the injected custody port, not live truth."""

    envelope: SignedTargetHealthCustodyEnvelopeV2
    receipt: TargetHealthCustodyReceipt
    event: TargetHealthCustodyEvent
    replayed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_dict(),
            "receipt": self.receipt.to_dict(),
            "event": self.event.to_dict(),
            "replayed": self.replayed,
        }


@dataclass(frozen=True, slots=True)
class TargetHealthCaptureResult:
    """In-memory bounded progress; no schema, authority or qualification claim."""

    publications: tuple[TargetHealthCapturePublication, ...]
    source_calls: int
    source_bytes: int
    context_calls: int
    signing_calls: int
    append_calls: int
    terminal_stage: str
    reason: str
    uncertain_envelope: SignedTargetHealthCustodyEnvelopeV2 | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "publications": [item.to_dict() for item in self.publications],
            "source_calls": self.source_calls,
            "source_bytes": self.source_bytes,
            "context_calls": self.context_calls,
            "signing_calls": self.signing_calls,
            "append_calls": self.append_calls,
            "terminal_stage": self.terminal_stage,
            "reason": self.reason,
            "uncertain_envelope": (
                None if self.uncertain_envelope is None else self.uncertain_envelope.to_dict()
            ),
            "authority_effect": "none",
            "qualification_effect": "none",
            "pause_effect": "none",
            "resume_effect": "none",
            "network_call_performed": False,
            "target_effect_performed": False,
        }


def _scalar(value: Any, name: str) -> None:
    if name in _INTEGER_FIELDS and not (
        type(value) is int or (name == "latency_milliseconds" and value is None)
    ):
        raise TargetHealthCaptureError("integer metadata requires native integers")
    if name in _BOOLEAN_FIELDS and type(value) is not bool:
        raise TargetHealthCaptureError("boolean metadata requires native booleans")


def _native_document(raw: Any) -> dict[str, Any]:
    """Charge every repeated subtree and escaped byte before replay or hashing."""

    remaining = MAX_DOCUMENT_BYTES
    nodes = 0

    def charge(size: int) -> None:
        nonlocal remaining
        remaining -= size
        if remaining < 0:
            raise TargetHealthCaptureError("metadata exceeds its document byte bound")

    def string(value: str) -> str:
        if len(value) > MAX_STRING_BYTES or len(value) > remaining:
            raise TargetHealthCaptureError("metadata string exceeds its byte bound")
        charge(2)
        for character in value:
            code = ord(character)
            if code < 32 or code > 126:
                raise TargetHealthCaptureError("metadata strings must be printable ASCII")
            charge(2 if character in {'"', "\\"} else 1)
        return value

    def visit(value: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > MAX_DOCUMENT_DEPTH or nodes > MAX_DOCUMENT_NODES:
            raise TargetHealthCaptureError("metadata exceeds its structure bound")
        if type(value) is dict:
            if len(value) > MAX_DOCUMENT_NODES:
                raise TargetHealthCaptureError("metadata exceeds its structure bound")
            if any(type(key) is not str for key in value):
                raise TargetHealthCaptureError("metadata requires native keys")
            charge(2 + len(value) + max(0, len(value) - 1))
            result = {}
            for key, item in value.items():
                string(key)
                _scalar(item, key)
                result[key] = visit(item, depth + 1)
            return result
        if type(value) is list:
            if len(value) > MAX_DOCUMENT_NODES:
                raise TargetHealthCaptureError("metadata exceeds its structure bound")
            charge(2 + max(0, len(value) - 1))
            return [visit(item, depth + 1) for item in value]
        if type(value) is str:
            return string(value)
        if type(value) is int:
            if not -MAX_SEQUENCE <= value <= MAX_SEQUENCE:
                raise TargetHealthCaptureError("metadata integer exceeds its local bound")
            charge(len(str(value)))
            return value
        if value is None or type(value) is bool:
            charge(4 if value is None or value is True else 5)
            return value
        raise TargetHealthCaptureError("metadata contains a non-native value")

    if type(raw) is not dict:
        raise TargetHealthCaptureError("metadata document must be a native object")
    return visit(raw, 0)


def _capture(value: Any, family: Any) -> Any:
    if type(value) is not family:
        raise TargetHealthCaptureError("metadata wrapper family is invalid")
    nodes = 0

    def check(item: Any, name: str, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_DOCUMENT_NODES or depth > MAX_DOCUMENT_DEPTH:
            raise TargetHealthCaptureError("metadata wrapper exceeds its structure bound")
        _scalar(item, name)
        selected = type(item)
        if selected in _WRAPPERS:
            for slot in fields(selected):
                try:
                    child = getattr(item, slot.name)
                except AttributeError as exc:
                    raise TargetHealthCaptureError("metadata wrapper is incomplete") from exc
                check(child, slot.name, depth + 1)
        elif selected is tuple:
            if len(item) > MAX_DOCUMENT_NODES:
                raise TargetHealthCaptureError("metadata tuple exceeds its structure bound")
            for child in item:
                check(child, "", depth + 1)
        elif selected is str:
            if len(item) > MAX_STRING_BYTES:
                raise TargetHealthCaptureError("metadata string exceeds its byte bound")
        elif selected is int:
            if not -MAX_SEQUENCE <= item <= MAX_SEQUENCE:
                raise TargetHealthCaptureError("metadata integer exceeds its local bound")
        elif item is not None and selected is not bool and selected not in _ENUMS:
            raise TargetHealthCaptureError("metadata wrapper contains a non-native value")

    check(value, "", 0)
    try:
        original = _native_document(value.to_dict())
        rebuilt = (
            parse_target_health_receipt(original)
            if family is TargetHealthReceipt
            else family.from_dict(original)
        )
        if canonical_json(rebuilt.to_dict()) != canonical_json(original):
            raise TargetHealthCaptureError("metadata wrapper does not reproduce its document")
        return rebuilt
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError) as exc:
        if isinstance(exc, TargetHealthCaptureError):
            raise
        raise TargetHealthCaptureError("metadata wrapper replay failed") from exc


def _parse_receipt(raw: bytes) -> TargetHealthReceipt:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, item in items:
            if key in result:
                raise TargetHealthCaptureError("receipt contains duplicate keys")
            result[key] = item
        return result

    def invalid_number(value: str) -> Any:
        raise TargetHealthCaptureError("receipt contains unsupported numbers")

    try:
        document = _native_document(
            json.loads(
                raw.decode("ascii"),
                object_pairs_hook=pairs,
                parse_float=invalid_number,
                parse_constant=invalid_number,
            )
        )
        if canonical_json(document).encode("ascii") != raw:
            raise TargetHealthCaptureError("receipt bytes are not canonical")
        receipt = _capture(parse_target_health_receipt(document), TargetHealthReceipt)
        if canonical_json(receipt.to_dict()).encode("ascii") != raw:
            raise TargetHealthCaptureError("receipt bytes do not replay exactly")
        return receipt
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, TargetHealthCaptureError):
            raise
        raise TargetHealthCaptureError("receipt replay failed") from exc


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _utc_datetime(value: Any) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC or value.microsecond:
        raise TargetHealthCaptureError("time must be a native whole-second UTC datetime")
    return value


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class _Halt(Exception):
    def __init__(self, reason: str) -> None:
        self.reason = reason


class _Capture:
    def __init__(self, **configuration: Any) -> None:
        self.__dict__.update(configuration)
        self.publications: list[TargetHealthCapturePublication] = []
        self.source_calls = self.source_bytes = self.context_calls = 0
        self.signing_calls = self.append_calls = 0
        self.stage = "context"
        self.previous_time: datetime | None = None
        self.boundary_sample: datetime | None = None
        self.uncertain: SignedTargetHealthCustodyEnvelopeV2 | None = None

    def boundary(self) -> datetime:
        self.boundary_sample = None
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise _Halt(
                exc.code if exc.code in {"canceled", "emergency_stop"} else "canceled"
            ) from exc
        try:
            now = self.clock()
        except Exception as exc:
            raise _Halt("clock_failed") from exc
        try:
            now = _utc_datetime(now)
        except TargetHealthCaptureError as exc:
            raise _Halt("clock_invalid") from exc
        if self.previous_time is None or now >= self.previous_time:
            self.boundary_sample = now
        try:
            self.stop_state.check()
        except AdapterStopRequested as exc:
            raise _Halt(
                exc.code if exc.code in {"canceled", "emergency_stop"} else "canceled"
            ) from exc
        if self.previous_time is not None and now < self.previous_time:
            raise _Halt("clock_regressed")
        self.previous_time = now
        if now >= self.deadline:
            raise _Halt("deadline_reached")
        try:
            verify_target_health_collector_policy(
                self.trust_root, self.policy, verified_at=_time(now), current=True
            )
        except ValueError as exc:
            raise _Halt("policy_not_current") from exc
        return now

    def context(self) -> TargetHealthSigningContext:
        self.stage = "context"
        before = self.boundary()
        self.context_calls += 1
        try:
            returned = self.custody.prepare_signing_context(
                tenant_id=self.policy.tenant_id,
                mission_id=self.policy.mission_id,
                collector_id=self.policy.collector_id,
                binding_sha256=self.policy.binding_sha256,
            )
        except Exception as exc:
            raise _Halt("context_failed") from exc
        try:
            context = _capture(returned, TargetHealthSigningContext)
        except TargetHealthCaptureError as exc:
            raise _Halt("context_invalid") from exc
        after = self.boundary()
        for name in (
            "tenant_id",
            "mission_id",
            "binding_sha256",
            "policy_id",
            "policy_sha256",
            "policy_revision",
            "collector_id",
            "collector_epoch",
            "chain_id",
        ):
            if getattr(context, name) != getattr(self.policy, name):
                raise _Halt("context_mismatch")
        if not before <= _instant(context.prepared_at) <= after:
            raise _Halt("context_time_invalid")
        if context.next_sequence == 1:
            expected_predecessor = (
                (None, None)
                if self.policy.collector_epoch == 1
                else (
                    self.policy.prior_epoch_head_envelope_id,
                    self.policy.prior_epoch_head_envelope_sha256,
                )
            )
            if (
                context.previous_envelope_id,
                context.previous_envelope_sha256,
            ) != expected_predecessor:
                raise _Halt("context_mismatch")
        if self.publications:
            confirmed = self.publications[-1].envelope
            if context.current_head_sequence < confirmed.sequence or (
                context.current_head_sequence == confirmed.sequence
                and (
                    context.current_head_envelope_id != confirmed.envelope_id
                    or context.current_head_envelope_sha256 != confirmed.envelope_sha256
                )
            ):
                raise _Halt("context_mismatch")
        return context

    def fresh_receipt(self, receipt: TargetHealthReceipt, now: datetime) -> None:
        try:
            observed = _instant(receipt.observed_at)
            if (
                not _instant(self.policy.effective_at)
                <= observed
                < _instant(self.policy.expires_at)
            ):
                raise TargetHealthCaptureError("receipt observation is outside policy validity")
            _verify_evidence_current(self.policy, receipt, _time(now))
        except ValueError as exc:
            raise _Halt("receipt_not_current") from exc

    def envelope(
        self, context: TargetHealthSigningContext, receipt: TargetHealthReceipt
    ) -> SignedTargetHealthCustodyEnvelopeV2:
        self.stage = "sign"
        arguments = {
            name: getattr(self.policy, name)
            for name in (
                "tenant_id",
                "mission_id",
                "binding",
                "binding_sha256",
                "runtime_policy_id",
                "runtime_policy_sha256",
                "policy_id",
                "policy_sha256",
                "policy_revision",
                "collector_id",
                "collector_epoch",
                "chain_id",
                "collector_key_id",
                "collector_public_key",
                "collector_public_key_sha256",
                "deployment_attestation_id",
                "deployment_attestation_sha256",
            )
        }
        # Nested values in this temporary signing object are also private copies.
        arguments["binding"] = ExecutionBinding(**self.policy.binding.to_dict())
        arguments.update(
            sequence=context.next_sequence,
            predecessor_envelope_id=context.previous_envelope_id,
            predecessor_envelope_sha256=context.previous_envelope_sha256,
            receipt=_capture(receipt, TargetHealthReceipt),
            receipt_id=receipt.receipt_id,
            receipt_sha256=receipt.receipt_sha256,
            observed_at=receipt.observed_at,
        )
        try:
            unsigned = _native_document(
                {
                    **arguments,
                    "binding": arguments["binding"].to_dict(),
                    "receipt": arguments["receipt"].to_dict(),
                    "signature_algorithm": SIGNATURE_ALGORITHM,
                    **_NO_EFFECTS,
                }
            )
            # Bound the combined existing signing shape before its constructor
            # derives identity; no caller callback has received it yet.
            _native_document(
                {
                    "domain": "sunderkey.target-health-custody-envelope-signature.v2",
                    "envelope": unsigned,
                }
            )
            placeholder = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
            candidate = SignedTargetHealthCustodyEnvelopeV2(
                **arguments, collector_signature=placeholder
            )
            _native_document(candidate.to_dict())
            if canonical_json(candidate.unsigned_body()) != canonical_json(unsigned):
                raise TargetHealthCaptureError(
                    "generated envelope does not replay its unsigned body"
                )
            payload = candidate.signing_bytes()
            if type(payload) is not bytes or len(payload) > MAX_DOCUMENT_BYTES:
                raise TargetHealthCaptureError("generated signing payload exceeds its byte bound")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            raise _Halt("envelope_invalid") from exc
        self.fresh_receipt(receipt, self.boundary())
        self.signing_calls += 1
        try:
            signature = self.signer.sign(payload)
        except Exception as exc:
            raise _Halt("signer_failed") from exc
        if type(signature) is not bytes or len(signature) != 64:
            raise _Halt("signature_invalid")
        signed = SignedTargetHealthCustodyEnvelopeV2(
            **arguments,
            collector_signature=base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        )
        now = self.boundary()
        self.fresh_receipt(receipt, now)
        try:
            # A new envelope is not yet a durable head. This checks only the
            # signature, current policy and exact existing V2 relations.
            _verify_envelope_common(
                self.trust_root, self.policy, signed, verified_at=_time(now), current=True
            )
        except ValueError as exc:
            raise _Halt("signature_invalid") from exc
        return _capture(signed, SignedTargetHealthCustodyEnvelopeV2)

    def verify_envelope(
        self, envelope: SignedTargetHealthCustodyEnvelopeV2, verified_at: str
    ) -> TargetHealthCustodyVerificationResult:
        return verify_target_health_custody_envelope_current(
            self.trust_root,
            self.policy,
            envelope,
            verified_at=verified_at,
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=envelope.envelope_id,
            expected_head_envelope_sha256=envelope.envelope_sha256,
            expected_head_sequence=envelope.sequence,
            policy_revocation=None,
        )

    def acknowledge(
        self,
        returned: Any,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        context: TargetHealthSigningContext,
        before: datetime,
    ) -> TargetHealthCapturePublication:
        if type(returned) is not TargetHealthAppendResult:
            raise TargetHealthCaptureError("append result family is invalid")
        try:
            raw_receipt, raw_event, replayed = returned.receipt, returned.event, returned.replayed
        except AttributeError as exc:
            raise TargetHealthCaptureError("append result is incomplete") from exc
        if type(replayed) is not bool:
            raise TargetHealthCaptureError("append replay flag requires a native boolean")
        if type(raw_receipt) is not TargetHealthCustodyReceipt:
            raise TargetHealthCaptureError("append receipt family is invalid")
        try:
            original_verification = _capture(
                raw_receipt.verification, TargetHealthCustodyVerificationResult
            )
        except AttributeError as exc:
            raise TargetHealthCaptureError("append verification is incomplete") from exc
        receipt = _capture(raw_receipt, TargetHealthCustodyReceipt)
        event = _capture(raw_event, TargetHealthCustodyEvent)
        verification = receipt.verification
        if canonical_json(original_verification.to_dict()) != canonical_json(
            verification.to_dict()
        ):
            raise TargetHealthCaptureError(
                "flattened append receipt hides its verification metadata"
            )
        lower = max(before, _instant(context.prepared_at))
        if _instant(verification.verified_at) < lower or _instant(receipt.recorded_at) < lower:
            raise TargetHealthCaptureError(
                "append acknowledgement predates its context or invocation"
            )
        expected = self.verify_envelope(envelope, verification.verified_at).to_dict()
        actual = verification.to_dict()
        # The context has no revocation body; custody owns that durable assertion.
        unavailable = {
            "policy_revocation_id",
            "policy_revocation_sha256",
            "verification_id",
            "verification_sha256",
        }
        if canonical_json(
            {key: value for key, value in expected.items() if key not in unavailable}
        ) != canonical_json(
            {key: value for key, value in actual.items() if key not in unavailable}
        ):
            raise TargetHealthCaptureError(
                "append verification does not match the attempted envelope"
            )
        joins = {
            "tenant_id": self.policy.tenant_id,
            "mission_id": self.policy.mission_id,
            "chain_id": self.policy.chain_id,
            "event_sequence": envelope.sequence,
            "custody_receipt_id": receipt.custody_receipt_id,
            "custody_receipt_sha256": receipt.custody_receipt_sha256,
            "envelope_id": envelope.envelope_id,
            "envelope_sha256": envelope.envelope_sha256,
            "recorded_at": receipt.recorded_at,
        }
        if any(getattr(event, key) != value for key, value in joins.items()):
            raise TargetHealthCaptureError("append event does not match its receipt and envelope")
        if self.publications:
            previous = self.publications[-1]
            if envelope.sequence == previous.envelope.sequence + 1 and (
                envelope.predecessor_envelope_id == previous.envelope.envelope_id
            ):
                if (
                    event.predecessor_event_id != previous.event.event_id
                    or event.predecessor_event_sha256 != previous.event.event_sha256
                ):
                    raise TargetHealthCaptureError(
                        "append event does not link the known previous event"
                    )
        return TargetHealthCapturePublication(
            envelope=_capture(envelope, SignedTargetHealthCustodyEnvelopeV2),
            receipt=receipt,
            event=event,
            replayed=replayed,
        )

    def post_append_boundary(
        self,
        publication: TargetHealthCapturePublication,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
    ) -> None:
        self.publications.append(publication)
        self.uncertain = None
        halted = None
        try:
            self.boundary()
        except _Halt as exc:
            halted = exc
        sample = self.boundary_sample
        if sample is not None and (
            _instant(publication.receipt.verification.verified_at) > sample
            or _instant(publication.receipt.recorded_at) > sample
        ):
            # Only this provisional acknowledgement contradicts an available
            # post-callback sample. The port may still have committed it.
            self.publications.pop()
            self.uncertain = envelope
            raise _Halt("append_result_invalid")
        if halted is not None:
            raise halted

    def run(self) -> TargetHealthCaptureResult:
        try:
            while self.source_calls < self.maximum_source_calls:
                if self.source_bytes >= self.maximum_total_bytes:
                    self.stage = "complete"
                    raise _Halt("total_byte_limit")
                context = self.context()
                self.stage = "source"
                self.boundary()
                maximum = min(
                    self.maximum_receipt_bytes, self.maximum_total_bytes - self.source_bytes
                )
                self.source_calls += 1
                try:
                    raw = self.source.read_receipt(maximum_bytes=maximum)
                except Exception as exc:
                    raise _Halt("source_failed") from exc
                if raw is not None:
                    if type(raw) is not bytes:
                        raise _Halt("source_invalid")
                    self.source_bytes += len(raw)
                    if len(raw) > self.maximum_receipt_bytes:
                        raise _Halt("receipt_byte_limit")
                    if self.source_bytes > self.maximum_total_bytes:
                        raise _Halt("total_byte_limit")
                self.boundary()
                if raw is None:
                    self.stage = "complete"
                    raise _Halt("source_exhausted")
                self.stage = "receipt"
                try:
                    receipt = _parse_receipt(raw)
                except TargetHealthCaptureError as exc:
                    raise _Halt("receipt_invalid") from exc
                if (
                    canonical_json(receipt.binding.to_dict())
                    != canonical_json(self.policy.binding.to_dict())
                    or receipt.binding_sha256 != self.policy.binding_sha256
                    or receipt.runtime_policy_id != self.policy.runtime_policy_id
                    or receipt.runtime_policy_sha256 != self.policy.runtime_policy_sha256
                ):
                    raise _Halt("receipt_mismatch")
                self.fresh_receipt(receipt, self.previous_time)
                refreshed = self.context()
                if canonical_json(
                    {key: value for key, value in context.to_dict().items() if key != "prepared_at"}
                ) != canonical_json(
                    {
                        key: value
                        for key, value in refreshed.to_dict().items()
                        if key != "prepared_at"
                    }
                ):
                    raise _Halt("context_mismatch")
                envelope = self.envelope(refreshed, receipt)
                self.stage = "append"
                before = self.boundary()
                self.fresh_receipt(receipt, before)
                delivered = _capture(envelope, SignedTargetHealthCustodyEnvelopeV2)
                self.uncertain = envelope
                self.append_calls += 1
                try:
                    returned = self.custody.append_envelope(delivered)
                except Exception as exc:
                    raise _Halt("append_failed") from exc
                try:
                    publication = self.acknowledge(returned, envelope, refreshed, before)
                except (ValueError, TypeError, AttributeError, KeyError) as exc:
                    raise _Halt("append_result_invalid") from exc
                self.post_append_boundary(publication, envelope)
            self.stage = "complete"
            raise _Halt("source_call_limit")
        except _Halt as halted:
            return TargetHealthCaptureResult(
                publications=tuple(self.publications),
                source_calls=self.source_calls,
                source_bytes=self.source_bytes,
                context_calls=self.context_calls,
                signing_calls=self.signing_calls,
                append_calls=self.append_calls,
                terminal_stage=self.stage,
                reason=halted.reason,
                uncertain_envelope=self.uncertain,
            )


def capture_target_health_receipts(
    *,
    trust_root: TargetHealthTrustRoot,
    policy: TargetHealthCollectorPolicyRevision,
    source: TargetHealthReceiptSource,
    signer: TargetHealthEnvelopeSigner,
    custody: TargetHealthCaptureCustody,
    stop_state: AdapterStopState,
    clock: Callable[[], datetime],
    maximum_source_calls: int,
    maximum_receipt_bytes: int,
    maximum_total_bytes: int,
    deadline: datetime,
) -> TargetHealthCaptureResult:
    """Capture finite supplied canonical receipts; never collect or control targets.

    Callback failures are sanitized progress results. An append attempt may have
    committed even when its acknowledgement fails. No retry or rollback is made.
    """

    for value, maximum in (
        (maximum_source_calls, MAX_SOURCE_CALLS),
        (maximum_receipt_bytes, MAX_DOCUMENT_BYTES),
        (maximum_total_bytes, MAX_TOTAL_BYTES),
    ):
        if type(value) is not int or not 1 <= value <= maximum:
            raise TargetHealthCaptureError(
                "capture limits require bounded native positive integers"
            )
    deadline = _utc_datetime(deadline)
    if type(stop_state) is not AdapterStopState or not callable(clock):
        raise TargetHealthCaptureError("stop state or clock configuration is invalid")
    try:
        stop_code = stop_state.code
    except (AttributeError, TypeError) as exc:
        raise TargetHealthCaptureError("stop state configuration is incomplete") from exc
    if stop_code is not None and (
        type(stop_code) is not str or stop_code not in {"canceled", "emergency_stop"}
    ):
        raise TargetHealthCaptureError("stop state configuration has an invalid code")
    owned_root = _capture(trust_root, TargetHealthTrustRoot)
    owned_policy = _capture(policy, TargetHealthCollectorPolicyRevision)
    try:
        verify_target_health_collector_policy(
            owned_root, owned_policy, verified_at=owned_policy.issued_at, current=False
        )
    except ValueError as exc:
        raise TargetHealthCaptureError(
            "collector policy does not verify against the supplied root"
        ) from exc
    return _Capture(
        trust_root=owned_root,
        policy=owned_policy,
        source=source,
        signer=signer,
        custody=custody,
        stop_state=stop_state,
        clock=clock,
        maximum_source_calls=maximum_source_calls,
        maximum_receipt_bytes=maximum_receipt_bytes,
        maximum_total_bytes=maximum_total_bytes,
        deadline=deadline,
    ).run()


__all__ = [
    "TargetHealthCaptureError",
    "TargetHealthReceiptSource",
    "TargetHealthEnvelopeSigner",
    "TargetHealthCaptureCustody",
    "TargetHealthCapturePublication",
    "TargetHealthCaptureResult",
    "capture_target_health_receipts",
]

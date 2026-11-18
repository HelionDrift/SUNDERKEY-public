"""Bounded reference audit append composed from the existing D012 custody ports."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime

from .candidate_enrollment_production_custody_contract import (
    ConditionalLedgerHeadProvider,
    LedgerHeadCompareAndSwapReceipt,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadReceipt,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutReceipt,
    LedgerObjectPutRequest,
    LedgerObjectReadReceipt,
    LedgerObjectReadRequest,
    ProviderPolicyRejection,
    ReleaseAuditAppendReceipt,
    ReleaseAuditAppendRequest,
    ReleaseAuditEventDescriptor,
    RetentionLockedLedgerObjectProvider,
    RetentionStateReadReceipt,
    RetentionStateReadRequest,
    provider_subject_sha256,
)
from .errors import QualificationError
from .qualification import _canonical_json, _canonical_sha256

ENVIRONMENT_CLASS = "reference_simulation_nonqualifying"
RECORD_DOMAIN = "sunderkey.custody-release-audit-chain-record.v1"
MAXIMUM_RECORD_BYTES = 16_384
MAXIMUM_CHAIN_EVENTS = 4096
_MAX_INTEGER = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_MISSING = object()


class CustodyAuditChainError(QualificationError):
    """Unverified source, exhausted bound or unsupported audit-chain material."""


class CustodyAuditChainConflict(CustodyAuditChainError):
    """A confirmed event collision or a different winner, not a transport failure."""


class CustodyAuditAppendUnconfirmed(CustodyAuditChainError):
    """A provider outcome is unconfirmed; no receipt, retry or rollback is implied."""


def _identifier(value, label):
    if type(value) is not str or len(value) > 256 or _ID.fullmatch(value) is None:
        raise CustodyAuditChainError(f"{label} must be an exact bounded identifier")


def _instant(value):
    if type(value) is not str or len(value) != 20 or _UTC.fullmatch(value) is None:
        raise CustodyAuditChainError("Protection and record times must be native whole-second UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CustodyAuditChainError("Audit time is invalid") from exc


def _digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


_FAMILIES = {
    ReleaseAuditEventDescriptor: {
        "event_id": str,
        "event_type": str,
        "artifact_sha256": str,
        "actor_identity_id": str,
        "occurred_at": str,
    },
    ReleaseAuditAppendRequest: {"request_id": str, "event": ReleaseAuditEventDescriptor},
    ReleaseAuditAppendReceipt: {
        "request_id": str,
        "event": ReleaseAuditEventDescriptor,
        "audit_sequence": int,
        "append_status": str,
    },
    LedgerObjectDescriptor: {
        "object_id": str,
        "sha256": str,
        "size_bytes": int,
        "retention_until": str,
        "namespace_id": str,
        "failure_domain_id": str,
    },
    LedgerObjectPutRequest: {
        "request_id": str,
        "object": LedgerObjectDescriptor,
        "payload": bytes,
    },
    LedgerObjectPutReceipt: {
        "request_id": str,
        "object": LedgerObjectDescriptor,
        "write_status": str,
        "retention_lock_verified": bool,
    },
    LedgerObjectReadReceipt: {
        "request_id": str,
        "object": LedgerObjectDescriptor,
        "payload": bytes,
        "digest_verified": bool,
    },
    LedgerObjectReadRequest: {
        "request_id": str,
        "object_id": str,
        "expected_sha256": str,
    },
    RetentionStateReadRequest: {
        "request_id": str,
        "object_id": str,
        "required_retention_until": str,
    },
    RetentionStateReadReceipt: {
        "request_id": str,
        "object": LedgerObjectDescriptor,
        "retention_lock_verified": bool,
        "deletion_protection_verified": bool,
    },
    LedgerHeadDescriptor: {
        "deployment_id": str,
        "ledger_sequence": int,
        "entry_id": str,
        "entry_sha256": str,
        "previous_head_sha256": (str, type(None)),
    },
    LedgerHeadReadReceipt: {"request_id": str, "head": (LedgerHeadDescriptor, type(None))},
    LedgerHeadReadRequest: {"request_id": str, "deployment_id": str},
    LedgerHeadCompareAndSwapRequest: {
        "request_id": str,
        "expected_head_sha256": (str, type(None)),
        "proposed_head": LedgerHeadDescriptor,
    },
    LedgerHeadCompareAndSwapReceipt: {
        "request_id": str,
        "head": LedgerHeadDescriptor,
        "compare_and_swap_status": str,
    },
}
_REQUEST_FAMILIES = frozenset(
    {
        LedgerObjectPutRequest,
        LedgerObjectReadRequest,
        RetentionStateReadRequest,
        LedgerHeadReadRequest,
        LedgerHeadCompareAndSwapRequest,
    }
)


def _capture(value, family):
    if type(value) is not family or family not in _FAMILIES:
        raise CustodyAuditChainError("An exact D012 typed family is required")
    captured = {}
    for key, expected in _FAMILIES[family].items():
        item = getattr(value, key, _MISSING)
        choices = expected if type(expected) is tuple else (expected,)
        if type(item) not in choices:
            raise CustodyAuditChainError("D012 field types must be exact before reconstruction")
        if type(item) is str:
            if len(item) > 256 or not item.isascii() or any(not 32 <= ord(c) <= 126 for c in item):
                raise CustodyAuditChainError("D012 strings must be bounded printable ASCII")
        elif type(item) is int:
            if not 0 <= item <= _MAX_INTEGER:
                raise CustodyAuditChainError("D012 counters exceed the supported native bound")
        elif type(item) is bytes:
            if len(item) > MAXIMUM_RECORD_BYTES:
                raise CustodyAuditChainError("Audit payload exceeds its pre-hash bound")
        elif type(item) in _FAMILIES:
            item = _capture(item, type(item))
        captured[key] = item
    try:
        return family(**captured)
    except (TypeError, ValueError) as exc:
        raise CustodyAuditChainError("D012 value fails semantic reconstruction") from exc


def _from_dict(raw, family):
    if (
        type(raw) is not dict
        or len(raw) != len(_FAMILIES[family])
        or any(type(key) is not str for key in raw)
        or set(raw) != set(_FAMILIES[family])
    ):
        raise CustodyAuditChainError("Stored D012 fields must be exact")
    try:
        return _capture(family(**raw), family)
    except (TypeError, ValueError) as exc:
        raise CustodyAuditChainError("Stored D012 value does not reconstruct") from exc


def _head_digest(head):
    return _canonical_sha256(asdict(_capture(head, LedgerHeadDescriptor)))


def _load_json(payload):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise CustodyAuditChainError("Duplicate audit record keys are unsupported")
            result[key] = value
        return result

    def invalid_number(_):
        raise CustodyAuditChainError("Audit records require native bounded integers")

    def integer(text):
        if len(text) > 19:
            invalid_number(text)
        value = int(text)
        if not 0 <= value <= _MAX_INTEGER:
            invalid_number(text)
        return value

    try:
        return json.loads(
            payload.decode("ascii"),
            object_pairs_hook=pairs,
            parse_float=invalid_number,
            parse_constant=invalid_number,
            parse_int=integer,
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CustodyAuditChainError("Stored audit bytes are not strict bounded JSON") from exc


@dataclass(frozen=True)
class _Configuration:
    namespace_id: str
    failure_domain_id: str
    deployment_id: str
    retention_until: str
    maximum_traversal_records: int
    maximum_provider_calls: int
    maximum_read_bytes: int
    maximum_object_bytes: int

    def __post_init__(self):
        for field in ("namespace_id", "failure_domain_id", "deployment_id"):
            _identifier(getattr(self, field), field)
        _instant(self.retention_until)
        for field, maximum in (
            ("maximum_traversal_records", 2 * MAXIMUM_CHAIN_EVENTS + 1),
            ("maximum_provider_calls", 4 * MAXIMUM_CHAIN_EVENTS + 16),
            ("maximum_read_bytes", (2 * MAXIMUM_CHAIN_EVENTS + 1) * MAXIMUM_RECORD_BYTES),
            ("maximum_object_bytes", MAXIMUM_RECORD_BYTES),
        ):
            value = getattr(self, field)
            if type(value) is not int or not 1 <= value <= maximum:
                raise CustodyAuditChainError(f"{field} must be an explicit bounded native integer")


class _Budget:
    def __init__(self, owner, configuration):
        self.owner, self.configuration = owner, configuration
        self.calls = self.records = self.bytes = 0
        self.last_time = None

    def now(self):
        try:
            at = self.owner._clock()
        except Exception as exc:
            raise CustodyAuditChainError("The explicit audit clock failed") from exc
        if type(at) is not datetime or at.tzinfo is None or at.utcoffset() is None:
            raise CustodyAuditChainError("The clock must return an exact aware datetime")
        at = at.astimezone(UTC)
        if at >= _instant(self.configuration.retention_until):
            raise CustodyAuditChainError("The declared audit protection horizon has expired")
        if self.last_time is not None and at < self.last_time:
            raise CustodyAuditChainError("The operation clock moved backwards")
        self.last_time = at
        self.owner._verify_ports()
        return at

    def reserve(self, *, calls=0, records=0, read_bytes=0):
        config = self.configuration
        if (
            self.calls + calls > config.maximum_provider_calls
            or self.records + records > config.maximum_traversal_records
            or self.bytes + read_bytes > config.maximum_read_bytes
        ):
            raise CustodyAuditChainError("The explicit audit traversal or call budget is exhausted")

    def call(self, method, request):
        family = type(request)
        if family not in _REQUEST_FAMILIES:
            raise CustodyAuditChainError("An exact supported custody request is required")
        expected = _capture(request, family)
        dispatched = _capture(expected, family)

        def unchanged():
            if _capture(request, family) != expected or _capture(dispatched, family) != expected:
                raise CustodyAuditAppendUnconfirmed("The captured custody request changed")

        def settled():
            unchanged()
            self.now()
            unchanged()

        self.now()
        unchanged()
        self.reserve(calls=1)
        self.calls += 1
        try:
            result = method(dispatched)
        except ProviderPolicyRejection:
            settled()
            raise
        except Exception as exc:
            settled()
            raise CustodyAuditAppendUnconfirmed(
                "The custody provider outcome is unconfirmed"
            ) from exc
        settled()
        return result


@dataclass(frozen=True)
class _Snapshot:
    head: LedgerHeadDescriptor | None
    events: dict
    heads: dict
    payload_bytes: int


class CustodyReleaseAuditChain:
    """Reference-only append adapter; explicit injected ports own storage guarantees."""

    environment_class = ENVIRONMENT_CLASS

    def __init__(
        self,
        *,
        ledger_objects,
        ledger_heads,
        namespace_id,
        failure_domain_id,
        deployment_id,
        retention_until,
        clock,
        maximum_traversal_records,
        maximum_provider_calls,
        maximum_read_bytes,
        maximum_object_bytes,
    ):
        self._configuration = _Configuration(
            namespace_id,
            failure_domain_id,
            deployment_id,
            retention_until,
            maximum_traversal_records,
            maximum_provider_calls,
            maximum_read_bytes,
            maximum_object_bytes,
        )
        self._configuration_sha256 = _canonical_sha256(asdict(self._configuration))
        if not callable(clock):
            raise CustodyAuditChainError("An explicit aware clock is required")
        self._clock, self._ledger, self._heads = clock, ledger_objects, ledger_heads
        self._highest_head = None
        self._lock = threading.Lock()
        self._verify_ports()

    def _verify_ports(self):
        for value, protocol in (
            (self._ledger, RetentionLockedLedgerObjectProvider),
            (self._heads, ConditionalLedgerHeadProvider),
        ):
            environment = getattr(value, "environment_class", None)
            if (
                type(environment) is not str
                or environment != ENVIRONMENT_CLASS
                or not isinstance(value, protocol)
            ):
                raise CustodyAuditChainError(
                    "Explicit complete reference custody ports are required"
                )

    @staticmethod
    def _request_id(request, operation, index=0):
        digest = _canonical_sha256(
            {
                "request_id": request.request_id,
                "operation": operation,
                "index": index,
            }
        )
        return "audit." + digest[7:39]

    def _head(self, request, budget, operation):
        query = LedgerHeadReadRequest(
            self._request_id(request, operation), budget.configuration.deployment_id
        )
        query_request_id = query.request_id
        receipt = _capture(budget.call(self._heads.read_head, query), LedgerHeadReadReceipt)
        if receipt.request_id != query_request_id:
            raise CustodyAuditChainError("Head receipt substitutes the exact read request")
        head = receipt.head
        if head is not None and (
            head.deployment_id != budget.configuration.deployment_id
            or head.ledger_sequence > MAXIMUM_CHAIN_EVENTS
        ):
            raise CustodyAuditChainError("Head substitutes the dedicated bounded audit chain")
        return head

    def _descriptor(self, descriptor, head, budget):
        config = budget.configuration
        if (
            descriptor.object_id != "audit." + descriptor.sha256[7:]
            or descriptor.object_id != head.entry_id
            or descriptor.sha256 != head.entry_sha256
            or not 1 <= descriptor.size_bytes <= config.maximum_object_bytes
            or descriptor.namespace_id != config.namespace_id
            or descriptor.failure_domain_id != config.failure_domain_id
            or descriptor.retention_until != config.retention_until
        ):
            raise CustodyAuditChainError(
                "Audit object differs from the dedicated protected mapping"
            )

    def _record(self, payload, head, budget):
        raw = _load_json(payload)
        keys = {
            "schema_version",
            "kind",
            "deployment_id",
            "namespace_id",
            "failure_domain_id",
            "retention_until",
            "audit_sequence",
            "recorded_at",
            "event",
            "previous_head",
        }
        if type(raw) is not dict or set(raw) != keys:
            raise CustodyAuditChainError("Audit record requires exact closed fields")
        config = budget.configuration
        if (
            type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["kind"] != RECORD_DOMAIN
            or raw["deployment_id"] != config.deployment_id
            or raw["namespace_id"] != config.namespace_id
            or raw["failure_domain_id"] != config.failure_domain_id
            or raw["retention_until"] != config.retention_until
            or type(raw["audit_sequence"]) is not int
            or raw["audit_sequence"] != head.ledger_sequence
        ):
            raise CustodyAuditChainError("Audit record substitutes its declared chain or sequence")
        event = _from_dict(raw["event"], ReleaseAuditEventDescriptor)
        recorded = _instant(raw["recorded_at"])
        if not _instant(event.occurred_at) <= recorded <= budget.now():
            raise CustodyAuditChainError("Audit record chronology is not current")
        previous = raw["previous_head"]
        previous = None if previous is None else _from_dict(previous, LedgerHeadDescriptor)
        if previous is None:
            if head.ledger_sequence != 1 or head.previous_head_sha256 is not None:
                raise CustodyAuditChainError("Audit chain omits its required predecessor")
        elif (
            previous.deployment_id != config.deployment_id
            or previous.ledger_sequence != head.ledger_sequence - 1
            or head.previous_head_sha256 != _head_digest(previous)
        ):
            raise CustodyAuditChainError("Audit chain predecessor does not reproduce")
        if _canonical_json(raw).encode("ascii") != payload:
            raise CustodyAuditChainError("Stored audit bytes are not canonical")
        return event, previous, recorded

    def _read_record(self, request, head, budget, phase):
        config = budget.configuration
        query = LedgerObjectReadRequest(
            self._request_id(request, phase + ".object", head.ledger_sequence),
            head.entry_id,
            head.entry_sha256,
        )
        query_request_id, object_id, expected_sha256 = (
            query.request_id,
            query.object_id,
            query.expected_sha256,
        )
        receipt = _capture(budget.call(self._ledger.read_verified, query), LedgerObjectReadReceipt)
        if (
            receipt.request_id != query_request_id
            or receipt.object.object_id != object_id
            or receipt.object.sha256 != expected_sha256
            or len(receipt.payload) != receipt.object.size_bytes
        ):
            raise CustodyAuditChainError("Audit read does not bind the exact requested object")
        self._descriptor(receipt.object, head, budget)
        budget.reserve(read_bytes=len(receipt.payload))
        budget.bytes += len(receipt.payload)
        retention = RetentionStateReadRequest(
            self._request_id(request, phase + ".retention", head.ledger_sequence),
            head.entry_id,
            config.retention_until,
        )
        retention_request_id = retention.request_id
        protected = _capture(
            budget.call(self._ledger.read_retention_state, retention), RetentionStateReadReceipt
        )
        if protected.request_id != retention_request_id or protected.object != receipt.object:
            raise CustodyAuditChainError("Live audit protection differs from the consumed object")
        event, previous, recorded = self._record(receipt.payload, head, budget)
        return event, previous, recorded, len(receipt.payload)

    def _snapshot(self, request, budget, phase):
        initial = self._head(request, budget, phase + ".head")
        length = 0 if initial is None else initial.ledger_sequence
        budget.reserve(calls=2 * length + 1, records=length)
        events, heads, total_bytes = {}, {}, 0
        current, successor_time = initial, None
        while current is not None:
            budget.records += 1
            event, previous, recorded, size = self._read_record(request, current, budget, phase)
            if event.event_id in events:
                raise CustodyAuditChainError("Audit chain repeats an already allocated event ID")
            if successor_time is not None and recorded > successor_time:
                raise CustodyAuditChainError("Audit predecessor chronology runs backwards")
            events[event.event_id] = (event, current.ledger_sequence)
            heads[current.ledger_sequence] = current
            total_bytes += size
            current, successor_time = previous, recorded
        final = self._head(request, budget, phase + ".fence")
        if final != initial:
            raise CustodyAuditChainError("The current audit head changed during reconstruction")
        highest = self._highest_head
        if highest is not None and heads.get(highest.ledger_sequence) != highest:
            raise CustodyAuditChainError(
                "The current audit view rolls back or forks observed history"
            )
        self._highest_head = initial
        budget.now()
        return _Snapshot(initial, events, heads, total_bytes)

    @staticmethod
    def _existing(request, snapshot):
        existing = snapshot.events.get(request.event.event_id)
        if existing is None:
            return None
        if existing[0] != request.event:
            raise CustodyAuditChainConflict("The original audit event ID has different content")
        return existing[1]

    @staticmethod
    def _receipt(request, sequence, status, budget):
        budget.now()
        return _capture(
            ReleaseAuditAppendReceipt(request.request_id, request.event, sequence, status),
            ReleaseAuditAppendReceipt,
        )

    def append_audit_event(self, request):
        """Allocate only through confirmed logical-head custody, never an orphan upload."""
        request = _capture(request, ReleaseAuditAppendRequest)
        with self._lock:
            config = getattr(self, "_configuration", _MISSING)
            if type(config) is not _Configuration:
                raise CustodyAuditChainError("The captured audit configuration is invalid")
            config = _Configuration(
                **{field.name: getattr(config, field.name, _MISSING) for field in fields(config)}
            )
            captured_digest = getattr(self, "_configuration_sha256", _MISSING)
            if (
                type(captured_digest) is not str
                or len(captured_digest) != 71
                or _canonical_sha256(asdict(config)) != captured_digest
            ):
                raise CustodyAuditChainError("The original audit configuration changed")
            budget = _Budget(self, config)
            if _instant(request.event.occurred_at) > budget.now():
                raise CustodyAuditChainError("The audit event is from the future")
            before = self._snapshot(request, budget, "before")
            existing = self._existing(request, before)
            if existing is not None:
                return self._receipt(request, existing, "already_appended_same_digest", budget)
            sequence = 1 if before.head is None else before.head.ledger_sequence + 1
            if sequence > MAXIMUM_CHAIN_EVENTS:
                raise CustodyAuditChainError("The bounded audit chain is at capacity")
            at = budget.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            raw = {
                "schema_version": 1,
                "kind": RECORD_DOMAIN,
                "deployment_id": config.deployment_id,
                "namespace_id": config.namespace_id,
                "failure_domain_id": config.failure_domain_id,
                "retention_until": config.retention_until,
                "audit_sequence": sequence,
                "recorded_at": at,
                "event": asdict(request.event),
                "previous_head": None if before.head is None else asdict(before.head),
            }
            payload = _canonical_json(raw).encode("ascii")
            if len(payload) > config.maximum_object_bytes:
                raise CustodyAuditChainError("The new audit record exceeds its explicit byte bound")
            # Reserve known settlement work before the first write. Concurrent growth
            # may still exhaust a bound and is never a reason to report acceptance.
            budget.reserve(
                calls=2 * sequence + 6,
                records=sequence,
                read_bytes=before.payload_bytes + 2 * len(payload),
            )
            digest = _digest(payload)
            descriptor = LedgerObjectDescriptor(
                "audit." + digest[7:],
                digest,
                len(payload),
                config.retention_until,
                config.namespace_id,
                config.failure_domain_id,
            )
            put = LedgerObjectPutRequest(self._request_id(request, "put"), descriptor, payload)
            put_request_id = put.request_id
            written = _capture(budget.call(self._ledger.put_if_absent, put), LedgerObjectPutReceipt)
            if written.request_id != put_request_id or written.object != descriptor:
                raise CustodyAuditChainError("Audit upload acknowledgement substitutes its object")
            proposed = LedgerHeadDescriptor(
                config.deployment_id,
                sequence,
                descriptor.object_id,
                descriptor.sha256,
                None if before.head is None else _head_digest(before.head),
            )
            self._read_record(request, proposed, budget, "prepared")
            cas = LedgerHeadCompareAndSwapRequest(
                self._request_id(request, "cas"), proposed.previous_head_sha256, proposed
            )
            cas_request_id = cas.request_id
            cas_subject_sha256 = provider_subject_sha256(proposed)
            try:
                advanced = _capture(
                    budget.call(self._heads.compare_and_swap_head, cas),
                    LedgerHeadCompareAndSwapReceipt,
                )
            except ProviderPolicyRejection as exc:
                if (
                    type(exc) is not ProviderPolicyRejection
                    or type(getattr(exc, "rejection_code", _MISSING)) is not str
                    or exc.rejection_code != "ledger_head_conflict"
                    or type(getattr(exc, "request_id", _MISSING)) is not str
                    or exc.request_id != cas_request_id
                    or type(getattr(exc, "subject_sha256", _MISSING)) is not str
                    or exc.subject_sha256 != cas_subject_sha256
                ):
                    raise CustodyAuditAppendUnconfirmed(
                        "CAS denial is not an exact bound conflict"
                    ) from exc
                after = self._snapshot(request, budget, "conflict")
                existing = self._existing(request, after)
                if existing is None:
                    raise CustodyAuditChainConflict(
                        "Another audit append won; uploaded bytes are orphaned"
                    )
                return self._receipt(request, existing, "already_appended_same_digest", budget)
            if advanced.request_id != cas_request_id or advanced.head != proposed:
                raise CustodyAuditChainError(
                    "Audit CAS acknowledgement substitutes its logical head"
                )
            after = self._snapshot(request, budget, "after")
            if self._existing(request, after) != sequence or after.heads.get(sequence) != proposed:
                raise CustodyAuditAppendUnconfirmed(
                    "Acknowledged audit event is not in the current chain"
                )
            status = (
                "appended"
                if advanced.compare_and_swap_status == "advanced"
                else "already_appended_same_digest"
            )
            return self._receipt(request, sequence, status, budget)

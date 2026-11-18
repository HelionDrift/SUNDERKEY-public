"""Immutable target-health gate use custody for action boundaries.

The records in this module preserve which exact live gate decision was used by
one action consumer. Historical verification reconstructs stored documents and
lineage. It never treats an old decision as proof of current target health.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar

from .action_admission_contracts import (
    ActionAdmissionRequest,
    ContextBinding,
    CredentialLease,
    TargetBinding,
    WorkerSession,
)
from .action_resolution import parse_target_action_descriptor
from .target_health_gate_contracts import (
    TargetHealthGateDecision,
    TargetHealthGateDecisionStatus,
    TargetHealthGateHead,
    TargetHealthGateState,
    TargetHealthGateTransition,
    build_target_health_execution_binding,
    execution_binding_sha256,
)

SCHEMA_VERSION = 1
STORE_SCHEMA_VERSION = 36
EXECUTION_STORE_SCHEMA_VERSION = 37
HASH_PREFIX = "sha256:"
LEGACY_BASELINE_STATUS = "historical_records_not_health_gated"
EXECUTION_LEGACY_BASELINE_STATUS = (
    "historical_execution_records_not_health_gated"
)

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)
_NO_EFFECTS = {
    "authority_effect": "none",
    "budget_effect": "none",
    "credential_effect": "none",
    "dispatch_effect": "none",
    "network_call_performed": False,
    "qualification_effect": "none",
    "scope_effect": "none",
    "target_effect_performed": False,
    "tier_effect": "none",
}


class ActionTargetHealthGateUseError(ValueError):
    """Raised when target-health gate use custody is not exact."""


class ActionTargetHealthGateUseKind(StrEnum):
    """All action boundaries that may consume one fresh gate decision."""

    ACTION_AUTHORITY_PUBLICATION = "action_authority_publication"
    ACTION_AUTHORITY_PUBLICATION_REPLAY_FOR_USE = (
        "action_authority_publication_replay_for_use"
    )
    ACTION_ADMISSION = "action_admission"
    ACTION_ADMISSION_REPLAY_FOR_USE = "action_admission_replay_for_use"
    ACTION_ADMISSION_CURRENT_VERIFICATION = (
        "action_admission_current_verification"
    )
    ACTION_EXECUTION_CLAIM = "action_execution_claim"
    ACTION_EXECUTION_DISPATCH = "action_execution_dispatch"
    ACTION_EXECUTION_INVOCATION = "action_execution_invocation"
    ACTION_EXECUTION_TERMINAL_REPLAY_FOR_USE = (
        "action_execution_terminal_replay_for_use"
    )


NONREPEATABLE_USE_KINDS = frozenset(
    {
        ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION,
        ActionTargetHealthGateUseKind.ACTION_ADMISSION,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION,
    }
)
SCHEMA36_RESERVED_USE_KINDS = frozenset(
    {ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION}
)


class LegacyActionRecordKind(StrEnum):
    ACTION_AUTHORITY_PUBLICATION = "action_authority_publication"
    ACTION_ADMISSION_RECEIPT = "action_admission_receipt"
    ACTION_EXECUTION_REQUEST = "action_execution_request"


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ActionTargetHealthGateUseError(
            "value cannot be canonicalized"
        ) from exc


def canonical_sha256(value: Any) -> str:
    return HASH_PREFIX + hashlib.sha256(
        canonical_json(value).encode("ascii")
    ).hexdigest()


def _identity(prefix: str, kind: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = canonical_sha256({"body": dict(body), "kind": kind})
    return f"{prefix}-{digest[7:39].upper()}", digest


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise ActionTargetHealthGateUseError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ActionTargetHealthGateUseError(
            f"{label} must be a SHA-256 content address"
        )
    return value


def _utc(value: Any, label: str) -> str:
    if not isinstance(value, str) or _UTC_RE.fullmatch(value) is None:
        raise ActionTargetHealthGateUseError(f"{label} must be canonical UTC")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise ActionTargetHealthGateUseError(f"{label} is invalid") from exc
    return value


def _instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ActionTargetHealthGateUseError(f"{label} fields are invalid")
    return dict(value)


def _no_effects(
    value: Mapping[str, Any],
    *,
    sqlite_row: bool = False,
) -> None:
    for field, expected in _NO_EFFECTS.items():
        actual = value.get(field)
        if isinstance(expected, bool):
            valid = actual == 0 if sqlite_row else actual is expected
        else:
            valid = actual == expected
        if not valid:
            raise ActionTargetHealthGateUseError(
                "target-health custody attempts effect escalation"
            )


@dataclass(frozen=True, slots=True)
class ActionTargetHealthGateUse:
    """One positive use of one exact, freshly produced health decision."""

    use_kind: ActionTargetHealthGateUseKind
    tenant_id: str
    mission_id: str
    consumer_id: str
    consumer_sha256: str
    binding_sha256: str
    decision: TargetHealthGateDecision
    transition: TargetHealthGateTransition
    head: TargetHealthGateHead
    used_at: str
    use_id: str = ""
    use_sha256: str = ""

    KIND: ClassVar[str] = "sunderkey.action-target-health-gate-use.v1"
    PREFIX: ClassVar[str] = "ATHU"

    def __post_init__(self) -> None:
        try:
            use_kind = ActionTargetHealthGateUseKind(self.use_kind)
        except (TypeError, ValueError) as exc:
            raise ActionTargetHealthGateUseError("use_kind is invalid") from exc
        object.__setattr__(self, "use_kind", use_kind)
        _identifier(self.tenant_id, "tenant_id")
        _identifier(self.mission_id, "mission_id")
        _identifier(self.consumer_id, "consumer_id")
        _digest(self.consumer_sha256, "consumer_sha256")
        _digest(self.binding_sha256, "binding_sha256")
        if not isinstance(self.decision, TargetHealthGateDecision):
            raise ActionTargetHealthGateUseError("decision is invalid")
        if not isinstance(self.transition, TargetHealthGateTransition):
            raise ActionTargetHealthGateUseError("transition is invalid")
        if not isinstance(self.head, TargetHealthGateHead):
            raise ActionTargetHealthGateUseError("head snapshot is invalid")
        decision = self.decision
        observation = decision.current_observation
        if observation.inspection.inspection_context_sha256 is None:
            raise ActionTargetHealthGateUseError(
                "legacy contextless inspection cannot authorize a use"
            )
        subject = decision.subject
        if decision.status is not (
            TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
        ):
            raise ActionTargetHealthGateUseError(
                "only a positive health decision may be consumed"
            )
        if (
            subject.tenant_id != self.tenant_id
            or subject.mission_id != self.mission_id
            or not hmac.compare_digest(decision.binding_sha256, self.binding_sha256)
        ):
            raise ActionTargetHealthGateUseError(
                "decision crosses the consumer boundary"
            )
        if (
            self.head != decision.head
            or self.head.latch_state is not TargetHealthGateState.ACTIVE
            or self.transition.subject != subject
            or self.transition.to_state is not TargetHealthGateState.ACTIVE
            or self.transition.observation_id != observation.observation_id
            or not hmac.compare_digest(
                self.transition.observation_sha256 or "",
                observation.observation_sha256,
            )
            or not hmac.compare_digest(
                self.head.transition_head_sha256,
                self.transition.transition_sha256,
            )
            or self.head.last_observation_id != observation.observation_id
            or not hmac.compare_digest(
                self.head.last_observation_sha256,
                observation.observation_sha256,
            )
        ):
            raise ActionTargetHealthGateUseError(
                "decision lineage does not bind one active head snapshot"
            )
        _utc(self.used_at, "used_at")
        if self.used_at != decision.evaluated_at:
            raise ActionTargetHealthGateUseError(
                "use time does not match its live decision"
            )
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.use_id and not hmac.compare_digest(self.use_id, identifier):
            raise ActionTargetHealthGateUseError("use_id does not match content")
        if self.use_sha256 and not hmac.compare_digest(self.use_sha256, digest):
            raise ActionTargetHealthGateUseError(
                "use_sha256 does not match content"
            )
        object.__setattr__(self, "use_id", identifier)
        object.__setattr__(self, "use_sha256", digest)

    def body(self) -> dict[str, Any]:
        observation = self.decision.current_observation
        return {
            "binding_sha256": self.binding_sha256,
            "consumer_id": self.consumer_id,
            "consumer_sha256": self.consumer_sha256,
            "decision": self.decision.to_dict(),
            "head": self.head.to_dict(),
            "mission_id": self.mission_id,
            "observation_id": observation.observation_id,
            "observation_sha256": observation.observation_sha256,
            "tenant_id": self.tenant_id,
            "transition": self.transition.to_dict(),
            "use_kind": self.use_kind.value,
            "used_at": self.used_at,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
            "use_id": self.use_id,
            "use_sha256": self.use_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ActionTargetHealthGateUse:
        fields = set(cls.__dataclass_fields__) - {"KIND", "PREFIX"}
        data = _exact(
            value,
            fields
            | {
                "kind",
                "schema_version",
                "observation_id",
                "observation_sha256",
                *_NO_EFFECTS,
            },
            "target-health gate use",
        )
        if data["kind"] != cls.KIND or data["schema_version"] != SCHEMA_VERSION:
            raise ActionTargetHealthGateUseError("use metadata is invalid")
        _no_effects(data)
        decision = TargetHealthGateDecision.from_dict(data["decision"])
        if (
            data["observation_id"] != decision.current_observation.observation_id
            or data["observation_sha256"]
            != decision.current_observation.observation_sha256
        ):
            raise ActionTargetHealthGateUseError(
                "use observation lineage is invalid"
            )
        return cls(
            use_kind=data["use_kind"],
            tenant_id=data["tenant_id"],
            mission_id=data["mission_id"],
            consumer_id=data["consumer_id"],
            consumer_sha256=data["consumer_sha256"],
            binding_sha256=data["binding_sha256"],
            decision=decision,
            transition=TargetHealthGateTransition.from_dict(data["transition"]),
            head=TargetHealthGateHead.from_dict(data["head"]),
            used_at=data["used_at"],
            use_id=data["use_id"],
            use_sha256=data["use_sha256"],
        )


@dataclass(frozen=True, slots=True)
class LegacyActionRecordReference:
    """One pre-schema 36 record that carries no health permit."""

    record_kind: LegacyActionRecordKind
    mission_id: str
    record_id: str
    record_sha256: str

    def __post_init__(self) -> None:
        try:
            kind = LegacyActionRecordKind(self.record_kind)
        except (TypeError, ValueError) as exc:
            raise ActionTargetHealthGateUseError(
                "legacy record kind is invalid"
            ) from exc
        object.__setattr__(self, "record_kind", kind)
        _identifier(self.mission_id, "legacy mission_id")
        _identifier(self.record_id, "legacy record_id")
        _digest(self.record_sha256, "legacy record_sha256")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "record_id": self.record_id,
            "record_kind": self.record_kind.value,
            "record_sha256": self.record_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> LegacyActionRecordReference:
        return cls(
            **_exact(
                value,
                {"mission_id", "record_id", "record_kind", "record_sha256"},
                "legacy action record",
            )
        )


@dataclass(frozen=True, slots=True)
class ActionTargetHealthGateLegacyBaseline:
    """Content-addressed cutover inventory without permit semantics."""

    store_id: str
    records: tuple[LegacyActionRecordReference, ...]
    baseline_id: str = ""
    baseline_sha256: str = ""

    KIND: ClassVar[str] = (
        "sunderkey.action-target-health-gate-legacy-baseline.v1"
    )
    PREFIX: ClassVar[str] = "ATHB"

    def __post_init__(self) -> None:
        _identifier(self.store_id, "store_id")
        if not isinstance(self.records, tuple) or not all(
            isinstance(item, LegacyActionRecordReference) for item in self.records
        ):
            raise ActionTargetHealthGateUseError("legacy records are invalid")
        expected = tuple(
            sorted(
                self.records,
                key=lambda item: (
                    item.record_kind.value,
                    item.mission_id,
                    item.record_id,
                    item.record_sha256,
                ),
            )
        )
        if self.records != expected or len(
            {(item.record_kind, item.record_id) for item in self.records}
        ) != len(self.records):
            raise ActionTargetHealthGateUseError(
                "legacy records must be unique and canonically ordered"
            )
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.baseline_id and not hmac.compare_digest(
            self.baseline_id, identifier
        ):
            raise ActionTargetHealthGateUseError(
                "baseline_id does not match content"
            )
        if self.baseline_sha256 and not hmac.compare_digest(
            self.baseline_sha256, digest
        ):
            raise ActionTargetHealthGateUseError(
                "baseline_sha256 does not match content"
            )
        object.__setattr__(self, "baseline_id", identifier)
        object.__setattr__(self, "baseline_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "cutover_schema_version": STORE_SCHEMA_VERSION,
            "health_gate_qualification": "not_established",
            "permit_effect": "none",
            "records": [item.to_dict() for item in self.records],
            "status": LEGACY_BASELINE_STATUS,
            "store_id": self.store_id,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "baseline_id": self.baseline_id,
            "baseline_sha256": self.baseline_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ActionTargetHealthGateLegacyBaseline:
        fields = {
            "authority_effect",
            "baseline_id",
            "baseline_sha256",
            "budget_effect",
            "credential_effect",
            "cutover_schema_version",
            "dispatch_effect",
            "health_gate_qualification",
            "kind",
            "network_call_performed",
            "permit_effect",
            "qualification_effect",
            "records",
            "schema_version",
            "scope_effect",
            "status",
            "store_id",
            "target_effect_performed",
            "tier_effect",
        }
        data = _exact(value, fields, "legacy baseline")
        if (
            data["kind"] != cls.KIND
            or data["schema_version"] != SCHEMA_VERSION
            or data["cutover_schema_version"] != STORE_SCHEMA_VERSION
            or data["status"] != LEGACY_BASELINE_STATUS
            or data["health_gate_qualification"] != "not_established"
            or data["permit_effect"] != "none"
        ):
            raise ActionTargetHealthGateUseError(
                "legacy baseline metadata is invalid"
            )
        _no_effects(data)
        raw_records = data["records"]
        if isinstance(raw_records, (str, bytes)) or not isinstance(
            raw_records, Sequence
        ):
            raise ActionTargetHealthGateUseError("legacy records are invalid")
        return cls(
            store_id=data["store_id"],
            records=tuple(
                LegacyActionRecordReference.from_dict(item)
                for item in raw_records
            ),
            baseline_id=data["baseline_id"],
            baseline_sha256=data["baseline_sha256"],
        )


@dataclass(frozen=True, slots=True)
class ActionTargetHealthGateUseVerificationReport:
    baseline_id: str
    legacy_record_count: int
    use_count: int
    execution_baseline_id: str
    legacy_execution_count: int


@dataclass(frozen=True, slots=True)
class LegacyExecutionHealthRecordReference:
    """Frozen pre-schema 37 execution coverage state."""

    mission_id: str
    request_id: str
    request_sha256: str
    claim_id: str
    claim_sha256: str
    claim_use_count: int
    dispatch_id: str | None
    dispatch_sha256: str | None
    dispatch_use_count: int
    coverage_status: str

    def __post_init__(self) -> None:
        _identifier(self.mission_id, "execution legacy mission_id")
        _identifier(self.request_id, "execution legacy request_id")
        _digest(self.request_sha256, "execution legacy request_sha256")
        _identifier(self.claim_id, "execution legacy claim_id")
        _digest(self.claim_sha256, "execution legacy claim_sha256")
        if (self.dispatch_id is None) != (self.dispatch_sha256 is None):
            raise ActionTargetHealthGateUseError(
                "execution legacy dispatch lineage is incomplete"
            )
        if self.dispatch_id is not None:
            _identifier(self.dispatch_id, "execution legacy dispatch_id")
            _digest(
                self.dispatch_sha256,
                "execution legacy dispatch_sha256",
            )
        if (
            type(self.claim_use_count) is not int
            or type(self.dispatch_use_count) is not int
            or self.claim_use_count not in {0, 1}
            or self.dispatch_use_count not in {0, 1}
        ):
            raise ActionTargetHealthGateUseError(
                "execution legacy use counts are invalid"
            )
        expected_dispatch_count = 1 if self.dispatch_id is not None else 0
        if self.coverage_status == "legacy_zero_coverage":
            valid = self.claim_use_count == 0 and self.dispatch_use_count == 0
        elif self.coverage_status == "precutover_complete_coverage":
            valid = (
                self.claim_use_count == 1
                and self.dispatch_use_count == expected_dispatch_count
            )
        else:
            valid = False
        if not valid:
            raise ActionTargetHealthGateUseError(
                "execution legacy coverage state is invalid"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_sha256": self.claim_sha256,
            "claim_use_count": self.claim_use_count,
            "coverage_status": self.coverage_status,
            "dispatch_id": self.dispatch_id,
            "dispatch_sha256": self.dispatch_sha256,
            "dispatch_use_count": self.dispatch_use_count,
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> LegacyExecutionHealthRecordReference:
        return cls(
            **_exact(
                value,
                {
                    "claim_id",
                    "claim_sha256",
                    "claim_use_count",
                    "coverage_status",
                    "dispatch_id",
                    "dispatch_sha256",
                    "dispatch_use_count",
                    "mission_id",
                    "request_id",
                    "request_sha256",
                },
                "execution legacy record",
            )
        )


@dataclass(frozen=True, slots=True)
class ActionExecutionTargetHealthGateLegacyBaseline:
    """Exact execution requests exempted at the schema 37 cutover."""

    store_id: str
    records: tuple[LegacyExecutionHealthRecordReference, ...]
    baseline_id: str = ""
    baseline_sha256: str = ""

    KIND: ClassVar[str] = (
        "sunderkey.action-execution-target-health-legacy-baseline.v1"
    )
    PREFIX: ClassVar[str] = "ATHX"

    def __post_init__(self) -> None:
        _identifier(self.store_id, "store_id")
        if not isinstance(self.records, tuple) or any(
            not isinstance(item, LegacyExecutionHealthRecordReference)
            for item in self.records
        ):
            raise ActionTargetHealthGateUseError(
                "execution legacy records are invalid"
            )
        expected = tuple(
            sorted(
                self.records,
                key=lambda item: (
                    item.mission_id,
                    item.request_id,
                    item.request_sha256,
                ),
            )
        )
        if self.records != expected or len(
            {(item.mission_id, item.request_id) for item in self.records}
        ) != len(self.records):
            raise ActionTargetHealthGateUseError(
                "execution legacy records must be unique and ordered"
            )
        identifier, digest = _identity(self.PREFIX, self.KIND, self.body())
        if self.baseline_id and not hmac.compare_digest(
            self.baseline_id,
            identifier,
        ):
            raise ActionTargetHealthGateUseError(
                "execution baseline_id does not match content"
            )
        if self.baseline_sha256 and not hmac.compare_digest(
            self.baseline_sha256,
            digest,
        ):
            raise ActionTargetHealthGateUseError(
                "execution baseline_sha256 does not match content"
            )
        object.__setattr__(self, "baseline_id", identifier)
        object.__setattr__(self, "baseline_sha256", digest)

    def body(self) -> dict[str, Any]:
        return {
            "cutover_schema_version": EXECUTION_STORE_SCHEMA_VERSION,
            "health_gate_qualification": "not_established",
            "permit_effect": "none",
            "records": [item.to_dict() for item in self.records],
            "status": EXECUTION_LEGACY_BASELINE_STATUS,
            "store_id": self.store_id,
            **_NO_EFFECTS,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.body(),
            "baseline_id": self.baseline_id,
            "baseline_sha256": self.baseline_sha256,
            "kind": self.KIND,
            "schema_version": SCHEMA_VERSION,
        }

    @classmethod
    def from_dict(
        cls,
        value: Any,
    ) -> ActionExecutionTargetHealthGateLegacyBaseline:
        fields = {
            "authority_effect",
            "baseline_id",
            "baseline_sha256",
            "budget_effect",
            "credential_effect",
            "cutover_schema_version",
            "dispatch_effect",
            "health_gate_qualification",
            "kind",
            "network_call_performed",
            "permit_effect",
            "qualification_effect",
            "records",
            "schema_version",
            "scope_effect",
            "status",
            "store_id",
            "target_effect_performed",
            "tier_effect",
        }
        data = _exact(value, fields, "execution legacy baseline")
        if (
            data["kind"] != cls.KIND
            or data["schema_version"] != SCHEMA_VERSION
            or data["cutover_schema_version"] != EXECUTION_STORE_SCHEMA_VERSION
            or data["status"] != EXECUTION_LEGACY_BASELINE_STATUS
            or data["health_gate_qualification"] != "not_established"
            or data["permit_effect"] != "none"
        ):
            raise ActionTargetHealthGateUseError(
                "execution legacy baseline metadata is invalid"
            )
        _no_effects(data)
        raw_records = data["records"]
        if isinstance(raw_records, (str, bytes)) or not isinstance(
            raw_records,
            Sequence,
        ):
            raise ActionTargetHealthGateUseError(
                "execution legacy records are invalid"
            )
        return cls(
            store_id=data["store_id"],
            records=tuple(
                LegacyExecutionHealthRecordReference.from_dict(item)
                for item in raw_records
            ),
            baseline_id=data["baseline_id"],
            baseline_sha256=data["baseline_sha256"],
        )


def _legacy_records(
    connection: sqlite3.Connection,
) -> tuple[LegacyActionRecordReference, ...]:
    specifications = (
        (
            LegacyActionRecordKind.ACTION_AUTHORITY_PUBLICATION,
            "action_authority_publications",
            "publication_id",
            "publication_sha256",
        ),
        (
            LegacyActionRecordKind.ACTION_ADMISSION_RECEIPT,
            "action_admission_receipts",
            "receipt_id",
            "receipt_sha256",
        ),
        (
            LegacyActionRecordKind.ACTION_EXECUTION_REQUEST,
            "action_execution_requests",
            "request_id",
            "request_sha256",
        ),
    )
    records: list[LegacyActionRecordReference] = []
    for kind, table, identifier, digest in specifications:
        rows = connection.execute(
            f"SELECT mission_id, {identifier}, {digest} "
            f"FROM {table} ORDER BY mission_id, {identifier}"
        ).fetchall()
        records.extend(
            LegacyActionRecordReference(
                record_kind=kind,
                mission_id=str(row[0]),
                record_id=str(row[1]),
                record_sha256=str(row[2]),
            )
            for row in rows
        )
    return tuple(
        sorted(
            records,
            key=lambda item: (
                item.record_kind.value,
                item.mission_id,
                item.record_id,
                item.record_sha256,
            ),
        )
    )


def insert_action_target_health_gate_legacy_baseline(
    connection: sqlite3.Connection,
) -> ActionTargetHealthGateLegacyBaseline:
    """Capture the exact pre-schema 36 action inventory once."""

    identity_rows = connection.execute(
        "SELECT store_id FROM store_identity ORDER BY singleton_id"
    ).fetchall()
    if len(identity_rows) != 1:
        raise ActionTargetHealthGateUseError(
            "legacy baseline requires one store identity"
        )
    baseline = ActionTargetHealthGateLegacyBaseline(
        store_id=str(identity_rows[0][0]),
        records=_legacy_records(connection),
    )
    counts = {
        kind: sum(item.record_kind is kind for item in baseline.records)
        for kind in LegacyActionRecordKind
    }
    connection.execute(
        """
        INSERT INTO action_target_health_gate_legacy_baselines(
            singleton_id,
            baseline_id,
            baseline_sha256,
            store_id,
            cutover_schema_version,
            status,
            publication_count,
            admission_count,
            execution_count,
            baseline_json
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            baseline.baseline_id,
            baseline.baseline_sha256,
            baseline.store_id,
            STORE_SCHEMA_VERSION,
            LEGACY_BASELINE_STATUS,
            counts[LegacyActionRecordKind.ACTION_AUTHORITY_PUBLICATION],
            counts[LegacyActionRecordKind.ACTION_ADMISSION_RECEIPT],
            counts[LegacyActionRecordKind.ACTION_EXECUTION_REQUEST],
            canonical_json(baseline.to_dict()),
        ),
    )
    return baseline


def insert_action_execution_target_health_gate_legacy_baseline(
    connection: sqlite3.Connection,
) -> ActionExecutionTargetHealthGateLegacyBaseline:
    """Classify complete schema 36 execution coverage at cutover."""

    identity_rows = connection.execute(
        "SELECT store_id FROM store_identity ORDER BY singleton_id"
    ).fetchall()
    if len(identity_rows) != 1:
        raise ActionTargetHealthGateUseError(
            "execution baseline requires one store identity"
        )
    frozen: list[LegacyExecutionHealthRecordReference] = []
    original_legacy = {
        (str(row[0]), str(row[1]), str(row[2]))
        for row in connection.execute(
            "SELECT json_extract(record.value, '$.mission_id'), "
            "json_extract(record.value, '$.record_id'), "
            "json_extract(record.value, '$.record_sha256') "
            "FROM action_target_health_gate_legacy_baselines AS baseline, "
            "json_each(baseline.baseline_json, '$.records') AS record "
            "WHERE json_extract(record.value, '$.record_kind') = ?",
            (LegacyActionRecordKind.ACTION_EXECUTION_REQUEST.value,),
        ).fetchall()
    }
    requests = connection.execute(
        "SELECT mission_id, request_id, request_sha256 FROM "
        "action_execution_requests ORDER BY mission_id, request_id"
    ).fetchall()
    for mission_id, request_id, request_sha256 in requests:
        claim = connection.execute(
            "SELECT claim_id, claim_sha256 FROM action_execution_claims "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchall()
        dispatch = connection.execute(
            "SELECT dispatch_id, dispatch_sha256 FROM "
            "action_execution_dispatch_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchall()
        if len(claim) != 1 or len(dispatch) > 1:
            raise ActionTargetHealthGateUseError(
                "execution cutover lineage is malformed"
            )
        claim_uses = int(
            connection.execute(
                "SELECT COUNT(*) FROM action_target_health_gate_uses "
                "WHERE use_kind = ? AND consumer_id = ? AND consumer_sha256 = ?",
                (
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM.value,
                    claim[0][0],
                    claim[0][1],
                ),
            ).fetchone()[0]
        )
        dispatch_uses = 0
        invocation_uses = 0
        if dispatch:
            dispatch_uses = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ? AND consumer_id = ? "
                    "AND consumer_sha256 = ?",
                    (
                        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH.value,
                        dispatch[0][0],
                        dispatch[0][1],
                    ),
                ).fetchone()[0]
            )
            invocation_uses = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ? AND consumer_id = ? "
                    "AND consumer_sha256 = ?",
                    (
                        ActionTargetHealthGateUseKind
                        .ACTION_EXECUTION_INVOCATION.value,
                        dispatch[0][0],
                        dispatch[0][1],
                    ),
                ).fetchone()[0]
            )
        expected_dispatch_uses = 1 if dispatch else 0
        original_legacy_key = (
            str(mission_id),
            str(request_id),
            str(request_sha256),
        )
        if original_legacy_key in original_legacy and (
            claim_uses != 0 or dispatch_uses != 0 or invocation_uses != 0
        ):
            raise ActionTargetHealthGateUseError(
                "original legacy execution acquired health-use custody"
            )
        if claim_uses == 0 and dispatch_uses == 0 and invocation_uses == 0:
            coverage_status = "legacy_zero_coverage"
        elif (
            claim_uses == 1
            and dispatch_uses == expected_dispatch_uses
            and invocation_uses == 0
        ):
            coverage_status = "precutover_complete_coverage"
        else:
            raise ActionTargetHealthGateUseError(
                "execution cutover health-use coverage is partial or duplicated"
            )
        frozen.append(
            LegacyExecutionHealthRecordReference(
                mission_id=str(mission_id),
                request_id=str(request_id),
                request_sha256=str(request_sha256),
                claim_id=str(claim[0][0]),
                claim_sha256=str(claim[0][1]),
                claim_use_count=claim_uses,
                dispatch_id=None if not dispatch else str(dispatch[0][0]),
                dispatch_sha256=(
                    None if not dispatch else str(dispatch[0][1])
                ),
                dispatch_use_count=dispatch_uses,
                coverage_status=coverage_status,
            )
        )
    baseline = ActionExecutionTargetHealthGateLegacyBaseline(
        store_id=str(identity_rows[0][0]),
        records=tuple(frozen),
    )
    connection.execute(
        """
        INSERT INTO action_execution_target_health_gate_legacy_baselines(
            singleton_id, baseline_id, baseline_sha256, store_id,
            cutover_schema_version, status, request_count, baseline_json
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            baseline.baseline_id,
            baseline.baseline_sha256,
            baseline.store_id,
            EXECUTION_STORE_SCHEMA_VERSION,
            EXECUTION_LEGACY_BASELINE_STATUS,
            len(baseline.records),
            canonical_json(baseline.to_dict()),
        ),
    )
    return baseline


def insert_action_target_health_gate_use(
    connection: sqlite3.Connection,
    use: ActionTargetHealthGateUse,
) -> None:
    """Append one validated positive use to an existing write transaction."""

    if type(connection) is not sqlite3.Connection or not connection.in_transaction:
        raise ActionTargetHealthGateUseError(
            "target-health use requires an active transaction"
        )
    if not isinstance(use, ActionTargetHealthGateUse):
        raise TypeError("use must be an ActionTargetHealthGateUse")
    use = ActionTargetHealthGateUse.from_dict(use.to_dict())
    _require_exact_consumer(connection, use)
    observation = use.decision.current_observation
    connection.execute(
        """
        INSERT INTO action_target_health_gate_uses(
            use_id,
            use_sha256,
            use_kind,
            tenant_id,
            mission_id,
            consumer_id,
            consumer_sha256,
            subject_id,
            subject_sha256,
            binding_sha256,
            decision_id,
            decision_sha256,
            decision_json,
            observation_id,
            observation_sha256,
            transition_id,
            transition_sha256,
            transition_json,
            head_id,
            head_sha256,
            head_json,
            used_at,
            authority_effect,
            budget_effect,
            credential_effect,
            dispatch_effect,
            network_call_performed,
            qualification_effect,
            scope_effect,
            target_effect_performed,
            tier_effect,
            use_json
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            'none', 'none', 'none', 'none', 0, 'none', 'none', 0, 'none', ?
        )
        """,
        (
            use.use_id,
            use.use_sha256,
            use.use_kind.value,
            use.tenant_id,
            use.mission_id,
            use.consumer_id,
            use.consumer_sha256,
            use.decision.subject.subject_id,
            use.decision.subject.subject_sha256,
            use.binding_sha256,
            use.decision.decision_id,
            use.decision.decision_sha256,
            canonical_json(use.decision.to_dict()),
            observation.observation_id,
            observation.observation_sha256,
            use.transition.transition_id,
            use.transition.transition_sha256,
            canonical_json(use.transition.to_dict()),
            use.head.head_id,
            use.head.head_sha256,
            canonical_json(use.head.to_dict()),
            use.used_at,
            canonical_json(use.to_dict()),
        ),
    )


def _stored_use_from_row(row: sqlite3.Row) -> ActionTargetHealthGateUse:
    try:
        raw = json.loads(str(row["use_json"]))
        use = ActionTargetHealthGateUse.from_dict(raw)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ActionTargetHealthGateUseError(
            "stored target-health use is invalid"
        ) from exc
    expected = (
        use.use_id,
        use.use_sha256,
        use.use_kind.value,
        use.tenant_id,
        use.mission_id,
        use.consumer_id,
        use.consumer_sha256,
        use.decision.subject.subject_id,
        use.decision.subject.subject_sha256,
        use.binding_sha256,
        use.decision.decision_id,
        use.decision.decision_sha256,
        canonical_json(use.decision.to_dict()),
        use.decision.current_observation.observation_id,
        use.decision.current_observation.observation_sha256,
        use.transition.transition_id,
        use.transition.transition_sha256,
        canonical_json(use.transition.to_dict()),
        use.head.head_id,
        use.head.head_sha256,
        canonical_json(use.head.to_dict()),
        use.used_at,
    )
    fields = (
        "use_id",
        "use_sha256",
        "use_kind",
        "tenant_id",
        "mission_id",
        "consumer_id",
        "consumer_sha256",
        "subject_id",
        "subject_sha256",
        "binding_sha256",
        "decision_id",
        "decision_sha256",
        "decision_json",
        "observation_id",
        "observation_sha256",
        "transition_id",
        "transition_sha256",
        "transition_json",
        "head_id",
        "head_sha256",
        "head_json",
        "used_at",
    )
    if tuple(row[field] for field in fields) != expected:
        raise ActionTargetHealthGateUseError(
            "stored target-health use columns do not match its document"
        )
    _no_effects(dict(row), sqlite_row=True)
    return use


def _require_exact_consumer(
    connection: sqlite3.Connection,
    use: ActionTargetHealthGateUse,
) -> None:
    publication_kinds = {
        ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION,
        (
            ActionTargetHealthGateUseKind
            .ACTION_AUTHORITY_PUBLICATION_REPLAY_FOR_USE
        ),
    }
    admission_kinds = {
        ActionTargetHealthGateUseKind.ACTION_ADMISSION,
        ActionTargetHealthGateUseKind.ACTION_ADMISSION_REPLAY_FOR_USE,
        ActionTargetHealthGateUseKind.ACTION_ADMISSION_CURRENT_VERIFICATION,
    }
    if use.use_kind in publication_kinds:
        row = connection.execute(
            """
            SELECT material.material_json AS binding_source_json,
                   publication.published_at AS consumer_at
            FROM action_authority_publications AS publication
            JOIN action_authority_material_snapshots AS material
              ON material.material_snapshot_id = publication.material_snapshot_id
             AND material.material_snapshot_sha256 =
                 publication.material_snapshot_sha256
            WHERE publication.mission_id = ? AND publication.publication_id = ?
              AND publication.publication_sha256 = ?
            """,
            (use.mission_id, use.consumer_id, use.consumer_sha256),
        ).fetchone()
    elif use.use_kind in admission_kinds:
        row = connection.execute(
            """
            SELECT request_json AS binding_source_json,
                   created_at AS consumer_at
            FROM action_admission_receipts
            WHERE tenant_id = ? AND mission_id = ? AND receipt_id = ?
              AND receipt_sha256 = ?
            """,
            (
                use.tenant_id,
                use.mission_id,
                use.consumer_id,
                use.consumer_sha256,
            ),
        ).fetchone()
    elif use.use_kind is ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM:
        row = connection.execute(
            """
            SELECT receipt.request_json AS binding_source_json,
                   claim.claimed_at AS consumer_at
            FROM action_execution_claims AS claim
            JOIN action_execution_requests AS request
              ON request.request_id = claim.request_id
            JOIN action_admission_receipts AS receipt
              ON receipt.receipt_id = request.receipt_id
             AND receipt.receipt_sha256 = request.receipt_sha256
            WHERE request.tenant_id = ? AND request.mission_id = ?
              AND claim.claim_id = ? AND claim.claim_sha256 = ?
            """,
            (
                use.tenant_id,
                use.mission_id,
                use.consumer_id,
                use.consumer_sha256,
            ),
        ).fetchone()
    elif use.use_kind in {
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_INVOCATION,
    }:
        row = connection.execute(
            """
            SELECT receipt.request_json AS binding_source_json,
                   dispatch.attempted_at AS consumer_at
            FROM action_execution_dispatch_attempts AS dispatch
            JOIN action_execution_requests AS request
              ON request.request_id = dispatch.request_id
            JOIN action_admission_receipts AS receipt
              ON receipt.receipt_id = request.receipt_id
             AND receipt.receipt_sha256 = request.receipt_sha256
            WHERE request.tenant_id = ? AND request.mission_id = ?
              AND dispatch.dispatch_id = ? AND dispatch.dispatch_sha256 = ?
            """,
            (
                use.tenant_id,
                use.mission_id,
                use.consumer_id,
                use.consumer_sha256,
            ),
        ).fetchone()
    else:
        row = connection.execute(
            """
            SELECT receipt.request_json AS binding_source_json,
                   terminal.settled_at AS consumer_at
            FROM action_execution_terminals AS terminal
            JOIN action_execution_requests AS request
              ON request.request_id = terminal.request_id
            JOIN action_admission_receipts AS receipt
              ON receipt.receipt_id = request.receipt_id
             AND receipt.receipt_sha256 = request.receipt_sha256
            WHERE request.tenant_id = ? AND request.mission_id = ?
              AND terminal.terminal_id = ? AND terminal.terminal_sha256 = ?
            """,
            (
                use.tenant_id,
                use.mission_id,
                use.consumer_id,
                use.consumer_sha256,
            ),
        ).fetchone()
    if row is None:
        raise ActionTargetHealthGateUseError(
            "target-health use consumer is missing or cross-digest"
        )
    try:
        source_document = json.loads(str(row["binding_source_json"]))
        if use.use_kind in publication_kinds:
            context = ContextBinding.from_dict(source_document["context"])
            worker_session = WorkerSession.from_dict(
                source_document["worker_session"]
            )
            credential_lease = CredentialLease.from_dict(
                source_document["credential_lease"]
            )
            target_document = parse_target_action_descriptor(
                source_document["target"]
            ).to_dict()
            target = TargetBinding(
                target_id=target_document["target_id"],
                target_sha256=target_document["target_sha256"],
                authority_sha256=target_document["authority_snapshot_sha256"],
                tenant_id=target_document["tenant_id"],
                mission_id=target_document["mission_id"],
                scope_sha256=target_document["target_scope_sha256"],
                environment=target_document["environment"],
            )
        else:
            request = ActionAdmissionRequest.from_dict(source_document)
            context = request.context
            worker_session = request.worker_session
            credential_lease = request.credential_lease
            target = request.target
        expected_binding_sha256 = execution_binding_sha256(
            build_target_health_execution_binding(
                context=context,
                worker_session=worker_session,
                credential_lease=credential_lease,
                target=target,
            )
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ActionTargetHealthGateUseError(
            "target-health use consumer binding is invalid"
        ) from exc
    if not hmac.compare_digest(expected_binding_sha256, use.binding_sha256):
        raise ActionTargetHealthGateUseError(
            "target-health use decision does not match its consumer binding"
        )
    consumer_at = _utc(row["consumer_at"], "consumer_at")
    creation_kinds = {
        ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION,
        ActionTargetHealthGateUseKind.ACTION_ADMISSION,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM,
        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH,
    }
    if use.use_kind in creation_kinds:
        valid_time = use.used_at == consumer_at
    else:
        valid_time = _instant(use.used_at) >= _instant(consumer_at)
    if not valid_time:
        raise ActionTargetHealthGateUseError(
            "target-health use time does not match its consumer lifecycle"
        )


def _require_creation_coverage(
    connection: sqlite3.Connection,
    baseline: ActionTargetHealthGateLegacyBaseline,
) -> None:
    baseline_records = {
        (item.record_kind, item.mission_id, item.record_id, item.record_sha256)
        for item in baseline.records
    }
    specifications = (
        (
            LegacyActionRecordKind.ACTION_AUTHORITY_PUBLICATION,
            ActionTargetHealthGateUseKind.ACTION_AUTHORITY_PUBLICATION,
            "action_authority_publications",
            "publication_id",
            "publication_sha256",
        ),
        (
            LegacyActionRecordKind.ACTION_ADMISSION_RECEIPT,
            ActionTargetHealthGateUseKind.ACTION_ADMISSION,
            "action_admission_receipts",
            "receipt_id",
            "receipt_sha256",
        ),
    )
    for record_kind, use_kind, table, identifier, digest in specifications:
        records = connection.execute(
            f"SELECT mission_id, {identifier}, {digest} FROM {table} "
            f"ORDER BY mission_id, {identifier}"
        ).fetchall()
        for mission_id, consumer_id, consumer_sha256 in records:
            legacy_key = (
                record_kind,
                str(mission_id),
                str(consumer_id),
                str(consumer_sha256),
            )
            count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM action_target_health_gate_uses
                    WHERE use_kind = ? AND mission_id = ?
                      AND consumer_id = ? AND consumer_sha256 = ?
                    """,
                    (
                        use_kind.value,
                        mission_id,
                        consumer_id,
                        consumer_sha256,
                    ),
                ).fetchone()[0]
            )
            if legacy_key in baseline_records:
                if count != 0:
                    raise ActionTargetHealthGateUseError(
                        "legacy action record cannot acquire a creation permit"
                    )
            elif count != 1:
                raise ActionTargetHealthGateUseError(
                    "post-cutover action record lacks exact health-use custody"
                )


def _require_execution_creation_coverage(
    connection: sqlite3.Connection,
    baseline: ActionExecutionTargetHealthGateLegacyBaseline,
) -> None:
    frozen_requests = {
        (item.mission_id, item.request_id, item.request_sha256): item
        for item in baseline.records
    }
    requests = connection.execute(
        "SELECT mission_id, request_id, request_sha256 FROM "
        "action_execution_requests ORDER BY mission_id, request_id"
    ).fetchall()
    for mission_id, request_id, request_sha256 in requests:
        claims = connection.execute(
            "SELECT claim_id, claim_sha256 FROM action_execution_claims "
            "WHERE request_id = ?",
            (request_id,),
        ).fetchall()
        dispatches = connection.execute(
            "SELECT dispatch_id, dispatch_sha256 FROM "
            "action_execution_dispatch_attempts WHERE request_id = ?",
            (request_id,),
        ).fetchall()
        if len(claims) != 1 or len(dispatches) > 1:
            raise ActionTargetHealthGateUseError(
                "execution health-use lineage is malformed"
            )
        claim_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM action_target_health_gate_uses "
                "WHERE use_kind = ? AND mission_id = ? AND consumer_id = ? "
                "AND consumer_sha256 = ?",
                (
                    ActionTargetHealthGateUseKind.ACTION_EXECUTION_CLAIM.value,
                    mission_id,
                    claims[0][0],
                    claims[0][1],
                ),
            ).fetchone()[0]
        )
        dispatch_count = 0
        invocation_count = 0
        if dispatches:
            dispatch_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ? AND mission_id = ? AND consumer_id = ? "
                    "AND consumer_sha256 = ?",
                    (
                        ActionTargetHealthGateUseKind.ACTION_EXECUTION_DISPATCH.value,
                        mission_id,
                        dispatches[0][0],
                        dispatches[0][1],
                    ),
                ).fetchone()[0]
            )
            invocation_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM action_target_health_gate_uses "
                    "WHERE use_kind = ? AND mission_id = ? AND consumer_id = ? "
                    "AND consumer_sha256 = ?",
                    (
                        ActionTargetHealthGateUseKind
                        .ACTION_EXECUTION_INVOCATION.value,
                        mission_id,
                        dispatches[0][0],
                        dispatches[0][1],
                    ),
                ).fetchone()[0]
            )
        frozen_key = (str(mission_id), str(request_id), str(request_sha256))
        frozen = frozen_requests.get(frozen_key)
        if frozen is not None:
            exact_dispatch = (
                (None, None)
                if not dispatches
                else (str(dispatches[0][0]), str(dispatches[0][1]))
            )
            if (
                (str(claims[0][0]), str(claims[0][1]))
                != (frozen.claim_id, frozen.claim_sha256)
                or exact_dispatch
                != (frozen.dispatch_id, frozen.dispatch_sha256)
                or claim_count != frozen.claim_use_count
                or dispatch_count != frozen.dispatch_use_count
                or invocation_count != 0
            ):
                raise ActionTargetHealthGateUseError(
                    "precutover execution health custody changed"
                )
        elif claim_count != 1 or dispatch_count != len(dispatches):
            raise ActionTargetHealthGateUseError(
                "post-cutover execution lacks exact health-use custody"
            )
        elif dispatches:
            terminal = connection.execute(
                "SELECT json_extract(terminal_json, "
                "'$.adapter_call_count_status') "
                "FROM action_execution_terminals "
                "WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if terminal is None:
                valid_invocation_count = invocation_count in {0, 1}
            elif terminal[0] == "exactly_zero":
                use_one_abort = None
                if invocation_count == 1:
                    use_one_abort = connection.execute(
                        "SELECT 1 FROM "
                        "action_execution_preinvocation_aborts AS abort "
                        "JOIN action_target_health_gate_uses AS use "
                        "ON use.use_id = abort.invocation_use_id "
                        "AND use.use_sha256 = abort.invocation_use_sha256 "
                        "WHERE abort.request_id = ? "
                        "AND abort.dispatch_id = ? "
                        "AND abort.dispatch_sha256 = ? "
                        "AND use.use_kind = ? "
                        "AND use.consumer_id = abort.dispatch_id "
                        "AND use.consumer_sha256 = abort.dispatch_sha256",
                        (
                            request_id,
                            dispatches[0][0],
                            dispatches[0][1],
                            ActionTargetHealthGateUseKind
                            .ACTION_EXECUTION_INVOCATION.value,
                        ),
                    ).fetchone()
                valid_invocation_count = (
                    invocation_count == 0
                    or invocation_count == 1
                    and use_one_abort is not None
                )
            elif terminal[0] == "unknown_zero_or_one":
                valid_invocation_count = invocation_count in {0, 1}
            elif terminal[0] == "exactly_one":
                valid_invocation_count = invocation_count == 1
            else:
                valid_invocation_count = False
            if not valid_invocation_count:
                raise ActionTargetHealthGateUseError(
                    "post-cutover invocation lacks exact health-use custody"
                )


def verify_action_target_health_gate_use_store(
    connection: sqlite3.Connection,
    mission_id: str | None = None,
) -> ActionTargetHealthGateUseVerificationReport:
    """Verify immutable use history without asserting live currentness."""

    from .mission_store_target_health_gate import verify_target_health_gate_store

    verify_target_health_gate_store(connection, mission_id)
    original_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    try:
        from .mission_store_target_health_gate import (
            verify_target_health_gate_store,
        )

        verify_target_health_gate_store(connection, mission_id=mission_id)
        baselines = connection.execute(
            "SELECT * FROM action_target_health_gate_legacy_baselines"
        ).fetchall()
        if len(baselines) != 1:
            raise ActionTargetHealthGateUseError(
                "target-health legacy baseline is missing or duplicated"
            )
        baseline_row = baselines[0]
        try:
            document = str(baseline_row["baseline_json"])
            raw = json.loads(document)
            if canonical_json(raw) != document:
                raise ActionTargetHealthGateUseError(
                    "legacy baseline document is not canonical"
                )
            baseline = ActionTargetHealthGateLegacyBaseline.from_dict(raw)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ActionTargetHealthGateUseError(
                "stored target-health legacy baseline is invalid"
            ) from exc
        counts = {
            kind: sum(item.record_kind is kind for item in baseline.records)
            for kind in LegacyActionRecordKind
        }
        expected_baseline = (
            1,
            baseline.baseline_id,
            baseline.baseline_sha256,
            baseline.store_id,
            STORE_SCHEMA_VERSION,
            LEGACY_BASELINE_STATUS,
            counts[LegacyActionRecordKind.ACTION_AUTHORITY_PUBLICATION],
            counts[LegacyActionRecordKind.ACTION_ADMISSION_RECEIPT],
            counts[LegacyActionRecordKind.ACTION_EXECUTION_REQUEST],
            canonical_json(baseline.to_dict()),
        )
        baseline_fields = (
            "singleton_id",
            "baseline_id",
            "baseline_sha256",
            "store_id",
            "cutover_schema_version",
            "status",
            "publication_count",
            "admission_count",
            "execution_count",
            "baseline_json",
        )
        if tuple(baseline_row[field] for field in baseline_fields) != expected_baseline:
            raise ActionTargetHealthGateUseError(
                "stored target-health legacy baseline columns do not match"
            )
        identity = connection.execute(
            "SELECT store_id FROM store_identity WHERE singleton_id = 1"
        ).fetchone()
        if identity is None or identity[0] != baseline.store_id:
            raise ActionTargetHealthGateUseError(
                "legacy baseline crosses its store identity"
            )
        execution_baseline: (
            ActionExecutionTargetHealthGateLegacyBaseline | None
        ) = None
        execution_table = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = "
            "'action_execution_target_health_gate_legacy_baselines'"
        ).fetchone()
        if execution_table is not None:
            execution_baselines = connection.execute(
                "SELECT * FROM "
                "action_execution_target_health_gate_legacy_baselines"
            ).fetchall()
            if len(execution_baselines) != 1:
                raise ActionTargetHealthGateUseError(
                    "execution target-health legacy baseline is missing or duplicated"
                )
            execution_baseline_row = execution_baselines[0]
            try:
                execution_document = str(
                    execution_baseline_row["baseline_json"]
                )
                execution_raw = json.loads(execution_document)
                if canonical_json(execution_raw) != execution_document:
                    raise ActionTargetHealthGateUseError(
                        "execution legacy baseline document is not canonical"
                    )
                execution_baseline = (
                    ActionExecutionTargetHealthGateLegacyBaseline.from_dict(
                        execution_raw
                    )
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ActionTargetHealthGateUseError(
                    "stored execution target-health baseline is invalid"
                ) from exc
            execution_expected = (
                1,
                execution_baseline.baseline_id,
                execution_baseline.baseline_sha256,
                execution_baseline.store_id,
                EXECUTION_STORE_SCHEMA_VERSION,
                EXECUTION_LEGACY_BASELINE_STATUS,
                len(execution_baseline.records),
                canonical_json(execution_baseline.to_dict()),
            )
            execution_fields = (
                "singleton_id",
                "baseline_id",
                "baseline_sha256",
                "store_id",
                "cutover_schema_version",
                "status",
                "request_count",
                "baseline_json",
            )
            if (
                tuple(
                    execution_baseline_row[field]
                    for field in execution_fields
                )
                != execution_expected
                or execution_baseline.store_id != baseline.store_id
            ):
                raise ActionTargetHealthGateUseError(
                    "stored execution legacy baseline columns do not match"
                )
            for reference in execution_baseline.records:
                found = connection.execute(
                    "SELECT 1 FROM action_execution_requests "
                    "WHERE mission_id = ? AND request_id = ? "
                    "AND request_sha256 = ?",
                    (
                        reference.mission_id,
                        reference.request_id,
                        reference.request_sha256,
                    ),
                ).fetchone()
                if found is None:
                    raise ActionTargetHealthGateUseError(
                        "execution legacy baseline record is missing"
                    )
        legacy_tables = {
            LegacyActionRecordKind.ACTION_AUTHORITY_PUBLICATION: (
                "action_authority_publications",
                "publication_id",
                "publication_sha256",
            ),
            LegacyActionRecordKind.ACTION_ADMISSION_RECEIPT: (
                "action_admission_receipts",
                "receipt_id",
                "receipt_sha256",
            ),
            LegacyActionRecordKind.ACTION_EXECUTION_REQUEST: (
                "action_execution_requests",
                "request_id",
                "request_sha256",
            ),
        }
        for reference in baseline.records:
            table, identifier, digest = legacy_tables[reference.record_kind]
            found = connection.execute(
                f"SELECT 1 FROM {table} WHERE mission_id = ? "
                f"AND {identifier} = ? AND {digest} = ?",
                (
                    reference.mission_id,
                    reference.record_id,
                    reference.record_sha256,
                ),
            ).fetchone()
            if found is None:
                raise ActionTargetHealthGateUseError(
                    "legacy baseline record is missing"
                )
        arguments: tuple[Any, ...]
        where = ""
        if mission_id is None:
            arguments = ()
        else:
            _identifier(mission_id, "mission_id")
            where = " WHERE mission_id = ?"
            arguments = (mission_id,)
        rows = connection.execute(
            "SELECT * FROM action_target_health_gate_uses"
            + where
            + " ORDER BY used_at, use_id",
            arguments,
        ).fetchall()
        if execution_baseline is None and any(
            row["use_kind"]
            in {item.value for item in SCHEMA36_RESERVED_USE_KINDS}
            for row in rows
        ):
            raise ActionTargetHealthGateUseError(
                "reserved target-health use predates its execution cutover"
            )
        seen_decisions: set[tuple[str, str]] = set()
        seen_nonrepeatable_consumers: set[tuple[str, str, str]] = set()
        for row in rows:
            use = _stored_use_from_row(row)
            if execution_baseline is None and use.use_kind in SCHEMA36_RESERVED_USE_KINDS:
                raise ActionTargetHealthGateUseError(
                    "reserved execution health use is unavailable in schema 36"
                )
            _require_exact_consumer(connection, use)
            decision_key = (
                use.decision.decision_id,
                use.decision.decision_sha256,
            )
            if decision_key in seen_decisions:
                raise ActionTargetHealthGateUseError(
                    "one health decision was consumed more than once"
                )
            seen_decisions.add(decision_key)
            if use.use_kind in NONREPEATABLE_USE_KINDS:
                consumer_key = (
                    use.use_kind.value,
                    use.consumer_id,
                    use.consumer_sha256,
                )
                if consumer_key in seen_nonrepeatable_consumers:
                    raise ActionTargetHealthGateUseError(
                        "nonrepeatable consumer has multiple health uses"
                    )
                seen_nonrepeatable_consumers.add(consumer_key)
            observation = connection.execute(
                """
                SELECT subject_id, tenant_id, mission_id, binding_sha256
                FROM target_health_gate_observations
                WHERE observation_id = ? AND observation_sha256 = ?
                """,
                (
                    use.decision.current_observation.observation_id,
                    use.decision.current_observation.observation_sha256,
                ),
            ).fetchone()
            transition = connection.execute(
                """
                SELECT transition_json FROM target_health_gate_transitions
                WHERE transition_id = ? AND transition_sha256 = ?
                """,
                (use.transition.transition_id, use.transition.transition_sha256),
            ).fetchone()
            if (
                observation is None
                or tuple(observation)
                != (
                    use.decision.subject.subject_id,
                    use.tenant_id,
                    use.mission_id,
                    use.binding_sha256,
                )
                or transition is None
                or transition[0] != canonical_json(use.transition.to_dict())
            ):
                raise ActionTargetHealthGateUseError(
                    "target-health use source lineage is invalid"
                )
        _require_creation_coverage(connection, baseline)
        if execution_baseline is not None:
            _require_execution_creation_coverage(
                connection,
                execution_baseline,
            )
        return ActionTargetHealthGateUseVerificationReport(
            baseline_id=baseline.baseline_id,
            legacy_record_count=len(baseline.records),
            use_count=len(rows),
            execution_baseline_id=(
                "" if execution_baseline is None else execution_baseline.baseline_id
            ),
            legacy_execution_count=(
                0 if execution_baseline is None else len(execution_baseline.records)
            ),
        )
    finally:
        connection.row_factory = original_factory

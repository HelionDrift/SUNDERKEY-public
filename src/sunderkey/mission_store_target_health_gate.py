"""Transaction-scoped MissionStore target-health gate service.

The service joins fresh Phase 199 custody inspection to the schema 35 latch.
It performs no collection, network call, dispatch, executor control, or target
effect. Historical verification reconstructs stored content without treating
an old serialized inspection as live currentness.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .authenticated import AuthenticatedMissionControlService
from .authorized_target_health_runtime import HealthSignalState, TargetHealthStatus
from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .execution_control_runtime import ExecutionBinding
from .identity import (
    PrincipalAssertion,
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_principal_assertion,
    verify_scope_grant,
)
from .registry import ExpertRegistry
from .store import (
    TARGET_HEALTH_GATE_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    parse_timestamp,
    principal_assertion_effects_hash,
    principal_assertion_entry_hash,
    sha256_text,
)
from .target_health_custody import SQLiteTargetHealthCustody
from .target_health_custody_contracts import TargetHealthCurrentHeadInspection
from .target_health_gate_contracts import (
    TARGET_HEALTH_GATE_RESUME_OPERATION,
    TargetHealthGateClassification,
    TargetHealthGateDecision,
    TargetHealthGateDecisionStatus,
    TargetHealthGateHead,
    TargetHealthGateObservation,
    TargetHealthGateRecoveryIntent,
    TargetHealthGateResumption,
    TargetHealthGateState,
    TargetHealthGateSubject,
    TargetHealthGateTransition,
    TargetHealthGateTransitionKind,
    build_target_health_gate_head,
    build_target_health_gate_observation,
    build_target_health_gate_transition,
    execution_binding_sha256,
    target_health_gate_inspection_context_sha256,
    target_health_gate_subject,
)
from .target_health_gate_contracts import canonical_json as gate_canonical_json
from .types import ProfileKind

DEFAULT_RECOVERY_INTENT_TTL_SECONDS = 300
MAX_RECOVERY_INTENT_TTL_SECONDS = 3600

_PRINCIPAL_ASSERTION_ENTRY_FIELDS = (
    "mission_id",
    "use_sequence",
    "issuer",
    "assertion_id",
    "assertion_hash",
    "subject",
    "principal_profile_id",
    "key_id",
    "key_hash",
    "audience",
    "store_id",
    "operation",
    "operation_intent_json",
    "signed_intent_hash",
    "domain_request_hash",
    "idempotency_key_hash",
    "scope_grant_hash",
    "trust_policy_id",
    "trust_policy_version",
    "trust_policy_hash",
    "issued_at",
    "not_before",
    "expires_at",
    "consumed_at",
    "effects_hash",
    "previous_hash",
)


@dataclass(frozen=True, slots=True)
class TargetHealthGateObservationResult:
    """One atomically stored observation and its health-only decision."""

    observation: TargetHealthGateObservation
    transition: TargetHealthGateTransition
    head: TargetHealthGateHead
    decision: TargetHealthGateDecision


@dataclass(frozen=True, slots=True)
class TargetHealthGateResumptionResult:
    """One newly stored Control resumption."""

    resumption: TargetHealthGateResumption
    transition: TargetHealthGateTransition
    head: TargetHealthGateHead


@dataclass(frozen=True, slots=True)
class TargetHealthGateStoreVerificationReport:
    """Historical target-health gate reconstruction summary."""

    mission_id: str | None
    mission_count: int
    subject_count: int
    observation_count: int
    resumption_count: int
    transition_count: int
    active_count: int
    paused_count: int
    recovery_pending_count: int
    status: str = "valid"


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if type(value) is not str:
        raise StoreIntegrityError(f"Stored {label} is not text")
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise StoreIntegrityError(f"Stored {label} is invalid") from exc
    if not isinstance(parsed, dict) or gate_canonical_json(parsed) != value:
        raise StoreIntegrityError(f"Stored {label} is not canonical")
    return parsed


def _binding_from_json(value: Any) -> ExecutionBinding:
    document = _json_object(value, "target-health binding")
    try:
        return ExecutionBinding(**document)
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health binding is invalid") from exc


def _inspection_from_json(value: Any, label: str) -> TargetHealthCurrentHeadInspection:
    document = _json_object(value, label)
    try:
        inspection = TargetHealthCurrentHeadInspection.from_dict(document)
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError(f"Stored {label} is invalid") from exc
    if gate_canonical_json(inspection.to_dict()) != value:
        raise StoreIntegrityError(f"Stored {label} is not canonical")
    return inspection


def _subject_from_row(row: sqlite3.Row) -> TargetHealthGateSubject:
    try:
        subject = TargetHealthGateSubject(
            tenant_id=row["tenant_id"],
            mission_id=row["mission_id"],
            scope_sha256=row["scope_sha256"],
            target_sha256=row["target_sha256"],
            subject_id=row["subject_id"],
        )
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health subject is invalid") from exc
    if subject.subject_id != row["subject_id"]:
        raise StoreIntegrityError("Stored target-health subject identity is invalid")
    return subject


def _observation_from_row(row: sqlite3.Row) -> TargetHealthGateObservation:
    subject = _subject_from_row(row)
    binding = _binding_from_json(row["binding_json"])
    inspection = _inspection_from_json(row["inspection_json"], "target-health inspection")
    try:
        observation = TargetHealthGateObservation(
            subject=subject,
            observation_sequence=row["observation_sequence"],
            previous_observation_sha256=row["previous_observation_sha256"],
            binding=binding,
            binding_sha256=row["binding_sha256"],
            inspection=inspection,
            classification=row["classification"],
            evidence_advanced=bool(row["evidence_advanced"]),
            recorded_at=row["recorded_at"],
            observation_id=row["observation_id"],
            observation_sha256=row["observation_sha256"],
        )
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health observation is invalid") from exc
    expected = (
        observation.observation_id,
        observation.observation_sha256,
        observation.subject.subject_id,
        observation.subject.tenant_id,
        observation.subject.mission_id,
        observation.subject.scope_sha256,
        observation.subject.target_sha256,
        observation.observation_sequence,
        observation.previous_observation_sha256,
        observation.binding_sha256,
        gate_canonical_json(observation.binding.to_dict()),
        observation.inspection_id,
        observation.inspection_sha256,
        gate_canonical_json(observation.inspection.to_dict()),
        observation.head_binding_id,
        observation.head_binding_sha256,
        observation.global_transition_sequence,
        observation.chain_id,
        observation.envelope_id,
        observation.envelope_sha256,
        observation.envelope_sequence,
        observation.predecessor_envelope_id,
        observation.predecessor_envelope_sha256,
        observation.receipt_id,
        observation.receipt_sha256,
        observation.receipt_status,
        observation.overall_health,
        observation.classification.value,
        int(observation.evidence_advanced),
        observation.observed_at,
        observation.inspected_at,
        observation.recorded_at,
    )
    if tuple(row) != expected:
        raise StoreIntegrityError("Stored target-health observation row is inconsistent")
    return observation


def _resumption_from_row(row: sqlite3.Row) -> TargetHealthGateResumption:
    document = _json_object(row["resumption_json"], "target-health resumption")
    try:
        resumption = TargetHealthGateResumption.from_dict(document)
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health resumption is invalid") from exc
    if gate_canonical_json(resumption.to_dict()) != row["resumption_json"]:
        raise StoreIntegrityError("Stored target-health resumption is not canonical")
    expected = (
        resumption.resumption_id,
        resumption.resumption_sha256,
        resumption.subject.subject_id,
        resumption.subject.tenant_id,
        resumption.subject.mission_id,
        resumption.subject.scope_sha256,
        resumption.subject.target_sha256,
        resumption.pause_epoch,
        resumption.recovery_intent.recovery_intent_id,
        resumption.recovery_intent.recovery_intent_sha256,
        gate_canonical_json(resumption.recovery_intent.to_dict()),
        gate_canonical_json(list(resumption.qualifying_observation_ids)),
        gate_canonical_json(list(resumption.qualifying_observation_sha256s)),
        resumption.fresh_inspection_id,
        resumption.fresh_inspection_sha256,
        resumption.fresh_head_binding_sha256,
        gate_canonical_json(dict(resumption.authorization)),
        resumption.assertion_issuer,
        resumption.assertion_id,
        resumption.assertion_sha256,
        resumption.authority_use_sequence,
        resumption.canonical_replay_key_sha256,
        resumption.operation_intent_sha256,
        gate_canonical_json(resumption.to_dict()),
        resumption.resumed_at,
    )
    if tuple(row) != expected:
        raise StoreIntegrityError("Stored target-health resumption row is inconsistent")
    return resumption


def _transition_from_row(row: sqlite3.Row) -> TargetHealthGateTransition:
    document = _json_object(row["transition_json"], "target-health transition")
    try:
        transition = TargetHealthGateTransition.from_dict(document)
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health transition is invalid") from exc
    if gate_canonical_json(transition.to_dict()) != row["transition_json"]:
        raise StoreIntegrityError("Stored target-health transition is not canonical")
    expected = (
        transition.transition_id,
        transition.transition_sha256,
        transition.subject.subject_id,
        transition.subject.tenant_id,
        transition.subject.mission_id,
        transition.subject.scope_sha256,
        transition.subject.target_sha256,
        transition.transition_sequence,
        transition.previous_transition_sha256,
        transition.transition_kind.value,
        None if transition.from_state is None else transition.from_state.value,
        transition.to_state.value,
        transition.pause_epoch,
        transition.recovery_healthy_count,
        transition.observation_id,
        transition.observation_sha256,
        transition.resumption_id,
        transition.resumption_sha256,
        gate_canonical_json(transition.to_dict()),
        transition.occurred_at,
    )
    if tuple(row) != expected:
        raise StoreIntegrityError("Stored target-health transition row is inconsistent")
    return transition


def _head_from_row(row: sqlite3.Row) -> TargetHealthGateHead:
    subject = _subject_from_row(row)
    try:
        head = TargetHealthGateHead(
            subject=subject,
            latch_state=row["latch_state"],
            pause_epoch=row["pause_epoch"],
            observation_count=row["observation_count"],
            observation_head_sha256=row["observation_head_sha256"],
            transition_count=row["transition_count"],
            transition_head_sha256=row["transition_head_sha256"],
            resumption_count=row["resumption_count"],
            recovery_healthy_count=row["recovery_healthy_count"],
            recovery_chain_id=row["recovery_chain_id"],
            recovery_envelope_id=row["recovery_envelope_id"],
            recovery_envelope_sha256=row["recovery_envelope_sha256"],
            recovery_envelope_sequence=row["recovery_envelope_sequence"],
            recovery_observed_at=row["recovery_observed_at"],
            last_observation_id=row["last_observation_id"],
            last_observation_sha256=row["last_observation_sha256"],
            last_binding_sha256=row["last_binding_sha256"],
            last_inspection_id=row["last_inspection_id"],
            last_inspection_sha256=row["last_inspection_sha256"],
            last_head_binding_id=row["last_head_binding_id"],
            last_head_binding_sha256=row["last_head_binding_sha256"],
            last_global_transition_sequence=row["last_global_transition_sequence"],
            last_current_material_sha256=row["last_current_material_sha256"],
            last_adverse_observation_id=row["last_adverse_observation_id"],
            last_adverse_observation_sha256=row["last_adverse_observation_sha256"],
            last_resumption_id=row["last_resumption_id"],
            last_resumption_sha256=row["last_resumption_sha256"],
            version=row["version"],
            updated_at=row["updated_at"],
            head_id=row["head_id"],
            head_sha256=row["head_sha256"],
        )
    except (TypeError, ValueError) as exc:
        raise StoreIntegrityError("Stored target-health head is invalid") from exc
    expected = (
        head.subject.subject_id,
        head.head_id,
        head.head_sha256,
        head.subject.tenant_id,
        head.subject.mission_id,
        head.subject.scope_sha256,
        head.subject.target_sha256,
        head.latch_state.value,
        head.pause_epoch,
        head.observation_count,
        head.observation_head_sha256,
        head.transition_count,
        head.transition_head_sha256,
        head.resumption_count,
        head.recovery_healthy_count,
        head.recovery_chain_id,
        head.recovery_envelope_id,
        head.recovery_envelope_sha256,
        head.recovery_envelope_sequence,
        head.recovery_observed_at,
        head.last_observation_id,
        head.last_observation_sha256,
        head.last_binding_sha256,
        head.last_inspection_id,
        head.last_inspection_sha256,
        head.last_head_binding_id,
        head.last_head_binding_sha256,
        head.last_global_transition_sequence,
        head.last_current_material_sha256,
        head.last_adverse_observation_id,
        head.last_adverse_observation_sha256,
        head.last_resumption_id,
        head.last_resumption_sha256,
        head.version,
        head.updated_at,
    )
    if tuple(row) != expected:
        raise StoreIntegrityError("Stored target-health head row is inconsistent")
    return head


def _load_head_in_connection(
    connection: sqlite3.Connection,
    subject: TargetHealthGateSubject,
) -> TargetHealthGateHead | None:
    row = connection.execute(
        "SELECT * FROM target_health_gate_heads WHERE subject_id = ?",
        (subject.subject_id,),
    ).fetchone()
    if row is None:
        return None
    head = _head_from_row(row)
    if head.subject != subject:
        raise StoreIntegrityError("Target-health head crosses its requested subject")
    return head


def _target_tables_available(connection: sqlite3.Connection) -> None:
    expected = {
        "target_health_gate_heads",
        "target_health_gate_observations",
        "target_health_gate_resumptions",
        "target_health_gate_transitions",
    }
    rows = connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name IN (?,?,?,?)",
        tuple(sorted(expected)),
    ).fetchall()
    if {row[0] for row in rows} != expected:
        raise StoreIntegrityError("Target-health gate schema is unavailable")


def _verify_resumption_principal_custody(
    connection: sqlite3.Connection,
    resumption: TargetHealthGateResumption,
) -> None:
    use = connection.execute(
        "SELECT * FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ? "
        "AND mission_id = ?",
        (
            resumption.assertion_issuer,
            resumption.assertion_id,
            resumption.subject.mission_id,
        ),
    ).fetchone()
    effects = connection.execute(
        "SELECT * FROM principal_assertion_effects WHERE issuer = ? AND assertion_id = ? "
        "AND mission_id = ? ORDER BY effect_index",
        (
            resumption.assertion_issuer,
            resumption.assertion_id,
            resumption.subject.mission_id,
        ),
    ).fetchall()
    if use is None or len(effects) != 1:
        raise StoreIntegrityError("Target-health resumption principal custody is missing")
    effect = effects[0]
    authorization = dict(resumption.authorization)
    operation_intent = {
        "idempotency_key_sha256": resumption.canonical_replay_key_sha256,
        "mission_id": resumption.subject.mission_id,
        "principal_profile_id": authorization["principal_profile_id"],
        "recovery_intent_sha256": resumption.recovery_intent.recovery_intent_sha256,
        "role": "independent_control",
    }
    operation_intent_json = canonical_json(operation_intent)
    expected_intent_sha256 = compute_operation_intent_hash(
        PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
        operation_intent,
    )
    assertion_document = _json_object(
        use["assertion_json"],
        "target-health principal assertion",
    )
    try:
        assertion = PrincipalAssertion.from_dict(assertion_document)
    except (TypeError, ValueError, PrincipalAuthenticationError) as exc:
        raise StoreIntegrityError(
            "Stored target-health principal assertion is invalid"
        ) from exc
    if (
        use["mission_id"] != resumption.subject.mission_id
        or use["issuer"] != resumption.assertion_issuer
        or use["assertion_id"] != resumption.assertion_id
        or use["use_sequence"] != resumption.authority_use_sequence
        or sha256_text(use["assertion_json"]) != resumption.assertion_sha256
        or use["assertion_hash"] != resumption.assertion_sha256
        or use["operation"] != TARGET_HEALTH_GATE_RESUME_OPERATION
        or use["operation_intent_json"] != operation_intent_json
        or use["signed_intent_hash"] != resumption.operation_intent_sha256
        or use["domain_request_hash"] != resumption.operation_intent_sha256
        or use["idempotency_key_hash"] != resumption.canonical_replay_key_sha256
        or use["consumed_at"] != resumption.resumed_at
        or use["principal_profile_id"] != authorization["principal_profile_id"]
        or use["subject"] != authorization["principal_subject"]
        or use["issuer"] == use["subject"]
        or use["issued_at"] != authorization["issued_at"]
        or use["expires_at"] != authorization["expires_at"]
        or expected_intent_sha256 != resumption.operation_intent_sha256
        or assertion.issuer != resumption.assertion_issuer
        or assertion.assertion_id != resumption.assertion_id
        or assertion.subject != authorization["principal_subject"]
        or assertion.profile_id != authorization["principal_profile_id"]
        or assertion.key_id != use["key_id"]
        or assertion.audience != use["audience"]
        or assertion.store_id != use["store_id"]
        or assertion.mission_id != resumption.subject.mission_id
        or assertion.operation is not PrincipalOperation.TARGET_HEALTH_GATE_RESUME
        or assertion.operation_intent_sha256 != resumption.operation_intent_sha256
        or assertion.scope_grant_sha256 != use["scope_grant_hash"]
        or assertion.policy_id != use["trust_policy_id"]
        or assertion.policy_version != use["trust_policy_version"]
        or assertion.issued_at != authorization["issued_at"]
        or assertion.not_before != use["not_before"]
        or assertion.expires_at != authorization["expires_at"]
        or effect["effect_index"] != 1
        or effect["effect_kind"] != TARGET_HEALTH_GATE_RESUME_OPERATION
        or effect["effect_id"] != resumption.resumption_id
        or effect["recorded_at"] != resumption.resumed_at
    ):
        raise StoreIntegrityError("Target-health resumption principal custody is invalid")
    effect_document = _json_object(effect["effect_json"], "target-health principal effect")
    expected_effect = {
        "effect_id": resumption.resumption_id,
        "effect_kind": TARGET_HEALTH_GATE_RESUME_OPERATION,
        "payload": {
            "recovery_intent_id": resumption.recovery_intent.recovery_intent_id,
            "result_id": resumption.resumption_id,
            "result_sha256": resumption.resumption_sha256,
            "subject_id": resumption.subject.subject_id,
        },
        "recorded_at": resumption.resumed_at,
        "schema_version": 1,
    }
    effect_hash = sha256_text(effect["effect_json"])
    expected_effects_hash = principal_assertion_effects_hash((effect_hash,))
    entry_material = {field: use[field] for field in _PRINCIPAL_ASSERTION_ENTRY_FIELDS}
    expected_entry_hash = principal_assertion_entry_hash(entry_material)
    if (
        effect_document != expected_effect
        or effect_hash != effect["effect_hash"]
        or use["effects_hash"] != expected_effects_hash
        or use["entry_hash"] != expected_entry_hash
    ):
        raise StoreIntegrityError("Target-health resumption effect is invalid")
    previous = connection.execute(
        "SELECT entry_hash FROM principal_assertion_uses WHERE mission_id = ? "
        "AND use_sequence = ?",
        (resumption.subject.mission_id, resumption.authority_use_sequence - 1),
    ).fetchone()
    following = connection.execute(
        "SELECT previous_hash FROM principal_assertion_uses WHERE mission_id = ? "
        "AND use_sequence = ?",
        (resumption.subject.mission_id, resumption.authority_use_sequence + 1),
    ).fetchone()
    last_use = connection.execute(
        "SELECT use_sequence, entry_hash, consumed_at FROM principal_assertion_uses "
        "WHERE mission_id = ? ORDER BY use_sequence DESC LIMIT 1",
        (resumption.subject.mission_id,),
    ).fetchone()
    ledger = connection.execute(
        "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
        (resumption.subject.mission_id,),
    ).fetchone()
    use_count = connection.execute(
        "SELECT COUNT(*) FROM principal_assertion_uses WHERE mission_id = ?",
        (resumption.subject.mission_id,),
    ).fetchone()[0]
    effect_count = connection.execute(
        "SELECT COUNT(*) FROM principal_assertion_effects WHERE mission_id = ?",
        (resumption.subject.mission_id,),
    ).fetchone()[0]
    if (
        (resumption.authority_use_sequence > 1 and previous is None)
        or (previous is not None and use["previous_hash"] != previous["entry_hash"])
        or (resumption.authority_use_sequence < use_count and following is None)
        or (following is not None and following["previous_hash"] != use["entry_hash"])
        or ledger is None
        or last_use is None
        or ledger["assertion_count"] != use_count
        or last_use["use_sequence"] != use_count
        or ledger["effect_count"] != effect_count
        or ledger["head_hash"] != last_use["entry_hash"]
        or ledger["updated_at"] != last_use["consumed_at"]
    ):
        raise StoreIntegrityError("Target-health resumption principal ledger is invalid")


def _verify_historical_resumption_source(
    resumption: TargetHealthGateResumption,
    previous_head: TargetHealthGateHead | None,
    observation_by_id: Mapping[str, TargetHealthGateObservation],
    prior_transitions: tuple[TargetHealthGateTransition, ...],
) -> None:
    if previous_head is None:
        raise StoreIntegrityError("Target-health resumption has no prior head")
    intent = resumption.recovery_intent
    last_observation = observation_by_id.get(previous_head.last_observation_id)
    if last_observation is None:
        raise StoreIntegrityError("Target-health resumption head observation is missing")
    expected_head_binding = (
        previous_head.last_head_binding_id,
        previous_head.last_head_binding_sha256,
        previous_head.last_global_transition_sequence,
    )
    intent_head_binding = (
        intent.latest_head_binding_id,
        intent.latest_head_binding_sha256,
        intent.global_transition_sequence,
    )
    fresh = resumption.fresh_inspection
    fresh_head_binding = (
        fresh.head_binding.head_binding_id,
        fresh.head_binding.head_binding_sha256,
        fresh.head_binding.global_transition_sequence,
    )
    expected_recovery = (
        previous_head.recovery_chain_id,
        previous_head.recovery_envelope_id,
        previous_head.recovery_envelope_sha256,
        previous_head.recovery_envelope_sequence,
    )
    intent_recovery = (
        fresh.chain_id,
        intent.current_envelope_id,
        intent.current_envelope_sha256,
        fresh.envelope.sequence,
    )
    fresh_recovery = (
        fresh.chain_id,
        fresh.envelope.envelope_id,
        fresh.envelope.envelope_sha256,
        fresh.envelope.sequence,
    )
    expected_head_inspection = (
        previous_head.last_inspection_id,
        previous_head.last_inspection_sha256,
        previous_head.last_current_material_sha256,
    )
    intent_head_inspection = (
        intent.head_last_inspection_id,
        intent.head_last_inspection_sha256,
        intent.head_last_current_material_sha256,
    )
    last_inspection = last_observation.inspection
    if (
        intent_head_binding != expected_head_binding
        or fresh_head_binding != expected_head_binding
        or intent_recovery != expected_recovery
        or fresh_recovery != expected_recovery
        or intent_head_inspection != expected_head_inspection
        or execution_binding_sha256(fresh.envelope.receipt.binding)
        != previous_head.last_binding_sha256
        or fresh.head_binding.binding_sha256 != previous_head.last_binding_sha256
        or fresh.custody_receipt.custody_receipt_id
        != last_inspection.custody_receipt.custody_receipt_id
        or fresh.custody_receipt.custody_receipt_sha256
        != last_inspection.custody_receipt.custody_receipt_sha256
        or fresh.custody_event.event_id != last_inspection.custody_event.event_id
        or fresh.custody_event.event_sha256
        != last_inspection.custody_event.event_sha256
        or parse_timestamp(intent.prepared_at, "target-health recovery prepared_at")
        < parse_timestamp(previous_head.updated_at, "target-health head updated_at")
    ):
        raise StoreIntegrityError("Target-health resumption source is substituted")

    qualifying: list[TargetHealthGateObservation] = []
    for observation_id, observation_sha256 in zip(
        resumption.qualifying_observation_ids,
        resumption.qualifying_observation_sha256s,
        strict=True,
    ):
        observation = observation_by_id.get(observation_id)
        if (
            observation is None
            or observation.observation_sha256 != observation_sha256
            or observation.subject != resumption.subject
        ):
            raise StoreIntegrityError(
                "Target-health resumption qualifying observation is invalid"
            )
        qualifying.append(observation)
    first, second = qualifying
    transition_by_observation = {
        transition.observation_id: transition
        for transition in prior_transitions
        if transition.observation_id is not None
    }
    first_transition = transition_by_observation.get(first.observation_id)
    second_transition = transition_by_observation.get(second.observation_id)
    if (
        first.classification is not TargetHealthGateClassification.HEALTHY
        or second.classification is not TargetHealthGateClassification.HEALTHY
        or not first.evidence_advanced
        or not second.evidence_advanced
        or second.observation_sequence != first.observation_sequence + 1
        or first.chain_id != second.chain_id
        or second.predecessor_envelope_id != first.envelope_id
        or second.predecessor_envelope_sha256 != first.envelope_sha256
        or second.envelope_sequence != first.envelope_sequence + 1
        or parse_timestamp(second.observed_at, "target-health second observed_at")
        <= parse_timestamp(first.observed_at, "target-health first observed_at")
        or second.global_transition_sequence <= first.global_transition_sequence
        or first_transition is None
        or second_transition is None
        or first_transition.transition_kind
        not in {
            TargetHealthGateTransitionKind.RECOVERY_STARTED,
            TargetHealthGateTransitionKind.RECOVERY_RESTARTED,
        }
        or second_transition.transition_kind
        is not TargetHealthGateTransitionKind.RECOVERY_ADVANCED
        or first_transition.pause_epoch != resumption.pause_epoch
        or second_transition.pause_epoch != resumption.pause_epoch
        or second_transition.transition_sequence
        != first_transition.transition_sequence + 1
        or any(
            transition.transition_kind
            is not TargetHealthGateTransitionKind.RECOVERY_HELD
            or transition.pause_epoch != resumption.pause_epoch
            for transition in prior_transitions
            if transition.transition_sequence > second_transition.transition_sequence
        )
    ):
        raise StoreIntegrityError("Target-health resumption evidence is not exact")


def verify_target_health_gate_store(
    connection: sqlite3.Connection,
    mission_id: str | None = None,
) -> TargetHealthGateStoreVerificationReport:
    """Recompute immutable target-health chains without live source checks."""

    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3.Connection")
    if mission_id is not None and (not isinstance(mission_id, str) or not mission_id):
        raise ValueError("mission_id is invalid")
    _target_tables_available(connection)
    suffix = "" if mission_id is None else " WHERE mission_id = ?"
    parameters: tuple[Any, ...] = () if mission_id is None else (mission_id,)
    observation_rows = connection.execute(
        "SELECT * FROM target_health_gate_observations"
        + suffix
        + " ORDER BY subject_id, observation_sequence",
        parameters,
    ).fetchall()
    resumption_rows = connection.execute(
        "SELECT * FROM target_health_gate_resumptions"
        + suffix
        + " ORDER BY subject_id, pause_epoch",
        parameters,
    ).fetchall()
    transition_rows = connection.execute(
        "SELECT * FROM target_health_gate_transitions"
        + suffix
        + " ORDER BY subject_id, transition_sequence",
        parameters,
    ).fetchall()
    head_rows = connection.execute(
        "SELECT * FROM target_health_gate_heads" + suffix + " ORDER BY subject_id",
        parameters,
    ).fetchall()

    observations = [_observation_from_row(row) for row in observation_rows]
    resumptions = [_resumption_from_row(row) for row in resumption_rows]
    transitions = [_transition_from_row(row) for row in transition_rows]
    heads = [_head_from_row(row) for row in head_rows]
    observation_by_id = {item.observation_id: item for item in observations}
    resumption_by_id = {item.resumption_id: item for item in resumptions}
    if len(observation_by_id) != len(observations):
        raise StoreIntegrityError("Target-health observation identities are not unique")
    if len(resumption_by_id) != len(resumptions):
        raise StoreIntegrityError("Target-health resumption identities are not unique")

    transitions_by_subject: dict[str, list[TargetHealthGateTransition]] = {}
    for transition in transitions:
        transitions_by_subject.setdefault(transition.subject.subject_id, []).append(transition)
    heads_by_subject = {head.subject.subject_id: head for head in heads}
    if len(heads_by_subject) != len(heads):
        raise StoreIntegrityError("Target-health head subjects are not unique")
    history_subjects = {
        item.subject.subject_id for item in (*observations, *resumptions, *transitions)
    }
    if history_subjects != set(heads_by_subject):
        raise StoreIntegrityError("Target-health history and head inventory differ")

    seen_observations: set[str] = set()
    seen_resumptions: set[str] = set()
    for subject_id, subject_transitions in transitions_by_subject.items():
        projected: TargetHealthGateHead | None = None
        for sequence, stored_transition in enumerate(subject_transitions, 1):
            if stored_transition.transition_sequence != sequence:
                raise StoreIntegrityError("Target-health transition sequence is discontinuous")
            observation = None
            resumption = None
            if stored_transition.observation_id is not None:
                observation = observation_by_id.get(stored_transition.observation_id)
                if observation is None:
                    raise StoreIntegrityError("Target-health transition observation is missing")
                if observation.observation_id in seen_observations:
                    raise StoreIntegrityError("Target-health observation is reused")
                seen_observations.add(observation.observation_id)
            else:
                resumption = resumption_by_id.get(stored_transition.resumption_id or "")
                if resumption is None:
                    raise StoreIntegrityError("Target-health transition resumption is missing")
                if resumption.resumption_id in seen_resumptions:
                    raise StoreIntegrityError("Target-health resumption is reused")
                seen_resumptions.add(resumption.resumption_id)
                _verify_historical_resumption_source(
                    resumption,
                    projected,
                    observation_by_id,
                    tuple(subject_transitions[: sequence - 1]),
                )
                _verify_resumption_principal_custody(connection, resumption)
            try:
                expected_transition = build_target_health_gate_transition(
                    previous_head=projected,
                    observation=observation,
                    resumption=resumption,
                )
                if stored_transition != expected_transition:
                    raise StoreIntegrityError(
                        "Stored target-health transition differs from reconstruction"
                    )
                projected = build_target_health_gate_head(
                    transition=stored_transition,
                    observation=observation,
                    resumption=resumption,
                    previous_head=projected,
                )
            except StoreIntegrityError:
                raise
            except (TypeError, ValueError) as exc:
                raise StoreIntegrityError(
                    "Target-health history cannot be reconstructed"
                ) from exc
        if projected is None or projected != heads_by_subject[subject_id]:
            raise StoreIntegrityError("Target-health head differs from reconstructed history")
    if seen_observations != set(observation_by_id):
        raise StoreIntegrityError("Target-health observation history is incomplete")
    if seen_resumptions != set(resumption_by_id):
        raise StoreIntegrityError("Target-health resumption history is incomplete")

    states = [head.latch_state for head in heads]
    missions = {head.subject.mission_id for head in heads}
    return TargetHealthGateStoreVerificationReport(
        mission_id=mission_id,
        mission_count=len(missions),
        subject_count=len(heads),
        observation_count=len(observations),
        resumption_count=len(resumptions),
        transition_count=len(transitions),
        active_count=states.count(TargetHealthGateState.ACTIVE),
        paused_count=states.count(TargetHealthGateState.PAUSED),
        recovery_pending_count=states.count(TargetHealthGateState.RECOVERY_PENDING),
    )


class MissionStoreTargetHealthGateService:
    """Persist fresh target health and consume Control resumption authority.

    ``resume`` is live-current only. A consumed assertion, intent, or replay key
    is rejected even when the retry content is exact. Historical custody is
    available through ``verify_store`` and is never returned as a positive
    resumption result.
    """

    def __init__(
        self,
        store: MissionStore,
        custody: SQLiteTargetHealthCustody,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
        recovery_intent_ttl_seconds: int = DEFAULT_RECOVERY_INTENT_TTL_SECONDS,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(custody, SQLiteTargetHealthCustody):
            raise TypeError("custody must be a SQLiteTargetHealthCustody")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        if (
            isinstance(recovery_intent_ttl_seconds, bool)
            or not isinstance(recovery_intent_ttl_seconds, int)
            or not 1
            <= recovery_intent_ttl_seconds
            <= MAX_RECOVERY_INTENT_TTL_SECONDS
        ):
            raise ValueError("recovery_intent_ttl_seconds is outside its allowed range")
        registry.validate()
        self._store = store
        self._custody = custody
        self._registry = registry
        self._clock = clock or store._clock
        self._recovery_intent_ttl_seconds = recovery_intent_ttl_seconds
        self._authenticated = AuthenticatedMissionControlService(
            store,
            registry,
            clock=self._clock,
        )

    def initialize(self) -> None:
        self._store.initialize()
        with self._store._read_connection() as connection:
            version = self._store._require_schema(connection)
            if version < TARGET_HEALTH_GATE_SCHEMA_VERSION:
                raise StoreIntegrityError("MissionStore target-health gate schema is unavailable")
            verify_target_health_gate_store(connection)

    def observe_current(
        self,
        binding: ExecutionBinding,
    ) -> TargetHealthGateObservationResult:
        """Inspect before locking, then store a final inspection atomically."""

        binding = self._canonical_binding(binding)
        self._inspect_binding(binding)
        try:
            with self._store._write_connection() as connection:
                return self._record_current_observation(connection, binding)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Target-health observation conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist target-health observation") from exc

    def observe_current_in_transaction(
        self,
        connection: sqlite3.Connection,
        binding: ExecutionBinding,
    ) -> TargetHealthGateObservationResult:
        """Inspect twice and append one result in an owned caller transaction."""

        binding = self._canonical_binding(binding)
        self._require_owned_write_transaction(connection)
        self._inspect_binding(binding)
        try:
            return self._record_current_observation(connection, binding)
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Target-health observation conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist target-health observation") from exc

    def load_head(self, binding: ExecutionBinding) -> TargetHealthGateHead | None:
        binding = self._canonical_binding(binding)
        subject = target_health_gate_subject(binding)
        with self._store._read_connection() as connection:
            verify_target_health_gate_store(connection, binding.context_id)
            return _load_head_in_connection(connection, subject)

    def prepare_recovery(
        self,
        binding: ExecutionBinding,
    ) -> TargetHealthGateRecoveryIntent:
        """Prepare a short-lived intent without mutating MissionStore."""

        binding = self._canonical_binding(binding)
        subject = target_health_gate_subject(binding)
        with self._store._read_connection() as connection:
            verify_target_health_gate_store(connection, binding.context_id)
            head = _load_head_in_connection(connection, subject)
            if (
                head is None
                or head.latch_state is not TargetHealthGateState.RECOVERY_PENDING
                or head.recovery_healthy_count != 2
            ):
                raise StoreConflictError("Target-health gate is not recovery eligible")
            qualifying = self._qualifying_observations(connection, head)
            inspection = self._inspect_binding(binding)
            self._require_recovery_inspection(head, inspection)
            prepared = parse_timestamp(
                inspection.inspected_at,
                "target-health recovery prepared_at",
            )
            expires = prepared + timedelta(seconds=self._recovery_intent_ttl_seconds)
            return TargetHealthGateRecoveryIntent(
                subject=head.subject,
                pause_epoch=head.pause_epoch,
                current_head_id=head.head_id,
                current_head_sha256=head.head_sha256,
                qualifying_observation_ids=tuple(item.observation_id for item in qualifying),
                qualifying_observation_sha256s=tuple(
                    item.observation_sha256 for item in qualifying
                ),
                latest_head_binding_id=head.last_head_binding_id,
                latest_head_binding_sha256=head.last_head_binding_sha256,
                global_transition_sequence=head.last_global_transition_sequence,
                current_envelope_id=head.recovery_envelope_id or "",
                current_envelope_sha256=head.recovery_envelope_sha256 or "",
                current_inspection_id=inspection.inspection_id,
                current_inspection_sha256=inspection.inspection_sha256,
                current_material_sha256=inspection.current_material_sha256,
                head_last_inspection_id=head.last_inspection_id,
                head_last_inspection_sha256=head.last_inspection_sha256,
                head_last_current_material_sha256=head.last_current_material_sha256,
                prepared_at=inspection.inspected_at,
                authority_expires_at=expires.astimezone(UTC).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            )

    def resume(
        self,
        assertion: PrincipalAssertion,
        recovery_intent: TargetHealthGateRecoveryIntent,
        *,
        canonical_replay_key_sha256: str,
    ) -> TargetHealthGateResumptionResult:
        """Consume fresh independent Control authority and resume atomically."""

        if type(assertion) is not PrincipalAssertion:
            raise PrincipalAuthenticationError(
                "Target-health resumption requires a signed principal assertion"
            )
        assertion = PrincipalAssertion.from_dict(assertion.to_dict())
        if not isinstance(recovery_intent, TargetHealthGateRecoveryIntent):
            raise TypeError("recovery_intent must be a TargetHealthGateRecoveryIntent")
        try:
            recovery_intent = TargetHealthGateRecoveryIntent.from_dict(
                recovery_intent.to_dict()
            )
        except (TypeError, ValueError) as exc:
            raise StoreIntegrityError("Recovery intent is invalid") from exc
        if (
            not isinstance(canonical_replay_key_sha256, str)
            or len(canonical_replay_key_sha256) != 71
            or not canonical_replay_key_sha256.startswith("sha256:")
        ):
            raise ValueError("canonical_replay_key_sha256 is invalid")

        try:
            with self._store._write_connection() as connection:
                mission_id = recovery_intent.subject.mission_id
                verify_target_health_gate_store(connection, mission_id)
                head = _load_head_in_connection(connection, recovery_intent.subject)
                if (
                    head is None
                    or head.latch_state is not TargetHealthGateState.RECOVERY_PENDING
                    or head.recovery_healthy_count != 2
                    or head.pause_epoch != recovery_intent.pause_epoch
                    or head.head_id != recovery_intent.current_head_id
                    or head.head_sha256 != recovery_intent.current_head_sha256
                ):
                    raise StoreConflictError("Recovery intent no longer binds the gate head")
                qualifying = self._qualifying_observations(connection, head)
                if (
                    tuple(item.observation_id for item in qualifying)
                    != recovery_intent.qualifying_observation_ids
                    or tuple(item.observation_sha256 for item in qualifying)
                    != recovery_intent.qualifying_observation_sha256s
                ):
                    raise StoreConflictError("Recovery intent evidence is no longer exact")
                binding = qualifying[-1].binding
                inspection = self._inspect_binding(binding)
                self._require_resumption_inspection(head, recovery_intent, inspection)
                principal, use_sequence, intent, intent_sha256, assertion_sha256 = (
                    self._verify_resumption_authority(
                        connection,
                        assertion,
                        recovery_intent,
                        canonical_replay_key_sha256,
                        inspection.inspected_at,
                    )
                )
                authorization = {
                    "assertion_id": assertion.assertion_id,
                    "assertion_issuer": assertion.issuer,
                    "assertion_sha256": assertion_sha256,
                    "authority_use_sequence": use_sequence,
                    "canonical_replay_key_sha256": canonical_replay_key_sha256,
                    "decision": "approved",
                    "expires_at": assertion.expires_at,
                    "issued_at": assertion.issued_at,
                    "mission_id": mission_id,
                    "operation": TARGET_HEALTH_GATE_RESUME_OPERATION,
                    "operation_intent_sha256": intent_sha256,
                    "pause_epoch": head.pause_epoch,
                    "principal_profile_id": assertion.profile_id,
                    "principal_subject": assertion.subject,
                    "recovery_intent_id": recovery_intent.recovery_intent_id,
                    "recovery_intent_sha256": recovery_intent.recovery_intent_sha256,
                    "role": "independent_control",
                    "scope_sha256": head.subject.scope_sha256,
                    "target_sha256": head.subject.target_sha256,
                    "tenant_id": head.subject.tenant_id,
                }
                resumption = TargetHealthGateResumption(
                    subject=head.subject,
                    pause_epoch=head.pause_epoch,
                    recovery_intent=recovery_intent,
                    qualifying_observation_ids=recovery_intent.qualifying_observation_ids,
                    qualifying_observation_sha256s=(
                        recovery_intent.qualifying_observation_sha256s
                    ),
                    fresh_inspection=inspection,
                    authorization=authorization,
                    assertion_issuer=assertion.issuer,
                    assertion_id=assertion.assertion_id,
                    assertion_sha256=assertion_sha256,
                    authority_use_sequence=use_sequence,
                    canonical_replay_key_sha256=canonical_replay_key_sha256,
                    operation_intent_sha256=intent_sha256,
                    resumed_at=inspection.inspected_at,
                )
                transition = build_target_health_gate_transition(
                    previous_head=head,
                    resumption=resumption,
                )
                updated_head = build_target_health_gate_head(
                    transition=transition,
                    observation=None,
                    resumption=resumption,
                    previous_head=head,
                )
                self._consume_resumption_authority(
                    connection,
                    principal=principal,
                    assertion=assertion,
                    assertion_sha256=assertion_sha256,
                    use_sequence=use_sequence,
                    operation_intent=intent,
                    operation_intent_sha256=intent_sha256,
                    canonical_replay_key_sha256=canonical_replay_key_sha256,
                    resumption=resumption,
                )
                self._insert_resumption(connection, resumption)
                self._insert_transition(connection, transition)
                self._store_head(connection, updated_head, head)
                verify_target_health_gate_store(connection, mission_id)
                return TargetHealthGateResumptionResult(
                    resumption=resumption,
                    transition=transition,
                    head=updated_head,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Target-health resumption conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist target-health resumption") from exc

    def verify_store(
        self,
        mission_id: str | None = None,
    ) -> TargetHealthGateStoreVerificationReport:
        with self._store._read_connection() as connection:
            return verify_target_health_gate_store(connection, mission_id)

    @staticmethod
    def _canonical_binding(binding: ExecutionBinding) -> ExecutionBinding:
        if not isinstance(binding, ExecutionBinding):
            raise TypeError("binding must be an ExecutionBinding")
        try:
            return ExecutionBinding(**binding.to_dict())
        except (TypeError, ValueError) as exc:
            raise ValueError("binding is invalid") from exc

    def _require_owned_write_transaction(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        if type(connection) is not sqlite3.Connection:
            raise TypeError("connection must be a sqlite3.Connection")
        if not connection.in_transaction:
            raise StoreError(
                "Target-health observation requires an active MissionStore transaction"
            )
        databases = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [item[2] for item in databases if item[1] == "main"]
        if (
            len(main_paths) != 1
            or type(main_paths[0]) is not str
            or not main_paths[0]
            or Path(main_paths[0]).resolve() != self._store.path.resolve()
        ):
            raise StoreError(
                "Target-health observation requires the owned MissionStore transaction"
            )
        query_only = connection.execute("PRAGMA query_only").fetchone()
        if (
            query_only is None
            or len(query_only) != 1
            or type(query_only[0]) is not int
            or query_only[0] != 0
        ):
            raise StoreError(
                "Target-health observation requires a writable MissionStore transaction"
            )
        try:
            connection.execute("UPDATE store_metadata SET value = value WHERE 0")
        except sqlite3.Error as exc:
            raise StoreError(
                "Target-health observation requires a writable MissionStore transaction"
            ) from exc
        version = self._store._require_schema(connection)
        if version < TARGET_HEALTH_GATE_SCHEMA_VERSION:
            raise StoreIntegrityError("MissionStore target-health gate schema is unavailable")

    def _record_current_observation(
        self,
        connection: sqlite3.Connection,
        binding: ExecutionBinding,
    ) -> TargetHealthGateObservationResult:
        self._require_owned_write_transaction(connection)
        verify_target_health_gate_store(connection, binding.context_id)
        subject = target_health_gate_subject(binding)
        previous_head = _load_head_in_connection(connection, subject)
        observation_sequence = (
            1 if previous_head is None else previous_head.observation_count + 1
        )
        previous_observation_sha256 = (
            None if previous_head is None else previous_head.observation_head_sha256
        )
        inspection = self._inspect_binding(
            binding,
            inspection_context_sha256=target_health_gate_inspection_context_sha256(
                subject=subject,
                binding_sha256=execution_binding_sha256(binding),
                observation_sequence=observation_sequence,
                previous_observation_sha256=previous_observation_sha256,
            ),
        )
        evidence_advanced = self._evidence_advanced(previous_head, inspection)
        observation = build_target_health_gate_observation(
            inspection=inspection,
            observation_sequence=observation_sequence,
            previous_observation_sha256=previous_observation_sha256,
            evidence_advanced=evidence_advanced,
            recorded_at=inspection.inspected_at,
        )
        transition = build_target_health_gate_transition(
            previous_head=previous_head,
            observation=observation,
        )
        head = build_target_health_gate_head(
            transition=transition,
            observation=observation,
            resumption=None,
            previous_head=previous_head,
        )
        self._insert_observation(connection, observation)
        self._insert_transition(connection, transition)
        self._store_head(connection, head, previous_head)
        decision = self._decision(observation, head)
        verify_target_health_gate_store(connection, binding.context_id)
        return TargetHealthGateObservationResult(
            observation=observation,
            transition=transition,
            head=head,
            decision=decision,
        )

    def _inspect_binding(
        self,
        binding: ExecutionBinding,
        *,
        inspection_context_sha256: str | None = None,
    ) -> TargetHealthCurrentHeadInspection:
        inspection = self._custody.inspect_unique_current_binding_head(
            tenant_id=binding.tenant_id,
            mission_id=binding.context_id,
            binding_sha256=execution_binding_sha256(binding),
            inspection_context_sha256=inspection_context_sha256,
        )
        if inspection.envelope.receipt.binding != binding:
            raise StoreConflictError("Target-health custody returned a substituted binding")
        return inspection

    @staticmethod
    def _evidence_advanced(
        head: TargetHealthGateHead | None,
        inspection: TargetHealthCurrentHeadInspection,
    ) -> bool:
        receipt = inspection.envelope.receipt
        healthy = (
            receipt.status is TargetHealthStatus.COMPLETED
            and receipt.overall_health is HealthSignalState.HEALTHY
        )
        if not healthy or head is None or head.latch_state is TargetHealthGateState.ACTIVE:
            return False
        if head.latch_state is TargetHealthGateState.PAUSED:
            return True
        if head.recovery_healthy_count == 2:
            return False
        return not (
            inspection.chain_id == head.recovery_chain_id
            and inspection.envelope.envelope_id == head.recovery_envelope_id
            and inspection.envelope.envelope_sha256 == head.recovery_envelope_sha256
        )

    @staticmethod
    def _decision(
        observation: TargetHealthGateObservation,
        head: TargetHealthGateHead,
    ) -> TargetHealthGateDecision:
        permit = (
            head.latch_state is TargetHealthGateState.ACTIVE
            and observation.classification is TargetHealthGateClassification.HEALTHY
        )
        return TargetHealthGateDecision(
            subject=head.subject,
            binding=observation.binding,
            binding_sha256=observation.binding_sha256,
            head=head,
            current_observation=observation,
            evaluated_at=observation.inspected_at,
            status=(
                TargetHealthGateDecisionStatus.PERMIT_HEALTH_GATE_EVALUATION
                if permit
                else TargetHealthGateDecisionStatus.DENY_NEW_TARGET_WORK
            ),
            reason="health_gate_current" if permit else "health_gate_denied",
            pause_effect="none" if permit else "deny_new_target_work",
            resume_effect="none",
        )

    @staticmethod
    def _qualifying_observations(
        connection: sqlite3.Connection,
        head: TargetHealthGateHead,
    ) -> tuple[TargetHealthGateObservation, TargetHealthGateObservation]:
        rows = connection.execute(
            """
            SELECT first.observation_id AS first_id,
                   second.observation_id AS second_id
            FROM target_health_gate_observations AS first
            JOIN target_health_gate_observations AS second
              ON second.subject_id = first.subject_id
             AND second.observation_sequence = first.observation_sequence + 1
            JOIN target_health_gate_transitions AS first_transition
              ON first_transition.observation_id = first.observation_id
             AND first_transition.observation_sha256 = first.observation_sha256
            JOIN target_health_gate_transitions AS second_transition
              ON second_transition.observation_id = second.observation_id
             AND second_transition.observation_sha256 = second.observation_sha256
            WHERE first.subject_id = ?
              AND first.classification = 'healthy'
              AND first.evidence_advanced = 1
              AND second.classification = 'healthy'
              AND second.evidence_advanced = 1
              AND first.chain_id = second.chain_id
              AND second.predecessor_envelope_id = first.envelope_id
              AND second.predecessor_envelope_sha256 = first.envelope_sha256
              AND second.envelope_sequence = first.envelope_sequence + 1
              AND second.observed_at > first.observed_at
              AND second.global_transition_sequence > first.global_transition_sequence
              AND first_transition.pause_epoch = ?
              AND second_transition.pause_epoch = ?
              AND first_transition.transition_kind IN (
                  'recovery_started', 'recovery_restarted'
              )
              AND second_transition.transition_kind = 'recovery_advanced'
              AND second_transition.transition_sequence =
                  first_transition.transition_sequence + 1
              AND second.chain_id = ?
              AND second.envelope_id = ?
              AND second.envelope_sha256 = ?
              AND second.envelope_sequence = ?
              AND NOT EXISTS (
                  SELECT 1 FROM target_health_gate_transitions AS later
                  WHERE later.subject_id = first.subject_id
                    AND later.transition_sequence > second_transition.transition_sequence
                    AND (
                        later.transition_kind != 'recovery_held'
                        OR later.pause_epoch != ?
                    )
              )
            """,
            (
                head.subject.subject_id,
                head.pause_epoch,
                head.pause_epoch,
                head.recovery_chain_id,
                head.recovery_envelope_id,
                head.recovery_envelope_sha256,
                head.recovery_envelope_sequence,
                head.pause_epoch,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise StoreIntegrityError("Recovery qualifying observations are not exact")
        first_row = connection.execute(
            "SELECT * FROM target_health_gate_observations WHERE observation_id = ?",
            (rows[0]["first_id"],),
        ).fetchone()
        second_row = connection.execute(
            "SELECT * FROM target_health_gate_observations WHERE observation_id = ?",
            (rows[0]["second_id"],),
        ).fetchone()
        if first_row is None or second_row is None:
            raise StoreIntegrityError("Recovery qualifying observation is missing")
        return _observation_from_row(first_row), _observation_from_row(second_row)

    @staticmethod
    def _require_recovery_inspection(
        head: TargetHealthGateHead,
        inspection: TargetHealthCurrentHeadInspection,
    ) -> None:
        receipt = inspection.envelope.receipt
        if (
            receipt.status is not TargetHealthStatus.COMPLETED
            or receipt.overall_health is not HealthSignalState.HEALTHY
            or target_health_gate_subject(receipt.binding) != head.subject
            or inspection.head_binding.head_binding_id != head.last_head_binding_id
            or inspection.head_binding.head_binding_sha256
            != head.last_head_binding_sha256
            or inspection.head_binding.global_transition_sequence
            != head.last_global_transition_sequence
            or inspection.chain_id != head.recovery_chain_id
            or inspection.envelope.envelope_id != head.recovery_envelope_id
            or inspection.envelope.envelope_sha256 != head.recovery_envelope_sha256
            or inspection.envelope.sequence != head.recovery_envelope_sequence
            or inspection.inspection_id == head.last_inspection_id
            or inspection.inspection_sha256 == head.last_inspection_sha256
            or inspection.current_material_sha256 == head.last_current_material_sha256
        ):
            raise StoreConflictError("Recovery preparation inspection is not fresh and exact")

    @staticmethod
    def _require_resumption_inspection(
        head: TargetHealthGateHead,
        recovery_intent: TargetHealthGateRecoveryIntent,
        inspection: TargetHealthCurrentHeadInspection,
    ) -> None:
        MissionStoreTargetHealthGateService._require_recovery_inspection(head, inspection)
        if (
            inspection.inspection_id == recovery_intent.current_inspection_id
            or inspection.inspection_sha256 == recovery_intent.current_inspection_sha256
            or inspection.current_material_sha256
            == recovery_intent.current_material_sha256
            or inspection.head_binding.head_binding_id
            != recovery_intent.latest_head_binding_id
            or inspection.head_binding.head_binding_sha256
            != recovery_intent.latest_head_binding_sha256
            or inspection.head_binding.global_transition_sequence
            != recovery_intent.global_transition_sequence
            or inspection.envelope.envelope_id != recovery_intent.current_envelope_id
            or inspection.envelope.envelope_sha256
            != recovery_intent.current_envelope_sha256
        ):
            raise StoreConflictError("Resumption inspection is not fresh and exact")

    def _verify_resumption_authority(
        self,
        connection: sqlite3.Connection,
        assertion: PrincipalAssertion,
        recovery_intent: TargetHealthGateRecoveryIntent,
        replay_key_sha256: str,
        resumed_at: str,
    ) -> tuple[Any, int, dict[str, Any], str, str]:
        if assertion.operation is not PrincipalOperation.TARGET_HEALTH_GATE_RESUME:
            raise PrincipalAuthenticationError("Principal operation cannot resume health gate")
        intent = {
            "idempotency_key_sha256": replay_key_sha256,
            "mission_id": recovery_intent.subject.mission_id,
            "principal_profile_id": assertion.profile_id,
            "recovery_intent_sha256": recovery_intent.recovery_intent_sha256,
            "role": "independent_control",
        }
        intent_sha256 = compute_operation_intent_hash(assertion.operation, intent)
        if assertion.operation_intent_sha256 != intent_sha256:
            raise PrincipalAuthenticationError("Signed resumption intent differs")
        assertion_json = canonical_json(assertion.to_dict())
        assertion_sha256 = sha256_text(assertion_json)
        existing = connection.execute(
            "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
            (assertion.issuer, assertion.assertion_id),
        ).fetchone()
        if existing is not None:
            raise StoreConflictError("Resumption assertion was already consumed")
        conflict = connection.execute(
            "SELECT 1 FROM principal_assertion_uses WHERE mission_id = ? AND operation = ? "
            "AND (domain_request_hash = ? OR idempotency_key_hash = ?) LIMIT 1",
            (
                recovery_intent.subject.mission_id,
                TARGET_HEALTH_GATE_RESUME_OPERATION,
                intent_sha256,
                replay_key_sha256,
            ),
        ).fetchone()
        if conflict is not None:
            raise StoreConflictError("Resumption intent or replay key was already consumed")
        identity, policies, mission, scopes = self._authenticated._verified_mission_state(
            connection,
            recovery_intent.subject.mission_id,
        )
        checked_time = parse_timestamp(resumed_at, "target-health resumption resumed_at")
        policy_hash = identity["trust_policy_hash"]
        if policy_hash is None or str(policy_hash) not in policies:
            raise PrincipalAuthenticationError("Current trust policy is unavailable")
        policy = policies[str(policy_hash)]
        if (
            self._store._trust_policy_high_water_at(policies, checked_time).policy_sha256
            != policy.policy_sha256
        ):
            raise PrincipalAuthenticationError("Resumption trust policy is not current")
        scope_entry = scopes.get(assertion.scope_grant_sha256)
        if scope_entry is None:
            raise PrincipalAuthenticationError("Resumption scope grant is not accepted")
        scope_row, scope_grant = scope_entry
        if (
            parse_timestamp(scope_row["accepted_at"], "resumption scope accepted_at")
            > checked_time
            or self._store._effective_scope_grant_revocation(connection, scope_row)
            is not None
        ):
            raise PrincipalAuthenticationError("Resumption scope grant is not current")
        scope_document_hash = mission.mission.scope_document_hash
        if scope_document_hash is None:
            raise PrincipalAuthenticationError("Mission has no authenticated scope")
        verified_scope = verify_scope_grant(
            scope_grant,
            policy,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=recovery_intent.subject.mission_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.mission.to_dict()["constraints"])
            ),
            expected_operation=PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
            clock=lambda: checked_time,
        )
        principal = verify_principal_assertion(
            assertion,
            policy,
            verified_scope,
            expected_audience=str(identity["audience"]),
            expected_store_id=str(identity["store_id"]),
            expected_mission_id=recovery_intent.subject.mission_id,
            expected_operation=PrincipalOperation.TARGET_HEALTH_GATE_RESUME,
            expected_operation_intent_sha256=intent_sha256,
            clock=lambda: checked_time,
        )
        self._require_independent_control(
            connection,
            mission,
            assertion,
            resumed_at,
        )
        ledger = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (recovery_intent.subject.mission_id,),
        ).fetchone()
        if ledger is None:
            raise StoreIntegrityError("Mission principal ledger is missing")
        if parse_timestamp(ledger["updated_at"], "principal ledger updated_at") > checked_time:
            raise PrincipalAuthenticationError("Resumption clock precedes principal ledger")
        return (
            principal,
            int(ledger["assertion_count"]) + 1,
            intent,
            intent_sha256,
            assertion_sha256,
        )

    def _require_independent_control(
        self,
        connection: sqlite3.Connection,
        mission: Any,
        assertion: PrincipalAssertion,
        checked_at: str,
    ) -> None:
        try:
            profile = self._registry.profile(assertion.profile_id)
        except Exception as exc:
            raise PrincipalAuthenticationError(
                "Resumption principal has no current registry profile"
            ) from exc
        policy_row = connection.execute(
            "SELECT policy_json FROM collaboration_mission_policy_commits "
            "WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1",
            (mission.mission.mission_id,),
        ).fetchone()
        if policy_row is None:
            raise PrincipalAuthenticationError(
                "Resumption requires current collaboration Control"
            )
        policy = _json_object(policy_row["policy_json"], "collaboration policy")
        approvals = policy.get("approval_bindings")
        binding = (
            None
            if not isinstance(approvals, Mapping)
            else approvals.get("independent_control")
        )
        if not isinstance(binding, Mapping):
            raise StoreIntegrityError("Collaboration Control binding is invalid")
        bound_rows = connection.execute(
            "SELECT issuer, subject FROM principal_assertion_uses WHERE mission_id = ? "
            "AND assertion_id = ? AND assertion_hash = ? AND principal_profile_id = ?",
            (
                mission.mission.mission_id,
                binding.get("assertion_id"),
                binding.get("assertion_sha256"),
                binding.get("profile_id"),
            ),
        ).fetchall()
        if len(bound_rows) != 1:
            raise PrincipalAuthenticationError(
                "Collaboration Control binding has no authenticated principal"
            )
        bound = bound_rows[0]
        effective_at = policy.get("effective_at")
        expires_at = policy.get("expires_at")
        current_window = (
            isinstance(effective_at, str)
            and isinstance(expires_at, str)
            and effective_at <= checked_at < expires_at
        )
        valid = (
            current_window
            and assertion.profile_id == binding.get("profile_id")
            and assertion.issuer == bound["issuer"]
            and assertion.subject == bound["subject"]
            and assertion.issuer != assertion.subject
            and assertion.profile_id in mission.control_profile_ids
            and profile.status in {"defined", "qualified"}
            and profile.kind is ProfileKind.SHARED
            and profile.category == "independent control"
        )
        if not valid:
            raise PrincipalAuthenticationError(
                "Resumption principal lacks current independent Control entitlement"
            )

    def _consume_resumption_authority(
        self,
        connection: sqlite3.Connection,
        *,
        principal: Any,
        assertion: PrincipalAssertion,
        assertion_sha256: str,
        use_sequence: int,
        operation_intent: Mapping[str, Any],
        operation_intent_sha256: str,
        canonical_replay_key_sha256: str,
        resumption: TargetHealthGateResumption,
    ) -> None:
        effect = {
            "effect_id": resumption.resumption_id,
            "effect_kind": TARGET_HEALTH_GATE_RESUME_OPERATION,
            "payload": {
                "recovery_intent_id": resumption.recovery_intent.recovery_intent_id,
                "result_id": resumption.resumption_id,
                "result_sha256": resumption.resumption_sha256,
                "subject_id": resumption.subject.subject_id,
            },
            "recorded_at": resumption.resumed_at,
            "schema_version": 1,
        }
        effect_json = canonical_json(effect)
        effect_hash = sha256_text(effect_json)
        effects_hash = principal_assertion_effects_hash((effect_hash,))
        ledger = connection.execute(
            "SELECT * FROM mission_principal_ledgers WHERE mission_id = ?",
            (resumption.subject.mission_id,),
        ).fetchone()
        if ledger is None or int(ledger["assertion_count"]) + 1 != use_sequence:
            raise StoreConflictError("Mission principal ledger changed during resumption")
        previous_hash = ledger["head_hash"]
        assertion_json = canonical_json(assertion.to_dict())
        entry = self._authenticated._assertion_entry(
            principal=principal,
            assertion=assertion,
            mission_id=resumption.subject.mission_id,
            use_sequence=use_sequence,
            assertion_hash=assertion_sha256,
            operation_intent_json=canonical_json(dict(operation_intent)),
            signed_intent_hash=operation_intent_sha256,
            domain_request_hash=operation_intent_sha256,
            idempotency_key_hash=canonical_replay_key_sha256,
            consumed_at=resumption.resumed_at,
            effects_hash=effects_hash,
            previous_hash=previous_hash,
        )
        entry_hash = principal_assertion_entry_hash(entry)
        self._authenticated._insert_assertion_use(
            connection,
            assertion_json=assertion_json,
            entry=entry,
            entry_hash=entry_hash,
        )
        connection.execute(
            """
            INSERT INTO principal_assertion_effects(
                issuer, assertion_id, mission_id, effect_index,
                effect_kind, effect_id, effect_json, effect_hash, recorded_at
            ) VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
            """,
            (
                assertion.issuer,
                assertion.assertion_id,
                resumption.subject.mission_id,
                TARGET_HEALTH_GATE_RESUME_OPERATION,
                resumption.resumption_id,
                effect_json,
                effect_hash,
                resumption.resumed_at,
            ),
        )
        cursor = connection.execute(
            "UPDATE mission_principal_ledgers SET head_hash = ?, "
            "assertion_count = assertion_count + 1, effect_count = effect_count + 1, "
            "updated_at = ? WHERE mission_id = ? AND assertion_count = ? AND head_hash = ?",
            (
                entry_hash,
                resumption.resumed_at,
                resumption.subject.mission_id,
                use_sequence - 1,
                previous_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError("Mission principal ledger changed during resumption")

    @staticmethod
    def _insert_observation(
        connection: sqlite3.Connection,
        observation: TargetHealthGateObservation,
    ) -> None:
        connection.execute(
            "INSERT INTO target_health_gate_observations VALUES("
            + ",".join("?" for _ in range(32))
            + ")",
            (
                observation.observation_id,
                observation.observation_sha256,
                observation.subject.subject_id,
                observation.subject.tenant_id,
                observation.subject.mission_id,
                observation.subject.scope_sha256,
                observation.subject.target_sha256,
                observation.observation_sequence,
                observation.previous_observation_sha256,
                observation.binding_sha256,
                gate_canonical_json(observation.binding.to_dict()),
                observation.inspection_id,
                observation.inspection_sha256,
                gate_canonical_json(observation.inspection.to_dict()),
                observation.head_binding_id,
                observation.head_binding_sha256,
                observation.global_transition_sequence,
                observation.chain_id,
                observation.envelope_id,
                observation.envelope_sha256,
                observation.envelope_sequence,
                observation.predecessor_envelope_id,
                observation.predecessor_envelope_sha256,
                observation.receipt_id,
                observation.receipt_sha256,
                observation.receipt_status,
                observation.overall_health,
                observation.classification.value,
                int(observation.evidence_advanced),
                observation.observed_at,
                observation.inspected_at,
                observation.recorded_at,
            ),
        )

    @staticmethod
    def _insert_resumption(
        connection: sqlite3.Connection,
        resumption: TargetHealthGateResumption,
    ) -> None:
        connection.execute(
            "INSERT INTO target_health_gate_resumptions VALUES("
            + ",".join("?" for _ in range(25))
            + ")",
            (
                resumption.resumption_id,
                resumption.resumption_sha256,
                resumption.subject.subject_id,
                resumption.subject.tenant_id,
                resumption.subject.mission_id,
                resumption.subject.scope_sha256,
                resumption.subject.target_sha256,
                resumption.pause_epoch,
                resumption.recovery_intent.recovery_intent_id,
                resumption.recovery_intent.recovery_intent_sha256,
                gate_canonical_json(resumption.recovery_intent.to_dict()),
                gate_canonical_json(list(resumption.qualifying_observation_ids)),
                gate_canonical_json(list(resumption.qualifying_observation_sha256s)),
                resumption.fresh_inspection_id,
                resumption.fresh_inspection_sha256,
                resumption.fresh_head_binding_sha256,
                gate_canonical_json(dict(resumption.authorization)),
                resumption.assertion_issuer,
                resumption.assertion_id,
                resumption.assertion_sha256,
                resumption.authority_use_sequence,
                resumption.canonical_replay_key_sha256,
                resumption.operation_intent_sha256,
                gate_canonical_json(resumption.to_dict()),
                resumption.resumed_at,
            ),
        )

    @staticmethod
    def _insert_transition(
        connection: sqlite3.Connection,
        transition: TargetHealthGateTransition,
    ) -> None:
        connection.execute(
            "INSERT INTO target_health_gate_transitions VALUES("
            + ",".join("?" for _ in range(20))
            + ")",
            (
                transition.transition_id,
                transition.transition_sha256,
                transition.subject.subject_id,
                transition.subject.tenant_id,
                transition.subject.mission_id,
                transition.subject.scope_sha256,
                transition.subject.target_sha256,
                transition.transition_sequence,
                transition.previous_transition_sha256,
                transition.transition_kind.value,
                None if transition.from_state is None else transition.from_state.value,
                transition.to_state.value,
                transition.pause_epoch,
                transition.recovery_healthy_count,
                transition.observation_id,
                transition.observation_sha256,
                transition.resumption_id,
                transition.resumption_sha256,
                gate_canonical_json(transition.to_dict()),
                transition.occurred_at,
            ),
        )

    @staticmethod
    def _store_head(
        connection: sqlite3.Connection,
        head: TargetHealthGateHead,
        previous_head: TargetHealthGateHead | None,
    ) -> None:
        values = (
            head.subject.subject_id,
            head.head_id,
            head.head_sha256,
            head.subject.tenant_id,
            head.subject.mission_id,
            head.subject.scope_sha256,
            head.subject.target_sha256,
            head.latch_state.value,
            head.pause_epoch,
            head.observation_count,
            head.observation_head_sha256,
            head.transition_count,
            head.transition_head_sha256,
            head.resumption_count,
            head.recovery_healthy_count,
            head.recovery_chain_id,
            head.recovery_envelope_id,
            head.recovery_envelope_sha256,
            head.recovery_envelope_sequence,
            head.recovery_observed_at,
            head.last_observation_id,
            head.last_observation_sha256,
            head.last_binding_sha256,
            head.last_inspection_id,
            head.last_inspection_sha256,
            head.last_head_binding_id,
            head.last_head_binding_sha256,
            head.last_global_transition_sequence,
            head.last_current_material_sha256,
            head.last_adverse_observation_id,
            head.last_adverse_observation_sha256,
            head.last_resumption_id,
            head.last_resumption_sha256,
            head.version,
            head.updated_at,
        )
        if previous_head is None:
            connection.execute(
                "INSERT INTO target_health_gate_heads VALUES("
                + ",".join("?" for _ in values)
                + ")",
                values,
            )
            return
        columns = (
            "head_id",
            "head_sha256",
            "tenant_id",
            "mission_id",
            "scope_sha256",
            "target_sha256",
            "latch_state",
            "pause_epoch",
            "observation_count",
            "observation_head_sha256",
            "transition_count",
            "transition_head_sha256",
            "resumption_count",
            "recovery_healthy_count",
            "recovery_chain_id",
            "recovery_envelope_id",
            "recovery_envelope_sha256",
            "recovery_envelope_sequence",
            "recovery_observed_at",
            "last_observation_id",
            "last_observation_sha256",
            "last_binding_sha256",
            "last_inspection_id",
            "last_inspection_sha256",
            "last_head_binding_id",
            "last_head_binding_sha256",
            "last_global_transition_sequence",
            "last_current_material_sha256",
            "last_adverse_observation_id",
            "last_adverse_observation_sha256",
            "last_resumption_id",
            "last_resumption_sha256",
            "version",
            "updated_at",
        )
        cursor = connection.execute(
            "UPDATE target_health_gate_heads SET "
            + ",".join(f"{column} = ?" for column in columns)
            + " WHERE subject_id = ? AND version = ? AND head_sha256 = ?",
            (
                *values[1:],
                head.subject.subject_id,
                previous_head.version,
                previous_head.head_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise StoreConflictError("Target-health gate head changed")


__all__ = [
    "MissionStoreTargetHealthGateService",
    "TargetHealthGateObservationResult",
    "TargetHealthGateResumptionResult",
    "TargetHealthGateStoreVerificationReport",
    "verify_target_health_gate_store",
]

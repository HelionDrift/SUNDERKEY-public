"""Schema 35 durable target-health latch persistence coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from sunderkey.registry import load_registry
from sunderkey.store import (
    ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION,
    AUTHENTICATED_ACTION_EXECUTION_SCHEMA_VERSION,
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V34,
    EXPECTED_SCHEMA_MANIFEST_V35,
    EXPECTED_SCHEMA_MANIFEST_V39,
    SCHEMA_VERSION,
    TARGET_HEALTH_GATE_SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
)

from .test_store import REGISTRY_PATH, remove_schema_v36_objects


def digest(character: str) -> str:
    """Return one syntactically valid deterministic digest."""

    return "sha256:" + character * 64


def canonical(value: object) -> str:
    """Return deterministic compact JSON for schema fixtures."""

    return json.dumps(value, separators=(",", ":"), sort_keys=True)

V35_TABLE_COLUMNS = {
    "target_health_gate_observations": (
        "observation_id",
        "observation_sha256",
        "subject_id",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "observation_sequence",
        "previous_observation_sha256",
        "binding_sha256",
        "binding_json",
        "inspection_id",
        "inspection_sha256",
        "inspection_json",
        "head_binding_id",
        "head_binding_sha256",
        "global_transition_sequence",
        "chain_id",
        "envelope_id",
        "envelope_sha256",
        "envelope_sequence",
        "predecessor_envelope_id",
        "predecessor_envelope_sha256",
        "receipt_id",
        "receipt_sha256",
        "receipt_status",
        "overall_health",
        "classification",
        "evidence_advanced",
        "observed_at",
        "inspected_at",
        "recorded_at",
    ),
    "target_health_gate_transitions": (
        "transition_id",
        "transition_sha256",
        "subject_id",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "transition_sequence",
        "previous_transition_sha256",
        "transition_kind",
        "from_state",
        "to_state",
        "pause_epoch",
        "recovery_healthy_count",
        "observation_id",
        "observation_sha256",
        "resumption_id",
        "resumption_sha256",
        "transition_json",
        "occurred_at",
    ),
    "target_health_gate_heads": (
        "subject_id",
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
    ),
    "target_health_gate_resumptions": (
        "resumption_id",
        "resumption_sha256",
        "subject_id",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "pause_epoch",
        "recovery_intent_id",
        "recovery_intent_sha256",
        "recovery_intent_json",
        "qualifying_observation_ids_json",
        "qualifying_observation_sha256s_json",
        "fresh_inspection_id",
        "fresh_inspection_sha256",
        "fresh_head_binding_sha256",
        "authorization_json",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "authority_use_sequence",
        "canonical_replay_key_sha256",
        "operation_intent_sha256",
        "resumption_json",
        "resumed_at",
    ),
}

V35_INDEXES = {
    "target_health_gate_heads_mission_state_idx",
    "target_health_gate_observations_classification_idx",
    "target_health_gate_observations_mission_subject_idx",
    "target_health_gate_resumptions_mission_subject_idx",
    "target_health_gate_transitions_kind_idx",
    "target_health_gate_transitions_mission_subject_idx",
}

V35_TRIGGERS = {
    "principal_target_health_gate_resume_effect_guard",
    "principal_target_health_gate_resume_replay_key_guard",
    "target_health_gate_heads_insert_guard",
    "target_health_gate_heads_no_delete",
    "target_health_gate_heads_update_guard",
    "target_health_gate_observations_immutable",
    "target_health_gate_observations_insert_guard",
    "target_health_gate_observations_no_delete",
    "target_health_gate_resumptions_immutable",
    "target_health_gate_resumptions_insert_guard",
    "target_health_gate_resumptions_no_delete",
    "target_health_gate_transitions_immutable",
    "target_health_gate_transitions_insert_guard",
    "target_health_gate_transitions_no_delete",
}


def insert_mapping(
    connection: sqlite3.Connection,
    table: str,
    values: dict[str, object],
) -> None:
    """Insert one deterministic mapping into a test table."""

    columns = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    connection.execute(
        f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})',
        tuple(values.values()),
    )


def observation_values(**overrides: object) -> dict[str, object]:
    """Return one valid first healthy observation row."""

    values: dict[str, object] = {
        "observation_id": "THO-1",
        "observation_sha256": "sha256:observation-1",
        "subject_id": "THS-1",
        "tenant_id": "tenant-1",
        "mission_id": "MISSION-1",
        "scope_sha256": "sha256:scope-1",
        "target_sha256": "sha256:target-1",
        "observation_sequence": 1,
        "previous_observation_sha256": None,
        "binding_sha256": "sha256:binding-1",
        "inspection_id": "THI-1",
        "inspection_sha256": "sha256:inspection-1",
        "head_binding_id": "THB-1",
        "head_binding_sha256": "sha256:head-binding-1",
        "global_transition_sequence": 1,
        "chain_id": "THC-1",
        "envelope_id": "THE-1",
        "envelope_sha256": "sha256:envelope-1",
        "envelope_sequence": 1,
        "predecessor_envelope_id": None,
        "predecessor_envelope_sha256": None,
        "receipt_id": "THR-1",
        "receipt_sha256": "sha256:receipt-1",
        "receipt_status": "completed",
        "overall_health": "healthy",
        "classification": "healthy",
        "evidence_advanced": 0,
        "observed_at": "2026-01-01T00:00:00Z",
        "inspected_at": "2026-01-01T00:00:01Z",
        "recorded_at": "2026-01-01T00:00:02Z",
    }
    values.update(overrides)
    binding = {
        "context_id": values["mission_id"],
        "scope_sha256": values["scope_sha256"],
        "target_sha256": values["target_sha256"],
        "tenant_id": values["tenant_id"],
    }
    if "binding_json" not in overrides:
        values["binding_json"] = canonical(binding)
    if "inspection_json" not in overrides:
        values["inspection_json"] = canonical(
            {
                "chain_id": values["chain_id"],
                "current_material_sha256": (
                    "sha256:material-" + str(values["observation_sequence"])
                ),
                "custody_event": {
                    "event_id": "THCE-" + str(values["observation_sequence"]),
                    "event_sha256": (
                        "sha256:event-" + str(values["observation_sequence"])
                    ),
                },
                "custody_receipt": {
                    "custody_receipt_id": (
                        "THCR-" + str(values["observation_sequence"])
                    ),
                    "custody_receipt_sha256": (
                        "sha256:custody-receipt-" + str(values["observation_sequence"])
                    ),
                },
                "envelope": {
                    "envelope_id": values["envelope_id"],
                    "envelope_sha256": values["envelope_sha256"],
                    "predecessor_envelope_id": values["predecessor_envelope_id"],
                    "predecessor_envelope_sha256": values[
                        "predecessor_envelope_sha256"
                    ],
                    "receipt": {
                        "binding": binding,
                        "binding_sha256": values["binding_sha256"],
                        "observed_at": values["observed_at"],
                        "overall_health": values["overall_health"],
                        "receipt_id": values["receipt_id"],
                        "receipt_sha256": values["receipt_sha256"],
                        "status": values["receipt_status"],
                    },
                    "sequence": values["envelope_sequence"],
                },
                "head_binding": {
                    "binding_sha256": values["binding_sha256"],
                    "chain_head_envelope_id": values["envelope_id"],
                    "chain_head_envelope_sha256": values["envelope_sha256"],
                    "chain_head_sequence": values["envelope_sequence"],
                    "chain_id": values["chain_id"],
                    "global_transition_sequence": values[
                        "global_transition_sequence"
                    ],
                    "head_binding_id": values["head_binding_id"],
                    "head_binding_sha256": values["head_binding_sha256"],
                },
                "inspected_at": values["inspected_at"],
                "inspection_id": values["inspection_id"],
                "inspection_sha256": values["inspection_sha256"],
                "inspection_context_sha256": digest("c"),
                "mission_id": values["mission_id"],
                "tenant_id": values["tenant_id"],
                "verification": {
                    "binding_sha256": values["binding_sha256"],
                    "mode": "current",
                },
            }
        )
    return values


def transition_values(**overrides: object) -> dict[str, object]:
    """Return one valid initialized-active transition row."""

    values: dict[str, object] = {
        "transition_id": "THT-1",
        "transition_sha256": "sha256:transition-1",
        "subject_id": "THS-1",
        "tenant_id": "tenant-1",
        "mission_id": "MISSION-1",
        "scope_sha256": "sha256:scope-1",
        "target_sha256": "sha256:target-1",
        "transition_sequence": 1,
        "previous_transition_sha256": None,
        "transition_kind": "initialized_active",
        "from_state": None,
        "to_state": "active",
        "pause_epoch": 0,
        "recovery_healthy_count": 0,
        "observation_id": "THO-1",
        "observation_sha256": "sha256:observation-1",
        "resumption_id": None,
        "resumption_sha256": None,
        "occurred_at": "2026-01-01T00:00:02Z",
    }
    values.update(overrides)
    if "transition_json" not in overrides:
        values["transition_json"] = canonical(
            {
                "from_state": values["from_state"],
                "observation_id": values["observation_id"],
                "observation_sha256": values["observation_sha256"],
                "occurred_at": values["occurred_at"],
                "pause_epoch": values["pause_epoch"],
                "previous_transition_sha256": values[
                    "previous_transition_sha256"
                ],
                "recovery_healthy_count": values["recovery_healthy_count"],
                "resumption_id": values["resumption_id"],
                "resumption_sha256": values["resumption_sha256"],
                "subject": {
                    "mission_id": values["mission_id"],
                    "scope_sha256": values["scope_sha256"],
                    "subject_id": values["subject_id"],
                    "target_sha256": values["target_sha256"],
                    "tenant_id": values["tenant_id"],
                },
                "to_state": values["to_state"],
                "transition_id": values["transition_id"],
                "transition_kind": values["transition_kind"],
                "transition_sequence": values["transition_sequence"],
                "transition_sha256": values["transition_sha256"],
            }
        )
    return values


def head_values(**overrides: object) -> dict[str, object]:
    """Return one valid initialized-active head row."""

    values: dict[str, object] = {
        "subject_id": "THS-1",
        "head_id": "THGH-" + "1" * 32,
        "head_sha256": digest("1"),
        "tenant_id": "tenant-1",
        "mission_id": "MISSION-1",
        "scope_sha256": "sha256:scope-1",
        "target_sha256": "sha256:target-1",
        "latch_state": "active",
        "pause_epoch": 0,
        "observation_count": 1,
        "observation_head_sha256": "sha256:observation-1",
        "transition_count": 1,
        "transition_head_sha256": "sha256:transition-1",
        "resumption_count": 0,
        "recovery_healthy_count": 0,
        "recovery_chain_id": None,
        "recovery_envelope_id": None,
        "recovery_envelope_sha256": None,
        "recovery_envelope_sequence": None,
        "recovery_observed_at": None,
        "last_observation_id": "THO-1",
        "last_observation_sha256": "sha256:observation-1",
        "last_binding_sha256": "sha256:binding-1",
        "last_inspection_id": "THI-1",
        "last_inspection_sha256": "sha256:inspection-1",
        "last_head_binding_id": "THB-1",
        "last_head_binding_sha256": "sha256:head-binding-1",
        "last_global_transition_sequence": 1,
        "last_current_material_sha256": "sha256:material-1",
        "last_adverse_observation_id": None,
        "last_adverse_observation_sha256": None,
        "last_resumption_id": None,
        "last_resumption_sha256": None,
        "version": 1,
        "updated_at": "2026-01-01T00:00:02Z",
    }
    values.update(overrides)
    return values


def update_head(
    connection: sqlite3.Connection,
    **overrides: object,
) -> None:
    """Replace one head with a complete deterministic next version."""

    values = head_values(**overrides)
    subject_id = values.pop("subject_id")
    assignments = ", ".join(f'"{column}" = ?' for column in values)
    connection.execute(
        f'UPDATE target_health_gate_heads SET {assignments} WHERE subject_id = ?',
        (*values.values(), subject_id),
    )


def insert_initial_active_gate(connection: sqlite3.Connection) -> None:
    """Insert one internally consistent active gate history."""

    insert_mapping(connection, "target_health_gate_observations", observation_values())
    insert_mapping(connection, "target_health_gate_transitions", transition_values())
    insert_mapping(connection, "target_health_gate_heads", head_values())


def advance_gate_to_first_recovery_observation(
    connection: sqlite3.Connection,
) -> None:
    """Advance one active gate through pause to recovery count one."""

    insert_initial_active_gate(connection)
    insert_mapping(
        connection,
        "target_health_gate_observations",
        observation_values(
            observation_id="THO-2",
            observation_sha256="sha256:observation-2",
            observation_sequence=2,
            previous_observation_sha256="sha256:observation-1",
            inspection_id="THI-2",
            inspection_sha256="sha256:inspection-2",
            head_binding_id="THB-2",
            head_binding_sha256="sha256:head-binding-2",
            global_transition_sequence=2,
            envelope_id="THE-2",
            envelope_sha256="sha256:envelope-2",
            envelope_sequence=2,
            predecessor_envelope_id="THE-1",
            predecessor_envelope_sha256="sha256:envelope-1",
            receipt_id="THR-2",
            receipt_sha256="sha256:receipt-2",
            overall_health="unhealthy",
            classification="adverse",
            observed_at="2026-01-01T00:01:00Z",
            inspected_at="2026-01-01T00:01:01Z",
            recorded_at="2026-01-01T00:01:02Z",
        ),
    )
    insert_mapping(
        connection,
        "target_health_gate_transitions",
        transition_values(
            transition_id="THT-2",
            transition_sha256="sha256:transition-2",
            transition_sequence=2,
            previous_transition_sha256="sha256:transition-1",
            transition_kind="pause_asserted",
            from_state="active",
            to_state="paused",
            pause_epoch=1,
            observation_id="THO-2",
            observation_sha256="sha256:observation-2",
            occurred_at="2026-01-01T00:01:02Z",
        ),
    )
    update_head(
        connection,
        head_id="THGH-" + "2" * 32,
        head_sha256=digest("2"),
        latch_state="paused",
        pause_epoch=1,
        observation_count=2,
        observation_head_sha256="sha256:observation-2",
        transition_count=2,
        transition_head_sha256="sha256:transition-2",
        last_observation_id="THO-2",
        last_observation_sha256="sha256:observation-2",
        last_inspection_id="THI-2",
        last_inspection_sha256="sha256:inspection-2",
        last_head_binding_id="THB-2",
        last_head_binding_sha256="sha256:head-binding-2",
        last_global_transition_sequence=2,
        last_current_material_sha256="sha256:material-2",
        last_adverse_observation_id="THO-2",
        last_adverse_observation_sha256="sha256:observation-2",
        version=2,
        updated_at="2026-01-01T00:01:02Z",
    )
    insert_mapping(
        connection,
        "target_health_gate_observations",
        observation_values(
            observation_id="THO-3",
            observation_sha256="sha256:observation-3",
            observation_sequence=3,
            previous_observation_sha256="sha256:observation-2",
            inspection_id="THI-3",
            inspection_sha256="sha256:inspection-3",
            head_binding_id="THB-3",
            head_binding_sha256="sha256:head-binding-3",
            global_transition_sequence=3,
            envelope_id="THE-3",
            envelope_sha256="sha256:envelope-3",
            envelope_sequence=3,
            predecessor_envelope_id="THE-2",
            predecessor_envelope_sha256="sha256:envelope-2",
            receipt_id="THR-3",
            receipt_sha256="sha256:receipt-3",
            evidence_advanced=1,
            observed_at="2026-01-01T00:02:00Z",
            inspected_at="2026-01-01T00:02:01Z",
            recorded_at="2026-01-01T00:02:02Z",
        ),
    )
    insert_mapping(
        connection,
        "target_health_gate_transitions",
        transition_values(
            transition_id="THT-3",
            transition_sha256="sha256:transition-3",
            transition_sequence=3,
            previous_transition_sha256="sha256:transition-2",
            transition_kind="recovery_started",
            from_state="paused",
            to_state="recovery_pending",
            pause_epoch=1,
            recovery_healthy_count=1,
            observation_id="THO-3",
            observation_sha256="sha256:observation-3",
            occurred_at="2026-01-01T00:02:02Z",
        ),
    )
    update_head(
        connection,
        head_id="THGH-" + "3" * 32,
        head_sha256=digest("3"),
        latch_state="recovery_pending",
        pause_epoch=1,
        observation_count=3,
        observation_head_sha256="sha256:observation-3",
        transition_count=3,
        transition_head_sha256="sha256:transition-3",
        recovery_healthy_count=1,
        recovery_chain_id="THC-1",
        recovery_envelope_id="THE-3",
        recovery_envelope_sha256="sha256:envelope-3",
        recovery_envelope_sequence=3,
        recovery_observed_at="2026-01-01T00:02:00Z",
        last_observation_id="THO-3",
        last_observation_sha256="sha256:observation-3",
        last_inspection_id="THI-3",
        last_inspection_sha256="sha256:inspection-3",
        last_head_binding_id="THB-3",
        last_head_binding_sha256="sha256:head-binding-3",
        last_global_transition_sequence=3,
        last_current_material_sha256="sha256:material-3",
        last_adverse_observation_id="THO-2",
        last_adverse_observation_sha256="sha256:observation-2",
        version=3,
        updated_at="2026-01-01T00:02:02Z",
    )


def advance_gate_to_recovery_ready(connection: sqlite3.Connection) -> None:
    """Advance one gate to two exact healthy recovery observations."""

    advance_gate_to_first_recovery_observation(connection)
    insert_mapping(
        connection,
        "target_health_gate_observations",
        observation_values(
            observation_id="THO-4",
            observation_sha256="sha256:observation-4",
            observation_sequence=4,
            previous_observation_sha256="sha256:observation-3",
            inspection_id="THI-4",
            inspection_sha256="sha256:inspection-4",
            head_binding_id="THB-4",
            head_binding_sha256="sha256:head-binding-4",
            global_transition_sequence=4,
            envelope_id="THE-4",
            envelope_sha256="sha256:envelope-4",
            envelope_sequence=4,
            predecessor_envelope_id="THE-3",
            predecessor_envelope_sha256="sha256:envelope-3",
            receipt_id="THR-4",
            receipt_sha256="sha256:receipt-4",
            evidence_advanced=1,
            observed_at="2026-01-01T00:03:00Z",
            inspected_at="2026-01-01T00:03:01Z",
            recorded_at="2026-01-01T00:03:02Z",
        ),
    )
    insert_mapping(
        connection,
        "target_health_gate_transitions",
        transition_values(
            transition_id="THT-4",
            transition_sha256="sha256:transition-4",
            transition_sequence=4,
            previous_transition_sha256="sha256:transition-3",
            transition_kind="recovery_advanced",
            from_state="recovery_pending",
            to_state="recovery_pending",
            pause_epoch=1,
            recovery_healthy_count=2,
            observation_id="THO-4",
            observation_sha256="sha256:observation-4",
            occurred_at="2026-01-01T00:03:02Z",
        ),
    )
    update_head(
        connection,
        head_id="THGH-" + "4" * 32,
        head_sha256=digest("4"),
        latch_state="recovery_pending",
        pause_epoch=1,
        observation_count=4,
        observation_head_sha256="sha256:observation-4",
        transition_count=4,
        transition_head_sha256="sha256:transition-4",
        recovery_healthy_count=2,
        recovery_chain_id="THC-1",
        recovery_envelope_id="THE-4",
        recovery_envelope_sha256="sha256:envelope-4",
        recovery_envelope_sequence=4,
        recovery_observed_at="2026-01-01T00:03:00Z",
        last_observation_id="THO-4",
        last_observation_sha256="sha256:observation-4",
        last_inspection_id="THI-4",
        last_inspection_sha256="sha256:inspection-4",
        last_head_binding_id="THB-4",
        last_head_binding_sha256="sha256:head-binding-4",
        last_global_transition_sequence=4,
        last_current_material_sha256="sha256:material-4",
        last_adverse_observation_id="THO-2",
        last_adverse_observation_sha256="sha256:observation-2",
        version=4,
        updated_at="2026-01-01T00:03:02Z",
    )


def resumption_values(*, reuse_head_inspection: bool = False) -> dict[str, object]:
    """Return one state-valid resumption with intentionally absent authority."""

    recovery_intent = {
        "authority_expires_at": "2026-01-01T00:10:00Z",
        "current_envelope_id": "THE-4",
        "current_envelope_sha256": "sha256:envelope-4",
        "current_head_id": "THGH-" + "4" * 32,
        "current_head_sha256": digest("4"),
        "current_inspection_id": "THI-preparation",
        "current_inspection_sha256": "sha256:inspection-preparation",
        "current_material_sha256": "sha256:material-preparation",
        "global_transition_sequence": 4,
        "head_last_current_material_sha256": "sha256:material-4",
        "head_last_inspection_id": "THI-4",
        "head_last_inspection_sha256": "sha256:inspection-4",
        "latest_head_binding_id": "THB-4",
        "latest_head_binding_sha256": "sha256:head-binding-4",
        "pause_epoch": 1,
        "prepared_at": "2026-01-01T00:04:00Z",
        "qualifying_observation_ids": ["THO-3", "THO-4"],
        "qualifying_observation_sha256s": [
            "sha256:observation-3",
            "sha256:observation-4",
        ],
        "recovery_intent_id": "THGI-1",
        "recovery_intent_sha256": "sha256:recovery-intent-1",
        "subject": {
            "mission_id": "MISSION-1",
            "scope_sha256": "sha256:scope-1",
            "subject_id": "THS-1",
            "target_sha256": "sha256:target-1",
            "tenant_id": "tenant-1",
        },
    }
    authorization = {
        "assertion_id": "assertion:fabricated",
        "assertion_issuer": "issuer:fabricated",
        "assertion_sha256": "sha256:assertion-fabricated",
        "authority_use_sequence": 1,
        "canonical_replay_key_sha256": "sha256:replay-fabricated",
        "decision": "approved",
        "expires_at": "2026-01-01T00:10:00Z",
        "issued_at": "2026-01-01T00:00:00Z",
        "mission_id": "MISSION-1",
        "operation": "sunderkey.target-health-gate.resume.v1",
        "operation_intent_sha256": "sha256:intent-fabricated",
        "pause_epoch": 1,
        "principal_profile_id": "profile:fabricated",
        "principal_subject": "subject:fabricated",
        "recovery_intent_id": "THGI-1",
        "recovery_intent_sha256": "sha256:recovery-intent-1",
        "role": "independent_control",
        "scope_sha256": "sha256:scope-1",
        "target_sha256": "sha256:target-1",
        "tenant_id": "tenant-1",
    }
    fresh_id = "THI-4" if reuse_head_inspection else "THI-fresh"
    fresh_sha256 = (
        "sha256:inspection-4"
        if reuse_head_inspection
        else "sha256:inspection-fresh"
    )
    fresh_inspection = {
        "chain_id": "THC-1",
        "current_material_sha256": "sha256:material-fresh",
        "custody_event": {
            "event_id": "THCE-4",
            "event_sha256": "sha256:event-4",
        },
        "custody_receipt": {
            "custody_receipt_id": "THCR-4",
            "custody_receipt_sha256": "sha256:custody-receipt-4",
        },
        "envelope": {
            "envelope_id": "THE-4",
            "envelope_sha256": "sha256:envelope-4",
            "receipt": {
                "binding": {
                    "context_id": "MISSION-1",
                    "scope_sha256": "sha256:scope-1",
                    "target_sha256": "sha256:target-1",
                    "tenant_id": "tenant-1",
                },
                "binding_sha256": "sha256:binding-1",
                "overall_health": "healthy",
                "status": "completed",
            },
            "sequence": 4,
        },
        "head_binding": {
            "binding_sha256": "sha256:binding-1",
            "chain_head_envelope_id": "THE-4",
            "chain_head_envelope_sha256": "sha256:envelope-4",
            "chain_head_sequence": 4,
            "chain_id": "THC-1",
            "global_transition_sequence": 4,
            "head_binding_id": "THB-4",
            "head_binding_sha256": "sha256:head-binding-4",
        },
        "inspected_at": "2026-01-01T00:05:00Z",
        "inspection_id": fresh_id,
        "inspection_sha256": fresh_sha256,
        "mission_id": "MISSION-1",
        "tenant_id": "tenant-1",
        "verification": {
            "binding_sha256": "sha256:binding-1",
            "mode": "current",
        },
    }
    resumption = {
        "assertion_id": "assertion:fabricated",
        "assertion_issuer": "issuer:fabricated",
        "assertion_sha256": "sha256:assertion-fabricated",
        "authority_use_sequence": 1,
        "authorization": authorization,
        "canonical_replay_key_sha256": "sha256:replay-fabricated",
        "fresh_inspection": fresh_inspection,
        "operation_intent_sha256": "sha256:intent-fabricated",
        "pause_epoch": 1,
        "qualifying_observation_ids": ["THO-3", "THO-4"],
        "qualifying_observation_sha256s": [
            "sha256:observation-3",
            "sha256:observation-4",
        ],
        "recovery_intent": recovery_intent,
        "resumed_at": "2026-01-01T00:05:00Z",
        "resumption_id": "THGR-1",
        "resumption_sha256": "sha256:resumption-1",
        "subject": {
            "mission_id": "MISSION-1",
            "scope_sha256": "sha256:scope-1",
            "subject_id": "THS-1",
            "target_sha256": "sha256:target-1",
            "tenant_id": "tenant-1",
        },
    }

    return {
        "resumption_id": "THGR-1",
        "resumption_sha256": "sha256:resumption-1",
        "subject_id": "THS-1",
        "tenant_id": "tenant-1",
        "mission_id": "MISSION-1",
        "scope_sha256": "sha256:scope-1",
        "target_sha256": "sha256:target-1",
        "pause_epoch": 1,
        "recovery_intent_id": "THGI-1",
        "recovery_intent_sha256": "sha256:recovery-intent-1",
        "recovery_intent_json": canonical(recovery_intent),
        "qualifying_observation_ids_json": canonical(["THO-3", "THO-4"]),
        "qualifying_observation_sha256s_json": canonical(
            ["sha256:observation-3", "sha256:observation-4"]
        ),
        "fresh_inspection_id": fresh_id,
        "fresh_inspection_sha256": fresh_sha256,
        "fresh_head_binding_sha256": "sha256:head-binding-4",
        "authorization_json": canonical(authorization),
        "assertion_issuer": "issuer:fabricated",
        "assertion_id": "assertion:fabricated",
        "assertion_sha256": "sha256:assertion-fabricated",
        "authority_use_sequence": 1,
        "canonical_replay_key_sha256": "sha256:replay-fabricated",
        "operation_intent_sha256": "sha256:intent-fabricated",
        "resumption_json": canonical(resumption),
        "resumed_at": "2026-01-01T00:05:00Z",
    }


def remove_schema_v35_objects(connection: sqlite3.Connection) -> None:
    """Remove only schema 35 objects from a current test store."""

    remove_schema_v36_objects(connection)
    for name in sorted(V35_TRIGGERS):
        connection.execute(f'DROP TRIGGER IF EXISTS "{name}"')
    for name in sorted(V35_INDEXES):
        connection.execute(f'DROP INDEX IF EXISTS "{name}"')
    for name in (
        "target_health_gate_heads",
        "target_health_gate_transitions",
        "target_health_gate_resumptions",
        "target_health_gate_observations",
    ):
        connection.execute(f'DROP TABLE IF EXISTS "{name}"')
    connection.execute(
        "UPDATE store_metadata SET value = '34' WHERE key = 'schema_version'"
    )
    connection.execute("PRAGMA user_version = 34")


class Phase199StoreSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.store = MissionStore(self.path)
        self.store.initialize()

    def test_v35_adds_only_target_health_gate_objects(self) -> None:
        self.assertEqual(AUTHENTICATED_ACTION_EXECUTION_SCHEMA_VERSION, 34)
        self.assertEqual(TARGET_HEALTH_GATE_SCHEMA_VERSION, 35)
        self.assertEqual(ACTION_TARGET_HEALTH_GATE_USE_SCHEMA_VERSION, 36)
        self.assertEqual(SCHEMA_VERSION, 39)
        self.assertEqual(EXPECTED_SCHEMA_MANIFEST, EXPECTED_SCHEMA_MANIFEST_V39)

        v34 = {(item[0], item[1]): item for item in EXPECTED_SCHEMA_MANIFEST_V34}
        v35 = {(item[0], item[1]): item for item in EXPECTED_SCHEMA_MANIFEST_V35}
        self.assertFalse(set(v34) - set(v35))
        self.assertFalse(
            {
                key
                for key in set(v34) & set(v35)
                if v34[key] != v35[key]
            }
        )
        self.assertEqual(
            set(v35) - set(v34),
            {
                *(('table', name) for name in V35_TABLE_COLUMNS),
                *(('index', name) for name in V35_INDEXES),
                *(('trigger', name) for name in V35_TRIGGERS),
            },
        )

    def test_v35_tables_are_strict_and_have_exact_columns(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            table_rows = {
                row[1]: row
                for row in connection.execute("PRAGMA table_list")
            }
            for table, expected_columns in V35_TABLE_COLUMNS.items():
                self.assertEqual(table_rows[table][5], 1)
                columns = tuple(
                    row[1]
                    for row in connection.execute(f'PRAGMA table_info("{table}")')
                )
                self.assertEqual(columns, expected_columns)

    def test_v35_tables_restrict_mission_deletion(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            for table in V35_TABLE_COLUMNS:
                mission_foreign_keys = [
                    row
                    for row in connection.execute(
                        f'PRAGMA foreign_key_list("{table}")'
                    )
                    if row[2] == "missions" and row[3] == "mission_id"
                ]
                self.assertEqual(len(mission_foreign_keys), 1)
                self.assertEqual(mission_foreign_keys[0][6], "RESTRICT")

    def test_v36_requires_a_syntactic_inspection_context_on_new_rows(
        self,
    ) -> None:
        with (
            closing(sqlite3.connect(self.path)) as connection,
            self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "target health inspection context is invalid",
            ),
        ):
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    inspection_json=canonical(
                        {"inspection_context_sha256": "sha256:not-a-digest"}
                    )
                ),
            )

    def test_v35_guards_freeze_history_and_reconstruct_heads(self) -> None:
        manifest = {
            item[1]: item[3]
            for item in EXPECTED_SCHEMA_MANIFEST_V35
        }
        for table in (
            "target_health_gate_observations",
            "target_health_gate_transitions",
            "target_health_gate_resumptions",
        ):
            self.assertIn(f"BEFORE UPDATE ON {table}", manifest[f"{table}_immutable"])
            self.assertIn(f"BEFORE DELETE ON {table}", manifest[f"{table}_no_delete"])

        insert_guard = manifest["target_health_gate_heads_insert_guard"]
        update_guard = manifest["target_health_gate_heads_update_guard"]
        self.assertIn("NEW.version != 1", insert_guard)
        self.assertIn("NEW.version != OLD.version + 1", update_guard)
        self.assertIn(
            "NEW.transition_count != OLD.transition_count + 1",
            update_guard,
        )
        self.assertIn(
            "NEW.observation_count = OLD.observation_count + 1",
            update_guard,
        )
        self.assertIn(
            "NEW.resumption_count = OLD.resumption_count + 1",
            update_guard,
        )
        self.assertIn(
            "transition_count = observation_count + resumption_count",
            manifest["target_health_gate_heads"],
        )
        resumption_table = manifest["target_health_gate_resumptions"]
        self.assertIn(
            "REFERENCES principal_assertion_uses( issuer, assertion_id, mission_id )",
            resumption_table,
        )
        self.assertIn(
            "REFERENCES principal_assertion_uses( mission_id, use_sequence )",
            resumption_table,
        )
        resumption_guard = manifest["target_health_gate_resumptions_insert_guard"]
        for required_fragment in (
            "NEW.fresh_inspection_id != head.last_inspection_id",
            "NEW.fresh_inspection_sha256 != head.last_inspection_sha256",
            "$.fresh_inspection.current_material_sha256",
            "sunderkey.target-health-gate.resume.v1",
            "use.use_sequence = NEW.authority_use_sequence",
            "use.assertion_hash = NEW.assertion_sha256",
            "use.subject != NEW.assertion_issuer",
            "use.signed_intent_hash = NEW.operation_intent_sha256",
            "use.idempotency_key_hash = NEW.canonical_replay_key_sha256",
            "$.role' ) = 'independent_control'",
            "effect.effect_id = NEW.resumption_id",
        ):
            self.assertIn(required_fragment, resumption_guard)

    def test_v35_rejects_contradictory_embedded_records_and_chronology(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            contradicted = observation_values()
            inspection = json.loads(str(contradicted["inspection_json"]))
            inspection["envelope"]["receipt"]["binding"]["target_sha256"] = (
                "sha256:substituted-target"
            )
            contradicted["inspection_json"] = canonical(inspection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "observation chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_observations",
                    contradicted,
                )

            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "observation chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_observations",
                    observation_values(recorded_at="2025-12-31T23:59:59Z"),
                )

            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(),
            )
            contradicted_transition = transition_values()
            transition = json.loads(str(contradicted_transition["transition_json"]))
            transition["observation_sha256"] = "sha256:substituted-observation"
            contradicted_transition["transition_json"] = canonical(transition)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    contradicted_transition,
                )

            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "head initialization is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_heads",
                    head_values(updated_at="2026-01-01T00:00:03Z"),
                )

    def test_v35_runtime_guards_reject_chain_and_head_mutation(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(),
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE target_health_gate_observations "
                    "SET recorded_at = 'changed' WHERE observation_id = 'THO-1'"
                )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "observation chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_observations",
                    observation_values(
                        observation_id="THO-2",
                        observation_sha256="sha256:observation-2",
                        inspection_id="THI-2",
                        inspection_sha256="sha256:inspection-2",
                        observation_sequence=2,
                        previous_observation_sha256="sha256:wrong",
                    ),
                )

            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "head initialization is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_heads",
                    head_values(version=2),
                )
            insert_mapping(
                connection,
                "target_health_gate_heads",
                head_values(),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "head transition is inconsistent",
            ):
                connection.execute(
                    "UPDATE target_health_gate_heads SET version = 2 "
                    "WHERE subject_id = 'THS-1'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(
                    "DELETE FROM target_health_gate_heads "
                    "WHERE subject_id = 'THS-1'"
                )

    def test_v35_resume_authority_requires_replay_key_before_consumption(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection, self.assertRaisesRegex(
            sqlite3.IntegrityError,
            "resumption requires a replay key",
        ):
            insert_mapping(
                connection,
                "principal_assertion_uses",
                {
                    "mission_id": "MISSION-fabricated",
                    "use_sequence": 1,
                    "issuer": "issuer:fabricated",
                    "assertion_id": "assertion:fabricated",
                    "assertion_json": "{}",
                    "assertion_hash": digest("a"),
                    "subject": "subject:fabricated",
                    "principal_profile_id": "profile:fabricated",
                    "key_id": "key:fabricated",
                    "key_hash": digest("b"),
                    "audience": "audience:fabricated",
                    "store_id": "STR-00000000000000000000000000000000",
                    "operation": "sunderkey.target-health-gate.resume.v1",
                    "operation_intent_json": "{}",
                    "signed_intent_hash": digest("c"),
                    "domain_request_hash": digest("d"),
                    "idempotency_key_hash": None,
                    "scope_grant_hash": digest("e"),
                    "trust_policy_id": "policy:fabricated",
                    "trust_policy_version": 1,
                    "trust_policy_hash": digest("f"),
                    "issued_at": "2026-01-01T00:00:00Z",
                    "not_before": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-01-01T00:10:00Z",
                    "consumed_at": "2026-01-01T00:01:00Z",
                    "effects_hash": digest("1"),
                    "previous_hash": digest("2"),
                    "entry_hash": digest("3"),
                },
            )

    def test_v35_resume_effect_requires_matching_authority_use(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection, self.assertRaisesRegex(
            sqlite3.IntegrityError,
            "resumption effect is inconsistent",
        ):
            insert_mapping(
                connection,
                "principal_assertion_effects",
                {
                    "issuer": "issuer:fabricated",
                    "assertion_id": "assertion:fabricated",
                    "mission_id": "MISSION-fabricated",
                    "effect_index": 1,
                    "effect_kind": "sunderkey.target-health-gate.resume.v1",
                    "effect_id": "THGR-fabricated",
                    "effect_json": "{}",
                    "effect_hash": digest("4"),
                    "recorded_at": "2026-01-01T00:01:00Z",
                },
            )

    def test_v35_head_requires_exact_latest_adverse_observation(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            insert_initial_active_gate(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-2",
                    observation_sha256="sha256:observation-2",
                    observation_sequence=2,
                    previous_observation_sha256="sha256:observation-1",
                    inspection_id="THI-2",
                    inspection_sha256="sha256:inspection-2",
                    head_binding_id="THB-2",
                    head_binding_sha256="sha256:head-binding-2",
                    global_transition_sequence=2,
                    envelope_id="THE-2",
                    envelope_sha256="sha256:envelope-2",
                    envelope_sequence=2,
                    predecessor_envelope_id="THE-1",
                    predecessor_envelope_sha256="sha256:envelope-1",
                    receipt_id="THR-2",
                    receipt_sha256="sha256:receipt-2",
                    overall_health="unhealthy",
                    classification="adverse",
                    observed_at="2026-01-01T00:01:00Z",
                    inspected_at="2026-01-01T00:01:01Z",
                    recorded_at="2026-01-01T00:01:02Z",
                ),
            )
            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(
                    transition_id="THT-2",
                    transition_sha256="sha256:transition-2",
                    transition_sequence=2,
                    previous_transition_sha256="sha256:transition-1",
                    transition_kind="pause_asserted",
                    from_state="active",
                    to_state="paused",
                    pause_epoch=1,
                    observation_id="THO-2",
                    observation_sha256="sha256:observation-2",
                    occurred_at="2026-01-01T00:01:02Z",
                ),
            )
            next_head = {
                "latch_state": "paused",
                "pause_epoch": 1,
                "observation_count": 2,
                "observation_head_sha256": "sha256:observation-2",
                "transition_count": 2,
                "transition_head_sha256": "sha256:transition-2",
                "last_observation_id": "THO-2",
                "last_observation_sha256": "sha256:observation-2",
                "last_inspection_id": "THI-2",
                "last_inspection_sha256": "sha256:inspection-2",
                "last_head_binding_id": "THB-2",
                "last_head_binding_sha256": "sha256:head-binding-2",
                "last_global_transition_sequence": 2,
                "last_current_material_sha256": "sha256:material-2",
                "version": 2,
                "updated_at": "2026-01-01T00:01:02Z",
            }
            for last_id, last_sha256 in (
                (None, None),
                ("THO-substituted", "sha256:substituted"),
            ):
                with self.subTest(last_id=last_id), self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "head transition is inconsistent",
                ):
                    update_head(
                        connection,
                        **next_head,
                        last_adverse_observation_id=last_id,
                        last_adverse_observation_sha256=last_sha256,
                    )

    def test_v35_transition_rejects_wrong_observation_classification(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            insert_initial_active_gate(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-2",
                    observation_sha256="sha256:observation-2",
                    observation_sequence=2,
                    previous_observation_sha256="sha256:observation-1",
                    inspection_id="THI-2",
                    inspection_sha256="sha256:inspection-2",
                    global_transition_sequence=2,
                    envelope_id="THE-2",
                    envelope_sha256="sha256:envelope-2",
                    envelope_sequence=2,
                    predecessor_envelope_id="THE-1",
                    predecessor_envelope_sha256="sha256:envelope-1",
                    receipt_id="THR-2",
                    receipt_sha256="sha256:receipt-2",
                    overall_health="unhealthy",
                    classification="adverse",
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    transition_values(
                        transition_id="THT-2",
                        transition_sha256="sha256:transition-2",
                        transition_sequence=2,
                        previous_transition_sha256="sha256:transition-1",
                        transition_kind="active_health_confirmed",
                        from_state="active",
                        observation_id="THO-2",
                        observation_sha256="sha256:observation-2",
                    ),
                )

    def test_v35_transition_rejects_arbitrary_pause_epoch(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            insert_initial_active_gate(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-2",
                    observation_sha256="sha256:observation-2",
                    observation_sequence=2,
                    previous_observation_sha256="sha256:observation-1",
                    inspection_id="THI-2",
                    inspection_sha256="sha256:inspection-2",
                    global_transition_sequence=2,
                    envelope_id="THE-2",
                    envelope_sha256="sha256:envelope-2",
                    envelope_sequence=2,
                    predecessor_envelope_id="THE-1",
                    predecessor_envelope_sha256="sha256:envelope-1",
                    receipt_id="THR-2",
                    receipt_sha256="sha256:receipt-2",
                    overall_health="unhealthy",
                    classification="adverse",
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    transition_values(
                        transition_id="THT-2",
                        transition_sha256="sha256:transition-2",
                        transition_sequence=2,
                        previous_transition_sha256="sha256:transition-1",
                        transition_kind="pause_asserted",
                        from_state="active",
                        to_state="paused",
                        pause_epoch=7,
                        observation_id="THO-2",
                        observation_sha256="sha256:observation-2",
                    ),
                )

    def test_v35_transition_rejects_stale_global_transition(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            insert_initial_active_gate(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-2",
                    observation_sha256="sha256:observation-2",
                    observation_sequence=2,
                    previous_observation_sha256="sha256:observation-1",
                    inspection_id="THI-2",
                    inspection_sha256="sha256:inspection-2",
                    global_transition_sequence=1,
                    envelope_id="THE-2",
                    envelope_sha256="sha256:envelope-2",
                    envelope_sequence=2,
                    predecessor_envelope_id="THE-1",
                    predecessor_envelope_sha256="sha256:envelope-1",
                    receipt_id="THR-2",
                    receipt_sha256="sha256:receipt-2",
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    transition_values(
                        transition_id="THT-2",
                        transition_sha256="sha256:transition-2",
                        transition_sequence=2,
                        previous_transition_sha256="sha256:transition-1",
                        transition_kind="active_health_confirmed",
                        from_state="active",
                        observation_id="THO-2",
                        observation_sha256="sha256:observation-2",
                    ),
                )

    def test_v35_recovery_advance_rejects_noncontiguous_envelope(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_first_recovery_observation(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    observation_sequence=4,
                    previous_observation_sha256="sha256:observation-3",
                    inspection_id="THI-4",
                    inspection_sha256="sha256:inspection-4",
                    head_binding_id="THB-4",
                    head_binding_sha256="sha256:head-binding-4",
                    global_transition_sequence=4,
                    envelope_id="THE-5",
                    envelope_sha256="sha256:envelope-5",
                    envelope_sequence=5,
                    predecessor_envelope_id="THE-3",
                    predecessor_envelope_sha256="sha256:envelope-3",
                    receipt_id="THR-4",
                    receipt_sha256="sha256:receipt-4",
                    evidence_advanced=1,
                    observed_at="2026-01-01T00:03:00Z",
                    inspected_at="2026-01-01T00:03:01Z",
                    recorded_at="2026-01-01T00:03:02Z",
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    transition_values(
                        transition_id="THT-4",
                        transition_sha256="sha256:transition-4",
                        transition_sequence=4,
                        previous_transition_sha256="sha256:transition-3",
                        transition_kind="recovery_advanced",
                        from_state="recovery_pending",
                        to_state="recovery_pending",
                        pause_epoch=1,
                        recovery_healthy_count=2,
                        observation_id="THO-4",
                        observation_sha256="sha256:observation-4",
                        occurred_at="2026-01-01T00:03:02Z",
                    ),
                )
            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(
                    transition_id="THT-4-restarted",
                    transition_sha256="sha256:transition-4-restarted",
                    transition_sequence=4,
                    previous_transition_sha256="sha256:transition-3",
                    transition_kind="recovery_restarted",
                    from_state="recovery_pending",
                    to_state="recovery_pending",
                    pause_epoch=1,
                    recovery_healthy_count=1,
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    occurred_at="2026-01-01T00:03:02Z",
                ),
            )

    def test_v35_recovery_held_accepts_equal_exact_current_source(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_first_recovery_observation(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    observation_sequence=4,
                    previous_observation_sha256="sha256:observation-3",
                    inspection_id="THI-4",
                    inspection_sha256="sha256:inspection-4",
                    head_binding_id="THB-3",
                    head_binding_sha256="sha256:head-binding-3",
                    global_transition_sequence=3,
                    envelope_id="THE-3",
                    envelope_sha256="sha256:envelope-3",
                    envelope_sequence=3,
                    predecessor_envelope_id="THE-2",
                    predecessor_envelope_sha256="sha256:envelope-2",
                    receipt_id="THR-3",
                    receipt_sha256="sha256:receipt-3",
                    evidence_advanced=0,
                    observed_at="2026-01-01T00:02:00Z",
                    inspected_at="2026-01-01T00:03:01Z",
                    recorded_at="2026-01-01T00:03:02Z",
                ),
            )
            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(
                    transition_id="THT-4",
                    transition_sha256="sha256:transition-4",
                    transition_sequence=4,
                    previous_transition_sha256="sha256:transition-3",
                    transition_kind="recovery_held",
                    from_state="recovery_pending",
                    to_state="recovery_pending",
                    pause_epoch=1,
                    recovery_healthy_count=1,
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    occurred_at="2026-01-01T00:03:02Z",
                ),
            )

    def test_v35_equal_high_water_rejects_source_substitution(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_first_recovery_observation(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    observation_sequence=4,
                    previous_observation_sha256="sha256:observation-3",
                    inspection_id="THI-4",
                    inspection_sha256="sha256:inspection-4",
                    head_binding_id="THB-3",
                    head_binding_sha256="sha256:head-binding-3",
                    global_transition_sequence=3,
                    envelope_id="THE-3",
                    envelope_sha256="sha256:envelope-3",
                    envelope_sequence=3,
                    predecessor_envelope_id="THE-2",
                    predecessor_envelope_sha256="sha256:envelope-2",
                    receipt_id="THR-substituted",
                    receipt_sha256="sha256:receipt-substituted",
                    evidence_advanced=0,
                    observed_at="2026-01-01T00:02:00Z",
                    inspected_at="2026-01-01T00:03:01Z",
                    recorded_at="2026-01-01T00:03:02Z",
                ),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "transition chain is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_transitions",
                    transition_values(
                        transition_id="THT-4",
                        transition_sha256="sha256:transition-4",
                        transition_sequence=4,
                        previous_transition_sha256="sha256:transition-3",
                        transition_kind="recovery_held",
                        from_state="recovery_pending",
                        to_state="recovery_pending",
                        pause_epoch=1,
                        recovery_healthy_count=1,
                        observation_id="THO-4",
                        observation_sha256="sha256:observation-4",
                        occurred_at="2026-01-01T00:03:02Z",
                    ),
                )

    def test_v35_recovery_count_one_holds_same_envelope_at_new_high_water(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_first_recovery_observation(connection)
            insert_mapping(
                connection,
                "target_health_gate_observations",
                observation_values(
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    observation_sequence=4,
                    previous_observation_sha256="sha256:observation-3",
                    inspection_id="THI-4",
                    inspection_sha256="sha256:inspection-4",
                    head_binding_id="THB-4-admin",
                    head_binding_sha256="sha256:head-binding-4-admin",
                    global_transition_sequence=4,
                    envelope_id="THE-3",
                    envelope_sha256="sha256:envelope-3",
                    envelope_sequence=3,
                    predecessor_envelope_id="THE-2",
                    predecessor_envelope_sha256="sha256:envelope-2",
                    receipt_id="THR-3",
                    receipt_sha256="sha256:receipt-3",
                    evidence_advanced=0,
                    observed_at="2026-01-01T00:02:00Z",
                    inspected_at="2026-01-01T00:03:01Z",
                    recorded_at="2026-01-01T00:03:02Z",
                ),
            )
            insert_mapping(
                connection,
                "target_health_gate_transitions",
                transition_values(
                    transition_id="THT-4-held",
                    transition_sha256="sha256:transition-4-held",
                    transition_sequence=4,
                    previous_transition_sha256="sha256:transition-3",
                    transition_kind="recovery_held",
                    from_state="recovery_pending",
                    to_state="recovery_pending",
                    pause_epoch=1,
                    recovery_healthy_count=1,
                    observation_id="THO-4",
                    observation_sha256="sha256:observation-4",
                    occurred_at="2026-01-01T00:03:02Z",
                ),
            )

    def test_v35_resumption_rejects_reused_head_inspection(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_recovery_ready(connection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "resumption is inconsistent",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_resumptions",
                    resumption_values(reuse_head_inspection=True),
                )

    def test_v35_resumption_rejects_fabricated_control_authority(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            advance_gate_to_recovery_ready(connection)
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "resumption is inconsistent|FOREIGN KEY constraint failed",
            ):
                insert_mapping(
                    connection,
                    "target_health_gate_resumptions",
                    resumption_values(),
                )

    def test_v34_migration_creates_verified_backup_and_v35_manifest(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            remove_schema_v35_objects(connection)
            connection.commit()
            self.assertEqual(
                _schema_manifest(connection),
                EXPECTED_SCHEMA_MANIFEST_V34,
            )

        backup = self.directory / "before-v35.sqlite3"
        report = self.store.migrate(self.registry, backup)
        self.assertEqual(report.status, "migrated")
        self.assertEqual(report.source_version, 34)
        self.assertEqual(report.target_version, 39)
        self.assertEqual(report.backup, str(backup.resolve()))

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 39)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 34)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V34)

    def test_current_v35_migration_is_idempotent_without_backup(self) -> None:
        unused_backup = self.directory / "unused.sqlite3"
        report = self.store.migrate(self.registry, unused_backup)
        self.assertEqual(report.status, "already_current")
        self.assertEqual(report.source_version, 39)
        self.assertEqual(report.target_version, 39)
        self.assertIsNone(report.backup)
        self.assertFalse(unused_backup.exists())


if __name__ == "__main__":
    unittest.main()

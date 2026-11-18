from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

from sunderkey.approvals import ApprovalService
from sunderkey.errors import (
    EventError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.events import MissionEvent, compute_proposal_action_hash
from sunderkey.identity import PrincipalOperation
from sunderkey.mission import MissionRequest, assemble_joint_mission_cell
from sunderkey.registry import load_registry
from sunderkey.simulation import SimulationService
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V31,
    EXPECTED_SCHEMA_MANIFEST_V32,
    EXPECTED_SCHEMA_MANIFEST_V33,
    EXPECTED_SCHEMA_MANIFEST_V34,
    EXPECTED_SCHEMA_MANIFEST_V35,
    EXPECTED_SCHEMA_MANIFEST_V36,
    EXPECTED_SCHEMA_MANIFEST_V37,
    EXPECTED_SCHEMA_MANIFEST_V38,
    EXPECTED_SCHEMA_MANIFEST_V39,
    SCHEMA_V11_ADDITION_STATEMENTS,
    MissionStore,
    canonical_json,
    sha256_text,
)
from sunderkey.types import EventType


def remove_schema_v39_objects(connection: sqlite3.Connection) -> None:
    """Remove only empty synthetic repository custody from a legacy fixture."""

    tables = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value
    for table, field in (
        ("principal_assertion_uses", "operation"),
        ("principal_assertion_effects", "effect_kind"),
    ):
        if table in tables and connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {field} = ?", (operation,)
        ).fetchone()[0]:
            raise AssertionError("Signed repository ACK history cannot become a legacy fixture")
    table = "provider_evidence_repository_ingest_authentications"
    if table not in tables:
        return
    if connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]:
        raise AssertionError("Signed repository custody cannot become a legacy fixture")
    names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V38}
    additions = [
        item for item in EXPECTED_SCHEMA_MANIFEST_V39 if (item[0], item[1]) not in names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} IF EXISTS "{item[1]}"')
    connection.execute(f'DROP TABLE "{table}"')


def remove_schema_v38_objects(connection: sqlite3.Connection) -> None:
    """Restore an isolated legacy fixture, never a runtime migration path."""

    remove_schema_v39_objects(connection)
    present = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE name = 'plan_replacement_reviewer_admissions'"
    ).fetchone()
    if present is None:
        return
    if connection.execute(
        "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions"
    ).fetchone()[0]:
        raise AssertionError("Signed reviewer history cannot become a legacy fixture")
    names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V37}
    for item in EXPECTED_SCHEMA_MANIFEST_V38:
        if item[0] == "trigger" and (item[0], item[1]) not in names:
            connection.execute(f'DROP TRIGGER IF EXISTS "{item[1]}"')
    connection.execute("DROP TABLE plan_replacement_reviewer_admissions")
    authentication = "collaboration_plan_replacement_authentications"
    rows = connection.execute(f"SELECT * FROM {authentication}").fetchall()
    for item in EXPECTED_SCHEMA_MANIFEST_V37:
        if item[0] == "trigger" and item[2] == authentication:
            connection.execute(f'DROP TRIGGER IF EXISTS "{item[1]}"')
    connection.execute(f"DROP TABLE {authentication}")
    for item in EXPECTED_SCHEMA_MANIFEST_V37:
        if item[0] == "table" and item[1] == authentication:
            connection.execute(item[3])
    for row in rows:
        connection.execute(
            f"INSERT INTO {authentication} VALUES ({','.join('?' for _ in row)})",
            tuple(row),
        )
    for item in EXPECTED_SCHEMA_MANIFEST_V37:
        if item[0] == "trigger" and item[2] == authentication:
            connection.execute(item[3])


def remove_schema_v37_objects(connection: sqlite3.Connection) -> None:
    """Remove execution target-health cutover custody from a test store."""

    remove_schema_v38_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V36}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V37
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(
                    f'DROP {object_type.upper()} IF EXISTS "{item[1]}"'
                )
    connection.execute(
        "DROP TABLE IF EXISTS action_execution_preinvocation_aborts"
    )
    connection.execute(
        "DROP TABLE IF EXISTS "
        "action_execution_target_health_gate_legacy_baselines"
    )


def remove_schema_v36_objects(connection: sqlite3.Connection) -> None:
    """Remove action target-health use custody from a test store."""

    remove_schema_v37_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V35}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V36
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(
                    f'DROP {object_type.upper()} IF EXISTS "{item[1]}"'
                )
    connection.execute("DROP TABLE IF EXISTS action_target_health_gate_uses")
    connection.execute(
        "DROP TABLE IF EXISTS action_target_health_gate_legacy_baselines"
    )


def remove_schema_v35_objects(connection: sqlite3.Connection) -> None:
    """Remove target health gate objects from a test store."""

    remove_schema_v36_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V34}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V35
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(
                    f'DROP {object_type.upper()} IF EXISTS "{item[1]}"'
                )
    for table in (
        "target_health_gate_heads",
        "target_health_gate_transitions",
        "target_health_gate_resumptions",
        "target_health_gate_observations",
    ):
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


def remove_schema_v34_objects(connection: sqlite3.Connection) -> None:
    """Remove authenticated action execution custody objects from a test store."""

    remove_schema_v35_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V33}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V34
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} IF EXISTS "{item[1]}"')
    for table in (
        "action_execution_reconciliations",
        "action_execution_closures",
        "action_execution_terminals",
        "action_execution_predispatch_aborts",
        "action_execution_dispatch_attempts",
        "action_execution_reservations",
        "action_execution_authority_consumptions",
        "action_execution_claims",
        "action_execution_authority_checkpoints",
        "action_execution_requests",
    ):
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


def remove_schema_v33_objects(connection: sqlite3.Connection) -> None:
    """Remove authenticated action admission custody objects from a test store."""

    remove_schema_v34_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V32}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V33
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} IF EXISTS "{item[1]}"')
    for table in (
        "action_authority_grant_submissions",
        "action_budget_receipt_reservations",
        "action_budget_account_heads",
        "action_budget_account_events",
        "action_budget_policy_bindings",
        "action_budget_accounts",
        "action_authority_publications",
        "action_authority_observations",
        "action_authority_material_snapshots",
        "action_authority_source_bundles",
        "action_authority_source_heads",
        "action_authority_proposal_imports",
        "action_authority_revisions",
        "action_admission_execution_consumptions",
        "action_admission_workspace_high_waters",
        "action_admission_revocations",
        "action_admission_budget_reservations",
        "action_admission_replay_uses",
        "action_admission_assertion_uses",
        "action_admission_quorums",
        "action_admission_resolutions",
        "action_admission_receipts",
    ):
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


def remove_schema_v32_objects(connection: sqlite3.Connection) -> None:
    """Remove authenticated expert review custody objects from a test store."""

    remove_schema_v33_objects(connection)
    old_names = {(item[0], item[1]) for item in EXPECTED_SCHEMA_MANIFEST_V31}
    additions = [
        item
        for item in EXPECTED_SCHEMA_MANIFEST_V32
        if (item[0], item[1]) not in old_names
    ]
    for object_type in ("trigger", "index"):
        for item in additions:
            if item[0] == object_type:
                connection.execute(f'DROP {object_type.upper()} IF EXISTS "{item[1]}"')
    for table in (
        "authenticated_expert_review_revocation_projections",
        "authenticated_expert_review_closure_projections",
        "authenticated_expert_review_closure_receipts",
        "authenticated_expert_review_revocations",
        "authenticated_expert_review_closures",
        "authenticated_expert_review_receipts",
        "authenticated_expert_review_snapshot_slots",
        "authenticated_expert_review_snapshot_products",
        "authenticated_expert_review_snapshot_registrations",
        "authenticated_expert_review_replay_uses",
    ):
        connection.execute(f'DROP TABLE IF EXISTS "{table}"')


def remove_schema_v31_objects(connection: sqlite3.Connection) -> None:
    """Remove authenticated model execution custody objects from a test store."""

    remove_schema_v32_objects(connection)
    for trigger in (
        "authenticated_model_execution_budget_update_guard",
        "authenticated_model_execution_budget_no_delete",
        "authenticated_model_execution_budget_event_immutable",
        "authenticated_model_execution_budget_event_no_delete",
        "authenticated_model_execution_budget_event_insert_guard",
        "authenticated_model_execution_admission_insert_guard",
        "authenticated_model_execution_admission_core_immutable",
        "authenticated_model_execution_admission_no_delete",
        "authenticated_model_execution_dispatch_immutable",
        "authenticated_model_execution_dispatch_no_delete",
        "authenticated_model_execution_settlement_immutable",
        "authenticated_model_execution_settlement_no_delete",
        "authenticated_model_execution_provider_request_immutable",
        "authenticated_model_execution_provider_request_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for table in (
        "authenticated_model_execution_provider_requests",
        "authenticated_model_execution_settlements",
        "authenticated_model_execution_dispatches",
        "authenticated_model_execution_admissions",
        "authenticated_model_execution_budget_events",
        "authenticated_model_execution_budgets",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"

MISSION_ID = "MISSION-STORE-001"
SPECIALIST_ID = "AOE-GB-D06-S09"
CONTROL_ID = "AOE-HQ-12"
ASSURANCE_ID = "AOE-HQ-18"
FIXED_TIME = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
DECISION_TIME = datetime(2026, 1, 1, 10, 5, tzinfo=UTC)


def remove_schema_v29_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove schema v29 and restore the exact v28 activation table."""

    remove_schema_v31_objects(connection)
    if connection.execute(
        """
        SELECT 1 FROM sqlite_master
        WHERE type = 'table' AND name = 'collaboration_plan_active_heads'
        """
    ).fetchone() is None:
        return

    prior_foreign_keys = int(
        connection.execute("PRAGMA foreign_keys").fetchone()[0]
    )
    if prior_foreign_keys:
        if connection.in_transaction:
            connection.commit()
        connection.execute("PRAGMA foreign_keys = OFF")

    prior_legacy_alter = int(
        connection.execute("PRAGMA legacy_alter_table").fetchone()[0]
    )
    connection.execute("PRAGMA legacy_alter_table = ON")
    for trigger in (
        "collaboration_plan_replacement_authentications_insert_guard",
        "collaboration_plan_replacement_authentications_immutable",
        "collaboration_plan_replacement_authentications_no_delete",
        "collaboration_plan_replacement_authority_consumptions_insert_guard",
        "collaboration_plan_replacement_authority_consumptions_immutable",
        "collaboration_plan_replacement_authority_consumptions_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_plan_replacement_authority_consumptions"
    )
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_plan_replacement_authentications"
    )
    for trigger in (
        "collaboration_plan_replacement_activation_guard",
        "collaboration_plan_active_heads_insert_guard",
        "collaboration_plan_active_heads_update_guard",
        "collaboration_plan_active_heads_no_delete",
        "collaboration_plan_replacement_commits_immutable",
        "collaboration_plan_replacement_commits_no_delete",
        "collaboration_plan_replacement_authorities_immutable",
        "collaboration_plan_replacement_authorities_no_delete",
        "collaboration_plan_replacement_source_settlements_immutable",
        "collaboration_plan_replacement_source_settlements_no_delete",
        "collaboration_plan_completed_work_carry_forwards_immutable",
        "collaboration_plan_completed_work_carry_forwards_no_delete",
        "collaboration_plan_work_initializations_immutable",
        "collaboration_plan_work_initializations_no_delete",
        "collaboration_plan_activation_authenticated_guard",
        "collaboration_plan_activations_immutable",
        "collaboration_plan_activations_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for table in (
        "collaboration_plan_replacement_authorities",
        "collaboration_plan_completed_work_carry_forwards",
        "collaboration_plan_work_initializations",
        "collaboration_plan_replacement_source_settlements",
        "collaboration_plan_active_heads",
        "collaboration_plan_replacement_commits",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    connection.execute(
        "ALTER TABLE collaboration_plan_activations "
        "RENAME TO collaboration_plan_activations_v29"
    )
    connection.execute(SCHEMA_V11_ADDITION_STATEMENTS[0])
    connection.execute(
        """
        INSERT INTO collaboration_plan_activations(
            plan_id, mission_id, store_id, plan_json, plan_sha256,
            plan_content_sha256, registry_sha256, mission_sha256,
            joint_mission_cell_sha256, readiness_owner_profile_id,
            activated_at, issuer, assertion_id
        )
        SELECT plan_id, mission_id, store_id, plan_json, plan_sha256,
               plan_content_sha256, registry_sha256, mission_sha256,
               joint_mission_cell_sha256, readiness_owner_profile_id,
               activated_at, issuer, assertion_id
        FROM collaboration_plan_activations_v29
        """
    )
    connection.execute("DROP TABLE collaboration_plan_activations_v29")
    for statement in SCHEMA_V11_ADDITION_STATEMENTS[1:]:
        connection.execute(statement)
    connection.execute(
        f"PRAGMA legacy_alter_table = {prior_legacy_alter}"
    )
    if prior_foreign_keys:
        if connection.in_transaction:
            connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")


def remove_schema_v28_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v28 layer from a test fixture."""

    remove_schema_v29_objects(connection)

    for trigger in (
        "executor_invocation_provider_report_authentication_guard",
        "executor_invocation_provider_report_authentications_immutable",
        "executor_invocation_provider_report_authentications_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP TABLE IF EXISTS "
        "executor_invocation_provider_report_authentications"
    )


def remove_schema_v27_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v27 layer from a test fixture."""

    remove_schema_v28_objects(connection)

    for trigger in (
        "executor_invocation_provider_report_guard",
        "executor_invocation_provider_reports_immutable",
        "executor_invocation_provider_reports_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS executor_invocation_provider_reports")


def remove_schema_v26_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v26 layer from a test fixture."""

    remove_schema_v27_objects(connection)

    for trigger in (
        "executor_dispatch_invocation_preparation_guard",
        "executor_dispatch_invocation_resolution_guard",
        "executor_dispatch_invocation_preparations_immutable",
        "executor_dispatch_invocation_preparations_no_delete",
        "executor_dispatch_invocation_resolutions_immutable",
        "executor_dispatch_invocation_resolutions_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP TABLE IF EXISTS executor_dispatch_invocation_resolutions"
    )
    connection.execute(
        "DROP TABLE IF EXISTS executor_dispatch_invocation_preparations"
    )


def remove_schema_v22_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove schema v22 and all later layers from a test fixture."""

    remove_schema_v26_objects(connection)

    for trigger in (
        "executor_dispatch_delivery_claim_guard",
        "executor_dispatch_delivery_claims_immutable",
        "executor_dispatch_delivery_claims_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS executor_dispatch_delivery_claims")

    for trigger in (
        "executor_dispatch_reservation_guard",
        "executor_dispatch_reservations_immutable",
        "executor_dispatch_reservations_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS executor_dispatch_reservations")

    for trigger in (
        "execution_session_activation_guard",
        "execution_session_revocation_guard",
        "execution_session_activation_commits_immutable",
        "execution_session_activation_commits_no_delete",
        "execution_session_revocation_commits_immutable",
        "execution_session_revocation_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS execution_session_revocation_commits")
    connection.execute("DROP TABLE IF EXISTS execution_session_activation_commits")

    for trigger in (
        "execution_session_authority_basis_guard",
        "execution_session_authority_commits_immutable",
        "execution_session_authority_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP INDEX IF EXISTS execution_session_handoff_basis_identity")
    connection.execute("DROP TABLE IF EXISTS execution_session_authority_commits")


def remove_schema_v21_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v21 layer from a test fixture."""

    remove_schema_v22_objects(connection)

    for trigger in (
        "execution_terminal_custody_participant_guard",
        "execution_terminal_custody_commits_immutable",
        "execution_terminal_custody_commits_no_delete",
        "execution_terminal_custody_participants_immutable",
        "execution_terminal_custody_participants_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute("DROP TABLE IF EXISTS execution_terminal_custody_participants")
    connection.execute("DROP TABLE IF EXISTS execution_terminal_custody_commits")


def remove_schema_v20_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v20 layer from a test fixture."""

    remove_schema_v21_objects(connection)

    for trigger in (
        "principal_execution_channel_policy_use_guard",
        "execution_channel_policy_authenticated_guard",
        "execution_channel_policy_commits_immutable",
        "execution_channel_policy_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_execution_channel_policy_effect_identity"
    )
    connection.execute("DROP TABLE IF EXISTS execution_channel_policy_commits")


def remove_schema_v17_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v17 layer from a test fixture."""

    remove_schema_v20_objects(connection)
    for trigger in (
        "principal_collaboration_ownership_use_guard",
        "collaboration_ownership_authenticated_guard",
        "collaboration_ownership_revocation_authenticated_guard",
        "collaboration_ownership_privileged_authenticated_guard",
        "collaboration_ownership_privileged_control_guard",
        "collaboration_ownership_chain_entries_immutable",
        "collaboration_ownership_chain_entries_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_collaboration_ownership_effect_identity"
    )
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_ownership_chain_entries"
    )


def remove_schema_v16_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v16 layer from a test fixture."""

    remove_schema_v17_objects(connection)
    for trigger in (
        "principal_collaboration_policy_use_guard",
        "collaboration_mission_policy_authenticated_guard",
        "collaboration_mission_policy_commits_immutable",
        "collaboration_mission_policy_commits_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_collaboration_policy_effect_identity"
    )
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_mission_policy_commits"
    )


def remove_schema_v15_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v15 layer from a test fixture."""

    remove_schema_v16_objects(connection)
    for trigger in (
        "principal_work_handoff_use_guard",
        "collaboration_work_handoff_authenticated_guard",
        "collaboration_work_item_handoffs_immutable",
        "collaboration_work_item_handoffs_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_work_handoff_request_identity",
        "principal_work_handoff_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_work_item_handoffs"
    )


def remove_schema_v14_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v14 layer from a test fixture."""

    remove_schema_v15_objects(connection)
    for trigger in (
        "principal_work_cancellation_use_guard",
        "collaboration_work_cancellation_authenticated_guard",
        "collaboration_work_item_cancellations_immutable",
        "collaboration_work_item_cancellations_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_work_cancellation_identity",
        "principal_work_cancellation_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_work_item_cancellations"
    )


def remove_schema_v13_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v13 layer from a test fixture."""

    remove_schema_v14_objects(connection)
    for trigger in (
        "principal_work_recovery_use_guard",
        "collaboration_work_recovery_request_authenticated_guard",
        "collaboration_work_recovery_decision_authenticated_guard",
        "collaboration_work_recovery_transition_authenticated_guard",
        "collaboration_work_recovery_requests_immutable",
        "collaboration_work_recovery_requests_no_delete",
        "collaboration_work_recovery_decisions_immutable",
        "collaboration_work_recovery_decisions_no_delete",
        "collaboration_work_recovery_transitions_immutable",
        "collaboration_work_recovery_transitions_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "collaboration_work_item_recovery_generation_claim",
        "collaboration_work_item_recovery_completion",
        "principal_work_recovery_request_identity",
        "principal_work_recovery_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    for table in (
        "collaboration_work_item_recovery_transitions",
        "collaboration_work_item_recovery_decisions",
        "collaboration_work_item_recovery_requests",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")


def remove_schema_v12_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v12 layer from a test fixture."""

    remove_schema_v13_objects(connection)
    for trigger in (
        "principal_work_item_use_guard",
        "collaboration_work_item_transitions_immutable",
        "collaboration_work_item_transitions_no_delete",
        "collaboration_work_item_authenticated_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "collaboration_work_item_generation_claim",
        "collaboration_work_item_completion",
        "principal_work_item_request_identity",
        "principal_work_item_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_work_item_transitions"
    )


def remove_schema_v11_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v11 layer from a test fixture."""

    remove_schema_v12_objects(connection)
    for trigger in (
        "collaboration_plan_activations_insert_once",
        "collaboration_plan_activations_immutable",
        "collaboration_plan_activations_no_delete",
        "principal_collaboration_activation_use_guard",
        "collaboration_plan_activation_authenticated_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_collaboration_activation_request_identity",
        "principal_collaboration_activation_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS collaboration_plan_activations"
    )


def remove_schema_v10_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v10 layer from a test fixture."""

    remove_schema_v11_objects(connection)
    for trigger in (
        "mission_creation_provenance_insert_once",
        "mission_creation_provenance_immutable",
        "mission_creation_provenance_no_delete",
        "principal_mission_creation_use_guard",
        "mission_creation_authenticated_provenance_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_mission_creation_request_identity",
        "principal_mission_creation_effect_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS mission_creation_provenance"
    )


def remove_schema_v9_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v9 layer from a test fixture."""

    remove_schema_v10_objects(connection)
    for trigger in (
        "mission_simulation_authentication_baseline_insert_once",
        "mission_simulation_authentication_baseline_snapshot_guard",
        "mission_simulation_authentication_baseline_immutable",
        "mission_simulation_authentication_baseline_no_delete",
        "simulation_receipt_requires_authentication_baseline",
        "simulation_receipt_insert_once",
        "simulation_receipt_immutable",
        "simulation_receipt_no_delete",
        "simulation_receipt_insert_guard",
        "simulation_consumption_transition_guard",
        "simulation_consumption_core_write_once",
        "principal_simulation_use_guard",
        "principal_simulation_effect_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_simulation_request_identity",
        "principal_simulation_idempotency_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS "
        "mission_simulation_authentication_baselines"
    )


def remove_schema_v8_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v8 layer from a test fixture."""

    remove_schema_v9_objects(connection)
    for trigger in (
        "mission_approval_revocation_authentication_baseline_insert_once",
        "mission_approval_revocation_authentication_baseline_snapshot_guard",
        "mission_approval_revocation_authentication_baseline_immutable",
        "mission_approval_revocation_authentication_baseline_no_delete",
        "approval_revocation_requires_authentication_baseline",
        "approval_revocation_insert_once",
        "approval_revocation_immutable",
        "approval_revocation_no_delete",
        "approval_revocation_insert_guard",
        "approval_revocation_transition_guard",
        "principal_approval_revocation_use_guard",
        "principal_approval_revocation_effect_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_approval_revocation_request_identity",
        "principal_approval_revocation_idempotency_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS "
        "mission_approval_revocation_authentication_baselines"
    )


def remove_schema_v7_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v7 layer from a test fixture."""

    remove_schema_v8_objects(connection)
    for trigger in (
        "mission_approval_submission_authentication_baseline_insert_once",
        "mission_approval_submission_authentication_baseline_snapshot_guard",
        "mission_approval_submission_authentication_baseline_immutable",
        "mission_approval_submission_authentication_baseline_no_delete",
        "approval_submission_requires_authentication_baseline",
        "approval_submission_no_delete",
        "approval_submission_insert_once",
        "approval_submission_core_write_once",
        "principal_approval_submission_use_guard",
        "principal_approval_submission_effect_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_approval_submission_request_identity",
        "principal_approval_submission_idempotency_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS "
        "mission_approval_submission_authentication_baselines"
    )


def remove_schema_v6_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v6 layer from a test fixture."""

    remove_schema_v7_objects(connection)
    for trigger in (
        "mission_approval_decision_authentication_baseline_insert_once",
        "mission_approval_decision_authentication_baseline_snapshot_guard",
        "mission_approval_decision_authentication_baseline_immutable",
        "mission_approval_decision_authentication_baseline_no_delete",
        "approval_decision_requires_authentication_baseline",
        "approval_decision_core_write_once",
        "approval_decision_state_transition_guard",
        "approval_decision_no_delete",
        "approval_decision_insert_once",
        "approval_identity_write_once",
        "principal_approval_decision_use_guard",
        "principal_approval_decision_effect_guard",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    for index in (
        "principal_approval_decision_request_identity",
        "principal_approval_decision_idempotency_identity",
    ):
        connection.execute(f"DROP INDEX IF EXISTS {index}")
    connection.execute(
        "DROP TABLE IF EXISTS "
        "mission_approval_decision_authentication_baselines"
    )


def remove_schema_v5_objects(
    connection: sqlite3.Connection,
) -> None:
    """Remove the complete schema v5 layer from a test fixture."""

    remove_schema_v6_objects(connection)
    for trigger in (
        "mission_event_authentication_baseline_insert_once",
        "mission_event_authentication_baseline_snapshot_guard",
        "mission_event_authentication_baseline_immutable",
        "mission_event_authentication_baseline_no_delete",
        "mission_event_requires_authentication_baseline",
        "principal_assertion_use_insert_once",
        "principal_event_append_idempotency_null",
        "principal_assertion_effect_insert_once",
        "principal_event_append_effect_guard",
        "mission_principal_ledger_insert_once",
        "mission_principal_ledger_no_delete",
    ):
        connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    connection.execute(
        "DROP INDEX IF EXISTS principal_event_append_request_identity"
    )
    connection.execute(
        "DROP TABLE IF EXISTS mission_event_authentication_baselines"
    )


def downgrade_connection_to_schema_v1(
    connection: sqlite3.Connection,
) -> None:
    """Convert a current test store into an exact schema v1 fixture."""

    connection.execute("PRAGMA foreign_keys = OFF")
    remove_schema_v5_objects(connection)
    for table in (
        "mission_scope_grant_revocations",
        "mission_scope_revocation_baselines",
        "principal_assertion_effects",
        "principal_assertion_uses",
        "mission_principal_ledgers",
        "mission_scope_grants",
        "trust_policy_history",
        "store_identity",
        "approval_revocations",
        "mission_controls",
    ):
        connection.execute(f"DROP TABLE IF EXISTS {table}")
    connection.execute(
        """
        UPDATE store_metadata
        SET value = '1'
        WHERE key = 'schema_version'
        """
    )
    connection.execute("PRAGMA user_version = 1")
    connection.commit()


def mission_data() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "mission_id": MISSION_ID,
        "objective": "Validate durable coordination for a synthetic API",
        "environment": "test",
        "requested_specialist_ids": [SPECIALIST_ID],
        "max_action_tier": "R2",
        "required_evidence_level": "E2",
        "scope_reference": "scope://unit/store",
        "constraints": {
            "production": False,
            "third_party": False,
            "synthetic_data_only": True,
            "isolated_research_range": False,
            "max_cell_size": 20,
        },
    }


def observation_data(
    event_id: str,
    *,
    minute: int = 0,
    target: str | None = None,
    references: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": event_id,
        "mission_id": MISSION_ID,
        "event_type": "observation",
        "actor_profile_id": SPECIALIST_ID,
        "timestamp": f"2026-01-01T10:{minute:02d}:00Z",
        "payload": {
            "target": target or f"synthetic://store/{event_id.lower()}",
            "evidence_refs": [f"evidence://store/{event_id.lower()}"],
            "confidence": "high",
            "sensitivity": "synthetic",
        },
        "references": list(references),
    }


def observation(
    event_id: str,
    *,
    minute: int = 0,
    target: str | None = None,
    references: tuple[str, ...] = (),
) -> MissionEvent:
    return MissionEvent.from_dict(
        observation_data(
            event_id,
            minute=minute,
            target=target,
            references=references,
        )
    )


def proposal_data() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "event_id": "EVT-PROP-001",
        "mission_id": MISSION_ID,
        "event_type": "proposal",
        "actor_profile_id": SPECIALIST_ID,
        "timestamp": "2026-01-01T10:00:00Z",
        "payload": {
            "target": "synthetic://store/policy-model",
            "method": "Evaluate a fixed plan against local policy",
            "action_tier": "R2",
            "expected_effect": "Produce a plan-only validation result",
            "safeguards": [
                "Synthetic data only",
                "No external actions",
            ],
            "rollback": "Discard the local simulation record",
        },
        "references": [],
    }


class MissionStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not REGISTRY_PATH.is_file():
            raise unittest.SkipTest(f"Registry fixture is not available: {REGISTRY_PATH}")
        cls.registry = load_registry(REGISTRY_PATH)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.path = self.directory / "missions.sqlite3"
        self.mission = MissionRequest.from_dict(mission_data())

    def new_store(self, path: Path | None = None) -> MissionStore:
        return MissionStore(path or self.path, clock=lambda: FIXED_TIME)

    def initialized_store(self) -> MissionStore:
        store = self.new_store()
        store.initialize()
        store.create_mission(self.registry, self.mission)
        return store

    def submitted_approval(self) -> tuple[MissionStore, ApprovalService, str]:
        store = self.initialized_store()
        store.append_event(
            self.registry,
            MissionEvent.from_dict(proposal_data()),
            expected_revision=0,
        )
        approvals = ApprovalService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        )
        record = approvals.submit(
            mission_id=MISSION_ID,
            proposal_id="EVT-PROP-001",
            executor_profile_id=SPECIALIST_ID,
            review_expires_at="2026-01-01T10:30:00Z",
            idempotency_key="store-submit-001",
            principal_profile_id=SPECIALIST_ID,
        )
        return store, approvals, record.approval_id

    def consumed_simulation(
        self,
    ) -> tuple[MissionStore, str, str]:
        store, approvals, approval_id = self.submitted_approval()
        approvals.approve(
            approval_id,
            authority="unit-control",
            constraints=("Simulation only",),
            authorization_expires_at="2026-01-01T11:00:00Z",
            idempotency_key="store-approve-001",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        receipt = SimulationService(
            store,
            self.registry,
            clock=lambda: DECISION_TIME,
        ).simulate(
            approval_id,
            idempotency_key="store-simulate-001",
            principal_profile_id=SPECIALIST_ID,
        )
        return store, approval_id, receipt.simulation_id

    def test_initialize_is_idempotent_and_preserves_data(self) -> None:
        store = self.new_store()
        store.initialize()
        created = store.create_mission(self.registry, self.mission)

        store.initialize()

        reopened = self.new_store().get_mission(self.registry, MISSION_ID)
        self.assertEqual(reopened.mission, self.mission)
        self.assertEqual(reopened.context_hash, created.context_hash)
        self.assertEqual(reopened.revision, 0)
        with closing(sqlite3.connect(self.path)) as connection:
            mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode, "delete")

    def test_schema_v2_rejects_wal_journal_mode_on_open(self) -> None:
        store = self.initialized_store()
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        self.assertEqual(mode, "wal")

        with self.assertRaises(StoreIntegrityError):
            store.get_mission(self.registry, MISSION_ID)
        with self.assertRaises(StoreIntegrityError):
            store.append_event(
                self.registry,
                observation("EVT-WAL-WRITE"),
                expected_revision=0,
            )
        with self.assertRaises(StoreIntegrityError):
            store.initialize()

    def test_initialize_rejects_an_unrelated_database(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("CREATE TABLE unrelated(value TEXT)")
            connection.execute("INSERT INTO unrelated(value) VALUES ('keep')")
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            self.new_store().initialize()

        with closing(sqlite3.connect(self.path)) as connection:
            value = connection.execute("SELECT value FROM unrelated").fetchone()[0]
            mission_table = connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'missions'"
            ).fetchone()
        self.assertEqual(value, "keep")
        self.assertIsNone(mission_table)

    def test_initialize_wraps_filesystem_errors(self) -> None:
        store = self.new_store(self.directory / "blocked" / "missions.sqlite3")

        with (
            mock.patch(
                "sunderkey.store.Path.mkdir",
                side_effect=PermissionError("denied"),
            ),
            self.assertRaisesRegex(
                StoreError,
                "Could not initialize mission store",
            ),
        ):
            store.initialize()

    def test_schema_manifest_rejects_a_wrong_object_type(self) -> None:
        store = self.initialized_store()

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP INDEX mission_events_by_id")
            connection.execute(
                "CREATE TABLE mission_events_by_id(value TEXT)"
            )
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "schema manifest",
        ):
            store.verify_store(self.registry)

    def test_mission_round_trip_preserves_context_and_cell(self) -> None:
        store = self.new_store()
        store.initialize()
        created = store.create_mission(self.registry, self.mission)

        loaded = self.new_store().get_mission(self.registry, MISSION_ID)
        expected_cell = assemble_joint_mission_cell(self.registry, self.mission)

        self.assertEqual(loaded.mission, self.mission)
        self.assertEqual(loaded.cell, expected_cell)
        self.assertEqual(
            loaded.allowed_profile_ids,
            tuple(sorted(set(expected_cell.all_profile_ids))),
        )
        self.assertEqual(loaded.context_hash, created.context_hash)
        self.assertEqual(loaded.head_hash, loaded.context_hash)
        self.assertEqual(loaded.revision, 0)

    def test_valid_append_survives_reopen(self) -> None:
        store = self.initialized_store()
        event = observation("EVT-OBS-001")

        receipt = store.append_event(
            self.registry,
            event,
            expected_revision=0,
        )

        reopened = self.new_store()
        events = reopened.list_events(self.registry, MISSION_ID)
        report = reopened.verify_mission(self.registry, MISSION_ID)
        self.assertEqual(receipt.sequence, 1)
        self.assertEqual(receipt.revision, 1)
        self.assertFalse(receipt.idempotent)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event.to_dict(), event.to_dict())
        self.assertEqual(events[0].entry_hash, receipt.entry_hash)
        self.assertEqual(report.event_count, 1)
        self.assertEqual(report.revision, 1)

    def test_exact_retry_is_idempotent(self) -> None:
        store = self.initialized_store()
        event = observation("EVT-OBS-001")
        first = store.append_event(
            self.registry,
            event,
            expected_revision=0,
        )

        retry = store.append_event(
            self.registry,
            MissionEvent.from_dict(event.to_dict()),
            expected_revision=0,
        )

        self.assertTrue(retry.idempotent)
        self.assertEqual(retry.sequence, first.sequence)
        self.assertEqual(retry.revision, 1)
        self.assertEqual(retry.entry_hash, first.entry_hash)
        self.assertEqual(len(store.list_events(self.registry, MISSION_ID)), 1)

    def test_conflicting_event_id_reuse_is_rejected(self) -> None:
        store = self.initialized_store()
        store.append_event(self.registry, observation("EVT-OBS-001"))

        with self.assertRaises(StoreConflictError):
            store.append_event(
                self.registry,
                observation(
                    "EVT-OBS-001",
                    target="synthetic://store/different-target",
                ),
            )

        events = store.list_events(self.registry, MISSION_ID)
        self.assertEqual(len(events), 1)
        self.assertEqual(
            events[0].event.payload["target"],
            "synthetic://store/evt-obs-001",
        )

    def test_stale_expected_revision_rejects_new_event(self) -> None:
        store = self.initialized_store()
        store.append_event(
            self.registry,
            observation("EVT-OBS-001"),
            expected_revision=0,
        )

        with self.assertRaises(StoreConflictError):
            store.append_event(
                self.registry,
                observation("EVT-OBS-002", minute=1),
                expected_revision=0,
            )

        mission = store.get_mission(self.registry, MISSION_ID)
        self.assertEqual(mission.revision, 1)
        self.assertEqual(len(store.list_events(self.registry, MISSION_ID)), 1)

    def test_invalid_event_rolls_back_the_full_batch(self) -> None:
        store = self.initialized_store()
        events = (
            observation("EVT-OBS-001"),
            observation(
                "EVT-OBS-002",
                minute=1,
                references=("EVT-MISSING-001",),
            ),
        )

        with self.assertRaises(EventError):
            store.append_events(
                self.registry,
                MISSION_ID,
                events,
                expected_revision=0,
            )

        mission = store.get_mission(self.registry, MISSION_ID)
        self.assertEqual(mission.revision, 0)
        self.assertEqual(store.list_events(self.registry, MISSION_ID), ())

    def test_batch_receipts_use_the_final_committed_revision(self) -> None:
        store = self.initialized_store()
        events = tuple(
            observation(f"EVT-OBS-{index:03d}", minute=index - 1)
            for index in range(1, 4)
        )

        receipts = store.append_events(
            self.registry,
            MISSION_ID,
            events,
            expected_revision=0,
        )

        self.assertEqual([receipt.sequence for receipt in receipts], [1, 2, 3])
        self.assertEqual([receipt.revision for receipt in receipts], [3, 3, 3])
        self.assertTrue(all(not receipt.idempotent for receipt in receipts))
        self.assertEqual(store.get_mission(self.registry, MISSION_ID).revision, 3)

    def test_direct_invalid_event_object_is_rejected_without_storage(self) -> None:
        store = self.initialized_store()
        invalid = MissionEvent(
            schema_version=1,
            event_id="EVT-OBS-001",
            mission_id=MISSION_ID,
            event_type=EventType.OBSERVATION,
            actor_profile_id=SPECIALIST_ID,
            timestamp="2026-01-01T10:00:00Z",
            payload={},
            references=(),
        )

        with self.assertRaises(EventError):
            store.append_event(self.registry, invalid)

        self.assertEqual(store.get_mission(self.registry, MISSION_ID).revision, 0)
        self.assertEqual(store.list_events(self.registry, MISSION_ID), ())

    def test_event_json_tampering_is_detected(self) -> None:
        store = self.initialized_store()
        store.append_event(self.registry, observation("EVT-OBS-001"))

        with closing(sqlite3.connect(self.path)) as connection:
            raw = connection.execute(
                """
                SELECT event_json FROM mission_events
                WHERE mission_id = ? AND sequence = 1
                """,
                (MISSION_ID,),
            ).fetchone()[0]
            event_value = json.loads(raw)
            event_value["payload"]["target"] = "synthetic://store/tampered"
            tampered = json.dumps(
                event_value,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            connection.execute(
                """
                UPDATE mission_events SET event_json = ?
                WHERE mission_id = ? AND sequence = 1
                """,
                (tampered, MISSION_ID),
            )
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            store.verify_mission(self.registry, MISSION_ID)

    def test_foreign_key_violation_is_detected(self) -> None:
        store = self.initialized_store()
        orphan = observation_data("EVT-ORPHAN-001")
        orphan["mission_id"] = "MISSION-ORPHAN-001"

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("PRAGMA foreign_keys = OFF")
            baseline_trigger = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger'
                  AND name =
                    'mission_event_requires_authentication_baseline'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER "
                "mission_event_requires_authentication_baseline"
            )
            connection.execute(
                """
                INSERT INTO mission_events(
                    mission_id,
                    sequence,
                    event_id,
                    event_type,
                    actor_profile_id,
                    event_timestamp,
                    event_json,
                    previous_hash,
                    entry_hash,
                    stored_at
                ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "MISSION-ORPHAN-001",
                    "EVT-ORPHAN-001",
                    "observation",
                    SPECIALIST_ID,
                    "2026-01-01T10:00:00Z",
                    canonical_json(orphan),
                    "sha256:" + ("0" * 64),
                    "sha256:" + ("1" * 64),
                    "2026-01-01T10:00:00Z",
                ),
            )
            connection.execute(str(baseline_trigger))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "foreign key check",
        ):
            store.verify_store(self.registry)

    def test_global_counts_must_reconcile(self) -> None:
        store, _, _ = self.submitted_approval()

        with (
            mock.patch.object(
                store,
                "_verify_auxiliary_state",
                return_value=(0, 0),
            ),
            self.assertRaisesRegex(
                StoreIntegrityError,
                "counts do not reconcile",
            ),
        ):
            store.verify_store(self.registry)

    def test_pending_approval_id_must_be_deterministic(self) -> None:
        store, _, approval_id = self.submitted_approval()

        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_identity_write_once'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_identity_write_once"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET approval_id = 'NOT-A-STABLE-ID'
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Approval ID binding is invalid",
        ):
            store.verify_store(self.registry)

    def test_denied_decision_timestamp_must_match_blocker(self) -> None:
        store, approvals, approval_id = self.submitted_approval()
        approvals.deny(
            approval_id,
            reason_code="scope-not-confirmed",
            reason="Scope confirmation is incomplete",
            risk="Target identity is ambiguous",
            decision_owner="owner://unit/control",
            idempotency_key="store-deny-001",
            expected_version=1,
            principal_profile_id=CONTROL_ID,
        )
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

        with closing(sqlite3.connect(self.path)) as connection:
            trigger_sql = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'approval_decision_core_write_once'
                """
            ).fetchone()[0]
            connection.execute(
                "DROP TRIGGER approval_decision_core_write_once"
            )
            connection.execute(
                """
                UPDATE approval_queue
                SET decision_at = '2026-01-01T10:06:00Z'
                WHERE approval_id = ?
                """,
                (approval_id,),
            )
            connection.execute(str(trigger_sql))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Denied approval binding is invalid",
        ):
            store.verify_store(self.registry)

    def test_public_append_rejects_orphan_simulation_authorization(self) -> None:
        store = self.initialized_store()
        proposal = MissionEvent.from_dict(proposal_data())
        store.append_event(
            self.registry,
            proposal,
            expected_revision=0,
        )
        authorization = MissionEvent.from_dict(
            {
                "schema_version": 1,
                "event_id": "EVT-AUTH-ORPHAN-001",
                "mission_id": MISSION_ID,
                "event_type": "authorization",
                "actor_profile_id": CONTROL_ID,
                "timestamp": "2026-01-01T10:05:00Z",
                "payload": {
                    "proposal_id": proposal.event_id,
                    "executor_profile_id": SPECIALIST_ID,
                    "authority": "unit-control",
                    "scope_token": "scope://unit/store",
                    "action_hash": compute_proposal_action_hash(
                        proposal.payload
                    ),
                    "action_tier": "R2",
                    "expires_at": "2026-01-01T11:00:00Z",
                    "constraints": ["Simulation only"],
                    "approval_id": "APR-ORPHAN-001",
                    "purpose": "simulation",
                },
                "references": [proposal.event_id],
            }
        )
        with self.assertRaisesRegex(
            StoreError,
            "must be created through ApprovalService",
        ):
            store.append_event(
                self.registry,
                authorization,
                expected_revision=1,
            )
        report = store.verify_store(self.registry)
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.event_count, 1)

    def test_simulation_receipt_executor_must_match_approval(self) -> None:
        store, approval_id, simulation_id = self.consumed_simulation()
        self.assertEqual(
            store.verify_store(self.registry).status,
            "valid",
        )

        with closing(sqlite3.connect(self.path)) as connection:
            trigger = connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE type = 'trigger'
                  AND name = 'simulation_receipt_immutable'
                """
            ).fetchone()
            assert trigger is not None
            connection.execute(
                "DROP TRIGGER simulation_receipt_immutable"
            )
            receipt_json = connection.execute(
                """
                SELECT receipt_json
                FROM simulation_receipts
                WHERE approval_id = ?
                """,
                (approval_id,),
            ).fetchone()[0]
            receipt = json.loads(receipt_json)
            receipt["executor_profile_id"] = ASSURANCE_ID
            content = dict(receipt)
            content.pop("receipt_hash")
            receipt_hash = sha256_text(canonical_json(content))
            receipt["receipt_hash"] = receipt_hash
            connection.execute(
                """
                UPDATE simulation_receipts
                SET receipt_json = ?, receipt_hash = ?
                WHERE simulation_id = ?
                """,
                (
                    canonical_json(receipt),
                    receipt_hash,
                    simulation_id,
                ),
            )
            connection.execute(str(trigger[0]))
            connection.commit()

        with self.assertRaisesRegex(
            StoreIntegrityError,
            "Simulation receipt indexes are invalid",
        ):
            store.verify_store(self.registry)

    def test_backup_rejects_a_semantically_invalid_source(self) -> None:
        store = self.initialized_store()
        store.append_event(self.registry, observation("EVT-OBS-001"))
        backup_path = self.directory / "invalid-backup.sqlite3"

        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                """
                UPDATE mission_events
                SET actor_profile_id = ?
                WHERE mission_id = ? AND sequence = 1
                """,
                (ASSURANCE_ID, MISSION_ID),
            )
            connection.commit()

        with self.assertRaises(StoreIntegrityError):
            store.backup(self.registry, backup_path)
        self.assertFalse(backup_path.exists())

    def test_backup_wraps_filesystem_errors(self) -> None:
        store = self.initialized_store()
        backup_path = self.directory / "blocked-backup.sqlite3"

        with (
            mock.patch(
                "sunderkey.store.tempfile.mkstemp",
                side_effect=PermissionError("denied"),
            ),
            self.assertRaisesRegex(
                StoreError,
                "Could not prepare mission store backup",
            ),
        ):
            store.backup(self.registry, backup_path)
        self.assertFalse(backup_path.exists())

    def test_backup_race_never_overwrites_destination(self) -> None:
        store = self.initialized_store()
        store.append_event(self.registry, observation("EVT-OBS-001"))
        backup_path = self.directory / "raced-backup.sqlite3"
        competing_content = b"created-by-another-process"

        def raced_publish(source: Path, destination: Path) -> None:
            del source
            Path(destination).write_bytes(competing_content)
            raise FileExistsError("destination won the race")

        with (
            mock.patch(
                "sunderkey.store.os.link",
                side_effect=raced_publish,
            ),
            self.assertRaises(StoreConflictError),
        ):
            store.backup(self.registry, backup_path)

        self.assertEqual(backup_path.read_bytes(), competing_content)
        self.assertEqual(
            tuple(self.directory.glob(".raced-backup.sqlite3.*.tmp")),
            (),
        )

    def test_backup_is_verified_and_does_not_overwrite(self) -> None:
        store = self.initialized_store()
        store.append_event(self.registry, observation("EVT-OBS-001"))
        backup_path = self.directory / "backup.sqlite3"

        created = store.backup(self.registry, backup_path)

        self.assertEqual(created, backup_path.resolve())
        report = self.new_store(backup_path).verify_mission(
            self.registry,
            MISSION_ID,
        )
        self.assertEqual(report.event_count, 1)

        original_bytes = backup_path.read_bytes()
        with self.assertRaises(StoreConflictError):
            store.backup(self.registry, backup_path)
        self.assertEqual(backup_path.read_bytes(), original_bytes)


if __name__ == "__main__":
    unittest.main()

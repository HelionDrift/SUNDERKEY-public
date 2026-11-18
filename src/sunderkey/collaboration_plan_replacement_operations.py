"""Read-only readiness and authenticated plan replacement operator boundary."""

from __future__ import annotations

import json
import re
import sqlite3
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .authenticated_collaboration_plan_replacement import (
    AuthenticatedCollaborationPlanReplacementStoreService,
    _verify_authenticated_replacement_replay_state,
)
from .collaboration import CollaborationPlan, WorkItem, WorkItemKind
from .collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
)
from .collaboration_plan_replacement_authentication import (
    CollaborationPlanReplacementAuthorityCredential,
    _normalize_credentials,
    authenticate_collaboration_plan_replacement_authority,
    collaboration_plan_replacement_authority_replay_keys,
    validate_plan_replacement_authority_requirement_count,
)
from .collaboration_plan_replacement_authority import (
    CollaborationPlanReplacementAuthorityPlan,
    build_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from .collaboration_plan_replacement_authority_upgrade import (
    CollaborationPlanReplacementAuthorityUpgrade,
    build_collaboration_plan_replacement_authority_upgrade,
)
from .collaboration_plan_replacement_preflight import (
    CollaborationPlanReplacementPreflight,
    build_collaboration_plan_replacement_preflight,
)
from .collaboration_plan_replacement_store import (
    CollaborationPlanReplacementCommitReceipt,
    _build_source_snapshots_in_connection,
    _latest_work_rows,
    _verify_collaboration_plan_replacement_state,
)
from .collaboration_reconfiguration_policy import (
    CollaborationReconfigurationAuthorityPolicy,
)
from .errors import (
    CollaborationPlanError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import PrincipalAssertion, ScopeGrant
from .registry import ExpertRegistry
from .store import MissionStore, canonical_json, format_timestamp, sha256_text
from .validation import loads_json_without_duplicate_keys

SCHEMA_VERSION = 1
READINESS_DOMAIN = "sunderkey.collaboration-plan-replacement-readiness.v1"
PREPARATION_DOMAIN = "sunderkey.collaboration-plan-replacement-preparation.v1"
SCOPE_HIGH_WATER_DOMAIN = "sunderkey.collaboration-plan-replacement-scope-high-water.v1"
EXPERT_REVIEW_HIGH_WATER_DOMAIN = (
    "sunderkey.collaboration-plan-replacement-expert-review-high-water.v1"
)
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_MAPPING_ITEMS = 10_000
MAX_DOCUMENT_DEPTH = 64
MAX_DOCUMENT_NODES = 250_000
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
STORE_ID_PATTERN = re.compile(r"STR-[0-9A-F]{32}\Z")
TIMESTAMP_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SOURCE_SNAPSHOT_FIELDS = frozenset(
    {
        "ownership_snapshot_sha256",
        "work_snapshot_sha256",
        "cancellation_snapshot_sha256",
        "execution_session_snapshot_sha256",
        "terminal_custody_snapshot_sha256",
    }
)
BLOCKER_OPERATIONS = {
    "active_work_lease": "terminalize_work_lease",
    "active_execution_session": "revoke_execution_session",
    "terminal_custody_missing": "commit_terminal_custody",
    "expert_review_incomplete": "complete_expert_review",
    "expert_review_closure_unprojected": "project_expert_review_closure",
    "expert_review_revocation_unprojected": "project_expert_review_revocation",
}


class PlanReplacementReadinessError(StoreConflictError):
    """Raised when an exact replacement preparation is not ready."""


class StalePlanReplacementReadinessError(StoreConflictError):
    """Raised when durable state no longer matches a prepared assessment."""


class PlanReplacementDrainError(StoreConflictError):
    """Raised when work or execution sessions have not reached terminal state."""


class PlanReplacementCustodyError(StoreIntegrityError):
    """Raised when terminal execution lacks required durable custody."""


class PlanReplacementCompareAndSwapError(StoreConflictError):
    """Raised when an optimistic durable-state comparison fails."""


def _canonical_sha256(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 256


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None


def _is_store_id(value: Any) -> bool:
    return isinstance(value, str) and STORE_ID_PATTERN.fullmatch(value) is not None


def _is_timestamp(value: Any) -> bool:
    return isinstance(value, str) and TIMESTAMP_PATTERN.fullmatch(value) is not None


def _is_nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reject_control_characters(value: Any, label: str) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > MAX_DOCUMENT_DEPTH or nodes > MAX_DOCUMENT_NODES:
            raise CollaborationPlanError(f"{label} exceeds structural limits")
        if isinstance(current, str):
            if any(
                ord(character) < 32
                or ord(character) == 127
                or character in {"\u2028", "\u2029"}
                or unicodedata.category(character) in {"Cf", "Cs"}
                for character in current
            ):
                raise CollaborationPlanError(f"{label} contains control characters")
        elif isinstance(current, Mapping):
            pending.extend((item, depth + 1) for item in current)
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            pending.extend((item, depth + 1) for item in current)


def _load_bounded_json(path: str | Path, label: str) -> Any:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_DOCUMENT_BYTES:
            raise CollaborationPlanError(f"{label} exceeds the size limit")
        text = source.read_text(encoding="utf-8")
        if len(text.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise CollaborationPlanError(f"{label} exceeds the size limit")
        raw = loads_json_without_duplicate_keys(text)
    except CollaborationPlanError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise CollaborationPlanError(f"Could not load {label}") from exc
    _reject_control_characters(raw, label)
    return raw


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise StoreError("Plan replacement operations clock must return an aware datetime")
    return value.astimezone(UTC).replace(microsecond=0)


def _owner_class(item: WorkItem) -> str:
    return {
        WorkItemKind.READINESS: "mission_coordination",
        WorkItemKind.SPECIALIST_ANALYSIS: "specialist",
        WorkItemKind.DOMAIN_SYNTHESIS: "domain_command",
        WorkItemKind.GROUP_INTEGRATION: "mission_coordination",
        WorkItemKind.CROSS_SURFACE_INTEGRATION: "mission_coordination",
        WorkItemKind.CONTROL_REVIEW: "independent_control",
        WorkItemKind.EVIDENCE_REVIEW: "independent_assurance",
        WorkItemKind.ASSURANCE_REVIEW: "independent_assurance",
    }[item.kind]


def _objective_sha256(item: WorkItem) -> str:
    return _canonical_sha256(
        {
            "domain": "sunderkey.collaboration-work-objective.v1",
            "kind": item.kind.value,
            "role_mission": item.role_mission,
            "deliverable": item.deliverable,
        }
    )


def _mapping_intents(raw: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Any], ...]:
    if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
        raise CollaborationPlanError("mapping_intents must be a sequence")
    if len(raw) > MAX_MAPPING_ITEMS:
        raise CollaborationPlanError("mapping_intents exceeds the size limit")
    result: list[dict[str, Any]] = []
    source_ids: set[str] = set()
    replacement_ids: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping) or set(item) != {
            "source_work_item_id",
            "replacement_work_item_id",
            "cross_command_evidence",
        }:
            raise CollaborationPlanError(f"mapping_intents[{index}] fields are invalid")
        source_id = item.get("source_work_item_id")
        replacement_id = item.get("replacement_work_item_id")
        if not isinstance(source_id, str) or not source_id:
            raise CollaborationPlanError("Mapping source identity is invalid")
        if not isinstance(replacement_id, str) or not replacement_id:
            raise CollaborationPlanError("Mapping replacement identity is invalid")
        if source_id in source_ids or replacement_id in replacement_ids:
            raise CollaborationPlanError("Mapping intent identities must be one-to-one")
        evidence = item.get("cross_command_evidence")
        if evidence is not None:
            if not isinstance(evidence, Mapping) or set(evidence) != {
                "capability_catalog_sha256",
                "capability_revalidation_sha256",
                "proposed_owner_qualification_sha256",
                "source_command_review_sha256",
                "destination_command_review_sha256",
            }:
                raise CollaborationPlanError("Cross-command evidence fields are invalid")
            evidence = dict(evidence)
        source_ids.add(source_id)
        replacement_ids.add(replacement_id)
        result.append(
            {
                "source_work_item_id": source_id,
                "replacement_work_item_id": replacement_id,
                "cross_command_evidence": evidence,
            }
        )
    return tuple(sorted(result, key=lambda item: item["source_work_item_id"]))


def _policy_commit(connection: sqlite3.Connection, mission_id: str) -> tuple[Any, Any]:
    row = connection.execute(
        """
        SELECT * FROM collaboration_mission_policy_commits
        WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1
        """,
        (mission_id,),
    ).fetchone()
    if row is None:
        raise PlanReplacementReadinessError(
            "Mission has no authenticated collaboration reconfiguration policy"
        )
    try:
        policy = CollaborationMissionReconfigurationPolicy.from_dict(
            json.loads(str(row["policy_json"]))
        )
    except (json.JSONDecodeError, CollaborationPlanError) as exc:
        raise StoreIntegrityError("Durable collaboration mission policy is invalid") from exc
    owner = connection.execute(
        "SELECT assertion_hash, entry_hash FROM principal_assertion_uses "
        "WHERE issuer = ? AND assertion_id = ?",
        (row["owner_issuer"], row["owner_assertion_id"]),
    ).fetchone()
    control = connection.execute(
        "SELECT assertion_hash, entry_hash FROM principal_assertion_uses "
        "WHERE issuer = ? AND assertion_id = ?",
        (row["control_issuer"], row["control_assertion_id"]),
    ).fetchone()
    if owner is None or control is None:
        raise StoreIntegrityError("Mission policy principal custody is missing")
    commit = {
        "policy_id": str(row["policy_id"]),
        "policy_sha256": str(row["policy_sha256"]),
        "policy_selection_sha256": str(row["selection_sha256"]),
        "authentication_id": str(row["authentication_id"]),
        "authentication_sha256": str(row["authentication_sha256"]),
        "committed_at": str(row["committed_at"]),
        "mission_owner_assertion_id": str(row["owner_assertion_id"]),
        "mission_owner_assertion_sha256": str(owner["assertion_hash"]),
        "mission_owner_ledger_entry_sha256": str(owner["entry_hash"]),
        "independent_control_assertion_id": str(row["control_assertion_id"]),
        "independent_control_assertion_sha256": str(control["assertion_hash"]),
        "independent_control_ledger_entry_sha256": str(control["entry_hash"]),
        "commit_status": "committed_inactive",
    }
    return policy, commit


def _expert_review_high_water(
    connection: sqlite3.Connection,
    mission_id: str,
    *,
    before_use_sequence: int | None = None,
) -> dict[str, Any]:
    query = (
        "SELECT replay.canonical_replay_key_sha256 "
        "FROM authenticated_expert_review_replay_uses AS replay "
        "JOIN principal_assertion_uses AS use "
        "ON use.issuer = replay.assertion_issuer "
        "AND use.assertion_id = replay.assertion_id "
        "AND use.mission_id = replay.mission_id "
        "WHERE replay.mission_id = ?"
    )
    parameters: tuple[Any, ...] = (mission_id,)
    if before_use_sequence is not None:
        query += " AND use.use_sequence < ?"
        parameters = (mission_id, before_use_sequence)
    query += " ORDER BY replay.canonical_replay_key_sha256"
    keys = [str(row[0]) for row in connection.execute(query, parameters).fetchall()]
    return {
        "expert_review_consumed_count": len(keys),
        "expert_review_consumed_sha256": _canonical_sha256(
            {
                "domain": EXPERT_REVIEW_HIGH_WATER_DOMAIN,
                "mission_id": mission_id,
                "replay_keys": keys,
            }
        ),
    }


def _high_water_state(
    connection: sqlite3.Connection,
    store: MissionStore,
    mission_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], Any]:
    identity = store._verify_store_identity(connection)
    trust_policies = store._verify_trust_policy_history(connection, identity)
    current_policy_sha256 = identity["trust_policy_hash"]
    if current_policy_sha256 is None:
        raise PlanReplacementReadinessError("Store has no active principal trust policy")
    verified_policy = trust_policies.get(str(current_policy_sha256))
    if verified_policy is None:
        raise StoreIntegrityError("Current trust policy high-water record is missing")
    trust = {
        "policy_id": str(identity["trust_policy_id"]),
        "policy_version": int(identity["trust_policy_version"]),
        "policy_sha256": str(current_policy_sha256),
        "applied_at": str(identity["policy_applied_at"]),
    }
    grants = connection.execute(
        """
        SELECT grant_hash, grant_id, accepted_at, expires_at
        FROM mission_scope_grants
        WHERE mission_id = ? ORDER BY grant_hash
        """,
        (mission_id,),
    ).fetchall()
    revocations = connection.execute(
        """
        SELECT revocation_sequence, revocation_hash, scope_grant_hash, accepted_at
        FROM mission_scope_grant_revocations
        WHERE mission_id = ? ORDER BY revocation_sequence
        """,
        (mission_id,),
    ).fetchall()
    baseline = connection.execute(
        """
        SELECT head_hash, signed_revocation_count
        FROM mission_scope_revocation_baselines WHERE mission_id = ?
        """,
        (mission_id,),
    ).fetchone()
    if baseline is None:
        raise StoreIntegrityError("Mission scope revocation high-water record is missing")
    scope_body = {
        "mission_id": mission_id,
        "accepted_grants": [
            {
                "grant_id": str(row["grant_id"]),
                "grant_sha256": str(row["grant_hash"]),
                "accepted_at": str(row["accepted_at"]),
                "expires_at": str(row["expires_at"]),
            }
            for row in grants
        ],
        "revocations": [
            {
                "revocation_sequence": int(row["revocation_sequence"]),
                "revocation_sha256": str(row["revocation_hash"]),
                "scope_grant_sha256": str(row["scope_grant_hash"]),
                "accepted_at": str(row["accepted_at"]),
            }
            for row in revocations
        ],
        "revocation_head_sha256": str(baseline["head_hash"]),
        "signed_revocation_count": int(baseline["signed_revocation_count"]),
    }
    scope = {
        "accepted_grant_count": len(grants),
        "revocation_count": len(revocations),
        "revocation_head_sha256": str(baseline["head_hash"]),
        "scope_state_sha256": _canonical_sha256(
            {"domain": SCOPE_HIGH_WATER_DOMAIN, "scope": scope_body}
        ),
    }
    ledger = connection.execute(
        "SELECT assertion_count, head_hash FROM mission_principal_ledgers WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    if ledger is None:
        raise StoreIntegrityError("Mission principal ledger high-water record is missing")
    principal = {
        "assertion_count": int(ledger["assertion_count"]),
        "head_sha256": str(ledger["head_hash"]),
        **_expert_review_high_water(connection, mission_id),
    }
    return trust, scope, principal, verified_policy


def _current_source(
    connection: sqlite3.Connection,
    store: MissionStore,
    registry: ExpertRegistry,
    replacement: CollaborationPlan,
) -> tuple[Any, CollaborationPlan, int]:
    mission_row = connection.execute(
        "SELECT * FROM missions WHERE mission_id = ?", (replacement.mission_id,)
    ).fetchone()
    if mission_row is None:
        raise StoreError("Replacement mission does not exist")
    mission = store._stored_mission_from_row(connection, registry, mission_row)
    head = connection.execute(
        "SELECT * FROM collaboration_plan_active_heads WHERE mission_id = ?",
        (replacement.mission_id,),
    ).fetchone()
    if head is None:
        raise PlanReplacementReadinessError("Mission has no active collaboration plan head")
    activation = connection.execute(
        """
        SELECT plan_json, plan_content_sha256
        FROM collaboration_plan_activations
        WHERE mission_id = ? AND plan_id = ?
        """,
        (replacement.mission_id, head["active_plan_id"]),
    ).fetchone()
    if activation is None:
        raise StoreIntegrityError("Active collaboration plan activation is missing")
    try:
        prior = CollaborationPlan.from_dict(json.loads(str(activation["plan_json"])))
    except (json.JSONDecodeError, CollaborationPlanError) as exc:
        raise StoreIntegrityError("Active collaboration plan is invalid") from exc
    if activation["plan_content_sha256"] != prior.content_sha256:
        raise StoreIntegrityError("Active collaboration plan content is inconsistent")
    return mission, prior, int(head["plan_version"])


def _source_mapping_inputs(
    connection: sqlite3.Connection,
    prior: CollaborationPlan,
    replacement: CollaborationPlan,
    intents: tuple[dict[str, Any], ...],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    prior_items = {item.work_item_id: item for item in prior.work_items}
    replacement_items = {item.work_item_id: item for item in replacement.work_items}
    intent_by_source = {item["source_work_item_id"]: item for item in intents}
    if not set(intent_by_source) <= set(prior_items):
        raise CollaborationPlanError("Mapping intent names an unknown source work item")
    if not {item["replacement_work_item_id"] for item in intents} <= set(replacement_items):
        raise CollaborationPlanError("Mapping intent names an unknown replacement work item")
    latest = _latest_work_rows(connection, prior.mission_id, prior.plan_id)
    carried = {
        str(row["replacement_work_item_id"]): row
        for row in connection.execute(
            """
            SELECT carry.replacement_work_item_id, carry.completed_result_sha256,
                   carry.source_transition_id
            FROM collaboration_plan_activations AS activation
            JOIN collaboration_plan_completed_work_carry_forwards AS carry
              ON carry.replacement_commit_id = activation.replacement_commit_id
            WHERE activation.plan_id = ?
            """,
            (prior.plan_id,),
        ).fetchall()
    }
    translated = {item["source_work_item_id"]: item["replacement_work_item_id"] for item in intents}
    inputs: list[dict[str, Any]] = []
    work_state: dict[str, dict[str, Any]] = {}
    for source_id in sorted(prior_items):
        row = latest.get(source_id)
        carried_row = carried.get(source_id)
        completed = (row is not None and row["transition_kind"] == "complete") or (
            row is None and carried_row is not None
        )
        result_sha256 = (
            str(carried_row["completed_result_sha256"])
            if row is None and carried_row is not None
            else (
                None if row is None or row["result_sha256"] is None else str(row["result_sha256"])
            )
        )
        transition_id = (
            str(carried_row["source_transition_id"])
            if row is None and carried_row is not None
            else (None if row is None else str(row["transition_id"]))
        )
        work_state[source_id] = {
            "state": "completed" if completed else "not_completed",
            "latest_transition_id": transition_id,
            "latest_transition_kind": None if row is None else str(row["transition_kind"]),
            "completed_result_sha256": result_sha256,
        }
        intent = intent_by_source.get(source_id)
        if intent is None:
            continue
        target_id = intent["replacement_work_item_id"]
        source = prior_items[source_id]
        target = replacement_items[target_id]
        translated_dependencies = {
            translated[item] for item in source.dependency_ids if item in translated
        }
        preservation_eligible = all(
            (
                _objective_sha256(source) == _objective_sha256(target),
                _owner_class(source) == _owner_class(target),
                source.required_evidence_level == target.required_evidence_level,
                len(translated_dependencies) == len(source.dependency_ids),
                translated_dependencies == set(target.dependency_ids),
            )
        )
        inputs.append(
            {
                "source_work_item_id": source_id,
                "replacement_work_item_id": target_id,
                "source_state": "completed" if completed else "not_completed",
                "disposition": (
                    "preserve_completed_result"
                    if completed and preservation_eligible
                    else "restart_in_replacement"
                ),
                "completed_result_sha256": result_sha256,
                "cross_command_evidence": intent["cross_command_evidence"],
            }
        )
    return inputs, work_state


def _drain_state(
    connection: sqlite3.Connection,
    mission_id: str,
    plan_id: str,
    cancellation_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []
    operations: list[dict[str, Any]] = []
    latest = _latest_work_rows(connection, mission_id, plan_id)
    for subject, row in sorted(latest.items()):
        if row["transition_kind"] not in {"claim", "renew"}:
            continue
        blockers.append(
            {
                "blocker_code": "active_work_lease",
                "subject_id": subject,
                "work_item_id": subject,
                "detail": "Source work lease must reach a terminal transition",
            }
        )
        operations.append(
            {
                "operation": "terminalize_work_lease",
                "subject_id": subject,
                "work_item_id": subject,
                "required_generation": int(row["generation"]),
            }
        )
    sessions = connection.execute(
        """
        SELECT authority.session_authority_id, authority.session_id, authority.work_item_id,
               activation.session_authority_id IS NOT NULL AS activated,
               revocation.session_authority_id IS NOT NULL AS revoked
        FROM execution_session_authority_commits AS authority
        LEFT JOIN execution_session_activation_commits AS activation
          ON activation.session_authority_id = authority.session_authority_id
        LEFT JOIN execution_session_revocation_commits AS revocation
          ON revocation.session_authority_id = authority.session_authority_id
        WHERE authority.mission_id = ? AND authority.collaboration_plan_id = ?
        ORDER BY authority.session_authority_id
        """,
        (mission_id, plan_id),
    ).fetchall()
    custody_sessions = {
        (str(row["work_item_id"]), str(row["source_session_id"]))
        for row in connection.execute(
            "SELECT work_item_id, "
            "json_extract(custody_plan_json, "
            "'$.transfer_request.source_session.session_id') AS source_session_id "
            "FROM execution_terminal_custody_commits "
            "WHERE mission_id = ? ORDER BY work_item_id",
            (mission_id,),
        ).fetchall()
        if row["source_session_id"] is not None
    }
    for row in sessions:
        session_id = str(row["session_authority_id"])
        worker_session_id = str(row["session_id"])
        work_item_id = str(row["work_item_id"])
        if bool(row["activated"]) and not bool(row["revoked"]):
            blockers.append(
                {
                    "blocker_code": "active_execution_session",
                    "subject_id": session_id,
                    "work_item_id": work_item_id,
                    "detail": "Activated source execution session must be revoked",
                }
            )
            operations.append(
                {
                    "operation": "revoke_execution_session",
                    "subject_id": session_id,
                    "work_item_id": work_item_id,
                    "required_generation": None,
                }
            )
        if (
            work_item_id in cancellation_ids
            and bool(row["activated"])
            and bool(row["revoked"])
            and (work_item_id, worker_session_id) not in custody_sessions
        ):
            blockers.append(
                {
                    "blocker_code": "terminal_custody_missing",
                    "subject_id": session_id,
                    "work_item_id": work_item_id,
                    "detail": "Cancelled executed work requires terminal custody",
                }
            )
            operations.append(
                {
                    "operation": "commit_terminal_custody",
                    "subject_id": session_id,
                    "work_item_id": work_item_id,
                    "required_generation": None,
                }
            )
    has_review_custody = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
        "AND name = 'authenticated_expert_review_snapshot_registrations'"
    ).fetchone()
    review_rows = (
        []
        if has_review_custody is None
        else connection.execute(
            """
        SELECT registration.snapshot_id, closure.closure_id,
               closure_projection.closure_id IS NOT NULL AS closure_projected,
               revocation.revocation_id,
               revocation_projection.revocation_id IS NOT NULL AS revocation_projected
        FROM authenticated_expert_review_snapshot_registrations AS registration
        LEFT JOIN authenticated_expert_review_closures AS closure
          ON closure.snapshot_id = registration.snapshot_id
        LEFT JOIN authenticated_expert_review_closure_projections AS closure_projection
          ON closure_projection.closure_id = closure.closure_id
        LEFT JOIN authenticated_expert_review_revocations AS revocation
          ON revocation.closure_id = closure.closure_id
        LEFT JOIN authenticated_expert_review_revocation_projections AS revocation_projection
          ON revocation_projection.revocation_id = revocation.revocation_id
        WHERE registration.mission_id = ? AND registration.plan_id = ?
        ORDER BY registration.snapshot_id
        """,
            (mission_id, plan_id),
        ).fetchall()
    )
    for row in review_rows:
        snapshot_id = str(row["snapshot_id"])
        if row["closure_id"] is None:
            blockers.append(
                {
                    "blocker_code": "expert_review_incomplete",
                    "subject_id": snapshot_id,
                    "work_item_id": snapshot_id,
                    "detail": "Registered expert review must reach authenticated closure",
                }
            )
            operations.append(
                {
                    "operation": "complete_expert_review",
                    "subject_id": snapshot_id,
                    "work_item_id": snapshot_id,
                    "required_generation": None,
                }
            )
            continue
        closure_id = str(row["closure_id"])
        if not bool(row["closure_projected"]):
            blockers.append(
                {
                    "blocker_code": "expert_review_closure_unprojected",
                    "subject_id": closure_id,
                    "work_item_id": snapshot_id,
                    "detail": "Authenticated expert review closure must be projected",
                }
            )
            operations.append(
                {
                    "operation": "project_expert_review_closure",
                    "subject_id": closure_id,
                    "work_item_id": snapshot_id,
                    "required_generation": None,
                }
            )
        if row["revocation_id"] is not None and not bool(row["revocation_projected"]):
            revocation_id = str(row["revocation_id"])
            blockers.append(
                {
                    "blocker_code": "expert_review_revocation_unprojected",
                    "subject_id": revocation_id,
                    "work_item_id": snapshot_id,
                    "detail": "Expert review revocation must be projected",
                }
            )
            operations.append(
                {
                    "operation": "project_expert_review_revocation",
                    "subject_id": revocation_id,
                    "work_item_id": snapshot_id,
                    "required_generation": None,
                }
            )
    return (
        sorted(blockers, key=lambda item: (item["blocker_code"], item["subject_id"])),
        sorted(operations, key=lambda item: (item["operation"], item["subject_id"])),
    )


def _validate_high_water(value: Any, label: str, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CollaborationPlanError(f"Plan replacement {label} is invalid")
    return value


def _validate_readiness_high_waters(raw: Mapping[str, Any]) -> None:
    trust = _validate_high_water(
        raw.get("trust_high_water"),
        "trust high-water",
        {"policy_id", "policy_version", "policy_sha256", "applied_at"},
    )
    if (
        not _is_identifier(trust.get("policy_id"))
        or not isinstance(trust.get("policy_version"), int)
        or isinstance(trust.get("policy_version"), bool)
        or trust.get("policy_version") < 1
        or not _is_sha256(trust.get("policy_sha256"))
        or not _is_timestamp(trust.get("applied_at"))
    ):
        raise CollaborationPlanError("Plan replacement trust high-water is invalid")
    scope = _validate_high_water(
        raw.get("scope_high_water"),
        "scope high-water",
        {
            "accepted_grant_count",
            "revocation_count",
            "revocation_head_sha256",
            "scope_state_sha256",
        },
    )
    if (
        not _is_nonnegative_integer(scope.get("accepted_grant_count"))
        or not _is_nonnegative_integer(scope.get("revocation_count"))
        or not _is_sha256(scope.get("revocation_head_sha256"))
        or not _is_sha256(scope.get("scope_state_sha256"))
    ):
        raise CollaborationPlanError("Plan replacement scope high-water is invalid")
    principal = _validate_high_water(
        raw.get("principal_ledger_high_water"),
        "principal ledger high-water",
        {
            "assertion_count",
            "head_sha256",
            "expert_review_consumed_count",
            "expert_review_consumed_sha256",
        },
    )
    if (
        not _is_nonnegative_integer(principal.get("assertion_count"))
        or not _is_sha256(principal.get("head_sha256"))
        or not _is_nonnegative_integer(principal.get("expert_review_consumed_count"))
        or not _is_sha256(principal.get("expert_review_consumed_sha256"))
    ):
        raise CollaborationPlanError("Plan replacement principal ledger high-water is invalid")
    replay = _validate_high_water(
        raw.get("replacement_replay_high_water"),
        "replacement replay high-water",
        {"consumed_count", "consumed_replay_keys_sha256"},
    )
    if not _is_nonnegative_integer(replay.get("consumed_count")) or not _is_sha256(
        replay.get("consumed_replay_keys_sha256")
    ):
        raise CollaborationPlanError("Plan replacement replay high-water is invalid")


def _validate_drain_state(
    blockers: Any,
    operations: Any,
) -> None:
    if (
        not isinstance(blockers, list)
        or len(blockers) > 20_000
        or not isinstance(operations, list)
        or len(operations) > 20_000
    ):
        raise CollaborationPlanError("Plan replacement drain assessment is too large")
    blocker_keys: set[tuple[str, str, str | None]] = set()
    for blocker in blockers:
        if not isinstance(blocker, Mapping) or set(blocker) != {
            "blocker_code",
            "subject_id",
            "work_item_id",
            "detail",
        }:
            raise CollaborationPlanError("Plan replacement drain blocker is invalid")
        code = blocker.get("blocker_code")
        subject = blocker.get("subject_id")
        work_item = blocker.get("work_item_id")
        detail = blocker.get("detail")
        if (
            code not in {*BLOCKER_OPERATIONS, "mission_not_active"}
            or not _is_identifier(subject)
            or (work_item is not None and not _is_identifier(work_item))
            or not isinstance(detail, str)
            or not 0 < len(detail) <= 512
            or (code == "mission_not_active") != (work_item is None)
        ):
            raise CollaborationPlanError("Plan replacement drain blocker is invalid")
        key = (str(code), str(subject), work_item)
        if key in blocker_keys:
            raise CollaborationPlanError("Plan replacement drain blocker is duplicated")
        blocker_keys.add(key)
    operation_keys: set[tuple[str, str, str]] = set()
    for operation in operations:
        if not isinstance(operation, Mapping) or set(operation) != {
            "operation",
            "subject_id",
            "work_item_id",
            "required_generation",
        }:
            raise CollaborationPlanError("Plan replacement drain operation is invalid")
        kind = operation.get("operation")
        subject = operation.get("subject_id")
        work_item = operation.get("work_item_id")
        generation = operation.get("required_generation")
        if (
            kind not in set(BLOCKER_OPERATIONS.values())
            or not _is_identifier(subject)
            or not _is_identifier(work_item)
            or (
                kind == "terminalize_work_lease"
                and (
                    not isinstance(generation, int)
                    or isinstance(generation, bool)
                    or generation < 1
                )
            )
            or (kind != "terminalize_work_lease" and generation is not None)
        ):
            raise CollaborationPlanError("Plan replacement drain operation is invalid")
        key = (str(kind), str(subject), str(work_item))
        if key in operation_keys:
            raise CollaborationPlanError("Plan replacement drain operation is duplicated")
        operation_keys.add(key)
    expected = {
        (BLOCKER_OPERATIONS[code], subject, str(work_item))
        for code, subject, work_item in blocker_keys
        if code in BLOCKER_OPERATIONS
    }
    if operation_keys != expected:
        raise CollaborationPlanError("Plan replacement drain operations do not match blockers")


@dataclass(frozen=True, slots=True)
class CollaborationPlanReplacementReadiness:
    """Content-addressed read-only replacement and drain assessment."""

    readiness_id: str
    readiness_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlanReplacementReadiness:
        if not isinstance(raw, Mapping):
            raise CollaborationPlanError("Plan replacement readiness must be an object")
        _reject_control_characters(raw, "Plan replacement readiness")
        if len(canonical_json(raw).encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise CollaborationPlanError("Plan replacement readiness exceeds the size limit")
        required = {
            "schema_version",
            "readiness_id",
            "readiness_sha256",
            "observed_at",
            "store_id",
            "mission_id",
            "mission_revision",
            "active_head",
            "prior_plan",
            "replacement_plan",
            "mission_policy",
            "authority_policy",
            "trust_high_water",
            "scope_high_water",
            "principal_ledger_high_water",
            "replacement_replay_high_water",
            "source_snapshot_hashes",
            "mapping_intents",
            "work_state",
            "preflight",
            "required_authority_operations",
            "required_assertion_count",
            "required_replay_key_count",
            "drain_blockers",
            "required_drain_operations",
            "readiness_status",
            "runtime_effect",
        }
        if set(raw) != required or raw.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Plan replacement readiness fields are invalid")
        if raw.get("runtime_effect") != "none":
            raise CollaborationPlanError("Readiness assessment cannot have an operational effect")
        blockers = raw.get("drain_blockers")
        status = raw.get("readiness_status")
        if not isinstance(blockers, list) or status not in {
            "ready_for_signed_authority",
            "blocked_pending_drain",
        }:
            raise CollaborationPlanError("Plan replacement readiness status is invalid")
        if (not blockers) != (status == "ready_for_signed_authority"):
            raise CollaborationPlanError("Plan replacement blockers do not match readiness status")
        preflight = CollaborationPlanReplacementPreflight.from_dict(raw.get("preflight"))
        preflight_document = preflight.to_dict()
        try:
            requirement_count = validate_plan_replacement_authority_requirement_count(
                len(preflight_document["authority_requirements"])
            )
            assertion_count = validate_plan_replacement_authority_requirement_count(
                raw.get("required_assertion_count"), "required_assertion_count"
            )
            replay_key_count = validate_plan_replacement_authority_requirement_count(
                raw.get("required_replay_key_count"), "required_replay_key_count"
            )
        except PrincipalAuthenticationError as exc:
            raise CollaborationPlanError("Plan replacement authority counts are invalid") from exc
        if assertion_count != requirement_count or replay_key_count != requirement_count:
            raise CollaborationPlanError(
                "Plan replacement authority counts differ from requirements"
            )
        operations = raw.get("required_authority_operations")
        if not isinstance(operations, list) or len(operations) != requirement_count:
            raise CollaborationPlanError("Plan replacement authority operations are incomplete")
        prior = CollaborationPlan.from_dict(raw.get("prior_plan"))
        replacement = CollaborationPlan.from_dict(raw.get("replacement_plan"))
        mission_policy = CollaborationMissionReconfigurationPolicy.from_dict(
            raw.get("mission_policy")
        )
        authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
            raw.get("authority_policy")
        )
        active_head = raw.get("active_head")
        if not isinstance(active_head, Mapping) or set(active_head) != {
            "plan_id",
            "plan_sha256",
            "plan_version",
        }:
            raise CollaborationPlanError("Plan replacement active head is invalid")
        if (
            raw.get("mission_id") != prior.mission_id
            or replacement.mission_id != prior.mission_id
            or not _is_store_id(raw.get("store_id"))
            or mission_policy.to_dict()["mission_id"] != prior.mission_id
            or mission_policy.to_dict()["authority_policy"]
            != {
                "policy_id": authority_policy.policy_id,
                "policy_sha256": authority_policy.policy_sha256,
            }
            or active_head.get("plan_id") != prior.plan_id
            or active_head.get("plan_sha256") != prior.content_sha256
            or not isinstance(active_head.get("plan_version"), int)
            or isinstance(active_head.get("plan_version"), bool)
            or active_head.get("plan_version") < 1
            or not _is_nonnegative_integer(raw.get("mission_revision"))
            or raw.get("mission_revision") != preflight_document["source_state"]["mission_revision"]
            or preflight_document["prior_plan"]
            != {"plan_id": prior.plan_id, "plan_sha256": prior.content_sha256}
            or preflight_document["replacement_plan"]
            != {
                "plan_id": replacement.plan_id,
                "plan_sha256": replacement.content_sha256,
            }
            or preflight_document["mission_policy_commit"]["policy_id"] != mission_policy.policy_id
            or preflight_document["mission_policy_commit"]["policy_sha256"]
            != mission_policy.policy_sha256
        ):
            raise CollaborationPlanError("Plan replacement readiness source binding is stale")
        snapshots = raw.get("source_snapshot_hashes")
        if (
            not isinstance(snapshots, Mapping)
            or set(snapshots) != SOURCE_SNAPSHOT_FIELDS
            or any(not _is_sha256(value) for value in snapshots.values())
            or any(
                preflight_document["source_state"].get(key) != value
                for key, value in snapshots.items()
            )
        ):
            raise CollaborationPlanError("Plan replacement source snapshots are invalid")
        intents = _mapping_intents(raw.get("mapping_intents"))
        if list(intents) != raw.get("mapping_intents"):
            raise CollaborationPlanError("Plan replacement mapping intents are not canonical")
        expected_intents = sorted(
            (
                {
                    "source_work_item_id": str(item["source_work_item_id"]),
                    "replacement_work_item_id": str(item["replacement_work_item_id"]),
                    "cross_command_evidence": item.get("cross_command_evidence"),
                }
                for item in preflight_document["item_mappings"]
            ),
            key=lambda item: item["source_work_item_id"],
        )
        if list(intents) != expected_intents:
            raise CollaborationPlanError("Plan replacement mapping intents are stale")
        work_state = raw.get("work_state")
        prior_ids = {item.work_item_id for item in prior.work_items}
        if (
            not isinstance(work_state, Mapping)
            or set(work_state) != prior_ids
            or len(work_state) > MAX_MAPPING_ITEMS
            or any(
                not isinstance(value, Mapping)
                or set(value)
                != {
                    "state",
                    "latest_transition_id",
                    "latest_transition_kind",
                    "completed_result_sha256",
                }
                or value.get("state") not in {"completed", "not_completed"}
                or (
                    value.get("latest_transition_id") is not None
                    and not _is_identifier(value.get("latest_transition_id"))
                )
                or (
                    value.get("latest_transition_kind") is not None
                    and not _is_identifier(value.get("latest_transition_kind"))
                )
                or (
                    value.get("completed_result_sha256") is not None
                    and not _is_sha256(value.get("completed_result_sha256"))
                )
                or (
                    value.get("state") == "completed"
                    and (
                        value.get("latest_transition_id") is None
                        or value.get("completed_result_sha256") is None
                    )
                )
                or (
                    value.get("state") == "not_completed"
                    and value.get("completed_result_sha256") is not None
                )
                for value in work_state.values()
            )
        ):
            raise CollaborationPlanError("Plan replacement work state is invalid")
        expected_operations = [
            {
                "requirement_id": str(item["requirement_id"]),
                "operation": str(item["operation"]),
                "role": str(item["role"]),
                "authority_id": str(item["authority_id"]),
                "work_item_id": item.get("work_item_id"),
            }
            for item in preflight_document["authority_requirements"]
        ]
        if operations != expected_operations:
            raise CollaborationPlanError("Plan replacement authority operations are stale")
        source_state = preflight_document["source_state"]
        if (
            active_head.get("plan_id") != source_state["active_plan_id"]
            or active_head.get("plan_sha256") != source_state["active_plan_sha256"]
            or raw.get("observed_at") != source_state["observed_at"]
        ):
            raise CollaborationPlanError("Plan replacement active source state is stale")
        _validate_readiness_high_waters(raw)
        drain_operations = raw.get("required_drain_operations")
        _validate_drain_state(blockers, drain_operations)
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"readiness_id", "readiness_sha256"}
        }
        digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": body})
        readiness_id = "RRA-" + digest.removeprefix("sha256:")[:32].upper()
        if raw.get("readiness_sha256") != digest or raw.get("readiness_id") != readiness_id:
            raise CollaborationPlanError("Plan replacement readiness identity is invalid")
        return cls(readiness_id, digest, canonical_json(dict(raw)))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


@dataclass(frozen=True, slots=True)
class PreparedCollaborationPlanReplacement:
    """Exact no-effect operator preparation awaiting every derived signed assertion."""

    preparation_id: str
    preparation_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> PreparedCollaborationPlanReplacement:
        if not isinstance(raw, Mapping):
            raise CollaborationPlanError("Plan replacement preparation must be an object")
        _reject_control_characters(raw, "Plan replacement preparation")
        if len(canonical_json(raw).encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise CollaborationPlanError("Plan replacement preparation exceeds the size limit")
        required = {
            "schema_version",
            "preparation_id",
            "preparation_sha256",
            "prepared_at",
            "readiness",
            "authority_plan",
            "authority_upgrade",
            "expected_plan_version",
            "preparation_status",
            "runtime_effect",
        }
        if set(raw) != required or raw.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Plan replacement preparation fields are invalid")
        readiness = CollaborationPlanReplacementReadiness.from_dict(raw.get("readiness"))
        if readiness.to_dict()["readiness_status"] != "ready_for_signed_authority":
            raise CollaborationPlanError("Blocked readiness cannot produce a preparation")
        plan = CollaborationPlanReplacementAuthorityPlan.from_dict(raw.get("authority_plan"))
        upgrade = CollaborationPlanReplacementAuthorityUpgrade.from_dict(
            raw.get("authority_upgrade")
        )
        readiness_document = readiness.to_dict()
        preflight_document = readiness_document["preflight"]
        requirement_count = readiness_document["required_assertion_count"]
        plan_requirements = plan.to_dict()["assertion_requirements"]
        upgrade_requirements = upgrade.to_dict()["authority_requirements"]
        expected_requirement_ids = {
            item["requirement_id"] for item in preflight_document["authority_requirements"]
        }
        if (
            len(plan_requirements) != requirement_count
            or len(upgrade_requirements) != requirement_count
            or {item["requirement_id"] for item in plan_requirements} != expected_requirement_ids
            or {item["source_requirement_id"] for item in upgrade_requirements}
            != expected_requirement_ids
        ):
            raise CollaborationPlanError("Preparation authority requirement coverage is invalid")
        expected_source = {
            "preflight_id": preflight_document["preflight_id"],
            "preflight_sha256": preflight_document["preflight_sha256"],
            "selection_sha256": preflight_document["selection_sha256"],
        }
        if plan.to_dict()["source_preflight"] != expected_source or upgrade.to_dict()[
            "source_preflight"
        ] != {
            "preflight_id": expected_source["preflight_id"],
            "preflight_sha256": expected_source["preflight_sha256"],
        }:
            raise CollaborationPlanError("Preparation authority artifacts are stale")
        source_policies = plan.to_dict()["source_policies"]
        readiness_authority_policy = readiness_document["authority_policy"]
        readiness_mission_policy = readiness_document["mission_policy"]
        if source_policies != {
            "reconfiguration_authority_policy": {
                "policy_id": readiness_authority_policy["policy_id"],
                "policy_sha256": readiness_authority_policy["policy_sha256"],
            },
            "mission_reconfiguration_policy": {
                "policy_id": readiness_mission_policy["policy_id"],
                "policy_sha256": readiness_mission_policy["policy_sha256"],
                "policy_selection_sha256": preflight_document["mission_policy_commit"][
                    "policy_selection_sha256"
                ],
            },
            "mission_policy_commit": preflight_document["mission_policy_commit"],
        }:
            raise CollaborationPlanError("Preparation policy sources are stale")
        if raw.get("preparation_status") != "awaiting_exact_signed_authority":
            raise CollaborationPlanError("Plan replacement preparation status is invalid")
        if raw.get("runtime_effect") != "none":
            raise CollaborationPlanError("Plan replacement preparation cannot have an effect")
        version = raw.get("expected_plan_version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise CollaborationPlanError("Preparation plan version is invalid")
        if (
            raw.get("prepared_at") != readiness_document["observed_at"]
            or version != readiness_document["active_head"]["plan_version"]
        ):
            raise CollaborationPlanError("Preparation source version is stale")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"preparation_id", "preparation_sha256"}
        }
        digest = _canonical_sha256({"domain": PREPARATION_DOMAIN, "preparation": body})
        preparation_id = "RPP-" + digest.removeprefix("sha256:")[:32].upper()
        if raw.get("preparation_sha256") != digest or raw.get("preparation_id") != preparation_id:
            raise CollaborationPlanError("Plan replacement preparation identity is invalid")
        return cls(preparation_id, digest, canonical_json(dict(raw)))

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def load_collaboration_plan_replacement_readiness(
    path: str | Path,
) -> CollaborationPlanReplacementReadiness:
    raw = _load_bounded_json(path, "plan replacement readiness")
    return CollaborationPlanReplacementReadiness.from_dict(raw)


def load_prepared_collaboration_plan_replacement(
    path: str | Path,
) -> PreparedCollaborationPlanReplacement:
    raw = _load_bounded_json(path, "plan replacement preparation")
    return PreparedCollaborationPlanReplacement.from_dict(raw)


def load_collaboration_plan_replacement_mapping_intents(
    path: str | Path,
) -> tuple[dict[str, Any], ...]:
    raw = _load_bounded_json(path, "plan replacement mapping intents")
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "mapping_intents"}:
        raise CollaborationPlanError("Plan replacement mapping intent document is invalid")
    if raw.get("schema_version") != 1:
        raise CollaborationPlanError("Plan replacement mapping intent schema is invalid")
    return _mapping_intents(raw.get("mapping_intents"))


def load_collaboration_plan_replacement_credentials(
    path: str | Path,
) -> tuple[CollaborationPlanReplacementAuthorityCredential, ...]:
    try:
        raw = _load_bounded_json(path, "plan replacement credentials")
    except CollaborationPlanError as exc:
        raise PrincipalAuthenticationError("Could not load replacement credentials") from exc
    if not isinstance(raw, Mapping) or set(raw) != {"schema_version", "credentials"}:
        raise PrincipalAuthenticationError("Replacement credential document is invalid")
    if type(raw.get("schema_version")) is not int or raw.get("schema_version") != 1:
        raise PrincipalAuthenticationError("Replacement credential document is invalid")
    if type(raw.get("credentials")) is not list:
        raise PrincipalAuthenticationError("Replacement credential document is invalid")
    validate_plan_replacement_authority_requirement_count(
        len(raw["credentials"]), "replacement credential count"
    )
    result: list[CollaborationPlanReplacementAuthorityCredential] = []
    for item in raw["credentials"]:
        if not isinstance(item, Mapping) or set(item) != {
            "source_requirement_id",
            "upgraded_requirement_id",
            "replay_key_sha256",
            "scope_grant",
            "assertion",
        }:
            raise PrincipalAuthenticationError("Replacement credential fields are invalid")
        result.append(
            CollaborationPlanReplacementAuthorityCredential(
                source_requirement_id=item["source_requirement_id"],
                upgraded_requirement_id=item["upgraded_requirement_id"],
                replay_key_sha256=item["replay_key_sha256"],
                scope_grant=ScopeGrant.from_dict(item["scope_grant"]),
                assertion=PrincipalAssertion.from_dict(item["assertion"]),
            )
        )
    for values in (
        [item.source_requirement_id for item in result],
        [item.upgraded_requirement_id for item in result],
        [item.replay_key_sha256 for item in result],
        [item.assertion.assertion_id for item in result],
        [item.assertion.content_sha256 for item in result],
    ):
        if len(values) != len(set(values)):
            raise PrincipalAuthenticationError("Replacement credentials contain duplicate coverage")
    return tuple(result)


class CollaborationPlanReplacementOperationsService:
    """Prepare, assess, and execute exact authenticated plan replacements."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        authority_policy: CollaborationReconfigurationAuthorityPolicy,
        *,
        registry_source: bytes | str | Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        if not isinstance(authority_policy, CollaborationReconfigurationAuthorityPolicy):
            raise TypeError(
                "authority_policy must be a CollaborationReconfigurationAuthorityPolicy"
            )
        registry.validate()
        self._store = store
        self._registry = ExpertRegistry.from_dict(registry.to_dict())
        self._authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
            authority_policy.to_dict()
        )
        self._registry_source = registry_source
        self._clock = clock or store._clock

    def assess(
        self,
        *,
        replacement_plan: CollaborationPlan,
        mapping_intents: Sequence[Mapping[str, Any]],
        independent_control_profile_id: str | None = None,
        independent_assurance_profile_id: str | None = None,
        second_control_profile_id: str | None = None,
    ) -> CollaborationPlanReplacementReadiness:
        return self._assess(
            replacement_plan=replacement_plan,
            mapping_intents=mapping_intents,
            independent_control_profile_id=independent_control_profile_id,
            independent_assurance_profile_id=independent_assurance_profile_id,
            second_control_profile_id=second_control_profile_id,
            observed_at=format_timestamp(_clock_value(self._clock)),
        )

    def _assess(
        self,
        *,
        replacement_plan: CollaborationPlan,
        mapping_intents: Sequence[Mapping[str, Any]],
        independent_control_profile_id: str | None = None,
        independent_assurance_profile_id: str | None,
        second_control_profile_id: str | None,
        observed_at: str,
    ) -> CollaborationPlanReplacementReadiness:
        replacement = CollaborationPlan.from_dict(replacement_plan.to_dict())
        intents = _mapping_intents(mapping_intents)
        try:
            with self._store._read_connection() as connection:
                mission, prior, plan_version = _current_source(
                    connection, self._store, self._registry, replacement
                )
                policy, policy_commit = _policy_commit(connection, replacement.mission_id)
                trust, scope, principal, _verified_policy = _high_water_state(
                    connection, self._store, replacement.mission_id
                )
                consumed_replay_keys = sorted(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT canonical_replay_key_sha256 "
                        "FROM collaboration_plan_replacement_authority_consumptions "
                        "ORDER BY canonical_replay_key_sha256"
                    ).fetchall()
                )
                snapshots = _build_source_snapshots_in_connection(
                    connection, replacement.mission_id, prior.plan_id
                )
                derived_mappings, work_state = _source_mapping_inputs(
                    connection, prior, replacement, intents
                )
                preflight = build_collaboration_plan_replacement_preflight(
                    prior_plan=prior,
                    replacement_plan=replacement,
                    mission_policy=policy,
                    mission_policy_commit=policy_commit,
                    source_state={
                        "mission_revision": mission.revision,
                        "active_plan_id": prior.plan_id,
                        "active_plan_sha256": prior.content_sha256,
                        **snapshots.hashes,
                        "observed_at": observed_at,
                    },
                    mapping_inputs=derived_mappings,
                    independent_control_profile_id=independent_control_profile_id,
                    independent_assurance_profile_id=independent_assurance_profile_id,
                    second_control_profile_id=second_control_profile_id,
                )
                preflight_document = preflight.to_dict()
                cancellation_ids = {
                    str(item["source_work_item_id"])
                    for item in preflight_document["cancellation_actions"]
                }
                blockers, drain_operations = _drain_state(
                    connection,
                    replacement.mission_id,
                    prior.plan_id,
                    cancellation_ids,
                )
                control = connection.execute(
                    "SELECT state FROM mission_controls WHERE mission_id = ?",
                    (replacement.mission_id,),
                ).fetchone()
                if control is None:
                    raise StoreIntegrityError("Mission control state is missing")
                if control["state"] != "active":
                    blockers.append(
                        {
                            "blocker_code": "mission_not_active",
                            "subject_id": replacement.mission_id,
                            "work_item_id": None,
                            "detail": "Mission must be active before plan replacement",
                        }
                    )
                requirements = [
                    {
                        "requirement_id": str(item["requirement_id"]),
                        "operation": str(item["operation"]),
                        "role": str(item["role"]),
                        "authority_id": str(item["authority_id"]),
                        "work_item_id": item.get("work_item_id"),
                    }
                    for item in preflight_document["authority_requirements"]
                ]
                requirement_count = validate_plan_replacement_authority_requirement_count(
                    len(requirements)
                )
                body = {
                    "schema_version": SCHEMA_VERSION,
                    "observed_at": observed_at,
                    "store_id": str(
                        connection.execute(
                            "SELECT store_id FROM store_identity WHERE singleton_id = 1"
                        ).fetchone()[0]
                    ),
                    "mission_id": replacement.mission_id,
                    "mission_revision": mission.revision,
                    "active_head": {
                        "plan_id": prior.plan_id,
                        "plan_sha256": prior.content_sha256,
                        "plan_version": plan_version,
                    },
                    "prior_plan": prior.to_dict(),
                    "replacement_plan": replacement.to_dict(),
                    "mission_policy": policy.to_dict(),
                    "authority_policy": self._authority_policy.to_dict(),
                    "trust_high_water": trust,
                    "scope_high_water": scope,
                    "principal_ledger_high_water": principal,
                    "replacement_replay_high_water": {
                        "consumed_count": len(consumed_replay_keys),
                        "consumed_replay_keys_sha256": _canonical_sha256(consumed_replay_keys),
                    },
                    "source_snapshot_hashes": snapshots.hashes,
                    "mapping_intents": list(intents),
                    "work_state": work_state,
                    "preflight": preflight_document,
                    "required_authority_operations": requirements,
                    "required_assertion_count": requirement_count,
                    "required_replay_key_count": requirement_count,
                    "drain_blockers": sorted(
                        blockers,
                        key=lambda item: (item["blocker_code"], item["subject_id"]),
                    ),
                    "required_drain_operations": drain_operations,
                    "readiness_status": (
                        "ready_for_signed_authority" if not blockers else "blocked_pending_drain"
                    ),
                    "runtime_effect": "none",
                }
        except sqlite3.Error as exc:
            raise StoreError("Could not assess plan replacement readiness") from exc
        digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": body})
        return CollaborationPlanReplacementReadiness.from_dict(
            {
                **body,
                "readiness_id": "RRA-" + digest.removeprefix("sha256:")[:32].upper(),
                "readiness_sha256": digest,
            }
        )

    def prepare(
        self,
        *,
        replacement_plan: CollaborationPlan,
        mapping_intents: Sequence[Mapping[str, Any]],
        issued_at: str,
        expires_at: str,
        independent_control_profile_id: str | None = None,
        independent_assurance_profile_id: str | None = None,
        second_control_profile_id: str | None = None,
    ) -> PreparedCollaborationPlanReplacement:
        readiness = self.assess(
            replacement_plan=replacement_plan,
            mapping_intents=mapping_intents,
            independent_control_profile_id=independent_control_profile_id,
            independent_assurance_profile_id=independent_assurance_profile_id,
            second_control_profile_id=second_control_profile_id,
        )
        document = readiness.to_dict()
        self._raise_blockers(document)
        preflight = CollaborationPlanReplacementPreflight.from_dict(document["preflight"])
        mission_policy = CollaborationMissionReconfigurationPolicy.from_dict(
            document["mission_policy"]
        )
        authority_plan = build_collaboration_plan_replacement_authority_plan(
            preflight=preflight,
            authority_policy=self._authority_policy,
            mission_policy=mission_policy,
            registry=self._registry,
            registry_source=self._registry_source,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        verified = verify_collaboration_plan_replacement_authority_plan_offline(
            authority_plan,
            preflight=preflight,
            prior_plan=CollaborationPlan.from_dict(document["prior_plan"]),
            replacement_plan=CollaborationPlan.from_dict(document["replacement_plan"]),
            authority_policy=self._authority_policy,
            mission_policy=mission_policy,
            registry=self._registry,
            registry_source=self._registry_source,
            verified_at=document["observed_at"],
            consumed_replay_keys=self._consumed_replay_keys(),
        )
        verified.to_dict()
        upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=preflight,
            army_registry=self._registry,
        )
        body = {
            "schema_version": SCHEMA_VERSION,
            "prepared_at": document["observed_at"],
            "readiness": document,
            "authority_plan": authority_plan.to_dict(),
            "authority_upgrade": upgrade.to_dict(),
            "expected_plan_version": document["active_head"]["plan_version"],
            "preparation_status": "awaiting_exact_signed_authority",
            "runtime_effect": "none",
        }
        digest = _canonical_sha256({"domain": PREPARATION_DOMAIN, "preparation": body})
        return PreparedCollaborationPlanReplacement.from_dict(
            {
                **body,
                "preparation_id": "RPP-" + digest.removeprefix("sha256:")[:32].upper(),
                "preparation_sha256": digest,
            }
        )

    @staticmethod
    def _raise_blockers(readiness: Mapping[str, Any]) -> None:
        blockers = readiness["drain_blockers"]
        if not blockers:
            return
        codes = {str(item["blocker_code"]) for item in blockers}
        if "terminal_custody_missing" in codes:
            raise PlanReplacementCustodyError("Plan replacement terminal custody is incomplete")
        raise PlanReplacementDrainError("Plan replacement source state is not drained")

    def _consumed_replay_keys(self) -> set[str]:
        with self._store._read_connection() as connection:
            return {
                str(row[0])
                for row in connection.execute(
                    "SELECT canonical_replay_key_sha256 "
                    "FROM collaboration_plan_replacement_authority_consumptions"
                ).fetchall()
            }

    def _current_execution_state(self, mission_id: str) -> tuple[Any, set[str], set[str], Any]:
        with self._store._read_connection() as connection:
            identity = self._store._verify_store_identity(connection)
            trust_policies = self._store._verify_trust_policy_history(connection, identity)
            policy_sha256 = str(identity["trust_policy_hash"])
            verified_policy = trust_policies.get(policy_sha256)
            if verified_policy is None:
                raise StoreIntegrityError("Current verified trust policy is missing")
            revoked = {
                str(row[0])
                for row in connection.execute(
                    "SELECT scope_grant_hash FROM mission_scope_grant_revocations "
                    "WHERE mission_id = ?",
                    (mission_id,),
                ).fetchall()
            }
            consumed = {
                str(row[0])
                for row in connection.execute(
                    "SELECT canonical_replay_key_sha256 "
                    "FROM collaboration_plan_replacement_authority_consumptions"
                ).fetchall()
            }
            mission_row = connection.execute(
                "SELECT * FROM missions WHERE mission_id = ?", (mission_id,)
            ).fetchone()
            if mission_row is None:
                raise StoreError("Replacement mission is missing")
            mission = self._store._stored_mission_from_row(connection, self._registry, mission_row)
            return verified_policy, revoked, consumed, mission

    def _durable_replay_readiness(
        self,
        connection: sqlite3.Connection,
        commit: sqlite3.Row,
        authentication: sqlite3.Row,
    ) -> dict[str, Any]:
        try:
            preflight = CollaborationPlanReplacementPreflight.from_dict(
                json.loads(str(commit["preflight_json"]))
            )
        except (json.JSONDecodeError, CollaborationPlanError) as exc:
            raise StoreIntegrityError("Durable replacement preflight is invalid") from exc
        preflight_document = preflight.to_dict()
        mission_id = str(commit["mission_id"])
        observed_at = str(preflight_document["source_state"]["observed_at"])
        activations = connection.execute(
            "SELECT plan_id, plan_json, plan_content_sha256 "
            "FROM collaboration_plan_activations WHERE plan_id IN (?, ?)",
            (commit["predecessor_plan_id"], commit["replacement_plan_id"]),
        ).fetchall()
        by_plan = {str(row["plan_id"]): row for row in activations}
        if set(by_plan) != {
            str(commit["predecessor_plan_id"]),
            str(commit["replacement_plan_id"]),
        }:
            raise StoreIntegrityError("Durable replacement plan custody is incomplete")
        try:
            prior = CollaborationPlan.from_dict(
                json.loads(str(by_plan[str(commit["predecessor_plan_id"])]["plan_json"]))
            )
            replacement = CollaborationPlan.from_dict(
                json.loads(str(by_plan[str(commit["replacement_plan_id"])]["plan_json"]))
            )
        except (json.JSONDecodeError, CollaborationPlanError) as exc:
            raise StoreIntegrityError("Durable replacement plan custody is invalid") from exc
        if (
            prior.content_sha256 != commit["predecessor_plan_sha256"]
            or replacement.content_sha256 != commit["replacement_plan_sha256"]
            or by_plan[prior.plan_id]["plan_content_sha256"] != prior.content_sha256
            or by_plan[replacement.plan_id]["plan_content_sha256"] != replacement.content_sha256
        ):
            raise StoreIntegrityError("Durable replacement plan content is inconsistent")
        policy_commit = preflight_document["mission_policy_commit"]
        policy_row = connection.execute(
            "SELECT * FROM collaboration_mission_policy_commits "
            "WHERE mission_id = ? AND policy_id = ? AND policy_sha256 = ?",
            (mission_id, policy_commit["policy_id"], policy_commit["policy_sha256"]),
        ).fetchone()
        if policy_row is None:
            raise StoreIntegrityError("Durable replacement policy custody is missing")
        try:
            mission_policy = CollaborationMissionReconfigurationPolicy.from_dict(
                json.loads(str(policy_row["policy_json"]))
            )
            authority_policy = CollaborationReconfigurationAuthorityPolicy.from_dict(
                json.loads(str(policy_row["authority_policy_json"]))
            )
        except (json.JSONDecodeError, CollaborationPlanError) as exc:
            raise StoreIntegrityError("Durable replacement policy custody is invalid") from exc
        trust_row = connection.execute(
            "SELECT policy_id, policy_version, policy_hash, applied_at "
            "FROM trust_policy_history WHERE policy_hash = ?",
            (authentication["trust_policy_sha256"],),
        ).fetchone()
        if trust_row is None:
            raise StoreIntegrityError("Durable replacement trust high-water is missing")
        trust = {
            "policy_id": str(trust_row["policy_id"]),
            "policy_version": int(trust_row["policy_version"]),
            "policy_sha256": str(trust_row["policy_hash"]),
            "applied_at": str(trust_row["applied_at"]),
        }
        grants = connection.execute(
            "SELECT grant_hash, grant_id, accepted_at, expires_at "
            "FROM mission_scope_grants WHERE mission_id = ? AND accepted_at <= ? "
            "ORDER BY grant_hash",
            (mission_id, observed_at),
        ).fetchall()
        revocations = connection.execute(
            "SELECT revocation_sequence, revocation_hash, scope_grant_hash, accepted_at, "
            "entry_hash FROM mission_scope_grant_revocations "
            "WHERE mission_id = ? AND accepted_at <= ? ORDER BY revocation_sequence",
            (mission_id, observed_at),
        ).fetchall()
        baseline = connection.execute(
            "SELECT baseline_root_hash FROM mission_scope_revocation_baselines "
            "WHERE mission_id = ?",
            (mission_id,),
        ).fetchone()
        if baseline is None:
            raise StoreIntegrityError("Durable replacement scope baseline is missing")
        revocation_head = (
            str(revocations[-1]["entry_hash"])
            if revocations
            else str(baseline["baseline_root_hash"])
        )
        scope_body = {
            "mission_id": mission_id,
            "accepted_grants": [
                {
                    "grant_id": str(row["grant_id"]),
                    "grant_sha256": str(row["grant_hash"]),
                    "accepted_at": str(row["accepted_at"]),
                    "expires_at": str(row["expires_at"]),
                }
                for row in grants
            ],
            "revocations": [
                {
                    "revocation_sequence": int(row["revocation_sequence"]),
                    "revocation_sha256": str(row["revocation_hash"]),
                    "scope_grant_sha256": str(row["scope_grant_hash"]),
                    "accepted_at": str(row["accepted_at"]),
                }
                for row in revocations
            ],
            "revocation_head_sha256": revocation_head,
            "signed_revocation_count": len(revocations),
        }
        scope = {
            "accepted_grant_count": len(grants),
            "revocation_count": len(revocations),
            "revocation_head_sha256": revocation_head,
            "scope_state_sha256": _canonical_sha256(
                {"domain": SCOPE_HIGH_WATER_DOMAIN, "scope": scope_body}
            ),
        }
        first_use = connection.execute(
            """
            SELECT use.use_sequence, use.previous_hash
            FROM collaboration_plan_replacement_authority_consumptions AS consumption
            JOIN principal_assertion_uses AS use
              ON use.issuer = consumption.issuer
             AND use.assertion_id = consumption.assertion_id
            WHERE consumption.preflight_id = ?
            ORDER BY use.use_sequence LIMIT 1
            """,
            (preflight.preflight_id,),
        ).fetchone()
        first_replay = connection.execute(
            "SELECT MIN(rowid) FROM collaboration_plan_replacement_authority_consumptions "
            "WHERE preflight_id = ?",
            (preflight.preflight_id,),
        ).fetchone()[0]
        if first_use is None or first_replay is None:
            raise StoreIntegrityError("Durable replacement consumption custody is incomplete")
        principal = {
            "assertion_count": int(first_use["use_sequence"]) - 1,
            "head_sha256": str(first_use["previous_hash"]),
            **_expert_review_high_water(
                connection,
                mission_id,
                before_use_sequence=int(first_use["use_sequence"]),
            ),
        }
        earlier_replay_keys = sorted(
            str(item[0])
            for item in connection.execute(
                "SELECT canonical_replay_key_sha256 "
                "FROM collaboration_plan_replacement_authority_consumptions "
                "WHERE rowid < ? ORDER BY canonical_replay_key_sha256",
                (first_replay,),
            ).fetchall()
        )
        intents = [
            {
                "source_work_item_id": str(item["source_work_item_id"]),
                "replacement_work_item_id": str(item["replacement_work_item_id"]),
                "cross_command_evidence": item.get("cross_command_evidence"),
            }
            for item in preflight_document["item_mappings"]
        ]
        canonical_intents = list(_mapping_intents(intents))
        _mapping_inputs, work_state = _source_mapping_inputs(
            connection, prior, replacement, tuple(canonical_intents)
        )
        requirements = [
            {
                "requirement_id": str(item["requirement_id"]),
                "operation": str(item["operation"]),
                "role": str(item["role"]),
                "authority_id": str(item["authority_id"]),
                "work_item_id": item.get("work_item_id"),
            }
            for item in preflight_document["authority_requirements"]
        ]
        requirement_count = validate_plan_replacement_authority_requirement_count(len(requirements))
        source_snapshots = {field: str(commit[field]) for field in sorted(SOURCE_SNAPSHOT_FIELDS)}
        identity = connection.execute("SELECT store_id FROM store_identity").fetchone()
        if identity is None:
            raise StoreIntegrityError("Durable replacement store identity is missing")
        body = {
            "schema_version": SCHEMA_VERSION,
            "observed_at": observed_at,
            "store_id": str(identity["store_id"]),
            "mission_id": mission_id,
            "mission_revision": int(commit["mission_revision"]),
            "active_head": {
                "plan_id": prior.plan_id,
                "plan_sha256": prior.content_sha256,
                "plan_version": int(commit["predecessor_plan_version"]),
            },
            "prior_plan": prior.to_dict(),
            "replacement_plan": replacement.to_dict(),
            "mission_policy": mission_policy.to_dict(),
            "authority_policy": authority_policy.to_dict(),
            "trust_high_water": trust,
            "scope_high_water": scope,
            "principal_ledger_high_water": principal,
            "replacement_replay_high_water": {
                "consumed_count": len(earlier_replay_keys),
                "consumed_replay_keys_sha256": _canonical_sha256(earlier_replay_keys),
            },
            "source_snapshot_hashes": source_snapshots,
            "mapping_intents": canonical_intents,
            "work_state": work_state,
            "preflight": preflight_document,
            "required_authority_operations": requirements,
            "required_assertion_count": requirement_count,
            "required_replay_key_count": requirement_count,
            "drain_blockers": [],
            "required_drain_operations": [],
            "readiness_status": "ready_for_signed_authority",
            "runtime_effect": "none",
        }
        digest = _canonical_sha256({"domain": READINESS_DOMAIN, "readiness": body})
        return CollaborationPlanReplacementReadiness.from_dict(
            {
                **body,
                "readiness_id": "RRA-" + digest.removeprefix("sha256:")[:32].upper(),
                "readiness_sha256": digest,
            }
        ).to_dict()

    def _exact_replay(
        self,
        preparation: PreparedCollaborationPlanReplacement,
        credentials: tuple[CollaborationPlanReplacementAuthorityCredential, ...],
    ) -> CollaborationPlanReplacementCommitReceipt | None:
        document = preparation.to_dict()
        preflight_id = document["readiness"]["preflight"]["preflight_id"]
        with self._store._read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM collaboration_plan_replacement_commits WHERE preflight_id = ?",
                (preflight_id,),
            ).fetchone()
            if row is None:
                return None
            mission_row = connection.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (row["mission_id"],),
            ).fetchone()
            if mission_row is None:
                raise StoreIntegrityError("Durable replacement mission is missing")
            mission = self._store._stored_mission_from_row(
                connection,
                self._registry,
                mission_row,
            )
            identity = self._store._verify_store_identity(connection, verify_history=False)
            trust_policies = self._store._verify_trust_policy_history(connection, identity)
            self._store._verify_phase4_mission_state(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                trust_policies=trust_policies,
                registry=self._registry,
            )
            _verify_collaboration_plan_replacement_state(
                connection,
                mission_id=str(row["mission_id"]),
                registry=self._registry,
                mission=mission.mission,
            )
            authority = connection.execute(
                "SELECT * FROM collaboration_plan_replacement_authentications "
                "WHERE preflight_id = ?",
                (preflight_id,),
            ).fetchone()
            authority_plan = document["authority_plan"]
            authority_upgrade = document["authority_upgrade"]
            durable_readiness = None
            if authority is not None:
                durable_readiness = self._durable_replay_readiness(connection, row, authority)
            try:
                durable_authority_plan = (
                    json.loads(str(authority["authority_plan_json"]))
                    if authority is not None
                    else None
                )
                durable_authority_upgrade = (
                    json.loads(str(authority["authority_upgrade_json"]))
                    if authority is not None
                    else None
                )
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError(
                    "Durable replacement authentication custody is invalid"
                ) from exc
            expected_preparation_body = {
                "schema_version": SCHEMA_VERSION,
                "prepared_at": durable_readiness["observed_at"] if durable_readiness else None,
                "readiness": durable_readiness,
                "authority_plan": durable_authority_plan,
                "authority_upgrade": durable_authority_upgrade,
                "expected_plan_version": (
                    durable_readiness["active_head"]["plan_version"] if durable_readiness else None
                ),
                "preparation_status": "awaiting_exact_signed_authority",
                "runtime_effect": "none",
            }
            preparation_digest = _canonical_sha256(
                {"domain": PREPARATION_DOMAIN, "preparation": expected_preparation_body}
            )
            expected_preparation = {
                **expected_preparation_body,
                "preparation_id": (
                    "RPP-" + preparation_digest.removeprefix("sha256:")[:32].upper()
                ),
                "preparation_sha256": preparation_digest,
            }
            if (
                authority is None
                or document != expected_preparation
                or authority["authority_plan_id"] != authority_plan["authority_plan_id"]
                or authority["authority_plan_sha256"] != authority_plan["authority_plan_sha256"]
                or authority["authority_plan_json"] != canonical_json(authority_plan)
                or authority["authority_upgrade_id"] != authority_upgrade["upgrade_id"]
                or authority["authority_upgrade_sha256"] != authority_upgrade["upgrade_sha256"]
                or authority["authority_upgrade_json"] != canonical_json(authority_upgrade)
                or authority["requirement_count"]
                != document["readiness"]["required_assertion_count"]
                or row["preflight_sha256"] != document["readiness"]["preflight"]["preflight_sha256"]
                or row["preflight_json"] != canonical_json(document["readiness"]["preflight"])
            ):
                raise StoreConflictError("Committed plan replacement replay preparation conflicts")
            consumptions = connection.execute(
                """
                SELECT consumption.source_requirement_id,
                       consumption.upgraded_requirement_id,
                       consumption.canonical_replay_key_sha256,
                       consumption.assertion_id,
                       consumption.assertion_sha256,
                       consumption.issuer,
                       consumption.scope_grant_sha256,
                       consumption.operation,
                       assertion_use.assertion_hash AS ledger_assertion_sha256
                FROM collaboration_plan_replacement_authority_consumptions AS consumption
                JOIN principal_assertion_uses AS assertion_use
                  ON assertion_use.issuer = consumption.issuer
                 AND assertion_use.assertion_id = consumption.assertion_id
                WHERE consumption.preflight_id = ?
                ORDER BY consumption.source_requirement_id
                """,
                (preflight_id,),
            ).fetchall()
            supplied = sorted(
                (
                    item.source_requirement_id,
                    item.upgraded_requirement_id,
                    item.replay_key_sha256,
                    item.assertion.assertion_id,
                    item.assertion.content_sha256,
                    item.assertion.issuer,
                    item.scope_grant.content_sha256,
                    item.assertion.operation.value,
                    item.assertion.content_sha256,
                )
                for item in credentials
            )
            durable = [
                (
                    str(item["source_requirement_id"]),
                    str(item["upgraded_requirement_id"]),
                    str(item["canonical_replay_key_sha256"]),
                    str(item["assertion_id"]),
                    str(item["assertion_sha256"]),
                    str(item["issuer"]),
                    str(item["scope_grant_sha256"]),
                    str(item["operation"]),
                    str(item["ledger_assertion_sha256"]),
                )
                for item in consumptions
            ]
            if supplied != durable:
                raise StoreConflictError("Committed plan replacement replay inputs conflict")
            try:
                receipt = CollaborationPlanReplacementCommitReceipt.from_dict(
                    json.loads(str(row["receipt_json"]))
                )
            except (json.JSONDecodeError, StoreError) as exc:
                raise StoreIntegrityError("Durable replacement receipt is invalid") from exc
            receipt_document = receipt.to_dict()
            if (
                canonical_json(receipt_document) != row["receipt_json"]
                or receipt.replacement_commit_id != row["replacement_commit_id"]
                or receipt.receipt_sha256 != row["receipt_sha256"]
                or receipt_document["preflight_id"] != preflight_id
                or receipt_document["replacement_plan_id"]
                != document["readiness"]["replacement_plan"]["plan_id"]
            ):
                raise StoreIntegrityError("Durable replacement receipt custody is invalid")
            _verify_authenticated_replacement_replay_state(
                connection,
                store=self._store,
                registry=self._registry,
                preflight=CollaborationPlanReplacementPreflight.from_dict(
                    document["readiness"]["preflight"]
                ),
                credentials=credentials,
                at=self._clock(),
            )
            return receipt

    def execute(
        self,
        *,
        preparation: PreparedCollaborationPlanReplacement,
        credentials: Iterable[CollaborationPlanReplacementAuthorityCredential],
    ) -> CollaborationPlanReplacementCommitReceipt:
        prepared = PreparedCollaborationPlanReplacement.from_dict(preparation.to_dict())
        credential_tuple = _normalize_credentials(credentials)
        requirement_count = prepared.to_dict()["readiness"]["required_assertion_count"]
        if len(credential_tuple) != requirement_count:
            raise PrincipalAuthenticationError(
                f"Exactly {requirement_count} replacement credentials are required"
            )
        replay = self._exact_replay(prepared, credential_tuple)
        if replay is not None:
            return replay
        document = prepared.to_dict()
        prior_readiness = document["readiness"]
        current = self._assess(
            replacement_plan=CollaborationPlan.from_dict(prior_readiness["replacement_plan"]),
            mapping_intents=prior_readiness["mapping_intents"],
            independent_control_profile_id=(
                next(
                    (
                        item["authority_id"]
                        for item in prior_readiness["required_authority_operations"]
                        if item["role"] == "independent_control"
                    ),
                    None,
                )
            ),
            independent_assurance_profile_id=(
                next(
                    (
                        item["authority_id"]
                        for item in prior_readiness["required_authority_operations"]
                        if item["role"] == "independent_assurance"
                    ),
                    None,
                )
            ),
            second_control_profile_id=(
                next(
                    (
                        item["authority_id"]
                        for item in prior_readiness["required_authority_operations"]
                        if item["role"] == "second_control"
                    ),
                    None,
                )
            ),
            observed_at=prior_readiness["observed_at"],
        )
        if current.to_dict() != prior_readiness:
            raise StalePlanReplacementReadinessError(
                "Prepared plan replacement readiness no longer matches durable state"
            )
        self._raise_blockers(current.to_dict())
        preflight = CollaborationPlanReplacementPreflight.from_dict(prior_readiness["preflight"])
        prior_plan = CollaborationPlan.from_dict(prior_readiness["prior_plan"])
        replacement_plan = CollaborationPlan.from_dict(prior_readiness["replacement_plan"])
        mission_policy = CollaborationMissionReconfigurationPolicy.from_dict(
            prior_readiness["mission_policy"]
        )
        authority_plan = CollaborationPlanReplacementAuthorityPlan.from_dict(
            document["authority_plan"]
        )
        upgrade = CollaborationPlanReplacementAuthorityUpgrade.from_dict(
            document["authority_upgrade"]
        )
        verified_policy, revoked, consumed, mission = self._current_execution_state(
            replacement_plan.mission_id
        )
        now = _clock_value(self._clock)
        verified_plan = verify_collaboration_plan_replacement_authority_plan_offline(
            authority_plan,
            preflight=preflight,
            prior_plan=prior_plan,
            replacement_plan=replacement_plan,
            authority_policy=self._authority_policy,
            mission_policy=mission_policy,
            registry=self._registry,
            registry_source=self._registry_source,
            verified_at=format_timestamp(now),
            consumed_replay_keys=consumed,
        )
        replay_keys = collaboration_plan_replacement_authority_replay_keys(
            verified_plan,
            upgrade,
            preflight=preflight,
            army_registry=self._registry,
        )
        if len(replay_keys) != requirement_count:
            raise PrincipalAuthenticationError("Replacement replay key coverage is incomplete")
        constraints_hash = sha256_text(canonical_json(mission.mission.to_dict()["constraints"]))
        bundle = authenticate_collaboration_plan_replacement_authority(
            verified_plan,
            upgrade,
            preflight=preflight,
            army_registry=self._registry,
            credentials=credential_tuple,
            verified_policy=verified_policy,
            expected_audience=verified_policy.policy.audience,
            expected_store_id=verified_policy.policy.store_id,
            expected_mission_context_hash=mission.context_hash,
            expected_scope_reference=mission.mission.scope_reference,
            expected_scope_document_hash=mission.mission.scope_document_hash,
            expected_environment=mission.mission.environment,
            expected_max_action_tier=mission.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            revoked_scope_grant_sha256s=revoked,
            consumed_replay_keys=consumed,
            clock=lambda: now,
        )
        try:
            return AuthenticatedCollaborationPlanReplacementStoreService(
                self._store,
                self._registry,
                clock=lambda: now,
            ).replace(
                preflight=preflight,
                prior_plan=prior_plan,
                replacement_plan=replacement_plan,
                verified_authority_plan=verified_plan,
                authority_upgrade=upgrade,
                authenticated_bundle=bundle,
                credentials=credential_tuple,
                expected_plan_version=int(document["expected_plan_version"]),
            )
        except StoreConflictError as exc:
            message = str(exc)
            if message.startswith("Source work leases are not terminal") or message == (
                "Source execution sessions are not terminal"
            ):
                raise PlanReplacementDrainError(message) from exc
            if message in {
                "Source work state drifted after preflight",
                "Source completed result drifted after preflight",
                "Completed carry-forward source is not complete",
                "Replacement source head binding is stale",
                "Mission revision drifted after preflight",
                "Replacement source snapshots drifted",
            }:
                raise StalePlanReplacementReadinessError(message) from exc
            if message in {
                "Active collaboration plan head changed",
                "Active collaboration plan content changed",
                "Mission principal ledger changed during plan replacement",
                "Atomic collaboration plan replacement conflicts with durable state",
            }:
                raise PlanReplacementCompareAndSwapError(message) from exc
            raise


__all__ = [
    "CollaborationPlanReplacementOperationsService",
    "CollaborationPlanReplacementReadiness",
    "PlanReplacementCustodyError",
    "PlanReplacementCompareAndSwapError",
    "PlanReplacementDrainError",
    "PlanReplacementReadinessError",
    "PreparedCollaborationPlanReplacement",
    "StalePlanReplacementReadinessError",
    "load_collaboration_plan_replacement_credentials",
    "load_collaboration_plan_replacement_mapping_intents",
    "load_collaboration_plan_replacement_readiness",
    "load_prepared_collaboration_plan_replacement",
]

"""Atomic durable collaboration plan replacement storage."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from .collaboration import CollaborationPlan, WorkItemKind, validate_collaboration_plan
from .collaboration_plan_replacement_authority import (
    CollaborationPlanReplacementAuthorityPlan,
)
from .collaboration_plan_replacement_authority_upgrade import (
    CollaborationPlanReplacementAuthorityUpgrade,
    verify_collaboration_plan_replacement_authority_upgrade,
)
from .collaboration_plan_replacement_preflight import (
    CollaborationPlanReplacementPreflight,
)
from .errors import (
    CollaborationPlanError,
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .registry import ExpertRegistry
from .store import (
    AUTHENTICATED_MODEL_EXECUTION_SCHEMA_VERSION,
    AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    format_timestamp,
    sha256_text,
)

REPLACEMENT_REQUEST_DOMAIN = "sunderkey.collaboration-plan-replacement-request.v1"
REPLACEMENT_RECEIPT_DOMAIN = "sunderkey.collaboration-plan-replacement-receipt.v1"
SOURCE_SNAPSHOT_DOMAIN = "sunderkey.collaboration-plan-replacement-source-snapshot.v1"
AUTHENTICATION_CUSTODY_DOMAIN = "sunderkey.collaboration-plan-replacement-authentication-custody.v1"
AUTHORITY_EVIDENCE_DOMAIN = "sunderkey.collaboration-plan-replacement-signed-authority-evidence.v1"
AUTHORITY_EFFECT_DOMAIN = "sunderkey.collaboration-plan-replacement-signed-authority-effect.v1"


def _canonical_sha256(value: Any) -> str:
    return sha256_text(canonical_json(value))


def _validate_replacement_plan_binding(
    registry: ExpertRegistry,
    mission: Any,
    prior: CollaborationPlan,
    replacement: CollaborationPlan,
) -> None:
    replacement._validate_integrity()
    profile_ids = set(registry.profiles_by_id)
    referenced_profiles = {
        profile_id
        for item in replacement.work_items
        for profile_id in (item.owner_profile_id, *item.supporting_profile_ids)
    }
    if (
        replacement.mission_id != prior.mission_id
        or replacement.mission_id != mission.mission_id
        or replacement.registry_catalog_id != prior.registry_catalog_id
        or replacement.registry_sha256 != prior.registry_sha256
        or replacement.mission_sha256 != prior.mission_sha256
        or replacement.joint_mission_cell_sha256 != prior.joint_mission_cell_sha256
        or replacement.plan_id == prior.plan_id
        or replacement.content_sha256 == prior.content_sha256
        or not referenced_profiles <= profile_ids
    ):
        raise CollaborationPlanError("Replacement collaboration plan bindings are invalid")


def _rows(
    connection: sqlite3.Connection,
    query: str,
    parameters: tuple[Any, ...],
) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, parameters).fetchall()]


def _snapshot(kind: str, mission_id: str, plan_id: str, rows: Any) -> dict[str, Any]:
    return {
        "domain": SOURCE_SNAPSHOT_DOMAIN,
        "kind": kind,
        "mission_id": mission_id,
        "plan_id": plan_id,
        "rows": rows,
    }


@dataclass(frozen=True)
class CollaborationPlanReplacementSourceSnapshots:
    """Five deterministic source snapshots used by replacement preflight."""

    ownership: dict[str, Any]
    work: dict[str, Any]
    cancellation: dict[str, Any]
    execution_session: dict[str, Any]
    terminal_custody: dict[str, Any]

    @property
    def hashes(self) -> dict[str, str]:
        return {
            "ownership_snapshot_sha256": _canonical_sha256(self.ownership),
            "work_snapshot_sha256": _canonical_sha256(self.work),
            "cancellation_snapshot_sha256": _canonical_sha256(self.cancellation),
            "execution_session_snapshot_sha256": _canonical_sha256(self.execution_session),
            "terminal_custody_snapshot_sha256": _canonical_sha256(self.terminal_custody),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "documents": {
                "ownership": self.ownership,
                "work": self.work,
                "cancellation": self.cancellation,
                "execution_session": self.execution_session,
                "terminal_custody": self.terminal_custody,
            },
            "hashes": self.hashes,
        }


def _build_source_snapshots_in_connection(
    connection: sqlite3.Connection,
    mission_id: str,
    plan_id: str,
) -> CollaborationPlanReplacementSourceSnapshots:
    activation = connection.execute(
        """
        SELECT plan_json FROM collaboration_plan_activations
        WHERE mission_id = ? AND plan_id = ?
        """,
        (mission_id, plan_id),
    ).fetchone()
    if activation is None:
        raise StoreError("Source collaboration plan activation does not exist")
    try:
        plan = CollaborationPlan.from_dict(json.loads(str(activation["plan_json"])))
    except (json.JSONDecodeError, CollaborationPlanError) as exc:
        raise StoreIntegrityError("Source collaboration plan is invalid") from exc
    work_item_ids = tuple(sorted(item.work_item_id for item in plan.work_items))

    ownership_rows = _rows(
        connection,
        """
        SELECT * FROM collaboration_ownership_chain_entries
        WHERE mission_id = ? AND plan_id = ?
        ORDER BY chain_id, sequence, entry_id
        """,
        (mission_id, plan_id),
    )
    transition_rows = _rows(
        connection,
        """
        SELECT * FROM collaboration_work_item_transitions
        WHERE mission_id = ? AND plan_id = ?
        ORDER BY work_item_id, generation, recorded_at, transition_id
        """,
        (mission_id, plan_id),
    )
    recovery_rows = _rows(
        connection,
        """
        SELECT * FROM collaboration_work_item_recovery_transitions
        WHERE mission_id = ? AND plan_id = ?
        ORDER BY work_item_id, generation, recorded_at, transition_id
        """,
        (mission_id, plan_id),
    )
    cancellation_rows = _rows(
        connection,
        """
        SELECT * FROM collaboration_work_item_cancellations
        WHERE mission_id = ? AND plan_id = ?
        ORDER BY work_item_id, cancelled_at, cancellation_id
        """,
        (mission_id, plan_id),
    )
    authority_rows = _rows(
        connection,
        """
        SELECT * FROM execution_session_authority_commits
        WHERE mission_id = ? AND collaboration_plan_id = ?
        ORDER BY work_item_id, session_authority_id
        """,
        (mission_id, plan_id),
    )
    authority_ids = tuple(row["session_authority_id"] for row in authority_rows)
    if authority_ids:
        placeholders = ", ".join("?" for _ in authority_ids)
        activation_rows = _rows(
            connection,
            f"""
            SELECT * FROM execution_session_activation_commits
            WHERE session_authority_id IN ({placeholders})
            ORDER BY work_item_id, session_authority_id
            """,
            authority_ids,
        )
        revocation_rows = _rows(
            connection,
            f"""
            SELECT * FROM execution_session_revocation_commits
            WHERE session_authority_id IN ({placeholders})
            ORDER BY work_item_id, session_authority_id
            """,
            authority_ids,
        )
    else:
        activation_rows = []
        revocation_rows = []
    if work_item_ids:
        placeholders = ", ".join("?" for _ in work_item_ids)
        custody_rows = _rows(
            connection,
            f"""
            SELECT * FROM execution_terminal_custody_commits
            WHERE mission_id = ? AND work_item_id IN ({placeholders})
            ORDER BY work_item_id, committed_at, custody_plan_id
            """,
            (mission_id, *work_item_ids),
        )
    else:
        custody_rows = []
    custody_ids = tuple(row["custody_plan_id"] for row in custody_rows)
    if custody_ids:
        placeholders = ", ".join("?" for _ in custody_ids)
        participant_rows = _rows(
            connection,
            f"""
            SELECT * FROM execution_terminal_custody_participants
            WHERE custody_plan_id IN ({placeholders})
            ORDER BY custody_plan_id, participant_index
            """,
            custody_ids,
        )
    else:
        participant_rows = []
    return CollaborationPlanReplacementSourceSnapshots(
        ownership=_snapshot(
            "ownership",
            mission_id,
            plan_id,
            {"chain_entries": ownership_rows},
        ),
        work=_snapshot(
            "work",
            mission_id,
            plan_id,
            {
                "recovery_transitions": recovery_rows,
                "transitions": transition_rows,
            },
        ),
        cancellation=_snapshot(
            "cancellation",
            mission_id,
            plan_id,
            {"cancellations": cancellation_rows},
        ),
        execution_session=_snapshot(
            "execution_session",
            mission_id,
            plan_id,
            {
                "activations": activation_rows,
                "authorities": authority_rows,
                "revocations": revocation_rows,
            },
        ),
        terminal_custody=_snapshot(
            "terminal_custody",
            mission_id,
            plan_id,
            {
                "commits": custody_rows,
                "participants": participant_rows,
            },
        ),
    )


def build_collaboration_plan_replacement_source_snapshots(
    store: MissionStore,
    mission_id: str,
    plan_id: str,
) -> CollaborationPlanReplacementSourceSnapshots:
    """Read the exact five source snapshots from one durable transaction."""

    if not isinstance(store, MissionStore):
        raise TypeError("store must be a MissionStore")
    with store._read_connection() as connection:
        return _build_source_snapshots_in_connection(connection, mission_id, plan_id)


@dataclass(frozen=True)
class ReplacementAuthorityEvidence:
    """Opaque authority evidence verified inside the replacement transaction."""

    requirement_id: str
    evidence_id: str
    evidence_sha256: str
    evidence_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ReplacementAuthorityEvidence:
        if not isinstance(raw, Mapping) or set(raw) != {
            "requirement_id",
            "evidence_id",
            "evidence_sha256",
            "evidence",
        }:
            raise PrincipalAuthenticationError("Replacement authority evidence is invalid")
        requirement_id = raw.get("requirement_id")
        evidence_id = raw.get("evidence_id")
        evidence = raw.get("evidence")
        if not all(isinstance(value, str) and value for value in (requirement_id, evidence_id)):
            raise PrincipalAuthenticationError("Replacement authority identity is invalid")
        if not isinstance(evidence, Mapping):
            raise PrincipalAuthenticationError("Replacement authority evidence is invalid")
        evidence_json = canonical_json(dict(evidence))
        evidence_sha256 = sha256_text(evidence_json)
        if raw.get("evidence_sha256") != evidence_sha256:
            raise PrincipalAuthenticationError("Replacement authority evidence hash is invalid")
        return cls(
            requirement_id=requirement_id,
            evidence_id=evidence_id,
            evidence_sha256=evidence_sha256,
            evidence_json=evidence_json,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "evidence": json.loads(self.evidence_json),
        }


@dataclass(frozen=True)
class VerifiedReplacementAuthority:
    """Exact authority result returned by a transaction-scoped verifier."""

    requirement_id: str
    role: str
    authority_id: str
    authority_kind: str
    operation: str
    work_item_id: str | None
    operation_intent_sha256: str
    evidence_id: str
    evidence_sha256: str


class ReplacementAuthorityVerifier(Protocol):
    """Authenticate and consume one exact authority in the open transaction.

    A concrete signed-principal adapter must use the supplied connection to
    query durable revocation and replay state and to consume the assertion in
    the global principal assertion ledger. Envelope replay keys do not replace
    global assertion identity consumption. Caller-supplied state collections
    are advisory and cannot be the authority source.
    """

    def verify(
        self,
        connection: sqlite3.Connection,
        *,
        requirement: Mapping[str, Any],
        evidence: ReplacementAuthorityEvidence,
        consumed_at: str,
    ) -> VerifiedReplacementAuthority: ...


@dataclass(frozen=True)
class CollaborationPlanReplacementCommitReceipt:
    """Exact durable result of one atomic plan replacement."""

    replacement_commit_id: str
    receipt_sha256: str
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CollaborationPlanReplacementCommitReceipt:
        if not isinstance(raw, Mapping):
            raise StoreIntegrityError("Replacement receipt is invalid")
        required = {
            "schema_version",
            "replacement_commit_id",
            "receipt_sha256",
            "request_sha256",
            "mission_id",
            "preflight_id",
            "preflight_sha256",
            "predecessor_plan_id",
            "predecessor_plan_sha256",
            "replacement_plan_id",
            "replacement_plan_sha256",
            "predecessor_plan_version",
            "replacement_plan_version",
            "mission_revision",
            "source_snapshot_hashes",
            "authority_count",
            "source_settlement_count",
            "completed_carry_forward_count",
            "work_initialization_count",
            "committed_at",
            "commit_status",
        }
        if set(raw) != required or raw.get("schema_version") != 1:
            raise StoreIntegrityError("Replacement receipt fields are invalid")
        body = {
            key: value
            for key, value in raw.items()
            if key not in {"replacement_commit_id", "receipt_sha256"}
        }
        digest = _canonical_sha256({"domain": REPLACEMENT_RECEIPT_DOMAIN, "receipt": body})
        commit_id = "CPR-" + digest.removeprefix("sha256:")[:32].upper()
        if raw.get("receipt_sha256") != digest or raw.get("replacement_commit_id") != commit_id:
            raise StoreIntegrityError("Replacement receipt identity is invalid")
        document_json = canonical_json(dict(raw))
        return cls(commit_id, digest, document_json)

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise StoreIntegrityError("Replacement receipt is invalid")
        return value


@dataclass(frozen=True)
class _SourceSettlement:
    source_work_item_id: str
    replacement_work_item_id: str | None
    source_state: str
    disposition: str
    source_transition_id: str | None
    completed_result_sha256: str | None
    settlement_sha256: str


def _latest_work_rows(
    connection: sqlite3.Connection,
    mission_id: str,
    plan_id: str,
) -> dict[str, sqlite3.Row]:
    rows = connection.execute(
        """
        SELECT transition_id, work_item_id, generation, transition_kind,
               result_sha256, recorded_at
        FROM collaboration_work_item_transitions
        WHERE mission_id = ? AND plan_id = ?
        UNION ALL
        SELECT transition_id, work_item_id, generation, transition_kind,
               result_sha256, recorded_at
        FROM collaboration_work_item_recovery_transitions
        WHERE mission_id = ? AND plan_id = ?
        ORDER BY work_item_id, generation, recorded_at, transition_id
        """,
        (mission_id, plan_id, mission_id, plan_id),
    ).fetchall()
    latest: dict[str, sqlite3.Row] = {}
    for row in rows:
        latest[str(row["work_item_id"])] = row
    return latest


def _require_terminal_source_state(
    connection: sqlite3.Connection,
    *,
    mission_id: str,
    plan_id: str,
    prior_plan: CollaborationPlan,
    preflight: Mapping[str, Any],
) -> tuple[list[_SourceSettlement], list[_SourceSettlement]]:
    latest = _latest_work_rows(connection, mission_id, plan_id)
    carried = {
        str(row["replacement_work_item_id"]): row
        for row in connection.execute(
            """
            SELECT carry.replacement_work_item_id,
                   carry.completed_result_sha256,
                   carry.source_transition_id
            FROM collaboration_plan_activations AS activation
            JOIN collaboration_plan_completed_work_carry_forwards AS carry
              ON carry.replacement_commit_id = activation.replacement_commit_id
            WHERE activation.plan_id = ?
            ORDER BY carry.replacement_work_item_id
            """,
            (plan_id,),
        ).fetchall()
    }
    nonterminal = sorted(
        work_item_id
        for work_item_id, row in latest.items()
        if row["transition_kind"] in {"claim", "renew"}
    )
    if nonterminal:
        raise StoreConflictError("Source work leases are not terminal: " + ", ".join(nonterminal))
    active_sessions = connection.execute(
        """
        SELECT activation.session_authority_id
        FROM execution_session_activation_commits AS activation
        JOIN execution_session_authority_commits AS authority
          ON authority.session_authority_id = activation.session_authority_id
        LEFT JOIN execution_session_revocation_commits AS revocation
          ON revocation.session_authority_id = activation.session_authority_id
        WHERE authority.mission_id = ?
          AND authority.collaboration_plan_id = ?
          AND revocation.session_authority_id IS NULL
        ORDER BY activation.session_authority_id
        """,
        (mission_id, plan_id),
    ).fetchall()
    if active_sessions:
        raise StoreConflictError("Source execution sessions are not terminal")
    schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if schema_version >= AUTHENTICATED_MODEL_EXECUTION_SCHEMA_VERSION:
        active_model_executions = connection.execute(
            """
            SELECT dispatch.admission_id
            FROM authenticated_model_execution_dispatches AS dispatch
            JOIN authenticated_model_execution_admissions AS admission
              ON admission.admission_id = dispatch.admission_id
            LEFT JOIN authenticated_model_execution_settlements AS settlement
              ON settlement.admission_id = dispatch.admission_id
            WHERE admission.mission_id = ?
              AND admission.plan_id = ?
              AND settlement.admission_id IS NULL
            ORDER BY dispatch.admission_id
            """,
            (mission_id, plan_id),
        ).fetchall()
        if active_model_executions:
            raise StoreConflictError("Source model executions are not terminal")

    item_mappings = preflight.get("item_mappings")
    cancellations = preflight.get("cancellation_actions")
    if not isinstance(item_mappings, list) or not isinstance(cancellations, list):
        raise CollaborationPlanError("Replacement preflight work mapping is invalid")
    mapping_by_source = {str(item["source_work_item_id"]): item for item in item_mappings}
    cancellation_by_source = {str(item["source_work_item_id"]): item for item in cancellations}
    source_ids = {item.work_item_id for item in prior_plan.work_items}
    if (
        set(mapping_by_source) & set(cancellation_by_source)
        or set(mapping_by_source) | set(cancellation_by_source) != source_ids
    ):
        raise CollaborationPlanError(
            "Replacement preflight does not settle every source work item exactly once"
        )
    settlements: list[_SourceSettlement] = []
    carry_forwards: list[_SourceSettlement] = []
    for source_id in sorted(source_ids):
        row = latest.get(source_id)
        carried_row = carried.get(source_id)
        actual_state = (
            "completed"
            if (
                (row is not None and row["transition_kind"] == "complete")
                or (row is None and carried_row is not None)
            )
            else "not_completed"
        )
        result_sha256 = (
            carried_row["completed_result_sha256"]
            if row is None and carried_row is not None
            else (None if row is None else row["result_sha256"])
        )
        transition_id = (
            str(carried_row["source_transition_id"])
            if row is None and carried_row is not None
            else (None if row is None else str(row["transition_id"]))
        )
        if source_id in mapping_by_source:
            item = mapping_by_source[source_id]
            replacement_id = str(item["replacement_work_item_id"])
            disposition = str(item["disposition"])
            if item.get("source_state") != actual_state:
                raise StoreConflictError("Source work state drifted after preflight")
            if item.get("completed_result_sha256") != result_sha256:
                raise StoreConflictError("Source completed result drifted after preflight")
        else:
            replacement_id = None
            disposition = "cancel_without_history_rewrite"
        material = {
            "disposition": disposition,
            "replacement_work_item_id": replacement_id,
            "source_state": actual_state,
            "source_transition_id": transition_id,
            "source_work_item_id": source_id,
            "completed_result_sha256": result_sha256,
        }
        settlement = _SourceSettlement(
            source_work_item_id=source_id,
            replacement_work_item_id=replacement_id,
            source_state=actual_state,
            disposition=disposition,
            source_transition_id=transition_id,
            completed_result_sha256=result_sha256,
            settlement_sha256=_canonical_sha256(material),
        )
        settlements.append(settlement)
        if disposition == "preserve_completed_result":
            if actual_state != "completed" or transition_id is None or result_sha256 is None:
                raise StoreConflictError("Completed carry-forward source is not complete")
            carry_forwards.append(settlement)
    return settlements, carry_forwards


class _CollaborationPlanReplacementAtomicStore:
    """Internal atomic engine, including isolated historical schema29 fixtures."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        authority_verifier: ReplacementAuthorityVerifier,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        if not callable(getattr(authority_verifier, "verify", None)):
            raise TypeError("authority_verifier must implement verify")
        registry.validate()
        self._store = store
        self._registry = registry
        self._authority_verifier = authority_verifier
        self._clock = clock or store._clock

    def _require_replacement_transaction(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
    ) -> None:
        """Historical engine hook; the runtime service requires signed custody."""

    def _verify_replacement_target(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
        receipt: CollaborationPlanReplacementCommitReceipt,
    ) -> None:
        """Historical engine hook; runtime writes and replays verify target custody."""

    def _verify_replacement_replay(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
    ) -> None:
        """Historical engine hook; runtime replay requires current authority context."""

    def replace(
        self,
        *,
        preflight: CollaborationPlanReplacementPreflight,
        prior_plan: CollaborationPlan,
        replacement_plan: CollaborationPlan,
        authority_evidence: Sequence[ReplacementAuthorityEvidence],
        expected_plan_version: int,
    ) -> CollaborationPlanReplacementCommitReceipt:
        parsed_preflight = CollaborationPlanReplacementPreflight.from_dict(preflight.to_dict())
        prior = CollaborationPlan.from_dict(prior_plan.to_dict())
        replacement = CollaborationPlan.from_dict(replacement_plan.to_dict())
        document = parsed_preflight.to_dict()
        if (
            document["mission_id"] != prior.mission_id
            or replacement.mission_id != prior.mission_id
            or document["prior_plan"]
            != {"plan_id": prior.plan_id, "plan_sha256": prior.content_sha256}
            or document["replacement_plan"]
            != {
                "plan_id": replacement.plan_id,
                "plan_sha256": replacement.content_sha256,
            }
        ):
            raise CollaborationPlanError("Replacement preflight plan bindings are stale")
        if (
            not isinstance(expected_plan_version, int)
            or isinstance(expected_plan_version, bool)
            or expected_plan_version < 1
        ):
            raise CollaborationPlanError("expected_plan_version is invalid")
        evidence = tuple(
            ReplacementAuthorityEvidence.from_dict(item.to_dict()) for item in authority_evidence
        )
        by_requirement = {item.requirement_id: item for item in evidence}
        if len(by_requirement) != len(evidence):
            raise PrincipalAuthenticationError("Replacement authority evidence is duplicated")
        requirements = document["authority_requirements"]
        requirement_ids = {str(item["requirement_id"]) for item in requirements}
        if set(by_requirement) != requirement_ids:
            raise PrincipalAuthenticationError(
                "Replacement authority evidence coverage is incomplete"
            )
        request = {
            "domain": REPLACEMENT_REQUEST_DOMAIN,
            "authority_evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "evidence_sha256": item.evidence_sha256,
                    "requirement_id": item.requirement_id,
                }
                for item in sorted(evidence, key=lambda value: value.requirement_id)
            ],
            "expected_plan_version": expected_plan_version,
            "mission_id": prior.mission_id,
            "preflight_id": parsed_preflight.preflight_id,
            "preflight_sha256": parsed_preflight.preflight_sha256,
            "prior_plan_id": prior.plan_id,
            "prior_plan_sha256": prior.content_sha256,
            "replacement_plan_id": replacement.plan_id,
            "replacement_plan_sha256": replacement.content_sha256,
        }
        request_json = canonical_json(request)
        request_sha256 = sha256_text(request_json)
        try:
            with self._store._write_connection() as connection:
                self._require_replacement_transaction(connection, parsed_preflight)
                exact = connection.execute(
                    """
                    SELECT * FROM collaboration_plan_replacement_commits
                    WHERE request_sha256 = ?
                    """,
                    (request_sha256,),
                ).fetchone()
                if exact is not None:
                    receipt = CollaborationPlanReplacementCommitReceipt.from_dict(
                        json.loads(str(exact["receipt_json"]))
                    )
                    if (
                        canonical_json(receipt.to_dict()) != exact["receipt_json"]
                        or receipt.replacement_commit_id != exact["replacement_commit_id"]
                        or receipt.receipt_sha256 != exact["receipt_sha256"]
                        or receipt.to_dict()["request_sha256"] != request_sha256
                    ):
                        raise StoreIntegrityError(
                            "Durable replacement replay receipt is inconsistent"
                        )
                    self._verify_replacement_target(connection, parsed_preflight, receipt)
                    self._verify_replacement_replay(connection, parsed_preflight)
                    return receipt
                collision = connection.execute(
                    """
                    SELECT request_sha256
                    FROM collaboration_plan_replacement_commits
                    WHERE preflight_id = ? OR replacement_plan_id = ?
                    LIMIT 1
                    """,
                    (parsed_preflight.preflight_id, replacement.plan_id),
                ).fetchone()
                if collision is not None:
                    raise StoreConflictError(
                        "Replacement preflight or plan was already committed differently"
                    )
                stored_mission_row = connection.execute(
                    "SELECT * FROM missions WHERE mission_id = ?",
                    (prior.mission_id,),
                ).fetchone()
                if stored_mission_row is None:
                    raise StoreIntegrityError("Replacement mission is missing")
                mission = self._store._stored_mission_from_row(
                    connection,
                    self._registry,
                    stored_mission_row,
                )
                if expected_plan_version == 1:
                    validate_collaboration_plan(
                        self._registry,
                        mission.mission,
                        prior,
                    )
                else:
                    prior._validate_integrity()
                    if (
                        prior.mission_id != mission.mission.mission_id
                        or prior.mission_sha256 != replacement.mission_sha256
                        or prior.joint_mission_cell_sha256 != replacement.joint_mission_cell_sha256
                        or prior.registry_sha256 != replacement.registry_sha256
                    ):
                        raise CollaborationPlanError("Prior replacement plan bindings are invalid")
                _validate_replacement_plan_binding(
                    self._registry,
                    mission.mission,
                    prior,
                    replacement,
                )
                control = connection.execute(
                    "SELECT state FROM mission_controls WHERE mission_id = ?",
                    (prior.mission_id,),
                ).fetchone()
                if control is None:
                    raise StoreIntegrityError("Mission control state is missing")
                if control["state"] != "active":
                    raise MissionStoppedError("Stopped mission cannot replace a plan")
                mission_row = connection.execute(
                    "SELECT revision FROM missions WHERE mission_id = ?",
                    (prior.mission_id,),
                ).fetchone()
                head = connection.execute(
                    """
                    SELECT * FROM collaboration_plan_active_heads
                    WHERE mission_id = ?
                    """,
                    (prior.mission_id,),
                ).fetchone()
                if mission_row is None or head is None:
                    raise StoreIntegrityError("Replacement source head is missing")
                if (
                    head["active_plan_id"] != prior.plan_id
                    or int(head["plan_version"]) != expected_plan_version
                ):
                    raise StoreConflictError("Active collaboration plan head changed")
                source_activation = connection.execute(
                    """
                    SELECT plan_json, plan_content_sha256
                    FROM collaboration_plan_activations
                    WHERE mission_id = ? AND plan_id = ?
                    """,
                    (prior.mission_id, prior.plan_id),
                ).fetchone()
                if (
                    source_activation is None
                    or source_activation["plan_json"] != canonical_json(prior.to_dict())
                    or source_activation["plan_content_sha256"] != prior.content_sha256
                ):
                    raise StoreConflictError("Active collaboration plan content changed")
                source_state = document["source_state"]
                if (
                    source_state.get("active_plan_id") != prior.plan_id
                    or source_state.get("active_plan_sha256") != prior.content_sha256
                ):
                    raise StoreConflictError("Replacement source head binding is stale")
                if int(mission_row["revision"]) != source_state.get("mission_revision"):
                    raise StoreConflictError("Mission revision drifted after preflight")
                snapshots = _build_source_snapshots_in_connection(
                    connection, prior.mission_id, prior.plan_id
                )
                if snapshots.hashes != {key: source_state[key] for key in snapshots.hashes}:
                    raise StoreConflictError("Replacement source snapshots drifted")
                settlements, carry_forwards = _require_terminal_source_state(
                    connection,
                    mission_id=prior.mission_id,
                    plan_id=prior.plan_id,
                    prior_plan=prior,
                    preflight=document,
                )
                mapped_target_ids = [
                    str(item["replacement_work_item_id"]) for item in document["item_mappings"]
                ]
                new_target_ids = [
                    str(item["replacement_work_item_id"]) for item in document["new_item_actions"]
                ]
                replacement_ids = {item.work_item_id for item in replacement.work_items}
                if (
                    len(set(mapped_target_ids)) != len(mapped_target_ids)
                    or len(set(new_target_ids)) != len(new_target_ids)
                    or set(mapped_target_ids) & set(new_target_ids)
                    or set(mapped_target_ids) | set(new_target_ids) != replacement_ids
                ):
                    raise CollaborationPlanError(
                        "Replacement preflight does not initialize every target exactly once"
                    )
                committed_at = format_timestamp(self._clock())
                verified_authorities: list[VerifiedReplacementAuthority] = []
                for requirement in sorted(
                    requirements, key=lambda item: str(item["requirement_id"])
                ):
                    authority = self._authority_verifier.verify(
                        connection,
                        requirement=requirement,
                        evidence=by_requirement[str(requirement["requirement_id"])],
                        consumed_at=committed_at,
                    )
                    expected = (
                        str(requirement["requirement_id"]),
                        str(requirement["role"]),
                        str(requirement["authority_id"]),
                        str(requirement["authority_kind"]),
                        str(requirement["operation"]),
                        requirement.get("work_item_id"),
                        str(requirement["operation_intent_sha256"]),
                    )
                    actual = (
                        authority.requirement_id,
                        authority.role,
                        authority.authority_id,
                        authority.authority_kind,
                        authority.operation,
                        authority.work_item_id,
                        authority.operation_intent_sha256,
                    )
                    evidence_item = by_requirement[authority.requirement_id]
                    if (
                        actual != expected
                        or authority.evidence_id != evidence_item.evidence_id
                        or authority.evidence_sha256 != evidence_item.evidence_sha256
                    ):
                        raise PrincipalAuthenticationError(
                            "Replacement authority verification result is stale"
                        )
                    verified_authorities.append(authority)
                initialization_rows = self._work_initializations(replacement, carry_forwards)
                receipt_body = {
                    "schema_version": 1,
                    "request_sha256": request_sha256,
                    "mission_id": prior.mission_id,
                    "preflight_id": parsed_preflight.preflight_id,
                    "preflight_sha256": parsed_preflight.preflight_sha256,
                    "predecessor_plan_id": prior.plan_id,
                    "predecessor_plan_sha256": prior.content_sha256,
                    "replacement_plan_id": replacement.plan_id,
                    "replacement_plan_sha256": replacement.content_sha256,
                    "predecessor_plan_version": expected_plan_version,
                    "replacement_plan_version": expected_plan_version + 1,
                    "mission_revision": int(mission_row["revision"]),
                    "source_snapshot_hashes": snapshots.hashes,
                    "authority_count": len(verified_authorities),
                    "source_settlement_count": len(settlements),
                    "completed_carry_forward_count": len(carry_forwards),
                    "work_initialization_count": len(initialization_rows),
                    "committed_at": committed_at,
                    "commit_status": "committed_active",
                }
                receipt_sha256 = _canonical_sha256(
                    {"domain": REPLACEMENT_RECEIPT_DOMAIN, "receipt": receipt_body}
                )
                commit_id = "CPR-" + receipt_sha256.removeprefix("sha256:")[:32].upper()
                receipt = CollaborationPlanReplacementCommitReceipt.from_dict(
                    {
                        **receipt_body,
                        "replacement_commit_id": commit_id,
                        "receipt_sha256": receipt_sha256,
                    }
                )
                self._insert_commit_graph(
                    connection,
                    receipt=receipt,
                    preflight=parsed_preflight,
                    request_json=request_json,
                    prior=prior,
                    replacement=replacement,
                    snapshots=snapshots,
                    authorities=verified_authorities,
                    evidence=by_requirement,
                    settlements=settlements,
                    carry_forwards=carry_forwards,
                    initializations=initialization_rows,
                )
                cursor = connection.execute(
                    """
                    UPDATE collaboration_plan_active_heads
                    SET active_plan_id = ?, plan_version = ?,
                        replacement_commit_id = ?, updated_at = ?
                    WHERE mission_id = ? AND active_plan_id = ? AND plan_version = ?
                    """,
                    (
                        replacement.plan_id,
                        expected_plan_version + 1,
                        commit_id,
                        committed_at,
                        prior.mission_id,
                        prior.plan_id,
                        expected_plan_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StoreConflictError("Active collaboration plan head changed")
                _verify_collaboration_plan_replacement_state(
                    connection,
                    mission_id=prior.mission_id,
                    registry=self._registry,
                    mission=mission.mission,
                )
                self._verify_replacement_target(connection, parsed_preflight, receipt)
                return receipt
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Atomic collaboration plan replacement conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist collaboration plan replacement") from exc

    @staticmethod
    def _work_initializations(
        replacement: CollaborationPlan,
        carry_forwards: Sequence[_SourceSettlement],
    ) -> list[dict[str, Any]]:
        carried = {
            item.replacement_work_item_id: item
            for item in carry_forwards
            if item.replacement_work_item_id is not None
        }
        rows: list[dict[str, Any]] = []
        for item in sorted(replacement.work_items, key=lambda value: value.work_item_id):
            source = carried.get(item.work_item_id)
            material = {
                "completed_result_sha256": (
                    None if source is None else source.completed_result_sha256
                ),
                "initial_state": ("pending" if source is None else "completed_carried_forward"),
                "replacement_work_item_id": item.work_item_id,
                "source_work_item_id": (None if source is None else source.source_work_item_id),
            }
            rows.append({**material, "initialization_sha256": _canonical_sha256(material)})
        return rows

    def _insert_commit_graph(
        self,
        connection: sqlite3.Connection,
        *,
        receipt: CollaborationPlanReplacementCommitReceipt,
        preflight: CollaborationPlanReplacementPreflight,
        request_json: str,
        prior: CollaborationPlan,
        replacement: CollaborationPlan,
        snapshots: CollaborationPlanReplacementSourceSnapshots,
        authorities: Sequence[VerifiedReplacementAuthority],
        evidence: Mapping[str, ReplacementAuthorityEvidence],
        settlements: Sequence[_SourceSettlement],
        carry_forwards: Sequence[_SourceSettlement],
        initializations: Sequence[Mapping[str, Any]],
    ) -> None:
        value = receipt.to_dict()
        connection.execute(
            """
            INSERT INTO collaboration_plan_activations(
                plan_id, mission_id, store_id, plan_json, plan_sha256,
                plan_content_sha256, registry_sha256, mission_sha256,
                joint_mission_cell_sha256, readiness_owner_profile_id,
                plan_version, activation_kind, replacement_commit_id,
                activated_at, issuer, assertion_id
            )
            SELECT ?, ?, store_id, ?, ?, ?, ?, ?, ?, ?, ?, 'replacement', ?, ?, NULL, NULL
            FROM collaboration_plan_activations WHERE plan_id = ?
            """,
            (
                replacement.plan_id,
                replacement.mission_id,
                canonical_json(replacement.to_dict()),
                sha256_text(canonical_json(replacement.to_dict())),
                replacement.content_sha256,
                replacement.registry_sha256,
                replacement.mission_sha256,
                replacement.joint_mission_cell_sha256,
                next(
                    item.owner_profile_id
                    for item in replacement.work_items
                    if item.kind is WorkItemKind.READINESS
                ),
                value["replacement_plan_version"],
                receipt.replacement_commit_id,
                value["committed_at"],
                prior.plan_id,
            ),
        )
        connection.execute(
            """
            INSERT INTO collaboration_plan_replacement_commits(
                replacement_commit_id, mission_id, preflight_id,
                preflight_sha256, preflight_json, request_sha256, request_json,
                predecessor_plan_id, predecessor_plan_sha256,
                replacement_plan_id, replacement_plan_sha256,
                predecessor_plan_version, replacement_plan_version,
                mission_revision, ownership_snapshot_sha256,
                work_snapshot_sha256, cancellation_snapshot_sha256,
                execution_session_snapshot_sha256,
                terminal_custody_snapshot_sha256, committed_at,
                receipt_json, receipt_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.replacement_commit_id,
                value["mission_id"],
                value["preflight_id"],
                value["preflight_sha256"],
                preflight.document_json,
                value["request_sha256"],
                request_json,
                value["predecessor_plan_id"],
                value["predecessor_plan_sha256"],
                value["replacement_plan_id"],
                value["replacement_plan_sha256"],
                value["predecessor_plan_version"],
                value["replacement_plan_version"],
                value["mission_revision"],
                snapshots.hashes["ownership_snapshot_sha256"],
                snapshots.hashes["work_snapshot_sha256"],
                snapshots.hashes["cancellation_snapshot_sha256"],
                snapshots.hashes["execution_session_snapshot_sha256"],
                snapshots.hashes["terminal_custody_snapshot_sha256"],
                value["committed_at"],
                receipt.document_json,
                receipt.receipt_sha256,
            ),
        )
        for authority in authorities:
            item = evidence[authority.requirement_id]
            connection.execute(
                """
                INSERT INTO collaboration_plan_replacement_authorities(
                    replacement_commit_id, requirement_id, role, authority_id,
                    authority_kind, operation, work_item_id,
                    operation_intent_sha256, evidence_id, evidence_sha256,
                    evidence_json, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.replacement_commit_id,
                    authority.requirement_id,
                    authority.role,
                    authority.authority_id,
                    authority.authority_kind,
                    authority.operation,
                    authority.work_item_id,
                    authority.operation_intent_sha256,
                    authority.evidence_id,
                    authority.evidence_sha256,
                    item.evidence_json,
                    value["committed_at"],
                ),
            )
        for settlement in settlements:
            connection.execute(
                """
                INSERT INTO collaboration_plan_replacement_source_settlements(
                    replacement_commit_id, source_work_item_id,
                    replacement_work_item_id, source_state, disposition,
                    source_transition_id, completed_result_sha256,
                    settlement_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.replacement_commit_id,
                    settlement.source_work_item_id,
                    settlement.replacement_work_item_id,
                    settlement.source_state,
                    settlement.disposition,
                    settlement.source_transition_id,
                    settlement.completed_result_sha256,
                    settlement.settlement_sha256,
                ),
            )
        for item in carry_forwards:
            material = {
                "completed_result_sha256": item.completed_result_sha256,
                "replacement_work_item_id": item.replacement_work_item_id,
                "source_transition_id": item.source_transition_id,
                "source_work_item_id": item.source_work_item_id,
            }
            connection.execute(
                """
                INSERT INTO collaboration_plan_completed_work_carry_forwards(
                    replacement_commit_id, source_work_item_id,
                    replacement_work_item_id, completed_result_sha256,
                    source_transition_id, carry_forward_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.replacement_commit_id,
                    item.source_work_item_id,
                    item.replacement_work_item_id,
                    item.completed_result_sha256,
                    item.source_transition_id,
                    _canonical_sha256(material),
                ),
            )
        for item in initializations:
            connection.execute(
                """
                INSERT INTO collaboration_plan_work_initializations(
                    replacement_commit_id, replacement_work_item_id,
                    initial_state, source_work_item_id,
                    completed_result_sha256, initialization_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.replacement_commit_id,
                    item["replacement_work_item_id"],
                    item["initial_state"],
                    item["source_work_item_id"],
                    item["completed_result_sha256"],
                    item["initialization_sha256"],
                ),
            )

    def get(self, mission_id: str) -> CollaborationPlanReplacementCommitReceipt:
        """Return the latest exact replacement receipt for a mission."""

        with self._store._read_connection() as connection:
            row = connection.execute(
                """
                SELECT replacement.receipt_json
                FROM collaboration_plan_active_heads AS head
                JOIN collaboration_plan_replacement_commits AS replacement
                  ON replacement.replacement_commit_id = head.replacement_commit_id
                WHERE head.mission_id = ?
                """,
                (mission_id,),
            ).fetchone()
            if row is None:
                raise StoreError("Mission has no collaboration plan replacement")
            return CollaborationPlanReplacementCommitReceipt.from_dict(
                json.loads(str(row["receipt_json"]))
            )


class CollaborationPlanReplacementStoreService(_CollaborationPlanReplacementAtomicStore):
    """Runtime replacement entrypoint requiring transaction-scoped signed authority.

    Historical ``get`` remains read-only. The private atomic engine is not a
    production authorization boundary; durable schema guards fence writes too.
    """

    def replace(
        self,
        *,
        preflight: CollaborationPlanReplacementPreflight,
        prior_plan: CollaborationPlan,
        replacement_plan: CollaborationPlan,
        authority_evidence: Sequence[ReplacementAuthorityEvidence],
        expected_plan_version: int,
    ) -> CollaborationPlanReplacementCommitReceipt:
        from .authenticated_collaboration_plan_replacement import (
            _require_transaction_scoped_replacement_verifier,
        )

        _require_transaction_scoped_replacement_verifier(
            self._authority_verifier,
            store=self._store,
            registry=self._registry,
            preflight=preflight,
        )
        return super().replace(
            preflight=preflight,
            prior_plan=prior_plan,
            replacement_plan=replacement_plan,
            authority_evidence=authority_evidence,
            expected_plan_version=expected_plan_version,
        )

    def _require_replacement_transaction(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
    ) -> None:
        from .authenticated_collaboration_plan_replacement import (
            _require_transaction_scoped_replacement_verifier,
        )

        _require_transaction_scoped_replacement_verifier(
            self._authority_verifier,
            store=self._store,
            registry=self._registry,
            preflight=preflight,
        )
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if schema_version < AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION:
            raise StoreIntegrityError("Runtime replacement requires signed-custody schema30")

    def _verify_replacement_target(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
        receipt: CollaborationPlanReplacementCommitReceipt,
    ) -> None:
        commit = connection.execute(
            """
            SELECT * FROM collaboration_plan_replacement_commits
            WHERE replacement_commit_id = ?
            """,
            (receipt.replacement_commit_id,),
        ).fetchone()
        if commit is None or commit["preflight_id"] != preflight.preflight_id:
            raise StoreIntegrityError("Runtime replacement target custody is missing")
        if commit["preflight_json"] != canonical_json(preflight.to_dict()):
            raise StoreIntegrityError("Runtime replacement target preflight is inconsistent")
        authorities = connection.execute(
            """
            SELECT * FROM collaboration_plan_replacement_authorities
            WHERE replacement_commit_id = ? ORDER BY requirement_id
            """,
            (receipt.replacement_commit_id,),
        ).fetchall()
        _verify_authenticated_replacement_custody(
            connection,
            commit=commit,
            preflight=preflight,
            authorities=authorities,
            registry=self._registry,
            require_signed=True,
        )

    def _verify_replacement_replay(
        self,
        connection: sqlite3.Connection,
        preflight: CollaborationPlanReplacementPreflight,
    ) -> None:
        from .authenticated_collaboration_plan_replacement import (
            _verify_authenticated_replacement_replay_state,
        )
        from .store import parse_timestamp

        at = parse_timestamp(format_timestamp(self._clock()), "replacement replay time")
        self._authority_verifier._require_call_scope(connection, format_timestamp(at))
        _verify_authenticated_replacement_replay_state(
            connection,
            store=self._store,
            registry=self._registry,
            preflight=preflight,
            credentials=self._authority_verifier._credentials.values(),
            at=at,
        )


def _replacement_principal_intent(
    requirement: Mapping[str, Any],
    preflight: Mapping[str, Any],
) -> dict[str, Any]:
    intent: dict[str, Any] = {
        "authority_intent_sha256": requirement["authority_intent_sha256"],
        "mission_id": preflight["mission_id"],
        "principal_profile_id": requirement["principal_profile_id"],
        "prior_plan_id": preflight["prior_plan"]["plan_id"],
        "prior_plan_sha256": preflight["prior_plan"]["plan_sha256"],
        "replacement_plan_id": preflight["replacement_plan"]["plan_id"],
        "replacement_plan_sha256": preflight["replacement_plan"]["plan_sha256"],
        "role": requirement["role"],
        "selection_sha256": requirement["selection_sha256"],
        "work_item_id": requirement["work_item_id"],
    }
    command_binding = requirement.get("command_authority_binding_sha256")
    if command_binding is not None:
        intent["command_authority_binding_sha256"] = command_binding
    return intent


def _verify_authenticated_replacement_custody(
    connection: sqlite3.Connection,
    *,
    commit: sqlite3.Row,
    preflight: CollaborationPlanReplacementPreflight,
    authorities: Sequence[sqlite3.Row],
    registry: ExpertRegistry,
    require_signed: bool = False,
) -> None:
    from .collaboration_plan_replacement_authentication import (
        validate_plan_replacement_authority_requirement_count,
    )

    rows = connection.execute(
        """
        SELECT * FROM collaboration_plan_replacement_authentications
        WHERE preflight_id = ?
        """,
        (preflight.preflight_id,),
    ).fetchall()
    if not rows:
        if require_signed:
            raise StoreIntegrityError("Runtime replacement requires signed authority custody")
        for authority in authorities:
            try:
                evidence = json.loads(str(authority["evidence_json"]))
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError("Replacement authority evidence is invalid") from exc
            if evidence.get("domain") == AUTHORITY_EVIDENCE_DOMAIN:
                raise StoreIntegrityError("Signed replacement authority custody is missing")
        return
    if len(rows) != 1:
        raise StoreIntegrityError(
            "Replacement signed authentication custody is missing or duplicated"
        )
    authentication = rows[0]
    try:
        plan_document = json.loads(str(authentication["authority_plan_json"]))
        authority_plan = CollaborationPlanReplacementAuthorityPlan.from_dict(plan_document)
        upgrade_document = json.loads(str(authentication["authority_upgrade_json"]))
        upgrade = CollaborationPlanReplacementAuthorityUpgrade.from_dict(upgrade_document)
        verified_upgrade = verify_collaboration_plan_replacement_authority_upgrade(
            upgrade,
            preflight=preflight,
            army_registry=registry,
        )
        requirement_count = validate_plan_replacement_authority_requirement_count(
            len(plan_document["assertion_requirements"])
        )
        validate_plan_replacement_authority_requirement_count(
            authentication["requirement_count"], "durable authority requirement count"
        )
    except (json.JSONDecodeError, CollaborationPlanError) as exc:
        raise StoreIntegrityError(
            "Replacement signed authentication documents are invalid"
        ) from exc
    body = {
        "schema_version": 1,
        "domain": AUTHENTICATION_CUSTODY_DOMAIN,
        "preflight_id": preflight.preflight_id,
        "mission_id": commit["mission_id"],
        "authority_plan_id": authority_plan.authority_plan_id,
        "authority_plan_sha256": authority_plan.authority_plan_sha256,
        "authority_plan_document_sha256": authority_plan.document_sha256,
        "authority_upgrade_id": verified_upgrade.upgrade_id,
        "authority_upgrade_sha256": verified_upgrade.upgrade_sha256,
        "composition_sha256": authentication["composition_sha256"],
        "trust_policy_id": authentication["trust_policy_id"],
        "trust_policy_version": authentication["trust_policy_version"],
        "trust_policy_sha256": authentication["trust_policy_sha256"],
        "authenticated_at": authentication["authenticated_at"],
        "consumed_at": authentication["consumed_at"],
        "requirement_count": authentication["requirement_count"],
    }
    preflight_document = preflight.to_dict()
    upgraded_requirements = {
        str(item["source_requirement_id"]): item
        for item in upgrade_document["authority_requirements"]
    }
    plan_source = plan_document["source_preflight"]
    plan_requirement_ids = {
        item["requirement_id"] for item in plan_document["assertion_requirements"]
    }
    preflight_requirement_ids = {
        item["requirement_id"] for item in preflight_document["authority_requirements"]
    }
    if (
        canonical_json(plan_document) != authentication["authority_plan_json"]
        or canonical_json(upgrade_document) != authentication["authority_upgrade_json"]
        or authentication["mission_id"] != commit["mission_id"]
        or authentication["authority_plan_id"] != authority_plan.authority_plan_id
        or authentication["authority_plan_sha256"] != authority_plan.authority_plan_sha256
        or authentication["authority_upgrade_id"] != verified_upgrade.upgrade_id
        or authentication["authority_upgrade_sha256"] != verified_upgrade.upgrade_sha256
        or plan_source["preflight_id"] != preflight.preflight_id
        or plan_source["preflight_sha256"] != preflight.preflight_sha256
        or authentication["requirement_count"] != requirement_count
        or authentication["consumed_at"] != commit["committed_at"]
        or authentication["authenticated_at"] > authentication["consumed_at"]
        or _canonical_sha256(body) != authentication["authentication_sha256"]
        or len(upgraded_requirements) != requirement_count
        or len(plan_requirement_ids) != requirement_count
        or plan_requirement_ids != preflight_requirement_ids
        or set(upgraded_requirements) != plan_requirement_ids
    ):
        raise StoreIntegrityError("Replacement signed authentication custody does not reconcile")

    consumptions = connection.execute(
        """
        SELECT consumption.*, use.assertion_json, use.operation_intent_json,
               use.signed_intent_hash, use.trust_policy_id AS use_policy_id,
               use.trust_policy_version AS use_policy_version,
               use.trust_policy_hash AS use_policy_hash,
               effect.effect_json, authority.evidence_json,
               authority.evidence_sha256, authority.evidence_id
        FROM collaboration_plan_replacement_authority_consumptions AS consumption
        JOIN principal_assertion_uses AS use
          ON use.issuer = consumption.issuer
         AND use.assertion_id = consumption.assertion_id
        JOIN principal_assertion_effects AS effect
          ON effect.issuer = use.issuer
         AND effect.assertion_id = use.assertion_id
         AND effect.effect_index = 1
        JOIN collaboration_plan_replacement_commits AS replacement
          ON replacement.preflight_id = consumption.preflight_id
        JOIN collaboration_plan_replacement_authorities AS authority
          ON authority.replacement_commit_id = replacement.replacement_commit_id
         AND authority.requirement_id = consumption.source_requirement_id
        WHERE consumption.preflight_id = ?
        ORDER BY consumption.source_requirement_id
        """,
        (preflight.preflight_id,),
    ).fetchall()
    if len(consumptions) != requirement_count or len(authorities) != requirement_count:
        raise StoreIntegrityError("Replacement signed authority consumption is incomplete")
    for consumption in consumptions:
        source_id = str(consumption["source_requirement_id"])
        upgraded = upgraded_requirements.get(source_id)
        if upgraded is None:
            raise StoreIntegrityError("Replacement signed authority requirement mapping is missing")
        try:
            assertion = json.loads(str(consumption["assertion_json"]))
            evidence = json.loads(str(consumption["evidence_json"]))
            effect = json.loads(str(consumption["effect_json"]))
            scope_row = connection.execute(
                "SELECT grant_json FROM mission_scope_grants WHERE grant_hash = ?",
                (consumption["scope_grant_sha256"],),
            ).fetchone()
            if scope_row is None:
                raise StoreIntegrityError("Replacement signed authority scope grant is missing")
            scope_grant = json.loads(str(scope_row["grant_json"]))
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError(
                "Replacement signed authority custody JSON is invalid"
            ) from exc
        credential = {
            "source_requirement_id": source_id,
            "upgraded_requirement_id": consumption["upgraded_requirement_id"],
            "canonical_replay_key_sha256": consumption["canonical_replay_key_sha256"],
            "scope_grant": scope_grant,
            "assertion": assertion,
        }
        expected_evidence = {
            "schema_version": 1,
            "domain": AUTHORITY_EVIDENCE_DOMAIN,
            "authority_plan_id": authentication["authority_plan_id"],
            "authority_upgrade_id": authentication["authority_upgrade_id"],
            "composition_sha256": authentication["composition_sha256"],
            **credential,
        }
        intent = _replacement_principal_intent(upgraded, preflight_document)
        payload = effect.get("payload")
        if (
            consumption["upgraded_requirement_id"] != upgraded["requirement_id"]
            or consumption["operation"] != upgraded["operation"]
            or consumption["effect_id"] != upgraded["requirement_id"]
            or consumption["assertion_sha256"] != sha256_text(str(consumption["assertion_json"]))
            or consumption["credential_sha256"] != _canonical_sha256(credential)
            or consumption["consumed_at"] != authentication["consumed_at"]
            or consumption["use_policy_id"] != authentication["trust_policy_id"]
            or consumption["use_policy_version"] != authentication["trust_policy_version"]
            or consumption["use_policy_hash"] != authentication["trust_policy_sha256"]
            or canonical_json(intent) != consumption["operation_intent_json"]
            or consumption["signed_intent_hash"] != upgraded["principal_operation_intent_sha256"]
            or evidence != expected_evidence
            or canonical_json(evidence) != consumption["evidence_json"]
            or _canonical_sha256(evidence) != consumption["evidence_sha256"]
            or consumption["evidence_id"] != assertion.get("assertion_id")
            or not isinstance(payload, dict)
            or payload.get("domain") != AUTHORITY_EFFECT_DOMAIN
            or payload.get("preflight_id") != preflight.preflight_id
            or payload.get("source_requirement_id") != source_id
            or payload.get("upgraded_requirement_id") != upgraded["requirement_id"]
            or payload.get("canonical_replay_key_sha256")
            != consumption["canonical_replay_key_sha256"]
            or payload.get("composition_sha256") != authentication["composition_sha256"]
        ):
            raise StoreIntegrityError("Replacement signed authority consumption does not reconcile")


def _verify_collaboration_plan_replacement_state(
    connection: sqlite3.Connection,
    *,
    mission_id: str,
    registry: ExpertRegistry,
    mission: Any,
) -> int:
    """Verify the complete append-only replacement chain for one mission."""

    head = connection.execute(
        "SELECT * FROM collaboration_plan_active_heads WHERE mission_id = ?",
        (mission_id,),
    ).fetchone()
    activations = connection.execute(
        """
        SELECT * FROM collaboration_plan_activations
        WHERE mission_id = ? ORDER BY plan_version
        """,
        (mission_id,),
    ).fetchall()
    commits = connection.execute(
        """
        SELECT * FROM collaboration_plan_replacement_commits
        WHERE mission_id = ? ORDER BY replacement_plan_version
        """,
        (mission_id,),
    ).fetchall()
    if not activations:
        if head is not None or commits:
            raise StoreIntegrityError("Replacement head exists without plan activation")
        return 0
    if (
        head is None
        or len(commits) != len(activations) - 1
        or int(head["plan_version"]) != len(activations)
        or head["active_plan_id"] != activations[-1]["plan_id"]
        or head["replacement_commit_id"]
        != (None if not commits else commits[-1]["replacement_commit_id"])
    ):
        raise StoreIntegrityError("Replacement active head does not reconcile")
    plans: dict[str, CollaborationPlan] = {}
    for expected_version, row in enumerate(activations, start=1):
        try:
            plan = CollaborationPlan.from_dict(json.loads(str(row["plan_json"])))
            if expected_version == 1:
                validate_collaboration_plan(registry, mission, plan)
            else:
                _validate_replacement_plan_binding(
                    registry,
                    mission,
                    plans[str(activations[0]["plan_id"])],
                    plan,
                )
        except (json.JSONDecodeError, CollaborationPlanError) as exc:
            raise StoreIntegrityError("Replacement activation plan is invalid") from exc
        if (
            canonical_json(plan.to_dict()) != row["plan_json"]
            or sha256_text(str(row["plan_json"])) != row["plan_sha256"]
            or row["mission_id"] != mission_id
            or row["plan_id"] != plan.plan_id
            or row["plan_content_sha256"] != plan.content_sha256
            or row["registry_sha256"] != plan.registry_sha256
            or row["mission_sha256"] != plan.mission_sha256
            or row["joint_mission_cell_sha256"] != plan.joint_mission_cell_sha256
            or int(row["plan_version"]) != expected_version
            or (expected_version == 1) != (row["activation_kind"] == "initial")
        ):
            raise StoreIntegrityError("Replacement activation binding is invalid")
        plans[plan.plan_id] = plan
    previous = activations[0]
    for commit in commits:
        try:
            preflight = CollaborationPlanReplacementPreflight.from_dict(
                json.loads(str(commit["preflight_json"]))
            )
            request = json.loads(str(commit["request_json"]))
            receipt = CollaborationPlanReplacementCommitReceipt.from_dict(
                json.loads(str(commit["receipt_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            StoreIntegrityError,
        ) as exc:
            raise StoreIntegrityError("Replacement commit document is invalid") from exc
        preflight_document = preflight.to_dict()
        value = receipt.to_dict()
        authorities = connection.execute(
            """
            SELECT * FROM collaboration_plan_replacement_authorities
            WHERE replacement_commit_id = ? ORDER BY requirement_id
            """,
            (commit["replacement_commit_id"],),
        ).fetchall()
        settlements = connection.execute(
            """
            SELECT * FROM collaboration_plan_replacement_source_settlements
            WHERE replacement_commit_id = ? ORDER BY source_work_item_id
            """,
            (commit["replacement_commit_id"],),
        ).fetchall()
        carry_forwards = connection.execute(
            """
            SELECT * FROM collaboration_plan_completed_work_carry_forwards
            WHERE replacement_commit_id = ? ORDER BY replacement_work_item_id
            """,
            (commit["replacement_commit_id"],),
        ).fetchall()
        initializations = connection.execute(
            """
            SELECT * FROM collaboration_plan_work_initializations
            WHERE replacement_commit_id = ? ORDER BY replacement_work_item_id
            """,
            (commit["replacement_commit_id"],),
        ).fetchall()
        prior = plans.get(str(commit["predecessor_plan_id"]))
        replacement = plans.get(str(commit["replacement_plan_id"]))
        if prior is None or replacement is None:
            raise StoreIntegrityError("Replacement commit plan is missing")
        replacement_activation = next(
            (row for row in activations if row["plan_id"] == replacement.plan_id),
            None,
        )
        snapshot_hashes = {
            "ownership_snapshot_sha256": commit["ownership_snapshot_sha256"],
            "work_snapshot_sha256": commit["work_snapshot_sha256"],
            "cancellation_snapshot_sha256": commit["cancellation_snapshot_sha256"],
            "execution_session_snapshot_sha256": commit["execution_session_snapshot_sha256"],
            "terminal_custody_snapshot_sha256": commit["terminal_custody_snapshot_sha256"],
        }
        expected_request_authorities = [
            {
                "evidence_id": str(row["evidence_id"]),
                "evidence_sha256": str(row["evidence_sha256"]),
                "requirement_id": str(row["requirement_id"]),
            }
            for row in authorities
        ]
        expected_authorities = sorted(
            preflight_document["authority_requirements"],
            key=lambda item: item["requirement_id"],
        )
        durable_authorities = [
            {
                "requirement_id": str(row["requirement_id"]),
                "role": str(row["role"]),
                "authority_id": str(row["authority_id"]),
                "authority_kind": str(row["authority_kind"]),
                "operation": str(row["operation"]),
                "work_item_id": row["work_item_id"],
                "operation_intent_sha256": str(row["operation_intent_sha256"]),
            }
            for row in authorities
        ]
        source_state = preflight_document["source_state"]
        if (
            preflight.document_json != commit["preflight_json"]
            or preflight.preflight_id != commit["preflight_id"]
            or preflight.preflight_sha256 != commit["preflight_sha256"]
            or preflight_document["mission_id"] != mission_id
            or preflight_document["prior_plan"]
            != {
                "plan_id": prior.plan_id,
                "plan_sha256": prior.content_sha256,
            }
            or preflight_document["replacement_plan"]
            != {
                "plan_id": replacement.plan_id,
                "plan_sha256": replacement.content_sha256,
            }
            or source_state["mission_revision"] != commit["mission_revision"]
            or source_state["active_plan_id"] != prior.plan_id
            or source_state["active_plan_sha256"] != prior.content_sha256
            or any(source_state[key] != value for key, value in snapshot_hashes.items())
            or durable_authorities != expected_authorities
            or canonical_json(request) != commit["request_json"]
            or sha256_text(str(commit["request_json"])) != commit["request_sha256"]
            or request.get("domain") != REPLACEMENT_REQUEST_DOMAIN
            or request.get("mission_id") != mission_id
            or request.get("preflight_id") != commit["preflight_id"]
            or request.get("preflight_sha256") != commit["preflight_sha256"]
            or request.get("prior_plan_id") != prior.plan_id
            or request.get("prior_plan_sha256") != prior.content_sha256
            or request.get("replacement_plan_id") != replacement.plan_id
            or request.get("replacement_plan_sha256") != replacement.content_sha256
            or request.get("expected_plan_version") != commit["predecessor_plan_version"]
            or request.get("authority_evidence") != expected_request_authorities
            or receipt.replacement_commit_id != commit["replacement_commit_id"]
            or receipt.receipt_sha256 != commit["receipt_sha256"]
            or canonical_json(value) != commit["receipt_json"]
            or value["request_sha256"] != commit["request_sha256"]
            or value["mission_id"] != mission_id
            or value["preflight_id"] != commit["preflight_id"]
            or value["preflight_sha256"] != commit["preflight_sha256"]
            or value["predecessor_plan_id"] != prior.plan_id
            or value["predecessor_plan_sha256"] != prior.content_sha256
            or value["replacement_plan_id"] != replacement.plan_id
            or value["replacement_plan_sha256"] != replacement.content_sha256
            or value["predecessor_plan_version"] != commit["predecessor_plan_version"]
            or value["replacement_plan_version"] != commit["replacement_plan_version"]
            or value["mission_revision"] != commit["mission_revision"]
            or value["source_snapshot_hashes"] != snapshot_hashes
            or value["committed_at"] != commit["committed_at"]
            or int(commit["predecessor_plan_version"]) != int(previous["plan_version"])
            or int(commit["replacement_plan_version"]) != int(previous["plan_version"]) + 1
            or replacement_activation is None
            or replacement_activation["replacement_commit_id"] != commit["replacement_commit_id"]
            or replacement_activation["activated_at"] != commit["committed_at"]
            or int(replacement_activation["plan_version"])
            != int(commit["replacement_plan_version"])
            or len(authorities) != value["authority_count"]
            or len(settlements) != len(prior.work_items)
            or len(settlements) != value["source_settlement_count"]
            or len(carry_forwards) != value["completed_carry_forward_count"]
            or len(initializations) != len(replacement.work_items)
            or len(initializations) != value["work_initialization_count"]
        ):
            raise StoreIntegrityError("Replacement commit does not reconcile")
        for authority in authorities:
            try:
                raw_evidence = json.loads(str(authority["evidence_json"]))
            except json.JSONDecodeError as exc:
                raise StoreIntegrityError("Replacement authority evidence is invalid") from exc
            if (
                canonical_json(raw_evidence) != authority["evidence_json"]
                or sha256_text(str(authority["evidence_json"])) != authority["evidence_sha256"]
                or authority["consumed_at"] != commit["committed_at"]
            ):
                raise StoreIntegrityError("Replacement authority evidence does not reconcile")
        schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if schema_version >= AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION:
            _verify_authenticated_replacement_custody(
                connection,
                commit=commit,
                preflight=preflight,
                authorities=authorities,
                registry=registry,
            )
        settlements_by_source = {str(row["source_work_item_id"]): row for row in settlements}
        expected_settlements: dict[str, dict[str, Any]] = {}
        for item in preflight_document["item_mappings"]:
            expected_settlements[str(item["source_work_item_id"])] = {
                "completed_result_sha256": item["completed_result_sha256"],
                "disposition": item["disposition"],
                "replacement_work_item_id": item["replacement_work_item_id"],
                "source_state": item["source_state"],
            }
        for item in preflight_document["cancellation_actions"]:
            expected_settlements[str(item["source_work_item_id"])] = {
                "completed_result_sha256": None,
                "disposition": item["disposition"],
                "replacement_work_item_id": None,
                "source_state": "not_completed",
            }
        for row in settlements:
            material = {
                "disposition": row["disposition"],
                "replacement_work_item_id": row["replacement_work_item_id"],
                "source_state": row["source_state"],
                "source_transition_id": row["source_transition_id"],
                "source_work_item_id": row["source_work_item_id"],
                "completed_result_sha256": row["completed_result_sha256"],
            }
            expected_settlement = expected_settlements.get(str(row["source_work_item_id"]))
            if (
                _canonical_sha256(material) != row["settlement_sha256"]
                or expected_settlement is None
                or any(row[key] != value for key, value in expected_settlement.items())
            ):
                raise StoreIntegrityError("Replacement source settlement hash is invalid")
        carry_by_target = {str(row["replacement_work_item_id"]): row for row in carry_forwards}
        for row in carry_forwards:
            material = {
                "completed_result_sha256": row["completed_result_sha256"],
                "replacement_work_item_id": row["replacement_work_item_id"],
                "source_transition_id": row["source_transition_id"],
                "source_work_item_id": row["source_work_item_id"],
            }
            settlement = settlements_by_source.get(str(row["source_work_item_id"]))
            if (
                _canonical_sha256(material) != row["carry_forward_sha256"]
                or settlement is None
                or settlement["disposition"] != "preserve_completed_result"
                or settlement["replacement_work_item_id"] != row["replacement_work_item_id"]
                or settlement["completed_result_sha256"] != row["completed_result_sha256"]
                or settlement["source_transition_id"] != row["source_transition_id"]
            ):
                raise StoreIntegrityError("Replacement completed carry-forward is invalid")
        for row in initializations:
            material = {
                "completed_result_sha256": row["completed_result_sha256"],
                "initial_state": row["initial_state"],
                "replacement_work_item_id": row["replacement_work_item_id"],
                "source_work_item_id": row["source_work_item_id"],
            }
            carried = carry_by_target.get(str(row["replacement_work_item_id"]))
            if (
                _canonical_sha256(material) != row["initialization_sha256"]
                or (row["initial_state"] == "completed_carried_forward") != (carried is not None)
                or (
                    carried is not None
                    and (
                        carried["source_work_item_id"] != row["source_work_item_id"]
                        or carried["completed_result_sha256"] != row["completed_result_sha256"]
                    )
                )
            ):
                raise StoreIntegrityError("Replacement work initialization is invalid")
        settlement_sources = {str(row["source_work_item_id"]) for row in settlements}
        initialization_targets = {str(row["replacement_work_item_id"]) for row in initializations}
        preflight_targets = {
            str(item["replacement_work_item_id"]) for item in preflight_document["item_mappings"]
        } | {
            str(item["replacement_work_item_id"]) for item in preflight_document["new_item_actions"]
        }
        carried_targets = {str(row["replacement_work_item_id"]) for row in carry_forwards}
        completed_initializations = {
            str(row["replacement_work_item_id"])
            for row in initializations
            if row["initial_state"] == "completed_carried_forward"
        }
        if (
            settlement_sources != {item.work_item_id for item in prior.work_items}
            or set(expected_settlements) != settlement_sources
            or initialization_targets != {item.work_item_id for item in replacement.work_items}
            or preflight_targets != initialization_targets
            or carried_targets != completed_initializations
        ):
            raise StoreIntegrityError("Replacement work conservation is invalid")
        previous = replacement_activation
    return len(commits)


__all__ = [
    "CollaborationPlanReplacementCommitReceipt",
    "CollaborationPlanReplacementSourceSnapshots",
    "CollaborationPlanReplacementStoreService",
    "ReplacementAuthorityEvidence",
    "ReplacementAuthorityVerifier",
    "VerifiedReplacementAuthority",
    "build_collaboration_plan_replacement_source_snapshots",
]

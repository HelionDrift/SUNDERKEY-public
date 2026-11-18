"""Pure plan-only simulation for an approved control-plane path."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .approvals import ApprovalRecord, ApprovalService, ApprovalState
from .errors import (
    ApprovalConflictError,
    ApprovalExpiredError,
    SimulationError,
    StoreError,
)
from .events import (
    ACTION_HASH_PATTERN,
    APPROVAL_ID_PATTERN,
    EVENT_ID_PATTERN,
    MISSION_ID_PATTERN,
    PROFILE_ID_PATTERN,
    compute_proposal_action_hash,
)
from .registry import ExpertRegistry
from .store import (
    SIMULATION_AUTHENTICATION_SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    sha256_text,
    utc_now,
)
from .types import ActionTier, EventType, EvidenceLevel
from .validation import is_ascii_text

SIMULATION_ENGINE = "policy-manifest-v1"
SIMULATION_OUTCOME = "control_path_validated"
SIMULATION_ID_PATTERN = re.compile(r"SIM-[A-Z0-9][A-Z0-9._-]{2,59}")
SIMULATION_CONTROLS = (
    "mission-bound",
    "scope-reference-matched",
    "independent-control-approved",
    "executor-bound",
    "proposal-hash-matched",
    "authorization-expiry-checked",
    "no-external-actions",
)


@dataclass(frozen=True)
class AuthorizedSimulationContext:
    simulation_id: str
    mission_id: str
    approval_id: str
    proposal_id: str
    authorization_id: str
    action_hash: str
    executor_profile_id: str
    action_tier: str
    recorded_at: str


@dataclass(frozen=True)
class SimulationReceipt:
    schema_version: int
    simulation_id: str
    mission_id: str
    approval_id: str
    proposal_id: str
    authorization_id: str
    action_hash: str
    executor_profile_id: str
    action_tier: str
    simulation_engine: str
    outcome: str
    evidence_level: EvidenceLevel
    controls_validated: tuple[str, ...]
    recorded_at: str
    external_actions_performed: bool
    approval_consumed: bool
    receipt_hash: str

    def content_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "simulation_id": self.simulation_id,
            "mission_id": self.mission_id,
            "approval_id": self.approval_id,
            "proposal_id": self.proposal_id,
            "authorization_id": self.authorization_id,
            "action_hash": self.action_hash,
            "executor_profile_id": self.executor_profile_id,
            "action_tier": self.action_tier,
            "simulation_engine": self.simulation_engine,
            "outcome": self.outcome,
            "evidence_level": self.evidence_level.value,
            "controls_validated": list(self.controls_validated),
            "recorded_at": self.recorded_at,
            "external_actions_performed": self.external_actions_performed,
            "approval_consumed": self.approval_consumed,
        }

    def to_dict(self) -> dict[str, Any]:
        value = self.content_dict()
        value["receipt_hash"] = self.receipt_hash
        return value

    @classmethod
    def from_dict(cls, raw: Any) -> SimulationReceipt:
        if not isinstance(raw, dict):
            raise SimulationError("Simulation receipt must be an object")
        allowed = {
            "schema_version",
            "simulation_id",
            "mission_id",
            "approval_id",
            "proposal_id",
            "authorization_id",
            "action_hash",
            "executor_profile_id",
            "action_tier",
            "simulation_engine",
            "outcome",
            "evidence_level",
            "controls_validated",
            "recorded_at",
            "external_actions_performed",
            "approval_consumed",
            "receipt_hash",
        }
        if set(raw) != allowed:
            raise SimulationError("Simulation receipt fields do not match schema 1")
        text_fields = allowed - {
            "schema_version",
            "controls_validated",
            "external_actions_performed",
            "approval_consumed",
        }
        if not all(is_ascii_text(raw.get(field)) for field in text_fields):
            raise SimulationError("Simulation receipt text must be non-empty ASCII")
        controls = raw.get("controls_validated")
        if (
            not isinstance(controls, list)
            or not controls
            or not all(is_ascii_text(value) for value in controls)
        ):
            raise SimulationError(
                "controls_validated must be a non-empty ASCII text list"
            )
        if raw.get("schema_version") != 1:
            raise SimulationError("Simulation receipt schema_version must be 1")
        if SIMULATION_ID_PATTERN.fullmatch(raw["simulation_id"]) is None:
            raise SimulationError("Invalid simulation_id")
        if MISSION_ID_PATTERN.fullmatch(raw["mission_id"]) is None:
            raise SimulationError("Invalid mission_id")
        if APPROVAL_ID_PATTERN.fullmatch(raw["approval_id"]) is None:
            raise SimulationError("Invalid approval_id")
        if EVENT_ID_PATTERN.fullmatch(raw["proposal_id"]) is None:
            raise SimulationError("Invalid proposal_id")
        if EVENT_ID_PATTERN.fullmatch(raw["authorization_id"]) is None:
            raise SimulationError("Invalid authorization_id")
        if ACTION_HASH_PATTERN.fullmatch(raw["action_hash"]) is None:
            raise SimulationError("Invalid action_hash")
        if PROFILE_ID_PATTERN.fullmatch(raw["executor_profile_id"]) is None:
            raise SimulationError("Invalid executor_profile_id")
        try:
            ActionTier(raw["action_tier"])
        except (TypeError, ValueError) as exc:
            raise SimulationError("Invalid action_tier") from exc
        parse_timestamp(str(raw["recorded_at"]), "recorded_at")
        if raw.get("external_actions_performed") is not False:
            raise SimulationError(
                "Simulation receipt must declare no external actions"
            )
        if raw.get("approval_consumed") is not True:
            raise SimulationError(
                "Simulation receipt must consume its simulation approval"
            )
        try:
            evidence_level = EvidenceLevel(raw.get("evidence_level"))
        except (TypeError, ValueError) as exc:
            raise SimulationError("Invalid simulation evidence level") from exc
        if evidence_level is not EvidenceLevel.E0:
            raise SimulationError("Simulation receipts must remain at E0")
        value = cls(
            schema_version=1,
            simulation_id=str(raw["simulation_id"]),
            mission_id=str(raw["mission_id"]),
            approval_id=str(raw["approval_id"]),
            proposal_id=str(raw["proposal_id"]),
            authorization_id=str(raw["authorization_id"]),
            action_hash=str(raw["action_hash"]),
            executor_profile_id=str(raw["executor_profile_id"]),
            action_tier=str(raw["action_tier"]),
            simulation_engine=str(raw["simulation_engine"]),
            outcome=str(raw["outcome"]),
            evidence_level=evidence_level,
            controls_validated=tuple(controls),
            recorded_at=str(raw["recorded_at"]),
            external_actions_performed=False,
            approval_consumed=True,
            receipt_hash=str(raw["receipt_hash"]),
        )
        if value.simulation_engine != SIMULATION_ENGINE:
            raise SimulationError("Unsupported simulation engine")
        if value.outcome != SIMULATION_OUTCOME:
            raise SimulationError("Unsupported simulation outcome")
        if value.controls_validated != SIMULATION_CONTROLS:
            raise SimulationError("Simulation control manifest is invalid")
        expected_hash = sha256_text(canonical_json(value.content_dict()))
        if value.receipt_hash != expected_hash:
            raise SimulationError("Simulation receipt hash is invalid")
        return value


class PolicySimulationAdapter:
    """Renders a fixed manifest and performs no external action."""

    def render(self, context: AuthorizedSimulationContext) -> SimulationReceipt:
        content = _receipt_content(context)
        receipt_hash = sha256_text(canonical_json(content))
        return SimulationReceipt.from_dict(
            {
                **content,
                "receipt_hash": receipt_hash,
            }
        )


def _receipt_content(context: AuthorizedSimulationContext) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "simulation_id": context.simulation_id,
        "mission_id": context.mission_id,
        "approval_id": context.approval_id,
        "proposal_id": context.proposal_id,
        "authorization_id": context.authorization_id,
        "action_hash": context.action_hash,
        "executor_profile_id": context.executor_profile_id,
        "action_tier": context.action_tier,
        "simulation_engine": SIMULATION_ENGINE,
        "outcome": SIMULATION_OUTCOME,
        "evidence_level": EvidenceLevel.E0.value,
        "controls_validated": list(SIMULATION_CONTROLS),
        "recorded_at": context.recorded_at,
        "external_actions_performed": False,
        "approval_consumed": True,
    }


def _normalize_fixed_receipt(
    value: Any,
    context: AuthorizedSimulationContext,
) -> SimulationReceipt:
    try:
        raw = json.loads(canonical_json(value.to_dict()))
        receipt = SimulationReceipt.from_dict(raw)
    except (AttributeError, TypeError, ValueError) as exc:
        raise SimulationError("Fixed simulation adapter returned an invalid receipt") from exc
    if receipt.content_dict() != _receipt_content(context):
        raise SimulationError(
            "Fixed simulation receipt does not match the authorized context"
        )
    return receipt


def _idempotency_hash(value: str) -> str:
    if not is_ascii_text(value) or len(value) > 256:
        raise SimulationError(
            "idempotency_key must be non-empty ASCII text up to 256 characters"
        )
    return sha256_text(value)


def _simulation_id(approval_id: str, key_hash: str) -> str:
    digest = hashlib.sha256(
        f"{approval_id}\n{key_hash}".encode("ascii")
    ).hexdigest()[:24].upper()
    return f"SIM-{digest}"


@dataclass(frozen=True)
class _SimulationCommand:
    approval_id: str
    idempotency_key_hash: str
    principal_profile_id: str
    simulation_id: str

    def operation_intent(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "idempotency_key_sha256": self.idempotency_key_hash,
            "principal_profile_id": self.principal_profile_id,
        }


@dataclass(frozen=True)
class _AppliedSimulation:
    receipt: SimulationReceipt
    approval: ApprovalRecord
    request_hash: str
    idempotency_key_hash: str
    pre_approval_version: int
    pre_approval_state: ApprovalState
    final_approval_version: int
    final_approval_state: ApprovalState
    mission_revision: int
    mission_head_hash: str


def _simulation_command(
    approval_id: str,
    *,
    idempotency_key: str,
    principal_profile_id: str,
) -> _SimulationCommand:
    if (
        not is_ascii_text(approval_id)
        or len(approval_id) > 64
        or APPROVAL_ID_PATTERN.fullmatch(approval_id) is None
    ):
        raise SimulationError(
            "approval_id must use the stable approval ID form"
        )
    if (
        not is_ascii_text(principal_profile_id)
        or len(principal_profile_id) > 64
        or PROFILE_ID_PATTERN.fullmatch(principal_profile_id) is None
    ):
        raise SimulationError(
            "principal_profile_id must be a valid profile ID"
        )
    key_hash = _idempotency_hash(idempotency_key)
    return _SimulationCommand(
        approval_id=approval_id,
        idempotency_key_hash=key_hash,
        principal_profile_id=principal_profile_id,
        simulation_id=_simulation_id(approval_id, key_hash),
    )


class SimulationService:
    """Consumes a simulation approval and stores one plan-only receipt."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        adapter: PolicySimulationAdapter | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        if adapter is not None:
            raise SimulationError(
                "Custom simulation adapters are not supported in Phase 2"
            )
        self.store = store
        self.registry = registry
        self._clock = clock
        self._approvals = ApprovalService(store, registry, clock=clock)

    def simulate(
        self,
        approval_id: str,
        *,
        idempotency_key: str,
        principal_profile_id: str,
    ) -> SimulationReceipt:
        command = _simulation_command(
            approval_id,
            idempotency_key=idempotency_key,
            principal_profile_id=principal_profile_id,
        )

        try:
            with self.store._write_connection() as connection:
                now = self._clock()
                self._require_authenticated_simulation_path(
                    connection,
                    authenticated_principal=False,
                )
                row = self._approvals._approval_row(connection, approval_id)
                record = self._approvals._record_from_row(row, now)
                if record.executor_profile_id != principal_profile_id:
                    raise SimulationError(
                        "Simulation principal does not match the bound executor"
                    )
                stored_mission, ledger = self._approvals._mission_and_ledger(
                    connection,
                    record.mission_id,
                )
                self._approvals._validate_submission_binding(
                    row,
                    record,
                    stored_mission,
                    ledger,
                )
                self.store._verify_auxiliary_state(
                    connection,
                    stored_mission,
                    ledger,
                )
                if row["simulation_key_hash"] is not None:
                    if (
                        row["simulation_key_hash"]
                        != command.idempotency_key_hash
                    ):
                        raise ApprovalConflictError(
                            "Simulation approval has already been consumed"
                        )
                    if (
                        row["simulation_id"] is None
                        or str(row["simulation_id"])
                        != command.simulation_id
                    ):
                        raise SimulationError(
                            "Stored simulation ID does not match its idempotency key"
                        )
                    return self._load_receipt(
                        connection,
                        record.mission_id,
                        command.simulation_id,
                        now=now,
                    )
                return self._simulate_in_connection(
                    connection,
                    command,
                    now,
                    authenticated_principal=False,
                ).receipt
        except sqlite3.IntegrityError as exc:
            raise ApprovalConflictError(
                "Could not record simulation receipt"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not persist simulation receipt") from exc

    def _simulate_in_connection(
        self,
        connection: sqlite3.Connection,
        command: _SimulationCommand,
        now: datetime,
        *,
        authenticated_principal: bool,
    ) -> _AppliedSimulation:
        self._require_authenticated_simulation_path(
            connection,
            authenticated_principal=authenticated_principal,
        )
        row = self._approvals._approval_row(
            connection,
            command.approval_id,
        )
        record = self._approvals._record_from_row(row, now)
        if (
            record.executor_profile_id
            != command.principal_profile_id
        ):
            raise SimulationError(
                "Simulation principal does not match the bound executor"
            )
        stored_mission, ledger = self._approvals._mission_and_ledger(
            connection,
            record.mission_id,
        )
        self._approvals._validate_submission_binding(
            row,
            record,
            stored_mission,
            ledger,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        if row["simulation_key_hash"] is not None:
            raise ApprovalConflictError(
                "Simulation approval has already been consumed"
            )
        recorded_at = format_timestamp(now)
        self.store._require_mission_active(
            connection,
            record.mission_id,
        )
        if record.state is ApprovalState.EXPIRED:
            raise ApprovalExpiredError(
                "Simulation authorization has expired"
            )
        if (
            record.state is not ApprovalState.APPROVED
            or record.version != 2
        ):
            raise SimulationError(
                "Approval is not ready for simulation consumption"
            )
        authorization = self._validate_authorization_binding(
            record,
            command.approval_id,
            command.principal_profile_id,
            stored_mission,
            ledger,
            now,
            require_unexpired=True,
        )
        context = AuthorizedSimulationContext(
            simulation_id=command.simulation_id,
            mission_id=record.mission_id,
            approval_id=command.approval_id,
            proposal_id=record.proposal_id,
            authorization_id=authorization.event_id,
            action_hash=record.proposal_hash,
            executor_profile_id=record.executor_profile_id,
            action_tier=record.action_tier.value,
            recorded_at=recorded_at,
        )
        rendered = PolicySimulationAdapter.render(
            PolicySimulationAdapter(),
            context,
        )
        receipt = _normalize_fixed_receipt(rendered, context)
        receipt_json = canonical_json(receipt.to_dict())
        connection.execute(
            """
            INSERT INTO simulation_receipts(
                mission_id,
                simulation_id,
                approval_id,
                proposal_id,
                authorization_id,
                receipt_json,
                receipt_hash,
                recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.mission_id,
                command.simulation_id,
                command.approval_id,
                record.proposal_id,
                record.authorization_event_id,
                receipt_json,
                receipt.receipt_hash,
                recorded_at,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE approval_queue
            SET status = 'consumed',
                version = version + 1,
                simulation_key_hash = ?,
                simulation_id = ?
            WHERE approval_id = ?
              AND status = 'approved'
              AND version = 2
              AND simulation_key_hash IS NULL
              AND simulation_id IS NULL
            """,
            (
                command.idempotency_key_hash,
                command.simulation_id,
                command.approval_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ApprovalConflictError(
                "Approval changed while simulation was being recorded"
            )
        final_row = self._approvals._approval_row(
            connection,
            command.approval_id,
        )
        final_record = self._approvals._record_from_row(
            final_row,
            now,
        )
        if (
            final_record.state is not ApprovalState.CONSUMED
            or final_record.version != 3
            or final_record.simulation_id
            != command.simulation_id
        ):
            raise SimulationError(
                "Simulation consumption transition is invalid"
            )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        return _AppliedSimulation(
            receipt=receipt,
            approval=final_record,
            request_hash=sha256_text(
                canonical_json(command.operation_intent())
            ),
            idempotency_key_hash=(
                command.idempotency_key_hash
            ),
            pre_approval_version=record.version,
            pre_approval_state=record.state,
            final_approval_version=final_record.version,
            final_approval_state=final_record.state,
            mission_revision=stored_mission.revision,
            mission_head_hash=stored_mission.head_hash,
        )

    @staticmethod
    def _require_authenticated_simulation_path(
        connection: sqlite3.Connection,
        *,
        authenticated_principal: bool,
    ) -> None:
        schema_version = int(
            connection.execute("PRAGMA user_version").fetchone()[0]
        )
        if schema_version < SIMULATION_AUTHENTICATION_SCHEMA_VERSION:
            return
        identity = connection.execute(
            """
            SELECT trust_policy_hash
            FROM store_identity
            WHERE singleton_id = 1
            """
        ).fetchone()
        if identity is None:
            raise SimulationError("Mission store identity is missing")
        if (
            identity["trust_policy_hash"] is not None
            and not authenticated_principal
        ):
            raise SimulationError(
                "Authenticated simulation is required after trust "
                "policy enrollment"
            )

    def _validate_authorization_binding(
        self,
        record: ApprovalRecord,
        approval_id: str,
        principal_profile_id: str,
        stored_mission: Any,
        ledger: Any,
        now: datetime,
        *,
        require_unexpired: bool,
    ) -> Any:
        if record.authorization_event_id is None:
            raise SimulationError("Approved simulation is missing authorization")
        authorization = ledger.get(record.authorization_event_id)
        if authorization.event_type is not EventType.AUTHORIZATION:
            raise SimulationError(
                "Approval authorization does not reference an authorization event"
            )
        if authorization.payload.get("approval_id") != approval_id:
            raise SimulationError("Authorization approval binding does not match")
        if authorization.payload.get("purpose") != "simulation":
            raise SimulationError("Authorization is not restricted to simulation")
        if authorization.payload["proposal_id"] != record.proposal_id:
            raise SimulationError("Authorization proposal binding does not match")
        if authorization.payload["executor_profile_id"] != principal_profile_id:
            raise SimulationError("Authorization executor binding does not match")
        if authorization.payload["action_tier"] != record.action_tier.value:
            raise SimulationError("Authorization action tier does not match")
        if (
            authorization.payload["scope_token"] != record.scope_reference
            or stored_mission.mission.scope_reference != record.scope_reference
        ):
            raise SimulationError("Mission scope binding does not match")
        if (
            record.decision_actor_profile_id is None
            or authorization.actor_profile_id != record.decision_actor_profile_id
        ):
            raise SimulationError("Authorization decision actor does not match")
        if (
            record.authorization_expires_at
            != authorization.payload["expires_at"]
        ):
            raise SimulationError("Authorization expiry binding does not match")
        if require_unexpired and parse_timestamp(
            str(authorization.payload["expires_at"]),
            "authorization.expires_at",
        ) <= now:
            raise ApprovalExpiredError("Simulation authorization has expired")
        proposal = ledger.get(record.proposal_id)
        proposal_hash = compute_proposal_action_hash(proposal.payload)
        if (
            proposal_hash != record.proposal_hash
            or authorization.payload["action_hash"] != proposal_hash
        ):
            raise SimulationError("Proposal action hash does not match")
        return authorization

    def get(self, mission_id: str, simulation_id: str) -> SimulationReceipt:
        try:
            with self.store._read_connection() as connection:
                return self._load_receipt(
                    connection,
                    mission_id,
                    simulation_id,
                    now=self._clock(),
                )
        except sqlite3.Error as exc:
            raise StoreError("Could not read simulation receipt") from exc

    def _load_receipt(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
        simulation_id: str,
        *,
        now: datetime,
    ) -> SimulationReceipt:
        row = connection.execute(
            """
            SELECT * FROM simulation_receipts
            WHERE mission_id = ? AND simulation_id = ?
            """,
            (mission_id, simulation_id),
        ).fetchone()
        if row is None:
            raise SimulationError(f"Unknown simulation receipt: {simulation_id}")
        receipt_json = str(row["receipt_json"])
        try:
            raw = json.loads(receipt_json)
        except json.JSONDecodeError as exc:
            raise SimulationError("Stored simulation receipt is not valid JSON") from exc
        if canonical_json(raw) != receipt_json:
            raise SimulationError("Stored simulation receipt is not canonical")
        receipt = SimulationReceipt.from_dict(raw)
        if (
            receipt.mission_id != mission_id
            or receipt.simulation_id != simulation_id
            or receipt.approval_id != row["approval_id"]
            or receipt.proposal_id != row["proposal_id"]
            or receipt.authorization_id != row["authorization_id"]
            or receipt.receipt_hash != row["receipt_hash"]
            or receipt.recorded_at != row["recorded_at"]
        ):
            raise SimulationError(
                "Stored simulation receipt indexes do not match its content"
            )
        approval_row = self._approvals._approval_row(
            connection,
            receipt.approval_id,
        )
        record = self._approvals._record_from_row(approval_row, now)
        if (
            record.state is not ApprovalState.CONSUMED
            or record.mission_id != mission_id
            or record.simulation_id != simulation_id
        ):
            raise SimulationError(
                "Stored simulation receipt is not bound to a consumed approval"
            )
        stored_mission, ledger = self._approvals._mission_and_ledger(
            connection,
            record.mission_id,
        )
        self._approvals._validate_submission_binding(
            approval_row,
            record,
            stored_mission,
            ledger,
        )
        self.store._verify_auxiliary_state(
            connection,
            stored_mission,
            ledger,
        )
        authorization = self._validate_authorization_binding(
            record,
            receipt.approval_id,
            record.executor_profile_id,
            stored_mission,
            ledger,
            now,
            require_unexpired=False,
        )
        context = AuthorizedSimulationContext(
            simulation_id=simulation_id,
            mission_id=record.mission_id,
            approval_id=record.approval_id,
            proposal_id=record.proposal_id,
            authorization_id=authorization.event_id,
            action_hash=record.proposal_hash,
            executor_profile_id=record.executor_profile_id,
            action_tier=record.action_tier.value,
            recorded_at=receipt.recorded_at,
        )
        normalized = _normalize_fixed_receipt(receipt, context)
        recorded = parse_timestamp(normalized.recorded_at, "receipt.recorded_at")
        issued = parse_timestamp(authorization.timestamp, "authorization.timestamp")
        expires = parse_timestamp(
            str(authorization.payload["expires_at"]),
            "authorization.expires_at",
        )
        if recorded < issued or recorded >= expires:
            raise SimulationError(
                "Stored simulation receipt is outside its authorization window"
            )
        return normalized

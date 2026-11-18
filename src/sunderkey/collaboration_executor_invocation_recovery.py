"""Fail-closed recovery assessment for durable invocation attempts."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .collaboration_executor_invocation_attempt import (
    CollaborationExecutorInvocationPreparation,
    CollaborationExecutorInvocationResolution,
)
from .collaboration_executor_invocation_attempt_store import (
    CollaborationExecutorInvocationAttemptService,
)
from .errors import CollaborationPlanError, StoreError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .registry import ExpertRegistry
from .store import MissionStore, format_timestamp, parse_timestamp

SCHEMA_VERSION = 1
RECOVERY_DOMAIN = "sunderkey.collaboration-executor-invocation-recovery.v1"


@dataclass(frozen=True)
class CollaborationExecutorInvocationRecoveryAssessment:
    """Read-only recovery state that never grants retry authority."""

    assessment_id: str
    assessment_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CollaborationExecutorInvocationRecoveryAssessment:
        value = _mapping(raw, "collaboration executor invocation recovery assessment")
        fields = {
            "schema_version",
            "assessment_id",
            "assessment_sha256",
            "invocation_preparation",
            "terminal_resolution",
            "observed_at",
            "knowledge_state",
            "recovery_disposition",
            "retry_authority",
            "external_effect_status",
            "runtime_effect",
        }
        _exact_fields(value, fields, "collaboration executor invocation recovery assessment")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError("Invocation recovery schema is invalid")
        assessment_id = value.get("assessment_id")
        assessment_sha256 = value.get("assessment_sha256")
        if (
            not isinstance(assessment_id, str)
            or re.fullmatch(r"EIA-[0-9A-F]{32}", assessment_id) is None
            or not isinstance(assessment_sha256, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", assessment_sha256) is None
        ):
            raise CollaborationPlanError("Invocation recovery identity is invalid")
        preparation = _mapping(
            value.get("invocation_preparation"),
            "invocation_preparation",
        )
        _exact_fields(
            preparation,
            {
                "attempt_id",
                "attempt_sha256",
                "prepared_at",
                "idempotency_status",
            },
            "invocation_preparation",
        )
        if (
            not isinstance(preparation["attempt_id"], str)
            or re.fullmatch(r"EIP-[0-9A-F]{32}", preparation["attempt_id"])
            is None
            or not isinstance(preparation["attempt_sha256"], str)
            or re.fullmatch(
                r"sha256:[0-9a-f]{64}",
                preparation["attempt_sha256"],
            )
            is None
            or preparation["idempotency_status"]
            not in {"absent", "declared_unverified", "verified"}
        ):
            raise CollaborationPlanError("Invocation recovery preparation is invalid")
        prepared_at = parse_timestamp(
            preparation["prepared_at"],
            "invocation_preparation.prepared_at",
        )
        observed_at = parse_timestamp(value.get("observed_at"), "observed_at")
        if observed_at < prepared_at:
            raise CollaborationPlanError("Invocation recovery precedes preparation")
        terminal = value.get("terminal_resolution")
        if terminal is None:
            expected = (
                "unresolved_after_preparation",
                "manual_reconciliation_required",
                "not_authorized",
                "outcome_uncertain",
            )
        else:
            resolution = _mapping(terminal, "terminal_resolution")
            _exact_fields(
                resolution,
                {
                    "resolution_id",
                    "resolution_sha256",
                    "attempt_id",
                    "attempt_sha256",
                    "outcome",
                    "resolved_at",
                    "retry_disposition",
                    "external_effect_status",
                },
                "terminal_resolution",
            )
            if (
                not isinstance(resolution["resolution_id"], str)
                or re.fullmatch(r"EIR-[0-9A-F]{32}", resolution["resolution_id"])
                is None
                or not isinstance(resolution["resolution_sha256"], str)
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    resolution["resolution_sha256"],
                )
                is None
                or resolution["attempt_id"] != preparation["attempt_id"]
                or resolution["attempt_sha256"]
                != preparation["attempt_sha256"]
            ):
                raise CollaborationPlanError("Invocation recovery resolution is invalid")
            resolved_at = parse_timestamp(
                resolution["resolved_at"],
                "terminal_resolution.resolved_at",
            )
            if resolved_at < prepared_at or resolved_at > observed_at:
                raise CollaborationPlanError("Invocation recovery precedes resolution")
            outcome = resolution["outcome"]
            if outcome == "failed_before_invocation":
                expected_retry = "retry_allowed_no_external_effect"
                expected = (
                    "terminal_resolution_recorded",
                    "terminal_retry_disposition_requires_reauthorization",
                    "separate_reauthorization_required",
                    "not_started",
                )
            elif outcome == "provider_report_received":
                expected_retry = (
                    "complete_provider_report_pending_authentication"
                )
                expected = (
                    "terminal_resolution_recorded",
                    "provider_report_authentication_required",
                    "not_authorized",
                    "provider_report_pending_authentication",
                )
            elif outcome == "outcome_uncertain":
                expected_retry = (
                    "retry_allowed_verified_idempotency"
                    if preparation["idempotency_status"] == "verified"
                    else "retry_forbidden_uncertain_effect"
                )
                expected = (
                    "terminal_resolution_recorded",
                    "manual_reconciliation_required",
                    "not_authorized",
                    "outcome_uncertain",
                )
            else:
                raise CollaborationPlanError("Invocation recovery outcome is invalid")
            if (
                resolution["retry_disposition"] != expected_retry
                or resolution["external_effect_status"] != expected[3]
            ):
                raise CollaborationPlanError(
                    "Invocation recovery external effect is inconsistent"
                )
        if (
            value.get("knowledge_state") != expected[0]
            or value.get("recovery_disposition") != expected[1]
            or value.get("retry_authority") != expected[2]
            or value.get("external_effect_status") != expected[3]
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError("Invocation recovery boundary is invalid")
        body = {
            key: item
            for key, item in value.items()
            if key not in {"assessment_id", "assessment_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": RECOVERY_DOMAIN, "invocation_recovery": body}
        )
        expected_id = "EIA-" + digest.removeprefix("sha256:")[:32].upper()
        if assessment_sha256 != digest or assessment_id != expected_id:
            raise CollaborationPlanError("Invocation recovery hash is invalid")
        return cls(assessment_id, assessment_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError("Invocation recovery assessment is invalid")
        return value


class CollaborationExecutorInvocationRecoveryService:
    """Assess durable attempt state without writing or invoking anything."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._attempts = CollaborationExecutorInvocationAttemptService(
            store,
            registry,
            clock=clock,
        )
        self._store = self._attempts._store
        self._clock = self._attempts._clock
        self._activation = self._attempts._activation

    def assess(
        self,
        attempt_id: str,
    ) -> CollaborationExecutorInvocationRecoveryAssessment:
        selected = self._attempts._attempt_id(attempt_id)
        try:
            with self._store._read_connection() as connection:
                preparation_row = self._attempts._preparation_row(
                    connection,
                    selected,
                    required=True,
                )
                _, _, mission, _, _ = self._activation._verified_mission_state(
                    connection,
                    str(preparation_row["mission_id"]),
                )
                self._attempts._verify(connection, mission)
                preparation = self._attempts._preparation_receipt(
                    preparation_row
                ).preparation
                resolution_row = self._attempts._resolution_row(connection, selected)
                resolution = (
                    None
                    if resolution_row is None
                    else self._attempts._resolution_receipt(resolution_row).resolution
                )
                return build_collaboration_executor_invocation_recovery_assessment(
                    preparation,
                    resolution,
                    observed_at=format_timestamp(self._clock_value()),
                )
        except sqlite3.Error as exc:
            raise StoreError("Could not assess executor invocation recovery") from exc

    def _clock_value(self) -> datetime:
        now = self._clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise StoreError("clock must return a timezone-aware datetime")
        return now.astimezone(UTC).replace(microsecond=0)


def build_collaboration_executor_invocation_recovery_assessment(
    preparation: CollaborationExecutorInvocationPreparation,
    resolution: CollaborationExecutorInvocationResolution | None,
    *,
    observed_at: str,
) -> CollaborationExecutorInvocationRecoveryAssessment:
    """Build a content-addressed, non-authorizing recovery assessment."""

    if not isinstance(preparation, CollaborationExecutorInvocationPreparation):
        raise TypeError("preparation must be an invocation preparation")
    if resolution is not None and not isinstance(
        resolution,
        CollaborationExecutorInvocationResolution,
    ):
        raise TypeError("resolution must be an invocation resolution or None")
    attempt = preparation.to_dict()
    terminal = None
    if resolution is None:
        knowledge_state = "unresolved_after_preparation"
        recovery_disposition = "manual_reconciliation_required"
        retry_authority = "not_authorized"
        external_effect_status = "outcome_uncertain"
    else:
        resolved = resolution.to_dict()
        binding = resolved["invocation_preparation"]
        if (
            binding["attempt_id"] != preparation.attempt_id
            or binding["attempt_sha256"] != preparation.attempt_sha256
        ):
            raise CollaborationPlanError(
                "Invocation recovery resolution does not bind preparation"
            )
        terminal = {
            "resolution_id": resolution.resolution_id,
            "resolution_sha256": resolution.resolution_sha256,
            "attempt_id": binding["attempt_id"],
            "attempt_sha256": binding["attempt_sha256"],
            "outcome": resolved["outcome"],
            "resolved_at": resolved["resolved_at"],
            "retry_disposition": resolved["retry_disposition"],
            "external_effect_status": resolved["external_effect_status"],
        }
        knowledge_state = "terminal_resolution_recorded"
        if resolved["outcome"] == "failed_before_invocation":
            recovery_disposition = (
                "terminal_retry_disposition_requires_reauthorization"
            )
            retry_authority = "separate_reauthorization_required"
        elif resolved["outcome"] == "provider_report_received":
            recovery_disposition = "provider_report_authentication_required"
            retry_authority = "not_authorized"
        else:
            recovery_disposition = "manual_reconciliation_required"
            retry_authority = "not_authorized"
        external_effect_status = resolved["external_effect_status"]
    body = {
        "schema_version": SCHEMA_VERSION,
        "invocation_preparation": {
            "attempt_id": preparation.attempt_id,
            "attempt_sha256": preparation.attempt_sha256,
            "prepared_at": attempt["prepared_at"],
            "idempotency_status": attempt["idempotency"]["status"],
        },
        "terminal_resolution": terminal,
        "observed_at": observed_at,
        "knowledge_state": knowledge_state,
        "recovery_disposition": recovery_disposition,
        "retry_authority": retry_authority,
        "external_effect_status": external_effect_status,
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": RECOVERY_DOMAIN, "invocation_recovery": body}
    )
    return CollaborationExecutorInvocationRecoveryAssessment.from_dict(
        {
            **body,
            "assessment_id": "EIA-"
            + digest.removeprefix("sha256:")[:32].upper(),
            "assessment_sha256": digest,
        }
    )


__all__ = [
    "CollaborationExecutorInvocationRecoveryAssessment",
    "CollaborationExecutorInvocationRecoveryService",
    "build_collaboration_executor_invocation_recovery_assessment",
]

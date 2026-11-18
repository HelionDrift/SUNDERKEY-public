"""Read-only status projection for durable execution session authority."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .collaboration_execution_session_authority import (
    CollaborationExecutionSessionAuthority,
)
from .errors import CollaborationPlanError, StoreError, StoreIntegrityError
from .events import MISSION_ID_PATTERN
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .registry import ExpertRegistry
from .store import MissionStore, format_timestamp, parse_timestamp

SCHEMA_VERSION = 1
STATUS_DOMAIN = "sunderkey.execution-session-authority-status.v1"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
AUTHORITY_ID_PATTERN = re.compile(r"ESA-[0-9A-F]{32}")
STATUS_STATES = {
    "pending_effective_time",
    "pending_activation",
    "available_for_executor",
    "expired_unactivated",
    "expired",
    "revoked",
}


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    if not callable(clock):
        raise StoreError("clock must be callable")
    now = clock()
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise StoreError("clock must return a timezone-aware datetime")
    return now.astimezone(UTC).replace(microsecond=0)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise CollaborationPlanError(f"{label} is invalid")
    return value


def _binding(
    raw: Any,
    label: str,
    *,
    fields: set[str],
) -> dict[str, Any]:
    value = _mapping(raw, label)
    _exact_fields(value, fields, label)
    return dict(value)


@dataclass(frozen=True)
class CollaborationExecutionSessionAuthorityStatus:
    """Content-addressed control-plane status for one session authority."""

    status_id: str
    status_sha256: str
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
    ) -> CollaborationExecutionSessionAuthorityStatus:
        value = _mapping(raw, "execution session authority status")
        fields = {
            "schema_version",
            "status_id",
            "status_sha256",
            "session_authority",
            "mission_id",
            "work_item_id",
            "session",
            "credential",
            "fence_generation",
            "authority_effective_at",
            "authority_expires_at",
            "activation",
            "revocation",
            "observed_at",
            "control_plane_state",
            "external_worker_state",
            "runtime_effect",
        }
        _exact_fields(value, fields, "execution session authority status")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise CollaborationPlanError(
                "Execution session authority status schema is invalid"
            )
        status_id = value.get("status_id")
        status_sha256 = value.get("status_sha256")
        if (
            not isinstance(status_id, str)
            or re.fullmatch(r"ESS-[0-9A-F]{32}", status_id) is None
        ):
            raise CollaborationPlanError(
                "Execution session authority status identity is invalid"
            )
        _sha256(status_sha256, "status_sha256")
        authority = _binding(
            value.get("session_authority"),
            "session_authority",
            fields={"session_authority_id", "session_authority_sha256"},
        )
        if (
            not isinstance(authority["session_authority_id"], str)
            or AUTHORITY_ID_PATTERN.fullmatch(authority["session_authority_id"])
            is None
        ):
            raise CollaborationPlanError(
                "Execution session authority status binding is invalid"
            )
        _sha256(
            authority["session_authority_sha256"],
            "session_authority.session_authority_sha256",
        )
        session = _binding(
            value.get("session"),
            "session",
            fields={"session_id", "session_sha256"},
        )
        credential = _binding(
            value.get("credential"),
            "credential",
            fields={"credential_reference_id", "credential_sha256"},
        )
        _sha256(session["session_sha256"], "session.session_sha256")
        _sha256(
            credential["credential_sha256"],
            "credential.credential_sha256",
        )
        if (
            not isinstance(value.get("mission_id"), str)
            or not isinstance(value.get("work_item_id"), str)
            or not isinstance(session["session_id"], str)
            or not isinstance(credential["credential_reference_id"], str)
            or not isinstance(value.get("fence_generation"), int)
            or isinstance(value.get("fence_generation"), bool)
            or value["fence_generation"] < 1
        ):
            raise CollaborationPlanError(
                "Execution session authority status subject is invalid"
            )
        effective = parse_timestamp(
            value.get("authority_effective_at"),
            "authority_effective_at",
        )
        expires = parse_timestamp(
            value.get("authority_expires_at"),
            "authority_expires_at",
        )
        observed = parse_timestamp(value.get("observed_at"), "observed_at")
        if effective >= expires:
            raise CollaborationPlanError(
                "Execution session authority status window is invalid"
            )
        activation = value.get("activation")
        if activation is not None:
            activation = _binding(
                activation,
                "activation",
                fields={
                    "authentication_id",
                    "authentication_sha256",
                    "committed_at",
                },
            )
            if (
                not isinstance(activation["authentication_id"], str)
                or re.fullmatch(
                    r"EAS-[0-9A-F]{32}", activation["authentication_id"]
                )
                is None
            ):
                raise CollaborationPlanError(
                    "Execution session activation status binding is invalid"
                )
            _sha256(
                activation["authentication_sha256"],
                "activation.authentication_sha256",
            )
            if parse_timestamp(
                activation["committed_at"],
                "activation.committed_at",
            ) > observed:
                raise CollaborationPlanError(
                    "Execution session status precedes activation"
                )
        revocation = value.get("revocation")
        if revocation is not None:
            revocation = _binding(
                revocation,
                "revocation",
                fields={
                    "authentication_id",
                    "authentication_sha256",
                    "reason_code",
                    "committed_at",
                },
            )
            if (
                not isinstance(revocation["authentication_id"], str)
                or re.fullmatch(
                    r"ESV-[0-9A-F]{32}", revocation["authentication_id"]
                )
                is None
            ):
                raise CollaborationPlanError(
                    "Execution session revocation status binding is invalid"
                )
            _sha256(
                revocation["authentication_sha256"],
                "revocation.authentication_sha256",
            )
            if (
                not isinstance(revocation["reason_code"], str)
                or parse_timestamp(
                    revocation["committed_at"],
                    "revocation.committed_at",
                )
                > observed
            ):
                raise CollaborationPlanError(
                    "Execution session status precedes revocation"
                )
        expected_state = _state(
            observed=observed,
            effective=effective,
            expires=expires,
            activation=activation,
            revocation=revocation,
        )
        if (
            value.get("control_plane_state") not in STATUS_STATES
            or value.get("control_plane_state") != expected_state
            or value.get("external_worker_state") != "unobserved"
            or value.get("runtime_effect") != "none"
        ):
            raise CollaborationPlanError(
                "Execution session authority status boundary is invalid"
            )
        body = {
            key: item
            for key, item in value.items()
            if key not in {"status_id", "status_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": STATUS_DOMAIN, "authority_status": body}
        )
        expected_id = "ESS-" + digest.removeprefix("sha256:")[:32].upper()
        if status_sha256 != digest or status_id != expected_id:
            raise CollaborationPlanError(
                "Execution session authority status hash is invalid"
            )
        return cls(status_id, status_sha256, _canonical_json(value))

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self.document_json)
        if not isinstance(value, dict):
            raise CollaborationPlanError(
                "Execution session authority status is invalid"
            )
        return value


def _state(
    *,
    observed: datetime,
    effective: datetime,
    expires: datetime,
    activation: dict[str, Any] | None,
    revocation: dict[str, Any] | None,
) -> str:
    if revocation is not None:
        return "revoked"
    if observed < effective:
        return "pending_effective_time"
    if activation is None:
        return "expired_unactivated" if observed >= expires else "pending_activation"
    return "expired" if observed >= expires else "available_for_executor"


def _build_status(
    authority: CollaborationExecutionSessionAuthority,
    *,
    activation: sqlite3.Row | None,
    revocation: sqlite3.Row | None,
    observed_at: str,
) -> CollaborationExecutionSessionAuthorityStatus:
    document = authority.to_dict()
    session = document["session"]
    observed = parse_timestamp(observed_at, "observed_at")
    effective = parse_timestamp(document["effective_at"], "authority_effective_at")
    expires = parse_timestamp(document["expires_at"], "authority_expires_at")
    activation_binding = (
        None
        if activation is None
        else {
            "authentication_id": str(activation["authentication_id"]),
            "authentication_sha256": str(activation["authentication_sha256"]),
            "committed_at": str(activation["committed_at"]),
        }
    )
    revocation_binding = (
        None
        if revocation is None
        else {
            "authentication_id": str(revocation["authentication_id"]),
            "authentication_sha256": str(revocation["authentication_sha256"]),
            "reason_code": str(revocation["reason_code"]),
            "committed_at": str(revocation["committed_at"]),
        }
    )
    body = {
        "schema_version": SCHEMA_VERSION,
        "session_authority": {
            "session_authority_id": authority.session_authority_id,
            "session_authority_sha256": authority.session_authority_sha256,
        },
        "mission_id": session["mission_id"],
        "work_item_id": session["work_item_id"],
        "session": {
            "session_id": session["session_id"],
            "session_sha256": session["session_sha256"],
        },
        "credential": {
            "credential_reference_id": session["credential_reference_id"],
            "credential_sha256": session["credential_sha256"],
        },
        "fence_generation": session["fence_generation"],
        "authority_effective_at": document["effective_at"],
        "authority_expires_at": document["expires_at"],
        "activation": activation_binding,
        "revocation": revocation_binding,
        "observed_at": observed_at,
        "control_plane_state": _state(
            observed=observed,
            effective=effective,
            expires=expires,
            activation=activation_binding,
            revocation=revocation_binding,
        ),
        "external_worker_state": "unobserved",
        "runtime_effect": "none",
    }
    digest = _canonical_sha256(
        {"domain": STATUS_DOMAIN, "authority_status": body}
    )
    return CollaborationExecutionSessionAuthorityStatus.from_dict(
        {
            **body,
            "status_id": "ESS-" + digest.removeprefix("sha256:")[:32].upper(),
            "status_sha256": digest,
        }
    )


class CollaborationExecutionSessionAuthorityStatusService:
    """Project verified durable session state without changing the store."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        self._store = store
        self._registry = registry
        self._clock = clock or (lambda: datetime.now(UTC))

    def get(
        self,
        session_authority_id: str,
    ) -> CollaborationExecutionSessionAuthorityStatus:
        if (
            not isinstance(session_authority_id, str)
            or AUTHORITY_ID_PATTERN.fullmatch(session_authority_id) is None
        ):
            raise StoreError("session_authority_id is invalid")
        try:
            with self._store._read_connection() as connection:
                row = connection.execute(
                    """
                    SELECT * FROM execution_session_authority_commits
                    WHERE session_authority_id = ?
                    """,
                    (session_authority_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("Execution session authority is not committed")
                return self._project(connection, row)
        except sqlite3.Error as exc:
            raise StoreError("Could not read execution session authority status") from exc

    def list_for_mission(
        self,
        mission_id: str,
    ) -> tuple[CollaborationExecutionSessionAuthorityStatus, ...]:
        if (
            not isinstance(mission_id, str)
            or MISSION_ID_PATTERN.fullmatch(mission_id) is None
        ):
            raise StoreError("mission_id is invalid")
        try:
            with self._store._read_connection() as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM execution_session_authority_commits
                    WHERE mission_id = ?
                    ORDER BY work_item_id, fence_generation
                    """,
                    (mission_id,),
                ).fetchall()
                if not rows:
                    mission_row = connection.execute(
                        "SELECT 1 FROM missions WHERE mission_id = ?",
                        (mission_id,),
                    ).fetchone()
                    if mission_row is None:
                        raise StoreError(f"Unknown stored mission: {mission_id}")
                    return ()
                observed = format_timestamp(_clock_value(self._clock))
                _, _, mission, _, _ = self._verified_state(
                    connection,
                    str(rows[0]["mission_id"]),
                )
                self._verify_session_state(connection, mission)
                return tuple(
                    self._project_row(connection, row, observed)
                    for row in rows
                )
        except sqlite3.Error as exc:
            raise StoreError("Could not list execution session authority status") from exc

    def _project(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> CollaborationExecutionSessionAuthorityStatus:
        observed = format_timestamp(_clock_value(self._clock))
        _, _, mission, _, _ = self._verified_state(
            connection,
            str(row["mission_id"]),
        )
        self._verify_session_state(connection, mission)
        return self._project_row(connection, row, observed)

    def _verified_state(
        self,
        connection: sqlite3.Connection,
        mission_id: str,
    ) -> tuple[Any, Any, Any, Any, Any]:
        from .authenticated_collaboration_mission_policy import (
            AuthenticatedCollaborationMissionPolicyService,
        )

        service = AuthenticatedCollaborationMissionPolicyService(
            self._store,
            self._registry,
            clock=self._clock,
        )
        return service._activation._verified_mission_state(
            connection,
            mission_id,
        )

    def _verify_session_state(
        self,
        connection: sqlite3.Connection,
        mission: Any,
    ) -> None:
        self._store._verify_execution_session_authority_commits(
            connection,
            mission,
        )
        self._store._verify_execution_session_state_commits(
            connection,
            mission,
        )

    @staticmethod
    def _project_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        observed_at: str,
    ) -> CollaborationExecutionSessionAuthorityStatus:
        try:
            authority = CollaborationExecutionSessionAuthority.from_dict(
                json.loads(str(row["authority_json"]))
            )
        except (
            json.JSONDecodeError,
            CollaborationPlanError,
            TypeError,
            ValueError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored execution session authority is invalid"
            ) from exc
        activation = connection.execute(
            """
            SELECT authentication_id, authentication_sha256, committed_at
            FROM execution_session_activation_commits
            WHERE session_authority_id = ?
            """,
            (authority.session_authority_id,),
        ).fetchone()
        revocation = connection.execute(
            """
            SELECT authentication_id, authentication_sha256, reason_code, committed_at
            FROM execution_session_revocation_commits
            WHERE session_authority_id = ?
            """,
            (authority.session_authority_id,),
        ).fetchone()
        return _build_status(
            authority,
            activation=activation,
            revocation=revocation,
            observed_at=observed_at,
        )


__all__ = [
    "CollaborationExecutionSessionAuthorityStatus",
    "CollaborationExecutionSessionAuthorityStatusService",
]

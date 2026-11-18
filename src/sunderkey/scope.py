"""Signed scope grant and revocation acceptance for the mission store."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from .identity import (
    ScopeGrant,
    ScopeGrantRevocation,
    verify_scope_grant,
    verify_scope_grant_revocation,
)
from .registry import ExpertRegistry
from .store import (
    MissionStore,
    canonical_json,
    format_timestamp,
    parse_timestamp,
    scope_grant_revocation_entry_hash,
    sha256_text,
)


@dataclass(frozen=True)
class ScopeGrantAcceptance:
    """Durable result of accepting one root-authorized scope grant."""

    grant: ScopeGrant
    grant_sha256: str
    key_sha256: str
    policy_sha256: str
    accepted_at: str
    revoked_at: str | None
    revocation_reason: str | None
    idempotent: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "grant": self.grant.to_dict(),
            "grant_sha256": self.grant_sha256,
            "key_sha256": self.key_sha256,
            "policy_sha256": self.policy_sha256,
            "accepted_at": self.accepted_at,
            "revoked_at": self.revoked_at,
            "revocation_reason": self.revocation_reason,
            "idempotent": self.idempotent,
        }


class ScopeGrantAcceptanceService:
    """Verify and atomically store public-key authorized mission scope."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        self._store = store
        self._registry = registry

    @staticmethod
    def _acceptance_from_row(
        row: sqlite3.Row,
        *,
        idempotent: bool,
    ) -> ScopeGrantAcceptance:
        try:
            raw_grant = json.loads(str(row["grant_json"]))
            grant = ScopeGrant.from_dict(raw_grant)
        except (json.JSONDecodeError, PrincipalAuthenticationError) as exc:
            raise StoreIntegrityError(
                "Stored mission scope grant contract is invalid"
            ) from exc
        return ScopeGrantAcceptance(
            grant=grant,
            grant_sha256=str(row["grant_hash"]),
            key_sha256=str(row["key_hash"]),
            policy_sha256=str(row["trust_policy_hash"]),
            accepted_at=str(row["accepted_at"]),
            revoked_at=(
                None
                if row["revoked_at"] is None
                else str(row["revoked_at"])
            ),
            revocation_reason=(
                None
                if row["revocation_reason"] is None
                else str(row["revocation_reason"])
            ),
            idempotent=idempotent,
        )

    def accept(self, grant: ScopeGrant) -> ScopeGrantAcceptance:
        """Accept a current-policy scope grant or replay its stored record."""

        if not isinstance(grant, ScopeGrant):
            raise PrincipalAuthenticationError(
                "grant must be a ScopeGrant"
            )
        grant = ScopeGrant.from_dict(grant.to_dict())
        grant_json = canonical_json(grant.to_dict())
        grant_hash = sha256_text(grant_json)

        with self._store._write_connection() as connection:
            identity = self._store._verify_store_identity(
                connection,
                verify_history=False,
            )
            trust_policies = self._store._verify_trust_policy_history(
                connection,
                identity,
            )
            mission_row = connection.execute(
                "SELECT * FROM missions WHERE mission_id = ?",
                (grant.mission_id,),
            ).fetchone()
            if mission_row is None:
                raise StoreError(
                    f"Unknown stored mission: {grant.mission_id}"
                )
            mission = self._store._stored_mission_from_row(
                connection,
                self._registry,
                mission_row,
            )
            ledger, _ = self._store._load_verified_ledger(
                connection,
                mission,
            )
            self._store._verify_auxiliary_state(
                connection,
                mission,
                ledger,
            )
            verified_grants, _ = self._store._verify_scope_grants(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                trust_policies=trust_policies,
                registry=self._registry,
            )
            self._store._verify_scope_revocation_state(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                trust_policies=trust_policies,
                scope_grants=verified_grants,
            )
            self._store._verify_principal_ledger(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                scope_grants=verified_grants,
                trust_policies=trust_policies,
                registry=self._registry,
            )

            existing = connection.execute(
                """
                SELECT * FROM mission_scope_grants
                WHERE issuer = ? AND grant_id = ?
                """,
                (grant.issuer, grant.grant_id),
            ).fetchone()
            if existing is not None:
                exact_replay = (
                    existing["grant_hash"] == grant_hash
                    and existing["grant_json"] == grant_json
                    and grant_hash in verified_grants
                )
                if not exact_replay:
                    raise StoreConflictError(
                        "Scope grant issuer and grant ID already have different content"
                    )
                if (
                    self._store._effective_scope_grant_revocation(
                        connection,
                        existing,
                    )
                    is not None
                ):
                    raise StoreConflictError(
                        "Revoked scope grant cannot be reaccepted"
                    )
                return self._acceptance_from_row(
                    existing,
                    idempotent=True,
                )

            hash_collision = connection.execute(
                """
                SELECT issuer, grant_id FROM mission_scope_grants
                WHERE grant_hash = ?
                """,
                (grant_hash,),
            ).fetchone()
            if hash_collision is not None:
                raise StoreConflictError(
                    "Scope grant hash is already bound to another record"
                )

            from .plan_replacement_reviewer_admission import REVIEWER_OPERATIONS
            from .store import PLAN_REPLACEMENT_REVIEWER_ADMISSION_SCHEMA_VERSION

            if connection.execute("PRAGMA user_version").fetchone()[0] >= (
                PLAN_REPLACEMENT_REVIEWER_ADMISSION_SCHEMA_VERSION
            ) and any(operation in REVIEWER_OPERATIONS.values() for operation in grant.operations):
                raise PrincipalAuthenticationError(
                    "Replacement reviewer scope requires signed mission-scoped admission"
                )

            current_policy_hash = identity["trust_policy_hash"]
            if current_policy_hash is None:
                raise StoreConflictError(
                    "A current trust policy is required before scope acceptance"
                )
            verified_policy = trust_policies.get(
                str(current_policy_hash)
            )
            if verified_policy is None:
                raise StoreIntegrityError(
                    "Current trust policy is missing from verified history"
                )
            if (
                grant.profile_id not in mission.allowed_profile_ids
                and not self._store._allows_unassigned_privileged_scope(
                    connection,
                    mission.mission.mission_id,
                    grant,
                    self._registry,
                )
            ):
                raise PrincipalAuthenticationError(
                    "Scope grant profile is not assigned to the mission"
                )
            scope_document_hash = mission.mission.scope_document_hash
            if scope_document_hash is None:
                raise PrincipalAuthenticationError(
                    "Mission has no scope document hash for authenticated scope"
                )
            self._store._require_mission_active(
                connection,
                grant.mission_id,
            )
            constraints_hash = sha256_text(
                canonical_json(
                    mission.mission.to_dict()["constraints"]
                )
            )
            acceptance_time = self._store._clock()
            accepted_at_text = format_timestamp(acceptance_time)
            verified = verify_scope_grant(
                grant,
                verified_policy,
                expected_audience=str(identity["audience"]),
                expected_store_id=str(identity["store_id"]),
                expected_mission_id=mission.mission.mission_id,
                expected_mission_context_hash=mission.context_hash,
                expected_scope_reference=mission.mission.scope_reference,
                expected_scope_document_hash=scope_document_hash,
                expected_environment=mission.mission.environment,
                expected_max_action_tier=mission.mission.max_action_tier,
                expected_constraints_hash=constraints_hash,
                expected_operation=grant.operations[0],
                clock=lambda: acceptance_time,
            )
            accepted_at = parse_timestamp(
                accepted_at_text,
                "scope grant accepted_at",
            )
            if verified.verified_at != accepted_at_text:
                raise StoreIntegrityError(
                    "Scope grant verification time is inconsistent"
                )
            policy_high_water = self._store._trust_policy_high_water_at(
                trust_policies,
                accepted_at,
            )
            if (
                policy_high_water.policy_sha256
                != verified_policy.policy_sha256
            ):
                raise PrincipalAuthenticationError(
                    "Scope grant does not use the policy high-water record"
                )

            try:
                connection.execute(
                    """
                    INSERT INTO mission_scope_grants(
                        grant_hash,
                        grant_id,
                        grant_json,
                        issuer,
                        key_id,
                        key_hash,
                        audience,
                        store_id,
                        mission_id,
                        mission_context_hash,
                        scope_document_hash,
                        environment,
                        max_action_tier,
                        constraints_hash,
                        issued_at,
                        not_before,
                        expires_at,
                        accepted_at,
                        revoked_at,
                        revocation_reason,
                        trust_policy_id,
                        trust_policy_version,
                        trust_policy_hash
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, NULL, NULL, ?, ?, ?
                    )
                    """,
                    (
                        verified.grant_sha256,
                        grant.grant_id,
                        grant_json,
                        grant.issuer,
                        grant.key_id,
                        verified.key_sha256,
                        grant.audience,
                        grant.store_id,
                        grant.mission_id,
                        grant.mission_context_hash,
                        grant.scope_document_hash,
                        grant.environment.value,
                        grant.max_action_tier.value,
                        grant.constraints_hash,
                        grant.issued_at,
                        grant.not_before,
                        grant.expires_at,
                        accepted_at_text,
                        grant.policy_id,
                        grant.policy_version,
                        verified.policy_sha256,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise StoreConflictError(
                    "Scope grant conflicts with existing durable state"
                ) from exc

            row = connection.execute(
                """
                SELECT * FROM mission_scope_grants
                WHERE grant_hash = ?
                """,
                (grant_hash,),
            ).fetchone()
            if row is None:
                raise StoreIntegrityError(
                    "Accepted scope grant was not stored"
                )
            verified_grants, _ = self._store._verify_scope_grants(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                trust_policies=trust_policies,
                registry=self._registry,
            )
            if grant_hash not in verified_grants:
                raise StoreIntegrityError(
                    "Accepted scope grant failed storage verification"
                )
            self._store._verify_scope_revocation_state(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                trust_policies=trust_policies,
                scope_grants=verified_grants,
            )
            self._store._verify_principal_ledger(
                connection,
                mission,
                store_id=str(identity["store_id"]),
                scope_grants=verified_grants,
                trust_policies=trust_policies,
                registry=self._registry,
            )
            return self._acceptance_from_row(
                row,
                idempotent=False,
            )


@dataclass(frozen=True)
class ScopeGrantRevocationAcceptance:
    """Durable result of accepting one signed scope-grant revocation."""

    revocation: ScopeGrantRevocation
    revocation_sha256: str
    target_grant_sha256: str
    key_sha256: str
    policy_sha256: str
    accepted_at: str
    idempotent: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "revocation": self.revocation.to_dict(),
            "revocation_sha256": self.revocation_sha256,
            "target_grant_sha256": self.target_grant_sha256,
            "key_sha256": self.key_sha256,
            "policy_sha256": self.policy_sha256,
            "accepted_at": self.accepted_at,
            "idempotent": self.idempotent,
        }


class ScopeGrantRevocationAcceptanceService:
    """Verify and append externally signed scope-grant revocations."""

    def __init__(
        self,
        store: MissionStore,
        registry: ExpertRegistry,
    ) -> None:
        if not isinstance(store, MissionStore):
            raise TypeError("store must be a MissionStore")
        if not isinstance(registry, ExpertRegistry):
            raise TypeError("registry must be an ExpertRegistry")
        registry.validate()
        self._store = store
        self._registry = registry

    @staticmethod
    def _acceptance_from_row(
        row: sqlite3.Row,
        *,
        idempotent: bool,
    ) -> ScopeGrantRevocationAcceptance:
        try:
            raw_revocation = json.loads(str(row["revocation_json"]))
            revocation = ScopeGrantRevocation.from_dict(raw_revocation)
        except (
            json.JSONDecodeError,
            PrincipalAuthenticationError,
        ) as exc:
            raise StoreIntegrityError(
                "Stored scope-grant revocation contract is invalid"
            ) from exc
        return ScopeGrantRevocationAcceptance(
            revocation=revocation,
            revocation_sha256=str(row["revocation_hash"]),
            target_grant_sha256=str(row["scope_grant_hash"]),
            key_sha256=str(row["key_hash"]),
            policy_sha256=str(row["trust_policy_hash"]),
            accepted_at=str(row["accepted_at"]),
            idempotent=idempotent,
        )

    def accept(
        self,
        revocation: ScopeGrantRevocation,
    ) -> ScopeGrantRevocationAcceptance:
        """Accept a current-policy revocation or replay its stored record."""

        if not isinstance(revocation, ScopeGrantRevocation):
            raise PrincipalAuthenticationError(
                "revocation must be a ScopeGrantRevocation"
            )
        revocation = ScopeGrantRevocation.from_dict(
            revocation.to_dict()
        )
        revocation_json = canonical_json(revocation.to_dict())
        revocation_hash = sha256_text(revocation_json)

        try:
            with self._store._write_connection() as connection:
                identity = self._store._verify_store_identity(
                    connection,
                    verify_history=False,
                )
                trust_policies = (
                    self._store._verify_trust_policy_history(
                        connection,
                        identity,
                    )
                )
                mission_row = connection.execute(
                    "SELECT * FROM missions WHERE mission_id = ?",
                    (revocation.mission_id,),
                ).fetchone()
                if mission_row is None:
                    raise StoreError(
                        f"Unknown stored mission: {revocation.mission_id}"
                    )
                mission = self._store._stored_mission_from_row(
                    connection,
                    self._registry,
                    mission_row,
                )
                ledger, _ = self._store._load_verified_ledger(
                    connection,
                    mission,
                )
                self._store._verify_auxiliary_state(
                    connection,
                    mission,
                    ledger,
                )
                scope_grants, _ = self._store._verify_scope_grants(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    registry=self._registry,
                )
                (
                    revocation_ledger,
                    revocations_by_hash,
                    revocations_by_grant,
                    _,
                ) = self._store._verify_scope_revocation_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                )
                self._store._verify_principal_ledger(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    scope_grants=scope_grants,
                    trust_policies=trust_policies,
                    registry=self._registry,
                )

                existing = connection.execute(
                    """
                    SELECT * FROM mission_scope_grant_revocations
                    WHERE issuer = ? AND revocation_id = ?
                    """,
                    (
                        revocation.issuer,
                        revocation.revocation_id,
                    ),
                ).fetchone()
                if existing is not None:
                    exact_replay = (
                        existing["revocation_hash"]
                        == revocation_hash
                        and existing["revocation_json"]
                        == revocation_json
                        and revocation_hash in revocations_by_hash
                    )
                    if not exact_replay:
                        raise StoreConflictError(
                            "Scope-grant revocation issuer and ID "
                            "already have different content"
                        )
                    return self._acceptance_from_row(
                        existing,
                        idempotent=True,
                    )

                hash_collision = connection.execute(
                    """
                    SELECT issuer, revocation_id
                    FROM mission_scope_grant_revocations
                    WHERE revocation_hash = ?
                    """,
                    (revocation_hash,),
                ).fetchone()
                if hash_collision is not None:
                    raise StoreConflictError(
                        "Scope-grant revocation hash is already bound "
                        "to another record"
                    )

                scope_entry = scope_grants.get(
                    revocation.scope_grant_sha256
                )
                if scope_entry is None:
                    raise PrincipalAuthenticationError(
                        "Scope-grant revocation target is not accepted"
                    )
                scope_row, scope_grant = scope_entry
                if (
                    revocation.scope_grant_sha256
                    in revocations_by_grant
                    or self._store._effective_scope_grant_revocation(
                        connection,
                        scope_row,
                    )
                    is not None
                ):
                    raise StoreConflictError(
                        "Scope grant already has a durable revocation"
                    )

                current_policy_hash = identity["trust_policy_hash"]
                if current_policy_hash is None:
                    raise StoreConflictError(
                        "A current trust policy is required before "
                        "scope-grant revocation acceptance"
                    )
                verified_policy = trust_policies.get(
                    str(current_policy_hash)
                )
                if verified_policy is None:
                    raise StoreIntegrityError(
                        "Current trust policy is missing from "
                        "verified history"
                    )

                acceptance_time = self._store._clock()
                accepted_at = format_timestamp(acceptance_time)
                accepted_time = parse_timestamp(
                    accepted_at,
                    "scope-grant revocation accepted_at",
                )
                verified = verify_scope_grant_revocation(
                    revocation,
                    verified_policy,
                    scope_grant,
                    expected_audience=str(identity["audience"]),
                    expected_store_id=str(identity["store_id"]),
                    expected_mission_id=mission.mission.mission_id,
                    expected_mission_context_hash=mission.context_hash,
                    clock=lambda: acceptance_time,
                )
                if verified.verified_at != accepted_at:
                    raise StoreIntegrityError(
                        "Scope-grant revocation verification time "
                        "is inconsistent"
                    )
                policy_high_water = (
                    self._store._trust_policy_high_water_at(
                        trust_policies,
                        accepted_time,
                    )
                )
                if (
                    policy_high_water.policy_sha256
                    != verified_policy.policy_sha256
                ):
                    raise PrincipalAuthenticationError(
                        "Scope-grant revocation does not use the "
                        "policy high-water record"
                    )

                latest_use = connection.execute(
                    """
                    SELECT MAX(consumed_at)
                    FROM principal_assertion_uses
                    WHERE mission_id = ?
                      AND scope_grant_hash = ?
                    """,
                    (
                        revocation.mission_id,
                        verified.target_grant_sha256,
                    ),
                ).fetchone()[0]
                if latest_use is not None:
                    latest_use_time = parse_timestamp(
                        str(latest_use),
                        "principal assertion consumed_at",
                    )
                    if accepted_time <= latest_use_time:
                        raise StoreConflictError(
                            "Scope-grant revocation acceptance time "
                            "must be strictly later than the latest "
                            "durable principal use; retry after the "
                            "store clock advances"
                        )

                revocation_sequence = (
                    int(revocation_ledger["signed_revocation_count"])
                    + 1
                )
                previous_hash = str(
                    revocation_ledger["head_hash"]
                )
                entry = {
                    "mission_id": revocation.mission_id,
                    "revocation_sequence": revocation_sequence,
                    "revocation_hash": verified.revocation_sha256,
                    "revocation_id": revocation.revocation_id,
                    "issuer": revocation.issuer,
                    "key_id": revocation.key_id,
                    "key_hash": verified.key_sha256,
                    "audience": revocation.audience,
                    "store_id": revocation.store_id,
                    "mission_context_hash": (
                        revocation.mission_context_hash
                    ),
                    "scope_grant_hash": (
                        verified.target_grant_sha256
                    ),
                    "scope_grant_issuer": (
                        revocation.scope_grant_issuer
                    ),
                    "scope_grant_id": revocation.scope_grant_id,
                    "scope_grant_subject": (
                        revocation.scope_grant_subject
                    ),
                    "scope_grant_profile_id": (
                        revocation.scope_grant_profile_id
                    ),
                    "reason_code": revocation.reason_code,
                    "reason": revocation.reason,
                    "issued_at": revocation.issued_at,
                    "not_before": revocation.not_before,
                    "expires_at": revocation.expires_at,
                    "accepted_at": accepted_at,
                    "trust_policy_id": revocation.policy_id,
                    "trust_policy_version": (
                        revocation.policy_version
                    ),
                    "trust_policy_hash": (
                        verified.policy_sha256
                    ),
                    "previous_hash": previous_hash,
                }
                entry_hash = scope_grant_revocation_entry_hash(
                    entry
                )
                connection.execute(
                    """
                    INSERT INTO mission_scope_grant_revocations(
                        mission_id,
                        revocation_sequence,
                        revocation_hash,
                        revocation_id,
                        revocation_json,
                        issuer,
                        key_id,
                        key_hash,
                        audience,
                        store_id,
                        mission_context_hash,
                        scope_grant_hash,
                        scope_grant_issuer,
                        scope_grant_id,
                        scope_grant_subject,
                        scope_grant_profile_id,
                        reason_code,
                        reason,
                        issued_at,
                        not_before,
                        expires_at,
                        accepted_at,
                        trust_policy_id,
                        trust_policy_version,
                        trust_policy_hash,
                        previous_hash,
                        entry_hash
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        entry["mission_id"],
                        entry["revocation_sequence"],
                        entry["revocation_hash"],
                        entry["revocation_id"],
                        revocation_json,
                        entry["issuer"],
                        entry["key_id"],
                        entry["key_hash"],
                        entry["audience"],
                        entry["store_id"],
                        entry["mission_context_hash"],
                        entry["scope_grant_hash"],
                        entry["scope_grant_issuer"],
                        entry["scope_grant_id"],
                        entry["scope_grant_subject"],
                        entry["scope_grant_profile_id"],
                        entry["reason_code"],
                        entry["reason"],
                        entry["issued_at"],
                        entry["not_before"],
                        entry["expires_at"],
                        entry["accepted_at"],
                        entry["trust_policy_id"],
                        entry["trust_policy_version"],
                        entry["trust_policy_hash"],
                        entry["previous_hash"],
                        entry_hash,
                    ),
                )

                (
                    _,
                    stored_by_hash,
                    stored_by_grant,
                    _,
                ) = self._store._verify_scope_revocation_state(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    trust_policies=trust_policies,
                    scope_grants=scope_grants,
                )
                row = stored_by_hash.get(revocation_hash)
                if (
                    row is None
                    or stored_by_grant.get(
                        verified.target_grant_sha256
                    )
                    is not row
                ):
                    raise StoreIntegrityError(
                        "Accepted scope-grant revocation failed "
                        "storage verification"
                    )
                self._store._verify_principal_ledger(
                    connection,
                    mission,
                    store_id=str(identity["store_id"]),
                    scope_grants=scope_grants,
                    trust_policies=trust_policies,
                    registry=self._registry,
                )
                return self._acceptance_from_row(
                    row,
                    idempotent=False,
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Scope-grant revocation conflicts with durable state"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError(
                "Could not persist scope-grant revocation"
            ) from exc


__all__ = [
    "ScopeGrantAcceptance",
    "ScopeGrantAcceptanceService",
    "ScopeGrantRevocationAcceptance",
    "ScopeGrantRevocationAcceptanceService",
]

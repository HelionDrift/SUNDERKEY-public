"""Durable replay custody for Phase 157 signed evidence challenges."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .errors import StoreConflictError, StoreError, StoreIntegrityError
from .qualification import _canonical_json, _canonical_sha256

SCHEMA_VERSION = 1
APPLICATION_ID = 0x53554E44
DATABASE_FILENAME = "challenge-replay.sqlite3"
MAX_SEQUENCE_NUMBER = 2**63 - 1
MAX_CHALLENGE_LIFETIME_SECONDS = 900

IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{2,127}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
RESERVATION_ID_PATTERN = re.compile(r"CRV-[0-9A-F]{32}")


class ChallengeContext(StrEnum):
    """The only challenge domains this store is allowed to hold."""

    CONFORMANCE = "signed_conformance_evidence"
    CANDIDATE_EXECUTION = "signed_candidate_execution_evidence"


CONFORMANCE_CONTEXT = ChallengeContext.CONFORMANCE.value
CANDIDATE_EXECUTION_CONTEXT = ChallengeContext.CANDIDATE_EXECUTION.value


@dataclass(frozen=True)
class _ContextContract:
    challenge_domain: str
    challenge_prefix: str
    evidence_prefix: str
    execution_scope: str


_CONTEXT_CONTRACTS = {
    ChallengeContext.CONFORMANCE: _ContextContract(
        "sunderkey.containment-conformance-challenge.v1",
        "BCC-",
        "BCB-",
        "external_synthetic_conformance_only",
    ),
    ChallengeContext.CANDIDATE_EXECUTION: _ContextContract(
        "sunderkey.candidate-execution-evidence-challenge.v1",
        "CEC-",
        "CES-",
        "phase157_synthetic_candidate_evidence",
    ),
}

_CHALLENGE_FIELDS = {
    ChallengeContext.CONFORMANCE: {
        "schema_version",
        "challenge_id",
        "challenge_sha256",
        "suite_catalog_sha256",
        "suite_id",
        "suite_version",
        "backend_id",
        "backend_attestation_sha256",
        "isolation_class",
        "collector_id",
        "key_id",
        "public_key_sha256",
        "nonce",
        "sequence_number",
        "issued_at",
        "expires_at",
        "probe_ids",
        "execution_scope",
        "qualification_effect",
        "routing_effect",
        "deployment_effect",
        "target_authority_effect",
    },
    ChallengeContext.CANDIDATE_EXECUTION: {
        "schema_version",
        "challenge_id",
        "challenge_sha256",
        "adapter_id",
        "profile_id",
        "vector_id",
        "manifest_sha256",
        "backend_id",
        "backend_attestation_sha256",
        "conformance_report_id",
        "conformance_report_sha256",
        "backend_admission_id",
        "backend_admission_sha256",
        "collector_id",
        "key_id",
        "public_key_sha256",
        "nonce",
        "sequence_number",
        "issued_at",
        "expires_at",
        "execution_scope",
        "qualification_effect",
        "routing_effect",
        "deployment_effect",
        "target_authority_effect",
    },
}


class ChallengeReplayConflictError(StoreConflictError):
    """Raised when a challenge operation conflicts with durable replay state."""


class ChallengeExpiredError(ChallengeReplayConflictError):
    """Raised when an issued challenge is no longer consumable."""


class ChallengeReplayAccessController(Protocol):
    """Filesystem custody required around the SQLite database."""

    def protect_directory(self, path: Path) -> None: ...

    def verify_directory(self, path: Path) -> None: ...

    def protect_file(self, path: Path) -> None: ...

    def verify_file(self, path: Path) -> None: ...

    def sync_directory(self, path: Path) -> None: ...


class PosixOwnerOnlyChallengeReplayAccess:
    """Owner-only POSIX access control for a dedicated store directory."""

    @staticmethod
    def _require_posix() -> None:
        if os.name != "posix" or not hasattr(os, "getuid"):
            raise StoreIntegrityError("POSIX challenge replay access control is unavailable")

    def protect_directory(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o700, follow_symlinks=False)

    def verify_directory(self, path: Path) -> None:
        self._verify(path, directory=True)

    def protect_file(self, path: Path) -> None:
        self._require_posix()
        os.chmod(path, 0o600, follow_symlinks=False)

    def verify_file(self, path: Path) -> None:
        self._verify(path, directory=False)

    def sync_directory(self, path: Path) -> None:
        self._require_posix()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _verify(self, path: Path, *, directory: bool) -> None:
        self._require_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise StoreIntegrityError("Challenge replay custody cannot use a symlink")
        if directory and not stat.S_ISDIR(metadata.st_mode):
            raise StoreIntegrityError("Challenge replay custody directory is invalid")
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise StoreIntegrityError("Challenge replay custody file is invalid")
        expected_mode = 0o700 if directory else 0o600
        if stat.S_IMODE(metadata.st_mode) != expected_mode:
            raise StoreIntegrityError("Challenge replay custody permissions are not owner-only")
        if metadata.st_uid != os.getuid():
            raise StoreIntegrityError("Challenge replay custody ownership is invalid")


def _require_access_controller(value: Any) -> ChallengeReplayAccessController:
    for method in (
        "protect_directory",
        "verify_directory",
        "protect_file",
        "verify_file",
        "sync_directory",
    ):
        if not callable(getattr(value, method, None)):
            raise StoreIntegrityError("Challenge replay access controller is incomplete")
    return value


@dataclass(frozen=True)
class ChallengeReservation:
    """A durable nonce and sequence reservation made before dispatch."""

    reservation_id: str
    context: str
    collector_id: str
    key_id: str
    public_key_sha256: str
    nonce: str
    sequence_number: int
    reserved_at: str


@dataclass(frozen=True)
class ChallengeReplayRecord:
    """A point-in-time view of one reservation and its replay state."""

    reservation: ChallengeReservation
    status: str
    challenge_id: str | None
    challenge_sha256: str | None
    issued_at: str | None
    expires_at: str | None
    evidence_id: str | None
    evidence_sha256: str | None
    consumed_at: str | None


_SCHEMA = """
CREATE TABLE challenge_sequence_heads (
    context TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key_sha256 TEXT NOT NULL,
    last_sequence INTEGER NOT NULL CHECK(last_sequence >= 0),
    PRIMARY KEY (context, collector_id, key_id)
) STRICT;

CREATE TABLE challenge_reservations (
    reservation_id TEXT PRIMARY KEY,
    context TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key_sha256 TEXT NOT NULL,
    nonce TEXT NOT NULL UNIQUE,
    sequence_number INTEGER NOT NULL CHECK(sequence_number >= 1),
    reserved_at TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL CHECK(
        lifecycle_state IN ('reserved', 'issued', 'consumed')
    ),
    challenge_id TEXT UNIQUE,
    challenge_sha256 TEXT UNIQUE,
    challenge_json TEXT,
    issued_at TEXT,
    expires_at TEXT,
    evidence_id TEXT UNIQUE,
    evidence_sha256 TEXT UNIQUE,
    consumed_at TEXT,
    UNIQUE (context, collector_id, key_id, sequence_number),
    FOREIGN KEY (context, collector_id, key_id)
        REFERENCES challenge_sequence_heads(context, collector_id, key_id),
    CHECK (
        (lifecycle_state = 'reserved'
            AND challenge_id IS NULL
            AND challenge_sha256 IS NULL
            AND challenge_json IS NULL
            AND issued_at IS NULL
            AND expires_at IS NULL
            AND evidence_id IS NULL
            AND evidence_sha256 IS NULL
            AND consumed_at IS NULL)
        OR
        (lifecycle_state = 'issued'
            AND challenge_id IS NOT NULL
            AND challenge_sha256 IS NOT NULL
            AND challenge_json IS NOT NULL
            AND issued_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND evidence_id IS NULL
            AND evidence_sha256 IS NULL
            AND consumed_at IS NULL)
        OR
        (lifecycle_state = 'consumed'
            AND challenge_id IS NOT NULL
            AND challenge_sha256 IS NOT NULL
            AND challenge_json IS NOT NULL
            AND issued_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND evidence_id IS NOT NULL
            AND evidence_sha256 IS NOT NULL
            AND consumed_at IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER challenge_sequence_heads_no_delete
BEFORE DELETE ON challenge_sequence_heads
BEGIN
    SELECT RAISE(ABORT, 'challenge sequence heads are append-only');
END;

CREATE TRIGGER challenge_sequence_heads_monotonic
BEFORE UPDATE ON challenge_sequence_heads
WHEN NEW.context IS NOT OLD.context
    OR NEW.collector_id IS NOT OLD.collector_id
    OR NEW.key_id IS NOT OLD.key_id
    OR NEW.public_key_sha256 IS NOT OLD.public_key_sha256
    OR NEW.last_sequence != OLD.last_sequence + 1
BEGIN
    SELECT RAISE(ABORT, 'challenge sequence head update is invalid');
END;

CREATE TRIGGER challenge_reservations_no_delete
BEFORE DELETE ON challenge_reservations
BEGIN
    SELECT RAISE(ABORT, 'challenge reservations are append-only');
END;

CREATE TRIGGER challenge_reservations_base_immutable
BEFORE UPDATE ON challenge_reservations
WHEN NEW.reservation_id IS NOT OLD.reservation_id
    OR NEW.context IS NOT OLD.context
    OR NEW.collector_id IS NOT OLD.collector_id
    OR NEW.key_id IS NOT OLD.key_id
    OR NEW.public_key_sha256 IS NOT OLD.public_key_sha256
    OR NEW.nonce IS NOT OLD.nonce
    OR NEW.sequence_number IS NOT OLD.sequence_number
    OR NEW.reserved_at IS NOT OLD.reserved_at
BEGIN
    SELECT RAISE(ABORT, 'challenge reservation identity is immutable');
END;

CREATE TRIGGER challenge_reservations_transition_guard
BEFORE UPDATE ON challenge_reservations
WHEN NOT (
    (OLD.lifecycle_state = 'reserved' AND NEW.lifecycle_state = 'issued')
    OR (OLD.lifecycle_state = 'issued' AND NEW.lifecycle_state = 'consumed')
)
BEGIN
    SELECT RAISE(ABORT, 'challenge lifecycle transition is invalid');
END;

CREATE TRIGGER challenge_reservations_challenge_immutable
BEFORE UPDATE ON challenge_reservations
WHEN OLD.lifecycle_state != 'reserved'
    AND (
        NEW.challenge_id IS NOT OLD.challenge_id
        OR NEW.challenge_sha256 IS NOT OLD.challenge_sha256
        OR NEW.challenge_json IS NOT OLD.challenge_json
        OR NEW.issued_at IS NOT OLD.issued_at
        OR NEW.expires_at IS NOT OLD.expires_at
    )
BEGIN
    SELECT RAISE(ABORT, 'issued challenge binding is immutable');
END;
"""

_EXPECTED_COLUMNS = {
    "challenge_sequence_heads": (
        "context",
        "collector_id",
        "key_id",
        "public_key_sha256",
        "last_sequence",
    ),
    "challenge_reservations": (
        "reservation_id",
        "context",
        "collector_id",
        "key_id",
        "public_key_sha256",
        "nonce",
        "sequence_number",
        "reserved_at",
        "lifecycle_state",
        "challenge_id",
        "challenge_sha256",
        "challenge_json",
        "issued_at",
        "expires_at",
        "evidence_id",
        "evidence_sha256",
        "consumed_at",
    ),
}

_EXPECTED_TRIGGERS = {
    "challenge_sequence_heads_no_delete",
    "challenge_sequence_heads_monotonic",
    "challenge_reservations_no_delete",
    "challenge_reservations_base_immutable",
    "challenge_reservations_transition_guard",
    "challenge_reservations_challenge_immutable",
}


class ChallengeReplayStore:
    """SQLite custody for nonce, sequence, challenge, and one-time use state."""

    def __init__(
        self,
        directory: str | Path,
        access_controller: ChallengeReplayAccessController,
        *,
        clock: Callable[[], datetime] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.directory = Path(directory).resolve()
        self.path = self.directory / DATABASE_FILENAME
        self.access_controller = _require_access_controller(access_controller)
        self._clock = clock or (lambda: datetime.now(UTC))
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
            raise StoreError("Challenge replay timeout must be numeric")
        if not 0.1 <= float(timeout_seconds) <= 60.0:
            raise StoreError("Challenge replay timeout must be from 0.1 through 60 seconds")
        self._timeout_seconds = float(timeout_seconds)

    def initialize(self) -> None:
        """Create a new database or verify an existing database without migration."""

        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            if self.directory.is_symlink():
                raise StoreIntegrityError("Challenge replay directory cannot be a symbolic link")
            self.access_controller.protect_directory(self.directory)
            self.access_controller.verify_directory(self.directory)
            created = self._create_database_file()
            self.access_controller.protect_file(self.path)
            self.access_controller.verify_file(self.path)
            self._protect_existing_sidecars()
            with self._raw_connection() as connection:
                if created:
                    connection.execute("PRAGMA journal_mode = DELETE")
                    connection.execute("PRAGMA synchronous = FULL")
                    try:
                        connection.executescript(
                            "BEGIN IMMEDIATE;\n"
                            + _SCHEMA
                            + f"\nPRAGMA application_id = {APPLICATION_ID};\n"
                            + f"PRAGMA user_version = {SCHEMA_VERSION};\n"
                            + "COMMIT;"
                        )
                    except Exception:
                        if connection.in_transaction:
                            connection.rollback()
                        raise
                self._verify_database(connection)
            self.access_controller.protect_file(self.path)
            self.access_controller.verify_file(self.path)
            self.access_controller.sync_directory(self.directory)
        except StoreError:
            raise
        except sqlite3.Error as exc:
            raise StoreError("Could not initialize challenge replay database") from exc
        except OSError as exc:
            raise StoreError("Could not initialize challenge replay custody") from exc

    def reserve_sequence(
        self,
        *,
        context: ChallengeContext | str,
        collector_id: str,
        key_id: str,
        public_key_sha256: str,
    ) -> ChallengeReservation:
        """Atomically reserve the next sequence with a generated 256-bit nonce."""

        return self._reserve(
            context=context,
            collector_id=collector_id,
            key_id=key_id,
            public_key_sha256=public_key_sha256,
            nonce=_encode_nonce(secrets.token_bytes(32)),
            requested_sequence=None,
        )

    def register_sequence(
        self,
        *,
        context: ChallengeContext | str,
        collector_id: str,
        key_id: str,
        public_key_sha256: str,
        nonce: str,
        sequence_number: int,
    ) -> ChallengeReservation:
        """Register caller-generated material only when its sequence is exactly next."""

        _nonce(nonce)
        _positive_sequence(sequence_number)
        return self._reserve(
            context=context,
            collector_id=collector_id,
            key_id=key_id,
            public_key_sha256=public_key_sha256,
            nonce=nonce,
            requested_sequence=sequence_number,
        )

    def issue_challenge(
        self,
        reservation: ChallengeReservation,
        challenge: Mapping[str, Any] | Any,
    ) -> ChallengeReplayRecord:
        """Bind one canonical challenge to an unused durable reservation."""

        if not isinstance(reservation, ChallengeReservation):
            raise StoreError("reservation must be a ChallengeReservation")
        raw = _challenge_document(challenge)
        challenge_json = _canonical_json(raw)
        try:
            with self._write_connection() as connection:
                now = self._clock_value()
                parsed = _validate_challenge(raw, reservation=reservation, now=now)
                row = self._reservation_row(connection, reservation.reservation_id, required=True)
                stored = self._reservation_from_row(row)
                if stored != reservation:
                    raise ChallengeReplayConflictError(
                        "Challenge reservation does not match durable custody"
                    )
                if row["lifecycle_state"] != "reserved":
                    raise ChallengeReplayConflictError(
                        "Challenge reservation was already issued or consumed"
                    )
                connection.execute(
                    """
                    UPDATE challenge_reservations
                    SET lifecycle_state = 'issued',
                        challenge_id = ?, challenge_sha256 = ?, challenge_json = ?,
                        issued_at = ?, expires_at = ?
                    WHERE reservation_id = ? AND lifecycle_state = 'reserved'
                    """,
                    (
                        parsed["challenge_id"],
                        parsed["challenge_sha256"],
                        challenge_json,
                        parsed["issued_at"],
                        parsed["expires_at"],
                        reservation.reservation_id,
                    ),
                )
                committed = self._reservation_row(
                    connection, reservation.reservation_id, required=True
                )
                self._verify_state(connection)
                return self._record_from_row(committed, now=now)
        except sqlite3.IntegrityError as exc:
            raise ChallengeReplayConflictError(
                "Challenge identity or binding is already registered"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not issue durable evidence challenge") from exc

    def consume_challenge(
        self,
        *,
        context: ChallengeContext | str,
        challenge: Mapping[str, Any] | Any,
        evidence_id: str,
        evidence_sha256: str,
    ) -> ChallengeReplayRecord:
        """Atomically consume one issued challenge for one verified evidence item."""

        selected_context = _context(context)
        contract = _CONTEXT_CONTRACTS[selected_context]
        raw = _challenge_document(challenge)
        challenge_id = _challenge_id(raw.get("challenge_id"), contract)
        evidence_value = _evidence_id(evidence_id, contract)
        evidence_digest = _sha256(evidence_sha256, "evidence_sha256")
        challenge_json = _canonical_json(raw)
        try:
            with self._write_connection() as connection:
                now = self._clock_value()
                row = connection.execute(
                    """
                    SELECT * FROM challenge_reservations
                    WHERE context = ? AND challenge_id = ?
                    """,
                    (selected_context.value, challenge_id),
                ).fetchone()
                if row is None:
                    raise ChallengeReplayConflictError(
                        "Challenge is not issued in the selected context"
                    )
                record = self._record_from_row(row, now=now)
                _validate_challenge(raw, reservation=record.reservation, now=None)
                if row["challenge_json"] != challenge_json:
                    raise ChallengeReplayConflictError(
                        "Challenge does not match its durable issuance binding"
                    )
                if row["lifecycle_state"] == "consumed":
                    raise ChallengeReplayConflictError("Challenge was already consumed")
                if row["lifecycle_state"] != "issued":
                    raise ChallengeReplayConflictError("Challenge has not been issued")
                expires_at = _parse_timestamp(str(row["expires_at"]), "expires_at")
                if now >= expires_at:
                    raise ChallengeExpiredError("Challenge expired before consumption")
                cursor = connection.execute(
                    """
                    UPDATE challenge_reservations
                    SET lifecycle_state = 'consumed', evidence_id = ?,
                        evidence_sha256 = ?, consumed_at = ?
                    WHERE reservation_id = ? AND lifecycle_state = 'issued'
                    """,
                    (
                        evidence_value,
                        evidence_digest,
                        _format_timestamp(now),
                        record.reservation.reservation_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ChallengeReplayConflictError(
                        "Challenge consumption lost an atomic state race"
                    )
                consumed = self._reservation_row(
                    connection, record.reservation.reservation_id, required=True
                )
                self._verify_state(connection)
                return self._record_from_row(consumed, now=now)
        except sqlite3.IntegrityError as exc:
            raise ChallengeReplayConflictError(
                "Evidence or challenge was already consumed"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not consume durable evidence challenge") from exc

    def get_challenge(
        self,
        *,
        context: ChallengeContext | str,
        challenge_id: str,
    ) -> ChallengeReplayRecord | None:
        """Read one challenge record, reporting expiry without mutating custody."""

        selected_context = _context(context)
        selected_id = _challenge_id(challenge_id, _CONTEXT_CONTRACTS[selected_context])
        try:
            with self._read_connection() as connection:
                row = connection.execute(
                    """
                    SELECT * FROM challenge_reservations
                    WHERE context = ? AND challenge_id = ?
                    """,
                    (selected_context.value, selected_id),
                ).fetchone()
                return None if row is None else self._record_from_row(row, now=self._clock_value())
        except sqlite3.Error as exc:
            raise StoreError("Could not read durable evidence challenge") from exc

    def latest_sequence(
        self,
        *,
        context: ChallengeContext | str,
        collector_id: str,
        key_id: str,
        public_key_sha256: str,
    ) -> int:
        """Return the durable head for one isolated context and collector key."""

        selected_context = _context(context)
        selected_collector = _identifier(collector_id, "collector_id")
        selected_key = _identifier(key_id, "key_id")
        selected_digest = _sha256(public_key_sha256, "public_key_sha256")
        try:
            with self._read_connection() as connection:
                row = connection.execute(
                    """
                    SELECT public_key_sha256, last_sequence
                    FROM challenge_sequence_heads
                    WHERE context = ? AND collector_id = ? AND key_id = ?
                    """,
                    (selected_context.value, selected_collector, selected_key),
                ).fetchone()
                if row is None:
                    return 0
                if row["public_key_sha256"] != selected_digest:
                    raise ChallengeReplayConflictError(
                        "Collector key ID is bound to another public key digest"
                    )
                return int(row["last_sequence"])
        except sqlite3.Error as exc:
            raise StoreError("Could not read durable challenge sequence") from exc

    def _reserve(
        self,
        *,
        context: ChallengeContext | str,
        collector_id: str,
        key_id: str,
        public_key_sha256: str,
        nonce: str,
        requested_sequence: int | None,
    ) -> ChallengeReservation:
        selected_context = _context(context)
        selected_collector = _identifier(collector_id, "collector_id")
        selected_key = _identifier(key_id, "key_id")
        selected_digest = _sha256(public_key_sha256, "public_key_sha256")
        selected_nonce = _nonce(nonce)
        try:
            with self._write_connection() as connection:
                reserved_at = _format_timestamp(self._clock_value())
                head = connection.execute(
                    """
                    SELECT public_key_sha256, last_sequence
                    FROM challenge_sequence_heads
                    WHERE context = ? AND collector_id = ? AND key_id = ?
                    """,
                    (selected_context.value, selected_collector, selected_key),
                ).fetchone()
                if head is None:
                    last_sequence = 0
                    connection.execute(
                        """
                        INSERT INTO challenge_sequence_heads(
                            context, collector_id, key_id,
                            public_key_sha256, last_sequence
                        ) VALUES (?, ?, ?, ?, 0)
                        """,
                        (
                            selected_context.value,
                            selected_collector,
                            selected_key,
                            selected_digest,
                        ),
                    )
                else:
                    if head["public_key_sha256"] != selected_digest:
                        raise ChallengeReplayConflictError(
                            "Collector key ID is bound to another public key digest"
                        )
                    last_sequence = int(head["last_sequence"])
                if last_sequence >= MAX_SEQUENCE_NUMBER:
                    raise ChallengeReplayConflictError("Challenge sequence space is exhausted")
                sequence_number = last_sequence + 1
                if requested_sequence is not None and requested_sequence != sequence_number:
                    raise ChallengeReplayConflictError(
                        "Challenge sequence is a duplicate, rollback, or gap"
                    )
                reservation = _build_reservation(
                    context=selected_context.value,
                    collector_id=selected_collector,
                    key_id=selected_key,
                    public_key_sha256=selected_digest,
                    nonce=selected_nonce,
                    sequence_number=sequence_number,
                    reserved_at=reserved_at,
                )
                connection.execute(
                    """
                    INSERT INTO challenge_reservations(
                        reservation_id, context, collector_id, key_id,
                        public_key_sha256, nonce, sequence_number, reserved_at,
                        lifecycle_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'reserved')
                    """,
                    (
                        reservation.reservation_id,
                        reservation.context,
                        reservation.collector_id,
                        reservation.key_id,
                        reservation.public_key_sha256,
                        reservation.nonce,
                        reservation.sequence_number,
                        reservation.reserved_at,
                    ),
                )
                connection.execute(
                    """
                    UPDATE challenge_sequence_heads
                    SET last_sequence = ?
                    WHERE context = ? AND collector_id = ? AND key_id = ?
                    """,
                    (
                        sequence_number,
                        selected_context.value,
                        selected_collector,
                        selected_key,
                    ),
                )
                self._verify_state(connection)
                return reservation
        except sqlite3.IntegrityError as exc:
            raise ChallengeReplayConflictError(
                "Challenge nonce or sequence is already registered"
            ) from exc
        except sqlite3.Error as exc:
            raise StoreError("Could not reserve durable challenge sequence") from exc

    def _create_database_file(self) -> bool:
        if self.path.exists() or self.path.is_symlink():
            if self.path.is_symlink() or not self.path.is_file():
                raise StoreIntegrityError("Challenge replay database is non-regular or ambiguous")
            return False
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(self.path, flags, 0o600)
        os.close(descriptor)
        return True

    def _verify_custody(self) -> None:
        if not self.directory.exists() or self.directory.is_symlink():
            raise StoreIntegrityError("Challenge replay custody directory is unavailable")
        if not self.path.exists() or self.path.is_symlink():
            raise StoreIntegrityError("Challenge replay database is unavailable")
        self.access_controller.verify_directory(self.directory)
        self.access_controller.verify_file(self.path)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if not sidecar.exists():
                continue
            if sidecar.is_symlink() or not sidecar.is_file():
                raise StoreIntegrityError("Challenge replay database sidecar is ambiguous")
            if suffix in {"-wal", "-shm"}:
                raise StoreIntegrityError("Challenge replay database is not in DELETE mode")
            self.access_controller.verify_file(sidecar)

    def _protect_existing_sidecars(self) -> None:
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if not sidecar.exists():
                continue
            if sidecar.is_symlink() or not sidecar.is_file():
                raise StoreIntegrityError("Challenge replay database sidecar is ambiguous")
            if suffix in {"-wal", "-shm"}:
                raise StoreIntegrityError("Challenge replay database is not in DELETE mode")
            self.access_controller.protect_file(sidecar)
            self.access_controller.verify_file(sidecar)

    @contextmanager
    def _raw_connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _read_connection(self) -> Iterator[sqlite3.Connection]:
        self._verify_custody()
        with self._raw_connection() as connection:
            self._verify_database(connection)
            yield connection

    @contextmanager
    def _write_connection(self) -> Iterator[sqlite3.Connection]:
        self._verify_custody()
        with self._raw_connection() as connection:
            self._verify_database(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        self.access_controller.verify_file(self.path)

    def _verify_database(self, connection: sqlite3.Connection) -> None:
        quick_check = connection.execute("PRAGMA quick_check(1)").fetchone()
        if quick_check is None or quick_check[0] != "ok":
            raise StoreIntegrityError("Challenge replay database integrity check failed")
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        if application_id != APPLICATION_ID or version != SCHEMA_VERSION:
            raise StoreIntegrityError(
                "Challenge replay database identity or schema version is invalid"
            )
        if journal_mode.lower() != "delete":
            raise StoreIntegrityError("Challenge replay database journal mode is unsafe")
        tables = {
            str(row["name"])
            for row in connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                """
            )
        }
        if tables != set(_EXPECTED_COLUMNS):
            raise StoreIntegrityError("Challenge replay database tables are invalid")
        for table, expected in _EXPECTED_COLUMNS.items():
            columns = tuple(
                str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})")
            )
            if columns != expected:
                raise StoreIntegrityError("Challenge replay database columns are invalid")
        triggers = {
            str(row["name"])
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
        }
        if triggers != _EXPECTED_TRIGGERS:
            raise StoreIntegrityError("Challenge replay database triggers are invalid")
        self._verify_state(connection)

    def _verify_state(self, connection: sqlite3.Connection) -> None:
        heads = connection.execute("SELECT * FROM challenge_sequence_heads").fetchall()
        for head in heads:
            selected_context = _context(str(head["context"]))
            _identifier(str(head["collector_id"]), "stored collector_id")
            _identifier(str(head["key_id"]), "stored key_id")
            _sha256(str(head["public_key_sha256"]), "stored public_key_sha256")
            last_sequence = int(head["last_sequence"])
            if last_sequence < 1:
                raise StoreIntegrityError("Challenge replay sequence head is empty")
            summary = connection.execute(
                """
                SELECT COUNT(*) AS row_count,
                    COALESCE(MIN(sequence_number), 0) AS minimum_sequence,
                    COALESCE(MAX(sequence_number), 0) AS maximum_sequence,
                    COUNT(DISTINCT public_key_sha256) AS digest_count
                FROM challenge_reservations
                WHERE context = ? AND collector_id = ? AND key_id = ?
                """,
                (
                    selected_context.value,
                    head["collector_id"],
                    head["key_id"],
                ),
            ).fetchone()
            if (
                int(summary["row_count"]) != last_sequence
                or int(summary["minimum_sequence"]) != (1 if last_sequence else 0)
                or int(summary["maximum_sequence"]) != last_sequence
                or int(summary["digest_count"]) != (1 if last_sequence else 0)
            ):
                raise StoreIntegrityError(
                    "Challenge replay sequence history is incomplete or rolled back"
                )
        orphan = connection.execute(
            """
            SELECT 1 FROM challenge_reservations AS reservation
            LEFT JOIN challenge_sequence_heads AS head
              ON head.context = reservation.context
             AND head.collector_id = reservation.collector_id
             AND head.key_id = reservation.key_id
            WHERE head.context IS NULL
               OR head.public_key_sha256 != reservation.public_key_sha256
            LIMIT 1
            """
        ).fetchone()
        if orphan is not None:
            raise StoreIntegrityError("Challenge replay reservation scope is invalid")
        for row in connection.execute("SELECT * FROM challenge_reservations"):
            self._verify_row(row)

    def _verify_row(self, row: sqlite3.Row) -> None:
        reservation = self._reservation_from_row(row)
        lifecycle = str(row["lifecycle_state"])
        if lifecycle == "reserved":
            return
        try:
            raw = json.loads(str(row["challenge_json"]))
        except json.JSONDecodeError as exc:
            raise StoreIntegrityError("Stored challenge JSON is invalid") from exc
        if not isinstance(raw, dict) or _canonical_json(raw) != row["challenge_json"]:
            raise StoreIntegrityError("Stored challenge JSON is not canonical")
        parsed = _validate_challenge(raw, reservation=reservation, now=None)
        if (
            parsed["challenge_id"] != row["challenge_id"]
            or parsed["challenge_sha256"] != row["challenge_sha256"]
            or parsed["issued_at"] != row["issued_at"]
            or parsed["expires_at"] != row["expires_at"]
        ):
            raise StoreIntegrityError("Stored challenge columns do not match content")
        if lifecycle == "consumed":
            contract = _CONTEXT_CONTRACTS[_context(reservation.context)]
            _evidence_id(str(row["evidence_id"]), contract)
            _sha256(str(row["evidence_sha256"]), "stored evidence_sha256")
            consumed_at = _parse_timestamp(str(row["consumed_at"]), "consumed_at")
            issued_at = _parse_timestamp(str(row["issued_at"]), "issued_at")
            expires_at = _parse_timestamp(str(row["expires_at"]), "expires_at")
            if not issued_at <= consumed_at < expires_at:
                raise StoreIntegrityError(
                    "Stored challenge consumption time is outside its validity window"
                )

    @staticmethod
    def _reservation_row(
        connection: sqlite3.Connection,
        reservation_id: str,
        *,
        required: bool,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM challenge_reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()
        if row is None and required:
            raise ChallengeReplayConflictError("Challenge reservation is not registered")
        return row

    @staticmethod
    def _reservation_from_row(row: sqlite3.Row) -> ChallengeReservation:
        reservation = _build_reservation(
            context=str(row["context"]),
            collector_id=str(row["collector_id"]),
            key_id=str(row["key_id"]),
            public_key_sha256=str(row["public_key_sha256"]),
            nonce=str(row["nonce"]),
            sequence_number=int(row["sequence_number"]),
            reserved_at=str(row["reserved_at"]),
        )
        if reservation.reservation_id != row["reservation_id"]:
            raise StoreIntegrityError("Stored challenge reservation identity is invalid")
        return reservation

    def _record_from_row(
        self,
        row: sqlite3.Row,
        *,
        now: datetime,
    ) -> ChallengeReplayRecord:
        self._verify_row(row)
        lifecycle = str(row["lifecycle_state"])
        status = lifecycle
        if lifecycle == "issued" and now >= _parse_timestamp(str(row["expires_at"]), "expires_at"):
            status = "expired"
        return ChallengeReplayRecord(
            self._reservation_from_row(row),
            status,
            row["challenge_id"],
            row["challenge_sha256"],
            row["issued_at"],
            row["expires_at"],
            row["evidence_id"],
            row["evidence_sha256"],
            row["consumed_at"],
        )

    def _clock_value(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise StoreError("clock must return a timezone-aware datetime")
        return now.astimezone(UTC).replace(microsecond=0)


def _context(value: ChallengeContext | str) -> ChallengeContext:
    try:
        return ChallengeContext(value)
    except (TypeError, ValueError) as exc:
        raise StoreError("Challenge context is invalid") from exc


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise StoreError(f"{label} is invalid")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise StoreError(f"{label} must be a SHA-256 digest")
    return value


def _positive_sequence(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_SEQUENCE_NUMBER
    ):
        raise StoreError("sequence_number must be a positive 63-bit integer")
    return value


def _encode_nonce(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _nonce(value: Any) -> str:
    if not isinstance(value, str) or "=" in value:
        raise StoreError("nonce must be canonical unpadded base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise StoreError("nonce must be canonical unpadded base64url") from exc
    if len(decoded) != 32 or _encode_nonce(decoded) != value:
        raise StoreError("nonce must encode exactly 256 bits")
    return value


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise StoreIntegrityError(f"{label} must use whole-second UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise StoreIntegrityError(f"{label} is invalid") from exc
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise StoreIntegrityError(f"{label} must use whole-second UTC Z notation")
    return parsed


def _build_reservation(
    *,
    context: str,
    collector_id: str,
    key_id: str,
    public_key_sha256: str,
    nonce: str,
    sequence_number: int,
    reserved_at: str,
) -> ChallengeReservation:
    selected_context = _context(context).value
    body = {
        "context": selected_context,
        "collector_id": _identifier(collector_id, "collector_id"),
        "key_id": _identifier(key_id, "key_id"),
        "public_key_sha256": _sha256(public_key_sha256, "public_key_sha256"),
        "nonce": _nonce(nonce),
        "sequence_number": _positive_sequence(sequence_number),
        "reserved_at": _format_timestamp(_parse_timestamp(reserved_at, "reserved_at")),
    }
    digest = _canonical_sha256(
        {"domain": "sunderkey.challenge-replay-reservation.v1", "reservation": body}
    )
    return ChallengeReservation(
        "CRV-" + digest.removeprefix("sha256:")[:32].upper(),
        **body,
    )


def _challenge_document(value: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        raw = dict(value)
    else:
        to_dict = getattr(value, "to_dict", None)
        if not callable(to_dict):
            raise StoreError("challenge must be a mapping or expose to_dict()")
        raw = to_dict()
    if not isinstance(raw, dict):
        raise StoreError("challenge document must be an object")
    _reject_sensitive_fields(raw)
    try:
        return json.loads(_canonical_json(raw))
    except (TypeError, ValueError) as exc:
        raise StoreError("challenge document is not canonical JSON data") from exc


def _reject_sensitive_fields(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            lowered = str(key).lower()
            if "private_key" in lowered or lowered in {
                "secret",
                "secrets",
                "credential",
                "credentials",
                "grant",
                "grants",
            }:
                raise StoreError("challenge contains prohibited secret or grant material")
            _reject_sensitive_fields(item)
    elif isinstance(value, list):
        for item in value:
            _reject_sensitive_fields(item)


def _challenge_id(value: Any, contract: _ContextContract) -> str:
    pattern = re.compile(re.escape(contract.challenge_prefix) + r"[0-9A-F]{32}")
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise StoreError("challenge_id is invalid for its context")
    return value


def _evidence_id(value: Any, contract: _ContextContract) -> str:
    pattern = re.compile(re.escape(contract.evidence_prefix) + r"[0-9A-F]{32}")
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise StoreError("evidence_id is invalid for its context")
    return value


def _validate_challenge(
    raw: dict[str, Any],
    *,
    reservation: ChallengeReservation,
    now: datetime | None,
) -> dict[str, str]:
    selected_context = _context(reservation.context)
    contract = _CONTEXT_CONTRACTS[selected_context]
    if set(raw) != _CHALLENGE_FIELDS[selected_context]:
        raise StoreError("Challenge fields are invalid for its context")
    challenge_id = _challenge_id(raw.get("challenge_id"), contract)
    challenge_sha256 = _sha256(raw.get("challenge_sha256"), "challenge_sha256")
    if raw.get("schema_version") != 1:
        raise StoreError("Challenge schema version is invalid")
    expected_bindings = {
        "collector_id": reservation.collector_id,
        "key_id": reservation.key_id,
        "public_key_sha256": reservation.public_key_sha256,
        "nonce": reservation.nonce,
        "sequence_number": reservation.sequence_number,
        "execution_scope": contract.execution_scope,
        "qualification_effect": "none",
        "routing_effect": "none",
        "deployment_effect": "none",
        "target_authority_effect": "none",
    }
    if any(raw.get(key) != value for key, value in expected_bindings.items()):
        raise ChallengeReplayConflictError(
            "Challenge does not match its nonce, sequence, collector, key, or scope"
        )
    issued_at = _parse_timestamp(raw.get("issued_at"), "issued_at")
    expires_at = _parse_timestamp(raw.get("expires_at"), "expires_at")
    reserved_at = _parse_timestamp(reservation.reserved_at, "reserved_at")
    lifetime = int((expires_at - issued_at).total_seconds())
    if not 1 <= lifetime <= MAX_CHALLENGE_LIFETIME_SECONDS:
        raise StoreError("Challenge lifetime is invalid")
    if issued_at < reserved_at:
        raise ChallengeReplayConflictError("Challenge issue time predates its durable reservation")
    if now is not None and (issued_at > now or now >= expires_at):
        raise ChallengeExpiredError("Challenge is not currently issuable")
    body = {
        key: value for key, value in raw.items() if key not in {"challenge_id", "challenge_sha256"}
    }
    expected_sha256 = _canonical_sha256({"domain": contract.challenge_domain, "challenge": body})
    expected_id = contract.challenge_prefix + expected_sha256.removeprefix("sha256:")[:32].upper()
    if challenge_sha256 != expected_sha256 or challenge_id != expected_id:
        raise ChallengeReplayConflictError(
            "Challenge identity does not match its canonical content"
        )
    return {
        "challenge_id": challenge_id,
        "challenge_sha256": challenge_sha256,
        "issued_at": _format_timestamp(issued_at),
        "expires_at": _format_timestamp(expires_at),
    }


__all__ = [
    "CANDIDATE_EXECUTION_CONTEXT",
    "CONFORMANCE_CONTEXT",
    "ChallengeContext",
    "ChallengeExpiredError",
    "ChallengeReplayAccessController",
    "ChallengeReplayConflictError",
    "ChallengeReplayRecord",
    "ChallengeReplayStore",
    "ChallengeReservation",
    "PosixOwnerOnlyChallengeReplayAccess",
]

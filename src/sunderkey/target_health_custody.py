"""Durable local custody for signed target health envelopes.

This module owns repository-only SQLite state. It performs no collection,
network access, target interaction, execution control, or authority grant.
"""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .execution_control_runtime import canonical_json
from .target_health_custody_contracts import (
    SignedTargetHealthCustodyEnvelopeV2,
    TargetHealthCollectorPolicyRevision,
    TargetHealthCollectorPolicyRevocation,
    TargetHealthCurrentHeadInspection,
    TargetHealthCustodyContractError,
    TargetHealthCustodyEvent,
    TargetHealthCustodyHeadBinding,
    TargetHealthCustodyReceipt,
    TargetHealthCustodyVerificationResult,
    TargetHealthSigningContext,
    TargetHealthTrustRoot,
    build_target_health_custody_event,
    build_target_health_custody_receipt,
    parse_target_health_custody_document,
    target_health_chain_id,
    verify_target_health_collector_policy,
    verify_target_health_collector_policy_revocation,
    verify_target_health_custody_envelope_current,
    verify_target_health_custody_envelope_historical,
)

APPLICATION_ID = 0x53544843
SCHEMA_VERSION = 1
MIGRATION_ID = "sunderkey.target-health-custody.sqlite.v1"
SAFE_JOURNAL_MODE = "wal"
DEFAULT_BUSY_TIMEOUT_SECONDS = 2.0
MAX_BUSY_TIMEOUT_SECONDS = 30.0
MAX_PAGE_SIZE = 200
MAX_SQLITE_INTEGER = 2**63 - 1

_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CHAIN_ID_RE = re.compile(r"THCH-[0-9A-F]{32}\Z")
_MIGRATION_LOCK = threading.Lock()


class TargetHealthCustodyError(ValueError):
    """Base class for local custody failures."""


class TargetHealthCustodyValidationError(TargetHealthCustodyError):
    """Raised when a caller supplies an invalid request."""


class TargetHealthCustodyConflictError(TargetHealthCustodyError):
    """Raised when a signed transition conflicts with durable state."""


class TargetHealthCustodyIntegrityError(TargetHealthCustodyError):
    """Raised when durable state or trusted time is invalid."""


class TargetHealthCustodyBusyError(TargetHealthCustodyError):
    """Raised when SQLite cannot obtain the bounded writer lock."""


class TargetHealthCustodyNotFoundError(TargetHealthCustodyError):
    """Raised when a tenant-scoped durable record is absent."""


@dataclass(frozen=True, slots=True)
class TargetHealthAppendResult:
    """One atomic custody acceptance or exact replay."""

    receipt: TargetHealthCustodyReceipt
    event: TargetHealthCustodyEvent
    replayed: bool


@dataclass(frozen=True, slots=True)
class TargetHealthCustodyVerificationReport:
    """Historical whole-store verification summary."""

    application_id: int
    schema_version: int
    schema_manifest_sha256: str
    trust_root_id: str
    policy_count: int
    revocation_count: int
    envelope_count: int
    custody_receipt_count: int
    event_count: int
    chain_count: int
    transition_count: int
    status: str = "valid"


_MIGRATION_1 = r"""
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version = 1),
    migration_id TEXT NOT NULL UNIQUE,
    migration_sha256 TEXT NOT NULL UNIQUE,
    applied_at TEXT NOT NULL
) STRICT;

CREATE TABLE custody_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_id INTEGER NOT NULL,
    schema_version INTEGER NOT NULL,
    migration_id TEXT NOT NULL,
    migration_sha256 TEXT NOT NULL,
    schema_manifest_sha256 TEXT NOT NULL,
    trust_root_id TEXT NOT NULL,
    trust_root_sha256 TEXT NOT NULL
) STRICT;

CREATE TABLE target_health_trust_roots (
    trust_root_id TEXT PRIMARY KEY,
    trust_root_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    trust_root_revision INTEGER NOT NULL,
    root_json TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE target_health_collector_policies (
    transition_sequence INTEGER PRIMARY KEY,
    policy_id TEXT NOT NULL UNIQUE,
    policy_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    trust_root_id TEXT NOT NULL,
    trust_root_sha256 TEXT NOT NULL,
    trust_root_revision INTEGER NOT NULL,
    chain_id TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    collector_epoch INTEGER NOT NULL,
    policy_revision INTEGER NOT NULL,
    predecessor_policy_id TEXT,
    predecessor_policy_sha256 TEXT,
    prior_epoch_head_envelope_id TEXT,
    prior_epoch_head_envelope_sha256 TEXT,
    published_at TEXT NOT NULL,
    policy_json TEXT NOT NULL UNIQUE,
    UNIQUE (chain_id, policy_revision),
    FOREIGN KEY (predecessor_policy_id)
        REFERENCES target_health_collector_policies(policy_id),
    FOREIGN KEY (trust_root_id) REFERENCES target_health_trust_roots(trust_root_id)
) STRICT;

CREATE TABLE target_health_collector_policy_revocations (
    transition_sequence INTEGER PRIMARY KEY,
    revocation_id TEXT NOT NULL UNIQUE,
    revocation_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    trust_root_id TEXT NOT NULL,
    trust_root_sha256 TEXT NOT NULL,
    trust_root_revision INTEGER NOT NULL,
    chain_id TEXT NOT NULL,
    policy_id TEXT NOT NULL UNIQUE,
    policy_sha256 TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    collector_epoch INTEGER NOT NULL,
    revoked_at TEXT NOT NULL,
    published_at TEXT NOT NULL,
    revocation_json TEXT NOT NULL UNIQUE,
    FOREIGN KEY (policy_id) REFERENCES target_health_collector_policies(policy_id),
    FOREIGN KEY (trust_root_id) REFERENCES target_health_trust_roots(trust_root_id)
) STRICT;

CREATE TABLE target_health_policy_revocation_heads (
    policy_id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    revocation_id TEXT NOT NULL UNIQUE,
    revocation_sha256 TEXT NOT NULL UNIQUE,
    revoked_at TEXT NOT NULL,
    transition_sequence INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (policy_id) REFERENCES target_health_collector_policies(policy_id),
    FOREIGN KEY (revocation_id)
        REFERENCES target_health_collector_policy_revocations(revocation_id)
) STRICT;

CREATE TABLE target_health_policy_heads (
    chain_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    policy_id TEXT NOT NULL UNIQUE,
    policy_sha256 TEXT NOT NULL UNIQUE,
    policy_revision INTEGER NOT NULL,
    collector_epoch INTEGER NOT NULL,
    transition_sequence INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (policy_id) REFERENCES target_health_collector_policies(policy_id)
) STRICT;

CREATE TABLE target_health_envelopes (
    transition_sequence INTEGER PRIMARY KEY,
    envelope_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    collector_epoch INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    predecessor_envelope_id TEXT,
    predecessor_envelope_sha256 TEXT,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    policy_revision INTEGER NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL,
    signing_payload_sha256 TEXT NOT NULL UNIQUE,
    observed_at TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    envelope_json TEXT NOT NULL UNIQUE,
    UNIQUE (chain_id, sequence),
    FOREIGN KEY (predecessor_envelope_id)
        REFERENCES target_health_envelopes(envelope_id),
    FOREIGN KEY (policy_id) REFERENCES target_health_collector_policies(policy_id)
) STRICT;

CREATE TABLE target_health_custody_receipts (
    custody_receipt_id TEXT PRIMARY KEY,
    custody_receipt_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    envelope_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL,
    receipt_json TEXT NOT NULL UNIQUE,
    UNIQUE (chain_id, sequence),
    FOREIGN KEY (envelope_id) REFERENCES target_health_envelopes(envelope_id)
) STRICT;

CREATE TABLE target_health_custody_events (
    event_id TEXT PRIMARY KEY,
    event_sha256 TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    chain_id TEXT NOT NULL,
    event_sequence INTEGER NOT NULL,
    predecessor_event_id TEXT,
    predecessor_event_sha256 TEXT,
    custody_receipt_id TEXT NOT NULL UNIQUE,
    custody_receipt_sha256 TEXT NOT NULL UNIQUE,
    envelope_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    recorded_at TEXT NOT NULL,
    event_json TEXT NOT NULL UNIQUE,
    UNIQUE (chain_id, event_sequence),
    FOREIGN KEY (predecessor_event_id)
        REFERENCES target_health_custody_events(event_id),
    FOREIGN KEY (custody_receipt_id)
        REFERENCES target_health_custody_receipts(custody_receipt_id),
    FOREIGN KEY (envelope_id) REFERENCES target_health_envelopes(envelope_id)
) STRICT;

CREATE TABLE target_health_chain_heads (
    chain_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    binding_sha256 TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    collector_epoch INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    envelope_id TEXT NOT NULL UNIQUE,
    envelope_sha256 TEXT NOT NULL UNIQUE,
    custody_receipt_id TEXT NOT NULL UNIQUE,
    custody_receipt_sha256 TEXT NOT NULL UNIQUE,
    policy_id TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    transition_sequence INTEGER NOT NULL UNIQUE,
    FOREIGN KEY (envelope_id) REFERENCES target_health_envelopes(envelope_id),
    FOREIGN KEY (custody_receipt_id)
        REFERENCES target_health_custody_receipts(custody_receipt_id),
    FOREIGN KEY (policy_id) REFERENCES target_health_collector_policies(policy_id)
) STRICT;

CREATE TABLE target_health_event_heads (
    chain_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    mission_id TEXT NOT NULL,
    event_sequence INTEGER NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    event_sha256 TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES target_health_custody_events(event_id)
) STRICT;

CREATE INDEX target_health_policies_tenant_chain_revision
    ON target_health_collector_policies(tenant_id, mission_id, chain_id, policy_revision);
CREATE INDEX target_health_revocations_tenant_chain_policy
    ON target_health_collector_policy_revocations(tenant_id, mission_id, chain_id, policy_revision);
CREATE INDEX target_health_envelopes_tenant_chain_sequence
    ON target_health_envelopes(tenant_id, mission_id, chain_id, sequence);
CREATE INDEX target_health_receipts_tenant_chain_sequence
    ON target_health_custody_receipts(tenant_id, mission_id, chain_id, sequence);
CREATE INDEX target_health_events_tenant_chain_sequence
    ON target_health_custody_events(tenant_id, mission_id, chain_id, event_sequence);

CREATE TRIGGER schema_migrations_no_update BEFORE UPDATE ON schema_migrations
BEGIN SELECT RAISE(ABORT, 'schema migrations are immutable'); END;
CREATE TRIGGER schema_migrations_no_delete BEFORE DELETE ON schema_migrations
BEGIN SELECT RAISE(ABORT, 'schema migrations are immutable'); END;
CREATE TRIGGER custody_metadata_no_update BEFORE UPDATE ON custody_metadata
BEGIN SELECT RAISE(ABORT, 'custody metadata is immutable'); END;
CREATE TRIGGER custody_metadata_no_delete BEFORE DELETE ON custody_metadata
BEGIN SELECT RAISE(ABORT, 'custody metadata is immutable'); END;
CREATE TRIGGER target_health_trust_roots_no_update
BEFORE UPDATE ON target_health_trust_roots
BEGIN SELECT RAISE(ABORT, 'target health trust roots are immutable'); END;
CREATE TRIGGER target_health_trust_roots_no_delete
BEFORE DELETE ON target_health_trust_roots
BEGIN SELECT RAISE(ABORT, 'target health trust roots are immutable'); END;
CREATE TRIGGER target_health_collector_policies_no_update
BEFORE UPDATE ON target_health_collector_policies
BEGIN SELECT RAISE(ABORT, 'target health collector policies are immutable'); END;
CREATE TRIGGER target_health_collector_policies_no_delete
BEFORE DELETE ON target_health_collector_policies
BEGIN SELECT RAISE(ABORT, 'target health collector policies are immutable'); END;
CREATE TRIGGER target_health_collector_policy_revocations_no_update
BEFORE UPDATE ON target_health_collector_policy_revocations
BEGIN SELECT RAISE(ABORT, 'target health policy revocations are immutable'); END;
CREATE TRIGGER target_health_collector_policy_revocations_no_delete
BEFORE DELETE ON target_health_collector_policy_revocations
BEGIN SELECT RAISE(ABORT, 'target health policy revocations are immutable'); END;
CREATE TRIGGER target_health_policy_revocation_heads_no_update
BEFORE UPDATE ON target_health_policy_revocation_heads
BEGIN SELECT RAISE(ABORT, 'target health policy revocation heads are terminal'); END;
CREATE TRIGGER target_health_policy_revocation_heads_no_delete
BEFORE DELETE ON target_health_policy_revocation_heads
BEGIN SELECT RAISE(ABORT, 'target health policy revocation heads are terminal'); END;
CREATE TRIGGER target_health_envelopes_no_update
BEFORE UPDATE ON target_health_envelopes
BEGIN SELECT RAISE(ABORT, 'target health envelopes are immutable'); END;
CREATE TRIGGER target_health_envelopes_no_delete
BEFORE DELETE ON target_health_envelopes
BEGIN SELECT RAISE(ABORT, 'target health envelopes are immutable'); END;
CREATE TRIGGER target_health_custody_receipts_no_update
BEFORE UPDATE ON target_health_custody_receipts
BEGIN SELECT RAISE(ABORT, 'target health custody receipts are immutable'); END;
CREATE TRIGGER target_health_custody_receipts_no_delete
BEFORE DELETE ON target_health_custody_receipts
BEGIN SELECT RAISE(ABORT, 'target health custody receipts are immutable'); END;
CREATE TRIGGER target_health_custody_events_no_update
BEFORE UPDATE ON target_health_custody_events
BEGIN SELECT RAISE(ABORT, 'target health custody events are immutable'); END;
CREATE TRIGGER target_health_custody_events_no_delete
BEFORE DELETE ON target_health_custody_events
BEGIN SELECT RAISE(ABORT, 'target health custody events are immutable'); END;
CREATE TRIGGER target_health_policy_heads_no_delete
BEFORE DELETE ON target_health_policy_heads
BEGIN SELECT RAISE(ABORT, 'target health policy heads cannot be deleted'); END;
CREATE TRIGGER target_health_policy_heads_identity
BEFORE UPDATE ON target_health_policy_heads
WHEN NEW.chain_id != OLD.chain_id
  OR NEW.tenant_id != OLD.tenant_id
  OR NEW.mission_id != OLD.mission_id
  OR NEW.transition_sequence <= OLD.transition_sequence
BEGIN SELECT RAISE(ABORT, 'target health policy head identity is immutable'); END;
CREATE TRIGGER target_health_chain_heads_no_delete
BEFORE DELETE ON target_health_chain_heads
BEGIN SELECT RAISE(ABORT, 'target health chain heads cannot be deleted'); END;
CREATE TRIGGER target_health_chain_heads_identity
BEFORE UPDATE ON target_health_chain_heads
WHEN NEW.chain_id != OLD.chain_id
  OR NEW.tenant_id != OLD.tenant_id
  OR NEW.mission_id != OLD.mission_id
  OR NEW.binding_sha256 != OLD.binding_sha256
  OR NEW.collector_id != OLD.collector_id
  OR NEW.transition_sequence <= OLD.transition_sequence
BEGIN SELECT RAISE(ABORT, 'target health chain head identity is immutable'); END;
CREATE TRIGGER target_health_event_heads_no_delete
BEFORE DELETE ON target_health_event_heads
BEGIN SELECT RAISE(ABORT, 'target health event heads cannot be deleted'); END;
CREATE TRIGGER target_health_event_heads_identity
BEFORE UPDATE ON target_health_event_heads
WHEN NEW.chain_id != OLD.chain_id
  OR NEW.tenant_id != OLD.tenant_id
  OR NEW.mission_id != OLD.mission_id
  OR NEW.event_sequence <= OLD.event_sequence
BEGIN SELECT RAISE(ABORT, 'target health event head identity is immutable'); END;
""".strip()

MIGRATION_SHA256 = "sha256:" + hashlib.sha256(_MIGRATION_1.encode("ascii")).hexdigest()


def _schema_manifest(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    manifest = [
        {
            "name": row["name"],
            "sql": row["sql"],
            "table": row["tbl_name"],
            "type": row["type"],
        }
        for row in rows
    ]
    return "sha256:" + hashlib.sha256(canonical_json(manifest).encode("ascii")).hexdigest()


def _expected_schema_manifest() -> str:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(_MIGRATION_1)
        return _schema_manifest(connection)
    finally:
        connection.close()


EXPECTED_SCHEMA_MANIFEST_SHA256 = _expected_schema_manifest()


def _instant(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise TargetHealthCustodyIntegrityError("stored UTC timestamp is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise TargetHealthCustodyIntegrityError("stored UTC timestamp is invalid")
    return parsed


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise TargetHealthCustodyValidationError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise TargetHealthCustodyValidationError(f"{label} is invalid")
    return value


def _chain_id(value: Any) -> str:
    if not isinstance(value, str) or _CHAIN_ID_RE.fullmatch(value) is None:
        raise TargetHealthCustodyValidationError("chain_id is invalid")
    return value


def _document(record: Any) -> str:
    return canonical_json(record.to_dict())


def _signing_payload_sha256(envelope: SignedTargetHealthCustodyEnvelopeV2) -> str:
    return "sha256:" + hashlib.sha256(envelope.signing_bytes()).hexdigest()


class SQLiteTargetHealthCustody:
    """File-backed signed target health custody with no external effects."""

    def __init__(
        self,
        path: str | Path,
        *,
        trust_root: TargetHealthTrustRoot,
        busy_timeout_seconds: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
        trusted_clock: Callable[[], datetime] | None = None,
    ) -> None:
        raw_path = str(path)
        if not raw_path or raw_path == ":memory:" or raw_path.lower().startswith("file:"):
            raise TargetHealthCustodyValidationError("file-backed SQLite is required")
        if not isinstance(trust_root, TargetHealthTrustRoot):
            raise TargetHealthCustodyValidationError("trust_root is invalid")
        if (
            isinstance(busy_timeout_seconds, bool)
            or not isinstance(busy_timeout_seconds, (int, float))
            or not math.isfinite(busy_timeout_seconds)
            or not 0 < busy_timeout_seconds <= MAX_BUSY_TIMEOUT_SECONDS
        ):
            raise TargetHealthCustodyValidationError("busy timeout is outside its allowed range")
        if trusted_clock is not None and not callable(trusted_clock):
            raise TargetHealthCustodyValidationError("trusted clock is not callable")
        self.path = Path(path)
        self.trust_root = trust_root
        self.busy_timeout_seconds = float(busy_timeout_seconds)
        self._trusted_clock = trusted_clock or (lambda: datetime.now(UTC))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _trusted_now(self) -> str:
        try:
            value = self._trusted_clock()
        except Exception as exc:
            raise TargetHealthCustodyIntegrityError("trusted clock failed") from exc
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise TargetHealthCustodyIntegrityError("trusted clock returned an invalid value")
        return value.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _connect(self, *, require_safe_mode: bool = True) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                isolation_level=None,
                timeout=self.busy_timeout_seconds,
            )
        except sqlite3.OperationalError as exc:
            lowered = str(exc).lower()
            if "locked" in lowered or "busy" in lowered:
                raise TargetHealthCustodyBusyError(
                    "target health custody is busy"
                ) from exc
            raise TargetHealthCustodyIntegrityError(
                "custody database could not be opened"
            ) from exc
        except sqlite3.Error as exc:
            raise TargetHealthCustodyIntegrityError(
                "custody database could not be opened"
            ) from exc
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute(
                f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}"
            )
            if require_safe_mode:
                mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
                if mode != SAFE_JOURNAL_MODE:
                    raise TargetHealthCustodyIntegrityError(
                        "custody journal mode is unsafe"
                    )
        except sqlite3.OperationalError as exc:
            connection.close()
            lowered = str(exc).lower()
            if "locked" in lowered or "busy" in lowered:
                raise TargetHealthCustodyBusyError(
                    "target health custody is busy"
                ) from exc
            raise TargetHealthCustodyIntegrityError(
                "custody database configuration failed"
            ) from exc
        except sqlite3.Error as exc:
            connection.close()
            raise TargetHealthCustodyIntegrityError(
                "custody database configuration failed"
            ) from exc
        except Exception:
            connection.close()
            raise
        return connection

    @contextmanager
    def _read(
        self, *, reconstruct_history: bool = True
    ) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._verify_database_identity(connection)
            if reconstruct_history:
                self._verify_history(connection)
            yield connection
        except sqlite3.OperationalError as exc:
            lowered = str(exc).lower()
            if "locked" in lowered or "busy" in lowered:
                raise TargetHealthCustodyBusyError("target health custody is busy") from exc
            raise TargetHealthCustodyIntegrityError("SQLite read failed") from exc
        except sqlite3.Error as exc:
            raise TargetHealthCustodyIntegrityError("SQLite read failed") from exc
        finally:
            if connection.in_transaction:
                connection.rollback()
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._verify_database_identity(connection)
            self._verify_history(connection)
            yield connection
            self._verify_history(connection)
            connection.commit()
        except sqlite3.OperationalError as exc:
            if connection.in_transaction:
                connection.rollback()
            lowered = str(exc).lower()
            if "locked" in lowered or "busy" in lowered:
                raise TargetHealthCustodyBusyError("target health custody is busy") from exc
            raise TargetHealthCustodyIntegrityError("SQLite operation failed") from exc
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise TargetHealthCustodyIntegrityError("SQLite integrity constraint failed") from exc
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.rollback()
            raise TargetHealthCustodyIntegrityError("SQLite operation failed") from exc
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _migrate(self) -> None:
        with _MIGRATION_LOCK:
            connection = self._connect(require_safe_mode=False)
            try:
                application_id = connection.execute("PRAGMA application_id").fetchone()[0]
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                object_count = connection.execute(
                    "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
                if version == 0:
                    if application_id != 0 or object_count != 0:
                        raise TargetHealthCustodyIntegrityError(
                            "unmarked target health custody database is not empty"
                        )
                elif application_id != APPLICATION_ID or version != SCHEMA_VERSION:
                    raise TargetHealthCustodyIntegrityError(
                        "target health custody database identity is invalid"
                    )
                mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
                if mode != SAFE_JOURNAL_MODE:
                    raise TargetHealthCustodyIntegrityError("safe journal mode is unavailable")
                if version == 0:
                    try:
                        connection.executescript("BEGIN IMMEDIATE;\n" + _MIGRATION_1)
                    except sqlite3.OperationalError:
                        if connection.in_transaction:
                            connection.rollback()
                        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
                        version = connection.execute("PRAGMA user_version").fetchone()[0]
                        if application_id != APPLICATION_ID or version != SCHEMA_VERSION:
                            raise
                    else:
                        root_json = _document(self.trust_root)
                        connection.execute(
                            "INSERT INTO schema_migrations VALUES(1,?,?,?)",
                            (MIGRATION_ID, MIGRATION_SHA256, "1970-01-01T00:00:00Z"),
                        )
                        connection.execute(
                            "INSERT INTO target_health_trust_roots VALUES(?,?,?,?,?,?)",
                            (
                                self.trust_root.trust_root_id,
                                self.trust_root.trust_root_sha256,
                                self.trust_root.tenant_id,
                                self.trust_root.mission_id,
                                self.trust_root.trust_root_revision,
                                root_json,
                            ),
                        )
                        connection.execute(
                            "INSERT INTO custody_metadata VALUES(1,?,?,?,?,?,?,?)",
                            (
                                APPLICATION_ID,
                                SCHEMA_VERSION,
                                MIGRATION_ID,
                                MIGRATION_SHA256,
                                EXPECTED_SCHEMA_MANIFEST_SHA256,
                                self.trust_root.trust_root_id,
                                self.trust_root.trust_root_sha256,
                            ),
                        )
                        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                        connection.commit()
                self._verify_database_identity(connection)
            except sqlite3.Error as exc:
                if connection.in_transaction:
                    connection.rollback()
                raise TargetHealthCustodyIntegrityError(
                    "target health custody migration failed"
                ) from exc
            except Exception:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()

    def _verify_database_identity(self, connection: sqlite3.Connection) -> None:
        application_id = connection.execute("PRAGMA application_id").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != APPLICATION_ID or version != SCHEMA_VERSION:
            raise TargetHealthCustodyIntegrityError(
                "target health custody database identity is invalid"
            )
        mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
        if mode != SAFE_JOURNAL_MODE:
            raise TargetHealthCustodyIntegrityError("custody journal mode is unsafe")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise TargetHealthCustodyIntegrityError("foreign keys are disabled")
        if connection.execute("PRAGMA synchronous").fetchone()[0] != 2:
            raise TargetHealthCustodyIntegrityError("SQLite synchronous mode is unsafe")
        migration_rows = connection.execute(
            "SELECT version,migration_id,migration_sha256,applied_at "
            "FROM schema_migrations ORDER BY version"
        ).fetchall()
        expected_migration = (1, MIGRATION_ID, MIGRATION_SHA256, "1970-01-01T00:00:00Z")
        if len(migration_rows) != 1 or tuple(migration_rows[0]) != expected_migration:
            raise TargetHealthCustodyIntegrityError("custody migration identity is invalid")
        if _schema_manifest(connection) != EXPECTED_SCHEMA_MANIFEST_SHA256:
            raise TargetHealthCustodyIntegrityError("custody schema manifest is invalid")
        metadata_rows = connection.execute(
            "SELECT * FROM custody_metadata ORDER BY singleton"
        ).fetchall()
        expected_metadata = (
            1,
            APPLICATION_ID,
            SCHEMA_VERSION,
            MIGRATION_ID,
            MIGRATION_SHA256,
            EXPECTED_SCHEMA_MANIFEST_SHA256,
            self.trust_root.trust_root_id,
            self.trust_root.trust_root_sha256,
        )
        if len(metadata_rows) != 1 or tuple(metadata_rows[0]) != expected_metadata:
            raise TargetHealthCustodyIntegrityError("custody metadata is invalid")
        root = self._load_root(connection)
        if root != self.trust_root:
            raise TargetHealthCustodyIntegrityError("pinned target health trust root changed")

    @staticmethod
    def _parse_document(document: str, expected_type: type[Any], label: str) -> Any:
        if not isinstance(document, str):
            raise TargetHealthCustodyIntegrityError(f"stored {label} is not text")
        try:
            parsed = parse_target_health_custody_document(document)
        except (TypeError, ValueError) as exc:
            raise TargetHealthCustodyIntegrityError(f"stored {label} is invalid") from exc
        if not isinstance(parsed, expected_type) or _document(parsed) != document:
            raise TargetHealthCustodyIntegrityError(f"stored {label} is invalid")
        return parsed

    def _load_root(self, connection: sqlite3.Connection) -> TargetHealthTrustRoot:
        rows = connection.execute("SELECT * FROM target_health_trust_roots").fetchall()
        if len(rows) != 1:
            raise TargetHealthCustodyIntegrityError("pinned trust root inventory is invalid")
        row = rows[0]
        root = self._parse_document(row["root_json"], TargetHealthTrustRoot, "trust root")
        expected = (
            root.trust_root_id,
            root.trust_root_sha256,
            root.tenant_id,
            root.mission_id,
            root.trust_root_revision,
            _document(root),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("pinned trust root row is invalid")
        return root

    @staticmethod
    def _load_policy_row(row: sqlite3.Row) -> TargetHealthCollectorPolicyRevision:
        policy = SQLiteTargetHealthCustody._parse_document(
            row["policy_json"], TargetHealthCollectorPolicyRevision, "collector policy"
        )
        expected = (
            row["transition_sequence"],
            policy.policy_id,
            policy.policy_sha256,
            policy.tenant_id,
            policy.mission_id,
            policy.trust_root_id,
            policy.trust_root_sha256,
            policy.trust_root_revision,
            policy.chain_id,
            policy.binding_sha256,
            policy.collector_id,
            policy.collector_epoch,
            policy.policy_revision,
            policy.predecessor_policy_id,
            policy.predecessor_policy_sha256,
            policy.prior_epoch_head_envelope_id,
            policy.prior_epoch_head_envelope_sha256,
            row["published_at"],
            _document(policy),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("stored collector policy row is invalid")
        _instant(row["published_at"])
        return policy

    @staticmethod
    def _load_revocation_row(row: sqlite3.Row) -> TargetHealthCollectorPolicyRevocation:
        revocation = SQLiteTargetHealthCustody._parse_document(
            row["revocation_json"],
            TargetHealthCollectorPolicyRevocation,
            "collector policy revocation",
        )
        expected = (
            row["transition_sequence"],
            revocation.revocation_id,
            revocation.revocation_sha256,
            revocation.tenant_id,
            revocation.mission_id,
            revocation.trust_root_id,
            revocation.trust_root_sha256,
            revocation.trust_root_revision,
            revocation.chain_id,
            revocation.policy_id,
            revocation.policy_sha256,
            revocation.policy_revision,
            revocation.collector_epoch,
            revocation.revoked_at,
            row["published_at"],
            _document(revocation),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("stored policy revocation row is invalid")
        _instant(row["published_at"])
        return revocation

    @staticmethod
    def _load_envelope_row(row: sqlite3.Row) -> SignedTargetHealthCustodyEnvelopeV2:
        envelope = SQLiteTargetHealthCustody._parse_document(
            row["envelope_json"], SignedTargetHealthCustodyEnvelopeV2, "custody envelope"
        )
        expected = (
            row["transition_sequence"],
            envelope.envelope_id,
            envelope.envelope_sha256,
            envelope.tenant_id,
            envelope.mission_id,
            envelope.chain_id,
            envelope.binding_sha256,
            envelope.collector_id,
            envelope.collector_epoch,
            envelope.sequence,
            envelope.predecessor_envelope_id,
            envelope.predecessor_envelope_sha256,
            envelope.policy_id,
            envelope.policy_sha256,
            envelope.policy_revision,
            envelope.receipt_id,
            envelope.receipt_sha256,
            _signing_payload_sha256(envelope),
            envelope.observed_at,
            row["accepted_at"],
            _document(envelope),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("stored custody envelope row is invalid")
        _instant(row["accepted_at"])
        return envelope

    @staticmethod
    def _load_receipt_row(row: sqlite3.Row) -> TargetHealthCustodyReceipt:
        receipt = SQLiteTargetHealthCustody._parse_document(
            row["receipt_json"], TargetHealthCustodyReceipt, "custody receipt"
        )
        body = receipt.body()
        expected = (
            receipt.custody_receipt_id,
            receipt.custody_receipt_sha256,
            body["tenant_id"],
            body["mission_id"],
            body["chain_id"],
            body["sequence"],
            body["envelope_id"],
            body["envelope_sha256"],
            receipt.recorded_at,
            _document(receipt),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("stored custody receipt row is invalid")
        return receipt

    @staticmethod
    def _load_event_row(row: sqlite3.Row) -> TargetHealthCustodyEvent:
        event = SQLiteTargetHealthCustody._parse_document(
            row["event_json"], TargetHealthCustodyEvent, "custody event"
        )
        expected = (
            event.event_id,
            event.event_sha256,
            event.tenant_id,
            event.mission_id,
            event.chain_id,
            event.event_sequence,
            event.predecessor_event_id,
            event.predecessor_event_sha256,
            event.custody_receipt_id,
            event.custody_receipt_sha256,
            event.envelope_id,
            event.envelope_sha256,
            event.recorded_at,
            _document(event),
        )
        if tuple(row) != expected:
            raise TargetHealthCustodyIntegrityError("stored custody event row is invalid")
        return event

    @staticmethod
    def _verify_materialized_heads(connection: sqlite3.Connection) -> None:
        expected_policies = connection.execute(
            "SELECT p.chain_id,p.tenant_id,p.mission_id,p.policy_id,p.policy_sha256,"
            "p.policy_revision,p.collector_epoch,p.transition_sequence "
            "FROM target_health_collector_policies p WHERE NOT EXISTS ("
            "SELECT 1 FROM target_health_collector_policies newer "
            "WHERE newer.chain_id=p.chain_id "
            "AND newer.transition_sequence>p.transition_sequence) ORDER BY p.chain_id"
        ).fetchall()
        actual_policies = connection.execute(
            "SELECT chain_id,tenant_id,mission_id,policy_id,policy_sha256,"
            "policy_revision,collector_epoch,transition_sequence "
            "FROM target_health_policy_heads ORDER BY chain_id"
        ).fetchall()
        if [tuple(row) for row in actual_policies] != [
            tuple(row) for row in expected_policies
        ]:
            raise TargetHealthCustodyIntegrityError("collector policy heads are invalid")
        expected_revocations = connection.execute(
            "SELECT policy_id,chain_id,tenant_id,mission_id,revocation_id,"
            "revocation_sha256,revoked_at,transition_sequence "
            "FROM target_health_collector_policy_revocations ORDER BY policy_id"
        ).fetchall()
        actual_revocations = connection.execute(
            "SELECT policy_id,chain_id,tenant_id,mission_id,revocation_id,"
            "revocation_sha256,revoked_at,transition_sequence "
            "FROM target_health_policy_revocation_heads ORDER BY policy_id"
        ).fetchall()
        if [tuple(row) for row in actual_revocations] != [
            tuple(row) for row in expected_revocations
        ]:
            raise TargetHealthCustodyIntegrityError("policy revocation heads are invalid")
        expected_chains = connection.execute(
            "SELECT e.chain_id,e.tenant_id,e.mission_id,e.binding_sha256,e.collector_id,"
            "e.collector_epoch,e.sequence,e.envelope_id,e.envelope_sha256,"
            "r.custody_receipt_id,r.custody_receipt_sha256,e.policy_id,e.policy_sha256,"
            "e.transition_sequence FROM target_health_envelopes e "
            "JOIN target_health_custody_receipts r ON r.envelope_id=e.envelope_id "
            "WHERE NOT EXISTS (SELECT 1 FROM target_health_envelopes newer "
            "WHERE newer.chain_id=e.chain_id AND newer.transition_sequence>e.transition_sequence) "
            "ORDER BY e.chain_id"
        ).fetchall()
        actual_chains = connection.execute(
            "SELECT chain_id,tenant_id,mission_id,binding_sha256,collector_id,"
            "collector_epoch,sequence,envelope_id,envelope_sha256,custody_receipt_id,"
            "custody_receipt_sha256,policy_id,policy_sha256,transition_sequence "
            "FROM target_health_chain_heads ORDER BY chain_id"
        ).fetchall()
        if [tuple(row) for row in actual_chains] != [tuple(row) for row in expected_chains]:
            raise TargetHealthCustodyIntegrityError("custody chain heads are invalid")
        expected_events = connection.execute(
            "SELECT e.chain_id,e.tenant_id,e.mission_id,e.event_sequence,e.event_id,"
            "e.event_sha256 FROM target_health_custody_events e WHERE NOT EXISTS ("
            "SELECT 1 FROM target_health_custody_events newer "
            "WHERE newer.chain_id=e.chain_id AND newer.event_sequence>e.event_sequence) "
            "ORDER BY e.chain_id"
        ).fetchall()
        actual_events = connection.execute(
            "SELECT chain_id,tenant_id,mission_id,event_sequence,event_id,event_sha256 "
            "FROM target_health_event_heads ORDER BY chain_id"
        ).fetchall()
        if [tuple(row) for row in actual_events] != [tuple(row) for row in expected_events]:
            raise TargetHealthCustodyIntegrityError("custody event heads are invalid")

    @staticmethod
    def _last_transition(connection: sqlite3.Connection) -> tuple[int, str] | None:
        row = connection.execute(
            "SELECT transition_sequence,recorded_at FROM ("
            "SELECT transition_sequence,published_at AS recorded_at "
            "FROM target_health_collector_policies UNION ALL "
            "SELECT transition_sequence,published_at AS recorded_at "
            "FROM target_health_collector_policy_revocations UNION ALL "
            "SELECT transition_sequence,accepted_at AS recorded_at "
            "FROM target_health_envelopes) ORDER BY transition_sequence DESC LIMIT 1"
        ).fetchone()
        return None if row is None else (row["transition_sequence"], row["recorded_at"])

    @classmethod
    def _next_transition(cls, connection: sqlite3.Connection) -> int:
        last = cls._last_transition(connection)
        return 1 if last is None else last[0] + 1

    @classmethod
    def _require_nonregressing_time(
        cls, connection: sqlite3.Connection, trusted_at: str
    ) -> None:
        last = cls._last_transition(connection)
        if last is not None and _instant(trusted_at) < _instant(last[1]):
            raise TargetHealthCustodyIntegrityError("trusted clock regressed")

    @staticmethod
    def _mutation_checkpoint(name: str) -> None:
        del name

    def publish_policy(
        self, policy: TargetHealthCollectorPolicyRevision
    ) -> TargetHealthCollectorPolicyRevision:
        if not isinstance(policy, TargetHealthCollectorPolicyRevision):
            raise TargetHealthCustodyValidationError("policy is invalid")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT * FROM target_health_collector_policies WHERE policy_id = ?",
                (policy.policy_id,),
            ).fetchone()
            if existing is not None:
                stored = self._load_policy_row(existing)
                if stored != policy:
                    raise TargetHealthCustodyIntegrityError("policy identity was substituted")
                self._verify_history(connection)
                replay_revocation = self._load_revocation_for_policy(
                    connection, stored.policy_id
                )
                replay_at = self._trusted_now()
                self._require_nonregressing_time(connection, replay_at)
                head = connection.execute(
                    "SELECT policy_id,policy_sha256 FROM target_health_policy_heads "
                    "WHERE chain_id=?",
                    (stored.chain_id,),
                ).fetchone()
                if (
                    head is None
                    or head["policy_id"] != stored.policy_id
                    or head["policy_sha256"] != stored.policy_sha256
                ):
                    raise TargetHealthCustodyConflictError(
                        "replayed collector policy is not current"
                    )
                if self._revocation_effective(replay_revocation, replay_at):
                    raise TargetHealthCustodyConflictError(
                        "collector policy is terminally revoked"
                    )
                try:
                    verify_target_health_collector_policy(
                        self._load_root(connection),
                        stored,
                        verified_at=replay_at,
                        current=True,
                    )
                except TargetHealthCustodyContractError as exc:
                    raise TargetHealthCustodyConflictError(
                        "replayed collector policy is not current"
                    ) from exc
                return stored
            root = self._load_root(connection)
            if policy.tenant_id != root.tenant_id or policy.mission_id != root.mission_id:
                raise TargetHealthCustodyConflictError("policy is outside the pinned root scope")
            head_row = connection.execute(
                "SELECT p.* FROM target_health_policy_heads h "
                "JOIN target_health_collector_policies p ON p.policy_id = h.policy_id "
                "WHERE h.chain_id = ?",
                (policy.chain_id,),
            ).fetchone()
            previous = None if head_row is None else self._load_policy_row(head_row)
            previous_revocation = (
                None
                if previous is None
                else self._load_revocation_for_policy(connection, previous.policy_id)
            )
            envelope_head = connection.execute(
                "SELECT * FROM target_health_chain_heads WHERE chain_id = ?",
                (policy.chain_id,),
            ).fetchone()
            self._require_policy_transition(policy, previous, envelope_head)
            initial_at = self._trusted_now()
            self._require_nonregressing_time(connection, initial_at)
            self._require_revoked_policy_replacement(
                policy, previous, previous_revocation, initial_at
            )
            try:
                verify_target_health_collector_policy(
                    root, policy, verified_at=initial_at, current=True
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "collector policy verification failed"
                ) from exc
            final_at = self._trusted_now()
            if _instant(final_at) < _instant(initial_at):
                raise TargetHealthCustodyIntegrityError("trusted clock regressed")
            self._require_nonregressing_time(connection, final_at)
            self._require_revoked_policy_replacement(
                policy, previous, previous_revocation, final_at
            )
            try:
                verify_target_health_collector_policy(
                    root, policy, verified_at=final_at, current=True
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "collector policy verification failed"
                ) from exc
            transition = self._next_transition(connection)
            connection.execute(
                "INSERT INTO target_health_collector_policies "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    transition,
                    policy.policy_id,
                    policy.policy_sha256,
                    policy.tenant_id,
                    policy.mission_id,
                    policy.trust_root_id,
                    policy.trust_root_sha256,
                    policy.trust_root_revision,
                    policy.chain_id,
                    policy.binding_sha256,
                    policy.collector_id,
                    policy.collector_epoch,
                    policy.policy_revision,
                    policy.predecessor_policy_id,
                    policy.predecessor_policy_sha256,
                    policy.prior_epoch_head_envelope_id,
                    policy.prior_epoch_head_envelope_sha256,
                    final_at,
                    _document(policy),
                ),
            )
            self._mutation_checkpoint("after_policy_insert")
            if previous is None:
                connection.execute(
                    "INSERT INTO target_health_policy_heads VALUES(?,?,?,?,?,?,?,?)",
                    (
                        policy.chain_id,
                        policy.tenant_id,
                        policy.mission_id,
                        policy.policy_id,
                        policy.policy_sha256,
                        policy.policy_revision,
                        policy.collector_epoch,
                        transition,
                    ),
                )
            else:
                changed = connection.execute(
                    "UPDATE target_health_policy_heads SET policy_id=?,policy_sha256=?,"
                    "policy_revision=?,collector_epoch=?,transition_sequence=? "
                    "WHERE chain_id=? AND policy_id=? AND policy_sha256=? "
                    "AND policy_revision=? AND transition_sequence=?",
                    (
                        policy.policy_id,
                        policy.policy_sha256,
                        policy.policy_revision,
                        policy.collector_epoch,
                        transition,
                        policy.chain_id,
                        previous.policy_id,
                        previous.policy_sha256,
                        previous.policy_revision,
                        head_row["transition_sequence"],
                    ),
                ).rowcount
                if changed != 1:
                    raise TargetHealthCustodyConflictError("collector policy head changed")
            self._mutation_checkpoint("after_policy_head")
            self._mutation_checkpoint("before_commit")
            return policy

    @classmethod
    def _require_revoked_policy_replacement(
        cls,
        policy: TargetHealthCollectorPolicyRevision,
        previous: TargetHealthCollectorPolicyRevision | None,
        revocation: TargetHealthCollectorPolicyRevocation | None,
        trusted_at: str,
    ) -> None:
        if previous is None or not cls._revocation_effective(revocation, trusted_at):
            return
        if (
            policy.collector_epoch != previous.collector_epoch + 1
            or policy.collector_key_id == previous.collector_key_id
            or policy.collector_public_key == previous.collector_public_key
            or policy.collector_public_key_sha256
            == previous.collector_public_key_sha256
        ):
            raise TargetHealthCustodyConflictError(
                "revoked policy requires a replacement collector epoch and key"
            )

    @staticmethod
    def _load_revocation_for_policy(
        connection: sqlite3.Connection, policy_id: str
    ) -> TargetHealthCollectorPolicyRevocation | None:
        rows = connection.execute(
            "SELECT * FROM target_health_collector_policy_revocations WHERE policy_id=?",
            (policy_id,),
        ).fetchall()
        if len(rows) > 1:
            raise TargetHealthCustodyIntegrityError("policy revocation inventory is invalid")
        return None if not rows else SQLiteTargetHealthCustody._load_revocation_row(rows[0])

    @staticmethod
    def _revocation_effective(
        revocation: TargetHealthCollectorPolicyRevocation | None,
        trusted_at: str,
    ) -> bool:
        return revocation is not None and _instant(trusted_at) >= _instant(
            revocation.revoked_at
        )

    def publish_revocation(
        self, revocation: TargetHealthCollectorPolicyRevocation
    ) -> TargetHealthCollectorPolicyRevocation:
        if not isinstance(revocation, TargetHealthCollectorPolicyRevocation):
            raise TargetHealthCustodyValidationError("revocation is invalid")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT * FROM target_health_collector_policy_revocations "
                "WHERE revocation_id=?",
                (revocation.revocation_id,),
            ).fetchone()
            if existing is not None:
                stored = self._load_revocation_row(existing)
                if stored != revocation:
                    raise TargetHealthCustodyIntegrityError(
                        "policy revocation identity was substituted"
                    )
                self._verify_history(connection)
                return stored
            root = self._load_root(connection)
            policy_row = connection.execute(
                "SELECT * FROM target_health_collector_policies "
                "WHERE chain_id=? AND policy_id=? AND policy_sha256=?",
                (revocation.chain_id, revocation.policy_id, revocation.policy_sha256),
            ).fetchone()
            if policy_row is None:
                raise TargetHealthCustodyConflictError(
                    "revocation policy lineage was not found"
                )
            policy = self._load_policy_row(policy_row)
            prior = self._load_revocation_for_policy(connection, policy.policy_id)
            if prior is not None:
                raise TargetHealthCustodyConflictError("collector policy is already revoked")
            initial_at = self._trusted_now()
            self._require_nonregressing_time(connection, initial_at)
            try:
                verify_target_health_collector_policy_revocation(
                    root, policy, revocation
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "collector policy revocation verification failed"
                ) from exc
            final_at = self._trusted_now()
            if _instant(final_at) < _instant(initial_at):
                raise TargetHealthCustodyIntegrityError("trusted clock regressed")
            self._require_nonregressing_time(connection, final_at)
            try:
                verify_target_health_collector_policy_revocation(
                    root, policy, revocation
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "collector policy revocation verification failed"
                ) from exc
            transition = self._next_transition(connection)
            connection.execute(
                "INSERT INTO target_health_collector_policy_revocations "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    transition,
                    revocation.revocation_id,
                    revocation.revocation_sha256,
                    revocation.tenant_id,
                    revocation.mission_id,
                    revocation.trust_root_id,
                    revocation.trust_root_sha256,
                    revocation.trust_root_revision,
                    revocation.chain_id,
                    revocation.policy_id,
                    revocation.policy_sha256,
                    revocation.policy_revision,
                    revocation.collector_epoch,
                    revocation.revoked_at,
                    final_at,
                    _document(revocation),
                ),
            )
            self._mutation_checkpoint("after_revocation_insert")
            connection.execute(
                "INSERT INTO target_health_policy_revocation_heads VALUES(?,?,?,?,?,?,?,?)",
                (
                    revocation.policy_id,
                    revocation.chain_id,
                    revocation.tenant_id,
                    revocation.mission_id,
                    revocation.revocation_id,
                    revocation.revocation_sha256,
                    revocation.revoked_at,
                    transition,
                ),
            )
            self._mutation_checkpoint("after_revocation_head")
            self._mutation_checkpoint("before_commit")
            return revocation

    @staticmethod
    def _require_policy_transition(
        policy: TargetHealthCollectorPolicyRevision,
        previous: TargetHealthCollectorPolicyRevision | None,
        envelope_head: sqlite3.Row | None,
    ) -> None:
        if previous is None:
            if (
                policy.policy_revision != 1
                or policy.collector_epoch != 1
                or policy.predecessor_policy_id is not None
                or envelope_head is not None
            ):
                raise TargetHealthCustodyConflictError("first collector policy is invalid")
            return
        if (
            policy.tenant_id != previous.tenant_id
            or policy.mission_id != previous.mission_id
            or policy.binding != previous.binding
            or policy.binding_sha256 != previous.binding_sha256
            or policy.collector_id != previous.collector_id
            or policy.chain_id != previous.chain_id
            or policy.trust_root_id != previous.trust_root_id
            or policy.trust_root_sha256 != previous.trust_root_sha256
            or policy.trust_root_revision != previous.trust_root_revision
        ):
            raise TargetHealthCustodyConflictError("collector policy lineage changed")
        if (
            policy.policy_revision != previous.policy_revision + 1
            or policy.predecessor_policy_id != previous.policy_id
            or policy.predecessor_policy_sha256 != previous.policy_sha256
        ):
            raise TargetHealthCustodyConflictError("collector policy predecessor is stale")
        if policy.collector_epoch not in {
            previous.collector_epoch,
            previous.collector_epoch + 1,
        }:
            raise TargetHealthCustodyConflictError("collector epoch is not contiguous")
        if policy.collector_epoch == previous.collector_epoch:
            if (
                policy.collector_key_id != previous.collector_key_id
                or policy.collector_public_key != previous.collector_public_key
                or policy.collector_public_key_sha256
                != previous.collector_public_key_sha256
                or policy.prior_epoch_head_envelope_id
                != previous.prior_epoch_head_envelope_id
                or policy.prior_epoch_head_envelope_sha256
                != previous.prior_epoch_head_envelope_sha256
            ):
                raise TargetHealthCustodyConflictError(
                    "same collector epoch changed key or prior head"
                )
        else:
            if envelope_head is None:
                raise TargetHealthCustodyConflictError(
                    "new collector epoch requires a durable envelope head"
                )
            if (
                policy.prior_epoch_head_envelope_id != envelope_head["envelope_id"]
                or policy.prior_epoch_head_envelope_sha256
                != envelope_head["envelope_sha256"]
            ):
                raise TargetHealthCustodyConflictError(
                    "new collector epoch prior head is stale"
                )
            if (
                policy.collector_key_id == previous.collector_key_id
                or policy.collector_public_key == previous.collector_public_key
                or policy.collector_public_key_sha256
                == previous.collector_public_key_sha256
            ):
                raise TargetHealthCustodyConflictError(
                    "new collector epoch must use a distinct key"
                )

    def prepare_signing_context(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        collector_id: str,
        binding_sha256: str,
    ) -> TargetHealthSigningContext:
        _identifier(tenant_id, "tenant_id")
        _identifier(mission_id, "mission_id")
        _identifier(collector_id, "collector_id")
        _digest(binding_sha256, "binding_sha256")
        chain_id = target_health_chain_id(collector_id, mission_id, binding_sha256)
        with self._read() as connection:
            policy_row = connection.execute(
                "SELECT p.* FROM target_health_policy_heads h "
                "JOIN target_health_collector_policies p ON p.policy_id=h.policy_id "
                "WHERE h.tenant_id=? AND h.mission_id=? AND h.chain_id=?",
                (tenant_id, mission_id, chain_id),
            ).fetchone()
            if policy_row is None:
                raise TargetHealthCustodyNotFoundError("current collector policy was not found")
            policy = self._load_policy_row(policy_row)
            if policy.binding_sha256 != binding_sha256 or policy.collector_id != collector_id:
                raise TargetHealthCustodyIntegrityError("collector policy head is substituted")
            prepared_at = self._trusted_now()
            self._require_nonregressing_time(connection, prepared_at)
            revocation = self._load_revocation_for_policy(connection, policy.policy_id)
            if self._revocation_effective(revocation, prepared_at):
                raise TargetHealthCustodyConflictError(
                    "collector policy is terminally revoked"
                )
            try:
                verify_target_health_collector_policy(
                    self._load_root(connection),
                    policy,
                    verified_at=prepared_at,
                    current=True,
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "collector policy is not current"
                ) from exc
            head = connection.execute(
                "SELECT * FROM target_health_chain_heads WHERE tenant_id=? "
                "AND mission_id=? AND chain_id=?",
                (tenant_id, mission_id, chain_id),
            ).fetchone()
            sequence = 0 if head is None else head["sequence"]
            envelope_id = None if head is None else head["envelope_id"]
            envelope_sha256 = None if head is None else head["envelope_sha256"]
            try:
                return TargetHealthSigningContext(
                    tenant_id=tenant_id,
                    mission_id=mission_id,
                    binding_sha256=binding_sha256,
                    policy_id=policy.policy_id,
                    policy_sha256=policy.policy_sha256,
                    policy_revision=policy.policy_revision,
                    collector_id=collector_id,
                    collector_epoch=policy.collector_epoch,
                    chain_id=chain_id,
                    next_sequence=sequence + 1,
                    previous_envelope_id=envelope_id,
                    previous_envelope_sha256=envelope_sha256,
                    current_head_sequence=sequence,
                    current_head_envelope_id=envelope_id,
                    current_head_envelope_sha256=envelope_sha256,
                    prepared_at=prepared_at,
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyIntegrityError(
                    "durable signing context could not be reconstructed"
                ) from exc

    def append_envelope(
        self, envelope: SignedTargetHealthCustodyEnvelopeV2
    ) -> TargetHealthAppendResult:
        if not isinstance(envelope, SignedTargetHealthCustodyEnvelopeV2):
            raise TargetHealthCustodyValidationError("envelope is invalid")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT * FROM target_health_envelopes WHERE envelope_id=?",
                (envelope.envelope_id,),
            ).fetchone()
            if existing is not None:
                return self._load_replay(connection, envelope, existing)
            root = self._load_root(connection)
            if envelope.tenant_id != root.tenant_id or envelope.mission_id != root.mission_id:
                raise TargetHealthCustodyConflictError("envelope is outside pinned root scope")
            policy_row = connection.execute(
                "SELECT p.* FROM target_health_policy_heads h "
                "JOIN target_health_collector_policies p ON p.policy_id=h.policy_id "
                "WHERE h.chain_id=?",
                (envelope.chain_id,),
            ).fetchone()
            if policy_row is None:
                raise TargetHealthCustodyConflictError("envelope has no current policy")
            policy = self._load_policy_row(policy_row)
            if (
                envelope.policy_id != policy.policy_id
                or envelope.policy_sha256 != policy.policy_sha256
            ):
                raise TargetHealthCustodyConflictError("envelope policy is not current")
            revocation = self._load_revocation_for_policy(connection, policy.policy_id)
            head_row = connection.execute(
                "SELECT e.* FROM target_health_chain_heads h "
                "JOIN target_health_envelopes e ON e.envelope_id=h.envelope_id "
                "WHERE h.chain_id=?",
                (envelope.chain_id,),
            ).fetchone()
            previous = None if head_row is None else self._load_envelope_row(head_row)
            self._require_envelope_transition(envelope, previous)
            duplicate = connection.execute(
                "SELECT envelope_id FROM target_health_envelopes "
                "WHERE receipt_id=? OR signing_payload_sha256=? LIMIT 1",
                (envelope.receipt_id, _signing_payload_sha256(envelope)),
            ).fetchone()
            if duplicate is not None:
                raise TargetHealthCustodyConflictError(
                    "receipt or signing payload was already accepted"
                )
            initial_at = self._trusted_now()
            self._require_nonregressing_time(connection, initial_at)
            self._verify_current(root, policy, envelope, initial_at, revocation)
            final_at = self._trusted_now()
            if _instant(final_at) < _instant(initial_at):
                raise TargetHealthCustodyIntegrityError("trusted clock regressed")
            self._require_nonregressing_time(connection, final_at)
            verification = self._verify_current(
                root, policy, envelope, final_at, revocation
            )
            try:
                receipt = build_target_health_custody_receipt(
                    verification, recorded_at=final_at
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyConflictError(
                    "custody acceptance chronology is invalid"
                ) from exc
            event_head = connection.execute(
                "SELECT * FROM target_health_event_heads WHERE chain_id=?",
                (envelope.chain_id,),
            ).fetchone()
            event_sequence = 1 if event_head is None else event_head["event_sequence"] + 1
            if event_sequence != envelope.sequence:
                raise TargetHealthCustodyIntegrityError("event and envelope heads diverged")
            try:
                event = build_target_health_custody_event(
                    receipt,
                    event_sequence=event_sequence,
                    predecessor_event_id=(
                        None if event_head is None else event_head["event_id"]
                    ),
                    predecessor_event_sha256=(
                        None if event_head is None else event_head["event_sha256"]
                    ),
                    recorded_at=final_at,
                )
            except TargetHealthCustodyContractError as exc:
                raise TargetHealthCustodyIntegrityError(
                    "custody event could not be constructed"
                ) from exc
            transition = self._next_transition(connection)
            connection.execute(
                "INSERT INTO target_health_envelopes "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    transition,
                    envelope.envelope_id,
                    envelope.envelope_sha256,
                    envelope.tenant_id,
                    envelope.mission_id,
                    envelope.chain_id,
                    envelope.binding_sha256,
                    envelope.collector_id,
                    envelope.collector_epoch,
                    envelope.sequence,
                    envelope.predecessor_envelope_id,
                    envelope.predecessor_envelope_sha256,
                    envelope.policy_id,
                    envelope.policy_sha256,
                    envelope.policy_revision,
                    envelope.receipt_id,
                    envelope.receipt_sha256,
                    _signing_payload_sha256(envelope),
                    envelope.observed_at,
                    final_at,
                    _document(envelope),
                ),
            )
            self._mutation_checkpoint("after_envelope_insert")
            connection.execute(
                "INSERT INTO target_health_custody_receipts VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    receipt.custody_receipt_id,
                    receipt.custody_receipt_sha256,
                    envelope.tenant_id,
                    envelope.mission_id,
                    envelope.chain_id,
                    envelope.sequence,
                    envelope.envelope_id,
                    envelope.envelope_sha256,
                    receipt.recorded_at,
                    _document(receipt),
                ),
            )
            self._mutation_checkpoint("after_receipt_insert")
            connection.execute(
                "INSERT INTO target_health_custody_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.event_id,
                    event.event_sha256,
                    event.tenant_id,
                    event.mission_id,
                    event.chain_id,
                    event.event_sequence,
                    event.predecessor_event_id,
                    event.predecessor_event_sha256,
                    event.custody_receipt_id,
                    event.custody_receipt_sha256,
                    event.envelope_id,
                    event.envelope_sha256,
                    event.recorded_at,
                    _document(event),
                ),
            )
            self._mutation_checkpoint("after_event_insert")
            self._write_chain_head(connection, envelope, receipt, transition, previous)
            self._write_event_head(connection, event, event_head)
            self._mutation_checkpoint("after_heads")
            self._mutation_checkpoint("before_commit")
            return TargetHealthAppendResult(receipt=receipt, event=event, replayed=False)

    @staticmethod
    def _verify_current(
        root: TargetHealthTrustRoot,
        policy: TargetHealthCollectorPolicyRevision,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        trusted_at: str,
        revocation: TargetHealthCollectorPolicyRevocation | None,
    ) -> TargetHealthCustodyVerificationResult:
        try:
            return verify_target_health_custody_envelope_current(
                root,
                policy,
                envelope,
                verified_at=trusted_at,
                expected_policy_id=policy.policy_id,
                expected_policy_sha256=policy.policy_sha256,
                expected_head_envelope_id=envelope.envelope_id,
                expected_head_envelope_sha256=envelope.envelope_sha256,
                expected_head_sequence=envelope.sequence,
                policy_revocation=revocation,
            )
        except TargetHealthCustodyContractError as exc:
            raise TargetHealthCustodyConflictError(
                "custody envelope current verification failed"
            ) from exc

    @staticmethod
    def _require_envelope_transition(
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        previous: SignedTargetHealthCustodyEnvelopeV2 | None,
    ) -> None:
        if previous is None:
            if (
                envelope.sequence != 1
                or envelope.predecessor_envelope_id is not None
                or envelope.collector_epoch != 1
            ):
                raise TargetHealthCustodyConflictError("first custody envelope is invalid")
            return
        if (
            envelope.tenant_id != previous.tenant_id
            or envelope.mission_id != previous.mission_id
            or envelope.binding != previous.binding
            or envelope.binding_sha256 != previous.binding_sha256
            or envelope.collector_id != previous.collector_id
            or envelope.chain_id != previous.chain_id
        ):
            raise TargetHealthCustodyConflictError("custody envelope lineage changed")
        if (
            envelope.sequence != previous.sequence + 1
            or envelope.predecessor_envelope_id != previous.envelope_id
            or envelope.predecessor_envelope_sha256 != previous.envelope_sha256
        ):
            raise TargetHealthCustodyConflictError("custody envelope predecessor is stale")
        if envelope.collector_epoch not in {
            previous.collector_epoch,
            previous.collector_epoch + 1,
        }:
            raise TargetHealthCustodyConflictError("envelope collector epoch is not contiguous")
        if envelope.receipt.monotonic_tick <= previous.receipt.monotonic_tick:
            raise TargetHealthCustodyConflictError("receipt monotonic tick did not advance")
        if _instant(envelope.observed_at) < _instant(previous.observed_at):
            raise TargetHealthCustodyConflictError("receipt observation time regressed")

    def _load_replay(
        self,
        connection: sqlite3.Connection,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        envelope_row: sqlite3.Row,
    ) -> TargetHealthAppendResult:
        stored = self._load_envelope_row(envelope_row)
        if stored != envelope:
            raise TargetHealthCustodyIntegrityError("envelope identity was substituted")
        receipt_rows = connection.execute(
            "SELECT * FROM target_health_custody_receipts WHERE envelope_id=?",
            (envelope.envelope_id,),
        ).fetchall()
        event_rows = connection.execute(
            "SELECT * FROM target_health_custody_events WHERE envelope_id=?",
            (envelope.envelope_id,),
        ).fetchall()
        if len(receipt_rows) != 1 or len(event_rows) != 1:
            raise TargetHealthCustodyIntegrityError("replayed envelope custody is incomplete")
        receipt = self._load_receipt_row(receipt_rows[0])
        event = self._load_event_row(event_rows[0])
        if (
            event.custody_receipt_id != receipt.custody_receipt_id
            or event.custody_receipt_sha256 != receipt.custody_receipt_sha256
        ):
            raise TargetHealthCustodyIntegrityError("replayed envelope custody is inconsistent")
        self._verify_history(connection)
        policy_row = connection.execute(
            "SELECT * FROM target_health_collector_policies WHERE policy_id=?",
            (envelope.policy_id,),
        ).fetchone()
        if policy_row is None:
            raise TargetHealthCustodyIntegrityError("replayed envelope policy is missing")
        policy = self._load_policy_row(policy_row)
        revocation = self._load_revocation_for_policy(connection, policy.policy_id)
        replay_at = self._trusted_now()
        self._require_nonregressing_time(connection, replay_at)
        policy_head = connection.execute(
            "SELECT policy_id,policy_sha256 FROM target_health_policy_heads "
            "WHERE chain_id=?",
            (envelope.chain_id,),
        ).fetchone()
        envelope_head = connection.execute(
            "SELECT envelope_id,envelope_sha256,sequence FROM target_health_chain_heads "
            "WHERE chain_id=?",
            (envelope.chain_id,),
        ).fetchone()
        if (
            policy_head is None
            or policy_head["policy_id"] != policy.policy_id
            or policy_head["policy_sha256"] != policy.policy_sha256
            or envelope_head is None
            or envelope_head["envelope_id"] != envelope.envelope_id
            or envelope_head["envelope_sha256"] != envelope.envelope_sha256
            or envelope_head["sequence"] != envelope.sequence
        ):
            raise TargetHealthCustodyConflictError(
                "replayed envelope is not the current durable head"
            )
        if self._revocation_effective(revocation, replay_at):
            raise TargetHealthCustodyConflictError(
                "replayed envelope policy is terminally revoked"
            )
        self._verify_current(root=self._load_root(connection), policy=policy,
            envelope=envelope, trusted_at=replay_at, revocation=revocation)
        return TargetHealthAppendResult(receipt=receipt, event=event, replayed=True)

    @staticmethod
    def _write_chain_head(
        connection: sqlite3.Connection,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        receipt: TargetHealthCustodyReceipt,
        transition: int,
        previous: SignedTargetHealthCustodyEnvelopeV2 | None,
    ) -> None:
        values = (
            envelope.collector_epoch,
            envelope.sequence,
            envelope.envelope_id,
            envelope.envelope_sha256,
            receipt.custody_receipt_id,
            receipt.custody_receipt_sha256,
            envelope.policy_id,
            envelope.policy_sha256,
            transition,
        )
        if previous is None:
            connection.execute(
                "INSERT INTO target_health_chain_heads VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    envelope.chain_id,
                    envelope.tenant_id,
                    envelope.mission_id,
                    envelope.binding_sha256,
                    envelope.collector_id,
                    *values,
                ),
            )
            return
        changed = connection.execute(
            "UPDATE target_health_chain_heads SET collector_epoch=?,sequence=?,"
            "envelope_id=?,envelope_sha256=?,custody_receipt_id=?,"
            "custody_receipt_sha256=?,policy_id=?,policy_sha256=?,transition_sequence=? "
            "WHERE chain_id=? AND envelope_id=? AND envelope_sha256=? AND sequence=?",
            (
                *values,
                envelope.chain_id,
                previous.envelope_id,
                previous.envelope_sha256,
                previous.sequence,
            ),
        ).rowcount
        if changed != 1:
            raise TargetHealthCustodyConflictError("custody envelope head changed")

    @staticmethod
    def _write_event_head(
        connection: sqlite3.Connection,
        event: TargetHealthCustodyEvent,
        previous: sqlite3.Row | None,
    ) -> None:
        if previous is None:
            connection.execute(
                "INSERT INTO target_health_event_heads VALUES(?,?,?,?,?,?)",
                (
                    event.chain_id,
                    event.tenant_id,
                    event.mission_id,
                    event.event_sequence,
                    event.event_id,
                    event.event_sha256,
                ),
            )
            return
        changed = connection.execute(
            "UPDATE target_health_event_heads SET event_sequence=?,event_id=?,event_sha256=? "
            "WHERE chain_id=? AND event_sequence=? AND event_id=? AND event_sha256=?",
            (
                event.event_sequence,
                event.event_id,
                event.event_sha256,
                event.chain_id,
                previous["event_sequence"],
                previous["event_id"],
                previous["event_sha256"],
            ),
        ).rowcount
        if changed != 1:
            raise TargetHealthCustodyConflictError("custody event head changed")

    def _inspect_current_head_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        inspection_context_sha256: str | None = None,
    ) -> TargetHealthCurrentHeadInspection:
        policy_head = connection.execute(
            "SELECT * FROM target_health_policy_heads WHERE tenant_id=? "
            "AND mission_id=? AND chain_id=?",
            (tenant_id, mission_id, chain_id),
        ).fetchone()
        chain_head = connection.execute(
            "SELECT * FROM target_health_chain_heads WHERE tenant_id=? "
            "AND mission_id=? AND chain_id=?",
            (tenant_id, mission_id, chain_id),
        ).fetchone()
        event_head = connection.execute(
            "SELECT * FROM target_health_event_heads WHERE tenant_id=? "
            "AND mission_id=? AND chain_id=?",
            (tenant_id, mission_id, chain_id),
        ).fetchone()
        if policy_head is None or chain_head is None or event_head is None:
            raise TargetHealthCustodyNotFoundError("current custody head was not found")

        policy_row = connection.execute(
            "SELECT * FROM target_health_collector_policies WHERE policy_id=? "
            "AND policy_sha256=?",
            (policy_head["policy_id"], policy_head["policy_sha256"]),
        ).fetchone()
        envelope_row = connection.execute(
            "SELECT * FROM target_health_envelopes WHERE envelope_id=? "
            "AND envelope_sha256=?",
            (chain_head["envelope_id"], chain_head["envelope_sha256"]),
        ).fetchone()
        receipt_row = connection.execute(
            "SELECT * FROM target_health_custody_receipts WHERE custody_receipt_id=? "
            "AND custody_receipt_sha256=?",
            (
                chain_head["custody_receipt_id"],
                chain_head["custody_receipt_sha256"],
            ),
        ).fetchone()
        event_row = connection.execute(
            "SELECT * FROM target_health_custody_events WHERE event_id=? "
            "AND event_sha256=?",
            (event_head["event_id"], event_head["event_sha256"]),
        ).fetchone()
        if any(row is None for row in (policy_row, envelope_row, receipt_row, event_row)):
            raise TargetHealthCustodyIntegrityError(
                "current custody head material is incomplete"
            )

        root = self._load_root(connection)
        policy = self._load_policy_row(policy_row)
        envelope = self._load_envelope_row(envelope_row)
        receipt = self._load_receipt_row(receipt_row)
        event = self._load_event_row(event_row)

        revocation_head = connection.execute(
            "SELECT * FROM target_health_policy_revocation_heads WHERE policy_id=?",
            (policy.policy_id,),
        ).fetchone()
        revocation = None
        if revocation_head is not None:
            revocation_row = connection.execute(
                "SELECT * FROM target_health_collector_policy_revocations "
                "WHERE revocation_id=? AND revocation_sha256=?",
                (
                    revocation_head["revocation_id"],
                    revocation_head["revocation_sha256"],
                ),
            ).fetchone()
            if revocation_row is None:
                raise TargetHealthCustodyIntegrityError(
                    "current policy revocation material is incomplete"
                )
            revocation = self._load_revocation_row(revocation_row)
            expected_revocation_head = (
                revocation.policy_id,
                revocation.chain_id,
                revocation.tenant_id,
                revocation.mission_id,
                revocation.revocation_id,
                revocation.revocation_sha256,
                revocation.revoked_at,
                revocation_row["transition_sequence"],
            )
            if tuple(revocation_head) != expected_revocation_head:
                raise TargetHealthCustodyIntegrityError(
                    "current policy revocation head is invalid"
                )

        expected_policy_head = (
            policy.chain_id,
            policy.tenant_id,
            policy.mission_id,
            policy.policy_id,
            policy.policy_sha256,
            policy.policy_revision,
            policy.collector_epoch,
            policy_row["transition_sequence"],
        )
        expected_chain_head = (
            envelope.chain_id,
            envelope.tenant_id,
            envelope.mission_id,
            envelope.binding_sha256,
            envelope.collector_id,
            envelope.collector_epoch,
            envelope.sequence,
            envelope.envelope_id,
            envelope.envelope_sha256,
            receipt.custody_receipt_id,
            receipt.custody_receipt_sha256,
            envelope.policy_id,
            envelope.policy_sha256,
            envelope_row["transition_sequence"],
        )
        expected_event_head = (
            event.chain_id,
            event.tenant_id,
            event.mission_id,
            event.event_sequence,
            event.event_id,
            event.event_sha256,
        )
        if tuple(policy_head) != expected_policy_head:
            raise TargetHealthCustodyIntegrityError("current collector policy head is invalid")
        if tuple(chain_head) != expected_chain_head:
            raise TargetHealthCustodyIntegrityError("current custody chain head is invalid")
        if tuple(event_head) != expected_event_head:
            raise TargetHealthCustodyIntegrityError("current custody event head is invalid")
        if (
            event.custody_receipt_id != receipt.custody_receipt_id
            or event.custody_receipt_sha256 != receipt.custody_receipt_sha256
            or event.envelope_id != envelope.envelope_id
            or event.envelope_sha256 != envelope.envelope_sha256
        ):
            raise TargetHealthCustodyIntegrityError(
                "current custody event material is substituted"
            )

        last_transition = self._last_transition(connection)
        if last_transition is None:
            raise TargetHealthCustodyIntegrityError(
                "current custody transition inventory is empty"
            )
        global_transition_sequence = last_transition[0]
        bound_transitions = [
            policy_head["transition_sequence"],
            chain_head["transition_sequence"],
        ]
        if revocation_head is not None:
            bound_transitions.append(revocation_head["transition_sequence"])
        if global_transition_sequence < max(bound_transitions):
            raise TargetHealthCustodyIntegrityError(
                "global custody transition does not cover current heads"
            )

        initial_at = self._trusted_now()
        self._require_nonregressing_time(connection, initial_at)
        self._verify_current(root, policy, envelope, initial_at, revocation)
        final_at = self._trusted_now()
        if _instant(final_at) < _instant(initial_at):
            raise TargetHealthCustodyIntegrityError("trusted clock regressed")
        self._require_nonregressing_time(connection, final_at)
        verification = self._verify_current(
            root,
            policy,
            envelope,
            final_at,
            revocation,
        )

        try:
            head_binding = TargetHealthCustodyHeadBinding(
                tenant_id=tenant_id,
                mission_id=mission_id,
                chain_id=chain_id,
                store_application_id=APPLICATION_ID,
                store_schema_version=SCHEMA_VERSION,
                store_migration_version=SCHEMA_VERSION,
                store_migration_id=MIGRATION_ID,
                store_migration_sha256=MIGRATION_SHA256,
                store_schema_manifest_sha256=EXPECTED_SCHEMA_MANIFEST_SHA256,
                global_transition_sequence=global_transition_sequence,
                trust_root_id=root.trust_root_id,
                trust_root_sha256=root.trust_root_sha256,
                trust_root_revision=root.trust_root_revision,
                policy_id=policy.policy_id,
                policy_sha256=policy.policy_sha256,
                policy_revision=policy.policy_revision,
                policy_collector_epoch=policy.collector_epoch,
                policy_head_transition_sequence=policy_head["transition_sequence"],
                policy_revocation_id=(
                    None if revocation is None else revocation.revocation_id
                ),
                policy_revocation_sha256=(
                    None if revocation is None else revocation.revocation_sha256
                ),
                policy_revoked_at=None if revocation is None else revocation.revoked_at,
                policy_revocation_transition_sequence=(
                    None
                    if revocation_head is None
                    else revocation_head["transition_sequence"]
                ),
                binding_sha256=envelope.binding_sha256,
                collector_id=envelope.collector_id,
                collector_epoch=envelope.collector_epoch,
                chain_head_sequence=envelope.sequence,
                chain_head_envelope_id=envelope.envelope_id,
                chain_head_envelope_sha256=envelope.envelope_sha256,
                chain_head_custody_receipt_id=receipt.custody_receipt_id,
                chain_head_custody_receipt_sha256=receipt.custody_receipt_sha256,
                chain_head_policy_id=envelope.policy_id,
                chain_head_policy_sha256=envelope.policy_sha256,
                chain_head_transition_sequence=chain_head["transition_sequence"],
                event_head_sequence=event.event_sequence,
                event_head_event_id=event.event_id,
                event_head_event_sha256=event.event_sha256,
            )
            return TargetHealthCurrentHeadInspection(
                tenant_id=tenant_id,
                mission_id=mission_id,
                chain_id=chain_id,
                head_binding=head_binding,
                trust_root=root,
                current_policy=policy,
                policy_revocation=revocation,
                envelope=envelope,
                custody_receipt=receipt,
                custody_event=event,
                verification=verification,
                inspected_at=final_at,
                inspection_context_sha256=inspection_context_sha256,
            )
        except TargetHealthCustodyContractError as exc:
            raise TargetHealthCustodyIntegrityError(
                "current custody head inspection could not be reconstructed"
            ) from exc

    def inspect_current_head(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        inspection_context_sha256: str | None = None,
    ) -> TargetHealthCurrentHeadInspection:
        _identifier(tenant_id, "tenant_id")
        _identifier(mission_id, "mission_id")
        _chain_id(chain_id)
        if inspection_context_sha256 is not None:
            _digest(inspection_context_sha256, "inspection_context_sha256")
        with self._read() as connection:
            return self._inspect_current_head_in_transaction(
                connection,
                tenant_id=tenant_id,
                mission_id=mission_id,
                chain_id=chain_id,
                inspection_context_sha256=inspection_context_sha256,
            )

    def inspect_unique_current_binding_head(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        binding_sha256: str,
        inspection_context_sha256: str | None = None,
    ) -> TargetHealthCurrentHeadInspection:
        _identifier(tenant_id, "tenant_id")
        _identifier(mission_id, "mission_id")
        _digest(binding_sha256, "binding_sha256")
        if inspection_context_sha256 is not None:
            _digest(inspection_context_sha256, "inspection_context_sha256")
        with self._read() as connection:
            rows = connection.execute(
                "SELECT h.chain_id FROM target_health_policy_heads h "
                "JOIN target_health_collector_policies p "
                "ON p.policy_id=h.policy_id AND p.policy_sha256=h.policy_sha256 "
                "WHERE h.tenant_id=? AND h.mission_id=? AND p.binding_sha256=? "
                "ORDER BY h.chain_id",
                (tenant_id, mission_id, binding_sha256),
            ).fetchall()
            if not rows:
                raise TargetHealthCustodyNotFoundError(
                    "current custody binding head was not found"
                )
            if len(rows) != 1:
                raise TargetHealthCustodyConflictError(
                    "current custody binding resolves to multiple chains"
                )
            return self._inspect_current_head_in_transaction(
                connection,
                tenant_id=tenant_id,
                mission_id=mission_id,
                chain_id=rows[0]["chain_id"],
                inspection_context_sha256=inspection_context_sha256,
            )

    def verify_current_head(
        self, *, tenant_id: str, mission_id: str, chain_id: str
    ) -> TargetHealthCustodyVerificationResult:
        return self.inspect_current_head(
            tenant_id=tenant_id,
            mission_id=mission_id,
            chain_id=chain_id,
        ).verification

    def list_policies(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        after_revision: int = 0,
        limit: int = 100,
    ) -> tuple[TargetHealthCollectorPolicyRevision, ...]:
        self._validate_page(tenant_id, mission_id, chain_id, after_revision, limit)
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM target_health_collector_policies WHERE tenant_id=? "
                "AND mission_id=? AND chain_id=? AND policy_revision>? "
                "ORDER BY policy_revision LIMIT ?",
                (tenant_id, mission_id, chain_id, after_revision, limit),
            ).fetchall()
            return tuple(self._load_policy_row(row) for row in rows)

    def list_revocations(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        after_revision: int = 0,
        limit: int = 100,
    ) -> tuple[TargetHealthCollectorPolicyRevocation, ...]:
        _identifier(tenant_id, "tenant_id")
        _identifier(mission_id, "mission_id")
        self._validate_cursor_and_limit(after_revision, limit)
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM target_health_collector_policy_revocations "
                "WHERE tenant_id=? AND mission_id=? AND policy_revision>? "
                "ORDER BY policy_revision,transition_sequence LIMIT ?",
                (tenant_id, mission_id, after_revision, limit),
            ).fetchall()
            return tuple(self._load_revocation_row(row) for row in rows)

    def list_receipts(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[TargetHealthCustodyReceipt, ...]:
        self._validate_page(tenant_id, mission_id, chain_id, after_sequence, limit)
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM target_health_custody_receipts WHERE tenant_id=? "
                "AND mission_id=? AND chain_id=? AND sequence>? "
                "ORDER BY sequence LIMIT ?",
                (tenant_id, mission_id, chain_id, after_sequence, limit),
            ).fetchall()
            return tuple(self._load_receipt_row(row) for row in rows)

    def list_events(
        self,
        *,
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> tuple[TargetHealthCustodyEvent, ...]:
        self._validate_page(tenant_id, mission_id, chain_id, after_sequence, limit)
        with self._read() as connection:
            rows = connection.execute(
                "SELECT * FROM target_health_custody_events WHERE tenant_id=? "
                "AND mission_id=? AND chain_id=? AND event_sequence>? "
                "ORDER BY event_sequence LIMIT ?",
                (tenant_id, mission_id, chain_id, after_sequence, limit),
            ).fetchall()
            return tuple(self._load_event_row(row) for row in rows)

    @staticmethod
    def _validate_page(
        tenant_id: str,
        mission_id: str,
        chain_id: str,
        after_sequence: int,
        limit: int,
    ) -> None:
        _identifier(tenant_id, "tenant_id")
        _identifier(mission_id, "mission_id")
        _chain_id(chain_id)
        SQLiteTargetHealthCustody._validate_cursor_and_limit(after_sequence, limit)

    @staticmethod
    def _validate_cursor_and_limit(cursor: int, limit: int) -> None:
        if (
            isinstance(cursor, bool)
            or not isinstance(cursor, int)
            or not 0 <= cursor <= MAX_SQLITE_INTEGER
        ):
            raise TargetHealthCustodyValidationError("page cursor is invalid")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_PAGE_SIZE:
            raise TargetHealthCustodyValidationError("page limit is invalid")

    def verify(self) -> TargetHealthCustodyVerificationReport:
        with self._read(reconstruct_history=False) as connection:
            return self._verify_history(connection)

    def _verify_history(
        self, connection: sqlite3.Connection
    ) -> TargetHealthCustodyVerificationReport:
        try:
            return self._verify_history_records(connection)
        except TargetHealthCustodyIntegrityError:
            raise
        except (
            TargetHealthCustodyContractError,
            TargetHealthCustodyConflictError,
            TargetHealthCustodyValidationError,
            TypeError,
        ) as exc:
            raise TargetHealthCustodyIntegrityError(
                "stored target health custody history is invalid"
            ) from exc

    def _verify_history_records(
        self, connection: sqlite3.Connection
    ) -> TargetHealthCustodyVerificationReport:
            quick = connection.execute("PRAGMA quick_check").fetchall()
            if len(quick) != 1 or quick[0][0] != "ok":
                raise TargetHealthCustodyIntegrityError("SQLite quick check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise TargetHealthCustodyIntegrityError("SQLite foreign key check failed")
            root = self._load_root(connection)
            policy_rows = connection.execute(
                "SELECT * FROM target_health_collector_policies ORDER BY transition_sequence"
            ).fetchall()
            revocation_rows = connection.execute(
                "SELECT * FROM target_health_collector_policy_revocations "
                "ORDER BY transition_sequence"
            ).fetchall()
            envelope_rows = connection.execute(
                "SELECT * FROM target_health_envelopes ORDER BY transition_sequence"
            ).fetchall()
            receipt_rows = connection.execute(
                "SELECT * FROM target_health_custody_receipts ORDER BY chain_id,sequence"
            ).fetchall()
            event_rows = connection.execute(
                "SELECT * FROM target_health_custody_events ORDER BY chain_id,event_sequence"
            ).fetchall()
            policies = {row["policy_id"]: self._load_policy_row(row) for row in policy_rows}
            revocations = {
                row["revocation_id"]: self._load_revocation_row(row)
                for row in revocation_rows
            }
            envelopes = {
                row["envelope_id"]: self._load_envelope_row(row) for row in envelope_rows
            }
            receipts = {
                row["envelope_id"]: self._load_receipt_row(row) for row in receipt_rows
            }
            events = {row["envelope_id"]: self._load_event_row(row) for row in event_rows}
            if (
                len(policies) != len(policy_rows)
                or len(revocations) != len(revocation_rows)
                or len(envelopes) != len(envelope_rows)
            ):
                raise TargetHealthCustodyIntegrityError("duplicate history identity detected")
            if (
                set(envelopes) != set(receipts)
                or set(envelopes) != set(events)
                or len(receipts) != len(receipt_rows)
                or len(events) != len(event_rows)
            ):
                raise TargetHealthCustodyIntegrityError("custody history inventory is invalid")
            transitions: list[tuple[int, str, sqlite3.Row]] = [
                (row["transition_sequence"], "policy", row) for row in policy_rows
            ] + [
                (row["transition_sequence"], "revocation", row)
                for row in revocation_rows
            ] + [
                (row["transition_sequence"], "envelope", row) for row in envelope_rows
            ]
            transitions.sort(key=lambda item: item[0])
            if [item[0] for item in transitions] != list(range(1, len(transitions) + 1)):
                raise TargetHealthCustodyIntegrityError("custody transition order is invalid")
            policy_state: dict[str, TargetHealthCollectorPolicyRevision] = {}
            published_policy_ids: set[str] = set()
            revocation_state: dict[str, TargetHealthCollectorPolicyRevocation] = {}
            envelope_state: dict[str, SignedTargetHealthCustodyEnvelopeV2] = {}
            event_state: dict[str, TargetHealthCustodyEvent] = {}
            previous_time: str | None = None
            for _, kind, row in transitions:
                recorded_at = (
                    row["accepted_at"] if kind == "envelope" else row["published_at"]
                )
                if previous_time is not None and _instant(recorded_at) < _instant(previous_time):
                    raise TargetHealthCustodyIntegrityError("custody transition time regressed")
                previous_time = recorded_at
                if kind == "policy":
                    policy = policies[row["policy_id"]]
                    verify_target_health_collector_policy(
                        root, policy, verified_at=recorded_at, current=True
                    )
                    prior_policy = policy_state.get(policy.chain_id)
                    prior_envelope = envelope_state.get(policy.chain_id)
                    prior_row = None
                    if prior_envelope is not None:
                        prior_row = {
                            "envelope_id": prior_envelope.envelope_id,
                            "envelope_sha256": prior_envelope.envelope_sha256,
                        }
                    self._require_policy_transition(policy, prior_policy, prior_row)
                    if (
                        prior_policy is not None
                        and self._revocation_effective(
                            revocation_state.get(prior_policy.policy_id), recorded_at
                        )
                        and (
                            policy.collector_epoch != prior_policy.collector_epoch + 1
                            or policy.collector_key_id == prior_policy.collector_key_id
                            or policy.collector_public_key_sha256
                            == prior_policy.collector_public_key_sha256
                        )
                    ):
                        raise TargetHealthCustodyIntegrityError(
                            "revoked policy successor is invalid"
                        )
                    policy_state[policy.chain_id] = policy
                    published_policy_ids.add(policy.policy_id)
                    continue
                if kind == "revocation":
                    revocation = revocations[row["revocation_id"]]
                    policy = policies.get(revocation.policy_id)
                    if (
                        policy is None
                        or revocation.policy_id not in published_policy_ids
                        or revocation.policy_id in revocation_state
                    ):
                        raise TargetHealthCustodyIntegrityError(
                            "policy revocation lineage is invalid"
                        )
                    verify_target_health_collector_policy_revocation(
                        root, policy, revocation
                    )
                    revocation_state[revocation.policy_id] = revocation
                    continue
                envelope = envelopes[row["envelope_id"]]
                policy = policies.get(envelope.policy_id)
                if policy is None or policy_state.get(envelope.chain_id) != policy:
                    raise TargetHealthCustodyIntegrityError(
                        "envelope did not use the current collector policy"
                    )
                revocation = revocation_state.get(policy.policy_id)
                verification = verify_target_health_custody_envelope_current(
                    root,
                    policy,
                    envelope,
                    verified_at=row["accepted_at"],
                    expected_policy_id=policy.policy_id,
                    expected_policy_sha256=policy.policy_sha256,
                    expected_head_envelope_id=envelope.envelope_id,
                    expected_head_envelope_sha256=envelope.envelope_sha256,
                    expected_head_sequence=envelope.sequence,
                    policy_revocation=revocation,
                )
                verify_target_health_custody_envelope_historical(
                    root,
                    policy,
                    envelope,
                    verified_at=row["accepted_at"],
                    policy_revocation=revocation,
                )
                prior_envelope = envelope_state.get(envelope.chain_id)
                self._require_envelope_transition(envelope, prior_envelope)
                receipt = receipts[envelope.envelope_id]
                event = events[envelope.envelope_id]
                if (
                    receipt.verification.verified_at != row["accepted_at"]
                    or receipt.recorded_at != row["accepted_at"]
                    or event.recorded_at != row["accepted_at"]
                    or receipt.verification != verification
                ):
                    raise TargetHealthCustodyIntegrityError(
                        "custody acceptance chronology is invalid"
                    )
                expected_receipt = build_target_health_custody_receipt(
                    verification, recorded_at=row["accepted_at"]
                )
                if receipt != expected_receipt or receipt.recorded_at != row["accepted_at"]:
                    raise TargetHealthCustodyIntegrityError("custody receipt lineage is invalid")
                prior_event = event_state.get(envelope.chain_id)
                expected_event = build_target_health_custody_event(
                    receipt,
                    event_sequence=envelope.sequence,
                    predecessor_event_id=(None if prior_event is None else prior_event.event_id),
                    predecessor_event_sha256=(
                        None if prior_event is None else prior_event.event_sha256
                    ),
                    recorded_at=row["accepted_at"],
                )
                if event != expected_event:
                    raise TargetHealthCustodyIntegrityError("custody event lineage is invalid")
                envelope_state[envelope.chain_id] = envelope
                event_state[envelope.chain_id] = event
            self._verify_heads(
                connection,
                policy_state,
                revocation_state,
                envelope_state,
                event_state,
                receipts,
            )
            return TargetHealthCustodyVerificationReport(
                application_id=APPLICATION_ID,
                schema_version=SCHEMA_VERSION,
                schema_manifest_sha256=EXPECTED_SCHEMA_MANIFEST_SHA256,
                trust_root_id=root.trust_root_id,
                policy_count=len(policies),
                revocation_count=len(revocations),
                envelope_count=len(envelopes),
                custody_receipt_count=len(receipts),
                event_count=len(events),
                chain_count=len(envelope_state),
                transition_count=len(transitions),
            )

    @staticmethod
    def _verify_heads(
        connection: sqlite3.Connection,
        policy_state: dict[str, TargetHealthCollectorPolicyRevision],
        revocation_state: dict[str, TargetHealthCollectorPolicyRevocation],
        envelope_state: dict[str, SignedTargetHealthCustodyEnvelopeV2],
        event_state: dict[str, TargetHealthCustodyEvent],
        receipts: dict[str, TargetHealthCustodyReceipt],
    ) -> None:
        policy_rows = connection.execute("SELECT * FROM target_health_policy_heads").fetchall()
        if {row["chain_id"] for row in policy_rows} != set(policy_state):
            raise TargetHealthCustodyIntegrityError("collector policy head inventory is invalid")
        for row in policy_rows:
            policy = policy_state[row["chain_id"]]
            transition = connection.execute(
                "SELECT transition_sequence FROM target_health_collector_policies "
                "WHERE policy_id=?",
                (policy.policy_id,),
            ).fetchone()[0]
            expected = (
                policy.chain_id,
                policy.tenant_id,
                policy.mission_id,
                policy.policy_id,
                policy.policy_sha256,
                policy.policy_revision,
                policy.collector_epoch,
                transition,
            )
            if tuple(row) != expected:
                raise TargetHealthCustodyIntegrityError("collector policy head is invalid")
        revocation_rows = connection.execute(
            "SELECT * FROM target_health_policy_revocation_heads"
        ).fetchall()
        if {row["policy_id"] for row in revocation_rows} != set(revocation_state):
            raise TargetHealthCustodyIntegrityError("policy revocation head inventory is invalid")
        for row in revocation_rows:
            revocation = revocation_state[row["policy_id"]]
            transition = connection.execute(
                "SELECT transition_sequence FROM target_health_collector_policy_revocations "
                "WHERE revocation_id=?",
                (revocation.revocation_id,),
            ).fetchone()[0]
            expected = (
                revocation.policy_id,
                revocation.chain_id,
                revocation.tenant_id,
                revocation.mission_id,
                revocation.revocation_id,
                revocation.revocation_sha256,
                revocation.revoked_at,
                transition,
            )
            if tuple(row) != expected:
                raise TargetHealthCustodyIntegrityError("policy revocation head is invalid")
        chain_rows = connection.execute("SELECT * FROM target_health_chain_heads").fetchall()
        if {row["chain_id"] for row in chain_rows} != set(envelope_state):
            raise TargetHealthCustodyIntegrityError("custody chain head inventory is invalid")
        for row in chain_rows:
            envelope = envelope_state[row["chain_id"]]
            receipt = receipts[envelope.envelope_id]
            transition = connection.execute(
                "SELECT transition_sequence FROM target_health_envelopes WHERE envelope_id=?",
                (envelope.envelope_id,),
            ).fetchone()[0]
            expected = (
                envelope.chain_id,
                envelope.tenant_id,
                envelope.mission_id,
                envelope.binding_sha256,
                envelope.collector_id,
                envelope.collector_epoch,
                envelope.sequence,
                envelope.envelope_id,
                envelope.envelope_sha256,
                receipt.custody_receipt_id,
                receipt.custody_receipt_sha256,
                envelope.policy_id,
                envelope.policy_sha256,
                transition,
            )
            if tuple(row) != expected:
                raise TargetHealthCustodyIntegrityError("custody chain head is invalid")
        event_rows = connection.execute("SELECT * FROM target_health_event_heads").fetchall()
        if {row["chain_id"] for row in event_rows} != set(event_state):
            raise TargetHealthCustodyIntegrityError("custody event head inventory is invalid")
        for row in event_rows:
            event = event_state[row["chain_id"]]
            expected = (
                event.chain_id,
                event.tenant_id,
                event.mission_id,
                event.event_sequence,
                event.event_id,
                event.event_sha256,
            )
            if tuple(row) != expected:
                raise TargetHealthCustodyIntegrityError("custody event head is invalid")


__all__ = [
    "APPLICATION_ID",
    "DEFAULT_BUSY_TIMEOUT_SECONDS",
    "EXPECTED_SCHEMA_MANIFEST_SHA256",
    "MAX_BUSY_TIMEOUT_SECONDS",
    "MAX_PAGE_SIZE",
    "MIGRATION_ID",
    "MIGRATION_SHA256",
    "SAFE_JOURNAL_MODE",
    "SCHEMA_VERSION",
    "SQLiteTargetHealthCustody",
    "TargetHealthAppendResult",
    "TargetHealthCustodyBusyError",
    "TargetHealthCustodyConflictError",
    "TargetHealthCustodyError",
    "TargetHealthCustodyIntegrityError",
    "TargetHealthCustodyNotFoundError",
    "TargetHealthCustodyValidationError",
    "TargetHealthCustodyVerificationReport",
]

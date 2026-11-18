"""Crash-safe SQLite repository and framework-neutral ASGI service adapter.

The SQLite repository is intended for local development and evaluation. The
ASGI callable opens no socket and performs no live authentication or target
action. Deployment controls remain the responsibility of an external host.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .local_api_service import (
    AccessAuthorizer,
    AccessContext,
    AuditEntry,
    CommitCommand,
    CommitResult,
    IntegrationEvent,
    LocalApiService,
    LocalApiServiceError,
    MutationAdmitter,
    Operation,
    ResourceKind,
    ResourceRecord,
    ServiceRequest,
    _validate_atomic_commit_result,
    canonical_json,
    canonical_sha256,
)
from .offline_planning_preview import (
    OfflinePlanningPreviewError,
    OfflinePlanningPreviewService,
    PlanningBundleReader,
    PlanningPreviewRequest,
)
from .registry import ExpertRegistry

SCHEMA_VERSION = 1
MAX_BODY_BYTES = 131_072
MAX_HEADER_COUNT = 64
MAX_HEADER_BYTES = 16_384
MAX_PAGE_SIZE = 100
ASGI_PATH = "/v1/service/requests"
PLANNING_PREVIEW_PATH = "/v1/planning/previews"

CORRELATION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
WINDOWS_PATH_RE = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\)")
FORBIDDEN_VALUE_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization_value",
        "client_secret",
        "credential",
        "credential_value",
        "password",
        "private_key",
        "refresh_token",
        "secret",
    }
)


class LocalApiRuntimeError(RuntimeError):
    """Base error for fail-closed local runtime behavior."""


class RepositoryConflict(LocalApiRuntimeError):
    """Raised for stale concurrency or rebound idempotency."""


class RepositoryBusy(LocalApiRuntimeError):
    """Raised when the bounded SQLite writer lock cannot be acquired."""


class MigrationIdentityError(LocalApiRuntimeError):
    """Raised when applied migration content differs from the embedded migration."""


class RepositoryIntegrityError(LocalApiRuntimeError):
    """Raised when persisted atomic or audit-chain state is incoherent."""


class AsgiReceive(Protocol):
    async def __call__(self) -> Mapping[str, Any]: ...


class AsgiSend(Protocol):
    async def __call__(self, message: Mapping[str, Any]) -> None: ...


_MIGRATION_1 = """
CREATE TABLE resources(
 resource_kind TEXT NOT NULL, tenant_id TEXT NOT NULL, context_id TEXT NOT NULL,
 resource_id TEXT NOT NULL, version INTEGER NOT NULL, concurrency_token TEXT NOT NULL,
 resource_json TEXT NOT NULL, resource_sha256 TEXT NOT NULL,
 PRIMARY KEY(resource_kind, tenant_id, context_id, resource_id));
CREATE INDEX resources_page_idx
 ON resources(resource_kind, tenant_id, context_id, resource_id);
CREATE TABLE audit_entries(
 audit_ref TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, context_id TEXT NOT NULL,
 resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL, resource_version INTEGER NOT NULL,
 prior_audit_ref TEXT, entry_json TEXT NOT NULL, entry_sha256 TEXT NOT NULL,
 UNIQUE(resource_kind, tenant_id, context_id, resource_id, resource_version));
CREATE TABLE integration_events(
 event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, context_id TEXT NOT NULL,
 resource_kind TEXT NOT NULL, resource_id TEXT NOT NULL, resource_version INTEGER NOT NULL,
 event_json TEXT NOT NULL, event_sha256 TEXT NOT NULL,
 UNIQUE(resource_kind, tenant_id, context_id, resource_id, resource_version));
CREATE TABLE idempotency_results(
 tenant_id TEXT NOT NULL, context_id TEXT NOT NULL, idempotency_sha256 TEXT NOT NULL,
 request_sha256 TEXT NOT NULL, result_json TEXT NOT NULL, result_sha256 TEXT NOT NULL,
 PRIMARY KEY(tenant_id, context_id, idempotency_sha256));
""".strip()


def _sha256_text(value: str) -> str:
    if type(value) is not str:
        raise RepositoryIntegrityError("persisted text is not native")
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


SQLITE_MIGRATION_ID = "migrationref:local-api-runtime.sqlite.0001"
SQLITE_MIGRATION_SHA256 = _sha256_text(_MIGRATION_1)
_MIGRATION_TABLE_SQL = (
    "CREATE TABLE schema_migrations("
    "version INTEGER PRIMARY KEY, migration_id TEXT NOT NULL, "
    "migration_sha256 TEXT NOT NULL)"
)


def _expected_schema_sql() -> dict[tuple[str, str], str]:
    """Compile the embedded migration into exact SQLite schema definitions."""

    with closing(sqlite3.connect(":memory:")) as connection:
        connection.executescript(_MIGRATION_TABLE_SQL + ";\n" + _MIGRATION_1)
        return {
            (kind, name): definition
            for kind, name, definition in connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }


def runtime_adapter_manifest() -> dict[str, Any]:
    """Return implementation scope without claiming deployment qualification."""

    return {
        "adapter": "framework-neutral-asgi-with-sqlite",
        "asgi_path": ASGI_PATH,
        "deployment_scope": "local_development_and_evaluation_only",
        "effects": {
            "authentication": "injected_authorizer_only",
            "database": "caller_selected_local_sqlite_file",
            "ha": "not_implemented",
            "ingress": "not_implemented",
            "network_listener": "none",
            "production_qualification": "none",
            "target_actions": "none",
            "tls": "not_implemented",
        },
        "kind": "sunderkey.local-api-runtime-adapter.v1",
        "limits": {
            "body_bytes": MAX_BODY_BYTES,
            "header_bytes": MAX_HEADER_BYTES,
            "header_count": MAX_HEADER_COUNT,
            "page_size": MAX_PAGE_SIZE,
        },
        "migration": {
            "migration_id": SQLITE_MIGRATION_ID,
            "migration_sha256": SQLITE_MIGRATION_SHA256,
            "version": 1,
        },
        "schema_version": SCHEMA_VERSION,
    }


def _resource_from_dict(raw: Mapping[str, Any]) -> ResourceRecord:
    return ResourceRecord(
        resource_kind=ResourceKind(raw["resource_kind"]),
        resource_id=raw["resource_id"],
        tenant_id=raw["tenant_id"],
        context_id=raw["context_id"],
        version=raw["version"],
        concurrency_token=raw["concurrency_token"],
        payload=raw["payload"],
        payload_sha256=raw["payload_sha256"],
        audit_refs=tuple(raw["audit_refs"]),
        created_at=raw["created_at"],
        updated_at=raw["updated_at"],
    )


def _audit_from_dict(raw: Mapping[str, Any]) -> AuditEntry:
    return AuditEntry(
        audit_ref=raw["audit_ref"],
        request_sha256=raw["request_sha256"],
        authorization_ref=raw["authorization_ref"],
        admission_ref=raw["admission_ref"],
        admission_audit_ref=raw["admission_audit_ref"],
        prior_concurrency_token=raw["prior_concurrency_token"],
        resulting_concurrency_token=raw["resulting_concurrency_token"],
        resource_kind=ResourceKind(raw["resource_kind"]),
        resource_id=raw["resource_id"],
        tenant_id=raw["tenant_id"],
        context_id=raw["context_id"],
        principal_id=raw["principal_id"],
        recorded_at=raw["recorded_at"],
    )


def _event_from_dict(raw: Mapping[str, Any]) -> IntegrationEvent:
    return IntegrationEvent(
        event_id=raw["event_id"],
        event_type=raw["event_type"],
        tenant_id=raw["tenant_id"],
        context_id=raw["context_id"],
        resource_kind=ResourceKind(raw["resource_kind"]),
        resource_id=raw["resource_id"],
        resource_version=raw["resource_version"],
        resource_sha256=raw["resource_sha256"],
        audit_ref=raw["audit_ref"],
        occurred_at=raw["occurred_at"],
    )


def _result_document(result: CommitResult) -> dict[str, Any]:
    return {
        "audit_entry": result.audit_entry.to_dict(),
        "idempotency_sha256": result.idempotency_sha256,
        "integration_event": result.integration_event.to_dict(),
        "record": result.record.to_dict(),
        "request_sha256": result.request_sha256,
    }


def _unique_persisted_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate persisted field")
        value[key] = item
    return value


def _resource_from_row(row: sqlite3.Row) -> ResourceRecord:
    if _sha256_text(row["resource_json"]) != row["resource_sha256"]:
        raise RepositoryIntegrityError("resource content digest does not match")
    try:
        raw = json.loads(row["resource_json"], object_pairs_hook=_unique_persisted_object)
        record = _resource_from_dict(raw)
        if canonical_json(raw) != canonical_json(record.to_dict()):
            raise ValueError("persisted resource content was normalized")
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise RepositoryIntegrityError("persisted resource is invalid") from exc
    if (
        tuple(row[name] for name in (
            "resource_kind", "tenant_id", "context_id", "resource_id"
        )) != (
            record.resource_kind.value, record.tenant_id,
            record.context_id, record.resource_id,
        )
        or row["version"] != record.version
        or row["concurrency_token"] != record.concurrency_token
    ):
        raise RepositoryIntegrityError("resource row metadata is inconsistent")
    return record


def _result_from_row(row: sqlite3.Row) -> CommitResult:
    if _sha256_text(row["result_json"]) != row["result_sha256"]:
        raise RepositoryIntegrityError("idempotency result digest does not match")
    result = _result_from_json(row["result_json"], replayed=True)
    if (
        row["tenant_id"] != result.record.tenant_id
        or row["context_id"] != result.record.context_id
        or row["idempotency_sha256"] != result.idempotency_sha256
        or row["request_sha256"] != result.request_sha256
    ):
        raise RepositoryIntegrityError("idempotency row metadata is inconsistent")
    return result


def _audit_from_row(row: sqlite3.Row) -> AuditEntry:
    if _sha256_text(row["entry_json"]) != row["entry_sha256"]:
        raise RepositoryIntegrityError("audit entry digest does not match")
    try:
        raw = json.loads(row["entry_json"], object_pairs_hook=_unique_persisted_object)
        audit = _audit_from_dict(raw)
        if canonical_json(raw) != canonical_json(audit.to_dict()):
            raise ValueError("persisted audit content was normalized")
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise RepositoryIntegrityError("persisted audit is invalid") from exc
    if (
        row["audit_ref"] != audit.audit_ref
        or tuple(row[name] for name in (
            "resource_kind", "tenant_id", "context_id", "resource_id"
        )) != (
            audit.resource_kind.value, audit.tenant_id,
            audit.context_id, audit.resource_id,
        )
    ):
        raise RepositoryIntegrityError("audit row metadata is inconsistent")
    return audit


def _event_from_row(row: sqlite3.Row) -> IntegrationEvent:
    if _sha256_text(row["event_json"]) != row["event_sha256"]:
        raise RepositoryIntegrityError("integration event digest does not match")
    try:
        raw = json.loads(row["event_json"], object_pairs_hook=_unique_persisted_object)
        event = _event_from_dict(raw)
        if canonical_json(raw) != canonical_json(event.to_dict()):
            raise ValueError("persisted event content was normalized")
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise RepositoryIntegrityError("persisted event is invalid") from exc
    if (
        row["event_id"] != event.event_id
        or tuple(row[name] for name in (
            "resource_kind", "tenant_id", "context_id", "resource_id",
            "resource_version"
        )) != (
            event.resource_kind.value, event.tenant_id,
            event.context_id, event.resource_id, event.resource_version,
        )
    ):
        raise RepositoryIntegrityError("event row metadata is inconsistent")
    return event


def _result_from_json(document: str, *, replayed: bool) -> CommitResult:

    try:
        if type(document) is not str:
            raise ValueError("persisted commit document must be a native string")
        raw = json.loads(document, object_pairs_hook=_unique_persisted_object)
        result = CommitResult(
            request_sha256=raw["request_sha256"],
            idempotency_sha256=raw["idempotency_sha256"],
            record=_resource_from_dict(raw["record"]),
            audit_entry=_audit_from_dict(raw["audit_entry"]),
            integration_event=_event_from_dict(raw["integration_event"]),
            replayed=replayed,
        )
        if canonical_json(raw) != canonical_json(_result_document(result)):
            raise ValueError("persisted commit content was discarded or normalized")
        _validate_atomic_commit_result(result)
        return result
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError) as exc:
        raise RepositoryIntegrityError("persisted commit result is invalid") from exc


class SQLiteServiceRepository:
    """Crash-safe implementation of the local service repository port."""

    def __init__(self, path: str | Path, *, busy_timeout_seconds: float = 1.0) -> None:
        if str(path) == ":memory:":
            raise LocalApiRuntimeError("file-based SQLite is required for restart durability")
        self.path = Path(os.path.abspath(path))
        if busy_timeout_seconds <= 0:
            raise LocalApiRuntimeError("busy_timeout_seconds must be positive")
        self.busy_timeout_seconds = busy_timeout_seconds
        self._inspect_path(require_file=False)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._inspect_path(require_file=False)
        self.migrate()

    def _inspect_path(self, *, require_file: bool) -> None:
        """Reject path links and Windows reparse points before opening SQLite."""

        sidecars = tuple(Path(str(self.path) + suffix) for suffix in ("-wal", "-shm", "-journal"))
        for candidate in (self.path, *sidecars, *self.path.parents):
            try:
                info = os.lstat(candidate)
            except FileNotFoundError:
                if candidate == self.path and require_file:
                    raise LocalApiRuntimeError("repository database is absent") from None
                continue
            except OSError as exc:
                raise LocalApiRuntimeError("repository path cannot be inspected") from exc
            if stat.S_ISLNK(info.st_mode) or (
                os.name == "nt"
                and getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
            ):
                raise LocalApiRuntimeError("repository path contains a link or reparse point")
            if candidate == self.path or candidate in sidecars:
                if not stat.S_ISREG(info.st_mode):
                    raise LocalApiRuntimeError("repository database path is not a regular file")
            elif not stat.S_ISDIR(info.st_mode):
                raise LocalApiRuntimeError("repository parent is not a directory")

    def _verify_existing_file(self) -> None:
        """Check existing main database identity with SQL read-only access."""

        self._inspect_path(require_file=True)
        try:
            with closing(
                sqlite3.connect(
                    self.path.as_uri() + "?mode=ro",
                    uri=True,
                    isolation_level=None,
                    timeout=self.busy_timeout_seconds,
                )
            ) as connection:
                connection.execute("PRAGMA query_only = ON")
                expected_schema = _expected_schema_sql()
                schema = {
                    (kind, name): definition
                    for kind, name, definition in connection.execute(
                        "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                        " LIMIT ?",
                        (len(expected_schema) + 1,),
                    )
                }
                if schema != expected_schema:
                    raise MigrationIdentityError("existing repository schema is foreign")
                migrations = connection.execute(
                    "SELECT version,migration_id,migration_sha256 "
                    "FROM schema_migrations ORDER BY version LIMIT 2"
                ).fetchall()
                if migrations != [(1, SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256)]:
                    raise MigrationIdentityError("existing repository migration is foreign")
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise MigrationIdentityError("existing repository failed SQLite integrity")
        except sqlite3.Error as exc:
            raise MigrationIdentityError(
                "existing repository is not a valid local API store"
            ) from exc

    def _connect(self) -> sqlite3.Connection:
        self._inspect_path(require_file=True)
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            timeout=self.busy_timeout_seconds,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {int(self.busy_timeout_seconds * 1000)}")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.OperationalError as exc:
            connection.rollback()
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise RepositoryBusy("SQLite writer lock was not acquired") from exc
            raise
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migrate(self) -> None:
        self._inspect_path(require_file=False)
        if self.path.exists():
            self._verify_existing_file()
            return
        try:
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_BINARY", 0),
                0o600,
            )
            os.close(descriptor)
        except FileExistsError as exc:
            raise MigrationIdentityError("repository path appeared during creation") from exc
        except OSError as exc:
            raise LocalApiRuntimeError("repository database could not be created") from exc
        with self._read() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            try:
                connection.executescript(
                    "BEGIN IMMEDIATE;\n" + _MIGRATION_TABLE_SQL + ";\n" + _MIGRATION_1
                )
                connection.execute(
                    "INSERT INTO schema_migrations VALUES(1,?,?)",
                    (SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256),
                )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def migration_identity(self) -> tuple[str, str]:
        with self._read() as connection:
            row = connection.execute(
                "SELECT migration_id,migration_sha256 FROM schema_migrations WHERE version=1"
            ).fetchone()
        if row is None:
            raise MigrationIdentityError("SQLite migration is absent")
        return row["migration_id"], row["migration_sha256"]

    def get(
        self, resource_kind: ResourceKind, tenant_id: str, context_id: str, resource_id: str
    ) -> ResourceRecord | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT resource_kind,tenant_id,context_id,resource_id,version,"
                "concurrency_token,resource_json,resource_sha256 FROM resources "
                "WHERE resource_kind=? AND tenant_id=? AND context_id=? AND resource_id=?",
                (resource_kind.value, tenant_id, context_id, resource_id),
            ).fetchone()
        if row is None:
            return None
        return _resource_from_row(row)

    def list_after(
        self,
        resource_kind: ResourceKind,
        tenant_id: str,
        context_id: str,
        after_resource_id: str | None,
        limit: int,
    ) -> Sequence[ResourceRecord]:
        if isinstance(limit, bool) or not 1 <= limit <= MAX_PAGE_SIZE + 1:
            raise LocalApiRuntimeError("repository page limit is invalid")
        query = (
            "SELECT resource_kind,tenant_id,context_id,resource_id,version,"
            "concurrency_token,resource_json,resource_sha256 FROM resources "
            "WHERE resource_kind=? AND tenant_id=? AND context_id=?"
        )
        parameters: list[Any] = [resource_kind.value, tenant_id, context_id]
        if after_resource_id is not None:
            query += " AND resource_id>?"
            parameters.append(after_resource_id)
        query += " ORDER BY resource_id ASC LIMIT ?"
        parameters.append(limit)
        with self._read() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return tuple(_resource_from_row(row) for row in rows)

    def lookup_idempotency(
        self, tenant_id: str, context_id: str, idempotency_sha256: str
    ) -> CommitResult | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT tenant_id,context_id,idempotency_sha256,request_sha256,"
                "result_json,result_sha256 FROM idempotency_results "
                "WHERE tenant_id=? AND context_id=? AND idempotency_sha256=?",
                (tenant_id, context_id, idempotency_sha256),
            ).fetchone()
        if row is None:
            return None
        return _result_from_row(row)

    def commit(self, command: CommitCommand) -> CommitResult:
        _validate_commit_command(command)
        record = command.record
        key = (record.resource_kind.value, record.tenant_id, record.context_id, record.resource_id)
        with self._write() as connection:
            replay = connection.execute(
                "SELECT tenant_id,context_id,idempotency_sha256,request_sha256,"
                "result_json,result_sha256 FROM idempotency_results "
                "WHERE tenant_id=? AND context_id=? AND idempotency_sha256=?",
                (record.tenant_id, record.context_id, command.idempotency_sha256),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != command.request_sha256:
                    raise RepositoryConflict("idempotency key was rebound")
                return _result_from_row(replay)
            live_row = connection.execute(
                "SELECT resource_kind,tenant_id,context_id,resource_id,version,"
                "concurrency_token,resource_json,resource_sha256 FROM resources "
                "WHERE resource_kind=? AND tenant_id=? AND context_id=? AND resource_id=?",
                key,
            ).fetchone()
            live = (
                None
                if live_row is None
                else _resource_from_row(live_row)
            )
            live_token = None if live is None else live.concurrency_token
            if live_token != command.expected_concurrency_token:
                raise RepositoryConflict("atomic concurrency token is stale")
            if live != command.prior_record:
                raise RepositoryConflict("prior resource changed before commit")
            document = canonical_json(record.to_dict())
            digest = _sha256_text(document)
            connection.execute(
                "INSERT INTO resources VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(resource_kind,tenant_id,context_id,resource_id) DO UPDATE SET "
                "version=excluded.version,concurrency_token=excluded.concurrency_token,"
                "resource_json=excluded.resource_json,resource_sha256=excluded.resource_sha256",
                (*key, record.version, record.concurrency_token, document, digest),
            )
            prior_audit_ref = None if live is None else live.audit_refs[-1]
            audit_json = canonical_json(command.audit_entry.to_dict())
            connection.execute(
                "INSERT INTO audit_entries VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    command.audit_entry.audit_ref,
                    record.tenant_id,
                    record.context_id,
                    record.resource_kind.value,
                    record.resource_id,
                    record.version,
                    prior_audit_ref,
                    audit_json,
                    _sha256_text(audit_json),
                ),
            )
            event_json = canonical_json(command.integration_event.to_dict())
            connection.execute(
                "INSERT INTO integration_events VALUES(?,?,?,?,?,?,?,?)",
                (
                    command.integration_event.event_id,
                    record.tenant_id,
                    record.context_id,
                    record.resource_kind.value,
                    record.resource_id,
                    record.version,
                    event_json,
                    _sha256_text(event_json),
                ),
            )
            result = CommitResult(
                request_sha256=command.request_sha256,
                idempotency_sha256=command.idempotency_sha256,
                record=record,
                audit_entry=command.audit_entry,
                integration_event=command.integration_event,
                replayed=False,
            )
            result_json = canonical_json(_result_document(result))
            connection.execute(
                "INSERT INTO idempotency_results VALUES(?,?,?,?,?,?)",
                (
                    record.tenant_id,
                    record.context_id,
                    command.idempotency_sha256,
                    command.request_sha256,
                    result_json,
                    _sha256_text(result_json),
                ),
            )
        return result

    def integration_events(self, tenant_id: str, context_id: str) -> tuple[IntegrationEvent, ...]:
        with self._read() as connection:
            rows = connection.execute(
                "SELECT event_id,tenant_id,context_id,resource_kind,resource_id,"
                "resource_version,event_json,event_sha256 FROM integration_events "
                "WHERE tenant_id=? AND context_id=? "
                "ORDER BY resource_kind,resource_id,resource_version",
                (tenant_id, context_id),
            ).fetchall()
        return tuple(_event_from_row(row) for row in rows)

    def verify_integrity(self) -> dict[str, int | str]:
        """Verify SQLite and content-bound record, audit, event, and result state."""

        with self._read() as connection:
            connection.execute("BEGIN")
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick != "ok":
                raise RepositoryIntegrityError("SQLite quick check failed")
            migrations = connection.execute(
                "SELECT version,migration_id,migration_sha256 "
                "FROM schema_migrations ORDER BY version"
            ).fetchall()
            if [tuple(row) for row in migrations] != [
                (1, SQLITE_MIGRATION_ID, SQLITE_MIGRATION_SHA256)
            ]:
                raise RepositoryIntegrityError("SQLite migration identity is inconsistent")
            resource_rows = connection.execute(
                "SELECT resource_kind,tenant_id,context_id,resource_id,version,"
                "concurrency_token,resource_json,resource_sha256 FROM resources"
            ).fetchall()
            audit_rows = connection.execute(
                "SELECT audit_ref,tenant_id,context_id,resource_kind,resource_id,"
                "resource_version,prior_audit_ref,entry_json,entry_sha256 FROM audit_entries"
            ).fetchall()
            event_rows = connection.execute(
                "SELECT event_id,tenant_id,context_id,resource_kind,resource_id,"
                "resource_version,event_json,event_sha256 FROM integration_events"
            ).fetchall()
            result_rows = connection.execute(
                "SELECT tenant_id,context_id,idempotency_sha256,request_sha256,"
                "result_json,result_sha256 FROM idempotency_results"
            ).fetchall()
            connection.rollback()
        resources: dict[tuple[str, str, str, str], ResourceRecord] = {}
        for row in resource_rows:
            record = _resource_from_row(row)
            key = (
                record.resource_kind.value, record.tenant_id,
                record.context_id, record.resource_id,
            )
            if len(record.audit_refs) != record.version:
                raise RepositoryIntegrityError("resource row metadata is inconsistent")
            resources[key] = record

        audits: dict[tuple[str, str, str, str, int], tuple[AuditEntry, sqlite3.Row]] = {}
        for row in audit_rows:
            audit = _audit_from_row(row)
            key = (
                audit.resource_kind.value, audit.tenant_id, audit.context_id,
                audit.resource_id, row["resource_version"],
            )
            if key in audits:
                raise RepositoryIntegrityError("audit row metadata is inconsistent")
            audits[key] = audit, row

        events: dict[tuple[str, str, str, str, int], IntegrationEvent] = {}
        for row in event_rows:
            event = _event_from_row(row)
            key = (
                event.resource_kind.value, event.tenant_id, event.context_id,
                event.resource_id, event.resource_version,
            )
            if key in events:
                raise RepositoryIntegrityError("event row metadata is inconsistent")
            events[key] = event

        results: dict[tuple[str, str, str, str, int], CommitResult] = {}
        for row in result_rows:
            result = _result_from_row(row)
            record = result.record
            key = (
                record.resource_kind.value, record.tenant_id,
                record.context_id, record.resource_id, record.version,
            )
            if key in results:
                raise RepositoryIntegrityError("idempotency row metadata is inconsistent")
            results[key] = result

        expected_versions = {
            (*key, version)
            for key, record in resources.items()
            for version in range(1, record.version + 1)
        }
        if set(audits) != expected_versions or set(events) != expected_versions:
            raise RepositoryIntegrityError("audit or event history is incomplete")
        if set(results) != expected_versions:
            raise RepositoryIntegrityError("idempotency history is incomplete")
        for key in sorted(expected_versions):
            record = resources[key[:4]]
            version = key[4]
            audit, audit_row = audits[key]
            event = events[key]
            result = results[key]
            prior = results[(*key[:4], version - 1)] if version > 1 else None
            if (
                audit.audit_ref != record.audit_refs[version - 1]
                or audit_row["prior_audit_ref"] != (
                    None if prior is None else prior.audit_entry.audit_ref
                )
                or audit.prior_concurrency_token != (
                    None if prior is None else prior.record.concurrency_token
                )
                or result.record.audit_refs != record.audit_refs[:version]
                or result.record.created_at != record.created_at
                or (version == record.version and result.record != record)
                or result.audit_entry != audit
                or result.integration_event != event
                or event.audit_ref != audit.audit_ref
            ):
                raise RepositoryIntegrityError("retained commit history is inconsistent")
        return {
            "audit_entries": len(audit_rows),
            "idempotency_results": len(result_rows),
            "integration_events": len(event_rows),
            "resources": len(resource_rows),
            "sqlite": "ok",
        }


def _validate_commit_command(command: CommitCommand) -> None:
    record = command.record
    audit = command.audit_entry
    event = command.integration_event
    expected_prior_refs: tuple[str, ...] = ()
    if command.prior_record is not None:
        prior = command.prior_record
        if (
            prior.resource_kind is not record.resource_kind
            or prior.resource_id != record.resource_id
            or prior.tenant_id != record.tenant_id
            or prior.context_id != record.context_id
            or prior.concurrency_token != command.expected_concurrency_token
            or record.version != prior.version + 1
            or record.created_at != prior.created_at
        ):
            raise RepositoryIntegrityError("commit prior resource binding is invalid")
        expected_prior_refs = prior.audit_refs
    elif command.expected_concurrency_token is not None or record.version != 1:
        raise RepositoryIntegrityError("create commit carries prior state")
    if record.audit_refs != (*expected_prior_refs, audit.audit_ref):
        raise RepositoryIntegrityError("record audit chain is not append-only")
    binding = (record.resource_kind, record.resource_id, record.tenant_id, record.context_id)
    if (
        (audit.resource_kind, audit.resource_id, audit.tenant_id, audit.context_id) != binding
        or audit.request_sha256 != command.request_sha256
        or audit.prior_concurrency_token != command.expected_concurrency_token
        or audit.resulting_concurrency_token != record.concurrency_token
    ):
        raise RepositoryIntegrityError("audit entry is not bound to the commit")
    if (
        (event.resource_kind, event.resource_id, event.tenant_id, event.context_id) != binding
        or event.resource_version != record.version
        or event.resource_sha256 != canonical_sha256(record.to_dict())
        or event.audit_ref != audit.audit_ref
    ):
        raise RepositoryIntegrityError("integration event is not bound to the commit")
    try:
        _validate_atomic_commit_result(
            CommitResult(
                request_sha256=command.request_sha256,
                idempotency_sha256=command.idempotency_sha256,
                record=record,
                audit_entry=audit,
                integration_event=event,
                replayed=False,
            )
        )
    except LocalApiServiceError as exc:
        raise RepositoryIntegrityError(
            "commit evidence does not reproduce its atomic joins"
        ) from exc


@dataclass(frozen=True, slots=True)
class HttpError(Exception):
    status: int
    code: str
    public_message: str


class LocalApiAsgiApp:
    """ASGI 3 callable that maps one bounded JSON route to LocalApiService."""

    def __init__(
        self,
        repository: SQLiteServiceRepository,
        authorizer: AccessAuthorizer,
        admitter: MutationAdmitter,
    ) -> None:
        self.repository = repository
        self.service = LocalApiService(repository, authorizer, admitter)

    async def __call__(
        self,
        scope: Mapping[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        correlation_id = _correlation_id(scope)
        try:
            _validate_scope(scope)
            body = await _receive_body(receive)
            raw = _decode_request(body)
            request = _service_request(raw)
            response = self.service.handle(request)
            await _send_json(
                send,
                200,
                {
                    "correlation_id": correlation_id,
                    "data": response.to_dict(),
                    "schema_version": SCHEMA_VERSION,
                },
                correlation_id,
            )
        except HttpError as exc:
            await _send_error(send, exc, correlation_id)
        except LocalApiServiceError as exc:
            await _send_error(send, _normalize_service_error(exc), correlation_id)
        except RepositoryConflict:
            await _send_error(
                send,
                HttpError(409, "repository_conflict", "The stored resource changed."),
                correlation_id,
            )
        except RepositoryBusy:
            await _send_error(
                send,
                HttpError(503, "repository_busy", "The local repository is busy."),
                correlation_id,
            )
        except (MigrationIdentityError, RepositoryIntegrityError):
            await _send_error(
                send,
                HttpError(500, "repository_integrity", "Repository integrity validation failed."),
                correlation_id,
            )
        except Exception:
            await _send_error(
                send,
                HttpError(500, "internal_error", "The request could not be completed."),
                correlation_id,
            )


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class OfflinePlanningPreviewAsgiApp:
    """One bounded read-only planning route with injected storage and policy."""

    def __init__(
        self,
        reader: PlanningBundleReader,
        authorizer: AccessAuthorizer,
        registry: ExpertRegistry,
        *,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        self.service = OfflinePlanningPreviewService(reader, authorizer, registry)
        self.clock = clock

    async def __call__(
        self,
        scope: Mapping[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        correlation_id = _correlation_id(scope)
        try:
            _validate_scope(scope, expected_path=PLANNING_PREVIEW_PATH)
            raw = _decode_request(await _receive_body(receive))
            request = _preview_request(raw, self.clock())
            preview = self.service.preview(request, as_of=request.requested_at)
            await _send_json(
                send,
                200,
                {
                    "correlation_id": correlation_id,
                    "data": preview,
                    "schema_version": SCHEMA_VERSION,
                },
                correlation_id,
            )
        except HttpError as exc:
            await _send_error(send, exc, correlation_id)
        except OfflinePlanningPreviewError as exc:
            await _send_error(send, _normalize_preview_error(exc), correlation_id)
        except Exception:
            await _send_error(
                send,
                HttpError(500, "internal_error", "The request could not be completed."),
                correlation_id,
            )


def _preview_request(raw: Mapping[str, Any], now: str) -> PlanningPreviewRequest:
    if set(raw) != {
        "access",
        "bundle_sha256",
        "expected_scope_sha256",
        "request_id",
    }:
        raise HttpError(400, "invalid_request_shape", "Preview request fields are invalid.")
    access = raw["access"]
    if not isinstance(access, dict) or set(access) != {
        "tenant_id",
        "context_id",
        "principal_id",
        "session_ref",
    }:
        raise HttpError(400, "invalid_access_context", "Access context fields are invalid.")
    try:
        return PlanningPreviewRequest(
            request_id=raw["request_id"],
            access=AccessContext(**access),
            requested_at=now,
            bundle_sha256=raw["bundle_sha256"],
            expected_scope_sha256=raw["expected_scope_sha256"],
        )
    except (TypeError, ValueError) as exc:
        raise HttpError(400, "invalid_request", "The preview request is invalid.") from exc


def _normalize_preview_error(exc: OfflinePlanningPreviewError) -> HttpError:
    message = str(exc).lower()
    if "authorization" in message:
        return HttpError(403, "authorization_denied", "Authorization was denied.")
    if "not found" in message or "tenant binding" in message:
        return HttpError(404, "preview_not_found", "The planning preview was not found.")
    return HttpError(409, "preview_integrity", "The planning preview is unavailable.")


def _headers(scope: Mapping[str, Any]) -> dict[str, str]:
    raw_headers = scope.get("headers", ())
    if not isinstance(raw_headers, Sequence) or len(raw_headers) > MAX_HEADER_COUNT:
        raise HttpError(431, "headers_too_large", "Request headers exceed the limit.")
    total = 0
    headers: dict[str, str] = {}
    try:
        for name, value in raw_headers:
            total += len(name) + len(value)
            decoded_name = bytes(name).decode("ascii").lower()
            decoded_value = bytes(value).decode("ascii")
            if decoded_name in headers:
                raise HttpError(400, "invalid_headers", "Duplicate headers are not accepted.")
            headers[decoded_name] = decoded_value
    except (TypeError, UnicodeDecodeError, ValueError) as exc:
        raise HttpError(400, "invalid_headers", "Request headers are invalid.") from exc
    if total > MAX_HEADER_BYTES:
        raise HttpError(431, "headers_too_large", "Request headers exceed the limit.")
    return headers


def _correlation_id(scope: Mapping[str, Any]) -> str:
    try:
        value = _headers(scope).get("x-correlation-id")
    except HttpError:
        value = None
    if value is not None and CORRELATION_RE.fullmatch(value) is not None:
        return value
    return "corr:" + uuid.uuid4().hex


def _validate_scope(scope: Mapping[str, Any], *, expected_path: str = ASGI_PATH) -> None:
    if scope.get("type") != "http":
        raise HttpError(400, "invalid_scope", "Only HTTP ASGI requests are accepted.")
    if scope.get("http_version") not in {"1.1", "2", "3"}:
        raise HttpError(400, "invalid_http_version", "The HTTP version is not supported.")
    if scope.get("method") != "POST":
        raise HttpError(405, "method_not_allowed", "Only POST is accepted.")
    if scope.get("path") != expected_path or scope.get("query_string", b""):
        raise HttpError(404, "route_not_found", "The versioned route was not found.")
    headers = _headers(scope)
    if "authorization" in headers or "cookie" in headers:
        raise HttpError(
            400,
            "credential_transport_rejected",
            "Credential-bearing headers are not accepted by this local adapter.",
        )
    content_type = headers.get("content-type", "").lower().replace(" ", "")
    if content_type not in {"application/json", "application/json;charset=utf-8"}:
        raise HttpError(415, "unsupported_media_type", "Content-Type must be application/json.")


async def _receive_body(receive: AsgiReceive) -> bytes:
    body = bytearray()
    while True:
        message = await receive()
        if message.get("type") == "http.disconnect":
            raise HttpError(400, "request_disconnected", "The request was disconnected.")
        if message.get("type") != "http.request":
            raise HttpError(400, "invalid_asgi_event", "The request event is invalid.")
        chunk = message.get("body", b"")
        if not isinstance(chunk, bytes):
            raise HttpError(400, "invalid_body", "The request body is invalid.")
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HttpError(413, "body_too_large", "The request body exceeds the limit.")
        if not message.get("more_body", False):
            return bytes(body)


def _decode_request(body: bytes) -> Mapping[str, Any]:
    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HttpError(400, "invalid_json", "The request body must be valid UTF-8 JSON.") from exc
    if not isinstance(raw, dict):
        raise HttpError(400, "invalid_request", "The request body must be a JSON object.")
    _validate_wire_value(raw)
    return raw


def _validate_wire_value(value: Any, *, key: str | None = None) -> None:
    if key is not None and key.lower() in FORBIDDEN_VALUE_KEYS:
        raise HttpError(
            400,
            "credential_value_rejected",
            "Credential values are not accepted in wire data.",
        )
    if isinstance(value, str):
        if (
            WINDOWS_PATH_RE.search(value)
            or value.startswith("/")
            or "../" in value
            or "..\\" in value
        ):
            raise HttpError(
                400,
                "filesystem_path_rejected",
                "Filesystem paths are not accepted in wire data.",
            )
        return
    if isinstance(value, list):
        for item in value:
            _validate_wire_value(item)
        return
    if isinstance(value, dict):
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise HttpError(400, "invalid_request", "Object keys must be strings.")
            _validate_wire_value(child, key=child_key)


def _service_request(raw: Mapping[str, Any]) -> ServiceRequest:
    allowed = {
        "access",
        "cursor",
        "expected_concurrency_token",
        "idempotency_key",
        "operation",
        "page_size",
        "payload",
        "request_id",
        "requested_at",
        "resource_id",
        "resource_kind",
    }
    required = {"access", "operation", "request_id", "requested_at", "resource_kind"}
    if not required.issubset(raw) or not set(raw).issubset(allowed):
        raise HttpError(400, "invalid_request_shape", "Request fields do not match the API.")
    access = raw["access"]
    if not isinstance(access, dict) or set(access) != {
        "context_id",
        "principal_id",
        "session_ref",
        "tenant_id",
    }:
        raise HttpError(400, "invalid_access_context", "Access context fields are invalid.")
    page_size = raw.get("page_size")
    if page_size is not None and (
        isinstance(page_size, bool) or not isinstance(page_size, int) or page_size > MAX_PAGE_SIZE
    ):
        raise HttpError(400, "page_limit_exceeded", "Page size exceeds the limit.")
    try:
        return ServiceRequest(
            request_id=raw["request_id"],
            operation=Operation(raw["operation"]),
            access=AccessContext(
                tenant_id=access["tenant_id"],
                context_id=access["context_id"],
                principal_id=access["principal_id"],
                session_ref=access["session_ref"],
            ),
            requested_at=raw["requested_at"],
            resource_kind=ResourceKind(raw["resource_kind"]),
            resource_id=raw.get("resource_id"),
            payload=raw.get("payload"),
            expected_concurrency_token=raw.get("expected_concurrency_token"),
            idempotency_key=raw.get("idempotency_key"),
            cursor=raw.get("cursor"),
            page_size=page_size,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise HttpError(400, "invalid_request", "The service request is invalid.") from exc


def _normalize_service_error(exc: LocalApiServiceError) -> HttpError:
    message = str(exc).lower()
    if "authorization" in message:
        return HttpError(403, "authorization_denied", "Authorization was denied.")
    if "admission" in message:
        return HttpError(403, "mutation_rejected", "Mutation admission was rejected.")
    if "not found" in message:
        return HttpError(404, "resource_not_found", "The resource was not found.")
    if any(token in message for token in ("conflict", "stale", "rebound", "existing state")):
        return HttpError(409, "state_conflict", "The request conflicts with stored state.")
    return HttpError(400, "invalid_request", "The service request is invalid.")


async def _send_error(send: AsgiSend, error: HttpError, correlation_id: str) -> None:
    await _send_json(
        send,
        error.status,
        {
            "correlation_id": correlation_id,
            "error": {"code": error.code, "message": error.public_message},
            "schema_version": SCHEMA_VERSION,
        },
        correlation_id,
    )


async def _send_json(
    send: AsgiSend,
    status: int,
    document: Mapping[str, Any],
    correlation_id: str,
) -> None:
    body = canonical_json(dict(document)).encode("ascii")
    await send(
        {
            "headers": (
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
                (b"x-correlation-id", correlation_id.encode("ascii")),
            ),
            "status": status,
            "type": "http.response.start",
        }
    )
    await send({"body": body, "type": "http.response.body"})

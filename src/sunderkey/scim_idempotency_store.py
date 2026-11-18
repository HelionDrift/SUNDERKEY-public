"""Local durable coordination for the existing non-production SCIM protocol."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator

from .enterprise_identity_contracts import EnterpriseIdentityError, canonical_json, canonical_sha256
from .enterprise_identity_runtime import (
    COMPLETION_KIND,
    RESERVATION_KIND,
    EnterpriseIdentityRuntimeError,
    ScimIdempotencyCompletion,
    ScimIdempotencyReservation,
)

SCHEMA_VERSION = 1
APPLICATION_ID = 0x5343494D
COORDINATION_SCOPE = "local_nonproduction_coordination"
MAX_PATH_CHARACTERS = 4096
MAX_RECORD_BYTES = 4096
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_RESERVATION_FIELDS = (
    "store_id",
    "reservation_token",
    "idempotency_key",
    "command_sha256",
    "admission_sha256",
    "dispatcher_id",
    "environment",
    "reserved_at",
)
_COMPLETION_FIELDS = ("store_id", "reservation_sha256", "result_sha256", "completed_at")
_SCHEMA = (
    (
        "table",
        "scim_store_metadata",
        """CREATE TABLE scim_store_metadata (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        schema_version INTEGER NOT NULL CHECK(typeof(schema_version) = 'integer'),
        store_id TEXT NOT NULL CHECK(typeof(store_id) = 'text'),
        coordination_scope TEXT NOT NULL CHECK(typeof(coordination_scope) = 'text'),
        schema_sha256 TEXT NOT NULL CHECK(typeof(schema_sha256) = 'text')
    )""",
    ),
    (
        "table",
        "scim_reservations",
        """CREATE TABLE scim_reservations (
        idempotency_key TEXT PRIMARY KEY NOT NULL CHECK(typeof(idempotency_key) = 'text'),
        reservation_id TEXT NOT NULL UNIQUE CHECK(typeof(reservation_id) = 'text'),
        reservation_sha256 TEXT NOT NULL UNIQUE CHECK(typeof(reservation_sha256) = 'text'),
        reservation_json TEXT NOT NULL CHECK(typeof(reservation_json) = 'text')
    )""",
    ),
    (
        "table",
        "scim_completions",
        """CREATE TABLE scim_completions (
        reservation_sha256 TEXT PRIMARY KEY NOT NULL
            REFERENCES scim_reservations(reservation_sha256) ON DELETE RESTRICT,
        completion_id TEXT NOT NULL UNIQUE CHECK(typeof(completion_id) = 'text'),
        completion_sha256 TEXT NOT NULL UNIQUE CHECK(typeof(completion_sha256) = 'text'),
        completion_json TEXT NOT NULL CHECK(typeof(completion_json) = 'text'),
        CHECK(typeof(reservation_sha256) = 'text')
    )""",
    ),
    *tuple(
        (
            "trigger",
            f"{table}_{operation.lower()}_guard",
            f"CREATE TRIGGER {table}_{operation.lower()}_guard BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'SCIM custody is immutable'); END",
        )
        for table in ("scim_store_metadata", "scim_reservations", "scim_completions")
        for operation in ("UPDATE", "DELETE")
    ),
    (
        "trigger",
        "scim_store_metadata_insert_guard",
        "CREATE TRIGGER scim_store_metadata_insert_guard BEFORE INSERT ON scim_store_metadata "
        "WHEN EXISTS (SELECT 1 FROM scim_store_metadata) "
        "BEGIN SELECT RAISE(ABORT, 'SCIM metadata already exists'); END",
    ),
    (
        "trigger",
        "scim_reservations_insert_guard",
        "CREATE TRIGGER scim_reservations_insert_guard BEFORE INSERT ON scim_reservations "
        "WHEN EXISTS (SELECT 1 FROM scim_reservations WHERE "
        "idempotency_key = NEW.idempotency_key OR reservation_id = NEW.reservation_id "
        "OR reservation_sha256 = NEW.reservation_sha256) "
        "BEGIN SELECT RAISE(ABORT, 'SCIM reservation already exists'); END",
    ),
    (
        "trigger",
        "scim_completions_insert_guard",
        "CREATE TRIGGER scim_completions_insert_guard BEFORE INSERT ON scim_completions "
        "WHEN EXISTS (SELECT 1 FROM scim_completions WHERE "
        "reservation_sha256 = NEW.reservation_sha256 OR completion_id = NEW.completion_id "
        "OR completion_sha256 = NEW.completion_sha256) "
        "BEGIN SELECT RAISE(ABORT, 'SCIM completion already exists'); END",
    ),
)
_SCHEMA_SHA256 = canonical_sha256(
    {
        "application_id": APPLICATION_ID,
        "domain": "sunderkey.scim-sqlite-schema.v1",
        "schema": [list(item) for item in _SCHEMA],
        "schema_version": SCHEMA_VERSION,
    }
)


class ScimIdempotencyStoreError(EnterpriseIdentityRuntimeError):
    """A local SCIM reservation, completion or SQLite integrity check failed."""


def _text(value: Any, label: str, pattern: re.Pattern[str], maximum: int) -> str:
    if type(value) is not str or len(value) > maximum or pattern.fullmatch(value) is None:
        raise ScimIdempotencyStoreError(f"{label} must be an exact bounded native string")
    return value


def _timestamp(value: Any, label: str) -> str:
    value = _text(value, label, _UTC, 20)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ScimIdempotencyStoreError(f"{label} must be valid canonical UTC") from exc
    return value


def _local_path(value: Any) -> tuple[Path, tuple[int, int] | None]:
    if type(value) is str:
        declared = value
    elif isinstance(value, Path):
        declared = str(value)
    else:
        raise ScimIdempotencyStoreError("path must be an explicit local path")
    if (
        not declared
        or len(declared) > MAX_PATH_CHARACTERS
        or any(ord(char) < 32 for char in declared)
        or declared.startswith(("\\\\", "//"))
        or "://" in declared
        or declared.lower().startswith("file:")
        or declared == ":memory:"
    ):
        raise ScimIdempotencyStoreError("path must not be a URI, UNC or device path")
    path = Path(declared)
    if not path.is_absolute() or any(part in {".", ".."} for part in re.split(r"[\\/]", declared)):
        raise ScimIdempotencyStoreError("path must be an unambiguous absolute local path")
    windows = PureWindowsPath(declared)
    if windows.drive.startswith("\\\\"):
        raise ScimIdempotencyStoreError("UNC and device paths are forbidden")
    if os.name != "nt" and len(path.parts) > 1 and path.parts[1] == "dev":
        raise ScimIdempotencyStoreError("device paths are forbidden")
    parts = path.parts[1:]
    if any(":" in part for part in parts):
        raise ScimIdempotencyStoreError("alternate streams and URI paths are forbidden")
    if os.name == "nt":
        devices = {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
        devices.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10))
        if any(
            part.endswith((" ", "."))
            or part.split(".")[0].upper() in devices
            or PureWindowsPath(part).is_reserved()
            for part in parts
        ):
            raise ScimIdempotencyStoreError("ambiguous Windows device paths are forbidden")
    if not path.parent.is_dir():
        raise ScimIdempotencyStoreError("path needs an existing parent and a regular local file")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return path, None
    except OSError as exc:
        raise ScimIdempotencyStoreError("local file identity could not be read") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ScimIdempotencyStoreError("path must identify a regular local file")
    return path, (metadata.st_dev, metadata.st_ino)


def _document(record: ScimIdempotencyReservation | ScimIdempotencyCompletion) -> str:
    if type(record) is ScimIdempotencyReservation:
        raw = {
            **record._body(),
            "reservation_id": record.reservation_id,
            "reservation_sha256": record.reservation_sha256,
        }
    else:
        raw = {
            **record._body(),
            "completion_id": record.completion_id,
            "completion_sha256": record.completion_sha256,
        }
    try:
        document = canonical_json(raw)
    except EnterpriseIdentityError as exc:
        raise ScimIdempotencyStoreError("record cannot be serialized") from exc
    if len(document) > MAX_RECORD_BYTES:
        raise ScimIdempotencyStoreError("record exceeds the byte bound")
    return document


def _capture_reservation(value: Any) -> ScimIdempotencyReservation:
    if type(value) is not ScimIdempotencyReservation:
        raise ScimIdempotencyStoreError("reservation must be the native protocol record")
    try:
        fields = {name: getattr(value, name) for name in _RESERVATION_FIELDS}
        supplied_id = getattr(value, "reservation_id")
        supplied_sha = getattr(value, "reservation_sha256")
    except AttributeError as exc:
        raise ScimIdempotencyStoreError("reservation fields are missing") from exc
    for name in ("store_id", "reservation_token", "idempotency_key", "dispatcher_id"):
        _text(fields[name], name, _ID, 256)
    for name in ("command_sha256", "admission_sha256"):
        _text(fields[name], name, _SHA, 71)
    if type(fields["environment"]) is not str or fields["environment"] not in {"test", "staging"}:
        raise ScimIdempotencyStoreError("environment must be native test or staging")
    _timestamp(fields["reserved_at"], "reserved_at")
    candidate = ScimIdempotencyReservation(**fields)
    if (
        type(supplied_id) is not str
        or type(supplied_sha) is not str
        or supplied_id != candidate.reservation_id
        or supplied_sha != candidate.reservation_sha256
    ):
        raise ScimIdempotencyStoreError("reservation does not replay its content address")
    return candidate


def _decode(
    document: Any, completion: bool
) -> ScimIdempotencyReservation | ScimIdempotencyCompletion:
    if (
        type(document) is not str
        or not 1 <= len(document) <= MAX_RECORD_BYTES
        or not document.isascii()
    ):
        raise ScimIdempotencyStoreError("stored record is not bounded canonical ASCII JSON")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ScimIdempotencyStoreError("stored record contains duplicate keys")
            result[key] = value
        return result

    def reject_number(_value: str) -> None:
        raise ScimIdempotencyStoreError("stored record contains unsupported numbers")

    try:
        raw = json.loads(
            document,
            object_pairs_hook=pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (ValueError, RecursionError) as exc:
        raise ScimIdempotencyStoreError("stored record is invalid JSON") from exc
    fields = _COMPLETION_FIELDS if completion else _RESERVATION_FIELDS
    id_field = "completion_id" if completion else "reservation_id"
    sha_field = "completion_sha256" if completion else "reservation_sha256"
    expected = {*fields, id_field, sha_field, "kind", "schema_version"}
    kind = COMPLETION_KIND if completion else RESERVATION_KIND
    if (
        type(raw) is not dict
        or len(raw) != len(expected)
        or set(raw) != expected
        or type(raw["schema_version"]) is not int
        or raw["schema_version"] != 1
        or type(raw["kind"]) is not str
        or raw["kind"] != kind
        or any(type(raw[name]) is not str for name in (*fields, id_field, sha_field))
    ):
        raise ScimIdempotencyStoreError("stored record has invalid native fields")
    try:
        if completion:
            _text(raw["store_id"], "store_id", _ID, 256)
            for name in ("reservation_sha256", "result_sha256"):
                _text(raw[name], name, _SHA, 71)
            _timestamp(raw["completed_at"], "completed_at")
            record = ScimIdempotencyCompletion(**{name: raw[name] for name in fields})
        else:
            record = ScimIdempotencyReservation(**{name: raw[name] for name in fields})
            record = _capture_reservation(record)
    except EnterpriseIdentityRuntimeError as exc:
        raise ScimIdempotencyStoreError("stored record values are invalid") from exc
    if _document(record) != document:
        raise ScimIdempotencyStoreError(
            "stored record does not replay its canonical content address"
        )
    return record


def _busy(error: sqlite3.Error) -> bool:
    return getattr(error, "sqlite_errorcode", 0) & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


@dataclass(frozen=True, slots=True, init=False)
class SQLiteScimIdempotencyStore:
    """An explicitly selected local SQLite implementation, not an authority issuer."""

    path: Path
    store_id: str
    busy_timeout_ms: int
    _file_identity: tuple[int, int]

    def __init__(self, path: Path | str, *, store_id: str, busy_timeout_ms: int = 5000) -> None:
        owned_path, existing_identity = _local_path(path)
        owned_id = _text(store_id, "store_id", _ID, 256)
        if type(busy_timeout_ms) is not int or not 1 <= busy_timeout_ms <= 120_000:
            raise ScimIdempotencyStoreError("busy_timeout_ms must be a native integer in 1..120000")
        object.__setattr__(self, "path", owned_path)
        object.__setattr__(self, "store_id", owned_id)
        object.__setattr__(self, "busy_timeout_ms", busy_timeout_ms)
        created = existing_identity is None
        if created:
            try:
                descriptor = os.open(owned_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    metadata = os.fstat(descriptor)
                    existing_identity = (metadata.st_dev, metadata.st_ino)
                finally:
                    os.close(descriptor)
            except FileExistsError as exc:
                raise ScimIdempotencyStoreError(
                    "a file appeared before exclusive creation"
                ) from exc
            except OSError as exc:
                raise ScimIdempotencyStoreError("exclusive local file creation failed") from exc
        object.__setattr__(self, "_file_identity", existing_identity)
        try:
            with self._transaction(initializing=created) as connection:
                if created:
                    count = connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]
                    app = connection.execute("PRAGMA application_id").fetchone()[0]
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    if count != 0 or app != 0 or version != 0:
                        raise ScimIdempotencyStoreError("exclusively created file is not empty")
                    for _kind, _name, sql in _SCHEMA:
                        connection.execute(sql)
                    connection.execute(
                        "INSERT INTO scim_store_metadata VALUES (1, ?, ?, ?, ?)",
                        (SCHEMA_VERSION, self.store_id, COORDINATION_SCOPE, _SCHEMA_SHA256),
                    )
                    connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._verify_schema(connection)
        except sqlite3.Error as exc:
            raise ScimIdempotencyStoreError("SCIM SQLite initialization failed") from exc

    @contextmanager
    def _transaction(self, *, initializing: bool = False) -> Iterator[sqlite3.Connection]:
        if not initializing:
            self._read_only_preflight()
        self._verify_file_identity()
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw",
            uri=True,
            isolation_level=None,
            timeout=self.busy_timeout_ms / 1000,
        )
        try:
            self._verify_file_identity()
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            if (
                connection.execute("PRAGMA journal_mode").fetchone() != ("delete",)
                or connection.execute("PRAGMA foreign_keys").fetchone() != (1,)
                or connection.execute("PRAGMA synchronous").fetchone() != (2,)
            ):
                raise ScimIdempotencyStoreError("SQLite coordination settings do not match")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _verify_file_identity(self) -> None:
        try:
            metadata = self.path.lstat()
        except OSError as exc:
            raise ScimIdempotencyStoreError(
                "selected local file is missing or unavailable"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != self._file_identity
        ):
            raise ScimIdempotencyStoreError("selected local file identity changed")

    def _read_only_preflight(self) -> None:
        self._verify_file_identity()
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=ro",
            uri=True,
            isolation_level=None,
            timeout=self.busy_timeout_ms / 1000,
        )
        try:
            self._verify_file_identity()
            connection.execute("BEGIN")
            self._verify_schema(connection)
            if connection.execute("PRAGMA journal_mode").fetchone() != ("delete",):
                raise ScimIdempotencyStoreError("SQLite coordination settings do not match")
            self._verify_file_identity()
        finally:
            connection.rollback()
            connection.close()

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise ScimIdempotencyStoreError("SQLite application or schema identity does not match")
        count = connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%'"
        ).fetchone()[0]
        if count != len(_SCHEMA):
            raise ScimIdempotencyStoreError("SQLite contains missing or unknown schema objects")
        rows = connection.execute(
            "SELECT CASE WHEN typeof(type) = 'text' AND length(CAST(type AS BLOB)) "
            "BETWEEN 1 AND 16 THEN type END, "
            "CASE WHEN typeof(name) = 'text' AND length(CAST(name AS BLOB)) "
            "BETWEEN 1 AND 256 THEN name END, "
            "CASE WHEN typeof(sql) = 'text' AND length(CAST(sql AS BLOB)) <= 8192 "
            "THEN sql END "
            "FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY name"
        ).fetchall()
        expected = sorted(_SCHEMA, key=lambda item: item[1])
        if rows != expected:
            raise ScimIdempotencyStoreError("SQLite schema or immutable guards do not match")
        if connection.execute("SELECT COUNT(*) FROM scim_store_metadata").fetchone()[0] != 1:
            raise ScimIdempotencyStoreError("SQLite store identity metadata is invalid")
        metadata = connection.execute(
            "SELECT singleton, schema_version, "
            "CASE WHEN typeof(store_id) = 'text' AND length(CAST(store_id AS BLOB)) "
            "BETWEEN 1 AND 256 THEN store_id END, "
            "CASE WHEN coordination_scope = ? THEN coordination_scope END, "
            "CASE WHEN typeof(schema_sha256) = 'text' AND length(schema_sha256) = 71 "
            "THEN schema_sha256 END FROM scim_store_metadata",
            (COORDINATION_SCOPE,),
        ).fetchone()
        if metadata != (1, SCHEMA_VERSION, self.store_id, COORDINATION_SCOPE, _SCHEMA_SHA256):
            raise ScimIdempotencyStoreError("SQLite store identity metadata does not match")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ScimIdempotencyStoreError("SQLite contains orphaned completion custody")

    def _reservation(
        self, connection: sqlite3.Connection, key: str
    ) -> ScimIdempotencyReservation | None:
        row = connection.execute(
            "SELECT CASE WHEN typeof(reservation_id) = 'text' AND length(reservation_id) = 37 "
            "THEN reservation_id END, "
            "CASE WHEN typeof(reservation_sha256) = 'text' AND length(reservation_sha256) = 71 "
            "THEN reservation_sha256 END, "
            "CASE WHEN length(CAST(reservation_json AS BLOB)) BETWEEN 1 AND ? "
            "THEN reservation_json END FROM scim_reservations WHERE idempotency_key = ?",
            (MAX_RECORD_BYTES, key),
        ).fetchone()
        if row is None:
            return None
        record = _decode(row[2], False)
        if (
            record.store_id != self.store_id
            or record.idempotency_key != key
            or (record.reservation_id, record.reservation_sha256) != row[:2]
        ):
            raise ScimIdempotencyStoreError("stored reservation binding does not match")
        return record

    def _completion(
        self, connection: sqlite3.Connection, reservation: ScimIdempotencyReservation
    ) -> ScimIdempotencyCompletion | None:
        row = connection.execute(
            "SELECT CASE WHEN typeof(completion_id) = 'text' AND length(completion_id) = 37 "
            "THEN completion_id END, "
            "CASE WHEN typeof(completion_sha256) = 'text' AND length(completion_sha256) = 71 "
            "THEN completion_sha256 END, "
            "CASE WHEN length(CAST(completion_json AS BLOB)) BETWEEN 1 AND ? "
            "THEN completion_json END FROM scim_completions WHERE reservation_sha256 = ?",
            (MAX_RECORD_BYTES, reservation.reservation_sha256),
        ).fetchone()
        if row is None:
            return None
        record = _decode(row[2], True)
        if (
            record.store_id != self.store_id
            or record.reservation_sha256 != reservation.reservation_sha256
            or record.completed_at < reservation.reserved_at
            or (record.completion_id, record.completion_sha256) != row[:2]
        ):
            raise ScimIdempotencyStoreError("stored completion binding does not match")
        return record

    def reserve(
        self,
        *,
        idempotency_key: str,
        command_sha256: str,
        admission_sha256: str,
        dispatcher_id: str,
        environment: str,
        reserved_at: str,
    ) -> ScimIdempotencyReservation | None:
        binding = {
            "store_id": self.store_id,
            "idempotency_key": _text(idempotency_key, "idempotency_key", _ID, 256),
            "command_sha256": _text(command_sha256, "command_sha256", _SHA, 71),
            "admission_sha256": _text(admission_sha256, "admission_sha256", _SHA, 71),
            "dispatcher_id": _text(dispatcher_id, "dispatcher_id", _ID, 256),
            "environment": environment,
            "reserved_at": _timestamp(reserved_at, "reserved_at"),
        }
        if type(environment) is not str or environment not in {"test", "staging"}:
            raise ScimIdempotencyStoreError("environment must be native test or staging")
        token = canonical_sha256({"content": binding, "domain": "sunderkey.scim-sqlite-token.v1"})
        reservation = ScimIdempotencyReservation(
            reservation_token="reservation:" + token[7:], **binding
        )
        document = _document(reservation)
        try:
            with self._transaction() as connection:
                self._verify_schema(connection)
                existing = self._reservation(connection, idempotency_key)
                if existing is not None:
                    self._completion(connection, existing)
                    return None
                connection.execute(
                    "INSERT INTO scim_reservations VALUES (?, ?, ?, ?)",
                    (
                        idempotency_key,
                        reservation.reservation_id,
                        reservation.reservation_sha256,
                        document,
                    ),
                )
                if _document(self._reservation(connection, idempotency_key)) != document:
                    raise ScimIdempotencyStoreError("new reservation did not replay")
            return reservation
        except sqlite3.Error as exc:
            if _busy(exc):
                return None
            raise ScimIdempotencyStoreError("SCIM SQLite reservation failed") from exc

    def complete(
        self, reservation: ScimIdempotencyReservation, *, result_sha256: str, completed_at: str
    ) -> ScimIdempotencyCompletion:
        owned = _capture_reservation(reservation)
        result_sha256 = _text(result_sha256, "result_sha256", _SHA, 71)
        completed_at = _timestamp(completed_at, "completed_at")
        if owned.store_id != self.store_id or completed_at < owned.reserved_at:
            raise ScimIdempotencyStoreError("completion store or chronology does not match")
        completion = ScimIdempotencyCompletion(
            self.store_id, owned.reservation_sha256, result_sha256, completed_at
        )
        document = _document(completion)
        try:
            with self._transaction() as connection:
                self._verify_schema(connection)
                held = self._reservation(connection, owned.idempotency_key)
                if held is None or _document(held) != _document(owned):
                    raise ScimIdempotencyStoreError("exact reservation is not held")
                if self._completion(connection, held) is not None:
                    raise ScimIdempotencyStoreError("reservation is already completed")
                connection.execute(
                    "INSERT INTO scim_completions VALUES (?, ?, ?, ?)",
                    (
                        owned.reservation_sha256,
                        completion.completion_id,
                        completion.completion_sha256,
                        document,
                    ),
                )
                if _document(self._completion(connection, held)) != document:
                    raise ScimIdempotencyStoreError("new completion did not replay")
            return completion
        except sqlite3.Error as exc:
            raise ScimIdempotencyStoreError("SCIM SQLite completion failed") from exc


__all__ = ["SQLiteScimIdempotencyStore", "ScimIdempotencyStoreError"]

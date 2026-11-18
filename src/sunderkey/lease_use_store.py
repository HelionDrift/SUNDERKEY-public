"""Explicit local SQLite custody for the injected atomic lease-use protocol.

This leaf stores secret-free reservation metadata only. It does not authenticate
leases, determine current authority, execute a provider, or qualify deployment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .assessment_transport_contracts import canonical_json
from .authorized_target_session_runtime import (
    AuthorizedTargetSessionRuntimeError,
    LeaseUseCompletionEvidence,
    LeaseUseReservationEvidence,
    LeaseUseReservationRequest,
    LeaseUseStoreFailure,
)
from .credential_broker_contracts import LeaseMode

APPLICATION_ID = 0x534C5531
SCHEMA_VERSION = 1
STORE_KIND = "sunderkey.local_sqlite_atomic_lease_use.v1"
MAX_RECORDS = 4096
MAX_DOCUMENT_BYTES = 4096
MAX_BUSY_TIMEOUT_MS = 1000

_DDL = (
    "CREATE TABLE lease_use_store_identity ("
    "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "store_kind TEXT NOT NULL, schema_sha256 TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE lease_use_reservations ("
    "reservation_key_sha256 TEXT PRIMARY KEY, "
    "lease_id TEXT NOT NULL, lease_sha256 TEXT NOT NULL, lease_mode TEXT NOT NULL, "
    "lease_use_number INTEGER NOT NULL CHECK(lease_use_number BETWEEN 1 AND 100), "
    "request_json TEXT NOT NULL, reservation_id TEXT NOT NULL, "
    "reservation_sha256 TEXT NOT NULL) WITHOUT ROWID",
    "CREATE UNIQUE INDEX lease_use_reservation_id ON lease_use_reservations(reservation_id)",
    "CREATE UNIQUE INDEX lease_use_reservation_sha ON lease_use_reservations(reservation_sha256)",
    "CREATE UNIQUE INDEX lease_use_number ON "
    "lease_use_reservations(lease_id,lease_sha256,lease_use_number)",
    "CREATE TABLE lease_use_completions ("
    "reservation_id TEXT PRIMARY KEY REFERENCES lease_use_reservations(reservation_id), "
    "completion_json TEXT NOT NULL, completion_sha256 TEXT NOT NULL) WITHOUT ROWID",
    "CREATE UNIQUE INDEX lease_use_completion_sha ON lease_use_completions(completion_sha256)",
    "CREATE TRIGGER lease_use_identity_no_update BEFORE UPDATE ON "
    "lease_use_store_identity BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_identity_no_delete BEFORE DELETE ON "
    "lease_use_store_identity BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_identity_no_replace BEFORE INSERT ON "
    "lease_use_store_identity WHEN EXISTS(SELECT 1 FROM lease_use_store_identity) "
    "BEGIN SELECT RAISE(ABORT,'lease-use identity already exists'); END",
    "CREATE TRIGGER lease_use_reservation_no_update BEFORE UPDATE ON "
    "lease_use_reservations BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_reservation_no_delete BEFORE DELETE ON "
    "lease_use_reservations BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_reservation_no_replace BEFORE INSERT ON "
    "lease_use_reservations WHEN EXISTS(SELECT 1 FROM lease_use_reservations WHERE "
    "reservation_key_sha256=NEW.reservation_key_sha256 OR reservation_id=NEW.reservation_id "
    "OR reservation_sha256=NEW.reservation_sha256 OR (lease_id=NEW.lease_id AND "
    "lease_sha256=NEW.lease_sha256 AND (lease_use_number=NEW.lease_use_number OR "
    "lease_mode<>NEW.lease_mode OR lease_mode='one_time'))) "
    "BEGIN SELECT RAISE(ABORT,'lease-use reservation already exists or mode changed'); END",
    "CREATE TRIGGER lease_use_completion_no_update BEFORE UPDATE ON "
    "lease_use_completions BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_completion_no_delete BEFORE DELETE ON "
    "lease_use_completions BEGIN SELECT RAISE(ABORT,'lease-use custody is immutable'); END",
    "CREATE TRIGGER lease_use_completion_no_replace BEFORE INSERT ON "
    "lease_use_completions WHEN EXISTS(SELECT 1 FROM lease_use_completions WHERE "
    "reservation_id=NEW.reservation_id OR completion_sha256=NEW.completion_sha256) "
    "BEGIN SELECT RAISE(ABORT,'lease-use completion already exists'); END",
)
SCHEMA_SHA256 = "sha256:" + hashlib.sha256(";\n".join(_DDL).encode("ascii")).hexdigest()
_MANIFEST = tuple(
    sorted(
        (
            ("table", "lease_use_store_identity", "lease_use_store_identity", _DDL[0]),
            ("table", "lease_use_reservations", "lease_use_reservations", _DDL[1]),
            ("index", "lease_use_reservation_id", "lease_use_reservations", _DDL[2]),
            ("index", "lease_use_reservation_sha", "lease_use_reservations", _DDL[3]),
            ("index", "lease_use_number", "lease_use_reservations", _DDL[4]),
            ("table", "lease_use_completions", "lease_use_completions", _DDL[5]),
            ("index", "lease_use_completion_sha", "lease_use_completions", _DDL[6]),
            ("trigger", "lease_use_identity_no_update", "lease_use_store_identity", _DDL[7]),
            ("trigger", "lease_use_identity_no_delete", "lease_use_store_identity", _DDL[8]),
            ("trigger", "lease_use_identity_no_replace", "lease_use_store_identity", _DDL[9]),
            ("trigger", "lease_use_reservation_no_update", "lease_use_reservations", _DDL[10]),
            ("trigger", "lease_use_reservation_no_delete", "lease_use_reservations", _DDL[11]),
            ("trigger", "lease_use_reservation_no_replace", "lease_use_reservations", _DDL[12]),
            ("trigger", "lease_use_completion_no_update", "lease_use_completions", _DDL[13]),
            ("trigger", "lease_use_completion_no_delete", "lease_use_completions", _DDL[14]),
            ("trigger", "lease_use_completion_no_replace", "lease_use_completions", _DDL[15]),
        )
    )
)
_REQUEST_FIELDS = {
    "lease_id",
    "lease_sha256",
    "lease_binding_sha256",
    "lease_use_number",
    "lease_mode",
    "execution_request_id",
    "execution_request_sha256",
    "execution_binding_sha256",
    "requested_session_id",
    "reservation_key_sha256",
}
_RESERVATION_FIELDS = {
    "reservation_id",
    "reservation_sha256",
    "reservation_key_sha256",
}
_COMPLETION_FIELDS = _RESERVATION_FIELDS | {
    "outcome",
    "provider_called",
    "completion_sha256",
}
_WINDOWS_DEVICE = re.compile(
    r"(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[0-9\u00b9\u00b2\u00b3]|"
    r"LPT[0-9\u00b9\u00b2\u00b3])(?:\..*)?\Z",
    re.I,
)


def _failure(code: str = "lease_use_store_corrupt") -> LeaseUseStoreFailure:
    return LeaseUseStoreFailure(code)


def _text(value: dict[str, Any]) -> str:
    result = canonical_json(value)
    if len(result) > MAX_DOCUMENT_BYTES:
        raise _failure("lease_use_metadata_limit")
    return result


def _native_string(value: Any, maximum: int = 256) -> None:
    if type(value) is not str or not value or len(value) > maximum:
        raise _failure("invalid_lease_use_metadata")


def _fields(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise _failure()
    if set(value) != fields:
        raise _failure()
    return value


def _slots(value: Any, family: type, fields: set[str]) -> dict[str, Any]:
    if type(value) is not family:
        raise _failure("invalid_lease_use_metadata")
    try:
        return {name: getattr(value, name) for name in fields}
    except AttributeError as exc:
        raise _failure("invalid_lease_use_metadata") from exc


def _request(raw: dict[str, Any]) -> LeaseUseReservationRequest:
    _fields(raw, _REQUEST_FIELDS)
    for key, value in raw.items():
        if key != "lease_use_number":
            _native_string(value, 71 if key.endswith("sha256") else 256)
    number = raw["lease_use_number"]
    if type(number) is not int or not 1 <= number <= 100:
        raise _failure("invalid_lease_use_metadata")
    try:
        candidate = LeaseUseReservationRequest(**raw)
        if _text(
            {**candidate.body(), "reservation_key_sha256": candidate.reservation_key_sha256}
        ) != _text(raw):
            raise _failure()
        return candidate
    except (AuthorizedTargetSessionRuntimeError, ValueError, TypeError) as exc:
        raise _failure("invalid_lease_use_metadata") from exc


def _capture_request(value: Any) -> LeaseUseReservationRequest:
    raw = _slots(value, LeaseUseReservationRequest, _REQUEST_FIELDS)
    if type(raw["lease_mode"]) is not LeaseMode or (
        raw["lease_mode"] is not LeaseMode.ONE_TIME
        and raw["lease_mode"] is not LeaseMode.SESSION_BOUND
    ):
        raise _failure("invalid_lease_use_metadata")
    raw["lease_mode"] = raw["lease_mode"].value
    return _request(raw)


def _reservation(raw: dict[str, Any]) -> LeaseUseReservationEvidence:
    _fields(raw, _RESERVATION_FIELDS)
    for key, value in raw.items():
        _native_string(value, 71 if key.endswith("sha256") else 256)
    try:
        return LeaseUseReservationEvidence(**raw)
    except (AuthorizedTargetSessionRuntimeError, ValueError, TypeError) as exc:
        raise _failure("invalid_lease_use_metadata") from exc


def _capture_reservation(value: Any) -> LeaseUseReservationEvidence:
    return _reservation(_slots(value, LeaseUseReservationEvidence, _RESERVATION_FIELDS))


def _completion(raw: dict[str, Any]) -> LeaseUseCompletionEvidence:
    _fields(raw, _COMPLETION_FIELDS)
    for key, value in raw.items():
        if key != "provider_called":
            _native_string(value, 64 if key == "outcome" else 71 if key.endswith("sha256") else 256)
    if type(raw["provider_called"]) is not bool:
        raise _failure("invalid_lease_use_metadata")
    try:
        candidate = LeaseUseCompletionEvidence(**raw)
        if _text({**candidate.body(), "completion_sha256": candidate.completion_sha256}) != _text(
            raw
        ):
            raise _failure()
        return candidate
    except (AuthorizedTargetSessionRuntimeError, ValueError, TypeError) as exc:
        raise _failure("invalid_lease_use_metadata") from exc


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _failure()
        result[key] = value
    return result


def _invalid_number(value: str) -> None:
    raise _failure()


def _document(value: Any) -> dict[str, Any]:
    if type(value) is not str or len(value) > MAX_DOCUMENT_BYTES or not value.isascii():
        raise _failure()
    try:
        result = json.loads(
            value,
            object_pairs_hook=_pairs,
            parse_float=_invalid_number,
            parse_constant=_invalid_number,
        )
    except (ValueError, TypeError, RecursionError) as exc:
        raise _failure() from exc
    if type(result) is not dict:
        raise _failure()
    return result


def _timeout(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_BUSY_TIMEOUT_MS:
        raise _failure("invalid_lease_use_timeout")
    return value


def _reparse(information: os.stat_result) -> bool:
    return stat.S_ISLNK(information.st_mode) or bool(
        getattr(information, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _path(value: Any, *, existing: bool) -> Path:
    if type(value) is str:
        text = value
    elif type(value) is type(Path()):
        text = str(value)
    else:
        raise _failure("invalid_lease_use_path")
    if not text or len(text) > 1024 or any(ord(char) < 32 for char in text):
        raise _failure("invalid_lease_use_path")
    if text.startswith(("\\", "//")) or "://" in text or text.lower().startswith("file:"):
        raise _failure("invalid_lease_use_path")
    path = Path(text)
    if not path.is_absolute() or not path.name:
        raise _failure("invalid_lease_use_path")
    components = text.replace("\\", "/").split("/")
    if os.name == "nt":
        if not re.fullmatch(r"[A-Za-z]:", components[0]):
            raise _failure("invalid_lease_use_path")
        components = components[1:]
    else:
        components = components[1:]
    if any(
        not part
        or part in (".", "..")
        or part.endswith((".", " "))
        or ":" in part
        or (os.name == "nt" and _WINDOWS_DEVICE.fullmatch(part))
        for part in components
    ):
        raise _failure("invalid_lease_use_path")
    try:
        for item in (*reversed(path.parent.parents), path.parent):
            information = item.lstat()
            if not stat.S_ISDIR(information.st_mode) or _reparse(information):
                raise _failure("invalid_lease_use_path")
        if existing:
            information = path.lstat()
            if not stat.S_ISREG(information.st_mode) or _reparse(information):
                raise _failure("invalid_lease_use_path")
        else:
            try:
                information = path.lstat()
            except FileNotFoundError:
                information = None
            if information is not None and (
                not stat.S_ISREG(information.st_mode) or _reparse(information)
            ):
                raise _failure("invalid_lease_use_path")
        return path.resolve(strict=existing)
    except OSError as exc:
        raise _failure("invalid_lease_use_path") from exc


def _regular_file_identity(path: Path) -> tuple[int, int]:
    try:
        information = path.lstat()
    except OSError as exc:
        raise _failure("lease_use_store_identity_changed") from exc
    if not stat.S_ISREG(information.st_mode) or _reparse(information):
        raise _failure("lease_use_store_identity_changed")
    return information.st_dev, information.st_ino


def _require_file_identity(path: Path, expected: tuple[int, int]) -> None:
    if _regular_file_identity(path) != expected:
        raise _failure("lease_use_store_identity_changed")


class SQLiteAtomicLeaseUseStore:
    """An explicit caller-owned local store, never an admission authority."""

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 100) -> None:
        self._open_existing(path, busy_timeout_ms)

    def _open_existing(
        self,
        path: str | Path,
        busy_timeout_ms: int,
        *,
        expected_file_identity: tuple[int, int] | None = None,
    ) -> None:
        self._busy_timeout_ms = _timeout(busy_timeout_ms)
        self._path = _path(path, existing=True)
        observed = _regular_file_identity(self._path)
        if expected_file_identity is not None and observed != expected_file_identity:
            raise _failure("lease_use_store_identity_changed")
        self._file_identity = observed
        with self._connection(write=False) as connection:
            connection.execute("BEGIN")
            self._verify(connection)

    @classmethod
    def create(cls, path: str | Path, *, busy_timeout_ms: int = 100) -> SQLiteAtomicLeaseUseStore:
        """Exclusively create one new file; uncertain files are never removed."""

        timeout = _timeout(busy_timeout_ms)
        selected = _path(path, existing=False)
        try:
            descriptor = os.open(selected, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except OSError as exc:
            raise _failure("lease_use_store_create_denied") from exc
        try:
            try:
                information = os.fstat(descriptor)
                if not stat.S_ISREG(information.st_mode) or _reparse(information):
                    raise _failure("lease_use_store_identity_changed")
                exclusive_identity = (information.st_dev, information.st_ino)
            finally:
                os.close(descriptor)
            cls._initialize(selected, timeout, expected_file_identity=exclusive_identity)
            reopened = cls.__new__(cls)
            reopened._open_existing(selected, timeout, expected_file_identity=exclusive_identity)
            return reopened
        except Exception as exc:
            raise _failure("lease_use_store_initialization_failed") from exc

    @staticmethod
    def _initialize(path: Path, timeout: int, *, expected_file_identity: tuple[int, int]) -> None:
        _require_file_identity(path, expected_file_identity)
        preflight = sqlite3.connect(
            path.as_uri() + "?mode=ro", uri=True, timeout=timeout / 1000, isolation_level=None
        )
        try:
            _require_file_identity(path, expected_file_identity)
            preflight.execute("BEGIN")
            if (
                preflight.execute("PRAGMA application_id").fetchone()[0] != 0
                or preflight.execute("PRAGMA user_version").fetchone()[0] != 0
                or preflight.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or preflight.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None
            ):
                raise _failure()
            _require_file_identity(path, expected_file_identity)
        finally:
            preflight.rollback()
            preflight.close()
        _require_file_identity(path, expected_file_identity)
        connection = sqlite3.connect(
            path.as_uri() + "?mode=rw", uri=True, timeout=timeout / 1000, isolation_level=None
        )
        try:
            _require_file_identity(path, expected_file_identity)
            if (
                connection.execute("PRAGMA application_id").fetchone()[0] != 0
                or connection.execute("PRAGMA user_version").fetchone()[0] != 0
                or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or connection.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None
            ):
                raise _failure()
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("BEGIN IMMEDIATE")
            if (
                connection.execute("PRAGMA application_id").fetchone()[0] != 0
                or connection.execute("PRAGMA user_version").fetchone()[0] != 0
                or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
                or connection.execute("PRAGMA synchronous").fetchone()[0] != 2
                or connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1
                or connection.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone() is not None
            ):
                raise _failure()
            for statement in _DDL:
                connection.execute(statement)
            connection.execute(
                "INSERT INTO lease_use_store_identity VALUES(1,?,?)", (STORE_KIND, SCHEMA_SHA256)
            )
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _connection(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            if write:
                self._read_only_preflight()
            selected = _path(self._path, existing=True)
            _require_file_identity(selected, self._file_identity)
            mode = "rw" if write else "ro"
            connection = sqlite3.connect(
                selected.as_uri() + "?mode=" + mode,
                uri=True,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1000,
            )
            _require_file_identity(selected, self._file_identity)
            connection.row_factory = sqlite3.Row
            self._verify_schema(connection)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            if not write:
                connection.execute("PRAGMA query_only=ON")
            yield connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.rollback()
            if getattr(exc, "sqlite_errorcode", 0) & 0xFF in (
                sqlite3.SQLITE_BUSY,
                sqlite3.SQLITE_LOCKED,
            ):
                raise _failure("lease_use_store_busy") from exc
            raise _failure("lease_use_store_database_failure") from exc
        finally:
            if connection is not None:
                connection.close()

    def _read_only_preflight(self) -> None:
        with self._connection(write=False) as connection:
            connection.execute("BEGIN")
            self._verify_schema(connection)
            _require_file_identity(self._path, self._file_identity)

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        with self._connection(write=True) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._verify(connection)
                yield connection
                self._verify(connection)
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def _verify_schema(self, connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
            or connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete"
        ):
            raise _failure("lease_use_store_identity_mismatch")
        manifest = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT substr(type,1,32),substr(name,1,256),substr(tbl_name,1,256),"
                "substr(sql,1,4097) FROM sqlite_schema ORDER BY type,name LIMIT 17"
            )
        )
        if manifest != _MANIFEST:
            raise _failure("lease_use_store_schema_mismatch")
        identity = connection.execute(
            "SELECT singleton,CASE WHEN typeof(store_kind)='text' AND "
            "length(CAST(store_kind AS BLOB))<=256 THEN store_kind END,"
            "CASE WHEN typeof(schema_sha256)='text' AND "
            "length(CAST(schema_sha256 AS BLOB))<=71 THEN schema_sha256 END "
            "FROM lease_use_store_identity LIMIT 2"
        ).fetchall()
        if len(identity) != 1 or tuple(identity[0]) != (1, STORE_KIND, SCHEMA_SHA256):
            raise _failure("lease_use_store_identity_mismatch")

    def _verify(self, connection: sqlite3.Connection) -> None:
        self._verify_schema(connection)
        if (
            connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1
            or connection.execute("PRAGMA synchronous").fetchone()[0] != 2
        ):
            raise _failure("lease_use_store_unsafe_connection")
        for table in ("lease_use_reservations", "lease_use_completions"):
            if connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] > MAX_RECORDS:
                raise _failure("lease_use_store_capacity")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _failure()
        if (
            connection.execute(
                "SELECT 1 FROM lease_use_reservations WHERE "
                "typeof(request_json)<>'text' OR length(CAST(request_json AS BLOB))>? OR "
                "length(CAST(lease_id AS BLOB))>256 OR length(CAST(lease_sha256 AS BLOB))>71 OR "
                "length(CAST(lease_mode AS BLOB))>32 OR "
                "length(CAST(reservation_key_sha256 AS BLOB))>71 OR "
                "length(CAST(reservation_id AS BLOB))>256 OR "
                "length(CAST(reservation_sha256 AS BLOB))>71 LIMIT 1",
                (MAX_DOCUMENT_BYTES,),
            ).fetchone()
            is not None
        ):
            raise _failure()
        modes: dict[tuple[str, str], str] = {}
        reservations: dict[str, LeaseUseReservationEvidence] = {}
        for row in connection.execute("SELECT * FROM lease_use_reservations"):
            request = _request(_document(row["request_json"]))
            expected = {
                "reservation_key_sha256": request.reservation_key_sha256,
                "lease_id": request.lease_id,
                "lease_sha256": request.lease_sha256,
                "lease_mode": request.lease_mode.value,
                "lease_use_number": request.lease_use_number,
            }
            if _text({name: row[name] for name in expected}) != _text(expected):
                raise _failure()
            if (
                _text({**request.body(), "reservation_key_sha256": request.reservation_key_sha256})
                != row["request_json"]
            ):
                raise _failure()
            reservation = _reservation({name: row[name] for name in _RESERVATION_FIELDS})
            identity_key = (request.lease_id, request.lease_sha256)
            if identity_key in modes and (
                modes[identity_key] != request.lease_mode.value
                or request.lease_mode is LeaseMode.ONE_TIME
            ):
                raise _failure()
            modes[identity_key] = request.lease_mode.value
            reservations[reservation.reservation_id] = reservation
        if (
            connection.execute(
                "SELECT 1 FROM lease_use_completions WHERE typeof(completion_json)<>'text' OR "
                "length(CAST(completion_json AS BLOB))>? OR "
                "length(CAST(reservation_id AS BLOB))>256 OR "
                "length(CAST(completion_sha256 AS BLOB))>71 LIMIT 1",
                (MAX_DOCUMENT_BYTES,),
            ).fetchone()
            is not None
        ):
            raise _failure()
        for row in connection.execute("SELECT * FROM lease_use_completions"):
            completion = _completion(_document(row["completion_json"]))
            reservation = reservations.get(completion.reservation_id)
            if reservation is None or (
                completion.reservation_sha256 != reservation.reservation_sha256
                or completion.reservation_key_sha256 != reservation.reservation_key_sha256
                or completion.reservation_id != row["reservation_id"]
                or completion.completion_sha256 != row["completion_sha256"]
            ):
                raise _failure()
            if (
                _text({**completion.body(), "completion_sha256": completion.completion_sha256})
                != row["completion_json"]
            ):
                raise _failure()

    def reserve(self, request: LeaseUseReservationRequest) -> LeaseUseReservationEvidence:
        owned = _capture_request(request)
        document = _text({**owned.body(), "reservation_key_sha256": owned.reservation_key_sha256})
        reservation = LeaseUseReservationEvidence(owned.reservation_key_sha256)
        with self._write() as connection:
            prior = connection.execute(
                "SELECT lease_mode FROM lease_use_reservations WHERE lease_id=? AND lease_sha256=?",
                (owned.lease_id, owned.lease_sha256),
            ).fetchone()
            if prior is not None and prior["lease_mode"] != owned.lease_mode.value:
                raise _failure("lease_mode_rebound")
            if connection.execute(
                "SELECT 1 FROM lease_use_reservations WHERE reservation_key_sha256=? OR "
                "(lease_id=? AND lease_sha256=? AND lease_use_number=?)",
                (
                    owned.reservation_key_sha256,
                    owned.lease_id,
                    owned.lease_sha256,
                    owned.lease_use_number,
                ),
            ).fetchone() is not None or (
                prior is not None and owned.lease_mode is LeaseMode.ONE_TIME
            ):
                raise _failure("lease_use_replayed")
            if (
                connection.execute("SELECT count(*) FROM lease_use_reservations").fetchone()[0]
                >= MAX_RECORDS
            ):
                raise _failure("lease_use_store_capacity")
            connection.execute(
                "INSERT INTO lease_use_reservations VALUES(?,?,?,?,?,?,?,?)",
                (
                    owned.reservation_key_sha256,
                    owned.lease_id,
                    owned.lease_sha256,
                    owned.lease_mode.value,
                    owned.lease_use_number,
                    document,
                    reservation.reservation_id,
                    reservation.reservation_sha256,
                ),
            )
        return reservation

    def complete(
        self,
        reservation: LeaseUseReservationEvidence,
        outcome: str,
        provider_called: bool,
    ) -> LeaseUseCompletionEvidence:
        _native_string(outcome, 64)
        if type(provider_called) is not bool:
            raise _failure("invalid_lease_use_metadata")
        owned = _capture_reservation(reservation)
        try:
            completion = LeaseUseCompletionEvidence(
                reservation_id=owned.reservation_id,
                reservation_sha256=owned.reservation_sha256,
                reservation_key_sha256=owned.reservation_key_sha256,
                outcome=outcome,
                provider_called=provider_called,
            )
        except AuthorizedTargetSessionRuntimeError as exc:
            raise _failure("invalid_lease_use_metadata") from exc
        document = _text({**completion.body(), "completion_sha256": completion.completion_sha256})
        with self._write() as connection:
            row = connection.execute(
                "SELECT reservation_id,reservation_sha256 FROM lease_use_reservations "
                "WHERE reservation_key_sha256=?",
                (owned.reservation_key_sha256,),
            ).fetchone()
            if row is None or tuple(row) != (owned.reservation_id, owned.reservation_sha256):
                raise _failure("reservation_not_found")
            if (
                connection.execute(
                    "SELECT 1 FROM lease_use_completions WHERE reservation_id=?",
                    (owned.reservation_id,),
                ).fetchone()
                is not None
            ):
                raise _failure("lease_use_already_completed")
            connection.execute(
                "INSERT INTO lease_use_completions VALUES(?,?,?)",
                (owned.reservation_id, document, completion.completion_sha256),
            )
        return completion


__all__ = [
    "APPLICATION_ID",
    "MAX_BUSY_TIMEOUT_MS",
    "MAX_DOCUMENT_BYTES",
    "MAX_RECORDS",
    "SCHEMA_SHA256",
    "SCHEMA_VERSION",
    "STORE_KIND",
    "SQLiteAtomicLeaseUseStore",
]

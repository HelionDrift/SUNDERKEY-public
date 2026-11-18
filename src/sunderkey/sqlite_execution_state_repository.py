"""Bounded local sequential storage for the unchanged execution-control port.

These records coordinate a caller-selected local file. They are neither action
authority nor authenticated observations of a provider or a current clock.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, fields
from enum import StrEnum
from pathlib import Path
from typing import Any

from . import execution_control_runtime as runtime

APPLICATION_ID = 0x534B4553
SCHEMA_VERSION = 1
MAX_INTEGER = (1 << 63) - 1
MAX_DOCUMENT_BYTES = 65536
MAX_HISTORY_RECORDS = 1024
MAX_HISTORY_BYTES = 16 * 1024 * 1024
MAX_STRING_CHARACTERS = 512
_FORMAT = "sqlite_execution_state_repository.v1"
_DOMAIN = "sunderkey.local_sequential_execution_storage.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{1,255}\Z")
_WINDOWS_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"} | {
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
}


class SQLiteExecutionStateError(runtime.ExecutionControlError):
    """Invalid input, unavailable storage or an unverified transition."""


@dataclass(frozen=True, slots=True)
class _Items:
    item: type
    maximum: int


@dataclass(frozen=True, slots=True)
class _Optional:
    item: type


def _model_schema(model: type, **overrides: Any) -> dict[str, Any]:
    return {field.name: overrides.get(field.name, str) for field in fields(model)}


_MODELS = {
    runtime.ClockObservation: _model_schema(runtime.ClockObservation, monotonic_tick=int),
    runtime.AllowedUtcWindow: _model_schema(runtime.AllowedUtcWindow),
    runtime.ExecutionBinding: _model_schema(runtime.ExecutionBinding, fence_epoch=int),
    runtime.ExecutionControlPolicy: _model_schema(
        runtime.ExecutionControlPolicy,
        allowed_windows=_Items(runtime.AllowedUtcWindow, 64),
        rate_mode=runtime.RateMode,
        request_ceiling=int,
        period_seconds=int,
        token_capacity=int,
        token_refill_amount=int,
        byte_ceiling=int,
        maximum_concurrent_sessions=int,
        sequential_only=bool,
        maximum_attempts=int,
        retryable_failure_codes=_Items(str, 256),
        cleanup_required=bool,
    ),
    runtime.ExecutionRequest: _model_schema(
        runtime.ExecutionRequest,
        binding=runtime.ExecutionBinding,
        payload_size_bytes=int,
        attempt_number=int,
        prior_execution_sha256=_Optional(str),
    ),
    runtime.ControlState: _model_schema(
        runtime.ControlState,
        binding=runtime.ExecutionBinding,
        health=runtime.HealthState,
        canceled=bool,
        emergency_stop=bool,
        active_sessions=_Items(str, 1),
        active_executions=int,
        requests_used=int,
        bytes_used=int,
        tokens_available=int,
        token_refill_tick=int,
        last_monotonic_tick=int,
        state_version=int,
        reservation_request_sha256=_Optional(str),
    ),
    runtime.AdmissionReceipt: _model_schema(
        runtime.AdmissionReceipt,
        status=runtime.AdmissionStatus,
        reason=_Optional(str),
        monotonic_tick=int,
        state_before_sha256=_Optional(str),
        state_after_sha256=_Optional(str),
    ),
    runtime.ExecutionReceipt: _model_schema(
        runtime.ExecutionReceipt,
        status=runtime.ExecutionStatus,
        transport_called=bool,
        transport_succeeded=bool,
        transport_failure_code=_Optional(str),
        response_size_bytes=int,
        retry_disposition=runtime.RetryDisposition,
        cleanup_required=bool,
        cleanup_status=runtime.CleanupStatus,
        monotonic_tick=int,
        completion_state_sha256=_Optional(str),
    ),
    runtime.StoredExecution: _model_schema(
        runtime.StoredExecution,
        admission=runtime.AdmissionReceipt,
        execution=runtime.ExecutionReceipt,
    ),
    runtime.TransportEnvelope: _model_schema(
        runtime.TransportEnvelope, binding=runtime.ExecutionBinding, payload_size_bytes=int
    ),
    runtime.TransportObservation: _model_schema(
        runtime.TransportObservation,
        succeeded=bool,
        failure_code=_Optional(str),
        response_size_bytes=int,
    ),
}


def _text(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > MAX_STRING_CHARACTERS
        or not value.isascii()
        or (value and not value.isprintable())
    ):
        raise SQLiteExecutionStateError("Fields require bounded native ASCII text")
    return value


def _identifier(value: Any) -> str:
    value = _text(value)
    if _IDENTIFIER.fullmatch(value) is None:
        raise SQLiteExecutionStateError("Local namespace, tenant or key is invalid")
    return value


def _project(value: Any, rule: Any) -> Any:
    if type(rule) is _Optional:
        return None if value is None else _project(value, rule.item)
    if type(rule) is _Items:
        if type(value) is not tuple or len(value) > rule.maximum:
            raise SQLiteExecutionStateError("A bounded native tuple is required")
        return [_project(item, rule.item) for item in value]
    if rule in _MODELS:
        if type(value) is not rule:
            raise SQLiteExecutionStateError("The exact native model family is required")
        return {name: _project(getattr(value, name), item) for name, item in _MODELS[rule].items()}
    if isinstance(rule, type) and issubclass(rule, StrEnum):
        if type(value) is not rule:
            raise SQLiteExecutionStateError("The exact source enum is required")
        return value.value
    if rule is str:
        return _text(value)
    if type(value) is not rule or (rule is int and not 0 <= value <= MAX_INTEGER):
        raise SQLiteExecutionStateError("A bounded exact native primitive is required")
    return value


def _restore(value: Any, rule: Any) -> Any:
    if type(rule) is _Optional:
        return None if value is None else _restore(value, rule.item)
    if type(rule) is _Items:
        if type(value) is not list or len(value) > rule.maximum:
            raise SQLiteExecutionStateError("Stored tuple projection is invalid")
        return tuple(_restore(item, rule.item) for item in value)
    if rule in _MODELS:
        if type(value) is not dict or set(value) != set(_MODELS[rule]):
            raise SQLiteExecutionStateError("Stored model fields are invalid")
        return rule(**{name: _restore(value[name], item) for name, item in _MODELS[rule].items()})
    if isinstance(rule, type) and issubclass(rule, StrEnum):
        return rule(_text(value))
    if rule is str:
        return _text(value)
    if type(value) is not rule or (rule is int and not 0 <= value <= MAX_INTEGER):
        raise SQLiteExecutionStateError("Stored primitive is invalid")
    return value


def _canonical(value: Any) -> str:
    document = runtime.canonical_json(value)
    if len(document) > MAX_DOCUMENT_BYTES:
        raise SQLiteExecutionStateError("Local document exceeds its byte ceiling")
    return document


def _owned(value: Any, model: type) -> Any:
    try:
        projection = _project(value, model)
        document = _canonical(projection)
        owned = _restore(projection, model)
        if _canonical(_project(owned, model)) != document:
            raise SQLiteExecutionStateError("Original model identities are not canonical")
        return owned
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SQLiteExecutionStateError("Source model is invalid or noncanonical") from exc


def _dump(value: Any, model: type) -> str:
    return _canonical(_project(_owned(value, model), model))


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise SQLiteExecutionStateError("Duplicate stored JSON field")
        result[key] = value
    return result


def _integer(value: str) -> int:
    if len(value) > 19:
        raise SQLiteExecutionStateError("Stored integer exceeds its bound")
    number = int(value)
    if not 0 <= number <= MAX_INTEGER:
        raise SQLiteExecutionStateError("Stored integer exceeds its bound")
    return number


def _not_numeric(_: str) -> Any:
    raise SQLiteExecutionStateError("Stored floats and nonfinite values are forbidden")


def _load(document: Any) -> dict[str, Any]:
    if type(document) is not str or len(document) > MAX_DOCUMENT_BYTES or not document.isascii():
        raise SQLiteExecutionStateError("Stored document is invalid or oversized")
    try:
        value = json.loads(
            document,
            object_pairs_hook=_pairs,
            parse_int=_integer,
            parse_float=_not_numeric,
            parse_constant=_not_numeric,
        )
        nodes = 0

        def visit(item: Any, depth: int = 0) -> None:
            nonlocal nodes
            nodes += 1
            if nodes > 4096 or depth > 12:
                raise SQLiteExecutionStateError("Stored structure exceeds its ceiling")
            if type(item) is dict:
                for key, child in item.items():
                    _text(key)
                    visit(child, depth + 1)
            elif type(item) is list:
                for child in item:
                    visit(child, depth + 1)
            elif type(item) is str:
                _text(item)
            elif type(item) not in (bool, int, type(None)):
                raise SQLiteExecutionStateError("Stored primitive is invalid")

        visit(value)
        if type(value) is not dict or _canonical(value) != document:
            raise SQLiteExecutionStateError("Stored document is not canonical")
        return value
    except (TypeError, ValueError, RecursionError) as exc:
        raise SQLiteExecutionStateError("Stored document cannot be reconstructed") from exc


def _read_model(document: str, model: type) -> Any:
    try:
        restored = _restore(_load(document), model)
        if _dump(restored, model) != document:
            raise SQLiteExecutionStateError("Stored model addresses changed on reconstruction")
        return restored
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SQLiteExecutionStateError("Stored model cannot be reconstructed") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _local_path(value: Any) -> Path:
    if type(value) not in (str, type(Path())):
        raise SQLiteExecutionStateError("An explicit native local path is required")
    raw = value if type(value) is str else str(value)
    if (
        not raw
        or len(raw) > 4096
        or not raw.isascii()
        or not raw.isprintable()
        or raw.startswith(("\\\\", "//"))
    ):
        raise SQLiteExecutionStateError("Local path is unsupported")
    if os.name == "nt":
        spelling = raw.replace("/", "\\")
        pieces = spelling.split("\\")
        if len(pieces) < 2 or re.fullmatch(r"[A-Za-z]:", pieces[0]) is None:
            raise SQLiteExecutionStateError("An absolute local drive path is required")
        for piece in pieces[1:]:
            if (
                not piece
                or piece in (".", "..")
                or piece.endswith((".", " "))
                or any(character in '<>:"|?*' for character in piece)
                or piece.split(".", 1)[0].rstrip(" .").upper() in _WINDOWS_DEVICES
            ):
                raise SQLiteExecutionStateError("Local path contains an ambiguous component")
    elif not raw.startswith("/") or any(piece in ("", ".", "..") for piece in raw.split("/")[1:]):
        raise SQLiteExecutionStateError("An absolute unambiguous path is required")
    path = Path(raw)
    if not path.is_absolute():
        raise SQLiteExecutionStateError("An absolute local path is required")
    return path


def _bounded_column(name: str, maximum: int = MAX_DOCUMENT_BYTES) -> str:
    return (
        f"CASE WHEN typeof({name})='text' AND length(CAST({name} AS BLOB))<={maximum} "
        f"THEN {name} ELSE NULL END AS {name}"
    )


_DDL = (
    "CREATE TABLE execution_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "format TEXT NOT NULL, schema_sha256 TEXT NOT NULL, config_json TEXT NOT NULL "
    "CHECK(length(CAST(config_json AS BLOB))<=65536), config_sha256 TEXT NOT NULL) STRICT",
    "CREATE TABLE control_head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "state_version INTEGER NOT NULL CHECK(state_version>=1), state_sha256 TEXT NOT NULL, "
    "state_json TEXT NOT NULL CHECK(length(CAST(state_json AS BLOB))<=65536)) STRICT",
    "CREATE TABLE reservations (sequence INTEGER PRIMARY KEY CHECK(sequence BETWEEN 1 AND 1024), "
    "idempotency_key TEXT NOT NULL UNIQUE, request_sha256 TEXT NOT NULL UNIQUE, "
    "request_json TEXT NOT NULL, observation_json TEXT NOT NULL, before_json TEXT NOT NULL, "
    "reserved_json TEXT NOT NULL, record_sha256 TEXT NOT NULL, "
    "CHECK(length(CAST(request_json AS BLOB))<=65536), "
    "CHECK(length(CAST(observation_json AS BLOB))<=65536), "
    "CHECK(length(CAST(before_json AS BLOB))<=65536), "
    "CHECK(length(CAST(reserved_json AS BLOB))<=65536)) STRICT",
    "CREATE TABLE completions (sequence INTEGER PRIMARY KEY REFERENCES reservations(sequence), "
    "observation_json TEXT NOT NULL, outcome_json TEXT NOT NULL, completed_json TEXT NOT NULL, "
    "record_sha256 TEXT NOT NULL, CHECK(length(CAST(observation_json AS BLOB))<=65536), "
    "CHECK(length(CAST(outcome_json AS BLOB))<=65536), "
    "CHECK(length(CAST(completed_json AS BLOB))<=65536)) STRICT",
    *tuple(
        statement
        for table in ("execution_metadata", "reservations", "completions")
        for statement in (
            f"CREATE TRIGGER {table}_no_update BEFORE UPDATE ON {table} "
            "BEGIN SELECT RAISE(ABORT,'execution records are immutable'); END",
            f"CREATE TRIGGER {table}_no_delete BEFORE DELETE ON {table} "
            "BEGIN SELECT RAISE(ABORT,'execution records cannot be deleted'); END",
            f"CREATE TRIGGER {table}_no_replace BEFORE INSERT ON {table} "
            f"WHEN EXISTS(SELECT 1 FROM {table} WHERE "
            + (
                "singleton=NEW.singleton"
                if table == "execution_metadata"
                else "sequence=NEW.sequence"
                + (
                    " OR idempotency_key=NEW.idempotency_key OR request_sha256=NEW.request_sha256"
                    if table == "reservations"
                    else ""
                )
            )
            + ") BEGIN SELECT RAISE(ABORT,'execution records cannot be replaced'); END",
        )
    ),
    "CREATE TRIGGER control_head_no_delete BEFORE DELETE ON control_head "
    "BEGIN SELECT RAISE(ABORT,'execution head cannot be deleted'); END",
    "CREATE TRIGGER control_head_no_replace BEFORE INSERT ON control_head "
    "WHEN EXISTS(SELECT 1 FROM control_head) "
    "BEGIN SELECT RAISE(ABORT,'execution head cannot be replaced'); END",
    "CREATE TRIGGER control_head_step BEFORE UPDATE ON control_head "
    "WHEN NEW.singleton!=OLD.singleton OR NEW.state_version!=OLD.state_version+1 "
    "BEGIN SELECT RAISE(ABORT,'execution head requires one version step'); END",
)
_SCHEMA_SHA256 = _digest(list(_DDL))
_SCHEMA_OBJECTS = {statement.split()[2]: statement for statement in _DDL}
_RESERVATION_COLUMNS = (
    "sequence",
    "idempotency_key",
    "request_sha256",
    "request_json",
    "observation_json",
    "before_json",
    "reserved_json",
    "record_sha256",
)
_COMPLETION_COLUMNS = (
    "sequence",
    "observation_json",
    "outcome_json",
    "completed_json",
    "record_sha256",
)


def _record_digest(kind: str, record: dict[str, Any], configuration_sha256: str) -> str:
    return _digest(
        {
            "configuration_sha256": configuration_sha256,
            "domain": _DOMAIN,
            "kind": kind,
            "record": record,
        }
    )


def _outcome(
    request: runtime.ExecutionRequest,
    policy: runtime.ExecutionControlPolicy,
    before: runtime.ControlState,
    reserved: runtime.ControlState,
    admitted: runtime.ClockObservation,
    completed: runtime.ClockObservation,
    supplied: runtime.StoredExecution,
) -> tuple[runtime.StoredExecution, runtime.ControlState]:
    """Reconstruct the unchanged producer's complete reciprocal receipt joins."""
    supplied = _owned(supplied, runtime.StoredExecution)
    after = _owned(runtime._expected_completion(reserved, request, completed), runtime.ControlState)
    admission = runtime.AdmissionReceipt(
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        policy_id=policy.policy_id,
        policy_sha256=policy.policy_sha256,
        status=runtime.AdmissionStatus.ADMITTED,
        reason=None,
        observed_at=admitted.observed_at,
        monotonic_tick=admitted.monotonic_tick,
        state_before_sha256=before.state_sha256,
        state_after_sha256=reserved.state_sha256,
    )
    source = supplied.execution
    if source.transport_succeeded:
        retry = runtime.RetryDisposition.NOT_APPLICABLE
    elif (
        source.transport_failure_code in policy.retryable_failure_codes
        and request.attempt_number < policy.maximum_attempts
    ):
        retry = runtime.RetryDisposition.RETRY_PERMITTED
    elif request.attempt_number >= policy.maximum_attempts:
        retry = runtime.RetryDisposition.RETRY_EXHAUSTED
    else:
        retry = runtime.RetryDisposition.FAILURE_NOT_RETRYABLE
    execution = runtime.ExecutionReceipt(
        admission_receipt_id=admission.receipt_id,
        admission_receipt_sha256=admission.receipt_sha256,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        status=(
            runtime.ExecutionStatus.SUCCEEDED
            if source.transport_succeeded
            else runtime.ExecutionStatus.TRANSPORT_FAILED
        ),
        transport_called=True,
        transport_succeeded=source.transport_succeeded,
        transport_failure_code=source.transport_failure_code,
        response_sha256=source.response_sha256,
        response_size_bytes=source.response_size_bytes,
        retry_disposition=retry,
        cleanup_required=policy.cleanup_required,
        cleanup_status=(
            runtime.CleanupStatus.PENDING_EXTERNAL_VERIFICATION
            if policy.cleanup_required
            else runtime.CleanupStatus.NOT_REQUIRED
        ),
        completed_at=completed.observed_at,
        monotonic_tick=completed.monotonic_tick,
        reservation_state_sha256=reserved.state_sha256,
        completion_state_sha256=after.state_sha256,
    )
    expected = runtime.StoredExecution(request.request_sha256, admission, execution)
    if _dump(expected, runtime.StoredExecution) != _dump(supplied, runtime.StoredExecution):
        raise SQLiteExecutionStateError("Completion does not match its reservation and clock")
    return expected, after


class SQLiteExecutionStateRepository:
    """One fixed binding/policy with atomic sequential local budget transitions."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        namespace: str,
        tenant_id: str,
        expected_binding: runtime.ExecutionBinding,
        expected_policy: runtime.ExecutionControlPolicy,
        initial_state: runtime.ControlState,
    ) -> None:
        namespace, tenant_id = _identifier(namespace), _identifier(tenant_id)
        binding = _owned(expected_binding, runtime.ExecutionBinding)
        policy = _owned(expected_policy, runtime.ExecutionControlPolicy)
        initial = _owned(initial_state, runtime.ControlState)
        if (
            binding.tenant_id != tenant_id
            or _dump(initial.binding, runtime.ExecutionBinding)
            != _dump(binding, runtime.ExecutionBinding)
            or policy.sequential_only is not True
            or initial.active_executions != 0
            or initial.active_sessions != ()
            or initial.reservation_request_sha256 is not None
            or initial.bytes_used > policy.byte_ceiling
            or initial.tokens_available > policy.token_capacity
            or (
                policy.rate_mode is runtime.RateMode.FIXED_WINDOW
                and initial.requests_used > policy.request_ceiling
            )
            or initial.token_refill_tick > initial.last_monotonic_tick
            or runtime._instant(initial.fixed_window_started_at)
            > runtime._instant(initial.last_observed_at)
        ):
            raise SQLiteExecutionStateError(
                "Initial configuration is not the supported idle subset"
            )
        path = _local_path(database_path)
        try:
            parent = path.parent.resolve(strict=True)
            if not parent.is_dir() or path.is_symlink() or (path.exists() and not path.is_file()):
                raise SQLiteExecutionStateError("Database must be a regular local file")
        except OSError as exc:
            raise SQLiteExecutionStateError("Local parent directory is unavailable") from exc
        config = _canonical(
            {
                "namespace": namespace,
                "tenant_id": tenant_id,
                "binding": _project(binding, runtime.ExecutionBinding),
                "policy": _project(policy, runtime.ExecutionControlPolicy),
                "initial_state": _project(initial, runtime.ControlState),
            }
        )
        resolved_path = _local_path(str(parent / path.name))
        self._configuration = (str(resolved_path), config, _digest(_load(config)))
        self._captured_configuration = self._configuration
        self._initialize()

    def _config(self) -> tuple[str, str, str]:
        value = getattr(self, "_configuration", None)
        if (
            type(value) is not tuple
            or len(value) != 3
            or any(type(item) is not str for item in value)
            or value != getattr(self, "_captured_configuration", None)
        ):
            raise SQLiteExecutionStateError("Captured local configuration changed")
        return value

    def _sources(
        self,
    ) -> tuple[runtime.ExecutionBinding, runtime.ExecutionControlPolicy, runtime.ControlState]:
        _, document, digest = self._config()
        config = _load(document)
        if _digest(config) != digest:
            raise SQLiteExecutionStateError("Captured configuration digest changed")
        return (
            _owned(_restore(config["binding"], runtime.ExecutionBinding), runtime.ExecutionBinding),
            _owned(
                _restore(config["policy"], runtime.ExecutionControlPolicy),
                runtime.ExecutionControlPolicy,
            ),
            _owned(_restore(config["initial_state"], runtime.ControlState), runtime.ControlState),
        )

    def _request(
        self, request: runtime.ExecutionRequest, policy: runtime.ExecutionControlPolicy
    ) -> tuple[runtime.ExecutionRequest, runtime.ExecutionControlPolicy]:
        request = _owned(request, runtime.ExecutionRequest)
        policy = _owned(policy, runtime.ExecutionControlPolicy)
        binding, expected_policy, _ = self._sources()
        if (
            _dump(request.binding, runtime.ExecutionBinding)
            != _dump(binding, runtime.ExecutionBinding)
            or _dump(policy, runtime.ExecutionControlPolicy)
            != _dump(expected_policy, runtime.ExecutionControlPolicy)
            or request.policy_id != policy.policy_id
            or request.policy_sha256 != policy.policy_sha256
        ):
            raise SQLiteExecutionStateError(
                "Request does not match the captured binding and policy"
            )
        return request, policy

    @staticmethod
    def _file_identity(path: str) -> tuple[int, int]:
        try:
            current = os.lstat(path)
            if (
                not stat.S_ISREG(current.st_mode)
                or Path(path).is_symlink()
                or getattr(current, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                raise SQLiteExecutionStateError("Local database is not a regular non-reparse file")
            return current.st_dev, current.st_ino
        except OSError as exc:
            raise SQLiteExecutionStateError("Local database file is unavailable") from exc

    def _connect(
        self, *, mode: str, expected_file_identity: tuple[int, int] | None = None
    ) -> sqlite3.Connection:
        path, _, _ = self._config()
        if mode not in ("ro", "rw"):
            raise SQLiteExecutionStateError("Local database is unavailable")
        identity = self._file_identity(path)
        if expected_file_identity is not None and (
            type(expected_file_identity) is not tuple
            or len(expected_file_identity) != 2
            or any(type(item) is not int for item in expected_file_identity)
            or identity != expected_file_identity
        ):
            raise SQLiteExecutionStateError("The captured local file identity changed before open")
        connection = sqlite3.connect(Path(path).as_uri() + f"?mode={mode}", uri=True, timeout=0)
        try:
            connection.row_factory = sqlite3.Row
            if self._file_identity(path) != identity:
                raise SQLiteExecutionStateError("Local file identity changed during open")
            return connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _exclusive_create(path: str) -> tuple[int, int]:
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
            try:
                opened, current = os.fstat(descriptor), os.lstat(path)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(current.st_mode)
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                    or Path(path).is_symlink()
                    or getattr(current, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
                ):
                    raise SQLiteExecutionStateError("Exclusive local creation changed")
                return opened.st_dev, opened.st_ino
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise SQLiteExecutionStateError("Exclusive local file creation failed") from exc

    @staticmethod
    def _empty(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != 0
            or connection.execute("PRAGMA user_version").fetchone()[0] != 0
            or connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone() is not None
        ):
            raise SQLiteExecutionStateError("Created file is no longer an unmarked empty database")

    @staticmethod
    def _journal(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise SQLiteExecutionStateError("Only DELETE journal mode is supported")

    @classmethod
    def _configure_owned(cls, connection: sqlite3.Connection) -> None:
        cls._journal(connection)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=0")
        cls._settings(connection)

    @classmethod
    def _settings(cls, connection: sqlite3.Connection) -> None:
        cls._journal(connection)
        if (
            connection.execute("PRAGMA synchronous").fetchone()[0] != 2
            or connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1
            or connection.execute("PRAGMA busy_timeout").fetchone()[0] != 0
        ):
            raise SQLiteExecutionStateError("Local connection durability settings changed")

    def _schema(self, connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise SQLiteExecutionStateError("Database identity is incompatible")
        objects = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT "
                + _bounded_column("name", 512)
                + ","
                + _bounded_column("sql")
                + " FROM sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT ?",
                (len(_SCHEMA_OBJECTS) + 1,),
            )
        }
        if objects != _SCHEMA_OBJECTS:
            raise SQLiteExecutionStateError("Database schema differs from the supported leaf")
        rows = connection.execute(
            "SELECT singleton,"
            + ",".join(
                _bounded_column(name)
                for name in ("format", "schema_sha256", "config_json", "config_sha256")
            )
            + " FROM execution_metadata LIMIT 2"
        ).fetchall()
        _, document, digest = self._config()
        if len(rows) != 1 or tuple(rows[0]) != (1, _FORMAT, _SCHEMA_SHA256, document, digest):
            raise SQLiteExecutionStateError("Database captured configuration differs")

    def _initialize(self) -> None:
        path, document, digest = self._config()
        created = not Path(path).exists()
        if created:
            identity = self._exclusive_create(path)
            if (
                type(identity) is not tuple
                or len(identity) != 2
                or any(type(item) is not int for item in identity)
            ):
                raise SQLiteExecutionStateError(
                    "Exclusive creation did not preserve native identity"
                )
        try:
            if created:
                with closing(
                    self._connect(mode="ro", expected_file_identity=identity)
                ) as connection:
                    self._empty(connection)
                    self._journal(connection)
            else:
                identity = self._readonly_ownership_preflight()
            with closing(self._connect(mode="rw", expected_file_identity=identity)) as connection:
                self._empty(connection) if created else self._schema(connection)
                self._configure_owned(connection)
                connection.execute("BEGIN IMMEDIATE")
                if created:
                    self._empty(connection)
                    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    for statement in _DDL:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO execution_metadata VALUES(1,?,?,?,?)",
                        (_FORMAT, _SCHEMA_SHA256, document, digest),
                    )
                    initial = self._sources()[2]
                    connection.execute(
                        "INSERT INTO control_head VALUES(1,?,?,?)",
                        (
                            initial.state_version,
                            initial.state_sha256,
                            _dump(initial, runtime.ControlState),
                        ),
                    )
                self._schema(connection)
                self._settings(connection)
                self._history(connection)
                connection.commit()
            with closing(self._connect(mode="ro", expected_file_identity=identity)) as connection:
                connection.execute("BEGIN")
                self._schema(connection)
                self._journal(connection)
                self._history(connection)
        except sqlite3.Error as exc:
            raise SQLiteExecutionStateError("Local database initialization failed") from exc

    def _readonly_ownership_preflight(self) -> tuple[int, int]:
        # Opening rw can itself recover a hot journal. Refuse foreign or
        # unreadable files through a read-only handle before permitting that.
        identity = self._file_identity(self._config()[0])
        with closing(self._connect(mode="ro", expected_file_identity=identity)) as connection:
            self._schema(connection)
            self._journal(connection)
            if self._file_identity(self._config()[0]) != identity:
                raise SQLiteExecutionStateError("Local file changed after ownership preflight")
        return identity

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        try:
            identity = self._readonly_ownership_preflight() if write else None
            with closing(
                self._connect(mode="rw" if write else "ro", expected_file_identity=identity)
            ) as connection:
                self._schema(connection)
                self._configure_owned(connection)
                connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                self._schema(connection)
                self._settings(connection)
                yield connection
                if write:
                    connection.commit()
        except sqlite3.Error as exc:
            raise SQLiteExecutionStateError("Local transaction failed; no automatic retry") from exc

    @staticmethod
    def _rows(
        connection: sqlite3.Connection, table: str, columns: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        selected = ",".join(
            name if name == "sequence" else _bounded_column(name) for name in columns
        )
        rows = connection.execute(
            f"SELECT {selected} FROM {table} ORDER BY sequence LIMIT ?", (MAX_HISTORY_RECORDS + 1,)
        ).fetchall()
        if len(rows) > MAX_HISTORY_RECORDS:
            raise SQLiteExecutionStateError("Local history exceeds its record ceiling")
        result = []
        for row in rows:
            if type(row["sequence"]) is not int or not 1 <= row["sequence"] <= MAX_HISTORY_RECORDS:
                raise SQLiteExecutionStateError("Stored sequence is invalid")
            if any(type(row[name]) is not str for name in columns if name != "sequence"):
                raise SQLiteExecutionStateError("Stored projection is nonnative or oversized")
            result.append(dict(row))
        return result

    def _history(
        self, connection: sqlite3.Connection
    ) -> tuple[runtime.ControlState, list[dict[str, Any]], dict[str, runtime.StoredExecution]]:
        _, policy, current = self._sources()
        total_bytes = 0
        for table, columns in (
            ("reservations", _RESERVATION_COLUMNS),
            ("completions", _COMPLETION_COLUMNS),
        ):
            length_sum = "+".join(
                f"COALESCE(length(CAST({name} AS BLOB)),0)"
                for name in columns
                if name != "sequence"
            )
            count, byte_count = connection.execute(
                f"SELECT COUNT(*),COALESCE(SUM({length_sum}),0) FROM {table}"
            ).fetchone()
            if count > MAX_HISTORY_RECORDS:
                raise SQLiteExecutionStateError("Local history exceeds its record ceiling")
            total_bytes += byte_count
            if total_bytes > MAX_HISTORY_BYTES:
                raise SQLiteExecutionStateError("Local history exceeds its aggregate byte ceiling")
        reservations = self._rows(connection, "reservations", _RESERVATION_COLUMNS)
        completions = self._rows(connection, "completions", _COMPLETION_COLUMNS)
        if (
            sum(
                len(value)
                for row in reservations + completions
                for value in row.values()
                if type(value) is str
            )
            > MAX_HISTORY_BYTES
        ):
            raise SQLiteExecutionStateError("Local history exceeds its aggregate byte ceiling")
        completed_by_sequence = {row["sequence"]: row for row in completions}
        results: dict[str, runtime.StoredExecution] = {}
        for sequence, row in enumerate(reservations, 1):
            if row["sequence"] != sequence:
                raise SQLiteExecutionStateError("Reservation sequence is not contiguous")
            record = {name: value for name, value in row.items() if name != "record_sha256"}
            if _record_digest("reservation", record, self._config()[2]) != row["record_sha256"]:
                raise SQLiteExecutionStateError("Reservation record digest differs")
            request = _read_model(row["request_json"], runtime.ExecutionRequest)
            self._request(request, policy)
            observation = _read_model(row["observation_json"], runtime.ClockObservation)
            before = _read_model(row["before_json"], runtime.ControlState)
            reserved = _read_model(row["reserved_json"], runtime.ControlState)
            expected, reason = runtime._expected_reservation(current, request, policy, observation)
            if (
                row["idempotency_key"] != request.idempotency_key
                or row["request_sha256"] != request.request_sha256
                or row["idempotency_key"] in results
                or _dump(before, runtime.ControlState) != _dump(current, runtime.ControlState)
                or reason is not None
                or _dump(reserved, runtime.ControlState) != _dump(expected, runtime.ControlState)
            ):
                raise SQLiteExecutionStateError(
                    "Reservation has inconsistent source or budget joins"
                )
            current = reserved
            completion = completed_by_sequence.pop(sequence, None)
            if completion is None:
                if sequence != len(reservations):
                    raise SQLiteExecutionStateError(
                        "An unresolved reservation is not the final head"
                    )
                continue
            record = {name: value for name, value in completion.items() if name != "record_sha256"}
            if (
                _record_digest("completion", record, self._config()[2])
                != completion["record_sha256"]
            ):
                raise SQLiteExecutionStateError("Completion record digest differs")
            completed = _read_model(completion["observation_json"], runtime.ClockObservation)
            outcome = _read_model(completion["outcome_json"], runtime.StoredExecution)
            outcome, after = _outcome(
                request, policy, before, reserved, observation, completed, outcome
            )
            if _dump(after, runtime.ControlState) != completion["completed_json"]:
                raise SQLiteExecutionStateError(
                    "Completion state differs from the exact transition"
                )
            current = after
            results[request.idempotency_key] = outcome
        if completed_by_sequence:
            raise SQLiteExecutionStateError("Completion has no reciprocal reservation")
        heads = connection.execute(
            "SELECT singleton,state_version,"
            + _bounded_column("state_sha256")
            + ","
            + _bounded_column("state_json")
            + " FROM control_head LIMIT 2"
        ).fetchall()
        if len(heads) != 1 or tuple(heads[0]) != (
            1,
            current.state_version,
            current.state_sha256,
            _dump(current, runtime.ControlState),
        ):
            raise SQLiteExecutionStateError("Current head does not match immutable history")
        return current, reservations, results

    def current_state(self) -> runtime.ControlState:
        """Return detached historical local state, not current action authority."""
        with self._transaction(write=False) as connection:
            return self._history(connection)[0]

    def lookup(
        self, binding: runtime.ExecutionBinding, idempotency_key: str
    ) -> runtime.StoredExecution | None:
        binding = _owned(binding, runtime.ExecutionBinding)
        key = _identifier(idempotency_key)
        if _dump(binding, runtime.ExecutionBinding) != _dump(
            self._sources()[0], runtime.ExecutionBinding
        ):
            raise SQLiteExecutionStateError("Lookup binding differs from the captured source")
        with self._transaction(write=False) as connection:
            return self._history(connection)[2].get(key)

    @staticmethod
    def _advance(
        connection: sqlite3.Connection, before: runtime.ControlState, after: runtime.ControlState
    ) -> None:
        changed = connection.execute(
            "UPDATE control_head SET state_version=?,state_sha256=?,state_json=? "
            "WHERE singleton=1 AND state_version=? AND state_sha256=? AND state_json=?",
            (
                after.state_version,
                after.state_sha256,
                _dump(after, runtime.ControlState),
                before.state_version,
                before.state_sha256,
                _dump(before, runtime.ControlState),
            ),
        ).rowcount
        if changed != 1:
            raise SQLiteExecutionStateError("Local state compare-and-swap was not exact")

    def reserve(
        self,
        request: runtime.ExecutionRequest,
        policy: runtime.ExecutionControlPolicy,
        observation: runtime.ClockObservation,
    ) -> runtime.StateTransition:
        request, policy = self._request(request, policy)
        observation = _owned(observation, runtime.ClockObservation)
        with self._transaction(write=True) as connection:
            before, rows, results = self._history(connection)
            if request.idempotency_key in results:
                raise SQLiteExecutionStateError("A completed key cannot be reserved again")
            after, reason = runtime._expected_reservation(before, request, policy, observation)
            if reason is not None:
                return runtime.StateTransition(before, before)
            after = _owned(after, runtime.ControlState)
            if len(rows) >= MAX_HISTORY_RECORDS:
                raise SQLiteExecutionStateError("Local reservation capacity is exhausted")
            record = {
                "sequence": len(rows) + 1,
                "idempotency_key": request.idempotency_key,
                "request_sha256": request.request_sha256,
                "request_json": _dump(request, runtime.ExecutionRequest),
                "observation_json": _dump(observation, runtime.ClockObservation),
                "before_json": _dump(before, runtime.ControlState),
                "reserved_json": _dump(after, runtime.ControlState),
            }
            connection.execute(
                "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                (*record.values(), _record_digest("reservation", record, self._config()[2])),
            )
            self._advance(connection, before, after)
            self._history(connection)
        return runtime.StateTransition(before, after)

    def complete(
        self,
        request: runtime.ExecutionRequest,
        reservation: runtime.ControlState,
        observation: runtime.ClockObservation,
        outcome: runtime.StoredExecution,
    ) -> runtime.StateTransition:
        request, policy = self._request(request, self._sources()[1])
        reservation = _owned(reservation, runtime.ControlState)
        observation = _owned(observation, runtime.ClockObservation)
        outcome = _owned(outcome, runtime.StoredExecution)
        with self._transaction(write=True) as connection:
            current, rows, results = self._history(connection)
            if (
                not rows
                or current.reservation_request_sha256 != request.request_sha256
                or _dump(current, runtime.ControlState) != _dump(reservation, runtime.ControlState)
                or rows[-1]["request_json"] != _dump(request, runtime.ExecutionRequest)
                or request.idempotency_key in results
            ):
                raise SQLiteExecutionStateError(
                    "Completion is not for the exact pending reservation"
                )
            row = rows[-1]
            before = _read_model(row["before_json"], runtime.ControlState)
            admitted = _read_model(row["observation_json"], runtime.ClockObservation)
            outcome, after = _outcome(
                request, policy, before, reservation, admitted, observation, outcome
            )
            record = {
                "sequence": row["sequence"],
                "observation_json": _dump(observation, runtime.ClockObservation),
                "outcome_json": _dump(outcome, runtime.StoredExecution),
                "completed_json": _dump(after, runtime.ControlState),
            }
            connection.execute(
                "INSERT INTO completions VALUES(?,?,?,?,?)",
                (*record.values(), _record_digest("completion", record, self._config()[2])),
            )
            self._advance(connection, current, after)
            self._history(connection)
        return runtime.StateTransition(reservation, after)


class _OwnedClock:
    def __init__(self, clock: runtime.ExecutionClock) -> None:
        self.clock = clock

    def observe(self) -> runtime.ClockObservation:
        return _owned(self.clock.observe(), runtime.ClockObservation)


class _OwnedTransport:
    def __init__(self, transport: runtime.ExecutionTransport) -> None:
        self.transport = transport

    def execute(self, envelope: runtime.TransportEnvelope) -> runtime.TransportObservation:
        snapshot = _dump(envelope, runtime.TransportEnvelope)
        delivered = _read_model(snapshot, runtime.TransportEnvelope)
        try:
            result = self.transport.execute(delivered)
        except Exception:
            if _dump(delivered, runtime.TransportEnvelope) != snapshot:
                raise SQLiteExecutionStateError("Transport mutated its delivery input") from None
            raise
        if _dump(delivered, runtime.TransportEnvelope) != snapshot:
            raise SQLiteExecutionStateError("Transport mutated its delivery input")
        return _owned(result, runtime.TransportObservation)


def execute_with_durable_controls(
    request: runtime.ExecutionRequest,
    policy: runtime.ExecutionControlPolicy,
    clock: runtime.ExecutionClock,
    repository: SQLiteExecutionStateRepository,
    transport: runtime.ExecutionTransport,
) -> runtime.ExecutionControlResult:
    """Validate actual inputs before the original port's context-free lookup."""
    if type(repository) is not SQLiteExecutionStateRepository:
        raise SQLiteExecutionStateError("The exact local durable repository is required")
    request, policy = repository._request(request, policy)
    return runtime.execute_with_controls(
        request, policy, _OwnedClock(clock), repository, _OwnedTransport(transport)
    )


__all__ = [
    "SQLiteExecutionStateError",
    "SQLiteExecutionStateRepository",
    "execute_with_durable_controls",
]

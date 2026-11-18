"""Explicit local SQLite replay reservations for existing specialist boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Any

from . import specialist_cloud_identity_adapters as cloud
from . import specialist_web_api_adapters as web
from .types import ActionTier

MAX_DOCUMENT_BYTES = 262_144
MAX_STRING_CHARACTERS = 512
MAX_PATH_CHARACTERS = 4096
MAX_JSON_NODES = 4096
MAX_INTEGER = 2**63 - 1
APPLICATION_ID = 0x5352504C
SCHEMA_VERSION = 1
_DOMAIN = "sunderkey.specialist-durable-replay-reservation.v1"
_NAMESPACE = re.compile(r"replayns:[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z")
_TENANT = re.compile(r"tenantref:[A-Za-z0-9][A-Za-z0-9._/-]{0,190}\Z")
_KEY = re.compile(r"idem:[A-Za-z0-9][A-Za-z0-9._/-]{7,190}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_WINDOWS_DEVICES = frozenset(
    ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$")
    + tuple(f"COM{number}" for number in range(1, 10))
    + tuple(f"LPT{number}" for number in range(1, 10))
)


class SpecialistDurableReplayError(ValueError):
    """Invalid native binding or already-held specialist replay reservation."""


class SpecialistReplayStorageError(SpecialistDurableReplayError):
    """Local storage is unavailable, busy, incompatible or inconsistent."""


@dataclass(frozen=True, slots=True)
class _Items:
    item: Any
    maximum: int


def _model_schema(model: type, **overrides: Any) -> dict[str, Any]:
    return {field.name: overrides.get(field.name, str) for field in fields(model)}


_MODELS = {
    web.SpecialistContext: _model_schema(web.SpecialistContext),
    web.PrincipalSessionBinding: _model_schema(web.PrincipalSessionBinding),
    web.ApprovalBinding: _model_schema(
        web.ApprovalBinding, operation=web.SpecialistOperation, maximum_tier=ActionTier
    ),
    web.SpecialistBudget: {field.name: int for field in fields(web.SpecialistBudget)},
    web.SpecialistActionRequest: _model_schema(
        web.SpecialistActionRequest,
        context=web.SpecialistContext,
        operation=web.SpecialistOperation,
        requested_tier=ActionTier,
        approval=web.ApprovalBinding,
        sessions=_Items(web.PrincipalSessionBinding, 256),
        evidence_refs=_Items(str, 64),
        budget=web.SpecialistBudget,
    ),
    cloud.ScopeBinding: _model_schema(
        cloud.ScopeBinding,
        account_refs=_Items(str, 32),
        project_refs=_Items(str, 32),
        subscription_refs=_Items(str, 32),
        cluster_refs=_Items(str, 32),
    ),
    cloud.ExecutionContext: _model_schema(cloud.ExecutionContext, scope=cloud.ScopeBinding),
    cloud.ApprovalBinding: _model_schema(
        cloud.ApprovalBinding,
        provider=cloud.ProviderKind,
        operation=cloud.SpecialistOperation,
        maximum_tier=ActionTier,
        allow_mutation=bool,
        require_dry_run=bool,
    ),
    cloud.SessionBinding: _model_schema(cloud.SessionBinding, provider=cloud.ProviderKind),
    cloud.ExecutionBudget: {field.name: int for field in fields(cloud.ExecutionBudget)},
    cloud.SpecialistActionRequest: _model_schema(
        cloud.SpecialistActionRequest,
        context=cloud.ExecutionContext,
        provider=cloud.ProviderKind,
        operation=cloud.SpecialistOperation,
        requested_tier=ActionTier,
        approval=cloud.ApprovalBinding,
        session=cloud.SessionBinding,
        evidence_refs=_Items(str, 256),
        evidence_sha256=_Items(str, 256),
        dry_run=bool,
        budget=cloud.ExecutionBudget,
    ),
}
_ENUMS = (ActionTier, web.SpecialistOperation, cloud.SpecialistOperation, cloud.ProviderKind)


def _text(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > MAX_STRING_CHARACTERS
        or not value.isascii()
        or (value and not value.isprintable())
    ):
        raise SpecialistDurableReplayError("Replay fields require bounded native ASCII text")
    return value


def _matched(value: Any, pattern: re.Pattern[str], label: str) -> str:
    value = _text(value)
    if pattern.fullmatch(value) is None:
        raise SpecialistDurableReplayError(f"Invalid replay {label}")
    return value


def _local_path(value: Any) -> Path:
    if type(value) not in (str, type(Path())):
        raise SpecialistDurableReplayError("An explicit native local database path is required")
    raw = value if type(value) is str else str(value)
    if (
        not raw
        or len(raw) > MAX_PATH_CHARACTERS
        or not raw.isascii()
        or not raw.isprintable()
        or raw.startswith(("\\\\", "//"))
    ):
        raise SpecialistDurableReplayError("Database path is oversized or unsupported")
    if os.name == "nt":
        spelling = raw.replace("/", "\\")
        pieces = spelling.split("\\")
        if (
            len(pieces) < 2
            or re.fullmatch(r"[A-Za-z]:", pieces[0]) is None
            or spelling[2:3] != "\\"
        ):
            raise SpecialistDurableReplayError("Database path must use an absolute local drive")
        components = pieces[1:]
        for component in components:
            if (
                not component
                or component in (".", "..")
                or component.endswith((".", " "))
                or any(character in '<>:"|?*' for character in component)
                or component.split(".", 1)[0].rstrip(" .").upper() in _WINDOWS_DEVICES
            ):
                raise SpecialistDurableReplayError("Database path contains an ambiguous component")
    else:
        if not raw.startswith("/") or any(
            component in ("", ".", "..") for component in raw.split("/")[1:]
        ):
            raise SpecialistDurableReplayError("Database path must be absolute and unambiguous")
    path = Path(raw)
    if not path.is_absolute():
        raise SpecialistDurableReplayError("Database path must be absolute and non-UNC")
    return path


def _project(value: Any, rule: Any) -> Any:
    if type(rule) is _Items:
        if type(value) is not tuple or len(value) > rule.maximum:
            raise SpecialistDurableReplayError("Replay model requires a bounded native tuple")
        return [_project(item, rule.item) for item in value]
    if rule in _MODELS:
        if type(value) is not rule:
            raise SpecialistDurableReplayError("Replay model family must be exact")
        return {name: _project(getattr(value, name), item) for name, item in _MODELS[rule].items()}
    if rule in _ENUMS:
        if type(value) is not rule:
            raise SpecialistDurableReplayError("Replay model enum must be exact")
        return value.value
    if rule is str:
        return _text(value)
    if type(value) is not rule or (rule is int and not -MAX_INTEGER - 1 <= value <= MAX_INTEGER):
        raise SpecialistDurableReplayError("Replay model primitive must be exact and bounded")
    return value


def _restore(value: Any, rule: Any) -> Any:
    if type(rule) is _Items:
        if type(value) is not list or len(value) > rule.maximum:
            raise SpecialistDurableReplayError("Stored replay tuple projection is invalid")
        return tuple(_restore(item, rule.item) for item in value)
    if rule in _MODELS:
        if type(value) is not dict or set(value) != set(_MODELS[rule]):
            raise SpecialistDurableReplayError("Stored replay model fields are invalid")
        return rule(**{name: _restore(value[name], item) for name, item in _MODELS[rule].items()})
    if rule in _ENUMS:
        return rule(_text(value))
    if rule is str:
        return _text(value)
    if type(value) is not rule or (rule is int and not -MAX_INTEGER - 1 <= value <= MAX_INTEGER):
        raise SpecialistDurableReplayError("Stored replay primitive is invalid")
    return value


def _canonical(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise SpecialistDurableReplayError("Replay document exceeds its byte ceiling")
    return encoded


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SpecialistDurableReplayError("Duplicate stored replay JSON member")
        result[key] = value
    return result


def _integer(text: str) -> int:
    if len(text) > 20:
        raise SpecialistDurableReplayError("Stored replay integer is too large")
    value = int(text)
    if not -MAX_INTEGER - 1 <= value <= MAX_INTEGER:
        raise SpecialistDurableReplayError("Stored replay integer is too large")
    return value


def _not_numeric(_: str) -> Any:
    raise SpecialistDurableReplayError("Stored replay floating-point values are forbidden")


def _load(document: Any) -> dict[str, Any]:
    if type(document) is not str or len(document) > MAX_DOCUMENT_BYTES or not document.isascii():
        raise SpecialistDurableReplayError("Stored replay document is invalid or oversized")
    raw = json.loads(
        document,
        object_pairs_hook=_pairs,
        parse_int=_integer,
        parse_float=_not_numeric,
        parse_constant=_not_numeric,
    )
    nodes = 0

    def visit(value: Any, depth: int = 0) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > 12:
            raise SpecialistDurableReplayError("Stored replay structure exceeds its ceiling")
        if type(value) is dict:
            for key, child in value.items():
                _text(key)
                visit(child, depth + 1)
        elif type(value) is list:
            for child in value:
                visit(child, depth + 1)
        elif type(value) is str:
            _text(value)
        elif type(value) not in (bool, int, type(None)):
            raise SpecialistDurableReplayError("Stored replay JSON primitive is invalid")

    visit(raw)
    if type(raw) is not dict or _canonical(raw) != document:
        raise SpecialistDurableReplayError("Stored replay JSON is not canonical")
    return raw


def _owned_model(value: Any, model: type) -> Any:
    try:
        projection = _project(value, model)
        owned = _restore(projection, model)
        if _canonical(_project(owned, model)) != _canonical(projection):
            raise SpecialistDurableReplayError("Replay model is not canonical")
        return owned
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SpecialistDurableReplayError(
            "Replay source model is invalid or noncanonical"
        ) from exc


@dataclass(frozen=True, slots=True)
class _Request:
    family: str
    tenant_ref: str
    idempotency_key: str
    request_id: str
    request_sha256: str
    context_sha256: str
    model_json: str


def _request(value: Any, family: str) -> _Request:
    model = web.SpecialistActionRequest if family == "web_api" else cloud.SpecialistActionRequest
    owned = _owned_model(value, model)
    identifier = re.compile(r"SAR-[0-9A-F]{32}\Z" if family == "web_api" else r"CIR-[0-9A-F]{32}\Z")
    tenant = owned.context.tenant_ref if family == "web_api" else owned.context.scope.tenant_ref
    return _Request(
        family,
        _matched(tenant, _TENANT, "tenant"),
        _matched(owned.idempotency_key, _KEY, "idempotency key"),
        _matched(owned.request_id, identifier, "request identifier"),
        _matched(owned.request_sha256, _SHA256, "request digest"),
        _matched(owned.context.context_sha256, _SHA256, "context digest"),
        _canonical(_project(owned, model)),
    )


def _request_from_json(document: str, family: str) -> Any:
    model = web.SpecialistActionRequest if family == "web_api" else cloud.SpecialistActionRequest
    return _restore(_load(document), model)


_DDL = (
    "CREATE TABLE replay_metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
    "format TEXT NOT NULL CHECK(format='specialist_durable_replay.v1'), "
    "schema_sha256 TEXT NOT NULL) STRICT",
    "CREATE TABLE specialist_reservations (namespace TEXT NOT NULL, tenant_ref TEXT NOT NULL, "
    "idempotency_key TEXT NOT NULL, "
    "family TEXT NOT NULL CHECK(family IN ('web_api','cloud_identity')), "
    "request_id TEXT NOT NULL, request_sha256 TEXT NOT NULL, context_sha256 TEXT NOT NULL, "
    "model_json TEXT NOT NULL CHECK(length(model_json)<=262144), record_sha256 TEXT NOT NULL, "
    "PRIMARY KEY(namespace,tenant_ref,idempotency_key)) STRICT",
    "CREATE TRIGGER replay_metadata_immutable BEFORE UPDATE ON replay_metadata "
    "BEGIN SELECT RAISE(ABORT,'replay metadata is immutable'); END",
    "CREATE TRIGGER replay_metadata_no_delete BEFORE DELETE ON replay_metadata "
    "BEGIN SELECT RAISE(ABORT,'replay metadata cannot be deleted'); END",
    "CREATE TRIGGER replay_metadata_no_replace BEFORE INSERT ON replay_metadata "
    "WHEN EXISTS(SELECT 1 FROM replay_metadata) "
    "BEGIN SELECT RAISE(ABORT,'replay metadata cannot be replaced'); END",
    "CREATE TRIGGER specialist_reservations_immutable BEFORE UPDATE ON specialist_reservations "
    "BEGIN SELECT RAISE(ABORT,'specialist reservation is immutable'); END",
    "CREATE TRIGGER specialist_reservations_no_delete BEFORE DELETE ON specialist_reservations "
    "BEGIN SELECT RAISE(ABORT,'specialist reservation cannot be deleted'); END",
    "CREATE TRIGGER specialist_reservations_no_replace BEFORE INSERT ON specialist_reservations "
    "WHEN EXISTS(SELECT 1 FROM specialist_reservations WHERE namespace=NEW.namespace "
    "AND tenant_ref=NEW.tenant_ref AND idempotency_key=NEW.idempotency_key) "
    "BEGIN SELECT RAISE(ABORT,'specialist reservation cannot be replaced'); END",
)
_SCHEMA_SHA256 = "sha256:" + hashlib.sha256(_canonical(list(_DDL)).encode("ascii")).hexdigest()
_SCHEMA_OBJECTS = {statement.split()[2]: statement for statement in _DDL}
_COLUMNS = (
    "namespace",
    "tenant_ref",
    "idempotency_key",
    "family",
    "request_id",
    "request_sha256",
    "context_sha256",
    "model_json",
    "record_sha256",
)


def _record(namespace: str, request: _Request) -> dict[str, str]:
    return {
        "namespace": namespace,
        **{field.name: getattr(request, field.name) for field in fields(_Request)},
    }


def _record_digest(record: dict[str, str]) -> str:
    encoded = _canonical({"domain": _DOMAIN, "record": record})
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _bounded_column(name: str, maximum: int) -> str:
    return (
        f"CASE WHEN typeof({name})='text' AND length(CAST({name} AS BLOB))<={maximum} "
        f"THEN {name} ELSE NULL END AS {name}"
    )


class SQLiteSpecialistReplayStore:
    """Caller-selected local storage. Reservations are not action authority."""

    def __init__(self, database_path: str | Path, *, namespace: str, tenant_ref: str) -> None:
        namespace = _matched(namespace, _NAMESPACE, "namespace")
        tenant_ref = _matched(tenant_ref, _TENANT, "tenant")
        path = _local_path(database_path)
        try:
            parent = path.parent.resolve(strict=True)
            if not parent.is_dir() or path.is_symlink() or (path.exists() and not path.is_file()):
                raise SpecialistDurableReplayError(
                    "Database path must identify a regular local file"
                )
        except OSError as exc:
            raise SpecialistReplayStorageError(
                "Local replay parent directory is unavailable"
            ) from exc
        self._binding = (str(parent / path.name), namespace, tenant_ref)
        self._initial_binding = self._binding
        self._initialize()

    def _config(self) -> tuple[str, str, str]:
        binding = getattr(self, "_binding", None)
        if (
            type(binding) is not tuple
            or len(binding) != 3
            or any(type(item) is not str for item in binding)
            or binding != getattr(self, "_initial_binding", None)
        ):
            raise SpecialistDurableReplayError("Local replay configuration changed")
        return self._binding

    def _connect(self, *, mode: str) -> sqlite3.Connection:
        path, _, _ = self._config()
        if mode not in ("ro", "rw"):
            raise SpecialistReplayStorageError("Local replay connection mode is unsupported")
        if Path(path).is_symlink() or not Path(path).is_file():
            raise SpecialistReplayStorageError("Local replay database is unavailable")
        connection = sqlite3.connect(Path(path).as_uri() + f"?mode={mode}", uri=True, timeout=0)
        try:
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.Error:
            connection.close()
            raise

    @staticmethod
    def _exclusive_create(path: str) -> None:
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
                opened = os.fstat(descriptor)
                current = os.lstat(path)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or not stat.S_ISREG(current.st_mode)
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                    or Path(path).is_symlink()
                ):
                    raise SpecialistReplayStorageError("Exclusive replay file creation changed")
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise SpecialistReplayStorageError("Exclusive replay file creation failed") from exc

    @staticmethod
    def _empty_database(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != 0
            or connection.execute("PRAGMA user_version").fetchone()[0] != 0
            or connection.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone() is not None
        ):
            raise SpecialistReplayStorageError("New replay file is not an unmarked empty database")

    @staticmethod
    def _journal(connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise SpecialistReplayStorageError("Local replay requires DELETE journal mode")

    @classmethod
    def _configure_owned(cls, connection: sqlite3.Connection) -> None:
        cls._journal(connection)
        connection.execute("PRAGMA busy_timeout=0")
        connection.execute("PRAGMA synchronous=FULL")
        cls._settings(connection)

    @classmethod
    def _settings(cls, connection: sqlite3.Connection) -> None:
        cls._journal(connection)
        if (
            connection.execute("PRAGMA synchronous").fetchone()[0] != 2
            or connection.execute("PRAGMA busy_timeout").fetchone()[0] != 0
        ):
            raise SpecialistReplayStorageError("Local replay durability configuration changed")

    @staticmethod
    def _schema(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION
        ):
            raise SpecialistReplayStorageError("Local replay database identity is incompatible")
        objects = {
            row["name"]: row["sql"]
            for row in connection.execute(
                "SELECT "
                + _bounded_column("name", MAX_STRING_CHARACTERS)
                + ","
                + _bounded_column("sql", MAX_DOCUMENT_BYTES)
                + " FROM sqlite_master WHERE substr(name,1,7)!='sqlite_' LIMIT ?",
                (len(_SCHEMA_OBJECTS) + 1,),
            )
        }
        if objects != _SCHEMA_OBJECTS:
            raise SpecialistReplayStorageError("Local replay schema is inconsistent")
        metadata = connection.execute(
            "SELECT singleton,"
            + _bounded_column("format", MAX_STRING_CHARACTERS)
            + ","
            + _bounded_column("schema_sha256", MAX_STRING_CHARACTERS)
            + " FROM replay_metadata LIMIT 2"
        ).fetchall()
        if len(metadata) != 1 or tuple(metadata[0]) != (
            1,
            "specialist_durable_replay.v1",
            _SCHEMA_SHA256,
        ):
            raise SpecialistReplayStorageError("Local replay metadata is inconsistent")

    def _initialize(self) -> None:
        path, _, _ = self._config()
        created = not Path(path).exists()
        if created:
            self._exclusive_create(path)
        else:
            self._read_only_preflight()
        try:
            with closing(self._connect(mode="rw")) as connection:
                if created:
                    self._empty_database(connection)
                else:
                    self._schema(connection)
                self._configure_owned(connection)
                connection.execute("BEGIN IMMEDIATE")
                if created:
                    self._empty_database(connection)
                    connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                    connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    for statement in _DDL:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO replay_metadata VALUES(1,?,?)",
                        ("specialist_durable_replay.v1", _SCHEMA_SHA256),
                    )
                self._schema(connection)
                self._settings(connection)
                connection.commit()
        except sqlite3.Error as exc:
            raise SpecialistReplayStorageError("Local replay initialization failed") from exc

    def _read_only_preflight(self) -> None:
        # A writable SQLite open can recover a foreign hot journal before any
        # explicit write. Establish the supported schema without permitting it.
        try:
            with closing(self._connect(mode="ro")) as connection:
                connection.execute("BEGIN")
                self._schema(connection)
                self._journal(connection)
        except sqlite3.Error as exc:
            raise SpecialistReplayStorageError("Local replay read-only preflight failed") from exc

    def _row(self, connection: sqlite3.Connection, key: str) -> sqlite3.Row | None:
        _, namespace, tenant = self._config()
        selected = ",".join(
            _bounded_column(
                name, MAX_DOCUMENT_BYTES if name == "model_json" else MAX_STRING_CHARACTERS
            )
            for name in _COLUMNS
        )
        return connection.execute(
            "SELECT "
            + selected
            + " FROM specialist_reservations WHERE namespace=? AND tenant_ref=? "
            "AND idempotency_key=?",
            (namespace, tenant, key),
        ).fetchone()

    def _verified_row(self, row: sqlite3.Row) -> None:
        try:
            if tuple(row.keys()) != _COLUMNS or any(type(value) is not str for value in row):
                raise SpecialistDurableReplayError("Stored replay projection types are invalid")
            family = row["family"]
            if family not in ("web_api", "cloud_identity"):
                raise SpecialistDurableReplayError("Stored replay family is invalid")
            request = _request(_request_from_json(row["model_json"], family), family)
            _, namespace, tenant = self._config()
            record = _record(namespace, request)
            if (
                request.tenant_ref != tenant
                or any(row[key] != value for key, value in record.items())
                or row["record_sha256"] != _record_digest(record)
            ):
                raise SpecialistDurableReplayError("Stored replay bindings are inconsistent")
        except (AttributeError, KeyError, TypeError, ValueError, RecursionError) as exc:
            raise SpecialistReplayStorageError(
                "Stored specialist replay reservation is invalid"
            ) from exc

    def contains(self, idempotency_key: str) -> bool:
        key = _matched(idempotency_key, _KEY, "idempotency key")
        try:
            with closing(self._connect(mode="ro")) as connection:
                self._schema(connection)
                self._configure_owned(connection)
                connection.execute("BEGIN")
                self._schema(connection)
                self._settings(connection)
                row = self._row(connection, key)
                if row is not None:
                    self._verified_row(row)
                return row is not None
        except sqlite3.Error as exc:
            raise SpecialistReplayStorageError("Local replay lookup failed") from exc

    def _reserve(self, request: _Request) -> None:
        _, namespace, tenant = self._config()
        if request.tenant_ref != tenant:
            raise SpecialistDurableReplayError("Specialist request belongs to a foreign tenant")
        record = _record(namespace, request)
        self._read_only_preflight()
        try:
            with closing(self._connect(mode="rw")) as connection:
                self._schema(connection)
                self._configure_owned(connection)
                connection.execute("BEGIN IMMEDIATE")
                self._schema(connection)
                self._settings(connection)
                row = self._row(connection, request.idempotency_key)
                if row is not None:
                    self._verified_row(row)
                    raise SpecialistDurableReplayError("Specialist replay key is already reserved")
                connection.execute(
                    "INSERT INTO specialist_reservations VALUES(?,?,?,?,?,?,?,?,?)",
                    tuple(record[name] for name in _COLUMNS[:-1]) + (_record_digest(record),),
                )
                connection.commit()
        except sqlite3.Error as exc:
            raise SpecialistReplayStorageError("Local specialist reservation failed") from exc


def _store(value: Any) -> SQLiteSpecialistReplayStore:
    if type(value) is not SQLiteSpecialistReplayStore:
        raise SpecialistDurableReplayError("An exact local specialist replay store is required")
    value._config()
    return value


def _bound_store(facade: Any) -> SQLiteSpecialistReplayStore:
    selected = getattr(facade, "_store", None)
    if selected is not getattr(facade, "_initial_store", None):
        raise SpecialistDurableReplayError("Expected replay store changed")
    return _store(selected)


class SQLiteWebApiReplayGuard:
    """Full native request reserve facade for the unchanged web/API execution port."""

    def __init__(
        self, store: SQLiteSpecialistReplayStore, *, expected_context: web.SpecialistContext
    ):
        self._store = _store(store)
        self._initial_store = self._store
        context = _owned_model(expected_context, web.SpecialistContext)
        if context.tenant_ref != store._config()[2]:
            raise SpecialistDurableReplayError("Expected context belongs to a foreign tenant")
        self._context_json = _canonical(_project(context, web.SpecialistContext))
        self._initial_context_json = self._context_json

    def reserve(self, request: web.SpecialistActionRequest) -> None:
        expected = getattr(self, "_context_json", None)
        if type(expected) is not str or expected != getattr(self, "_initial_context_json", None):
            raise SpecialistDurableReplayError("Expected web context changed")
        captured = _request(request, "web_api")
        context = _load(captured.model_json)["context"]
        if _canonical(context) != self._context_json:
            raise SpecialistDurableReplayError("Specialist request differs from expected context")
        _bound_store(self)._reserve(captured)

    def contains(self, idempotency_key: str) -> bool:
        return _bound_store(self).contains(idempotency_key)


class SQLiteCloudIdentityReplayGuard:
    """Captured-request facade for the unchanged cloud string-only reserve port."""

    def __init__(
        self,
        store: SQLiteSpecialistReplayStore,
        *,
        expected_request: cloud.SpecialistActionRequest,
        expected_context: cloud.ExecutionContext,
    ) -> None:
        self._store = _store(store)
        self._initial_store = self._store
        captured = _request(expected_request, "cloud_identity")
        context = _owned_model(expected_context, cloud.ExecutionContext)
        self._context_json = _canonical(_project(context, cloud.ExecutionContext))
        if (
            captured.tenant_ref != store._config()[2]
            or _canonical(_load(captured.model_json)["context"]) != self._context_json
        ):
            raise SpecialistDurableReplayError(
                "Cloud request differs from expected tenant or context"
            )
        self._request_json = captured.model_json
        self._initial_binding = (self._request_json, self._context_json)

    def _binding(self) -> tuple[str, str]:
        request_json = getattr(self, "_request_json", None)
        context_json = getattr(self, "_context_json", None)
        if (
            type(request_json) is not str
            or type(context_json) is not str
            or (request_json, context_json) != getattr(self, "_initial_binding", None)
        ):
            raise SpecialistDurableReplayError("Expected cloud binding changed")
        return request_json, context_json

    @property
    def expected_request(self) -> cloud.SpecialistActionRequest:
        """Return an independently reconstructed copy, never the original input."""
        return _request_from_json(self._binding()[0], "cloud_identity")

    def reserve(self, idempotency_key: str) -> None:
        key = _matched(idempotency_key, _KEY, "idempotency key")
        captured = _request(self.expected_request, "cloud_identity")
        if key != captured.idempotency_key:
            raise SpecialistDurableReplayError("Cloud reserve key differs from captured request")
        _bound_store(self)._reserve(captured)


def execute_cloud_identity_with_durable_replay(
    request: cloud.SpecialistActionRequest,
    *,
    expected_context: cloud.ExecutionContext,
    adapter: cloud.CloudIdentityExecutionAdapter,
    replay_guard: SQLiteCloudIdentityReplayGuard,
    evaluated_at: datetime,
) -> cloud.SpecialistActionReceipt:
    """Compare full actual inputs before delegating to the unchanged cloud boundary."""
    if type(replay_guard) is not SQLiteCloudIdentityReplayGuard:
        raise SpecialistDurableReplayError("An exact durable cloud replay facade is required")
    _bound_store(replay_guard)
    actual = _request(request, "cloud_identity")
    context = _owned_model(expected_context, cloud.ExecutionContext)
    expected_request_json, expected_context_json = replay_guard._binding()
    if (
        actual.model_json != expected_request_json
        or _canonical(_project(context, cloud.ExecutionContext)) != expected_context_json
    ):
        raise SpecialistDurableReplayError(
            "Actual cloud request differs from captured request or context"
        )
    delivered = _request_from_json(actual.model_json, "cloud_identity")
    result = cloud.execute_specialist_action(
        delivered,
        expected_context=context,
        adapter=adapter,
        replay_guard=replay_guard,
        evaluated_at=evaluated_at,
    )
    if _request(delivered, "cloud_identity").model_json != actual.model_json:
        raise SpecialistDurableReplayError("Cloud adapter changed its delivered request")
    return result


__all__ = [
    "SpecialistDurableReplayError",
    "SpecialistReplayStorageError",
    "SQLiteSpecialistReplayStore",
    "SQLiteWebApiReplayGuard",
    "SQLiteCloudIdentityReplayGuard",
    "execute_cloud_identity_with_durable_replay",
]

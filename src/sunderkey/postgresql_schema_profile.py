"""Pure, addressed executable DDL for the existing PostgreSQL adapter surface."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, ClassVar

from .postgresql_runtime_adapter import (
    POSTGRESQL_MIGRATION_ID,
    POSTGRESQL_MIGRATION_SHA256,
    POSTGRESQL_MIGRATION_VERSION,
)

SCHEMA_VERSION = 1
POSTGRESQL_MAJOR_VERSION = 18
SIGNED64_MAX = 9_223_372_036_854_775_807
MAX_SQL_BYTES = 131_072
MAX_PROFILE_BYTES = 262_144
PROFILE_KIND = "sunderkey.postgresql-executable-schema-profile.v1"
SCHEMA_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROFILE_ID_RE = re.compile(r"PGS-[0-9A-F]{32}\Z")

TABLE_NAMES = (
    "schema_migrations",
    "aggregate_heads",
    "resource_fences",
    "transaction_batches",
    "outbox_events",
    "runtime_receipts",
    "schedules",
    "occurrences",
    "lease_snapshots",
    "scheduler_results",
)
RUNTIME_SCOPE = (
    "aggregate_transactions",
    "schedule_registration",
    "due_materialization",
    "due_claims",
)
NO_EFFECTS = MappingProxyType(
    {
        "authorization": "none",
        "database_connection": "none",
        "deployment": "none",
        "migration": "none",
        "network": "none",
        "persistence": "none",
        "qualification": "none",
        "sql_execution": "none",
    }
)


class PostgreSQLSchemaProfileError(ValueError):
    """An offline profile cannot be reproduced exactly."""


def _schema_name(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) > 63
        or SCHEMA_NAME_RE.fullmatch(value) is None
        or value.startswith("pg_")
        or value == "information_schema"
    ):
        raise PostgreSQLSchemaProfileError("schema_name must be an explicit bounded identifier")
    return value


def _canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _digest(document: str) -> str:
    return "sha256:" + hashlib.sha256(document.encode("utf-8")).hexdigest()


def _regex(column: str, pattern: str) -> str:
    # Escape-string syntax preserves grouped ARE anchors across string settings.
    escaped = (r"\A(?:" + pattern + r")\Z").replace("\\", "\\\\")
    return f"\"{column}\" ~ E'{escaped}'"


def _text(column: str, pattern: str | None = None, *, nullable: bool = False) -> str:
    declaration = f'"{column}" TEXT COLLATE pg_catalog."C"'
    if not nullable:
        declaration += " NOT NULL"
    if pattern is not None:
        declaration += f" CHECK ({_regex(column, pattern)})"
    return declaration


def _reference(column: str, namespace: str) -> str:
    return _text(column, namespace + r":[A-Za-z0-9][A-Za-z0-9._/-]{0,190}")


def _sha(column: str) -> str:
    return _text(column, r"sha256:[0-9a-f]{64}")


def _record(column: str, prefix: str, *, nullable: bool = False) -> str:
    return _text(column, prefix + r"-[0-9A-F]{32}", nullable=nullable)


def _integer(column: str, minimum: int, maximum: int, *, bigint: bool = False) -> str:
    datatype = "BIGINT" if bigint else "INTEGER"
    return f'"{column}" {datatype} NOT NULL CHECK ("{column}" BETWEEN {minimum} AND {maximum})'


def _json(column: str) -> str:
    # TEXT is intentional: existing DB-API consumers call json.loads on strings.
    return (
        _text(column) + f" CHECK (pg_catalog.json_typeof(\"{column}\"::pg_catalog.json) = 'object')"
    )


def _utc(column: str, *, nullable: bool = False) -> str:
    value = f'"{column}"'
    year = f"pg_catalog.substr({value}, 1, 4)::INTEGER"
    month = f"pg_catalog.substr({value}, 6, 2)::INTEGER"
    day = f"pg_catalog.substr({value}, 9, 2)::INTEGER"
    shape = (
        r"[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])"
        r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
    )
    # CASE guards casts; Gregorian arithmetic has no clock/timezone dependency.
    leap = f"({year} % 4 = 0 AND ({year} % 100 <> 0 OR {year} % 400 = 0))"
    limit = (
        f"CASE {month} WHEN 2 THEN CASE WHEN {leap} THEN 29 ELSE 28 END "
        "WHEN 4 THEN 30 WHEN 6 THEN 30 WHEN 9 THEN 30 WHEN 11 THEN 30 ELSE 31 END"
    )
    calendar = f"{year} BETWEEN 1 AND 9999 AND {day} <= ({limit})"
    predicate = f"CASE WHEN {_regex(column, shape)} THEN ({calendar}) ELSE FALSE END"
    if nullable:
        predicate = f"{value} IS NULL OR ({predicate})"
    return _text(column, nullable=nullable) + f" CHECK ({predicate})"


def _qualified(schema_name: str, table: str) -> str:
    return f'"{schema_name}"."{table}"'


def _render_sql(schema_name: str) -> str:
    ref = _reference
    ident = r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"
    tx_idem = r"idem:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}"
    scheduler_idem = r"idem:[A-Za-z0-9][A-Za-z0-9._:/-]{7,255}"
    definitions = (
        (
            "schema_migrations",
            (
                _integer("version", 1, 2_147_483_647),
                ref("migration_id", "migrationref"),
                _sha("migration_sha256"),
                'PRIMARY KEY ("version") NOT DEFERRABLE',
            ),
        ),
        (
            "aggregate_heads",
            (
                ref("tenant_ref", "tenantref"),
                ref("aggregate_ref", "aggregateref"),
                _integer("version", 1, SIGNED64_MAX, bigint=True),
                _sha("content_sha256"),
                'PRIMARY KEY ("tenant_ref", "aggregate_ref") NOT DEFERRABLE',
            ),
        ),
        (
            "resource_fences",
            (
                ref("tenant_ref", "tenantref"),
                ref("resource_ref", "resourceref"),
                _text("fence_token", r"fence:[A-Za-z0-9][A-Za-z0-9._:-]{15,127}"),
                _integer("fence_epoch", 1, 1_000_000),
                'PRIMARY KEY ("tenant_ref", "resource_ref") NOT DEFERRABLE',
            ),
        ),
        (
            "transaction_batches",
            (
                ref("tenant_ref", "tenantref"),
                ref("assessment_ref", "assessmentref"),
                ref("scope_ref", "scoperef"),
                _text("idempotency_key", tx_idem),
                _record("batch_id", "PTB"),
                _sha("batch_sha256"),
                _json("batch_json"),
                'PRIMARY KEY ("tenant_ref", "idempotency_key") NOT DEFERRABLE',
            ),
        ),
        (
            "outbox_events",
            (
                _text("tenant_ref", ident),
                ref("event_ref", "outboxref"),
                _text("batch_id", r"(PTB|DSL)-[0-9A-F]{32}"),
                _json("event_json"),
                _utc("created_at"),
                _utc("published_at", nullable=True),
                'PRIMARY KEY ("tenant_ref", "event_ref") NOT DEFERRABLE',
            ),
        ),
        (
            "runtime_receipts",
            (
                ref("tenant_ref", "tenantref"),
                _record("receipt_id", "PGR"),
                _sha("receipt_sha256"),
                _json("receipt_json"),
                _utc("created_at"),
                'PRIMARY KEY ("tenant_ref", "receipt_id") NOT DEFERRABLE',
            ),
        ),
        (
            "schedules",
            (
                _text("tenant_id", ident),
                _record("schedule_id", "DSD"),
                _sha("schedule_sha256"),
                _integer("definition_version", 1, 2_147_483_647),
                _json("schedule_json"),
                '"cancelled" BOOLEAN NOT NULL',
                'PRIMARY KEY ("tenant_id", "schedule_id") NOT DEFERRABLE',
            ),
        ),
        (
            "occurrences",
            (
                _text("tenant_id", ident),
                _record("occurrence_id", "DSO"),
                _record("schedule_id", "DSD"),
                _integer("occurrence_index", 0, 2_147_483_647),
                _json("occurrence_json"),
                _integer("occurrence_version", 1, 2_147_483_647),
                _text("state", r"pending|retry|leased|completed|dead_lettered|cancelled"),
                _utc("ready_at"),
                _integer("attempt_number", 0, 32),
                _integer("fence_epoch", 0, 2_147_483_647),
                _record("lease_id", "DSL", nullable=True),
                'PRIMARY KEY ("tenant_id", "occurrence_id") NOT DEFERRABLE',
                'UNIQUE ("tenant_id", "schedule_id", "occurrence_index") NOT DEFERRABLE',
                'FOREIGN KEY ("tenant_id", "schedule_id") REFERENCES '
                + _qualified(schema_name, "schedules")
                + '("tenant_id", "schedule_id") NOT DEFERRABLE',
                'CHECK (("state" = \'leased\') = ("lease_id" IS NOT NULL))',
            ),
        ),
        (
            "lease_snapshots",
            (
                _text("tenant_id", ident),
                _record("lease_id", "DSL"),
                _integer("lease_version", 1, 2_147_483_647),
                _record("occurrence_id", "DSO"),
                _integer("fence_epoch", 1, 2_147_483_647),
                _utc("expires_at"),
                '"active" BOOLEAN NOT NULL',
                _json("lease_json"),
                'PRIMARY KEY ("tenant_id", "lease_id", "lease_version") NOT DEFERRABLE',
                'FOREIGN KEY ("tenant_id", "occurrence_id") REFERENCES '
                + _qualified(schema_name, "occurrences")
                + '("tenant_id", "occurrence_id") NOT DEFERRABLE',
            ),
        ),
        (
            "scheduler_results",
            (
                _text("tenant_id", ident),
                _text("idempotency_key", scheduler_idem),
                _text("result_kind", "claim"),
                _sha("result_sha256"),
                _json("result_json"),
                'PRIMARY KEY ("tenant_id", "idempotency_key") NOT DEFERRABLE',
            ),
        ),
    )
    statements = [
        f"CREATE TABLE {_qualified(schema_name, table)} (\n    " + ",\n    ".join(columns) + "\n);"
        for table, columns in definitions
    ]
    statements.extend(
        (
            'CREATE INDEX "occurrence_due_idx" ON '
            + _qualified(schema_name, "occurrences")
            + '("tenant_id", "schedule_id", "ready_at", "occurrence_index") '
            + "WHERE \"state\" IN ('pending', 'retry');",
            'CREATE UNIQUE INDEX "one_active_occurrence_lease" ON '
            + _qualified(schema_name, "lease_snapshots")
            + '("tenant_id", "occurrence_id") WHERE "active";',
        )
    )
    sql = "\n\n".join(statements) + "\n"
    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
        raise PostgreSQLSchemaProfileError("fixed SQL profile exceeds its bound")
    return sql


def _body(schema_name: str, sql: str, sql_sha256: str, byte_count: int) -> dict[str, Any]:
    return {
        "kind": PROFILE_KIND,
        "schema_version": SCHEMA_VERSION,
        "postgresql_major_version": POSTGRESQL_MAJOR_VERSION,
        "schema_name": schema_name,
        "table_names": list(TABLE_NAMES),
        "runtime_scope": list(RUNTIME_SCOPE),
        "aggregate_version_storage": {"minimum": 1, "maximum": SIGNED64_MAX, "type": "bigint"},
        "json_storage": "text_object_syntax_only",
        "timestamp_storage": "canonical_utc_text",
        "sql_encoding": "utf-8",
        "sql_line_endings": "lf",
        "legacy_compatibility_marker": {
            "version": POSTGRESQL_MIGRATION_VERSION,
            "migration_id": POSTGRESQL_MIGRATION_ID,
            "migration_sha256": POSTGRESQL_MIGRATION_SHA256,
        },
        "ddl_sql": sql,
        "ddl_byte_count": byte_count,
        "ddl_sha256": sql_sha256,
        "effects": dict(NO_EFFECTS),
    }


def _identity(body: dict[str, Any]) -> tuple[str, str]:
    digest = _digest(_canonical({"domain": PROFILE_KIND, "body": body}))
    return "PGS-" + digest[7:39].upper(), digest


@dataclass(frozen=True, slots=True)
class PostgreSQLExecutableSchemaProfile:
    """Fixed SQL description, not a migration execution or deployment receipt."""

    schema_name: str
    ddl_sql: str = field(init=False)
    ddl_byte_count: int = field(init=False)
    ddl_sha256: str = field(init=False)
    profile_id: str = field(init=False)
    profile_sha256: str = field(init=False)
    KIND: ClassVar[str] = PROFILE_KIND

    def __post_init__(self) -> None:
        schema = _schema_name(self.schema_name)
        sql = _render_sql(schema)
        byte_count = len(sql.encode("utf-8"))
        sql_sha = _digest(sql)
        profile_id, profile_sha = _identity(_body(schema, sql, sql_sha, byte_count))
        for name, value in (
            ("ddl_sql", sql),
            ("ddl_byte_count", byte_count),
            ("ddl_sha256", sql_sha),
            ("profile_id", profile_id),
            ("profile_sha256", profile_sha),
        ):
            object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, Any]:
        owned = verify_postgresql_executable_schema_profile(self)
        document = _body(owned.schema_name, owned.ddl_sql, owned.ddl_sha256, owned.ddl_byte_count)
        document.update(profile_id=owned.profile_id, profile_sha256=owned.profile_sha256)
        return document

    def to_json(self) -> str:
        return _canonical(self.to_dict())

    def to_sql(self) -> str:
        return verify_postgresql_executable_schema_profile(self).ddl_sql

    @classmethod
    def from_dict(cls, document: Any) -> PostgreSQLExecutableSchemaProfile:
        fields = set(_body("a", "", "", 0)) | {"profile_id", "profile_sha256"}
        _object(document, fields, "profile")
        _string(document["schema_name"], 63, "schema_name")
        expected = cls(document["schema_name"])
        expected_document = expected.to_dict()
        _closed_native_shape(document, expected_document)
        if _canonical(document) != _canonical(expected_document):
            raise PostgreSQLSchemaProfileError("profile does not match fixed schema/SQL replay")
        return expected

    @classmethod
    def from_json(cls, document: Any) -> PostgreSQLExecutableSchemaProfile:
        _string(document, MAX_PROFILE_BYTES, "profile JSON", ascii_only=False)
        try:
            if len(document.encode("utf-8")) > MAX_PROFILE_BYTES:
                raise PostgreSQLSchemaProfileError("profile JSON exceeds its byte bound")
            raw = json.loads(
                document,
                object_pairs_hook=_json_object,
                parse_int=_json_integer,
                parse_float=_reject_json_number,
                parse_constant=_reject_json_number,
            )
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise PostgreSQLSchemaProfileError("profile JSON is not bounded native JSON") from exc
        result = cls.from_dict(raw)
        if document != result.to_json():
            raise PostgreSQLSchemaProfileError("profile JSON must be exactly canonical")
        return result


def _object(value: Any, fields: set[str], label: str) -> None:
    if (
        type(value) is not dict
        or len(value) != len(fields)
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise PostgreSQLSchemaProfileError(f"{label} must be an exact closed native object")


def _string(value: Any, maximum: int, label: str, *, ascii_only: bool = True) -> None:
    if type(value) is not str or len(value) > maximum or (ascii_only and not value.isascii()):
        raise PostgreSQLSchemaProfileError(f"{label} must be a bounded native string")


def _closed_native_shape(value: Any, expected: Any) -> None:
    # Only the known, small generated document shape is traversed before encoding.
    if type(expected) is dict:
        _object(value, set(expected), "profile member")
        for key in expected:
            _closed_native_shape(value[key], expected[key])
    elif type(expected) is list:
        if type(value) is not list or len(value) != len(expected):
            raise PostgreSQLSchemaProfileError("profile lists must have the fixed native shape")
        for item, expected_item in zip(value, expected, strict=True):
            _closed_native_shape(item, expected_item)
    elif type(expected) is str:
        _string(value, MAX_SQL_BYTES if len(expected) > 256 else 256, "profile member")
    elif type(expected) is int:
        if type(value) is not int or not 0 <= value <= SIGNED64_MAX:
            raise PostgreSQLSchemaProfileError(
                "profile integers must be exact bounded native values"
            )
    else:
        raise PostgreSQLSchemaProfileError("fixed profile has an unsupported shape")


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > 32:
        raise PostgreSQLSchemaProfileError("profile JSON object exceeds its fixed shape")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PostgreSQLSchemaProfileError("profile JSON contains a duplicate key")
        result[key] = value
    return result


def _json_integer(token: str) -> int:
    if len(token.removeprefix("-")) > 19:
        raise PostgreSQLSchemaProfileError("profile JSON integer exceeds its bound")
    return int(token)


def _reject_json_number(token: str) -> Any:
    raise PostgreSQLSchemaProfileError("profile JSON must not contain floating/nonfinite values")


def build_postgresql_executable_schema_profile(
    *, schema_name: str
) -> PostgreSQLExecutableSchemaProfile:
    return PostgreSQLExecutableSchemaProfile(schema_name)


def verify_postgresql_executable_schema_profile(
    profile: PostgreSQLExecutableSchemaProfile,
) -> PostgreSQLExecutableSchemaProfile:
    if type(profile) is not PostgreSQLExecutableSchemaProfile:
        raise PostgreSQLSchemaProfileError("profile must be the exact native profile type")
    names = (
        "schema_name",
        "ddl_sql",
        "ddl_byte_count",
        "ddl_sha256",
        "profile_id",
        "profile_sha256",
    )
    try:
        captured = tuple(getattr(profile, name) for name in names)
    except AttributeError as exc:
        raise PostgreSQLSchemaProfileError("profile is missing a required field") from exc
    _schema_name(captured[0])
    _string(captured[1], MAX_SQL_BYTES, "SQL")
    if type(captured[2]) is not int or not 0 < captured[2] <= MAX_SQL_BYTES:
        raise PostgreSQLSchemaProfileError("SQL byte count must be an exact bounded integer")
    for digest in (captured[3], captured[5]):
        _string(digest, 71, "digest")
        if SHA256_RE.fullmatch(digest) is None:
            raise PostgreSQLSchemaProfileError("profile digest has an invalid form")
    _string(captured[4], 36, "profile_id")
    if PROFILE_ID_RE.fullmatch(captured[4]) is None:
        raise PostgreSQLSchemaProfileError("profile_id has an invalid form")
    expected = PostgreSQLExecutableSchemaProfile(captured[0])
    if captured != tuple(getattr(expected, name) for name in names):
        raise PostgreSQLSchemaProfileError("profile fields do not match fixed SQL replay")
    return expected


__all__ = [
    "PostgreSQLExecutableSchemaProfile",
    "PostgreSQLSchemaProfileError",
    "build_postgresql_executable_schema_profile",
    "verify_postgresql_executable_schema_profile",
]

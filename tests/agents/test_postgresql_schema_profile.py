"""Pure verification of the additive offline PostgreSQL schema profile."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import re
import socket
import sqlite3
import unittest
from dataclasses import FrozenInstanceError
from enum import IntEnum
from types import MappingProxyType
from unittest import mock

from sunderkey import postgresql_runtime_adapter as runtime
from sunderkey import postgresql_schema_profile as profile_module
from sunderkey.persistence_port_contracts import AggregateVersionBinding
from sunderkey.postgresql_schema_profile import (
    PostgreSQLExecutableSchemaProfile,
    PostgreSQLSchemaProfileError,
    build_postgresql_executable_schema_profile,
    verify_postgresql_executable_schema_profile,
)
from tests.agents import test_postgresql_runtime_adapter_phase170 as phase170

SCHEMA_NAME = "offline_fixture"
COLUMNS = {
    "schema_migrations": ("version", "migration_id", "migration_sha256"),
    "aggregate_heads": ("tenant_ref", "aggregate_ref", "version", "content_sha256"),
    "resource_fences": ("tenant_ref", "resource_ref", "fence_token", "fence_epoch"),
    "transaction_batches": (
        "tenant_ref",
        "assessment_ref",
        "scope_ref",
        "idempotency_key",
        "batch_id",
        "batch_sha256",
        "batch_json",
    ),
    "outbox_events": (
        "tenant_ref",
        "event_ref",
        "batch_id",
        "event_json",
        "created_at",
        "published_at",
    ),
    "runtime_receipts": (
        "tenant_ref",
        "receipt_id",
        "receipt_sha256",
        "receipt_json",
        "created_at",
    ),
    "schedules": (
        "tenant_id",
        "schedule_id",
        "schedule_sha256",
        "definition_version",
        "schedule_json",
        "cancelled",
    ),
    "occurrences": (
        "tenant_id",
        "occurrence_id",
        "schedule_id",
        "occurrence_index",
        "occurrence_json",
        "occurrence_version",
        "state",
        "ready_at",
        "attempt_number",
        "fence_epoch",
        "lease_id",
    ),
    "lease_snapshots": (
        "tenant_id",
        "lease_id",
        "lease_version",
        "occurrence_id",
        "fence_epoch",
        "expires_at",
        "active",
        "lease_json",
    ),
    "scheduler_results": (
        "tenant_id",
        "idempotency_key",
        "result_kind",
        "result_sha256",
        "result_json",
    ),
}


def _canonical(value):
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )


def _sha(text):
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _readdress(document):
    changed = copy.deepcopy(document)
    changed["ddl_byte_count"] = len(changed["ddl_sql"].encode("utf-8"))
    changed["ddl_sha256"] = _sha(changed["ddl_sql"])
    body = {
        key: value for key, value in changed.items() if key not in {"profile_id", "profile_sha256"}
    }
    digest = _sha(_canonical({"domain": profile_module.PROFILE_KIND, "body": body}))
    changed.update(profile_sha256=digest, profile_id="PGS-" + digest[7:39].upper())
    return changed


def _blocks(sql):
    matches = re.findall(r'CREATE TABLE "([a-z0-9_]+)"\."([a-z_]+)" \(\n(.*?)\n\);', sql, re.S)
    return {table: body for _, table, body in matches}


def _patterns(block):
    # The fixed generated ARE subset also has compatible Python anchor semantics.
    return {
        column: re.compile(encoded.replace("\\\\", "\\"))
        for column, encoded in re.findall(r'"([a-z0-9_]+)" ~ E\'([^\']+)\'', block)
    }


def _sql_calls():
    tree = ast.parse(inspect.getsource(runtime))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "execute"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and type(node.args[0].value) is str
    ]


class TextAlias(str):
    pass


class IntegerAlias(IntEnum):
    ONE = 1


class ListAlias(list):
    pass


class DictAlias(dict):
    pass


class PostgreSQLSchemaProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile = build_postgresql_executable_schema_profile(schema_name=SCHEMA_NAME)
        self.document = self.profile.to_dict()
        self.blocks = _blocks(self.profile.ddl_sql)

    def assertRejected(self, document):
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_dict(document)
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_json(_canonical(document))

    def test_repeat_build_and_all_canonical_round_trips_preserve_identity(self):
        repeat = build_postgresql_executable_schema_profile(schema_name=SCHEMA_NAME)
        self.assertEqual(repeat.to_dict(), self.document)
        self.assertEqual(repeat.to_sql(), self.profile.ddl_sql)
        for restored in (
            PostgreSQLExecutableSchemaProfile.from_dict(self.document),
            PostgreSQLExecutableSchemaProfile.from_json(self.profile.to_json()),
            verify_postgresql_executable_schema_profile(self.profile),
        ):
            self.assertIsNot(restored, self.profile)
            self.assertEqual(restored.to_dict(), self.document)
            self.assertEqual(restored.to_json(), self.profile.to_json())

    def test_sql_sha_is_of_exact_lf_utf8_bytes_and_separate_profile_domain(self):
        self.assertTrue(self.profile.ddl_sql.isascii())
        self.assertTrue(self.profile.ddl_sql.endswith("\n"))
        self.assertNotIn("\r", self.profile.ddl_sql)
        self.assertEqual(self.profile.ddl_byte_count, len(self.profile.ddl_sql.encode("utf-8")))
        self.assertEqual(self.profile.ddl_sha256, _sha(self.profile.ddl_sql))
        self.assertEqual(_readdress(self.document), self.document)
        self.assertNotEqual(self.profile.ddl_sha256, self.profile.profile_sha256)
        self.assertNotEqual(self.profile.ddl_sha256, runtime.POSTGRESQL_MIGRATION_SHA256)

    def test_v1_offline_fixture_literal_golden_addresses(self):
        self.assertEqual(self.profile.ddl_byte_count, 11487)
        self.assertEqual(
            self.profile.ddl_sha256,
            "sha256:5033fdaff1631d517e6034cabb3ed1dab57176dd8e3614b62f210401fe86855b",
        )
        self.assertEqual(self.profile.profile_id, "PGS-BAB6F2E9B44B53B10390FC92E14D36DF")
        self.assertEqual(
            self.profile.profile_sha256,
            "sha256:bab6f2e9b44b53b10390fc92e14d36df686c5738acdab4f7e56d0ed47ddbe476",
        )

    def test_legacy_marker_remains_description_identity_not_sql_proof(self):
        expected = {
            "version": 1,
            "migration_id": "migrationref:persistence-scheduler-runtime.postgresql.0001-expand",
            "migration_sha256": (
                "sha256:d0d00f91a480a15768d29a0afca756e0b07f47e9a1897b578ee0a80b69468d47"
            ),
        }
        self.assertEqual(self.document["legacy_compatibility_marker"], expected)
        description = (
            "tenant-scoped aggregates, fences, scheduler records, and transactional outbox"
        )
        self.assertEqual(expected["migration_sha256"], _sha(description))
        self.assertNotIn(expected["migration_sha256"], self.profile.ddl_sql)
        self.assertNotIn("INSERT", self.profile.ddl_sql)

    def test_schema_selection_is_explicit_bounded_and_quoted(self):
        for schema in ("a", "s" * 63, "public", "select", "fixture_2"):
            with self.subTest(schema=schema):
                profile = build_postgresql_executable_schema_profile(schema_name=schema)
                self.assertEqual(len(_blocks(profile.ddl_sql)), 10)
                self.assertLess(profile.ddl_byte_count, profile_module.MAX_SQL_BYTES)
                self.assertIn(f'CREATE TABLE "{schema}"."schema_migrations"', profile.ddl_sql)
                self.assertEqual(
                    PostgreSQLExecutableSchemaProfile.from_json(profile.to_json()), profile
                )
        with self.assertRaises(TypeError):
            build_postgresql_executable_schema_profile()

    def test_schema_native_type_and_injection_forms_are_rejected(self):
        invalid = (
            None,
            True,
            1,
            1.0,
            b"fixture",
            TextAlias("fixture"),
            "",
            "s" * 64,
            "Fixture",
            "fixture.name",
            "fixture name",
            "fixture\n",
            "fixture\x00",
            'fixture"',
            "fixture;drop",
            "fixture--",
            "fixture/*",
            "pg_catalog",
            "pg_fixture",
            "information_schema",
            "f\u00e9xture",
            "_fixture",
        )
        for value in invalid:
            with self.subTest(value=repr(value)):
                with self.assertRaises(PostgreSQLSchemaProfileError):
                    build_postgresql_executable_schema_profile(schema_name=value)

    def test_changed_selected_schema_changes_both_content_addresses(self):
        other = build_postgresql_executable_schema_profile(schema_name="other_fixture")
        self.assertNotEqual(other.ddl_sha256, self.profile.ddl_sha256)
        self.assertNotEqual(other.profile_sha256, self.profile.profile_sha256)
        self.assertNotEqual(other.profile_id, self.profile.profile_id)
        self.assertEqual(
            other.to_dict()["legacy_compatibility_marker"],
            self.document["legacy_compatibility_marker"],
        )
        changed = copy.deepcopy(self.document)
        changed["schema_name"] = other.schema_name
        self.assertRejected(changed)

    def test_exact_ten_table_and_column_inventory_has_no_extra_lifecycle_tables(self):
        self.assertEqual(tuple(self.blocks), tuple(COLUMNS))
        self.assertEqual(self.document["table_names"], list(COLUMNS))
        for table, columns in COLUMNS.items():
            actual = re.findall(
                r'^    "([a-z0-9_]+)" (?:TEXT|INTEGER|BIGINT|BOOLEAN)\b', self.blocks[table], re.M
            )
            self.assertEqual(tuple(actual), columns, table)
        self.assertEqual(self.profile.ddl_sql.count("CREATE TABLE "), 10)
        self.assertNotIn('"completions"', self.profile.ddl_sql)
        self.assertNotIn('"recoveries"', self.profile.ddl_sql)
        self.assertNotIn('"cancellations"', self.profile.ddl_sql)

    def test_actual_adapter_insert_select_and_predicate_columns_are_covered(self):
        calls = _sql_calls()
        self.assertEqual(len(calls), 23)
        tables = set()
        inserts = []
        for call in calls:
            sql = call.args[0].value
            referenced = set(re.findall(r"\b(?:FROM|INTO|UPDATE)\s+([a-z_]+)", sql, re.I))
            referenced -= {"SET", "SKIP"}
            tables.update(referenced)
            allowed = {column for table in referenced for column in COLUMNS[table]}
            for table, projection in re.findall(r"INSERT INTO ([a-z_]+)\s*\(([^)]+)\)", sql):
                actual = tuple(item.strip() for item in projection.split(","))
                self.assertEqual(actual, COLUMNS[table])
                inserts.append(table)
            for projection, table in re.findall(r"SELECT (.*?) FROM ([a-z_]+)", sql, re.S):
                self.assertTrue(
                    {item.strip() for item in projection.split(",")}.issubset(COLUMNS[table])
                )
            compared = set(re.findall(r"\b([a-z_]+)\s*(?:[<>=]|IN\s*\()", sql, re.I))
            self.assertTrue(compared.issubset(allowed), (sql, compared - allowed))
        self.assertEqual(tables, set(COLUMNS))
        self.assertEqual(len(inserts), 9)
        self.assertEqual(inserts.count("outbox_events"), 2)

    def test_actual_on_conflict_keys_have_immediate_unique_constraints(self):
        found = []
        for call in _sql_calls():
            sql = call.args[0].value
            match = re.search(r"ON CONFLICT\s*\(([^)]+)\)", sql)
            if match is not None:
                table = re.search(r"INSERT INTO ([a-z_]+)", sql).group(1)
                columns = tuple(match.group(1).split(","))
                quoted = ", ".join(f'"{name}"' for name in columns)
                self.assertRegex(
                    self.blocks[table],
                    rf"(?:PRIMARY KEY|UNIQUE) \({re.escape(quoted)}\) NOT DEFERRABLE",
                )
                found.append((table, columns))
        self.assertEqual(
            set(found),
            {
                ("aggregate_heads", ("tenant_ref", "aggregate_ref")),
                ("occurrences", ("tenant_id", "schedule_id", "occurrence_index")),
            },
        )

    def test_two_tenant_parent_fks_and_no_polymorphic_outbox_fk(self):
        sql = self.profile.ddl_sql
        self.assertEqual(sql.count("FOREIGN KEY"), 2)
        self.assertIn(
            f'REFERENCES "{SCHEMA_NAME}"."schedules"("tenant_id", "schedule_id")',
            self.blocks["occurrences"],
        )
        self.assertIn(
            f'REFERENCES "{SCHEMA_NAME}"."occurrences"("tenant_id", "occurrence_id")',
            self.blocks["lease_snapshots"],
        )
        self.assertNotIn("FOREIGN KEY", self.blocks["outbox_events"])
        self.assertNotIn("REFERENCES", self.blocks["transaction_batches"])
        self.assertNotIn("CASCADE", sql)

    def test_index_names_are_local_and_indexed_tables_are_qualified(self):
        sql = self.profile.ddl_sql
        self.assertIn(f'CREATE INDEX "occurrence_due_idx" ON "{SCHEMA_NAME}"."occurrences"', sql)
        self.assertIn(
            '("tenant_id", "schedule_id", "ready_at", "occurrence_index") '
            "WHERE \"state\" IN ('pending', 'retry')",
            sql,
        )
        self.assertIn(
            'CREATE UNIQUE INDEX "one_active_occurrence_lease" ON '
            f'"{SCHEMA_NAME}"."lease_snapshots"',
            sql,
        )
        self.assertIn('("tenant_id", "occurrence_id") WHERE "active";', sql)
        self.assertEqual(len(re.findall(r"CREATE (?:UNIQUE )?INDEX ", sql)), 2)
        self.assertNotRegex(sql, r'INDEX "[a-z0-9_]+"\."')

    def test_json_and_boolean_dbapi_storage_types_are_not_normalized(self):
        for table, body in self.blocks.items():
            for column in COLUMNS[table]:
                if column.endswith("_json"):
                    self.assertIn(f'"{column}" TEXT COLLATE pg_catalog."C" NOT NULL', body)
                    self.assertIn(
                        f"pg_catalog.json_typeof(\"{column}\"::pg_catalog.json) = 'object'", body
                    )
        self.assertEqual(self.profile.ddl_sql.count("json_typeof("), 7)
        self.assertIn('"active" BOOLEAN NOT NULL', self.blocks["lease_snapshots"])
        self.assertIn('"cancelled" BOOLEAN NOT NULL', self.blocks["schedules"])
        self.assertNotIn("JSONB", self.profile.ddl_sql)
        self.assertNotIn("TIMESTAMP", self.profile.ddl_sql)

    def test_all_text_identities_use_exact_c_collation(self):
        declarations = re.findall(r'^    "[a-z0-9_]+" TEXT[^\n]*', self.profile.ddl_sql, re.M)
        self.assertEqual(len(declarations), 47)
        self.assertTrue(all('COLLATE pg_catalog."C"' in column for column in declarations))

    def test_signed64_representation_is_explicit_not_pure_contract_restriction(self):
        self.assertEqual(
            self.document["aggregate_version_storage"],
            {
                "minimum": 1,
                "maximum": 9_223_372_036_854_775_807,
                "type": "bigint",
            },
        )
        self.assertIn(
            '"version" BIGINT NOT NULL CHECK ("version" BETWEEN 1 AND 9223372036854775807)',
            self.blocks["aggregate_heads"],
        )
        existing = AggregateVersionBinding("aggregateref:larger-counter", 2**63)
        self.assertEqual(existing.expected_version, 2**63)
        for fragment in (
            '"attempt_number" BETWEEN 0 AND 32',
            '"occurrence_index" BETWEEN 0 AND 2147483647',
            '"fence_epoch" BETWEEN 1 AND 1000000',
            '"definition_version" BETWEEN 1 AND 2147483647',
        ):
            self.assertIn(fragment, self.profile.ddl_sql)

    def test_claim_only_scope_does_not_invent_lifecycle_or_publisher_apis(self):
        self.assertEqual(
            self.document["runtime_scope"],
            [
                "aggregate_transactions",
                "schedule_registration",
                "due_materialization",
                "due_claims",
            ],
        )
        self.assertEqual(
            _patterns(self.blocks["scheduler_results"])["result_kind"].fullmatch("claim").group(),
            "claim",
        )
        for other in ("heartbeat", "completion", "recovery", "cancellation", "claim-extra"):
            self.assertIsNone(
                _patterns(self.blocks["scheduler_results"])["result_kind"].fullmatch(other)
            )
        self.assertIn(
            'CHECK (("state" = \'leased\') = ("lease_id" IS NOT NULL))', self.blocks["occurrences"]
        )

    def test_genuine_transaction_and_scheduler_outbox_native_families_match(self):
        transaction = phase170._batch()
        schedule = phase170._schedule()
        pattern = _patterns(self.blocks["outbox_events"])
        for tenant in (transaction.tenant_ref, schedule.tenant_id):
            self.assertIsNotNone(pattern["tenant_ref"].fullmatch(tenant))
        self.assertIsNotNone(pattern["batch_id"].fullmatch(transaction.batch_id))
        self.assertIsNotNone(pattern["batch_id"].fullmatch("DSL-" + "A" * 32))
        for bad in ("PTB-" + "a" * 32, "PGR-" + "A" * 32, "DSL-" + "A" * 32 + "\n"):
            self.assertIsNone(pattern["batch_id"].fullmatch(bad))
        outbox_calls = [
            node for node in _sql_calls() if "INSERT INTO outbox_events" in node.args[0].value
        ]
        self.assertEqual(
            {node.args[1].elts[2].attr for node in outbox_calls}, {"batch_id", "lease_id"}
        )

    def test_regex_alternatives_are_grouped_and_whole_string_anchored(self):
        pattern = _patterns(self.blocks["occurrences"])["state"]
        self.assertTrue(pattern.pattern.startswith(r"\A(?:"))
        self.assertTrue(pattern.pattern.endswith(r")\Z"))
        for state in ("pending", "retry", "leased", "completed", "dead_lettered", "cancelled"):
            self.assertIsNotNone(pattern.fullmatch(state))
        for state in ("pending-extra", "xretry", "leased\n", "uncancelled", "unknown"):
            self.assertIsNone(pattern.fullmatch(state))

    def test_utc_calendar_clauses_are_session_independent_and_guard_casts(self):
        locations = (
            ("outbox_events", "created_at"),
            ("outbox_events", "published_at"),
            ("runtime_receipts", "created_at"),
            ("occurrences", "ready_at"),
            ("lease_snapshots", "expires_at"),
        )
        for table, column in locations:
            line = next(
                line
                for line in self.blocks[table].splitlines()
                if line.startswith(f'    "{column}" ')
            )
            self.assertIn("CHECK (", line)
            self.assertIn("CASE WHEN", line)
            self.assertIn("ELSE FALSE END", line)
            self.assertIn("BETWEEN 1 AND 9999", line)
            for divisor in (4, 100, 400):
                self.assertIn(f'pg_catalog.substr("{column}", 1, 4)::INTEGER % {divisor}', line)
            self.assertIn("THEN 29 ELSE 28 END", line)
            for month in (4, 6, 9, 11):
                self.assertIn(f"WHEN {month} THEN 30", line)
            self.assertIn("ELSE 31 END", line)
        published = next(
            line
            for line in self.blocks["outbox_events"].splitlines()
            if line.startswith('    "published_at" ')
        )
        self.assertIn('"published_at" IS NULL OR', published)
        self.assertNotIn("NOT NULL", published)
        for forbidden in (
            "CURRENT_TIMESTAMP",
            "CURRENT_DATE",
            "now(",
            "TO_DATE",
            "TIMESTAMP",
            "TIME ZONE",
        ):
            self.assertNotIn(forbidden, self.profile.ddl_sql)

    def test_utc_shape_bounds_reject_offsets_subseconds_and_component_overflow(self):
        pattern = _patterns(self.blocks["outbox_events"])["created_at"]
        for valid in ("0001-01-01T00:00:00Z", "2000-02-29T23:59:59Z", "9999-12-31T23:59:59Z"):
            self.assertIsNotNone(pattern.fullmatch(valid))
        for invalid in (
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:60:00Z",
            "2026-01-01T00:00:60Z",
            "2026-01-01T00:00:00+00:00",
            "2026-01-01T00:00:00.0Z",
            "2026-01-01T00:00:00Z\n",
        ):
            self.assertIsNone(pattern.fullmatch(invalid))

    def test_no_implicit_admin_migration_activation_or_connection_statements(self):
        for forbidden in (
            "IF NOT EXISTS",
            "CREATE SCHEMA",
            "SET search_path",
            "GRANT ",
            "REVOKE ",
            "CREATE ROLE",
            "CREATE EXTENSION",
            "ROW LEVEL",
            "CREATE POLICY",
            "ALTER ",
            "DROP ",
            "CONCURRENTLY",
            "INSERT ",
            "BEGIN;",
            "COMMIT;",
        ):
            self.assertNotIn(forbidden, self.profile.ddl_sql)
        self.assertFalse(hasattr(self.profile, "apply"))
        self.assertFalse(hasattr(self.profile, "connection_factory"))
        self.assertTrue(all("schema_name" not in node.args[0].value for node in _sql_calls()))

    def test_native_integer_aliases_reject_old_content_identity(self):
        locations = (
            ("schema_version",),
            ("postgresql_major_version",),
            ("ddl_byte_count",),
            ("legacy_compatibility_marker", "version"),
            ("aggregate_version_storage", "minimum"),
            ("aggregate_version_storage", "maximum"),
        )
        for path in locations:
            for alias in (True, False, 1.0, 18.0):
                with self.subTest(path=path, alias=alias):
                    changed = copy.deepcopy(self.document)
                    target = changed if len(path) == 1 else changed[path[0]]
                    target[path[-1]] = alias
                    self.assertRejected(changed)
        changed = copy.deepcopy(self.document)
        changed["schema_version"] = IntegerAlias.ONE
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_dict(changed)

    def test_native_string_key_and_container_aliases_are_not_normalized(self):
        for field, alias in (
            ("schema_name", TextAlias(SCHEMA_NAME)),
            ("ddl_sql", TextAlias(self.profile.ddl_sql)),
            ("table_names", tuple(self.document["table_names"])),
            ("table_names", ListAlias(self.document["table_names"])),
            ("effects", DictAlias(self.document["effects"])),
            ("effects", MappingProxyType(self.document["effects"])),
        ):
            changed = copy.deepcopy(self.document)
            changed[field] = alias
            with self.subTest(field=field, type=type(alias).__name__):
                with self.assertRaises(PostgreSQLSchemaProfileError):
                    PostgreSQLExecutableSchemaProfile.from_dict(changed)
        for alias in (DictAlias(self.document), MappingProxyType(self.document)):
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_dict(alias)
        changed = copy.deepcopy(self.document)
        changed[TextAlias("kind")] = changed.pop("kind")
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_dict(changed)

    def test_missing_and_extra_fields_reject_at_each_closed_level(self):
        for path in (
            (),
            ("effects",),
            ("aggregate_version_storage",),
            ("legacy_compatibility_marker",),
        ):
            changed = copy.deepcopy(self.document)
            target = changed if not path else changed[path[0]]
            for field in tuple(target):
                omitted = copy.deepcopy(changed)
                destination = omitted if not path else omitted[path[0]]
                destination.pop(field)
                self.assertRejected(omitted)
            target["unexpected"] = "none"
            self.assertRejected(changed)

    def test_correlated_sql_and_profile_rehash_cannot_substitute_fixed_templates(self):
        substitutions = (
            self.profile.ddl_sql + "\n",
            self.profile.ddl_sql.replace("BIGINT", "NUMERIC"),
            self.profile.ddl_sql.replace("% 400", "% 399"),
            self.profile.ddl_sql.replace('"offline_fixture".', '"other_fixture".'),
            self.profile.ddl_sql.replace("NOT DEFERRABLE", "DEFERRABLE"),
            self.profile.ddl_sql.replace("\n", "\r\n"),
        )
        for sql in substitutions:
            changed = copy.deepcopy(self.document)
            changed["ddl_sql"] = sql
            addressed = _readdress(changed)
            self.assertEqual(addressed["ddl_sha256"], _sha(sql))
            self.assertNotEqual(addressed["profile_sha256"], self.profile.profile_sha256)
            self.assertRejected(addressed)

    def test_rehashed_marker_effect_scope_and_storage_substitution_is_not_promoted(self):
        for field, value in (
            ("table_names", list(reversed(self.document["table_names"]))),
            (
                "runtime_scope",
                [
                    "aggregate_transactions",
                    "schedule_registration",
                    "due_materialization",
                    "completion",
                ],
            ),
            ("json_storage", "jsonb"),
            ("timestamp_storage", "timestamp"),
            ("sql_encoding", "ascii"),
            ("sql_line_endings", "crlf"),
        ):
            changed = copy.deepcopy(self.document)
            changed[field] = value
            self.assertRejected(_readdress(changed))
        changed = copy.deepcopy(self.document)
        changed["legacy_compatibility_marker"]["migration_sha256"] = "sha256:" + "0" * 64
        self.assertRejected(_readdress(changed))
        changed = copy.deepcopy(self.document)
        changed["effects"]["sql_execution"] = "observed"
        self.assertRejected(_readdress(changed))

    def test_canonical_json_only_and_duplicate_keys_at_all_levels(self):
        for value in (
            "",
            "{}",
            "[]",
            self.profile.to_json() + "\n",
            json.dumps(self.document, indent=2),
        ):
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_json(value)
        for original, duplicate in (
            ('"schema_version":1', '"schema_version":1,"schema_version":1'),
            ('"sql_execution":"none"', '"sql_execution":"none","sql_execution":"none"'),
            (
                '"maximum":9223372036854775807',
                '"maximum":9223372036854775807,"maximum":9223372036854775807',
            ),
            ('"version":1', '"version":1,"version":1'),
        ):
            self.assertIn(original, self.profile.to_json())
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_json(
                    self.profile.to_json().replace(original, duplicate, 1)
                )

    def test_json_float_nonfinite_huge_integer_and_depth_fail_bounded(self):
        for token in ("1.0", "1e0", "NaN", "Infinity", "-Infinity", "9" * 20):
            malformed = self.profile.to_json().replace(
                '"schema_version":1', '"schema_version":' + token, 1
            )
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_json(malformed)
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_json("[" * 2000 + "0" + "]" * 2000)
        with self.assertRaises(PostgreSQLSchemaProfileError):
            PostgreSQLExecutableSchemaProfile.from_json(
                " " * (profile_module.MAX_PROFILE_BYTES + 1)
            )

    def test_malformed_unicode_and_oversized_native_sql_reject_before_raw_encoding(self):
        for value in (
            "\ud800",
            self.profile.to_json().replace(
                '"schema_name":"offline_fixture"', '"schema_name":"\\ud800"'
            ),
        ):
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_json(value)
        for value in (
            "X" * (profile_module.MAX_SQL_BYTES + 1),
            "\ud800",
            None,
            {"deep": [1] * 1000},
        ):
            changed = copy.deepcopy(self.document)
            changed["ddl_sql"] = value
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_dict(changed)
        for value in (None, b"{}", TextAlias(self.profile.to_json())):
            with self.assertRaises(PostgreSQLSchemaProfileError):
                PostgreSQLExecutableSchemaProfile.from_json(value)

    def test_frozen_record_and_late_field_mutation_fail_all_public_exports(self):
        with self.assertRaises(FrozenInstanceError):
            self.profile.schema_name = "other"
        changes = (
            ("schema_name", "other_fixture"),
            ("ddl_sql", self.profile.ddl_sql + " "),
            ("ddl_byte_count", self.profile.ddl_byte_count + 1),
            ("ddl_byte_count", float(self.profile.ddl_byte_count)),
            ("ddl_sha256", "sha256:" + "0" * 64),
            ("profile_id", "PGS-" + "0" * 32),
            ("profile_sha256", "sha256:" + "0" * 64),
        )
        for field, value in changes:
            changed = build_postgresql_executable_schema_profile(schema_name=SCHEMA_NAME)
            object.__setattr__(changed, field, value)
            for callback in (
                lambda: verify_postgresql_executable_schema_profile(changed),
                changed.to_dict,
                changed.to_json,
                changed.to_sql,
            ):
                with self.subTest(field=field, callback=callback):
                    with self.assertRaises(PostgreSQLSchemaProfileError):
                        callback()

    def test_missing_record_slots_and_wrong_record_types_have_domain_errors(self):
        for field in (
            "schema_name",
            "ddl_sql",
            "ddl_byte_count",
            "ddl_sha256",
            "profile_id",
            "profile_sha256",
        ):
            changed = build_postgresql_executable_schema_profile(schema_name=SCHEMA_NAME)
            object.__delattr__(changed, field)
            with self.assertRaises(PostgreSQLSchemaProfileError):
                verify_postgresql_executable_schema_profile(changed)
        for value in (None, self.document, self.profile.to_json()):
            with self.assertRaises(PostgreSQLSchemaProfileError):
                verify_postgresql_executable_schema_profile(value)

    def test_exported_metadata_and_effects_are_detached_from_every_repeat(self):
        exported = self.profile.to_dict()
        exported["effects"]["network"] = "changed"
        exported["table_names"].clear()
        exported["legacy_compatibility_marker"]["version"] = 2
        exported["aggregate_version_storage"]["maximum"] = 0
        self.assertEqual(self.profile.to_dict(), self.document)
        with self.assertRaises(TypeError):
            profile_module.NO_EFFECTS["network"] = "changed"
        self.assertEqual(set(self.document["effects"].values()), {"none"})

    def test_build_parse_and_verify_have_no_file_database_or_socket_effects(self):
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("socket called")),
            mock.patch.object(sqlite3, "connect", side_effect=AssertionError("database called")),
            mock.patch("builtins.open", side_effect=AssertionError("file called")),
        ):
            created = build_postgresql_executable_schema_profile(schema_name=SCHEMA_NAME)
            restored = PostgreSQLExecutableSchemaProfile.from_json(created.to_json())
            self.assertEqual(
                verify_postgresql_executable_schema_profile(restored).to_sql(), created.ddl_sql
            )


if __name__ == "__main__":
    unittest.main()

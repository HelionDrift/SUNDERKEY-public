"""Additive schema 39 custody and bounded historical reconstruction coverage."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.authenticated_provider_evidence_repository import (
    AuthenticatedProviderEvidenceRepositoryService,
)
from sunderkey.collaboration_executor import CollaborationExecutorAcknowledgement
from sunderkey.collaboration_executor_authentication import (
    collaboration_executor_acknowledgement_selection_sha256,
)
from sunderkey.errors import StoreError, StoreIntegrityError, StoreMigrationRequiredError
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    ScopeGrant,
    compute_operation_intent_hash,
    verify_principal_assertion,
)
from sunderkey.provider_evidence_repository_authentication import (
    AUTHENTICATION_DOMAIN,
    provider_evidence_repository_ingest_authentication_effect_payload,
    provider_evidence_repository_ingest_receipt_selection_sha256,
    validate_authenticated_provider_evidence_repository_ingest_receipt_document,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST,
    EXPECTED_SCHEMA_MANIFEST_V38,
    EXPECTED_SCHEMA_MANIFEST_V39,
    PROVIDER_EVIDENCE_REPOSITORY_AUTHENTICATION_SCHEMA_VERSION,
    SCHEMA_V38_STATEMENTS,
    SCHEMA_V39_STATEMENTS,
    SCHEMA_VERSION,
    MissionStore,
    _schema_manifest,
    canonical_json,
    format_timestamp,
    parse_timestamp,
)
from sunderkey.trust import TrustProvisioningService

from . import test_provider_evidence_repository_authentication_phase149 as phase149
from .test_authenticated_provider_evidence_repository import (
    repository_assertion,
    repository_grant,
    repository_service_fixture,
)
from .test_identity_phase4 import ZERO_SIGNATURE, b64url
from .test_store import remove_schema_v39_objects

ROOT = Path(__file__).resolve().parents[2]
TABLE = "provider_evidence_repository_ingest_authentications"


class ProviderEvidenceRepositorySchema39Tests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "custody.sqlite3"
        self.store = MissionStore(self.path)
        self.store.initialize()
        self.registry = load_registry(ROOT / "registry" / "army-v2.json")

    def test_schema_is_additive_and_preserves_every_v38_object(self) -> None:
        self.assertEqual(SCHEMA_VERSION, 39)
        self.assertEqual(PROVIDER_EVIDENCE_REPOSITORY_AUTHENTICATION_SCHEMA_VERSION, 39)
        self.assertEqual(SCHEMA_V39_STATEMENTS[: len(SCHEMA_V38_STATEMENTS)], SCHEMA_V38_STATEMENTS)
        old = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V38}
        current = {item[1]: item for item in EXPECTED_SCHEMA_MANIFEST_V39}
        self.assertTrue(all(current[name] == item for name, item in old.items()))
        self.assertEqual(len(current.keys() - old.keys()), 5)
        with self.store._read_connection() as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            definition = connection.execute(
                "SELECT strict, ncol FROM pragma_table_list WHERE name = ?",
                (TABLE,),
            ).fetchone()
            self.assertEqual(tuple(definition), (1, 38))

    def test_raw_empty_or_null_json_cannot_skip_signed_custody(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            for document in (None, "{}", '{"schema_version":1}', '{"schema_version":null}'):
                with self.subTest(document=document), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        f"INSERT INTO {TABLE}(authentication_id, authentication_json) "
                        "VALUES (?, ?)",
                        ("ERI-" + "A" * 32, document),
                    )
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0], 0)

    def test_empty_v38_migration_keeps_exact_backup_without_inventing_acks(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            remove_schema_v39_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '38' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 38")
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V38)
        with self.assertRaises(StoreMigrationRequiredError):
            self.store.initialize()
        backup = self.path.with_name("before-v39.sqlite3")
        migrated = self.store.migrate(self.registry, backup)
        self.assertEqual((migrated.source_version, migrated.target_version), (38, 39))
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V38)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 38)
        with self.store._read_connection() as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0], 0)
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def test_durable_intake_rejects_non_native_or_oversized_text_before_json_decode(self) -> None:
        class TextAlias(str):
            pass

        # Deliberately incomplete row shapes are parser probes, not fabricated custody.
        for text in (TextAlias("{}"), b"{}", " " * 1_048_577):
            with (
                self.subTest(kind=type(text).__name__),
                patch(
                    "sunderkey.provider_evidence_repository_authentication.json.loads",
                    side_effect=AssertionError("Unbounded intake reached JSON decoding"),
                ),
                self.assertRaises(StoreIntegrityError),
            ):
                self.store._repository_ingest_authentication_document({"authentication_json": text})

    def test_durable_intake_rejects_duplicate_keys_float_and_nonfinite(self) -> None:
        for text in (
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":1.0}',
            '{"schema_version":NaN}',
            '{"schema_version":9223372036854775808}',
        ):
            with self.subTest(text=text), self.assertRaises(StoreIntegrityError):
                self.store._repository_ingest_authentication_document({"authentication_json": text})

    def test_public_custody_row_lookup_has_closed_native_identity(self) -> None:
        class TextAlias(str):
            pass

        with self.store._read_connection() as connection:
            for identifier in (
                None,
                TextAlias("ERI-" + "A" * 32),
                "ERI-" + "a" * 32,
                "EIR-" + "A" * 32,
            ):
                with self.subTest(identifier=identifier), self.assertRaises(StoreError):
                    self.store._provider_evidence_repository_ingest_authentication_row(
                        connection,
                        identifier,
                    )
            with self.assertRaisesRegex(StoreError, "not committed"):
                self.store._provider_evidence_repository_ingest_authentication_row(
                    connection,
                    "ERI-" + "A" * 32,
                )

    def test_migration_guard_classifies_both_use_and_effect_provenance(self) -> None:
        # The pure schema contract must retain the exact enum value, never an inferred alias.
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value
        self.assertEqual(operation, "sunderkey.evidence.repository.acknowledge.v1")
        statement = next(
            item
            for item in SCHEMA_V39_STATEMENTS
            if item.startswith(
                "CREATE TRIGGER provider_evidence_repository_ingest_authentication_guard"
            )
        )
        self.assertIn(f"repository_use.operation = '{operation}'", statement)
        self.assertIn("repository_effect.effect_kind = repository_use.operation", statement)
        self.assertIn(
            "json_type(NEW.authentication_json, '$.raw_evidence_in_contract') IS NOT 'false'",
            statement,
        )


class ProviderEvidenceRepositorySchema39SignedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        holder = unittest.TestCase(methodName="runTest")
        cls.addClassCleanup(holder.doCleanups)
        cls.fixture = repository_service_fixture(holder)
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.ready_path = Path(temporary.name) / "before-ack.sqlite3"
        cls.committed_path = Path(temporary.name) / "signed-ack.sqlite3"
        with closing(sqlite3.connect(cls.fixture.root.path)) as source:
            with closing(sqlite3.connect(cls.ready_path)) as destination:
                source.backup(destination)
        first = cls.fixture.service.authenticate(
            cls.fixture.request,
            cls.fixture.receipt,
            cls.fixture.lifecycle,
            repository_assertion=cls.fixture.assertion,
        )
        cls.first = first.to_dict()["repository_ingest_authentication"]
        second_receipt = cls.fixture._receipt(
            cls.fixture.request,
            object_version_id="version.synthetic-second",
            outcome="failed",
        )
        second_assertion = repository_assertion(cls.fixture, receipt=second_receipt)
        second = cls.fixture.service.authenticate(
            cls.fixture.request,
            second_receipt,
            cls.fixture.lifecycle,
            repository_assertion=second_assertion,
        )
        cls.second = second.to_dict()["repository_ingest_authentication"]
        with closing(sqlite3.connect(cls.fixture.root.path)) as source:
            with closing(sqlite3.connect(cls.committed_path)) as destination:
                source.backup(destination)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "custody.sqlite3"
        with closing(sqlite3.connect(self.committed_path)) as source:
            with closing(sqlite3.connect(self.path)) as destination:
                source.backup(destination)
        self.now = self.fixture.now
        self.store = MissionStore(self.path, clock=lambda: self.now)
        self.registry = self.fixture.root.registry
        self.service = AuthenticatedProviderEvidenceRepositoryService(
            self.store,
            self.registry,
            repository_principal_subject=phase149.SUBJECT,
            repository_principal_profile_id=phase149.PROFILE_ID,
            clock=lambda: self.now,
        )

    def _mission(self, connection):
        row = connection.execute(
            "SELECT * FROM missions WHERE mission_id = ?",
            (self.fixture.root.mission.mission_id,),
        ).fetchone()
        return self.store._stored_mission_from_row(connection, self.registry, row)

    def _restore_ready(self) -> None:
        with closing(sqlite3.connect(self.ready_path)) as source:
            with closing(sqlite3.connect(self.path)) as destination:
                source.backup(destination)

    def _signed_raw_authentication(
        self, *, early_assertion: bool = False, long_scope: bool = False
    ):
        """Build an isolated rejection probe from real signed original credentials."""
        self._restore_ready()
        grant = self.fixture.scope.grant
        if long_scope:
            grant = repository_grant(
                self.fixture,
                token="E9",
                expires_at="2026-07-30T10:14:40Z",
            )
            ScopeGrantAcceptanceService(self.store, self.registry).accept(grant)
        assertion = repository_assertion(self.fixture, token="EA", grant=grant)
        if early_assertion:
            raw = assertion.to_dict()
            raw["issued_at"] = raw["not_before"] = "2026-07-30T10:08:44Z"
            raw["signature"] = ZERO_SIGNATURE
            unsigned = PrincipalAssertion.from_dict(raw)
            assertion = replace(
                unsigned,
                signature=b64url(
                    self.fixture.root.factory.assertion_private.sign(unsigned.signing_bytes())
                ),
            )
        policy = AuthenticatedCollaborationMissionPolicyService(
            self.store,
            self.registry,
            clock=lambda: self.now,
        )
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
        receipt_selection = provider_evidence_repository_ingest_receipt_selection_sha256(
            self.fixture.receipt
        )
        intent = {
            "ingest_receipt_selection_sha256": receipt_selection,
            "ingest_request_sha256": self.fixture.request.request_sha256,
            "lifecycle_policy_sha256": self.fixture.lifecycle.policy_sha256,
            "mission_id": self.fixture.root.mission.mission_id,
            "principal_profile_id": phase149.PROFILE_ID,
        }
        with self.store._write_connection() as connection:
            identity, trust, mission, scopes, ledger = policy._activation._verified_mission_state(
                connection,
                self.fixture.root.mission.mission_id,
            )
            verified_policy, verified_scope = policy._verified_scope(
                connection,
                assertion=assertion,
                operation=operation,
                mission=mission,
                identity=identity,
                trust_policies=trust,
                scope_grants=scopes,
                now=self.now,
                consumed_time=parse_timestamp(format_timestamp(self.now), "now"),
            )
            principal = verify_principal_assertion(
                assertion,
                verified_policy,
                verified_scope,
                expected_audience=identity["audience"],
                expected_store_id=identity["store_id"],
                expected_mission_id=mission.mission.mission_id,
                expected_operation=operation,
                expected_operation_intent_sha256=assertion.operation_intent_sha256,
                clock=lambda: self.now,
            )
            document = json.loads(canonical_json(self.first))
            document["repository_attestor"] = principal.to_dict()
            body = {
                key: value
                for key, value in document.items()
                if key not in {"authentication_id", "authentication_sha256"}
            }
            digest = _canonical_sha256({"domain": AUTHENTICATION_DOMAIN, "authentication": body})
            document["authentication_sha256"] = digest
            document["authentication_id"] = "ERI-" + digest.removeprefix("sha256:")[:32].upper()
            self.assertEqual(
                validate_authenticated_provider_evidence_repository_ingest_receipt_document(
                    document
                ),
                document,
            )
            effect = policy._effect(
                document["authentication_id"],
                operation,
                provider_evidence_repository_ingest_authentication_effect_payload(document),
                document["authenticated_at"],
            )
            policy._record_assertion(
                connection,
                principal=principal,
                assertion=assertion,
                mission_id=mission.mission.mission_id,
                operation=operation,
                material=policy._assertion_material(assertion, operation, intent),
                effect=effect,
                ledger=ledger,
                consumed_at=document["authenticated_at"],
            )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "inconsistent"):
                self.store._insert_provider_evidence_repository_ingest_authentication(
                    connection, document
                )
            # Deliberately bypass only the new insert guard in an isolated corrupt fixture.
            # Restore its exact definition so verification tests the historical relationship.
            name = "provider_evidence_repository_ingest_authentication_guard"
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?", (name,)
            ).fetchone()[0]
            connection.execute(f'DROP TRIGGER "{name}"')
            self.store._insert_provider_evidence_repository_ingest_authentication(
                connection, document
            )
            connection.execute(definition)
        return document

    def _corrupt(self, trigger: str, sql: str, parameters: tuple = ()) -> None:
        # Isolated fixture corruption restores the exact manifest before verification.
        with closing(sqlite3.connect(self.path)) as connection:
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger,),
            ).fetchone()[0]
            connection.execute(f'DROP TRIGGER "{trigger}"')
            connection.execute(sql, parameters)
            connection.execute(definition)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)

    def _legacy_repository_provenance(self, *, effect_only: bool) -> None:
        """Retain genuine generic signed metadata under an isolated schema 38 fixture."""
        self._restore_ready()
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
        assertion = self.fixture.assertion
        receipt_selection = provider_evidence_repository_ingest_receipt_selection_sha256(
            self.fixture.receipt
        )
        intent = {
            "ingest_receipt_selection_sha256": receipt_selection,
            "ingest_request_sha256": self.fixture.request.request_sha256,
            "lifecycle_policy_sha256": self.fixture.lifecycle.policy_sha256,
            "mission_id": self.fixture.root.mission.mission_id,
            "principal_profile_id": phase149.PROFILE_ID,
        }
        if effect_only:
            operation = PrincipalOperation.EXECUTOR_ACKNOWLEDGE
            trust_policy = self.fixture.root.factory.policy(
                policy_version=900150,
                store_id=self.fixture.root.store_id,
                allowed_profiles=[phase149.PROFILE_ID],
                allowed_subjects=[phase149.SUBJECT],
                allowed_operations=[operation.value],
                max_scope_lifetime_seconds=600,
                max_assertion_lifetime_seconds=300,
            )
            TrustProvisioningService(self.store).apply_policy(trust_policy)
            raw = self.fixture.scope.grant.to_dict()
            raw.update(
                grant_id="SGR-" + "EB" * 16,
                policy_version=900150,
                operations=[operation.value],
                signature=ZERO_SIGNATURE,
            )
            unsigned = ScopeGrant.from_dict(raw)
            grant = replace(
                unsigned,
                signature=b64url(
                    self.fixture.root.factory.scope_private.sign(unsigned.signing_bytes())
                ),
            )
            self.now += timedelta(seconds=1)
            ScopeGrantAcceptanceService(self.store, self.registry).accept(grant)
            self.now += timedelta(seconds=1)
            source_acknowledgement = CollaborationExecutorAcknowledgement.from_dict(
                self.first["source_report_authentication"]["provider_report"][
                    "provider_acknowledgement"
                ]
            )
            acknowledgement_selection = collaboration_executor_acknowledgement_selection_sha256(
                source_acknowledgement
            )
            intent = {
                "acknowledgement_selection_sha256": acknowledgement_selection,
                "dispatch_sha256": self.fixture.source_dispatch.dispatch_sha256,
                "mission_id": self.fixture.root.mission.mission_id,
                "principal_profile_id": phase149.PROFILE_ID,
            }
            assertion = self.fixture.root.factory.assertion(
                grant=grant,
                assertion_id="PAS-" + "EC" * 16,
                policy_version=900150,
                scope_grant_id=grant.grant_id,
                subject=phase149.SUBJECT,
                profile_id=phase149.PROFILE_ID,
                audience=grant.audience,
                store_id=grant.store_id,
                mission_id=grant.mission_id,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(operation, intent),
                issued_at="2026-07-30T10:08:51Z",
                not_before="2026-07-30T10:08:51Z",
                expires_at="2026-07-30T10:10:00Z",
            )
        with closing(sqlite3.connect(self.path)) as connection:
            remove_schema_v39_objects(connection)
            connection.execute("UPDATE store_metadata SET value='38' WHERE key='schema_version'")
            connection.execute("PRAGMA user_version = 38")
            connection.commit()
        policy = AuthenticatedCollaborationMissionPolicyService(self.store, self.registry)
        with closing(sqlite3.connect(self.path, isolation_level=None)) as connection:
            self.store._configure(connection)
            connection.execute("BEGIN IMMEDIATE")
            identity, trust, mission, scopes, ledger = policy._activation._verified_mission_state(
                connection,
                self.fixture.root.mission.mission_id,
            )
            verified_policy, verified_scope = policy._verified_scope(
                connection,
                assertion=assertion,
                operation=operation,
                mission=mission,
                identity=identity,
                trust_policies=trust,
                scope_grants=scopes,
                now=self.now,
                consumed_time=parse_timestamp(format_timestamp(self.now), "now"),
            )
            principal = verify_principal_assertion(
                assertion,
                verified_policy,
                verified_scope,
                expected_audience=identity["audience"],
                expected_store_id=identity["store_id"],
                expected_mission_id=mission.mission.mission_id,
                expected_operation=operation,
                expected_operation_intent_sha256=assertion.operation_intent_sha256,
                clock=lambda: self.now,
            )
            effect = policy._effect(
                "legacy.repository-metadata",
                operation,
                {"metadata_only": True},
                format_timestamp(self.now),
            )
            effect["effect_kind"] = (
                PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value
                if effect_only
                else "sunderkey.synthetic.metadata-report.v1"
            )
            policy._record_assertion(
                connection,
                principal=principal,
                assertion=assertion,
                mission_id=mission.mission.mission_id,
                operation=operation,
                material=policy._assertion_material(assertion, operation, intent),
                effect=effect,
                ledger=ledger,
                consumed_at=format_timestamp(self.now),
            )
            # The normal writer always projects operation.value as effect_kind.
            # This isolated legacy probe aligns the projection with its already
            # hash-bound effect JSON, retaining the genuine signed use and ledger.
            name = "principal_assertion_effect_immutable"
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?",
                (name,),
            ).fetchone()[0]
            connection.execute(f'DROP TRIGGER "{name}"')
            connection.execute(
                "UPDATE principal_assertion_effects SET effect_kind = ? "
                "WHERE issuer = ? AND assertion_id = ?",
                (effect["effect_kind"], assertion.issuer, assertion.assertion_id),
            )
            connection.execute(definition)
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V38)
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def _assert_legacy_migration_refuses_and_preserves_verified_backup(
        self, *, effect_only: bool
    ) -> None:
        self._legacy_repository_provenance(effect_only=effect_only)
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value
        with closing(sqlite3.connect(self.path)) as connection:
            before = tuple(connection.iterdump())
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_uses WHERE operation = ?",
                    (operation,),
                ).fetchone()[0],
                0 if effect_only else 1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM principal_assertion_effects WHERE effect_kind = ?",
                    (operation,),
                ).fetchone()[0],
                1 if effect_only else 0,
            )
        backup = self.path.with_name("before-refused-migration.sqlite3")
        with self.assertRaisesRegex(StoreIntegrityError, "Pre-v39 repository acknowledgement"):
            self.store.migrate(self.registry, backup)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V38)
        self.assertTrue(backup.is_file())
        with closing(sqlite3.connect(backup)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V38)
        self.assertEqual(MissionStore(backup).verify_store(self.registry).status, "valid")

    def test_genuine_shared_source_reports_have_distinct_exact_custody_and_effects(self) -> None:
        self.assertNotEqual(self.first["authentication_id"], self.second["authentication_id"])
        self.assertEqual(
            self.first["source_report_authentication"], self.second["source_report_authentication"]
        )
        self.assertEqual(self.first["ingest_request"], self.second["ingest_request"])
        self.assertEqual(self.second["ingest_receipt"]["outcome"], "failed")
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")
        for document in (self.first, self.second):
            historical = self.service.get(document["authentication_id"]).to_dict()
            self.assertEqual(historical["repository_ingest_authentication"], document)
            self.assertFalse(document["raw_evidence_in_contract"])
            self.assertEqual(document["evidence_custody_status"], "provider_report_only")

    def test_history_validators_are_called_once_for_multiple_shared_source_eris(self) -> None:
        names = (
            "_verify_executor_dispatch_reservations",
            "_verify_executor_invocation_provider_reports",
            "_verify_executor_invocation_provider_report_authentications",
        )
        with self.store._read_connection() as connection:
            mission = self._mission(connection)
            with (
                patch.object(self.store, names[0], wraps=getattr(self.store, names[0])) as dispatch,
                patch.object(self.store, names[1], wraps=getattr(self.store, names[1])) as report,
                patch.object(
                    self.store, names[2], wraps=getattr(self.store, names[2])
                ) as authentication,
            ):
                self.assertEqual(
                    self.store._verify_provider_evidence_repository_ingest_authentications(
                        connection,
                        mission,
                    ),
                    2,
                )
            self.assertEqual(
                (dispatch.call_count, report.call_count, authentication.call_count), (1, 1, 1)
            )

    def test_deleting_only_eri_keeps_signed_ledger_intact_but_reciprocal_check_rejects(
        self,
    ) -> None:
        with self.store._read_connection() as connection:
            before = tuple(
                connection.execute(
                    "SELECT issuer, assertion_id, entry_hash, effects_hash "
                    "FROM principal_assertion_uses "
                    "WHERE operation = ? ORDER BY use_sequence",
                    (PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value,),
                ).fetchall()
            )
        self._corrupt(
            "provider_evidence_repository_ingest_authentications_no_delete",
            f"DELETE FROM {TABLE} WHERE authentication_id = ?",
            (self.first["authentication_id"],),
        )
        with self.store._read_connection() as connection:
            after = tuple(
                connection.execute(
                    "SELECT issuer, assertion_id, entry_hash, effects_hash "
                    "FROM principal_assertion_uses "
                    "WHERE operation = ? ORDER BY use_sequence",
                    (PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE.value,),
                ).fetchall()
            )
            self.assertEqual(before, after)
            with self.assertRaisesRegex(StoreIntegrityError, "custody is missing"):
                self.store._verify_provider_evidence_repository_ingest_authentications(
                    connection,
                    self._mission(connection),
                )
        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)
        with self.assertRaises(StoreIntegrityError):
            self.service.get(self.second["authentication_id"])

    def test_immutable_guards_prevent_raw_update_and_delete(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(f"UPDATE {TABLE} SET outcome = 'failed'")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                connection.execute(f"DELETE FROM {TABLE}")

    def test_retained_eri_cannot_lose_its_original_repository_assertion_use(self) -> None:
        principal = self.first["repository_attestor"]
        self._corrupt(
            "principal_assertion_use_no_delete",
            "DELETE FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
            (principal["issuer"], principal["assertion_id"]),
        )
        with self.store._read_connection() as connection, self.assertRaises(StoreIntegrityError):
            self.store._verify_provider_evidence_repository_ingest_authentications(
                connection,
                self._mission(connection),
            )
        with self.assertRaises(StoreIntegrityError):
            self.service.get(self.first["authentication_id"])

    def test_retained_eri_cannot_lose_its_exact_repository_effect(self) -> None:
        principal = self.first["repository_attestor"]
        self._corrupt(
            "principal_assertion_effect_no_delete",
            "DELETE FROM principal_assertion_effects WHERE issuer = ? AND assertion_id = ?",
            (principal["issuer"], principal["assertion_id"]),
        )
        with self.store._read_connection() as connection, self.assertRaises(StoreIntegrityError):
            self.store._verify_provider_evidence_repository_ingest_authentications(
                connection,
                self._mission(connection),
            )
        with self.assertRaises(StoreIntegrityError):
            self.service.get(self.first["authentication_id"])

    def test_retained_eri_cannot_lose_its_exact_source_epa(self) -> None:
        self._corrupt(
            "executor_invocation_provider_report_authentications_no_delete",
            "DELETE FROM executor_invocation_provider_report_authentications "
            "WHERE report_authentication_id = ?",
            (self.first["source_report_authentication"]["report_authentication_id"],),
        )
        with self.store._read_connection() as connection, self.assertRaises(StoreIntegrityError):
            self.store._verify_provider_evidence_repository_ingest_authentications(
                connection,
                self._mission(connection),
            )
        with self.assertRaises(StoreIntegrityError):
            self.service.get(self.first["authentication_id"])

    def test_projection_change_cannot_substitute_a_reported_object_version(self) -> None:
        self._corrupt(
            "provider_evidence_repository_ingest_authentications_immutable",
            f"UPDATE {TABLE} SET object_version_id = 'version.substituted' "
            "WHERE authentication_id = ?",
            (self.first["authentication_id"],),
        )
        with self.store._read_connection() as connection, self.assertRaises(StoreIntegrityError):
            self.store._provider_evidence_repository_ingest_authentication_row(
                connection,
                self.first["authentication_id"],
            )
        with self.assertRaises(StoreIntegrityError):
            self.store.verify_store(self.registry)

    def test_sql_native_projection_guard_rejects_missing_null_and_alias_fields(self) -> None:
        columns = self.store._repository_ingest_authentication_columns(self.first)
        statement = (
            f"INSERT INTO {TABLE}({', '.join(columns)}) VALUES ({', '.join('?' for _ in columns)})"
        )
        with closing(sqlite3.connect(self.path)) as connection:
            for key, value in (
                ("schema_version", True),
                ("authentication_id", None),
                ("authentication_sha256", None),
                ("raw_evidence_in_contract", 0),
                ("authenticated_at", None),
            ):
                raw = json.loads(canonical_json(self.first))
                raw[key] = value
                parameters = dict(columns, authentication_json=canonical_json(raw))
                with (
                    self.subTest(key=key),
                    self.assertRaisesRegex(sqlite3.IntegrityError, "inconsistent"),
                ):
                    connection.execute(statement, tuple(parameters.values()))
            raw = json.loads(canonical_json(self.first))
            del raw["ingest_receipt"]["repository_object"]["object_version_id"]
            parameters = dict(columns, authentication_json=canonical_json(raw))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "inconsistent"):
                connection.execute(statement, tuple(parameters.values()))

    def test_signed_custody_backup_keeps_historical_records_and_exact_manifest(self) -> None:
        backup = self.path.with_name("signed-backup.sqlite3")
        self.store.backup(self.registry, backup)
        copied = MissionStore(backup)
        self.assertEqual(copied.verify_store(self.registry).status, "valid")
        with copied._read_connection() as connection:
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0], 2)

    def test_historical_original_assertion_must_not_predate_repository_receipt(self) -> None:
        document = self._signed_raw_authentication(early_assertion=True)
        policy = AuthenticatedCollaborationMissionPolicyService(self.store, self.registry)
        with self.store._read_connection() as connection:
            with patch.object(
                self.store,
                "_verify_provider_evidence_repository_ingest_authentications",
                return_value=1,
            ):
                # All generic original-time signature, trust, scope and ledger checks pass.
                policy._activation._verified_mission_state(
                    connection, self.fixture.root.mission.mission_id
                )
            with self.assertRaisesRegex(StoreIntegrityError, "precedes the provider receipt"):
                self.store._verify_provider_evidence_repository_ingest_authentications(
                    connection, self._mission(connection)
                )
        with self.assertRaises(StoreIntegrityError):
            self.service.get(document["authentication_id"])

    def test_historical_original_scope_must_fit_original_lifecycle_access_ceiling(self) -> None:
        document = self._signed_raw_authentication(long_scope=True)
        policy = AuthenticatedCollaborationMissionPolicyService(self.store, self.registry)
        with self.store._read_connection() as connection:
            with patch.object(
                self.store,
                "_verify_provider_evidence_repository_ingest_authentications",
                return_value=1,
            ):
                policy._activation._verified_mission_state(
                    connection, self.fixture.root.mission.mission_id
                )
            with self.assertRaisesRegex(StoreIntegrityError, "original lifecycle access"):
                self.store._verify_provider_evidence_repository_ingest_authentications(
                    connection, self._mission(connection)
                )
        with self.assertRaises(StoreIntegrityError):
            self.service.get(document["authentication_id"])

    def test_migration_refuses_signed_legacy_ack_use_even_without_ack_effect_kind(self) -> None:
        self._assert_legacy_migration_refuses_and_preserves_verified_backup(effect_only=False)

    def test_migration_refuses_signed_legacy_ack_effect_even_without_ack_use_operation(
        self,
    ) -> None:
        self._assert_legacy_migration_refuses_and_preserves_verified_backup(effect_only=True)


if __name__ == "__main__":
    unittest.main()

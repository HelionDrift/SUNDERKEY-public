"""Genuine historical repository metadata reads without current authority."""

from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from sunderkey import authenticated_provider_evidence_repository as repository
from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_collaboration import AuthenticatedCollaborationActivationService
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.errors import (
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    compute_operation_intent_hash,
)
from sunderkey.scope import ScopeGrantRevocationAcceptanceService
from sunderkey.store import (
    EXPECTED_SCHEMA_MANIFEST_V39,
    MissionStore,
    _schema_manifest,
    format_timestamp,
    sha256_text,
)
from sunderkey.trust import TrustProvisioningService

from . import test_provider_evidence_repository_authentication_phase149 as phase149
from .test_authenticated_provider_evidence_repository import (
    CONTROL_SUBJECT,
    TABLE,
    logical_store,
    repository_assertion,
    repository_counts,
    repository_revocation,
    repository_service_fixture,
)
from .test_identity_phase4 import ZERO_SIGNATURE, b64url
from .test_store import remove_schema_v39_objects


class ProviderEvidenceRepositoryHistoricalReaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        owner = unittest.TestCase(methodName="runTest")
        cls.addClassCleanup(owner.doCleanups)
        cls.base = repository_service_fixture(owner)
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.ready_path = cls.directory / "before-repository-ack.sqlite3"
        cls.committed_path = cls.directory / "signed-repository-ack.sqlite3"
        with closing(sqlite3.connect(cls.base.root.path)) as source:
            with closing(sqlite3.connect(cls.ready_path)) as destination:
                source.backup(destination)
        cls.committed = cls.base.service.authenticate(
            cls.base.request,
            cls.base.receipt,
            cls.base.lifecycle,
            repository_assertion=cls.base.assertion,
        )
        with closing(sqlite3.connect(cls.base.root.path)) as source:
            with closing(sqlite3.connect(cls.committed_path)) as destination:
                source.backup(destination)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "reader.sqlite3"
        self._restore(self.committed_path)
        self.fixture = copy.copy(self.base)
        self.fixture.root = copy.copy(self.base.root)
        self.fixture.root.path = self.path
        self.fixture.root.now = self.fixture.now
        self.store = MissionStore(self.path, clock=lambda: self.fixture.now)
        self.registry = self.fixture.root.registry
        self.fixture.root.store = self.store
        self.fixture.root.trust = TrustProvisioningService(self.store)
        self.fixture.service = repository.AuthenticatedProviderEvidenceRepositoryService(
            self.store,
            self.registry,
            repository_principal_subject=phase149.SUBJECT,
            repository_principal_profile_id=phase149.PROFILE_ID,
            clock=lambda: self.fixture.now,
        )
        self.authentication_id = self.committed.authentication_id

    def _restore(self, source_path: Path) -> None:
        with closing(sqlite3.connect(source_path)) as source:
            with closing(sqlite3.connect(self.path)) as destination:
                source.backup(destination)

    def _read(self, authentication_id=None):
        selected = self.authentication_id if authentication_id is None else authentication_id
        return repository.read_provider_evidence_repository_ingest_authentication(
            self.store, self.registry, selected
        )

    def _authenticate(self):
        fixture = self.fixture
        return fixture.service.authenticate(
            fixture.request,
            fixture.receipt,
            fixture.lifecycle,
            repository_assertion=fixture.assertion,
        )

    def _tick(self, seconds: int = 1) -> None:
        self.fixture.now += timedelta(seconds=seconds)
        self.fixture.root.now = self.fixture.now

    def _corrupt(self, trigger: str, statement: str, parameters: tuple = ()) -> None:
        """Alter only a synthetic copy, restoring the exact immutable manifest."""
        with closing(sqlite3.connect(self.path)) as connection:
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?", (trigger,)
            ).fetchone()[0]
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute(f'DROP TRIGGER "{trigger}"')
            connection.execute(statement, parameters)
            connection.execute(definition)
            connection.execute("PRAGMA ignore_check_constraints = OFF")
            connection.commit()
            self.assertEqual(_schema_manifest(connection), EXPECTED_SCHEMA_MANIFEST_V39)

    def _assert_historical(self) -> None:
        before = logical_store(self.fixture)
        receipt = self._read()
        self.assertEqual(receipt, self.committed)
        self.assertEqual(self.fixture.service.get(self.authentication_id), receipt)
        document = receipt.to_dict()
        self.assertEqual(document["current_authority_status"], "not_verified")
        self.assertEqual(document["evidence_custody_status"], "provider_report_only")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(logical_store(self.fixture), before)

    def test_reader_get_and_reopened_store_return_original_detached_receipt(self) -> None:
        self._assert_historical()
        clock = mock.Mock(side_effect=AssertionError("historical reader requested current time"))
        reopened = MissionStore(self.path, clock=clock)
        receipt = repository.read_provider_evidence_repository_ingest_authentication(
            reopened, self.registry, self.authentication_id
        )
        self.assertEqual(receipt, self.committed)
        first = receipt.to_dict()
        first["repository_ingest_authentication"]["ingest_receipt"]["outcome"] = "failed"
        self.assertNotEqual(first, receipt.to_dict())
        clock.assert_not_called()

    def test_existing_get_delegates_to_the_shared_reader(self) -> None:
        with mock.patch.object(
            repository,
            "read_provider_evidence_repository_ingest_authentication",
            wraps=repository.read_provider_evidence_repository_ingest_authentication,
        ) as reader:
            self.assertEqual(self.fixture.service.get(self.authentication_id), self.committed)
        reader.assert_called_once_with(self.store, self.registry, self.authentication_id)

    def test_reader_never_instantiates_publication_or_calls_live_or_write_hooks(self) -> None:
        before = logical_store(self.fixture)
        clock = mock.Mock(side_effect=AssertionError("historical reader requested current clock"))
        self.store._clock = clock
        forbidden = AssertionError("historical reader reached a publication or mutation hook")
        with (
            mock.patch.object(self.store, "_write_connection", side_effect=forbidden) as write,
            mock.patch.object(self.store, "initialize", side_effect=forbidden) as initialize,
            mock.patch.object(self.store, "migrate", side_effect=forbidden) as migrate,
            mock.patch.object(
                repository.AuthenticatedProviderEvidenceRepositoryService,
                "__init__",
                side_effect=forbidden,
            ) as publication,
            mock.patch.object(
                AuthenticatedCollaborationMissionPolicyService,
                "_verified_scope",
                side_effect=forbidden,
            ) as live_scope,
            mock.patch.object(
                repository,
                "authenticate_provider_evidence_repository_ingest_receipt",
                side_effect=forbidden,
            ) as producer,
        ):
            self.assertEqual(self._read(), self.committed)
            for hook in (write, initialize, migrate, publication, live_scope, producer, clock):
                hook.assert_not_called()
        self.assertEqual(logical_store(self.fixture), before)

    def test_query_only_fence_blocks_dml_without_changing_a_later_writer(self) -> None:
        before = logical_store(self.fixture)
        original = self.store._provider_evidence_repository_ingest_authentication_row
        observed = []

        def row(connection, authentication_id):
            self.assertTrue(connection.in_transaction)
            self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 1)
            with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                connection.execute(
                    "UPDATE store_metadata SET value = value WHERE key = 'schema_version'"
                )
            observed.append(connection)
            return original(connection, authentication_id)

        with mock.patch.object(
            self.store, "_provider_evidence_repository_ingest_authentication_row", side_effect=row
        ):
            self.assertEqual(self._read(), self.committed)
        self.assertEqual(len(observed), 1)
        self.assertEqual(logical_store(self.fixture), before)
        with self.store._write_connection() as connection:
            self.assertEqual(connection.execute("PRAGMA query_only").fetchone()[0], 0)
        assertion = repository_assertion(self.fixture, token="F8")
        later = self.fixture.service.authenticate(
            self.fixture.request,
            self.fixture.receipt,
            self.fixture.lifecycle,
            repository_assertion=assertion,
        )
        self.assertNotEqual(later.authentication_id, self.authentication_id)
        self.assertEqual(repository_counts(self.fixture)[0], 2)
        self.assertEqual(self._read(), self.committed)

    def test_unconfirmed_query_only_fence_fails_before_row_and_state_verification(self) -> None:
        original = self.store._read_connection
        before = logical_store(self.fixture)

        class View:
            def __init__(self, connection, result):
                self.connection = connection
                self.result = result

            def execute(self, statement, *arguments):
                if statement == "PRAGMA query_only":
                    return mock.Mock(fetchone=lambda: self.result)
                return self.connection.execute(statement, *arguments)

        for result in (None, (0,), (True,), (1.0,)):

            @contextmanager
            def connection():
                with original() as actual:
                    yield View(actual, result)

            with (
                self.subTest(result=result),
                mock.patch.object(self.store, "_read_connection", side_effect=connection),
                mock.patch.object(
                    self.store, "_provider_evidence_repository_ingest_authentication_row"
                ) as row,
                mock.patch.object(
                    AuthenticatedCollaborationActivationService, "_verified_mission_state"
                ) as state,
                self.assertRaisesRegex(StoreIntegrityError, "query-only fence"),
            ):
                self._read()
            row.assert_not_called()
            state.assert_not_called()
            self.assertEqual(logical_store(self.fixture), before)

    def test_native_invalid_identity_rejects_before_a_read_connection(self) -> None:
        class StringAlias(str):
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

        invalid = (
            None,
            1,
            b"ERI-" + b"00" * 16,
            StringAlias(self.authentication_id),
            self.authentication_id.lower(),
            self.authentication_id + "\n",
            "ERI-" + "A" * 100_000,
        )
        before = logical_store(self.fixture)
        with mock.patch.object(self.store, "_read_connection") as connection:
            for value in invalid:
                with self.subTest(kind=type(value).__name__), self.assertRaises(StoreError):
                    repository.read_provider_evidence_repository_ingest_authentication(
                        self.store, self.registry, value
                    )
            connection.assert_not_called()
        self.assertEqual(logical_store(self.fixture), before)

    def test_unsupported_store_or_registry_family_is_not_a_reader_fallback(self) -> None:
        with self.assertRaises(TypeError):
            repository.read_provider_evidence_repository_ingest_authentication(
                object(), self.registry, self.authentication_id
            )
        with mock.patch.object(self.store, "_read_connection") as connection:
            with self.assertRaises(TypeError):
                repository.read_provider_evidence_repository_ingest_authentication(
                    self.store, object(), self.authentication_id
                )
            connection.assert_not_called()

    def test_unknown_identity_or_missing_store_creates_no_custody_or_file(self) -> None:
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(StoreError, "not committed"):
            self._read("ERI-" + "00" * 16)
        self.assertEqual(logical_store(self.fixture), before)
        missing = self.path.parent / "not-created.sqlite3"
        store = MissionStore(missing)
        with self.assertRaisesRegex(StoreError, "does not exist"):
            repository.read_provider_evidence_repository_ingest_authentication(
                store, self.registry, self.authentication_id
            )
        self.assertFalse(missing.exists())

    def test_pre39_history_requires_explicit_migration_without_mutating_the_store(self) -> None:
        self._restore(self.ready_path)
        with closing(sqlite3.connect(self.path)) as connection:
            remove_schema_v39_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '38' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 38")
            connection.commit()
        before = logical_store(self.fixture)
        with mock.patch.object(self.store, "migrate") as migrate:
            with self.assertRaises(StoreMigrationRequiredError):
                self._read()
            migrate.assert_not_called()
        self.assertEqual(logical_store(self.fixture), before)

    def test_an_otherwise_valid_wrong_registry_cannot_reinterpret_stored_mission_context(
        self,
    ) -> None:
        before = logical_store(self.fixture)
        other = replace(self.registry, catalog_version="0.0.0-synthetic-other")
        other.validate()
        with self.assertRaisesRegex(StoreIntegrityError, "different expert catalog"):
            repository.read_provider_evidence_repository_ingest_authentication(
                self.store, other, self.authentication_id
            )
        self.assertEqual(logical_store(self.fixture), before)

    def test_expired_positive_replay_denies_while_reader_keeps_original_history(self) -> None:
        self._tick()
        self.assertEqual(self._authenticate(), self.committed)
        self.fixture.now = datetime(2026, 7, 30, 10, 10, 1, tzinfo=UTC)
        self.fixture.root.now = self.fixture.now
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self._assert_historical()

    def test_real_revocation_denies_positive_replay_without_revoking_history(self) -> None:
        self._tick()
        self.assertEqual(self._authenticate(), self.committed)
        policy_hash = self.fixture.root.trust.status().policy_hash
        self._tick()
        ScopeGrantRevocationAcceptanceService(self.store, self.registry).accept(
            repository_revocation(self.fixture)
        )
        self.assertEqual(self.fixture.root.trust.status().policy_hash, policy_hash)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self._assert_historical()

    def test_signed_trust_rotation_denies_positive_replay_not_historical_reader(self) -> None:
        self._tick()
        self.assertEqual(self._authenticate(), self.committed)
        self._tick()
        raw = self.fixture.repository_policy.to_dict()
        raw["policy_version"] += 1
        raw["signature"] = ZERO_SIGNATURE
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        rotated = replace(
            unsigned,
            signature=b64url(self.fixture.root.factory.root_private.sign(unsigned.signing_bytes())),
        )
        self.fixture.root.trust.apply_policy(rotated)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "policy"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self._assert_historical()

    def test_authenticated_stop_denies_positive_replay_not_original_metadata(self) -> None:
        self._tick()
        self.assertEqual(self._authenticate(), self.committed)
        self._tick()
        fixture = self.fixture
        arguments = {
            "reason_code": "operator_request",
            "reason": "Synthetic mission stopped for the historical-reader regression.",
            "risk": "Only historical metadata inspection remains available.",
            "decision_owner": "synthetic-range-control",
            "idempotency_key": "repository-reader-synthetic-stop",
            "expected_version": 1,
        }
        intent = {
            "mission_id": fixture.root.mission.mission_id,
            "principal_profile_id": phase149.PROFILE_ID,
            **{key: value for key, value in arguments.items() if key != "idempotency_key"},
            "idempotency_key_sha256": sha256_text(arguments["idempotency_key"]),
        }
        assertion = fixture.root.factory.assertion(
            grant=fixture.stop_grant,
            assertion_id="PAS-" + "F9" * 16,
            scope_grant_id=fixture.stop_grant.grant_id,
            policy_version=phase149.POLICY_VERSION,
            subject=CONTROL_SUBJECT,
            profile_id=phase149.PROFILE_ID,
            store_id=fixture.root.store_id,
            mission_id=fixture.root.mission.mission_id,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.MISSION_STOP, intent
            ),
            issued_at=format_timestamp(fixture.now),
            not_before=format_timestamp(fixture.now),
            expires_at="2026-07-30T10:10:00Z",
        )
        AuthenticatedMissionControlService(
            self.store, self.registry, clock=lambda: fixture.now
        ).stop(assertion, fixture.root.mission.mission_id, **arguments)
        before = logical_store(fixture)
        with self.assertRaises(MissionStoppedError):
            self._authenticate()
        self.assertEqual(logical_store(fixture), before)
        self._assert_historical()

    def test_corrupted_eri_source_use_and_effect_fail_closed_without_read_mutation(self) -> None:
        cases = (
            (
                "provider_evidence_repository_ingest_authentications_immutable",
                f"UPDATE {TABLE} SET authentication_json = '{{}}' WHERE authentication_id = ?",
                (self.authentication_id,),
            ),
            (
                "executor_invocation_provider_report_authentications_immutable",
                "UPDATE executor_invocation_provider_report_authentications "
                "SET authentication_json = '{}' WHERE report_authentication_id = ?",
                (self.fixture.source_authentication["report_authentication_id"],),
            ),
            (
                "principal_assertion_use_no_delete",
                "DELETE FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                (self.fixture.assertion.issuer, self.fixture.assertion.assertion_id),
            ),
            (
                "principal_assertion_effect_no_delete",
                "DELETE FROM principal_assertion_effects WHERE effect_id = ?",
                (self.authentication_id,),
            ),
            (
                "provider_evidence_repository_ingest_authentications_no_delete",
                f"DELETE FROM {TABLE} WHERE authentication_id = ?",
                (self.authentication_id,),
            ),
        )
        for trigger, statement, parameters in cases:
            with self.subTest(trigger=trigger):
                self._restore(self.committed_path)
                self._corrupt(trigger, statement, parameters)
                before = logical_store(self.fixture)
                with self.assertRaises(StoreError):
                    self._read()
                self.assertEqual(logical_store(self.fixture), before)

    def test_strict_raw_json_denial_keeps_exact_corrupted_fixture_unchanged(self) -> None:
        original = self.committed.authentication_json
        cases = (
            "{",
            "[]",
            original.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            original.replace('"schema_version":1', '"schema_version":1.0', 1),
            original.replace('"schema_version":1', '"schema_version":true', 1),
            original.replace('"schema_version":1', '"schema_version":NaN', 1),
            "{" + " " * 2_000_000,
        )
        for index, text in enumerate(cases):
            with self.subTest(case=index):
                self._restore(self.committed_path)
                self._corrupt(
                    "provider_evidence_repository_ingest_authentications_immutable",
                    f"UPDATE {TABLE} SET authentication_json = ? WHERE authentication_id = ?",
                    (text, self.authentication_id),
                )
                before = logical_store(self.fixture)
                with self.assertRaises(StoreIntegrityError):
                    self._read()
                self.assertEqual(logical_store(self.fixture), before)


if __name__ == "__main__":
    unittest.main()

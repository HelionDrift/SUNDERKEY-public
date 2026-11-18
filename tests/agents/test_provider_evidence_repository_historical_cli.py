"""Explicit local historical inspection, without publication or read authority claims."""

from __future__ import annotations

import io
import json
import sqlite3
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from sunderkey import cli
from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_provider_evidence_repository import (
    AuthenticatedProviderEvidenceRepositoryService,
    ProviderEvidenceRepositoryPrincipalCommit,
)
from sunderkey.errors import MissionStoppedError, PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.scope import ScopeGrantRevocationAcceptanceService
from sunderkey.store import MissionStore, format_timestamp, sha256_text

from . import test_provider_evidence_repository_authentication_phase149 as phase149
from .test_authenticated_provider_evidence_repository import (
    CONTROL_SUBJECT,
    logical_store,
    repository_assertion,
    repository_revocation,
    repository_service_fixture,
)
from .test_store import REGISTRY_PATH, remove_schema_v39_objects

ROOT = Path(__file__).resolve().parents[2]
COMMAND = "provider-evidence-repository-authentication-show"
TABLE = "provider_evidence_repository_ingest_authentications"


class ProviderEvidenceRepositoryHistoricalCLIParserTests(unittest.TestCase):
    def test_exact_explicit_inputs_and_handler(self) -> None:
        args = cli.build_parser().parse_args(
            [
                COMMAND,
                "--store",
                "store",
                "--registry",
                "registry",
                "--authentication-id",
                "ERI-" + "A" * 32,
            ]
        )
        self.assertEqual(args.store, "store")
        self.assertEqual(args.registry, "registry")
        self.assertEqual(args.authentication_id, "ERI-" + "A" * 32)
        self.assertIs(args.handler, cli._show_provider_evidence_repository_authentication)
        self.assertFalse(hasattr(args, "output"))

    def test_required_and_unsupported_options_fail_before_inputs_open(self) -> None:
        tokens = [
            "--store",
            "store",
            "--registry",
            "registry",
            "--authentication-id",
            "ERI-" + "A" * 32,
        ]
        candidates = [tokens[:index] + tokens[index + 2 :] for index in (0, 2, 4)]
        candidates.extend(
            tokens + extra
            for extra in (
                ["--output", "must-not-be-created.json"],
                ["--latest"],
                ["--initialize"],
                ["--migrate"],
                ["--repository-principal-subject", "service:synthetic"],
                ["--repository-principal-profile-id", "synthetic"],
                ["--principal-assertion", "must-not-be-opened.json"],
                ["--api-key", "synthetic-not-a-credential"],
            )
        )
        with (
            mock.patch.object(cli, "MissionStore") as store,
            mock.patch.object(cli, "load_registry") as registry,
        ):
            for tokens in candidates:
                with (
                    self.subTest(arguments=tokens),
                    mock.patch("sys.argv", ["sunderkey", COMMAND, *tokens]),
                    redirect_stdout(io.StringIO()),
                    redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    cli.main()
                self.assertEqual(raised.exception.code, 2)
            store.assert_not_called()
            registry.assert_not_called()


class ProviderEvidenceRepositoryHistoricalCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = repository_service_fixture(self)

    def _publish(self, *, assertion=None):
        fixture = self.fixture
        return fixture.service.authenticate(
            fixture.request,
            fixture.receipt,
            fixture.lifecycle,
            repository_assertion=fixture.assertion if assertion is None else assertion,
        )

    def _arguments(self, authentication_id: str, *, path: Path | None = None) -> list[str]:
        return [
            COMMAND,
            "--store",
            str(self.fixture.root.path if path is None else path),
            "--registry",
            str(REGISTRY_PATH),
            "--authentication-id",
            authentication_id,
        ]

    def _show(self, authentication_id: str) -> dict:
        capture = io.StringIO()
        with (
            mock.patch("sys.argv", ["sunderkey", *self._arguments(authentication_id)]),
            redirect_stdout(capture),
        ):
            cli.main()
        return json.loads(capture.getvalue())

    def _failure(self, arguments: list[str]) -> str:
        capture = io.StringIO()
        with (
            mock.patch("sys.argv", ["sunderkey", *arguments]),
            redirect_stdout(capture),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            cli.main()
        self.assertEqual(capture.getvalue(), "")
        self.assertTrue(str(raised.exception).startswith("Validation error:"))
        return str(raised.exception)

    def _corrupt(self, trigger: str, statement: str, parameters: tuple) -> None:
        # Only this disposable signed fixture is corrupted, then its manifest is restored.
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            definition = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?",
                (trigger,),
            ).fetchone()[0]
            connection.execute(f'DROP TRIGGER "{trigger}"')
            connection.execute(statement, parameters)
            connection.execute(definition)
            connection.commit()

    def test_genuine_stdout_is_original_historical_metadata_and_store_is_unchanged(self) -> None:
        receipt = self._publish()
        before = logical_store(self.fixture)
        result = self._show(receipt.authentication_id)
        self.assertEqual(
            result,
            {
                "verification_scope": "historical_custody_only",
                "current_authority_verified": False,
                "receipt": receipt.to_dict(),
            },
        )
        self.assertEqual(result["receipt"]["evidence_custody_status"], "provider_report_only")
        self.assertEqual(result["receipt"]["current_authority_status"], "not_verified")
        self.assertEqual(result["receipt"]["runtime_effect"], "none")
        self.assertEqual(result["receipt"]["qualification_effect"], "none")
        result["receipt"]["repository_ingest_authentication"]["ingest_receipt"]["outcome"] = (
            "failed"
        )
        self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        self.assertEqual(logical_store(self.fixture), before)

    def test_expired_historical_read_never_calls_live_clock_or_positive_paths(self) -> None:
        receipt = self._publish()
        self.fixture.now += timedelta(seconds=71)
        self.fixture.root.now = self.fixture.now
        with self.assertRaises(PrincipalAuthenticationError):
            self._publish()
        before = logical_store(self.fixture)
        forbidden_clock = mock.Mock(side_effect=AssertionError("historical CLI invoked clock"))
        with (
            mock.patch.object(
                cli,
                "MissionStore",
                side_effect=lambda path: MissionStore(path, clock=forbidden_clock),
            ),
            mock.patch.object(
                MissionStore, "_write_connection", side_effect=AssertionError("write")
            ),
            mock.patch.object(MissionStore, "initialize", side_effect=AssertionError("initialize")),
            mock.patch.object(MissionStore, "migrate", side_effect=AssertionError("migrate")),
            mock.patch.object(
                AuthenticatedProviderEvidenceRepositoryService,
                "authenticate",
                side_effect=AssertionError("historical CLI attempted publication"),
            ),
        ):
            self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        forbidden_clock.assert_not_called()
        self.assertEqual(logical_store(self.fixture), before)

    def test_actual_revocation_denies_publication_but_not_local_history(self) -> None:
        receipt = self._publish()
        self.fixture.now += timedelta(seconds=2)
        self.fixture.root.now = self.fixture.now
        ScopeGrantRevocationAcceptanceService(
            self.fixture.root.store, self.fixture.root.registry
        ).accept(repository_revocation(self.fixture))
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            self._publish()
        before = logical_store(self.fixture)
        self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        self.assertEqual(logical_store(self.fixture), before)

    def test_authenticated_stop_denies_publication_but_not_local_history(self) -> None:
        receipt = self._publish()
        fixture = self.fixture
        fixture.now += timedelta(seconds=2)
        fixture.root.now = fixture.now
        arguments = {
            "reason_code": "operator_request",
            "reason": "Synthetic historical CLI mission stopped for this regression.",
            "risk": "No further positive publication is authorized.",
            "decision_owner": "synthetic-range-control",
            "idempotency_key": "repository-historical-cli-stop",
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
            assertion_id="PAS-" + "FA" * 16,
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
            fixture.root.store, fixture.root.registry, clock=lambda: fixture.now
        ).stop(assertion, fixture.root.mission.mission_id, **arguments)
        with self.assertRaises(MissionStoppedError):
            self._publish()
        before = logical_store(fixture)
        self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        self.assertEqual(logical_store(fixture), before)

    def test_invalid_unknown_and_missing_store_fail_without_stdout_or_creation(self) -> None:
        receipt = self._publish()
        before = logical_store(self.fixture)
        for identifier in ("", "ERI-" + "a" * 32, "ERI-" + "0" * 32):
            with self.subTest(identifier=identifier):
                self._failure(self._arguments(identifier))
        missing = self.fixture.root.path.parent / "missing-historical-store.sqlite3"
        self._failure(self._arguments(receipt.authentication_id, path=missing))
        self.assertFalse(missing.exists())
        self.assertEqual(logical_store(self.fixture), before)

    def test_schema38_is_not_automatically_migrated(self) -> None:
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            remove_schema_v39_objects(connection)
            connection.execute("UPDATE store_metadata SET value='38' WHERE key='schema_version'")
            connection.execute("PRAGMA user_version = 38")
            connection.commit()
        before = logical_store(self.fixture)
        self.assertIn("schema39", self._failure(self._arguments("ERI-" + "A" * 32)))
        self.assertEqual(logical_store(self.fixture), before)

    def test_wrong_catalog_fails_without_success_output_or_store_mutation(self) -> None:
        receipt = self._publish()
        before = logical_store(self.fixture)
        arguments = self._arguments(receipt.authentication_id)
        arguments[arguments.index("--registry") + 1] = str(ROOT / "registry" / "army-v2.json")
        self.assertIn("different expert catalog", self._failure(arguments))
        self.assertEqual(logical_store(self.fixture), before)

    def test_duplicate_raw_custody_json_fails_before_any_success_output(self) -> None:
        receipt = self._publish()
        self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        duplicate = '{"schema_version":1,' + receipt.authentication_json[1:]
        self._corrupt(
            "provider_evidence_repository_ingest_authentications_immutable",
            f"UPDATE {TABLE} SET authentication_json = ? WHERE authentication_id = ?",
            (duplicate, receipt.authentication_id),
        )
        before = logical_store(self.fixture)
        self._failure(self._arguments(receipt.authentication_id))
        self.assertEqual(logical_store(self.fixture), before)

    def test_reciprocal_orphan_fails_even_when_selected_row_is_intact(self) -> None:
        original = self._publish()
        later = self._publish(assertion=repository_assertion(self.fixture, token="FB"))
        self.assertEqual(self._show(later.authentication_id)["receipt"], later.to_dict())
        self._corrupt(
            "provider_evidence_repository_ingest_authentications_no_delete",
            f"DELETE FROM {TABLE} WHERE authentication_id = ?",
            (original.authentication_id,),
        )
        before = logical_store(self.fixture)
        self._failure(self._arguments(later.authentication_id))
        self.assertEqual(logical_store(self.fixture), before)

    def test_missing_exact_source_fails_without_success_output(self) -> None:
        receipt = self._publish()
        self.assertEqual(self._show(receipt.authentication_id)["receipt"], receipt.to_dict())
        source = receipt.to_dict()["repository_ingest_authentication"][
            "source_report_authentication"
        ]
        self._corrupt(
            "executor_invocation_provider_report_authentications_no_delete",
            "DELETE FROM executor_invocation_provider_report_authentications "
            "WHERE report_authentication_id = ?",
            (source["report_authentication_id"],),
        )
        before = logical_store(self.fixture)
        self._failure(self._arguments(receipt.authentication_id))
        self.assertEqual(logical_store(self.fixture), before)

    def test_receipt_serialization_finishes_before_stdout(self) -> None:
        receipt = self._publish()
        invalid = replace(
            receipt,
            repository_attestor=ProviderEvidenceRepositoryPrincipalCommit(
                "PAS-" + "0" * 32, "sha256:" + "0" * 64, "sha256:" + "0" * 64
            ),
        )
        before = logical_store(self.fixture)
        with mock.patch.object(
            cli, "read_provider_evidence_repository_ingest_authentication", return_value=invalid
        ):
            self._failure(self._arguments(receipt.authentication_id))
        self.assertEqual(logical_store(self.fixture), before)


if __name__ == "__main__":
    unittest.main()

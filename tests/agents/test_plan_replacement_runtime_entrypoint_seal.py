"""Runtime seal coverage independent of the unsigned Phase186D bootstrap."""

from __future__ import annotations

import sqlite3
import unittest
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.build_collaboration_plan_replacement_authority_plan import (
    build_parser,
    build_sources,
)
from sunderkey.authenticated_collaboration_plan_replacement import (
    AuthenticatedCollaborationPlanReplacementStoreService,
    _normalize_credentials,
    _TransactionScopedReplacementAuthorityVerifier,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
)
from sunderkey.collaboration_plan_replacement_store import (
    REPLACEMENT_RECEIPT_DOMAIN,
    REPLACEMENT_REQUEST_DOMAIN,
    CollaborationPlanReplacementCommitReceipt,
    CollaborationPlanReplacementStoreService,
    ReplacementAuthorityEvidence,
    _CollaborationPlanReplacementAtomicStore,
    _verify_authenticated_replacement_custody,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreIntegrityError
from sunderkey.store import (
    AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION,
    SCHEMA_VERSION,
    MissionStore,
    canonical_json,
    sha256_text,
)

from . import test_collaboration_plan_replacement_authentication_phase186c as authority_fixture


def digest(value: object) -> str:
    return sha256_text(canonical_json(value))


class PlanReplacementRuntimeEntrypointSealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (
            cls.preflight,
            cls.prior,
            cls.replacement,
            _,
            _,
            cls.registry,
            _,
        ) = build_sources(build_parser().parse_args([]))

    def setUp(self) -> None:
        # This constructor performs no I/O. All SQLite probes stay in memory.
        self.store = MissionStore(Path("nonexistent-runtime-seal-sentinel.sqlite3"))
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.row_factory = sqlite3.Row

    def verifier(self, **changes: object) -> _TransactionScopedReplacementAuthorityVerifier:
        values = {
            "store": self.store,
            "registry": self.registry,
            "preflight": self.preflight,
            "verified_authority_plan": None,
            "authority_upgrade": None,
            "bundle": None,
            "credentials": (),
        }
        values.update(changes)
        # No signed-write assertion is made by this binding-only test adapter.
        return _TransactionScopedReplacementAuthorityVerifier(**values)

    def service(self, verifier: object) -> CollaborationPlanReplacementStoreService:
        return CollaborationPlanReplacementStoreService(self.store, self.registry, verifier)

    def arguments(self) -> dict[str, object]:
        evidence = []
        for requirement in self.preflight.to_dict()["authority_requirements"]:
            body = {"requirement_id": requirement["requirement_id"], "accepted": True}
            evidence.append(
                ReplacementAuthorityEvidence.from_dict(
                    {
                        "requirement_id": requirement["requirement_id"],
                        "evidence_id": "PAE-" + requirement["requirement_id"][4:],
                        "evidence_sha256": digest(body),
                        "evidence": body,
                    }
                )
            )
        return {
            "preflight": self.preflight,
            "prior_plan": self.prior,
            "replacement_plan": self.replacement,
            "authority_evidence": tuple(evidence),
            "expected_plan_version": 1,
        }

    def seed_replay(self) -> CollaborationPlanReplacementCommitReceipt:
        arguments = self.arguments()
        evidence = arguments["authority_evidence"]
        request = {
            "domain": REPLACEMENT_REQUEST_DOMAIN,
            "authority_evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "evidence_sha256": item.evidence_sha256,
                    "requirement_id": item.requirement_id,
                }
                for item in sorted(evidence, key=lambda item: item.requirement_id)
            ],
            "expected_plan_version": 1,
            "mission_id": self.prior.mission_id,
            "preflight_id": self.preflight.preflight_id,
            "preflight_sha256": self.preflight.preflight_sha256,
            "prior_plan_id": self.prior.plan_id,
            "prior_plan_sha256": self.prior.content_sha256,
            "replacement_plan_id": self.replacement.plan_id,
            "replacement_plan_sha256": self.replacement.content_sha256,
        }
        preflight_document = self.preflight.to_dict()
        body = {
            "schema_version": 1,
            "request_sha256": digest(request),
            "mission_id": self.prior.mission_id,
            "preflight_id": self.preflight.preflight_id,
            "preflight_sha256": self.preflight.preflight_sha256,
            "predecessor_plan_id": self.prior.plan_id,
            "predecessor_plan_sha256": self.prior.content_sha256,
            "replacement_plan_id": self.replacement.plan_id,
            "replacement_plan_sha256": self.replacement.content_sha256,
            "predecessor_plan_version": 1,
            "replacement_plan_version": 2,
            "mission_revision": 1,
            "source_snapshot_hashes": {
                key: value
                for key, value in preflight_document["source_state"].items()
                if key.endswith("snapshot_sha256")
            },
            "authority_count": len(evidence),
            "source_settlement_count": len(self.prior.work_items),
            "completed_carry_forward_count": 0,
            "work_initialization_count": len(self.replacement.work_items),
            "committed_at": "2026-08-03T00:03:00Z",
            "commit_status": "committed_active",
        }
        receipt_sha256 = digest({"domain": REPLACEMENT_RECEIPT_DOMAIN, "receipt": body})
        receipt = CollaborationPlanReplacementCommitReceipt.from_dict(
            {
                **body,
                "replacement_commit_id": "CPR-"
                + receipt_sha256.removeprefix("sha256:")[:32].upper(),
                "receipt_sha256": receipt_sha256,
            }
        )
        self.connection.executescript(
            """
            PRAGMA user_version = 30;
            CREATE TABLE collaboration_plan_replacement_commits (
                replacement_commit_id TEXT, mission_id TEXT, preflight_id TEXT,
                preflight_json TEXT, request_sha256 TEXT, receipt_json TEXT,
                receipt_sha256 TEXT
            );
            CREATE TABLE collaboration_plan_replacement_authorities (
                replacement_commit_id TEXT, requirement_id TEXT, evidence_json TEXT
            );
            CREATE TABLE collaboration_plan_replacement_authentications (preflight_id TEXT);
            CREATE TABLE collaboration_plan_active_heads (
                mission_id TEXT, replacement_commit_id TEXT
            );
            """
        )
        self.connection.execute(
            "INSERT INTO collaboration_plan_replacement_commits VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                receipt.replacement_commit_id,
                self.prior.mission_id,
                self.preflight.preflight_id,
                canonical_json(self.preflight.to_dict()),
                body["request_sha256"],
                canonical_json(receipt.to_dict()),
                receipt.receipt_sha256,
            ),
        )
        self.connection.execute(
            "INSERT INTO collaboration_plan_active_heads VALUES (?, ?)",
            (self.prior.mission_id, receipt.replacement_commit_id),
        )
        return receipt

    def test_arbitrary_verifier_denied_before_serialization_or_store_on_every_schema(self) -> None:
        for version in (29, AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION, SCHEMA_VERSION):
            with self.subTest(version=version):
                self.connection.execute(f"PRAGMA user_version = {version}")
                verifier = mock.Mock()
                preflight = mock.Mock()
                with mock.patch.object(self.store, "_write_connection") as write:
                    with self.assertRaisesRegex(PrincipalAuthenticationError, "authenticated"):
                        self.service(verifier).replace(
                            **{**self.arguments(), "preflight": preflight}
                        )
                write.assert_not_called()
                preflight.to_dict.assert_not_called()
                verifier.verify.assert_not_called()

    def test_exact_verifier_family_and_method_required(self) -> None:
        class VerifierSubclass(_TransactionScopedReplacementAuthorityVerifier):
            pass

        verifier = self.verifier()
        for invalid in (
            object.__new__(VerifierSubclass),
            object.__new__(_TransactionScopedReplacementAuthorityVerifier),
        ):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaises(PrincipalAuthenticationError):
                    self.service(invalid).replace(**self.arguments())
        verifier.verify = mock.Mock()
        with self.assertRaises(PrincipalAuthenticationError):
            self.service(verifier).replace(**self.arguments())
        verifier.verify.assert_not_called()

    def test_store_and_registry_binding_are_instance_exact(self) -> None:
        for name, replacement in (("_store", object()), ("_registry", object())):
            with self.subTest(name=name):
                verifier = self.verifier()
                setattr(verifier, name, replacement)
                with mock.patch.object(self.store, "_write_connection") as write:
                    with self.assertRaises(PrincipalAuthenticationError):
                        self.service(verifier).replace(**self.arguments())
                write.assert_not_called()

    def test_readdressed_distinct_preflight_denied_before_transaction(self) -> None:
        document = self.preflight.to_dict()
        document["source_state"]["observed_at"] = "2026-08-03T00:04:00Z"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        document["preflight_sha256"] = digest({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        document["preflight_id"] = (
            "PRF-" + document["preflight_sha256"].removeprefix("sha256:")[:32].upper()
        )
        stale = CollaborationPlanReplacementPreflight.from_dict(document)
        with mock.patch.object(self.store, "_write_connection") as write:
            with self.assertRaisesRegex(PrincipalAuthenticationError, "preflight"):
                self.service(self.verifier(preflight=stale)).replace(**self.arguments())
        write.assert_not_called()

    def test_consumed_or_malformed_transaction_adapter_denied_before_write(self) -> None:
        for field, value in (
            ("_connection_identity", 1),
            ("_consumed_at", "2026-08-03T00:03:00Z"),
            ("_prepared", True),
            ("_used_requirements", {"already-used"}),
            ("_used_requirements", []),
        ):
            with self.subTest(field=field, value=value):
                verifier = self.verifier()
                setattr(verifier, field, value)
                with mock.patch.object(self.store, "_write_connection") as write:
                    with self.assertRaises(PrincipalAuthenticationError):
                        self.service(verifier).replace(**self.arguments())
                write.assert_not_called()

    def test_schema29_denied_before_exact_replay_lookup(self) -> None:
        self.connection.execute("PRAGMA user_version = 29")
        statements = []
        self.connection.set_trace_callback(statements.append)
        with mock.patch.object(
            self.store, "_write_connection", return_value=nullcontext(self.connection)
        ):
            with self.assertRaisesRegex(StoreIntegrityError, "schema30"):
                self.service(self.verifier()).replace(**self.arguments())
        self.assertEqual(statements, ["PRAGMA user_version"])

    def test_current_schema_and_byte_identical_preflight_clone_accept_binding(self) -> None:
        clone = CollaborationPlanReplacementPreflight.from_dict(self.preflight.to_dict())
        verifier = self.verifier(preflight=clone)
        for version in (AUTHENTICATED_PLAN_REPLACEMENT_SCHEMA_VERSION, SCHEMA_VERSION):
            with self.subTest(version=version):
                self.connection.execute(f"PRAGMA user_version = {version}")
                self.service(verifier)._require_replacement_transaction(
                    self.connection, self.preflight
                )

    def test_exact_unsigned_replay_denied_without_calling_adapter(self) -> None:
        self.seed_replay()
        verifier = self.verifier()
        with (
            mock.patch.object(
                self.store, "_write_connection", return_value=nullcontext(self.connection)
            ),
            mock.patch.object(verifier, "_prepare") as prepare,
        ):
            with self.assertRaisesRegex(StoreIntegrityError, "signed authority custody"):
                self.service(verifier).replace(**self.arguments())
        prepare.assert_not_called()
        self.assertEqual(verifier._used_requirements, set())

    def test_exact_replay_requires_target_signed_custody_hook(self) -> None:
        receipt = self.seed_replay()
        with (
            mock.patch.object(
                self.store, "_write_connection", return_value=nullcontext(self.connection)
            ),
            mock.patch(
                "sunderkey.collaboration_plan_replacement_store._verify_authenticated_replacement_custody"
            ) as verify_custody,
            mock.patch(
                "sunderkey.authenticated_collaboration_plan_replacement._verify_authenticated_replacement_replay_state"
            ) as verify_replay,
        ):
            actual = self.service(self.verifier()).replace(**self.arguments())
        self.assertEqual(actual, receipt)
        self.assertTrue(verify_custody.call_args.kwargs["require_signed"])
        self.assertEqual(verify_custody.call_args.kwargs["preflight"], self.preflight)
        verify_replay.assert_called_once()
        self.assertIs(verify_replay.call_args.kwargs["store"], self.store)
        self.assertIs(verify_replay.call_args.kwargs["registry"], self.registry)

    def test_target_commit_and_canonical_preflight_binding_required(self) -> None:
        receipt = self.seed_replay()
        service = self.service(self.verifier())
        self.connection.execute(
            "UPDATE collaboration_plan_replacement_commits SET preflight_json = '{}'"
        )
        with self.assertRaisesRegex(StoreIntegrityError, "preflight"):
            service._verify_replacement_target(self.connection, self.preflight, receipt)
        self.connection.execute("DELETE FROM collaboration_plan_replacement_commits")
        with self.assertRaisesRegex(StoreIntegrityError, "target custody"):
            service._verify_replacement_target(self.connection, self.preflight, receipt)

    def test_replayed_transaction_adapter_cannot_be_reused(self) -> None:
        receipt = self.seed_replay()
        verifier = self.verifier()
        service = self.service(verifier)
        with (
            mock.patch.object(
                self.store, "_write_connection", return_value=nullcontext(self.connection)
            ),
            mock.patch(
                "sunderkey.collaboration_plan_replacement_store._verify_authenticated_replacement_custody"
            ),
            mock.patch(
                "sunderkey.authenticated_collaboration_plan_replacement._verify_authenticated_replacement_replay_state"
            ) as replay,
        ):
            self.assertEqual(service.replace(**self.arguments()), receipt)
            with self.assertRaises(PrincipalAuthenticationError):
                service.replace(**self.arguments())
        replay.assert_called_once()
        self.assertEqual(verifier._connection_identity, id(self.connection))

    def test_historical_get_does_not_consume_or_require_new_authentication(self) -> None:
        receipt = self.seed_replay()
        self.connection.execute("PRAGMA user_version = 29")
        verifier = mock.Mock()
        with mock.patch.object(
            self.store, "_read_connection", return_value=nullcontext(self.connection)
        ):
            self.assertEqual(self.service(verifier).get(self.prior.mission_id), receipt)
        verifier.verify.assert_not_called()

    def test_historical_optional_custody_remains_distinct_from_runtime(self) -> None:
        self.seed_replay()
        arguments = {
            "commit": {},
            "preflight": self.preflight,
            "authorities": [{"evidence_json": '{"historical":true}'}],
            "registry": self.registry,
        }
        _verify_authenticated_replacement_custody(self.connection, **arguments)
        with self.assertRaisesRegex(StoreIntegrityError, "signed authority custody"):
            _verify_authenticated_replacement_custody(
                self.connection, **arguments, require_signed=True
            )

    def test_runtime_delegates_only_after_fresh_authenticated_binding(self) -> None:
        with mock.patch.object(
            _CollaborationPlanReplacementAtomicStore, "replace", return_value="sealed-delegation"
        ) as atomic:
            result = self.service(self.verifier()).replace(**self.arguments())
        self.assertEqual(result, "sealed-delegation")
        atomic.assert_called_once_with(**self.arguments())

    def test_existing_signed_bundle_preserves_authenticated_runtime_composition(self) -> None:
        fixture = authority_fixture.CollaborationPlanReplacementAuthenticationPhase186CTests(
            methodName="runTest"
        )
        fixture.setUpClass()
        fixture.setUp()
        bundle = fixture._authenticate()
        with mock.patch.object(
            _CollaborationPlanReplacementAtomicStore, "replace", return_value="signed-composition"
        ) as atomic:
            result = AuthenticatedCollaborationPlanReplacementStoreService(
                self.store, self.registry
            ).replace(
                preflight=fixture.preflight,
                prior_plan=fixture.prior_plan,
                replacement_plan=fixture.replacement_plan,
                verified_authority_plan=fixture.verified_authority_plan,
                authority_upgrade=fixture.upgrade,
                authenticated_bundle=bundle,
                credentials=fixture.credentials,
                expected_plan_version=1,
            )
        self.assertEqual(result, "signed-composition")
        self.assertEqual(
            len(atomic.call_args.kwargs["authority_evidence"]), bundle.requirement_count
        )

    def test_normalization_uses_exact_requested_count_and_bounds_credential_iteration(self) -> None:
        fixture = authority_fixture.CollaborationPlanReplacementAuthenticationPhase186CTests(
            methodName="runTest"
        )
        fixture.setUpClass()
        fixture.setUp()
        credentials = fixture.credentials
        additional = replace(
            credentials[0],
            source_requirement_id="PAR-" + "F" * 32,
            upgraded_requirement_id="PRA-" + "F" * 32,
            replay_key_sha256="sha256:" + "f" * 64,
        )
        # Normalization is not authentication: this synthetic extra source is
        # accepted only at the supplied count and cannot pass source composition.
        expanded = (*credentials, additional)
        self.assertEqual(
            len(_normalize_credentials(expanded, requirement_count=len(expanded))), len(expanded)
        )
        with self.assertRaises(PrincipalAuthenticationError):
            _normalize_credentials(expanded, requirement_count=len(credentials))
        visits = []

        def unbounded():
            while True:
                visits.append(None)
                yield credentials[0]

        with self.assertRaises(PrincipalAuthenticationError):
            _normalize_credentials(unbounded(), requirement_count=len(credentials))
        self.assertEqual(len(visits), len(credentials) + 1)


if __name__ == "__main__":
    unittest.main()

"""Synthetic signed repository metadata custody and current-use regressions."""

from __future__ import annotations

import copy
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.authenticated import AuthenticatedMissionControlService
from sunderkey.authenticated_provider_evidence_repository import (
    AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt,
    AuthenticatedProviderEvidenceRepositoryService,
    ProviderEvidenceRepositoryPrincipalCommit,
)
from sunderkey.collaboration_executor_provider_evidence import VERIFICATION_DOMAIN
from sunderkey.errors import (
    MissionStoppedError,
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreIntegrityError,
    StoreMigrationRequiredError,
)
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrantRevocation,
    TrustKeyUse,
    compute_operation_intent_hash,
)
from sunderkey.mission_store_target_health_gate import MissionStoreTargetHealthGateService
from sunderkey.provider_evidence_repository import (
    INGEST_REQUEST_DOMAIN,
    ProviderEvidenceRepositoryIngestRequest,
)
from sunderkey.provider_evidence_repository_authentication import (
    provider_evidence_repository_ingest_receipt_selection_sha256,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.scope import (
    ScopeGrantAcceptanceService,
    ScopeGrantRevocationAcceptanceService,
)
from sunderkey.store import MissionStore, canonical_json, format_timestamp, sha256_text
from sunderkey.target_health_custody import SQLiteTargetHealthCustody
from sunderkey.target_health_custody_contracts import execution_binding_sha256

from . import test_authorized_target_health_runtime_phase175 as phase175
from . import test_mission_store_target_health_gate_phase199 as phase199
from . import test_provider_evidence_repository_authentication_phase149 as phase149
from . import test_target_health_custody_phase198 as phase198
from .test_identity_phase4 import AUDIENCE, ZERO_SIGNATURE, b64url, public_bytes
from .test_store import remove_schema_v39_objects

OPERATION = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
CONTROL_SUBJECT = "service:repository-control.synthetic-001"
REVOCATION_ISSUER = "repository-revocation.synthetic"
REVOCATION_KEY_ID = "key:repository-revocation.synthetic"
TABLE = "provider_evidence_repository_ingest_authentications"


def repository_service_fixture(test: unittest.TestCase, *, accept_scope: bool = True):
    """Reuse real Phase149 lineage, with explicitly provisioned synthetic authority."""
    fixture = phase149.ProviderEvidenceRepositoryAuthenticationPhase149Tests(methodName="runTest")
    fixture.setUp()
    test.addCleanup(fixture.doCleanups)
    root = fixture.root
    fixture.revocation_private = Ed25519PrivateKey.generate()
    raw = root.factory.policy(
        policy_version=phase149.POLICY_VERSION,
        store_id=root.store_id,
        max_scope_lifetime_seconds=600,
        max_assertion_lifetime_seconds=300,
        allowed_profiles=[phase149.PROFILE_ID],
        allowed_subjects=sorted([phase149.SUBJECT, CONTROL_SUBJECT]),
        allowed_operations=[OPERATION.value, PrincipalOperation.MISSION_STOP.value],
    ).to_dict()
    raw["keys"].append(
        {
            "key_id": REVOCATION_KEY_ID,
            "issuer": REVOCATION_ISSUER,
            "public_key": b64url(public_bytes(fixture.revocation_private)),
            "key_use": TrustKeyUse.SCOPE_GRANT_REVOCATION.value,
            "state": "active",
            "not_before": "2026-07-30T09:00:00Z",
            "not_after": "2026-07-30T12:00:00Z",
            "retire_at": None,
            "allowed_profiles": [phase149.PROFILE_ID],
            "allowed_subjects": [phase149.SUBJECT],
            "allowed_operations": [OPERATION.value],
        }
    )
    raw["keys"].sort(key=lambda item: item["key_id"])
    raw["signature"] = ZERO_SIGNATURE
    unsigned = PrincipalTrustPolicy.from_dict(raw)
    fixture.repository_policy = replace(
        unsigned,
        signature=b64url(root.factory.root_private.sign(unsigned.signing_bytes())),
    )
    root.now = datetime(2026, 7, 30, 10, 8, 40, tzinfo=UTC)
    root.trust.apply_policy(fixture.repository_policy)
    fixture.stop_grant = repository_grant(
        fixture,
        token="97",
        subject=CONTROL_SUBJECT,
        operation=PrincipalOperation.MISSION_STOP,
    )
    root.now += timedelta(seconds=1)
    acceptance = ScopeGrantAcceptanceService(root.store, root.registry)
    if accept_scope:
        acceptance.accept(fixture.scope.grant)
    acceptance.accept(fixture.stop_grant)
    root.now = fixture.now
    fixture.service = AuthenticatedProviderEvidenceRepositoryService(
        root.store,
        root.registry,
        repository_principal_subject=phase149.SUBJECT,
        repository_principal_profile_id=phase149.PROFILE_ID,
        clock=lambda: fixture.now,
    )
    return fixture


def repository_grant(
    fixture,
    *,
    token: str,
    subject: str = phase149.SUBJECT,
    operation: PrincipalOperation = OPERATION,
    expires_at: str = "2026-07-30T10:11:40Z",
):
    root = fixture.root
    mission = root.mission
    return root.factory.grant(
        grant_id="SGR-" + token * 16,
        profile_id=phase149.PROFILE_ID,
        subject=subject,
        store_id=root.store_id,
        mission_id=mission.mission_id,
        mission_context_hash=root.stored.context_hash,
        scope_reference=mission.scope_reference,
        scope_document_hash=mission.scope_document_hash,
        environment=mission.environment.value,
        max_action_tier=mission.max_action_tier.value,
        constraints_hash=sha256_text(canonical_json(mission.to_dict()["constraints"])),
        operations=[operation.value],
        policy_version=phase149.POLICY_VERSION,
        issued_at="2026-07-30T10:08:40Z",
        not_before="2026-07-30T10:08:40Z",
        expires_at=expires_at,
    )


def repository_assertion(
    fixture,
    *,
    token: str = "98",
    request=None,
    receipt=None,
    lifecycle=None,
    grant=None,
    expires_at: str = "2026-07-30T10:10:00Z",
):
    request = fixture.request if request is None else request
    receipt = fixture.receipt if receipt is None else receipt
    lifecycle = fixture.lifecycle if lifecycle is None else lifecycle
    grant = fixture.scope.grant if grant is None else grant
    intent = {
        "ingest_receipt_selection_sha256": (
            provider_evidence_repository_ingest_receipt_selection_sha256(receipt)
        ),
        "ingest_request_sha256": request.request_sha256,
        "lifecycle_policy_sha256": lifecycle.policy_sha256,
        "mission_id": fixture.root.mission.mission_id,
        "principal_profile_id": phase149.PROFILE_ID,
    }
    return fixture.root.factory.assertion(
        grant=grant,
        assertion_id="PAS-" + token * 16,
        policy_version=phase149.POLICY_VERSION,
        scope_grant_id=grant.grant_id,
        subject=grant.subject,
        profile_id=phase149.PROFILE_ID,
        audience=AUDIENCE,
        store_id=fixture.root.store_id,
        mission_id=fixture.root.mission.mission_id,
        operation=OPERATION,
        operation_intent_sha256=compute_operation_intent_hash(OPERATION, intent),
        issued_at="2026-07-30T10:08:46Z",
        not_before="2026-07-30T10:08:46Z",
        expires_at=expires_at,
    )


def logical_store(fixture) -> tuple:
    with closing(sqlite3.connect(fixture.root.path)) as connection:
        return connection.execute("PRAGMA user_version").fetchone()[0], tuple(connection.iterdump())


def _address(document, domain, body_name, id_name, hash_name, prefix):
    body = {key: value for key, value in document.items() if key not in {id_name, hash_name}}
    digest = _canonical_sha256({"domain": domain, body_name: body})
    document[id_name] = prefix + digest.removeprefix("sha256:")[:32].upper()
    document[hash_name] = digest


def repository_counts(fixture) -> tuple[int, int, int, int, int]:
    with closing(sqlite3.connect(fixture.root.path)) as connection:
        return (
            connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM principal_assertion_uses").fetchone()[0],
            connection.execute("SELECT COUNT(*) FROM principal_assertion_effects").fetchone()[0],
            connection.execute(
                "SELECT COUNT(*) FROM executor_invocation_provider_report_authentications"
            ).fetchone()[0],
            connection.execute(
                "SELECT assertion_count FROM mission_principal_ledgers WHERE mission_id = ?",
                (fixture.root.mission.mission_id,),
            ).fetchone()[0],
        )


def repository_revocation(fixture) -> ScopeGrantRevocation:
    grant = fixture.scope.grant
    raw = {
        "schema_version": 1,
        "revocation_id": "SRV-" + "98" * 16,
        "policy_id": fixture.repository_policy.policy_id,
        "policy_version": fixture.repository_policy.policy_version,
        "issuer": REVOCATION_ISSUER,
        "key_id": REVOCATION_KEY_ID,
        "audience": AUDIENCE,
        "store_id": fixture.root.store_id,
        "mission_id": fixture.root.mission.mission_id,
        "mission_context_hash": fixture.root.stored.context_hash,
        "scope_grant_issuer": grant.issuer,
        "scope_grant_id": grant.grant_id,
        "scope_grant_sha256": grant.content_sha256,
        "scope_grant_subject": grant.subject,
        "scope_grant_profile_id": grant.profile_id,
        "reason_code": "authorization_withdrawn",
        "reason": "Synthetic repository authority withdrawn for this regression.",
        "issued_at": format_timestamp(fixture.now),
        "not_before": format_timestamp(fixture.now),
        "expires_at": "2026-07-30T10:10:00Z",
        "signature": ZERO_SIGNATURE,
    }
    unsigned = ScopeGrantRevocation.from_dict(raw)
    return replace(
        unsigned,
        signature=b64url(fixture.revocation_private.sign(unsigned.signing_bytes())),
    )


def repository_health_fixture(fixture, *, state: str):
    """Create only a genuine signed synthetic local health latch, not an observation."""
    source = phase175.AuthorizedTargetHealthRuntimePhase175Tests(methodName="runTest")
    source.setUp()
    binding = replace(source.binding, context_id=fixture.root.mission.mission_id)
    receipt = phase199._rebound_receipt(binding, state=state)
    factory = phase198.ContractFactory(mission_id=fixture.root.mission.mission_id)
    factory.binding = binding
    factory.binding_sha256 = execution_binding_sha256(binding)
    factory.root = replace(
        factory.root,
        tenant_id=binding.tenant_id,
        effective_at="2026-09-19T00:00:00Z",
        expires_at="2026-09-21T00:00:00Z",
        trust_root_id="",
        trust_root_sha256="",
    )
    clock = phase198.FixedClock("2026-09-20T12:00:10Z")
    custody = SQLiteTargetHealthCustody(
        fixture.root.path.parent / "repository-health.synthetic.sqlite3",
        trust_root=factory.root,
        trusted_clock=clock,
    )
    policy = factory.make_policy(
        issued_at="2026-09-19T10:59:00Z",
        effective_at="2026-09-19T11:00:00Z",
        expires_at="2026-09-20T18:00:00Z",
        runtime_policy_id=receipt.runtime_policy_id,
        runtime_policy_sha256=receipt.runtime_policy_sha256,
    )
    custody.publish_policy(policy)
    envelope = factory.make_envelope(
        policy,
        sequence=1,
        observed_at=receipt.observed_at,
        monotonic_tick=receipt.monotonic_tick,
        receipt=receipt,
    )
    custody.append_envelope(envelope)
    service = MissionStoreTargetHealthGateService(
        fixture.root.store, custody, fixture.root.registry, clock=lambda: clock.value
    )
    service.initialize()
    service.observe_current(binding)
    return binding, factory, policy, envelope, custody, clock, service


class AuthenticatedProviderEvidenceRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = repository_service_fixture(self)

    def _authenticate(self, **changes):
        fixture = self.fixture
        values = {
            "request": fixture.request,
            "receipt": fixture.receipt,
            "lifecycle_policy": fixture.lifecycle,
            "repository_assertion": fixture.assertion,
        }
        values.update(changes)
        return fixture.service.authenticate(**values)

    def _tick(self, seconds: int = 1) -> None:
        self.fixture.now += timedelta(seconds=seconds)
        self.fixture.root.now = self.fixture.now

    def test_genuine_commit_is_atomic_durable_metadata_only(self) -> None:
        before = repository_counts(self.fixture)
        receipt = self._authenticate()
        after = repository_counts(self.fixture)
        self.assertEqual(after, (1, before[1] + 1, before[2] + 1, before[3], before[4] + 1))
        document = receipt.to_dict()
        self.assertEqual(document["evidence_custody_status"], "provider_report_only")
        self.assertEqual(document["current_authority_status"], "not_verified")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["qualification_effect"], "none")
        self.assertEqual(
            document["repository_ingest_authentication"]["ingest_request"],
            self.fixture.request.to_dict(),
        )
        reopened = AuthenticatedProviderEvidenceRepositoryService(
            MissionStore(self.fixture.root.path),
            self.fixture.root.registry,
            repository_principal_subject=phase149.SUBJECT,
            repository_principal_profile_id=phase149.PROFILE_ID,
            clock=mock.Mock(side_effect=AssertionError("historical read invoked live clock")),
        )
        self.assertEqual(reopened.get(receipt.authentication_id), receipt)
        self.fixture.root.store.verify_store(self.fixture.root.registry)

    def test_later_live_replay_returns_original_identity_without_mutation(self) -> None:
        receipt = self._authenticate()
        before = logical_store(self.fixture)
        self._tick()
        retry = self._authenticate()
        self.assertEqual(retry, receipt)
        self.assertEqual(retry.authentication_id, receipt.authentication_id)
        self.assertEqual(retry.authenticated_at, "2026-07-30T10:08:50Z")
        self.assertEqual(logical_store(self.fixture), before)

    def test_source_scope_use_and_insert_share_the_same_transaction(self) -> None:
        fixture = self.fixture
        store = fixture.root.store
        policy = fixture.service._policy
        observed = []

        def monitor(original):
            def call(connection, *args, **kwargs):
                self.assertTrue(connection.in_transaction)
                observed.append(connection)
                return original(connection, *args, **kwargs)

            return call

        with (
            mock.patch.object(
                store,
                "_resolve_provider_evidence_repository_ingest_sources",
                side_effect=monitor(store._resolve_provider_evidence_repository_ingest_sources),
            ),
            mock.patch.object(
                policy, "_verified_scope", side_effect=monitor(policy._verified_scope)
            ),
            mock.patch.object(
                policy, "_record_assertion", side_effect=monitor(policy._record_assertion)
            ),
            mock.patch.object(
                store,
                "_insert_provider_evidence_repository_ingest_authentication",
                side_effect=monitor(
                    store._insert_provider_evidence_repository_ingest_authentication
                ),
            ),
        ):
            self._authenticate()
        self.assertEqual(len(observed), 4)
        self.assertTrue(all(connection is observed[0] for connection in observed))

    def test_signed_policy_rotation_denies_current_replay_not_original_history(self) -> None:
        receipt = self._authenticate()
        self._tick()
        self.assertEqual(self._authenticate(), receipt)
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
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)
        self.fixture.root.store.verify_store(self.fixture.root.registry)

    def test_every_readdressed_epv_projection_requires_same_store_source(self) -> None:
        before = logical_store(self.fixture)
        fields = (
            "report_authentication_id",
            "report_authentication_sha256",
            "report_custody_id",
            "report_custody_sha256",
            "attempt_id",
            "acknowledgement_id",
            "acknowledgement_sha256",
            "provider_evidence_sha256",
        )
        for index, field in enumerate(fields):
            document = self.fixture.request.to_dict()
            verification = document["evidence_verification"]
            old = verification[field]
            verification[field] = (
                "sha256:" + "01" * 32 if field.endswith("sha256") else old[:4] + "01" * 16
            )
            _address(
                verification,
                VERIFICATION_DOMAIN,
                "provider_evidence_verification",
                "verification_id",
                "verification_sha256",
                "EPV-",
            )
            document["content_address"] = verification["provider_evidence_sha256"]
            _address(
                document,
                INGEST_REQUEST_DOMAIN,
                "ingest_request",
                "request_id",
                "request_sha256",
                "EIR-",
            )
            request = ProviderEvidenceRepositoryIngestRequest.from_dict(document)
            response = self.fixture._receipt(request)
            assertion = repository_assertion(
                self.fixture, token=f"{0xB0 + index:02X}", request=request, receipt=response
            )
            with (
                self.subTest(field=field),
                mock.patch.object(
                    self.fixture.service,
                    "_clock",
                    side_effect=AssertionError("foreign projection reached clock"),
                ) as clock,
                self.assertRaises(StoreIntegrityError),
            ):
                self._authenticate(
                    request=request, receipt=response, repository_assertion=assertion
                )
            clock.assert_not_called()
            self.assertEqual(logical_store(self.fixture), before)

    def test_schema38_requires_migration_before_publication(self) -> None:
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            remove_schema_v39_objects(connection)
            connection.execute(
                "UPDATE store_metadata SET value = '38' WHERE key = 'schema_version'"
            )
            connection.execute("PRAGMA user_version = 38")
            connection.commit()
        before = logical_store(self.fixture)
        with self.assertRaises(StoreMigrationRequiredError):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)

    def test_assertion_expiry_denies_live_replay_but_preserves_historical_get(self) -> None:
        receipt = self._authenticate()
        self._tick()
        self.assertEqual(self._authenticate(), receipt)
        self._tick(70)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)
        self.fixture.root.store.verify_store(self.fixture.root.registry)

    def test_request_expiry_denies_live_replay_without_erasing_history(self) -> None:
        request = self.fixture._request(self.fixture.lifecycle, expires_at="2026-07-30T10:08:52Z")
        response = self.fixture._receipt(request)
        assertion = repository_assertion(self.fixture, request=request, receipt=response)
        args = {"request": request, "receipt": response, "repository_assertion": assertion}
        receipt = self._authenticate(**args)
        self._tick()
        self.assertEqual(self._authenticate(**args), receipt)
        self._tick(2)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "ingest window"):
            self._authenticate(**args)
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)

    def test_scope_expiry_denies_live_replay_without_erasing_history(self) -> None:
        grant = repository_grant(self.fixture, token="F1", expires_at="2026-07-30T10:08:52Z")
        ScopeGrantAcceptanceService(self.fixture.root.store, self.fixture.root.registry).accept(
            grant
        )
        assertion = repository_assertion(
            self.fixture, grant=grant, expires_at="2026-07-30T10:08:52Z"
        )
        receipt = self._authenticate(repository_assertion=assertion)
        self._tick()
        self.assertEqual(self._authenticate(repository_assertion=assertion), receipt)
        self._tick(2)
        before = logical_store(self.fixture)
        with (
            mock.patch(
                "sunderkey.authenticated_provider_evidence_repository.authenticate_provider_evidence_repository_ingest_receipt",
                side_effect=AssertionError("expired scope reached principal producer"),
            ) as producer,
            self.assertRaisesRegex(PrincipalAuthenticationError, "expired"),
        ):
            self._authenticate(repository_assertion=assertion)
        producer.assert_not_called()
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)

    def test_actual_scope_revocation_denies_live_replay_without_policy_rotation(self) -> None:
        receipt = self._authenticate()
        policy_hash = self.fixture.root.trust.status().policy_hash
        self._tick()
        self.assertEqual(self._authenticate(), receipt)
        self._tick()
        ScopeGrantRevocationAcceptanceService(
            self.fixture.root.store, self.fixture.root.registry
        ).accept(repository_revocation(self.fixture))
        self.assertEqual(self.fixture.root.trust.status().policy_hash, policy_hash)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)
        self.fixture.root.store.verify_store(self.fixture.root.registry)

    def test_authenticated_stop_denies_fresh_and_replay_publication_not_historical_get(
        self,
    ) -> None:
        receipt = self._authenticate()
        self._tick()
        self.assertEqual(self._authenticate(), receipt)
        self._tick()
        fixture = self.fixture
        arguments = {
            "reason_code": "operator_request",
            "reason": "Synthetic metadata mission stopped for this regression.",
            "risk": "No further positive publication is authorized.",
            "decision_owner": "synthetic-range-control",
            "idempotency_key": "repository-service-synthetic-stop",
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
            assertion_id="PAS-" + "99" * 16,
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
        before = logical_store(fixture)
        for candidate in (fixture.assertion, repository_assertion(fixture, token="A2")):
            with (
                self.subTest(assertion=candidate.assertion_id),
                self.assertRaises(MissionStoppedError),
            ):
                self._authenticate(repository_assertion=candidate)
        self.assertEqual(logical_store(fixture), before)
        self.assertEqual(fixture.service.get(receipt.authentication_id), receipt)

    def test_recorded_paused_latch_denies_both_positive_paths(self) -> None:
        receipt = self._authenticate()
        self._tick()
        self.assertEqual(self._authenticate(), receipt)
        repository_health_fixture(self.fixture, state="rejected")
        before = logical_store(self.fixture)
        for candidate in (self.fixture.assertion, repository_assertion(self.fixture, token="A2")):
            with (
                self.subTest(assertion=candidate.assertion_id),
                self.assertRaisesRegex(StoreConflictError, "health latch"),
            ):
                self._authenticate(repository_assertion=candidate)
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)

    def test_recorded_recovery_pending_latch_denies_positive_replay(self) -> None:
        receipt = self._authenticate()
        binding, factory, policy, first, custody, clock, service = repository_health_fixture(
            self.fixture, state="rejected"
        )
        healthy = phase199._rebound_receipt(binding, state="healthy")
        healthy = replace(
            healthy,
            observed_at=format_timestamp(
                datetime.fromisoformat(first.observed_at.replace("Z", "+00:00"))
                + timedelta(seconds=1)
            ),
            monotonic_tick=first.receipt.monotonic_tick + 1,
            receipt_id="",
            receipt_sha256="",
        )
        envelope = factory.make_envelope(
            policy,
            sequence=2,
            observed_at=healthy.observed_at,
            monotonic_tick=healthy.monotonic_tick,
            predecessor=first,
            receipt=healthy,
        )
        clock.value += timedelta(seconds=1)
        custody.append_envelope(envelope)
        service.observe_current(binding)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(StoreConflictError, "health latch"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)

    def test_runtime_clock_cannot_precede_valid_local_health_head(self) -> None:
        receipt = self._authenticate()
        repository_health_fixture(self.fixture, state="healthy")
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "local mission health state"):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)
        self.assertEqual(self.fixture.service.get(receipt.authentication_id), receipt)

    def test_all_four_report_outcomes_remain_metadata_only(self) -> None:
        for token, outcome in zip(
            ("A3", "A4", "A5", "A6"),
            ("accepted", "already_exists_same_digest", "rejected", "failed"),
            strict=True,
        ):
            with self.subTest(outcome=outcome):
                response = self.fixture._receipt(self.fixture.request, outcome=outcome)
                assertion = repository_assertion(self.fixture, token=token, receipt=response)
                receipt = self._authenticate(receipt=response, repository_assertion=assertion)
                document = receipt.to_dict()
                self.assertEqual(
                    document["repository_ingest_authentication"]["ingest_receipt"]["outcome"],
                    outcome,
                )
                self.assertEqual(document["evidence_custody_status"], "provider_report_only")
                self.assertEqual(
                    document["repository_control_status"],
                    "provider_assertions_not_independently_verified",
                )
        self.assertEqual(repository_counts(self.fixture)[0], 4)

    def test_consumed_assertion_cannot_be_rebound_to_another_receipt(self) -> None:
        self._authenticate()
        before = logical_store(self.fixture)
        response = self.fixture._receipt(
            self.fixture.request, object_version_id="version.synthetic-other"
        )
        with self.assertRaises(StoreConflictError):
            self._authenticate(receipt=response)
        self.assertEqual(logical_store(self.fixture), before)

    def test_clock_mutation_cannot_rebind_owned_publication_inputs(self) -> None:
        fixture = self.fixture
        originals = {
            "ingest_request": fixture.request.to_dict(),
            "ingest_receipt": fixture.receipt.to_dict(),
            "lifecycle_policy": fixture.lifecycle.to_dict(),
            "repository_assertion": fixture.assertion.to_dict(),
        }

        def mutate():
            for wrapper in (fixture.request, fixture.receipt, fixture.lifecycle):
                object.__setattr__(wrapper, "document_json", "{" + " " * 2_000_000)
            object.__setattr__(fixture.assertion, "subject", "service:substituted.synthetic")
            object.__setattr__(fixture.assertion, "policy_version", True)
            return fixture.now

        fixture.service._clock = mutate
        receipt = self._authenticate()
        document = receipt.to_dict()["repository_ingest_authentication"]
        for key in ("ingest_request", "ingest_receipt", "lifecycle_policy"):
            self.assertEqual(document[key], originals[key])
        self.assertEqual(
            document["repository_attestor"]["subject"], originals["repository_assertion"]["subject"]
        )
        self.assertEqual(fixture.service.get(receipt.authentication_id), receipt)

    def test_native_assertion_and_wrapper_aliases_reject_before_store_or_clock(self) -> None:
        class StringAlias(str):
            pass

        class IntegerAlias(int):
            pass

        cases = []
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("schema_version", IntegerAlias(1)),
            ("policy_version", True),
            ("policy_version", float(phase149.POLICY_VERSION)),
            ("subject", StringAlias(phase149.SUBJECT)),
            ("assertion_id", StringAlias(self.fixture.assertion.assertion_id)),
            ("signature", StringAlias(self.fixture.assertion.signature)),
        ):
            assertion = copy.copy(self.fixture.assertion)
            object.__setattr__(assertion, field, value)
            cases.append({"repository_assertion": assertion})
        for field in ("request_id", "request_sha256", "document_json"):
            request = copy.copy(self.fixture.request)
            object.__setattr__(request, field, StringAlias(getattr(request, field)))
            cases.append({"request": request})
        bad = copy.copy(self.fixture.request)
        object.__setattr__(bad, "document_json", '{"schema_version":1,"schema_version":1}')
        cases.append({"request": bad})
        bad = copy.copy(self.fixture.request)
        object.__setattr__(bad, "document_json", '{"schema_version":1.0}')
        cases.append({"request": bad})
        bad = copy.copy(self.fixture.request)
        object.__setattr__(bad, "document_json", "{" + " " * 2_000_000)
        cases.append({"request": bad})
        assertion = copy.copy(self.fixture.assertion)
        object.__setattr__(assertion, "policy_version", 2**64)
        cases.append({"repository_assertion": assertion})
        with (
            mock.patch.object(
                self.fixture.root.store,
                "_write_connection",
                side_effect=AssertionError("invalid input reached SQL"),
            ) as write,
            mock.patch.object(
                self.fixture.service,
                "_clock",
                side_effect=AssertionError("invalid input reached clock"),
            ) as clock,
        ):
            for case in cases:
                with (
                    self.subTest(case=next(iter(case))),
                    self.assertRaises(PrincipalAuthenticationError),
                ):
                    self._authenticate(**case)
            write.assert_not_called()
            clock.assert_not_called()

    def test_expected_identity_revalidated_before_store_or_clock(self) -> None:
        class StringAlias(str):
            pass

        service = self.fixture.service
        for field, value in (
            ("_expected_subject", StringAlias(phase149.SUBJECT)),
            ("_expected_profile", StringAlias(phase149.PROFILE_ID)),
        ):
            original = getattr(service, field)
            setattr(service, field, value)
            try:
                with (
                    mock.patch.object(
                        self.fixture.root.store,
                        "_write_connection",
                        side_effect=AssertionError("invalid identity reached SQL"),
                    ),
                    mock.patch.object(
                        service,
                        "_clock",
                        side_effect=AssertionError("invalid identity reached clock"),
                    ),
                    self.assertRaises(PrincipalAuthenticationError),
                ):
                    self._authenticate()
            finally:
                setattr(service, field, original)

    def test_missing_scope_is_not_implicitly_accepted(self) -> None:
        grant = repository_grant(self.fixture, token="A7")
        assertion = repository_assertion(self.fixture, grant=grant)
        before = logical_store(self.fixture)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "not accepted"):
            self._authenticate(repository_assertion=assertion)
        self.assertEqual(logical_store(self.fixture), before)

    def test_output_is_detached_and_metadata_binding_is_revalidated(self) -> None:
        receipt = self._authenticate()
        first = receipt.to_dict()
        first["repository_ingest_authentication"]["ingest_receipt"]["outcome"] = "failed"
        self.assertNotEqual(receipt.to_dict(), first)
        altered = replace(
            receipt,
            repository_attestor=ProviderEvidenceRepositoryPrincipalCommit(
                "PAS-" + "00" * 16, "sha256:" + "00" * 32, "sha256:" + "00" * 32
            ),
        )
        with self.assertRaises(StoreIntegrityError):
            altered.to_dict()

        class CommitSubclass(AuthenticatedProviderEvidenceRepositoryIngestCommitReceipt):
            pass

        # Inert receipt constructors never restore a VerifiedPrincipal or live authority.
        inert = CommitSubclass(
            receipt.authentication_json, receipt.authenticated_at, receipt.repository_attestor
        )
        self.assertEqual(inert.to_dict()["current_authority_status"], "not_verified")

    def test_downgrade_helper_refuses_durable_ack_even_without_custody_table(self) -> None:
        self._authenticate()
        before = logical_store(self.fixture)
        with closing(sqlite3.connect(self.fixture.root.path)) as connection:
            connection.execute("BEGIN")
            for absent in (False, True):
                if absent:
                    connection.execute(f"DROP TABLE {TABLE}")
                snapshot = tuple(connection.iterdump())
                with (
                    self.subTest(absent=absent),
                    self.assertRaisesRegex(AssertionError, "repository ACK"),
                ):
                    remove_schema_v39_objects(connection)
                self.assertEqual(tuple(connection.iterdump()), snapshot)
            connection.rollback()
        self.assertEqual(logical_store(self.fixture), before)

    def test_late_insert_failure_restores_entire_logical_store(self) -> None:
        before = logical_store(self.fixture)
        with (
            mock.patch.object(
                self.fixture.root.store,
                "_insert_provider_evidence_repository_ingest_authentication",
                side_effect=sqlite3.IntegrityError("synthetic late insert failure"),
            ),
            self.assertRaises(StoreConflictError),
        ):
            self._authenticate()
        self.assertEqual(logical_store(self.fixture), before)

    def test_late_reconciliation_failure_restores_entire_logical_store(self) -> None:
        before = logical_store(self.fixture)
        service = self.fixture.service
        original = service._activation._verified_mission_state
        calls = 0

        def verify(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise StoreIntegrityError("synthetic late reconciliation failure")
            return original(*args)

        with (
            mock.patch.object(service._activation, "_verified_mission_state", side_effect=verify),
            self.assertRaises(StoreIntegrityError),
        ):
            self._authenticate()
        self.assertEqual(calls, 2)
        self.assertEqual(logical_store(self.fixture), before)


if __name__ == "__main__":
    unittest.main()

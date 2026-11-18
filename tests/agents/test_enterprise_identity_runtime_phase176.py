"""Phase 176 enterprise identity runtime coverage."""

from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import unittest
from dataclasses import MISSING, FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import sunderkey

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None

from sunderkey.enterprise_identity_contracts import (
    BindingStatus,
    EnterpriseIdentityPolicy,
    Permission,
    ProvisioningCommand,
    ProvisioningOperation,
    ResourceKind,
    RoleBinding,
    RoleDefinition,
    SsoTrustPolicy,
    validate_provisioning_command,
)
from sunderkey.enterprise_identity_runtime import (
    ALLOWED_JWS_ALGORITHM,
    NO_EFFECTS,
    AuthenticatedPinnedOidcKeyset,
    EnterpriseIdentityRuntimeError,
    ProvisioningDispatchAdmission,
    ScimDispatchResult,
    ScimIdempotencyCompletion,
    ScimIdempotencyReservation,
    dispatch_validated_provisioning,
    verify_pinned_oidc_jws,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "enterprise-identity-runtime-receipt-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "enterprise_identity_runtime.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "enterprise-identity-runtime.md",
)
TENANT = "tenant:helios"
NOW = "2026-09-20T12:00:00Z"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _epoch(value: str) -> int:
    return int(datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC).timestamp())


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _spki_sha256(public_key) -> str:
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class KeysetVerifier:
    verifier_id = "verifier:keyset-001"

    def __init__(self, expected_sha256: str, authenticated: bool = True) -> None:
        self.expected_sha256 = expected_sha256
        self.authenticated = authenticated
        self.calls = []

    def verify(self, keyset) -> bool:
        self.calls.append(keyset.keyset_sha256)
        return self.authenticated and keyset.keyset_sha256 == self.expected_sha256


class AdmissionVerifier:
    verifier_id = "verifier:admission-001"

    def __init__(self, authenticated: bool = True) -> None:
        self.authenticated = authenticated
        self.calls = []

    def verify(self, admission) -> bool:
        self.calls.append(admission.admission_sha256)
        return self.authenticated


class TestDispatcher:
    dispatcher_id = "dispatcher:scim-staging-001"
    environment = "staging"
    attestation_sha256 = "sha256:" + "c" * 64

    def __init__(self, callback) -> None:
        self.callback = callback
        self.calls = []

    def dispatch(self, command):
        self.calls.append(command.record_sha256)
        return self.callback(command)


class AtomicStore:
    store_id = "store:scim-idempotency-001"

    def __init__(self) -> None:
        self.records = {}
        self.reserve_calls = 0
        self.complete_calls = 0

    def reserve(self, **values):
        self.reserve_calls += 1
        key = values["idempotency_key"]
        if key in self.records:
            return None
        reservation = ScimIdempotencyReservation(
            store_id=self.store_id,
            reservation_token=f"reservation:{self.reserve_calls:03d}",
            **values,
        )
        self.records[key] = ("reserved", reservation)
        return reservation

    def complete(self, reservation, *, result_sha256, completed_at):
        self.complete_calls += 1
        record = self.records.get(reservation.idempotency_key)
        if record != ("reserved", reservation):
            raise RuntimeError("reservation is not held")
        completion = ScimIdempotencyCompletion(
            store_id=self.store_id,
            reservation_sha256=reservation.reservation_sha256,
            result_sha256=result_sha256,
            completed_at=completed_at,
        )
        self.records[reservation.idempotency_key] = ("completed", completion)
        return completion


class EnterpriseIdentityRuntimePhase176Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self) -> None:
        identity_admin = RoleDefinition(
            TENANT,
            "role:identity-admin",
            (Permission.IDENTITY_ADMIN, Permission.SESSION_REVOKE),
            "Administer authorized identity lifecycle changes.",
        )
        trust = SsoTrustPolicy(
            TENANT,
            "issuer:workforce",
            "audience:sunderkey",
            ("assurance:phishing-resistant",),
            True,
            3600,
            7200,
            30,
        )
        self.policy = EnterpriseIdentityPolicy(TENANT, (identity_admin,), trust)
        self.binding = RoleBinding(
            TENANT,
            "subject:directory-admin",
            ("role:identity-admin",),
            BindingStatus.ACTIVE,
            3,
            "2026-09-20T00:00:00Z",
            "2026-09-21T00:00:00Z",
        )
        self.command = ProvisioningCommand(
            tenant_id=TENANT,
            actor_subject_id="subject:directory-admin",
            operation=ProvisioningOperation.UPDATE,
            resource_kind=ResourceKind.USER,
            resource_id="user:analyst",
            external_id="external:001",
            idempotency_key="idempotency:update-001",
            expected_version=4,
            new_version=5,
            issued_at=NOW,
            precondition_sha256=DIGEST_A,
            attribute_digests=(DIGEST_B,),
        )
        self.claims = {
            "acr": "assurance:phishing-resistant",
            "amr": ["mfa", "pwd"],
            "aud": "audience:sunderkey",
            "auth_time": _epoch("2026-09-20T11:30:00Z"),
            "department": "security",
            "exp": _epoch("2026-09-20T13:00:00Z"),
            "iat": _epoch("2026-09-20T11:45:00Z"),
            "iss": "issuer:workforce",
            "jti": "replay:001",
            "nbf": _epoch("2026-09-20T11:45:00Z"),
            "nonce": "nonce:001",
            "sid": "session:alpha",
            "sub": "subject:analyst",
            "tenant_id": TENANT,
        }

    def token(
        self,
        *,
        claims: dict | None = None,
        header: dict | None = None,
        key=None,
    ) -> str:
        header = header or {"alg": "RS256", "kid": "key:2026-09", "typ": "JWT"}
        claims = claims or self.claims
        header_part = _b64url(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode("ascii")
        )
        claims_part = _b64url(
            json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("ascii")
        )
        signing_input = f"{header_part}.{claims_part}".encode("ascii")
        signature = (key or self.private_key).sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return f"{header_part}.{claims_part}.{_b64url(signature)}"

    def keyset(self, public_key=None, **changes):
        public_key = public_key or self.private_key.public_key()
        values = {
            "keyset_id": "keyset:workforce-2026-09",
            "policy_sha256": self.policy.record_sha256,
            "issuer": self.policy.sso_trust.issuer,
            "audience": self.policy.sso_trust.audience,
            "public_keys": {"key:2026-09": public_key},
            "key_fingerprints_sha256": {"key:2026-09": _spki_sha256(public_key)},
            "authenticator_id": KeysetVerifier.verifier_id,
            "authentication_sha256": "sha256:" + "d" * 64,
            "issued_at": "2026-09-20T00:00:00Z",
            "expires_at": "2026-09-21T00:00:00Z",
        }
        values.update(changes)
        return AuthenticatedPinnedOidcKeyset(**values)

    def verify(self, token: str | None = None, **changes):
        keyset = self.keyset()
        values = {
            "keyset": keyset,
            "keyset_verifier": KeysetVerifier(keyset.keyset_sha256),
            "evaluated_at": NOW,
            "expected_subject_id": "subject:analyst",
            "expected_nonce": "nonce:001",
            "required_claims": {"department": "security"},
        }
        values.update(changes)
        return verify_pinned_oidc_jws(token or self.token(), self.policy, **values)

    def decision(self):
        return validate_provisioning_command(
            self.policy,
            self.command,
            actor_binding=self.binding,
            current_version=4,
            current_sha256=DIGEST_A,
            seen_idempotency={},
            evaluated_at=NOW,
        )

    def admission(self, **changes) -> ProvisioningDispatchAdmission:
        decision = self.decision()
        values = {
            "tenant_id": TENANT,
            "policy_sha256": self.policy.record_sha256,
            "command_sha256": self.command.record_sha256,
            "decision_sha256": decision.record_sha256,
            "idempotency_key": self.command.idempotency_key,
            "environment": "staging",
            "dispatcher_id": TestDispatcher.dispatcher_id,
            "dispatcher_attestation_sha256": TestDispatcher.attestation_sha256,
            "idempotency_store_id": AtomicStore.store_id,
            "approval_verifier_id": AdmissionVerifier.verifier_id,
            "approval_authentication_sha256": "sha256:" + "e" * 64,
            "issued_at": "2026-09-20T11:55:00Z",
            "expires_at": "2026-09-20T12:05:00Z",
            "approved": True,
        }
        values.update(changes)
        return ProvisioningDispatchAdmission(**values)

    def result(self, **changes) -> ScimDispatchResult:
        values = {
            "tenant_id": TENANT,
            "command_sha256": self.command.record_sha256,
            "idempotency_key": self.command.idempotency_key,
            "operation": self.command.operation,
            "resource_kind": self.command.resource_kind,
            "resource_sha256": DIGEST_B,
            "resulting_version": 5,
            "applied": True,
            "tombstone_confirmed": False,
            "session_revocation_confirmed": False,
        }
        values.update(changes)
        return ScimDispatchResult(**values)

    def dispatch(self, dispatcher, **changes):
        dispatcher = (
            dispatcher if isinstance(dispatcher, TestDispatcher) else TestDispatcher(dispatcher)
        )
        values = {
            "actor_binding": self.binding,
            "current_version": 4,
            "current_sha256": DIGEST_A,
            "seen_idempotency": {},
            "evaluated_at": NOW,
            "admission": self.admission(),
            "admission_verifier": AdmissionVerifier(),
            "dispatcher": dispatcher,
            "idempotency_store": AtomicStore(),
        }
        values.update(changes)
        return dispatch_validated_provisioning(self.policy, self.command, **values)

    def test_pinned_oidc_verification_is_deterministic_and_secret_free(self) -> None:
        token = self.token()
        first = self.verify(token)
        second = self.verify(token)
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(first.decision.decision, "allow")
        self.assertTrue(first.assertion.externally_verified)
        self.assertEqual(first.receipt.algorithm, ALLOWED_JWS_ALGORITHM)
        self.assertEqual(first.receipt.dispatch_count, 0)
        self.assertEqual(first.receipt.keyset_id, "keyset:workforce-2026-09")
        self.assertRegex(
            first.receipt.key_fingerprint_sha256 or "",
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(first.receipt.receipt_id, r"^EIR-[0-9A-F]{32}$")
        rendered = first.receipt.to_json()
        self.assertNotIn(token, rendered)
        self.assertNotIn("nonce:001", rendered)
        self.assertEqual(first.receipt.to_dict()["effects"], NO_EFFECTS)
        with self.assertRaises(FrozenInstanceError):
            first.receipt.status = "changed"

    def test_oidc_rejects_algorithm_header_and_key_downgrades(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "algorithm or type"):
            self.verify(self.token(header={"alg": "none", "kid": "key:2026-09", "typ": "JWT"}))
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "unsupported shape"):
            self.verify(
                self.token(
                    header={
                        "alg": "RS256",
                        "jku": "issuer:keys",
                        "kid": "key:2026-09",
                        "typ": "JWT",
                    }
                )
            )
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "not pinned"):
            self.verify(self.token(header={"alg": "RS256", "kid": "key:other", "typ": "JWT"}))
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "RSA public key"):
            self.keyset(public_keys={"key:2026-09": object()})

    def test_oidc_rejects_unauthenticated_keyset_and_same_kid_replacement(self) -> None:
        keyset = self.keyset()
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "authentication failed"):
            self.verify(
                keyset=keyset,
                keyset_verifier=KeysetVerifier(keyset.keyset_sha256, authenticated=False),
            )
        verifier = KeysetVerifier(keyset.keyset_sha256)
        verifier.verifier_id = "verifier:other"
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "identity does not match"):
            self.verify(keyset=keyset, keyset_verifier=verifier)
        wrong_policy = self.keyset(policy_sha256=DIGEST_A)
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "does not match policy"):
            self.verify(
                keyset=wrong_policy,
                keyset_verifier=KeysetVerifier(wrong_policy.keyset_sha256),
            )
        replacement = self.other_private_key.public_key()
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "fingerprint does not match"):
            self.keyset(
                public_key=replacement,
                key_fingerprints_sha256={
                    "key:2026-09": _spki_sha256(self.private_key.public_key())
                },
            )

    def test_oidc_rejects_wrong_signature_and_claim_bindings(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "signature verification"):
            self.verify(self.token(key=self.other_private_key))
        for name, value, message in (
            ("iss", "issuer:other", "issuer"),
            ("aud", "audience:other", "audience"),
            ("tenant_id", "tenant:other", "tenant"),
            ("acr", "assurance:weak", "assurance"),
        ):
            claims = {**self.claims, name: value}
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(EnterpriseIdentityRuntimeError, message),
            ):
                self.verify(self.token(claims=claims))
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "subject"):
            self.verify(expected_subject_id="subject:other")
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "required OIDC claim"):
            self.verify(required_claims={"department": "engineering"})

    def test_oidc_enforces_nonce_or_unseen_replay_identifier(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "nonce"):
            self.verify(expected_nonce="nonce:other")
        admitted = self.verify(expected_nonce=None, seen_replay_ids=())
        self.assertRegex(admitted.receipt.replay_binding_sha256 or "", r"^sha256:[0-9a-f]{64}$")
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "already observed"):
            self.verify(expected_nonce=None, seen_replay_ids=("replay:001",))
        claims = dict(self.claims)
        claims.pop("jti")
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "jti"):
            self.verify(self.token(claims=claims), expected_nonce=None)

    def test_oidc_enforces_time_and_mfa_claims(self) -> None:
        expired = {**self.claims, "exp": _epoch("2026-09-20T11:50:00Z")}
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "expired"):
            self.verify(self.token(claims=expired))
        future = {
            **self.claims,
            "iat": _epoch("2026-09-20T12:10:00Z"),
            "nbf": _epoch("2026-09-20T12:10:00Z"),
        }
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "not yet valid"):
            self.verify(self.token(claims=future))
        no_mfa = {**self.claims, "amr": ["pwd"]}
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "MFA"):
            self.verify(self.token(claims=no_mfa))

    def test_scim_dispatch_occurs_once_after_exact_admission(self) -> None:
        calls = []

        def dispatcher(command):
            calls.append(command.record_sha256)
            return self.result()

        outcome = self.dispatch(dispatcher)
        self.assertEqual(calls, [self.command.record_sha256])
        self.assertEqual(outcome.receipt.dispatch_count, 1)
        self.assertEqual(outcome.receipt.status, "dispatched_non_production")
        self.assertEqual(outcome.receipt.admission_id, self.admission().admission_id)
        self.assertEqual(outcome.receipt.environment, "staging")
        self.assertEqual(outcome.receipt.dispatcher_id, TestDispatcher.dispatcher_id)
        self.assertEqual(
            outcome.receipt.dispatcher_attestation_sha256,
            TestDispatcher.attestation_sha256,
        )
        self.assertRegex(outcome.receipt.reservation_sha256 or "", r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(outcome.receipt.completion_sha256 or "", r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(outcome.receipt.to_dict()["effects"], NO_EFFECTS)
        self.assertNotIn("attribute_digests", outcome.receipt.to_json())

    def test_scim_validation_and_admission_fail_before_dispatch(self) -> None:
        calls = []

        def dispatcher(_command):
            calls.append(True)
            return self.result()

        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "denied"):
            self.dispatch(dispatcher, current_version=3)
        self.assertEqual(calls, [])
        wrong_admission = self.admission(command_sha256=DIGEST_B)
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "does not match"):
            self.dispatch(dispatcher, admission=wrong_admission)
        self.assertEqual(calls, [])
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "denied"):
            self.dispatch(
                dispatcher,
                seen_idempotency={self.command.idempotency_key: self.command.record_sha256},
            )
        self.assertEqual(calls, [])

    def test_scim_rejects_production_or_expired_admission(self) -> None:
        self.assertIs(
            inspect.signature(ProvisioningDispatchAdmission).parameters["approved"].default,
            inspect.Parameter.empty,
        )
        self.assertIs(
            ProvisioningDispatchAdmission.__dataclass_fields__["approved"].default,
            MISSING,
        )
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "explicitly approved"):
            self.admission(approved=False)
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "non-production"):
            self.admission(environment="production")
        expired = self.admission(
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T11:30:00Z",
        )
        calls = []
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "not active"):
            self.dispatch(lambda command: calls.append(command), admission=expired)
        self.assertEqual(calls, [])

    def test_scim_rejects_unauthenticated_admission_before_reservation(self) -> None:
        calls = []
        store = AtomicStore()
        dispatcher = TestDispatcher(lambda command: calls.append(command))
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "authentication failed"):
            self.dispatch(
                dispatcher,
                admission_verifier=AdmissionVerifier(authenticated=False),
                idempotency_store=store,
            )
        self.assertEqual(store.reserve_calls, 0)
        self.assertEqual(dispatcher.calls, [])
        verifier = AdmissionVerifier()
        verifier.verifier_id = "verifier:other"
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "identity does not match"):
            self.dispatch(
                dispatcher,
                admission_verifier=verifier,
                idempotency_store=store,
            )
        self.assertEqual(store.reserve_calls, 0)
        self.assertEqual(dispatcher.calls, [])

    def test_scim_rejects_dispatcher_environment_identity_or_attestation_mismatch(self) -> None:
        for name, value in (
            ("environment", "test"),
            ("dispatcher_id", "dispatcher:other"),
            ("attestation_sha256", "sha256:" + "f" * 64),
        ):
            with self.subTest(name=name):
                store = AtomicStore()
                dispatcher = TestDispatcher(lambda _command: self.result())
                setattr(dispatcher, name, value)
                with self.assertRaisesRegex(
                    EnterpriseIdentityRuntimeError,
                    "identity or attestation does not match",
                ):
                    self.dispatch(dispatcher, idempotency_store=store)
                self.assertEqual(store.reserve_calls, 0)
                self.assertEqual(dispatcher.calls, [])

    def test_scim_atomic_store_rejects_replay_and_concurrent_dispatch(self) -> None:
        store = AtomicStore()
        first_calls = []
        first = self.dispatch(
            lambda command: first_calls.append(command.record_sha256) or self.result(),
            idempotency_store=store,
        )
        self.assertEqual(first.receipt.idempotency_store_id, store.store_id)
        self.assertEqual(first_calls, [self.command.record_sha256])
        replay_calls = []
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reserved or completed"):
            self.dispatch(
                lambda command: replay_calls.append(command) or self.result(),
                idempotency_store=store,
            )
        self.assertEqual(replay_calls, [])

        concurrent_store = AtomicStore()
        nested_calls = []

        def outer(_command):
            with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reserved or completed"):
                self.dispatch(
                    lambda command: nested_calls.append(command) or self.result(),
                    idempotency_store=concurrent_store,
                )
            return self.result()

        self.dispatch(outer, idempotency_store=concurrent_store)
        self.assertEqual(nested_calls, [])

    def test_scim_store_and_reservation_mismatch_fail_before_dispatch(self) -> None:
        calls = []
        wrong_store = AtomicStore()
        wrong_store.store_id = "store:other"
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "store identity"):
            self.dispatch(lambda command: calls.append(command), idempotency_store=wrong_store)
        self.assertEqual(calls, [])

        class MismatchedStore(AtomicStore):
            def reserve(self, **values):
                reservation = super().reserve(**values)
                return replace(reservation, dispatcher_id="dispatcher:other")

        mismatch = MismatchedStore()
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reservation does not match"):
            self.dispatch(lambda command: calls.append(command), idempotency_store=mismatch)
        self.assertEqual(calls, [])

    def test_scim_postconditions_fail_closed_without_retry(self) -> None:
        calls = []
        store = AtomicStore()

        def bad_result(_command):
            calls.append(True)
            return self.result(resulting_version=6)

        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "postconditions"):
            self.dispatch(bad_result, idempotency_store=store)
        self.assertEqual(calls, [True])
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reserved or completed"):
            self.dispatch(bad_result, idempotency_store=store)
        self.assertEqual(calls, [True])

        calls.clear()
        store = AtomicStore()

        def failing_dispatcher(_command):
            calls.append(True)
            raise RuntimeError("external detail must not escape")

        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "dispatcher failed") as raised:
            self.dispatch(failing_dispatcher, idempotency_store=store)
        self.assertNotIn("external detail", str(raised.exception))
        self.assertEqual(calls, [True])

    def test_scim_completion_failure_occurs_after_one_dispatch_without_retry(self) -> None:
        calls = []

        class FailingCompletionStore(AtomicStore):
            def complete(self, reservation, *, result_sha256, completed_at):
                raise RuntimeError("external detail must not escape")

        store = FailingCompletionStore()
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "completion failed") as raised:
            self.dispatch(
                lambda command: calls.append(command.record_sha256) or self.result(),
                idempotency_store=store,
            )
        self.assertNotIn("external detail", str(raised.exception))
        self.assertEqual(calls, [self.command.record_sha256])
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reserved or completed"):
            self.dispatch(
                lambda command: calls.append(command.record_sha256) or self.result(),
                idempotency_store=store,
            )
        self.assertEqual(calls, [self.command.record_sha256])

    def test_scim_tombstone_requires_matching_postconditions(self) -> None:
        command = replace(
            self.command,
            operation=ProvisioningOperation.TOMBSTONE,
            idempotency_key="idempotency:tombstone-001",
        )
        self.command = command
        admission = self.admission()
        result = self.result(tombstone_confirmed=True, session_revocation_confirmed=True)
        outcome = self.dispatch(lambda _command: result, admission=admission)
        self.assertTrue(outcome.result.tombstone_confirmed)
        self.assertTrue(outcome.result.session_revocation_confirmed)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_receipts_validate_against_strict_draft_2020_12_schema(self) -> None:
        oidc_receipt = self.verify().receipt.to_dict()
        scim_receipt = self.dispatch(lambda _command: self.result()).receipt.to_dict()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(oidc_receipt)), [])
        self.assertEqual(list(validator.iter_errors(scim_receipt)), [])
        tampered = copy.deepcopy(scim_receipt)
        tampered["effects"]["production"] = "performed"
        self.assertNotEqual(list(validator.iter_errors(tampered)), [])

    def test_public_api_and_source_hygiene(self) -> None:
        import sunderkey.enterprise_identity_runtime as runtime

        self.assertEqual(
            runtime.__all__,
            [
                "ADMISSION_KIND",
                "ALLOWED_JWS_ALGORITHM",
                "COMPLETION_KIND",
                "KEYSET_KIND",
                "NO_EFFECTS",
                "RECEIPT_KIND",
                "RESERVATION_KIND",
                "AtomicScimIdempotencyStore",
                "AttestedScimDispatcher",
                "AuthenticatedAdmissionVerifier",
                "AuthenticatedOidcKeysetVerifier",
                "AuthenticatedPinnedOidcKeyset",
                "EnterpriseIdentityRuntimeError",
                "EnterpriseIdentityRuntimeReceipt",
                "OidcVerificationOutcome",
                "ProvisioningDispatchAdmission",
                "ScimDispatchOutcome",
                "ScimDispatchResult",
                "ScimDispatcher",
                "ScimIdempotencyCompletion",
                "ScimIdempotencyReservation",
                "dispatch_validated_provisioning",
                "verify_pinned_oidc_jws",
            ],
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.isascii())
            self.assertNotRegex(text, "[\u2013\u2014]")
        self.assertIs(sunderkey.EnterpriseIdentityRuntimeError, EnterpriseIdentityRuntimeError)
        self.assertIs(
            sunderkey.dispatch_validated_provisioning,
            dispatch_validated_provisioning,
        )
        self.assertIs(sunderkey.verify_pinned_oidc_jws, verify_pinned_oidc_jws)


if __name__ == "__main__":
    unittest.main()

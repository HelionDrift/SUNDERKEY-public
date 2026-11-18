"""Phase186C authenticated collaboration plan replacement authority tests."""

from __future__ import annotations

import ast
import base64
import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_collaboration_plan_replacement_authority_plan import (
    build_parser,
    build_sources,
)
from sunderkey.collaboration_plan_replacement_authentication import (
    EXPECTED_REQUIREMENT_COUNT,
    AuthenticatedPlanReplacementRequirement,
    CollaborationPlanReplacementAuthorityCredential,
    VerifiedCollaborationPlanReplacementAuthorityBundle,
    authenticate_collaboration_plan_replacement_authority,
    collaboration_plan_replacement_authority_replay_keys,
    validate_verified_collaboration_plan_replacement_authority_bundle,
)
from sunderkey.collaboration_plan_replacement_authority import (
    CollaborationPlanReplacementAuthorityPlan,
    build_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    CollaborationPlanReplacementAuthorityUpgrade,
    build_collaboration_plan_replacement_authority_upgrade,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
)
from sunderkey.errors import CollaborationPlanError, PrincipalAuthenticationError
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    TrustKeyUse,
    verify_trust_policy,
)
from sunderkey.qualification import _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_PLAN_PATH = ROOT / "registry" / "collaboration-plan-replacement-authority-plan-v1.json"
MODULE_PATH = ROOT / "src" / "sunderkey" / "collaboration_plan_replacement_authentication.py"
NOW = datetime(2026, 8, 3, 0, 10, tzinfo=UTC)
AUDIENCE = "sunderkey-runtime"
STORE_ID = "STR-0123456789ABCDEF0123456789ABCDEF"
ROOT_KEY_ID = "ROOT-PLAN-REPLACEMENT"
SCOPE_KEY_ID = "SCOPE-PLAN-REPLACEMENT"
ASSERTION_KEY_ID = "ASSERTION-PLAN-REPLACEMENT"
POLICY_ID = "POLICY-PLAN-REPLACEMENT"
MISSION_CONTEXT_HASH = "sha256:" + "1" * 64
SCOPE_DOCUMENT_HASH = "sha256:" + "2" * 64
CONSTRAINTS_HASH = "sha256:" + "3" * 64
SCOPE_REFERENCE = "scope:plan-replacement"
ZERO_SIGNATURE = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


class ReplacementCredentialFactory:
    def __init__(self, requirements: list[dict[str, Any]]) -> None:
        self.requirements = requirements
        self.root_private = Ed25519PrivateKey.generate()
        self.scope_private = Ed25519PrivateKey.generate()
        self.assertion_private = Ed25519PrivateKey.generate()

    @property
    def profiles(self) -> list[str]:
        return sorted({item["principal_profile_id"] for item in self.requirements})

    @property
    def operations(self) -> list[str]:
        return sorted({item["operation"] for item in self.requirements})

    def default_subjects(self) -> dict[str, str]:
        return {profile: "principal:" + profile.lower() for profile in self.profiles}

    def policy(
        self,
        *,
        subjects: dict[str, str] | None = None,
        policy_version: int = 7,
        assertion_public_key: bytes | None = None,
    ) -> PrincipalTrustPolicy:
        subject_map = subjects or self.default_subjects()
        allowed_subjects = sorted(set(subject_map.values()))
        keys = [
            {
                "key_id": ASSERTION_KEY_ID,
                "issuer": "identity-provider",
                "public_key": _b64url(
                    assertion_public_key or _public_bytes(self.assertion_private)
                ),
                "key_use": TrustKeyUse.PRINCIPAL_ASSERTION.value,
                "state": "active",
                "not_before": "2026-08-03T00:00:00Z",
                "not_after": "2026-08-03T01:00:00Z",
                "retire_at": None,
                "allowed_profiles": self.profiles,
                "allowed_subjects": allowed_subjects,
                "allowed_operations": self.operations,
            },
            {
                "key_id": SCOPE_KEY_ID,
                "issuer": "scope-authority",
                "public_key": _b64url(_public_bytes(self.scope_private)),
                "key_use": TrustKeyUse.SCOPE_GRANT.value,
                "state": "active",
                "not_before": "2026-08-03T00:00:00Z",
                "not_after": "2026-08-03T01:00:00Z",
                "retire_at": None,
                "allowed_profiles": self.profiles,
                "allowed_subjects": allowed_subjects,
                "allowed_operations": self.operations,
            },
        ]
        raw = {
            "schema_version": 1,
            "policy_id": POLICY_ID,
            "policy_version": policy_version,
            "issuer": "sunderkey-security",
            "audience": AUDIENCE,
            "store_id": STORE_ID,
            "issued_at": "2026-08-03T00:00:00Z",
            "not_before": "2026-08-03T00:00:00Z",
            "expires_at": "2026-08-03T01:00:00Z",
            "max_scope_lifetime_seconds": 3600,
            "max_assertion_lifetime_seconds": 600,
            "allowed_profiles": self.profiles,
            "allowed_subjects": allowed_subjects,
            "allowed_operations": self.operations,
            "keys": keys,
            "root_key_id": ROOT_KEY_ID,
            "signature": ZERO_SIGNATURE,
        }
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        return replace(
            unsigned,
            signature=_b64url(self.root_private.sign(unsigned.signing_bytes())),
        )

    def verified_policy(
        self,
        *,
        subjects: dict[str, str] | None = None,
        policy_version: int = 7,
        assertion_public_key: bytes | None = None,
    ):
        policy = self.policy(
            subjects=subjects,
            policy_version=policy_version,
            assertion_public_key=assertion_public_key,
        )
        return verify_trust_policy(
            policy,
            {ROOT_KEY_ID: _public_bytes(self.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=policy_version,
            clock=lambda: NOW,
        )

    def credentials(
        self,
        plan_document: dict[str, Any],
        replay_keys: dict[str, str],
        *,
        subjects: dict[str, str] | None = None,
        policy_version: int = 7,
        assertion_private: Ed25519PrivateKey | None = None,
    ) -> tuple[CollaborationPlanReplacementAuthorityCredential, ...]:
        subject_map = subjects or self.default_subjects()
        plan_by_source = {
            item["requirement_id"]: item for item in plan_document["assertion_requirements"]
        }
        result = []
        for index, requirement in enumerate(self.requirements, start=1):
            profile_id = requirement["principal_profile_id"]
            operation = PrincipalOperation(requirement["operation"])
            grant_raw = {
                "schema_version": 1,
                "grant_id": f"SGR-{index:032X}",
                "policy_id": POLICY_ID,
                "policy_version": policy_version,
                "issuer": "scope-authority",
                "key_id": SCOPE_KEY_ID,
                "subject": subject_map[profile_id],
                "profile_id": profile_id,
                "audience": AUDIENCE,
                "store_id": STORE_ID,
                "mission_id": plan_document["mission_id"],
                "mission_context_hash": MISSION_CONTEXT_HASH,
                "scope_reference": SCOPE_REFERENCE,
                "scope_document_hash": SCOPE_DOCUMENT_HASH,
                "environment": "test",
                "max_action_tier": "R1",
                "constraints_hash": CONSTRAINTS_HASH,
                "operations": [operation.value],
                "issued_at": "2026-08-03T00:03:00Z",
                "not_before": "2026-08-03T00:03:00Z",
                "expires_at": "2026-08-03T00:30:00Z",
                "signature": ZERO_SIGNATURE,
            }
            unsigned_grant = ScopeGrant.from_dict(grant_raw)
            grant = replace(
                unsigned_grant,
                signature=_b64url(self.scope_private.sign(unsigned_grant.signing_bytes())),
            )
            assertion_raw = {
                "schema_version": 1,
                "assertion_id": f"PAS-{index:032X}",
                "policy_id": POLICY_ID,
                "policy_version": policy_version,
                "scope_grant_id": grant.grant_id,
                "scope_grant_sha256": grant.content_sha256,
                "issuer": "identity-provider",
                "key_id": ASSERTION_KEY_ID,
                "subject": subject_map[profile_id],
                "profile_id": profile_id,
                "audience": AUDIENCE,
                "store_id": STORE_ID,
                "mission_id": plan_document["mission_id"],
                "operation": operation.value,
                "operation_intent_sha256": requirement["principal_operation_intent_sha256"],
                "issued_at": "2026-08-03T00:09:00Z",
                "not_before": "2026-08-03T00:09:00Z",
                "expires_at": "2026-08-03T00:14:00Z",
                "signature": ZERO_SIGNATURE,
            }
            unsigned_assertion = PrincipalAssertion.from_dict(assertion_raw)
            assertion = replace(
                unsigned_assertion,
                signature=_b64url(
                    (assertion_private or self.assertion_private).sign(
                        unsigned_assertion.signing_bytes()
                    )
                ),
            )
            source = plan_by_source[requirement["source_requirement_id"]]
            result.append(
                CollaborationPlanReplacementAuthorityCredential(
                    source_requirement_id=requirement["source_requirement_id"],
                    upgraded_requirement_id=requirement["requirement_id"],
                    replay_key_sha256=replay_keys[source["requirement_id"]],
                    scope_grant=grant,
                    assertion=assertion,
                )
            )
        return tuple(result)


class CollaborationPlanReplacementAuthenticationPhase186CTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.args = build_parser().parse_args([])
        (
            cls.preflight,
            cls.prior_plan,
            cls.replacement_plan,
            cls.authority_policy,
            cls.mission_policy,
            cls.registry,
            cls.registry_bytes,
        ) = build_sources(cls.args)
        checked = json.loads(AUTHORITY_PLAN_PATH.read_text(encoding="utf-8"))
        cls.authority_plan = CollaborationPlanReplacementAuthorityPlan.from_dict(checked)
        cls.verified_authority_plan = verify_collaboration_plan_replacement_authority_plan_offline(
            cls.authority_plan,
            preflight=cls.preflight,
            prior_plan=cls.prior_plan,
            replacement_plan=cls.replacement_plan,
            authority_policy=cls.authority_policy,
            mission_policy=cls.mission_policy,
            registry=cls.registry,
            registry_source=cls.registry_bytes,
            verified_at="2026-08-03T00:03:00Z",
        )
        cls.upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=cls.preflight,
            army_registry=cls.registry,
        )
        cls.plan_document = cls.authority_plan.to_dict()
        cls.factory = ReplacementCredentialFactory(cls.upgrade.to_dict()["authority_requirements"])
        cls.replay_keys = collaboration_plan_replacement_authority_replay_keys(
            cls.verified_authority_plan,
            cls.upgrade,
            preflight=cls.preflight,
            army_registry=cls.registry,
        )

    def setUp(self) -> None:
        self.policy = self.factory.verified_policy()
        self.credentials = self.factory.credentials(self.plan_document, self.replay_keys)

    def _authenticate(self, **overrides: Any):
        verified_authority_plan = overrides.pop(
            "verified_authority_plan",
            self.verified_authority_plan,
        )
        authority_upgrade = overrides.pop("authority_upgrade", self.upgrade)
        arguments = {
            "preflight": self.preflight,
            "army_registry": self.registry,
            "credentials": self.credentials,
            "verified_policy": self.policy,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_mission_context_hash": MISSION_CONTEXT_HASH,
            "expected_scope_reference": SCOPE_REFERENCE,
            "expected_scope_document_hash": SCOPE_DOCUMENT_HASH,
            "expected_environment": "test",
            "expected_max_action_tier": "R1",
            "expected_constraints_hash": CONSTRAINTS_HASH,
            "revoked_scope_grant_sha256s": (),
            "consumed_replay_keys": (),
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_plan_replacement_authority(
            verified_authority_plan,
            authority_upgrade,
            **arguments,
        )

    def test_authenticates_exact_sixteen_without_serializable_claim(self) -> None:
        original_credentials = copy.deepcopy(
            [(item.scope_grant.to_dict(), item.assertion.to_dict()) for item in self.credentials]
        )
        consumed: set[str] = set()
        revoked: set[str] = set()
        bundle = self._authenticate(
            consumed_replay_keys=consumed,
            revoked_scope_grant_sha256s=revoked,
        )
        self.assertIsInstance(
            bundle,
            VerifiedCollaborationPlanReplacementAuthorityBundle,
        )
        self.assertEqual(bundle.requirement_count, EXPECTED_REQUIREMENT_COUNT)
        self.assertEqual(len(bundle.requirements), EXPECTED_REQUIREMENT_COUNT)
        self.assertEqual(len(bundle.replay_keys), EXPECTED_REQUIREMENT_COUNT)
        self.assertEqual(len(bundle.assertion_identities), EXPECTED_REQUIREMENT_COUNT)
        self.assertEqual(len(set(bundle.assertion_identities)), EXPECTED_REQUIREMENT_COUNT)
        self.assertTrue(bundle.composition_sha256.startswith("sha256:"))
        self.assertTrue(
            set(bundle.replay_keys).isdisjoint(
                {item["replay_key_sha256"] for item in self.plan_document["assertion_requirements"]}
            )
        )
        self.assertEqual(bundle.authenticated_at, "2026-08-03T00:10:00Z")
        self.assertFalse(hasattr(bundle, "to_dict"))
        self.assertEqual(consumed, set())
        self.assertEqual(revoked, set())
        self.assertEqual(
            [(item.scope_grant.to_dict(), item.assertion.to_dict()) for item in self.credentials],
            original_credentials,
        )

    def test_omissions_extras_duplicates_and_substitutions_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Exactly 16"):
            self._authenticate(credentials=self.credentials[:-1])
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Exactly 16"):
            self._authenticate(credentials=(*self.credentials, self.credentials[0]))
        duplicate = list(self.credentials)
        duplicate[1] = duplicate[0]
        with self.assertRaisesRegex(PrincipalAuthenticationError, "exactly one"):
            self._authenticate(credentials=duplicate)
        swapped = list(self.credentials)
        first, second = swapped[0], swapped[1]
        swapped[0] = replace(first, assertion=second.assertion)
        swapped[1] = replace(second, assertion=first.assertion)
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(credentials=swapped)

    def test_wrong_replay_scope_signature_and_trust_generation_are_rejected(self) -> None:
        replay = self.credentials[0].replay_key_sha256
        with self.assertRaisesRegex(PrincipalAuthenticationError, "already consumed"):
            self._authenticate(consumed_replay_keys={replay})
        grant_hash = self.credentials[0].scope_grant.content_sha256
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            self._authenticate(revoked_scope_grant_sha256s={grant_hash})
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(expected_scope_document_hash="sha256:" + "f" * 64)
        attacker = Ed25519PrivateKey.generate()
        wrong_credentials = self.factory.credentials(
            self.plan_document,
            self.replay_keys,
            assertion_private=attacker,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(credentials=wrong_credentials)
        wrong_generation = self.factory.verified_policy(policy_version=8)
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(verified_policy=wrong_generation)

    def test_expiry_and_assertion_window_escape_are_rejected(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "validity window"):
            self._authenticate(clock=lambda: datetime(2026, 8, 3, 0, 34, tzinfo=UTC))
        changed = list(self.credentials)
        credential = changed[0]
        unsigned = replace(
            credential.assertion,
            expires_at="2026-08-03T00:34:00Z",
            signature=ZERO_SIGNATURE,
        )
        assertion = replace(
            unsigned,
            signature=_b64url(self.factory.assertion_private.sign(unsigned.signing_bytes())),
        )
        changed[0] = replace(credential, assertion=assertion)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "validity window"):
            self._authenticate(credentials=changed)

    def test_authentication_rejects_future_source_and_trust_verification(self) -> None:
        future_plan = verify_collaboration_plan_replacement_authority_plan_offline(
            self.authority_plan,
            preflight=self.preflight,
            prior_plan=self.prior_plan,
            replacement_plan=self.replacement_plan,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            verified_at="2026-08-03T00:12:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "precedes authority plan verification",
        ):
            self._authenticate(verified_authority_plan=future_plan)

        future_policy = verify_trust_policy(
            self.factory.policy(),
            {ROOT_KEY_ID: _public_bytes(self.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: datetime(2026, 8, 3, 0, 12, tzinfo=UTC),
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "precedes trust policy verification",
        ):
            self._authenticate(verified_policy=future_policy)

    def test_commanders_roles_intents_and_mission_are_exact(self) -> None:
        bundle = self._authenticate()
        commands = {
            item.authority_id: item.principal.profile_id
            for item in bundle.requirements
            if item.role in {"source_technical_command", "destination_technical_command"}
        }
        self.assertEqual(
            commands,
            {
                "AOE-GB-D06": "AOE-GB-D06-CMD",
                "AOE-GC-D11": "AOE-GC-D11-CMD",
            },
        )
        changed = list(self.credentials)
        command_index = next(
            index
            for index, item in enumerate(changed)
            if item.assertion.operation
            is PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW
        )
        replacement = next(
            item
            for item in changed
            if item.assertion.operation
            is PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW
        )
        changed[command_index] = replace(
            changed[command_index],
            scope_grant=replacement.scope_grant,
            assertion=replacement.assertion,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(credentials=changed)

        changed = list(self.credentials)
        source_index = next(
            index
            for index, item in enumerate(changed)
            if item.assertion.operation
            is PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW
        )
        destination = next(
            item
            for item in self.factory.requirements
            if item["role"] == "destination_technical_command"
        )
        credential = changed[source_index]
        substituted_subject = self.factory.default_subjects()[destination["principal_profile_id"]]
        unsigned_grant = replace(
            credential.scope_grant,
            profile_id=destination["principal_profile_id"],
            subject=substituted_subject,
            signature=ZERO_SIGNATURE,
        )
        substituted_grant = replace(
            unsigned_grant,
            signature=_b64url(self.factory.scope_private.sign(unsigned_grant.signing_bytes())),
        )
        unsigned_assertion = replace(
            credential.assertion,
            scope_grant_id=substituted_grant.grant_id,
            scope_grant_sha256=substituted_grant.content_sha256,
            profile_id=destination["principal_profile_id"],
            subject=substituted_subject,
            signature=ZERO_SIGNATURE,
        )
        substituted_assertion = replace(
            unsigned_assertion,
            signature=_b64url(
                self.factory.assertion_private.sign(unsigned_assertion.signing_bytes())
            ),
        )
        changed[source_index] = replace(
            credential,
            scope_grant=substituted_grant,
            assertion=substituted_assertion,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding differs"):
            self._authenticate(credentials=changed)

    def test_independence_uses_profile_and_authenticated_subject(self) -> None:
        subjects = self.factory.default_subjects()
        owner_profile = next(
            item["principal_profile_id"]
            for item in self.factory.requirements
            if item["role"] == "mission_owner"
        )
        control_profile = next(
            item["principal_profile_id"]
            for item in self.factory.requirements
            if item["role"] == "independent_control"
        )
        subjects[control_profile] = subjects[owner_profile]
        policy = self.factory.verified_policy(subjects=subjects)
        credentials = self.factory.credentials(
            self.plan_document,
            self.replay_keys,
            subjects=subjects,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Independent"):
            self._authenticate(credentials=credentials, verified_policy=policy)

        for role in ("independent_assurance", "second_control"):
            with self.subTest(role=role):
                role_subjects = self.factory.default_subjects()
                role_profile = next(
                    item["principal_profile_id"]
                    for item in self.factory.requirements
                    if item["role"] == role
                )
                role_subjects[role_profile] = role_subjects[owner_profile]
                role_policy = self.factory.verified_policy(subjects=role_subjects)
                role_credentials = self.factory.credentials(
                    self.plan_document,
                    self.replay_keys,
                    subjects=role_subjects,
                )
                with self.assertRaisesRegex(PrincipalAuthenticationError, "Independent"):
                    self._authenticate(
                        credentials=role_credentials,
                        verified_policy=role_policy,
                    )

    def test_replay_domain_and_requirement_identity_substitution_are_rejected(self) -> None:
        changed = list(self.credentials)
        changed[0] = replace(
            changed[0],
            replay_key_sha256=changed[1].replay_key_sha256,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(credentials=changed)
        changed = list(self.credentials)
        source_requirement = next(
            item
            for item in self.plan_document["assertion_requirements"]
            if item["requirement_id"] == changed[0].source_requirement_id
        )
        changed[0] = replace(
            changed[0],
            replay_key_sha256=source_requirement["replay_key_sha256"],
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "replay domain"):
            self._authenticate(credentials=changed)
        changed = list(self.credentials)
        changed[0] = replace(
            changed[0],
            upgraded_requirement_id=changed[1].upgraded_requirement_id,
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(credentials=changed)

    def test_overlapping_source_envelopes_need_assertion_and_replay_consumption(self) -> None:
        first = self._authenticate()
        alternate_plan = build_collaboration_plan_replacement_authority_plan(
            preflight=self.preflight,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            issued_at="2026-08-03T00:02:00Z",
            expires_at="2026-08-03T00:32:00Z",
        )
        alternate_verified = verify_collaboration_plan_replacement_authority_plan_offline(
            alternate_plan,
            preflight=self.preflight,
            prior_plan=self.prior_plan,
            replacement_plan=self.replacement_plan,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=self.registry_bytes,
            verified_at="2026-08-03T00:03:00Z",
        )
        alternate_replay_keys = collaboration_plan_replacement_authority_replay_keys(
            alternate_verified,
            self.upgrade,
            preflight=self.preflight,
            army_registry=self.registry,
        )
        alternate_credentials = self.factory.credentials(
            alternate_plan.to_dict(),
            alternate_replay_keys,
        )
        second = self._authenticate(
            verified_authority_plan=alternate_verified,
            credentials=alternate_credentials,
        )
        self.assertEqual(first.assertion_identities, second.assertion_identities)
        self.assertTrue(set(first.replay_keys).isdisjoint(second.replay_keys))
        self.assertNotEqual(first.composition_sha256, second.composition_sha256)

    def test_source_drift_between_verified_plan_and_upgrade_is_rejected(self) -> None:
        document = self.preflight.to_dict()
        document["source_state"]["observed_at"] = "2026-08-03T00:02:30Z"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        digest = _canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        document["preflight_id"] = "PRF-" + digest.removeprefix("sha256:")[:32].upper()
        document["preflight_sha256"] = digest
        drifted_preflight = CollaborationPlanReplacementPreflight.from_dict(document)
        drifted_upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=drifted_preflight,
            army_registry=self.registry,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "drifted"):
            authenticate_collaboration_plan_replacement_authority(
                self.verified_authority_plan,
                drifted_upgrade,
                preflight=drifted_preflight,
                army_registry=self.registry,
                credentials=self.credentials,
                verified_policy=self.policy,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_mission_context_hash=MISSION_CONTEXT_HASH,
                expected_scope_reference=SCOPE_REFERENCE,
                expected_scope_document_hash=SCOPE_DOCUMENT_HASH,
                expected_environment="test",
                expected_max_action_tier="R1",
                expected_constraints_hash=CONSTRAINTS_HASH,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys=(),
                clock=lambda: NOW,
            )

    def test_point_of_use_refresh_rechecks_replay_revocation_time_and_sources(self) -> None:
        bundle = self._authenticate()
        refreshed = validate_verified_collaboration_plan_replacement_authority_bundle(
            bundle,
            verified_authority_plan=self.verified_authority_plan,
            authority_upgrade=self.upgrade,
            preflight=self.preflight,
            army_registry=self.registry,
            verified_policy=self.policy,
            revoked_scope_grant_sha256s=(),
            consumed_replay_keys=(),
            clock=lambda: datetime(2026, 8, 3, 0, 11, tzinfo=UTC),
        )
        self.assertEqual(refreshed.authenticated_at, "2026-08-03T00:11:00Z")
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "precedes bundle authentication",
        ):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                bundle,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=self.policy,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys=(),
                clock=lambda: datetime(2026, 8, 3, 0, 9, tzinfo=UTC),
            )
        with self.assertRaises(PrincipalAuthenticationError):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                bundle,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=self.policy,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys=(),
                clock=lambda: datetime(2026, 8, 3, 0, 15, tzinfo=UTC),
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "already consumed"):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                bundle,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=self.policy,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys={bundle.replay_keys[0]},
                clock=lambda: NOW,
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                bundle,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=self.policy,
                revoked_scope_grant_sha256s={self.credentials[0].scope_grant.content_sha256},
                consumed_replay_keys=(),
                clock=lambda: NOW,
            )

        changed_policy_document = self.factory.policy().to_dict()
        changed_policy_document["issuer"] = "sunderkey-security-rotated"
        changed_policy_document["signature"] = ZERO_SIGNATURE
        unsigned_changed_policy = PrincipalTrustPolicy.from_dict(changed_policy_document)
        changed_policy = replace(
            unsigned_changed_policy,
            signature=_b64url(
                self.factory.root_private.sign(unsigned_changed_policy.signing_bytes())
            ),
        )
        verified_changed_policy = verify_trust_policy(
            changed_policy,
            {ROOT_KEY_ID: _public_bytes(self.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "trust generation has drifted"):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                bundle,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=verified_changed_policy,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys=(),
                clock=lambda: NOW,
            )

    def test_verified_bundle_rejects_construction_rebinding_and_proof_copy(self) -> None:
        with self.assertRaises(TypeError):
            VerifiedCollaborationPlanReplacementAuthorityBundle()
        bundle = self._authenticate()
        object.__setattr__(bundle, "_policy_sha256", "sha256:" + "f" * 64)
        with self.assertRaises(TypeError):
            _ = bundle.requirements

        intact = self._authenticate()
        clone = object.__new__(VerifiedCollaborationPlanReplacementAuthorityBundle)
        for slot in VerifiedCollaborationPlanReplacementAuthorityBundle.__slots__:
            object.__setattr__(clone, slot, object.__getattribute__(intact, slot))
        with self.assertRaises(TypeError):
            _ = clone.requirement_count

    def test_nested_requirement_mutation_and_standalone_claim_fail_closed(self) -> None:
        bundle = self._authenticate()
        requirement = bundle.requirements[0]
        standalone = AuthenticatedPlanReplacementRequirement(
            source_requirement_id=requirement.source_requirement_id,
            upgraded_requirement_id=requirement.upgraded_requirement_id,
            replay_key_sha256=requirement.replay_key_sha256,
            role=requirement.role,
            authority_id=requirement.authority_id,
            work_item_id=requirement.work_item_id,
            principal=requirement.principal,
        )
        with self.assertRaises(TypeError):
            validate_verified_collaboration_plan_replacement_authority_bundle(
                standalone,
                verified_authority_plan=self.verified_authority_plan,
                authority_upgrade=self.upgrade,
                preflight=self.preflight,
                army_registry=self.registry,
                verified_policy=self.policy,
                revoked_scope_grant_sha256s=(),
                consumed_replay_keys=(),
                clock=lambda: NOW,
            )

        object.__setattr__(requirement, "authority_id", "AOE-HQ-01")
        with self.assertRaises(TypeError):
            _ = bundle.requirements

    def test_rehashed_evidenceless_upgrade_cannot_replace_verified_sources(self) -> None:
        changed = copy.deepcopy(self.upgrade.to_dict())
        changed["runtime_effect"] = "authority_granted"
        with self.assertRaises(CollaborationPlanError):
            CollaborationPlanReplacementAuthorityUpgrade.from_dict(changed)

    def test_module_has_no_runtime_storage_transport_or_serialized_claim_boundary(self) -> None:
        tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imports.isdisjoint(
                {"http", "requests", "socket", "sqlite3", "store", "subprocess", "urllib"}
            )
        )
        self.assertFalse(
            (
                ROOT
                / "registry"
                / "schemas"
                / "collaboration-plan-replacement-authority-authentication-v1.schema.json"
            ).exists()
        )


if __name__ == "__main__":
    unittest.main()

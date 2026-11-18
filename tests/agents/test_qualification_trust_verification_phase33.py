"""Phase 33 fail-closed qualification trust verification."""

from __future__ import annotations

import ast
import base64
import copy
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import QualificationError
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_authority_decision import (
    load_qualification_authority_decision_record,
)
from sunderkey.qualification_trust import (
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    VerifiedQualificationReviewerCredential,
    VerifiedQualificationTrustPolicy,
    verify_qualification_reviewer_credential,
    verify_qualification_trust_policy,
)
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog
from tests.agents.test_qualification_trust_phase32 import (
    PROFILE_ID,
    qualification_reviewer_credential_document,
    qualification_trust_policy_document,
)

ROOT = Path(__file__).resolve().parents[2]
ROOT_KEY_ID = "qualification-offline-root-v1"
ROOT_SEED = 9
ISSUER_SEED = 3
REVIEWER_ID = "reviewer-technical-001"
NOW = datetime(2026, 2, 2, tzinfo=UTC)


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _raw_public_key(seed: int) -> bytes:
    return _private_key(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _signed_policy(
    document: dict[str, Any] | None = None,
    *,
    signing_seed: int = ROOT_SEED,
) -> QualificationTrustPolicy:
    raw = copy.deepcopy(document or qualification_trust_policy_document())
    unsigned = QualificationTrustPolicy.from_dict(raw)
    raw["signature"] = _encoded(
        _private_key(signing_seed).sign(unsigned.signing_bytes())
    )
    return QualificationTrustPolicy.from_dict(raw)


def _signed_credential(
    policy: QualificationTrustPolicy,
    document: dict[str, Any] | None = None,
    *,
    signing_seed: int = ISSUER_SEED,
    bind_policy: bool = True,
) -> QualificationReviewerCredential:
    raw = copy.deepcopy(document or qualification_reviewer_credential_document())
    if bind_policy:
        raw["policy_id"] = policy.policy_id
        raw["policy_version"] = policy.policy_version
        raw["policy_sha256"] = policy.content_sha256
    unsigned = QualificationReviewerCredential.from_dict(raw)
    raw["signature"] = _encoded(
        _private_key(signing_seed).sign(unsigned.signing_bytes())
    )
    return QualificationReviewerCredential.from_dict(raw)


class QualificationTrustVerificationPhase33Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = load_registry(ROOT / "registry" / "army-v1.json")
        cls.catalog = load_capability_catalog(
            ROOT / "registry" / "capabilities-army-v1.json",
            cls.registry,
        )
        cls.standard = load_qualification_standard(
            ROOT / "registry" / "qualification-standard-v1.json",
            cls.registry,
            cls.catalog,
        )
        cls.decision = load_qualification_authority_decision_record(
            ROOT / "registry" / "qualification-authority-decision-d008.json"
        )

    def _verify_policy(
        self,
        policy: QualificationTrustPolicy,
        *,
        trusted_roots: dict[str, bytes] | None = None,
        clock: datetime = NOW,
        **overrides: Any,
    ) -> VerifiedQualificationTrustPolicy:
        arguments = {
            "decision_record": self.decision,
            "qualification_standard": self.standard,
            "expected_issuer": "sunderkey-qualification-authority",
            "expected_audience": "sunderkey-qualification",
            "expected_root_key_id": ROOT_KEY_ID,
            "minimum_policy_version": 1,
            "clock": lambda: clock,
        }
        arguments.update(overrides)
        return verify_qualification_trust_policy(
            policy,
            trusted_roots or {ROOT_KEY_ID: _raw_public_key(ROOT_SEED)},
            **arguments,
        )

    def _verify_credential(
        self,
        credential: QualificationReviewerCredential,
        verified_policy: VerifiedQualificationTrustPolicy,
        *,
        clock: datetime = NOW,
        **overrides: Any,
    ) -> VerifiedQualificationReviewerCredential:
        arguments = {
            "expected_reviewer_id": REVIEWER_ID,
            "expected_role": QualificationReviewerRole.TECHNICAL_EVALUATOR,
            "expected_profile_id": PROFILE_ID,
            "clock": lambda: clock,
        }
        arguments.update(overrides)
        return verify_qualification_reviewer_credential(
            credential,
            verified_policy,
            **arguments,
        )

    def test_root_signed_policy_and_issuer_signed_credential_verify(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        credential = _signed_credential(policy)
        verified_credential = self._verify_credential(
            credential,
            verified_policy,
        )

        self.assertEqual(verified_policy.policy, policy)
        self.assertEqual(verified_policy.policy_sha256, policy.content_sha256)
        self.assertEqual(verified_policy.verified_at, "2026-02-02T00:00:00Z")
        self.assertEqual(verified_credential.credential, credential)
        self.assertEqual(verified_credential.reviewer_id, REVIEWER_ID)
        self.assertEqual(
            verified_credential.reviewer_role,
            QualificationReviewerRole.TECHNICAL_EVALUATOR,
        )
        self.assertEqual(verified_credential.verified_profile_id, PROFILE_ID)

    def test_policy_rejects_bad_signature_and_untrusted_root(self) -> None:
        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify_policy(_signed_policy(signing_seed=8))

        with self.assertRaisesRegex(QualificationError, "not trusted"):
            self._verify_policy(
                _signed_policy(),
                trusted_roots={"another-root": _raw_public_key(ROOT_SEED)},
            )

        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify_policy(
                _signed_policy(),
                trusted_roots={ROOT_KEY_ID: _raw_public_key(8)},
            )

    def test_policy_rejects_unexpected_identity_and_old_version(self) -> None:
        policy = _signed_policy()
        cases = (
            ({"expected_issuer": "another-issuer"}, "issuer"),
            ({"expected_audience": "another-audience"}, "audience"),
            ({"expected_root_key_id": "another-root"}, "root key"),
            ({"minimum_policy_version": 2}, "older"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                QualificationError,
                message,
            ):
                self._verify_policy(policy, **overrides)

    def test_policy_rejects_stale_approved_artifact_bindings(self) -> None:
        document = qualification_trust_policy_document()
        document["decision_record"]["sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "decision record binding"):
            self._verify_policy(_signed_policy(document))

        document = qualification_trust_policy_document()
        document["qualification_standard"]["sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "standard binding"):
            self._verify_policy(_signed_policy(document))

    def test_policy_rejects_root_key_material_reuse(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][0]["public_key"] = _encoded(_raw_public_key(ROOT_SEED))
        with self.assertRaisesRegex(QualificationError, "reuse root key material"):
            self._verify_policy(_signed_policy(document))

    def test_policy_rejects_inactive_window_and_invalid_clock(self) -> None:
        policy = _signed_policy()
        with self.assertRaisesRegex(QualificationError, "not active yet"):
            self._verify_policy(
                policy,
                clock=datetime(2025, 12, 31, tzinfo=UTC),
            )
        with self.assertRaisesRegex(QualificationError, "expired"):
            self._verify_policy(
                policy,
                clock=datetime(2027, 1, 1, tzinfo=UTC),
            )
        with self.assertRaisesRegex(QualificationError, "timezone-aware"):
            self._verify_policy(
                policy,
                clock=datetime(2026, 2, 2),
            )

    def test_verified_policy_wrapper_cannot_be_forged(self) -> None:
        policy = _signed_policy()
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationTrustPolicy(
                policy=policy,
                policy_sha256=policy.content_sha256,
                root_key_sha256="sha256:" + "0" * 64,
                verified_at="2026-02-02T00:00:00Z",
                _proof=b"not-a-verification-proof",
            )

    def test_credential_rejects_tampered_or_subclassed_policy_wrapper(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        credential = _signed_credential(policy)
        verified_policy.policy.decision_record["sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(QualificationError, "proof is invalid"):
            self._verify_credential(credential, verified_policy)

        class BypassVerifiedPolicy(VerifiedQualificationTrustPolicy):
            def __post_init__(self) -> None:
                pass

        forged = BypassVerifiedPolicy(
            policy=policy,
            policy_sha256=policy.content_sha256,
            root_key_sha256="sha256:" + "0" * 64,
            verified_at="2026-02-02T00:00:00Z",
            _proof=b"not-a-verification-proof",
        )
        with self.assertRaisesRegex(QualificationError, "must be"):
            self._verify_credential(credential, forged)

    def test_credential_rejects_bad_signature_and_stale_policy(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        with self.assertRaisesRegex(QualificationError, "signature"):
            self._verify_credential(
                _signed_credential(policy, signing_seed=5),
                verified_policy,
            )

        document = qualification_reviewer_credential_document()
        document["policy_sha256"] = "sha256:" + "0" * 64
        credential = _signed_credential(policy, document, bind_policy=False)
        with self.assertRaisesRegex(QualificationError, "policy binding"):
            self._verify_credential(credential, verified_policy)

    def test_credential_rejects_unexpected_reviewer_role_and_profile(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        credential = _signed_credential(policy)
        cases = (
            ({"expected_reviewer_id": "another-reviewer"}, "reviewer"),
            (
                {"expected_role": QualificationReviewerRole.INDEPENDENT_CONTROL},
                "role",
            ),
            ({"expected_profile_id": "AOE-GA-D01-S02"}, "expected profile"),
        )
        for overrides, message in cases:
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                QualificationError,
                message,
            ):
                self._verify_credential(
                    credential,
                    verified_policy,
                    **overrides,
                )

    def test_credential_rejects_wrong_key_use_and_revoked_key(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        document = qualification_reviewer_credential_document()
        document["issuer_key_id"] = "qualification-decision-v1"
        credential = _signed_credential(policy, document, signing_seed=1)
        with self.assertRaisesRegex(QualificationError, "key use"):
            self._verify_credential(credential, verified_policy)

        policy_document = qualification_trust_policy_document()
        policy_document["keys"][2]["state"] = "revoked"
        revoked_policy = _signed_policy(policy_document)
        verified_revoked_policy = self._verify_policy(revoked_policy)
        credential = _signed_credential(revoked_policy)
        with self.assertRaisesRegex(QualificationError, "revoked"):
            self._verify_credential(credential, verified_revoked_policy)

    def test_retiring_key_accepts_old_and_rejects_new_issuance(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][2]["state"] = "retiring"
        document["keys"][2]["retire_at"] = "2026-02-04T00:00:00Z"
        policy = _signed_policy(document)
        verified_policy = self._verify_policy(policy)
        self._verify_credential(_signed_credential(policy), verified_policy)

        credential_document = qualification_reviewer_credential_document()
        credential_document["issued_at"] = "2026-02-05T00:00:00Z"
        credential_document["not_before"] = "2026-02-05T00:00:00Z"
        credential = _signed_credential(policy, credential_document)
        with self.assertRaisesRegex(QualificationError, "after key retirement"):
            self._verify_credential(
                credential,
                verified_policy,
                clock=datetime(2026, 2, 6, tzinfo=UTC),
            )

    def test_credential_rejects_inactive_window_and_scope_escalation(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        credential = _signed_credential(policy)
        with self.assertRaisesRegex(QualificationError, "not active yet"):
            self._verify_credential(
                credential,
                verified_policy,
                clock=datetime(2026, 1, 31, tzinfo=UTC),
            )
        with self.assertRaisesRegex(QualificationError, "expired"):
            self._verify_credential(
                credential,
                verified_policy,
                clock=datetime(2026, 2, 8, tzinfo=UTC),
            )

        document = qualification_reviewer_credential_document()
        document["allowed_profile_ids"] = [PROFILE_ID, "AOE-GA-D01-S02"]
        credential = _signed_credential(policy, document)
        with self.assertRaisesRegex(QualificationError, "profiles exceed"):
            self._verify_credential(credential, verified_policy)

    def test_credential_rejects_policy_lifetime_and_issuer_window_excess(self) -> None:
        policy_document = qualification_trust_policy_document()
        policy_document["max_reviewer_credential_lifetime_seconds"] = 259200
        policy = _signed_policy(policy_document)
        verified_policy = self._verify_policy(policy)
        with self.assertRaisesRegex(QualificationError, "policy lifetime"):
            self._verify_credential(
                _signed_credential(policy),
                verified_policy,
            )

        policy_document = qualification_trust_policy_document()
        policy_document["keys"][2]["not_before"] = "2026-02-02T00:00:00Z"
        policy = _signed_policy(policy_document)
        verified_policy = self._verify_policy(policy)
        with self.assertRaisesRegex(QualificationError, "issuer key window"):
            self._verify_credential(
                _signed_credential(policy),
                verified_policy,
            )

    def test_credential_rejects_authority_key_material_reuse(self) -> None:
        policy = _signed_policy()
        verified_policy = self._verify_policy(policy)
        document = qualification_reviewer_credential_document()
        document["public_key"] = policy.key(
            "reviewer-credential-issuer-v1"
        ).public_key
        credential = _signed_credential(policy, document)
        with self.assertRaisesRegex(QualificationError, "reuse authority key material"):
            self._verify_credential(credential, verified_policy)

    def test_verified_credential_wrapper_cannot_be_forged(self) -> None:
        policy = _signed_policy()
        credential = _signed_credential(policy)
        with self.assertRaisesRegex(TypeError, "can be created only"):
            VerifiedQualificationReviewerCredential(
                credential=credential,
                credential_sha256=credential.content_sha256,
                policy_sha256=policy.content_sha256,
                issuer_key_sha256="sha256:" + "0" * 64,
                verified_profile_id=PROFILE_ID,
                verified_at="2026-02-02T00:00:00Z",
                _proof=b"not-a-verification-proof",
            )

    def test_verification_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "qualification_trust.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()

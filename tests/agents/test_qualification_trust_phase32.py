"""Phase 32 signed qualification trust and reviewer contracts."""

from __future__ import annotations

import ast
import base64
import copy
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.errors import QualificationError
from sunderkey.qualification_trust import (
    MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS,
    REVIEWER_CREDENTIAL_SIGNING_DOMAIN,
    TRUST_POLICY_SIGNING_DOMAIN,
    QualificationAuthorityKeyState,
    QualificationAuthorityKeyUse,
    QualificationReviewerCredential,
    QualificationReviewerRole,
    QualificationTrustPolicy,
    load_qualification_reviewer_credential,
    load_qualification_trust_policy,
)

ROOT = Path(__file__).resolve().parents[2]
PROFILE_ID = "AOE-GA-D01-S01"


def _encoded_public_key(seed: int) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _signature(seed: int = 0) -> str:
    raw = bytes((index + seed) % 256 for index in range(64))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def qualification_trust_policy_document() -> dict[str, Any]:
    profiles = [PROFILE_ID]
    return {
        "schema_version": 1,
        "policy_id": "QTP-11111111111111111111111111111111",
        "policy_version": 1,
        "decision_record": {
            "record_id": "QDR-7242E7ED90734BBE96A8036647FA227F",
            "sha256": (
                "sha256:7242e7ed90734bbe96a8036647fa227f"
                "65ef9c254e08cd4e50d3bf3684174850"
            ),
        },
        "qualification_standard": {
            "id": "sunderkey-specialist-qualification",
            "version": "1.0.0",
            "sha256": (
                "sha256:814aa71328244b3c608706a08504e13fd"
                "e8290f72d741b8c94d93cbd41e945cc"
            ),
        },
        "issuer": "sunderkey-qualification-authority",
        "audience": "sunderkey-qualification",
        "issued_at": "2026-01-01T00:00:00Z",
        "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "max_reviewer_credential_lifetime_seconds": 604800,
        "allowed_profile_ids": profiles,
        "keys": [
            {
                "key_id": "qualification-decision-v1",
                "issuer": "sunderkey-qualification-authority",
                "public_key": _encoded_public_key(1),
                "algorithm": "Ed25519",
                "key_use": "qualification_decision",
                "state": "active",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T00:00:00Z",
                "retire_at": None,
                "allowed_roles": [],
                "allowed_profile_ids": profiles,
            },
            {
                "key_id": "qualification-revocation-v1",
                "issuer": "sunderkey-qualification-authority",
                "public_key": _encoded_public_key(2),
                "algorithm": "Ed25519",
                "key_use": "qualification_revocation",
                "state": "active",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T00:00:00Z",
                "retire_at": None,
                "allowed_roles": [],
                "allowed_profile_ids": profiles,
            },
            {
                "key_id": "reviewer-credential-issuer-v1",
                "issuer": "sunderkey-qualification-authority",
                "public_key": _encoded_public_key(3),
                "algorithm": "Ed25519",
                "key_use": "reviewer_credential_issuer",
                "state": "active",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T00:00:00Z",
                "retire_at": None,
                "allowed_roles": [
                    "independent_assurance",
                    "independent_control",
                    "technical_evaluator",
                ],
                "allowed_profile_ids": profiles,
            },
        ],
        "root_key_id": "qualification-offline-root-v1",
        "signature": _signature(),
    }


def qualification_reviewer_credential_document() -> dict[str, Any]:
    policy = QualificationTrustPolicy.from_dict(
        qualification_trust_policy_document()
    )
    return {
        "schema_version": 1,
        "credential_id": "QRC-22222222222222222222222222222222",
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_sha256": policy.content_sha256,
        "issuer": "sunderkey-qualification-authority",
        "issuer_key_id": "reviewer-credential-issuer-v1",
        "reviewer_id": "reviewer-technical-001",
        "reviewer_role": "technical_evaluator",
        "allowed_profile_ids": [PROFILE_ID],
        "issued_at": "2026-02-01T00:00:00Z",
        "not_before": "2026-02-01T00:00:00Z",
        "expires_at": "2026-02-08T00:00:00Z",
        "algorithm": "Ed25519",
        "public_key": _encoded_public_key(4),
        "signature": _signature(1),
    }


class QualificationTrustPhase32Tests(unittest.TestCase):
    def test_policy_round_trip_and_signing_domain(self) -> None:
        policy = QualificationTrustPolicy.from_dict(
            qualification_trust_policy_document()
        )
        self.assertEqual(
            QualificationTrustPolicy.from_dict(policy.to_dict()),
            policy,
        )
        self.assertTrue(policy.signing_bytes().startswith(TRUST_POLICY_SIGNING_DOMAIN))
        self.assertRegex(policy.content_sha256, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            {key.key_use for key in policy.keys},
            set(QualificationAuthorityKeyUse),
        )
        self.assertEqual(policy.keys[0].state, QualificationAuthorityKeyState.ACTIVE)

    def test_credential_round_trip_and_signing_domain(self) -> None:
        credential = QualificationReviewerCredential.from_dict(
            qualification_reviewer_credential_document()
        )
        self.assertEqual(
            QualificationReviewerCredential.from_dict(credential.to_dict()),
            credential,
        )
        self.assertTrue(
            credential.signing_bytes().startswith(
                REVIEWER_CREDENTIAL_SIGNING_DOMAIN
            )
        )
        self.assertEqual(
            credential.reviewer_role,
            QualificationReviewerRole.TECHNICAL_EVALUATOR,
        )
        self.assertEqual(credential.allowed_profile_ids, (PROFILE_ID,))

    def test_policy_requires_every_separated_key_use(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][1]["key_use"] = "qualification_decision"
        with self.assertRaisesRegex(
            QualificationError,
            "every required key use",
        ):
            QualificationTrustPolicy.from_dict(document)

    def test_policy_rejects_duplicate_public_key_material(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][1]["public_key"] = document["keys"][0]["public_key"]
        with self.assertRaisesRegex(QualificationError, "distinct public keys"):
            QualificationTrustPolicy.from_dict(document)

    def test_policy_rejects_root_key_id_reuse(self) -> None:
        document = qualification_trust_policy_document()
        document["root_key_id"] = document["keys"][0]["key_id"]
        with self.assertRaisesRegex(QualificationError, "root key ID"):
            QualificationTrustPolicy.from_dict(document)

    def test_policy_rejects_key_outside_policy_window(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][0]["not_after"] = "2027-01-02T00:00:00Z"
        with self.assertRaisesRegex(QualificationError, "exceeds the policy window"):
            QualificationTrustPolicy.from_dict(document)

    def test_policy_rejects_invalid_ed25519_point(self) -> None:
        document = qualification_trust_policy_document()
        document["keys"][0]["public_key"] = (
            base64.urlsafe_b64encode(bytes(32)).rstrip(b"=").decode("ascii")
        )
        with self.assertRaises(QualificationError):
            QualificationTrustPolicy.from_dict(document)

    def test_policy_rejects_unsorted_profiles_and_keys(self) -> None:
        document = qualification_trust_policy_document()
        document["allowed_profile_ids"] = [
            "AOE-GA-D01-S02",
            "AOE-GA-D01-S01",
        ]
        with self.assertRaisesRegex(QualificationError, "ascending order"):
            QualificationTrustPolicy.from_dict(document)

        document = qualification_trust_policy_document()
        document["keys"] = list(reversed(document["keys"]))
        with self.assertRaisesRegex(QualificationError, "ascending key_id order"):
            QualificationTrustPolicy.from_dict(document)

    def test_credential_lifetime_is_globally_short_lived(self) -> None:
        self.assertEqual(MAX_REVIEWER_CREDENTIAL_LIFETIME_SECONDS, 2_592_000)
        document = qualification_reviewer_credential_document()
        document["expires_at"] = "2026-03-04T00:00:01Z"
        with self.assertRaisesRegex(QualificationError, "maximum lifetime"):
            QualificationReviewerCredential.from_dict(document)

    def test_credential_rejects_role_algorithm_and_unknown_fields(self) -> None:
        document = qualification_reviewer_credential_document()
        document["reviewer_role"] = "candidate_owner"
        with self.assertRaisesRegex(QualificationError, "role is invalid"):
            QualificationReviewerCredential.from_dict(document)

        document = qualification_reviewer_credential_document()
        document["algorithm"] = "unsupported"
        with self.assertRaisesRegex(QualificationError, "must be Ed25519"):
            QualificationReviewerCredential.from_dict(document)

        document = qualification_reviewer_credential_document()
        document["override"] = True
        with self.assertRaisesRegex(QualificationError, "unsupported fields"):
            QualificationReviewerCredential.from_dict(document)

    def test_loaders_reject_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            policy_path = Path(temporary) / "policy.json"
            credential_path = Path(temporary) / "credential.json"
            duplicate = '{"schema_version":1,"schema_version":1}'
            policy_path.write_text(duplicate, encoding="utf-8")
            credential_path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_qualification_trust_policy(policy_path)
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_qualification_reviewer_credential(credential_path)

    def test_contract_parsing_does_not_mutate_inputs(self) -> None:
        policy_document = qualification_trust_policy_document()
        credential_document = qualification_reviewer_credential_document()
        before = copy.deepcopy((policy_document, credential_document))
        QualificationTrustPolicy.from_dict(policy_document)
        QualificationReviewerCredential.from_dict(credential_document)
        self.assertEqual((policy_document, credential_document), before)

    def test_module_has_no_network_storage_or_execution_dependencies(self) -> None:
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

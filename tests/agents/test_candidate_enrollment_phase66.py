"""Phase 66 signed candidate enrollment catalog contract coverage."""

from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.candidate_enrollment import (
    ENROLLMENT_CATALOG_SIGNING_DOMAIN,
    ENROLLMENT_RELEASE_BODY_DOMAIN,
    ENROLLMENT_SIGNER_AUTHORIZATION_SIGNING_DOMAIN,
    CandidateEnrollmentCatalog,
    CandidateEnrollmentEntry,
    CandidateEnrollmentSignerAuthorization,
    load_candidate_enrollment_catalog,
    load_candidate_enrollment_signer_authorization,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
PROFILE_ID = "AOE-GA-D01-S01"


def _private_key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def _encoded_public_key(seed: int) -> str:
    raw = _private_key(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_key_sha256(seed: int) -> str:
    raw = _private_key(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _signature(seed: int = 0) -> str:
    raw = bytes((index + seed) % 256 for index in range(64))
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signer_authorization_document() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "authorization_id": "CEA-11111111111111111111111111111111",
        "authorization_version": 1,
        "d008_decision": {
            "record_id": "QDR-7242E7ED90734BBE96A8036647FA227F",
            "sha256": (
                "sha256:7242e7ed90734bbe96a8036647fa227f"
                "65ef9c254e08cd4e50d3bf3684174850"
            ),
        },
        "d009_decision": {
            "record_id": "CER-8E14690F10D716F768E1EE474B495F55",
            "sha256": (
                "sha256:8e14690f10d716f768e1ee474b495f55"
                "6926b88a4119a201e3c67c7aefb44aeb"
            ),
        },
        "issuer": "sunderkey-qualification-authority",
        "audience": "sunderkey-candidate-enrollment",
        "issued_at": "2026-01-01T00:00:00Z",
        "not_before": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "keys": [
            {
                "key_id": "candidate-enrollment-signer-v1",
                "issuer": "sunderkey-qualification-authority",
                "public_key": _encoded_public_key(10),
                "algorithm": "Ed25519",
                "key_use": "candidate_enrollment_catalog",
                "state": "active",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2026-12-31T00:00:00Z",
                "retire_at": None,
            }
        ],
        "root_key_id": "qualification-offline-root-v1",
        "algorithm": "Ed25519",
        "signature": _signature(),
    }


def enrollment_document(
    *,
    enrollment_id: str = "CEE-11111111111111111111111111111111",
    owner_seed: int = 11,
    owner_key_id: str = "candidate-owner-v1",
    repository_id: str = "sunderkey-evidence-primary",
    predecessor: dict[str, str] | None = None,
    not_before: str = "2026-02-01T00:00:00Z",
    expires_at: str = "2026-06-01T00:00:00Z",
) -> dict[str, Any]:
    return {
        "enrollment_id": enrollment_id,
        "profile_id": PROFILE_ID,
        "candidate": {
            "candidate_id": "development.passive-osint",
            "candidate_version": "1.0.0",
            "candidate_artifact_sha256": "sha256:" + "1" * 64,
        },
        "owner": {
            "owner_id": "sunderkey-candidate-owner",
            "key_id": owner_key_id,
            "public_key": _encoded_public_key(owner_seed),
            "public_key_sha256": _public_key_sha256(owner_seed),
        },
        "repository": {
            "repository_id": repository_id,
            "content_address_scheme": "sha256",
        },
        "not_before": not_before,
        "expires_at": expires_at,
        "predecessor": predecessor,
    }


def _release_body(document: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "schema_version",
        "catalog_id",
        "catalog_version",
        "previous_catalog_sha256",
        "authorization",
        "d009_decision",
        "qualification_policy",
        "issuer",
        "audience",
        "issued_at",
        "not_before",
        "expires_at",
        "enrollments",
        "rotations",
        "revocations",
    )
    return {field: copy.deepcopy(document[field]) for field in fields}


def _bind_release(document: dict[str, Any]) -> None:
    release_hash = _canonical_sha256(
        {"domain": ENROLLMENT_RELEASE_BODY_DOMAIN, "release": _release_body(document)}
    )
    document["release_body_sha256"] = release_hash
    for review in document["reviews"]:
        review["release_body_sha256"] = release_hash


def enrollment_catalog_document() -> dict[str, Any]:
    authorization = CandidateEnrollmentSignerAuthorization.from_dict(
        signer_authorization_document()
    )
    document = {
        "schema_version": 1,
        "catalog_id": "CEC-22222222222222222222222222222222",
        "catalog_version": 1,
        "previous_catalog_sha256": None,
        "authorization": {
            "authorization_id": authorization.authorization_id,
            "authorization_version": authorization.authorization_version,
            "sha256": authorization.content_sha256,
        },
        "d009_decision": signer_authorization_document()["d009_decision"],
        "qualification_policy": {
            "policy_id": "QTP-33333333333333333333333333333333",
            "policy_version": 1,
            "sha256": "sha256:" + "3" * 64,
        },
        "issuer": "sunderkey-qualification-authority",
        "audience": "sunderkey-qualification",
        "issued_at": "2026-02-01T00:00:00Z",
        "not_before": "2026-02-01T00:00:00Z",
        "expires_at": "2026-12-01T00:00:00Z",
        "enrollments": [enrollment_document()],
        "rotations": [],
        "revocations": [],
        "release_body_sha256": "sha256:" + "0" * 64,
        "reviews": [
            {
                "reviewer_id": "reviewer-assurance-001",
                "reviewer_role": "independent_assurance",
                "credential": {
                    "credential_id": "QRC-44444444444444444444444444444444",
                    "sha256": "sha256:" + "4" * 64,
                },
                "reviewed_at": "2026-01-31T22:00:00Z",
                "decision": "approved",
                "release_body_sha256": "sha256:" + "0" * 64,
                "algorithm": "Ed25519",
                "signature": _signature(2),
            },
            {
                "reviewer_id": "reviewer-control-001",
                "reviewer_role": "independent_control",
                "credential": {
                    "credential_id": "QRC-55555555555555555555555555555555",
                    "sha256": "sha256:" + "5" * 64,
                },
                "reviewed_at": "2026-01-31T21:00:00Z",
                "decision": "approved",
                "release_body_sha256": "sha256:" + "0" * 64,
                "algorithm": "Ed25519",
                "signature": _signature(3),
            },
        ],
        "signer_key_id": "candidate-enrollment-signer-v1",
        "algorithm": "Ed25519",
        "signature": _signature(1),
    }
    _bind_release(document)
    return document


class CandidateEnrollmentPhase66Tests(unittest.TestCase):
    def test_contracts_round_trip_with_separated_signing_domains(self) -> None:
        authorization = CandidateEnrollmentSignerAuthorization.from_dict(
            signer_authorization_document()
        )
        catalog = CandidateEnrollmentCatalog.from_dict(enrollment_catalog_document())
        self.assertEqual(
            CandidateEnrollmentSignerAuthorization.from_dict(authorization.to_dict()),
            authorization,
        )
        self.assertEqual(CandidateEnrollmentCatalog.from_dict(catalog.to_dict()), catalog)
        self.assertTrue(
            authorization.signing_bytes().startswith(
                ENROLLMENT_SIGNER_AUTHORIZATION_SIGNING_DOMAIN
            )
        )
        self.assertTrue(catalog.signing_bytes().startswith(ENROLLMENT_CATALOG_SIGNING_DOMAIN))

    def test_catalog_contains_only_logical_repository_addressing(self) -> None:
        document = enrollment_catalog_document()
        serialized = str(document["enrollments"][0]["repository"])
        self.assertEqual(
            document["enrollments"][0]["repository"],
            {
                "repository_id": "sunderkey-evidence-primary",
                "content_address_scheme": "sha256",
            },
        )
        for prohibited in ("endpoint", "credential", "password", "token", "private_key"):
            self.assertNotIn(prohibited, serialized)

    def test_owner_public_key_digest_is_exact(self) -> None:
        document = enrollment_catalog_document()
        document["enrollments"][0]["owner"]["public_key_sha256"] = "sha256:" + "0" * 64
        _bind_release(document)
        with self.assertRaisesRegex(QualificationError, "public key digest"):
            CandidateEnrollmentCatalog.from_dict(document)

    def test_independent_control_and_assurance_are_both_required(self) -> None:
        document = enrollment_catalog_document()
        document["reviews"][1]["reviewer_id"] = document["reviews"][0]["reviewer_id"]
        with self.assertRaisesRegex(QualificationError, "must be distinct"):
            CandidateEnrollmentCatalog.from_dict(document)

        document = enrollment_catalog_document()
        document["reviews"][1]["reviewer_role"] = "independent_assurance"
        with self.assertRaisesRegex(QualificationError, "canonical role order"):
            CandidateEnrollmentCatalog.from_dict(document)

    def test_review_binding_rejects_rehashed_release_change(self) -> None:
        document = enrollment_catalog_document()
        document["enrollments"][0]["expires_at"] = "2026-07-01T00:00:00Z"
        with self.assertRaisesRegex(QualificationError, "release body digest"):
            CandidateEnrollmentCatalog.from_dict(document)

    def test_reviewed_renewal_retains_exact_identity(self) -> None:
        document = enrollment_catalog_document()
        first = CandidateEnrollmentEntry.from_dict(
            document["enrollments"][0],
            label="first",
        )
        document["enrollments"].append(
            enrollment_document(
                enrollment_id="CEE-22222222222222222222222222222222",
                predecessor={
                    "enrollment_id": first.enrollment_id,
                    "sha256": first.content_sha256,
                },
                not_before="2026-05-01T00:00:00Z",
                expires_at="2026-10-01T00:00:00Z",
            )
        )
        _bind_release(document)
        catalog = CandidateEnrollmentCatalog.from_dict(document)
        self.assertEqual(len(catalog.enrollments), 2)

    def test_identity_change_requires_scoped_overlap_record(self) -> None:
        document = enrollment_catalog_document()
        first = CandidateEnrollmentEntry.from_dict(
            document["enrollments"][0],
            label="first",
        )
        successor = enrollment_document(
            enrollment_id="CEE-22222222222222222222222222222222",
            owner_seed=12,
            owner_key_id="candidate-owner-v2",
            predecessor={"enrollment_id": first.enrollment_id, "sha256": first.content_sha256},
            not_before="2026-05-01T00:00:00Z",
            expires_at="2026-10-01T00:00:00Z",
        )
        document["enrollments"].append(successor)
        _bind_release(document)
        with self.assertRaisesRegex(QualificationError, "requires a rotation"):
            CandidateEnrollmentCatalog.from_dict(document)

        successor_entry = CandidateEnrollmentEntry.from_dict(successor, label="successor")
        document["rotations"] = [
            {
                "rotation_id": "CRO-11111111111111111111111111111111",
                "rotation_kind": "owner_key",
                "predecessor": {
                    "enrollment_id": first.enrollment_id,
                    "sha256": first.content_sha256,
                },
                "successor": {
                    "enrollment_id": successor_entry.enrollment_id,
                    "sha256": successor_entry.content_sha256,
                },
                "overlap_not_before": "2026-05-01T00:00:00Z",
                "overlap_expires_at": "2026-06-01T00:00:00Z",
            }
        ]
        _bind_release(document)
        self.assertEqual(len(CandidateEnrollmentCatalog.from_dict(document).rotations), 1)

    def test_revocation_must_name_a_catalog_subject(self) -> None:
        document = enrollment_catalog_document()
        document["revocations"] = [
            {
                "revocation_id": "CRV-11111111111111111111111111111111",
                "revocation_kind": "owner_key",
                "subject_id": "unknown-owner-key",
                "recorded_at": "2026-02-01T00:00:00Z",
                "effective_at": "2026-02-02T00:00:00Z",
                "reason_sha256": "sha256:" + "4" * 64,
            }
        ]
        _bind_release(document)
        with self.assertRaisesRegex(QualificationError, "subject is unknown"):
            CandidateEnrollmentCatalog.from_dict(document)

    def test_loaders_reject_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_candidate_enrollment_signer_authorization(path)
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_candidate_enrollment_catalog(path)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_contracts_match_published_schemas(self) -> None:
        cases = (
            (
                "candidate-enrollment-signer-authorization.schema.json",
                signer_authorization_document(),
            ),
            (
                "candidate-enrollment-catalog.schema.json",
                enrollment_catalog_document(),
            ),
        )
        for filename, document in cases:
            with self.subTest(schema=filename):
                path = ROOT / "registry" / "schemas" / filename
                schema = json.loads(path.read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(document)

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        path = ROOT / "src" / "sunderkey" / "candidate_enrollment.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        prohibited = {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
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

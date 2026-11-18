"""Phase 157 signed containment conformance evidence import tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.candidate_adapter_runner import (
    OCI_GUARANTEES,
    ContainmentBackendAttestation,
)
from sunderkey.candidate_backend_conformance import (
    OCI_PROBES,
    build_conformance_observation,
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_backend_evidence_import import (
    SignedConformanceObservationBatch,
    _verify_evidence_directory,
    build_conformance_probe_challenge,
    build_report_from_verified_conformance_batch,
    finalize_conformance_observation_batch,
    prepare_conformance_observation_batch,
    verify_conformance_observation_batch,
)
from sunderkey.errors import PrincipalAuthenticationError, QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


class CandidateBackendEvidenceImportPhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.conformance.oci",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/containment-conformance-oci",
            license_spdx="LicenseRef-Test-Only",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = public_bytes(self.private_key)
        self.public_key_sha256 = f"sha256:{hashlib.sha256(self.public_key).hexdigest()}"
        self.challenge = build_conformance_probe_challenge(
            catalog=self.catalog,
            attestation=self.attestation,
            collector_id="collector.test.oci",
            key_id="key.test.oci.1",
            public_key_sha256=self.public_key_sha256,
            nonce=b64url(bytes(range(32))),
            sequence_number=7,
            issued_at="2026-09-19T19:00:00Z",
            expires_at="2026-09-19T19:10:00Z",
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.evidence_root = Path(self.temporary.name)
        self.evidence_bytes = b'{"probe":"synthetic","status":"passed"}\n'
        self.evidence_path = self.evidence_root / "probe-evidence.json"
        self.evidence_path.write_bytes(self.evidence_bytes)
        self.evidence_sha256 = f"sha256:{hashlib.sha256(self.evidence_bytes).hexdigest()}"
        self.observations = [
            build_conformance_observation(
                probe_id=probe_id,
                status="passed",
                evidence_sha256=(self.evidence_sha256,),
                measurement={"observed": True, "probe": probe_id},
            )
            for probe_id in OCI_PROBES
        ]
        self.evidence_files = [
            {
                "path": "probe-evidence.json",
                "sha256": self.evidence_sha256,
                "size_bytes": len(self.evidence_bytes),
                "media_type": "application/json",
            }
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def signed_batch(self):
        unsigned = prepare_conformance_observation_batch(
            challenge=self.challenge,
            catalog=self.catalog,
            attestation=self.attestation,
            collected_at="2026-09-19T19:05:00Z",
            observations=self.observations,
            evidence_files=self.evidence_files,
        )
        return finalize_conformance_observation_batch(
            unsigned,
            b64url(self.private_key.sign(unsigned.signing_bytes())),
            self.challenge,
            self.catalog,
            self.attestation,
        )

    def verified_batch(self):
        return verify_conformance_observation_batch(
            batch=self.signed_batch(),
            challenge=self.challenge,
            catalog=self.catalog,
            attestation=self.attestation,
            collector_public_key=self.public_key,
            evidence_root=self.evidence_root,
            observed_at="2026-09-19T19:06:00Z",
        )

    def test_signed_batch_verifies_and_builds_nonqualifying_report(self) -> None:
        batch = self.signed_batch()
        self.assertEqual(batch.sequence_number, 7)
        verified = self.verified_batch()
        report = build_report_from_verified_conformance_batch(
            verified=verified,
            catalog=self.catalog,
            attestation=self.attestation,
        )
        self.assertEqual(report.outcome, "conformant_nonqualifying")
        self.assertEqual(
            report.to_dict()["verifier_id"],
            "signed-collector:collector.test.oci:key.test.oci.1",
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(report.to_dict()[field], "none")

    def test_wrong_key_and_signature_are_rejected(self) -> None:
        batch = self.signed_batch()
        wrong_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(QualificationError, "does not match"):
            verify_conformance_observation_batch(
                batch=batch,
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collector_public_key=public_bytes(wrong_key),
                evidence_root=self.evidence_root,
                observed_at="2026-09-19T19:06:00Z",
            )
        tampered = batch.to_dict()
        tampered["signature"] = b64url(wrong_key.sign(batch.signing_bytes()))
        bad_signature = SignedConformanceObservationBatch.from_dict(
            tampered, self.challenge, self.catalog, self.attestation
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "verification failed"):
            verify_conformance_observation_batch(
                batch=bad_signature,
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collector_public_key=self.public_key,
                evidence_root=self.evidence_root,
                observed_at="2026-09-19T19:06:00Z",
            )

    def test_expired_or_future_challenge_is_rejected(self) -> None:
        batch = self.signed_batch()
        for observed_at in (
            "2026-09-19T18:59:59Z",
            "2026-09-19T19:10:00Z",
        ):
            with self.subTest(observed_at=observed_at):
                with self.assertRaisesRegex(QualificationError, "validity window"):
                    verify_conformance_observation_batch(
                        batch=batch,
                        challenge=self.challenge,
                        catalog=self.catalog,
                        attestation=self.attestation,
                        collector_public_key=self.public_key,
                        evidence_root=self.evidence_root,
                        observed_at=observed_at,
                    )

    def test_challenge_lifetime_is_bounded_and_sequence_is_positive(self) -> None:
        for sequence_number, expires_at, message in (
            (0, "2026-09-19T19:10:00Z", "sequence"),
            (7, "2026-09-19T19:15:01Z", "lifetime"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(QualificationError, message):
                    build_conformance_probe_challenge(
                        catalog=self.catalog,
                        attestation=self.attestation,
                        collector_id="collector.test.oci",
                        key_id="key.test.oci.1",
                        public_key_sha256=self.public_key_sha256,
                        nonce=b64url(bytes(range(32))),
                        sequence_number=sequence_number,
                        issued_at="2026-09-19T19:00:00Z",
                        expires_at=expires_at,
                    )

    def test_observation_order_and_evidence_manifest_are_exact(self) -> None:
        reordered = copy.deepcopy(self.observations)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(QualificationError, "unordered"):
            prepare_conformance_observation_batch(
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collected_at="2026-09-19T19:05:00Z",
                observations=reordered,
                evidence_files=self.evidence_files,
            )
        with self.assertRaisesRegex(QualificationError, "references"):
            prepare_conformance_observation_batch(
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collected_at="2026-09-19T19:05:00Z",
                observations=self.observations,
                evidence_files=[
                    {
                        **self.evidence_files[0],
                        "sha256": ZERO_SHA,
                    }
                ],
            )

    def test_traversal_and_absolute_evidence_paths_are_rejected(self) -> None:
        for path in ("../probe-evidence.json", "/probe-evidence.json", "C:/probe.json"):
            with self.subTest(path=path):
                files = [{**self.evidence_files[0], "path": path}]
                with self.assertRaisesRegex(QualificationError, "relative path|safe relative"):
                    prepare_conformance_observation_batch(
                        challenge=self.challenge,
                        catalog=self.catalog,
                        attestation=self.attestation,
                        collected_at="2026-09-19T19:05:00Z",
                        observations=self.observations,
                        evidence_files=files,
                    )

    def test_evidence_size_hash_and_missing_file_fail_closed(self) -> None:
        batch = self.signed_batch()
        self.evidence_path.write_bytes(b"tampered evidence with a different size")
        with self.assertRaisesRegex(QualificationError, "size does not match"):
            verify_conformance_observation_batch(
                batch=batch,
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collector_public_key=self.public_key,
                evidence_root=self.evidence_root,
                observed_at="2026-09-19T19:06:00Z",
            )
        self.evidence_path.unlink()
        with self.assertRaisesRegex(QualificationError, "escapes"):
            verify_conformance_observation_batch(
                batch=batch,
                challenge=self.challenge,
                catalog=self.catalog,
                attestation=self.attestation,
                collector_public_key=self.public_key,
                evidence_root=self.evidence_root,
                observed_at="2026-09-19T19:06:00Z",
            )

    def test_evidence_growth_after_size_check_is_bounded_and_rejected(self) -> None:
        self.evidence_path.write_bytes(self.evidence_bytes + b"x")
        observed_status = SimpleNamespace(
            st_mode=stat.S_IFREG,
            st_size=len(self.evidence_bytes),
        )
        with patch(
            "sunderkey.candidate_backend_evidence_import.os.fstat",
            return_value=observed_status,
        ):
            with self.assertRaisesRegex(QualificationError, "size changed during reading"):
                _verify_evidence_directory(self.evidence_root, tuple(self.evidence_files))

    def test_batch_cannot_be_rebound_to_another_challenge(self) -> None:
        batch = self.signed_batch()
        other_challenge = build_conformance_probe_challenge(
            catalog=self.catalog,
            attestation=self.attestation,
            collector_id="collector.test.oci",
            key_id="key.test.oci.1",
            public_key_sha256=self.public_key_sha256,
            nonce=b64url(bytes(reversed(range(32)))),
            sequence_number=8,
            issued_at="2026-09-19T19:00:00Z",
            expires_at="2026-09-19T19:10:00Z",
        )
        with self.assertRaisesRegex(QualificationError, "binding"):
            SignedConformanceObservationBatch.from_dict(
                batch.to_dict(), other_challenge, self.catalog, self.attestation
            )

    def test_verified_wrapper_cannot_be_forged_or_substituted(self) -> None:
        verified = self.verified_batch()
        with self.assertRaisesRegex(QualificationError, "proof"):
            replace(verified, proof=b"0" * 32)
        substitute_attestation = ContainmentBackendAttestation.build(
            **{
                **{
                    key: value
                    for key, value in self.attestation.to_dict().items()
                    if key != "attestation_sha256"
                },
                "executable_sha256": ONE_SHA,
                "guarantees": tuple(self.attestation.guarantees),
            }
        )
        with self.assertRaisesRegex(QualificationError, "attestation"):
            build_report_from_verified_conformance_batch(
                verified=verified,
                catalog=self.catalog,
                attestation=substitute_attestation,
            )


if __name__ == "__main__":
    unittest.main()

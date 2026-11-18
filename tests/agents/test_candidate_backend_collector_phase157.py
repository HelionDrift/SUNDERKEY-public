"""Phase 157 external containment collector packaging tests."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.candidate_adapter_runner import (
    OCI_GUARANTEES,
    ContainmentBackendAttestation,
)
from sunderkey.candidate_backend_collector import (
    MAX_COLLECTION_METADATA_BYTES,
    MAX_PROBE_MEASUREMENT_BYTES,
    ConformanceCollectorPlan,
    ProbeCapture,
    build_conformance_collector_plan,
    publish_signed_conformance_collection,
    verify_published_conformance_collection,
)
from sunderkey.candidate_backend_conformance import (
    OCI_PROBES,
    load_containment_conformance_suite_catalog,
)
from sunderkey.candidate_backend_evidence_import import build_conformance_probe_challenge
from sunderkey.candidate_backend_host_preflight import (
    assess_containment_host_preflight,
    build_containment_backend_deployment_binding,
    build_containment_host_snapshot,
    compute_provider_binary_bundle_sha256,
    compute_provider_configuration_bundle_sha256,
)
from sunderkey.errors import PrincipalAuthenticationError, QualificationError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class CandidateBackendCollectorPhase157Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_containment_conformance_suite_catalog(
            REGISTRY_DIR / "candidate-containment-conformance-suites-v1.json"
        )
        self.binaries = [
            {
                "name": "podman",
                "version": "test-1",
                "sha256": ZERO_SHA,
                "source_url": "https://example.invalid/podman",
                "license_spdx": "Apache-2.0",
            }
        ]
        self.configurations = [
            {
                "name": "containment-policy",
                "sha256": ONE_SHA,
                "media_type": "application/json",
            }
        ]
        binary_digest = compute_provider_binary_bundle_sha256(self.binaries, "oci_container")
        configuration_digest = compute_provider_configuration_bundle_sha256(self.configurations)
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.collector.oci",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=binary_digest,
            configuration_sha256=configuration_digest,
            source_url="https://example.invalid/containment-collector-oci",
            license_spdx="Apache-2.0",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )
        self.binding = build_containment_backend_deployment_binding(
            catalog=self.catalog,
            attestation=self.attestation,
            host_id="host.test.collector-oci",
            architecture="x86_64",
            service_identity_id="service.test.collector-oci",
            binary_components=self.binaries,
            configuration_components=self.configurations,
        )
        self.snapshot = self.build_snapshot()
        self.preflight = assess_containment_host_preflight(
            binding=self.binding,
            snapshot=self.snapshot,
            catalog=self.catalog,
            attestation=self.attestation,
        )
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.challenge = build_conformance_probe_challenge(
            catalog=self.catalog,
            attestation=self.attestation,
            collector_id="collector.test.oci",
            key_id="key.test.oci.1",
            public_key_sha256=f"sha256:{hashlib.sha256(self.public_key).hexdigest()}",
            nonce=b64url(bytes(range(32))),
            sequence_number=11,
            issued_at="2026-09-19T21:00:00Z",
            expires_at="2026-09-19T21:10:00Z",
        )
        self.plan = build_conformance_collector_plan(
            catalog=self.catalog,
            attestation=self.attestation,
            binding=self.binding,
            snapshot=self.snapshot,
            preflight=self.preflight,
            challenge=self.challenge,
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_snapshot(self, **overrides):
        values = {
            "host_id": "host.test.collector-oci",
            "collected_at": "2026-09-19T20:55:00Z",
            "os_name": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.12.0-test",
            "service_identity_id": "service.test.collector-oci",
            "binary_components": [{**self.binaries[0], "path": "/usr/bin/podman"}],
            "configuration_components": self.configurations,
            "cgroup_version": "v2",
            "seccomp_enabled": True,
            "rootless_provider": True,
            "user_namespace_enabled": True,
            "kvm_access": False,
            "dedicated_jailer_uid_gid": False,
            "single_tenant_vm": False,
            "bounded_logging": False,
            "host_hardening": False,
        }
        values.update(overrides)
        return build_containment_host_snapshot(**values)

    def captures(self, failed_probe: str | None = None) -> list[ProbeCapture]:
        result = []
        for index, probe_id in enumerate(OCI_PROBES, start=1):
            status = "failed" if probe_id == failed_probe else "passed"
            evidence = json.dumps(
                {
                    "probe_id": probe_id,
                    "sequence": index,
                    "status": status,
                    "synthetic_fixture": True,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            result.append(
                ProbeCapture(
                    probe_id=probe_id,
                    status=status,
                    measurement={
                        "probe_id": probe_id,
                        "observed": status == "passed",
                        "synthetic_fixture": True,
                    },
                    evidence=evidence,
                )
            )
        return result

    def publish(self, name: str, captures: list[ProbeCapture] | None = None):
        return publish_signed_conformance_collection(
            output_directory=self.root / name,
            plan=self.plan,
            catalog=self.catalog,
            attestation=self.attestation,
            binding=self.binding,
            snapshot=self.snapshot,
            preflight=self.preflight,
            challenge=self.challenge,
            captures=self.captures() if captures is None else captures,
            collected_at="2026-09-19T21:05:00Z",
            signer=self.private_key.sign,
            collector_public_key=self.public_key,
        )

    def verify(self, name: str):
        return verify_published_conformance_collection(
            directory=self.root / name,
            expected_plan=self.plan,
            catalog=self.catalog,
            attestation=self.attestation,
            binding=self.binding,
            snapshot=self.snapshot,
            preflight=self.preflight,
            challenge=self.challenge,
            collector_public_key=self.public_key,
            observed_at="2026-09-19T21:06:00Z",
        )

    def test_plan_binds_exact_host_challenge_and_ordered_probes(self) -> None:
        raw = self.plan.to_dict()
        self.assertEqual(self.plan.probe_count, 18)
        self.assertEqual(raw["binding_id"], self.binding.binding_id)
        self.assertEqual(raw["snapshot_id"], self.snapshot.snapshot_id)
        self.assertEqual(raw["preflight_report_id"], self.preflight.report_id)
        self.assertEqual(raw["challenge_id"], self.challenge.challenge_id)
        self.assertEqual(
            [item["probe_id"] for item in raw["probe_steps"]],
            list(OCI_PROBES),
        )
        self.assertEqual(
            ConformanceCollectorPlan.from_dict(
                raw,
                catalog=self.catalog,
                attestation=self.attestation,
                binding=self.binding,
                snapshot=self.snapshot,
                preflight=self.preflight,
                challenge=self.challenge,
            ),
            self.plan,
        )
        for field in (
            "qualification_effect",
            "routing_effect",
            "deployment_effect",
            "target_authority_effect",
        ):
            self.assertEqual(raw[field], "none")

    def test_blocked_host_cannot_create_a_collector_plan(self) -> None:
        blocked_snapshot = self.build_snapshot(rootless_provider=False)
        blocked_preflight = assess_containment_host_preflight(
            binding=self.binding,
            snapshot=blocked_snapshot,
            catalog=self.catalog,
            attestation=self.attestation,
        )
        with self.assertRaisesRegex(QualificationError, "passing host preflight"):
            build_conformance_collector_plan(
                catalog=self.catalog,
                attestation=self.attestation,
                binding=self.binding,
                snapshot=blocked_snapshot,
                preflight=blocked_preflight,
                challenge=self.challenge,
            )

    def test_published_collection_is_import_ready_and_exact(self) -> None:
        published = self.publish("complete")
        self.assertEqual(published.report.outcome, "conformant_nonqualifying")
        self.assertEqual(published.batch.sequence_number, 11)
        self.assertTrue((published.output_directory / "collector-plan.json").is_file())
        self.assertTrue((published.output_directory / "observation-batch.json").is_file())
        self.assertTrue((published.output_directory / "collection-manifest.json").is_file())
        self.assertEqual(self.verify("complete").collection_id, published.collection_id)

    def test_failure_is_preserved_as_a_signed_nonconforming_report(self) -> None:
        published = self.publish("failed", self.captures(failed_probe="network_deny_verified"))
        self.assertEqual(published.report.outcome, "nonconforming")
        self.assertEqual(
            published.report.to_dict()["failed_probe_ids"],
            ["network_deny_verified"],
        )

    def test_missing_reordered_and_duplicate_evidence_fail_closed(self) -> None:
        with self.assertRaisesRegex(QualificationError, "incomplete"):
            self.publish("missing", self.captures()[:-1])
        reordered = self.captures()
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(QualificationError, "unordered"):
            self.publish("reordered", reordered)
        duplicated = self.captures()
        duplicated[1] = ProbeCapture(
            probe_id=duplicated[1].probe_id,
            status=duplicated[1].status,
            measurement=duplicated[1].measurement,
            evidence=duplicated[0].evidence,
        )
        with self.assertRaisesRegex(QualificationError, "unique"):
            self.publish("duplicated", duplicated)

    def test_wrong_signature_tampering_extra_files_and_collision_are_rejected(self) -> None:
        wrong_key = Ed25519PrivateKey.generate()
        with self.assertRaises(PrincipalAuthenticationError):
            publish_signed_conformance_collection(
                output_directory=self.root / "wrong-key",
                plan=self.plan,
                catalog=self.catalog,
                attestation=self.attestation,
                binding=self.binding,
                snapshot=self.snapshot,
                preflight=self.preflight,
                challenge=self.challenge,
                captures=self.captures(),
                collected_at="2026-09-19T21:05:00Z",
                signer=wrong_key.sign,
                collector_public_key=self.public_key,
            )
        published = self.publish("tampered")
        evidence_path = next((published.output_directory / "evidence").iterdir())
        evidence_path.write_bytes(b"x" * evidence_path.stat().st_size)
        with self.assertRaisesRegex(QualificationError, "hash"):
            self.verify("tampered")
        published = self.publish("extra")
        (published.output_directory / "unexpected.txt").write_text("unexpected")
        with self.assertRaisesRegex(QualificationError, "inventory"):
            self.verify("extra")
        with self.assertRaisesRegex(QualificationError, "already exists"):
            self.publish("extra")

    def test_excess_inventory_entries_fail_before_evidence_verification(self) -> None:
        published = self.publish("many-entries")
        expected_count = len(list(published.output_directory.rglob("*")))
        for index in range(4 * expected_count + 33):
            (published.output_directory / f"extra-{index:03d}").mkdir()
        with self.assertRaisesRegex(QualificationError, "inventory exceeds hard limits"):
            self.verify("many-entries")

    def test_metadata_rejects_duplicate_noncanonical_and_oversized_json(self) -> None:
        published = self.publish("all-metadata-canonical")
        for name in (
            "collector-plan.json",
            "observation-batch.json",
            "collection-manifest.json",
        ):
            with self.subTest(name=name):
                path = published.output_directory / name
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(QualificationError, "not canonical JSON"):
                    self.verify("all-metadata-canonical")
                path.write_bytes(original)

        published = self.publish("duplicate-metadata")
        manifest = published.output_directory / "collection-manifest.json"
        data = manifest.read_bytes()
        manifest.write_bytes(data.replace(
            b'"status":',
            b'"status":"published_signed_pending_import","status":',
            1,
        ))
        with self.assertRaisesRegex(QualificationError, "could not be loaded"):
            self.verify("duplicate-metadata")

        published = self.publish("noncanonical-metadata")
        manifest = published.output_directory / "collection-manifest.json"
        manifest.write_text(json.dumps(json.loads(manifest.read_text()), indent=2))
        with self.assertRaisesRegex(QualificationError, "not canonical JSON"):
            self.verify("noncanonical-metadata")

        published = self.publish("oversized-metadata")
        manifest = published.output_directory / "collection-manifest.json"
        manifest.write_bytes(b" " * (MAX_COLLECTION_METADATA_BYTES + 1))
        with self.assertRaisesRegex(QualificationError, "hard limit"):
            self.verify("oversized-metadata")

    def test_publication_refuses_oversized_probe_measurement(self) -> None:
        captures = self.captures()
        first = captures[0]
        captures[0] = ProbeCapture(
            probe_id=first.probe_id,
            status=first.status,
            measurement={"oversized": "x" * MAX_PROBE_MEASUREMENT_BYTES},
            evidence=first.evidence,
        )
        with self.assertRaisesRegex(QualificationError, "measurement exceeds"):
            self.publish("oversized-publication", captures)
        self.assertFalse((self.root / "oversized-publication").exists())


if __name__ == "__main__":
    unittest.main()

"""Phase 157 immutable evidence packet and six-stage gate tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.build_candidate_development_gates import load_adapters
from sunderkey.candidate_adapter_evidence import (
    BLOCKED_STATUS,
    GATE_CATALOG_DOMAIN,
    GATE_DOMAIN,
    GATE_STAGES,
    MAX_PACKET_ARTIFACT_BYTES,
    MAX_PACKET_MANIFEST_BYTES,
    PACKET_DOMAIN,
    CandidateDevelopmentGateCatalog,
    CandidateEvidencePacket,
    _read_bounded_regular_file,
    build_candidate_development_gate_catalog,
    load_candidate_development_gate_catalog,
)
from sunderkey.candidate_adapter_runner import (
    OCI_GUARANTEES,
    BackendExecutionReport,
    ContainmentBackendAttestation,
    ContainmentLimits,
    execute_contained_adapter,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import AdapterInvocation, AdapterResult
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_sha256
from sunderkey.reference_adapters import build_reference_adapters

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_DIR = ROOT / "registry"
GATES_PATH = REGISTRY_DIR / "candidate-adapter-development-gates-v1.json"
ZERO_SHA = "sha256:" + "0" * 64
ONE_SHA = "sha256:" + "1" * 64


class PacketBackend:
    def __init__(self, adapter) -> None:
        self.adapter = adapter
        self.attestation = ContainmentBackendAttestation.build(
            backend_id="containment.test.packet",
            backend_version="test-1",
            isolation_class="oci_container",
            executable_sha256=ZERO_SHA,
            configuration_sha256=ONE_SHA,
            source_url="https://example.invalid/packet-test-backend",
            license_spdx="LicenseRef-Test-Only",
            host_os="linux",
            guarantees=tuple(sorted(OCI_GUARANTEES)),
        )

    def execute(self, plan, request):
        return BackendExecutionReport(
            plan_id=plan.plan_id,
            backend_attestation_sha256=self.attestation.attestation_sha256,
            started_at="2026-09-19T12:00:01Z",
            finished_at="2026-09-19T12:00:02Z",
            output_bytes=1024,
            timed_out=False,
            cancelled=False,
            result=self.adapter.execute(request),
        )

    def cancel(self, plan_id: str) -> bool:
        return bool(plan_id)


def api_invocation(adapter) -> AdapterInvocation:
    return AdapterInvocation(
        invocation_id="INV-EVIDENCE-001",
        mission_id="MISSION-SYNTHETIC-001",
        authority_ref="AUTH-SYNTHETIC-001",
        profile_id=adapter.manifest.profile_id,
        vector_id=adapter.manifest.vector_id,
        target_id="TARGET-SYNTHETIC-001",
        scope_id="SCOPE-SYNTHETIC-001",
        action_tier="R0",
        environment="synthetic",
        dry_run=True,
        credential_refs=(),
        input_data={
            "exchanges": [
                {
                    "evidence_id": "http-1",
                    "subject_id": "user-a",
                    "object_id": "object-b",
                    "expected_permitted": False,
                    "status_code": 200,
                }
            ]
        },
    )


class CandidateAdapterEvidencePhase157Tests(unittest.TestCase):
    def test_bounded_reader_requires_a_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular.json"
            regular.write_bytes(b"{}\n")
            self.assertEqual(_read_bounded_regular_file(regular, 2), b"{}\n")
            with self.assertRaises(OSError):
                _read_bounded_regular_file(root, 2)
            with patch.object(
                Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFIFO)
            ):
                with self.assertRaises(OSError):
                    _read_bounded_regular_file(regular, 2)
            link = root / "link.json"
            try:
                link.symlink_to(regular)
            except (NotImplementedError, OSError):
                pass
            else:
                with self.assertRaises(OSError):
                    _read_bounded_regular_file(link, 2)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO required")
    def test_bounded_reader_rejects_fifo_without_waiting_for_a_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "control.json"
            os.mkfifo(fifo)
            # Verify the existing stat gate without charging Python interpreter
            # startup to the FIFO decision. Opening the FIFO fails this test
            # immediately rather than waiting for a writer.
            with patch(
                "sunderkey.candidate_adapter_evidence.os.open",
                side_effect=AssertionError("FIFO must not be opened"),
            ) as opened:
                with self.assertRaisesRegex(OSError, "not a regular file"):
                    _read_bounded_regular_file(fifo, 100)
                opened.assert_not_called()

    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter_catalog = load_adapters()
        cls.adapters = build_reference_adapters(cls.adapter_catalog)
        cls.gates = load_candidate_development_gate_catalog(GATES_PATH, cls.adapter_catalog)

    def build_packet(self):
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = PacketBackend(adapter)
        request = api_invocation(adapter)
        plan = prepare_containment_execution_plan(
            adapter.manifest,
            request,
            backend.attestation,
            ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at="2026-09-19T12:01:00Z",
        )
        result = adapter.execute(request)
        receipt = execute_contained_adapter(
            backend,
            plan,
            request,
            observed_at="2026-09-19T12:00:01Z",
        )
        packet = CandidateEvidencePacket.build(
            manifest=adapter.manifest,
            attestation=backend.attestation,
            plan=plan,
            receipt=receipt,
            result=result,
            created_at="2026-09-19T12:00:03Z",
        )
        return packet, result

    def test_checked_gate_catalog_matches_source_bound_builder(self) -> None:
        expected = build_candidate_development_gate_catalog(self.adapter_catalog, ROOT)
        self.assertEqual(
            GATES_PATH.read_text(encoding="utf-8"),
            json.dumps(expected.to_dict(), ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.gates.catalog_sha256, expected.catalog_sha256)

    def test_all_candidates_have_five_reference_passes_and_one_real_blocker(self) -> None:
        document = self.gates.to_dict()
        self.assertEqual(
            document["coverage_summary"],
            {
                "candidate_count": 6,
                "gate_record_count": 36,
                "passed_reference_gate_count": 30,
                "blocked_gate_count": 6,
                "phase158_ready_candidate_count": 0,
            },
        )
        for profile_id, records in self.gates.records_by_profile_id.items():
            with self.subTest(profile_id=profile_id):
                self.assertEqual(tuple(item["stage"] for item in records), GATE_STAGES)
                containment = next(item for item in records if item["stage"] == "containment")
                self.assertEqual(containment["status"], BLOCKED_STATUS)
                self.assertEqual(len([item for item in records if not item["blockers"]]), 5)

    def test_rehashed_containment_pass_substitution_is_rejected(self) -> None:
        changed = copy.deepcopy(self.gates.to_dict())
        record = next(item for item in changed["gate_records"] if item["stage"] == "containment")
        record["status"] = "passed_reference_nonqualifying"
        record["blockers"] = []
        gate_body = {key: value for key, value in record.items() if key != "gate_sha256"}
        record["gate_sha256"] = _canonical_sha256({"domain": GATE_DOMAIN, "gate": gate_body})
        catalog_body = {key: value for key, value in changed.items() if key != "catalog_sha256"}
        changed["catalog_sha256"] = _canonical_sha256(
            {"domain": GATE_CATALOG_DOMAIN, "catalog": catalog_body}
        )
        with self.assertRaisesRegex(QualificationError, "must remain blocked"):
            CandidateDevelopmentGateCatalog.from_dict(changed, self.adapter_catalog)

    def test_result_and_evidence_round_trip_and_tamper_detection(self) -> None:
        _, result = self.build_packet()
        self.assertEqual(AdapterResult.from_dict(result.to_dict()), result)
        changed = result.to_dict()
        changed["evidence"][0]["content"]["adapter_id"] = "adapter.substituted"
        with self.assertRaisesRegex(QualificationError, "evidence hash"):
            AdapterResult.from_dict(changed)

    def test_packet_publish_verify_and_collision_protection(self) -> None:
        packet, _ = self.build_packet()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet"
            packet.publish(output)
            loaded = CandidateEvidencePacket.from_directory(output)
            self.assertEqual(loaded.packet_id, packet.packet_id)
            self.assertEqual(loaded.packet_sha256, packet.packet_sha256)
            self.assertEqual(dict(loaded.files), dict(packet.files))
            with self.assertRaisesRegex(QualificationError, "already exists"):
                packet.publish(output)

    def test_packet_publish_rejects_forged_files_before_publication(self) -> None:
        packet, _ = self.build_packet()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside.json"
            changed = dict(packet.files)
            changed["adapter-result.json"] = b"{}\n"
            forged_packets = {
                "traversal": replace(
                    packet,
                    files=packet.files + (("../outside.json", b"{}\n"),),
                ),
                "duplicate": replace(
                    packet,
                    files=packet.files + (packet.files[0],),
                ),
                "content": replace(packet, files=tuple(sorted(changed.items()))),
                "identity": replace(packet, packet_id="CEPK-" + "0" * 32),
                "manifest": replace(packet, manifest_json="{}"),
            }
            for label, forged in forged_packets.items():
                with self.subTest(label=label):
                    output = parent / label
                    with self.assertRaises(QualificationError):
                        forged.publish(output)
                    self.assertFalse(output.exists())
                    self.assertFalse(outside.exists())
                    self.assertEqual(list(parent.glob(f".{label}.*")), [])

    def test_packet_artifact_tampering_is_detected(self) -> None:
        packet, _ = self.build_packet()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet"
            packet.publish(output)
            target = output / "adapter-result.json"
            target.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "integrity failed"):
                CandidateEvidencePacket.from_directory(output)

    def test_packet_loader_rejects_duplicate_oversized_and_extra_files(self) -> None:
        packet, _ = self.build_packet()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet"
            packet.publish(output)
            manifest_path = output / "packet-manifest.json"
            original = manifest_path.read_bytes()
            manifest_path.write_bytes(original.replace(
                b'"packet_id":',
                b'"packet_id":"CEPK-00000000000000000000000000000000","packet_id":',
                1,
            ))
            with self.assertRaisesRegex(QualificationError, "could not be loaded"):
                CandidateEvidencePacket.from_directory(output)
            manifest_path.write_bytes(b" " * (MAX_PACKET_MANIFEST_BYTES + 1))
            with self.assertRaisesRegex(QualificationError, "hard limits"):
                CandidateEvidencePacket.from_directory(output)
            manifest_path.write_bytes(original)
            unexpected = output / "unexpected.json"
            unexpected.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
                CandidateEvidencePacket.from_directory(output)
            unexpected.unlink()
            (output / "empty-directory").mkdir()
            with self.assertRaisesRegex(QualificationError, "inventory is not exact"):
                CandidateEvidencePacket.from_directory(output)

    def test_packet_loader_rejects_forged_noncanonical_artifact(self) -> None:
        packet, _ = self.build_packet()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet"
            packet.publish(output)
            manifest_path = output / "packet-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            artifact = manifest["artifacts"][0]
            artifact_path = output / artifact["path"]
            content = artifact_path.read_bytes() + b" "
            artifact_path.write_bytes(content)
            artifact["byte_size"] = len(content)
            artifact["sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
            body = {
                key: value for key, value in manifest.items()
                if key not in {"packet_id", "packet_sha256"}
            }
            digest = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
            manifest["packet_sha256"] = digest
            manifest["packet_id"] = "CEPK-" + digest.removeprefix("sha256:")[:32].upper()
            manifest_path.write_bytes(
                (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
                .encode("utf-8")
            )
            with self.assertRaisesRegex(QualificationError, "not canonical JSON"):
                CandidateEvidencePacket.from_directory(output)

            artifact["byte_size"] = MAX_PACKET_ARTIFACT_BYTES + 1
            body = {
                key: value for key, value in manifest.items()
                if key not in {"packet_id", "packet_sha256"}
            }
            digest = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
            manifest["packet_sha256"] = digest
            manifest["packet_id"] = "CEPK-" + digest.removeprefix("sha256:")[:32].upper()
            manifest_path.write_bytes(
                (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
                .encode("utf-8")
            )
            with self.assertRaisesRegex(QualificationError, "hard limits"):
                CandidateEvidencePacket.from_directory(output)

    def test_packet_rejects_result_not_bound_to_receipt(self) -> None:
        packet, result = self.build_packet()
        self.assertEqual(packet.manifest["result_sha256"], result.result_sha256)
        replacement = AdapterResult.build(
            status="completed",
            disposition="negative_result",
            observations=(),
            evidence=(),
            restoration_status="not_required",
        )
        adapter = self.adapters["AOE-GB-D06-S09"]
        backend = PacketBackend(adapter)
        request = api_invocation(adapter)
        plan = prepare_containment_execution_plan(
            adapter.manifest,
            request,
            backend.attestation,
            ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at="2026-09-19T12:01:00Z",
        )
        receipt = execute_contained_adapter(
            backend, plan, request, observed_at="2026-09-19T12:00:01Z"
        )
        with self.assertRaisesRegex(QualificationError, "inconsistent"):
            CandidateEvidencePacket.build(
                manifest=adapter.manifest,
                attestation=backend.attestation,
                plan=plan,
                receipt=receipt,
                result=replacement,
                created_at="2026-09-19T12:00:03Z",
            )


if __name__ == "__main__":
    unittest.main()

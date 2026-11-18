"""Native SDK restoration and reciprocal contained-execution integrity tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_evidence import PACKET_DOMAIN, CandidateEvidencePacket
from sunderkey.candidate_adapter_runner import (
    RECEIPT_DOMAIN,
    ContainmentExecutionPlan,
    ContainmentExecutionReceipt,
    ContainmentLimits,
    execute_contained_adapter,
    prepare_containment_execution_plan,
)
from sunderkey.candidate_adapter_sdk import (
    SOURCE_PATH,
    AdapterResult,
    build_candidate_adapter_catalog,
)
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError
from sunderkey.qualification import _canonical_json, _canonical_sha256
from sunderkey.reference_adapters import OfflineReferenceAdapter, build_reference_adapters
from tests.agents import test_candidate_execution_evidence_import_phase157 as signed_fixture_module
from tests.agents.test_candidate_adapter_runner_phase157 import (
    TestBackend as FixtureBackend,
)
from tests.agents.test_candidate_adapter_runner_phase157 import (
    attestation,
    invocation,
)
from tests.agents.test_candidate_adapter_sdk_phase157 import invocation as sdk_invocation

ROOT = Path(__file__).resolve().parents[2]


class NativeIntAlias(int):
    """An equal-valued, nonnative counter fixture."""


class NativeStringAlias(str):
    """An equal-valued, nonnative text fixture."""


def readdress_receipt(raw: dict) -> dict:
    document = copy.deepcopy(raw)
    body = {
        key: value for key, value in document.items() if key not in {"receipt_id", "receipt_sha256"}
    }
    digest = _canonical_sha256({"domain": RECEIPT_DOMAIN, "receipt": body})
    document["receipt_sha256"] = digest
    document["receipt_id"] = f"CER-{digest.removeprefix('sha256:')[:32].upper()}"
    return document


def adversarial_packet(
    packet: CandidateEvidencePacket, receipt_raw: dict
) -> CandidateEvidencePacket:
    """Readdress test-only malicious artifacts without using the repaired producer."""

    files = dict(packet.files)
    files["execution-receipt.json"] = (_canonical_json(receipt_raw) + "\n").encode("ascii")
    manifest = packet.manifest
    manifest["receipt_id"] = receipt_raw["receipt_id"]
    manifest["receipt_sha256"] = receipt_raw["receipt_sha256"]
    for artifact in manifest["artifacts"]:
        content = files[artifact["path"]]
        artifact["byte_size"] = len(content)
        artifact["sha256"] = f"sha256:{hashlib.sha256(content).hexdigest()}"
    body = {
        key: value for key, value in manifest.items() if key not in {"packet_id", "packet_sha256"}
    }
    digest = _canonical_sha256({"domain": PACKET_DOMAIN, "packet": body})
    manifest["packet_sha256"] = digest
    manifest["packet_id"] = f"CEPK-{digest.removeprefix('sha256:')[:32].upper()}"
    files["packet-manifest.json"] = (_canonical_json(manifest) + "\n").encode("ascii")
    return CandidateEvidencePacket(
        manifest["packet_id"], digest, _canonical_json(manifest), tuple(sorted(files.items()))
    )


class CandidateSdkExecutionIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        strategy = load_candidate_implementation_strategy(
            ROOT / "registry/candidate-implementation-strategy-v1.json"
        )
        source_sha256 = f"sha256:{hashlib.sha256((ROOT / SOURCE_PATH).read_bytes()).hexdigest()}"
        # Source-bound integration artifacts belong to the release builder. This
        # native in-memory catalog binds the actual source under test instead.
        cls.catalog = build_candidate_adapter_catalog(strategy, load_blueprints(), source_sha256)
        cls.adapters = build_reference_adapters(cls.catalog)

    def setUp(self) -> None:
        self.adapter = self.adapters["AOE-GB-D06-S09"]
        self.invocation = invocation(self.adapter)
        self.attestation = attestation("oci_container")
        self.plan = prepare_containment_execution_plan(
            self.adapter.manifest,
            self.invocation,
            self.attestation,
            ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at="2026-09-19T12:01:00Z",
        )
        self.backend = FixtureBackend(self.adapter, self.attestation)
        self.receipt = self.execute()

    def execute(self) -> ContainmentExecutionReceipt:
        return execute_contained_adapter(
            self.backend,
            self.plan,
            self.invocation,
            observed_at="2026-09-19T12:00:01Z",
        )

    def signed_fixture(self):
        fixture = signed_fixture_module.CandidateExecutionEvidenceImportPhase157Tests(
            "test_signed_packet_verifies_and_binds_complete_execution_chain"
        )
        with mock.patch.object(signed_fixture_module, "load_adapters", return_value=self.catalog):
            fixture.setUp()
        self.addCleanup(fixture.tearDown)
        return fixture

    def test_public_ics_restoration_distinguishes_canonical_state_values(self) -> None:
        adapter = self.adapters["AOE-GD-D19-S01"]
        for before, after in (
            ({"flag": True}, {"flag": 1}),
            ({"counter": 1}, {"counter": 1.0}),
            ({"nested": [{"flag": False}]}, {"nested": [{"flag": 0}]}),
        ):
            with self.subTest(before=before, after=after):
                request = sdk_invocation(
                    adapter.manifest.profile_id,
                    adapter.manifest.vector_id,
                    {
                        "flows": [],
                        "allowed_pairs": [],
                        "state_before": before,
                        "state_after": after,
                    },
                )
                result = adapter.execute(request)
                self.assertEqual(result.restoration_status, "failed_closed")
                self.assertEqual(result.residual_effects, ("synthetic_state_delta_detected",))

    def test_public_ics_unchanged_canonical_state_preserves_restoration(self) -> None:
        adapter = self.adapters["AOE-GD-D19-S01"]
        request = sdk_invocation(
            adapter.manifest.profile_id,
            adapter.manifest.vector_id,
            {
                "flows": [],
                "allowed_pairs": [],
                "state_before": {"a": 1, "b": [True, 1.0]},
                "state_after": {"b": [True, 1.0], "a": 1},
            },
        )
        result = adapter.execute(request)
        self.assertEqual(result.restoration_status, "verified")
        self.assertEqual(result.residual_effects, ())

    def test_public_adapter_rejects_truthy_dry_run_aliases_before_analyzer(self) -> None:
        analyzer = mock.Mock(wraps=self.adapter.analyzer)
        adapter = OfflineReferenceAdapter(self.adapter.manifest, analyzer)
        for value in (1, 1.0, "false", NativeIntAlias(1)):
            with self.subTest(value=value, family=type(value)):
                with self.assertRaisesRegex(QualificationError, "dry_run"):
                    adapter.execute(replace(self.invocation, dry_run=value))
                analyzer.assert_not_called()
        self.assertEqual(adapter.execute(self.invocation).status, "completed")
        analyzer.assert_called_once()

    def test_plan_rejects_unchanged_identity_python_equality_aliases(self) -> None:
        original = self.plan.to_dict()
        for value in (True, 1.0, NativeIntAlias(1)):
            with self.subTest(value=value, family=type(value)):
                changed = copy.deepcopy(original)
                changed["schema_version"] = value
                self.assertEqual(changed["plan_id"], original["plan_id"])
                self.assertEqual(changed["plan_sha256"], original["plan_sha256"])
                with self.assertRaises(QualificationError):
                    ContainmentExecutionPlan.from_dict(
                        changed, self.adapter.manifest, self.invocation, self.attestation
                    )

    def test_plan_rejects_nested_nonnative_counter_without_normalization(self) -> None:
        changed = self.plan.to_dict()
        changed["limits"]["timeout_seconds"] = NativeIntAlias(60)
        with self.assertRaises(QualificationError):
            ContainmentExecutionPlan.from_dict(
                changed, self.adapter.manifest, self.invocation, self.attestation
            )

    def test_valid_plan_and_receipt_replay_preserve_canonical_identity(self) -> None:
        rebuilt_plan = ContainmentExecutionPlan.from_dict(
            self.plan.to_dict(), self.adapter.manifest, self.invocation, self.attestation
        )
        rebuilt_receipt = ContainmentExecutionReceipt.from_dict(
            self.receipt.to_dict(), rebuilt_plan
        )
        self.assertEqual(rebuilt_plan, self.plan)
        self.assertEqual(rebuilt_receipt, self.receipt)

    def test_prior_native_pure_vectors_preserve_hash_domains_and_ids(self) -> None:
        # These historical manifest bytes are test vectors, not a current-source
        # admission. Native current-source tests use the independently built catalog.
        prior_source_sha256 = (
            "sha256:65b7ba1bbbd4b0131707e378bb6194bab0c07cb3455bff9b7db2f3798d931e62"
        )
        strategy = load_candidate_implementation_strategy(
            ROOT / "registry/candidate-implementation-strategy-v1.json"
        )
        historical_catalog = build_candidate_adapter_catalog(
            strategy, load_blueprints(), prior_source_sha256
        )
        adapter = build_reference_adapters(historical_catalog)["AOE-GB-D06-S09"]
        request = invocation(adapter)
        backend = FixtureBackend(adapter, self.attestation)
        plan = prepare_containment_execution_plan(
            adapter.manifest,
            request,
            self.attestation,
            ContainmentLimits(),
            issued_at="2026-09-19T12:00:00Z",
            expires_at="2026-09-19T12:01:00Z",
        )
        receipt = execute_contained_adapter(
            backend, plan, request, observed_at="2026-09-19T12:00:01Z"
        )
        self.assertEqual(plan.plan_id, "CEP-EE6F356788DED22863B212B04F4EB69A")
        self.assertEqual(
            plan.plan_sha256,
            "sha256:ee6f356788ded22863b212b04f4eb69a4714bb55df4f45cef7123a556e47cb08",
        )
        self.assertEqual(receipt.receipt_id, "CER-07B5B8BD166A83142530CAB28C5C7C24")
        self.assertEqual(
            receipt.receipt_sha256,
            "sha256:07b5b8bd166a83142530cab28c5c7c246a8ccd95516e53e21e278e86cd794be3",
        )
        self.assertEqual(ContainmentExecutionReceipt.from_dict(receipt.to_dict(), plan), receipt)

    def test_readdressed_receipt_rejects_nonnative_counters_and_flags(self) -> None:
        cases = (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("duration_seconds", True),
            ("duration_seconds", 1.0),
            ("duration_seconds", NativeIntAlias(1)),
            ("output_bytes", True),
            ("output_bytes", 1024.0),
            ("output_bytes", NativeIntAlias(1024)),
            ("timed_out", 0),
            ("timed_out", 0.0),
            ("cancelled", 0),
            ("cancelled", "false"),
            ("started_at", NativeStringAlias("2026-09-19T12:00:01Z")),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value, family=type(value)):
                changed = self.receipt.to_dict()
                changed[field] = value
                with self.assertRaises(QualificationError):
                    ContainmentExecutionReceipt.from_dict(readdress_receipt(changed), self.plan)

    def test_readdressed_receipt_rejects_impossible_times_and_output(self) -> None:
        cases = (
            {"duration_seconds": -1},
            {"duration_seconds": 2},
            {"started_at": "not-a-time"},
            {"finished_at": "2026-09-19T12:00:00Z", "duration_seconds": -1},
            {"started_at": "2026-09-19T11:59:59Z", "duration_seconds": 3},
            {"finished_at": "2026-09-19T12:01:01Z", "duration_seconds": 60},
            {"output_bytes": -1},
            {"output_bytes": self.plan.limits.output_bytes + 1},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                changed = self.receipt.to_dict()
                changed.update(mutation)
                with self.assertRaises(QualificationError):
                    ContainmentExecutionReceipt.from_dict(readdress_receipt(changed), self.plan)

    def test_readdressed_receipt_rejects_unknown_or_inconsistent_statuses(self) -> None:
        cases = (
            {"result_status": "unknown"},
            {"result_disposition": "unknown"},
            {"restoration_status": "unknown"},
            {"residual_effects": [1]},
            {"run_status": "unknown"},
            {"run_status": "timed_out_fail_closed"},
            {"timed_out": True, "run_status": "timed_out_fail_closed"},
            {"cancelled": True, "run_status": "cancelled_fail_closed"},
            {"timed_out": True, "result_status": "cancelled"},
        )
        for mutation in cases:
            with self.subTest(mutation=mutation):
                changed = self.receipt.to_dict()
                changed.update(mutation)
                with self.assertRaises(QualificationError):
                    ContainmentExecutionReceipt.from_dict(readdress_receipt(changed), self.plan)

    def test_producer_rejects_backend_native_counter_and_flag_aliases(self) -> None:
        for field, value in (
            ("output_bytes", True),
            ("output_bytes", 1024.0),
            ("output_bytes", NativeIntAlias(1024)),
            ("timed_out", 0),
            ("cancelled", "false"),
        ):
            with self.subTest(field=field, value=value, family=type(value)):
                self.backend = FixtureBackend(self.adapter, self.attestation)
                setattr(self.backend, field, value)
                with self.assertRaises(QualificationError):
                    self.execute()

    def test_adverse_timeout_cancellation_and_residual_records_remain_replayable(self) -> None:
        for timed_out, cancelled, run_status in (
            (True, False, "timed_out_fail_closed"),
            (False, True, "cancelled_fail_closed"),
            (True, True, "timed_out_fail_closed"),
            (False, False, "completed_nonqualifying"),
        ):
            with self.subTest(timed_out=timed_out, cancelled=cancelled):
                self.backend = FixtureBackend(self.adapter, self.attestation)
                self.backend.timed_out = timed_out
                self.backend.cancelled = cancelled
                self.backend.result_override = AdapterResult.build(
                    status="failed_closed",
                    disposition="abstention",
                    observations=(),
                    evidence=(),
                    restoration_status="failed_closed",
                    residual_effects=("synthetic_state_delta_detected",),
                )
                receipt = self.execute()
                self.assertEqual(receipt.run_status, run_status)
                self.assertEqual(
                    ContainmentExecutionReceipt.from_dict(receipt.to_dict(), self.plan), receipt
                )
                packet = CandidateEvidencePacket.build(
                    manifest=self.adapter.manifest,
                    attestation=self.attestation,
                    plan=self.plan,
                    receipt=receipt,
                    result=self.backend.result_override,
                    created_at="2026-09-19T12:00:03Z",
                )
                self.assertEqual(packet.manifest["qualification_effect"], "none")

    def test_packet_builder_rejects_creation_before_completed_execution(self) -> None:
        with self.assertRaisesRegex(QualificationError, "predates|finished_at"):
            CandidateEvidencePacket.build(
                manifest=self.adapter.manifest,
                attestation=self.attestation,
                plan=self.plan,
                receipt=self.receipt,
                result=self.adapter.execute(self.invocation),
                created_at="2026-09-19T12:00:01Z",
            )

    def test_packet_creation_at_finish_is_valid(self) -> None:
        packet = CandidateEvidencePacket.build(
            manifest=self.adapter.manifest,
            attestation=self.attestation,
            plan=self.plan,
            receipt=self.receipt,
            result=self.adapter.execute(self.invocation),
            created_at="2026-09-19T12:00:02Z",
        )
        self.assertEqual(packet.manifest["created_at"], self.receipt.to_dict()["finished_at"])

    def test_zero_output_zero_duration_and_exact_expiry_finish_remain_valid(self) -> None:
        for started, finished in (
            ("2026-09-19T12:00:01Z", "2026-09-19T12:00:01Z"),
            ("2026-09-19T12:00:00Z", "2026-09-19T12:01:00Z"),
        ):
            with self.subTest(started=started, finished=finished):
                self.backend.started_at = started
                self.backend.finished_at = finished
                self.backend.output_bytes = 0
                receipt = self.execute()
                self.assertEqual(
                    ContainmentExecutionReceipt.from_dict(receipt.to_dict(), self.plan), receipt
                )

    def test_known_abstained_hypothesis_result_remains_nonqualifying_evidence(self) -> None:
        self.backend.result_override = AdapterResult.build(
            status="abstained",
            disposition="hypothesis",
            observations=(),
            evidence=(),
            restoration_status="not_required",
        )
        receipt = self.execute()
        self.assertEqual(receipt.run_status, "completed_nonqualifying")
        self.assertEqual(
            ContainmentExecutionReceipt.from_dict(receipt.to_dict(), self.plan), receipt
        )

    def test_genuinely_signed_impossible_execution_cannot_be_verified(self) -> None:
        fixture = self.signed_fixture()
        packet, _ = fixture.build_packet()
        original = json.loads(dict(packet.files)["execution-receipt.json"])
        for index, mutation in enumerate(
            (
                {"duration_seconds": -1},
                {"started_at": "2026-09-20T00:59:59Z", "duration_seconds": 3},
                {"finished_at": "2026-09-20T01:00:09Z", "duration_seconds": 8},
                {"finished_at": "2026-09-20T01:01:01Z", "duration_seconds": 60},
            )
        ):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(original)
                changed.update(mutation)
                malicious = adversarial_packet(packet, readdress_receipt(changed))
                directory = fixture.root / f"adversarial-{index}"
                malicious.publish(directory)
                submission = fixture.sign(malicious)
                encoded_signature = submission.to_dict()["signature"]
                fixture.private_key.public_key().verify(
                    base64.urlsafe_b64decode(encoded_signature + "=="), submission.signing_bytes()
                )
                with self.assertRaises(QualificationError):
                    fixture.verify(submission, directory)

    def test_signed_adverse_execution_is_preserved_but_not_verified_as_clean(self) -> None:
        fixture = self.signed_fixture()
        result = AdapterResult.build(
            status="failed_closed",
            disposition="abstention",
            observations=(),
            evidence=(),
            restoration_status="failed_closed",
            residual_effects=("synthetic_state_delta_detected",),
        )
        plan = prepare_containment_execution_plan(
            fixture.manifest,
            fixture.invocation,
            fixture.attestation,
            ContainmentLimits(),
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:01:00Z",
        )
        backend = signed_fixture_module.EvidenceBackend(fixture.attestation, result)
        for index, (timed_out, cancelled) in enumerate(
            ((True, False), (False, True), (False, False))
        ):
            with self.subTest(timed_out=timed_out, cancelled=cancelled):
                report = replace(
                    backend.execute(plan, fixture.invocation),
                    timed_out=timed_out,
                    cancelled=cancelled,
                )
                with mock.patch.object(backend, "execute", return_value=report):
                    receipt = execute_contained_adapter(
                        backend, plan, fixture.invocation, observed_at="2026-09-20T01:00:01Z"
                    )
                packet = CandidateEvidencePacket.build(
                    manifest=fixture.manifest,
                    attestation=fixture.attestation,
                    plan=plan,
                    receipt=receipt,
                    result=result,
                    created_at="2026-09-20T01:00:03Z",
                )
                directory = fixture.root / f"adverse-{index}"
                packet.publish(directory)
                stored_packet = CandidateEvidencePacket.from_directory(directory)
                stored_receipt = ContainmentExecutionReceipt.from_dict(
                    json.loads(dict(stored_packet.files)["execution-receipt.json"]), plan
                )
                self.assertEqual(stored_receipt, receipt)
                self.assertEqual(
                    stored_receipt.to_dict()["residual_effects"], list(result.residual_effects)
                )
                with self.assertRaisesRegex(QualificationError, "did not complete cleanly"):
                    fixture.verify(fixture.sign(stored_packet), directory)

    def test_signed_valid_execution_remains_verifiable_after_original_plan_expiry(self) -> None:
        fixture = self.signed_fixture()
        result = fixture.adapter.execute(fixture.invocation)
        plan = prepare_containment_execution_plan(
            fixture.manifest,
            fixture.invocation,
            fixture.attestation,
            ContainmentLimits(),
            issued_at="2026-09-20T01:00:00Z",
            expires_at="2026-09-20T01:00:02Z",
        )
        receipt = execute_contained_adapter(
            signed_fixture_module.EvidenceBackend(fixture.attestation, result),
            plan,
            fixture.invocation,
            observed_at="2026-09-20T01:00:01Z",
        )
        packet = CandidateEvidencePacket.build(
            manifest=fixture.manifest,
            attestation=fixture.attestation,
            plan=plan,
            receipt=receipt,
            result=result,
            created_at="2026-09-20T01:00:03Z",
        )
        directory = fixture.root / "historical-valid"
        packet.publish(directory)
        verified = fixture.verify(fixture.sign(packet), directory)
        self.assertEqual(verified.receipt.receipt_id, receipt.receipt_id)


if __name__ == "__main__":
    unittest.main()

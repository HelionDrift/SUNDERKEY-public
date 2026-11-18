import base64
import copy
import hashlib
import json
import unittest
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None
    Registry = None
    Resource = None

from sunderkey import target_health_custody as custody_store_module
from sunderkey.authorized_target_health_runtime import (
    TargetHealthReceipt,
    TargetHealthStatus,
)
from sunderkey.execution_control_runtime import ExecutionBinding, canonical_json
from sunderkey.target_health_custody_contracts import (
    CUSTODY_STORE_APPLICATION_ID,
    CUSTODY_STORE_MIGRATION_ID,
    CUSTODY_STORE_MIGRATION_SHA256,
    CUSTODY_STORE_MIGRATION_VERSION,
    CUSTODY_STORE_SCHEMA_MANIFEST_SHA256,
    CUSTODY_STORE_SCHEMA_VERSION,
    MAX_DOCUMENT_BYTES,
    SignedTargetHealthCustodyEnvelopeV2,
    TargetHealthCollectorPolicyRevision,
    TargetHealthCollectorPolicyRevocation,
    TargetHealthCurrentHeadInspection,
    TargetHealthCustodyContractError,
    TargetHealthCustodyEvent,
    TargetHealthCustodyHeadBinding,
    TargetHealthCustodyReceipt,
    TargetHealthCustodyVerificationResult,
    TargetHealthSigningContext,
    TargetHealthTrustRoot,
    TargetHealthVerificationMode,
    build_target_health_custody_event,
    build_target_health_custody_receipt,
    execution_binding_sha256,
    parse_target_health_custody_document,
    target_health_chain_id,
    verify_target_health_collector_policy,
    verify_target_health_collector_policy_revocation,
    verify_target_health_custody_envelope_current,
    verify_target_health_custody_envelope_historical,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "target_health_custody_contracts.py"
SCHEMA = ROOT / "registry" / "schemas" / "target-health-custody-v1.schema.json"
RECEIPT_SCHEMA = (
    ROOT / "registry" / "schemas" / "authorized-target-health-observation-v1.schema.json"
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
NO_EFFECTS = {
    "authority_effect": "none",
    "collection_effect": "none",
    "network_call_performed": False,
    "pause_effect": "none",
    "qualification_effect": "none",
    "resume_effect": "none",
    "target_effect_performed": False,
}


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_material(key: Ed25519PrivateKey) -> tuple[str, str]:
    raw = key.public_key().public_bytes_raw()
    return b64(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


class TargetHealthCustodyContractsPhase198Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.root_key = Ed25519PrivateKey.generate()
        self.collector_key = Ed25519PrivateKey.generate()
        root_public, root_fingerprint = public_material(self.root_key)
        collector_public, collector_fingerprint = public_material(self.collector_key)
        self.binding = ExecutionBinding(
            tenant_id="tenant:acme",
            context_id="context:health-1",
            context_sha256=DIGEST_A,
            scope_id="scope:health-1",
            scope_sha256=DIGEST_B,
            target_id="target:app-1",
            target_sha256=DIGEST_C,
            session_id="session:health-1",
            lease_id="lease:health-1",
            fence_epoch=7,
        )
        self.binding_sha256 = execution_binding_sha256(self.binding)
        self.receipt = TargetHealthReceipt(
            status=TargetHealthStatus.REJECTED,
            reason="missing_attestation",
            overall_health=None,
            scope_id=self.binding.scope_id,
            scope_sha256=self.binding.scope_sha256,
            execution_request_id="THQ-0123456789ABCDEF0123456789ABCDEF",
            execution_request_sha256=DIGEST_A,
            admission_receipt_id="ADM-0123456789ABCDEF0123456789ABCDEF",
            admission_receipt_sha256=DIGEST_B,
            execution_policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            execution_policy_sha256=DIGEST_C,
            runtime_policy_id="THP-0123456789ABCDEF0123456789ABCDEF",
            runtime_policy_sha256=DIGEST_A,
            binding=self.binding,
            binding_sha256=self.binding_sha256,
            target_url="https://app.example.test/assess/health",
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
            safety_attestation=None,
            safety_attestation_sha256=None,
            budget_state=None,
            budget_state_sha256=None,
            source_receipts=(),
            observations=(),
            source_validation_performed=False,
        )
        self.root = TargetHealthTrustRoot(
            tenant_id=self.binding.tenant_id,
            mission_id="mission:health-1",
            trust_root_revision=1,
            root_key_id="key:root-2026-09",
            root_public_key=root_public,
            root_public_key_sha256=root_fingerprint,
            deployment_attestation_id="attestation:collector-prod-1",
            deployment_attestation_sha256=DIGEST_B,
            effective_at="2026-09-21T00:00:00Z",
            expires_at="2026-09-22T00:00:00Z",
        )
        chain_id = target_health_chain_id(
            "collector:health-prod-1",
            self.root.mission_id,
            self.binding_sha256,
        )
        policy_unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": chain_id,
            "collector_epoch": 1,
            "collector_id": "collector:health-prod-1",
            "collector_key_id": "key:collector-2026-09",
            "collector_public_key": collector_public,
            "collector_public_key_sha256": collector_fingerprint,
            "deployment_attestation_id": self.root.deployment_attestation_id,
            "deployment_attestation_sha256": self.root.deployment_attestation_sha256,
            "effective_at": "2026-09-21T11:00:00Z",
            "expires_at": "2026-09-21T13:00:00Z",
            "issued_at": "2026-09-21T10:59:00Z",
            "maximum_future_skew_seconds": 5,
            "maximum_observation_age_seconds": 120,
            "mission_id": self.root.mission_id,
            "policy_revision": 1,
            "policy_status": "active",
            "predecessor_policy_id": None,
            "predecessor_policy_sha256": None,
            "prior_epoch_head_envelope_id": None,
            "prior_epoch_head_envelope_sha256": None,
            "revoked": False,
            "runtime_policy_id": self.receipt.runtime_policy_id,
            "runtime_policy_sha256": self.receipt.runtime_policy_sha256,
            "signature_algorithm": "Ed25519",
            "tenant_id": self.binding.tenant_id,
            "trust_root_id": self.root.trust_root_id,
            "trust_root_revision": self.root.trust_root_revision,
            "trust_root_sha256": self.root.trust_root_sha256,
            **NO_EFFECTS,
        }
        root_signature = b64(
            self.root_key.sign(
                TargetHealthCollectorPolicyRevision.signing_bytes_for(policy_unsigned)
            )
        )
        self.policy = TargetHealthCollectorPolicyRevision(
            **{
                key: value
                for key, value in policy_unsigned.items()
                if key not in set(NO_EFFECTS) | {"binding"}
            },
            binding=self.binding,
            root_signature=root_signature,
        )
        envelope_unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": chain_id,
            "collector_epoch": self.policy.collector_epoch,
            "collector_id": self.policy.collector_id,
            "collector_key_id": self.policy.collector_key_id,
            "collector_public_key": self.policy.collector_public_key,
            "collector_public_key_sha256": self.policy.collector_public_key_sha256,
            "deployment_attestation_id": self.policy.deployment_attestation_id,
            "deployment_attestation_sha256": self.policy.deployment_attestation_sha256,
            "mission_id": self.policy.mission_id,
            "observed_at": self.receipt.observed_at,
            "policy_id": self.policy.policy_id,
            "policy_revision": self.policy.policy_revision,
            "policy_sha256": self.policy.policy_sha256,
            "predecessor_envelope_id": None,
            "predecessor_envelope_sha256": None,
            "receipt": self.receipt.to_dict(),
            "receipt_id": self.receipt.receipt_id,
            "receipt_sha256": self.receipt.receipt_sha256,
            "runtime_policy_id": self.receipt.runtime_policy_id,
            "runtime_policy_sha256": self.receipt.runtime_policy_sha256,
            "sequence": 1,
            "signature_algorithm": "Ed25519",
            "tenant_id": self.binding.tenant_id,
            **NO_EFFECTS,
        }
        collector_signature = b64(
            self.collector_key.sign(
                SignedTargetHealthCustodyEnvelopeV2.signing_bytes_for(envelope_unsigned)
            )
        )
        self.envelope = SignedTargetHealthCustodyEnvelopeV2(
            **{
                key: value
                for key, value in envelope_unsigned.items()
                if key not in set(NO_EFFECTS) | {"binding", "receipt"}
            },
            binding=self.binding,
            receipt=self.receipt,
            collector_signature=collector_signature,
        )

    def current_result(self) -> TargetHealthCustodyVerificationResult:
        return verify_target_health_custody_envelope_current(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:10Z",
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=self.envelope.envelope_id,
            expected_head_envelope_sha256=self.envelope.envelope_sha256,
            expected_head_sequence=1,
            policy_revocation=None,
        )

    def make_revocation(
        self,
        revoked_at: str = "2026-09-21T12:00:08Z",
    ) -> TargetHealthCollectorPolicyRevocation:
        unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": self.policy.chain_id,
            "collector_epoch": self.policy.collector_epoch,
            "collector_id": self.policy.collector_id,
            "mission_id": self.policy.mission_id,
            "policy_id": self.policy.policy_id,
            "policy_revision": self.policy.policy_revision,
            "policy_sha256": self.policy.policy_sha256,
            "revocation_reason": "collector_key_compromised",
            "revoked": True,
            "revoked_at": revoked_at,
            "signature_algorithm": "Ed25519",
            "tenant_id": self.policy.tenant_id,
            "terminal": True,
            "trust_root_id": self.root.trust_root_id,
            "trust_root_revision": self.root.trust_root_revision,
            "trust_root_sha256": self.root.trust_root_sha256,
            **NO_EFFECTS,
        }
        signature = b64(
            self.root_key.sign(
                TargetHealthCollectorPolicyRevocation.signing_bytes_for(unsigned)
            )
        )
        return TargetHealthCollectorPolicyRevocation(
            **{
                key: value
                for key, value in unsigned.items()
                if key not in set(NO_EFFECTS) | {"binding"}
            },
            binding=self.binding,
            root_signature=signature,
        )

    def make_current_inspection(
        self,
        revocation: TargetHealthCollectorPolicyRevocation | None = None,
    ) -> TargetHealthCurrentHeadInspection:
        verification = verify_target_health_custody_envelope_current(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:10Z",
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=self.envelope.envelope_id,
            expected_head_envelope_sha256=self.envelope.envelope_sha256,
            expected_head_sequence=self.envelope.sequence,
            policy_revocation=revocation,
        )
        acceptance_verification = verify_target_health_custody_envelope_current(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:10Z",
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=self.envelope.envelope_id,
            expected_head_envelope_sha256=self.envelope.envelope_sha256,
            expected_head_sequence=self.envelope.sequence,
            policy_revocation=None,
        )
        custody = build_target_health_custody_receipt(
            acceptance_verification,
            recorded_at="2026-09-21T12:00:10Z",
        )
        event = build_target_health_custody_event(
            custody,
            event_sequence=self.envelope.sequence,
            predecessor_event_id=None,
            predecessor_event_sha256=None,
            recorded_at="2026-09-21T12:00:10Z",
        )
        head = TargetHealthCustodyHeadBinding(
            tenant_id=self.binding.tenant_id,
            mission_id=self.root.mission_id,
            chain_id=self.policy.chain_id,
            store_application_id=CUSTODY_STORE_APPLICATION_ID,
            store_schema_version=CUSTODY_STORE_SCHEMA_VERSION,
            store_migration_version=CUSTODY_STORE_MIGRATION_VERSION,
            store_migration_id=CUSTODY_STORE_MIGRATION_ID,
            store_migration_sha256=CUSTODY_STORE_MIGRATION_SHA256,
            store_schema_manifest_sha256=CUSTODY_STORE_SCHEMA_MANIFEST_SHA256,
            global_transition_sequence=3 if revocation is not None else 2,
            trust_root_id=self.root.trust_root_id,
            trust_root_sha256=self.root.trust_root_sha256,
            trust_root_revision=self.root.trust_root_revision,
            policy_id=self.policy.policy_id,
            policy_sha256=self.policy.policy_sha256,
            policy_revision=self.policy.policy_revision,
            policy_collector_epoch=self.policy.collector_epoch,
            policy_head_transition_sequence=1,
            policy_revocation_id=(
                None if revocation is None else revocation.revocation_id
            ),
            policy_revocation_sha256=(
                None if revocation is None else revocation.revocation_sha256
            ),
            policy_revoked_at=(None if revocation is None else revocation.revoked_at),
            policy_revocation_transition_sequence=(
                None if revocation is None else 3
            ),
            binding_sha256=self.binding_sha256,
            collector_id=self.policy.collector_id,
            collector_epoch=self.policy.collector_epoch,
            chain_head_sequence=self.envelope.sequence,
            chain_head_envelope_id=self.envelope.envelope_id,
            chain_head_envelope_sha256=self.envelope.envelope_sha256,
            chain_head_custody_receipt_id=custody.custody_receipt_id,
            chain_head_custody_receipt_sha256=custody.custody_receipt_sha256,
            chain_head_policy_id=self.policy.policy_id,
            chain_head_policy_sha256=self.policy.policy_sha256,
            chain_head_transition_sequence=2,
            event_head_sequence=event.event_sequence,
            event_head_event_id=event.event_id,
            event_head_event_sha256=event.event_sha256,
        )
        return TargetHealthCurrentHeadInspection(
            tenant_id=self.binding.tenant_id,
            mission_id=self.root.mission_id,
            chain_id=self.policy.chain_id,
            head_binding=head,
            trust_root=self.root,
            current_policy=self.policy,
            policy_revocation=revocation,
            envelope=self.envelope,
            custody_receipt=custody,
            custody_event=event,
            verification=verification,
            inspected_at=verification.verified_at,
        )

    def test_exact_records_round_trip_through_strict_parser(self) -> None:
        historical = verify_target_health_custody_envelope_historical(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:30:00Z",
        )
        current = self.current_result()
        signing_context = TargetHealthSigningContext(
            tenant_id=self.binding.tenant_id,
            mission_id=self.root.mission_id,
            binding_sha256=self.binding_sha256,
            policy_id=self.policy.policy_id,
            policy_sha256=self.policy.policy_sha256,
            policy_revision=1,
            collector_id=self.policy.collector_id,
            collector_epoch=1,
            chain_id=self.policy.chain_id,
            next_sequence=2,
            previous_envelope_id=self.envelope.envelope_id,
            previous_envelope_sha256=self.envelope.envelope_sha256,
            current_head_sequence=1,
            current_head_envelope_id=self.envelope.envelope_id,
            current_head_envelope_sha256=self.envelope.envelope_sha256,
            prepared_at="2026-09-21T12:00:10Z",
        )
        custody = build_target_health_custody_receipt(
            current,
            recorded_at="2026-09-21T12:00:11Z",
        )
        event = build_target_health_custody_event(
            custody,
            event_sequence=1,
            predecessor_event_id=None,
            predecessor_event_sha256=None,
            recorded_at="2026-09-21T12:00:11Z",
        )
        records = (
            self.root,
            self.policy,
            self.make_revocation(),
            self.envelope,
            signing_context,
            historical,
            current,
            custody,
            event,
        )
        for record in records:
            document = record.to_dict()
            parsed = parse_target_health_custody_document(canonical_json(document))
            self.assertEqual(parsed, record)
            self.assertEqual(
                parse_target_health_custody_document(canonical_json(document).encode()),
                record,
            )
        self.assertIsInstance(self.envelope.receipt, TargetHealthReceipt)
        self.assertIsInstance(custody, TargetHealthCustodyReceipt)
        self.assertIsInstance(event, TargetHealthCustodyEvent)

    def test_historical_verification_never_claims_currentness(self) -> None:
        result = verify_target_health_custody_envelope_historical(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2027-01-01T00:00:00Z",
        )
        self.assertEqual(result.mode, TargetHealthVerificationMode.HISTORICAL)
        self.assertFalse(result.current_policy_verified)
        self.assertFalse(result.current_head_verified)
        self.assertFalse(result.evidence_current_verified)

    def test_chain_identity_is_separated_by_mission(self) -> None:
        other = target_health_chain_id(
            self.policy.collector_id,
            "mission:health-2",
            self.binding_sha256,
        )
        self.assertNotEqual(other, self.policy.chain_id)
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "chain_id"):
            replace(
                self.policy,
                mission_id="mission:health-2",
                policy_id="",
                policy_sha256="",
            )

    def test_root_signed_revocation_is_terminal_and_blocks_current_verification(self) -> None:
        revocation = self.make_revocation()
        self.assertEqual(
            verify_target_health_collector_policy_revocation(
                self.root,
                self.policy,
                revocation,
            ),
            revocation,
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "revoked"):
            verify_target_health_custody_envelope_current(
                self.root,
                self.policy,
                self.envelope,
                verified_at="2026-09-21T12:00:10Z",
                expected_policy_id=self.policy.policy_id,
                expected_policy_sha256=self.policy.policy_sha256,
                expected_head_envelope_id=self.envelope.envelope_id,
                expected_head_envelope_sha256=self.envelope.envelope_sha256,
                expected_head_sequence=1,
                policy_revocation=revocation,
            )
        historical = verify_target_health_custody_envelope_historical(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:10Z",
            policy_revocation=revocation,
        )
        self.assertEqual(historical.mode, TargetHealthVerificationMode.HISTORICAL)
        self.assertEqual(historical.policy_revocation_id, revocation.revocation_id)
        self.assertEqual(
            historical.policy_revocation_sha256,
            revocation.revocation_sha256,
        )
        self.assertEqual(
            parse_target_health_custody_document(canonical_json(historical.to_dict())),
            historical,
        )
        scheduled = self.make_revocation("2026-09-21T12:01:00Z")
        current = verify_target_health_custody_envelope_current(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:10Z",
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=self.envelope.envelope_id,
            expected_head_envelope_sha256=self.envelope.envelope_sha256,
            expected_head_sequence=1,
            policy_revocation=scheduled,
        )
        self.assertEqual(current.policy_revocation_id, scheduled.revocation_id)
        custody = build_target_health_custody_receipt(
            current,
            recorded_at="2026-09-21T12:00:11Z",
        )
        self.assertEqual(custody.to_dict()["policy_revocation_id"], scheduled.revocation_id)
        self.assertEqual(
            parse_target_health_custody_document(canonical_json(custody.to_dict())),
            custody,
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "cannot sign"):
            verify_target_health_custody_envelope_historical(
                self.root,
                self.policy,
                self.envelope,
                verified_at="2026-09-21T12:00:10Z",
                policy_revocation=self.make_revocation("2026-09-21T12:00:04Z"),
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "terminal"):
            replace(
                revocation,
                terminal=False,
                revocation_id="",
                revocation_sha256="",
            )
        tampered = replace(
            revocation,
            root_signature=b64(bytes(64)),
            revocation_id="",
            revocation_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "signature"):
            verify_target_health_collector_policy_revocation(
                self.root,
                self.policy,
                tampered,
            )

    def test_policy_validity_must_be_contained_by_trust_root(self) -> None:
        short_root = replace(
            self.root,
            expires_at="2026-09-21T12:30:00Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        unsigned = self.policy.unsigned_body()
        unsigned.update(
            {
                "trust_root_id": short_root.trust_root_id,
                "trust_root_revision": short_root.trust_root_revision,
                "trust_root_sha256": short_root.trust_root_sha256,
            }
        )
        signature = b64(
            self.root_key.sign(
                TargetHealthCollectorPolicyRevision.signing_bytes_for(unsigned)
            )
        )
        escaping_policy = TargetHealthCollectorPolicyRevision(
            **{
                key: value
                for key, value in unsigned.items()
                if key not in set(NO_EFFECTS) | {"binding"}
            },
            binding=self.binding,
            root_signature=signature,
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "contained"):
            verify_target_health_collector_policy(
                short_root,
                escaping_policy,
                verified_at="2026-09-21T12:00:10Z",
                current=False,
            )

    def test_historical_and_custody_chronology_fail_closed(self) -> None:
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "predates"):
            verify_target_health_custody_envelope_historical(
                self.root,
                self.policy,
                self.envelope,
                verified_at="2026-09-21T12:00:04Z",
            )
        future_result = verify_target_health_custody_envelope_current(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:00:02Z",
            expected_policy_id=self.policy.policy_id,
            expected_policy_sha256=self.policy.policy_sha256,
            expected_head_envelope_id=self.envelope.envelope_id,
            expected_head_envelope_sha256=self.envelope.envelope_sha256,
            expected_head_sequence=1,
            policy_revocation=None,
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "predates"):
            build_target_health_custody_receipt(
                future_result,
                recorded_at="2026-09-21T12:00:03Z",
            )

    def test_current_verification_requires_exact_policy_head_and_freshness(self) -> None:
        result = self.current_result()
        self.assertEqual(result.mode, TargetHealthVerificationMode.CURRENT)
        self.assertTrue(result.current_policy_verified)
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "current head"):
            verify_target_health_custody_envelope_current(
                self.root,
                self.policy,
                self.envelope,
                verified_at="2026-09-21T12:00:10Z",
                expected_policy_id=self.policy.policy_id,
                expected_policy_sha256=self.policy.policy_sha256,
                expected_head_envelope_id="THCE-" + "A" * 32,
                expected_head_envelope_sha256=DIGEST_A,
                expected_head_sequence=1,
                policy_revocation=None,
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "too old"):
            verify_target_health_custody_envelope_current(
                self.root,
                self.policy,
                self.envelope,
                verified_at="2026-09-21T12:02:06Z",
                expected_policy_id=self.policy.policy_id,
                expected_policy_sha256=self.policy.policy_sha256,
                expected_head_envelope_id=self.envelope.envelope_id,
                expected_head_envelope_sha256=self.envelope.envelope_sha256,
                expected_head_sequence=1,
                policy_revocation=None,
            )

    def test_signatures_fingerprints_and_algorithm_fail_closed(self) -> None:
        bad_policy = replace(
            self.policy,
            root_signature=b64(bytes(64)),
            policy_id="",
            policy_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "signature"):
            verify_target_health_custody_envelope_historical(
                self.root,
                bad_policy,
                self.envelope,
                verified_at="2026-09-21T12:00:10Z",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "fingerprint"):
            replace(
                self.root,
                root_public_key_sha256=DIGEST_A,
                trust_root_id="",
                trust_root_sha256="",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "Ed25519"):
            replace(
                self.policy,
                signature_algorithm="HMAC-SHA256",
                policy_id="",
                policy_sha256="",
            )

    def test_tenant_binding_receipt_and_chain_tampering_fail_closed(self) -> None:
        foreign = replace(self.binding, tenant_id="tenant:other")
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "tenant"):
            replace(
                self.policy,
                binding=foreign,
                binding_sha256=execution_binding_sha256(foreign),
                policy_id="",
                policy_sha256="",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "receipt_id"):
            replace(
                self.envelope,
                receipt_id="THR-" + "A" * 32,
                envelope_id="",
                envelope_sha256="",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "deterministic"):
            replace(
                self.policy,
                chain_id="THCH-" + "A" * 32,
                policy_id="",
                policy_sha256="",
            )

    def test_parser_rejects_unknown_duplicate_noncanonical_and_oversized_input(self) -> None:
        document = self.root.to_dict()
        unknown = copy.deepcopy(document)
        unknown["unexpected"] = "value"
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "fields"):
            parse_target_health_custody_document(unknown)
        canonical = canonical_json(document)
        duplicate = canonical[:-1] + ',"tenant_id":"tenant:acme"}'
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "duplicate"):
            parse_target_health_custody_document(duplicate)
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "canonical"):
            parse_target_health_custody_document(json.dumps(document))
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "floating"):
            parse_target_health_custody_document('{"kind":1.5}')
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "size limit"):
            parse_target_health_custody_document(b"{" + b" " * MAX_DOCUMENT_BYTES + b"}")

    def test_parser_rejects_long_strings_non_ascii_and_bool_as_integer(self) -> None:
        document = self.root.to_dict()
        document["mission_id"] = "a" * 32_769
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "string"):
            parse_target_health_custody_document(document)
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "ASCII"):
            parse_target_health_custody_document('{"kind":"caf\\u00e9"}')
        document = self.root.to_dict()
        document["trust_root_revision"] = True
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "revision"):
            parse_target_health_custody_document(document)

    def test_content_identity_and_fixed_effects_are_deterministic(self) -> None:
        rebuilt = SignedTargetHealthCustodyEnvelopeV2.from_dict(self.envelope.to_dict())
        self.assertEqual(rebuilt.envelope_id, self.envelope.envelope_id)
        self.assertEqual(rebuilt.envelope_sha256, self.envelope.envelope_sha256)
        for record in (self.root, self.policy, self.envelope, self.current_result()):
            document = record.to_dict()
            for key, value in NO_EFFECTS.items():
                self.assertEqual(document[key], value)
            lowered_keys = {key.lower() for key in document}
            self.assertFalse(any("private" in key or "secret" in key for key in lowered_keys))

    def test_custody_event_cannot_predate_its_receipt(self) -> None:
        custody = build_target_health_custody_receipt(
            self.current_result(),
            recorded_at="2026-09-21T12:00:11Z",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "predates"):
            build_target_health_custody_event(
                custody,
                event_sequence=1,
                predecessor_event_id=None,
                predecessor_event_sha256=None,
                recorded_at="2026-09-21T12:00:10Z",
            )

    def test_current_head_inspection_round_trip_binds_exact_current_material(self) -> None:
        inspection = self.make_current_inspection()
        self.assertIsNone(inspection.inspection_context_sha256)
        self.assertNotIn("inspection_context_sha256", inspection.to_dict())
        parsed_head = parse_target_health_custody_document(
            canonical_json(inspection.head_binding.to_dict())
        )
        parsed = parse_target_health_custody_document(
            canonical_json(inspection.to_dict())
        )
        self.assertEqual(parsed_head, inspection.head_binding)
        self.assertEqual(parsed, inspection)
        self.assertEqual(
            inspection.current_material_sha256,
            TargetHealthCurrentHeadInspection.material_sha256(
                head_binding=inspection.head_binding,
                trust_root=self.root,
                current_policy=self.policy,
                policy_revocation=None,
                envelope=self.envelope,
                custody_receipt=inspection.custody_receipt,
                custody_event=inspection.custody_event,
                verification=inspection.verification,
            ),
        )
        self.assertEqual(
            inspection.envelope.receipt.status,
            TargetHealthStatus.REJECTED,
        )
        self.assertIsNone(inspection.envelope.receipt.overall_health)
        for effect in (
            "authority_effect",
            "control_effect",
            "qualification_effect",
            "reservation_effect",
        ):
            self.assertEqual(inspection.to_dict()[effect], "none")

    def test_contextual_inspection_round_trip_binds_context_to_identity_only(self) -> None:
        legacy = self.make_current_inspection()
        contextual = replace(
            legacy,
            inspection_context_sha256=DIGEST_A,
            inspection_id="",
            inspection_sha256="",
        )

        parsed = parse_target_health_custody_document(
            canonical_json(contextual.to_dict())
        )
        self.assertEqual(parsed, contextual)
        self.assertEqual(contextual.inspection_context_sha256, DIGEST_A)
        self.assertEqual(
            contextual.current_material_sha256,
            legacy.current_material_sha256,
        )
        self.assertNotEqual(contextual.inspection_id, legacy.inspection_id)
        self.assertNotEqual(contextual.inspection_sha256, legacy.inspection_sha256)

        tampered = contextual.to_dict()
        tampered["inspection_context_sha256"] = DIGEST_B
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "inspection_(id|sha256)",
        ):
            parse_target_health_custody_document(canonical_json(tampered))

    def test_current_head_inspection_embeds_exact_portable_custody_material(self) -> None:
        inspection = self.make_current_inspection()
        self.assertEqual(
            inspection.head_binding.chain_head_custody_receipt_id,
            inspection.custody_receipt.custody_receipt_id,
        )
        self.assertEqual(
            inspection.head_binding.chain_head_custody_receipt_sha256,
            inspection.custody_receipt.custody_receipt_sha256,
        )
        self.assertEqual(
            inspection.head_binding.event_head_event_id,
            inspection.custody_event.event_id,
        )
        self.assertEqual(
            inspection.head_binding.event_head_event_sha256,
            inspection.custody_event.event_sha256,
        )
        self.assertEqual(
            inspection.custody_event.custody_receipt_id,
            inspection.custody_receipt.custody_receipt_id,
        )
        self.assertEqual(
            inspection.custody_event.envelope_id,
            inspection.envelope.envelope_id,
        )

    def test_current_head_inspection_rejects_portable_custody_substitution(self) -> None:
        inspection = self.make_current_inspection()
        substituted_receipt = replace(
            inspection.custody_receipt,
            recorded_at="2026-09-21T12:00:11Z",
            custody_receipt_id="",
            custody_receipt_sha256="",
        )
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "acceptance chronology",
        ):
            replace(
                inspection,
                custody_receipt=substituted_receipt,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

        substituted_event = replace(
            inspection.custody_event,
            recorded_at="2026-09-21T12:00:11Z",
            event_id="",
            event_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "event head"):
            replace(
                inspection,
                custody_event=substituted_event,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

        for field_name in ("custody_receipt", "custody_event"):
            omitted = inspection.to_dict()
            omitted.pop(field_name)
            with self.subTest(omitted=field_name), self.assertRaisesRegex(
                TargetHealthCustodyContractError,
                "fields",
            ):
                parse_target_health_custody_document(omitted)

        unknown = inspection.to_dict()
        unknown["custody_event"]["untrusted_origin"] = "caller"
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "fields"):
            parse_target_health_custody_document(unknown)

    def test_effect_and_store_identity_booleans_fail_parser_type_checks(self) -> None:
        inspection = self.make_current_inspection()
        for field_name in ("network_call_performed", "target_effect_performed"):
            for replacement_value in (0, 1):
                changed = inspection.to_dict()
                changed[field_name] = replacement_value
                with (
                    self.subTest(field=field_name, value=replacement_value),
                    self.assertRaisesRegex(TargetHealthCustodyContractError, "effects"),
                ):
                    parse_target_health_custody_document(changed)

        nested_effect = inspection.to_dict()
        nested_effect["custody_receipt"]["network_call_performed"] = 0
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "effects"):
            parse_target_health_custody_document(nested_effect)

        head = inspection.head_binding.to_dict()
        for field_name in (
            "store_application_id",
            "store_schema_version",
            "store_migration_version",
        ):
            changed = copy.deepcopy(head)
            changed[field_name] = True
            with self.subTest(field=field_name), self.assertRaises(
                TargetHealthCustodyContractError
            ):
                parse_target_health_custody_document(changed)

        for field_path in (
            ("schema_version",),
            ("custody_receipt", "schema_version"),
            ("custody_event", "schema_version"),
        ):
            changed = inspection.to_dict()
            target = changed
            for key in field_path[:-1]:
                target = target[key]
            target[field_path[-1]] = True
            with self.subTest(path=field_path), self.assertRaises(
                TargetHealthCustodyContractError
            ):
                parse_target_health_custody_document(changed)

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema unavailable")
    def test_effect_and_store_identity_booleans_fail_schema_checks(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="ascii"))
        receipt_schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="ascii"))
        registry = Registry().with_resource(
            receipt_schema["$id"],
            Resource.from_contents(receipt_schema),
        )
        validator = Draft202012Validator(schema, registry=registry)
        inspection = self.make_current_inspection()
        documents = []
        for field_name in ("network_call_performed", "target_effect_performed"):
            for replacement_value in (0, 1):
                changed = inspection.to_dict()
                changed[field_name] = replacement_value
                documents.append(changed)
        nested_effect = inspection.to_dict()
        nested_effect["custody_receipt"]["network_call_performed"] = 0
        documents.append(nested_effect)
        for field_name in (
            "store_application_id",
            "store_schema_version",
            "store_migration_version",
        ):
            changed = inspection.head_binding.to_dict()
            changed[field_name] = True
            documents.append(changed)
        for field_path in (
            ("schema_version",),
            ("custody_receipt", "schema_version"),
            ("custody_event", "schema_version"),
        ):
            changed = inspection.to_dict()
            target = changed
            for key in field_path[:-1]:
                target = target[key]
            target[field_path[-1]] = True
            documents.append(changed)
        for index, document in enumerate(documents):
            with self.subTest(index=index):
                self.assertTrue(list(validator.iter_errors(document)))

    def test_current_head_binding_uses_exact_store_identity(self) -> None:
        self.assertEqual(
            CUSTODY_STORE_APPLICATION_ID,
            custody_store_module.APPLICATION_ID,
        )
        self.assertEqual(
            CUSTODY_STORE_SCHEMA_VERSION,
            custody_store_module.SCHEMA_VERSION,
        )
        self.assertEqual(
            CUSTODY_STORE_MIGRATION_ID,
            custody_store_module.MIGRATION_ID,
        )
        self.assertEqual(
            CUSTODY_STORE_MIGRATION_SHA256,
            custody_store_module.MIGRATION_SHA256,
        )
        self.assertEqual(
            CUSTODY_STORE_SCHEMA_MANIFEST_SHA256,
            custody_store_module.EXPECTED_SCHEMA_MANIFEST_SHA256,
        )
        head = self.make_current_inspection().head_binding
        for field_name, replacement_value in (
            ("store_application_id", CUSTODY_STORE_APPLICATION_ID + 1),
            ("store_schema_version", CUSTODY_STORE_SCHEMA_VERSION + 1),
            ("store_migration_version", CUSTODY_STORE_MIGRATION_VERSION + 1),
            ("store_migration_id", CUSTODY_STORE_MIGRATION_ID + ".other"),
            ("store_migration_sha256", DIGEST_A),
            ("store_schema_manifest_sha256", DIGEST_B),
        ):
            with self.subTest(field_name=field_name), self.assertRaises(
                TargetHealthCustodyContractError
            ):
                replace(
                    head,
                    **{field_name: replacement_value},
                    head_binding_id="",
                    head_binding_sha256="",
                )

    def test_current_head_inspection_rejects_substituted_heads_and_transition(self) -> None:
        inspection = self.make_current_inspection()
        head = inspection.head_binding
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "global transition"):
            replace(
                head,
                global_transition_sequence=1,
                head_binding_id="",
                head_binding_sha256="",
            )
        substituted_head = replace(
            head,
            chain_head_envelope_id="THCE-" + "A" * 32,
            chain_head_envelope_sha256=DIGEST_A,
            head_binding_id="",
            head_binding_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "chain head"):
            replace(
                inspection,
                head_binding=substituted_head,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )
        substituted_policy = replace(
            head,
            policy_sha256=DIGEST_A,
            chain_head_policy_sha256=DIGEST_A,
            head_binding_id="",
            head_binding_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "policy head"):
            replace(
                inspection,
                head_binding=substituted_policy,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

    def test_current_head_binding_rejects_impossible_transition_chronology(self) -> None:
        inspection = self.make_current_inspection()
        head = inspection.head_binding
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "precede chain"):
            replace(
                head,
                policy_head_transition_sequence=head.chain_head_transition_sequence,
                head_binding_id="",
                head_binding_sha256="",
            )
        impossible_chain = head.to_dict()
        impossible_chain["policy_head_transition_sequence"] = (
            impossible_chain["chain_head_transition_sequence"]
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "precede chain"):
            parse_target_health_custody_document(impossible_chain)

        revoked = self.make_current_inspection(
            self.make_revocation("2026-09-21T12:01:00Z")
        ).head_binding
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "precede revocation",
        ):
            replace(
                revoked,
                policy_revocation_transition_sequence=(
                    revoked.policy_head_transition_sequence
                ),
                head_binding_id="",
                head_binding_sha256="",
            )
        impossible_revocation = revoked.to_dict()
        impossible_revocation["policy_revocation_transition_sequence"] = (
            impossible_revocation["policy_head_transition_sequence"]
        )
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "precede revocation",
        ):
            parse_target_health_custody_document(impossible_revocation)

    def test_current_head_inspection_rejects_historical_and_receipt_substitution(self) -> None:
        inspection = self.make_current_inspection()
        historical = verify_target_health_custody_envelope_historical(
            self.root,
            self.policy,
            self.envelope,
            verified_at=inspection.inspected_at,
        )
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "custody receipt source material",
        ):
            replace(
                inspection,
                verification=historical,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

    def test_current_head_inspection_rejects_context_time_and_event_head_substitution(
        self,
    ) -> None:
        inspection = self.make_current_inspection()
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "boundary"):
            replace(
                inspection,
                mission_id="mission:other",
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "time"):
            replace(
                inspection,
                inspected_at="2026-09-21T12:00:11Z",
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "sequences"):
            replace(
                inspection.head_binding,
                event_head_sequence=2,
                head_binding_id="",
                head_binding_sha256="",
            )
        substituted_root = replace(
            inspection.head_binding,
            trust_root_sha256=DIGEST_A,
            head_binding_id="",
            head_binding_sha256="",
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "trust root"):
            replace(
                inspection,
                head_binding=substituted_root,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )
        substituted_receipt = replace(
            inspection.verification,
            receipt_id="THR-" + "A" * 32,
            receipt_sha256=DIGEST_A,
            verification_id="",
            verification_sha256="",
        )
        with self.assertRaisesRegex(
            TargetHealthCustodyContractError,
            "custody receipt source material",
        ):
            replace(
                inspection,
                verification=substituted_receipt,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

    def test_current_head_inspection_requires_exact_scheduled_revocation(self) -> None:
        revocation = self.make_revocation("2026-09-21T12:01:00Z")
        inspection = self.make_current_inspection(revocation)
        self.assertEqual(
            inspection.policy_revocation,
            revocation,
        )
        self.assertEqual(
            parse_target_health_custody_document(canonical_json(inspection.to_dict())),
            inspection,
        )
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "omitted"):
            replace(
                inspection,
                policy_revocation=None,
                current_material_sha256="",
                inspection_id="",
                inspection_sha256="",
            )

    def test_current_head_inspection_rejects_effect_claims_and_unknown_fields(self) -> None:
        inspection = self.make_current_inspection()
        claimed = inspection.to_dict()
        claimed["control_effect"] = "pause"
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "effects"):
            parse_target_health_custody_document(claimed)
        unknown = inspection.to_dict()
        unknown["current_health_claim"] = "healthy"
        with self.assertRaisesRegex(TargetHealthCustodyContractError, "fields"):
            parse_target_health_custody_document(unknown)

    @unittest.skipUnless(Draft202012Validator is not None, "jsonschema unavailable")
    def test_closed_schema_accepts_every_public_document(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="ascii"))
        receipt_schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="ascii"))
        registry = Registry().with_resource(
            receipt_schema["$id"],
            Resource.from_contents(receipt_schema),
        )
        validator = Draft202012Validator(schema, registry=registry)
        historical = verify_target_health_custody_envelope_historical(
            self.root,
            self.policy,
            self.envelope,
            verified_at="2026-09-21T12:30:00Z",
        )
        current = self.current_result()
        custody = build_target_health_custody_receipt(
            current,
            recorded_at="2026-09-21T12:00:11Z",
        )
        event = build_target_health_custody_event(
            custody,
            event_sequence=1,
            predecessor_event_id=None,
            predecessor_event_sha256=None,
            recorded_at="2026-09-21T12:00:11Z",
        )
        context = TargetHealthSigningContext(
            tenant_id=self.binding.tenant_id,
            mission_id=self.root.mission_id,
            binding_sha256=self.binding_sha256,
            policy_id=self.policy.policy_id,
            policy_sha256=self.policy.policy_sha256,
            policy_revision=1,
            collector_id=self.policy.collector_id,
            collector_epoch=1,
            chain_id=self.policy.chain_id,
            next_sequence=2,
            previous_envelope_id=self.envelope.envelope_id,
            previous_envelope_sha256=self.envelope.envelope_sha256,
            current_head_sequence=1,
            current_head_envelope_id=self.envelope.envelope_id,
            current_head_envelope_sha256=self.envelope.envelope_sha256,
            prepared_at="2026-09-21T12:00:10Z",
        )
        records = (
            self.root,
            self.policy,
            self.make_revocation(),
            self.envelope,
            context,
            historical,
            current,
            custody,
            event,
            self.make_current_inspection().head_binding,
            self.make_current_inspection(),
            self.make_current_inspection(
                self.make_revocation("2026-09-21T12:01:00Z")
            ).head_binding,
            self.make_current_inspection(
                self.make_revocation("2026-09-21T12:01:00Z")
            ),
        )
        for record in records:
            validator.validate(record.to_dict())
            changed = copy.deepcopy(record.to_dict())
            changed["unexpected"] = False
            self.assertTrue(list(validator.iter_errors(changed)))

    def test_artifacts_are_ascii_without_authorship_markers_or_long_dashes(self) -> None:
        markers = tuple(
            "".join(parts)
            for parts in (
                ("generated", " by"),
                ("written", " by ai"),
                ("as", " an ai"),
                ("chat", "gpt"),
                ("code", "x"),
                ("clau", "de"),
                ("gem", "ini"),
                ("co-authored", "-by"),
            )
        )
        for path in (MODULE, SCHEMA, Path(__file__)):
            text = path.read_bytes().decode("ascii")
            lowered = text.lower()
            self.assertFalse(any(marker in lowered for marker in markers), path)
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()

"""Complete GCS and audit-chain composition remains synthetic and nonqualifying."""

from __future__ import annotations

import copy
import unittest
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime

from sunderkey import custody_release_audit_chain as audit
from sunderkey import gcp_gcs_catalog as catalog
from sunderkey import gcp_gcs_custody as gcs
from sunderkey.candidate_enrollment_production_custody_conformance import (
    CASE_DEFINITIONS,
    REFERENCE_ENVIRONMENT,
    ProductionCustodyConformanceReport,
    build_production_custody_conformance_suite,
    run_production_custody_conformance,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadReadRequest,
    LedgerObjectPutRequest,
    ReleaseAuditAppendRequest,
)
from sunderkey.qualification import _canonical_sha256
from tests.agents import test_gcp_gcs_catalog as catalog_fixture
from tests.agents import test_gcp_gcs_custody as custody_fixture
from tests.agents import test_production_custody_conformance_phase185 as reference

AUDIT_NOW = datetime(2026, 9, 20, 0, 50, tzinfo=UTC)
AUDIT_HORIZON = "2030-01-01T00:00:00Z"
AUDIT_DEPLOYMENT = "deployment.synthetic.composed.audit"


class _FaultAwareAuditChain:
    """Keep D012's explicit test control separate from the real reference append."""

    environment_class = REFERENCE_ENVIRONMENT

    def __init__(self, chain, fault):
        self.chain = chain
        self.fault = fault
        self.receipts = []

    def append_audit_event(self, request):
        self.fault.rejects("audit_append")
        receipt = self.chain.append_audit_event(request)
        self.receipts.append(receipt)
        return receipt


@dataclass(frozen=True)
class _AuditComposition:
    profiles: gcs.GCSCustodyProfiles
    transport: custody_fixture.DeterministicGCSTransport
    arguments: dict
    adapter: _FaultAwareAuditChain


class _CompleteReferenceFactory(catalog_fixture.ThreeMappedCatalogFactory):
    """Four composed ports and four unchanged reference ports, with no cloud IO."""

    def __init__(self, *args):
        super().__init__(*args)
        self.audit_compositions = {}

    def create_bundle(self, case_id, fault_injector):
        bundle = super().create_bundle(case_id, fault_injector)
        horizon = datetime.fromisoformat(AUDIT_HORIZON.removesuffix("Z") + "+00:00")
        declared = gcs.GCSCustodyProfiles(
            gcs.GCSBucketProfile(
                "gcs-offline-composed-audit-ledger",
                "namespace.synthetic.composed.audit.ledger",
                "failure.synthetic.composed.audit.ledger",
                False,
                True,
                int((horizon - custody_fixture.NOW).total_seconds()),
            ),
            gcs.GCSBucketProfile(
                "gcs-offline-composed-audit-head",
                "namespace.synthetic.composed.audit.head",
                "failure.synthetic.composed.audit.head",
                False,
                False,
                0,
            ),
        )
        transport = custody_fixture.DeterministicGCSTransport(declared)
        arguments = {
            "ledger_objects": gcs.GCSRetentionLockedLedgerObjectProvider(
                transport, declared, clock=lambda: AUDIT_NOW
            ),
            "ledger_heads": gcs.GCSConditionalLedgerHeadProvider(
                transport, declared, clock=lambda: AUDIT_NOW
            ),
            "namespace_id": declared.ledger.namespace_id,
            "failure_domain_id": declared.ledger.failure_domain_id,
            "deployment_id": AUDIT_DEPLOYMENT,
            "retention_until": AUDIT_HORIZON,
            "clock": lambda: AUDIT_NOW,
            "maximum_traversal_records": 20,
            "maximum_provider_calls": 100,
            "maximum_read_bytes": 100_000,
            "maximum_object_bytes": 4096,
        }
        adapter = _FaultAwareAuditChain(audit.CustodyReleaseAuditChain(**arguments), fault_injector)
        descriptor = {
            **bundle.provider_descriptor,
            "adapter_id": "gcs_complete_reference_composite",
            "build_sha256": _canonical_sha256({"fixture": "gcs_complete_reference_v1"}),
            "configuration_sha256": _canonical_sha256(
                {
                    "prior": bundle.provider_descriptor["configuration_sha256"],
                    "audit_profiles": asdict(declared),
                    "audit_binding": {
                        key: value
                        for key, value in arguments.items()
                        if key not in {"ledger_objects", "ledger_heads", "clock"}
                    },
                    "audit_clock": "2026-09-20T00:50:00Z",
                }
            ),
        }
        result = replace(bundle, provider_descriptor=descriptor, release_audit=adapter)
        self.audit_compositions[case_id] = _AuditComposition(
            declared, transport, arguments, adapter
        )
        self.bundles[-1] = result
        return result


class GCSCompleteReferenceCompositionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference.ProductionCustodyConformancePhase185Tests.setUpClass()

    def factory(self, family=_CompleteReferenceFactory):
        fixture = reference.ProductionCustodyConformancePhase185Tests
        factory = family(
            fixture.initial_intent,
            fixture.initial_record,
            fixture.replacement_intent,
            fixture.replacement_record,
        )
        self.addCleanup(factory.close)
        return factory

    def bundle(self):
        factory = self.factory()
        case_id = "audit_append_blocks_release"
        bundle = factory.create_bundle(case_id, reference.ReferenceFaultInjector())
        return bundle, factory.audit_compositions[case_id]

    @staticmethod
    def release_head(bundle):
        return bundle.ledger_heads.read_head(
            LedgerHeadReadRequest("request.inspect.release", bundle.initial_head.deployment_id)
        ).head

    @staticmethod
    def audit_head(composition):
        return (
            composition.arguments["ledger_heads"]
            .read_head(LedgerHeadReadRequest("request.inspect.audit", AUDIT_DEPLOYMENT))
            .head
        )

    def seed_release(self, bundle):
        receipt = bundle.ledger_objects.put_if_absent(
            LedgerObjectPutRequest(
                "request.seed.release.object", bundle.ledger_object, bundle.ledger_payload
            )
        )
        self.assertEqual(receipt.write_status, "created")
        receipt = bundle.ledger_heads.compare_and_swap_head(
            LedgerHeadCompareAndSwapRequest("request.seed.release.head", None, bundle.initial_head)
        )
        self.assertEqual(receipt.compare_and_swap_status, "advanced")
        self.assertEqual(self.release_head(bundle), bundle.initial_head)

    @staticmethod
    def audit_then_sign(bundle, request_id):
        receipt = bundle.release_audit.append_audit_event(
            ReleaseAuditAppendRequest(request_id, bundle.audit_event)
        )
        signed = bundle.release_signer.sign_head(bundle.signing_request)
        return receipt, signed

    def assert_no_effects(self, report):
        document = report.to_dict()
        self.assertEqual(document["environment_class"], REFERENCE_ENVIRONMENT)
        self.assertIs(document["independent_review_required"], True)
        for name in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            self.assertEqual(document[name], "none")

    def test_all_twelve_unchanged_d012_cases_compose_gcs_ports_and_audit_chain(self):
        fixture = reference.ProductionCustodyConformancePhase185Tests
        cases_before = copy.deepcopy([case.to_dict() for case in CASE_DEFINITIONS])
        suite = build_production_custody_conformance_suite(fixture.contract)
        factory, faults = self.factory(), reference.ReferenceFaultFactory()
        report = run_production_custody_conformance(fixture.contract, suite, factory, faults)
        self.assertEqual(report.overall_outcome, "conformant", report.to_dict())
        self.assertEqual([case.to_dict() for case in CASE_DEFINITIONS], cases_before)
        self.assertEqual([case.to_dict() for case in suite.cases], cases_before)
        expected_ids = [case.case_id for case in CASE_DEFINITIONS]
        self.assertEqual(factory.created_case_ids, expected_ids)
        self.assertEqual(faults.created_case_ids, expected_ids)
        self.assertEqual([case.case_id for case in report.case_observations], expected_ids)
        self.assertEqual(len(report.case_observations), 12)
        for definition, observation in zip(CASE_DEFINITIONS, report.case_observations, strict=True):
            self.assertEqual(observation.outcome, "pass", observation.to_dict())
            self.assertEqual(
                [item.observed_outcome for item in observation.variant_observations],
                [item.expected_outcome for item in definition.variants],
            )
        self.assert_no_effects(report)
        self.assertEqual(ProductionCustodyConformanceReport.from_dict(report.to_dict()), report)
        for bundle in factory.bundles:
            self.assertIs(type(bundle.catalog_objects), catalog.GCSImmutableCatalogObjectProvider)
            self.assertIs(type(bundle.ledger_objects), gcs.GCSRetentionLockedLedgerObjectProvider)
            self.assertIs(type(bundle.ledger_heads), gcs.GCSConditionalLedgerHeadProvider)
            self.assertIs(type(bundle.release_audit), _FaultAwareAuditChain)
            self.assertIs(type(bundle.release_audit.chain), audit.CustodyReleaseAuditChain)
            self.assertIs(type(bundle.release_signer), reference.InMemorySigner)
            self.assertIs(type(bundle.release_verifier), reference.InMemoryVerifier)
            self.assertIs(type(bundle.workload_identity), reference.InMemoryWorkloadIdentity)
            self.assertIs(type(bundle.checkpoint_access), reference.InMemoryCheckpointAccess)
        for case_id, composition in factory.audit_compositions.items():
            bundle = factory.bundles[expected_ids.index(case_id)]
            release_profiles = bundle.ledger_objects._profiles
            catalog_domain = bundle.catalog_objects._profile.catalog
            self.assertEqual(
                len(
                    {
                        release_profiles.ledger.bucket,
                        release_profiles.head.bucket,
                        catalog_domain.bucket,
                        composition.profiles.ledger.bucket,
                        composition.profiles.head.bucket,
                    }
                ),
                5,
            )
            self.assertNotIn(
                composition.profiles.ledger.namespace_id,
                {bundle.ledger_object.namespace_id, bundle.catalog_object.namespace_id},
            )
            self.assertNotIn(
                composition.profiles.ledger.failure_domain_id,
                {bundle.ledger_object.failure_domain_id, bundle.catalog_object.failure_domain_id},
            )
            self.assertNotEqual(AUDIT_DEPLOYMENT, bundle.initial_head.deployment_id)
            expected_sequence = (
                1
                if case_id in {"audit_append_blocks_release", "partial_release_recovery"}
                else None
            )
            head = self.audit_head(composition)
            self.assertEqual(None if head is None else head.ledger_sequence, expected_sequence)
        case_eleven = factory.audit_compositions["audit_append_blocks_release"]
        self.assertEqual(len(case_eleven.adapter.receipts), 1)
        case_bundle = factory.bundles[expected_ids.index("audit_append_blocks_release")]
        self.assertEqual(case_bundle.release_signer.call_count, 1)

    def test_genuine_audit_failure_makes_unchanged_suite_nonconformant_and_blocks_signer(self):
        class FailedAuditFactory(_CompleteReferenceFactory):
            def create_bundle(self, case_id, fault_injector):
                bundle = super().create_bundle(case_id, fault_injector)
                if case_id == "audit_append_blocks_release":
                    self.audit_compositions[case_id].transport.ambiguous = "before"
                return bundle

        fixture = reference.ProductionCustodyConformancePhase185Tests
        factory = self.factory(FailedAuditFactory)
        report = run_production_custody_conformance(
            fixture.contract,
            build_production_custody_conformance_suite(fixture.contract),
            factory,
            reference.ReferenceFaultFactory(),
        )
        self.assertEqual(report.overall_outcome, "nonconformant")
        observations = {case.case_id: case for case in report.case_observations}
        observed = observations["audit_append_blocks_release"]
        self.assertEqual(observed.outcome, "fail")
        self.assertEqual(
            [item.observed_outcome for item in observed.variant_observations],
            ["unexpected", "blocked"],
        )
        self.assertTrue(
            all(
                case.outcome == "pass"
                for case in report.case_observations
                if case.case_id != "audit_append_blocks_release"
            )
        )
        composition = factory.audit_compositions["audit_append_blocks_release"]
        case_bundle = next(
            bundle for bundle in factory.bundles if bundle.release_audit is composition.adapter
        )
        self.assertEqual(case_bundle.release_signer.call_count, 0)
        self.assertEqual(composition.transport.applied_writes, 0)
        self.assertEqual(len(composition.transport.write_attempts), 1)
        self.assertEqual(composition.adapter.receipts, [])
        self.assertIsNone(self.audit_head(composition))
        self.assert_no_effects(report)

    def test_lost_audit_upload_acknowledgement_blocks_signing_until_explicit_retry(self):
        bundle, composition = self.bundle()
        self.seed_release(bundle)
        release_before = copy.deepcopy(bundle.ledger_objects._transport.objects)
        composition.transport.ambiguous = "after"
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.audit_then_sign(bundle, "request.audit.lost.upload")
        self.assertEqual(bundle.release_signer.call_count, 0)
        self.assertEqual(composition.transport.applied_writes, 1)
        self.assertEqual(len(composition.transport.write_attempts), 1)
        self.assertEqual(len(composition.transport.objects), 1)
        self.assertIsNone(self.audit_head(composition))
        self.assertEqual(composition.adapter.receipts, [])
        self.assertEqual(bundle.ledger_objects._transport.objects, release_before)
        composition.transport.ambiguous = None
        receipt, signed = self.audit_then_sign(bundle, "request.audit.explicit.upload.retry")
        self.assertEqual(receipt.audit_sequence, 1)
        self.assertEqual(receipt.append_status, "appended")
        self.assertEqual(self.audit_head(composition).ledger_sequence, 1)
        self.assertEqual(bundle.release_signer.call_count, 1)
        self.assertEqual(signed.signed_head.head, bundle.initial_head)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_before)

    def test_lost_audit_head_acknowledgement_does_not_authorize_signing_after_apply(self):
        bundle, composition = self.bundle()
        self.seed_release(bundle)
        release_before = copy.deepcopy(bundle.ledger_objects._transport.objects)

        def lose_next_write_acknowledgement(metadata):
            composition.transport.ambiguous = "after"
            return metadata

        composition.transport.write_transform = lose_next_write_acknowledgement
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.audit_then_sign(bundle, "request.audit.lost.head")
        self.assertEqual(bundle.release_signer.call_count, 0)
        self.assertEqual(composition.transport.applied_writes, 2)
        self.assertEqual(len(composition.transport.write_attempts), 2)
        self.assertEqual(composition.adapter.receipts, [])
        self.assertEqual(self.audit_head(composition).ledger_sequence, 1)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_before)
        audit_before = copy.deepcopy(composition.transport.objects)
        composition.transport.ambiguous = composition.transport.write_transform = None
        receipt, signed = self.audit_then_sign(bundle, "request.audit.explicit.head.retry")
        self.assertEqual(receipt.audit_sequence, 1)
        self.assertEqual(receipt.append_status, "already_appended_same_digest")
        self.assertEqual(bundle.release_signer.call_count, 1)
        self.assertEqual(signed.signed_head.head, bundle.initial_head)
        self.assertEqual(composition.transport.applied_writes, 2)
        self.assertEqual(composition.transport.objects, audit_before)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_before)

    def test_audit_successors_and_cold_old_event_replay_are_isolated_from_release_heads(self):
        bundle, composition = self.bundle()
        self.seed_release(bundle)
        release_before = copy.deepcopy(bundle.ledger_objects._transport.objects)
        first = bundle.release_audit.append_audit_event(
            ReleaseAuditAppendRequest("request.audit.first", bundle.audit_event)
        )
        self.assertEqual(first.audit_sequence, 1)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_before)
        head_receipt = bundle.ledger_heads.compare_and_swap_head(
            LedgerHeadCompareAndSwapRequest(
                "request.release.successor",
                bundle.successor_head.previous_head_sha256,
                bundle.successor_head,
            )
        )
        self.assertEqual(head_receipt.compare_and_swap_status, "advanced")
        release_after = copy.deepcopy(bundle.ledger_objects._transport.objects)
        successor_event = replace(
            bundle.audit_event,
            event_id="audit.release.successor",
            artifact_sha256=bundle.successor_head.entry_sha256,
        )
        second = bundle.release_audit.append_audit_event(
            ReleaseAuditAppendRequest("request.audit.successor", successor_event)
        )
        self.assertEqual(second.audit_sequence, 2)
        self.assertEqual(self.release_head(bundle), bundle.successor_head)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_after)
        audit_after = copy.deepcopy(composition.transport.objects)
        writes = composition.transport.applied_writes
        for sink in (
            composition.adapter.chain,
            audit.CustodyReleaseAuditChain(**composition.arguments),
        ):
            repeated = sink.append_audit_event(
                ReleaseAuditAppendRequest("request.audit.old.replay", bundle.audit_event)
            )
            self.assertEqual(repeated.audit_sequence, first.audit_sequence)
            self.assertEqual(repeated.append_status, "already_appended_same_digest")
        self.assertEqual(composition.transport.applied_writes, writes)
        self.assertEqual(composition.transport.objects, audit_after)
        self.assertEqual(self.audit_head(composition).ledger_sequence, 2)
        self.assertEqual(bundle.ledger_objects._transport.objects, release_after)
        self.assertEqual(bundle.release_signer.call_count, 0)


if __name__ == "__main__":
    unittest.main()

"""Phase 164 regional custody contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.regional_custody_contracts import (
    NO_EFFECTS,
    ArtifactCustodyDescriptor,
    CrossRegionTransferRequest,
    CustodyHold,
    RegionalCustodyContractError,
    RetentionSchedule,
    TenantRegionBinding,
    TransferApproval,
    evaluate_deletion_eligibility,
    evaluate_operation_admission,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "regional-custody-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "regional_custody_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "regional-custody-contracts.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")


class RegionalCustodyContractsPhase164Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.evaluate_deletion_eligibility,
            evaluate_deletion_eligibility,
        )
        self.assertIs(
            sunderkey.evaluate_regional_operation_admission,
            evaluate_operation_admission,
        )

    def binding(self, tenant: str = "tenantref:acme") -> TenantRegionBinding:
        return TenantRegionBinding(
            tenant_ref=tenant,
            policy_ref="policyref:regional-custody",
            policy_sha256=DIGESTS[1],
            policy_version="3.2.0",
            home_region="us-east-1",
            allowed_storage_regions=("us-east-1", "us-west-2"),
            allowed_processing_regions=("us-east-1", "us-west-2"),
            encryption_key_ref="keyref:tenant-acme-regional-v4",
            effective_at="2026-09-20T12:00:00Z",
        )

    def descriptor(self, tenant: str = "tenantref:acme") -> ArtifactCustodyDescriptor:
        return ArtifactCustodyDescriptor(
            tenant_ref=tenant,
            artifact_ref="artifactref:assessment-report-001",
            artifact_sha256=DIGESTS[2],
            evidence_ref="evidenceref:assessment-evidence-001",
            evidence_sha256=DIGESTS[3],
            scope_ref="scoperef:admission-001",
            scope_sha256=DIGESTS[4],
            policy_ref="policyref:regional-custody",
            policy_sha256=DIGESTS[1],
            policy_version="3.2.0",
            retention_schedule_ref="scheduleref:restricted-evidence",
            retention_schedule_version="2.1.0",
            classification="restricted",
            storage_region="us-east-1",
            processing_region="us-east-1",
            encryption_key_ref="keyref:tenant-acme-regional-v4",
            captured_at="2025-01-01T00:00:00Z",
        )

    def schedule(self, tenant: str = "tenantref:acme") -> RetentionSchedule:
        return RetentionSchedule(
            tenant_ref=tenant,
            schedule_ref="scheduleref:restricted-evidence",
            schedule_version="2.1.0",
            policy_ref="policyref:regional-custody",
            policy_sha256=DIGESTS[1],
            policy_version="3.2.0",
            classification="restricted",
            required_minimum_days=365,
            retention_days=365,
            deletion_grace_days=30,
            effective_at="2025-01-01T00:00:00Z",
        )

    def approvals(self) -> tuple[TransferApproval, ...]:
        return (
            TransferApproval(
                approval_ref="approvalref:transfer-control-001",
                principal_ref="principalref:reviewer-control",
                role_ref="roleref:independent-control",
                approved_at="2026-09-20T12:01:00Z",
            ),
            TransferApproval(
                approval_ref="approvalref:transfer-assurance-001",
                principal_ref="principalref:reviewer-assurance",
                role_ref="roleref:independent-assurance",
                approved_at="2026-09-20T12:02:00Z",
            ),
        )

    def transfer(self, tenant: str = "tenantref:acme") -> CrossRegionTransferRequest:
        descriptor = self.descriptor(tenant)
        return CrossRegionTransferRequest(
            tenant_ref=descriptor.tenant_ref,
            artifact_ref=descriptor.artifact_ref,
            artifact_sha256=descriptor.artifact_sha256,
            evidence_ref=descriptor.evidence_ref,
            evidence_sha256=descriptor.evidence_sha256,
            scope_ref=descriptor.scope_ref,
            scope_sha256=descriptor.scope_sha256,
            policy_ref=descriptor.policy_ref,
            policy_sha256=descriptor.policy_sha256,
            policy_version=descriptor.policy_version,
            source_region="us-east-1",
            destination_region="us-west-2",
            purpose="storage",
            legal_basis_ref="legalbasisref:customer-dpa-2026",
            approvals=self.approvals(),
            requested_at="2026-09-20T12:03:00Z",
        )

    def active_hold(self) -> CustodyHold:
        descriptor = self.descriptor()
        return CustodyHold(
            tenant_ref=descriptor.tenant_ref,
            artifact_ref=descriptor.artifact_ref,
            artifact_sha256=descriptor.artifact_sha256,
            evidence_ref=descriptor.evidence_ref,
            evidence_sha256=descriptor.evidence_sha256,
            scope_ref=descriptor.scope_ref,
            scope_sha256=descriptor.scope_sha256,
            policy_ref=descriptor.policy_ref,
            policy_sha256=descriptor.policy_sha256,
            policy_version=descriptor.policy_version,
            hold_ref="holdref:incident-2026-17",
            hold_kind="incident",
            authority_ref="authorityref:incident-commander",
            status="active",
            placed_at="2026-01-01T00:00:00Z",
            released_at=None,
        )

    def test_records_are_immutable_content_addressed_and_round_trip(self) -> None:
        records = (
            self.binding(),
            self.descriptor(),
            self.transfer(),
            self.schedule(),
            self.active_hold(),
        )
        for record in records:
            with self.subTest(kind=record.KIND):
                self.assertEqual(record, type(record).from_json(record.to_json()))
                self.assertEqual(record, parse_contract(record.to_dict()))
                self.assertEqual(record.to_dict()["effects"], dict(NO_EFFECTS))
        with self.assertRaises(FrozenInstanceError):
            records[0].home_region = "us-west-2"  # type: ignore[misc]

    def test_transfer_is_admissible_only_with_exact_independent_bindings(self) -> None:
        decision = evaluate_operation_admission(
            self.binding(),
            self.descriptor(),
            operation_ref="operationref:transfer-001",
            operation="transfer",
            requested_region="us-west-2",
            evaluated_at="2026-09-20T12:04:00Z",
            transfer=self.transfer(),
        )
        self.assertEqual(decision.status.value, "eligible_for_external_authorization")
        self.assertEqual(decision.to_dict()["authorization_effect"], "none")
        self.assertEqual(decision, type(decision).from_json(decision.to_json()))
        with self.assertRaisesRegex(RegionalCustodyContractError, "both independent roles"):
            replace(
                self.transfer(),
                approvals=(self.approvals()[0], self.approvals()[0]),
            )

    def test_unknown_regions_and_cross_tenant_use_fail_closed(self) -> None:
        unknown = evaluate_operation_admission(
            self.binding(),
            self.descriptor(),
            operation_ref="operationref:store-001",
            operation="store",
            requested_region="moon-base-1",
            evaluated_at="2026-09-20T12:04:00Z",
        )
        self.assertEqual(unknown.status.value, "denied")
        self.assertIn("unknown_or_disallowed_storage_region", unknown.blocker_codes)
        cross_tenant = evaluate_operation_admission(
            self.binding(),
            self.descriptor("tenantref:other"),
            operation_ref="operationref:process-001",
            operation="process",
            requested_region="us-east-1",
            evaluated_at="2026-09-20T12:04:00Z",
        )
        self.assertEqual(cross_tenant.status.value, "denied")
        self.assertIn("tenant_binding_mismatch", cross_tenant.blocker_codes)

    def test_retention_floor_and_active_hold_block_deletion(self) -> None:
        with self.assertRaisesRegex(RegionalCustodyContractError, "truncates"):
            RetentionSchedule(
                tenant_ref="tenantref:acme",
                schedule_ref="scheduleref:restricted-evidence",
                schedule_version="2.1.0",
                policy_ref="policyref:regional-custody",
                policy_sha256=DIGESTS[1],
                policy_version="3.2.0",
                classification="restricted",
                required_minimum_days=365,
                retention_days=30,
                deletion_grace_days=0,
                effective_at="2025-01-01T00:00:00Z",
            )
        plan = evaluate_deletion_eligibility(
            self.descriptor(),
            self.schedule(),
            (self.active_hold(),),
            evaluated_at="2026-09-20T12:05:00Z",
        )
        self.assertEqual(plan.status.value, "ineligible")
        self.assertIn("active_hold", plan.blocker_codes)
        decision = evaluate_operation_admission(
            self.binding(),
            self.descriptor(),
            operation_ref="operationref:delete-001",
            operation="delete",
            requested_region="us-east-1",
            evaluated_at="2026-09-20T12:06:00Z",
            deletion_plan=plan,
        )
        self.assertEqual(decision.status.value, "denied")
        self.assertIn("deletion_plan_ineligible", decision.blocker_codes)

    def test_expired_retention_produces_plan_not_execution_claim(self) -> None:
        plan = evaluate_deletion_eligibility(
            self.descriptor(),
            self.schedule(),
            (),
            evaluated_at="2026-09-20T12:05:00Z",
        )
        self.assertEqual(plan.status.value, "eligible_for_external_execution")
        self.assertEqual(plan.to_dict()["execution_status"], "planned_only")
        decision = evaluate_operation_admission(
            self.binding(),
            self.descriptor(),
            operation_ref="operationref:delete-002",
            operation="delete",
            requested_region="us-east-1",
            evaluated_at="2026-09-20T12:06:00Z",
            deletion_plan=plan,
        )
        self.assertEqual(decision.status.value, "eligible_for_external_authorization")

    def test_tampering_execution_claims_and_raw_keys_are_rejected(self) -> None:
        changed = copy.deepcopy(self.transfer().to_dict())
        changed["execution_status"] = "completed"
        with self.assertRaisesRegex(RegionalCustodyContractError, "cannot claim execution"):
            CrossRegionTransferRequest.from_dict(changed)
        changed = copy.deepcopy(self.descriptor().to_dict())
        changed["scope_sha256"] = DIGESTS[9]
        with self.assertRaisesRegex(RegionalCustodyContractError, "identity or contents"):
            ArtifactCustodyDescriptor.from_dict(changed)
        with self.assertRaisesRegex(RegionalCustodyContractError, "safe keyref"):
            TenantRegionBinding(
                tenant_ref="tenantref:acme",
                policy_ref="policyref:regional-custody",
                policy_sha256=DIGESTS[1],
                policy_version="3.2.0",
                home_region="us-east-1",
                allowed_storage_regions=("us-east-1",),
                allowed_processing_regions=("us-east-1",),
                encryption_key_ref="-----BEGIN " + "PRIVATE KEY-----",
                effective_at="2026-09-20T12:00:00Z",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_all_contracts_and_rejects_extra_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        eligible = evaluate_deletion_eligibility(
            self.descriptor(), self.schedule(), (), evaluated_at="2026-09-20T12:05:00Z"
        )
        documents = (
            self.binding().to_dict(),
            self.descriptor().to_dict(),
            self.transfer().to_dict(),
            self.schedule().to_dict(),
            self.active_hold().to_dict(),
            eligible.to_dict(),
            evaluate_operation_admission(
                self.binding(),
                self.descriptor(),
                operation_ref="operationref:delete-003",
                operation="delete",
                requested_region="us-east-1",
                evaluated_at="2026-09-20T12:06:00Z",
                deletion_plan=eligible,
            ).to_dict(),
        )
        for document in documents:
            with self.subTest(kind=document["kind"]):
                validator.validate(document)
                changed = copy.deepcopy(document)
                changed["unexpected"] = True
                self.assertTrue(list(validator.iter_errors(changed)))

    def test_increment_has_no_external_clients_unicode_dashes_or_markers(self) -> None:
        markers = (
            "generated " + "by",
            "written " + "by " + "an " + "ai",
            "as " + "an " + "ai",
            "chat" + "gpt",
            "co-authored" + "-by",
        )
        source = FILES[0].read_text(encoding="utf-8")
        for forbidden in (
            "import " + "sqlite3",
            "import " + "psycopg",
            "import " + "socket",
            "import " + "requests",
            "import " + "urllib",
        ):
            self.assertNotIn(forbidden, source)
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in markers:
                self.assertNotIn(marker, lowered, path)


if __name__ == "__main__":
    unittest.main()

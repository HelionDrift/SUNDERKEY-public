"""Phase 162 credential broker contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.credential_broker_contracts import (
    NO_EFFECTS,
    ApprovalAttestation,
    CredentialAccessRequest,
    CredentialBrokerContractError,
    CredentialDescriptor,
    CredentialLifecycleObligation,
    CredentialUsageReceipt,
    IndependentApprovalBinding,
    LeaseMode,
    MultiPrincipalTestIdentitySet,
    ObligationStatus,
    PrincipalCredentialBinding,
    ProviderAdapter,
    UsageOutcome,
    canonical_json,
    issue_lease,
    record_usage,
    validate_access_request,
    verify_content_address,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "credential-broker-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "credential_broker_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "credential-broker-contracts.md",
)
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class CredentialBrokerContractsPhase162Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.adapter = ProviderAdapter(
            provider_ref="providerref:enterprise-vault",
            adapter_ref="adapterref:vault-contract",
            adapter_version="2.4.1",
        )
        self.descriptor = CredentialDescriptor(
            tenant_ref="tenantref:example",
            assessment_ref="assessmentref:authorized-2026-09",
            credential_ref="credentialref:test-principal-a",
            subject_principal_ref="principalref:test-principal-a",
            adapter=self.adapter,
            allowed_target_refs=("targetref:application-a",),
            allowed_technique_refs=("techniqueref:authz-object-boundary",),
            allowed_purpose_refs=("purposeref:authorized-assessment",),
            allowed_scope_refs=("scoperef:read-own-record", "scoperef:update-own-record"),
            allowed_modes=(LeaseMode.ONE_TIME, LeaseMode.SESSION_BOUND),
            max_lease_ttl_seconds=900,
            max_uses_per_lease=4,
            revocation_obligation_ref="obligationref:revoke-on-completion",
            rotation_obligation_ref="obligationref:rotate-on-exposure",
            created_at="2026-09-20T10:00:00Z",
            expires_at="2026-09-21T10:00:00Z",
        )
        self.request = self.make_request()
        self.approval = self.make_approval(self.request)

    def make_request(self, **changes: object) -> CredentialAccessRequest:
        values: dict[str, object] = {
            "descriptor_sha256": self.descriptor.descriptor_sha256,
            "tenant_ref": self.descriptor.tenant_ref,
            "assessment_ref": self.descriptor.assessment_ref,
            "task_ref": "taskref:assessment-step-17",
            "requester_principal_ref": "principalref:operator-7",
            "subject_principal_ref": self.descriptor.subject_principal_ref,
            "target_ref": "targetref:application-a",
            "technique_ref": "techniqueref:authz-object-boundary",
            "purpose_ref": "purposeref:authorized-assessment",
            "requested_scope_refs": ("scoperef:read-own-record",),
            "action_tier": "R2",
            "lease_mode": LeaseMode.SESSION_BOUND,
            "requested_ttl_seconds": 600,
            "requested_max_uses": 3,
            "requested_at": "2026-09-20T11:55:00Z",
            "expires_at": "2026-09-20T12:30:00Z",
        }
        values.update(changes)
        return CredentialAccessRequest(**values)

    def make_approval(
        self, request: CredentialAccessRequest, **changes: object
    ) -> IndependentApprovalBinding:
        values: dict[str, object] = {
            "request_sha256": request.request_sha256,
            "action_tier": request.action_tier,
            "approved_scope_refs": request.requested_scope_refs,
            "approved_ttl_seconds": request.requested_ttl_seconds,
            "approved_max_uses": request.requested_max_uses,
            "lease_mode": request.lease_mode,
            "attestations": (
                ApprovalAttestation(
                    "principalref:control-reviewer",
                    "roleref:credential-control",
                    DIGEST_A,
                ),
                ApprovalAttestation(
                    "principalref:assurance-reviewer",
                    "roleref:independent-assurance",
                    DIGEST_B,
                ),
            ),
            "approved_at": "2026-09-20T11:58:00Z",
            "expires_at": "2026-09-20T12:20:00Z",
        }
        values.update(changes)
        return IndependentApprovalBinding(**values)

    def make_lease(self, **changes: object):
        values: dict[str, object] = {
            "issuance_ref": "issuanceref:lease-event-1",
            "session_ref": "sessionref:preexisting-session-a",
            "now": NOW,
        }
        values.update(changes)
        return issue_lease(self.descriptor, self.request, self.approval, **values)

    def record(self, lease, **changes: object) -> CredentialUsageReceipt:
        values: dict[str, object] = {
            "tenant_ref": lease.tenant_ref,
            "assessment_ref": lease.assessment_ref,
            "task_ref": lease.task_ref,
            "subject_principal_ref": lease.subject_principal_ref,
            "target_ref": lease.target_ref,
            "technique_ref": lease.technique_ref,
            "purpose_ref": lease.purpose_ref,
            "session_ref": lease.session_ref,
            "outcome": UsageOutcome.USED,
            "evidence_hashes": (DIGEST_C,),
            "now": NOW + timedelta(minutes=1),
        }
        values.update(changes)
        return record_usage(lease, **values)

    def test_content_addresses_are_deterministic_and_tamper_evident(self) -> None:
        duplicate = replace(self.descriptor)
        self.assertEqual(duplicate.descriptor_id, self.descriptor.descriptor_id)
        self.assertEqual(duplicate.descriptor_sha256, self.descriptor.descriptor_sha256)
        raw = self.descriptor.to_dict()
        verify_content_address(
            raw,
            id_field="descriptor_id",
            digest_field="descriptor_sha256",
            prefix="CBD",
            domain=CredentialDescriptor.KIND,
        )
        tampered = copy.deepcopy(raw)
        tampered["max_uses_per_lease"] = 5
        with self.assertRaisesRegex(CredentialBrokerContractError, "does not match"):
            verify_content_address(
                tampered,
                id_field="descriptor_id",
                digest_field="descriptor_sha256",
                prefix="CBD",
                domain=CredentialDescriptor.KIND,
            )

    def test_reference_only_fields_and_exact_adapter_version(self) -> None:
        with self.assertRaisesRegex(CredentialBrokerContractError, "opaque reference"):
            replace(self.descriptor, credential_ref="raw-user-name")
        with self.assertRaisesRegex(CredentialBrokerContractError, "exact numeric version"):
            ProviderAdapter("providerref:vault", "adapterref:vault", "latest")
        with self.assertRaisesRegex(CredentialBrokerContractError, "forbidden"):
            canonical_json({"value": "password" + "=plain-text-value"})

    def test_multi_principal_identities_require_distinct_credentials(self) -> None:
        other = replace(
            self.descriptor,
            credential_ref="credentialref:test-principal-b",
            subject_principal_ref="principalref:test-principal-b",
        )
        identity_set = MultiPrincipalTestIdentitySet(
            self.descriptor.tenant_ref,
            self.descriptor.assessment_ref,
            (
                PrincipalCredentialBinding(
                    self.descriptor.subject_principal_ref,
                    self.descriptor.descriptor_sha256,
                ),
                PrincipalCredentialBinding(other.subject_principal_ref, other.descriptor_sha256),
            ),
        )
        self.assertNotEqual(
            identity_set.bindings[0].descriptor_sha256,
            identity_set.bindings[1].descriptor_sha256,
        )
        with self.assertRaisesRegex(CredentialBrokerContractError, "separate credentials"):
            MultiPrincipalTestIdentitySet(
                self.descriptor.tenant_ref,
                self.descriptor.assessment_ref,
                (
                    PrincipalCredentialBinding(
                        "principalref:test-principal-a",
                        self.descriptor.descriptor_sha256,
                    ),
                    PrincipalCredentialBinding(
                        "principalref:test-principal-b",
                        self.descriptor.descriptor_sha256,
                    ),
                ),
            )

    def test_request_binding_substitution_and_overbroad_scope_are_denied(self) -> None:
        cases = (
            ("tenant", {"tenant_ref": "tenantref:other"}),
            ("assessment", {"assessment_ref": "assessmentref:other"}),
            ("principal", {"subject_principal_ref": "principalref:other"}),
            ("target", {"target_ref": "targetref:other"}),
            ("technique", {"technique_ref": "techniqueref:other"}),
            ("purpose", {"purpose_ref": "purposeref:other"}),
        )
        for label, changes in cases:
            with self.subTest(label=label), self.assertRaises(CredentialBrokerContractError):
                validate_access_request(self.descriptor, self.make_request(**changes), now=NOW)
        with self.assertRaisesRegex(CredentialBrokerContractError, "least privilege"):
            validate_access_request(
                self.descriptor,
                self.make_request(requested_scope_refs=("scoperef:administrator",)),
                now=NOW,
            )

    def test_self_approval_and_incomplete_separation_are_denied(self) -> None:
        with self.assertRaisesRegex(CredentialBrokerContractError, "more independent"):
            self.make_approval(
                self.request,
                attestations=(
                    ApprovalAttestation(
                        "principalref:control-reviewer",
                        "roleref:credential-control",
                        DIGEST_A,
                    ),
                ),
            )
        self_approval = self.make_approval(
            self.request,
            attestations=(
                ApprovalAttestation(
                    self.request.requester_principal_ref,
                    "roleref:credential-control",
                    DIGEST_A,
                ),
                ApprovalAttestation(
                    "principalref:assurance-reviewer",
                    "roleref:independent-assurance",
                    DIGEST_B,
                ),
            ),
        )
        with self.assertRaisesRegex(CredentialBrokerContractError, "self-approve"):
            issue_lease(
                self.descriptor,
                self.request,
                self_approval,
                issuance_ref="issuanceref:self-approval",
                session_ref="sessionref:existing",
                now=NOW,
            )

    def test_expiry_replay_and_use_ceilings_fail_closed(self) -> None:
        with self.assertRaisesRegex(CredentialBrokerContractError, "expired"):
            issue_lease(
                self.descriptor,
                self.request,
                self.approval,
                issuance_ref="issuanceref:late",
                session_ref="sessionref:existing",
                now=datetime(2026, 9, 20, 12, 21, tzinfo=UTC),
            )
        with self.assertRaisesRegex(CredentialBrokerContractError, "replay"):
            issue_lease(
                self.descriptor,
                self.request,
                self.approval,
                issuance_ref="issuanceref:replay",
                session_ref="sessionref:existing",
                now=NOW,
                consumed_approval_sha256s=(self.approval.approval_sha256,),
            )

    def test_one_time_and_session_bound_modes_are_enforced(self) -> None:
        one_request = self.make_request(
            lease_mode=LeaseMode.ONE_TIME,
            requested_max_uses=1,
        )
        one_approval = self.make_approval(
            one_request,
            lease_mode=LeaseMode.ONE_TIME,
            approved_max_uses=1,
        )
        one_lease = issue_lease(
            self.descriptor,
            one_request,
            one_approval,
            issuance_ref="issuanceref:one-time",
            session_ref=None,
            now=NOW,
        )
        first = self.record(one_lease, session_ref=None)
        with self.assertRaisesRegex(CredentialBrokerContractError, "exhausted"):
            self.record(one_lease, session_ref=None, prior_receipts=(first,))
        with self.assertRaisesRegex(CredentialBrokerContractError, "requires session_ref"):
            issue_lease(
                self.descriptor,
                self.request,
                self.approval,
                issuance_ref="issuanceref:no-session",
                session_ref=None,
                now=NOW,
            )

    def test_usage_rejects_cross_binding_substitution_replay_and_revocation(self) -> None:
        lease = self.make_lease()
        for label, changes in (
            ("tenant", {"tenant_ref": "tenantref:other"}),
            ("task", {"task_ref": "taskref:other"}),
            ("target", {"target_ref": "targetref:other"}),
            ("principal", {"subject_principal_ref": "principalref:other"}),
        ):
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(CredentialBrokerContractError, "substitution"),
            ):
                self.record(lease, **changes)
        receipt = self.record(lease)
        with self.assertRaisesRegex(CredentialBrokerContractError, "replay"):
            self.record(lease, prior_receipts=(receipt, receipt))
        with self.assertRaisesRegex(CredentialBrokerContractError, "revoked"):
            self.record(lease, revoked_lease_sha256s=(lease.lease_sha256,))
        with self.assertRaisesRegex(CredentialBrokerContractError, "not active"):
            self.record(
                lease,
                now=datetime(2026, 9, 20, 12, 21, tzinfo=UTC),
            )

    def test_renewal_requires_new_request_and_new_approval(self) -> None:
        prior = self.make_lease()
        renewal_request = self.make_request(
            requested_at="2026-09-20T12:02:00Z",
            expires_at="2026-09-20T12:40:00Z",
            renewal_of_lease_sha256=prior.lease_sha256,
        )
        with self.assertRaisesRegex(CredentialBrokerContractError, "not bound"):
            issue_lease(
                self.descriptor,
                renewal_request,
                self.approval,
                issuance_ref="issuanceref:old-approval",
                session_ref="sessionref:preexisting-session-a",
                now=datetime(2026, 9, 20, 12, 3, tzinfo=UTC),
                prior_lease=prior,
            )
        renewal_approval = self.make_approval(
            renewal_request,
            approved_at="2026-09-20T12:02:30Z",
            expires_at="2026-09-20T12:30:00Z",
        )
        renewed = issue_lease(
            self.descriptor,
            renewal_request,
            renewal_approval,
            issuance_ref="issuanceref:renewed",
            session_ref="sessionref:preexisting-session-a",
            now=datetime(2026, 9, 20, 12, 3, tzinfo=UTC),
            prior_lease=prior,
            consumed_approval_sha256s=(prior.approval_sha256,),
        )
        self.assertEqual(renewed.renewal_of_lease_sha256, prior.lease_sha256)
        self.assertNotEqual(renewed.approval_sha256, prior.approval_sha256)

    def test_revocation_and_rotation_obligations_are_evidence_bound(self) -> None:
        lease = self.make_lease()
        receipt = self.record(lease)
        revocation = CredentialLifecycleObligation(
            obligation_kind="revocation",
            obligation_ref=self.descriptor.revocation_obligation_ref,
            descriptor_sha256=self.descriptor.descriptor_sha256,
            lease_sha256=lease.lease_sha256,
            trigger_sha256=receipt.receipt_sha256,
            tenant_ref=lease.tenant_ref,
            assessment_ref=lease.assessment_ref,
            responsible_role_ref="roleref:credential-control",
            reason_ref="reasonref:assessment-completed",
            required_by="2026-09-20T12:30:00Z",
            status=ObligationStatus.PENDING,
        )
        rotation = CredentialLifecycleObligation(
            obligation_kind="rotation",
            obligation_ref=self.descriptor.rotation_obligation_ref,
            descriptor_sha256=self.descriptor.descriptor_sha256,
            lease_sha256=lease.lease_sha256,
            trigger_sha256=revocation.obligation_sha256,
            tenant_ref=lease.tenant_ref,
            assessment_ref=lease.assessment_ref,
            responsible_role_ref="roleref:risk-owner",
            reason_ref="reasonref:reference-exposure",
            required_by="2026-09-20T13:00:00Z",
            status=ObligationStatus.COMPLETED,
            completed_at="2026-09-20T12:40:00Z",
            completion_evidence_sha256=DIGEST_C,
        )
        self.assertEqual(revocation.status, ObligationStatus.PENDING)
        self.assertEqual(rotation.status, ObligationStatus.COMPLETED)
        with self.assertRaisesRegex(CredentialBrokerContractError, "completion proof"):
            replace(revocation, completed_at="2026-09-20T12:10:00Z")

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_all_records_match_the_strict_repository_schema(self) -> None:
        lease = self.make_lease()
        receipt = self.record(lease)
        other = replace(
            self.descriptor,
            credential_ref="credentialref:test-principal-b",
            subject_principal_ref="principalref:test-principal-b",
        )
        identity_set = MultiPrincipalTestIdentitySet(
            self.descriptor.tenant_ref,
            self.descriptor.assessment_ref,
            (
                PrincipalCredentialBinding(
                    self.descriptor.subject_principal_ref,
                    self.descriptor.descriptor_sha256,
                ),
                PrincipalCredentialBinding(other.subject_principal_ref, other.descriptor_sha256),
            ),
        )
        obligation = CredentialLifecycleObligation(
            "revocation",
            self.descriptor.revocation_obligation_ref,
            self.descriptor.descriptor_sha256,
            lease.lease_sha256,
            receipt.receipt_sha256,
            lease.tenant_ref,
            lease.assessment_ref,
            "roleref:credential-control",
            "reasonref:assessment-completed",
            "2026-09-20T12:30:00Z",
            ObligationStatus.PENDING,
        )
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for record in (
            self.descriptor,
            self.request,
            self.approval,
            identity_set,
            lease,
            receipt,
            obligation,
        ):
            with self.subTest(record=type(record).__name__):
                self.assertEqual(list(validator.iter_errors(record.to_dict())), [])
        tampered = self.request.to_dict()
        tampered["raw_value"] = "forbidden"
        self.assertTrue(list(validator.iter_errors(tampered)))

    def test_contract_has_no_operational_side_effect_surface(self) -> None:
        self.assertEqual(
            dict(NO_EFFECTS),
            {
                "approval_authority": "none",
                "authentication": "none",
                "credential_values": "none",
                "decryption": "none",
                "execution": "none",
                "login": "none",
                "network": "none",
                "provider_calls": "none",
                "secret_resolution": "none",
                "session_creation": "none",
                "vault_clients": "none",
            },
        )
        source = FILES[0].read_text(encoding="utf-8")
        for forbidden_import in ("requests", "urllib", "socket", "subprocess"):
            self.assertNotIn("import " + forbidden_import, source)

    def test_changed_files_have_no_unicode_dashes_or_authorship_markers(self) -> None:
        marker = (
            "(?i)("
            + "chat"
            + "gpt|gene"
            + "rated by "
            + "ai|cla"
            + "ude|co-auth"
            + "ored-by|as an "
            + "ai)"
        )
        import re

        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, "[\u2013\u2014]", str(path))
            self.assertIsNone(re.search(marker, text), str(path))


if __name__ == "__main__":
    unittest.main()

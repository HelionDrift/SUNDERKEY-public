"""Phase 162 enterprise identity contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None
    FormatChecker = None

from sunderkey.enterprise_identity_contracts import (
    NO_EFFECTS,
    AuthorizationRequest,
    BindingStatus,
    Decision,
    DutyConstraint,
    EnterpriseIdentityContract,
    EnterpriseIdentityError,
    EnterpriseIdentityPolicy,
    Permission,
    ProvisioningCommand,
    ProvisioningOperation,
    ResourceKind,
    RoleBinding,
    RoleDefinition,
    SsoTrustPolicy,
    VerifiedSsoAssertion,
    admit_sso_assertion,
    authorize,
    canonical_json,
    effective_permissions,
    validate_provisioning_command,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "enterprise-identity-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "enterprise_identity_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "enterprise-identity-contracts.md",
)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TENANT = "tenant:helios"
NOW = "2026-09-20T12:00:00Z"


class EnterpriseIdentityContractsPhase162Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.reader = RoleDefinition(
            TENANT,
            "role:reader",
            (Permission.MISSION_READ,),
            "Read authorized mission metadata.",
        )
        self.approver = RoleDefinition(
            TENANT,
            "role:approver",
            (Permission.MISSION_APPROVE,),
            "Approve an authorized mission plan.",
        )
        self.executor = RoleDefinition(
            TENANT,
            "role:executor",
            (Permission.MISSION_EXECUTE,),
            "Execute an independently approved mission.",
        )
        self.identity_admin = RoleDefinition(
            TENANT,
            "role:identity-admin",
            (Permission.IDENTITY_ADMIN, Permission.SESSION_REVOKE),
            "Review provisioning intent and revocation obligations.",
        )
        self.trust = SsoTrustPolicy(
            TENANT,
            "issuer:workforce",
            "audience:sunderkey",
            ("assurance:phishing-resistant",),
            True,
            3600,
            7200,
        )
        self.policy = EnterpriseIdentityPolicy(
            TENANT,
            (self.reader, self.approver, self.executor, self.identity_admin),
            self.trust,
        )
        self.reader_binding = self.binding("subject:analyst", ("role:reader",))
        self.admin_binding = self.binding("subject:directory-admin", ("role:identity-admin",))
        self.assertion = VerifiedSsoAssertion(
            TENANT,
            "issuer:workforce",
            "audience:sunderkey",
            "subject:analyst",
            "2026-09-20T11:30:00Z",
            "2026-09-20T11:45:00Z",
            "2026-09-20T13:00:00Z",
            True,
            "assurance:phishing-resistant",
            "session:alpha",
            DIGEST_A,
        )

    def binding(
        self,
        subject_id: str,
        role_ids: tuple[str, ...],
        *,
        tenant_id: str = TENANT,
        status: str = BindingStatus.ACTIVE,
    ) -> RoleBinding:
        return RoleBinding(
            tenant_id,
            subject_id,
            role_ids,
            status,
            3,
            "2026-09-20T00:00:00Z",
            "2026-09-21T00:00:00Z",
            ("group:operators",),
        )

    def request(
        self,
        permission: str = Permission.MISSION_READ,
        *,
        tenant_id: str = TENANT,
        resource_tenant_id: str = TENANT,
    ) -> AuthorizationRequest:
        return AuthorizationRequest(
            tenant_id,
            "subject:analyst",
            permission,
            resource_tenant_id,
            "mission:one",
            NOW,
            "session:alpha",
        )

    def command(self, **changes) -> ProvisioningCommand:
        values = {
            "tenant_id": TENANT,
            "actor_subject_id": "subject:directory-admin",
            "operation": ProvisioningOperation.UPDATE,
            "resource_kind": ResourceKind.USER,
            "resource_id": "user:analyst",
            "external_id": "external:001",
            "idempotency_key": "idempotency:update-001",
            "expected_version": 4,
            "new_version": 5,
            "issued_at": NOW,
            "precondition_sha256": DIGEST_A,
            "attribute_digests": (DIGEST_B,),
        }
        values.update(changes)
        return ProvisioningCommand(**values)

    def test_records_are_immutable_content_addressed_and_canonical(self) -> None:
        self.assertRegex(self.reader.record_id, r"^EIC-[0-9A-F]{32}$")
        self.assertRegex(self.reader.record_sha256, r"^sha256:[0-9a-f]{64}$")
        same = RoleDefinition(
            TENANT,
            "role:reader",
            (Permission.MISSION_READ,),
            "Read authorized mission metadata.",
        )
        self.assertEqual(same.record_sha256, self.reader.record_sha256)
        changed = replace(self.reader, description="Read mission records.")
        self.assertNotEqual(changed.record_sha256, self.reader.record_sha256)
        with self.assertRaises(FrozenInstanceError):
            self.reader.role_id = "role:changed"
        rendered = canonical_json(self.reader.to_dict())
        self.assertEqual(
            rendered, json.dumps(json.loads(rendered), sort_keys=True, separators=(",", ":"))
        )

    def test_role_rejects_unknown_permissions_secrets_and_duty_collision(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityError, "permission"):
            RoleDefinition(TENANT, "role:bad", ("superuser",), "Invalid permission.")
        with self.assertRaisesRegex(EnterpriseIdentityError, "secret-like"):
            RoleDefinition(TENANT, "role:bad", (Permission.MISSION_READ,), "password=hunter2")
        with self.assertRaisesRegex(EnterpriseIdentityError, "duty constraint"):
            RoleDefinition(
                TENANT,
                "role:combined",
                (Permission.MISSION_APPROVE, Permission.MISSION_EXECUTE),
                "Invalid combined role.",
            )

    def test_policy_requires_deny_default_and_all_required_constraints(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityError, "deny by default"):
            EnterpriseIdentityPolicy(TENANT, (self.reader,), self.trust, default_decision="allow")
        with self.assertRaisesRegex(EnterpriseIdentityError, "omits"):
            EnterpriseIdentityPolicy(
                TENANT,
                (self.reader,),
                self.trust,
                duty_constraints=(
                    DutyConstraint(
                        Permission.MISSION_APPROVE,
                        Permission.MISSION_EXECUTE,
                        "Approval and execution remain separate.",
                    ),
                ),
            )

    def test_combined_roles_cannot_bypass_separation_of_duty(self) -> None:
        binding = self.binding(
            "subject:conflicted",
            ("role:approver", "role:executor"),
        )
        with self.assertRaisesRegex(EnterpriseIdentityError, "combined roles"):
            effective_permissions(self.policy, binding)
        with self.assertRaisesRegex(EnterpriseIdentityError, "combined roles"):
            EnterpriseIdentityContract(self.policy, (binding,), (), (), ())

    def test_authorization_allows_exact_active_tenant_binding(self) -> None:
        decision = authorize(self.policy, (self.reader_binding,), self.request())
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertEqual(decision.reason_codes, ("authorized",))
        self.assertEqual(decision.effective_permissions, (Permission.MISSION_READ,))
        self.assertEqual(decision.to_dict()["effects"], NO_EFFECTS)

    def test_authorization_denies_missing_permission_and_binding_ambiguity(self) -> None:
        missing = authorize(
            self.policy,
            (self.reader_binding,),
            self.request(Permission.MISSION_EXECUTE),
        )
        self.assertEqual(missing.decision, Decision.DENY)
        self.assertIn("permission_missing", missing.reason_codes)
        duplicate = authorize(
            self.policy,
            (self.reader_binding, replace(self.reader_binding, version=4)),
            self.request(),
        )
        self.assertIn("binding_not_unique", duplicate.reason_codes)

    def test_authorization_denies_cross_tenant_and_inactive_bindings(self) -> None:
        cross_tenant = authorize(
            self.policy,
            (self.reader_binding,),
            self.request(resource_tenant_id="tenant:other"),
        )
        self.assertIn("tenant_mismatch", cross_tenant.reason_codes)
        suspended = self.binding(
            "subject:analyst",
            ("role:reader",),
            status=BindingStatus.SUSPENDED,
        )
        inactive = authorize(self.policy, (suspended,), self.request())
        self.assertIn("binding_inactive", inactive.reason_codes)

    def test_sso_requires_externally_verified_claims_and_time_ordering(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityError, "externally verified"):
            replace(self.assertion, externally_verified=False)
        with self.assertRaisesRegex(EnterpriseIdentityError, "time ordering"):
            replace(self.assertion, auth_time="2026-09-20T12:30:00Z")

    def test_sso_admits_bound_claims_and_denies_trust_failures(self) -> None:
        admitted = admit_sso_assertion(self.policy, self.assertion, evaluated_at=NOW)
        self.assertEqual(admitted.decision, Decision.ALLOW)
        rejected = admit_sso_assertion(
            self.policy,
            replace(
                self.assertion,
                audience="audience:other",
                mfa_present=False,
                assurance_context="assurance:weak",
            ),
            evaluated_at=NOW,
        )
        self.assertEqual(rejected.decision, Decision.DENY)
        self.assertEqual(
            set(rejected.reason_codes),
            {"assurance_rejected", "audience_mismatch", "mfa_required"},
        )

    def test_sso_denies_expired_old_or_excessive_sessions(self) -> None:
        expired = admit_sso_assertion(
            self.policy,
            self.assertion,
            evaluated_at="2026-09-20T14:00:00Z",
        )
        self.assertIn("expired", expired.reason_codes)
        self.assertIn("authentication_too_old", expired.reason_codes)
        long_session = replace(self.assertion, expires_at="2026-09-21T00:00:00Z")
        result = admit_sso_assertion(self.policy, long_session, evaluated_at=NOW)
        self.assertIn("session_too_long", result.reason_codes)

    def test_provisioning_create_and_update_shape_rules(self) -> None:
        create = self.command(
            operation=ProvisioningOperation.CREATE,
            expected_version=0,
            new_version=1,
            precondition_sha256=None,
            idempotency_key="idempotency:create-001",
        )
        self.assertFalse(create.deprovisioning)
        with self.assertRaisesRegex(EnterpriseIdentityError, "no precondition"):
            replace(create, precondition_sha256=DIGEST_A)
        with self.assertRaisesRegex(EnterpriseIdentityError, "increment"):
            replace(self.command(), new_version=7)
        with self.assertRaisesRegex(EnterpriseIdentityError, "require a precondition"):
            replace(self.command(), precondition_sha256=None)

    def test_membership_and_session_command_shapes_fail_closed(self) -> None:
        with self.assertRaisesRegex(EnterpriseIdentityError, "membership resources"):
            self.command(operation=ProvisioningOperation.ADD_MEMBER)
        removal = self.command(
            operation=ProvisioningOperation.REMOVE_MEMBER,
            resource_kind=ResourceKind.MEMBERSHIP,
            resource_id="membership:operators-analyst",
            member_subject_id="subject:analyst",
            idempotency_key="idempotency:remove-001",
        )
        self.assertTrue(removal.deprovisioning)
        self.assertTrue(removal.session_revocation_required)
        with self.assertRaisesRegex(EnterpriseIdentityError, "session revocation"):
            self.command(operation=ProvisioningOperation.REVOKE_SESSIONS)
        revoke = self.command(
            operation=ProvisioningOperation.REVOKE_SESSIONS,
            session_ids=("session:alpha",),
            idempotency_key="idempotency:revoke-001",
        )
        self.assertFalse(revoke.deprovisioning)

    def test_tombstone_declares_deprovisioning_and_revocation_obligations(self) -> None:
        command = self.command(
            operation=ProvisioningOperation.TOMBSTONE,
            idempotency_key="idempotency:tombstone-001",
        )
        self.assertTrue(command.deprovisioning)
        self.assertTrue(command.tombstone_required)
        self.assertTrue(command.session_revocation_required)
        decision = validate_provisioning_command(
            self.policy,
            command,
            actor_binding=self.admin_binding,
            current_version=4,
            current_sha256=DIGEST_A,
            seen_idempotency={},
            evaluated_at=NOW,
        )
        self.assertEqual(decision.decision, Decision.ALLOW)
        self.assertTrue(decision.session_revocation_required)
        group_command = replace(
            command,
            resource_kind=ResourceKind.GROUP,
            resource_id="group:operators",
            external_id="external:group-001",
            idempotency_key="idempotency:tombstone-group-001",
        )
        self.assertTrue(group_command.session_revocation_required)

    def test_provisioning_enforces_actor_version_precondition_and_tenant(self) -> None:
        command = self.command()
        result = validate_provisioning_command(
            self.policy,
            command,
            actor_binding=self.reader_binding,
            current_version=3,
            current_sha256=DIGEST_B,
            seen_idempotency={},
            evaluated_at=NOW,
        )
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(
            set(result.reason_codes),
            {"actor_binding_missing", "precondition_failed", "version_mismatch"},
        )
        cross = self.command(tenant_id="tenant:other", idempotency_key="idempotency:cross")
        result = validate_provisioning_command(
            self.policy,
            cross,
            actor_binding=None,
            current_version=4,
            current_sha256=DIGEST_A,
            seen_idempotency={},
            evaluated_at=NOW,
        )
        self.assertIn("tenant_mismatch", result.reason_codes)

    def test_provisioning_is_idempotent_and_detects_key_conflict(self) -> None:
        command = self.command()
        replay = validate_provisioning_command(
            self.policy,
            command,
            actor_binding=self.admin_binding,
            current_version=4,
            current_sha256=DIGEST_A,
            seen_idempotency={command.idempotency_key: command.record_sha256},
            evaluated_at=NOW,
        )
        self.assertIn("duplicate_command", replay.reason_codes)
        conflict = validate_provisioning_command(
            self.policy,
            command,
            actor_binding=self.admin_binding,
            current_version=4,
            current_sha256=DIGEST_A,
            seen_idempotency={command.idempotency_key: DIGEST_B},
            evaluated_at=NOW,
        )
        self.assertIn("idempotency_conflict", conflict.reason_codes)

    def test_contract_enforces_tenant_and_idempotency_isolation(self) -> None:
        command = self.command()
        admitted = admit_sso_assertion(self.policy, self.assertion, evaluated_at=NOW)
        contract = EnterpriseIdentityContract(
            self.policy,
            (self.reader_binding, self.admin_binding),
            (self.assertion,),
            (admitted,),
            (command,),
        )
        self.assertEqual(contract.to_dict()["tenant_id"], TENANT)
        with self.assertRaisesRegex(EnterpriseIdentityError, "idempotency keys"):
            EnterpriseIdentityContract(
                self.policy,
                (),
                (),
                (),
                (command, replace(command, attribute_digests=())),
            )
        other_assertion = replace(self.assertion, tenant_id="tenant:other")
        with self.assertRaisesRegex(EnterpriseIdentityError, "tenant boundary"):
            EnterpriseIdentityContract(self.policy, (), (other_assertion,), (), ())

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_complete_contract_validates_against_json_schema(self) -> None:
        command = self.command()
        admitted = admit_sso_assertion(self.policy, self.assertion, evaluated_at=NOW)
        authorized = authorize(self.policy, (self.reader_binding,), self.request())
        contract = EnterpriseIdentityContract(
            self.policy,
            (self.reader_binding, self.admin_binding),
            (self.assertion,),
            (admitted, authorized),
            (command,),
        )
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(contract.to_dict())), [])
        tampered = copy.deepcopy(contract.to_dict())
        tampered["effects"]["network"] = "performed"
        self.assertNotEqual(list(validator.iter_errors(tampered)), [])

    def test_zero_effects_and_source_hygiene(self) -> None:
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, "[\u2013\u2014]")
        values = (
            self.reader,
            self.reader_binding,
            self.trust,
            self.assertion,
            self.request(),
            self.command(),
        )
        for value in values:
            self.assertEqual(value.to_dict()["effects"], NO_EFFECTS)


if __name__ == "__main__":
    unittest.main()

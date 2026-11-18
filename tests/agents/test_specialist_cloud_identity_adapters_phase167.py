"""Phase 167 cloud and identity specialist adapter coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.specialist_cloud_identity_adapters import (
    OPERATION_POLICIES,
    REPOSITORY_ONLY_EFFECTS,
    AdapterIdentity,
    AdapterObservation,
    ApprovalBinding,
    CapabilityFamily,
    CloudIdentityAdapterError,
    CloudIdentityExecutionAdapter,
    ExecutionBudget,
    ExecutionContext,
    MutationClass,
    ProviderKind,
    ResultState,
    ScopeBinding,
    SessionBinding,
    SpecialistActionRequest,
    SpecialistOperation,
    SpecialistReplayGuard,
    canonical_json,
    capability_declarations,
    execute_specialist_action,
    provider_profile_declarations,
)
from sunderkey.types import ActionTier

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "specialist-cloud-identity-adapter-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "specialist_cloud_identity_adapters.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "specialist-cloud-identity-adapters.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(*, tenant: str = "acme", action: str = "approved-77") -> ExecutionContext:
    return ExecutionContext(
        mission_ref="missionref:assessment-77",
        worker_ref="workerref:cloud-specialist-one",
        action_ref=f"actionref:{action}",
        action_admission_sha256=digest("a"),
        scope=ScopeBinding(
            tenant_ref=f"tenantref:{tenant}",
            scope_ref="scoperef:signed-v4",
            account_refs=("accountref:aws-111122223333",),
            project_refs=("projectref:gcp-project-one",),
            subscription_refs=("subscriptionref:azure-sub-one",),
            cluster_refs=("clusterref:kube-test-one",),
        ),
    )


def request(
    operation: SpecialistOperation = SpecialistOperation.ROLE_SESSION_VALIDATE,
    *,
    provider: ProviderKind = ProviderKind.AWS,
    selected_context: ExecutionContext | None = None,
    idempotency_key: str = "idem:cloud-assessment-77",
    dry_run: bool = False,
) -> SpecialistActionRequest:
    selected_context = selected_context or context()
    policy = OPERATION_POLICIES[operation]
    mutation = policy.mutation_class is MutationClass.REVERSIBLE_MUTATION
    return SpecialistActionRequest(
        context=selected_context,
        provider=provider,
        operation=operation,
        requested_tier=policy.minimum_tier,
        approval=ApprovalBinding(
            approval_ref="approvalref:operator-77",
            approval_sha256=digest("b"),
            context_sha256=selected_context.context_sha256,
            provider=provider,
            operation=operation,
            maximum_tier=policy.minimum_tier,
            allow_mutation=mutation,
            require_dry_run=mutation,
            issued_at="2026-09-20T10:00:00Z",
            expires_at="2026-09-20T11:00:00Z",
        ),
        session=SessionBinding(
            session_ref="sessionref:leased-session-77",
            principal_ref="principalref:test-operator",
            session_sha256=digest("c"),
            context_sha256=selected_context.context_sha256,
            provider=provider,
            issued_at="2026-09-20T10:00:00Z",
            expires_at="2026-09-20T11:00:00Z",
        ),
        evidence_refs=("evidenceref:scope", "evidenceref:admission"),
        evidence_sha256=(digest("1"), digest("2")),
        idempotency_key=idempotency_key,
        dry_run=dry_run,
        budget=ExecutionBudget(4, 100, 1 if mutation else 0, 8),
        issued_at="2026-09-20T10:05:00Z",
        expires_at="2026-09-20T10:30:00Z",
    )


class FakeAdapter:
    def __init__(
        self,
        selected_request: SpecialistActionRequest,
        *,
        mutations: int = 0,
    ) -> None:
        self.identity = AdapterIdentity(
            "adapterref:fixture-cloud",
            "1.0.0",
            selected_request.provider,
            (selected_request.operation,),
        )
        self.calls: list[SpecialistActionRequest] = []
        self.mutations = mutations
        self.overrides: dict[str, object] = {}

    def execute(self, selected_request: SpecialistActionRequest) -> AdapterObservation:
        self.calls.append(selected_request)
        values = {
            "request_id": selected_request.request_id,
            "request_sha256": selected_request.request_sha256,
            "context_sha256": selected_request.context.context_sha256,
            "scope_binding_sha256": selected_request.context.scope.binding_sha256,
            "approval_sha256": selected_request.approval.approval_sha256,
            "session_sha256": selected_request.session.session_sha256,
            "idempotency_key": selected_request.idempotency_key,
            "state": ResultState.COMPLETED,
            "operations_performed": 1,
            "resources_observed": 3,
            "mutations_performed": self.mutations,
            "evidence_refs": (
                "evidenceref:scope",
                "evidenceref:admission",
                "evidenceref:result",
            ),
            "evidence_sha256": (digest("1"), digest("2"), digest("3")),
            "result_attestation_ref": "attestationref:fixture-result",
            "result_attestation_sha256": digest("d"),
            "restoration_evidence_refs": (("evidenceref:restoration",) if self.mutations else ()),
            "observed_at": "2026-09-20T10:10:00Z",
        }
        values.update(self.overrides)
        return AdapterObservation(**values)


class SpecialistCloudIdentityAdapterTests(unittest.TestCase):
    def run_action(
        self,
        selected: SpecialistActionRequest,
        adapter: FakeAdapter,
        guard: SpecialistReplayGuard | None = None,
    ):
        return execute_specialist_action(
            selected,
            expected_context=selected.context,
            adapter=adapter,
            replay_guard=guard or SpecialistReplayGuard(),
            evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
        )

    def test_declarations_cover_c43_through_c48_and_all_profiles(self) -> None:
        declarations = capability_declarations()
        self.assertEqual({item.family for item in declarations}, set(CapabilityFamily))
        self.assertEqual(
            {item.package_id for item in declarations},
            {"C4.3", "C4.4", "C4.5", "C4.6", "C4.7", "C4.8"},
        )
        self.assertTrue(all(item.repository_only for item in declarations))
        self.assertTrue(all(item.qualification_status == "not_qualified" for item in declarations))
        profiles = provider_profile_declarations()
        self.assertEqual({item.provider for item in profiles}, set(ProviderKind))
        self.assertTrue(all(item.to_dict()["repository_only"] for item in profiles))
        self.assertTrue(
            all(item.to_dict()["qualification_status"] == "not_qualified" for item in profiles)
        )

    def test_every_provider_profile_builds_a_bound_request(self) -> None:
        for index, profile in enumerate(provider_profile_declarations()):
            operation = profile.supported_operations[0]
            with self.subTest(provider=profile.provider):
                selected = request(
                    operation,
                    provider=profile.provider,
                    idempotency_key=f"idem:profile-{index}-request",
                )
                body = selected.to_dict()
                self.assertEqual(body["profile"], profile.to_dict())
                self.assertEqual(body["context"]["scope"]["tenant_ref"], "tenantref:acme")
                self.assertEqual(body["effects"], dict(REPOSITORY_ONLY_EFFECTS))

    def test_fixed_provider_scope_dimensions_fail_closed(self) -> None:
        selected_context = context()
        missing_account = replace(
            selected_context,
            scope=replace(selected_context.scope, account_refs=()),
        )
        with self.assertRaisesRegex(CloudIdentityAdapterError, "scope dimension"):
            request(selected_context=missing_account)
        missing_cluster = replace(
            selected_context,
            scope=replace(selected_context.scope, cluster_refs=()),
        )
        with self.assertRaisesRegex(CloudIdentityAdapterError, "scope dimension"):
            request(
                SpecialistOperation.KUBERNETES_RBAC_READ,
                provider=ProviderKind.KUBERNETES,
                selected_context=missing_cluster,
            )

    def test_r1_r2_r3_admission_and_dry_run_are_fixed(self) -> None:
        selected_context = context()
        mutation = request(
            SpecialistOperation.TEMPORARY_ROLE_BINDING,
            selected_context=selected_context,
            dry_run=True,
        )
        self.assertEqual(mutation.requested_tier, ActionTier.R3)
        self.assertTrue(mutation.approval.allow_mutation)
        with self.assertRaisesRegex(CloudIdentityAdapterError, "requires dry-run"):
            replace(mutation, dry_run=False, request_id="", request_sha256="")
        with self.assertRaisesRegex(CloudIdentityAdapterError, "explicit mutation approval"):
            replace(
                mutation,
                approval=replace(mutation.approval, allow_mutation=False),
                request_id="",
                request_sha256="",
            )
        validation = request()
        with self.assertRaisesRegex(CloudIdentityAdapterError, "below the operation minimum"):
            replace(validation, requested_tier=ActionTier.R1, request_id="", request_sha256="")

    def test_injected_adapter_produces_attested_content_addressed_receipt(self) -> None:
        selected = request()
        adapter = FakeAdapter(selected)
        receipt = self.run_action(selected, adapter)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(receipt.result_attestation_sha256, digest("d"))
        self.assertEqual(receipt.mutation_class, MutationClass.VALIDATION)
        self.assertEqual(receipt.to_dict()["effects"], dict(REPOSITORY_ONLY_EFFECTS))
        self.assertEqual(receipt.receipt_id[:4], "CIO-")
        with self.assertRaises(FrozenInstanceError):
            receipt.state = ResultState.BLOCKED

    def test_r3_result_requires_restoration_evidence(self) -> None:
        selected = request(SpecialistOperation.TEMPORARY_ROLE_BINDING, dry_run=True)
        adapter = FakeAdapter(selected, mutations=1)
        receipt = self.run_action(selected, adapter)
        self.assertEqual(receipt.restoration_evidence_refs, ("evidenceref:restoration",))
        missing = FakeAdapter(selected, mutations=1)
        missing.overrides["restoration_evidence_refs"] = ()
        with self.assertRaisesRegex(CloudIdentityAdapterError, "restoration evidence"):
            self.run_action(
                replace(
                    selected,
                    idempotency_key="idem:missing-restoration",
                    request_id="",
                    request_sha256="",
                ),
                missing,
            )

    def test_cross_context_is_rejected_before_adapter_call(self) -> None:
        selected = request()
        adapter = FakeAdapter(selected)
        with self.assertRaisesRegex(CloudIdentityAdapterError, "expected context"):
            execute_specialist_action(
                selected,
                expected_context=context(tenant="other"),
                adapter=adapter,
                replay_guard=SpecialistReplayGuard(),
                evaluated_at=datetime(2026, 9, 20, 10, 10, tzinfo=UTC),
            )
        self.assertEqual(adapter.calls, [])
        with self.assertRaisesRegex(CloudIdentityAdapterError, "approval context"):
            replace(
                selected,
                approval=replace(selected.approval, context_sha256=digest("f")),
                request_id="",
                request_sha256="",
            )
        with self.assertRaisesRegex(CloudIdentityAdapterError, "session context"):
            replace(
                selected,
                session=replace(selected.session, context_sha256=digest("f")),
                request_id="",
                request_sha256="",
            )

    def test_replay_is_rejected_without_second_adapter_call(self) -> None:
        selected = request()
        adapter = FakeAdapter(selected)
        guard = SpecialistReplayGuard()
        self.run_action(selected, adapter, guard)
        with self.assertRaisesRegex(CloudIdentityAdapterError, "already been used"):
            self.run_action(selected, adapter, guard)
        self.assertEqual(len(adapter.calls), 1)

    def test_observation_substitution_and_budget_overrun_fail_closed(self) -> None:
        cases = (
            ("context_sha256", digest("f"), "context_sha256"),
            ("scope_binding_sha256", digest("f"), "scope_binding_sha256"),
            ("approval_sha256", digest("f"), "approval_sha256"),
            ("session_sha256", digest("f"), "session_sha256"),
            ("idempotency_key", "idem:substituted-result", "idempotency_key"),
            ("operations_performed", 5, "operation budget"),
            ("resources_observed", 101, "resource budget"),
        )
        for index, (field, value, message) in enumerate(cases):
            selected = request(idempotency_key=f"idem:binding-case-{index}")
            adapter = FakeAdapter(selected)
            adapter.overrides[field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(CloudIdentityAdapterError, message),
            ):
                self.run_action(selected, adapter)

    def test_adapter_provider_and_operation_substitution_fail_before_call(self) -> None:
        selected = request()
        adapter = FakeAdapter(selected)
        adapter.identity = replace(adapter.identity, provider=ProviderKind.GCP)
        with self.assertRaisesRegex(CloudIdentityAdapterError, "does not support"):
            self.run_action(selected, adapter)
        self.assertEqual(adapter.calls, [])

    def test_secret_patterns_are_rejected(self) -> None:
        with self.assertRaisesRegex(CloudIdentityAdapterError, "secret material"):
            canonical_json({"access_token": "not-allowed-here"})
        encoded = json.dumps(request().to_dict()).lower()
        self.assertNotIn("access_token", encoded)
        self.assertNotIn("private_key", encoded)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_request_and_receipt_validate_against_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        selected = request()
        receipt = self.run_action(selected, FakeAdapter(selected))
        validator.validate(selected.to_dict())
        validator.validate(receipt.to_dict())
        tampered = copy.deepcopy(receipt.to_dict())
        tampered["provider"] = "unknown"
        self.assertTrue(list(validator.iter_errors(tampered)))

    def test_protocol_is_runtime_checkable(self) -> None:
        selected = request()
        self.assertIsInstance(FakeAdapter(selected), CloudIdentityExecutionAdapter)
        self.assertNotIsInstance(object(), CloudIdentityExecutionAdapter)

    def test_increment_has_no_markers_or_unicode_dashes(self) -> None:
        forbidden = (
            "generated " + "by",
            "written by " + "ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            lowered = text.lower()
            with self.subTest(path=path.name):
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                for marker in forbidden:
                    self.assertNotIn(marker, lowered)

    def test_public_package_exports_specialist_boundary(self) -> None:
        import sunderkey

        self.assertIs(
            sunderkey.SpecialistCloudIdentityActionRequest,
            SpecialistActionRequest,
        )
        self.assertIs(
            sunderkey.execute_cloud_identity_specialist_action,
            execute_specialist_action,
        )
        self.assertIs(
            sunderkey.cloud_identity_specialist_capabilities,
            capability_declarations,
        )
        self.assertIs(
            sunderkey.cloud_identity_provider_profiles,
            provider_profile_declarations,
        )


if __name__ == "__main__":
    unittest.main()

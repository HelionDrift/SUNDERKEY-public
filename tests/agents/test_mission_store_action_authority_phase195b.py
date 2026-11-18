from __future__ import annotations

import unittest

from sunderkey.action_admission_contracts import (
    REQUIRED_EVIDENCE,
    ArtifactBinding,
    ContextBinding,
    CredentialLease,
    EvidenceKind,
    EvidenceObligation,
    HealthEvidence,
    HealthStatus,
    RestorationDuties,
    StopConditions,
    WorkerSession,
)
from sunderkey.action_authority_contracts import (
    RESOURCE_FIELDS,
    build_authenticated_proposal_material_import,
    build_authoritative_action_catalog_revision,
    build_exact_action_source_head_bundle,
)
from sunderkey.action_resolution import (
    ActionTier,
    _catalog_action,
    _resolved_action_sha256,
    build_action_parameter_set,
    build_executable_action_catalog,
    build_target_action_descriptor,
    parameter_contract_sha256,
)
from sunderkey.errors import StoreIntegrityError
from sunderkey.mission_store_action_authority import (
    BUDGET_ACCOUNT_DOMAIN,
    BUDGET_EVENT_DOMAIN,
    ActionAuthorityMaterialSnapshot,
    AuthenticatedActionAuthorityPublication,
    action_fence_token_sha256,
    action_monitor_observation_sha256,
    action_review_revocation_head_sha256,
    action_stop_contract_sha256,
    build_action_authority_material_snapshot,
    build_action_authority_observation,
    build_authenticated_action_authority_publication,
    phase165_budget_binding_from_policy,
)
from sunderkey.qualification import _canonical_sha256

from . import test_action_authority_contracts_phase195b as portable_fixture


def _digest(character: str) -> str:
    return "sha256:" + character * 64


class MissionStoreActionAuthorityPhase195bTests(unittest.TestCase):
    def _records(self):  # type: ignore[no-untyped-def]
        policy, _catalog, target_source, budget, safety, _proposal, _bundle = (
            portable_fixture._records()
        )
        contract = [{"name": "path", "required": True, "value_type": "string"}]
        catalog = build_executable_action_catalog(
            catalog_name="catalog:actions",
            catalog_version="1.0.0",
            registry_sha256=_digest("9"),
            entries=[
                {
                    "action_type": "api.request",
                    "executor_supported": True,
                    "maximum_action_tier": "R4",
                    "parameter_contract": contract,
                    "parameter_contract_sha256": parameter_contract_sha256(contract),
                    "r4_executor_supported": True,
                    "supported_environments": ["live"],
                    "tool_artifact_ref": "artifact:api-adapter",
                    "tool_artifact_sha256": _digest("b"),
                    "tool_exact_version": "1.0.0",
                }
            ],
        )
        catalog_source = build_authoritative_action_catalog_revision(
            tenant_id="tenant:001",
            mission_id="mission:001",
            plan_id="plan:001",
            catalog_id=catalog.catalog_id,
            catalog_version="1.0.0",
            registry_sha256=_digest("9"),
            entries=[
                {
                    "action_type": "api.request",
                    "maximum_action_tier": "R4",
                    "target_kinds": ["web_api"],
                    "supported_environments": ["live"],
                    "parameter_schema_sha256": parameter_contract_sha256(contract),
                    "tool_artifact_ref": "artifact:api-adapter",
                    "tool_artifact_sha256": _digest("b"),
                    "tool_exact_version": "1.0.0",
                    "adapter_kind": "http",
                    "r4_executor_supported": True,
                }
            ],
            revision=1,
            previous_revision_sha256=None,
            effective_at="2026-09-21T10:00:00Z",
            expires_at="2026-09-21T12:00:00Z",
            revocation_policy_sha256=_digest("8"),
        )
        parameters = build_action_parameter_set(
            catalog,
            action_type="api.request",
            parameters={"path": "/health"},
        )
        target = build_target_action_descriptor(
            tenant_id="tenant:001",
            mission_id="mission:001",
            target_scope_sha256=_digest("5"),
            authority_snapshot_sha256=_digest("6"),
            target_id="target:001",
            target_sha256=_digest("c"),
            environment="live",
        )
        proposal = build_authenticated_proposal_material_import(
            product=portable_fixture._work_product(),
            tenant_id="tenant:001",
            workspace_id="workspace:001",
            review_snapshot_id="review-snapshot:001",
            review_snapshot_sha256=_digest("e"),
            review_closure_id="review-closure:001",
            review_closure_sha256=_digest("f"),
            catalog=catalog_source,
            target=target_source,
            parameter_set_id=parameters.parameter_set_id,
            parameter_set_sha256=parameters.parameter_set_sha256,
            selected_action_type="api.request",
            requested_action_tier="R3",
            imported_at="2026-09-21T10:24:00Z",
        )
        action_sha256 = _resolved_action_sha256(
            catalog=catalog,
            entry=_catalog_action(catalog, "api.request"),
            parameters=parameters,
            target=target,
            action_tier=ActionTier.R3,
        )
        fence = action_fence_token_sha256(
            session_authority_id="session-authority:001",
            execution_session_id="session:001",
            owner_epoch=4,
            fence_generation=9,
        )
        worker = WorkerSession(
            worker_id="worker:executor:001",
            worker_profile_id="AOE-GA-D01-S01",
            session_id="session:001",
            tenant_id="tenant:001",
            mission_id="mission:001",
            fence_token_sha256=fence,
            leader_epoch=4,
            issued_at="2026-09-21T10:20:00Z",
            expires_at="2026-09-21T11:00:00Z",
        )
        credential = CredentialLease(
            lease_id="credential:001",
            credential_ref_sha256=_digest("9"),
            tenant_id="tenant:001",
            mission_id="mission:001",
            scope_sha256=_digest("5"),
            worker_id=worker.worker_id,
            session_id=worker.session_id,
            fence_token_sha256=fence,
            leader_epoch=4,
            permitted_action_sha256=action_sha256,
            revoked=False,
            issued_at="2026-09-21T10:20:00Z",
            expires_at="2026-09-21T11:00:00Z",
        )
        health = HealthEvidence(
            worker_id=worker.worker_id,
            session_id=worker.session_id,
            fence_token_sha256=fence,
            leader_epoch=4,
            status=HealthStatus.HEALTHY,
            evidence_sha256=_digest("a"),
            observed_at="2026-09-21T10:29:00Z",
            expires_at="2026-09-21T10:40:00Z",
        )
        obligations = tuple(
            EvidenceObligation(
                evidence_kind=kind,
                evidence_sha256=_digest(str(index + 1)),
                tenant_id="tenant:001",
                mission_id="mission:001",
                scope_sha256=_digest("5"),
                target_sha256=_digest("c"),
                action_sha256=action_sha256,
                producer_id=f"producer:{kind.value}",
                issued_at="2026-09-21T10:20:00Z",
                expires_at="2026-09-21T11:00:00Z",
            )
            for index, kind in enumerate(sorted(REQUIRED_EVIDENCE, key=lambda item: item.value))
        )
        self.assertEqual(
            {item.evidence_kind for item in obligations},
            set(EvidenceKind),
        )
        monitor_observation_sha256 = action_monitor_observation_sha256(
            monitor_id="monitor:001",
            principal_profile_id="profile:monitor",
            principal_subject="subject:monitor",
            monitor_session_id="monitor-session:001",
            monitor_worker_id="profile:monitor",
            status="healthy",
            heartbeat_observed_at="2026-09-21T10:30:00Z",
            heartbeat_expires_at="2026-09-21T10:30:05Z",
        )
        stop = StopConditions(
            stop_contract_sha256=action_stop_contract_sha256(safety),
            monitor_session_id="monitor-session:001",
            monitor_worker_id="profile:monitor",
            scope_sha256=_digest("5"),
            target_sha256=_digest("c"),
            action_sha256=action_sha256,
            maximum_impact_events=1,
            stop_deadline_at="2026-09-21T10:30:05Z",
            expires_at="2026-09-21T10:30:05Z",
        )
        restoration = RestorationDuties(
            required=True,
            restoration_plan_sha256=_digest("d"),
            owner_profile_id="profile:restoration-owner",
            verifier_profile_id="profile:restoration-verifier",
            scope_sha256=_digest("5"),
            target_sha256=_digest("c"),
            action_sha256=action_sha256,
            completion_evidence_required=True,
        )
        material = build_action_authority_material_snapshot(
            tenant_id="tenant:001",
            mission_id="mission:001",
            plan_id="plan:001",
            proposal=proposal,
            catalog=catalog,
            parameters=parameters,
            target=target,
            resolver_profile_id="profile:resolver",
            resolver_subject="subject:resolver",
            context=ContextBinding(
                tenant_id="tenant:001",
                mission_id="mission:001",
                scope_id="scope:001",
                scope_sha256=_digest("5"),
                policy=ArtifactBinding("artifact:policy", _digest("8"), "1.0.0"),
            ),
            worker_session=worker,
            credential_lease=credential,
            health=health,
            budget=phase165_budget_binding_from_policy(
                budget,
                tenant_id="tenant:001",
                mission_id="mission:001",
            ),
            monitor_observation_sha256=monitor_observation_sha256,
            evidence_obligations=obligations,
            stop_conditions=stop,
            restoration_duties=restoration,
            resolved_at="2026-09-21T10:25:00Z",
            approved_at="2026-09-21T10:26:00Z",
            requested_at="2026-09-21T10:29:55Z",
            observed_at="2026-09-21T10:30:00Z",
            expires_at="2026-09-21T10:35:00Z",
            quorum_expires_at="2026-09-21T10:35:00Z",
            valid_until="2026-09-21T10:35:00Z",
        )
        opened_at = "2026-09-21T10:30:00Z"
        budget_document = budget.to_dict()
        account_id = (
            "ABA-"
            + _canonical_sha256(
                {
                    "account": {
                        "budget_id": budget_document["budget_id"],
                        "mission_id": "mission:001",
                        "opened_at": opened_at,
                        "tenant_id": "tenant:001",
                    },
                    "domain": BUDGET_ACCOUNT_DOMAIN,
                }
            )
            .removeprefix("sha256:")[:32]
            .upper()
        )
        empty_budget_head = _canonical_sha256(
            {"domain": BUDGET_EVENT_DOMAIN, "empty_account_id": account_id}
        )
        material_document = material.to_dict()
        high_water_body = {
            "application_id": "application:001",
            "application_sha256": _digest("1"),
            "closure_id": "review-closure:001",
            "closure_sha256": _digest("f"),
            "event_count": 8,
            "event_head_occurred_at": 1_795_000_000_000,
            "event_head_sha256": _digest("2"),
            "mission_id": "mission:001",
            "mission_store_id": "mission-store:001",
            "revocation_id": None,
            "revocation_sha256": None,
            "snapshot_id": "review-snapshot:001",
            "snapshot_sha256": _digest("e"),
            "state": "closure_applied_unrevoked",
            "workspace_id": "workspace:001",
            "workspace_revision": 8,
            "workspace_store_id": "workspace-store:001",
            "workspace_store_path": "E:\\workspace.sqlite3",
        }
        high_water_sha256 = _canonical_sha256(
            {
                "domain": "sunderkey.action-workspace-high-water.v1",
                "high_water": high_water_body,
            }
        )
        high_water = {
            **high_water_body,
            "high_water_id": (
                "AWH-" + high_water_sha256.removeprefix("sha256:")[:32].upper()
            ),
            "high_water_sha256": high_water_sha256,
        }
        observations = tuple(
            sorted(
                (
                    build_action_authority_observation(
                        observation_kind="execution_fence_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "session_authority_id": "session-authority:001",
                            "session_authority_sha256": _digest("7"),
                            "execution_session_id": "session:001",
                            "execution_session_sha256": _digest("8"),
                            "owner_epoch": 4,
                            "fence_generation": 9,
                            "fence_token_sha256": fence,
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                    build_action_authority_observation(
                        observation_kind="credential_lease_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "credential_lease": credential.to_dict(),
                            "credential_lease_sha256": (
                                material_document["credential_lease_sha256"]
                            ),
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                    build_action_authority_observation(
                        observation_kind="executor_health_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "health": health.to_dict(),
                            "health_observation_sha256": (
                                material_document["health_observation_sha256"]
                            ),
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                    build_action_authority_observation(
                        observation_kind="executor_deployment_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "worker_session": worker.to_dict(),
                            "executor_deployment_sha256": (
                                material_document["executor_deployment_sha256"]
                            ),
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                    build_action_authority_observation(
                        observation_kind="stop_monitor_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "monitor_id": "monitor:001",
                            "principal_profile_id": "profile:monitor",
                            "principal_subject": "subject:monitor",
                            "monitor_session_id": stop.monitor_session_id,
                            "monitor_worker_id": stop.monitor_worker_id,
                            "monitor_observation_sha256": (
                                monitor_observation_sha256
                            ),
                            "status": "healthy",
                            "heartbeat_observed_at": opened_at,
                            "heartbeat_expires_at": "2026-09-21T10:30:05Z",
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                    build_action_authority_observation(
                        observation_kind="workspace_high_water_observation",
                        tenant_id="tenant:001",
                        mission_id="mission:001",
                        plan_id="plan:001",
                        payload={
                            "high_water": {
                                **high_water,
                            },
                            "high_water_sha256": high_water_sha256,
                        },
                        observed_at=opened_at,
                        valid_until="2026-09-21T10:35:00Z",
                    ),
                ),
                key=lambda item: item.KIND,
            )
        )
        bundle = build_exact_action_source_head_bundle(
            policy=policy,
            catalog=catalog_source,
            target=target_source,
            budget=budget,
            safety=safety,
            proposal=proposal,
            active_plan_sha256=_digest("1"),
            active_plan_version=2,
            mission_revision=7,
            mission_policy_sha256=_digest("2"),
            trust_policy_sha256=_digest("3"),
            scope_grant_sha256=_digest("4"),
            scope_revocation_head_sha256=_digest("5"),
            workspace_high_water_sha256=high_water_sha256,
            review_closure_projection_sha256=_digest("d"),
            review_revocation_head_sha256=action_review_revocation_head_sha256(
                "review-closure:001"
            ),
            budget_policy_binding_sequence=1,
            budget_policy_binding_sha256=_canonical_sha256(
                {
                    "binding": {
                        "account_id": account_id,
                        "binding_sequence": 1,
                        "budget_revision_id": budget.budget_revision_id,
                        "budget_revision_sha256": budget.budget_revision_sha256,
                        "limits": budget_document["limits"],
                        "previous_binding_sha256": None,
                        "bound_at": opened_at,
                    },
                    "domain": "sunderkey.action-budget-policy-binding.v1",
                }
            ),
            budget_ledger_head_sha256=empty_budget_head,
            session_authority_id="session-authority:001",
            session_authority_sha256=_digest("7"),
            execution_session_id="session:001",
            execution_session_sha256=_digest("8"),
            owner_epoch=4,
            fence_generation=9,
            credential_lease_sha256=material_document["credential_lease_sha256"],
            health_observation_sha256=material_document["health_observation_sha256"],
            executor_deployment_sha256=material_document["executor_deployment_sha256"],
            monitor_observation_sha256=material_document["monitor_observation_sha256"],
            observed_at=opened_at,
            valid_until="2026-09-21T10:35:00Z",
        )
        publication = build_authenticated_action_authority_publication(
            policy=policy,
            catalog=catalog_source,
            target=target_source,
            budget=budget,
            safety=safety,
            proposal=proposal,
            source_bundle=bundle,
            material=material,
            observations=observations,
            idempotency_key_sha256=_digest("f"),
            published_at=opened_at,
        )
        return material, publication

    def test_complete_material_and_publication_are_closed_and_deterministic(self) -> None:
        material, publication = self._records()
        self.assertEqual(
            ActionAuthorityMaterialSnapshot.from_dict(material.document_json),
            material,
        )
        self.assertEqual(
            AuthenticatedActionAuthorityPublication.from_dict(publication.document_json),
            publication,
        )
        self.assertEqual(self._records(), (material, publication))

    def test_material_unknown_field_and_fence_substitution_fail_closed(self) -> None:
        material, _publication = self._records()
        unknown = material.to_dict()
        unknown["unknown"] = True
        with self.assertRaisesRegex(StoreIntegrityError, "fields"):
            ActionAuthorityMaterialSnapshot.from_dict(unknown)
        substituted = material.to_dict()
        substituted["worker_session"]["fence_token_sha256"] = _digest("0")
        with self.assertRaises(StoreIntegrityError):
            ActionAuthorityMaterialSnapshot.from_dict(substituted)

    def test_budget_mapping_uses_every_stable_source_axis(self) -> None:
        _policy, _catalog, _target, budget, _safety, _proposal, _bundle = (
            portable_fixture._records()
        )
        binding = phase165_budget_binding_from_policy(
            budget,
            tenant_id="tenant:001",
            mission_id="mission:001",
        )
        self.assertEqual(binding.request_limit, budget.to_dict()["limits"]["rate_units"])
        self.assertEqual(
            binding.token_limit,
            budget.to_dict()["limits"]["request_bytes"]
            + budget.to_dict()["limits"]["response_bytes"],
        )
        self.assertEqual(
            set(budget.to_dict()["limits"]),
            set(RESOURCE_FIELDS),
        )


if __name__ == "__main__":
    unittest.main()

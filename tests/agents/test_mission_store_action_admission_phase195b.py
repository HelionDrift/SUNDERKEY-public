from __future__ import annotations

import json
import sqlite3
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey.action_resolution as action_resolution
from scripts.build_expert_runtime import load_sources
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
    build_action_authority_policy_revision,
    build_action_budget_policy_revision,
    build_action_safety_policy_revision,
    build_authenticated_proposal_material_import,
    build_authoritative_action_catalog_revision,
    build_authoritative_target_descriptor_revision,
    build_exact_action_source_head_bundle,
)
from sunderkey.action_resolution import (
    ActionResolutionError,
    ActionTier,
    AuthorizationRole,
    _catalog_action,
    _resolved_action_sha256,
    build_action_authorization_quorum,
    build_action_parameter_set,
    build_executable_action_catalog,
    build_target_action_descriptor,
    parameter_contract_sha256,
    reconstruct_action_admission_request,
    resolve_action_proposal,
)
from sunderkey.authenticated_action_admission import (
    ActionAdmissionCommand,
    admission_authorization_intent_sha256,
    quorum_authorization_intent_sha256,
    resolution_authorization_intent_sha256,
    revocation_authorization_intent_sha256,
)
from sunderkey.authenticated_action_review_authority import (
    AuthenticatedExpertReviewClosureVerifierAdapter,
)
from sunderkey.authenticated_collaboration_execution_session_authority import (
    AuthenticatedCollaborationExecutionSessionAuthorityService,
)
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.authenticated_expert_review import (
    SQLiteAuthenticatedExpertReviewCustody,
    expert_review_snapshot_registration_intent,
    expert_work_product_review_intent,
    expert_workspace_review_close_intent,
)
from sunderkey.authorized_target_health_runtime import TargetHealthReceipt
from sunderkey.collaboration_execution_channel import (
    build_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_execution_session_authentication import (
    build_collaboration_execution_session_activation_request,
    collaboration_execution_session_activation_selection_sha256,
    collaboration_execution_session_revocation_selection_sha256,
)
from sunderkey.collaboration_execution_session_authority import (
    build_collaboration_execution_session_revocation,
    build_initial_collaboration_execution_session_authority,
)
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_ownership_chain import (
    collaboration_work_item_objective_sha256,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreConflictError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.expert_review import (
    ClosureDisposition,
    ReviewDecision,
    build_expert_review_closure_request,
    build_expert_review_submission,
)
from sunderkey.expert_runtime import (
    build_execution_envelope,
    content_address_work_product,
    load_runtime_pack_catalog,
    parse_execution_envelope,
    parse_work_product,
)
from sunderkey.expert_workspace import (
    SQLiteExpertWorkspaceStore,
    build_expert_workspace_definition,
)
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    compute_operation_intent_hash,
)
from sunderkey.mission_store_action_admission import (
    MissionStoreAuthenticatedActionAdmissionService,
    _current_budget_state,
    verify_authenticated_action_admission_store,
)
from sunderkey.mission_store_action_authority import (
    BUDGET_ACCOUNT_DOMAIN,
    BUDGET_EVENT_DOMAIN,
    BUDGET_POLICY_BINDING_DOMAIN,
    action_fence_token_sha256,
    action_monitor_observation_sha256,
    action_review_revocation_head_sha256,
    action_stop_contract_sha256,
    build_action_authority_material_snapshot,
    build_action_authority_observation,
    build_authenticated_action_authority_publication,
    load_current_action_source_bundle,
    phase165_budget_binding_from_policy,
    verify_action_authority_repository,
)
from sunderkey.mission_store_target_health_gate import (
    MissionStoreTargetHealthGateService,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import canonical_json, sha256_text
from sunderkey.target_health_custody import SQLiteTargetHealthCustody
from sunderkey.target_health_gate_contracts import (
    execution_binding_sha256,
)

from . import test_authenticated_collaboration_execution_session_authority_phase123 as phase123
from . import test_authorized_target_health_runtime_phase175 as phase175
from . import test_collaboration_plan_replacement_store_phase186 as phase186
from . import test_target_health_custody_phase198 as phase198
from .signed_plan_rotation_test_support import (
    REPLACEMENT_OPERATIONS,
    REPLACEMENT_REVIEWERS,
    commit_signed_plan_rotation,
    initialize_action_fixture_with_army_v2,
    replacement_subject,
)
from .test_identity_phase4 import AUDIENCE, SUBJECT, b64url, public_bytes

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "registry" / "expert-runtime-packs-army-v2.json"
TENANT_ID = "tenant:phase195b"
ASSURANCE_PROFILE = "AOE-HQ-18"
RESOLVER_PROFILE = "AOE-HQ-19"
ADMISSION_PROFILE = "AOE-HQ-22"
ASSURANCE_SUBJECT = "reviewer:phase195b-assurance"
CONTROL_REVIEW_SUBJECT = "reviewer:phase195b-control"
RESOLVER_SUBJECT = "resolver:phase195b-typed"
ADMISSION_SUBJECT = "service:phase195b-admission-control"
ZERO = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64


def _healthy_target_receipt(
    binding,  # type: ignore[no-untyped-def]
    observed_at: str,
) -> TargetHealthReceipt:
    """Build the real Phase 175 healthy receipt graph for one exact binding."""

    fixture = phase175.AuthorizedTargetHealthRuntimePhase175Tests(methodName="runTest")
    fixture.setUp()
    receipt = fixture.observe()
    binding_sha256 = execution_binding_sha256(binding)
    instant = datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def timestamp(value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    safety = replace(
        receipt.safety_attestation,
        binding_sha256=binding_sha256,
        observed_at=timestamp(instant - timedelta(seconds=1)),
        expires_at=timestamp(instant + timedelta(minutes=5)),
        attestation_sha256="",
    )
    budget = replace(
        receipt.budget_state,
        binding_sha256=binding_sha256,
        observed_at=timestamp(instant - timedelta(seconds=1)),
        expires_at=timestamp(instant + timedelta(minutes=5)),
        state_id="",
        state_sha256="",
    )
    source_receipts = tuple(
        replace(
            item,
            binding_sha256=binding_sha256,
            observed_at=timestamp(instant - timedelta(seconds=2)),
            reference_sha256="",
        )
        for item in receipt.source_receipts
    )
    observations = tuple(
        replace(
            item,
            observed_at=timestamp(instant - timedelta(seconds=1)),
            expires_at=timestamp(instant + timedelta(minutes=5)),
            observation_id="",
            observation_sha256="",
        )
        for item in receipt.observations
    )
    return replace(
        receipt,
        scope_id=binding.scope_id,
        scope_sha256=binding.scope_sha256,
        binding=binding,
        binding_sha256=binding_sha256,
        observed_at=observed_at,
        safety_attestation=safety,
        safety_attestation_sha256=safety.attestation_sha256,
        budget_state=budget,
        budget_state_sha256=budget.state_sha256,
        source_receipts=source_receipts,
        observations=observations,
        receipt_id="",
        receipt_sha256="",
    )


class MissionStoreActionAdmissionPhase195bTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_runtime_pack_catalog(CATALOG_PATH, *load_sources())

    def setUp(self) -> None:
        fixture = phase123.AuthenticatedCollaborationExecutionSessionAuthorityPhase123Tests(
            methodName="runTest"
        )
        initialize_action_fixture_with_army_v2(fixture)
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.activation = fixture._activate()
        self.root = fixture.root
        self.store = self.root.store
        self.registry = self.root.registry
        self.mission = self.root.mission
        self.plan = self.root.plan
        self.factory = self.root.factory
        self.mission_id = self.mission.mission_id
        self.owner_profile = phase123.phase109.OWNER_ID
        self.control_profile = phase123.phase109.CONTROL_ID
        self.policy_version = phase123.POLICY_VERSION + 1
        self.root.now = datetime(2026, 7, 30, 10, 9, tzinfo=UTC)
        operations = sorted(
            {
                PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER.value,
                PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW.value,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE.value,
                PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE.value,
                PrincipalOperation.ACTION_AUTHORITY_PUBLISH.value,
                PrincipalOperation.ACTION_RESOLVE.value,
                PrincipalOperation.ACTION_QUORUM_AUTHORIZE.value,
                PrincipalOperation.ACTION_ADMIT.value,
                PrincipalOperation.ACTION_EXECUTE.value,
                PrincipalOperation.ACTION_EXECUTION_RECONCILE.value,
                PrincipalOperation.ACTION_ADMISSION_REVOKE.value,
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
                PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
                PrincipalOperation.EXECUTION_SESSION_REVOKE.value,
                PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE.value,
                PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT.value,
                *(operation.value for operation in REPLACEMENT_OPERATIONS),
            }
        )
        profiles = sorted(
            {
                self.owner_profile,
                self.control_profile,
                ASSURANCE_PROFILE,
                RESOLVER_PROFILE,
                ADMISSION_PROFILE,
                "AOE-GB-D06-S09",
                *(item.owner_profile_id for item in self.plan.work_items),
                *REPLACEMENT_REVIEWERS.values(),
            }
        )
        subjects = sorted(
            {
                SUBJECT,
                ASSURANCE_SUBJECT,
                CONTROL_REVIEW_SUBJECT,
                RESOLVER_SUBJECT,
                ADMISSION_SUBJECT,
                *(replacement_subject(item.owner_profile_id) for item in self.plan.work_items),
                *(replacement_subject(profile) for profile in REPLACEMENT_REVIEWERS.values()),
            }
        )
        policy = self.factory.policy(
            max_assertion_lifetime_seconds=1800,
            policy_version=self.policy_version,
            store_id=self.root.store_id,
            allowed_profiles=profiles,
            allowed_subjects=subjects,
            allowed_operations=operations,
        )
        self.alternate_assertion_private = Ed25519PrivateKey.generate()
        self.alternate_assertion_key_id = "principal-key:phase195b-alternate"
        self.alternate_assertion_issuer = "alternate-identity-provider"
        policy_document = policy.to_dict()
        policy_document["keys"].append(
            {
                **policy_document["keys"][0],
                "key_id": self.alternate_assertion_key_id,
                "issuer": self.alternate_assertion_issuer,
                "public_key": b64url(public_bytes(self.alternate_assertion_private)),
            }
        )
        policy_document["keys"] = sorted(
            policy_document["keys"],
            key=lambda item: item["key_id"],
        )
        unsigned_policy = PrincipalTrustPolicy.from_dict(policy_document)
        policy = replace(
            unsigned_policy,
            signature=b64url(self.factory.root_private.sign(unsigned_policy.signing_bytes())),
        )
        self.root.trust.apply_policy(policy)
        self.policy = policy
        self.acceptance = ScopeGrantAcceptanceService(self.store, self.registry)
        self.grants = {
            "assurance": self._grant(
                "41",
                ASSURANCE_PROFILE,
                ASSURANCE_SUBJECT,
                (
                    PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
                    PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
                ),
            ),
            "control": self._grant(
                "42",
                self.control_profile,
                SUBJECT,
                (
                    PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
                    PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE,
                    PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
                    PrincipalOperation.ACTION_QUORUM_AUTHORIZE,
                    PrincipalOperation.ACTION_ADMISSION_REVOKE,
                    PrincipalOperation.ACTION_EXECUTION_RECONCILE,
                    PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
                ),
            ),
            "control_review": self._grant(
                "49",
                self.control_profile,
                CONTROL_REVIEW_SUBJECT,
                (PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,),
            ),
            "owner": self._grant(
                "43",
                self.owner_profile,
                SUBJECT,
                (PrincipalOperation.ACTION_QUORUM_AUTHORIZE,),
            ),
            "resolver": self._grant(
                "44",
                RESOLVER_PROFILE,
                RESOLVER_SUBJECT,
                (PrincipalOperation.ACTION_RESOLVE,),
            ),
            "admission": self._grant(
                "45",
                ADMISSION_PROFILE,
                ADMISSION_SUBJECT,
                (
                    PrincipalOperation.ACTION_ADMIT,
                    PrincipalOperation.ACTION_EXECUTE,
                ),
            ),
            "proposal_worker": self._grant(
                "46",
                "AOE-GB-D06-S09",
                SUBJECT,
                (PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,),
            ),
        }
        for grant in self.grants.values():
            self.acceptance.accept(grant)
        self.activation = self._activate_proposal_session()
        self.workspace_path = self.root.directory / "phase195b-workspace.sqlite3"
        self.workspace = SQLiteExpertWorkspaceStore(self.workspace_path)
        self.workspace.initialize()
        self.workspace_state, self.product = self._complete_workspace()
        self.snapshot = self.workspace.export_review_snapshot(
            self.workspace_state.workspace_id,
            runtime_catalog=self.catalog,
            expert_registry=self.registry,
        )
        self.review = SQLiteAuthenticatedExpertReviewCustody(
            self.store,
            self.registry,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
            clock=lambda: self.root.now,
        )
        self.review_proof = self._close_review()
        self.review_application = self.review.apply_closure(
            self.review_proof,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.review_adapter = AuthenticatedExpertReviewClosureVerifierAdapter(
            self.review,
            self.registry,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.health_custody_clock = lambda: self.root.now
        self.health_custody_factory = phase198.ContractFactory(mission_id=self.mission_id)
        self.health_custody_factory.root = replace(
            self.health_custody_factory.root,
            tenant_id=TENANT_ID,
            effective_at="2026-07-29T00:00:00Z",
            expires_at="2026-07-31T00:00:00Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        self.health_custody = SQLiteTargetHealthCustody(
            self.root.directory / "phase195b-target-health.sqlite3",
            trust_root=self.health_custody_factory.root,
            trusted_clock=self.health_custody_clock,
        )
        self.health_envelopes = {}
        self.health_policies = {}
        self.health_gate = MissionStoreTargetHealthGateService(
            self.store,
            self.health_custody,
            self.registry,
            clock=self.health_custody_clock,
        )
        self.health_gate.initialize()
        self.service = MissionStoreAuthenticatedActionAdmissionService(
            self.store,
            self.review_adapter,
            self.registry,
            health_gate=self.health_gate,
            clock=self.health_custody_clock,
        )
        self.service.initialize()

    def _seed_healthy_target_custody(self, sources):  # type: ignore[no-untyped-def]
        binding = self.service._target_health_binding_from_material(sources["material"])
        binding_sha256 = execution_binding_sha256(binding)
        if binding_sha256 in self.health_envelopes:
            return binding
        observed_at = self.root.now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt = _healthy_target_receipt(binding, observed_at)
        receipt = replace(
            receipt,
            monotonic_tick=1,
            receipt_id="",
            receipt_sha256="",
        )
        factory = self.health_custody_factory
        factory.binding = binding
        factory.binding_sha256 = binding_sha256
        policy = factory.make_policy(
            issued_at="2026-07-30T09:59:00Z",
            effective_at="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T10:30:00Z",
            runtime_policy_id=receipt.runtime_policy_id,
            runtime_policy_sha256=receipt.runtime_policy_sha256,
        )
        self.health_custody.publish_policy(policy)
        envelope = factory.make_envelope(
            policy,
            sequence=1,
            observed_at=receipt.observed_at,
            monotonic_tick=receipt.monotonic_tick,
            receipt=receipt,
        )
        self.health_custody.append_envelope(envelope)
        self.health_envelopes[binding_sha256] = envelope
        self.health_policies[binding_sha256] = policy
        return binding

    def _activate_proposal_session(self):  # type: ignore[no-untyped-def]
        item = next(
            value for value in self.plan.work_items if value.owner_profile_id == "AOE-GB-D06-S09"
        )
        channel_policy = self.fixture.fixture.fixture.fixture.policy
        session = build_collaboration_fenced_worker_session(
            channel_policy=channel_policy,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=collaboration_work_item_objective_sha256(item),
            ownership_chain_id="OCN-" + "C" * 32,
            ownership_entry_id="OCE-" + "D" * 32,
            ownership_entry_sha256="sha256:" + "c" * 64,
            owner_profile_id=item.owner_profile_id,
            owner_epoch=1,
            worker_principal_id=item.owner_profile_id,
            fence_generation=1,
            credential_reference_id="CREDENTIAL-PHASE195B-PROPOSAL",
            credential_sha256="sha256:" + "d" * 64,
            predecessor=None,
            prepared_at="2026-07-30T10:08:50Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        authority = build_initial_collaboration_execution_session_authority(
            collaboration_plan=self.plan,
            channel_policy=channel_policy,
            session=session,
            effective_at="2026-07-30T10:09:00Z",
        )
        provisional = build_collaboration_execution_session_activation_request(
            authority,
            control_plane_requester={
                "profile_id": self.control_profile,
                "assertion_id": "PAS-" + "7" * 32,
                "assertion_sha256": "sha256:" + "7" * 64,
            },
            worker_acceptor={
                "profile_id": item.owner_profile_id,
                "assertion_id": "PAS-" + "8" * 32,
                "assertion_sha256": "sha256:" + "8" * 64,
            },
            requested_at="2026-07-30T10:09:00Z",
        )
        selection = collaboration_execution_session_activation_selection_sha256(provisional)
        control_assertion = self._assertion(
            "control",
            "81",
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE,
            {
                "activation_selection_sha256": selection,
                "mission_id": self.mission_id,
                "principal_profile_id": self.control_profile,
            },
        )
        worker_assertion = self._assertion(
            "proposal_worker",
            "82",
            PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT,
            {
                "activation_selection_sha256": selection,
                "mission_id": self.mission_id,
                "principal_profile_id": item.owner_profile_id,
            },
        )
        request = build_collaboration_execution_session_activation_request(
            authority,
            control_plane_requester={
                "profile_id": self.control_profile,
                "assertion_id": control_assertion.assertion_id,
                "assertion_sha256": control_assertion.content_sha256,
            },
            worker_acceptor={
                "profile_id": item.owner_profile_id,
                "assertion_id": worker_assertion.assertion_id,
                "assertion_sha256": worker_assertion.content_sha256,
            },
            requested_at="2026-07-30T10:09:00Z",
        )
        service = AuthenticatedCollaborationExecutionSessionAuthorityService(
            self.store,
            self.registry,
            clock=lambda: self.root.now,
        )
        return service.activate(
            authority,
            request,
            control_plane_assertion=control_assertion,
            worker_assertion=worker_assertion,
        )

    def _grant(self, marker, profile_id, subject, operations):  # type: ignore[no-untyped-def]
        return self.factory.grant(
            grant_id="SGR-" + marker * 16,
            profile_id=profile_id,
            subject=subject,
            store_id=self.root.store_id,
            mission_id=self.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=self.mission.scope_reference,
            scope_document_hash=self.mission.scope_document_hash,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=sha256_text(canonical_json(self.mission.to_dict()["constraints"])),
            operations=[operation.value for operation in operations],
            issued_at="2026-07-30T10:09:00Z",
            not_before="2026-07-30T10:09:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=self.policy_version,
        )

    def _assertion(
        self,
        name: str,
        marker: str,
        operation: PrincipalOperation,
        intent: dict[str, object],
        *,
        issued_at: str = "2026-07-30T10:09:00Z",
        not_before: str = "2026-07-30T10:09:00Z",
        expires_at: str = "2026-07-30T10:29:00Z",
    ):
        grant = self.grants[name]
        return self.factory.assertion(
            grant=grant,
            assertion_id="PAS-" + marker * 16,
            policy_version=self.policy_version,
            scope_grant_id=grant.grant_id,
            subject=grant.subject,
            profile_id=grant.profile_id,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=self.mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
            issued_at=issued_at,
            not_before=not_before,
            expires_at=expires_at,
        )

    def _alternate_issuer_assertion(
        self,
        assertion: PrincipalAssertion,
    ) -> PrincipalAssertion:
        document = assertion.to_dict()
        document.update(
            {
                "issuer": self.alternate_assertion_issuer,
                "key_id": self.alternate_assertion_key_id,
            }
        )
        unsigned = PrincipalAssertion.from_dict(document)
        return replace(
            unsigned,
            signature=b64url(self.alternate_assertion_private.sign(unsigned.signing_bytes())),
        )

    def _complete_workspace(self):  # type: ignore[no-untyped-def]
        item = next(
            value for value in self.plan.work_items if value.owner_profile_id == "AOE-GB-D06-S09"
        )
        pack = self.catalog.packs_by_profile_id[item.owner_profile_id]
        definition = build_expert_workspace_definition(
            self.catalog,
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            plan_id=self.plan.plan_id,
            target_scope_sha256=self.mission.scope_document_hash,
            authority_snapshot_sha256=ZERO,
            evidence_snapshot_sha256=ONE,
            assignments=[
                {
                    "work_id": item.work_item_id,
                    "profile_id": pack["profile_id"],
                    "command_id": pack["command_id"],
                    "runtime_pack_id": pack["runtime_pack_id"],
                    "runtime_pack_sha256": pack["runtime_pack_sha256"],
                    "maximum_attempts": 2,
                }
            ],
            dependencies=[],
            review_requirements=[
                {
                    "work_id": item.work_item_id,
                    "required": True,
                    "reviewer_profile_ids": [
                        self.control_profile,
                        ASSURANCE_PROFILE,
                    ],
                    "producer_excluded": True,
                }
            ],
        )
        created_at = int(self.root.now.timestamp()) - 30
        state = self.workspace.create_workspace(
            definition,
            self.catalog,
            created_at=created_at,
        )
        envelope = build_execution_envelope(
            pack,
            self.catalog,
            mission_id=self.mission_id,
            plan_id=self.plan.plan_id,
            work_id=item.work_item_id,
            target_scope_sha256=self.mission.scope_document_hash,
            authority_snapshot_sha256=ZERO,
            evidence_snapshot_sha256=ONE,
            evidence_requirement_ids=["evidence:phase195b"],
            cleanup_requirement_ids=["cleanup:phase195b"],
            approval_requirement_ids=["approval:phase195b"],
            context_items=[
                {
                    "context_id": "context:phase195b",
                    "context_kind": "target_content",
                    "content": "Bounded authenticated review evidence.",
                    "content_sha256": _canonical_sha256("Bounded authenticated review evidence."),
                    "estimated_tokens": 38,
                    "trust": "untrusted_data",
                }
            ],
        )
        parsed = parse_execution_envelope(envelope, pack, self.catalog)
        lease = self.workspace.acquire_lease(
            state.workspace_id,
            tenant_id=TENANT_ID,
            expected_revision=0,
            envelope=envelope,
            runtime_catalog=self.catalog,
            acquired_at=created_at + 5,
            lease_seconds=20,
        )
        product = content_address_work_product(
            {
                "schema_version": 1,
                "product_type": "action_proposal",
                "runtime_catalog_sha256": self.catalog.catalog_sha256,
                "runtime_pack_id": pack["runtime_pack_id"],
                "runtime_pack_sha256": pack["runtime_pack_sha256"],
                "producer_profile_id": pack["profile_id"],
                "execution_envelope_id": parsed.envelope_id,
                "execution_envelope_sha256": parsed.envelope_sha256,
                "mission_id": self.mission_id,
                "plan_id": self.plan.plan_id,
                "work_id": item.work_item_id,
                "summary": "Reviewed bounded API request proposal.",
                "confidence": "high",
                "uncertainty": "Runtime authority remains separately gated.",
                "evidence_refs": [ONE],
                "lineage_product_ids": [],
                "independent_review": {
                    "required": True,
                    "status": "not_reviewed",
                    "reviewer_profile_ids": [],
                    "producer_excluded": True,
                },
                "payload": {
                    "target_scope_sha256": self.mission.scope_document_hash,
                    "authority_snapshot_sha256": ZERO,
                    "evidence_snapshot_sha256": ONE,
                    "mission_id": self.mission_id,
                    "plan_id": self.plan.plan_id,
                    "work_id": item.work_item_id,
                    "requested_action_tier": "R2",
                    "proposed_actions": ["api.request"],
                    "evidence_requirement_ids": ["evidence:phase195b"],
                    "cleanup_requirement_ids": ["cleanup:phase195b"],
                    "approval_requirement_ids": ["approval:phase195b"],
                    "stop_conditions": list(pack["instruction_contract"]["stop_conditions"]),
                },
                "model_output_effect": "advisory_only",
                "tool_effect": "none",
                "authorization_effect": "none",
            }
        )
        validated_product = parse_work_product(product, pack, parsed, self.catalog)
        self.workspace.accept_work_product(
            state.workspace_id,
            tenant_id=TENANT_ID,
            expected_revision=lease.workspace_revision,
            lease_id=lease.lease_id,
            fencing_token=lease.fencing_token,
            work_product=product,
            runtime_catalog=self.catalog,
            accepted_at=created_at + 10,
        )
        return state, validated_product

    def _close_review(self):  # type: ignore[no-untyped-def]
        self.root.now = datetime(2026, 7, 30, 10, 10, tzinfo=UTC)
        register_intent = expert_review_snapshot_registration_intent(
            self.snapshot,
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.root.stored.revision,
            principal_profile_id=ASSURANCE_PROFILE,
        )
        register = self._assertion(
            "assurance",
            "46",
            PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER,
            register_intent,
        )
        self.review.register_snapshot(
            register,
            self.snapshot,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )
        self.root.now = datetime(2026, 7, 30, 10, 11, tzinfo=UTC)
        receipts = []
        for slot in self.snapshot.to_dict()["review_slots"]:
            reviewer_name = (
                "assurance"
                if slot["reviewer_profile_id"] == ASSURANCE_PROFILE
                else "control_review"
            )
            marker = "47" if reviewer_name == "assurance" else "50"
            submission = build_expert_review_submission(
                snapshot=self.snapshot,
                work_id=slot["work_id"],
                product_id=slot["product_id"],
                product_sha256=slot["product_sha256"],
                reviewer_profile_id=slot["reviewer_profile_id"],
                reviewer_role=slot["reviewer_role"],
                decision=ReviewDecision.ACCEPTED,
                reason_code="evidence-sufficient",
                affected_work_ids=(),
                required_correction_ids=(),
                rationale="The bounded action proposal is suitable for separate admission.",
            )
            review_intent = expert_work_product_review_intent(
                self.snapshot,
                submission,
                active_plan_sha256=self.plan.content_sha256,
                active_plan_version=1,
                mission_revision=self.root.stored.revision,
                principal_profile_id=slot["reviewer_profile_id"],
            )
            reviewer = self._assertion(
                reviewer_name,
                marker,
                PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW,
                review_intent,
            )
            receipts.append(
                self.review.record_review(
                    reviewer,
                    submission,
                    workspace_store=self.workspace,
                    runtime_catalog=self.catalog,
                )
            )
        request = build_expert_review_closure_request(
            self.snapshot,
            tuple(receipts),
            expected_disposition=ClosureDisposition.ACCEPTED,
            closer_profile_id=self.control_profile,
            requested_at=int(self.root.now.timestamp()),
        )
        close_intent = expert_workspace_review_close_intent(
            self.snapshot,
            request,
            tuple(receipts),
            active_plan_sha256=self.plan.content_sha256,
            active_plan_version=1,
            mission_revision=self.root.stored.revision,
            principal_profile_id=self.control_profile,
        )
        self.root.now = datetime(2026, 7, 30, 10, 12, tzinfo=UTC)
        closer = self._assertion(
            "control",
            "48",
            PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE,
            close_intent,
        )
        return self.review.close_review(
            closer,
            request,
            workspace_store=self.workspace,
            runtime_catalog=self.catalog,
        )

    @staticmethod
    def _resources(value: int) -> dict[str, int]:
        return {field: value for field in RESOURCE_FIELDS}

    class _CurrentAuthorizationVerifier:
        @staticmethod
        def verify_current(authorization):  # type: ignore[no-untyped-def]
            return action_resolution._seal_current_principal_authorization(authorization)

    def _install_fresh_current_control(self) -> None:
        control_grant = self._grant(
            "62",
            self.control_profile,
            CONTROL_REVIEW_SUBJECT,
            (
                PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
                PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
                PrincipalOperation.ACTION_ADMISSION_REVOKE,
                PrincipalOperation.EXECUTION_SESSION_REVOKE,
            ),
        )
        owner_grant = self._grant(
            "61",
            self.owner_profile,
            SUBJECT,
            (PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,),
        )
        self.acceptance.accept(owner_grant)
        self.acceptance.accept(control_grant)
        with self.store._read_connection() as connection:
            previous = connection.execute(
                "SELECT policy_json FROM collaboration_mission_policy_commits "
                "WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1",
                (self.mission_id,),
            ).fetchone()
        self.assertIsNotNone(previous)
        previous_document = json.loads(previous["policy_json"])

        def build_policy(owner_binding, control_binding):  # type: ignore[no-untyped-def]
            selected = previous_document["selected_parameters"]
            return build_collaboration_mission_reconfiguration_policy(
                authority_policy=self.root.authority,
                policy_version=previous_document["policy_version"] + 1,
                previous_policy_sha256=previous_document["policy_sha256"],
                mission_id=self.mission_id,
                collaboration_plan_id=self.plan.plan_id,
                collaboration_plan_sha256=self.plan.content_sha256,
                maximum_delegation_depth=selected["maximum_delegation_depth"],
                reconfiguration_validity_seconds=selected["reconfiguration_validity_seconds"],
                execution_ack_timeout_seconds=selected["execution_ack_timeout_seconds"],
                maximum_plan_replacement_items=selected["maximum_plan_replacement_items"],
                transition_activation=previous_document["transition_activation"],
                mission_owner_approval=owner_binding,
                independent_control_approval=control_binding,
                effective_at="2026-07-30T10:12:00Z",
                expires_at="2026-07-30T11:00:00Z",
            )

        def placeholder(profile, marker):  # type: ignore[no-untyped-def]
            return {
                "profile_id": profile,
                "assertion_id": "PAS-" + marker * 16,
                "assertion_sha256": "sha256:" + marker[0].lower() * 64,
            }

        provisional = build_policy(
            placeholder(self.owner_profile, "65"),
            placeholder(self.control_profile, "66"),
        )
        selection = collaboration_mission_reconfiguration_selection_sha256(provisional)

        def policy_assertion(grant_value, marker, operation):  # type: ignore[no-untyped-def]
            return self.factory.assertion(
                grant=grant_value,
                assertion_id="PAS-" + marker * 16,
                policy_version=self.policy_version,
                scope_grant_id=grant_value.grant_id,
                subject=grant_value.subject,
                profile_id=grant_value.profile_id,
                audience=AUDIENCE,
                store_id=self.root.store_id,
                mission_id=self.mission_id,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(
                    operation,
                    {
                        "mission_id": self.mission_id,
                        "policy_selection_sha256": selection,
                        "principal_profile_id": grant_value.profile_id,
                    },
                ),
                issued_at="2026-07-30T10:09:00Z",
                not_before="2026-07-30T10:09:00Z",
                expires_at="2026-07-30T10:29:00Z",
            )

        owner = policy_assertion(
            owner_grant,
            "65",
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        control = policy_assertion(
            control_grant,
            "66",
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )

        def binding(assertion):  # type: ignore[no-untyped-def]
            return {
                "profile_id": assertion.profile_id,
                "assertion_id": assertion.assertion_id,
                "assertion_sha256": assertion.content_sha256,
            }

        policy = build_policy(binding(owner), binding(control))
        self.root.now = datetime(2026, 7, 30, 10, 12, 30, tzinfo=UTC)
        AuthenticatedCollaborationMissionPolicyService(
            self.store,
            self.registry,
            clock=lambda: self.root.now,
        ).commit(
            policy,
            authority_policy=self.root.authority,
            mission_owner_assertion=owner,
            independent_control_assertion=control,
        )
        self.grants["control"] = control_grant

    def _terminate_session_and_replace_plan(self):  # type: ignore[no-untyped-def]
        revoked_at = "2026-07-30T10:14:00Z"
        self.root.now = datetime(2026, 7, 30, 10, 14, tzinfo=UTC)
        service = AuthenticatedCollaborationExecutionSessionAuthorityService(
            self.store,
            self.registry,
            clock=lambda: self.root.now,
        )
        for authority, marker in (
            (self.fixture.authority, "68"),
            (self.activation.authority, "69"),
        ):
            provisional = build_collaboration_execution_session_revocation(
                authority,
                decision_owner={
                    "profile_id": self.control_profile,
                    "assertion_id": "PAS-" + marker * 16,
                    "assertion_sha256": "sha256:" + marker[0] * 64,
                },
                reason_code="policy_superseded",
                revoked_at=revoked_at,
            )
            selection = collaboration_execution_session_revocation_selection_sha256(provisional)
            assertion = self._assertion(
                "control",
                marker,
                PrincipalOperation.EXECUTION_SESSION_REVOKE,
                {
                    "mission_id": self.mission_id,
                    "principal_profile_id": self.control_profile,
                    "revocation_selection_sha256": selection,
                },
            )
            revocation = build_collaboration_execution_session_revocation(
                authority,
                decision_owner={
                    "profile_id": assertion.profile_id,
                    "assertion_id": assertion.assertion_id,
                    "assertion_sha256": assertion.content_sha256,
                },
                reason_code="policy_superseded",
                revoked_at=revoked_at,
            )
            service.revoke(
                authority,
                revocation,
                independent_control_assertion=assertion,
            )
        replacement = phase186.replacement_plan(self.plan, "9")
        self.root.now = datetime(2026, 7, 30, 10, 14, 1, tzinfo=UTC)
        commit_signed_plan_rotation(self, replacement)
        return replacement

    def _authority_sources(
        self,
        *,
        valid_until: str = "2026-07-30T10:20:00Z",
        source_expires_at: str = "2026-07-30T10:25:00Z",
    ):  # type: ignore[no-untyped-def]
        published_at = "2026-07-30T10:13:00Z"
        revision_common = {
            "tenant_id": TENANT_ID,
            "mission_id": self.mission_id,
            "plan_id": self.plan.plan_id,
            "revision": 1,
            "previous_revision_sha256": None,
            "effective_at": "2026-07-30T10:09:00Z",
            "expires_at": source_expires_at,
            "revocation_policy_sha256": _canonical_sha256(
                {"policy": "phase195b-source-revocation"}
            ),
        }
        authority_policy = build_action_authority_policy_revision(
            **revision_common,
            policy_id="policy:phase195b-action-authority",
            typed_resolver={
                "role": "typed_resolver",
                "principal_profile_id": RESOLVER_PROFILE,
                "principal_subject": RESOLVER_SUBJECT,
                "assertion_issuer": "identity-provider",
            },
            admission_control={
                "role": "admission_control",
                "principal_profile_id": ADMISSION_PROFILE,
                "principal_subject": ADMISSION_SUBJECT,
                "assertion_issuer": "identity-provider",
            },
            revocation_control={
                "role": "independent_control",
                "principal_profile_id": self.control_profile,
                "principal_subject": SUBJECT,
                "assertion_issuer": "identity-provider",
            },
        )
        parameter_contract = [{"name": "path", "required": True, "value_type": "string"}]
        environment = "replica"
        registry_sha256 = self.snapshot.to_dict()["registry_sha256"]
        executable_catalog = build_executable_action_catalog(
            catalog_name="catalog:phase195b-actions",
            catalog_version="1.0.0",
            registry_sha256=registry_sha256,
            entries=[
                {
                    "action_type": "api.request",
                    "executor_supported": True,
                    "maximum_action_tier": "R2",
                    "parameter_contract": parameter_contract,
                    "parameter_contract_sha256": parameter_contract_sha256(parameter_contract),
                    "r4_executor_supported": False,
                    "supported_environments": [environment],
                    "tool_artifact_ref": "artifact:phase195b-api-adapter",
                    "tool_artifact_sha256": _canonical_sha256(
                        {"artifact": "phase195b-api-adapter"}
                    ),
                    "tool_exact_version": "1.0.0",
                }
            ],
        )
        catalog_source = build_authoritative_action_catalog_revision(
            **revision_common,
            catalog_id=executable_catalog.catalog_id,
            catalog_version="1.0.0",
            registry_sha256=registry_sha256,
            entries=[
                {
                    "action_type": "api.request",
                    "maximum_action_tier": "R2",
                    "target_kinds": ["web_api"],
                    "supported_environments": [environment],
                    "parameter_schema_sha256": parameter_contract_sha256(parameter_contract),
                    "tool_artifact_ref": "artifact:phase195b-api-adapter",
                    "tool_artifact_sha256": _canonical_sha256(
                        {"artifact": "phase195b-api-adapter"}
                    ),
                    "tool_exact_version": "1.0.0",
                    "adapter_kind": "http",
                    "r4_executor_supported": False,
                }
            ],
        )
        parameters = build_action_parameter_set(
            executable_catalog,
            action_type="api.request",
            parameters={"path": "/health"},
        )
        target_sha256 = _canonical_sha256({"target": "phase195b-web-api"})
        target = build_target_action_descriptor(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            target_scope_sha256=self.mission.scope_document_hash,
            authority_snapshot_sha256=ZERO,
            target_id="target:phase195b-web-api",
            target_sha256=target_sha256,
            environment=environment,
        )
        target_source = build_authoritative_target_descriptor_revision(
            **revision_common,
            target_descriptor_id="target-descriptor:phase195b-web-api",
            target_id="target:phase195b-web-api",
            target_sha256=target_sha256,
            target_kind="web_api",
            environment=environment,
            scope_sha256=self.mission.scope_document_hash,
            authority_snapshot_sha256=ZERO,
            evidence_snapshot_sha256=ONE,
            allowed_action_types=["api.request"],
            maximum_action_tier="R2",
        )
        budget = build_action_budget_policy_revision(
            **revision_common,
            budget_id="budget:phase195b-mission",
            scope_sha256=self.mission.scope_document_hash,
            limits=self._resources(100_000),
            per_action_ceiling={
                "money_microunits": 1_000,
                "rate_units": 1,
                "request_bytes": 1_024,
                "response_bytes": 4_096,
                "duration_ms": 10_000,
                "impact_events": 1,
            },
        )
        restoration_sha256 = _canonical_sha256({"restoration": "phase195b-action"})
        safety = build_action_safety_policy_revision(
            **revision_common,
            safety_policy_id="safety:phase195b-action",
            scope_sha256=self.mission.scope_document_hash,
            target_sha256=target_sha256,
            action_types=["api.request"],
            maximum_action_tier="R2",
            stop_conditions=["monitor_loss", "scope_drift"],
            impact_limits={
                "maximum_duration_ms": 10_000,
                "maximum_impact_events": 1,
                "maximum_request_bytes": 1_024,
                "maximum_response_bytes": 4_096,
            },
            monitor={
                "monitor_id": "monitor:phase195b",
                "principal_profile_id": ASSURANCE_PROFILE,
                "principal_subject": ASSURANCE_SUBJECT,
                "heartbeat_timeout_seconds": 5,
                "required": True,
            },
            deadline={
                "hard_deadline_required": True,
                "maximum_duration_ms": 10_000,
            },
            restoration={
                "required": True,
                "restoration_plan_sha256": restoration_sha256,
                "owner_profile_id": self.owner_profile,
                "owner_subject": "owner:phase195b-restoration",
                "verifier_profile_id": self.control_profile,
                "verifier_subject": "control:phase195b-restoration",
                "completion_evidence_required": True,
            },
        )
        closure = self.review_proof.records.closure
        proposal = build_authenticated_proposal_material_import(
            product=self.product,
            tenant_id=TENANT_ID,
            workspace_id=self.workspace_state.workspace_id,
            review_snapshot_id=self.snapshot.snapshot_id,
            review_snapshot_sha256=self.snapshot.snapshot_sha256,
            review_closure_id=closure.closure_id,
            review_closure_sha256=closure.closure_sha256,
            catalog=catalog_source,
            target=target_source,
            parameter_set_id=parameters.parameter_set_id,
            parameter_set_sha256=parameters.parameter_set_sha256,
            selected_action_type="api.request",
            requested_action_tier="R2",
            imported_at="2026-07-30T10:12:00Z",
        )
        action_sha256 = _resolved_action_sha256(
            catalog=executable_catalog,
            entry=_catalog_action(executable_catalog, "api.request"),
            parameters=parameters,
            target=target,
            action_tier=ActionTier.R2,
        )
        activation_document = self.activation.to_dict()
        session_authority = activation_document["session_authority"]
        session = session_authority["session"]
        fence = action_fence_token_sha256(
            session_authority_id=session_authority["session_authority_id"],
            execution_session_id=session["session_id"],
            owner_epoch=session["owner_epoch"],
            fence_generation=session["fence_generation"],
        )
        worker = WorkerSession(
            worker_id=session["worker_principal_id"],
            worker_profile_id=session["owner_profile_id"],
            session_id=session["session_id"],
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            fence_token_sha256=fence,
            leader_epoch=session["owner_epoch"],
            issued_at=session_authority["effective_at"],
            expires_at=session_authority["expires_at"],
        )
        credential = CredentialLease(
            lease_id=session["credential_reference_id"],
            credential_ref_sha256=session["credential_sha256"],
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            scope_sha256=self.mission.scope_document_hash,
            worker_id=worker.worker_id,
            session_id=worker.session_id,
            fence_token_sha256=fence,
            leader_epoch=worker.leader_epoch,
            permitted_action_sha256=action_sha256,
            revoked=False,
            issued_at="2026-07-30T10:09:00Z",
            expires_at=valid_until,
        )
        health_sha256 = _canonical_sha256({"health": "phase195b-healthy"})
        health = HealthEvidence(
            worker_id=worker.worker_id,
            session_id=worker.session_id,
            fence_token_sha256=fence,
            leader_epoch=worker.leader_epoch,
            status=HealthStatus.HEALTHY,
            evidence_sha256=health_sha256,
            observed_at=published_at,
            expires_at=valid_until,
        )
        evidence_obligations = tuple(
            EvidenceObligation(
                evidence_kind=kind,
                evidence_sha256=_canonical_sha256(
                    {"evidence_kind": kind.value, "fixture": "phase195b"}
                ),
                tenant_id=TENANT_ID,
                mission_id=self.mission_id,
                scope_sha256=self.mission.scope_document_hash,
                target_sha256=target_sha256,
                action_sha256=action_sha256,
                producer_id=f"producer:{kind.value}",
                issued_at="2026-07-30T10:09:00Z",
                expires_at=valid_until,
            )
            for kind in sorted(REQUIRED_EVIDENCE, key=lambda item: item.value)
        )
        self.assertEqual(
            {item.evidence_kind for item in evidence_obligations},
            set(EvidenceKind),
        )
        monitor_observation_sha256 = action_monitor_observation_sha256(
            monitor_id="monitor:phase195b",
            principal_profile_id=ASSURANCE_PROFILE,
            principal_subject=ASSURANCE_SUBJECT,
            monitor_session_id="monitor-session:phase195b",
            monitor_worker_id=ASSURANCE_PROFILE,
            status="healthy",
            heartbeat_observed_at=published_at,
            heartbeat_expires_at="2026-07-30T10:13:05Z",
        )
        stop = StopConditions(
            stop_contract_sha256=action_stop_contract_sha256(safety),
            monitor_session_id="monitor-session:phase195b",
            monitor_worker_id=ASSURANCE_PROFILE,
            scope_sha256=self.mission.scope_document_hash,
            target_sha256=target_sha256,
            action_sha256=action_sha256,
            maximum_impact_events=1,
            stop_deadline_at="2026-07-30T10:13:05Z",
            expires_at="2026-07-30T10:13:05Z",
        )
        restoration = RestorationDuties(
            required=True,
            restoration_plan_sha256=restoration_sha256,
            owner_profile_id=self.owner_profile,
            verifier_profile_id=self.control_profile,
            scope_sha256=self.mission.scope_document_hash,
            target_sha256=target_sha256,
            action_sha256=action_sha256,
            completion_evidence_required=True,
        )
        context = ContextBinding(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            scope_id=self.mission.scope_reference,
            scope_sha256=self.mission.scope_document_hash,
            policy=ArtifactBinding(
                "artifact:phase195b-mission-policy",
                self.policy.content_sha256,
                "1.0.0",
            ),
        )
        budget_binding = phase165_budget_binding_from_policy(
            budget,
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
        )
        material = build_action_authority_material_snapshot(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            plan_id=self.plan.plan_id,
            proposal=proposal,
            catalog=executable_catalog,
            parameters=parameters,
            target=target,
            resolver_profile_id=RESOLVER_PROFILE,
            resolver_subject=RESOLVER_SUBJECT,
            context=context,
            worker_session=worker,
            credential_lease=credential,
            health=health,
            budget=budget_binding,
            monitor_observation_sha256=monitor_observation_sha256,
            evidence_obligations=evidence_obligations,
            stop_conditions=stop,
            restoration_duties=restoration,
            resolved_at="2026-07-30T10:12:10Z",
            approved_at="2026-07-30T10:12:20Z",
            quorum_expires_at=valid_until,
            requested_at="2026-07-30T10:12:55Z",
            expires_at=valid_until,
            observed_at=published_at,
            valid_until=valid_until,
        )
        with self.store._read_connection() as connection:
            mission_row = connection.execute(
                "SELECT revision FROM missions WHERE mission_id = ?",
                (self.mission_id,),
            ).fetchone()
            plan_row = connection.execute(
                "SELECT activation.plan_content_sha256, activation.plan_version "
                "FROM collaboration_plan_active_heads AS head "
                "JOIN collaboration_plan_activations AS activation "
                "ON activation.plan_id = head.active_plan_id "
                "WHERE head.mission_id = ?",
                (self.mission_id,),
            ).fetchone()
            mission_policy_row = connection.execute(
                "SELECT policy_sha256 FROM collaboration_mission_policy_commits "
                "WHERE mission_id = ? ORDER BY policy_version DESC LIMIT 1",
                (self.mission_id,),
            ).fetchone()
            baseline_row = connection.execute(
                "SELECT head_hash FROM mission_scope_revocation_baselines WHERE mission_id = ?",
                (self.mission_id,),
            ).fetchone()
            projection_row = connection.execute(
                "SELECT application_sha256 "
                "FROM authenticated_expert_review_closure_projections "
                "WHERE mission_id = ? AND closure_id = ?",
                (self.mission_id, closure.closure_id),
            ).fetchone()
            guard, high_water = self.review_adapter.open_local_workspace_guard(
                connection,
                self.review_proof.records,
            )
            try:
                high_water = dict(high_water)
            finally:
                self.review_adapter.close_local_workspace_guard(guard)
        for label, row in (
            ("mission", mission_row),
            ("plan", plan_row),
            ("mission policy", mission_policy_row),
            ("scope revocation baseline", baseline_row),
            ("review projection", projection_row),
        ):
            self.assertIsNotNone(row, label)
        material_document = material.to_dict()
        budget_document = budget.to_dict()
        account_id = (
            "ABA-"
            + _canonical_sha256(
                {
                    "account": {
                        "budget_id": budget_document["budget_id"],
                        "mission_id": self.mission_id,
                        "opened_at": published_at,
                        "tenant_id": TENANT_ID,
                    },
                    "domain": BUDGET_ACCOUNT_DOMAIN,
                }
            )
            .removeprefix("sha256:")[:32]
            .upper()
        )
        binding_sha256 = _canonical_sha256(
            {
                "binding": {
                    "account_id": account_id,
                    "binding_sequence": 1,
                    "budget_revision_id": budget.budget_revision_id,
                    "budget_revision_sha256": budget.budget_revision_sha256,
                    "limits": budget_document["limits"],
                    "previous_binding_sha256": None,
                    "bound_at": published_at,
                },
                "domain": BUDGET_POLICY_BINDING_DOMAIN,
            }
        )
        empty_budget_head = _canonical_sha256(
            {"domain": BUDGET_EVENT_DOMAIN, "empty_account_id": account_id}
        )
        observations = tuple(
            sorted(
                (
                    build_action_authority_observation(
                        observation_kind="execution_fence_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "session_authority_id": session_authority["session_authority_id"],
                            "session_authority_sha256": session_authority[
                                "session_authority_sha256"
                            ],
                            "execution_session_id": session["session_id"],
                            "execution_session_sha256": session["session_sha256"],
                            "owner_epoch": session["owner_epoch"],
                            "fence_generation": session["fence_generation"],
                            "fence_token_sha256": fence,
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                    build_action_authority_observation(
                        observation_kind="credential_lease_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "credential_lease": credential.to_dict(),
                            "credential_lease_sha256": material_document["credential_lease_sha256"],
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                    build_action_authority_observation(
                        observation_kind="executor_health_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "health": health.to_dict(),
                            "health_observation_sha256": material_document[
                                "health_observation_sha256"
                            ],
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                    build_action_authority_observation(
                        observation_kind="executor_deployment_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "worker_session": worker.to_dict(),
                            "executor_deployment_sha256": material_document[
                                "executor_deployment_sha256"
                            ],
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                    build_action_authority_observation(
                        observation_kind="stop_monitor_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "monitor_id": "monitor:phase195b",
                            "principal_profile_id": ASSURANCE_PROFILE,
                            "principal_subject": ASSURANCE_SUBJECT,
                            "monitor_session_id": stop.monitor_session_id,
                            "monitor_worker_id": stop.monitor_worker_id,
                            "monitor_observation_sha256": monitor_observation_sha256,
                            "status": "healthy",
                            "heartbeat_observed_at": published_at,
                            "heartbeat_expires_at": "2026-07-30T10:13:05Z",
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                    build_action_authority_observation(
                        observation_kind="workspace_high_water_observation",
                        tenant_id=TENANT_ID,
                        mission_id=self.mission_id,
                        plan_id=self.plan.plan_id,
                        payload={
                            "high_water": high_water,
                            "high_water_sha256": high_water["high_water_sha256"],
                        },
                        observed_at=published_at,
                        valid_until=valid_until,
                    ),
                ),
                key=lambda item: item.KIND,
            )
        )
        source_bundle = build_exact_action_source_head_bundle(
            policy=authority_policy,
            catalog=catalog_source,
            target=target_source,
            budget=budget,
            safety=safety,
            proposal=proposal,
            active_plan_sha256=str(plan_row["plan_content_sha256"]),
            active_plan_version=int(plan_row["plan_version"]),
            mission_revision=int(mission_row["revision"]),
            mission_policy_sha256=str(mission_policy_row["policy_sha256"]),
            trust_policy_sha256=self.policy.content_sha256,
            scope_grant_sha256=self.grants["control"].content_sha256,
            scope_revocation_head_sha256=str(baseline_row["head_hash"]),
            workspace_high_water_sha256=high_water["high_water_sha256"],
            review_closure_projection_sha256=str(projection_row["application_sha256"]),
            review_revocation_head_sha256=action_review_revocation_head_sha256(closure.closure_id),
            budget_policy_binding_sequence=1,
            budget_policy_binding_sha256=binding_sha256,
            budget_ledger_head_sha256=empty_budget_head,
            session_authority_id=session_authority["session_authority_id"],
            session_authority_sha256=session_authority["session_authority_sha256"],
            execution_session_id=session["session_id"],
            execution_session_sha256=session["session_sha256"],
            owner_epoch=session["owner_epoch"],
            fence_generation=session["fence_generation"],
            credential_lease_sha256=material_document["credential_lease_sha256"],
            health_observation_sha256=material_document["health_observation_sha256"],
            executor_deployment_sha256=material_document["executor_deployment_sha256"],
            monitor_observation_sha256=material_document["monitor_observation_sha256"],
            observed_at=published_at,
            valid_until=valid_until,
        )
        publication = build_authenticated_action_authority_publication(
            policy=authority_policy,
            catalog=catalog_source,
            target=target_source,
            budget=budget,
            safety=safety,
            proposal=proposal,
            source_bundle=source_bundle,
            material=material,
            observations=observations,
            idempotency_key_sha256=_canonical_sha256({"idempotency": "phase195b-publication"}),
            published_at=published_at,
        )
        sources = {
            "policy": authority_policy,
            "catalog": catalog_source,
            "target": target_source,
            "budget": budget,
            "safety": safety,
            "proposal": proposal,
            "source_bundle": source_bundle,
            "material": material,
            "observations": observations,
            "publication": publication,
            "executable_catalog": executable_catalog,
            "parameters": parameters,
            "action_target": target,
            "context": context,
            "worker": worker,
            "credential": credential,
            "health": health,
            "budget_binding": budget_binding,
            "evidence_obligations": evidence_obligations,
            "stop": stop,
            "restoration": restoration,
        }
        self._seed_healthy_target_custody(sources)
        return sources

    def _publish_sources(self):  # type: ignore[no-untyped-def]
        sources = self._authority_sources()
        publication = sources["publication"]
        publication_document = publication.to_dict()
        assertion = self._assertion(
            "control",
            "51",
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            {
                "idempotency_key_sha256": publication_document["idempotency_key_sha256"],
                "mission_id": self.mission_id,
                "principal_profile_id": self.control_profile,
                "publication_sha256": publication.publication_sha256,
            },
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        published = self.service.publish_authority_sources(
            assertion,
            publication,
            policy=sources["policy"],
            catalog=sources["catalog"],
            target=sources["target"],
            budget=sources["budget"],
            safety=sources["safety"],
            proposal=sources["proposal"],
            source_bundle=sources["source_bundle"],
            material=sources["material"],
            observations=sources["observations"],
        )
        self.assertEqual(published, publication)
        return sources

    def _authorization(
        self,
        resolution,
        *,
        name: str,
        marker: str,
        operation: PrincipalOperation,
        role: AuthorizationRole,
        operation_intent_sha256: str,
        replay_label: str,
        issued_at: str = "2026-07-30T10:09:00Z",
        expires_at: str = "2026-07-30T10:20:00Z",
        alternate_issuer: bool = False,
    ):  # type: ignore[no-untyped-def]
        replay_key = _canonical_sha256({"replay": replay_label})
        assertion = self._assertion(
            name,
            marker,
            operation,
            {
                "action_intent_sha256": operation_intent_sha256,
                "idempotency_key_sha256": replay_key,
                "mission_id": self.mission_id,
                "principal_profile_id": self.grants[name].profile_id,
                "role": role.value,
            },
        )
        if alternate_issuer:
            assertion = self._alternate_issuer_assertion(assertion)
        resolution_document = resolution.to_dict()
        authorization = {
            "role": role.value,
            "principal_profile_id": assertion.profile_id,
            "principal_subject": assertion.subject,
            "assertion_issuer": assertion.issuer,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": sha256_text(canonical_json(assertion.to_dict())),
            "assertion_key_sha256": self.policy.key(assertion.key_id).content_sha256,
            "trust_policy_sha256": self.policy.content_sha256,
            "scope_grant_sha256": assertion.scope_grant_sha256,
            "operation_intent_sha256": operation_intent_sha256,
            "canonical_replay_key_sha256": replay_key,
            "tenant_id": TENANT_ID,
            "mission_id": self.mission_id,
            "scope_sha256": resolution_document["target_scope_sha256"],
            "target_sha256": resolution_document["target_sha256"],
            "action_sha256": resolution_document["action_sha256"],
            "resolution_sha256": resolution.resolution_sha256,
            "authorized_tier": "R2",
            "decision": "approved",
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        self.assertEqual(
            self.service.submit_authorization_grant(assertion, authorization),
            authorization,
        )
        return authorization

    def _stage_admission_grants(
        self,
        sources,
        command,
        *,
        owner_alternate_issuer: bool = False,
    ):  # type: ignore[no-untyped-def]
        resolution = resolve_action_proposal(
            self.review_proof.records,
            self.registry,
            self.review_adapter,
            sources["executable_catalog"],
            sources["parameters"],
            sources["action_target"],
            proposal_product_id=self.product.product_id,
            action_type="api.request",
            action_tier=ActionTier.R2,
            idempotency_key_sha256=command.idempotency_key_sha256,
            resolver_profile_id=RESOLVER_PROFILE,
            resolver_subject=RESOLVER_SUBJECT,
            resolved_at="2026-07-30T10:12:10Z",
        )
        self._authorization(
            resolution,
            name="resolver",
            marker="52",
            operation=PrincipalOperation.ACTION_RESOLVE,
            role=AuthorizationRole.TYPED_RESOLVER,
            operation_intent_sha256=resolution_authorization_intent_sha256(resolution),
            replay_label="phase195b-resolution",
        )
        approved_at = "2026-07-30T10:12:20Z"
        quorum_expires_at = "2026-07-30T10:20:00Z"
        owner_authorization = self._authorization(
            resolution,
            name="owner",
            marker="53",
            operation=PrincipalOperation.ACTION_QUORUM_AUTHORIZE,
            role=AuthorizationRole.MISSION_OWNER,
            operation_intent_sha256=quorum_authorization_intent_sha256(
                resolution,
                AuthorizationRole.MISSION_OWNER,
                approved_at=approved_at,
                expires_at=quorum_expires_at,
            ),
            replay_label="phase195b-owner-quorum",
            alternate_issuer=owner_alternate_issuer,
        )
        quorum = build_action_authorization_quorum(
            resolution,
            self._CurrentAuthorizationVerifier(),
            approvals=(owner_authorization,),
            approved_at=approved_at,
            expires_at=quorum_expires_at,
        )
        request = reconstruct_action_admission_request(
            resolution,
            quorum,
            context=sources["context"],
            worker_session=sources["worker"],
            credential_lease=sources["credential"],
            health=sources["health"],
            budget=sources["budget_binding"],
            evidence_obligations=sources["evidence_obligations"],
            stop_conditions=sources["stop"],
            restoration_duties=sources["restoration"],
            requested_at="2026-07-30T10:12:55Z",
            expires_at="2026-07-30T10:20:00Z",
        )
        self._authorization(
            resolution,
            name="admission",
            marker="54",
            operation=PrincipalOperation.ACTION_ADMIT,
            role=AuthorizationRole.ADMISSION_CONTROL,
            operation_intent_sha256=admission_authorization_intent_sha256(
                resolution,
                quorum,
                request,
            ),
            replay_label="phase195b-admission",
        )
        return resolution, quorum, request

    def _admit_complete_sources(self):  # type: ignore[no-untyped-def]
        sources = self._publish_sources()
        command = ActionAdmissionCommand(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            proposal_product_id=self.product.product_id,
            action_type="api.request",
            action_tier=ActionTier.R2,
            idempotency_key_sha256=_canonical_sha256({"command": "phase195b-production-admit"}),
        )
        resolution, quorum, request = self._stage_admission_grants(sources, command)
        self.root.now = datetime(2026, 7, 30, 10, 13, 1, tzinfo=UTC)
        receipt = self.service.admit(command)
        return sources, command, resolution, quorum, request, receipt

    def _consume_receipt(
        self,
        receipt,
        *,
        execution_id: str = "EXE-PHASE195B",
        claim_id: str = "ACL-PHASE195B",
        consumed_at: str = "2026-07-30T10:13:02Z",
        service_time: datetime | None = None,
    ):  # type: ignore[no-untyped-def]
        execution_intent_sha256 = _canonical_sha256(
            {"execution_id": execution_id, "receipt_id": receipt.receipt_id}
        )
        claim_sha256 = _canonical_sha256(
            {
                "claim_id": claim_id,
                "execution_intent_sha256": execution_intent_sha256,
            }
        )
        self.root.now = service_time or datetime.fromisoformat(consumed_at.replace("Z", "+00:00"))
        guard = None
        try:
            with self.store._write_connection() as connection:
                guard, high_water = self.review_adapter.open_local_workspace_guard(
                    connection,
                    self.review_proof.records,
                )
                consumption = self.service._consume_for_execution_in_transaction(
                    connection,
                    receipt_id=receipt.receipt_id,
                    execution_id=execution_id,
                    execution_intent_sha256=execution_intent_sha256,
                    claim_id=claim_id,
                    claim_sha256=claim_sha256,
                    consumed_at=consumed_at,
                    workspace_connection=guard,
                    workspace_high_water=high_water,
                )
            return consumption
        finally:
            if guard is not None:
                self.review_adapter.close_local_workspace_guard(guard)

    def _revoke_with_current_control(
        self,
        resolution,
        receipt,
        *,
        revoked_at: str,
    ):  # type: ignore[no-untyped-def]
        reason_code = "operator_stop"
        intent = revocation_authorization_intent_sha256(
            receipt,
            reason_code=reason_code,
            revoked_at=revoked_at,
        )
        self._authorization(
            resolution,
            name="control",
            marker="67",
            operation=PrincipalOperation.ACTION_ADMISSION_REVOKE,
            role=AuthorizationRole.INDEPENDENT_CONTROL,
            operation_intent_sha256=intent,
            replay_label="phase195b-current-control-revocation",
            issued_at="2026-07-30T10:12:00Z",
            expires_at="2026-07-30T10:29:00Z",
        )
        self.root.now = datetime.fromisoformat(revoked_at.replace("Z", "+00:00"))
        return self.service.revoke(
            receipt.receipt_id,
            reason_code=reason_code,
            revoked_at=revoked_at,
        )

    def test_real_phase123_and_phase194_sources_are_current(self) -> None:
        self.assertIsNotNone(
            self.review_adapter.verify_current(
                self.review_proof.records,
                self.registry,
            )
        )
        self.assertEqual(self.product.product_type, "action_proposal")

    def test_complete_signed_repository_sources_publish(self) -> None:
        sources = self._publish_sources()
        self.root.now += timedelta(seconds=1)
        self.assertEqual(
            self.service.publish_authority_sources(
                self._assertion(
                    "control",
                    "51",
                    PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
                    {
                        "idempotency_key_sha256": sources["publication"].to_dict()[
                            "idempotency_key_sha256"
                        ],
                        "mission_id": self.mission_id,
                        "principal_profile_id": self.control_profile,
                        "publication_sha256": sources["publication"].publication_sha256,
                    },
                ),
                sources["publication"],
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=sources["observations"],
            ),
            sources["publication"],
        )

    def test_publication_rejects_same_role_from_unbound_trusted_issuer(self) -> None:
        sources = self._authority_sources()
        publication = sources["publication"]
        document = publication.to_dict()
        assertion = self._assertion(
            "control",
            "70",
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            {
                "idempotency_key_sha256": document["idempotency_key_sha256"],
                "mission_id": self.mission_id,
                "principal_profile_id": self.control_profile,
                "publication_sha256": publication.publication_sha256,
            },
        )
        alternate = self._alternate_issuer_assertion(assertion)
        self.root.now = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "Control entitlement",
        ):
            self.service.publish_authority_sources(
                alternate,
                publication,
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=sources["observations"],
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM action_authority_publications").fetchone()[
                    0
                ],
                0,
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                    (alternate.issuer, alternate.assertion_id),
                ).fetchone()
            )
        self.assertEqual(self._publish_sources()["publication"], publication)

    def test_store_verification_rejects_historical_unassigned_publisher(self) -> None:
        sources = self._authority_sources()
        publication = sources["publication"]
        document = publication.to_dict()
        alternate = self._alternate_issuer_assertion(
            self._assertion(
                "control",
                "77",
                PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
                {
                    "idempotency_key_sha256": document["idempotency_key_sha256"],
                    "mission_id": self.mission_id,
                    "principal_profile_id": self.control_profile,
                    "publication_sha256": publication.publication_sha256,
                },
            )
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        with (
            patch.object(
                self.service._principal_custody,
                "_require_role_entitlement",
                return_value=None,
            ),
            patch(
                "sunderkey.mission_store_action_admission.verify_action_authority_repository",
                return_value=None,
            ),
        ):
            self.service.publish_authority_sources(
                alternate,
                publication,
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=sources["observations"],
            )
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "publication assertion binding",
        ):
            self.store.verify_mission(self.registry, self.mission_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "publication assertion binding",
        ):
            self.store.verify_store(self.registry)

    def test_publication_rejects_expired_observation(self) -> None:
        sources = self._authority_sources()
        observations = list(sources["observations"])
        stale = observations[0].to_dict()
        observations[0] = build_action_authority_observation(
            observation_kind=stale["observation_kind"],
            tenant_id=stale["tenant_id"],
            mission_id=stale["mission_id"],
            plan_id=stale["plan_id"],
            payload=stale["payload"],
            observed_at="2026-07-30T10:12:58Z",
            valid_until="2026-07-30T10:12:59Z",
        )
        with self.assertRaisesRegex(StoreIntegrityError, "stale observation"):
            build_authenticated_action_authority_publication(
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=tuple(observations),
                idempotency_key_sha256=_canonical_sha256(
                    {"idempotency": "phase195b-stale-publication"}
                ),
                published_at="2026-07-30T10:13:00Z",
            )

    def test_publication_rejects_bundle_outliving_execution_session(self) -> None:
        sources = self._authority_sources(
            valid_until="2026-07-30T10:30:01Z",
            source_expires_at="2026-07-30T10:40:00Z",
        )
        publication = sources["publication"]
        document = publication.to_dict()
        assertion = self._assertion(
            "control",
            "76",
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            {
                "idempotency_key_sha256": document["idempotency_key_sha256"],
                "mission_id": self.mission_id,
                "principal_profile_id": self.control_profile,
                "publication_sha256": publication.publication_sha256,
            },
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "not current MissionStore state",
        ):
            self.service.publish_authority_sources(
                assertion,
                publication,
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=sources["observations"],
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM action_authority_publications").fetchone()[
                    0
                ],
                0,
            )

    def test_complete_signed_repository_sources_admit_and_exact_replay(self) -> None:
        _, command, resolution, quorum, request, receipt = self._admit_complete_sources()
        self.assertEqual(receipt.to_dict()["resolution_id"], resolution.resolution_id)
        self.assertEqual(receipt.to_dict()["quorum_id"], quorum.quorum_id)
        self.assertEqual(receipt.to_dict()["request_id"], request.request_id)
        self.root.now += timedelta(seconds=1)
        self.assertEqual(self.service.admit(command), receipt)
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_authority_grant_submissions WHERE mission_id = ?",
                    (self.mission_id,),
                ).fetchone()[0],
                3,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_budget_account_events "
                    "WHERE receipt_id = ? AND event_kind = 'reserve'",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                1,
            )

    def test_verify_current_rejects_caller_selected_time(self) -> None:
        *_, receipt = self._admit_complete_sources()
        cases = (
            (
                datetime(2026, 7, 30, 10, 21, tzinfo=UTC),
                "2026-07-30T10:14:00Z",
            ),
            (
                datetime(2026, 7, 30, 10, 14, tzinfo=UTC),
                "2026-07-30T10:19:00Z",
            ),
        )
        for service_time, supplied_time in cases:
            with self.subTest(supplied_time=supplied_time):
                self.root.now = service_time
                with self.assertRaisesRegex(
                    ActionResolutionError,
                    "verification time differs from service clock",
                ):
                    self.service.verify_current(
                        receipt.receipt_id,
                        evaluated_at=supplied_time,
                    )

    def test_mission_owner_rejects_unbound_issuer_at_admission_atomically(
        self,
    ) -> None:
        sources = self._publish_sources()
        command = ActionAdmissionCommand(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            proposal_product_id=self.product.product_id,
            action_type="api.request",
            action_tier=ActionTier.R2,
            idempotency_key_sha256=_canonical_sha256({"command": "phase195b-issuer-binding"}),
        )
        _resolution, _quorum, _request = self._stage_admission_grants(
            sources,
            command,
            owner_alternate_issuer=True,
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, 1, tzinfo=UTC)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "role entitlement",
        ):
            self.service.admit(command)
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM action_admission_receipts").fetchone()[0],
                0,
            )

    def test_store_verification_rejects_historical_unassigned_owner(self) -> None:
        sources = self._publish_sources()
        command = ActionAdmissionCommand(
            tenant_id=TENANT_ID,
            mission_id=self.mission_id,
            proposal_product_id=self.product.product_id,
            action_type="api.request",
            action_tier=ActionTier.R2,
            idempotency_key_sha256=_canonical_sha256({"command": "phase195b-historical-owner"}),
        )
        self._stage_admission_grants(
            sources,
            command,
            owner_alternate_issuer=True,
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, 1, tzinfo=UTC)
        with (
            patch.object(
                self.service._principal_custody,
                "_require_role_entitlement",
                return_value=None,
            ),
            patch(
                "sunderkey.mission_store_action_admission._verify_historical_admission_roles",
                return_value=None,
            ),
        ):
            self.service.admit(command)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "mission owner principal assignment",
        ):
            self.store.verify_mission(self.registry, self.mission_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "mission owner principal assignment",
        ):
            self.store.verify_store(self.registry)

    def test_revocation_rejects_unbound_issuer_atomically(self) -> None:
        self._install_fresh_current_control()
        _sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        revoked_at = "2026-07-30T10:14:00Z"
        intent = revocation_authorization_intent_sha256(
            receipt,
            reason_code="operator_stop",
            revoked_at=revoked_at,
        )
        alternate = self._authorization(
            resolution,
            name="control",
            marker="73",
            operation=PrincipalOperation.ACTION_ADMISSION_REVOKE,
            role=AuthorizationRole.INDEPENDENT_CONTROL,
            operation_intent_sha256=intent,
            replay_label="phase195b-alternate-revocation-control",
            alternate_issuer=True,
        )
        self.root.now = datetime(2026, 7, 30, 10, 14, tzinfo=UTC)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "Control entitlement",
        ):
            self.service.revoke(
                receipt.receipt_id,
                reason_code="operator_stop",
                revoked_at=revoked_at,
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_revocations WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM principal_assertion_uses WHERE issuer = ? AND assertion_id = ?",
                    (alternate["assertion_issuer"], alternate["assertion_id"]),
                ).fetchone()
            )

    def test_store_verification_rejects_historical_unassigned_revoker(self) -> None:
        self._install_fresh_current_control()
        _sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        revoked_at = "2026-07-30T10:14:00Z"
        intent = revocation_authorization_intent_sha256(
            receipt,
            reason_code="operator_stop",
            revoked_at=revoked_at,
        )
        self._authorization(
            resolution,
            name="control",
            marker="78",
            operation=PrincipalOperation.ACTION_ADMISSION_REVOKE,
            role=AuthorizationRole.INDEPENDENT_CONTROL,
            operation_intent_sha256=intent,
            replay_label="phase195b-historical-revoker",
            alternate_issuer=True,
        )
        self.root.now = datetime(2026, 7, 30, 10, 14, tzinfo=UTC)
        with (
            patch.object(
                self.service._principal_custody,
                "_require_role_entitlement",
                return_value=None,
            ),
            patch.object(
                MissionStoreAuthenticatedActionAdmissionService,
                "_verify_revocation_link",
                return_value=None,
            ),
        ):
            self.service.revoke(
                receipt.receipt_id,
                reason_code="operator_stop",
                revoked_at=revoked_at,
            )
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "revocation differs",
        ):
            self.store.verify_mission(self.registry, self.mission_id)
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "revocation differs",
        ):
            self.store.verify_store(self.registry)

    def test_execution_consumption_requires_atomic_schema34_claim(self) -> None:
        *_, receipt = self._admit_complete_sources()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "orphaned custody",
        ):
            self._consume_receipt(receipt)
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )

    def test_execution_consumption_rejects_caller_selected_time(self) -> None:
        *_, receipt = self._admit_complete_sources()
        cases = (
            (
                datetime(2026, 7, 30, 10, 14, tzinfo=UTC),
                "2026-07-30T10:13:02Z",
            ),
            (
                datetime(2026, 7, 30, 10, 14, tzinfo=UTC),
                "2026-07-30T10:19:00Z",
            ),
        )
        for service_time, supplied_time in cases:
            with (
                self.subTest(supplied_time=supplied_time),
                self.assertRaisesRegex(
                    ActionResolutionError,
                    "consumption time differs from service clock",
                ),
            ):
                self._consume_receipt(
                    receipt,
                    consumed_at=supplied_time,
                    service_time=service_time,
                )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )

    def test_execution_consumption_rejects_nonowned_connections(self) -> None:
        *_, receipt = self._admit_complete_sources()
        self.root.now = datetime(2026, 7, 30, 10, 13, 2, tzinfo=UTC)
        connection = self.store._open_existing_connection()
        connection.execute("BEGIN IMMEDIATE")
        unrelated = SQLiteExpertWorkspaceStore(self.root.directory / "unrelated-workspace.sqlite3")
        unrelated.initialize()
        wrong_guard = unrelated._connect()
        wrong_guard.execute("BEGIN")
        try:
            with self.assertRaisesRegex(StoreError, "owned MissionStore and workspace"):
                self.service._consume_for_execution_in_transaction(
                    connection,
                    receipt_id=receipt.receipt_id,
                    execution_id="EXE-PHASE195B",
                    execution_intent_sha256=_canonical_sha256({"execution": "phase195b"}),
                    claim_id="ACL-PHASE195B",
                    claim_sha256=_canonical_sha256({"claim": "phase195b"}),
                    consumed_at="2026-07-30T10:13:02Z",
                    workspace_connection=wrong_guard,
                    workspace_high_water={},
                )
        finally:
            wrong_guard.rollback()
            wrong_guard.close()
            connection.rollback()
            connection.close()
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )

    def test_budget_settlement_rejects_caller_supplied_dispatch_lineage(self) -> None:
        sources, *_, receipt = self._admit_complete_sources()
        with (
            self.store._write_connection() as connection,
            self.assertRaisesRegex(
                StoreIntegrityError,
                "durable authenticated dispatch custody",
            ),
        ):
            self.service._settle_budget_in_transaction(
                connection,
                receipt_id=receipt.receipt_id,
                charged_resources={field: 0 for field in RESOURCE_FIELDS},
                execution_id="EXE-SUBSTITUTED",
                claim_id="ACL-PHASE195B",
                dispatch_id="DSP-PHASE195B",
                recorded_at="2026-07-30T10:13:04Z",
            )
        with (
            self.store._write_connection() as connection,
            self.assertRaisesRegex(
                StoreIntegrityError,
                "durable authenticated dispatch custody",
            ),
        ):
            self.service._release_budget_in_transaction(
                connection,
                receipt_id=receipt.receipt_id,
                execution_id="EXE-PHASE195B",
                claim_id="ACL-PHASE195B",
                recorded_at="2026-07-30T10:13:04Z",
            )
        with self.store._read_connection() as connection:
            _account, _revision, usage = _current_budget_state(
                connection,
                tenant_id=TENANT_ID,
                mission_id=self.mission_id,
                expected_revision_sha256=sources["budget"].budget_revision_sha256,
                checked_at="2026-07-30T10:13:04Z",
            )
            self.assertEqual(
                usage,
                sources["budget"].to_dict()["per_action_ceiling"],
            )
            verify_authenticated_action_admission_store(
                connection,
                mission_id=self.mission_id,
            )

    def test_budget_terminal_primitive_rejects_nonrevocation_callers(self) -> None:
        _sources, *_, receipt = self._admit_complete_sources()
        for release_only in (False, True):
            with (
                self.store._write_connection() as connection,
                self.assertRaisesRegex(
                    StoreIntegrityError,
                    "durable authenticated dispatch custody",
                ),
            ):
                self.service._append_budget_terminal_events(
                    connection,
                    receipt_id=receipt.receipt_id,
                    charged_resources=(
                        None if release_only else {field: 0 for field in RESOURCE_FIELDS}
                    ),
                    execution_id="EXE-PHASE195B",
                    claim_id="ACL-PHASE195B",
                    dispatch_id=None if release_only else "DSP-FABRICATED",
                    recorded_at="2026-07-30T10:13:04Z",
                    release_only=release_only,
                )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_budget_account_events "
                    "WHERE receipt_id = ? AND event_kind != 'reserve'",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )

        foreign = sqlite3.connect(self.root.directory / "foreign-budget.sqlite3")
        foreign.execute("BEGIN")
        try:
            with self.assertRaisesRegex(StoreError, "owned MissionStore"):
                self.service._append_budget_terminal_events(
                    foreign,
                    receipt_id=receipt.receipt_id,
                    charged_resources=None,
                    execution_id="EXE-PHASE195B",
                    claim_id="ACL-PHASE195B",
                    dispatch_id=None,
                    recorded_at="2026-07-30T10:13:04Z",
                    release_only=True,
                )
        finally:
            foreign.rollback()
            foreign.close()

    def test_currentness_mode_requires_exact_bool(self) -> None:
        self._publish_sources()
        with self.store._read_connection() as connection:
            with self.assertRaisesRegex(TypeError, "must be a bool"):
                verify_action_authority_repository(
                    connection,
                    mission_id=self.mission_id,
                    require_current_sources=0,  # type: ignore[arg-type]
                )
            with self.assertRaisesRegex(TypeError, "must be a bool"):
                self.store._verify_connection(
                    connection,
                    self.registry,
                    schema_version=33,
                    require_current_action_sources=None,  # type: ignore[arg-type]
                )

    def test_new_revocation_rejects_backdated_and_future_times(self) -> None:
        *_, receipt = self._admit_complete_sources()
        self.root.now = datetime(2026, 7, 30, 10, 14, tzinfo=UTC)
        for revoked_at in (
            "2026-07-30T10:13:05Z",
            "2026-07-30T10:15:00Z",
        ):
            with self.assertRaisesRegex(
                ActionResolutionError,
                "differs from transaction time",
            ):
                self.service.revoke(
                    receipt.receipt_id,
                    reason_code="operator_stop",
                    revoked_at=revoked_at,
                )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM action_admission_revocations").fetchone()[
                    0
                ],
                0,
            )

    def test_fresh_current_control_revokes_after_action_policy_and_budget_expire(
        self,
    ) -> None:
        self._install_fresh_current_control()
        sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        revoked_at = "2026-07-30T10:26:00Z"
        self.assertLess(sources["policy"].to_dict()["expires_at"], revoked_at)
        self.assertLess(sources["budget"].to_dict()["expires_at"], revoked_at)
        self.assertLess(
            sources["source_bundle"].to_dict()["valid_until"],
            revoked_at,
        )
        self.assertTrue(
            all(
                observation.to_dict()["valid_until"] < revoked_at
                for observation in sources["observations"]
            )
        )
        revocation = self._revoke_with_current_control(
            resolution,
            receipt,
            revoked_at=revoked_at,
        )
        self.assertEqual(revocation.to_dict()["receipt_id"], receipt.receipt_id)
        with self.store._read_connection() as connection:
            release = connection.execute(
                "SELECT resources_json FROM action_budget_account_events "
                "WHERE receipt_id = ? AND event_kind = 'release'",
                (receipt.receipt_id,),
            ).fetchone()
            self.assertIsNotNone(release)
            self.assertEqual(
                json.loads(release["resources_json"]),
                sources["budget"].to_dict()["per_action_ceiling"],
            )
        self.assertEqual(
            self.service.revoke(
                receipt.receipt_id,
                reason_code="operator_stop",
                revoked_at=revoked_at,
            ),
            revocation,
        )

    def test_fresh_current_control_revokes_with_stale_health_and_observations(
        self,
    ) -> None:
        self._install_fresh_current_control()
        sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        revoked_at = "2026-07-30T10:21:00Z"
        self.assertLess(sources["health"].expires_at, revoked_at)
        self.assertTrue(
            all(
                observation.to_dict()["valid_until"] < revoked_at
                for observation in sources["observations"]
            )
        )
        self.assertGreater(
            sources["policy"].to_dict()["expires_at"],
            revoked_at,
        )
        revocation = self._revoke_with_current_control(
            resolution,
            receipt,
            revoked_at=revoked_at,
        )
        self.assertEqual(revocation.to_dict()["receipt_id"], receipt.receipt_id)

    def test_revocation_does_not_load_positive_source_publication(self) -> None:
        self._install_fresh_current_control()
        _sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        with patch(
            "sunderkey.mission_store_action_admission.load_current_action_source_bundle",
            side_effect=AssertionError("positive source publication was loaded"),
        ):
            revocation = self._revoke_with_current_control(
                resolution,
                receipt,
                revoked_at="2026-07-30T10:14:00Z",
            )
        self.assertEqual(revocation.to_dict()["receipt_id"], receipt.receipt_id)

    def test_fresh_current_control_revokes_after_session_and_plan_rotation(
        self,
    ) -> None:
        self._install_fresh_current_control()
        _sources, _command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        replacement = self._terminate_session_and_replace_plan()
        with self.store._read_connection() as connection:
            active = connection.execute(
                "SELECT active_plan_id FROM collaboration_plan_active_heads WHERE mission_id = ?",
                (self.mission_id,),
            ).fetchone()
        self.assertEqual(active["active_plan_id"], replacement.plan_id)
        revocation = self._revoke_with_current_control(
            resolution,
            receipt,
            revoked_at="2026-07-30T10:15:00Z",
        )
        self.assertEqual(revocation.to_dict()["receipt_id"], receipt.receipt_id)
        self.assertEqual(
            self.store.verify_mission(self.registry, self.mission_id).status,
            "valid",
        )
        self.assertEqual(self.store.verify_store(self.registry).status, "valid")

    def test_positive_use_paths_fail_closed_after_plan_rotation(self) -> None:
        self._install_fresh_current_control()
        sources, command, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        self._terminate_session_and_replace_plan()
        with (
            self.store._read_connection() as connection,
            self.assertRaisesRegex(StoreIntegrityError, "current"),
        ):
            load_current_action_source_bundle(
                connection,
                self.mission_id,
                "2026-07-30T10:15:00Z",
            )
        with self.assertRaises(
            (
                ActionResolutionError,
                PrincipalAuthenticationError,
                StoreConflictError,
                StoreIntegrityError,
            )
        ):
            self.service.admit(command)
        with self.assertRaises(
            (
                ActionResolutionError,
                PrincipalAuthenticationError,
                StoreConflictError,
                StoreIntegrityError,
            )
        ):
            self._consume_receipt(
                receipt,
                consumed_at="2026-07-30T10:15:00Z",
            )
        with self.assertRaises(
            (
                ActionResolutionError,
                PrincipalAuthenticationError,
                StoreConflictError,
                StoreIntegrityError,
            )
        ):
            self._authorization(
                resolution,
                name="resolver",
                marker="69",
                operation=PrincipalOperation.ACTION_RESOLVE,
                role=AuthorizationRole.TYPED_RESOLVER,
                operation_intent_sha256=resolution_authorization_intent_sha256(resolution),
                replay_label="phase195b-stale-plan-positive-grant",
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_authority_grant_submissions "
                    "WHERE assertion_id = ?",
                    ("PAS-" + "69" * 16,),
                ).fetchone()[0],
                0,
            )
        publication = sources["publication"]
        publication_document = publication.to_dict()
        publication_assertion = self._assertion(
            "control",
            "51",
            PrincipalOperation.ACTION_AUTHORITY_PUBLISH,
            {
                "idempotency_key_sha256": publication_document["idempotency_key_sha256"],
                "mission_id": self.mission_id,
                "principal_profile_id": self.control_profile,
                "publication_sha256": publication.publication_sha256,
            },
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, tzinfo=UTC)
        with self.assertRaises(
            (
                ActionResolutionError,
                PrincipalAuthenticationError,
                StoreConflictError,
                StoreIntegrityError,
            )
        ):
            self.service.publish_authority_sources(
                publication_assertion,
                publication,
                policy=sources["policy"],
                catalog=sources["catalog"],
                target=sources["target"],
                budget=sources["budget"],
                safety=sources["safety"],
                proposal=sources["proposal"],
                source_bundle=sources["source_bundle"],
                material=sources["material"],
                observations=sources["observations"],
            )

    def test_terminal_budget_primitive_stays_closed_after_plan_rotation(self) -> None:
        self._install_fresh_current_control()
        _sources, _command, _resolution, _quorum, _request, receipt = self._admit_complete_sources()
        self._terminate_session_and_replace_plan()
        with (
            self.store._write_connection() as connection,
            self.assertRaisesRegex(
                StoreIntegrityError,
                "durable authenticated dispatch custody",
            ),
        ):
            self.service._settle_budget_in_transaction(
                connection,
                receipt_id=receipt.receipt_id,
                charged_resources={field: 0 for field in RESOURCE_FIELDS},
                execution_id="EXE-PHASE195B-FABRICATED",
                claim_id="ACL-PHASE195B-FABRICATED",
                dispatch_id="DSP-PHASE195B-FABRICATED",
                recorded_at="2026-07-30T10:26:00Z",
            )
        self.assertEqual(
            self.store.verify_mission(self.registry, self.mission_id).status,
            "valid",
        )

    def test_revocation_rejects_nonindependent_current_control_atomically(self) -> None:
        *_, resolution, _quorum, _request, receipt = self._admit_complete_sources()
        revoked_at = "2026-07-30T10:13:05Z"
        reason_code = "operator_stop"
        intent = revocation_authorization_intent_sha256(
            receipt,
            reason_code=reason_code,
            revoked_at=revoked_at,
        )
        self._authorization(
            resolution,
            name="control",
            marker="55",
            operation=PrincipalOperation.ACTION_ADMISSION_REVOKE,
            role=AuthorizationRole.INDEPENDENT_CONTROL,
            operation_intent_sha256=intent,
            replay_label="phase195b-revocation",
        )
        self.root.now = datetime(2026, 7, 30, 10, 13, 5, tzinfo=UTC)
        with self.assertRaisesRegex(ActionResolutionError, "reuse principal_subject"):
            self.service.revoke(
                receipt.receipt_id,
                reason_code=reason_code,
                revoked_at=revoked_at,
            )
        restarted = MissionStoreAuthenticatedActionAdmissionService(
            self.store,
            self.review_adapter,
            self.registry,
            health_gate=self.health_gate,
            clock=self.health_custody_clock,
        )
        restarted.initialize()
        with self.assertRaisesRegex(
            StoreIntegrityError,
            "orphaned custody",
        ):
            self._consume_receipt(
                receipt,
                consumed_at="2026-07-30T10:13:04Z",
            )
        with self.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_revocations WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_admission_execution_consumptions "
                    "WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                0,
            )
            verify_authenticated_action_admission_store(
                connection,
                mission_id=self.mission_id,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM action_budget_receipt_reservations WHERE receipt_id = ?",
                    (receipt.receipt_id,),
                ).fetchone()[0],
                1,
            )

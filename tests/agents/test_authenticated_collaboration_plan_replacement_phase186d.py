"""Phase186D atomic signed-principal plan replacement coverage."""

from __future__ import annotations

import atexit
import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from scripts.build_collaboration_plan_replacement_authority_plan import (
    ASSURANCE_ID,
    CANCELLED_SPECIALIST_ID,
    CONTROL_ID,
    NEW_SPECIALIST_ID,
    READINESS_ID,
    SPECIALIST_ID,
    _canonical_sha256,
    _mapping,
    _plan,
)
from sunderkey.authenticated_collaboration import (
    AuthenticatedCollaborationActivationService,
)
from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.authenticated_collaboration_plan_replacement import (
    AuthenticatedCollaborationPlanReplacementStoreService,
)
from sunderkey.authenticated_events import (
    AuthenticatedEventAppendService,
    compute_event_batch_hash,
)
from sunderkey.collaboration import build_collaboration_plan
from sunderkey.collaboration_mission_policy import (
    build_collaboration_mission_reconfiguration_policy,
    collaboration_mission_reconfiguration_selection_sha256,
)
from sunderkey.collaboration_plan_replacement_authentication import (
    CollaborationPlanReplacementAuthorityCredential,
    authenticate_collaboration_plan_replacement_authority,
    collaboration_plan_replacement_authority_replay_keys,
)
from sunderkey.collaboration_plan_replacement_authority import (
    build_collaboration_plan_replacement_authority_plan,
    verify_collaboration_plan_replacement_authority_plan_offline,
)
from sunderkey.collaboration_plan_replacement_authority_upgrade import (
    build_collaboration_plan_replacement_authority_upgrade,
)
from sunderkey.collaboration_plan_replacement_preflight import (
    PREFLIGHT_DOMAIN,
    CollaborationPlanReplacementPreflight,
    build_collaboration_plan_replacement_preflight,
)
from sunderkey.collaboration_plan_replacement_store import (
    CollaborationPlanReplacementStoreService,
    build_collaboration_plan_replacement_source_snapshots,
)
from sunderkey.collaboration_reconfiguration_policy import (
    load_collaboration_reconfiguration_authority_policy,
)
from sunderkey.errors import (
    PrincipalAuthenticationError,
    StoreError,
    StoreIntegrityError,
)
from sunderkey.events import MissionEvent
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    compute_operation_intent_hash,
    verify_trust_policy,
)
from sunderkey.mission import MissionRequest
from sunderkey.plan_replacement_reviewer_admission import (
    AuthenticatedPlanReplacementReviewerAdmissionService,
    reviewer_admission_operation_intent,
)
from sunderkey.registry import load_registry
from sunderkey.scope import ScopeGrantAcceptanceService
from sunderkey.store import MissionStore, canonical_json, sha256_text
from sunderkey.trust import TrustProvisioningService

from . import test_collaboration_plan_replacement_store_phase186 as legacy_fixture
from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SUBJECT,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import observation_data

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v2.json"
AUTHORITY_PATH = ROOT / "registry" / "collaboration-reconfiguration-policy-d001-d005.json"
MISSION_ID = "EXAMPLE-API-DATA-001"
SCOPE_REFERENCE = "scope://example/internet-api-to-data"
SCOPE_DOCUMENT_HASH = "sha256:" + "d" * 64
POLICY_VERSION = 186
NOW = datetime(2026, 7, 30, 10, 10, tzinfo=UTC)
REPLACEMENT_AUTHORITY_OPERATIONS = (
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE,
    PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE,
)
REVIEWER_ROLE_OPERATIONS = {
    "independent_control": PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE,
    "independent_assurance": PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE,
    "second_control": PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE,
}


class AuthenticatedPlanReplacementFixture:
    _baseline_fixture: AuthenticatedPlanReplacementFixture | None = None
    _baseline_case: unittest.TestCase | None = None

    @classmethod
    def _baseline(cls) -> AuthenticatedPlanReplacementFixture:
        if cls._baseline_fixture is None:
            case = unittest.TestCase()
            baseline = cls(case, _fresh=True)
            cls._baseline_case = case
            cls._baseline_fixture = baseline
            atexit.register(case.doCleanups)
        return cls._baseline_fixture

    def __init__(
        self,
        test: unittest.TestCase,
        *,
        busy_timeout_ms: int = 5000,
        _fresh: bool = False,
    ) -> None:
        if not _fresh:
            baseline = self._baseline()
            temporary = tempfile.TemporaryDirectory()
            test.addCleanup(temporary.cleanup)
            self.path = Path(temporary.name) / "phase186d.sqlite3"
            with closing(sqlite3.connect(baseline.path)) as source:
                with closing(sqlite3.connect(self.path)) as destination:
                    source.backup(destination)
            for name, value in baseline.__dict__.items():
                if name not in {"path", "store", "acceptance"}:
                    # Verified proofs are identity-bound, so preserve their instances.
                    if name in {"baseline_counts", "reviewer_grants"}:
                        value = value.copy()
                    setattr(self, name, value)
            self.store = MissionStore(
                self.path, clock=lambda: NOW, busy_timeout_ms=busy_timeout_ms
            )
            self.acceptance = ScopeGrantAcceptanceService(self.store, self.registry)
            return
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "phase186d.sqlite3"
        self.registry = load_registry(REGISTRY_PATH)
        self.authority_policy = load_collaboration_reconfiguration_authority_policy(AUTHORITY_PATH)
        raw_mission = json.loads(
            (ROOT / "examples" / "missions" / "internet-api-to-data.json").read_text(
                encoding="utf-8"
            )
        )
        raw_mission["scope_document_hash"] = SCOPE_DOCUMENT_HASH
        raw_mission["environment"] = "production"
        raw_mission["max_action_tier"] = "R3"
        raw_mission["constraints"]["production"] = True
        raw_mission["requested_specialist_ids"] = sorted(
            [*raw_mission["requested_specialist_ids"], "AOE-GC-D11-S09"]
        )
        self.mission = MissionRequest.from_dict(raw_mission)
        template = build_collaboration_plan(self.registry, self.mission)
        self.full_plan = template
        common_changes = {
            CONTROL_ID: {"dependency_ids": [READINESS_ID], "layer": 1},
            ASSURANCE_ID: {"dependency_ids": [CONTROL_ID], "layer": 2},
        }
        self.prior = _plan(
            template,
            plan_id="CLP-" + "1" * 24,
            item_ids=(
                READINESS_ID,
                SPECIALIST_ID,
                CANCELLED_SPECIALIST_ID,
                CONTROL_ID,
                ASSURANCE_ID,
            ),
            changes=common_changes,
        )
        replacement_changes = {
            **common_changes,
            SPECIALIST_ID: {
                "command_id": "AOE-GC-D11",
                "group_id": "GC",
                "owner_profile_id": "AOE-GC-D11-S09",
                "supporting_profile_ids": [
                    "AOE-GC-D11-CMD",
                    "AOE-HQ-04",
                    "AOE-HQ-18",
                ],
            },
            NEW_SPECIALIST_ID: {"dependency_ids": [READINESS_ID], "layer": 1},
            CONTROL_ID: {
                "dependency_ids": [READINESS_ID],
                "layer": 1,
                "owner_profile_id": "AOE-HQ-09",
            },
        }
        self.replacement = _plan(
            template,
            plan_id="CLP-" + "2" * 24,
            item_ids=(
                READINESS_ID,
                SPECIALIST_ID,
                NEW_SPECIALIST_ID,
                CONTROL_ID,
                ASSURANCE_ID,
            ),
            changes=replacement_changes,
        )
        self.store = MissionStore(self.path, clock=lambda: NOW, busy_timeout_ms=busy_timeout_ms)
        self.store.initialize()
        self.stored = self.store.create_mission(self.registry, self.mission)
        self.factory = CredentialFactory()
        trust = TrustProvisioningService(self.store)
        self.store_id = trust.status().store_id
        root_public = public_bytes(self.factory.root_private)
        trust.pin_root(
            ROOT_KEY_ID,
            AUDIENCE,
            b64url(root_public),
            "sha256:" + hashlib.sha256(root_public).hexdigest(),
        )
        replacement_operations = [operation.value for operation in REPLACEMENT_AUTHORITY_OPERATIONS]
        all_operations = [
            PrincipalOperation.COLLABORATION_ACTIVATE.value,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
            PrincipalOperation.EVENT_APPEND.value,
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE.value,
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE.value,
            *replacement_operations,
        ]
        all_profiles = sorted(self.registry.profiles_by_id)
        self.policy = self.factory.policy(
            policy_version=POLICY_VERSION,
            store_id=self.store_id,
            allowed_profiles=all_profiles,
            allowed_subjects=[
                SUBJECT,
                *("principal:" + profile.lower() for profile in all_profiles),
            ],
            allowed_operations=all_operations,
        )
        trust.apply_policy(self.policy)
        self.verified_policy = verify_trust_policy(
            self.policy,
            {ROOT_KEY_ID: root_public},
            expected_audience=AUDIENCE,
            expected_store_id=self.store_id,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=POLICY_VERSION,
            clock=lambda: NOW,
        )
        self.acceptance = ScopeGrantAcceptanceService(self.store, self.registry)
        activation_grant = self._grant(
            index=0,
            profile_id="AOE-HQ-08",
            operation=PrincipalOperation.COLLABORATION_ACTIVATE,
        )
        self.acceptance.accept(activation_grant)
        activation_intent = {
            "mission_id": MISSION_ID,
            "plan_content_sha256": self.full_plan.content_sha256,
            "plan_id": self.full_plan.plan_id,
            "principal_profile_id": "AOE-HQ-08",
        }
        activation_assertion = self.factory.assertion(
            grant=activation_grant,
            assertion_id="PAS-" + "F" * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=activation_grant.grant_id,
            subject=SUBJECT,
            profile_id="AOE-HQ-08",
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.COLLABORATION_ACTIVATE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.COLLABORATION_ACTIVATE,
                activation_intent,
            ),
            issued_at="2026-07-30T10:08:00Z",
            not_before="2026-07-30T10:08:00Z",
            expires_at="2026-07-30T10:13:00Z",
        )
        AuthenticatedCollaborationActivationService(
            self.store, self.registry, clock=lambda: NOW
        ).activate(activation_assertion, self.full_plan)
        event_grant = self._grant(
            index=99,
            profile_id="AOE-HQ-08",
            operation=PrincipalOperation.EVENT_APPEND,
        )
        self.acceptance.accept(event_grant)
        raw_event = observation_data("EVT-PHASE186D-001")
        raw_event.update(
            {
                "mission_id": MISSION_ID,
                "actor_profile_id": "AOE-HQ-08",
                "timestamp": "2026-07-30T10:09:00Z",
            }
        )
        event = MissionEvent.from_dict(raw_event)
        event_intent = {
            "event_batch_sha256": compute_event_batch_hash((event,)),
            "expected_revision": 0,
            "mission_id": MISSION_ID,
            "principal_profile_id": "AOE-HQ-08",
        }
        event_assertion = self.factory.assertion(
            grant=event_grant,
            assertion_id="PAS-" + "E" * 32,
            policy_version=POLICY_VERSION,
            scope_grant_id=event_grant.grant_id,
            subject=SUBJECT,
            profile_id="AOE-HQ-08",
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            operation=PrincipalOperation.EVENT_APPEND,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EVENT_APPEND,
                event_intent,
            ),
            issued_at="2026-07-30T10:08:00Z",
            not_before="2026-07-30T10:08:00Z",
            expires_at="2026-07-30T10:13:00Z",
        )
        AuthenticatedEventAppendService(self.store, self.registry, clock=lambda: NOW).append(
            event_assertion, MISSION_ID, (event,), expected_revision=0
        )
        self._stage_subset_prior()
        self.mission_policy, self.mission_policy_commit = self._commit_mission_policy(
            plan=self.prior,
            policy_version=2,
            previous_policy_sha256=self.bootstrap_policy.policy_sha256,
            marker=220,
        )
        self.reviewer_grants = self._admit_reviewers(
            {
                "independent_control": "AOE-HQ-14",
                "independent_assurance": "AOE-HQ-18",
                "second_control": "AOE-HQ-15",
            },
            marker=2900,
        )
        self.preflight = self._preflight()
        self._prepare_authorities(marker=2000)
        with self.store._read_connection() as connection:
            self.baseline_counts = {
                table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in (
                    "collaboration_plan_replacement_authentications",
                    "collaboration_plan_replacement_authority_consumptions",
                    "collaboration_plan_replacement_commits",
                )
            }
            self.baseline_authority_uses = self.authority_use_count(connection)

    def _prepare_authorities(self, *, marker: int) -> None:
        self.authority_plan = build_collaboration_plan_replacement_authority_plan(
            preflight=self.preflight,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=REGISTRY_PATH.read_bytes(),
            issued_at="2026-07-30T10:10:00Z",
            expires_at="2026-07-30T10:25:00Z",
        )
        self.verified_authority_plan = verify_collaboration_plan_replacement_authority_plan_offline(
            self.authority_plan,
            preflight=self.preflight,
            prior_plan=self.prior,
            replacement_plan=self.replacement,
            authority_policy=self.authority_policy,
            mission_policy=self.mission_policy,
            registry=self.registry,
            registry_source=REGISTRY_PATH.read_bytes(),
            verified_at="2026-07-30T10:10:00Z",
        )
        self.upgrade = build_collaboration_plan_replacement_authority_upgrade(
            preflight=self.preflight,
            army_registry=self.registry,
        )
        replay_keys = collaboration_plan_replacement_authority_replay_keys(
            self.verified_authority_plan,
            self.upgrade,
            preflight=self.preflight,
            army_registry=self.registry,
        )
        plan_by_source = {
            item["requirement_id"]: item
            for item in self.authority_plan.to_dict()["assertion_requirements"]
        }
        credentials = []
        for index, requirement in enumerate(
            self.upgrade.to_dict()["authority_requirements"], start=1
        ):
            operation = PrincipalOperation(requirement["operation"])
            subject = "principal:" + requirement["principal_profile_id"].lower()
            grant = self.reviewer_grants.get(requirement["role"])
            if grant is None:
                grant = self._grant(
                    index=marker + index,
                    profile_id=requirement["principal_profile_id"],
                    operation=operation,
                    subject=subject,
                )
                self.acceptance.accept(grant)
            assertion = self.factory.assertion(
                grant=grant,
                assertion_id=f"PAS-{marker + index:032X}",
                policy_version=POLICY_VERSION,
                scope_grant_id=grant.grant_id,
                subject=subject,
                profile_id=requirement["principal_profile_id"],
                audience=AUDIENCE,
                store_id=self.store_id,
                mission_id=MISSION_ID,
                operation=operation,
                operation_intent_sha256=requirement["principal_operation_intent_sha256"],
                issued_at="2026-07-30T10:10:00Z",
                not_before="2026-07-30T10:10:00Z",
                expires_at="2026-07-30T10:14:00Z",
            )
            source = plan_by_source[requirement["source_requirement_id"]]
            credentials.append(
                CollaborationPlanReplacementAuthorityCredential(
                    source_requirement_id=requirement["source_requirement_id"],
                    upgraded_requirement_id=requirement["requirement_id"],
                    replay_key_sha256=replay_keys[source["requirement_id"]],
                    scope_grant=grant,
                    assertion=assertion,
                )
            )
        self.credentials = tuple(credentials)
        constraints_hash = sha256_text(canonical_json(self.mission.to_dict()["constraints"]))
        self.bundle = authenticate_collaboration_plan_replacement_authority(
            self.verified_authority_plan,
            self.upgrade,
            preflight=self.preflight,
            army_registry=self.registry,
            credentials=self.credentials,
            verified_policy=self.verified_policy,
            expected_audience=AUDIENCE,
            expected_store_id=self.store_id,
            expected_mission_context_hash=self.stored.context_hash,
            expected_scope_reference=SCOPE_REFERENCE,
            expected_scope_document_hash=SCOPE_DOCUMENT_HASH,
            expected_environment=self.mission.environment,
            expected_max_action_tier=self.mission.max_action_tier,
            expected_constraints_hash=constraints_hash,
            revoked_scope_grant_sha256s=(),
            consumed_replay_keys=(),
            clock=lambda: NOW,
        )

    def _grant(
        self,
        *,
        index: int,
        profile_id: str,
        operation: PrincipalOperation,
        subject: str = SUBJECT,
    ):
        return self.factory.grant(
            grant_id=f"SGR-{index:032X}",
            profile_id=profile_id,
            subject=subject,
            audience=AUDIENCE,
            store_id=self.store_id,
            mission_id=MISSION_ID,
            mission_context_hash=self.stored.context_hash,
            scope_reference=SCOPE_REFERENCE,
            scope_document_hash=SCOPE_DOCUMENT_HASH,
            environment=self.mission.environment.value,
            max_action_tier=self.mission.max_action_tier.value,
            constraints_hash=sha256_text(canonical_json(self.mission.to_dict()["constraints"])),
            operations=[operation.value],
            issued_at="2026-07-30T10:05:00Z",
            not_before="2026-07-30T10:05:00Z",
            expires_at="2026-07-30T10:30:00Z",
            policy_version=POLICY_VERSION,
        )

    @staticmethod
    def _approval_binding(assertion) -> dict[str, str]:
        return {
            "profile_id": assertion.profile_id,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
        }

    def _mission_policy(
        self,
        *,
        plan,
        policy_version: int,
        previous_policy_sha256: str | None,
        owner_binding: dict[str, str],
        control_binding: dict[str, str],
    ):
        return build_collaboration_mission_reconfiguration_policy(
            authority_policy=self.authority_policy,
            policy_version=policy_version,
            previous_policy_sha256=previous_policy_sha256,
            mission_id=MISSION_ID,
            collaboration_plan_id=plan.plan_id,
            collaboration_plan_sha256=plan.content_sha256,
            maximum_delegation_depth=3,
            reconfiguration_validity_seconds=3600,
            execution_ack_timeout_seconds=300,
            maximum_plan_replacement_items=100,
            transition_activation={
                "privileged_role_reassignment": False,
                "delegation_return_and_revocation": False,
                "cross_command_transfer": True,
                "activated_plan_replacement": True,
                "distributed_execution_transfer_or_cancellation": False,
            },
            mission_owner_approval=owner_binding,
            independent_control_approval=control_binding,
            effective_at="2026-07-30T10:00:00Z",
            expires_at="2026-07-30T11:00:00Z",
        )

    def _commit_mission_policy(
        self,
        *,
        plan,
        policy_version: int,
        previous_policy_sha256: str | None,
        marker: int,
    ):
        owner_grant = self._grant(
            index=marker,
            profile_id="AOE-HQ-08",
            operation=PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
        )
        control_grant = self._grant(
            index=marker + 1,
            profile_id="AOE-HQ-14",
            operation=PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
        )
        self.acceptance.accept(owner_grant)
        self.acceptance.accept(control_grant)
        provisional = self._mission_policy(
            plan=plan,
            policy_version=policy_version,
            previous_policy_sha256=previous_policy_sha256,
            owner_binding={
                "profile_id": "AOE-HQ-08",
                "assertion_id": "PAS-" + f"{marker + 100:032X}",
                "assertion_sha256": "sha256:" + "1" * 64,
            },
            control_binding={
                "profile_id": "AOE-HQ-14",
                "assertion_id": "PAS-" + f"{marker + 101:032X}",
                "assertion_sha256": "sha256:" + "2" * 64,
            },
        )
        selection_sha256 = collaboration_mission_reconfiguration_selection_sha256(provisional)

        def assertion(grant, profile_id: str, operation: PrincipalOperation, offset: int):
            intent = {
                "mission_id": MISSION_ID,
                "policy_selection_sha256": selection_sha256,
                "principal_profile_id": profile_id,
            }
            return self.factory.assertion(
                grant=grant,
                assertion_id="PAS-" + f"{marker + offset:032X}",
                policy_version=POLICY_VERSION,
                scope_grant_id=grant.grant_id,
                subject=SUBJECT,
                profile_id=profile_id,
                audience=AUDIENCE,
                store_id=self.store_id,
                mission_id=MISSION_ID,
                operation=operation,
                operation_intent_sha256=compute_operation_intent_hash(
                    operation,
                    intent,
                ),
                issued_at="2026-07-30T10:09:00Z",
                not_before="2026-07-30T10:09:00Z",
                expires_at="2026-07-30T10:14:00Z",
            )

        owner_assertion = assertion(
            owner_grant,
            "AOE-HQ-08",
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE,
            100,
        )
        control_assertion = assertion(
            control_grant,
            "AOE-HQ-14",
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE,
            101,
        )
        policy = self._mission_policy(
            plan=plan,
            policy_version=policy_version,
            previous_policy_sha256=previous_policy_sha256,
            owner_binding=self._approval_binding(owner_assertion),
            control_binding=self._approval_binding(control_assertion),
        )
        receipt = AuthenticatedCollaborationMissionPolicyService(
            self.store,
            self.registry,
            clock=lambda: NOW,
        ).commit(
            policy,
            authority_policy=self.authority_policy,
            mission_owner_assertion=owner_assertion,
            independent_control_assertion=control_assertion,
        )
        document = receipt.to_dict()
        commit = {
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "policy_selection_sha256": document["selection_sha256"],
            "authentication_id": document["authentication_id"],
            "authentication_sha256": document["authentication_sha256"],
            "committed_at": document["committed_at"],
            "mission_owner_assertion_id": document["mission_owner"]["assertion_id"],
            "mission_owner_assertion_sha256": document["mission_owner"]["assertion_sha256"],
            "mission_owner_ledger_entry_sha256": document["mission_owner"]["ledger_entry_sha256"],
            "independent_control_assertion_id": document["independent_control"]["assertion_id"],
            "independent_control_assertion_sha256": document["independent_control"][
                "assertion_sha256"
            ],
            "independent_control_ledger_entry_sha256": document["independent_control"][
                "ledger_entry_sha256"
            ],
            "commit_status": document["commit_status"],
        }
        return policy, commit

    def _stage_subset_prior(self) -> None:
        self.bootstrap_policy, policy_commit = self._commit_mission_policy(
            plan=self.full_plan,
            policy_version=1,
            previous_policy_sha256=None,
            marker=200,
        )
        reviewer_grants = self._admit_reviewers(
            {
                "independent_control": "AOE-HQ-14",
                "independent_assurance": "AOE-HQ-20",
                "second_control": "AOE-HQ-15",
            },
            marker=1900,
        )
        snapshots = build_collaboration_plan_replacement_source_snapshots(
            self.store, MISSION_ID, self.full_plan.plan_id
        )
        source_ids = {item.work_item_id for item in self.full_plan.work_items}
        generic_preflight = build_collaboration_plan_replacement_preflight(
            prior_plan=self.full_plan,
            replacement_plan=self.prior,
            mission_policy=self.bootstrap_policy,
            mission_policy_commit=policy_commit,
            source_state={
                "mission_revision": 1,
                "active_plan_id": self.full_plan.plan_id,
                "active_plan_sha256": self.full_plan.content_sha256,
                **snapshots.hashes,
                "observed_at": "2026-07-30T10:10:00Z",
            },
            mapping_inputs=[
                _mapping(item.work_item_id, item.work_item_id)
                for item in self.prior.work_items
                if item.work_item_id in source_ids
            ],
            independent_assurance_profile_id="AOE-HQ-20",
            second_control_profile_id="AOE-HQ-15",
        )
        # A separate stage context reuses the same signed credential producer,
        # without mutating the requested main replacement or weakening authority.
        stage = object.__new__(AuthenticatedPlanReplacementFixture)
        stage.__dict__ = dict(self.__dict__)
        stage.prior = self.full_plan
        stage.replacement = self.prior
        stage.mission_policy = self.bootstrap_policy
        stage.preflight = generic_preflight
        stage.reviewer_grants = reviewer_grants
        stage._prepare_authorities(marker=1000)
        self.bootstrap_requirement_count = stage.bundle.requirement_count
        self.service().replace(
            preflight=generic_preflight,
            prior_plan=self.full_plan,
            replacement_plan=self.prior,
            verified_authority_plan=stage.verified_authority_plan,
            authority_upgrade=stage.upgrade,
            authenticated_bundle=stage.bundle,
            credentials=stage.credentials,
            expected_plan_version=1,
        )

    def _admit_reviewers(self, profiles: dict[str, str], *, marker: int):
        service = AuthenticatedPlanReplacementReviewerAdmissionService(
            self.store, self.registry, clock=lambda: NOW
        )
        grants = {}
        for index, (role, profile_id) in enumerate(sorted(profiles.items())):
            subject = "principal:" + profile_id.lower()
            grant = self._grant(
                index=marker + index,
                profile_id=profile_id,
                operation=REVIEWER_ROLE_OPERATIONS[role],
                subject=subject,
            )
            approvals = {}
            for offset, (approval_role, approver_profile, operation, approver_subject) in enumerate(
                (
                    (
                        "mission_owner",
                        "AOE-HQ-08",
                        PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE,
                        SUBJECT,
                    ),
                    (
                        "independent_control",
                        "AOE-HQ-12",
                        PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE,
                        "principal:aoe-hq-12",
                    ),
                )
            ):
                approval_grant = self._grant(
                    index=100000 + marker + 10 * index + offset,
                    profile_id=approver_profile,
                    operation=operation,
                    subject=approver_subject,
                )
                self.acceptance.accept(approval_grant)
                approvals[approval_role] = (approval_grant, operation, approver_subject, offset)
            request = service.prepare(
                MISSION_ID,
                admission_id=f"RVA-{marker + index:032X}",
                reviewer_scope_grant=grant,
                reviewer_issuer="identity-provider",
                reviewer_subject=subject,
                role=role,
                issued_at="2026-07-30T10:10:00Z",
                not_before="2026-07-30T10:10:00Z",
                expires_at="2026-07-30T10:25:00Z",
            )
            assertions = {}
            for approval_role, (
                approval_grant,
                operation,
                approver_subject,
                offset,
            ) in approvals.items():
                assertions[approval_role] = self.factory.assertion(
                    grant=approval_grant,
                    assertion_id=f"PAS-{200000 + marker + 10 * index + offset:032X}",
                    policy_version=POLICY_VERSION,
                    scope_grant_id=approval_grant.grant_id,
                    subject=approver_subject,
                    profile_id=approval_grant.profile_id,
                    audience=AUDIENCE,
                    store_id=self.store_id,
                    mission_id=MISSION_ID,
                    operation=operation,
                    operation_intent_sha256=compute_operation_intent_hash(
                        operation,
                        reviewer_admission_operation_intent(
                            request,
                            principal_profile_id=approval_grant.profile_id,
                            role=approval_role,
                        ),
                    ),
                    issued_at="2026-07-30T10:10:00Z",
                    not_before="2026-07-30T10:10:00Z",
                    expires_at="2026-07-30T10:13:00Z",
                )
            service.admit(
                request,
                mission_owner_assertion=assertions["mission_owner"],
                independent_control_assertion=assertions["independent_control"],
            )
            grants[role] = grant
        return grants

    @staticmethod
    def authority_use_count(connection) -> int:
        placeholders = ", ".join("?" for _ in REPLACEMENT_AUTHORITY_OPERATIONS)
        return connection.execute(
            f"SELECT COUNT(*) FROM principal_assertion_uses WHERE operation IN ({placeholders})",
            tuple(operation.value for operation in REPLACEMENT_AUTHORITY_OPERATIONS),
        ).fetchone()[0]

    def _preflight(self):
        snapshots = build_collaboration_plan_replacement_source_snapshots(
            self.store, MISSION_ID, self.prior.plan_id
        )
        with self.store._read_connection() as connection:
            revision = int(
                connection.execute(
                    "SELECT revision FROM missions WHERE mission_id = ?",
                    (MISSION_ID,),
                ).fetchone()[0]
            )
        built = build_collaboration_plan_replacement_preflight(
            prior_plan=self.prior,
            replacement_plan=self.replacement,
            mission_policy=self.mission_policy,
            mission_policy_commit=self.mission_policy_commit,
            source_state={
                "mission_revision": max(1, revision),
                "active_plan_id": self.prior.plan_id,
                "active_plan_sha256": self.prior.content_sha256,
                **snapshots.hashes,
                "observed_at": "2026-07-30T10:10:00Z",
            },
            mapping_inputs=[
                _mapping(READINESS_ID, READINESS_ID),
                _mapping(SPECIALIST_ID, SPECIALIST_ID, cross_command=True),
                _mapping(CONTROL_ID, CONTROL_ID),
                _mapping(ASSURANCE_ID, ASSURANCE_ID),
            ],
            independent_assurance_profile_id="AOE-HQ-18",
            second_control_profile_id="AOE-HQ-15",
        )
        if revision:
            return built
        document = built.to_dict()
        body = {
            key: value
            for key, value in document.items()
            if key not in {"preflight_id", "preflight_sha256"}
        }
        body["source_state"]["mission_revision"] = 0
        digest = _canonical_sha256({"domain": PREFLIGHT_DOMAIN, "preflight": body})
        return CollaborationPlanReplacementPreflight.from_dict(
            {
                **body,
                "preflight_id": "PRF-" + digest.removeprefix("sha256:")[:32].upper(),
                "preflight_sha256": digest,
            }
        )

    def service(self, *, now: datetime = NOW):
        return AuthenticatedCollaborationPlanReplacementStoreService(
            self.store,
            self.registry,
            clock=lambda: now,
        )

    def replace(self, *, service=None, credentials=None):
        return (service or self.service()).replace(
            preflight=self.preflight,
            prior_plan=self.prior,
            replacement_plan=self.replacement,
            verified_authority_plan=self.verified_authority_plan,
            authority_upgrade=self.upgrade,
            authenticated_bundle=self.bundle,
            credentials=credentials or self.credentials,
            expected_plan_version=2,
        )


class AuthenticatedCollaborationPlanReplacementPhase186DTests(unittest.TestCase):
    def test_reused_seed_keeps_each_test_store_independent(self) -> None:
        first = AuthenticatedPlanReplacementFixture(self)
        second = AuthenticatedPlanReplacementFixture(self)
        self.assertNotEqual(first.path, second.path)
        self.assertIsNot(first.store, second.store)
        with closing(sqlite3.connect(first.path)) as connection:
            connection.execute("CREATE TABLE fixture_isolation_probe (value INTEGER)")
        with closing(sqlite3.connect(second.path)) as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT name FROM sqlite_master WHERE name = 'fixture_isolation_probe'"
                ).fetchone()
            )

    def test_signed_bootstrap_and_policy_history_are_source_bound(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        self.assertEqual(fixture.bootstrap_requirement_count, 25)
        self.assertEqual(len(fixture.credentials), 16)
        self.assertEqual(fixture.mission_policy.to_dict()["policy_version"], 2)
        self.assertEqual(
            fixture.mission_policy.to_dict()["previous_policy_sha256"],
            fixture.bootstrap_policy.policy_sha256,
        )
        with fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT requirement_count FROM collaboration_plan_replacement_authentications"
                ).fetchone()[0],
                fixture.bootstrap_requirement_count,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM plan_replacement_reviewer_admissions"
                ).fetchone()[0],
                6,
            )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_replay_preserves_historical_assertion_expiry_but_requires_current_admission(
        self,
    ) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        receipt = fixture.replace()
        # Main approval assertions expired at 10:14; signed review admission and
        # scope remain active, and replay does not consume these assertions again.
        replay = fixture.replace(
            service=fixture.service(now=datetime(2026, 7, 30, 10, 15, tzinfo=UTC))
        )
        self.assertEqual(replay, receipt)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "not currently active"):
            fixture.replace(service=fixture.service(now=datetime(2026, 7, 30, 10, 26, tzinfo=UTC)))
        with self.assertRaises(PrincipalAuthenticationError):
            fixture.replace(service=fixture.service(now=datetime(2026, 7, 30, 10, 31, tzinfo=UTC)))
        with fixture.store._read_connection() as connection:
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses + len(fixture.credentials),
            )
        historical = CollaborationPlanReplacementStoreService(
            fixture.store,
            fixture.registry,
            mock.Mock(),
            clock=lambda: datetime(2026, 7, 30, 10, 31, tzinfo=UTC),
        )
        self.assertEqual(historical.get(MISSION_ID), receipt)
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_replay_rejects_revoked_exact_principal_key_while_scope_key_is_active(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        fixture.replace()
        raw = fixture.policy.to_dict()
        raw["policy_version"] = POLICY_VERSION + 1
        raw["keys"][0]["state"] = "revoked"
        self.assertEqual(raw["keys"][1]["state"], "active")
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        newer = replace(
            unsigned, signature=b64url(fixture.factory.root_private.sign(unsigned.signing_bytes()))
        )
        now = datetime(2026, 7, 30, 10, 11, tzinfo=UTC)
        fixture.store._clock = lambda: now
        TrustProvisioningService(fixture.store).apply_policy(newer)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            fixture.replace(service=fixture.service(now=now))
        with fixture.store._read_connection() as connection:
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses + len(fixture.credentials),
            )

    def test_commit_consumes_all_signed_authorities_and_exact_replay_is_read_only(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        receipt = fixture.replace()
        replay = fixture.replace(service=fixture.service())
        self.assertEqual(replay.to_dict(), receipt.to_dict())
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authority_consumptions"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_authority_consumptions"]
                + len(fixture.credentials),
            )
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses + len(fixture.credentials),
            )
        reopened = MissionStore(fixture.path, clock=lambda: NOW)
        self.assertEqual(reopened.verify_store(fixture.registry).status, "valid")
        restarted_replay = AuthenticatedCollaborationPlanReplacementStoreService(
            reopened,
            fixture.registry,
            clock=lambda: NOW,
        ).replace(
            preflight=fixture.preflight,
            prior_plan=fixture.prior,
            replacement_plan=fixture.replacement,
            verified_authority_plan=fixture.verified_authority_plan,
            authority_upgrade=fixture.upgrade,
            authenticated_bundle=fixture.bundle,
            credentials=fixture.credentials,
            expected_plan_version=2,
        )
        self.assertEqual(restarted_replay.to_dict(), receipt.to_dict())

    def test_concurrent_exact_retry_converges_without_double_consumption(self) -> None:
        # This checks convergence, not a five-second latency guarantee. Use the
        # existing bounded store setting to allow the first signed transaction
        # to finish on slower runners; product defaults remain unchanged.
        fixture = AuthenticatedPlanReplacementFixture(self, busy_timeout_ms=120000)
        with ThreadPoolExecutor(max_workers=2) as executor:
            receipts = tuple(
                executor.map(
                    lambda _index: fixture.replace(service=fixture.service()),
                    range(2),
                )
            )
        self.assertEqual(receipts[0].to_dict(), receipts[1].to_dict())
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authority_consumptions"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_authority_consumptions"]
                + len(fixture.credentials),
            )

    def test_busy_writer_fails_without_mutation_then_explicit_retry_converges(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        bounded_store = MissionStore(fixture.path, clock=lambda: NOW, busy_timeout_ms=1)
        bounded_service = AuthenticatedCollaborationPlanReplacementStoreService(
            bounded_store, fixture.registry, clock=lambda: NOW
        )
        with closing(sqlite3.connect(fixture.path)) as connection:
            before = tuple(connection.iterdump())
            connection.execute("BEGIN IMMEDIATE")
            try:
                with (
                    mock.patch.object(
                        CollaborationPlanReplacementStoreService,
                        "_require_replacement_transaction",
                    ) as transaction_check,
                    mock.patch.object(
                        CollaborationPlanReplacementStoreService, "_insert_commit_graph"
                    ) as graph_insert,
                    self.assertRaises(StoreError) as caught,
                ):
                    fixture.replace(service=bounded_service)
                self.assertIsInstance(caught.exception.__cause__, sqlite3.OperationalError)
                self.assertEqual(caught.exception.__cause__.sqlite_errorcode, sqlite3.SQLITE_BUSY)
                # The unmodified sealed verifier is reachable only after this
                # transaction check; no authority work can start without it.
                transaction_check.assert_not_called()
                graph_insert.assert_not_called()
                self.assertEqual(tuple(connection.iterdump()), before)
            finally:
                connection.rollback()
        # This is an explicit operator retry after the blocker is released, not
        # an automatic retry. Each call constructs a fresh transaction verifier.
        receipt = fixture.replace(service=fixture.service())
        replay = fixture.replace(service=fixture.service())
        self.assertEqual(replay.to_dict(), receipt.to_dict())
        with fixture.store._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authority_consumptions"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_authority_consumptions"]
                + len(fixture.credentials),
            )
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses + len(fixture.credentials),
            )
        self.assertEqual(fixture.store.verify_store(fixture.registry).status, "valid")

    def test_bundle_credential_substitution_fails_without_partial_consumption(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        changed = list(fixture.credentials)
        first, second = changed[0], changed[1]
        changed[0] = replace(first, assertion=second.assertion)
        changed[1] = replace(second, assertion=first.assertion)
        with self.assertRaises(PrincipalAuthenticationError):
            fixture.replace(credentials=changed)
        with closing(sqlite3.connect(fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_authentications"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_authentications"],
            )
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses,
            )

    def test_failure_after_consumption_rolls_back_every_authority(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        with (
            mock.patch.object(
                CollaborationPlanReplacementStoreService,
                "_insert_commit_graph",
                side_effect=RuntimeError("forced rollback"),
            ),
            self.assertRaisesRegex(RuntimeError, "forced rollback"),
        ):
            fixture.replace()
        with closing(sqlite3.connect(fixture.path)) as connection:
            for table in (
                "collaboration_plan_replacement_authentications",
                "collaboration_plan_replacement_authority_consumptions",
            ):
                self.assertEqual(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    fixture.baseline_counts[table],
                )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM collaboration_plan_replacement_commits"
                ).fetchone()[0],
                fixture.baseline_counts["collaboration_plan_replacement_commits"],
            )
            self.assertEqual(
                fixture.authority_use_count(connection),
                fixture.baseline_authority_uses,
            )

    def test_clock_rollback_and_current_trust_drift_fail_closed(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        rolled_back = datetime(2026, 7, 30, 10, 9, tzinfo=UTC)
        with self.assertRaises(PrincipalAuthenticationError):
            fixture.replace(service=fixture.service(now=rolled_back))
        trust = TrustProvisioningService(fixture.store)
        newer = fixture.factory.policy(
            policy_version=POLICY_VERSION + 1,
            store_id=fixture.store_id,
            allowed_profiles=sorted(fixture.registry.profiles_by_id),
            allowed_operations=sorted(
                {
                    PrincipalOperation.COLLABORATION_ACTIVATE.value,
                    *(
                        operation.value
                        for operation in PrincipalOperation
                        if "collaboration.plan-replacement" in operation.value
                    ),
                }
            ),
        )
        fixture.store._clock = lambda: datetime(2026, 7, 30, 10, 11, tzinfo=UTC)
        trust.apply_policy(newer)
        with self.assertRaises(PrincipalAuthenticationError):
            fixture.replace()

    def test_current_durable_mission_policy_drift_fails_closed(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        fixture._commit_mission_policy(
            plan=fixture.prior,
            policy_version=3,
            previous_policy_sha256=fixture.mission_policy.policy_sha256,
            marker=240,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "current durable commit",
        ):
            fixture.replace()

    def test_tampered_signed_custody_is_detected_after_restart(self) -> None:
        fixture = AuthenticatedPlanReplacementFixture(self)
        fixture.replace()
        fixture.store.verify_store(fixture.registry)
        with closing(sqlite3.connect(fixture.path)) as connection:
            trigger = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name = ?",
                ("collaboration_plan_replacement_authentications_immutable",),
            ).fetchone()[0]
            original = dict(
                connection.execute(
                    "SELECT preflight_id, composition_sha256 "
                    "FROM collaboration_plan_replacement_authentications"
                ).fetchall()
            )
            self.assertIn(fixture.preflight.preflight_id, original)
            connection.execute(
                "DROP TRIGGER collaboration_plan_replacement_authentications_immutable"
            )
            cursor = connection.execute(
                """
                UPDATE collaboration_plan_replacement_authentications
                SET composition_sha256 = ?
                WHERE preflight_id = ?
                """,
                ("sha256:" + "0" * 64, fixture.preflight.preflight_id),
            )
            self.assertEqual(cursor.rowcount, 1)
            self.assertEqual(
                dict(
                    connection.execute(
                        "SELECT preflight_id, composition_sha256 "
                        "FROM collaboration_plan_replacement_authentications"
                    ).fetchall()
                ),
                {**original, fixture.preflight.preflight_id: "sha256:" + "0" * 64},
            )
            connection.execute(trigger)
            connection.commit()
        reopened = MissionStore(fixture.path, clock=lambda: NOW)
        with reopened._read_connection() as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE name = ?",
                    ("collaboration_plan_replacement_authentications_immutable",),
                ).fetchone()[0],
                trigger,
            )
        with self.assertRaises(StoreIntegrityError):
            reopened.verify_store(fixture.registry)

    def test_v29_migration_rejects_unprovenanced_replacement_history(self) -> None:
        fixture = legacy_fixture.phase14_fixture(self)
        replacement = legacy_fixture.replacement_plan(fixture.plan, "B")
        preflight = legacy_fixture.replacement_preflight(fixture.store, fixture.plan, replacement)
        legacy_fixture.service_for(fixture).replace(
            preflight=preflight,
            prior_plan=fixture.plan,
            replacement_plan=replacement,
            authority_evidence=legacy_fixture.authority_evidence(preflight),
            expected_plan_version=1,
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(StoreIntegrityError, "signed authority custody"),
        ):
            fixture.store.migrate(
                fixture.registry,
                Path(directory) / "before-v30.sqlite3",
            )


if __name__ == "__main__":
    unittest.main()

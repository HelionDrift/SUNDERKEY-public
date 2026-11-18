"""Current signed replacement composition for synthetic action-history fixtures."""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

from sunderkey.authenticated_collaboration_mission_policy import (
    AuthenticatedCollaborationMissionPolicyService,
)
from sunderkey.authenticated_collaboration_plan_replacement import (
    AuthenticatedCollaborationPlanReplacementStoreService,
)
from sunderkey.collaboration_mission_policy import (
    CollaborationMissionReconfigurationPolicy,
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
    build_collaboration_plan_replacement_preflight,
)
from sunderkey.collaboration_plan_replacement_store import (
    build_collaboration_plan_replacement_source_snapshots,
)
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.plan_replacement_reviewer_admission import (
    REVIEWER_OPERATIONS,
    AuthenticatedPlanReplacementReviewerAdmissionService,
    reviewer_admission_operation_intent,
)
from sunderkey.registry import load_registry
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from . import test_authenticated_collaboration_mission_policy_phase88 as phase88
from .test_identity_phase4 import AUDIENCE, SUBJECT
from .test_store import ROOT

REGISTRY_PATH = ROOT / "registry" / "army-v2.json"

REPLACEMENT_REVIEWERS = {
    "independent_control": "AOE-HQ-14",
    "second_control": "AOE-HQ-15",
    "independent_assurance": "AOE-HQ-20",
}
REPLACEMENT_OPERATIONS = tuple(
    operation
    for operation in PrincipalOperation
    if operation.value.startswith("sunderkey.collaboration.plan-replacement.")
)


def replacement_subject(profile_id: str) -> str:
    return "replacement-review:" + profile_id.lower()


def initialize_action_fixture_with_army_v2(fixture: Any) -> None:
    """Create original signed history against the real replacement catalog.

    The nested fixture's class setup chooses its source path. Both scoped patches
    restore that class state, while this instance keeps its exact registry.
    """
    registry = load_registry(REGISTRY_PATH)
    fixture_type = phase88.AuthenticatedCollaborationMissionPolicyPhase88Tests
    with (
        mock.patch.object(phase88, "REGISTRY_PATH", REGISTRY_PATH),
        mock.patch.object(fixture_type, "registry", registry, create=True),
    ):
        fixture.setUp()
        fixture.root.registry = registry


def action_history_rows(store: Any) -> dict[str, tuple[str, ...]]:
    """Capture the existing local action records, never rewrite their custody."""
    with store._read_connection() as connection:
        tables = tuple(
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name GLOB 'action_*' ORDER BY name"
            )
        )
        return {
            table: tuple(
                sorted(
                    canonical_json(dict(row))
                    for row in connection.execute(
                        'SELECT * FROM "' + table.replace('"', '""') + '"'
                    )
                )
            )
            for table in tables
        }


def commit_signed_plan_rotation(test: Any, replacement: Any, *, marker: int = 195_000) -> Any:
    """Use current typed custody, ephemeral fixture keys and no native adapters.

    The fixture provisions necessary trust before its action history is created.
    This helper neither rotates trust nor edits mission assignments or old rows.
    """
    prior = test.plan
    store = test.store
    registry = test.registry
    mission = test.mission
    mission_id = test.mission_id
    now = test.root.now
    at = format_timestamp(now)
    end = "2026-07-30T10:25:00Z"
    history = action_history_rows(store)
    context = test.root.stored.context_hash
    constraints = sha256_text(canonical_json(mission.to_dict()["constraints"]))

    def grant(index: int, profile: str, subject: str, operation: PrincipalOperation):
        return test.factory.grant(
            grant_id=f"SGR-{marker + index:032X}",
            profile_id=profile,
            subject=subject,
            audience=AUDIENCE,
            store_id=test.root.store_id,
            mission_id=mission_id,
            mission_context_hash=context,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=constraints,
            operations=[operation.value],
            policy_version=test.policy_version,
            issued_at=at,
            not_before=at,
            expires_at=end,
        )

    def assertion(index: int, scope: Any, operation: PrincipalOperation, intent_sha256: str):
        return test.factory.assertion(
            grant=scope,
            assertion_id=f"PAS-{marker + index:032X}",
            policy_version=test.policy_version,
            scope_grant_id=scope.grant_id,
            subject=scope.subject,
            profile_id=scope.profile_id,
            audience=AUDIENCE,
            store_id=test.root.store_id,
            mission_id=mission_id,
            operation=operation,
            operation_intent_sha256=intent_sha256,
            issued_at=at,
            not_before=at,
            expires_at=end,
        )

    def binding(principal: Any) -> dict[str, str]:
        return {
            "profile_id": principal.profile_id,
            "assertion_id": principal.assertion_id,
            "assertion_sha256": principal.content_sha256,
        }

    with store._read_connection() as connection:
        row = connection.execute(
            "SELECT policy_json FROM collaboration_mission_policy_commits "
            "WHERE mission_id=? ORDER BY policy_version DESC LIMIT 1",
            (mission_id,),
        ).fetchone()
    test.assertIsNotNone(row)
    previous = CollaborationMissionReconfigurationPolicy.from_dict(json.loads(row["policy_json"]))
    old = previous.to_dict()
    selected = old["selected_parameters"]
    owner_operation = PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE
    control_operation = PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE
    owner_scope = grant(10, test.owner_profile, SUBJECT, owner_operation)
    control_scope = grant(
        11, test.control_profile, test.grants["control"].subject, control_operation
    )
    test.acceptance.accept(owner_scope)
    test.acceptance.accept(control_scope)
    policy_arguments = dict(
        authority_policy=test.root.authority,
        policy_version=old["policy_version"] + 1,
        previous_policy_sha256=previous.policy_sha256,
        mission_id=mission_id,
        collaboration_plan_id=prior.plan_id,
        collaboration_plan_sha256=prior.content_sha256,
        maximum_delegation_depth=selected["maximum_delegation_depth"],
        reconfiguration_validity_seconds=selected["reconfiguration_validity_seconds"],
        execution_ack_timeout_seconds=selected["execution_ack_timeout_seconds"],
        maximum_plan_replacement_items=selected["maximum_plan_replacement_items"],
        transition_activation={**old["transition_activation"], "activated_plan_replacement": True},
        effective_at=at,
        expires_at="2026-07-30T11:00:00Z",
        mission_owner_approval={
            "profile_id": owner_scope.profile_id,
            "assertion_id": f"PAS-{marker + 10:032X}",
            "assertion_sha256": "sha256:" + "1" * 64,
        },
        independent_control_approval={
            "profile_id": control_scope.profile_id,
            "assertion_id": f"PAS-{marker + 11:032X}",
            "assertion_sha256": "sha256:" + "2" * 64,
        },
    )
    provisional = build_collaboration_mission_reconfiguration_policy(**policy_arguments)
    selection = collaboration_mission_reconfiguration_selection_sha256(provisional)
    owner = assertion(
        10,
        owner_scope,
        owner_operation,
        compute_operation_intent_hash(
            owner_operation,
            {
                "mission_id": mission_id,
                "policy_selection_sha256": selection,
                "principal_profile_id": owner_scope.profile_id,
            },
        ),
    )
    control = assertion(
        11,
        control_scope,
        control_operation,
        compute_operation_intent_hash(
            control_operation,
            {
                "mission_id": mission_id,
                "policy_selection_sha256": selection,
                "principal_profile_id": control_scope.profile_id,
            },
        ),
    )
    policy_arguments["mission_owner_approval"] = binding(owner)
    policy_arguments["independent_control_approval"] = binding(control)
    mission_policy = build_collaboration_mission_reconfiguration_policy(**policy_arguments)
    policy_receipt = (
        AuthenticatedCollaborationMissionPolicyService(store, registry, clock=lambda: now)
        .commit(
            mission_policy,
            authority_policy=test.root.authority,
            mission_owner_assertion=owner,
            independent_control_assertion=control,
        )
        .to_dict()
    )
    policy_commit = {
        "policy_id": mission_policy.policy_id,
        "policy_sha256": mission_policy.policy_sha256,
        "policy_selection_sha256": policy_receipt["selection_sha256"],
        "authentication_id": policy_receipt["authentication_id"],
        "authentication_sha256": policy_receipt["authentication_sha256"],
        "committed_at": policy_receipt["committed_at"],
        "mission_owner_assertion_id": policy_receipt["mission_owner"]["assertion_id"],
        "mission_owner_assertion_sha256": policy_receipt["mission_owner"]["assertion_sha256"],
        "mission_owner_ledger_entry_sha256": policy_receipt["mission_owner"]["ledger_entry_sha256"],
        "independent_control_assertion_id": policy_receipt["independent_control"]["assertion_id"],
        "independent_control_assertion_sha256": policy_receipt["independent_control"][
            "assertion_sha256"
        ],
        "independent_control_ledger_entry_sha256": policy_receipt["independent_control"][
            "ledger_entry_sha256"
        ],
        "commit_status": policy_receipt["commit_status"],
    }
    admission = AuthenticatedPlanReplacementReviewerAdmissionService(
        store, registry, clock=lambda: now
    )
    admission_owner_op = PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE
    admission_control_op = PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE
    admission_owner = grant(20, test.owner_profile, SUBJECT, admission_owner_op)
    admission_control = grant(
        21, test.control_profile, test.grants["control"].subject, admission_control_op
    )
    test.acceptance.accept(admission_owner)
    test.acceptance.accept(admission_control)
    reviewer_grants = {}
    for index, (role, profile) in enumerate(sorted(REPLACEMENT_REVIEWERS.items())):
        reviewer = grant(
            100 + index, profile, replacement_subject(profile), REVIEWER_OPERATIONS[role]
        )
        request = admission.prepare(
            mission_id,
            admission_id=f"RVA-{marker + 100 + index:032X}",
            reviewer_scope_grant=reviewer,
            reviewer_issuer="identity-provider",
            reviewer_subject=reviewer.subject,
            role=role,
            issued_at=at,
            not_before=at,
            expires_at=end,
        )
        owner = assertion(
            200 + 2 * index,
            admission_owner,
            admission_owner_op,
            compute_operation_intent_hash(
                admission_owner_op,
                reviewer_admission_operation_intent(
                    request, principal_profile_id=admission_owner.profile_id, role="mission_owner"
                ),
            ),
        )
        control = assertion(
            201 + 2 * index,
            admission_control,
            admission_control_op,
            compute_operation_intent_hash(
                admission_control_op,
                reviewer_admission_operation_intent(
                    request,
                    principal_profile_id=admission_control.profile_id,
                    role="independent_control",
                ),
            ),
        )
        admission.admit(
            request, mission_owner_assertion=owner, independent_control_assertion=control
        )
        reviewer_grants[role] = reviewer
    snapshots = build_collaboration_plan_replacement_source_snapshots(
        store, mission_id, prior.plan_id
    )
    with store._read_connection() as connection:
        identity = store._verify_store_identity(connection, verify_history=False)
        policies = store._verify_trust_policy_history(connection, identity)
        verified_policy = policies[test.policy.content_sha256]
        mission_row = connection.execute(
            "SELECT revision FROM missions WHERE mission_id=?", (mission_id,)
        ).fetchone()
        head = connection.execute(
            "SELECT plan_version FROM collaboration_plan_active_heads WHERE mission_id=?",
            (mission_id,),
        ).fetchone()
        latest_completed = {
            row["work_item_id"]: row["result_sha256"]
            for row in connection.execute(
                """SELECT transition.* FROM collaboration_work_item_transitions AS transition
                WHERE mission_id=? AND plan_id=? AND transition_kind='complete'
                AND NOT EXISTS (SELECT 1 FROM collaboration_work_item_transitions AS later
                    WHERE later.plan_id=transition.plan_id
                    AND later.work_item_id=transition.work_item_id
                    AND later.generation>transition.generation)""",
                (mission_id, prior.plan_id),
            )
        }
    preflight = build_collaboration_plan_replacement_preflight(
        prior_plan=prior,
        replacement_plan=replacement,
        mission_policy=mission_policy,
        mission_policy_commit=policy_commit,
        source_state={
            "mission_revision": mission_row["revision"],
            "active_plan_id": prior.plan_id,
            "active_plan_sha256": prior.content_sha256,
            **snapshots.hashes,
            "observed_at": at,
        },
        mapping_inputs=[
            {
                "source_work_item_id": item.work_item_id,
                "replacement_work_item_id": item.work_item_id,
                "source_state": "completed"
                if item.work_item_id in latest_completed
                else "not_completed",
                "disposition": "preserve_completed_result"
                if item.work_item_id in latest_completed
                else "restart_in_replacement",
                "completed_result_sha256": latest_completed.get(item.work_item_id),
                "cross_command_evidence": None,
            }
            for item in prior.work_items
        ],
        independent_control_profile_id=REPLACEMENT_REVIEWERS["independent_control"],
        independent_assurance_profile_id=REPLACEMENT_REVIEWERS["independent_assurance"],
        second_control_profile_id=REPLACEMENT_REVIEWERS["second_control"],
    )
    registry_source = REGISTRY_PATH.read_bytes()
    authority_plan = build_collaboration_plan_replacement_authority_plan(
        preflight=preflight,
        authority_policy=test.root.authority,
        mission_policy=mission_policy,
        registry=registry,
        registry_source=registry_source,
        issued_at=at,
        expires_at=end,
    )
    verified = verify_collaboration_plan_replacement_authority_plan_offline(
        authority_plan,
        preflight=preflight,
        prior_plan=prior,
        replacement_plan=replacement,
        authority_policy=test.root.authority,
        mission_policy=mission_policy,
        registry=registry,
        registry_source=registry_source,
        verified_at=at,
    )
    upgrade = build_collaboration_plan_replacement_authority_upgrade(
        preflight=preflight, army_registry=registry
    )
    keys = collaboration_plan_replacement_authority_replay_keys(
        verified, upgrade, preflight=preflight, army_registry=registry
    )
    credentials = []
    for index, requirement in enumerate(upgrade.to_dict()["authority_requirements"]):
        operation = PrincipalOperation(requirement["operation"])
        scope = reviewer_grants.get(requirement["role"])
        if scope is None:
            scope = grant(
                1000 + index,
                requirement["principal_profile_id"],
                replacement_subject(requirement["principal_profile_id"]),
                operation,
            )
            test.acceptance.accept(scope)
        principal = assertion(
            1000 + index, scope, operation, requirement["principal_operation_intent_sha256"]
        )
        credentials.append(
            CollaborationPlanReplacementAuthorityCredential(
                source_requirement_id=requirement["source_requirement_id"],
                upgraded_requirement_id=requirement["requirement_id"],
                replay_key_sha256=keys[requirement["source_requirement_id"]],
                scope_grant=scope,
                assertion=principal,
            )
        )
    credentials = tuple(credentials)
    bundle = authenticate_collaboration_plan_replacement_authority(
        verified,
        upgrade,
        preflight=preflight,
        army_registry=registry,
        credentials=credentials,
        verified_policy=verified_policy,
        expected_audience=AUDIENCE,
        expected_store_id=test.root.store_id,
        expected_mission_context_hash=context,
        expected_scope_reference=mission.scope_reference,
        expected_scope_document_hash=mission.scope_document_hash,
        expected_environment=mission.environment,
        expected_max_action_tier=mission.max_action_tier,
        expected_constraints_hash=constraints,
        revoked_scope_grant_sha256s=(),
        consumed_replay_keys=(),
        clock=lambda: now,
    )
    receipt = AuthenticatedCollaborationPlanReplacementStoreService(
        store, registry, clock=lambda: now
    ).replace(
        preflight=preflight,
        prior_plan=prior,
        replacement_plan=replacement,
        verified_authority_plan=verified,
        authority_upgrade=upgrade,
        authenticated_bundle=bundle,
        credentials=credentials,
        expected_plan_version=head["plan_version"],
    )
    test.assertEqual(action_history_rows(store), history)
    test.assertEqual(store.get_mission(registry, mission_id).context_hash, context)
    with store._read_connection() as connection:
        record = connection.execute(
            "SELECT requirement_count FROM collaboration_plan_replacement_authentications "
            "WHERE preflight_id=?",
            (preflight.preflight_id,),
        ).fetchone()
        consumed = connection.execute(
            "SELECT COUNT(*) FROM collaboration_plan_replacement_authority_consumptions "
            "WHERE preflight_id=?",
            (preflight.preflight_id,),
        ).fetchone()[0]
    test.assertEqual(record["requirement_count"], len(credentials))
    test.assertEqual(consumed, len(credentials))
    test.assertEqual(bundle.requirement_count, len(credentials))
    return receipt

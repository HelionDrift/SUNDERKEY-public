from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

import jsonschema

from sunderkey.identity_cloud_reasoning import (
    MAX_DEPTH,
    NO_EFFECTS,
    CompletePathValidationPlan,
    Condition,
    ConflictKind,
    ConflictReport,
    CredentialReference,
    CrossSurfacePath,
    EvidenceBinding,
    Group,
    IdentityCloudReasoningError,
    IdentityCloudSnapshot,
    IndependentPathReview,
    PathSearchResult,
    PathState,
    PermissionFact,
    Policy,
    Principal,
    ResolutionState,
    Resource,
    Role,
    SessionTransition,
    TrustRelation,
    WorkloadIdentity,
    build_complete_path_validation_plan,
    canonical_sha256,
    detect_reasoning_conflicts,
    parse_snapshot,
    resolve_effective_permission,
    search_cross_surface_paths,
    verify_complete_path_validation_plan,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "identity-cloud-reasoning-v1.schema.json"
NOW = "2026-09-20T12:00:00Z"


def digest(label: str) -> str:
    return canonical_sha256({"label": label})


def review_context_digest(result: PathSearchResult, attributes: dict[str, str], as_of: str) -> str:
    return canonical_sha256(
        {
            "attributes_sha256": canonical_sha256(attributes),
            "evaluated_at": as_of,
            "search_result_sha256": result.result_sha256,
            "snapshot_sha256": result.snapshot_sha256,
        }
    )


class Fixture:
    def __init__(
        self,
        *,
        deny: bool = False,
        permission_evidence_state: str = "verified",
        permission_evidence_expiry: str = "2027-09-20T12:00:00Z",
        use_trust: bool = True,
        use_transition: bool = False,
        credential_expiry: str = "2027-09-20T12:00:00Z",
    ) -> None:
        self.core_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("core"),
            "2026-09-19T12:00:00Z",
            "2027-09-20T12:00:00Z",
        )
        self.permission_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("permission"),
            "2026-09-19T12:00:00Z",
            permission_evidence_expiry,
            permission_evidence_state,
        )
        self.principal = Principal(
            "tenant.alpha",
            "assessment.alpha",
            "service.checkout",
            "service",
            "identity",
            self.core_evidence.evidence_id,
        )
        self.workload = WorkloadIdentity(
            "tenant.alpha",
            "assessment.alpha",
            "container.checkout",
            "container",
            self.principal.principal_id,
            self.core_evidence.evidence_id,
        )
        self.role = Role(
            "tenant.alpha",
            "assessment.alpha",
            "role.data.reader",
            self.core_evidence.evidence_id,
        )
        self.group = Group(
            "tenant.alpha",
            "assessment.alpha",
            "group.services",
            (self.principal.principal_id,),
            self.core_evidence.evidence_id,
        )
        self.resource = Resource(
            "tenant.alpha",
            "assessment.alpha",
            "warehouse.orders",
            "data_warehouse",
            "data",
            self.core_evidence.evidence_id,
        )
        self.credential = CredentialReference(
            "tenant.alpha",
            "assessment.alpha",
            "credential.checkout.reference",
            self.principal.principal_id,
            "workload_token_reference",
            credential_expiry,
            self.core_evidence.evidence_id,
        )
        condition = Condition("region", "in", ("us-west", "us-central"))
        self.trust = TrustRelation(
            "tenant.alpha",
            "assessment.alpha",
            self.principal.principal_id,
            self.role.role_id,
            (condition,),
            self.core_evidence.evidence_id,
        )
        self.transition = SessionTransition(
            "tenant.alpha",
            "assessment.alpha",
            self.principal.principal_id,
            self.role.role_id,
            "exchange_token",
            self.credential.credential_id,
            (condition,),
            self.core_evidence.evidence_id,
        )
        permission_condition = Condition("environment", "equals", ("production",))
        self.allow = PermissionFact(
            "tenant.alpha",
            "assessment.alpha",
            self.role.role_id,
            self.resource.resource_id,
            "data.read",
            "allow",
            (permission_condition,),
            self.permission_evidence.evidence_id,
        )
        facts = [self.allow]
        if deny:
            self.deny = PermissionFact(
                "tenant.alpha",
                "assessment.alpha",
                self.role.role_id,
                self.resource.resource_id,
                "data.read",
                "deny",
                (permission_condition,),
                self.permission_evidence.evidence_id,
            )
            facts.append(self.deny)
        self.policy = Policy(
            "tenant.alpha",
            "assessment.alpha",
            "policy.data.reader",
            (self.role.role_id,),
            tuple(item.permission_fact_id for item in facts),
            self.core_evidence.evidence_id,
        )
        self.snapshot = IdentityCloudSnapshot(
            tenant_id="tenant.alpha",
            context_id="assessment.alpha",
            observed_at="2026-09-20T11:00:00Z",
            evidence_bindings=(self.core_evidence, self.permission_evidence),
            principals=(self.principal,),
            groups=(self.group,),
            roles=(self.role,),
            policies=(self.policy,),
            resources=(self.resource,),
            credentials=(self.credential,),
            workload_identities=(self.workload,),
            trust_relations=(self.trust,) if use_trust else (),
            permission_facts=tuple(facts),
            session_transitions=(self.transition,) if use_transition else (),
        )

    @staticmethod
    def attributes() -> dict[str, str]:
        return {
            "environment": "production",
            "region": "us-west",
            "tenant_id": "tenant.alpha",
        }


class IdentityCloudReasoningTests(unittest.TestCase):
    def test_snapshot_is_content_addressed_round_trip_and_schema_valid(self) -> None:
        fixture = Fixture()
        document = fixture.snapshot.to_dict()
        self.assertEqual(parse_snapshot(document), fixture.snapshot)
        self.assertTrue(fixture.snapshot.snapshot_id.startswith("ICS-"))
        self.assertEqual(document["effects"], dict(NO_EFFECTS))
        jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(document)

    def test_effective_permission_expands_workload_and_trust_with_provenance(self) -> None:
        fixture = Fixture()
        result = resolve_effective_permission(
            fixture.snapshot,
            subject_id=fixture.workload.workload_identity_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.ALLOWED)
        self.assertIn(fixture.role.role_id, result.expanded_subject_ids)
        self.assertIn(fixture.trust.trust_relation_id, result.provenance_ids)
        self.assertIn(fixture.allow.permission_fact_id, result.allow_fact_ids)
        self.assertIn(fixture.policy.policy_id, result.provenance_ids)

    def test_unattached_permission_facts_do_not_grant_or_deny_access(self) -> None:
        fixture = Fixture()
        orphaned = replace(fixture.snapshot, policies=())
        result = resolve_effective_permission(
            orphaned,
            subject_id=fixture.role.role_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.NOT_APPLICABLE)
        self.assertFalse(result.allow_fact_ids)
        self.assertEqual(
            search_cross_surface_paths(
                orphaned,
                start_id=fixture.workload.workload_identity_id,
                target_resource_id=fixture.resource.resource_id,
                action="data.read",
                attributes=fixture.attributes(),
                as_of=NOW,
            ).state,
            PathState.BLOCKED,
        )
        with_deny = Fixture(deny=True)
        allow_only_policy = replace(
            with_deny.policy, permission_fact_ids=(with_deny.allow.permission_fact_id,)
        )
        allow_only = replace(with_deny.snapshot, policies=(allow_only_policy,))
        result = resolve_effective_permission(
            allow_only,
            subject_id=with_deny.role.role_id,
            resource_id=with_deny.resource.resource_id,
            action="data.read",
            attributes=with_deny.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.ALLOWED)
        self.assertFalse(result.deny_fact_ids)

    def test_stale_policy_evidence_cannot_activate_permission_fact(self) -> None:
        fixture = Fixture()
        stale_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("stale-policy"),
            "2026-09-19T12:00:00Z",
            "2026-09-20T11:30:00Z",
        )
        stale_policy = replace(fixture.policy, evidence_id=stale_evidence.evidence_id)
        stale_snapshot = replace(
            fixture.snapshot,
            evidence_bindings=(*fixture.snapshot.evidence_bindings, stale_evidence),
            policies=(stale_policy,),
        )
        result = resolve_effective_permission(
            stale_snapshot,
            subject_id=fixture.role.role_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertIn(stale_policy.policy_id, result.unknown_fact_ids)
        self.assertFalse(result.allow_fact_ids)
        mixed_snapshot = replace(stale_snapshot, policies=(stale_policy, fixture.policy))
        mixed_result = resolve_effective_permission(
            mixed_snapshot,
            subject_id=fixture.role.role_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(mixed_result.state, ResolutionState.ALLOWED)
        self.assertIn(fixture.policy.policy_id, mixed_result.provenance_ids)
        self.assertNotIn(stale_policy.policy_id, mixed_result.provenance_ids)

    def test_stale_workload_binding_cannot_expand_to_a_principal(self) -> None:
        fixture = Fixture()
        stale_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("stale-workload"),
            "2026-09-19T12:00:00Z",
            "2026-09-20T11:30:00Z",
        )
        stale_workload = replace(fixture.workload, evidence_id=stale_evidence.evidence_id)
        stale_snapshot = replace(
            fixture.snapshot,
            evidence_bindings=(*fixture.snapshot.evidence_bindings, stale_evidence),
            workload_identities=(stale_workload,),
        )
        result = resolve_effective_permission(
            stale_snapshot,
            subject_id=stale_workload.workload_identity_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertNotIn(fixture.principal.principal_id, result.expanded_subject_ids)
        self.assertNotIn(fixture.role.role_id, result.expanded_subject_ids)
        self.assertIn(stale_workload.workload_identity_id, result.unknown_fact_ids)

    def test_stale_group_membership_cannot_activate_group_permission(self) -> None:
        fixture = Fixture()
        group_allow = replace(fixture.allow, subject_id=fixture.group.group_id)
        group_policy = replace(
            fixture.policy,
            attached_subject_ids=(fixture.group.group_id,),
            permission_fact_ids=(group_allow.permission_fact_id,),
        )
        current_snapshot = replace(
            fixture.snapshot, permission_facts=(group_allow,), policies=(group_policy,)
        )
        current = resolve_effective_permission(
            current_snapshot,
            subject_id=fixture.principal.principal_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(current.state, ResolutionState.ALLOWED)
        self.assertIn(fixture.group.group_id, current.provenance_ids)
        stale_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("stale-group"),
            "2026-09-19T12:00:00Z",
            "2026-09-20T11:30:00Z",
        )
        stale_group = replace(fixture.group, evidence_id=stale_evidence.evidence_id)
        stale_allow = replace(group_allow, subject_id=stale_group.group_id)
        stale_policy = replace(
            group_policy,
            attached_subject_ids=(stale_group.group_id,),
            permission_fact_ids=(stale_allow.permission_fact_id,),
        )
        stale_snapshot = replace(
            fixture.snapshot,
            evidence_bindings=(*fixture.snapshot.evidence_bindings, stale_evidence),
            groups=(stale_group,),
            permission_facts=(stale_allow,),
            policies=(stale_policy,),
        )
        result = resolve_effective_permission(
            stale_snapshot,
            subject_id=fixture.principal.principal_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertNotIn(stale_group.group_id, result.expanded_subject_ids)
        self.assertIn(stale_group.group_id, result.unknown_fact_ids)
        self.assertFalse(result.allow_fact_ids)

    def test_stale_role_and_resource_records_withhold_positive_resolution(self) -> None:
        fixture = Fixture()
        stale_evidence = EvidenceBinding(
            "tenant.alpha",
            "assessment.alpha",
            digest("stale-identity-record"),
            "2026-09-19T12:00:00Z",
            "2026-09-20T11:30:00Z",
        )
        stale_role = replace(fixture.role, evidence_id=stale_evidence.evidence_id)
        stale_trust = replace(fixture.trust, target_role_id=stale_role.role_id)
        role_allow = replace(fixture.allow, subject_id=stale_role.role_id)
        role_policy = replace(
            fixture.policy,
            attached_subject_ids=(stale_role.role_id,),
            permission_fact_ids=(role_allow.permission_fact_id,),
        )
        role_snapshot = replace(
            fixture.snapshot,
            evidence_bindings=(*fixture.snapshot.evidence_bindings, stale_evidence),
            roles=(stale_role,),
            trust_relations=(stale_trust,),
            permission_facts=(role_allow,),
            policies=(role_policy,),
        )
        result = resolve_effective_permission(
            role_snapshot,
            subject_id=fixture.principal.principal_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertNotIn(stale_role.role_id, result.expanded_subject_ids)
        self.assertIn(stale_role.role_id, result.unknown_fact_ids)

        stale_resource = replace(fixture.resource, evidence_id=stale_evidence.evidence_id)
        resource_allow = replace(fixture.allow, resource_id=stale_resource.resource_id)
        resource_policy = replace(
            fixture.policy, permission_fact_ids=(resource_allow.permission_fact_id,)
        )
        resource_snapshot = replace(
            fixture.snapshot,
            evidence_bindings=(*fixture.snapshot.evidence_bindings, stale_evidence),
            resources=(stale_resource,),
            permission_facts=(resource_allow,),
            policies=(resource_policy,),
        )
        result = resolve_effective_permission(
            resource_snapshot,
            subject_id=fixture.role.role_id,
            resource_id=stale_resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertIn(stale_resource.resource_id, result.unknown_fact_ids)

    def test_explicit_deny_precedes_allow_and_reports_conflict(self) -> None:
        fixture = Fixture(deny=True)
        result = resolve_effective_permission(
            fixture.snapshot,
            subject_id=fixture.workload.workload_identity_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.DENIED)
        self.assertTrue(result.conflict)
        report = detect_reasoning_conflicts(fixture.snapshot, as_of=NOW)
        self.assertIn(ConflictKind.ALLOW_DENY, {item.conflict_kind for item in report.conflicts})
        self.assertEqual(ConflictReport.from_dict(report.to_dict()), report)

    def test_missing_bounded_condition_attribute_is_indeterminate(self) -> None:
        fixture = Fixture()
        result = resolve_effective_permission(
            fixture.snapshot,
            subject_id=fixture.workload.workload_identity_id,
            resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes={"tenant_id": "tenant.alpha"},
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        self.assertIn(fixture.trust.trust_relation_id, result.unknown_fact_ids)

    def test_unknown_and_stale_evidence_fail_closed(self) -> None:
        unknown = Fixture(permission_evidence_state="unknown")
        result = resolve_effective_permission(
            unknown.snapshot,
            subject_id=unknown.role.role_id,
            resource_id=unknown.resource.resource_id,
            action="data.read",
            attributes=unknown.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, ResolutionState.INDETERMINATE)
        stale = Fixture(permission_evidence_expiry="2026-09-20T11:30:00Z")
        report = detect_reasoning_conflicts(stale.snapshot, as_of=NOW)
        self.assertIn(
            ConflictKind.STALE_EVIDENCE, {item.conflict_kind for item in report.conflicts}
        )

    def test_cross_surface_search_returns_complete_deterministic_paths(self) -> None:
        fixture = Fixture()
        result = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        repeated = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, PathState.COMPLETE)
        self.assertEqual(result, repeated)
        self.assertEqual(PathSearchResult.from_dict(result.to_dict()), result)
        self.assertEqual(len(result.paths), 1)
        self.assertEqual(
            result.paths[0].node_ids,
            (
                fixture.workload.workload_identity_id,
                fixture.principal.principal_id,
                fixture.role.role_id,
                fixture.resource.resource_id,
            ),
        )

    def test_expired_transition_credential_makes_path_indeterminate(self) -> None:
        fixture = Fixture(
            use_trust=False,
            use_transition=True,
            credential_expiry="2026-09-20T11:30:00Z",
        )
        result = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        self.assertEqual(result.state, PathState.INDETERMINATE)
        self.assertIn(fixture.transition.session_transition_id, result.indeterminate_edge_ids)

    def test_complete_path_plan_requires_two_independent_bound_reviews(self) -> None:
        fixture = Fixture()
        result = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        path_digest = canonical_sha256(sorted(item.path_id for item in result.paths))
        context_digest = review_context_digest(result, fixture.attributes(), NOW)
        reviews = (
            IndependentPathReview(
                "reviewer.identity",
                "independent_identity",
                path_digest,
                digest("identity-review"),
                NOW,
                context_digest,
            ),
            IndependentPathReview(
                "reviewer.assurance",
                "independent_assurance",
                path_digest,
                digest("assurance-review"),
                NOW,
                context_digest,
            ),
        )
        plan = build_complete_path_validation_plan(
            fixture.snapshot, result, reviews=reviews, attributes=fixture.attributes(), as_of=NOW
        )
        self.assertIsInstance(plan, CompletePathValidationPlan)
        self.assertEqual(plan.attributes_sha256, canonical_sha256(fixture.attributes()))
        self.assertEqual(plan.evaluated_at, NOW)
        self.assertEqual(
            verify_complete_path_validation_plan(
                fixture.snapshot, result, plan, attributes=fixture.attributes(), as_of=NOW
            ),
            plan,
        )
        self.assertEqual(plan.to_dict()["effects"], dict(NO_EFFECTS))
        self.assertEqual(CompletePathValidationPlan.from_dict(plan.to_dict()), plan)

    def test_forged_complete_path_fails_source_replay_even_with_matching_reviews(self) -> None:
        fixture = Fixture()
        actual = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        forged_path = CrossSurfacePath(
            actual.paths[0].node_ids,
            ("edge.not.in.snapshot", *actual.paths[0].edge_ids[1:]),
            actual.paths[0].resolution_id,
        )
        forged = PathSearchResult(
            actual.snapshot_sha256,
            actual.start_id,
            actual.target_resource_id,
            actual.action,
            PathState.COMPLETE,
            (forged_path,),
            (),
            (),
            actual.max_depth,
            actual.max_paths,
            False,
        )
        path_digest = canonical_sha256([forged_path.path_id])
        context_digest = review_context_digest(forged, fixture.attributes(), NOW)
        reviews = (
            IndependentPathReview(
                "reviewer.identity",
                "independent_identity",
                path_digest,
                digest("r1"),
                NOW,
                context_digest,
            ),
            IndependentPathReview(
                "reviewer.assurance",
                "independent_assurance",
                path_digest,
                digest("r2"),
                NOW,
                context_digest,
            ),
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "snapshot replay"):
            build_complete_path_validation_plan(
                fixture.snapshot,
                forged,
                reviews=reviews,
                attributes=fixture.attributes(),
                as_of=NOW,
            )
        asserted_plan = CompletePathValidationPlan(
            fixture.snapshot.snapshot_sha256,
            forged.result_sha256,
            (forged_path.path_id,),
            reviews,
            len(forged_path.edge_ids) + 1,
            canonical_sha256(fixture.attributes()),
            NOW,
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "snapshot replay"):
            verify_complete_path_validation_plan(
                fixture.snapshot,
                forged,
                asserted_plan,
                attributes=fixture.attributes(),
                as_of=NOW,
            )

    def test_plan_replay_rejects_changed_context_and_unobserved_evidence(self) -> None:
        fixture = Fixture()
        result = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        path_digest = canonical_sha256([item.path_id for item in result.paths])
        context_digest = review_context_digest(result, fixture.attributes(), NOW)
        reviews = (
            IndependentPathReview(
                "reviewer.identity",
                "independent_identity",
                path_digest,
                digest("r1"),
                NOW,
                context_digest,
            ),
            IndependentPathReview(
                "reviewer.assurance",
                "independent_assurance",
                path_digest,
                digest("r2"),
                NOW,
                context_digest,
            ),
        )
        plan = build_complete_path_validation_plan(
            fixture.snapshot, result, reviews=reviews, attributes=fixture.attributes(), as_of=NOW
        )
        changed = {**fixture.attributes(), "network_zone": "internal"}
        with self.assertRaisesRegex(IdentityCloudReasoningError, "review evaluation context"):
            build_complete_path_validation_plan(
                fixture.snapshot, result, reviews=reviews, attributes=changed, as_of=NOW
            )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "review evaluation context"):
            verify_complete_path_validation_plan(
                fixture.snapshot, result, plan, attributes=changed, as_of=NOW
            )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "review evaluation context"):
            verify_complete_path_validation_plan(
                fixture.snapshot,
                result,
                plan,
                attributes=fixture.attributes(),
                as_of="2026-09-20T13:00:00Z",
            )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "predates the snapshot"):
            build_complete_path_validation_plan(
                fixture.snapshot,
                result,
                reviews=reviews,
                attributes=fixture.attributes(),
                as_of="2026-09-20T10:00:00Z",
            )
        self.assertEqual(
            search_cross_surface_paths(
                fixture.snapshot,
                start_id=fixture.workload.workload_identity_id,
                target_resource_id=fixture.resource.resource_id,
                action="data.read",
                attributes=fixture.attributes(),
                as_of="2026-09-19T11:00:00Z",
            ).state,
            PathState.INDETERMINATE,
        )

    def test_plan_rejects_incomplete_search_and_reused_reviewer(self) -> None:
        fixture = Fixture(use_trust=False)
        result = search_cross_surface_paths(
            fixture.snapshot,
            start_id=fixture.workload.workload_identity_id,
            target_resource_id=fixture.resource.resource_id,
            action="data.read",
            attributes=fixture.attributes(),
            as_of=NOW,
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "complete"):
            build_complete_path_validation_plan(
                fixture.snapshot, result, reviews=(), attributes=fixture.attributes(), as_of=NOW
            )

    def test_tenant_context_and_attribute_isolation_fail_closed(self) -> None:
        fixture = Fixture()
        foreign = Principal(
            "tenant.foreign",
            "assessment.alpha",
            "principal.foreign",
            "human",
            "identity",
            fixture.core_evidence.evidence_id,
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "isolation"):
            IdentityCloudSnapshot(
                **{
                    **{
                        key: value
                        for key, value in fixture.snapshot.__dict__.items()
                        if key not in {"snapshot_id", "snapshot_sha256", "principals"}
                    },
                    "principals": (foreign,),
                }
            )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "tenant isolation"):
            resolve_effective_permission(
                fixture.snapshot,
                subject_id=fixture.role.role_id,
                resource_id=fixture.resource.resource_id,
                action="data.read",
                attributes={**fixture.attributes(), "tenant_id": "tenant.foreign"},
                as_of=NOW,
            )

    def test_transition_credential_policy_and_owner_fail_closed(self) -> None:
        fixture = Fixture()
        invalid = SessionTransition(
            "tenant.alpha",
            "assessment.alpha",
            fixture.principal.principal_id,
            fixture.role.role_id,
            "exchange_token",
            None,
            (),
            fixture.core_evidence.evidence_id,
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "credential policy"):
            IdentityCloudSnapshot(
                **{
                    **{
                        key: value
                        for key, value in fixture.snapshot.__dict__.items()
                        if key not in {"snapshot_id", "snapshot_sha256", "session_transitions"}
                    },
                    "session_transitions": (invalid,),
                }
            )
        second_principal = Principal(
            "tenant.alpha",
            "assessment.alpha",
            "service.unrelated",
            "service",
            "identity",
            fixture.core_evidence.evidence_id,
        )
        wrong_credential = CredentialReference(
            "tenant.alpha",
            "assessment.alpha",
            "credential.unrelated.reference",
            second_principal.principal_id,
            "reference",
            "2027-09-20T12:00:00Z",
            fixture.core_evidence.evidence_id,
        )
        wrong_owner = SessionTransition(
            "tenant.alpha",
            "assessment.alpha",
            fixture.principal.principal_id,
            fixture.role.role_id,
            "assume_role",
            wrong_credential.credential_id,
            (),
            fixture.core_evidence.evidence_id,
        )
        with self.assertRaisesRegex(IdentityCloudReasoningError, "owner"):
            IdentityCloudSnapshot(
                **{
                    **{
                        key: value
                        for key, value in fixture.snapshot.__dict__.items()
                        if key
                        not in {
                            "credentials",
                            "principals",
                            "session_transitions",
                            "snapshot_id",
                            "snapshot_sha256",
                        }
                    },
                    "credentials": (fixture.credential, wrong_credential),
                    "principals": (fixture.principal, second_principal),
                    "session_transitions": (wrong_owner,),
                }
            )

    def test_cycle_is_detected_without_unbounded_search(self) -> None:
        fixture = Fixture()
        second_role = Role(
            "tenant.alpha",
            "assessment.alpha",
            "role.second",
            fixture.core_evidence.evidence_id,
        )
        forward = TrustRelation(
            "tenant.alpha",
            "assessment.alpha",
            fixture.role.role_id,
            second_role.role_id,
            (),
            fixture.core_evidence.evidence_id,
        )
        backward = TrustRelation(
            "tenant.alpha",
            "assessment.alpha",
            second_role.role_id,
            fixture.role.role_id,
            (),
            fixture.core_evidence.evidence_id,
        )
        snapshot = IdentityCloudSnapshot(
            **{
                **{
                    key: value
                    for key, value in fixture.snapshot.__dict__.items()
                    if key not in {"snapshot_id", "snapshot_sha256", "roles", "trust_relations"}
                },
                "roles": (fixture.role, second_role),
                "trust_relations": (fixture.trust, forward, backward),
            }
        )
        report = detect_reasoning_conflicts(snapshot, as_of=NOW)
        self.assertIn(ConflictKind.GRAPH_CYCLE, {item.conflict_kind for item in report.conflicts})

    def test_tamper_unknown_fields_and_effect_changes_fail_closed(self) -> None:
        document = Fixture().snapshot.to_dict()
        tampered = copy.deepcopy(document)
        tampered["principals"][0]["principal_key"] = "changed"
        with self.assertRaisesRegex(IdentityCloudReasoningError, "content address"):
            parse_snapshot(tampered)
        unknown = copy.deepcopy(document)
        unknown["provider"] = "called"
        with self.assertRaisesRegex(IdentityCloudReasoningError, "fields"):
            parse_snapshot(unknown)
        effects = copy.deepcopy(document)
        effects["effects"]["provider_call"] = "performed"
        with self.assertRaisesRegex(IdentityCloudReasoningError, "effects"):
            parse_snapshot(effects)

    def test_conditions_and_search_budgets_are_strict(self) -> None:
        with self.assertRaisesRegex(IdentityCloudReasoningError, "bounded vocabulary"):
            Condition("provider_expression", "equals", ("anything",))
        fixture = Fixture()
        with self.assertRaisesRegex(IdentityCloudReasoningError, "budget"):
            search_cross_surface_paths(
                fixture.snapshot,
                start_id=fixture.workload.workload_identity_id,
                target_resource_id=fixture.resource.resource_id,
                action="data.read",
                attributes=fixture.attributes(),
                as_of=NOW,
                max_depth=MAX_DEPTH + 1,
            )

    def test_secret_like_keys_are_rejected(self) -> None:
        fixture = Fixture()
        with self.assertRaisesRegex(IdentityCloudReasoningError, "secret"):
            Principal(
                "tenant.alpha",
                "assessment.alpha",
                "api_key:abcdefghijk",
                "service",
                "identity",
                fixture.core_evidence.evidence_id,
            )

    def test_input_sequences_and_effect_documents_are_not_mutable_aliases(self) -> None:
        fixture = Fixture()
        members = [fixture.principal.principal_id]
        copied = Group(
            "tenant.alpha",
            "assessment.alpha",
            "group.copy",
            members,
            fixture.core_evidence.evidence_id,
        )
        members.append(fixture.role.role_id)
        self.assertEqual(copied.member_ids, (fixture.principal.principal_id,))
        first = fixture.snapshot.to_dict()
        second = fixture.snapshot.to_dict()
        second["effects"]["network"] = "performed"
        self.assertEqual(first["effects"], dict(NO_EFFECTS))

    def test_public_package_exports_reasoning_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.IdentityCloudSnapshot, IdentityCloudSnapshot)
        self.assertIs(sunderkey.parse_identity_cloud_snapshot, parse_snapshot)
        self.assertIs(
            sunderkey.resolve_identity_cloud_permission,
            resolve_effective_permission,
        )
        self.assertIs(sunderkey.search_identity_cloud_paths, search_cross_surface_paths)
        self.assertIs(
            sunderkey.verify_identity_cloud_validation_plan,
            verify_complete_path_validation_plan,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from sunderkey.action_authority_contracts import (
    RESOURCE_FIELDS,
    ActionAuthorityContractError,
    ActionAuthorityPolicyRevision,
    ActionBudgetPolicyRevision,
    ActionSafetyPolicyRevision,
    AuthenticatedProposalMaterialImport,
    AuthoritativeActionCatalogRevision,
    AuthoritativeTargetDescriptorRevision,
    ExactActionSourceHeadBundle,
    action_authority_contracts_schema,
    build_action_authority_policy_revision,
    build_action_budget_policy_revision,
    build_action_safety_policy_revision,
    build_authenticated_proposal_material_import,
    build_authoritative_action_catalog_revision,
    build_authoritative_target_descriptor_revision,
    build_exact_action_source_head_bundle,
    parse_action_authority_contract,
    record_schema,
)
from sunderkey.expert_runtime import WorkProduct, content_address_work_product


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _assignment(role: str, name: str) -> dict[str, str]:
    return {
        "role": role,
        "principal_profile_id": f"profile:{name}",
        "principal_subject": f"subject:{name}",
        "assertion_issuer": "issuer:root",
    }


def _resources(value: int) -> dict[str, int]:
    return {field: value for field in RESOURCE_FIELDS}


def _work_product() -> WorkProduct:
    body = {
        "schema_version": 1,
        "product_type": "action_proposal",
        "runtime_pack_id": "ERP-11111111111111111111111111111111",
        "runtime_catalog_sha256": _digest("1"),
        "runtime_pack_sha256": _digest("2"),
        "producer_profile_id": "AOE-GA-D01-S01",
        "execution_envelope_id": "EEE-22222222222222222222222222222222",
        "execution_envelope_sha256": _digest("3"),
        "mission_id": "mission:001",
        "plan_id": "plan:001",
        "work_id": "work:001",
        "summary": "Typed action proposal for independent review",
        "confidence": "high",
        "uncertainty": "No runtime authority is claimed",
        "evidence_refs": [_digest("4")],
        "lineage_product_ids": [],
        "independent_review": {
            "required": True,
            "status": "not_reviewed",
            "reviewer_profile_ids": [],
            "producer_excluded": True,
        },
        "payload": {
            "target_scope_sha256": _digest("5"),
            "authority_snapshot_sha256": _digest("6"),
            "evidence_snapshot_sha256": _digest("7"),
            "mission_id": "mission:001",
            "plan_id": "plan:001",
            "work_id": "work:001",
            "requested_action_tier": "R3",
            "proposed_actions": ["api.request"],
            "evidence_requirement_ids": ["evidence:response"],
            "cleanup_requirement_ids": ["cleanup:session"],
            "approval_requirement_ids": ["approval:owner-control"],
            "stop_conditions": ["stop:on-monitor-loss"],
        },
        "model_output_effect": "advisory_only",
        "tool_effect": "none",
        "authorization_effect": "none",
    }
    document = content_address_work_product(body)
    return WorkProduct(
        product_id=document["product_id"],
        product_sha256=document["product_sha256"],
        product_type="action_proposal",
        producer_profile_id=document["producer_profile_id"],
        runtime_catalog_sha256=document["runtime_catalog_sha256"],
        envelope_id=document["execution_envelope_id"],
        mission_id=document["mission_id"],
        plan_id=document["plan_id"],
        work_id=document["work_id"],
        target_scope_sha256=document["payload"]["target_scope_sha256"],
        authority_snapshot_sha256=document["payload"]["authority_snapshot_sha256"],
        evidence_snapshot_sha256=document["payload"]["evidence_snapshot_sha256"],
        payload=document["payload"],
        document_json=json.dumps(document, sort_keys=True, separators=(",", ":")),
    )


def _records() -> tuple[
    ActionAuthorityPolicyRevision,
    AuthoritativeActionCatalogRevision,
    AuthoritativeTargetDescriptorRevision,
    ActionBudgetPolicyRevision,
    ActionSafetyPolicyRevision,
    AuthenticatedProposalMaterialImport,
    ExactActionSourceHeadBundle,
]:
    common = {
        "tenant_id": "tenant:001",
        "mission_id": "mission:001",
        "plan_id": "plan:001",
        "revision": 1,
        "previous_revision_sha256": None,
        "effective_at": "2026-09-21T10:00:00Z",
        "expires_at": "2026-09-21T12:00:00Z",
        "revocation_policy_sha256": _digest("8"),
    }
    policy = build_action_authority_policy_revision(
        **common,
        policy_id="policy:action-authority",
        typed_resolver=_assignment("typed_resolver", "resolver"),
        admission_control=_assignment("admission_control", "admission"),
        revocation_control=_assignment("independent_control", "control"),
    )
    catalog = build_authoritative_action_catalog_revision(
        **common,
        catalog_id="catalog:actions",
        catalog_version="1.0.0",
        registry_sha256=_digest("9"),
        entries=[
            {
                "action_type": "api.request",
                "maximum_action_tier": "R4",
                "target_kinds": ["web_api"],
                "supported_environments": ["live"],
                "parameter_schema_sha256": _digest("a"),
                "tool_artifact_ref": "artifact:api-adapter",
                "tool_artifact_sha256": _digest("b"),
                "tool_exact_version": "1.0.0",
                "adapter_kind": "http",
                "r4_executor_supported": True,
            }
        ],
    )
    target = build_authoritative_target_descriptor_revision(
        **common,
        target_descriptor_id="target-descriptor:001",
        target_id="target:001",
        target_sha256=_digest("c"),
        target_kind="web_api",
        environment="live",
        scope_sha256=_digest("5"),
        authority_snapshot_sha256=_digest("6"),
        evidence_snapshot_sha256=_digest("7"),
        allowed_action_types=["api.request"],
        maximum_action_tier="R4",
    )
    budget = build_action_budget_policy_revision(
        **common,
        budget_id="budget:mission:001",
        scope_sha256=_digest("5"),
        limits=_resources(10_000),
        per_action_ceiling={**_resources(1_000), "impact_events": 1},
    )
    safety = build_action_safety_policy_revision(
        **common,
        safety_policy_id="safety:mission:001",
        scope_sha256=_digest("5"),
        target_sha256=_digest("c"),
        action_types=["api.request"],
        maximum_action_tier="R4",
        stop_conditions=["monitor_loss", "scope_drift"],
        impact_limits={
            "maximum_duration_ms": 10_000,
            "maximum_impact_events": 1,
            "maximum_request_bytes": 65_536,
            "maximum_response_bytes": 262_144,
        },
        monitor={
            "monitor_id": "monitor:001",
            "principal_profile_id": "profile:monitor",
            "principal_subject": "subject:monitor",
            "heartbeat_timeout_seconds": 5,
            "required": True,
        },
        deadline={"hard_deadline_required": True, "maximum_duration_ms": 10_000},
        restoration={
            "required": True,
            "restoration_plan_sha256": _digest("d"),
            "owner_profile_id": "profile:restoration-owner",
            "owner_subject": "subject:restoration-owner",
            "verifier_profile_id": "profile:restoration-verifier",
            "verifier_subject": "subject:restoration-verifier",
            "completion_evidence_required": True,
        },
    )
    proposal = build_authenticated_proposal_material_import(
        product=_work_product(),
        tenant_id="tenant:001",
        workspace_id="workspace:001",
        review_snapshot_id="review-snapshot:001",
        review_snapshot_sha256=_digest("e"),
        review_closure_id="review-closure:001",
        review_closure_sha256=_digest("f"),
        catalog=catalog,
        target=target,
        parameter_set_id="parameters:001",
        parameter_set_sha256=_digest("0"),
        selected_action_type="api.request",
        requested_action_tier="R3",
        imported_at="2026-09-21T10:29:00Z",
    )
    bundle = build_exact_action_source_head_bundle(
        policy=policy,
        catalog=catalog,
        target=target,
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
        workspace_high_water_sha256=_digest("6"),
        review_closure_projection_sha256=_digest("d"),
        review_revocation_head_sha256=_digest("e"),
        budget_policy_binding_sequence=1,
        budget_policy_binding_sha256=_digest("0"),
        budget_ledger_head_sha256=_digest("f"),
        session_authority_id="session-authority:001",
        session_authority_sha256=_digest("7"),
        execution_session_id="session:001",
        execution_session_sha256=_digest("8"),
        owner_epoch=4,
        fence_generation=9,
        credential_lease_sha256=_digest("9"),
        health_observation_sha256=_digest("a"),
        executor_deployment_sha256=_digest("b"),
        monitor_observation_sha256=_digest("c"),
        observed_at="2026-09-21T10:30:00Z",
        valid_until="2026-09-21T10:31:00Z",
    )
    return policy, catalog, target, budget, safety, proposal, bundle


class ActionAuthorityContractsTests(unittest.TestCase):
    def test_all_records_are_deterministic_parseable_and_content_addressed(self) -> None:
        first = _records()
        second = _records()
        self.assertEqual(
            [(item.record_id, item.content_sha256) for item in first],
            [(item.record_id, item.content_sha256) for item in second],
        )
        for record in first:
            parsed = parse_action_authority_contract(record.document_json)
            self.assertEqual(type(parsed), type(record))
            self.assertEqual(parsed.document_json, record.document_json)

    def test_records_are_deeply_immutable_from_input_and_output(self) -> None:
        records = _records()
        catalog = records[1]
        output = catalog.to_dict()
        output["entries"][0]["action_type"] = "changed.action"
        self.assertEqual(catalog.to_dict()["entries"][0]["action_type"], "api.request")
        with self.assertRaisesRegex(Exception, "cannot assign"):
            catalog.document_json = "{}"  # type: ignore[misc]

        entries = [copy.deepcopy(catalog.to_dict()["entries"][0])]
        rebuilt = build_authoritative_action_catalog_revision(
            tenant_id="tenant:001",
            mission_id="mission:001",
            plan_id="plan:001",
            catalog_id="catalog:immutability",
            catalog_version="1.0.0",
            registry_sha256=_digest("1"),
            entries=entries,
            revision=1,
            previous_revision_sha256=None,
            effective_at="2026-09-21T10:00:00Z",
            expires_at="2026-09-21T12:00:00Z",
            revocation_policy_sha256=_digest("2"),
        )
        entries[0]["action_type"] = "changed.action"
        self.assertEqual(rebuilt.to_dict()["entries"][0]["action_type"], "api.request")

    def test_unknown_fields_duplicate_keys_and_address_tamper_fail_closed(self) -> None:
        policy = _records()[0]
        value = policy.to_dict()
        value["unknown"] = "rejected"
        with self.assertRaises(ActionAuthorityContractError):
            ActionAuthorityPolicyRevision.from_dict(value)
        value = policy.to_dict()
        value["policy_id"] = "policy:substitution"
        with self.assertRaisesRegex(ActionAuthorityContractError, "content address"):
            ActionAuthorityPolicyRevision.from_dict(value)
        duplicate = policy.document_json.replace('"kind":', '"kind":"substituted","kind":', 1)
        with self.assertRaisesRegex(ActionAuthorityContractError, "canonical JSON"):
            ActionAuthorityPolicyRevision.from_dict(duplicate)
        with self.assertRaisesRegex(ActionAuthorityContractError, "byte ceiling"):
            parse_action_authority_contract("{" + " " * 262_144 + "}")

    def test_control_hidden_and_non_normalized_text_fail_closed(self) -> None:
        target = _records()[2].to_dict()
        for bad in ("target:\u202e001", "targe\u0301t"):
            changed = copy.deepcopy(target)
            changed["target_id"] = bad
            with self.assertRaises(ActionAuthorityContractError):
                AuthoritativeTargetDescriptorRevision.from_dict(changed)

    def test_bool_integer_substitution_and_r5_are_rejected(self) -> None:
        bundle = _records()[-1].to_dict()
        bundle["active_plan_version"] = True
        with self.assertRaises(ActionAuthorityContractError):
            ExactActionSourceHeadBundle.from_dict(bundle)
        target = _records()[2].to_dict()
        target["maximum_action_tier"] = "R5"
        with self.assertRaisesRegex(ActionAuthorityContractError, "R0 through R4"):
            AuthoritativeTargetDescriptorRevision.from_dict(target)

    def test_revision_lineage_and_chronology_are_exact(self) -> None:
        common = {
            "tenant_id": "tenant:001",
            "mission_id": "mission:001",
            "plan_id": "plan:001",
            "policy_id": "policy:001",
            "typed_resolver": _assignment("typed_resolver", "resolver"),
            "admission_control": _assignment("admission_control", "admission"),
            "revocation_control": _assignment("independent_control", "control"),
            "effective_at": "2026-09-21T10:00:00Z",
            "expires_at": "2026-09-21T12:00:00Z",
            "revocation_policy_sha256": _digest("1"),
        }
        with self.assertRaisesRegex(ActionAuthorityContractError, "predecessor"):
            build_action_authority_policy_revision(
                **common, revision=1, previous_revision_sha256=_digest("2")
            )
        with self.assertRaisesRegex(ActionAuthorityContractError, "expiry"):
            build_action_authority_policy_revision(
                **{**common, "expires_at": common["effective_at"]},
                revision=1,
                previous_revision_sha256=None,
            )

    def test_authority_assignments_require_role_profile_subject_and_issuer_separation(self) -> None:
        policy = _records()[0].to_dict()
        policy["admission_control"]["role"] = "typed_resolver"
        with self.assertRaisesRegex(ActionAuthorityContractError, "role"):
            ActionAuthorityPolicyRevision.from_dict(policy)
        policy = _records()[0].to_dict()
        policy["typed_resolver"]["principal_subject"] = "issuer:root"
        with self.assertRaisesRegex(ActionAuthorityContractError, "issuer"):
            ActionAuthorityPolicyRevision.from_dict(policy)
        policy = _records()[0].to_dict()
        policy["typed_resolver"]["principal_profile_id"] = policy["admission_control"][
            "principal_profile_id"
        ]
        with self.assertRaisesRegex(ActionAuthorityContractError, "reuse"):
            ActionAuthorityPolicyRevision.from_dict(policy)

    def test_catalog_requires_sorted_unique_action_types_and_explicit_r4_support(self) -> None:
        catalog = _records()[1].to_dict()
        catalog["entries"][0]["r4_executor_supported"] = False
        with self.assertRaisesRegex(ActionAuthorityContractError, "R4"):
            AuthoritativeActionCatalogRevision.from_dict(catalog)
        catalog = _records()[1].to_dict()
        catalog["entries"].append(copy.deepcopy(catalog["entries"][0]))
        with self.assertRaisesRegex(ActionAuthorityContractError, "sorted and unique"):
            AuthoritativeActionCatalogRevision.from_dict(catalog)

    def test_budget_has_exact_six_axes_and_per_action_ceiling(self) -> None:
        budget = _records()[3].to_dict()
        del budget["limits"]["impact_events"]
        with self.assertRaises(ActionAuthorityContractError):
            ActionBudgetPolicyRevision.from_dict(budget)
        budget = _records()[3].to_dict()
        budget["per_action_ceiling"]["duration_ms"] = 10_001
        with self.assertRaisesRegex(ActionAuthorityContractError, "stable budget"):
            ActionBudgetPolicyRevision.from_dict(budget)

    def test_safety_requires_monitor_deadline_and_independent_restoration(self) -> None:
        safety = _records()[4].to_dict()
        safety["monitor"]["required"] = False
        with self.assertRaisesRegex(ActionAuthorityContractError, "monitor"):
            ActionSafetyPolicyRevision.from_dict(safety)
        safety = _records()[4].to_dict()
        safety["deadline"]["maximum_duration_ms"] += 1
        with self.assertRaisesRegex(ActionAuthorityContractError, "duration"):
            ActionSafetyPolicyRevision.from_dict(safety)
        safety = _records()[4].to_dict()
        safety["restoration"]["verifier_subject"] = safety["restoration"]["owner_subject"]
        with self.assertRaisesRegex(ActionAuthorityContractError, "independent"):
            ActionSafetyPolicyRevision.from_dict(safety)

    def test_phase188_product_and_review_material_are_recomputed(self) -> None:
        proposal = _records()[5].to_dict()
        proposal["reviewed_product"]["payload"]["work_id"] = "work:substitution"
        with self.assertRaises(ActionAuthorityContractError):
            AuthenticatedProposalMaterialImport.from_dict(proposal)
        proposal = _records()[5].to_dict()
        proposal["reviewed_product"]["independent_review"]["status"] = "accepted"
        with self.assertRaisesRegex(ActionAuthorityContractError, "nonauthoritative"):
            AuthenticatedProposalMaterialImport.from_dict(proposal)

    def test_proposal_import_requires_catalog_target_tier_and_reviewed_action_binding(self) -> None:
        _, catalog, target, *_ = _records()
        with self.assertRaisesRegex(ActionAuthorityContractError, "absent"):
            build_authenticated_proposal_material_import(
                product=_work_product(),
                tenant_id="tenant:001",
                workspace_id="workspace:001",
                review_snapshot_id="snapshot:001",
                review_snapshot_sha256=_digest("1"),
                review_closure_id="closure:001",
                review_closure_sha256=_digest("2"),
                catalog=catalog,
                target=target,
                parameter_set_id="parameters:001",
                parameter_set_sha256=_digest("3"),
                selected_action_type="api.delete",
                requested_action_tier="R3",
                imported_at="2026-09-21T10:29:00Z",
            )
        with self.assertRaisesRegex(ActionAuthorityContractError, "reviewed proposal"):
            build_authenticated_proposal_material_import(
                product=_work_product(),
                tenant_id="tenant:001",
                workspace_id="workspace:001",
                review_snapshot_id="snapshot:001",
                review_snapshot_sha256=_digest("1"),
                review_closure_id="closure:001",
                review_closure_sha256=_digest("2"),
                catalog=catalog,
                target=target,
                parameter_set_id="parameters:001",
                parameter_set_sha256=_digest("3"),
                selected_action_type="api.request",
                requested_action_tier="R4",
                imported_at="2026-09-21T10:29:00Z",
            )

    def test_source_bundle_rejects_stale_cross_scope_and_future_material(self) -> None:
        policy, catalog, target, budget, safety, proposal, _ = _records()
        arguments = {
            "policy": policy,
            "catalog": catalog,
            "target": target,
            "budget": budget,
            "safety": safety,
            "proposal": proposal,
            "active_plan_sha256": _digest("1"),
            "active_plan_version": 2,
            "mission_revision": 7,
            "mission_policy_sha256": _digest("2"),
            "trust_policy_sha256": _digest("3"),
            "scope_grant_sha256": _digest("4"),
            "scope_revocation_head_sha256": _digest("5"),
            "workspace_high_water_sha256": _digest("6"),
            "review_closure_projection_sha256": _digest("d"),
            "review_revocation_head_sha256": _digest("e"),
            "budget_policy_binding_sequence": 1,
            "budget_policy_binding_sha256": _digest("0"),
            "budget_ledger_head_sha256": _digest("f"),
            "session_authority_id": "session-authority:001",
            "session_authority_sha256": _digest("7"),
            "execution_session_id": "session:001",
            "execution_session_sha256": _digest("8"),
            "owner_epoch": 4,
            "fence_generation": 9,
            "credential_lease_sha256": _digest("9"),
            "health_observation_sha256": _digest("a"),
            "executor_deployment_sha256": _digest("b"),
            "monitor_observation_sha256": _digest("c"),
            "observed_at": "2026-09-21T10:30:00Z",
            "valid_until": "2026-09-21T10:31:00Z",
        }
        mismatched = build_action_budget_policy_revision(
            tenant_id="tenant:001",
            mission_id="mission:001",
            plan_id="plan:001",
            budget_id="budget:other-scope",
            scope_sha256=_digest("f"),
            limits=_resources(10_000),
            per_action_ceiling=_resources(1_000),
            revision=1,
            previous_revision_sha256=None,
            effective_at="2026-09-21T10:00:00Z",
            expires_at="2026-09-21T12:00:00Z",
            revocation_policy_sha256=_digest("8"),
        )
        with self.assertRaisesRegex(ActionAuthorityContractError, "target boundary"):
            build_exact_action_source_head_bundle(**{**arguments, "budget": mismatched})
        with self.assertRaisesRegex(ActionAuthorityContractError, "after source observation"):
            build_exact_action_source_head_bundle(
                **{**arguments, "observed_at": "2026-09-21T09:59:59Z"}
            )
        with self.assertRaisesRegex(ActionAuthorityContractError, "outlives"):
            build_exact_action_source_head_bundle(
                **{**arguments, "valid_until": "2026-09-21T12:00:01Z"}
            )

    def test_all_schemas_are_closed_and_validate_every_record(self) -> None:
        schema = action_authority_contracts_schema()
        Draft202012Validator.check_schema(schema)

        def assert_closed(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False)
                for child in value.values():
                    assert_closed(child)
            elif isinstance(value, list):
                for child in value:
                    assert_closed(child)

        assert_closed(schema)
        for record in _records():
            specific = record_schema(record.KIND)
            Draft202012Validator.check_schema(specific)
            Draft202012Validator(specific).validate(record.to_dict())
            changed = record.to_dict()
            changed["unknown"] = "rejected"
            with self.assertRaises(ValidationError):
                Draft202012Validator(specific).validate(changed)

    def test_checked_in_schema_exactly_matches_the_runtime_builder(self) -> None:
        schema_path = (
            Path(__file__).parents[2]
            / "registry"
            / "schemas"
            / "action-authority-contracts-v1.schema.json"
        )
        checked_in = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(checked_in, action_authority_contracts_schema())

    def test_schema_and_runtime_both_exclude_r5(self) -> None:
        target = _records()[2].to_dict()
        target["maximum_action_tier"] = "R5"
        with self.assertRaises(ValidationError):
            Draft202012Validator(record_schema(target["kind"])).validate(target)
        with self.assertRaises(ActionAuthorityContractError):
            AuthoritativeTargetDescriptorRevision.from_dict(target)


if __name__ == "__main__":
    unittest.main()

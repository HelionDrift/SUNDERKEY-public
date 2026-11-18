"""Effect declarations cannot escape or mutate behind content addresses."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime

import sunderkey.advisory_asset_applicability as applicability
import sunderkey.advisory_transition_review as transitions
import sunderkey.api_role_response_matrix as matrices
import sunderkey.assessment_guidance as guidance
import sunderkey.assessment_transport_contracts as transports
import sunderkey.asset_reconciliation as assets
import sunderkey.attack_surface_discovery as discovery
import sunderkey.durable_scheduler_contracts as scheduler
import sunderkey.human_escalation_routing as routing
import sunderkey.impact_demonstration_policy as impact
import sunderkey.metadata_impact_review as metadata
import sunderkey.software_supply_chain_assessment as supply_chain
import sunderkey.surface_drift_detection as drift
import tests.agents.test_durable_scheduler_contracts_phase164 as scheduler_fixture
from tests.agents.test_assessment_guidance_phase171 import _request as guidance_request
from tests.agents.test_asset_reconciliation_phase208 import observation as asset_observation
from tests.agents.test_attack_surface_discovery_phase167 import plan as discovery_plan
from tests.agents.test_impact_demonstration_policy_phase172 import _request as impact_request
from tests.agents.test_software_supply_chain_assessment_phase167 import plan as supply_plan
from tests.agents.test_surface_drift_detection_phase162 import child_snapshot, root_snapshot

DIGEST = "sha256:" + "a" * 64
AT = "2026-09-23T13:00:00Z"


def scheduler_records():
    fixture = scheduler_fixture.DurableSchedulerContractsPhase164Tests()
    fixture.setUp()
    completion = scheduler.observe_completion(
        fixture.schedule, fixture.occurrence, fixture.lease,
        expected_lease_version=1, expected_fence_epoch=1, expected_occurrence_version=1,
        status="succeeded", observed_at="2026-09-20T00:05:00Z",
        evidence_sha256s=(), idempotency_key="idem:completion:ownership:0001",
    )
    recovery = scheduler.plan_expired_lease_recovery(
        fixture.schedule, fixture.occurrence, fixture.lease,
        expected_occurrence_version=1, recovered_at="2026-09-20T00:12:00Z",
        idempotency_key="idem:recovery:ownership:0001",
    )
    cancellation = scheduler.create_cancellation_record(
        fixture.schedule, target="schedule", expected_version=7,
        requested_at="2026-09-20T00:04:00Z", reason_code="scope_revoked",
        active_leases=(fixture.lease,), idempotency_key="idem:cancellation:ownership:0001",
    )
    return (
        fixture.retry, fixture.schedule, fixture.occurrence, fixture.lease,
        completion, recovery, cancellation,
    )


def exported_records():
    return (
        (applicability, applicability.AdvisoryApplicabilityReport(
            DIGEST, DIGEST, "tenant:one", AT, (), (),
        )),
        (transitions, transitions.AdvisoryTransitionReport(
            DIGEST, "tenant:one", DIGEST, DIGEST, DIGEST, DIGEST, AT, (),
        )),
        (matrices, matrices.ApiRoleResponseMatrix(
            DIGEST, "tenant:one", "context:one", DIGEST, "scope:one", DIGEST, AT, (),
        )),
        (routing, routing.plan_human_review(
            tenant_id="tenant:one", planned_at=AT, cases=(), roster=(),
        )),
        (metadata, metadata.review_data_metadata(
            tenant_id="tenant:one", scope_sha256=DIGEST, reviewed_at=AT, observations=(),
        )),
        (assets, assets.reconcile_asset_observations(
            "tenant:alpha", "2026-09-21T10:00:00Z",
            (asset_observation(assets.SourceKind.CMDB, "record-1"),),
        )),
        *((scheduler, record) for record in scheduler_records()),
    )


def empty_discovery_batch(plan):
    kinds = tuple(sorted(
        {kind for spec in plan.collectors for kind in spec.surface_kinds}, key=str,
    ))
    body = {
        "collected_at": "2026-09-20T10:30:00Z",
        "collector_ids": [plan.collectors[0].collector_id],
        "collector_result_sha256s": [DIGEST],
        "context": plan.context.to_dict(), "limits": plan.limits.to_dict(),
        "no_effects": dict(discovery.NO_EFFECTS), "observations": [],
        "plan_sha256": plan.plan_sha256,
        "planned_surface_kinds": [kind.value for kind in kinds],
        "run_nonce_sha256": plan.run_nonce_sha256,
    }
    digest = discovery._digest("sunderkey.attack-surface-batch.v1", body)
    return discovery.ObservationBatch(
        batch_id="ADB-" + digest[7:39].upper(), batch_sha256=digest,
        collected_at=body["collected_at"], collector_ids=tuple(body["collector_ids"]),
        collector_result_sha256s=(DIGEST,), context=plan.context, limits=plan.limits,
        no_effects=dict(discovery.NO_EFFECTS), observations=(), plan_sha256=plan.plan_sha256,
        planned_surface_kinds=kinds, run_nonce_sha256=plan.run_nonce_sha256,
    )


def owned_records():
    plan = discovery_plan()
    batch = empty_discovery_batch(plan)
    report = discovery.correlate_attack_surface(batch, generated_at="2026-09-20T11:00:00Z")
    prior = root_snapshot(())
    current = child_snapshot(prior, ())
    assessment = drift.assess_surface_drift(prior, current, assessed_at="2026-09-20T11:35:00Z")
    replans = drift.plan_revalidation(assessment, planned_at="2026-09-20T11:40:00Z")
    demonstration = impact.build_impact_demonstration_plan(
        impact_request(mode=impact.DemonstrationMode.OFF),
        evaluated_at=datetime(2026, 9, 20, 12, 5, tzinfo=UTC),
    )
    return (
        (supply_chain, supply_plan(), "no_effects", supply_chain.SupplyChainAssessmentError),
        (discovery, plan, "no_effects", discovery.AttackSurfaceDiscoveryError),
        (discovery, batch, "no_effects", discovery.AttackSurfaceDiscoveryError),
        (discovery, report, "no_effects", discovery.AttackSurfaceDiscoveryError),
        (drift, prior, "no_effects", drift.SurfaceDriftError),
        (drift, assessment, "no_effects", drift.SurfaceDriftError),
        (drift, replans, "no_effects", drift.SurfaceDriftError),
        (guidance, guidance.build_assessment_guidance(guidance_request()), "effects",
         guidance.AssessmentGuidanceError),
        (impact, demonstration, "effects", impact.ImpactDemonstrationPolicyError),
        (impact, impact.build_impact_demonstration_receipt(demonstration), "effects",
         impact.ImpactDemonstrationPolicyError),
    )


def transport_factories():
    return (
        lambda effects: transports.HttpResponseSpec(200, "application/json", 0, None,
                                                    effects=effects),
        lambda effects: transports.BrowserResultSpec(effects=effects),
        lambda effects: transports.SessionResultSpec("session:one", "principal:one",
                                                      effects=effects),
    )


class ExportedEffectOwnershipTests(unittest.TestCase):
    def test_each_export_has_a_fresh_dictionary_not_the_module_constant(self) -> None:
        for module, record in exported_records():
            with self.subTest(record=type(record).__name__):
                first = record.to_dict()
                second = record.to_dict()
                self.assertIsNot(first["effects"], module.NO_EFFECTS)
                self.assertIsNot(first["effects"], second["effects"])
                self.assertEqual(first, second)

    def test_update_remove_and_add_cannot_change_later_exports_or_constants(self) -> None:
        for module, record in exported_records():
            before = record.to_dict()
            constants = dict(module.NO_EFFECTS)
            with self.subTest(record=type(record).__name__):
                for mutation in ("update", "remove", "add"):
                    exported = record.to_dict()
                    self.assertIsNot(exported["effects"], module.NO_EFFECTS)
                    field = next(iter(constants))
                    if mutation == "update":
                        exported["effects"][field] = "grant"
                    elif mutation == "remove":
                        exported["effects"].pop(field)
                    else:
                        exported["effects"]["unexpected"] = "grant"
                    self.assertEqual(record.to_dict(), before)
                    self.assertEqual(module.NO_EFFECTS, constants)
                    self.assertEqual(replace(record).to_dict(), before)

    def test_all_seven_scheduler_contracts_round_trip_after_export_mutation(self) -> None:
        records = scheduler_records()
        self.assertEqual(len(records), 7)
        for record in records:
            with self.subTest(record=type(record).__name__):
                before = record.to_dict()
                changed = record.to_dict()
                self.assertIsNot(changed["effects"], scheduler.NO_EFFECTS)
                changed["effects"]["authorization"] = "grant"
                with self.assertRaises(scheduler.DurableSchedulerContractError):
                    scheduler.parse_contract(changed)
                restored = scheduler.parse_contract(json.loads(json.dumps(before)))
                self.assertEqual(restored.to_dict(), before)

    def test_nested_retry_declarations_are_independently_detached(self) -> None:
        retry, schedule, *_ = scheduler_records()
        before = schedule.to_dict()
        exported = schedule.to_dict()
        nested = exported["retry_plan"]["effects"]
        self.assertIsNot(nested, scheduler.NO_EFFECTS)
        self.assertIsNot(nested, exported["effects"])
        self.assertIsNot(nested, retry.to_dict()["effects"])
        nested["authorization"] = "grant"
        self.assertEqual(schedule.to_dict(), before)
        self.assertEqual(retry.to_dict(), before["retry_plan"])
        with self.assertRaises(scheduler.DurableSchedulerContractError):
            scheduler.parse_contract(exported)

    def test_reconciliation_parser_keeps_immutable_effects_after_export_mutation(self) -> None:
        record = next(record for module, record in exported_records() if module is assets)
        before = record.to_dict()
        changed = record.to_dict()
        self.assertIsNot(changed["effects"], assets.NO_EFFECTS)
        changed["effects"]["active_probing"] = True
        with self.assertRaises(assets.AssetReconciliationError):
            assets.AssetReconciliationSnapshot.from_dict(changed)
        self.assertEqual(assets.AssetReconciliationSnapshot.from_dict(before).to_dict(), before)
        self.assertEqual(record.to_dict(), before)


class ConstructorEffectOwnershipTests(unittest.TestCase):
    def test_all_ten_addressed_fields_copy_and_freeze_caller_maps(self) -> None:
        records = owned_records()
        self.assertEqual(len(records), 10)
        for module, record, field, _ in records:
            before = record.to_dict()
            constants = dict(module.NO_EFFECTS)
            caller = dict(getattr(record, field))
            replacement = replace(record, **{field: caller})
            with self.subTest(record=type(record).__name__):
                self.assertIsNot(getattr(replacement, field), caller)
                self.assertIsNot(getattr(replacement, field), module.NO_EFFECTS)
                caller[next(iter(caller))] = "grant"
                self.assertEqual(replacement.to_dict(), before)
                self.assertEqual(replace(replacement).to_dict(), before)
                with self.assertRaises(TypeError):
                    getattr(replacement, field)[next(iter(constants))] = "grant"
                self.assertEqual(module.NO_EFFECTS, constants)

    def test_source_maps_can_be_cleared_without_changing_addressed_records(self) -> None:
        for _, record, field, _ in owned_records():
            before = record.to_dict()
            caller = dict(getattr(record, field))
            replacement = replace(record, **{field: caller})
            with self.subTest(record=type(record).__name__):
                self.assertIsNot(getattr(replacement, field), caller)
                caller.clear()
                caller["extra"] = "grant"
                self.assertEqual(replacement.to_dict(), before)

    def test_available_parsers_detach_raw_effect_objects(self) -> None:
        checked = []
        for _, record, field, _ in owned_records():
            parser = getattr(type(record), "from_dict", None)
            if parser is None:
                continue
            raw = record.to_dict()
            before = copy.deepcopy(raw)
            restored = parser(raw)
            with self.subTest(record=type(record).__name__):
                self.assertIsNot(getattr(restored, field), raw[field])
                raw[field][next(iter(raw[field]))] = "grant"
                self.assertEqual(restored.to_dict(), before)
                self.assertEqual(replace(restored).to_dict(), before)
            checked.append(type(record).__name__)
        self.assertEqual(set(checked), {
            "AssessmentPlan", "DiscoveryReport", "SurfaceSnapshot", "DriftAssessment",
            "RevalidationPlanSet", "AssessmentGuidanceCard", "ImpactDemonstrationPlan",
            "ImpactDemonstrationReceipt",
        })

    def test_exports_remain_plain_json_and_detached_from_owned_declarations(self) -> None:
        for module, record, field, _ in owned_records():
            before = record.to_dict()
            exported = record.to_dict()
            with self.subTest(record=type(record).__name__):
                self.assertIs(type(exported[field]), dict)
                exported[field][next(iter(exported[field]))] = "grant"
                self.assertEqual(record.to_dict(), before)
                self.assertEqual(json.loads(json.dumps(before)), before)
                self.assertEqual(getattr(record, field), module.NO_EFFECTS)

    def test_invalid_declarations_are_not_replaced_with_no_effects(self) -> None:
        for _, record, field, error in owned_records():
            for mutation in (None, {}, {**getattr(record, field), "authority": "grant"}):
                with self.subTest(record=type(record).__name__, mutation=mutation):
                    with self.assertRaises(error):
                        replace(record, **{field: mutation})

    def test_nested_impact_receipt_and_plan_bindings_stay_unchanged(self) -> None:
        records = owned_records()
        plan = next(record for _, record, _, _ in records if isinstance(
            record, impact.ImpactDemonstrationPlan
        ))
        receipt = next(record for _, record, _, _ in records if isinstance(
            record, impact.ImpactDemonstrationReceipt
        ))
        self.assertEqual(receipt.plan_sha256, plan.plan_sha256)
        self.assertEqual(receipt.binding_sha256, plan.binding_sha256)
        self.assertEqual(receipt.qualification_effect, "none")
        self.assertEqual(impact.build_impact_demonstration_receipt(replace(plan)), receipt)

    def test_transport_specs_snapshot_non_none_declarations_without_laundering(self) -> None:
        for factory in transport_factories():
            caller = dict(transports.NO_EFFECTS)
            caller["authority"] = "grant"
            record = factory(caller)
            with self.subTest(record=type(record).__name__):
                self.assertIsNot(record.effects, caller)
                caller["authority"] = "none"
                self.assertEqual(record.effects["authority"], "grant")
                with self.assertRaises(transports.TransportContractError):
                    transports._require_no_effects(record.effects, "scripted declaration")
                with self.assertRaises(TypeError):
                    record.effects["authority"] = "none"
                self.assertEqual(transports.NO_EFFECTS["authority"], "none")

    def test_transport_specs_keep_no_effects_after_the_caller_changes_or_clears(self) -> None:
        for factory in transport_factories():
            caller = dict(transports.NO_EFFECTS)
            record = factory(caller)
            with self.subTest(record=type(record).__name__):
                self.assertIsNot(record.effects, caller)
                caller.clear()
                caller["authority"] = "grant"
                transports._require_no_effects(record.effects, "scripted declaration")
                self.assertEqual(record.effects, transports.NO_EFFECTS)
                self.assertIsNot(record.effects, factory(dict(transports.NO_EFFECTS)).effects)


if __name__ == "__main__":
    unittest.main()

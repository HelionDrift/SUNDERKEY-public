"""Phase 161 deterministic coverage coordinator and scheduler coverage."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey.coverage_scheduler as scheduler_module
from sunderkey.attack_world_model import (
    AttackEdge,
    AttackNode,
    EvidenceBinding,
    NodeKind,
    ObservationDelta,
    apply_observation_delta,
    build_attack_world_snapshot,
)
from sunderkey.coverage_capacity_rehearsal import (
    NO_EFFECTS as CAPACITY_NO_EFFECTS,
)
from sunderkey.coverage_capacity_rehearsal import (
    CapacityRehearsalError,
    bind_rehearsal_to_army_registry,
    plan_capacity_rehearsal,
    select_next_capacity_ready_task,
    verify_capacity_rehearsal,
    verify_registry_capacity_binding,
)
from sunderkey.coverage_scheduler import (
    NO_EFFECTS,
    CoverageSchedule,
    CoverageSchedulerError,
    OutcomeStatus,
    ProposedCoverageTask,
    SchedulingLimits,
    TaskType,
    compute_coverage_schedule,
    replan_coverage_schedule,
    select_next_ready_task,
)
from sunderkey.coverage_outcome_snapshot import (
    CoverageOutcomeSnapshotError,
    build_coverage_outcome_snapshot,
    prior_task_outcomes_from_snapshot,
    verify_coverage_outcome_snapshot,
)
from sunderkey.registry import load_registry
from sunderkey.signed_scope_compiler import (
    compile_signed_scope,
    verify_signed_scope,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "coverage-schedule-v1.schema.json"
OUTCOME_SCHEMA = ROOT / "registry" / "schemas" / "coverage-outcome-snapshot-v1.schema.json"
CAPACITY_SCHEMA = ROOT / "registry" / "schemas" / "coverage-capacity-rehearsal-v1.schema.json"
REGISTRY_CAPACITY_SCHEMA = (
    ROOT / "registry" / "schemas" / "registry-capacity-binding-v1.schema.json"
)
FILES = (
    ROOT / "src" / "sunderkey" / "coverage_scheduler.py",
    ROOT / "src" / "sunderkey" / "coverage_capacity_rehearsal.py",
    Path(__file__),
    SCHEMA,
    CAPACITY_SCHEMA,
    REGISTRY_CAPACITY_SCHEMA,
    ROOT / "docs" / "coverage-scheduler.md",
    ROOT / "docs" / "coverage-capacity-rehearsal.md",
)
NOW = datetime(2026, 9, 20, 3, 30, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TECHNIQUE = "TECH-001"


def base_specification() -> dict:
    return {
        "schema_version": 1,
        "issuer": "assessment-authority.example",
        "key_id": "scope-signing-key.2026-09",
        "nonce": "ABCDEFGHIJKLMNOP",
        "sequence_number": 1,
        "issued_at": "2026-09-20T03:00:00Z",
        "expires_at": "2026-09-20T05:00:00Z",
        "assessment_window": {
            "starts_at": "2026-09-20T03:00:00Z",
            "ends_at": "2026-09-20T04:30:00Z",
        },
        "targets": {
            "https_origins": ["https://api.example.test"],
            "exact_hosts": ["api.example.test"],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [443],
            "http_methods": ["GET"],
            "path_prefixes": ["/"],
        },
        "exclusions": [],
        "protected_endpoints": [],
        "budgets": {
            "max_requests": 100,
            "max_concurrency": 2,
            "max_requests_per_minute": 10,
        },
        "impact_tier_ceiling": "R2",
        "allowed_technique_ids": [TECHNIQUE],
        "data_handling": {
            "classification": "confidential",
            "collection": "minimized_content",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }


def evidence(
    state: str = "verified",
    *,
    observed_at: str = "2026-09-20T03:10:00Z",
    expires_at: str | None = None,
    digest: str = DIGEST_A,
) -> EvidenceBinding:
    return EvidenceBinding(
        provenance_artifact_digest=digest,
        observed_at=observed_at,
        confidence=0.8,
        verification_state=state,
        source_kind="artifact",
        expires_at=expires_at,
    )


class CoverageSchedulerPhase161Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.specification = base_specification()
        signed = compile_signed_scope(self.specification, self.private_key, now=NOW)
        self.scope = verify_signed_scope(
            signed,
            self.private_key.public_key(),
            expected_issuer=self.specification["issuer"],
            expected_key_id=self.specification["key_id"],
            now=NOW,
        )
        self.snapshot = self.make_snapshot(("asset:a", "asset:b"))
        self.capabilities = self.make_capabilities()
        self.validators = self.make_validators()
        self.limits = SchedulingLimits(
            as_of="2026-09-20T03:30:00Z",
            max_tasks=100,
            max_total_cost_units=100,
            max_total_requests=100,
            max_concurrency=2,
            max_tasks_per_asset=20,
            max_snapshot_age_seconds=3600,
            review_impact_tier="R2",
        )

    def make_snapshot(
        self,
        asset_ids: tuple[str, ...],
        *,
        scope_id: str | None = None,
        asset_evidence: EvidenceBinding | None = None,
        edge_state: str | None = None,
        edge_expires_at: str | None = None,
    ):
        scope_ref = self.scope.scope_id if scope_id is None else scope_id
        nodes = [
            AttackNode(
                node_id=asset_id,
                node_kind=NodeKind.ASSET,
                label=f"Asset {asset_id}",
                scope_refs=(scope_ref,),
                technique_refs=(),
                evidence=asset_evidence or evidence(),
            )
            for asset_id in asset_ids
        ]
        edges = []
        if edge_state is not None:
            nodes.append(
                AttackNode(
                    node_id="service:one",
                    node_kind=NodeKind.SERVICE,
                    label="Service one",
                    scope_refs=(scope_ref,),
                    technique_refs=(),
                    evidence=evidence(digest=DIGEST_B),
                )
            )
            edges.append(
                AttackEdge(
                    fact_id=f"fact:{edge_state}",
                    source_node_id=asset_ids[0],
                    target_node_id="service:one",
                    edge_kind="reachable",
                    scope_refs=(scope_ref,),
                    technique_refs=(TECHNIQUE,),
                    evidence=evidence(
                        edge_state,
                        digest=DIGEST_B,
                        expires_at=edge_expires_at,
                    ),
                )
            )
        return build_attack_world_snapshot(nodes, edges)

    def make_capabilities(self) -> dict:
        return {
            task_type.value: {
                "available": True,
                "specialist_profile_id": f"profile.{task_type.value}",
                "commander_id": "commander.one",
                "qualified_scope_ids": [self.scope.scope_id],
                "qualified_technique_ids": [TECHNIQUE],
                "impact_tier": "R2" if task_type is TaskType.SAFE_PROBE else "R0",
                "estimated_cost_units": 1,
                "estimated_requests": 1 if task_type is TaskType.SAFE_PROBE else 0,
                "stop_conditions": ["Stop on scope or evidence change."],
                "expected_evidence": ["Digest-bound observation reference."],
                "restoration_required": task_type is TaskType.SAFE_PROBE,
            }
            for task_type in TaskType
        }

    def make_validators(self) -> dict:
        task_types = [item.value for item in TaskType]
        return {
            f"validator.{role}": {
                "available": True,
                "role": role,
                "version": "1.0.0",
                "qualified_task_types": task_types,
                "qualified_scope_ids": [self.scope.scope_id],
                "max_impact_tier": "R5",
            }
            for role in ("evidence", "control", "assurance")
        }

    def schedule(self, **overrides):
        return compute_coverage_schedule(
            overrides.get("scope", self.scope),
            overrides.get("snapshot", self.snapshot),
            overrides.get("capabilities", self.capabilities),
            overrides.get("validators", self.validators),
            overrides.get("outcomes", {}),
            overrides.get("limits", self.limits),
        )

    def validator_capacity(self, schedule: CoverageSchedule, slots: int = 2) -> dict[str, int]:
        return {
            validator.validator_id: slots
            for task in schedule.tasks
            for validator in task.validators
        }

    def multi_technique_inputs(
        self,
        techniques: tuple[str, ...] = (TECHNIQUE, "TECH-002"),
        assets: tuple[str, ...] = ("asset:a", "asset:b"),
    ):
        specification = copy.deepcopy(self.specification)
        specification["allowed_technique_ids"] = list(techniques)
        signed = compile_signed_scope(specification, self.private_key, now=NOW)
        scope = verify_signed_scope(
            signed,
            self.private_key.public_key(),
            expected_issuer=specification["issuer"],
            expected_key_id=specification["key_id"],
            now=NOW,
        )
        snapshot = self.make_snapshot(assets, scope_id=scope.scope_id)
        validators = copy.deepcopy(self.validators)
        for item in validators.values():
            item["qualified_scope_ids"] = [scope.scope_id]
        return scope, snapshot, validators

    def test_deterministic_content_addressed_dag_and_schema(self) -> None:
        first = self.schedule()
        second = self.schedule()
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual({task.task_type for task in first.tasks}, set(TaskType))
        self.assertEqual(len({task.task_id for task in first.tasks}), len(first.tasks))
        self.assertTrue(all(task.scope_sha256 == self.scope.content_sha256 for task in first.tasks))
        self.assertTrue(
            all(task.world_snapshot_sha256 == self.snapshot.snapshot_sha256 for task in first.tasks)
        )
        CoverageSchedule.from_dict(first.to_dict())
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(first.to_dict())

    def test_budget_exhaustion_and_round_robin_asset_fairness(self) -> None:
        limits = SchedulingLimits(**{**self.limits.to_dict(), "max_tasks": 2})
        result = self.schedule(limits=limits)
        self.assertEqual([task.asset_ids[0] for task in result.tasks], ["asset:a", "asset:b"])
        self.assertEqual(
            {task.task_type for task in result.tasks},
            {TaskType.CONTEXT_COLLECTION},
        )
        self.assertIn("schedule_budget_exhausted", {item.code for item in result.blocked_reasons})

    def test_dependency_cycle_detection_fails_closed(self) -> None:
        base = self.schedule().tasks[0]
        id_a = "CST-" + "A" * 32
        id_b = "CST-" + "B" * 32
        task_a = ProposedCoverageTask(
            **{
                **base.__dict__,
                "task_id": id_a,
                "prerequisite_task_ids": (id_b,),
            }
        )
        task_b = ProposedCoverageTask(
            **{
                **base.__dict__,
                "task_id": id_b,
                "task_key": "sha256:" + "c" * 64,
                "prerequisite_task_ids": (id_a,),
            }
        )
        with self.assertRaisesRegex(CoverageSchedulerError, "cycle"):
            scheduler_module._assert_acyclic((task_a, task_b), set())

    def test_negative_evidence_suppresses_probe_and_restoration(self) -> None:
        negative = self.make_snapshot(("asset:a",), edge_state="negative")
        result = self.schedule(snapshot=negative)
        task_types = {item.task_type for item in result.tasks}
        self.assertNotIn(TaskType.SAFE_PROBE, task_types)
        self.assertNotIn(TaskType.RESTORATION_CHECK, task_types)
        self.assertIn("active_negative_evidence", {item.code for item in result.blocked_reasons})

    def test_verified_technique_evidence_covers_only_its_asset(self) -> None:
        snapshot = self.make_snapshot(("asset:a", "asset:b"), edge_state="verified")
        result = self.schedule(snapshot=snapshot)
        self.assertFalse(any(task.asset_ids == ("asset:a",) for task in result.tasks))
        self.assertEqual(
            {task.task_type for task in result.tasks if task.asset_ids == ("asset:b",)},
            set(TaskType),
        )

    def test_negative_evidence_does_not_suppress_other_asset_probes(self) -> None:
        snapshot = self.make_snapshot(("asset:a", "asset:b"), edge_state="negative")
        result = self.schedule(snapshot=snapshot)
        self.assertFalse(
            any(
                task.task_type is TaskType.SAFE_PROBE and task.asset_ids == ("asset:a",)
                for task in result.tasks
            )
        )
        self.assertTrue(
            any(
                task.task_type is TaskType.SAFE_PROBE and task.asset_ids == ("asset:b",)
                for task in result.tasks
            )
        )

    def test_hypothesis_priority_is_local_to_its_asset(self) -> None:
        snapshot = self.make_snapshot(("asset:a", "asset:b"), edge_state="hypothesis")
        result = self.schedule(snapshot=snapshot)
        a_priorities = {task.priority for task in result.tasks if task.asset_ids == ("asset:a",)}
        b_priorities = {task.priority for task in result.tasks if task.asset_ids == ("asset:b",)}
        self.assertGreaterEqual(min(a_priorities), 60)
        self.assertLess(max(b_priorities), 60)

    def test_stale_hypothesis_penalty_is_local_to_its_asset(self) -> None:
        snapshot = self.make_snapshot(
            ("asset:a", "asset:b"),
            edge_state="hypothesis",
            edge_expires_at="2026-09-20T03:20:00Z",
        )
        result = self.schedule(snapshot=snapshot)
        a_priorities = {task.priority for task in result.tasks if task.asset_ids == ("asset:a",)}
        b_priorities = {task.priority for task in result.tasks if task.asset_ids == ("asset:b",)}
        self.assertGreaterEqual(min(a_priorities), 80)
        self.assertLess(max(b_priorities), 60)

    def test_cross_asset_edge_is_owned_by_its_target(self) -> None:
        snapshot = build_attack_world_snapshot(
            [
                AttackNode(
                    node_id=asset_id,
                    node_kind=NodeKind.ASSET,
                    label=asset_id,
                    scope_refs=(self.scope.scope_id,),
                    technique_refs=(),
                    evidence=evidence(),
                )
                for asset_id in ("asset:a", "asset:b")
            ],
            [
                AttackEdge(
                    fact_id="fact:cross-asset",
                    source_node_id="asset:a",
                    target_node_id="asset:b",
                    edge_kind="reachable",
                    scope_refs=(self.scope.scope_id,),
                    technique_refs=(TECHNIQUE,),
                    evidence=evidence("verified", digest=DIGEST_B),
                )
            ],
        )
        result = self.schedule(snapshot=snapshot)
        self.assertTrue(any(task.asset_ids == ("asset:a",) for task in result.tasks))
        self.assertFalse(any(task.asset_ids == ("asset:b",) for task in result.tasks))

    def test_conflicting_evidence_blocks_only_affected_asset_probe(self) -> None:
        for positive_state in ("hypothesis", "verified"):
            with self.subTest(positive_state=positive_state):
                baseline = self.make_snapshot(
                    ("asset:a", "asset:b"), edge_state=positive_state
                )
                negative = AttackEdge(
                    fact_id="fact:conflicting-negative",
                    source_node_id="asset:a",
                    target_node_id="service:one",
                    edge_kind="reachable",
                    scope_refs=(self.scope.scope_id,),
                    technique_refs=(TECHNIQUE,),
                    evidence=evidence("negative", digest=DIGEST_A),
                )
                snapshot = build_attack_world_snapshot(
                    baseline.nodes, (*baseline.edges, negative)
                )
                self.assertEqual(len(snapshot.conflicts), 1)
                result = self.schedule(snapshot=snapshot)
                self.assertFalse(
                    any(
                        task.task_type is TaskType.SAFE_PROBE
                        and task.asset_ids == ("asset:a",)
                        for task in result.tasks
                    )
                )
                self.assertTrue(
                    any(
                        task.task_type is TaskType.VALIDATION
                        and task.asset_ids == ("asset:a",)
                        for task in result.tasks
                    )
                )
                self.assertTrue(
                    any(
                        task.task_type is TaskType.SAFE_PROBE
                        and task.asset_ids == ("asset:b",)
                        for task in result.tasks
                    )
                )
                self.assertIn(
                    "active_evidence_conflict",
                    {item.code for item in result.blocked_reasons},
                )

    def test_hypothesis_and_stale_hypothesis_are_deprioritized(self) -> None:
        active = self.make_snapshot(("asset:a",), edge_state="hypothesis")
        stale = self.make_snapshot(
            ("asset:a",),
            edge_state="hypothesis",
            edge_expires_at="2026-09-20T03:20:00Z",
        )
        active_schedule = self.schedule(snapshot=active)
        stale_schedule = self.schedule(snapshot=stale)
        self.assertGreaterEqual(min(item.priority for item in active_schedule.tasks), 60)
        self.assertGreater(
            min(item.priority for item in stale_schedule.tasks),
            min(item.priority for item in active_schedule.tasks),
        )

    def test_unavailable_and_unqualified_profiles_emit_blockers(self) -> None:
        unavailable = copy.deepcopy(self.capabilities)
        unavailable[TaskType.CONTEXT_COLLECTION.value]["available"] = False
        result = self.schedule(capabilities=unavailable)
        self.assertFalse(result.tasks)
        self.assertIn("capability_unavailable", {item.code for item in result.blocked_reasons})

        unqualified = copy.deepcopy(self.capabilities)
        unqualified[TaskType.CONTEXT_COLLECTION.value]["qualified_technique_ids"] = ["TECH-OTHER"]
        result = self.schedule(capabilities=unqualified)
        self.assertFalse(result.tasks)
        self.assertIn(
            "profile_technique_unqualified",
            {item.code for item in result.blocked_reasons},
        )

    def test_technique_routes_select_distinct_specialists_per_stage(self) -> None:
        scope, snapshot, validators = self.multi_technique_inputs()
        capabilities = {}
        for task_type, base in self.capabilities.items():
            routes = {}
            for technique, suffix in ((TECHNIQUE, "one"), ("TECH-002", "two")):
                route = copy.deepcopy(base)
                route["qualified_scope_ids"] = [scope.scope_id]
                route["qualified_technique_ids"] = [technique]
                route["specialist_profile_id"] = f"profile.{task_type}.{suffix}"
                route["commander_id"] = f"commander.{suffix}"
                routes[technique] = route
            capabilities[task_type] = {"default": None, "by_technique": routes}
        result = self.schedule(
            scope=scope, snapshot=snapshot, validators=validators, capabilities=capabilities
        )
        self.assertEqual({task.technique_ids[0] for task in result.tasks}, {TECHNIQUE, "TECH-002"})
        self.assertEqual(len(result.tasks), 24)
        for task in result.tasks:
            suffix = "one" if task.technique_ids == (TECHNIQUE,) else "two"
            self.assertEqual(
                task.required_specialist_profile_id, f"profile.{task.task_type.value}.{suffix}"
            )
            self.assertEqual(task.required_commander_id, f"commander.{suffix}")
        unknown = copy.deepcopy(capabilities)
        unknown[TaskType.PASSIVE_ANALYSIS.value]["by_technique"]["TECH-OTHER"] = copy.deepcopy(
            unknown[TaskType.PASSIVE_ANALYSIS.value]["by_technique"][TECHNIQUE]
        )
        with self.assertRaisesRegex(CoverageSchedulerError, "outside scope"):
            self.schedule(
                scope=scope, snapshot=snapshot, validators=validators, capabilities=unknown
            )
        missing = copy.deepcopy(capabilities)
        del missing[TaskType.SAFE_PROBE.value]["by_technique"]["TECH-002"]
        partial = self.schedule(
            scope=scope, snapshot=snapshot, validators=validators, capabilities=missing
        )
        self.assertTrue(
            any(
                task.task_type is TaskType.SAFE_PROBE and task.technique_ids == (TECHNIQUE,)
                for task in partial.tasks
            )
        )
        self.assertFalse(
            any(
                task.task_type is TaskType.SAFE_PROBE and task.technique_ids == ("TECH-002",)
                for task in partial.tasks
            )
        )
        self.assertIn("capability_unavailable", {item.code for item in partial.blocked_reasons})

    def test_technique_route_can_override_a_legacy_default(self) -> None:
        scope, snapshot, validators = self.multi_technique_inputs()
        capabilities = copy.deepcopy(self.capabilities)
        for task_type, base in capabilities.items():
            base["qualified_scope_ids"] = [scope.scope_id]
            base["qualified_technique_ids"] = [TECHNIQUE, "TECH-002"]
            override = copy.deepcopy(base)
            override["specialist_profile_id"] = f"profile.{task_type}.two"
            override["qualified_technique_ids"] = ["TECH-002"]
            capabilities[task_type] = {
                "default": base,
                "by_technique": {"TECH-002": override},
            }
        result = self.schedule(
            scope=scope, snapshot=snapshot, validators=validators, capabilities=capabilities
        )
        for task in result.tasks:
            if task.technique_ids == ("TECH-002",):
                self.assertEqual(
                    task.required_specialist_profile_id,
                    f"profile.{task.task_type.value}.two",
                )
            else:
                self.assertEqual(
                    task.required_specialist_profile_id,
                    f"profile.{task.task_type.value}",
                )

    def test_all_domain_commands_can_plan_distinct_offline_specialists(self) -> None:
        registry = load_registry(ROOT / "registry" / "army-v2.json")
        techniques = tuple(f"TECH-{index:03d}" for index in range(1, 26))
        scope, snapshot, validators = self.multi_technique_inputs(
            techniques=techniques, assets=("asset:a",)
        )
        limits = SchedulingLimits(
            **{
                **self.limits.to_dict(),
                "max_tasks": 200,
                "max_tasks_per_asset": 200,
                "max_total_cost_units": 200,
            }
        )
        capabilities = {}
        for task_type, base in self.capabilities.items():
            routes = {}
            for technique, command in zip(techniques, registry.commands, strict=True):
                route = copy.deepcopy(base)
                route["qualified_scope_ids"] = [scope.scope_id]
                route["qualified_technique_ids"] = [technique]
                route["specialist_profile_id"] = command.specialist_profile_ids[0]
                route["commander_id"] = command.commander_profile_id
                routes[technique] = route
            capabilities[task_type] = {"default": None, "by_technique": routes}
        schedule = self.schedule(
            scope=scope,
            snapshot=snapshot,
            validators=validators,
            capabilities=capabilities,
            limits=limits,
        )
        self.assertEqual(len(schedule.tasks), 150)
        self.assertEqual(len({task.required_specialist_profile_id for task in schedule.tasks}), 25)
        self.assertEqual(len({task.required_commander_id for task in schedule.tasks}), 25)
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={task.required_specialist_profile_id: 1 for task in schedule.tasks},
            commander_capacity={task.required_commander_id: 1 for task in schedule.tasks},
            validator_capacity=self.validator_capacity(schedule),
        )
        binding = bind_rehearsal_to_army_registry(schedule, rehearsal, registry)
        self.assertEqual(binding.task_count, 150)

    def test_unavailable_validator_and_review_gates(self) -> None:
        result = self.schedule()
        probe = next(item for item in result.tasks if item.task_type is TaskType.SAFE_PROBE)
        self.assertEqual(
            {item.role.value for item in probe.validators},
            {"evidence", "control", "assurance"},
        )
        validators = copy.deepcopy(self.validators)
        validators["validator.evidence"]["available"] = False
        blocked = self.schedule(validators=validators)
        self.assertFalse(blocked.tasks)
        self.assertIn("validator_unavailable", {item.code for item in blocked.blocked_reasons})

    def test_specialist_and_commander_cannot_validate_their_own_tasks(self) -> None:
        for forbidden_id in ("profile.context_collection", "commander.one"):
            with self.subTest(forbidden_id=forbidden_id):
                validators = copy.deepcopy(self.validators)
                evidence_validator = validators.pop("validator.evidence")
                validators[forbidden_id] = evidence_validator
                blocked = self.schedule(validators=validators)
                self.assertFalse(blocked.tasks)
                self.assertIn(
                    "validator_unavailable", {item.code for item in blocked.blocked_reasons}
                )
                validators["validator.evidence.backup"] = copy.deepcopy(evidence_validator)
                result = self.schedule(validators=validators)
                self.assertTrue(result.tasks)
                for task in result.tasks:
                    self.assertTrue(
                        {item.validator_id for item in task.validators}.isdisjoint(
                            {
                                task.required_specialist_profile_id,
                                task.required_commander_id,
                            }
                        )
                    )
        task_document = self.schedule().tasks[0].to_dict()
        task_document["validators"][0]["validator_id"] = task_document[
            "required_specialist_profile_id"
        ]
        with self.assertRaisesRegex(CoverageSchedulerError, "specialist or commander"):
            ProposedCoverageTask.from_dict(task_document)

    def test_scope_mismatch_and_unverified_scope_fail_closed(self) -> None:
        mismatch = self.make_snapshot(("asset:a",), scope_id="SAS-" + "0" * 32)
        result = self.schedule(snapshot=mismatch)
        self.assertFalse(result.tasks)
        self.assertIn("scope_mismatch", {item.code for item in result.blocked_reasons})
        signed = compile_signed_scope(self.specification, self.private_key, now=NOW)
        with self.assertRaisesRegex(CoverageSchedulerError, "VerifiedAssessmentScope"):
            self.schedule(scope=signed)

    def test_stale_snapshot_is_blocked(self) -> None:
        stale_evidence = evidence(observed_at="2026-09-20T03:00:00Z")
        stale_snapshot = self.make_snapshot(("asset:a",), asset_evidence=stale_evidence)
        limits = SchedulingLimits(**{**self.limits.to_dict(), "max_snapshot_age_seconds": 60})
        result = self.schedule(snapshot=stale_snapshot, limits=limits)
        self.assertFalse(result.tasks)
        self.assertEqual(result.blocked_reasons[0].code, "stale_world_snapshot")

    def test_replan_preserves_schedule_and_task_supersession_lineage(self) -> None:
        first = self.schedule()
        child = apply_observation_delta(
            self.snapshot,
            ObservationDelta(
                nodes=(
                    AttackNode(
                        node_id="finding:new",
                        node_kind=NodeKind.FINDING,
                        label="New finding",
                        scope_refs=(self.scope.scope_id,),
                        technique_refs=(),
                        evidence=evidence(digest=DIGEST_B),
                    ),
                )
            ),
        )
        second = replan_coverage_schedule(
            first,
            self.scope,
            child,
            self.capabilities,
            self.validators,
            {},
            self.limits,
        )
        self.assertEqual(second.parent_schedule_sha256, first.schedule_sha256)
        self.assertEqual(second.supersedes_schedule_id, first.schedule_id)
        self.assertTrue(all(task.supersedes_task_ids for task in second.tasks))
        with self.assertRaisesRegex(CoverageSchedulerError, "new immutable"):
            replan_coverage_schedule(
                first,
                self.scope,
                self.snapshot,
                self.capabilities,
                self.validators,
                {},
                self.limits,
            )

    def test_prior_success_deduplicates_equivalent_task(self) -> None:
        first = self.schedule()
        completed = first.tasks[0]
        outcome = {
            completed.task_id: {
                "task_key": completed.task_key,
                "status": OutcomeStatus.SUCCEEDED.value,
                "world_snapshot_sha256": self.snapshot.snapshot_sha256,
                "evidence_digests": [DIGEST_A],
            }
        }
        second = self.schedule(outcomes=outcome)
        self.assertNotIn(completed.task_id, {item.task_id for item in second.tasks})
        self.assertIn(completed.task_id, second.accepted_prior_outcome_ids)

    def test_prior_success_requires_evidence_and_unique_task_identity(self) -> None:
        completed = self.schedule().tasks[0]
        success = {
            "task_key": completed.task_key,
            "status": OutcomeStatus.SUCCEEDED.value,
            "world_snapshot_sha256": self.snapshot.snapshot_sha256,
            "evidence_digests": [DIGEST_A],
        }
        empty = {**success, "evidence_digests": []}
        with self.assertRaisesRegex(CoverageSchedulerError, "requires evidence"):
            self.schedule(outcomes={completed.task_id: empty})
        other_id = "CST-" + ("F" * 32)
        self.assertNotEqual(other_id, completed.task_id)
        with self.assertRaisesRegex(CoverageSchedulerError, "ambiguous"):
            self.schedule(
                outcomes={completed.task_id: success, other_id: copy.deepcopy(success)}
            )
        with self.assertRaisesRegex(CoverageSchedulerError, "ambiguous"):
            self.schedule(
                outcomes={other_id: copy.deepcopy(success), completed.task_id: success}
            )

    def test_outcome_snapshot_derives_keys_from_exact_prior_schedule(self) -> None:
        first = self.schedule()
        completed = first.tasks[0]
        document = build_coverage_outcome_snapshot(
            first,
            {
                completed.task_id: {
                    "status": "succeeded",
                    "evidence_digests": [DIGEST_A],
                }
            },
        )
        self.assertEqual(verify_coverage_outcome_snapshot(first, document), document)
        if Draft202012Validator is not None:
            schema = json.loads(OUTCOME_SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            self.assertFalse(list(Draft202012Validator(schema).iter_errors(document)))
        outcomes = prior_task_outcomes_from_snapshot(first, document)
        self.assertEqual(outcomes[completed.task_id]["task_key"], completed.task_key)
        second = self.schedule(outcomes=outcomes)
        self.assertIn(completed.task_id, second.accepted_prior_outcome_ids)
        with self.assertRaisesRegex(CoverageOutcomeSnapshotError, "requires evidence"):
            build_coverage_outcome_snapshot(
                first,
                {completed.task_id: {"status": "succeeded", "evidence_digests": []}},
            )
        with self.assertRaisesRegex(CoverageOutcomeSnapshotError, "unknown task"):
            build_coverage_outcome_snapshot(
                first,
                {"CST-" + "F" * 32: {"status": "failed", "evidence_digests": []}},
            )
        changed = copy.deepcopy(document)
        changed["outcomes"][0]["task_key"] = DIGEST_B
        with self.assertRaisesRegex(CoverageOutcomeSnapshotError, "does not match"):
            verify_coverage_outcome_snapshot(first, changed)
        duplicated = copy.deepcopy(document)
        duplicated["outcomes"].append(copy.deepcopy(duplicated["outcomes"][0]))
        with self.assertRaisesRegex(CoverageOutcomeSnapshotError, "duplicate task IDs"):
            verify_coverage_outcome_snapshot(first, duplicated)
        unrelated = self.schedule(snapshot=self.make_snapshot(("asset:other",)))
        with self.assertRaisesRegex(CoverageOutcomeSnapshotError, "unknown task"):
            verify_coverage_outcome_snapshot(unrelated, document)

    def test_changed_specialist_route_does_not_consume_old_success(self) -> None:
        first = self.schedule()
        completed = first.tasks[0]
        outcome = {
            completed.task_id: {
                "task_key": completed.task_key,
                "status": OutcomeStatus.SUCCEEDED.value,
                "world_snapshot_sha256": self.snapshot.snapshot_sha256,
                "evidence_digests": [DIGEST_A],
            }
        }
        changed = copy.deepcopy(self.capabilities)
        changed[completed.task_type.value]["specialist_profile_id"] = "profile.replacement"
        second = self.schedule(capabilities=changed, outcomes=outcome)
        replacement = next(
            task
            for task in second.tasks
            if task.task_type is completed.task_type
            and task.asset_ids == completed.asset_ids
            and task.technique_ids == completed.technique_ids
        )
        self.assertNotEqual(replacement.task_key, completed.task_key)
        self.assertEqual(replacement.required_specialist_profile_id, "profile.replacement")
        self.assertNotIn(completed.task_id, second.accepted_prior_outcome_ids)

    def test_ready_selection_obeys_dependencies_and_concurrency(self) -> None:
        result = self.schedule()
        first = select_next_ready_task(result, {})
        self.assertIsNotNone(first)
        assert first is not None
        state = {first.task_id: OutcomeStatus.SUCCEEDED}
        next_task = select_next_ready_task(result, state)
        self.assertIsNotNone(next_task)
        self.assertNotEqual(next_task.task_id, first.task_id)
        running = {
            task.task_id: OutcomeStatus.RUNNING
            for task in result.tasks[: result.effective_max_concurrency]
        }
        self.assertIsNone(select_next_ready_task(result, running))

    def test_ready_selection_rejects_contradictory_completion_state(self) -> None:
        result = self.schedule()
        dependent = next(task for task in result.tasks if task.prerequisite_task_ids)
        with self.assertRaisesRegex(CoverageSchedulerError, "prerequisites"):
            select_next_ready_task(result, {dependent.task_id: OutcomeStatus.SUCCEEDED})
        with self.assertRaisesRegex(CoverageSchedulerError, "prerequisites"):
            select_next_ready_task(result, {dependent.task_id: OutcomeStatus.RUNNING})
        three_assets = self.schedule(snapshot=self.make_snapshot(("asset:a", "asset:b", "asset:c")))
        roots = [task for task in three_assets.tasks if not task.prerequisite_task_ids]
        running = {
            task.task_id: OutcomeStatus.RUNNING
            for task in roots[: three_assets.effective_max_concurrency + 1]
        }
        with self.assertRaisesRegex(CoverageSchedulerError, "concurrency"):
            select_next_ready_task(three_assets, running)

    def test_accepted_prior_outcome_cannot_be_reclassified(self) -> None:
        first = self.schedule()
        completed = first.tasks[0]
        second = self.schedule(
            outcomes={
                completed.task_id: {
                    "task_key": completed.task_key,
                    "status": OutcomeStatus.SUCCEEDED.value,
                    "world_snapshot_sha256": self.snapshot.snapshot_sha256,
                    "evidence_digests": [DIGEST_A],
                }
            }
        )
        self.assertIsNotNone(select_next_ready_task(second, {}))
        with self.assertRaisesRegex(CoverageSchedulerError, "accepted prior outcome"):
            select_next_ready_task(second, {completed.task_id: OutcomeStatus.FAILED})

    def test_capacity_rehearsal_exposes_specialist_and_commander_contention(self) -> None:
        schedule = self.schedule()
        specialists = {task.required_specialist_profile_id: 2 for task in schedule.tasks}
        commanders = {task.required_commander_id: 2 for task in schedule.tasks}
        validators = self.validator_capacity(schedule)
        unconstrained = plan_capacity_rehearsal(
            schedule,
            specialist_capacity=specialists,
            commander_capacity=commanders,
            validator_capacity=validators,
        )
        self.assertEqual(unconstrained.additional_waves, 0)
        specialist_limited = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={key: 1 for key in specialists},
            commander_capacity=commanders,
            validator_capacity=validators,
        )
        commander_limited = plan_capacity_rehearsal(
            schedule,
            specialist_capacity=specialists,
            commander_capacity={key: 1 for key in commanders},
            validator_capacity=validators,
        )
        validator_limited = plan_capacity_rehearsal(
            schedule,
            specialist_capacity=specialists,
            commander_capacity=commanders,
            validator_capacity={key: 1 for key in validators},
        )
        self.assertGreater(specialist_limited.additional_waves, 0)
        self.assertGreater(commander_limited.additional_waves, 0)
        self.assertGreater(validator_limited.additional_waves, 0)
        self.assertEqual(len(specialist_limited.assignments), len(schedule.tasks))
        self.assertEqual(specialist_limited.to_dict()["effects"], CAPACITY_NO_EFFECTS)
        for wave in range(specialist_limited.rehearsal_wave_count):
            members = [
                item for item in specialist_limited.assignments if item.rehearsal_wave == wave
            ]
            self.assertLessEqual(len(members), schedule.effective_max_concurrency)
            for profile_id, limit in specialist_limited.specialist_capacity:
                self.assertLessEqual(
                    sum(item.specialist_profile_id == profile_id for item in members), limit
                )
            for commander_id, limit in specialist_limited.commander_capacity:
                self.assertLessEqual(
                    sum(item.commander_id == commander_id for item in members), limit
                )
            for validator_id, limit in specialist_limited.validator_capacity:
                self.assertLessEqual(
                    sum(validator_id in item.validator_ids for item in members), limit
                )
        self.assertEqual(
            verify_capacity_rehearsal(schedule, specialist_limited), specialist_limited
        )
        if Draft202012Validator is not None:
            schema = json.loads(CAPACITY_SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(specialist_limited.to_dict())

    def test_capacity_rehearsal_preserves_dependencies_and_rejects_tampering(self) -> None:
        schedule = self.schedule()
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={task.required_specialist_profile_id: 1 for task in schedule.tasks},
            commander_capacity={task.required_commander_id: 1 for task in schedule.tasks},
            validator_capacity=self.validator_capacity(schedule, 1),
        )
        waves = {item.task_id: item.rehearsal_wave for item in rehearsal.assignments}
        accepted = set(schedule.accepted_prior_outcome_ids)
        for task in schedule.tasks:
            self.assertGreaterEqual(waves[task.task_id], task.wave)
            for prerequisite in task.prerequisite_task_ids:
                if prerequisite not in accepted:
                    self.assertLess(waves[prerequisite], waves[task.task_id])
        tampered = copy.deepcopy(rehearsal.to_dict())
        tampered["assignments"][0]["rehearsal_wave"] += 1
        with self.assertRaisesRegex(CapacityRehearsalError, "content or identity"):
            verify_capacity_rehearsal(schedule, tampered)
        tampered = copy.deepcopy(rehearsal.to_dict())
        tampered["effects"]["dispatch"] = "allowed"
        with self.assertRaisesRegex(CapacityRehearsalError, "content or identity"):
            verify_capacity_rehearsal(schedule, tampered)
        with self.assertRaisesRegex(CapacityRehearsalError, "content or identity"):
            verify_capacity_rehearsal(
                self.schedule(snapshot=self.make_snapshot(("asset:a",))), rehearsal
            )

    def test_capacity_rehearsal_requires_exact_positive_profile_limits(self) -> None:
        schedule = self.schedule()
        specialists = {task.required_specialist_profile_id: 1 for task in schedule.tasks}
        commanders = {task.required_commander_id: 1 for task in schedule.tasks}
        validators = self.validator_capacity(schedule, 1)
        missing = dict(specialists)
        missing.pop(next(iter(missing)))
        for invalid in (
            missing,
            {**specialists, "extra.profile": 1},
            {key: 0 for key in specialists},
            {key: True for key in specialists},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(CapacityRehearsalError):
                plan_capacity_rehearsal(
                    schedule,
                    specialist_capacity=invalid,
                    commander_capacity=commanders,
                    validator_capacity=validators,
                )
        with self.assertRaisesRegex(CapacityRehearsalError, "validator_capacity"):
            plan_capacity_rehearsal(
                schedule,
                specialist_capacity=specialists,
                commander_capacity=commanders,
                validator_capacity={},
            )

    def test_capacity_rehearsal_handles_empty_schedule_without_claims(self) -> None:
        unavailable = copy.deepcopy(self.capabilities)
        unavailable[TaskType.CONTEXT_COLLECTION.value]["available"] = False
        schedule = self.schedule(capabilities=unavailable)
        self.assertFalse(schedule.tasks)
        result = plan_capacity_rehearsal(
            schedule, specialist_capacity={}, commander_capacity={}, validator_capacity={}
        )
        self.assertEqual(result.rehearsal_wave_count, 0)
        self.assertEqual(result.additional_waves, 0)
        self.assertEqual(verify_capacity_rehearsal(schedule, result), result)

    def test_army_registry_binding_checks_exact_command_membership(self) -> None:
        registry = load_registry(ROOT / "registry" / "army-v2.json")
        command = registry.commands[0]
        specialist_id = command.specialist_profile_ids[0]
        capabilities = copy.deepcopy(self.capabilities)
        for item in capabilities.values():
            item["specialist_profile_id"] = specialist_id
            item["commander_id"] = command.commander_profile_id
        schedule = self.schedule(capabilities=capabilities)
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={specialist_id: 1},
            commander_capacity={command.commander_profile_id: 1},
            validator_capacity=self.validator_capacity(schedule, 1),
        )
        binding = bind_rehearsal_to_army_registry(schedule, rehearsal, registry)
        self.assertEqual(binding.task_count, len(schedule.tasks))
        self.assertEqual(binding.to_dict()["qualification_effect"], "none")
        self.assertEqual(
            verify_registry_capacity_binding(schedule, rehearsal, registry, binding), binding
        )
        if Draft202012Validator is not None:
            schema = json.loads(REGISTRY_CAPACITY_SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(binding.to_dict())
        tampered = copy.deepcopy(binding.to_dict())
        tampered["catalog_sha256"] = DIGEST_B
        with self.assertRaisesRegex(CapacityRehearsalError, "content or identity"):
            verify_registry_capacity_binding(schedule, rehearsal, registry, tampered)
        other_commander = registry.commands[1].commander_profile_id
        for item in capabilities.values():
            item["commander_id"] = other_commander
        mismatched_schedule = self.schedule(capabilities=capabilities)
        mismatched_rehearsal = plan_capacity_rehearsal(
            mismatched_schedule,
            specialist_capacity={specialist_id: 1},
            commander_capacity={other_commander: 1},
            validator_capacity=self.validator_capacity(mismatched_schedule, 1),
        )
        with self.assertRaisesRegex(CapacityRehearsalError, "different commands"):
            bind_rehearsal_to_army_registry(mismatched_schedule, mismatched_rehearsal, registry)
        baseline_registry = load_registry(ROOT / "registry" / "army-v1.json")
        with self.assertRaisesRegex(CapacityRehearsalError, "451-profile Army v2"):
            bind_rehearsal_to_army_registry(schedule, rehearsal, baseline_registry)

    def test_capacity_ready_selector_respects_each_slot_boundary(self) -> None:
        schedule = self.schedule()
        specialist_ids = {task.required_specialist_profile_id for task in schedule.tasks}
        commander_ids = {task.required_commander_id for task in schedule.tasks}
        for constrained in ("specialist", "commander", "validator"):
            with self.subTest(constrained=constrained):
                rehearsal = plan_capacity_rehearsal(
                    schedule,
                    specialist_capacity={
                        item: 1 if constrained == "specialist" else 2 for item in specialist_ids
                    },
                    commander_capacity={
                        item: 1 if constrained == "commander" else 2 for item in commander_ids
                    },
                    validator_capacity=self.validator_capacity(
                        schedule, 1 if constrained == "validator" else 2
                    ),
                )
                first = select_next_capacity_ready_task(schedule, rehearsal, {})
                self.assertIsNotNone(first)
                assert first is not None
                self.assertIsNone(
                    select_next_capacity_ready_task(
                        schedule, rehearsal, {first.task_id: OutcomeStatus.RUNNING}
                    )
                )
                self.assertIsNotNone(
                    select_next_capacity_ready_task(
                        schedule, rehearsal, {first.task_id: OutcomeStatus.SUCCEEDED}
                    )
                )

    def test_capacity_ready_selector_rejects_bad_state_and_rehearsal(self) -> None:
        schedule = self.schedule()
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={task.required_specialist_profile_id: 2 for task in schedule.tasks},
            commander_capacity={task.required_commander_id: 2 for task in schedule.tasks},
            validator_capacity=self.validator_capacity(schedule),
        )
        dependent = next(task for task in schedule.tasks if task.prerequisite_task_ids)
        with self.assertRaisesRegex(CapacityRehearsalError, "completion state"):
            select_next_capacity_ready_task(
                schedule, rehearsal, {dependent.task_id: OutcomeStatus.RUNNING}
            )
        tampered = copy.deepcopy(rehearsal.to_dict())
        tampered["additional_waves"] += 1
        with self.assertRaisesRegex(CapacityRehearsalError, "content or identity"):
            select_next_capacity_ready_task(schedule, tampered, {})

    def test_capacity_ready_selector_rejects_running_profile_overcommit(self) -> None:
        schedule = self.schedule(snapshot=self.make_snapshot(("asset:a", "asset:b", "asset:c")))
        roots = [task for task in schedule.tasks if not task.prerequisite_task_ids]
        state = {task.task_id: OutcomeStatus.RUNNING for task in roots[:2]}
        for constrained in ("specialist", "commander", "validator"):
            with self.subTest(constrained=constrained):
                rehearsal = plan_capacity_rehearsal(
                    schedule,
                    specialist_capacity={
                        task.required_specialist_profile_id:
                        1 if constrained == "specialist" else 2
                        for task in schedule.tasks
                    },
                    commander_capacity={
                        task.required_commander_id: 1 if constrained == "commander" else 2
                        for task in schedule.tasks
                    },
                    validator_capacity=self.validator_capacity(
                        schedule, 1 if constrained == "validator" else 2
                    ),
                )
                with self.assertRaisesRegex(CapacityRehearsalError, "running state exceeds"):
                    select_next_capacity_ready_task(schedule, rehearsal, state)

    def test_capacity_ready_selector_can_skip_a_busy_profile(self) -> None:
        schedule = self.schedule(snapshot=self.make_snapshot(("asset:a", "asset:b", "asset:c")))
        rehearsal = plan_capacity_rehearsal(
            schedule,
            specialist_capacity={task.required_specialist_profile_id: 1 for task in schedule.tasks},
            commander_capacity={task.required_commander_id: 2 for task in schedule.tasks},
            validator_capacity=self.validator_capacity(schedule),
        )
        roots = sorted(
            (task for task in schedule.tasks if not task.prerequisite_task_ids),
            key=lambda task: task.asset_ids,
        )
        state = {
            roots[0].task_id: OutcomeStatus.SUCCEEDED,
            roots[2].task_id: OutcomeStatus.RUNNING,
        }
        selected = select_next_capacity_ready_task(schedule, rehearsal, state)
        self.assertIsNotNone(selected)
        assert selected is not None
        self.assertEqual(selected.task_type, TaskType.PASSIVE_ANALYSIS)
        self.assertEqual(selected.asset_ids, roots[0].asset_ids)

    def test_tamper_and_noncanonical_documents_fail_closed(self) -> None:
        document = self.schedule().to_dict()
        tampered = copy.deepcopy(document)
        tampered["tasks"][0]["estimated_cost_units"] += 1
        with self.assertRaisesRegex(CoverageSchedulerError, "identity"):
            CoverageSchedule.from_dict(tampered)
        extra = copy.deepcopy(document)
        extra["unexpected"] = True
        with self.assertRaisesRegex(CoverageSchedulerError, "fields"):
            CoverageSchedule.from_dict(extra)

    def test_secrets_and_impact_above_scope_are_never_scheduled(self) -> None:
        secret = copy.deepcopy(self.capabilities)
        secret[TaskType.CONTEXT_COLLECTION.value]["stop_conditions"] = [
            "password=do-not-store-this"
        ]
        with self.assertRaisesRegex(CoverageSchedulerError, "secret"):
            self.schedule(capabilities=secret)
        high_impact = copy.deepcopy(self.capabilities)
        high_impact[TaskType.CONTEXT_COLLECTION.value]["impact_tier"] = "R5"
        result = self.schedule(capabilities=high_impact)
        self.assertFalse(result.tasks)
        self.assertIn(
            "scope_impact_ceiling_exceeded",
            {item.code for item in result.blocked_reasons},
        )

    def test_all_documents_declare_every_no_effect_field(self) -> None:
        result = self.schedule()
        self.assertEqual(result.to_dict()["effects"], NO_EFFECTS)
        self.assertTrue(all(item.to_dict()["effects"] == NO_EFFECTS for item in result.tasks))
        forbidden = {
            "url",
            "method",
            "headers",
            "body",
            "payload",
            "credential",
            "credential_value",
            "command",
        }
        serialized = result.to_dict()

        def keys(value):
            if isinstance(value, dict):
                for key, member in value.items():
                    yield key
                    yield from keys(member)
            elif isinstance(value, list):
                for member in value:
                    yield from keys(member)

        self.assertFalse(forbidden & set(keys(serialized)))

    def test_source_files_have_no_dash_or_placeholder_markers(self) -> None:
        markers = (
            "TO" + "DO",
            "FIX" + "ME",
            "T" + "BD",
            "X" + "XX",
            "PLACE" + "HOLDER",
        )
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, str(path))
            self.assertNotIn("\u2014", text, str(path))
            for marker in markers:
                self.assertNotIn(marker, text, str(path))


if __name__ == "__main__":
    unittest.main()

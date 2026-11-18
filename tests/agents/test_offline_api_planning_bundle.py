"""Synthetic API evidence through Army planning without target effects."""

from __future__ import annotations

import copy
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.run_offline_api_assessment import _native_adapter, _prepare_case, run_case
import sunderkey.offline_api_planning_bundle as planning_module
from sunderkey.attack_world_model import AttackWorldSnapshot
from sunderkey.coverage_capacity_rehearsal import (
    bind_rehearsal_to_army_registry,
    plan_capacity_rehearsal,
)
from sunderkey.coverage_scheduler import (
    CoverageSchedule,
    SchedulingLimits,
    replan_coverage_schedule,
)
from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    API_TECHNIQUE_ID,
    OfflineApiCaseSource,
    build_offline_api_batch,
    evaluate_offline_api_case,
)
from sunderkey.offline_api_planning_bundle import (
    OfflineApiPlanningError,
    build_offline_api_planning_bundle,
    inspect_offline_api_planning_integrity,
    verify_offline_api_planning_bundle,
)
from sunderkey.offline_api_world_projection import (
    append_offline_api_world_projection,
    build_offline_api_world_projection,
)
from sunderkey.registry import load_registry
from sunderkey.signed_scope_compiler import (
    SignedAssessmentScope,
    VerifiedAssessmentScope,
    compile_signed_scope,
    verify_signed_scope,
)
from sunderkey.target_context import TargetContextProvenance, ingest_target_context_bytes

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "offline-api-assessment" / "corroborated-synthetic-case.json"
NEGATIVE_EXAMPLE = (
    ROOT / "examples" / "offline-api-assessment" / "denied-synthetic-retest-case.json"
)
OBSERVED = "2026-09-24T12:00:00Z"


def scope_specification() -> dict:
    return {
        "schema_version": 1,
        "issuer": "assessment-authority.example",
        "key_id": "scope-signing-key.2026-09",
        "nonce": "ABCDEFGHIJKLMNOP",
        "sequence_number": 1,
        "issued_at": "2026-09-24T11:30:00Z",
        "expires_at": "2026-09-24T15:00:00Z",
        "assessment_window": {
            "starts_at": "2026-09-24T11:45:00Z",
            "ends_at": "2026-09-24T14:30:00Z",
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
        "allowed_technique_ids": [API_TECHNIQUE_ID],
        "data_handling": {
            "classification": "confidential",
            "collection": "minimized_content",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }


class OfflineApiPlanningBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()
        cls.registry = load_registry(ROOT / "registry" / "army-v2.json")

    def setUp(self) -> None:
        signer = Ed25519PrivateKey.generate()
        specification = scope_specification()
        now = datetime(2026, 9, 24, 12, tzinfo=UTC)
        signed = compile_signed_scope(specification, signer, now=now)
        self.scope = verify_signed_scope(
            signed,
            signer.public_key(),
            expected_issuer=specification["issuer"],
            expected_key_id=specification["key_id"],
            now=now,
        )
        raw = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        raw["scope_id"] = self.scope.scope_id
        result = run_case(raw)
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        self.source = OfflineApiCaseSource(case_id, invocation, evidence, result)
        self.batch = build_offline_api_batch(
            adapter=self.adapter, sources=(self.source,)
        ).to_dict()
        profile = self.registry.profiles_by_id[self.adapter.manifest.profile_id]
        command = self.registry.commands_by_id[profile.command_id]
        self.profile_id = profile.id
        self.commander_id = command.commander_profile_id
        self.capabilities = {
            task_type: {
                "available": True,
                "specialist_profile_id": self.profile_id,
                "commander_id": self.commander_id,
                "qualified_scope_ids": [self.scope.scope_id],
                "qualified_technique_ids": [API_TECHNIQUE_ID],
                "impact_tier": "R0",
                "estimated_cost_units": 1,
                "estimated_requests": 0,
                "stop_conditions": ["Stop on scope or evidence change."],
                "expected_evidence": ["Digest-bound synthetic observation."],
                "restoration_required": False,
            }
            for task_type in (
                "context_collection",
                "passive_analysis",
                "safe_probe",
                "validation",
                "restoration_check",
                "retest_plan",
            )
        }
        self.validators = {
            f"validator.{role}": {
                "available": True,
                "role": role,
                "version": "1.0.0",
                "qualified_task_types": list(self.capabilities),
                "qualified_scope_ids": [self.scope.scope_id],
                "max_impact_tier": "R5",
            }
            for role in ("evidence", "control", "assurance")
        }
        self.limits = SchedulingLimits(
            as_of="2026-09-24T12:01:00Z",
            max_tasks=20,
            max_total_cost_units=20,
            max_total_requests=20,
            max_concurrency=2,
            max_tasks_per_asset=20,
            max_snapshot_age_seconds=3600,
            review_impact_tier="R0",
        )

    def options(self) -> dict:
        return {
            "adapter": self.adapter,
            "sources": (self.source,),
            "batch": self.batch,
            "scope": self.scope,
            "observed_at": OBSERVED,
            "expires_at": "2026-09-25T12:00:00Z",
            "capability_availability": self.capabilities,
            "validator_availability": self.validators,
            "limits": self.limits,
            "specialist_capacity": {self.profile_id: 1},
            "commander_capacity": {self.commander_id: 1},
            "validator_capacity": {
                f"validator.{role}": 1 for role in ("evidence", "control", "assurance")
            },
            "registry": self.registry,
        }

    def context(
        self, mission_id: str, authority_ref: str = "AUTH-SYNTHETIC-NONQUALIFYING"
    ):
        document = json.dumps(
            {
                "openapi": "3.1.0",
                "info": {"title": "Synthetic API", "version": "1"},
                "servers": [{"url": "https://api.example.test"}],
                "paths": {"/records/{id}": {"get": {}}},
            },
            sort_keys=True,
        ).encode("utf-8")
        return ingest_target_context_bytes(
            document,
            name="openapi.json",
            mission_id=mission_id,
            authority_ref=authority_ref,
            provenance=TargetContextProvenance(
                source_id="upload.offline.api",
                supplied_by="principal.operator.1",
                collected_at=OBSERVED,
            ),
        )

    def test_synthetic_signal_reaches_bound_rehearsal_only(self) -> None:
        options = self.options()
        bundle = build_offline_api_planning_bundle(**options)
        self.assertEqual(bundle["effects"]["target_execution"], "none")
        self.assertEqual(bundle["effects"]["finding_publication"], "none")
        self.assertEqual(len(bundle["schedule"]["tasks"]), 6)
        self.assertEqual(bundle["army_roster_binding"]["task_count"], 6)
        self.assertEqual(
            {
                edge["evidence"]["verification_state"]
                for edge in bundle["projection"]["snapshot"]["edges"]
            },
            {"hypothesis"},
        )
        self.assertEqual(
            verify_offline_api_planning_bundle(bundle=bundle, **options), bundle
        )

    def test_scope_relabeling_and_bundle_tampering_fail_closed(self) -> None:
        options = self.options()
        mismatched = json.loads(EXAMPLE.read_text(encoding="utf-8"))
        result = run_case(mismatched)
        case_id, invocation, evidence = _prepare_case(mismatched, self.adapter)
        source = OfflineApiCaseSource(case_id, invocation, evidence, result)
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        with self.assertRaisesRegex(OfflineApiPlanningError, "scope differ"):
            build_offline_api_planning_bundle(
                **{**options, "sources": (source,), "batch": batch}
            )
        bundle = build_offline_api_planning_bundle(**options)
        changed = copy.deepcopy(bundle)
        changed["effects"]["target_execution"] = "allowed"
        with self.assertRaisesRegex(OfflineApiPlanningError, "does not match"):
            verify_offline_api_planning_bundle(bundle=changed, **options)

    def test_negative_synthetic_result_suppresses_probe_proposal(self) -> None:
        raw = json.loads(NEGATIVE_EXAMPLE.read_text(encoding="utf-8"))
        raw["scope_id"] = self.scope.scope_id
        result = run_case(raw)
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        source = OfflineApiCaseSource(case_id, invocation, evidence, result)
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        bundle = build_offline_api_planning_bundle(
            **{**self.options(), "sources": (source,), "batch": batch}
        )
        task_types = {task["task_type"] for task in bundle["schedule"]["tasks"]}
        self.assertNotIn("safe_probe", task_types)
        self.assertNotIn("restoration_check", task_types)
        self.assertEqual(
            {
                edge["evidence"]["verification_state"]
                for edge in bundle["projection"]["snapshot"]["edges"]
            },
            {"negative"},
        )

    def test_mixed_synthetic_result_requires_conflict_review(self) -> None:
        raw = json.loads(NEGATIVE_EXAMPLE.read_text(encoding="utf-8"))
        raw["scope_id"] = self.scope.scope_id
        result = run_case(raw)
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        negative = OfflineApiCaseSource(case_id, invocation, evidence, result)
        sources = (self.source, negative)
        batch = build_offline_api_batch(adapter=self.adapter, sources=sources).to_dict()
        bundle = build_offline_api_planning_bundle(
            **{**self.options(), "sources": sources, "batch": batch}
        )
        self.assertEqual(len(bundle["projection"]["snapshot"]["conflicts"]), 1)
        task_types = {task["task_type"] for task in bundle["schedule"]["tasks"]}
        self.assertIn("validation", task_types)
        self.assertNotIn("safe_probe", task_types)
        self.assertNotIn("restoration_check", task_types)
        self.assertIn(
            "active_evidence_conflict",
            {item["code"] for item in bundle["schedule"]["blocked_reasons"]},
        )

    def test_target_context_is_bound_to_the_exact_batch_mission(self) -> None:
        context = self.context(self.batch["mission_id"])
        options = {**self.options(), "target_context": context}
        bundle = build_offline_api_planning_bundle(**options)
        self.assertEqual(bundle["target_context_sha256"], context.bundle_sha256)
        self.assertEqual(
            verify_offline_api_planning_bundle(bundle=bundle, **options), bundle
        )
        with self.assertRaisesRegex(OfflineApiPlanningError, "inputs are invalid"):
            build_offline_api_planning_bundle(
                **{**options, "target_context": self.context("MISSION-OTHER-001")}
            )
        with self.assertRaisesRegex(OfflineApiPlanningError, "inputs are invalid"):
            build_offline_api_planning_bundle(
                **{
                    **options,
                    "target_context": self.context(
                        self.batch["mission_id"], "AUTH-OTHER-NONQUALIFYING"
                    ),
                }
            )

    def test_receipt_source_scope_digest_matches_verified_scope(self) -> None:
        def sourced_case(scope_digest: str):
            records = tuple(
                EvidenceRecord.from_bytes(
                    record.evidence_id,
                    record.content,
                    media_type=record.media_type,
                    role=record.role,
                    status_code=record.status_code,
                    headers=record.headers,
                    attributes={
                        **dict(record.attributes),
                        "source_receipt_sha256": "sha256:" + str(index + 1) * 64,
                        "source_session_id": f"session.{index + 1}",
                        "source_scope_id": self.scope.scope_id,
                        "source_scope_sha256": scope_digest,
                        "source_target_id": self.source.invocation.target_id,
                        "source_target_sha256": "sha256:" + "e" * 64,
                    },
                )
                for index, record in enumerate(self.source.evidence)
            )
            result = evaluate_offline_api_case(
                adapter=self.adapter,
                case_id=self.source.case_id,
                invocation=self.source.invocation,
                evidence=records,
            )
            source = OfflineApiCaseSource(
                self.source.case_id, self.source.invocation, records, result.to_dict()
            )
            batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
            return source, batch

        source, batch = sourced_case(self.scope.content_sha256)
        options = {**self.options(), "sources": (source,), "batch": batch}
        bundle = build_offline_api_planning_bundle(**options)
        self.assertEqual(bundle["scope_sha256"], self.scope.content_sha256)
        source, batch = sourced_case("sha256:" + "f" * 64)
        with self.assertRaisesRegex(OfflineApiPlanningError, "scope digest differ"):
            build_offline_api_planning_bundle(
                **{**options, "sources": (source,), "batch": batch}
            )

    def test_archived_integrity_is_not_source_replay_or_use_approval(self) -> None:
        bundle = build_offline_api_planning_bundle(**self.options())
        report = inspect_offline_api_planning_integrity(
            bundle=bundle, registry=self.registry
        )
        self.assertEqual(report["status"], "valid_historical_integrity")
        self.assertFalse(report["source_replay_performed"])
        self.assertFalse(report["positive_use_approved"])
        self.assertEqual(report["bundle_sha256"], bundle["bundle_sha256"])
        changed = copy.deepcopy(bundle)
        changed["schedule"]["scope_sha256"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(OfflineApiPlanningError, "content identity"):
            inspect_offline_api_planning_integrity(
                bundle=changed, registry=self.registry
            )
        rebound = copy.deepcopy(bundle)
        rebound["scope_sha256"] = "sha256:" + "f" * 64
        body = {key: value for key, value in rebound.items() if key != "bundle_sha256"}
        rebound["bundle_sha256"] = planning_module._digest(
            {"domain": planning_module.BUNDLE_DOMAIN, "bundle": body}
        )
        with self.assertRaisesRegex(OfflineApiPlanningError, "source binding"):
            inspect_offline_api_planning_integrity(
                bundle=rebound, registry=self.registry
            )
        wrong_version = copy.deepcopy(bundle)
        wrong_version["schema_version"] = True
        body = {
            key: value for key, value in wrong_version.items() if key != "bundle_sha256"
        }
        wrong_version["bundle_sha256"] = planning_module._digest(
            {"domain": planning_module.BUNDLE_DOMAIN, "bundle": body}
        )
        with self.assertRaisesRegex(OfflineApiPlanningError, "policy fields"):
            inspect_offline_api_planning_integrity(
                bundle=wrong_version, registry=self.registry
            )

    def test_malformed_typed_scope_fails_closed(self) -> None:
        malformed = VerifiedAssessmentScope(
            signed_scope=SignedAssessmentScope('{"allowed_technique_ids":[]}'),
            verified_at=OBSERVED,
            verification_key_sha256="sha256:" + "a" * 64,
        )
        with self.assertRaisesRegex(OfflineApiPlanningError, "inputs are invalid"):
            build_offline_api_planning_bundle(
                **{**self.options(), "scope": malformed}
            )

    def test_negative_retest_replans_child_world_for_independent_review(self) -> None:
        first_bundle = build_offline_api_planning_bundle(**self.options())
        previous = CoverageSchedule.from_dict(first_bundle["schedule"])
        parent = AttackWorldSnapshot.from_dict(first_bundle["projection"]["snapshot"])
        raw = json.loads(NEGATIVE_EXAMPLE.read_text(encoding="utf-8"))
        raw["scope_id"] = self.scope.scope_id
        result = run_case(raw)
        case_id, invocation, evidence = _prepare_case(raw, self.adapter)
        negative = OfflineApiCaseSource(case_id, invocation, evidence, result)
        sources = (negative,)
        batch = build_offline_api_batch(adapter=self.adapter, sources=sources).to_dict()
        projection = build_offline_api_world_projection(
            adapter=self.adapter,
            sources=sources,
            batch=batch,
            observed_at="2026-09-24T12:00:30Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        child = append_offline_api_world_projection(
            parent_snapshot=parent,
            projection=projection,
            adapter=self.adapter,
            sources=sources,
            batch=batch,
            observed_at="2026-09-24T12:00:30Z",
            expires_at="2026-09-25T12:00:00Z",
        )
        replanned = replan_coverage_schedule(
            previous,
            self.scope,
            child,
            self.capabilities,
            self.validators,
            {},
            self.limits,
        )
        self.assertEqual(replanned.parent_schedule_sha256, previous.schedule_sha256)
        self.assertEqual(replanned.world_snapshot_sha256, child.snapshot_sha256)
        self.assertEqual(len(child.conflicts), 1)
        self.assertNotIn("safe_probe", {task.task_type.value for task in replanned.tasks})
        self.assertIn(
            "active_evidence_conflict",
            {item.code for item in replanned.blocked_reasons},
        )
        rehearsal = plan_capacity_rehearsal(
            replanned,
            specialist_capacity={self.profile_id: 1},
            commander_capacity={self.commander_id: 1},
            validator_capacity=self.options()["validator_capacity"],
        )
        binding = bind_rehearsal_to_army_registry(
            replanned, rehearsal, self.registry
        )
        self.assertEqual(binding.task_count, len(replanned.tasks))


if __name__ == "__main__":
    unittest.main()

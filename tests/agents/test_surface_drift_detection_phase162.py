"""Phase 162 attack-surface drift and revalidation contract tests."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.surface_drift_detection import (
    NO_EFFECTS,
    ChangeCertainty,
    ChangeKind,
    DriftAssessment,
    DriftLimits,
    ObservationState,
    PlanAction,
    PlanDisposition,
    RevalidationPlanSet,
    SurfaceDriftError,
    SurfaceKind,
    SurfaceObservation,
    SurfaceSnapshot,
    assess_surface_drift,
    build_surface_snapshot,
    canonical_json,
    plan_revalidation,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "surface-drift-assessment-v1.schema.json"
SCOPE = "sha256:" + "1" * 64
CONTENT_A = "sha256:" + "a" * 64
CONTENT_B = "sha256:" + "b" * 64
CONTENT_C = "sha256:" + "c" * 64
PROVENANCE_A = "sha256:" + "d" * 64
PROVENANCE_B = "sha256:" + "e" * 64


def observation(
    surface_id: str,
    *,
    kind: SurfaceKind | str = SurfaceKind.ENDPOINT,
    content: str = CONTENT_A,
    provenance: str = PROVENANCE_A,
    state: ObservationState | str = ObservationState.VERIFIED,
    observed_at: str = "2026-09-20T10:00:00Z",
    expires_at: str = "2026-09-21T10:00:00Z",
    scope: str = SCOPE,
    techniques: tuple[str, ...] = ("technique:http",),
    profiles: tuple[str, ...] = ("profile:web",),
    commanders: tuple[str, ...] = ("commander:application",),
    risk: int = 40,
) -> SurfaceObservation:
    return SurfaceObservation(
        surface_id=surface_id,
        surface_kind=kind,
        content_sha256=content,
        provenance_sha256=provenance,
        observed_at=observed_at,
        freshness_expires_at=expires_at,
        observation_state=state,
        scope_binding_sha256=scope,
        technique_ids=techniques,
        profile_ids=profiles,
        commander_ids=commanders,
        risk_score=risk,
    )


def root_snapshot(
    observations: tuple[SurfaceObservation, ...],
    *,
    protected: tuple[str, ...] = (),
    excluded: tuple[str, ...] = (),
    limits: DriftLimits | None = None,
) -> SurfaceSnapshot:
    return build_surface_snapshot(
        observations,
        captured_at="2026-09-20T10:30:00Z",
        scope_binding_sha256=SCOPE,
        protected_endpoint_ids=protected,
        excluded_surface_ids=excluded,
        limits=limits,
    )


def child_snapshot(
    parent: SurfaceSnapshot,
    observations: tuple[SurfaceObservation, ...],
    *,
    protected: tuple[str, ...] | None = None,
    excluded: tuple[str, ...] | None = None,
    captured_at: str = "2026-09-20T11:30:00Z",
) -> SurfaceSnapshot:
    return build_surface_snapshot(
        observations,
        captured_at=captured_at,
        scope_binding_sha256=SCOPE,
        parent=parent,
        protected_endpoint_ids=(parent.protected_endpoint_ids if protected is None else protected),
        excluded_surface_ids=parent.excluded_surface_ids if excluded is None else excluded,
    )


class SurfaceDriftDetectionPhase162Tests(unittest.TestCase):
    def test_all_surface_and_evidence_states_are_explicit(self) -> None:
        self.assertEqual(
            {item.value for item in SurfaceKind},
            {
                "asset",
                "endpoint",
                "schema",
                "identity",
                "trust_edge",
                "control",
                "deployment",
            },
        )
        self.assertEqual(
            {item.value for item in ObservationState},
            {"verified", "negative", "hypothesis", "abstained"},
        )

    def test_snapshot_is_content_addressed_and_input_order_independent(self) -> None:
        items = (
            observation("endpoint:z"),
            observation("asset:a", kind=SurfaceKind.ASSET),
        )
        first = root_snapshot(items)
        second = root_snapshot(tuple(reversed(items)))
        self.assertEqual(first, second)
        self.assertEqual(
            [item.surface_id for item in first.observations],
            ["asset:a", "endpoint:z"],
        )
        SurfaceSnapshot.from_dict(first.to_dict())
        self.assertEqual(canonical_json(first), canonical_json(second))

    def test_snapshot_rejects_tamper_and_noncanonical_arrays(self) -> None:
        snapshot = root_snapshot(
            (
                observation(
                    "endpoint:a",
                    techniques=("technique:z", "technique:a"),
                ),
            )
        )
        tampered = copy.deepcopy(snapshot.to_dict())
        tampered["observations"][0]["content_sha256"] = CONTENT_B
        with self.assertRaisesRegex(SurfaceDriftError, "identity"):
            SurfaceSnapshot.from_dict(tampered)

        noncanonical = copy.deepcopy(snapshot.to_dict())
        noncanonical["observations"][0]["technique_ids"].reverse()
        with self.assertRaisesRegex(SurfaceDriftError, "canonical"):
            SurfaceSnapshot.from_dict(noncanonical)

    def test_scope_binding_and_freshness_are_enforced(self) -> None:
        wrong_scope = observation("endpoint:a", scope="sha256:" + "2" * 64)
        with self.assertRaisesRegex(SurfaceDriftError, "scope binding"):
            root_snapshot((wrong_scope,))
        with self.assertRaisesRegex(SurfaceDriftError, "must follow"):
            observation(
                "endpoint:a",
                observed_at="2026-09-20T10:00:00Z",
                expires_at="2026-09-20T10:00:00Z",
            )

    def test_added_removed_and_changed_order_is_deterministic(self) -> None:
        baseline = root_snapshot(
            (
                observation("endpoint:removed", content=CONTENT_A),
                observation("schema:changed", kind=SurfaceKind.SCHEMA, content=CONTENT_A),
            )
        )
        current = child_snapshot(
            baseline,
            (
                observation("asset:added", kind=SurfaceKind.ASSET, content=CONTENT_C),
                observation(
                    "schema:changed",
                    kind=SurfaceKind.SCHEMA,
                    content=CONTENT_B,
                    provenance=PROVENANCE_B,
                ),
            ),
        )
        result = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        self.assertEqual(
            [(item.surface_id, item.change_kind) for item in result.changes],
            [
                ("asset:added", ChangeKind.ADDED),
                ("endpoint:removed", ChangeKind.REMOVED),
                ("schema:changed", ChangeKind.CHANGED),
            ],
        )
        removed = result.changes[1]
        self.assertEqual(removed.certainty, ChangeCertainty.UNCERTAIN_ABSENCE)
        self.assertIsNotNone(removed.before)
        self.assertIsNone(removed.after)
        self.assertEqual(
            set(result.changes[2].changed_fields),
            {"content_sha256", "provenance_sha256"},
        )

    def test_uncertainty_states_and_stale_provenance_are_preserved(self) -> None:
        for state in ObservationState:
            with self.subTest(state=state.value):
                baseline = root_snapshot((observation("endpoint:a"),))
                current = child_snapshot(
                    baseline,
                    (
                        observation(
                            "endpoint:a",
                            content=CONTENT_B,
                            state=state,
                        ),
                    ),
                )
                result = assess_surface_drift(
                    baseline,
                    current,
                    assessed_at="2026-09-20T12:00:00Z",
                )
                self.assertEqual(result.changes[0].certainty.value, state.value)

        baseline = root_snapshot((observation("endpoint:a"),))
        stale = observation(
            "endpoint:a",
            content=CONTENT_B,
            expires_at="2026-09-20T11:45:00Z",
        )
        current = child_snapshot(baseline, (stale,))
        result = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        self.assertEqual(result.changes[0].certainty, ChangeCertainty.STALE_PROVENANCE)
        self.assertEqual(result.triggers[0].reason, "stale_provenance")

    def test_lineage_rejects_rollback_gaps_and_scope_changes(self) -> None:
        baseline = root_snapshot((observation("endpoint:a"),))
        current = child_snapshot(
            baseline,
            (observation("endpoint:a", content=CONTENT_B),),
        )
        with self.assertRaisesRegex(SurfaceDriftError, "direct baseline descendant"):
            assess_surface_drift(
                current,
                baseline,
                assessed_at="2026-09-20T12:00:00Z",
            )
        with self.assertRaisesRegex(SurfaceDriftError, "scope"):
            build_surface_snapshot(
                (observation("endpoint:a"),),
                captured_at="2026-09-20T12:30:00Z",
                scope_binding_sha256="sha256:" + "3" * 64,
                parent=current,
            )
        with self.assertRaisesRegex(SurfaceDriftError, "must follow"):
            child_snapshot(
                baseline,
                (observation("endpoint:a", content=CONTENT_B),),
                captured_at="2026-09-20T10:00:00Z",
            )

    def test_protected_endpoints_and_exclusions_fail_closed(self) -> None:
        baseline = root_snapshot(
            (
                observation("endpoint:protected"),
                observation("endpoint:excluded"),
            ),
            protected=("endpoint:protected",),
            excluded=("endpoint:excluded",),
        )
        current = child_snapshot(
            baseline,
            (
                observation("endpoint:protected", content=CONTENT_B),
                observation("endpoint:excluded", content=CONTENT_B),
            ),
        )
        assessment = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        protected = next(
            item for item in assessment.triggers if item.surface_id == "endpoint:protected"
        )
        excluded = next(
            item for item in assessment.triggers if item.surface_id == "endpoint:excluded"
        )
        self.assertTrue(protected.notification_permitted)
        self.assertFalse(protected.rescan_permitted)
        self.assertFalse(excluded.notification_permitted)
        self.assertFalse(excluded.rescan_permitted)

        plan = plan_revalidation(
            assessment,
            planned_at="2026-09-20T12:01:00Z",
        )
        by_surface_action = {
            (item.surface_id, item.action): item.disposition for item in plan.records
        }
        self.assertEqual(
            by_surface_action[("endpoint:protected", PlanAction.NOTIFICATION)],
            PlanDisposition.PLANNED,
        )
        self.assertEqual(
            by_surface_action[("endpoint:protected", PlanAction.RESCAN)],
            PlanDisposition.BLOCKED,
        )
        self.assertEqual(
            by_surface_action[("endpoint:excluded", PlanAction.NOTIFICATION)],
            PlanDisposition.BLOCKED,
        )

        with self.assertRaisesRegex(SurfaceDriftError, "drop protected"):
            child_snapshot(
                baseline,
                baseline.observations,
                protected=(),
            )
        with self.assertRaisesRegex(SurfaceDriftError, "drop exclusions"):
            child_snapshot(
                baseline,
                baseline.observations,
                excluded=(),
            )

    def test_triggers_are_risk_weighted_and_bound_to_routing_ids(self) -> None:
        baseline = root_snapshot(
            (
                observation(
                    "trust:a",
                    kind=SurfaceKind.TRUST_EDGE,
                    techniques=("technique:a",),
                    profiles=("profile:a",),
                    commanders=("commander:a",),
                    risk=70,
                ),
            )
        )
        current = child_snapshot(
            baseline,
            (
                observation(
                    "trust:a",
                    kind=SurfaceKind.TRUST_EDGE,
                    content=CONTENT_B,
                    techniques=("technique:b",),
                    profiles=("profile:b",),
                    commanders=("commander:b",),
                    risk=80,
                ),
            ),
        )
        result = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        trigger = result.triggers[0]
        self.assertGreaterEqual(trigger.risk_score, 80)
        self.assertEqual(trigger.technique_ids, ("technique:a", "technique:b"))
        self.assertEqual(trigger.profile_ids, ("profile:a", "profile:b"))
        self.assertEqual(trigger.commander_ids, ("commander:a", "commander:b"))

    def test_plan_deduplication_and_cooldown_are_deterministic(self) -> None:
        baseline = root_snapshot((observation("endpoint:a"),))
        current = child_snapshot(
            baseline,
            (observation("endpoint:a", content=CONTENT_B),),
        )
        first_assessment = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        first_plan = plan_revalidation(
            first_assessment,
            planned_at="2026-09-20T12:01:00Z",
        )
        repeated = plan_revalidation(
            first_assessment,
            planned_at="2026-09-20T12:02:00Z",
            prior_records=first_plan.records,
        )
        self.assertEqual(
            {item.disposition for item in repeated.records},
            {PlanDisposition.DEDUPLICATED},
        )

        next_snapshot = child_snapshot(
            current,
            (observation("endpoint:a", content=CONTENT_C),),
            captured_at="2026-09-20T12:10:00Z",
        )
        second_assessment = assess_surface_drift(
            current,
            next_snapshot,
            assessed_at="2026-09-20T12:15:00Z",
        )
        cooldown = plan_revalidation(
            second_assessment,
            planned_at="2026-09-20T12:20:00Z",
            prior_records=first_plan.records,
            cooldown_seconds=3600,
        )
        self.assertEqual(
            {item.disposition for item in cooldown.records},
            {PlanDisposition.COOLDOWN_SUPPRESSED},
        )
        RevalidationPlanSet.from_dict(cooldown.to_dict())

    def test_diff_and_plan_limits_fail_closed(self) -> None:
        limits = DriftLimits(
            max_observations=2,
            max_changes=1,
            max_triggers=2,
            max_plan_records=2,
        )
        baseline = root_snapshot(
            (observation("endpoint:a"), observation("endpoint:b")),
            limits=limits,
        )
        current = child_snapshot(
            baseline,
            (
                observation("endpoint:a", content=CONTENT_B),
                observation("endpoint:b", content=CONTENT_B),
            ),
        )
        with self.assertRaisesRegex(SurfaceDriftError, "max_changes"):
            assess_surface_drift(
                baseline,
                current,
                assessed_at="2026-09-20T12:00:00Z",
            )
        with self.assertRaisesRegex(SurfaceDriftError, "max_observations"):
            root_snapshot(
                (
                    observation("endpoint:a"),
                    observation("endpoint:b"),
                    observation("endpoint:c"),
                ),
                limits=limits,
            )

        plan_limits = DriftLimits(
            max_observations=2,
            max_changes=1,
            max_triggers=1,
            max_plan_records=1,
        )
        plan_baseline = root_snapshot(
            (observation("endpoint:plan"),),
            limits=plan_limits,
        )
        plan_current = child_snapshot(
            plan_baseline,
            (observation("endpoint:plan", content=CONTENT_B),),
        )
        plan_assessment = assess_surface_drift(
            plan_baseline,
            plan_current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        with self.assertRaisesRegex(SurfaceDriftError, "max_plan_records"):
            plan_revalidation(
                plan_assessment,
                planned_at="2026-09-20T12:01:00Z",
            )

    def test_assessment_and_plan_tamper_are_rejected(self) -> None:
        baseline = root_snapshot((observation("endpoint:a"),))
        current = child_snapshot(
            baseline,
            (observation("endpoint:a", content=CONTENT_B),),
        )
        assessment = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        DriftAssessment.from_dict(assessment.to_dict())
        tampered = copy.deepcopy(assessment.to_dict())
        tampered["changes"][0]["risk_score"] = 1
        with self.assertRaisesRegex(SurfaceDriftError, "identity"):
            DriftAssessment.from_dict(tampered)

        plan = plan_revalidation(
            assessment,
            planned_at="2026-09-20T12:01:00Z",
        )
        tampered_plan = copy.deepcopy(plan.to_dict())
        tampered_plan["records"][0]["reason"] = "changed_reason"
        with self.assertRaisesRegex(SurfaceDriftError, "identity"):
            RevalidationPlanSet.from_dict(tampered_plan)

    def test_schema_accepts_assessment_and_rejects_unknown_fields(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        baseline = root_snapshot((observation("endpoint:a"),))
        current = child_snapshot(
            baseline,
            (observation("endpoint:a", content=CONTENT_B),),
        )
        assessment = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        Draft202012Validator(schema).validate(assessment.to_dict())
        invalid = copy.deepcopy(assessment.to_dict())
        invalid["unexpected"] = True
        self.assertTrue(list(Draft202012Validator(schema).iter_errors(invalid)))

    def test_contract_declares_no_external_effects(self) -> None:
        baseline = root_snapshot((observation("endpoint:a"),))
        current = child_snapshot(
            baseline,
            (observation("endpoint:a", content=CONTENT_B),),
        )
        assessment = assess_surface_drift(
            baseline,
            current,
            assessed_at="2026-09-20T12:00:00Z",
        )
        plan = plan_revalidation(
            assessment,
            planned_at="2026-09-20T12:01:00Z",
        )
        self.assertEqual(dict(baseline.no_effects), NO_EFFECTS)
        self.assertEqual(dict(assessment.no_effects), NO_EFFECTS)
        self.assertEqual(dict(plan.no_effects), NO_EFFECTS)
        source = (ROOT / "src" / "sunderkey" / "surface_drift_detection.py").read_text(
            encoding="utf-8"
        )
        for forbidden_import in (
            "import socket",
            "import requests",
            "import subprocess",
            "from urllib",
            "boto3",
        ):
            self.assertNotIn(forbidden_import, source)


if __name__ == "__main__":
    unittest.main()

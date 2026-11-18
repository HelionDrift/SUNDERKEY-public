from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

import sunderkey
from sunderkey.health_state_contracts import (
    NO_EFFECTS,
    ExecutionRecoveryAdmission,
    HealthContext,
    HealthSnapshot,
    HealthState,
    HealthStateContractError,
    ObservationStatus,
    ProbeDefinition,
    ProbeObservation,
    RecoveryAdmissionStatus,
    aggregate_health,
    evaluate_execution_recovery_admission,
    parse_contract,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    del loader, tests, pattern
    suite = unittest.TestSuite()
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            suite.addTest(unittest.FunctionTestCase(value))
    return suite


def _case() -> unittest.TestCase:
    return unittest.TestCase()


def test_public_package_exports_are_available() -> None:
    case = _case()
    case.assertIs(sunderkey.aggregate_health, aggregate_health)
    case.assertIs(
        sunderkey.evaluate_execution_recovery_admission,
        evaluate_execution_recovery_admission,
    )


def _context(*, mission: str = "missionref:mission-7") -> HealthContext:
    return HealthContext(
        tenant_ref="tenantref:acme",
        mission_ref=mission,
        worker_ref="workerref:worker-4",
        system_version="0.198.0",
        worker_version="3.2.1",
    )


def _definition(
    *,
    context: HealthContext | None = None,
    required: bool = True,
    failure_threshold: int = 2,
    recovery_threshold: int = 2,
) -> ProbeDefinition:
    return ProbeDefinition(
        context=context or _context(),
        probe_ref="proberef:postgres-readiness",
        dependency_ref="dependencyref:postgres-primary",
        probe_version="1.1.0",
        kind="dependency",
        required=required,
        interval_seconds=30,
        max_age_seconds=90,
        failure_threshold=failure_threshold,
        recovery_threshold=recovery_threshold,
        issued_at="2026-09-20T10:00:00Z",
    )


def _observation(
    definition: ProbeDefinition,
    *,
    sequence: int,
    status: ObservationStatus | str = ObservationStatus.PASS,
    observed_at: str = "2026-09-20T10:00:30Z",
    collected_at: str | None = None,
    detail_sha256: str = HASH_A,
    context: HealthContext | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        context=context or definition.context,
        definition_id=definition.definition_id,
        definition_sha256=definition.definition_sha256,
        probe_ref=definition.probe_ref,
        probe_version=definition.probe_version,
        sequence=sequence,
        status=status,
        observed_at=observed_at,
        collected_at=collected_at or observed_at,
        provenance_ref="provenanceref:collector-12",
        provenance_sha256=HASH_B,
        detail_sha256=detail_sha256,
    )


def _healthy_chain() -> tuple[HealthSnapshot, HealthSnapshot, ProbeDefinition]:
    definition = _definition()
    first = aggregate_health(
        (definition,),
        (_observation(definition, sequence=1),),
        evaluated_at="2026-09-20T10:00:40Z",
    )
    second = aggregate_health(
        (definition,),
        (
            _observation(
                definition,
                sequence=2,
                observed_at="2026-09-20T10:01:00Z",
            ),
        ),
        evaluated_at="2026-09-20T10:01:10Z",
        prior_snapshot=first,
    )
    return first, second, definition


def test_definitions_are_immutable_content_addressed_and_exactly_bound() -> None:
    case = _case()
    definition = _definition()
    case.assertTrue(definition.definition_id.startswith("HPD-"))
    case.assertEqual(definition, ProbeDefinition.from_dict(definition.to_dict()))
    with case.assertRaises((AttributeError, TypeError)):
        definition.required = False  # type: ignore[misc]
    tampered = definition.to_dict()
    tampered["failure_threshold"] = 3
    with case.assertRaises(HealthStateContractError):
        ProbeDefinition.from_dict(tampered)


def test_observation_serialization_provenance_and_closed_fields() -> None:
    case = _case()
    definition = _definition()
    observation = _observation(definition, sequence=9)
    serialized = json.dumps(observation.to_dict(), sort_keys=True)
    case.assertEqual(observation, parse_contract(serialized))
    case.assertEqual(HASH_B, observation.provenance_sha256)
    extra = observation.to_dict()
    extra["live"] = True
    with case.assertRaises(HealthStateContractError):
        ProbeObservation.from_dict(extra)


def test_freshness_boundary_is_inclusive_then_fails_closed() -> None:
    case = _case()
    definition = _definition(recovery_threshold=1)
    observation = _observation(
        definition,
        sequence=1,
        observed_at="2026-09-20T10:00:00Z",
    )
    boundary = aggregate_health(
        (definition,), (observation,), evaluated_at="2026-09-20T10:01:30Z"
    )
    case.assertEqual(HealthState.HEALTHY, boundary.state)
    stale = aggregate_health(
        (definition,), (observation,), evaluated_at="2026-09-20T10:01:31Z"
    )
    case.assertEqual(HealthState.UNKNOWN, stale.state)
    case.assertIn("stale_required_observation", stale.pause_causes)


def test_conflicting_latest_observations_fail_closed() -> None:
    case = _case()
    definition = _definition(recovery_threshold=1)
    one = _observation(definition, sequence=4, detail_sha256=HASH_A)
    two = _observation(definition, sequence=4, detail_sha256=HASH_B)
    snapshot = aggregate_health(
        (definition,), (one, two), evaluated_at="2026-09-20T10:00:40Z"
    )
    case.assertEqual(HealthState.UNKNOWN, snapshot.state)
    case.assertIn("conflicting_observation", snapshot.pause_causes)
    case.assertIsNone(snapshot.dependencies[0].selected_observation_id)


def test_failure_and_recovery_hysteresis_thresholds() -> None:
    case = _case()
    first, healthy, definition = _healthy_chain()
    case.assertEqual(HealthState.RECOVERING, first.dependencies[0].state)
    case.assertEqual(HealthState.HEALTHY, healthy.state)
    failed_once = aggregate_health(
        (definition,),
        (
            _observation(
                definition,
                sequence=3,
                status="fail",
                observed_at="2026-09-20T10:01:30Z",
            ),
        ),
        evaluated_at="2026-09-20T10:01:40Z",
        prior_snapshot=healthy,
    )
    case.assertEqual(HealthState.DEGRADED, failed_once.dependencies[0].state)
    failed_twice = aggregate_health(
        (definition,),
        (
            _observation(
                definition,
                sequence=4,
                status="fail",
                observed_at="2026-09-20T10:02:00Z",
            ),
        ),
        evaluated_at="2026-09-20T10:02:10Z",
        prior_snapshot=failed_once,
    )
    case.assertEqual(HealthState.UNHEALTHY, failed_twice.state)


def test_missing_and_future_required_observations_pause() -> None:
    case = _case()
    definition = _definition()
    missing = aggregate_health(
        (definition,), (), evaluated_at="2026-09-20T10:00:40Z"
    )
    case.assertIn("missing_required_observation", missing.pause_causes)
    future = aggregate_health(
        (definition,),
        (
            _observation(
                definition,
                sequence=1,
                observed_at="2026-09-20T10:01:00Z",
            ),
        ),
        evaluated_at="2026-09-20T10:00:40Z",
    )
    case.assertIn("future_observation", future.pause_causes)


def test_cross_context_and_definition_binding_are_rejected() -> None:
    case = _case()
    definition = _definition()
    foreign = _context(mission="missionref:mission-8")
    with case.assertRaises(HealthStateContractError):
        aggregate_health(
            (definition,),
            (_observation(definition, sequence=1, context=foreign),),
            evaluated_at="2026-09-20T10:00:40Z",
        )
    other = _definition(context=foreign)
    with case.assertRaises(HealthStateContractError):
        aggregate_health(
            (definition, other), (), evaluated_at="2026-09-20T10:00:40Z"
        )


def test_recovery_admission_requires_fresh_contiguous_healthy_history() -> None:
    case = _case()
    first, second, definition = _healthy_chain()
    third = aggregate_health(
        (definition,),
        (
            _observation(
                definition,
                sequence=3,
                observed_at="2026-09-20T10:01:30Z",
            ),
        ),
        evaluated_at="2026-09-20T10:01:40Z",
        prior_snapshot=second,
    )
    admitted = evaluate_execution_recovery_admission(
        (second, third),
        evaluated_at="2026-09-20T10:01:50Z",
        max_snapshot_age_seconds=30,
        required_consecutive_healthy_snapshots=2,
    )
    case.assertEqual(
        RecoveryAdmissionStatus.ELIGIBLE_FOR_SEPARATE_AUTHORIZATION,
        admitted.status,
    )
    case.assertEqual("none", admitted.authorization_effect)
    denied = evaluate_execution_recovery_admission(
        (first, second),
        evaluated_at="2026-09-20T10:05:00Z",
        max_snapshot_age_seconds=30,
        required_consecutive_healthy_snapshots=2,
    )
    case.assertEqual(RecoveryAdmissionStatus.DENIED, denied.status)
    case.assertIn("latest_snapshot_stale", denied.blocker_codes)
    case.assertIn("healthy_sequence_not_met", denied.blocker_codes)


def test_snapshot_and_admission_tamper_detection() -> None:
    case = _case()
    _, snapshot, _ = _healthy_chain()
    raw = snapshot.to_dict()
    raw["evaluated_at"] = "2026-09-20T10:01:11Z"
    with case.assertRaises(HealthStateContractError):
        HealthSnapshot.from_dict(raw)
    admission = evaluate_execution_recovery_admission(
        (snapshot,),
        evaluated_at="2026-09-20T10:01:20Z",
        max_snapshot_age_seconds=30,
        required_consecutive_healthy_snapshots=1,
    )
    changed = admission.to_dict()
    changed["authorization_effect"] = "granted"
    with case.assertRaises(HealthStateContractError):
        ExecutionRecoveryAdmission.from_dict(changed)


def test_schema_accepts_records_and_rejects_extra_fields() -> None:
    if Draft202012Validator is None:
        return
    case = _case()
    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "registry/schemas/health-state-contract-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    definition = _definition()
    observation = _observation(definition, sequence=1)
    snapshot = aggregate_health(
        (definition,), (observation,), evaluated_at="2026-09-20T10:00:40Z"
    )
    for value in (definition, observation, snapshot):
        validator.validate(value.to_dict())
    malformed = copy.deepcopy(definition.to_dict())
    malformed["unexpected"] = True
    with case.assertRaises(ValidationError):
        validator.validate(malformed)


def test_no_effects_are_explicit_and_all_records_preserve_them() -> None:
    case = _case()
    first, second, _ = _healthy_chain()
    admission = evaluate_execution_recovery_admission(
        (second,),
        evaluated_at="2026-09-20T10:01:20Z",
        max_snapshot_age_seconds=30,
        required_consecutive_healthy_snapshots=1,
    )
    case.assertTrue(all(value == "none" for value in NO_EFFECTS.values()))
    for raw in (
        _definition().to_dict(),
        _observation(_definition(), sequence=1).to_dict(),
        first.to_dict(),
        admission.to_dict(),
    ):
        case.assertEqual(dict(NO_EFFECTS), raw["effects"])

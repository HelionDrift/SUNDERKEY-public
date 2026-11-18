from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator, ValidationError
except ImportError:
    Draft202012Validator = None
    ValidationError = None

from sunderkey.disaster_recovery_contracts import (
    NO_EFFECTS,
    BackupManifest,
    CustodiedObjectBinding,
    DisasterRecoveryContractError,
    EventStoreCheckpoint,
    GapKind,
    GapSubject,
    KeySnapshotBinding,
    ObservedRestorationResult,
    ReadinessStatus,
    RecoveryObjective,
    RecoveryReadinessAssessment,
    RegistrySnapshotBinding,
    RestorationRehearsalPlan,
    UnrecoverableGap,
    assess_recovery_readiness,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64
HASH_E = "sha256:" + "e" * 64
HASH_F = "sha256:" + "f" * 64


def test_public_package_exports_are_available() -> None:
    case = _case()
    case.assertIs(sunderkey.assess_recovery_readiness, assess_recovery_readiness)
    case.assertIs(sunderkey.RecoveryObjective, RecoveryObjective)


def _case() -> unittest.TestCase:
    return unittest.TestCase()


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


def _key(*, version: str = "1.2.0", digest: str = HASH_A) -> KeySnapshotBinding:
    return KeySnapshotBinding(
        key_ref="keyref:tenant-backup-key",
        key_version=version,
        key_descriptor_sha256=digest,
        custody_ref="custodyref:key-custody",
        custody_sha256=HASH_B,
    )


def _registry(*, digest: str = HASH_C) -> RegistrySnapshotBinding:
    return RegistrySnapshotBinding(
        registry_snapshot_ref="registrysnapshotref:registry-42",
        registry_version="42.1.0",
        registry_sha256=digest,
        parent_snapshot_ref="registrysnapshotref:registry-41",
        parent_snapshot_sha256=HASH_D,
        rollback_manifest_ref="migrationref:registry-42-to-41",
        rollback_manifest_sha256=HASH_E,
        sequence=42,
    )


def _artifact(*, digest: str = HASH_A) -> CustodiedObjectBinding:
    return CustodiedObjectBinding(
        reference="artifactref:mission-store",
        sha256=digest,
        version="3.4.0",
        custody_ref="custodyref:artifact-custody",
        custody_sha256=HASH_B,
    )


def _evidence(*, digest: str = HASH_C) -> CustodiedObjectBinding:
    return CustodiedObjectBinding(
        reference="evidenceref:provider-evidence",
        sha256=digest,
        version="2.1.0",
        custody_ref="custodyref:evidence-custody",
        custody_sha256=HASH_D,
    )


def _event(*, passed: bool = True) -> EventStoreCheckpoint:
    return EventStoreCheckpoint(
        event_ref="eventref:mission-head-1024",
        event_sequence=1024,
        event_sha256=HASH_E,
        verification_ref="verificationref:event-store-report",
        verification_sha256=HASH_F,
        verified_at="2026-09-20T00:55:00Z",
        verification_passed=passed,
    )


def _objective() -> RecoveryObjective:
    return RecoveryObjective(
        tenant_ref="tenantref:acme",
        system_ref="systemref:sunderkey-control-plane",
        system_version="0.190.0",
        objective_version="1.0.0",
        max_rpo_seconds=600,
        max_rto_seconds=1800,
        max_backup_age_seconds=3600,
        required_artifact_refs=("artifactref:mission-store",),
        required_event_refs=("eventref:mission-head-1024",),
        required_evidence_refs=("evidenceref:provider-evidence",),
        created_at="2026-09-19T23:00:00Z",
        reviewer_ref="reviewerref:objective-reviewer",
        reviewer_signature_ref="signatureref:objective-signature",
        reviewer_signature_sha256=HASH_A,
    )


def _backup(*, verified: bool = True, event_passed: bool = True) -> BackupManifest:
    return BackupManifest(
        tenant_ref="tenantref:acme",
        system_ref="systemref:sunderkey-control-plane",
        system_version="0.190.0",
        backup_ref="backupref:backup-20260920-0054",
        backup_version="1.0.0",
        created_at="2026-09-20T00:54:00Z",
        verified_at="2026-09-20T00:55:00Z",
        verification_ref="verificationref:backup-report",
        verification_sha256=HASH_A,
        verification_signature_ref="signatureref:backup-report-signature",
        verification_signature_sha256=HASH_B,
        verifier_ref="reviewerref:backup-verifier",
        verification_passed=verified,
        key_snapshot=_key(),
        registry_snapshot=_registry(),
        artifacts=(_artifact(),),
        event_checkpoint=_event(passed=event_passed),
        evidence=(_evidence(),),
    )


def _plan(objective: RecoveryObjective, backup: BackupManifest) -> RestorationRehearsalPlan:
    return RestorationRehearsalPlan(
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        system_version=objective.system_version,
        rehearsal_version="1.0.0",
        objective_id=objective.objective_id,
        objective_sha256=objective.objective_sha256,
        backup_manifest_id=backup.manifest_id,
        backup_manifest_sha256=backup.manifest_sha256,
        backup_ref=backup.backup_ref,
        backup_version=backup.backup_version,
        key_snapshot=backup.key_snapshot,
        registry_snapshot=backup.registry_snapshot,
        required_artifact_refs=objective.required_artifact_refs,
        required_event_refs=objective.required_event_refs,
        required_evidence_refs=objective.required_evidence_refs,
        simulated_failure_at="2026-09-20T01:00:00Z",
        restore_point_at="2026-09-20T00:54:00Z",
        planned_at="2026-09-20T00:56:00Z",
        executor_ref="principalref:recovery-operator",
        reviewer_ref="reviewerref:rehearsal-reviewer",
    )


def _result(
    plan: RestorationRehearsalPlan,
    backup: BackupManifest,
    *,
    key: KeySnapshotBinding | None = None,
    registry: RegistrySnapshotBinding | None = None,
    artifacts: tuple[CustodiedObjectBinding, ...] | None = None,
    evidence: tuple[CustodiedObjectBinding, ...] | None = None,
    gaps: tuple[UnrecoverableGap, ...] = (),
    signed: bool = True,
    claimed: bool = True,
    completed_at: str = "2026-09-20T01:20:00Z",
    restore_point_at: str = "2026-09-20T00:54:00Z",
) -> ObservedRestorationResult:
    return ObservedRestorationResult(
        tenant_ref=plan.tenant_ref,
        system_ref=plan.system_ref,
        system_version=plan.system_version,
        result_version="1.0.0",
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        backup_ref=backup.backup_ref,
        backup_version=backup.backup_version,
        key_snapshot=key or backup.key_snapshot,
        registry_snapshot=registry or backup.registry_snapshot,
        artifacts=artifacts or backup.artifacts,
        event_checkpoint=backup.event_checkpoint,
        evidence=evidence or backup.evidence,
        gaps=gaps,
        started_at="2026-09-20T01:01:00Z",
        completed_at=completed_at,
        restore_point_at=restore_point_at,
        observer_ref="principalref:recovery-observer",
        observation_ref="observationref:rehearsal-observation",
        observation_sha256=HASH_E,
        observation_signature_ref="signatureref:rehearsal-observation-signature",
        observation_signature_sha256=HASH_F,
        observation_signed=signed,
        restoration_claimed=claimed,
    )


def _assess(
    objective: RecoveryObjective,
    backup: BackupManifest,
    plan: RestorationRehearsalPlan,
    result: ObservedRestorationResult,
    *,
    assessed_at: str = "2026-09-20T01:30:00Z",
    reviewer_ref: str = "reviewerref:rehearsal-reviewer",
) -> RecoveryReadinessAssessment:
    return assess_recovery_readiness(
        objective,
        backup,
        plan,
        result,
        assessed_at=assessed_at,
        reviewer_ref=reviewer_ref,
        reviewer_signature_ref="signatureref:readiness-assessment-signature",
        reviewer_signature_sha256=HASH_A,
    )


def test_complete_rehearsal_is_contract_ready_but_not_qualified() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(plan, backup)

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.CONTRACT_READY_UNVERIFIED
    assert assessment.observed_rpo_seconds == 360
    assert assessment.observed_rto_seconds == 1200
    assert assessment.backup_age_seconds == 2100
    assert assessment.artifact_continuity_passed is True
    assert assessment.event_continuity_passed is True
    assert assessment.evidence_continuity_passed is True
    assert assessment.key_binding_passed is True
    assert assessment.registry_lineage_passed is True
    assert assessment.reasons == ("repository_contract_only_external_rehearsal_not_qualified",)
    assert assessment.to_dict()["effects"] == dict(NO_EFFECTS)


def test_content_addressed_records_round_trip() -> None:
    factories = (
        lambda objective, backup, plan, result: objective,
        lambda objective, backup, plan, result: backup,
        lambda objective, backup, plan, result: plan,
        lambda objective, backup, plan, result: result,
        lambda objective, backup, plan, result: _assess(objective, backup, plan, result),
    )
    for factory in factories:
        objective = _objective()
        backup = _backup()
        plan = _plan(objective, backup)
        result = _result(plan, backup)
        record = factory(objective, backup, plan, result)

        restored = type(record).from_dict(record.to_dict())

        assert restored == record
        encoded = json.dumps(record.to_dict(), ensure_ascii=False)
        assert all(ord(character) < 128 for character in encoded)


def test_tampered_content_address_is_rejected() -> None:
    raw = _objective().to_dict()
    raw["max_rpo_seconds"] = 601

    with _case().assertRaisesRegex(DisasterRecoveryContractError, "content address"):
        RecoveryObjective.from_dict(raw)


def test_unknown_fields_and_effect_mutation_are_rejected() -> None:
    raw = _backup().to_dict()
    unknown = copy.deepcopy(raw)
    unknown["restored"] = True
    effects = copy.deepcopy(raw)
    effects["effects"]["restore"] = "performed"

    with _case().assertRaisesRegex(DisasterRecoveryContractError, "fields"):
        BackupManifest.from_dict(unknown)
    with _case().assertRaisesRegex(DisasterRecoveryContractError, "no-effect"):
        BackupManifest.from_dict(effects)


def test_duplicate_artifact_references_are_rejected() -> None:
    backup = _backup()
    raw = backup.to_dict()
    raw.pop("manifest_id")
    raw.pop("manifest_sha256")

    with _case().assertRaisesRegex(DisasterRecoveryContractError, "duplicate references"):
        BackupManifest(
            **{
                key: value
                for key, value in raw.items()
                if key not in {"schema_version", "kind", "effects", "artifacts"}
            },
            artifacts=(backup.artifacts[0], backup.artifacts[0]),
        )


def test_unsigned_restoration_claim_is_rejected() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)

    with _case().assertRaisesRegex(DisasterRecoveryContractError, "signed observation"):
        _result(plan, backup, signed=False, claimed=True)


def test_self_review_is_rejected() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(plan, backup)

    with _case().assertRaisesRegex(DisasterRecoveryContractError, "independent review"):
        _assess(
            objective,
            backup,
            plan,
            result,
            reviewer_ref="reviewerref:recovery-operator",
        )


def test_assessment_reviewer_must_match_plan_binding() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(plan, backup)

    with _case().assertRaisesRegex(
        DisasterRecoveryContractError, "does not match the rehearsal plan"
    ):
        _assess(
            objective,
            backup,
            plan,
            result,
            reviewer_ref="reviewerref:another-independent-reviewer",
        )


def test_unverified_or_stale_backup_is_not_ready() -> None:
    objective = _objective()
    backup = _backup(verified=False, event_passed=False)
    plan = _plan(objective, backup)
    result = _result(plan, backup)

    assessment = _assess(
        objective,
        backup,
        plan,
        result,
        assessed_at="2026-09-20T03:00:00Z",
    )

    assert assessment.status is ReadinessStatus.NOT_READY
    assert {
        "backup_verification_failed",
        "backup_event_chain_unverified",
        "backup_is_stale",
        "event_store_continuity_failed",
    } <= set(assessment.reasons)


def test_key_and_registry_mismatch_fail_closed() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(
        plan,
        backup,
        key=_key(version="1.3.0", digest=HASH_B),
        registry=_registry(digest=HASH_D),
    )

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.NOT_READY
    assert assessment.key_binding_passed is False
    assert assessment.registry_lineage_passed is False
    assert "key_snapshot_mismatch" in assessment.reasons
    assert "registry_rollback_lineage_ambiguous" in assessment.reasons


def test_artifact_and_evidence_custody_breaks_fail_closed() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(
        plan,
        backup,
        artifacts=(_artifact(digest=HASH_B),),
        evidence=(_evidence(digest=HASH_D),),
    )

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.NOT_READY
    assert assessment.artifact_continuity_passed is False
    assert assessment.evidence_continuity_passed is False
    assert "artifact_continuity_failed" in assessment.reasons
    assert "evidence_custody_continuity_failed" in assessment.reasons


def test_rpo_and_rto_violations_are_not_ready() -> None:
    objective = _objective()
    backup = _backup()
    raw = _plan(objective, backup).to_dict()
    raw.pop("plan_id")
    raw.pop("plan_sha256")
    raw["restore_point_at"] = "2026-09-20T00:40:00Z"
    plan = RestorationRehearsalPlan(
        **{
            key: value
            for key, value in raw.items()
            if key not in {"schema_version", "kind", "effects"}
        }
    )
    result = _result(
        plan,
        backup,
        completed_at="2026-09-20T01:40:01Z",
        restore_point_at="2026-09-20T00:40:00Z",
    )

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.NOT_READY
    assert "rpo_objective_violated" in assessment.reasons
    assert "rto_objective_violated" in assessment.reasons


def test_restore_point_must_match_the_plan() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(plan, backup, restore_point_at="2026-09-20T00:53:59Z")

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.NOT_READY
    assert "restore_point_binding_mismatch" in assessment.reasons


def test_unrecoverable_gap_round_trips_and_blocks_readiness() -> None:
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    gap = UnrecoverableGap(
        subject=GapSubject.EVIDENCE,
        kind=GapKind.CUSTODY_BREAK,
        expected_ref="evidenceref:provider-evidence",
        expected_sha256=HASH_C,
        observed_ref="evidenceref:provider-evidence",
        observed_sha256=HASH_D,
        detected_at="2026-09-20T01:15:00Z",
        reason="Restored custody digest did not match the backup manifest.",
    )
    assert UnrecoverableGap.from_dict(gap.to_dict()) == gap
    result = _result(plan, backup, gaps=(gap,), claimed=False)

    assessment = _assess(objective, backup, plan, result)

    assert assessment.status is ReadinessStatus.NOT_READY
    assert assessment.gap_ids == (gap.gap_id,)
    assert "unrecoverable_gaps_present" in assessment.reasons


def test_schema_is_strict_and_accepts_all_top_level_records() -> None:
    if Draft202012Validator is None or ValidationError is None:
        raise unittest.SkipTest("jsonschema is not installed")
    root = Path(__file__).resolve().parents[2]
    schema = json.loads(
        (root / "registry/schemas/disaster-recovery-contract-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)
    objective = _objective()
    backup = _backup()
    plan = _plan(objective, backup)
    result = _result(plan, backup)
    assessment = _assess(objective, backup, plan, result)

    for record in (objective, backup, plan, result, assessment):
        validator.validate(record.to_dict())

    invalid = objective.to_dict()
    invalid["unexpected"] = "rejected"
    with _case().assertRaises(ValidationError):
        validator.validate(invalid)

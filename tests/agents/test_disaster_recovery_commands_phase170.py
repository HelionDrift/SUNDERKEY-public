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
from sunderkey.disaster_recovery_commands import (
    AuthorizationBinding,
    BackendCommandResult,
    CleanupBinding,
    CommandKind,
    CommandOutcome,
    DisasterRecoveryCommandError,
    DisasterRecoveryCommandReceipt,
    DisasterRecoveryCommandRequest,
    ExecutionBudget,
    FenceBinding,
    RehearsalIsolationBinding,
    build_disaster_recovery_command_request,
    execute_disaster_recovery_command,
    parse_disaster_recovery_command_record,
)
from sunderkey.disaster_recovery_contracts import (
    BackupManifest,
    CustodiedObjectBinding,
    EventStoreCheckpoint,
    KeySnapshotBinding,
    RecoveryObjective,
    RegistrySnapshotBinding,
    RestorationRehearsalPlan,
)

HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64
HASH_C = "sha256:" + "c" * 64
HASH_D = "sha256:" + "d" * 64
HASH_E = "sha256:" + "e" * 64
HASH_F = "sha256:" + "f" * 64


def _sources() -> tuple[RecoveryObjective, BackupManifest, RestorationRehearsalPlan]:
    key = KeySnapshotBinding(
        key_ref="keyref:tenant-backup-key",
        key_version="1.2.0",
        key_descriptor_sha256=HASH_A,
        custody_ref="custodyref:key-custody",
        custody_sha256=HASH_B,
    )
    registry = RegistrySnapshotBinding(
        registry_snapshot_ref="registrysnapshotref:registry-42",
        registry_version="42.1.0",
        registry_sha256=HASH_C,
        parent_snapshot_ref="registrysnapshotref:registry-41",
        parent_snapshot_sha256=HASH_D,
        rollback_manifest_ref="migrationref:registry-42-to-41",
        rollback_manifest_sha256=HASH_E,
        sequence=42,
    )
    artifact = CustodiedObjectBinding(
        reference="artifactref:mission-store",
        sha256=HASH_A,
        version="3.4.0",
        custody_ref="custodyref:artifact-custody",
        custody_sha256=HASH_B,
    )
    evidence = CustodiedObjectBinding(
        reference="evidenceref:provider-evidence",
        sha256=HASH_C,
        version="2.1.0",
        custody_ref="custodyref:evidence-custody",
        custody_sha256=HASH_D,
    )
    event = EventStoreCheckpoint(
        event_ref="eventref:mission-head-1024",
        event_sequence=1024,
        event_sha256=HASH_E,
        verification_ref="verificationref:event-store-report",
        verification_sha256=HASH_F,
        verified_at="2026-09-20T00:55:00Z",
        verification_passed=True,
    )
    objective = RecoveryObjective(
        tenant_ref="tenantref:acme",
        system_ref="systemref:sunderkey-control-plane",
        system_version="0.229.0",
        objective_version="1.0.0",
        max_rpo_seconds=600,
        max_rto_seconds=1800,
        max_backup_age_seconds=3600,
        required_artifact_refs=(artifact.reference,),
        required_event_refs=(event.event_ref,),
        required_evidence_refs=(evidence.reference,),
        created_at="2026-09-19T23:00:00Z",
        reviewer_ref="reviewerref:objective-reviewer",
        reviewer_signature_ref="signatureref:objective-signature",
        reviewer_signature_sha256=HASH_A,
    )
    manifest = BackupManifest(
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        system_version=objective.system_version,
        backup_ref="backupref:backup-20260920-0054",
        backup_version="1.0.0",
        created_at="2026-09-20T00:54:00Z",
        verified_at="2026-09-20T00:55:00Z",
        verification_ref="verificationref:backup-report",
        verification_sha256=HASH_A,
        verification_signature_ref="signatureref:backup-report-signature",
        verification_signature_sha256=HASH_B,
        verifier_ref="reviewerref:backup-verifier",
        verification_passed=True,
        key_snapshot=key,
        registry_snapshot=registry,
        artifacts=(artifact,),
        event_checkpoint=event,
        evidence=(evidence,),
    )
    plan = RestorationRehearsalPlan(
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        system_version=objective.system_version,
        rehearsal_version="1.0.0",
        objective_id=objective.objective_id,
        objective_sha256=objective.objective_sha256,
        backup_manifest_id=manifest.manifest_id,
        backup_manifest_sha256=manifest.manifest_sha256,
        backup_ref=manifest.backup_ref,
        backup_version=manifest.backup_version,
        key_snapshot=key,
        registry_snapshot=registry,
        required_artifact_refs=objective.required_artifact_refs,
        required_event_refs=objective.required_event_refs,
        required_evidence_refs=objective.required_evidence_refs,
        simulated_failure_at="2026-09-20T01:00:00Z",
        restore_point_at="2026-09-20T00:54:00Z",
        planned_at="2026-09-20T00:56:00Z",
        executor_ref="principalref:recovery-operator",
        reviewer_ref="reviewerref:rehearsal-reviewer",
    )
    return objective, manifest, plan


def _authorization(
    objective: RecoveryObjective,
    manifest: BackupManifest,
    plan: RestorationRehearsalPlan,
    isolation: RehearsalIsolationBinding,
) -> AuthorizationBinding:
    return AuthorizationBinding(
        authorization_ref="authorizationref:dr-window-1",
        authorization_sha256=HASH_A,
        tenant_ref=objective.tenant_ref,
        system_ref=objective.system_ref,
        scope_ref="scoperef:authorized-dr-scope",
        scope_sha256=HASH_D,
        objective_id=objective.objective_id,
        objective_sha256=objective.objective_sha256,
        manifest_id=manifest.manifest_id,
        manifest_sha256=manifest.manifest_sha256,
        plan_id=plan.plan_id,
        plan_sha256=plan.plan_sha256,
        backend_ref="backendref:dr-adapter",
        backend_version="1.4.0",
        destination_ref=isolation.destination_ref,
        destination_sha256=isolation.destination_sha256,
        operator_ref="principalref:recovery-operator",
        approver_ref="principalref:recovery-approver",
        allowed_command_kinds=tuple(CommandKind),
        authorized_at="2026-09-20T00:57:00Z",
        expires_at="2026-09-20T03:00:00Z",
    )


def _isolation(**changes: object) -> RehearsalIsolationBinding:
    values: dict[str, object] = {
        "destination_ref": "rehearsalref:dr-sandbox-1",
        "destination_sha256": HASH_B,
        "isolation_proof_ref": "evidenceref:dr-sandbox-proof",
        "isolation_proof_sha256": HASH_C,
        "isolation_class": "ephemeral_rehearsal",
        "network_mode": "isolated",
        "caller_proved_isolated": True,
        "production_destination": False,
    }
    values.update(changes)
    return RehearsalIsolationBinding(**values)


def _request(
    kind: CommandKind = CommandKind.REHEARSE_RESTORE,
    *,
    preflight_passed: bool = True,
) -> DisasterRecoveryCommandRequest:
    objective, manifest, plan = _sources()
    isolation = _isolation()
    return build_disaster_recovery_command_request(
        objective=objective,
        manifest=manifest,
        plan=plan,
        scope_ref="scoperef:authorized-dr-scope",
        scope_sha256=HASH_D,
        command_kind=kind,
        backend_ref="backendref:dr-adapter",
        backend_version="1.4.0",
        authorization=_authorization(objective, manifest, plan, isolation),
        idempotency_key=f"dr:{kind.value}:20260920:0001",
        budget=ExecutionBudget(
            max_runtime_seconds=3600,
            max_bytes=10_000_000,
            max_objects=500,
            max_backend_calls=1,
        ),
        isolation=isolation,
        fence=FenceBinding(
            fence_ref="fenceref:dr-coordinator",
            fence_sha256=HASH_E,
            fence_epoch=19,
            scope_ref="scoperef:authorized-dr-scope",
            scope_sha256=HASH_D,
        ),
        cleanup=CleanupBinding(
            cleanup_ref="cleanupref:dr-sandbox-cleanup",
            cleanup_sha256=HASH_F,
            destination_ref=isolation.destination_ref,
            destination_sha256=isolation.destination_sha256,
            cleanup_required=True,
            destination_absence_required=True,
            max_cleanup_seconds=900,
        ),
        preflight_passed=preflight_passed,
        preflight_evidence_ref="evidenceref:dr-preflight",
        preflight_evidence_sha256=HASH_A,
        preflight_reason_codes=() if preflight_passed else ("isolation_probe_failed",),
        requested_at="2026-09-20T01:00:00Z",
        expires_at="2026-09-20T02:00:00Z",
    )


class Backend:
    def __init__(
        self,
        *,
        outcome: CommandOutcome = CommandOutcome.COMPLETED,
        reasons: tuple[str, ...] = (),
    ) -> None:
        self.outcome = outcome
        self.reasons = reasons
        self.calls = 0

    def execute(self, request: DisasterRecoveryCommandRequest) -> BackendCommandResult:
        self.calls += 1
        completed = self.outcome is CommandOutcome.COMPLETED
        is_backup = request.command_kind in {
            CommandKind.CREATE_BACKUP,
            CommandKind.VERIFY_BACKUP,
        }
        is_restore = request.command_kind in {
            CommandKind.REHEARSE_RESTORE,
            CommandKind.VERIFY_RESTORE,
        }
        is_cleanup = request.command_kind is CommandKind.CLEANUP_REHEARSAL
        return BackendCommandResult(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            backend_ref=request.backend_ref,
            backend_version=request.backend_version,
            idempotency_key=request.idempotency_key,
            outcome=self.outcome,
            evidence_ref="evidenceref:backend-command-observation",
            evidence_sha256=HASH_F,
            backup_observed=completed and is_backup,
            restore_observed=completed and is_restore,
            recovery_objectives_observed_passed=(
                completed and request.command_kind is CommandKind.VERIFY_RESTORE
            ),
            cleanup_observed_complete=completed and is_cleanup,
            reason_codes=self.reasons,
            observed_at="2026-09-20T01:05:00Z",
        )


class DisasterRecoveryCommandsPhase170Tests(unittest.TestCase):
    def test_all_command_kinds_execute_through_injected_backend(self) -> None:
        for kind in CommandKind:
            with self.subTest(kind=kind):
                request = _request(kind)
                backend = Backend()
                observation, receipt = execute_disaster_recovery_command(
                    request,
                    backend,
                    observed_at="2026-09-20T01:05:00Z",
                )
                self.assertEqual(backend.calls, 1)
                self.assertEqual(observation.outcome, CommandOutcome.COMPLETED)
                self.assertEqual(receipt.outcome, CommandOutcome.COMPLETED)
                self.assertEqual(receipt.qualification_effect, "none")
                self.assertEqual(receipt.claim_source, "supplied_backend_result")

    def test_blocked_preflight_never_calls_backend(self) -> None:
        request = _request(preflight_passed=False)
        backend = Backend()
        observation, receipt = execute_disaster_recovery_command(
            request,
            backend,
            observed_at="2026-09-20T01:05:00Z",
        )
        self.assertEqual(backend.calls, 0)
        self.assertEqual(observation.outcome, CommandOutcome.BLOCKED_PREFLIGHT)
        self.assertFalse(observation.backend_call_performed)
        self.assertEqual(receipt.claim_source, "request_preflight")
        self.assertFalse(receipt.restore_observed)

    def test_failure_outcomes_remain_distinct(self) -> None:
        for outcome in (
            CommandOutcome.RETRYABLE_FAILURE,
            CommandOutcome.TERMINAL_FAILURE,
            CommandOutcome.PARTIAL_CLEANUP,
        ):
            with self.subTest(outcome=outcome):
                observation, receipt = execute_disaster_recovery_command(
                    _request(CommandKind.CLEANUP_REHEARSAL),
                    Backend(outcome=outcome, reasons=("backend_reported_failure",)),
                    observed_at="2026-09-20T01:05:00Z",
                )
                self.assertEqual(observation.outcome, outcome)
                self.assertEqual(receipt.outcome, outcome)
                self.assertFalse(receipt.recovery_objectives_observed_passed)

    def test_production_or_unproved_destination_is_rejected(self) -> None:
        for changes in (
            {"production_destination": True},
            {"caller_proved_isolated": False},
            {"network_mode": "host"},
            {"isolation_class": "production"},
        ):
            with self.subTest(changes=changes), self.assertRaises(DisasterRecoveryCommandError):
                _isolation(**changes)

    def test_operator_and_approver_must_be_separate(self) -> None:
        objective, manifest, plan = _sources()
        raw = _authorization(objective, manifest, plan, _isolation()).to_dict()
        raw["operator_ref"] = "principalref:same"
        raw["approver_ref"] = "principalref:same"
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "separate"):
            AuthorizationBinding.from_dict(raw)

    def test_authorization_must_allow_exact_command(self) -> None:
        raw = _request().to_dict()
        raw.pop("request_id")
        raw.pop("request_sha256")
        raw.pop("schema_version")
        raw.pop("kind")
        raw["authorization"]["allowed_command_kinds"] = ["create_backup"]
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "does not allow"):
            DisasterRecoveryCommandRequest(**raw)

    def test_authorization_and_fence_must_match_exact_request_context(self) -> None:
        for field, value, message in (
            ("scope_sha256", HASH_A, "authorization context"),
            ("backend_version", "1.5.0", "authorization context"),
        ):
            raw = _request().to_dict()
            raw.pop("request_id")
            raw.pop("request_sha256")
            raw.pop("schema_version")
            raw.pop("kind")
            raw["authorization"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(DisasterRecoveryCommandError, message),
            ):
                DisasterRecoveryCommandRequest(**raw)
        raw = _request().to_dict()
        raw.pop("request_id")
        raw.pop("request_sha256")
        raw.pop("schema_version")
        raw.pop("kind")
        raw["fence"]["scope_sha256"] = HASH_A
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "fence scope"):
            DisasterRecoveryCommandRequest(**raw)

    def test_source_context_mismatch_is_rejected(self) -> None:
        objective, manifest, plan = _sources()
        isolation = _isolation()
        raw = manifest.to_dict()
        raw.pop("manifest_id")
        raw.pop("manifest_sha256")
        raw.pop("schema_version")
        raw.pop("kind")
        raw.pop("effects")
        raw["tenant_ref"] = "tenantref:other"
        mismatched = BackupManifest(**raw)
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "bindings"):
            build_disaster_recovery_command_request(
                objective=objective,
                manifest=mismatched,
                plan=plan,
                scope_ref="scoperef:authorized-dr-scope",
                scope_sha256=HASH_D,
                command_kind=CommandKind.CREATE_BACKUP,
                backend_ref="backendref:dr-adapter",
                backend_version="1.4.0",
                authorization=_authorization(objective, manifest, plan, isolation),
                idempotency_key="dr:create_backup:20260920:0001",
                budget=ExecutionBudget(1, 1, 1, 1),
                isolation=isolation,
                fence=FenceBinding(
                    "fenceref:dr",
                    HASH_E,
                    1,
                    "scoperef:authorized-dr-scope",
                    HASH_D,
                ),
                cleanup=CleanupBinding(
                    "cleanupref:dr",
                    HASH_F,
                    isolation.destination_ref,
                    isolation.destination_sha256,
                    True,
                    True,
                    1,
                ),
                preflight_passed=True,
                preflight_evidence_ref="evidenceref:preflight",
                preflight_evidence_sha256=HASH_A,
                preflight_reason_codes=(),
                requested_at="2026-09-20T01:00:00Z",
                expires_at="2026-09-20T02:00:00Z",
            )

    def test_backend_cannot_change_request_binding(self) -> None:
        class WrongBackend(Backend):
            def execute(self, request: DisasterRecoveryCommandRequest) -> BackendCommandResult:
                result = super().execute(request)
                return BackendCommandResult(
                    request_id=result.request_id,
                    request_sha256=result.request_sha256,
                    backend_ref=result.backend_ref,
                    backend_version="1.5.0",
                    idempotency_key=result.idempotency_key,
                    outcome=result.outcome,
                    evidence_ref=result.evidence_ref,
                    evidence_sha256=result.evidence_sha256,
                    backup_observed=result.backup_observed,
                    restore_observed=result.restore_observed,
                    recovery_objectives_observed_passed=(
                        result.recovery_objectives_observed_passed
                    ),
                    cleanup_observed_complete=result.cleanup_observed_complete,
                    reason_codes=result.reason_codes,
                    observed_at=result.observed_at,
                )

        with self.assertRaisesRegex(DisasterRecoveryCommandError, "does not match"):
            execute_disaster_recovery_command(
                _request(),
                WrongBackend(),
                observed_at="2026-09-20T01:05:00Z",
            )

    def test_completed_restore_requires_backend_restore_observation(self) -> None:
        class NoRestoreBackend(Backend):
            def execute(self, request: DisasterRecoveryCommandRequest) -> BackendCommandResult:
                result = super().execute(request)
                return BackendCommandResult(
                    request_id=result.request_id,
                    request_sha256=result.request_sha256,
                    backend_ref=result.backend_ref,
                    backend_version=result.backend_version,
                    idempotency_key=result.idempotency_key,
                    outcome=result.outcome,
                    evidence_ref=result.evidence_ref,
                    evidence_sha256=result.evidence_sha256,
                    backup_observed=False,
                    restore_observed=False,
                    recovery_objectives_observed_passed=False,
                    cleanup_observed_complete=False,
                    reason_codes=(),
                    observed_at=result.observed_at,
                )

        with self.assertRaisesRegex(DisasterRecoveryCommandError, "restore observation"):
            execute_disaster_recovery_command(
                _request(),
                NoRestoreBackend(),
                observed_at="2026-09-20T01:05:00Z",
            )

    def test_content_addressed_records_round_trip_and_tamper_fails(self) -> None:
        request = _request(CommandKind.VERIFY_RESTORE)
        observation, receipt = execute_disaster_recovery_command(
            request,
            Backend(),
            observed_at="2026-09-20T01:05:00Z",
        )
        for record in (request, observation, receipt):
            restored = parse_disaster_recovery_command_record(record.to_dict())
            self.assertEqual(restored, record)
            self.assertTrue(all(ord(char) < 128 for char in json.dumps(record.to_dict())))
        tampered = copy.deepcopy(receipt.to_dict())
        tampered["outcome"] = "terminal_failure"
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "content address"):
            DisasterRecoveryCommandReceipt.from_dict(tampered)

    def test_unknown_fields_are_rejected(self) -> None:
        raw = _request().to_dict()
        raw["production_restore"] = True
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "fields"):
            DisasterRecoveryCommandRequest.from_dict(raw)

    def test_expired_request_fails_before_backend_call(self) -> None:
        backend = Backend()
        with self.assertRaisesRegex(DisasterRecoveryCommandError, "expired"):
            execute_disaster_recovery_command(
                _request(),
                backend,
                observed_at="2026-09-20T02:00:00Z",
            )
        self.assertEqual(backend.calls, 0)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_schema_accepts_records_and_rejects_unknown_fields(self) -> None:
        root = Path(__file__).resolve().parents[2]
        schema = json.loads(
            (root / "registry/schemas/disaster-recovery-command-receipt-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema)
        request = _request(CommandKind.VERIFY_RESTORE)
        observation, receipt = execute_disaster_recovery_command(
            request,
            Backend(),
            observed_at="2026-09-20T01:05:00Z",
        )
        for record in (request, observation, receipt):
            validator.validate(record.to_dict())
        blocked_request = _request(preflight_passed=False)
        blocked_observation, blocked_receipt = execute_disaster_recovery_command(
            blocked_request,
            Backend(),
            observed_at="2026-09-20T01:05:00Z",
        )
        for record in (blocked_request, blocked_observation, blocked_receipt):
            validator.validate(record.to_dict())
        invalid = receipt.to_dict()
        invalid["unexpected"] = True
        with self.assertRaises(ValidationError):
            validator.validate(invalid)

    def test_module_has_no_direct_runtime_clients(self) -> None:
        root = Path(__file__).resolve().parents[2]
        source = (root / "src/sunderkey/disaster_recovery_commands.py").read_text(encoding="utf-8")
        for forbidden in (
            "import subprocess",
            "import socket",
            "import sqlite3",
            "import psycopg",
            "import boto",
            "from pathlib import Path",
        ):
            self.assertNotIn(forbidden, source)

    def test_public_package_exports_recovery_command_boundary(self) -> None:
        self.assertIs(
            sunderkey.build_disaster_recovery_command_request,
            build_disaster_recovery_command_request,
        )
        self.assertIs(
            sunderkey.execute_disaster_recovery_command,
            execute_disaster_recovery_command,
        )
        self.assertIs(
            sunderkey.parse_disaster_recovery_command_record,
            parse_disaster_recovery_command_record,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.authorized_target_health_runtime import (
    HealthSignalState,
    TargetHealthReceipt,
    TargetHealthStatus,
)
from sunderkey.target_health_custody import (
    APPLICATION_ID,
    EXPECTED_SCHEMA_MANIFEST_SHA256,
    MIGRATION_ID,
    MIGRATION_SHA256,
    SCHEMA_VERSION,
    SQLiteTargetHealthCustody,
    TargetHealthCustodyBusyError,
    TargetHealthCustodyConflictError,
    TargetHealthCustodyIntegrityError,
    TargetHealthCustodyNotFoundError,
    TargetHealthCustodyValidationError,
)
from sunderkey.target_health_custody_contracts import (
    SignedTargetHealthCustodyEnvelopeV2,
    TargetHealthCollectorPolicyRevision,
    TargetHealthCurrentHeadInspection,
    execution_binding_sha256,
    target_health_chain_id,
)
from tests.agents import test_authorized_target_health_runtime_phase175 as phase175
from tests.agents import test_target_health_custody_phase198 as phase198

DIGEST_D = "sha256:" + "d" * 64
DIGEST_E = "sha256:" + "e" * 64
INSPECTION_EFFECTS = {
    "authority_effect": "none",
    "collection_effect": "none",
    "control_effect": "none",
    "network_call_performed": False,
    "pause_effect": "none",
    "qualification_effect": "none",
    "reservation_effect": "none",
    "resume_effect": "none",
    "target_effect_performed": False,
}


@dataclass(frozen=True, slots=True)
class PopulatedCustody:
    store: SQLiteTargetHealthCustody
    factory: phase198.ContractFactory
    policy: TargetHealthCollectorPolicyRevision
    envelope: SignedTargetHealthCustodyEnvelopeV2
    custody_receipt: object
    custody_event: object


class LockedReadConnection:
    """Connection proxy that deterministically reports a read lock."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection
        self.closed = False

    @property
    def row_factory(self) -> object:
        return self.connection.row_factory

    @row_factory.setter
    def row_factory(self, value: object) -> None:
        self.connection.row_factory = value

    @property
    def in_transaction(self) -> bool:
        return self.connection.in_transaction

    def execute(self, statement: str, *arguments: object) -> sqlite3.Cursor:
        if statement == "BEGIN":
            raise sqlite3.OperationalError("database is locked")
        return self.connection.execute(statement, *arguments)

    def rollback(self) -> None:
        self.connection.rollback()

    def close(self) -> None:
        self.connection.close()
        self.closed = True

    def __getattr__(self, name: str) -> object:
        return getattr(self.connection, name)


class ConfigurationFailureConnection:
    """Connection proxy that fails while SQLite safety pragmas are applied."""

    def __init__(self, connection: sqlite3.Connection, message: str) -> None:
        self.connection = connection
        self.message = message
        self.closed = False

    @property
    def row_factory(self) -> object:
        return self.connection.row_factory

    @row_factory.setter
    def row_factory(self, value: object) -> None:
        self.connection.row_factory = value

    def execute(self, statement: str, *arguments: object) -> sqlite3.Cursor:
        del statement, arguments
        raise sqlite3.OperationalError(self.message)

    def close(self) -> None:
        self.connection.close()
        self.closed = True


class TargetHealthCustodyInspectionPhase199Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    @staticmethod
    def _inspection_type() -> type[object]:
        return TargetHealthCurrentHeadInspection

    @staticmethod
    def _receipt(state: str) -> TargetHealthReceipt:
        fixture = phase175.AuthorizedTargetHealthRuntimePhase175Tests(
            "test_completed_receipt_composes_all_boundaries_and_dimensions"
        )
        fixture.setUp()
        if state == "healthy":
            return fixture.observe()
        if state == "degraded":
            return fixture.observe(
                observations=fixture.make_observations(
                    latency=250,
                    latency_state=HealthSignalState.DEGRADED,
                    latency_detail="above_healthy_latency_threshold",
                )
            )
        if state == "unhealthy":
            return fixture.observe(
                observations=fixture.make_observations(
                    latency=600,
                    latency_state=HealthSignalState.UNHEALTHY,
                    latency_detail="above_degraded_latency_threshold",
                )
            )
        if state == "rejected":
            return fixture.observe(safety_snapshot=None)
        raise AssertionError(f"unsupported test health state: {state}")

    def _populate(
        self,
        name: str,
        *,
        receipt: TargetHealthReceipt | None = None,
        clock: str = "2026-09-21T12:00:10Z",
    ) -> PopulatedCustody:
        factory = phase198.ContractFactory()
        policy_arguments: dict[str, str] = {}
        observed_at = "2026-09-21T12:00:05Z"
        monotonic_tick = 10
        if receipt is not None:
            factory.binding = receipt.binding
            factory.binding_sha256 = execution_binding_sha256(receipt.binding)
            factory.root = replace(
                factory.root,
                effective_at="2026-09-20T00:00:00Z",
                expires_at="2026-09-21T00:00:00Z",
                trust_root_id="",
                trust_root_sha256="",
            )
            policy_arguments = {
                "issued_at": "2026-09-20T10:59:00Z",
                "effective_at": "2026-09-20T11:00:00Z",
                "expires_at": "2026-09-20T18:00:00Z",
                "runtime_policy_id": receipt.runtime_policy_id,
                "runtime_policy_sha256": receipt.runtime_policy_sha256,
            }
            observed_at = receipt.observed_at
            monotonic_tick = receipt.monotonic_tick
        store = SQLiteTargetHealthCustody(
            self.directory / f"{name}.sqlite3",
            trust_root=factory.root,
            trusted_clock=phase198.FixedClock(clock),
        )
        policy = factory.make_policy(**policy_arguments)
        store.publish_policy(policy)
        envelope = factory.make_envelope(
            policy,
            sequence=1,
            observed_at=observed_at,
            monotonic_tick=monotonic_tick,
            receipt=receipt,
        )
        append = store.append_envelope(envelope)
        return PopulatedCustody(
            store=store,
            factory=factory,
            policy=policy,
            envelope=envelope,
            custody_receipt=append.receipt,
            custody_event=append.event,
        )

    @staticmethod
    def _inspect(populated: PopulatedCustody) -> object:
        return populated.store.inspect_current_head(
            tenant_id=populated.policy.tenant_id,
            mission_id=populated.policy.mission_id,
            chain_id=populated.policy.chain_id,
        )

    @staticmethod
    def _durable_snapshot(path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
        return phase198.TargetHealthCustodyPhase198Tests.durable_snapshot(path)

    @staticmethod
    def _rewrite(
        path: Path,
        tables: tuple[str, ...],
        mutation: Callable[[sqlite3.Connection], None],
    ) -> None:
        phase198.TargetHealthCustodyPhase198Tests.rewrite_with_triggers_restored(
            path,
            tables,
            mutation,
        )

    @staticmethod
    def _alternate_policy(
        factory: phase198.ContractFactory,
        *,
        collector_id: str,
        collector_key: Ed25519PrivateKey,
    ) -> TargetHealthCollectorPolicyRevision:
        template = factory.make_policy()
        public_key, fingerprint = phase198.public_material(collector_key)
        unsigned = template.unsigned_body()
        unsigned.update(
            {
                "chain_id": target_health_chain_id(
                    collector_id,
                    factory.root.mission_id,
                    factory.binding_sha256,
                ),
                "collector_id": collector_id,
                "collector_key_id": "key:collector-alternate-epoch-1",
                "collector_public_key": public_key,
                "collector_public_key_sha256": fingerprint,
            }
        )
        signature = phase198.b64(
            factory.root_key.sign(
                TargetHealthCollectorPolicyRevision.signing_bytes_for(unsigned)
            )
        )
        return TargetHealthCollectorPolicyRevision(
            **{
                key: value
                for key, value in unsigned.items()
                if key not in set(INSPECTION_EFFECTS) | {"binding"}
            },
            binding=factory.binding,
            root_signature=signature,
        )

    def test_inspection_returns_exact_current_material_in_one_read_transaction(self) -> None:
        populated = self._populate("exact-material")
        with patch.object(
            populated.store,
            "_read",
            wraps=populated.store._read,
        ) as read:
            inspection = self._inspect(populated)

        self.assertIsInstance(inspection, self._inspection_type())
        self.assertEqual(read.call_count, 1)
        self.assertEqual(inspection.tenant_id, populated.policy.tenant_id)
        self.assertEqual(inspection.mission_id, populated.policy.mission_id)
        self.assertEqual(inspection.chain_id, populated.policy.chain_id)
        self.assertEqual(inspection.current_policy.binding, populated.factory.binding)
        head = inspection.head_binding
        self.assertEqual(head.binding_sha256, populated.factory.binding_sha256)
        self.assertEqual(inspection.trust_root, populated.factory.root)
        self.assertEqual(inspection.current_policy, populated.policy)
        self.assertIsNone(inspection.policy_revocation)
        self.assertEqual(inspection.envelope, populated.envelope)
        self.assertEqual(inspection.custody_receipt, populated.custody_receipt)
        self.assertEqual(inspection.custody_event, populated.custody_event)
        self.assertEqual(
            head.chain_head_custody_receipt_id,
            populated.custody_receipt.custody_receipt_id,
        )
        self.assertEqual(
            head.chain_head_custody_receipt_sha256,
            populated.custody_receipt.custody_receipt_sha256,
        )
        self.assertEqual(head.event_head_event_id, populated.custody_event.event_id)
        self.assertEqual(
            head.event_head_event_sha256,
            populated.custody_event.event_sha256,
        )
        self.assertEqual(head.policy_head_transition_sequence, 1)
        self.assertEqual(head.policy_id, populated.policy.policy_id)
        self.assertEqual(head.chain_head_transition_sequence, 2)
        self.assertEqual(head.chain_head_sequence, 1)
        self.assertEqual(head.event_head_sequence, 1)
        self.assertEqual(head.global_transition_sequence, 2)
        self.assertEqual(inspection.verification.envelope_id, populated.envelope.envelope_id)
        self.assertEqual(inspection.inspected_at, "2026-09-21T12:00:10Z")
        self.assertRegex(inspection.current_material_sha256, r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(inspection.inspection_id, r"^THCI-[0-9A-F]{32}$")
        self.assertRegex(inspection.inspection_sha256, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(head.store_application_id, APPLICATION_ID)
        self.assertEqual(head.store_schema_version, SCHEMA_VERSION)
        self.assertEqual(head.store_migration_id, MIGRATION_ID)
        self.assertEqual(head.store_migration_sha256, MIGRATION_SHA256)
        self.assertEqual(
            head.store_schema_manifest_sha256,
            EXPECTED_SCHEMA_MANIFEST_SHA256,
        )

    def test_same_second_contexts_distinguish_inspection_identity_not_material(self) -> None:
        populated = self._populate("same-second-contexts")
        inspection_arguments = {
            "tenant_id": populated.policy.tenant_id,
            "mission_id": populated.policy.mission_id,
            "binding_sha256": populated.policy.binding_sha256,
        }

        first = populated.store.inspect_unique_current_binding_head(
            **inspection_arguments,
            inspection_context_sha256=DIGEST_D,
        )
        second = populated.store.inspect_unique_current_binding_head(
            **inspection_arguments,
            inspection_context_sha256=DIGEST_E,
        )

        self.assertEqual(first.inspected_at, second.inspected_at)
        self.assertEqual(first.inspection_context_sha256, DIGEST_D)
        self.assertEqual(second.inspection_context_sha256, DIGEST_E)
        self.assertEqual(first.current_material_sha256, second.current_material_sha256)
        self.assertNotEqual(first.inspection_id, second.inspection_id)
        self.assertNotEqual(first.inspection_sha256, second.inspection_sha256)
        self.assertEqual(first.head_binding, second.head_binding)
        self.assertEqual(first.verification, second.verification)

    def test_inspection_exposes_completed_and_rejected_health_without_reclassifying(self) -> None:
        expectations = {
            "healthy": (TargetHealthStatus.COMPLETED, HealthSignalState.HEALTHY),
            "degraded": (TargetHealthStatus.COMPLETED, HealthSignalState.DEGRADED),
            "unhealthy": (TargetHealthStatus.COMPLETED, HealthSignalState.UNHEALTHY),
            "rejected": (TargetHealthStatus.REJECTED, None),
        }
        for state, expected in expectations.items():
            with self.subTest(state=state):
                populated = self._populate(
                    f"receipt-{state}",
                    receipt=self._receipt(state),
                    clock="2026-09-20T12:00:10Z",
                )
                inspection = self._inspect(populated)
                embedded = inspection.envelope.receipt
                self.assertEqual((embedded.status, embedded.overall_health), expected)
                self.assertEqual(embedded, populated.envelope.receipt)
                self.assertEqual(
                    inspection.verification.receipt_sha256,
                    embedded.receipt_sha256,
                )

    def test_global_transition_high_water_advances_for_scheduled_revocation(self) -> None:
        populated = self._populate("scheduled-revocation")
        before = self._inspect(populated)
        revocation = populated.factory.make_revocation(
            populated.policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        populated.store.publish_revocation(revocation)
        after = self._inspect(populated)

        self.assertEqual(before.envelope.sequence, after.envelope.sequence)
        self.assertEqual(
            before.head_binding.chain_head_sequence,
            after.head_binding.chain_head_sequence,
        )
        self.assertEqual(before.head_binding.global_transition_sequence, 2)
        self.assertEqual(after.head_binding.global_transition_sequence, 3)
        self.assertEqual(after.policy_revocation, revocation)
        self.assertEqual(after.head_binding.policy_revocation_transition_sequence, 3)
        self.assertEqual(
            after.head_binding.policy_revocation_id,
            revocation.revocation_id,
        )

        snapshot = self._durable_snapshot(populated.store.path)
        populated.store._trusted_clock = phase198.FixedClock(
            "2026-09-21T12:00:20Z"
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self._inspect(populated)
        self.assertEqual(self._durable_snapshot(populated.store.path), snapshot)

    def test_policy_rotation_requires_a_current_envelope_and_updates_all_heads(self) -> None:
        populated = self._populate("policy-rotation")
        second_policy = populated.factory.make_policy(
            revision=2,
            previous=populated.policy,
        )
        populated.store.publish_policy(second_policy)
        with self.assertRaises(TargetHealthCustodyConflictError):
            self._inspect(populated)

        second_envelope = populated.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=populated.envelope,
        )
        appended = populated.store.append_envelope(second_envelope)
        inspection = populated.store.inspect_current_head(
            tenant_id=second_policy.tenant_id,
            mission_id=second_policy.mission_id,
            chain_id=second_policy.chain_id,
        )
        self.assertEqual(inspection.current_policy, second_policy)
        self.assertEqual(inspection.envelope, second_envelope)
        self.assertEqual(
            inspection.head_binding.chain_head_custody_receipt_id,
            appended.receipt.custody_receipt_id,
        )
        self.assertEqual(
            inspection.head_binding.event_head_event_id,
            appended.event.event_id,
        )
        self.assertEqual(inspection.head_binding.policy_head_transition_sequence, 3)
        self.assertEqual(inspection.head_binding.chain_head_transition_sequence, 4)
        self.assertEqual(inspection.head_binding.global_transition_sequence, 4)
        self.assertEqual(inspection.envelope.sequence, 2)

    def test_unique_binding_lookup_handles_zero_one_and_multiple_current_chains(self) -> None:
        factory = phase198.ContractFactory()
        store = SQLiteTargetHealthCustody(
            self.directory / "unique-binding.sqlite3",
            trust_root=factory.root,
            trusted_clock=phase198.FixedClock("2026-09-21T12:00:10Z"),
        )
        with self.assertRaises(TargetHealthCustodyNotFoundError):
            store.inspect_unique_current_binding_head(
                tenant_id=factory.root.tenant_id,
                mission_id=factory.root.mission_id,
                binding_sha256=factory.binding_sha256,
            )

        first_policy = factory.make_policy()
        store.publish_policy(first_policy)
        first_envelope = factory.make_envelope(
            first_policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        store.append_envelope(first_envelope)
        with patch.object(store, "_read", wraps=store._read) as read:
            unique = store.inspect_unique_current_binding_head(
                tenant_id=first_policy.tenant_id,
                mission_id=first_policy.mission_id,
                binding_sha256=first_policy.binding_sha256,
            )
        self.assertEqual(read.call_count, 1)
        self.assertEqual(unique.chain_id, first_policy.chain_id)

        alternate_key = Ed25519PrivateKey.generate()
        second_policy = self._alternate_policy(
            factory,
            collector_id="collector:health-prod-2",
            collector_key=alternate_key,
        )
        store.publish_policy(second_policy)
        factory.collector_keys[1] = alternate_key
        second_envelope = factory.make_envelope(
            second_policy,
            sequence=1,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
        )
        store.append_envelope(second_envelope)
        with self.assertRaises(TargetHealthCustodyConflictError):
            store.inspect_unique_current_binding_head(
                tenant_id=first_policy.tenant_id,
                mission_id=first_policy.mission_id,
                binding_sha256=first_policy.binding_sha256,
            )

    def test_inspection_is_restart_stable_and_performs_no_writes(self) -> None:
        populated = self._populate("restart-stable")
        before = self._durable_snapshot(populated.store.path)
        with patch.object(
            populated.store,
            "_mutation_checkpoint",
            side_effect=AssertionError("inspection attempted a mutation"),
        ):
            first = self._inspect(populated)
            second = self._inspect(populated)
        self.assertEqual(first, second)
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertEqual(self._durable_snapshot(populated.store.path), before)

        reopened = SQLiteTargetHealthCustody(
            populated.store.path,
            trust_root=populated.factory.root,
            trusted_clock=phase198.FixedClock("2026-09-21T12:00:10Z"),
        )
        restarted = reopened.inspect_current_head(
            tenant_id=populated.policy.tenant_id,
            mission_id=populated.policy.mission_id,
            chain_id=populated.policy.chain_id,
        )
        self.assertEqual(restarted, first)
        self.assertEqual(self._durable_snapshot(populated.store.path), before)

    def test_cross_scope_and_binding_substitution_fail_closed(self) -> None:
        populated = self._populate("cross-scope")
        for arguments in (
            {
                "tenant_id": "tenant:other",
                "mission_id": populated.policy.mission_id,
                "chain_id": populated.policy.chain_id,
            },
            {
                "tenant_id": populated.policy.tenant_id,
                "mission_id": "mission:other",
                "chain_id": populated.policy.chain_id,
            },
        ):
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(TargetHealthCustodyNotFoundError),
            ):
                populated.store.inspect_current_head(**arguments)
        with self.assertRaises(TargetHealthCustodyNotFoundError):
            populated.store.inspect_unique_current_binding_head(
                tenant_id=populated.policy.tenant_id,
                mission_id=populated.policy.mission_id,
                binding_sha256=DIGEST_D,
            )
        with self.assertRaises(TargetHealthCustodyValidationError):
            populated.store.inspect_current_head(
                tenant_id="",
                mission_id=populated.policy.mission_id,
                chain_id=populated.policy.chain_id,
            )

        def substitute_binding(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_chain_heads SET binding_sha256=? WHERE chain_id=?",
                (DIGEST_D, populated.policy.chain_id),
            )

        self._rewrite(
            populated.store.path,
            ("target_health_chain_heads",),
            substitute_binding,
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self._inspect(populated)

    def test_inspection_rejects_head_transition_and_record_tampering(self) -> None:
        cases = (
            (
                "chain-head",
                ("target_health_chain_heads",),
                "UPDATE target_health_chain_heads SET envelope_sha256=? WHERE chain_id=?",
                (DIGEST_D, "chain"),
            ),
            (
                "transition",
                ("target_health_envelopes",),
                "UPDATE target_health_envelopes SET transition_sequence=99 WHERE chain_id=?",
                ("chain",),
            ),
            (
                "root",
                ("target_health_trust_roots",),
                "UPDATE target_health_trust_roots SET root_json='{}' WHERE trust_root_id=?",
                ("root",),
            ),
            (
                "policy",
                ("target_health_collector_policies",),
                "UPDATE target_health_collector_policies SET policy_json='{}' WHERE policy_id=?",
                ("policy",),
            ),
            (
                "envelope",
                ("target_health_envelopes",),
                "UPDATE target_health_envelopes SET envelope_json='{}' WHERE envelope_id=?",
                ("envelope",),
            ),
            (
                "event",
                ("target_health_custody_events",),
                "UPDATE target_health_custody_events SET event_json='{}' WHERE envelope_id=?",
                ("envelope",),
            ),
            (
                "event-head",
                ("target_health_event_heads",),
                "UPDATE target_health_event_heads SET event_sha256=? WHERE chain_id=?",
                (DIGEST_D, "chain"),
            ),
        )
        for label, tables, statement, parameters in cases:
            with self.subTest(label=label):
                populated = self._populate(f"tamper-{label}")
                replacements = {
                    "chain": populated.policy.chain_id,
                    "root": populated.factory.root.trust_root_id,
                    "policy": populated.policy.policy_id,
                    "envelope": populated.envelope.envelope_id,
                }
                values = tuple(replacements.get(value, value) for value in parameters)

                def corrupt(
                    connection: sqlite3.Connection,
                    exact_statement: str = statement,
                    exact_values: tuple[object, ...] = values,
                ) -> None:
                    connection.execute(exact_statement, exact_values)

                self._rewrite(populated.store.path, tables, corrupt)
                before = self._durable_snapshot(populated.store.path)
                with self.assertRaises(TargetHealthCustodyIntegrityError):
                    self._inspect(populated)
                self.assertEqual(self._durable_snapshot(populated.store.path), before)

    def test_inspection_rejects_revocation_record_and_head_tampering(self) -> None:
        for label, table, statement in (
            (
                "revocation-record",
                "target_health_collector_policy_revocations",
                "UPDATE target_health_collector_policy_revocations "
                "SET revocation_json='{}' WHERE policy_id=?",
            ),
            (
                "revocation-head",
                "target_health_policy_revocation_heads",
                "UPDATE target_health_policy_revocation_heads "
                "SET revocation_sha256=? WHERE policy_id=?",
            ),
        ):
            with self.subTest(label=label):
                populated = self._populate(f"tamper-{label}")
                revocation = populated.factory.make_revocation(
                    populated.policy,
                    revoked_at="2026-09-21T12:00:20Z",
                )
                populated.store.publish_revocation(revocation)

                parameters = (
                    (populated.policy.policy_id,)
                    if label == "revocation-record"
                    else (DIGEST_D, populated.policy.policy_id)
                )

                def corrupt(
                    connection: sqlite3.Connection,
                    exact_statement: str = statement,
                    exact_parameters: tuple[object, ...] = parameters,
                ) -> None:
                    connection.execute(exact_statement, exact_parameters)

                self._rewrite(populated.store.path, (table,), corrupt)
                with self.assertRaises(TargetHealthCustodyIntegrityError):
                    self._inspect(populated)

    def test_busy_unavailable_and_regressing_clock_are_typed_failures(self) -> None:
        populated = self._populate("typed-failures")
        connection = sqlite3.connect(populated.store.path, isolation_level=None)
        locked = LockedReadConnection(connection)
        try:
            with (
                patch.object(populated.store, "_connect", return_value=locked),
                self.assertRaises(TargetHealthCustodyBusyError),
            ):
                self._inspect(populated)
        finally:
            if not locked.closed:
                locked.close()

        with (
            patch(
                "sunderkey.target_health_custody.sqlite3.connect",
                side_effect=sqlite3.OperationalError("open failed"),
            ),
            self.assertRaises(TargetHealthCustodyIntegrityError),
        ):
            self._inspect(populated)

        populated.store._trusted_clock = phase198.FixedClock("2026-09-21T12:00:09Z")
        before = self._durable_snapshot(populated.store.path)
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self._inspect(populated)
        self.assertEqual(self._durable_snapshot(populated.store.path), before)

    def test_configuration_stage_locked_and_busy_are_typed_busy_failures(self) -> None:
        populated = self._populate("configuration-busy")
        for message in ("database is locked", "database is busy"):
            with self.subTest(message=message):
                connection = sqlite3.connect(
                    populated.store.path,
                    isolation_level=None,
                )
                failing = ConfigurationFailureConnection(connection, message)
                try:
                    with (
                        patch(
                            "sunderkey.target_health_custody.sqlite3.connect",
                            return_value=failing,
                        ),
                        self.assertRaises(TargetHealthCustodyBusyError),
                    ):
                        self._inspect(populated)
                finally:
                    if not failing.closed:
                        failing.close()

    def test_final_clock_sample_enforces_scheduled_revocation_cutoff(self) -> None:
        populated = self._populate("final-clock-revocation")
        revocation = populated.factory.make_revocation(
            populated.policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        populated.store.publish_revocation(revocation)
        clock = phase198.SequenceClock(
            "2026-09-21T12:00:19Z",
            "2026-09-21T12:00:20Z",
        )
        populated.store._trusted_clock = clock
        before = self._durable_snapshot(populated.store.path)

        with self.assertRaises(TargetHealthCustodyConflictError):
            self._inspect(populated)

        self.assertEqual(clock.calls, 2)
        self.assertEqual(self._durable_snapshot(populated.store.path), before)

    def test_within_inspection_final_clock_regression_fails_integrity(self) -> None:
        populated = self._populate("final-clock-regression")
        clock = phase198.SequenceClock(
            "2026-09-21T12:00:11Z",
            "2026-09-21T12:00:10Z",
        )
        populated.store._trusted_clock = clock
        before = self._durable_snapshot(populated.store.path)

        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self._inspect(populated)

        self.assertEqual(clock.calls, 2)
        self.assertEqual(self._durable_snapshot(populated.store.path), before)

    def test_inspection_declares_no_authority_network_or_control_effects(self) -> None:
        populated = self._populate(
            "no-effects",
            receipt=self._receipt("unhealthy"),
            clock="2026-09-20T12:00:10Z",
        )
        inspection = self._inspect(populated)
        document = inspection.to_dict()
        for field, expected in INSPECTION_EFFECTS.items():
            self.assertIn(field, document)
            self.assertEqual(document[field], expected)
        self.assertEqual(inspection.envelope.receipt.authority_effect, "none")
        self.assertEqual(inspection.envelope.receipt.qualification_effect, "none")
        self.assertFalse(inspection.envelope.receipt.network_call_performed)
        self.assertNotIn("authorization", document)
        self.assertNotIn("command", document)


if __name__ == "__main__":
    unittest.main()

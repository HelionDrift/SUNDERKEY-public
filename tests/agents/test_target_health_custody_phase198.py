import base64
import hashlib
import importlib
import socket
import sqlite3
import tempfile
import unittest
import urllib.request
from collections import deque
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.authorized_target_health_runtime import TargetHealthReceipt, TargetHealthStatus
from sunderkey.execution_control_runtime import ExecutionBinding, canonical_json
from sunderkey.target_health_custody import (
    APPLICATION_ID,
    EXPECTED_SCHEMA_MANIFEST_SHA256,
    MAX_PAGE_SIZE,
    MIGRATION_ID,
    MIGRATION_SHA256,
    SCHEMA_VERSION,
    SQLiteTargetHealthCustody,
    TargetHealthCustodyBusyError,
    TargetHealthCustodyConflictError,
    TargetHealthCustodyError,
    TargetHealthCustodyIntegrityError,
    TargetHealthCustodyNotFoundError,
    TargetHealthCustodyValidationError,
)
from sunderkey.target_health_custody_contracts import (
    SignedTargetHealthCustodyEnvelopeV2,
    TargetHealthCollectorPolicyRevision,
    TargetHealthCollectorPolicyRevocation,
    TargetHealthCustodyContractError,
    TargetHealthCustodyEvent,
    TargetHealthCustodyReceipt,
    TargetHealthCustodyVerificationResult,
    TargetHealthTrustRoot,
    TargetHealthVerificationMode,
    build_target_health_custody_event,
    build_target_health_custody_receipt,
    execution_binding_sha256,
    target_health_chain_id,
)

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "src" / "sunderkey" / "target_health_custody.py"
TEST_FILE = Path(__file__)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64
NO_EFFECTS = {
    "authority_effect": "none",
    "collection_effect": "none",
    "network_call_performed": False,
    "pause_effect": "none",
    "qualification_effect": "none",
    "resume_effect": "none",
    "target_effect_performed": False,
}


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_material(key: Ed25519PrivateKey) -> tuple[str, str]:
    raw = key.public_key().public_bytes_raw()
    return b64(raw), "sha256:" + hashlib.sha256(raw).hexdigest()


def instant(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


class FixedClock:
    def __init__(self, value: str) -> None:
        self.value = instant(value)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        return self.value


class SequenceClock:
    def __init__(self, *values: str) -> None:
        self.values = deque(instant(value) for value in values)
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        if not self.values:
            raise AssertionError("trusted clock was sampled too many times")
        return self.values.popleft()


class FailingConnection:
    def __init__(self, connection: sqlite3.Connection, needle: str) -> None:
        self.connection = connection
        self.needle = needle

    @property
    def row_factory(self) -> object:
        return self.connection.row_factory

    @row_factory.setter
    def row_factory(self, value: object) -> None:
        self.connection.row_factory = value

    def execute(self, statement: str, *arguments: object) -> sqlite3.Cursor:
        if self.needle in statement:
            raise sqlite3.OperationalError("injected SQLite failure")
        return self.connection.execute(statement, *arguments)

    def __getattr__(self, name: str) -> object:
        return getattr(self.connection, name)


class ContractFactory:
    def __init__(self, *, mission_id: str = "mission:health-1") -> None:
        self.root_key = Ed25519PrivateKey.generate()
        self.collector_keys = {1: Ed25519PrivateKey.generate()}
        self.binding = ExecutionBinding(
            tenant_id="tenant:acme",
            context_id="context:health-1",
            context_sha256=DIGEST_A,
            scope_id="scope:health-1",
            scope_sha256=DIGEST_B,
            target_id="target:app-1",
            target_sha256=DIGEST_C,
            session_id="session:health-1",
            lease_id="lease:health-1",
            fence_epoch=7,
        )
        self.binding_sha256 = execution_binding_sha256(self.binding)
        root_public, root_fingerprint = public_material(self.root_key)
        self.root = TargetHealthTrustRoot(
            tenant_id=self.binding.tenant_id,
            mission_id=mission_id,
            trust_root_revision=1,
            root_key_id="key:root-2026-09",
            root_public_key=root_public,
            root_public_key_sha256=root_fingerprint,
            deployment_attestation_id="attestation:collector-prod-1",
            deployment_attestation_sha256=DIGEST_D,
            effective_at="2026-09-21T00:00:00Z",
            expires_at="2026-09-22T00:00:00Z",
        )

    def make_policy(
        self,
        *,
        revision: int = 1,
        epoch: int = 1,
        previous: TargetHealthCollectorPolicyRevision | None = None,
        prior_envelope: SignedTargetHealthCustodyEnvelopeV2 | None = None,
        collector_key: Ed25519PrivateKey | None = None,
        issued_at: str = "2026-09-21T10:59:00Z",
        effective_at: str = "2026-09-21T11:00:00Z",
        expires_at: str = "2026-09-21T18:00:00Z",
        runtime_policy_id: str = "THP-0123456789ABCDEF0123456789ABCDEF",
        runtime_policy_sha256: str = DIGEST_A,
    ) -> TargetHealthCollectorPolicyRevision:
        key = collector_key or self.collector_keys.setdefault(
            epoch, Ed25519PrivateKey.generate()
        )
        collector_public, collector_fingerprint = public_material(key)
        collector_id = "collector:health-prod-1"
        unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": target_health_chain_id(
                collector_id,
                self.root.mission_id,
                self.binding_sha256,
            ),
            "collector_epoch": epoch,
            "collector_id": collector_id,
            "collector_key_id": f"key:collector-epoch-{epoch}",
            "collector_public_key": collector_public,
            "collector_public_key_sha256": collector_fingerprint,
            "deployment_attestation_id": self.root.deployment_attestation_id,
            "deployment_attestation_sha256": self.root.deployment_attestation_sha256,
            "effective_at": effective_at,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "maximum_future_skew_seconds": 5,
            "maximum_observation_age_seconds": 120,
            "mission_id": self.root.mission_id,
            "policy_revision": revision,
            "policy_status": "active",
            "predecessor_policy_id": None if previous is None else previous.policy_id,
            "predecessor_policy_sha256": (
                None if previous is None else previous.policy_sha256
            ),
            "prior_epoch_head_envelope_id": (
                None if prior_envelope is None else prior_envelope.envelope_id
            ),
            "prior_epoch_head_envelope_sha256": (
                None if prior_envelope is None else prior_envelope.envelope_sha256
            ),
            "revoked": False,
            "runtime_policy_id": runtime_policy_id,
            "runtime_policy_sha256": runtime_policy_sha256,
            "signature_algorithm": "Ed25519",
            "tenant_id": self.binding.tenant_id,
            "trust_root_id": self.root.trust_root_id,
            "trust_root_revision": self.root.trust_root_revision,
            "trust_root_sha256": self.root.trust_root_sha256,
            **NO_EFFECTS,
        }
        signature = b64(
            self.root_key.sign(
                TargetHealthCollectorPolicyRevision.signing_bytes_for(unsigned)
            )
        )
        return TargetHealthCollectorPolicyRevision(
            **{
                name: value
                for name, value in unsigned.items()
                if name not in set(NO_EFFECTS) | {"binding"}
            },
            binding=self.binding,
            root_signature=signature,
        )

    def make_receipt(
        self,
        *,
        observed_at: str,
        monotonic_tick: int,
    ) -> TargetHealthReceipt:
        return TargetHealthReceipt(
            status=TargetHealthStatus.REJECTED,
            reason="missing_attestation",
            overall_health=None,
            scope_id=self.binding.scope_id,
            scope_sha256=self.binding.scope_sha256,
            execution_request_id=(
                f"THQ-{monotonic_tick:032X}"
            ),
            execution_request_sha256=DIGEST_A,
            admission_receipt_id=f"ADM-{monotonic_tick:032X}",
            admission_receipt_sha256=DIGEST_B,
            execution_policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            execution_policy_sha256=DIGEST_C,
            runtime_policy_id="THP-0123456789ABCDEF0123456789ABCDEF",
            runtime_policy_sha256=DIGEST_A,
            binding=self.binding,
            binding_sha256=self.binding_sha256,
            target_url="https://app.example.test/assess/health",
            observed_at=observed_at,
            monotonic_tick=monotonic_tick,
            safety_attestation=None,
            safety_attestation_sha256=None,
            budget_state=None,
            budget_state_sha256=None,
            source_receipts=(),
            observations=(),
            source_validation_performed=False,
        )

    def make_envelope(
        self,
        policy: TargetHealthCollectorPolicyRevision,
        *,
        sequence: int,
        observed_at: str,
        monotonic_tick: int,
        predecessor: SignedTargetHealthCustodyEnvelopeV2 | None = None,
        predecessor_id: str | None = None,
        predecessor_sha256: str | None = None,
        receipt: TargetHealthReceipt | None = None,
    ) -> SignedTargetHealthCustodyEnvelopeV2:
        exact_receipt = receipt or self.make_receipt(
            observed_at=observed_at, monotonic_tick=monotonic_tick
        )
        effective_predecessor_id = (
            predecessor.envelope_id if predecessor is not None else predecessor_id
        )
        effective_predecessor_sha256 = (
            predecessor.envelope_sha256 if predecessor is not None else predecessor_sha256
        )
        unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": policy.chain_id,
            "collector_epoch": policy.collector_epoch,
            "collector_id": policy.collector_id,
            "collector_key_id": policy.collector_key_id,
            "collector_public_key": policy.collector_public_key,
            "collector_public_key_sha256": policy.collector_public_key_sha256,
            "deployment_attestation_id": policy.deployment_attestation_id,
            "deployment_attestation_sha256": policy.deployment_attestation_sha256,
            "mission_id": policy.mission_id,
            "observed_at": exact_receipt.observed_at,
            "policy_id": policy.policy_id,
            "policy_revision": policy.policy_revision,
            "policy_sha256": policy.policy_sha256,
            "predecessor_envelope_id": effective_predecessor_id,
            "predecessor_envelope_sha256": effective_predecessor_sha256,
            "receipt": exact_receipt.to_dict(),
            "receipt_id": exact_receipt.receipt_id,
            "receipt_sha256": exact_receipt.receipt_sha256,
            "runtime_policy_id": exact_receipt.runtime_policy_id,
            "runtime_policy_sha256": exact_receipt.runtime_policy_sha256,
            "sequence": sequence,
            "signature_algorithm": "Ed25519",
            "tenant_id": self.binding.tenant_id,
            **NO_EFFECTS,
        }
        signature = b64(
            self.collector_keys[policy.collector_epoch].sign(
                SignedTargetHealthCustodyEnvelopeV2.signing_bytes_for(unsigned)
            )
        )
        return SignedTargetHealthCustodyEnvelopeV2(
            **{
                name: value
                for name, value in unsigned.items()
                if name not in set(NO_EFFECTS) | {"binding", "receipt"}
            },
            binding=self.binding,
            receipt=exact_receipt,
            collector_signature=signature,
        )

    def make_revocation(
        self,
        policy: TargetHealthCollectorPolicyRevision,
        *,
        revoked_at: str,
    ) -> TargetHealthCollectorPolicyRevocation:
        unsigned = {
            "binding": self.binding.to_dict(),
            "binding_sha256": self.binding_sha256,
            "chain_id": policy.chain_id,
            "collector_epoch": policy.collector_epoch,
            "collector_id": policy.collector_id,
            "mission_id": policy.mission_id,
            "policy_id": policy.policy_id,
            "policy_revision": policy.policy_revision,
            "policy_sha256": policy.policy_sha256,
            "revocation_reason": "collector_key_compromised",
            "revoked": True,
            "revoked_at": revoked_at,
            "signature_algorithm": "Ed25519",
            "tenant_id": policy.tenant_id,
            "terminal": True,
            "trust_root_id": self.root.trust_root_id,
            "trust_root_revision": self.root.trust_root_revision,
            "trust_root_sha256": self.root.trust_root_sha256,
            **NO_EFFECTS,
        }
        signature = b64(
            self.root_key.sign(
                TargetHealthCollectorPolicyRevocation.signing_bytes_for(unsigned)
            )
        )
        return TargetHealthCollectorPolicyRevocation(
            **{
                name: value
                for name, value in unsigned.items()
                if name not in set(NO_EFFECTS) | {"binding"}
            },
            binding=self.binding,
            root_signature=signature,
        )


class TargetHealthCustodyPhase198Tests(unittest.TestCase):
    MUTABLE_TABLES = (
        "target_health_collector_policies",
        "target_health_collector_policy_revocations",
        "target_health_policy_revocation_heads",
        "target_health_policy_heads",
        "target_health_envelopes",
        "target_health_custody_receipts",
        "target_health_custody_events",
        "target_health_chain_heads",
        "target_health_event_heads",
    )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.factory = ContractFactory()
        self.clock = FixedClock("2026-09-21T12:00:10Z")
        self.store = SQLiteTargetHealthCustody(
            self.directory / "custody.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=self.clock,
        )

    @staticmethod
    def table_count(path: Path, table: str) -> int:
        connection = sqlite3.connect(path)
        try:
            return int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            connection.close()

    @classmethod
    def durable_snapshot(cls, path: Path) -> dict[str, tuple[tuple[object, ...], ...]]:
        connection = sqlite3.connect(path)
        try:
            return {
                table: tuple(
                    tuple(row)
                    for row in connection.execute(
                        f'SELECT * FROM "{table}" ORDER BY rowid'
                    ).fetchall()
                )
                for table in cls.MUTABLE_TABLES
            }
        finally:
            connection.close()

    @staticmethod
    def insert_row(
        connection: sqlite3.Connection,
        table: str,
        values: dict[str, object],
    ) -> None:
        columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
        missing = set(columns) - set(values)
        if missing:
            raise AssertionError(f"missing fixture columns for {table}: {sorted(missing)}")
        placeholders = ",".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})",
            tuple(values[column] for column in columns),
        )

    @staticmethod
    def rewrite_with_triggers_restored(
        path: Path,
        tables: tuple[str, ...],
        mutation: Callable[[sqlite3.Connection], None],
    ) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute("PRAGMA foreign_keys=OFF")
            triggers = connection.execute(
                "SELECT name,sql FROM sqlite_schema WHERE type='trigger' "
                f"AND tbl_name IN ({','.join('?' for _ in tables)}) ORDER BY name",
                tables,
            ).fetchall()
            connection.execute("BEGIN IMMEDIATE")
            for name, _ in triggers:
                connection.execute(f'DROP TRIGGER "{name}"')
            mutation(connection)
            for _, sql in triggers:
                connection.execute(sql)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def inject_policy(
        self,
        policy: TargetHealthCollectorPolicyRevision,
        *,
        transition: int = 1,
        published_at: str = "2026-09-21T12:00:10Z",
        make_head: bool = True,
    ) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            self.insert_row(
                connection,
                "target_health_collector_policies",
                {
                    "transition_sequence": transition,
                    "policy_id": policy.policy_id,
                    "policy_sha256": policy.policy_sha256,
                    "tenant_id": policy.tenant_id,
                    "mission_id": policy.mission_id,
                    "trust_root_id": policy.trust_root_id,
                    "trust_root_sha256": policy.trust_root_sha256,
                    "trust_root_revision": policy.trust_root_revision,
                    "chain_id": policy.chain_id,
                    "binding_sha256": policy.binding_sha256,
                    "collector_id": policy.collector_id,
                    "collector_epoch": policy.collector_epoch,
                    "policy_revision": policy.policy_revision,
                    "predecessor_policy_id": policy.predecessor_policy_id,
                    "predecessor_policy_sha256": policy.predecessor_policy_sha256,
                    "prior_epoch_head_envelope_id": policy.prior_epoch_head_envelope_id,
                    "prior_epoch_head_envelope_sha256": (
                        policy.prior_epoch_head_envelope_sha256
                    ),
                    "published_at": published_at,
                    "policy_json": canonical_json(policy.to_dict()),
                },
            )
            if make_head:
                self.insert_row(
                    connection,
                    "target_health_policy_heads",
                    {
                        "chain_id": policy.chain_id,
                        "tenant_id": policy.tenant_id,
                        "mission_id": policy.mission_id,
                        "policy_id": policy.policy_id,
                        "policy_sha256": policy.policy_sha256,
                        "policy_revision": policy.policy_revision,
                        "collector_epoch": policy.collector_epoch,
                        "transition_sequence": transition,
                    },
                )
            connection.commit()
        finally:
            connection.close()

    def inject_revocation(
        self,
        revocation: TargetHealthCollectorPolicyRevocation,
        *,
        transition: int,
        published_at: str = "2026-09-21T12:00:10Z",
    ) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            self.insert_row(
                connection,
                "target_health_collector_policy_revocations",
                {
                    "transition_sequence": transition,
                    "revocation_id": revocation.revocation_id,
                    "revocation_sha256": revocation.revocation_sha256,
                    "tenant_id": revocation.tenant_id,
                    "mission_id": revocation.mission_id,
                    "trust_root_id": revocation.trust_root_id,
                    "trust_root_sha256": revocation.trust_root_sha256,
                    "trust_root_revision": revocation.trust_root_revision,
                    "chain_id": revocation.chain_id,
                    "policy_id": revocation.policy_id,
                    "policy_sha256": revocation.policy_sha256,
                    "policy_revision": revocation.policy_revision,
                    "collector_epoch": revocation.collector_epoch,
                    "revoked_at": revocation.revoked_at,
                    "published_at": published_at,
                    "revocation_json": canonical_json(revocation.to_dict()),
                },
            )
            self.insert_row(
                connection,
                "target_health_policy_revocation_heads",
                {
                    "policy_id": revocation.policy_id,
                    "chain_id": revocation.chain_id,
                    "tenant_id": revocation.tenant_id,
                    "mission_id": revocation.mission_id,
                    "revocation_id": revocation.revocation_id,
                    "revocation_sha256": revocation.revocation_sha256,
                    "revoked_at": revocation.revoked_at,
                    "transition_sequence": transition,
                },
            )
            connection.commit()
        finally:
            connection.close()

    def inject_envelope_bundle(
        self,
        policy: TargetHealthCollectorPolicyRevision,
        envelope: SignedTargetHealthCustodyEnvelopeV2,
        *,
        transition: int,
        accepted_at: str,
        verified_at: str | None = None,
        recorded_at: str | None = None,
    ) -> tuple[TargetHealthCustodyReceipt, TargetHealthCustodyEvent]:
        verification = TargetHealthCustodyVerificationResult(
            mode=TargetHealthVerificationMode.CURRENT,
            verified_at=verified_at or accepted_at,
            tenant_id=envelope.tenant_id,
            mission_id=envelope.mission_id,
            binding=envelope.binding,
            binding_sha256=envelope.binding_sha256,
            trust_root_id=self.factory.root.trust_root_id,
            trust_root_sha256=self.factory.root.trust_root_sha256,
            trust_root_revision=self.factory.root.trust_root_revision,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            policy_revision=policy.policy_revision,
            policy_revocation_id=None,
            policy_revocation_sha256=None,
            collector_id=envelope.collector_id,
            collector_epoch=envelope.collector_epoch,
            chain_id=envelope.chain_id,
            envelope_id=envelope.envelope_id,
            envelope_sha256=envelope.envelope_sha256,
            envelope_observed_at=envelope.observed_at,
            sequence=envelope.sequence,
            predecessor_envelope_id=envelope.predecessor_envelope_id,
            predecessor_envelope_sha256=envelope.predecessor_envelope_sha256,
            receipt_id=envelope.receipt_id,
            receipt_sha256=envelope.receipt_sha256,
            signatures_verified=True,
            current_policy_verified=True,
            current_head_verified=True,
            evidence_current_verified=True,
        )
        receipt = build_target_health_custody_receipt(
            verification,
            recorded_at=recorded_at or accepted_at,
        )
        event = build_target_health_custody_event(
            receipt,
            event_sequence=envelope.sequence,
            predecessor_event_id=None,
            predecessor_event_sha256=None,
            recorded_at=recorded_at or accepted_at,
        )
        connection = sqlite3.connect(self.store.path)
        try:
            payload_sha256 = "sha256:" + hashlib.sha256(envelope.signing_bytes()).hexdigest()
            self.insert_row(
                connection,
                "target_health_envelopes",
                {
                    "transition_sequence": transition,
                    "envelope_id": envelope.envelope_id,
                    "envelope_sha256": envelope.envelope_sha256,
                    "tenant_id": envelope.tenant_id,
                    "mission_id": envelope.mission_id,
                    "chain_id": envelope.chain_id,
                    "binding_sha256": envelope.binding_sha256,
                    "collector_id": envelope.collector_id,
                    "collector_epoch": envelope.collector_epoch,
                    "sequence": envelope.sequence,
                    "predecessor_envelope_id": envelope.predecessor_envelope_id,
                    "predecessor_envelope_sha256": envelope.predecessor_envelope_sha256,
                    "policy_id": envelope.policy_id,
                    "policy_sha256": envelope.policy_sha256,
                    "policy_revision": envelope.policy_revision,
                    "receipt_id": envelope.receipt_id,
                    "receipt_sha256": envelope.receipt_sha256,
                    "signing_payload_sha256": payload_sha256,
                    "observed_at": envelope.observed_at,
                    "accepted_at": accepted_at,
                    "envelope_json": canonical_json(envelope.to_dict()),
                },
            )
            self.insert_row(
                connection,
                "target_health_custody_receipts",
                {
                    "custody_receipt_id": receipt.custody_receipt_id,
                    "custody_receipt_sha256": receipt.custody_receipt_sha256,
                    "tenant_id": envelope.tenant_id,
                    "mission_id": envelope.mission_id,
                    "chain_id": envelope.chain_id,
                    "sequence": envelope.sequence,
                    "envelope_id": envelope.envelope_id,
                    "envelope_sha256": envelope.envelope_sha256,
                    "recorded_at": receipt.recorded_at,
                    "receipt_json": canonical_json(receipt.to_dict()),
                },
            )
            self.insert_row(
                connection,
                "target_health_custody_events",
                {
                    "event_id": event.event_id,
                    "event_sha256": event.event_sha256,
                    "tenant_id": event.tenant_id,
                    "mission_id": event.mission_id,
                    "chain_id": event.chain_id,
                    "event_sequence": event.event_sequence,
                    "predecessor_event_id": event.predecessor_event_id,
                    "predecessor_event_sha256": event.predecessor_event_sha256,
                    "custody_receipt_id": event.custody_receipt_id,
                    "custody_receipt_sha256": event.custody_receipt_sha256,
                    "envelope_id": event.envelope_id,
                    "envelope_sha256": event.envelope_sha256,
                    "recorded_at": event.recorded_at,
                    "event_json": canonical_json(event.to_dict()),
                },
            )
            self.insert_row(
                connection,
                "target_health_chain_heads",
                {
                    "chain_id": envelope.chain_id,
                    "tenant_id": envelope.tenant_id,
                    "mission_id": envelope.mission_id,
                    "binding_sha256": envelope.binding_sha256,
                    "collector_id": envelope.collector_id,
                    "collector_epoch": envelope.collector_epoch,
                    "sequence": envelope.sequence,
                    "envelope_id": envelope.envelope_id,
                    "envelope_sha256": envelope.envelope_sha256,
                    "custody_receipt_id": receipt.custody_receipt_id,
                    "custody_receipt_sha256": receipt.custody_receipt_sha256,
                    "policy_id": envelope.policy_id,
                    "policy_sha256": envelope.policy_sha256,
                    "transition_sequence": transition,
                },
            )
            self.insert_row(
                connection,
                "target_health_event_heads",
                {
                    "chain_id": event.chain_id,
                    "tenant_id": event.tenant_id,
                    "mission_id": event.mission_id,
                    "event_sequence": event.event_sequence,
                    "event_id": event.event_id,
                    "event_sha256": event.event_sha256,
                },
            )
            connection.commit()
        finally:
            connection.close()
        return receipt, event

    def populate_one(self) -> tuple[
        TargetHealthCollectorPolicyRevision,
        SignedTargetHealthCustodyEnvelopeV2,
    ]:
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        self.store.append_envelope(envelope)
        return policy, envelope

    def test_module_import_and_fresh_migration_identity(self) -> None:
        module = importlib.import_module("sunderkey.target_health_custody")
        self.assertIs(module.SQLiteTargetHealthCustody, SQLiteTargetHealthCustody)
        connection = sqlite3.connect(self.store.path)
        try:
            self.assertEqual(
                connection.execute("PRAGMA application_id").fetchone()[0],
                APPLICATION_ID,
            )
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            migration = connection.execute("SELECT * FROM schema_migrations").fetchone()
            self.assertEqual(
                migration,
                (1, MIGRATION_ID, MIGRATION_SHA256, "1970-01-01T00:00:00Z"),
            )
            metadata = connection.execute("SELECT * FROM custody_metadata").fetchone()
            self.assertEqual(metadata[5], EXPECTED_SCHEMA_MANIFEST_SHA256)
            self.assertEqual(metadata[6], self.factory.root.trust_root_id)
            self.assertEqual(metadata[7], self.factory.root.trust_root_sha256)
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(target_health_collector_policies)"
                )
            }
            self.assertIn("trust_root_id", columns)
        finally:
            connection.close()
        reopened = SQLiteTargetHealthCustody(
            self.store.path,
            trust_root=self.factory.root,
            trusted_clock=self.clock,
        )
        self.assertEqual(reopened.verify().status, "valid")

    def test_pinned_root_rejects_substitution(self) -> None:
        other = ContractFactory(mission_id="mission:health-2")
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            SQLiteTargetHealthCustody(
                self.store.path,
                trust_root=other.root,
                trusted_clock=self.clock,
            )

    def test_policy_publication_exact_replay_and_mission_separation(self) -> None:
        policy = self.factory.make_policy()
        self.assertEqual(self.store.publish_policy(policy), policy)
        before = self.table_count(self.store.path, "target_health_collector_policies")
        with patch.object(
            SQLiteTargetHealthCustody,
            "_mutation_checkpoint",
            side_effect=AssertionError("policy replay attempted a write"),
        ):
            self.assertEqual(self.store.publish_policy(policy), policy)
        self.assertEqual(
            self.table_count(self.store.path, "target_health_collector_policies"),
            before,
        )
        other = ContractFactory(mission_id="mission:health-2")
        other_policy = other.make_policy()
        self.assertNotEqual(policy.chain_id, other_policy.chain_id)
        self.assertNotEqual(
            target_health_chain_id(
                policy.collector_id,
                self.factory.root.mission_id,
                policy.binding_sha256,
            ),
            target_health_chain_id(
                policy.collector_id,
                other.root.mission_id,
                policy.binding_sha256,
            ),
        )

    def test_signing_context_tracks_durable_head_without_reservation(self) -> None:
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        initial = self.store.prepare_signing_context(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            collector_id=policy.collector_id,
            binding_sha256=policy.binding_sha256,
        )
        self.assertEqual(initial.next_sequence, 1)
        self.assertEqual(initial.current_head_sequence, 0)
        self.assertIsNone(initial.previous_envelope_id)
        self.assertEqual(initial.reservation_effect, "none")
        self.assertEqual(initial.authority_effect, "none")
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        self.store.append_envelope(envelope)
        current = self.store.prepare_signing_context(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            collector_id=policy.collector_id,
            binding_sha256=policy.binding_sha256,
        )
        self.assertEqual(current.next_sequence, 2)
        self.assertEqual(current.current_head_sequence, 1)
        self.assertEqual(current.previous_envelope_id, envelope.envelope_id)
        self.assertEqual(current.previous_envelope_sha256, envelope.envelope_sha256)

    def test_append_and_exact_replay_perform_zero_additional_writes(self) -> None:
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        accepted = self.store.append_envelope(envelope)
        self.assertFalse(accepted.replayed)
        counts = {
            table: self.table_count(self.store.path, table)
            for table in (
                "target_health_envelopes",
                "target_health_custody_receipts",
                "target_health_custody_events",
                "target_health_chain_heads",
                "target_health_event_heads",
            )
        }
        with patch.object(
            SQLiteTargetHealthCustody,
            "_mutation_checkpoint",
            side_effect=AssertionError("envelope replay attempted a write"),
        ):
            replay = self.store.append_envelope(envelope)
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.receipt, accepted.receipt)
        self.assertEqual(replay.event, accepted.event)
        for table, expected in counts.items():
            self.assertEqual(self.table_count(self.store.path, table), expected)

    def test_gap_fork_and_policy_substitution_are_rejected(self) -> None:
        policy, first = self.populate_one()
        gap = self.factory.make_envelope(
            policy,
            sequence=3,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first,
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.append_envelope(gap)
        fork = self.factory.make_envelope(
            policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor_id="THCE-" + "A" * 32,
            predecessor_sha256=DIGEST_A,
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.append_envelope(fork)
        unpublished = self.factory.make_policy(revision=2, previous=policy)
        substituted = self.factory.make_envelope(
            unpublished,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first,
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.append_envelope(substituted)
        self.assertEqual(self.table_count(self.store.path, "target_health_envelopes"), 1)

    def test_revocation_replay_blocks_current_but_preserves_pre_revocation_history(self) -> None:
        policy, first = self.populate_one()
        revocation = self.factory.make_revocation(
            policy,
            revoked_at="2026-09-21T12:00:08Z",
        )
        self.assertEqual(self.store.publish_revocation(revocation), revocation)
        before = self.table_count(
            self.store.path, "target_health_collector_policy_revocations"
        )
        with patch.object(
            SQLiteTargetHealthCustody,
            "_mutation_checkpoint",
            side_effect=AssertionError("revocation replay attempted a write"),
        ):
            self.assertEqual(self.store.publish_revocation(revocation), revocation)
        self.assertEqual(
            self.table_count(
                self.store.path, "target_health_collector_policy_revocations"
            ),
            before,
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.verify_current_head(
                tenant_id=policy.tenant_id,
                mission_id=policy.mission_id,
                chain_id=policy.chain_id,
            )
        post_revocation = self.factory.make_envelope(
            policy,
            sequence=2,
            observed_at="2026-09-21T12:00:09Z",
            monotonic_tick=11,
            predecessor=first,
        )
        expected_errors = (TargetHealthCustodyConflictError, TargetHealthCustodyContractError)
        with self.assertRaises(expected_errors):
            self.store.append_envelope(post_revocation)
        report = self.store.verify()
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.envelope_count, 1)

    def test_scheduled_revocation_has_live_cutoff_and_historical_parity(self) -> None:
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        revocation = self.factory.make_revocation(
            policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        self.store.publish_revocation(revocation)
        self.store._trusted_clock = FixedClock("2026-09-21T12:00:15Z")
        context = self.store.prepare_signing_context(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            collector_id=policy.collector_id,
            binding_sha256=policy.binding_sha256,
        )
        self.assertEqual(context.next_sequence, 1)
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:14Z",
            monotonic_tick=10,
        )
        accepted = self.store.append_envelope(envelope)
        self.assertEqual(
            accepted.receipt.verification.policy_revocation_id,
            revocation.revocation_id,
        )
        self.assertEqual(
            accepted.receipt.verification.policy_revocation_sha256,
            revocation.revocation_sha256,
        )
        self.assertEqual(
            self.store.verify_current_head(
                tenant_id=policy.tenant_id,
                mission_id=policy.mission_id,
                chain_id=policy.chain_id,
            ).policy_revocation_id,
            revocation.revocation_id,
        )

        before = self.durable_snapshot(self.store.path)
        self.store._trusted_clock = FixedClock("2026-09-21T12:00:20Z")
        for operation in (
            lambda: self.store.prepare_signing_context(
                tenant_id=policy.tenant_id,
                mission_id=policy.mission_id,
                collector_id=policy.collector_id,
                binding_sha256=policy.binding_sha256,
            ),
            lambda: self.store.verify_current_head(
                tenant_id=policy.tenant_id,
                mission_id=policy.mission_id,
                chain_id=policy.chain_id,
            ),
            lambda: self.store.append_envelope(envelope),
        ):
            with self.assertRaises(TargetHealthCustodyError):
                operation()
        self.assertEqual(self.durable_snapshot(self.store.path), before)
        self.assertEqual(self.store.verify().status, "valid")

    def test_revocation_is_terminal_only_for_exact_policy_revision(self) -> None:
        first_policy, first_envelope = self.populate_one()
        revocation = self.factory.make_revocation(
            first_policy,
            revoked_at="2026-09-21T12:00:08Z",
        )
        self.store.publish_revocation(revocation)
        second_key = Ed25519PrivateKey.generate()
        self.factory.collector_keys[2] = second_key
        second_policy = self.factory.make_policy(
            revision=2,
            epoch=2,
            previous=first_policy,
            prior_envelope=first_envelope,
            collector_key=second_key,
        )
        self.store.publish_policy(second_policy)
        context = self.store.prepare_signing_context(
            tenant_id=second_policy.tenant_id,
            mission_id=second_policy.mission_id,
            collector_id=second_policy.collector_id,
            binding_sha256=second_policy.binding_sha256,
        )
        self.assertEqual(context.collector_epoch, 2)
        replacement = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:09Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )
        self.store.append_envelope(replacement)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.append_envelope(first_envelope)
        self.assertEqual(self.store.verify().status, "valid")

    def test_superseded_policy_can_be_revoked_without_blocking_current_policy(self) -> None:
        first_policy, first_envelope = self.populate_one()
        second_policy = self.factory.make_policy(revision=2, previous=first_policy)
        self.store.publish_policy(second_policy)
        revocation = self.factory.make_revocation(
            first_policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        self.store.publish_revocation(revocation)
        self.assertEqual(self.store.publish_revocation(revocation), revocation)
        duplicate = self.factory.make_revocation(
            first_policy,
            revoked_at="2026-09-21T12:00:21Z",
        )
        with self.assertRaises(TargetHealthCustodyError):
            self.store.publish_revocation(duplicate)
        second_envelope = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:10Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )
        self.store.append_envelope(second_envelope)
        self.assertEqual(self.store.verify().status, "valid")

    def test_late_backdated_revocation_preserves_history_but_denies_live_replay(self) -> None:
        policy, envelope = self.populate_one()
        revocation = self.factory.make_revocation(
            policy,
            revoked_at="2026-09-21T12:00:04Z",
        )
        self.store.publish_revocation(revocation)
        self.assertEqual(self.store.publish_revocation(revocation), revocation)
        self.assertEqual(self.store.verify().status, "valid")
        for operation in (
            lambda: self.store.verify_current_head(
                tenant_id=policy.tenant_id,
                mission_id=policy.mission_id,
                chain_id=policy.chain_id,
            ),
            lambda: self.store.append_envelope(envelope),
        ):
            with self.assertRaises(TargetHealthCustodyError):
                operation()

    def test_policy_cutoff_race_requires_new_epoch_and_new_key(self) -> None:
        first_policy, first_envelope = self.populate_one()
        revocation = self.factory.make_revocation(
            first_policy,
            revoked_at="2026-09-21T12:00:11Z",
        )
        self.store.publish_revocation(revocation)
        same_epoch = self.factory.make_policy(revision=2, previous=first_policy)
        before = self.durable_snapshot(self.store.path)
        self.store._trusted_clock = SequenceClock(
            "2026-09-21T12:00:10Z",
            "2026-09-21T12:00:11Z",
        )
        with self.assertRaises(TargetHealthCustodyError):
            self.store.publish_policy(same_epoch)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

        replacement_key = Ed25519PrivateKey.generate()
        self.factory.collector_keys[2] = replacement_key
        replacement = self.factory.make_policy(
            revision=2,
            epoch=2,
            previous=first_policy,
            prior_envelope=first_envelope,
            collector_key=replacement_key,
        )
        self.store._trusted_clock = FixedClock("2026-09-21T12:00:11Z")
        self.assertEqual(self.store.publish_policy(replacement), replacement)

    def test_exact_replay_reverifies_durable_policy_and_revocation_signatures(self) -> None:
        policy = self.factory.make_policy()
        forged_policy = replace(
            policy,
            root_signature=b64(bytes(64)),
            policy_id="",
            policy_sha256="",
        )
        self.inject_policy(forged_policy)
        before = self.durable_snapshot(self.store.path)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.publish_policy(forged_policy)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

        revocation_path = self.directory / "forged-revocation.sqlite3"
        self.store = SQLiteTargetHealthCustody(
            revocation_path,
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        self.store.publish_policy(policy)
        revocation = self.factory.make_revocation(
            policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        forged_revocation = replace(
            revocation,
            root_signature=b64(bytes(64)),
            revocation_id="",
            revocation_sha256="",
        )
        self.inject_revocation(forged_revocation, transition=2)
        before = self.durable_snapshot(self.store.path)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.publish_revocation(forged_revocation)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

    def test_live_replays_fail_after_currentness_expires_with_zero_writes(self) -> None:
        policy, envelope = self.populate_one()
        before = self.durable_snapshot(self.store.path)
        self.store._trusted_clock = FixedClock("2026-09-21T12:03:00Z")
        self.assertEqual(self.store.publish_policy(policy), policy)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.append_envelope(envelope)
        self.assertEqual(self.durable_snapshot(self.store.path), before)
        for replay_at in ("2026-09-21T18:00:00Z", "2026-09-22T00:00:00Z"):
            with self.subTest(replay_at=replay_at):
                self.store._trusted_clock = FixedClock(replay_at)
                with self.assertRaises(TargetHealthCustodyError):
                    self.store.publish_policy(policy)
                with self.assertRaises(TargetHealthCustodyError):
                    self.store.append_envelope(envelope)
                self.assertEqual(self.durable_snapshot(self.store.path), before)

    def test_epoch_rollover_requires_exact_prior_head_and_new_key(self) -> None:
        first_policy, first_envelope = self.populate_one()
        second_key = Ed25519PrivateKey.generate()
        self.factory.collector_keys[2] = second_key
        second_policy = self.factory.make_policy(
            revision=2,
            epoch=2,
            previous=first_policy,
            prior_envelope=first_envelope,
            collector_key=second_key,
        )
        self.store.publish_policy(second_policy)
        context = self.store.prepare_signing_context(
            tenant_id=second_policy.tenant_id,
            mission_id=second_policy.mission_id,
            collector_id=second_policy.collector_id,
            binding_sha256=second_policy.binding_sha256,
        )
        self.assertEqual(context.collector_epoch, 2)
        self.assertEqual(context.next_sequence, 2)
        self.assertEqual(context.previous_envelope_id, first_envelope.envelope_id)
        second_envelope = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )
        self.store.append_envelope(second_envelope)
        stale = self.factory.make_policy(
            revision=3,
            epoch=3,
            previous=second_policy,
            prior_envelope=first_envelope,
            collector_key=Ed25519PrivateKey.generate(),
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.publish_policy(stale)

        same_key_epoch = self.factory.make_policy(
            revision=3,
            epoch=3,
            previous=second_policy,
            prior_envelope=second_envelope,
            collector_key=second_key,
        )
        with self.assertRaises(TargetHealthCustodyConflictError):
            self.store.publish_policy(same_key_epoch)

    def test_trusted_clock_regression_and_final_resample_roll_back(self) -> None:
        path = self.directory / "regression.sqlite3"
        regressing = SQLiteTargetHealthCustody(
            path,
            trust_root=self.factory.root,
            trusted_clock=SequenceClock(
                "2026-09-21T12:00:10Z",
                "2026-09-21T12:00:09Z",
            ),
        )
        with self.assertRaisesRegex(TargetHealthCustodyIntegrityError, "regressed"):
            regressing.publish_policy(self.factory.make_policy())
        self.assertEqual(self.table_count(path, "target_health_collector_policies"), 0)

        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        self.store._trusted_clock = SequenceClock(
            "2026-09-21T12:00:10Z",
            "2026-09-21T12:03:00Z",
        )
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        with self.assertRaises(TargetHealthCustodyError):
            self.store.append_envelope(envelope)
        self.assertEqual(self.table_count(self.store.path, "target_health_envelopes"), 0)
        self.assertEqual(self.table_count(self.store.path, "target_health_custody_receipts"), 0)

    def test_policy_mutation_checkpoints_roll_back_atomically(self) -> None:
        for checkpoint in ("after_policy_insert", "after_policy_head", "before_commit"):
            with self.subTest(checkpoint=checkpoint):
                path = self.directory / f"policy-{checkpoint}.sqlite3"
                store = SQLiteTargetHealthCustody(
                    path,
                    trust_root=self.factory.root,
                    trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
                )

                def fail(name: str, expected: str = checkpoint) -> None:
                    if name == expected:
                        raise RuntimeError(expected)

                before = self.durable_snapshot(path)
                with (
                    patch.object(
                        SQLiteTargetHealthCustody,
                        "_mutation_checkpoint",
                        staticmethod(fail),
                    ),
                    self.assertRaisesRegex(RuntimeError, checkpoint),
                ):
                    store.publish_policy(self.factory.make_policy())
                self.assertEqual(self.durable_snapshot(path), before)

    def test_append_mutation_checkpoints_roll_back_atomically(self) -> None:
        checkpoints = (
            "after_envelope_insert",
            "after_receipt_insert",
            "after_event_insert",
            "after_heads",
            "before_commit",
        )
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint):
                path = self.directory / f"append-{checkpoint}.sqlite3"
                store = SQLiteTargetHealthCustody(
                    path,
                    trust_root=self.factory.root,
                    trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
                )
                policy = self.factory.make_policy()
                store.publish_policy(policy)
                envelope = self.factory.make_envelope(
                    policy,
                    sequence=1,
                    observed_at="2026-09-21T12:00:05Z",
                    monotonic_tick=10,
                )

                def fail(name: str, expected: str = checkpoint) -> None:
                    if name == expected:
                        raise RuntimeError(expected)

                before = self.durable_snapshot(path)
                with (
                    patch.object(
                        SQLiteTargetHealthCustody,
                        "_mutation_checkpoint",
                        staticmethod(fail),
                    ),
                    self.assertRaisesRegex(RuntimeError, checkpoint),
                ):
                    store.append_envelope(envelope)
                self.assertEqual(self.durable_snapshot(path), before)

    def test_revocation_mutation_checkpoints_roll_back_atomically(self) -> None:
        for checkpoint in (
            "after_revocation_insert",
            "after_revocation_head",
            "before_commit",
        ):
            with self.subTest(checkpoint=checkpoint):
                path = self.directory / f"revocation-{checkpoint}.sqlite3"
                store = SQLiteTargetHealthCustody(
                    path,
                    trust_root=self.factory.root,
                    trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
                )
                policy = self.factory.make_policy()
                store.publish_policy(policy)
                revocation = self.factory.make_revocation(
                    policy,
                    revoked_at="2026-09-21T12:00:20Z",
                )

                def fail(name: str, expected: str = checkpoint) -> None:
                    if name == expected:
                        raise RuntimeError(expected)

                before = self.durable_snapshot(path)
                with (
                    patch.object(
                        SQLiteTargetHealthCustody,
                        "_mutation_checkpoint",
                        staticmethod(fail),
                    ),
                    self.assertRaisesRegex(RuntimeError, checkpoint),
                ):
                    store.publish_revocation(revocation)
                self.assertEqual(self.durable_snapshot(path), before)

    def test_tenant_scoped_reads_are_bounded_and_paginated(self) -> None:
        first_policy, first_envelope = self.populate_one()
        second_policy = self.factory.make_policy(revision=2, previous=first_policy)
        self.store.publish_policy(second_policy)
        second_envelope = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )
        self.store.append_envelope(second_envelope)
        revocation = self.factory.make_revocation(
            first_policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        self.store.publish_revocation(revocation)
        arguments = {
            "tenant_id": first_policy.tenant_id,
            "mission_id": first_policy.mission_id,
            "chain_id": first_policy.chain_id,
        }
        self.assertEqual(self.store.list_policies(**arguments, limit=1), (first_policy,))
        self.assertEqual(
            self.store.list_policies(**arguments, after_revision=1, limit=1),
            (second_policy,),
        )
        self.assertEqual(len(self.store.list_receipts(**arguments, limit=1)), 1)
        self.assertEqual(len(self.store.list_events(**arguments, limit=1)), 1)
        revocation_arguments = {
            "tenant_id": first_policy.tenant_id,
            "mission_id": first_policy.mission_id,
        }
        self.assertEqual(
            self.store.list_revocations(**revocation_arguments),
            (revocation,),
        )
        self.assertEqual(
            self.store.list_revocations(
                **revocation_arguments,
                after_revision=revocation.policy_revision,
            ),
            (),
        )
        wrong = {**arguments, "tenant_id": "tenant:other"}
        self.assertEqual(self.store.list_policies(**wrong), ())
        self.assertEqual(self.store.list_receipts(**wrong), ())
        self.assertEqual(self.store.list_events(**wrong), ())
        self.assertEqual(
            self.store.list_revocations(
                tenant_id="tenant:other",
                mission_id=first_policy.mission_id,
            ),
            (),
        )
        with self.assertRaises(TargetHealthCustodyNotFoundError):
            self.store.verify_current_head(**wrong)
        for limit in (0, MAX_PAGE_SIZE + 1, True):
            with (
                self.subTest(limit=limit),
                self.assertRaises(TargetHealthCustodyValidationError),
            ):
                self.store.list_events(**arguments, limit=limit)
        with self.assertRaises(TargetHealthCustodyValidationError):
            self.store.list_receipts(**arguments, after_sequence=True)
        cursor_calls = (
            lambda cursor: self.store.list_policies(
                **arguments, after_revision=cursor
            ),
            lambda cursor: self.store.list_revocations(
                **revocation_arguments, after_revision=cursor
            ),
            lambda cursor: self.store.list_receipts(
                **arguments, after_sequence=cursor
            ),
            lambda cursor: self.store.list_events(
                **arguments, after_sequence=cursor
            ),
        )
        for operation in cursor_calls:
            self.assertEqual(operation(2**63 - 1), ())
            for invalid_cursor in (True, -1, 2**63):
                with (
                    self.subTest(operation=operation, cursor=invalid_cursor),
                    self.assertRaises(TargetHealthCustodyValidationError),
                ):
                    operation(invalid_cursor)
        limit_calls = (
            lambda limit: self.store.list_policies(**arguments, limit=limit),
            lambda limit: self.store.list_revocations(
                **revocation_arguments, limit=limit
            ),
            lambda limit: self.store.list_receipts(**arguments, limit=limit),
            lambda limit: self.store.list_events(**arguments, limit=limit),
        )
        for operation in limit_calls:
            for invalid_limit in (True, 0, MAX_PAGE_SIZE + 1):
                with (
                    self.subTest(operation=operation, limit=invalid_limit),
                    self.assertRaises(TargetHealthCustodyValidationError),
                ):
                    operation(invalid_limit)

    def test_tamper_detection_rejects_modified_heads_and_rows(self) -> None:
        policy, _ = self.populate_one()
        def corrupt_head(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_chain_heads SET policy_sha256=? WHERE chain_id=?",
                (DIGEST_D, policy.chain_id),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            ("target_health_chain_heads",),
            corrupt_head,
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.store.verify()

        connection = sqlite3.connect(self.store.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE target_health_collector_policies SET tenant_id=? WHERE policy_id=?",
                    ("tenant:other", policy.policy_id),
                )
        finally:
            connection.close()

    def test_whole_store_rejects_recomputed_verified_at_rewrite(self) -> None:
        policy, envelope = self.populate_one()
        receipt = self.store.list_receipts(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            chain_id=policy.chain_id,
        )[0]
        event = self.store.list_events(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            chain_id=policy.chain_id,
        )[0]
        verification = replace(
            receipt.verification,
            verified_at="2026-09-21T12:00:09Z",
            verification_id="",
            verification_sha256="",
        )
        rewritten_receipt = TargetHealthCustodyReceipt(
            verification=verification,
            recorded_at=receipt.recorded_at,
        )
        rewritten_event = build_target_health_custody_event(
            rewritten_receipt,
            event_sequence=event.event_sequence,
            predecessor_event_id=event.predecessor_event_id,
            predecessor_event_sha256=event.predecessor_event_sha256,
            recorded_at=event.recorded_at,
        )

        def rewrite(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_custody_receipts SET "
                "custody_receipt_id=?,custody_receipt_sha256=?,receipt_json=? "
                "WHERE envelope_id=?",
                (
                    rewritten_receipt.custody_receipt_id,
                    rewritten_receipt.custody_receipt_sha256,
                    canonical_json(rewritten_receipt.to_dict()),
                    envelope.envelope_id,
                ),
            )
            connection.execute(
                "UPDATE target_health_custody_events SET event_id=?,event_sha256=?,"
                "custody_receipt_id=?,custody_receipt_sha256=?,event_json=? "
                "WHERE envelope_id=?",
                (
                    rewritten_event.event_id,
                    rewritten_event.event_sha256,
                    rewritten_receipt.custody_receipt_id,
                    rewritten_receipt.custody_receipt_sha256,
                    canonical_json(rewritten_event.to_dict()),
                    envelope.envelope_id,
                ),
            )
            connection.execute(
                "UPDATE target_health_chain_heads SET custody_receipt_id=?,"
                "custody_receipt_sha256=? WHERE chain_id=?",
                (
                    rewritten_receipt.custody_receipt_id,
                    rewritten_receipt.custody_receipt_sha256,
                    envelope.chain_id,
                ),
            )
            connection.execute(
                "UPDATE target_health_event_heads SET event_id=?,event_sha256=? "
                "WHERE chain_id=?",
                (
                    rewritten_event.event_id,
                    rewritten_event.event_sha256,
                    envelope.chain_id,
                ),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            (
                "target_health_custody_receipts",
                "target_health_custody_events",
                "target_health_chain_heads",
                "target_health_event_heads",
            ),
            rewrite,
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.store.verify()

    def test_whole_store_reconstructs_current_acceptance_at_accepted_at(self) -> None:
        cases = (
            ("stale", "2026-09-21T11:57:00Z", "2026-09-21T12:00:10Z"),
            ("future", "2026-09-21T12:00:20Z", "2026-09-21T12:00:10Z"),
            ("expired_policy", "2026-09-21T12:00:08Z", "2026-09-21T12:00:10Z"),
        )
        for label, observed_at, accepted_at in cases:
            with self.subTest(label=label):
                path = self.directory / f"acceptance-{label}.sqlite3"
                self.store = SQLiteTargetHealthCustody(
                    path,
                    trust_root=self.factory.root,
                    trusted_clock=FixedClock(accepted_at),
                )
                policy = self.factory.make_policy(
                    expires_at=(
                        "2026-09-21T12:00:09Z"
                        if label == "expired_policy"
                        else "2026-09-21T18:00:00Z"
                    )
                )
                self.inject_policy(policy, published_at="2026-09-21T12:00:05Z")
                envelope = self.factory.make_envelope(
                    policy,
                    sequence=1,
                    observed_at=observed_at,
                    monotonic_tick=10,
                )
                self.inject_envelope_bundle(
                    policy,
                    envelope,
                    transition=2,
                    accepted_at=accepted_at,
                    verified_at=(
                        observed_at if label == "future" else accepted_at
                    ),
                    recorded_at=(
                        observed_at if label == "future" else accepted_at
                    ),
                )
                with self.assertRaises(TargetHealthCustodyIntegrityError):
                    self.store.verify()

    def test_whole_store_rejects_expired_root_and_embedded_evidence(self) -> None:
        phase175_type = importlib.import_module(
            "tests.agents.test_authorized_target_health_runtime_phase175"
        ).AuthorizedTargetHealthRuntimePhase175Tests

        expired_root_factory = ContractFactory()
        expired_root_factory.root = replace(
            expired_root_factory.root,
            expires_at="2026-09-21T12:00:09Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        self.factory = expired_root_factory
        self.store = SQLiteTargetHealthCustody(
            self.directory / "expired-root.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        policy = self.factory.make_policy(expires_at="2026-09-21T12:00:09Z")
        self.inject_policy(policy, published_at="2026-09-21T12:00:05Z")
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:08Z",
            monotonic_tick=10,
        )
        self.inject_envelope_bundle(
            policy,
            envelope,
            transition=2,
            accepted_at="2026-09-21T12:00:10Z",
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.store.verify()

        phase175 = phase175_type(
            "test_completed_receipt_composes_all_boundaries_and_dimensions"
        )
        phase175.setUp()
        source_receipt = phase175.observe()
        evidence_factory = ContractFactory()
        evidence_factory.binding = source_receipt.binding
        evidence_factory.binding_sha256 = execution_binding_sha256(
            source_receipt.binding
        )
        evidence_factory.root = replace(
            evidence_factory.root,
            effective_at="2026-09-20T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        self.factory = evidence_factory
        self.store = SQLiteTargetHealthCustody(
            self.directory / "expired-evidence.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-20T12:02:00Z"),
        )
        policy = self.factory.make_policy(
            issued_at="2026-09-20T10:59:00Z",
            effective_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T18:00:00Z",
            runtime_policy_id=source_receipt.runtime_policy_id,
            runtime_policy_sha256=source_receipt.runtime_policy_sha256,
        )
        self.inject_policy(policy, published_at="2026-09-20T12:00:00Z")
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at=source_receipt.observed_at,
            monotonic_tick=source_receipt.monotonic_tick,
            receipt=source_receipt,
        )
        self.inject_envelope_bundle(
            policy,
            envelope,
            transition=2,
            accepted_at="2026-09-20T12:02:00Z",
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.store.verify()

    def test_positive_apis_fail_closed_on_materialized_head_tampering(self) -> None:
        operations = (
            (
                "policy",
                "target_health_policy_heads",
                "UPDATE target_health_policy_heads SET policy_sha256=? WHERE chain_id=?",
                lambda policy, envelope: self.store.prepare_signing_context(
                    tenant_id=policy.tenant_id,
                    mission_id=policy.mission_id,
                    collector_id=policy.collector_id,
                    binding_sha256=policy.binding_sha256,
                ),
            ),
            (
                "chain",
                "target_health_chain_heads",
                "UPDATE target_health_chain_heads SET envelope_sha256=? WHERE chain_id=?",
                lambda policy, envelope: self.store.verify_current_head(
                    tenant_id=policy.tenant_id,
                    mission_id=policy.mission_id,
                    chain_id=policy.chain_id,
                ),
            ),
            (
                "event",
                "target_health_event_heads",
                "UPDATE target_health_event_heads SET event_sha256=? WHERE chain_id=?",
                lambda policy, envelope: self.store.append_envelope(
                    self.factory.make_envelope(
                        policy,
                        sequence=2,
                        observed_at="2026-09-21T12:00:06Z",
                        monotonic_tick=11,
                        predecessor=envelope,
                    )
                ),
            ),
        )
        for label, table, statement, operation in operations:
            with self.subTest(label=label):
                self.store = SQLiteTargetHealthCustody(
                    self.directory / f"tampered-{label}.sqlite3",
                    trust_root=self.factory.root,
                    trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
                )
                policy, envelope = self.populate_one()

                def corrupt(
                    connection: sqlite3.Connection,
                    exact_statement: str = statement,
                    chain_id: str = policy.chain_id,
                ) -> None:
                    connection.execute(exact_statement, (DIGEST_D, chain_id))

                self.rewrite_with_triggers_restored(
                    self.store.path,
                    (table,),
                    corrupt,
                )
                before = self.durable_snapshot(self.store.path)
                with self.assertRaises(TargetHealthCustodyError):
                    operation(policy, envelope)
                self.assertEqual(self.durable_snapshot(self.store.path), before)

        self.store = SQLiteTargetHealthCustody(
            self.directory / "tampered-revocation-head.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        revocation = self.factory.make_revocation(
            policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        self.store.publish_revocation(revocation)

        def corrupt_revocation(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_policy_revocation_heads "
                "SET revocation_sha256=? WHERE policy_id=?",
                (DIGEST_D, policy.policy_id),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            ("target_health_policy_revocation_heads",),
            corrupt_revocation,
        )
        before = self.durable_snapshot(self.store.path)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.publish_revocation(revocation)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

        self.store = SQLiteTargetHealthCustody(
            self.directory / "rolled-back-policy-head.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        first_policy, _ = self.populate_one()
        second_policy = self.factory.make_policy(revision=2, previous=first_policy)
        self.store.publish_policy(second_policy)

        def roll_back_policy_head(connection: sqlite3.Connection) -> None:
            transition = connection.execute(
                "SELECT transition_sequence FROM target_health_collector_policies "
                "WHERE policy_id=?",
                (first_policy.policy_id,),
            ).fetchone()[0]
            connection.execute(
                "UPDATE target_health_policy_heads SET policy_id=?,policy_sha256=?,"
                "policy_revision=?,collector_epoch=?,transition_sequence=? "
                "WHERE chain_id=?",
                (
                    first_policy.policy_id,
                    first_policy.policy_sha256,
                    first_policy.policy_revision,
                    first_policy.collector_epoch,
                    transition,
                    first_policy.chain_id,
                ),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            ("target_health_policy_heads",),
            roll_back_policy_head,
        )
        with self.assertRaises(TargetHealthCustodyError):
            self.store.prepare_signing_context(
                tenant_id=first_policy.tenant_id,
                mission_id=first_policy.mission_id,
                collector_id=first_policy.collector_id,
                binding_sha256=first_policy.binding_sha256,
            )

        self.store = SQLiteTargetHealthCustody(
            self.directory / "cross-record-pointer.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        policy, envelope = self.populate_one()
        event = self.store.list_events(
            tenant_id=policy.tenant_id,
            mission_id=policy.mission_id,
            chain_id=policy.chain_id,
        )[0]
        substituted_event = replace(
            event,
            custody_receipt_id="THCR-" + "A" * 32,
            custody_receipt_sha256=DIGEST_D,
            event_id="",
            event_sha256="",
        )

        def substitute_pointer(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_custody_events SET event_id=?,event_sha256=?,"
                "custody_receipt_id=?,custody_receipt_sha256=?,event_json=? "
                "WHERE envelope_id=?",
                (
                    substituted_event.event_id,
                    substituted_event.event_sha256,
                    substituted_event.custody_receipt_id,
                    substituted_event.custody_receipt_sha256,
                    canonical_json(substituted_event.to_dict()),
                    envelope.envelope_id,
                ),
            )
            connection.execute(
                "UPDATE target_health_event_heads SET event_id=?,event_sha256=? "
                "WHERE chain_id=?",
                (
                    substituted_event.event_id,
                    substituted_event.event_sha256,
                    envelope.chain_id,
                ),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            ("target_health_custody_events", "target_health_event_heads"),
            substitute_pointer,
        )
        before = self.durable_snapshot(self.store.path)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.append_envelope(envelope)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

    def test_public_boundaries_translate_external_and_durable_failures(self) -> None:
        policy = self.factory.make_policy()
        self.store.publish_policy(policy)
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        invalid_signature = replace(
            envelope,
            collector_signature=b64(bytes(64)),
            envelope_id="",
            envelope_sha256="",
        )
        before = self.durable_snapshot(self.store.path)
        with self.assertRaises(TargetHealthCustodyError):
            self.store.append_envelope(invalid_signature)
        self.assertEqual(self.durable_snapshot(self.store.path), before)

        def corrupt_policy(connection: sqlite3.Connection) -> None:
            connection.execute(
                "UPDATE target_health_collector_policies SET policy_json=? "
                "WHERE policy_id=?",
                ("{}", policy.policy_id),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            ("target_health_collector_policies",),
            corrupt_policy,
        )
        with self.assertRaises(TargetHealthCustodyIntegrityError):
            self.store.verify()

        connect_path = self.directory / "connect-error.sqlite3"
        connect_store = SQLiteTargetHealthCustody(
            connect_path,
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
        )
        with (
            patch(
                "sunderkey.target_health_custody.sqlite3.connect",
                side_effect=sqlite3.OperationalError("open failed"),
            ),
            self.assertRaises(TargetHealthCustodyIntegrityError),
        ):
            connect_store.list_revocations(
                tenant_id=self.factory.root.tenant_id,
                mission_id=self.factory.root.mission_id,
            )

        for needle in (
            "PRAGMA foreign_keys",
            "SELECT * FROM target_health_collector_policy_revocations",
        ):
            with self.subTest(sqlite_failure=needle):
                connection = sqlite3.connect(connect_path, isolation_level=None)
                proxy = FailingConnection(connection, needle)
                with (
                    patch(
                        "sunderkey.target_health_custody.sqlite3.connect",
                        return_value=proxy,
                    ),
                    self.assertRaises(TargetHealthCustodyIntegrityError),
                ):
                    connect_store.list_revocations(
                        tenant_id=self.factory.root.tenant_id,
                        mission_id=self.factory.root.mission_id,
                    )

        busy_path = self.directory / "busy.sqlite3"
        busy_store = SQLiteTargetHealthCustody(
            busy_path,
            trust_root=self.factory.root,
            trusted_clock=FixedClock("2026-09-21T12:00:10Z"),
            busy_timeout_seconds=0.01,
        )
        locker = sqlite3.connect(busy_path, isolation_level=None)
        try:
            locker.execute("BEGIN IMMEDIATE")
            with self.assertRaises(TargetHealthCustodyBusyError):
                busy_store.publish_policy(policy)
        finally:
            locker.rollback()
            locker.close()

    def test_whole_store_historical_verification_rebuilds_all_lineage(self) -> None:
        first_policy, first_envelope = self.populate_one()
        second_policy = self.factory.make_policy(revision=2, previous=first_policy)
        self.store.publish_policy(second_policy)
        second_envelope = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )
        self.store.append_envelope(second_envelope)
        report = self.store.verify()
        self.assertEqual(report.status, "valid")
        self.assertEqual(report.policy_count, 2)
        self.assertEqual(report.envelope_count, 2)
        self.assertEqual(report.custody_receipt_count, 2)
        self.assertEqual(report.event_count, 2)
        self.assertEqual(report.chain_count, 1)
        self.assertEqual(report.transition_count, 4)

    def test_reordered_policy_transitions_poison_every_positive_boundary(self) -> None:
        first_policy, first_envelope = self.populate_one()
        second_policy = self.factory.make_policy(revision=2, previous=first_policy)
        self.store.publish_policy(second_policy)
        third_policy = self.factory.make_policy(revision=3, previous=second_policy)
        revocation = self.factory.make_revocation(
            second_policy,
            revoked_at="2026-09-21T12:00:20Z",
        )
        next_envelope = self.factory.make_envelope(
            second_policy,
            sequence=2,
            observed_at="2026-09-21T12:00:06Z",
            monotonic_tick=11,
            predecessor=first_envelope,
        )

        def reorder_history(connection: sqlite3.Connection) -> None:
            rows = connection.execute(
                "SELECT policy_id,transition_sequence "
                "FROM target_health_collector_policies WHERE policy_id IN (?,?)",
                (first_policy.policy_id, second_policy.policy_id),
            ).fetchall()
            transitions = {policy_id: sequence for policy_id, sequence in rows}
            first_transition = transitions[first_policy.policy_id]
            second_transition = transitions[second_policy.policy_id]
            connection.execute(
                "UPDATE target_health_collector_policies "
                "SET transition_sequence=-1 WHERE policy_id=?",
                (first_policy.policy_id,),
            )
            connection.execute(
                "UPDATE target_health_collector_policies SET transition_sequence=? "
                "WHERE policy_id=?",
                (first_transition, second_policy.policy_id),
            )
            connection.execute(
                "UPDATE target_health_collector_policies SET transition_sequence=? "
                "WHERE policy_id=?",
                (second_transition, first_policy.policy_id),
            )
            connection.execute(
                "UPDATE target_health_policy_heads SET policy_id=?,policy_sha256=?,"
                "policy_revision=?,collector_epoch=?,transition_sequence=? "
                "WHERE chain_id=?",
                (
                    first_policy.policy_id,
                    first_policy.policy_sha256,
                    first_policy.policy_revision,
                    first_policy.collector_epoch,
                    second_transition,
                    first_policy.chain_id,
                ),
            )

        self.rewrite_with_triggers_restored(
            self.store.path,
            (
                "target_health_collector_policies",
                "target_health_policy_heads",
            ),
            reorder_history,
        )
        before = self.durable_snapshot(self.store.path)
        scoped = {
            "tenant_id": first_policy.tenant_id,
            "mission_id": first_policy.mission_id,
            "chain_id": first_policy.chain_id,
        }
        operations = (
            (
                "prepare signing context",
                lambda: self.store.prepare_signing_context(
                    tenant_id=first_policy.tenant_id,
                    mission_id=first_policy.mission_id,
                    collector_id=first_policy.collector_id,
                    binding_sha256=first_policy.binding_sha256,
                ),
            ),
            ("publish replayed policy", lambda: self.store.publish_policy(second_policy)),
            ("publish new policy", lambda: self.store.publish_policy(third_policy)),
            ("publish revocation", lambda: self.store.publish_revocation(revocation)),
            ("append new", lambda: self.store.append_envelope(next_envelope)),
            ("append replay", lambda: self.store.append_envelope(first_envelope)),
            (
                "verify current head",
                lambda: self.store.verify_current_head(**scoped),
            ),
            ("list policies", lambda: self.store.list_policies(**scoped)),
            ("list receipts", lambda: self.store.list_receipts(**scoped)),
            ("list events", lambda: self.store.list_events(**scoped)),
            (
                "list revocations",
                lambda: self.store.list_revocations(
                    tenant_id=first_policy.tenant_id,
                    mission_id=first_policy.mission_id,
                ),
            ),
            ("verify whole store", self.store.verify),
        )
        for label, operation in operations:
            with self.subTest(operation=label):
                with self.assertRaises(TargetHealthCustodyIntegrityError):
                    operation()
                self.assertEqual(self.durable_snapshot(self.store.path), before)

    def test_no_network_collection_or_execution_control_effects(self) -> None:
        policy = self.factory.make_policy()
        envelope = self.factory.make_envelope(
            policy,
            sequence=1,
            observed_at="2026-09-21T12:00:05Z",
            monotonic_tick=10,
        )
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network access")),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=AssertionError("network access"),
            ),
        ):
            self.store.publish_policy(policy)
            result = self.store.append_envelope(envelope)
            self.store.verify()
        for document in (
            policy.to_dict(),
            envelope.to_dict(),
            result.receipt.to_dict(),
            result.event.to_dict(),
        ):
            for key, value in NO_EFFECTS.items():
                self.assertEqual(document[key], value)
        public_names = set(dir(SQLiteTargetHealthCustody))
        self.assertFalse(
            public_names
            & {
                "collect",
                "execute",
                "pause",
                "resume",
                "qualify",
                "send",
            }
        )

    def test_artifacts_are_ascii_without_authorship_markers_or_long_dashes(self) -> None:
        markers = tuple(
            "".join(parts)
            for parts in (
                ("generated", " by"),
                ("written", " by ai"),
                ("as", " an ai"),
                ("chat", "gpt"),
                ("code", "x"),
                ("clau", "de"),
                ("gem", "ini"),
                ("co-authored", "-by"),
            )
        )
        for path in (MODULE, TEST_FILE):
            text = path.read_bytes().decode("ascii")
            lowered = text.lower()
            self.assertFalse(any(marker in lowered for marker in markers), path)
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)


if __name__ == "__main__":
    unittest.main()

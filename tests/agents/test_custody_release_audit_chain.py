"""Only bounded synthetic custody ports exercise the reference audit chain."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import sunderkey.custody_release_audit_chain as audit
from sunderkey.candidate_enrollment_production_custody_conformance import (
    CASE_DEFINITIONS,
    _run_case,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    LedgerHeadCompareAndSwapReceipt,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadReceipt,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutRequest,
    ProviderPolicyRejection,
    ReleaseAuditAppendRequest,
    ReleaseAuditEventDescriptor,
    ReleaseHeadSigningRequest,
    provider_subject_sha256,
)
from sunderkey.qualification import _canonical_json
from tests.agents import test_production_custody_conformance_phase185 as reference

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)
HORIZON = "2030-01-01T00:00:00Z"
SHA = "sha256:" + "1" * 64


class Clock:
    def __init__(self):
        self.value = NOW

    def __call__(self):
        return self.value


class LedgerFixture(reference.InMemoryLedgerObjects):
    environment_class = audit.ENVIRONMENT_CLASS

    def __init__(self):
        super().__init__(reference.ReferenceFaultInjector())
        self.calls = []
        self.after_put = self.after_read = self.after_retention = None

    def put_if_absent(self, request):
        self.calls.append(("put", request))
        receipt = super().put_if_absent(request)
        return receipt if self.after_put is None else self.after_put(receipt)

    def read_verified(self, request):
        self.calls.append(("read", request))
        receipt = super().read_verified(request)
        return receipt if self.after_read is None else self.after_read(receipt)

    def read_retention_state(self, request):
        self.calls.append(("retention", request))
        receipt = super().read_retention_state(request)
        return receipt if self.after_retention is None else self.after_retention(receipt)


class HeadFixture(reference.InMemoryLedgerHeads):
    environment_class = audit.ENVIRONMENT_CLASS

    def __init__(self):
        super().__init__()
        self.calls = []
        self.before_cas = self.after_cas = self.after_read = None

    def read_head(self, request):
        self.calls.append(("read", request))
        receipt = super().read_head(request)
        return receipt if self.after_read is None else self.after_read(receipt)

    def compare_and_swap_head(self, request):
        self.calls.append(("cas", request))
        callback, self.before_cas = self.before_cas, None
        if callback is not None:
            callback(request)
        receipt = super().compare_and_swap_head(request)
        return receipt if self.after_cas is None else self.after_cas(receipt)


def event(identity="event.one", *, artifact=SHA):
    return ReleaseAuditEventDescriptor(
        identity, "release_ready", artifact, "identity.synthetic.audit", "2026-09-27T11:00:00Z"
    )


def request(identity="event.one", *, request_id="request.audit", artifact=SHA):
    return ReleaseAuditAppendRequest(request_id, event(identity, artifact=artifact))


class CustodyReleaseAuditChainTests(unittest.TestCase):
    def setUp(self):
        self.ledger, self.heads, self.clock = LedgerFixture(), HeadFixture(), Clock()
        self.arguments = {
            "ledger_objects": self.ledger,
            "ledger_heads": self.heads,
            "namespace_id": "namespace.synthetic.audit",
            "failure_domain_id": "failure.synthetic.audit",
            "deployment_id": "deployment.synthetic.audit",
            "retention_until": HORIZON,
            "clock": self.clock,
            "maximum_traversal_records": 100,
            "maximum_provider_calls": 300,
            "maximum_read_bytes": 1_000_000,
            "maximum_object_bytes": 4096,
        }
        self.sink = self.build()

    def build(self, **changes):
        return audit.CustodyReleaseAuditChain(**{**self.arguments, **changes})

    def head(self):
        return self.heads.heads.get(self.arguments["deployment_id"])

    def mutate_record(self, mutation):
        head = self.head()
        descriptor, payload = self.ledger.objects[head.entry_id]
        raw = json.loads(payload)
        mutation(raw)
        payload = _canonical_json(raw).encode("ascii")
        digest = audit._digest(payload)
        replacement = replace(
            descriptor, object_id="audit." + digest[7:], sha256=digest, size_bytes=len(payload)
        )
        self.ledger.objects[replacement.object_id] = (replacement, payload)
        self.heads.heads[head.deployment_id] = replace(
            head, entry_id=replacement.object_id, entry_sha256=replacement.sha256
        )

    def assert_delegated_request_mutation_blocks(self, provider, method_name):
        original = getattr(provider, method_name)
        delegated = []

        def mutate(derived):
            object.__setattr__(derived, "request_id", "request.substituted.native")
            receipt = original(derived)
            delegated.append(receipt)
            return receipt

        with patch.object(provider, method_name, side_effect=mutate):
            with self.assertRaisesRegex(audit.CustodyAuditAppendUnconfirmed, "request changed"):
                self.sink.append_audit_event(request())
        self.assertEqual(len(delegated), 1)
        self.assertEqual(delegated[0].request_id, "request.substituted.native")
        cas_calls = sum(kind == "cas" for kind, _ in self.heads.calls)
        if method_name == "compare_and_swap_head":
            self.assertEqual(cas_calls, 1)
            self.assertEqual(self.head().ledger_sequence, 1)
        else:
            self.assertEqual(cas_calls, 0)
            self.assertIsNone(self.head())

    def test_delegated_head_read_request_mutation_cannot_redefine_correlation(self):
        self.assert_delegated_request_mutation_blocks(self.heads, "read_head")
        self.assertEqual(self.ledger.calls, [])

    def test_delegated_object_read_request_mutation_blocks_before_cas(self):
        self.assert_delegated_request_mutation_blocks(self.ledger, "read_verified")

    def test_delegated_retention_request_mutation_blocks_before_cas(self):
        self.assert_delegated_request_mutation_blocks(self.ledger, "read_retention_state")

    def test_delegated_put_request_mutation_keeps_upload_unacknowledged_and_orphaned(self):
        self.assert_delegated_request_mutation_blocks(self.ledger, "put_if_absent")
        self.assertEqual(len(self.ledger.objects), 1)

    def test_delegated_cas_request_mutation_cannot_acknowledge_applied_head(self):
        self.assert_delegated_request_mutation_blocks(self.heads, "compare_and_swap_head")
        self.assertEqual(len(self.ledger.objects), 1)

    def test_request_mutation_on_genuine_typed_conflict_cannot_reconcile_winner(self):
        winner = self.build()
        winner_receipts, rejections = [], []

        def compete(_):
            self.clock.value += timedelta(seconds=1)
            winner_receipts.append(winner.append_audit_event(request(request_id="request.winner")))

        self.heads.before_cas = compete
        original = self.heads.compare_and_swap_head
        mutated = False

        def mutate_first(derived):
            nonlocal mutated
            if not mutated:
                mutated = True
                object.__setattr__(derived, "request_id", "request.substituted.native")
            try:
                return original(derived)
            except ProviderPolicyRejection as exc:
                rejections.append(exc)
                raise

        with patch.object(self.heads, "compare_and_swap_head", side_effect=mutate_first):
            with self.assertRaisesRegex(audit.CustodyAuditAppendUnconfirmed, "request changed"):
                self.sink.append_audit_event(request(request_id="request.loser"))
        self.assertEqual(winner_receipts[0].audit_sequence, 1)
        self.assertEqual(winner_receipts[0].append_status, "appended")
        self.assertEqual(len(rejections), 1)
        self.assertEqual(rejections[0].rejection_code, "ledger_head_conflict")
        self.assertEqual(rejections[0].request_id, "request.substituted.native")
        # Two initial reads for each operation plus two winner settlement reads.
        # The mutated loser must not read a winner to reinterpret its denial.
        self.assertEqual(sum(kind == "read" for kind, _ in self.heads.calls), 6)
        self.assertEqual(sum(kind == "cas" for kind, _ in self.heads.calls), 2)
        self.assertEqual(self.head().ledger_sequence, 1)

    def test_request_mutation_is_checked_on_generic_errors_before_or_after_application(self):
        for method_name in ("read_head", "compare_and_swap_head"):
            self.setUp()
            original = getattr(self.heads, method_name)

            def mutate_and_lose(derived):
                object.__setattr__(derived, "request_id", "request.substituted.native")
                original(derived)
                raise TimeoutError("synthetic acknowledgement loss")

            with (
                self.subTest(method=method_name),
                patch.object(self.heads, method_name, side_effect=mutate_and_lose),
            ):
                with self.assertRaisesRegex(audit.CustodyAuditAppendUnconfirmed, "request changed"):
                    self.sink.append_audit_event(request())
            self.assertEqual(
                sum(kind == "cas" for kind, _ in self.heads.calls),
                int(method_name == "compare_and_swap_head"),
            )
            if method_name == "read_head":
                self.assertIsNone(self.head())
            else:
                self.assertEqual(self.head().ledger_sequence, 1)

    def test_dispatch_owns_nested_request_copies_and_detects_original_request_mutation(self):
        payload = b"synthetic audit request"
        digest = audit._digest(payload)
        descriptor = LedgerObjectDescriptor(
            "audit." + digest[7:],
            digest,
            len(payload),
            HORIZON,
            self.arguments["namespace_id"],
            self.arguments["failure_domain_id"],
        )
        head = LedgerHeadDescriptor(
            self.arguments["deployment_id"], 1, descriptor.object_id, digest, None
        )
        requests = (
            (
                self.ledger.put_if_absent,
                LedgerObjectPutRequest("request.owned.put", descriptor, payload),
                "object",
            ),
            (
                self.heads.compare_and_swap_head,
                LedgerHeadCompareAndSwapRequest("request.owned.cas", None, head),
                "proposed_head",
            ),
        )
        for method, supplied, nested_field in requests:
            budget = audit._Budget(self.sink, self.sink._configuration)

            def change_original(dispatched):
                self.assertIsNot(dispatched, supplied)
                self.assertIsNot(getattr(dispatched, nested_field), getattr(supplied, nested_field))
                object.__setattr__(supplied, "request_id", "request.original.changed")
                return method(dispatched)

            with (
                self.subTest(family=type(supplied).__name__),
                self.assertRaisesRegex(audit.CustodyAuditAppendUnconfirmed, "request changed"),
            ):
                budget.call(change_original, supplied)
            self.assertEqual(budget.calls, 1)

    def test_internal_request_native_aliases_fail_before_normalization_or_provider_calls(self):
        class Alias(str):
            def __eq__(self, other):
                raise AssertionError("Request alias equality executed")

            __hash__ = str.__hash__

        query = LedgerHeadReadRequest("request.alias", self.arguments["deployment_id"])
        object.__setattr__(query, "request_id", Alias(query.request_id))
        budget = audit._Budget(self.sink, self.sink._configuration)
        with patch.object(self.heads, "read_head") as method:
            with self.assertRaises(audit.CustodyAuditChainError):
                budget.call(method, query)
            method.assert_not_called()
        self.assertEqual(budget.calls, 0)

    def test_first_append_replay_and_old_receipt_after_successors_and_cold_reconstruction(self):
        first = self.sink.append_audit_event(request())
        self.assertEqual((first.audit_sequence, first.append_status), (1, "appended"))
        initial_head = self.head()
        second = self.sink.append_audit_event(request("event.two", request_id="request.two"))
        self.assertEqual(second.audit_sequence, 2)
        self.assertEqual(self.head().previous_head_sha256, audit._head_digest(initial_head))
        third = self.sink.append_audit_event(request("event.three", request_id="request.three"))
        self.assertEqual(third.audit_sequence, 3)
        count = len(self.ledger.objects)
        for sink in (self.sink, self.build()):
            replay = sink.append_audit_event(request(request_id="request.old.replay"))
            self.assertEqual(replay.event, first.event)
            self.assertEqual(replay.audit_sequence, first.audit_sequence)
            self.assertEqual(replay.append_status, "already_appended_same_digest")
        self.assertEqual(len(self.ledger.objects), count)
        self.assertEqual(self.head().ledger_sequence, 3)

    def test_event_id_conflict_reconstructs_original_before_any_new_write(self):
        self.sink.append_audit_event(request())
        self.sink.append_audit_event(request("event.two"))
        before = len(self.ledger.objects)
        with self.assertRaises(audit.CustodyAuditChainConflict):
            self.build().append_audit_event(request(artifact="sha256:" + "2" * 64))
        self.assertEqual(len(self.ledger.objects), before)
        self.assertEqual(self.head().ledger_sequence, 2)

    def test_uploaded_orphan_without_head_does_not_allocate_or_acknowledge_sequence(self):
        def lost(receipt):
            raise TimeoutError("synthetic lost object acknowledgement")

        self.ledger.after_put = lost
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.sink.append_audit_event(request())
        self.assertEqual(len(self.ledger.objects), 1)
        self.assertIsNone(self.head())
        self.assertFalse(any(kind == "cas" for kind, _ in self.heads.calls))
        self.ledger.after_put = None
        retried = self.build().append_audit_event(request(request_id="request.retry"))
        self.assertEqual((retried.audit_sequence, retried.append_status), (1, "appended"))
        self.assertEqual(len(self.ledger.objects), 1)

    def test_lost_head_acknowledgement_is_unconfirmed_until_explicit_cold_replay(self):
        def lost(receipt):
            raise TimeoutError("synthetic lost CAS acknowledgement")

        self.heads.after_cas = lost
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.sink.append_audit_event(request())
        self.assertEqual(self.head().ledger_sequence, 1)
        self.assertEqual(sum(kind == "cas" for kind, _ in self.heads.calls), 1)
        self.heads.after_cas = None
        replay = self.build().append_audit_event(request(request_id="request.explicit.replay"))
        self.assertEqual(
            (replay.audit_sequence, replay.append_status), (1, "already_appended_same_digest")
        )
        self.assertEqual(sum(kind == "cas" for kind, _ in self.heads.calls), 1)

    def test_concurrent_different_winner_keeps_loser_object_orphaned_without_retry(self):
        winner = self.build()
        self.heads.before_cas = lambda _: winner.append_audit_event(request("event.winner"))
        with self.assertRaises(audit.CustodyAuditChainConflict):
            self.sink.append_audit_event(request("event.loser"))
        self.assertEqual(self.head().ledger_sequence, 1)
        self.assertEqual(len(self.ledger.objects), 2)
        self.assertEqual(sum(kind == "cas" for kind, _ in self.heads.calls), 2)
        replay = self.build().append_audit_event(request("event.winner"))
        self.assertEqual(replay.audit_sequence, 1)

    def test_confirmed_same_event_race_preserves_original_winner_sequence(self):
        winner = self.build()

        def compete(_):
            self.clock.value += timedelta(seconds=1)
            winner.append_audit_event(request(request_id="request.winner"))

        self.heads.before_cas = compete
        receipt = self.sink.append_audit_event(request(request_id="request.loser"))
        self.assertEqual(
            (receipt.audit_sequence, receipt.append_status), (1, "already_appended_same_digest")
        )
        self.assertEqual(len(self.ledger.objects), 2)
        self.assertEqual(self.head().ledger_sequence, 1)

    def test_identical_proposed_head_race_is_replay_not_a_second_allocation(self):
        winner = self.build()
        self.heads.before_cas = lambda _: winner.append_audit_event(request())
        receipt = self.sink.append_audit_event(request(request_id="request.loser"))
        self.assertEqual(receipt.append_status, "already_appended_same_digest")
        self.assertEqual(receipt.audit_sequence, 1)
        self.assertEqual(len(self.ledger.objects), 1)

    def test_unacknowledged_head_readback_does_not_upgrade_ambiguous_write(self):
        def applied_then_lost(receipt):
            raise RuntimeError("synthetic unknown write outcome")

        self.heads.after_cas = applied_then_lost
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.sink.append_audit_event(request())
        reads = [kind for kind, _ in self.heads.calls]
        self.assertEqual(reads, ["read", "read", "cas"])
        self.assertEqual(self.head().ledger_sequence, 1)

    def test_fabricated_success_without_current_head_is_not_a_receipt(self):
        def not_applied(cas):
            return LedgerHeadCompareAndSwapReceipt(cas.request_id, cas.proposed_head, "advanced")

        with patch.object(self.heads, "compare_and_swap_head", side_effect=not_applied):
            with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
                self.sink.append_audit_event(request())
        self.assertIsNone(self.head())
        self.assertEqual(len(self.ledger.objects), 1)

    def test_wrong_conflict_code_request_or_subject_cannot_be_reconciled(self):
        for key in ("code", "request", "subject", "missing"):
            self.setUp()

            def incorrect(cas):
                rejection = ProviderPolicyRejection(
                    "ledger_sequence_gap" if key == "code" else "ledger_head_conflict",
                    "request.foreign" if key == "request" else cas.request_id,
                    SHA if key == "subject" else provider_subject_sha256(cas.proposed_head),
                )
                if key == "missing":
                    object.__delattr__(rejection, "rejection_code")
                raise rejection

            with (
                self.subTest(key=key),
                patch.object(self.heads, "compare_and_swap_head", side_effect=incorrect),
            ):
                with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
                    self.sink.append_audit_event(request())
                self.assertIsNone(self.head())

    def test_live_retention_deleted_sources_and_changed_profile_block_old_replay(self):
        self.sink.append_audit_event(request())
        first = self.head()
        self.sink.append_audit_event(request("event.two"))
        descriptor, payload = self.ledger.objects[first.entry_id]
        self.ledger.objects[first.entry_id] = (
            replace(descriptor, retention_until="2029-01-01T00:00:00Z"),
            payload,
        )
        with self.assertRaises(audit.CustodyAuditChainError):
            self.build().append_audit_event(request())
        self.ledger.objects.pop(first.entry_id)
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.build().append_audit_event(request("event.two"))
        self.ledger.objects[first.entry_id] = (descriptor, payload)
        for changes in (
            {"namespace_id": "namespace.foreign"},
            {"failure_domain_id": "failure.foreign"},
            {"retention_until": "2029-01-01T00:00:00Z"},
        ):
            with self.subTest(changes=changes), self.assertRaises(audit.CustodyAuditChainError):
                self.build(**changes).append_audit_event(request())

    def test_expiry_before_during_and_after_storage_calls_never_yields_a_receipt(self):
        self.clock.value = datetime(2030, 1, 1, tzinfo=UTC)
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertEqual(self.ledger.calls + self.heads.calls, [])
        self.setUp()

        def expire(receipt):
            self.clock.value = datetime(2030, 1, 1, tzinfo=UTC)
            return receipt

        self.ledger.after_put = expire
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertIsNone(self.head())
        self.setUp()
        self.heads.after_cas = expire
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertEqual(self.head().ledger_sequence, 1)

    def test_same_instance_high_water_rejects_rollback_and_fork(self):
        self.sink.append_audit_event(request())
        initial = self.head()
        self.sink.append_audit_event(request("event.two"))
        latest = self.head()
        self.heads.heads[initial.deployment_id] = initial
        with self.assertRaisesRegex(audit.CustodyAuditChainError, "rolls back"):
            self.sink.append_audit_event(request())
        self.heads.heads[latest.deployment_id] = latest
        self.mutate_record(lambda raw: raw["event"].update(event_id="event.fork"))
        with self.assertRaisesRegex(audit.CustodyAuditChainError, "forks"):
            self.sink.append_audit_event(request())

    def test_valid_cold_prefix_requires_provider_currentness_not_a_fabricated_anchor(self):
        self.sink.append_audit_event(request())
        initial = self.head()
        self.sink.append_audit_event(request("event.two"))
        self.heads.heads[initial.deployment_id] = initial
        # A fresh instance has no independent anti-rollback anchor. This test
        # records that interface limitation instead of pretending it is a proof.
        receipt = self.build().append_audit_event(request())
        self.assertEqual(receipt.audit_sequence, 1)
        self.assertEqual(receipt.append_status, "already_appended_same_digest")

    def test_readdressed_foreign_duplicate_gapped_and_non_native_records_fail(self):
        changes = (
            lambda raw: raw.update(schema_version=True),
            lambda raw: raw.update(namespace_id="namespace.foreign"),
            lambda raw: raw.update(audit_sequence=3),
            lambda raw: raw.update(previous_head=None),
            lambda raw: raw["previous_head"].update(deployment_id="deployment.foreign"),
            lambda raw: raw["event"].update(event_id="event.one"),
            lambda raw: raw.update(recorded_at="2026-09-27T13:00:00Z"),
            lambda raw: raw.update(unexpected="field"),
        )
        for change in changes:
            self.setUp()
            self.sink.append_audit_event(request())
            self.sink.append_audit_event(request("event.two"))
            self.mutate_record(change)
            with (
                self.subTest(change=changes.index(change)),
                self.assertRaises(audit.CustodyAuditChainError),
            ):
                self.build().append_audit_event(request())

    def test_limits_reserve_settlement_before_mutation_and_bound_cold_traversal(self):
        for change in (
            {"maximum_provider_calls": 2},
            {"maximum_read_bytes": 1},
            {"maximum_object_bytes": 64},
        ):
            self.setUp()
            with self.subTest(change=change), self.assertRaises(audit.CustodyAuditChainError):
                self.build(**change).append_audit_event(request())
            self.assertEqual(len(self.ledger.objects), 0)
            self.assertIsNone(self.head())
        self.setUp()
        limited = self.build(maximum_traversal_records=1)
        limited.append_audit_event(request())
        with self.assertRaises(audit.CustodyAuditChainError):
            limited.append_audit_event(request("event.two"))
        self.assertEqual(len(self.ledger.objects), 1)
        self.sink.append_audit_event(request("event.two"))
        calls = len(self.ledger.calls)
        with self.assertRaises(audit.CustodyAuditChainError):
            self.build(maximum_traversal_records=1).append_audit_event(request())
        self.assertEqual(len(self.ledger.calls), calls)

    def test_native_aliases_subclasses_and_explicit_limits_fail_before_provider_hooks(self):
        class Alias(str):
            def __eq__(self, other):
                raise AssertionError("Native alias equality executed")

            __hash__ = str.__hash__

        class UnsupportedRequest(ReleaseAuditAppendRequest):
            def __post_init__(self):
                pass

            def __getattribute__(self, name):
                if name == "__post_init__":
                    return object.__getattribute__(self, name)
                raise AssertionError("Unsupported request hook executed")

        for field in ("event_id", "event_type", "actor_identity_id", "artifact_sha256"):
            value = request()
            object.__setattr__(value.event, field, Alias(getattr(value.event, field)))
            with self.subTest(field=field), self.assertRaises(audit.CustodyAuditChainError):
                self.sink.append_audit_event(value)
        value = request()
        object.__setattr__(value, "request_id", Alias(value.request_id))
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(value)
        unsupported = UnsupportedRequest("request.foreign", event())
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(unsupported)
        for field in (
            "maximum_traversal_records",
            "maximum_provider_calls",
            "maximum_read_bytes",
            "maximum_object_bytes",
        ):
            for value in (True, 1.0, 0, 2**10000):
                with self.subTest(field=field, kind=type(value).__name__):
                    with self.assertRaises(audit.CustodyAuditChainError):
                        self.build(**{field: value})
        self.assertEqual(self.ledger.calls + self.heads.calls, [])

    def test_valid_late_configuration_mutations_fail_before_clock_or_provider_calls(self):
        changes = (
            ("namespace_id", "namespace.changed"),
            ("failure_domain_id", "failure.changed"),
            ("deployment_id", "deployment.changed"),
            ("retention_until", "2031-01-01T00:00:00Z"),
            ("maximum_traversal_records", 101),
            ("maximum_provider_calls", 301),
            ("maximum_read_bytes", 1_000_001),
            ("maximum_object_bytes", 4097),
        )
        for field, value in changes:
            self.setUp()
            object.__setattr__(self.sink._configuration, field, value)
            with (
                self.subTest(field=field),
                patch.object(
                    self.sink, "_clock", side_effect=AssertionError("Clock must not be called")
                ) as clock,
            ):
                with self.assertRaisesRegex(audit.CustodyAuditChainError, "changed"):
                    self.sink.append_audit_event(request())
                clock.assert_not_called()
                self.assertEqual(self.ledger.calls + self.heads.calls, [])

    def test_valid_configuration_reassignment_and_missing_fields_fail_before_ports(self):
        self.sink._configuration = replace(
            self.sink._configuration, retention_until="2031-01-01T00:00:00Z"
        )
        with self.assertRaisesRegex(audit.CustodyAuditChainError, "changed"):
            self.sink.append_audit_event(request())
        self.assertEqual(self.ledger.calls + self.heads.calls, [])
        self.setUp()
        object.__delattr__(self.sink._configuration, "namespace_id")
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertEqual(self.ledger.calls + self.heads.calls, [])
        self.setUp()
        object.__delattr__(self.sink, "_configuration_sha256")
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertEqual(self.ledger.calls + self.heads.calls, [])

    def test_missing_d012_fields_and_oversized_times_have_bounded_typed_errors(self):
        for target, field in (("request", "request_id"), ("event", "event_type")):
            value = request()
            object.__delattr__(value if target == "request" else value.event, field)
            with self.subTest(target=target), self.assertRaises(audit.CustodyAuditChainError):
                self.sink.append_audit_event(value)
        self.assertEqual(self.ledger.calls + self.heads.calls, [])
        with patch.object(audit, "_UTC") as expression:
            with self.assertRaises(audit.CustodyAuditChainError):
                self.build(retention_until="x" * 1_000_000)
            expression.fullmatch.assert_not_called()

        def missing(receipt):
            object.__delattr__(receipt, "request_id")
            return receipt

        self.ledger.after_put = missing
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())
        self.assertIsNone(self.head())

    def test_mutated_receipts_request_bindings_and_byte_bounds_are_revalidated(self):
        for field, value in (("request_id", "request.foreign"), ("retention_lock_verified", 1)):
            self.setUp()

            def change(receipt):
                altered = copy.deepcopy(receipt)
                object.__setattr__(altered, field, value)
                return altered

            self.ledger.after_put = change
            with self.subTest(field=field), self.assertRaises(audit.CustodyAuditChainError):
                self.sink.append_audit_event(request())
            self.assertIsNone(self.head())
        self.setUp()
        self.sink.append_audit_event(request())

        def too_large(receipt):
            object.__setattr__(receipt, "payload", b"x" * (audit.MAXIMUM_RECORD_BYTES + 1))
            return receipt

        self.ledger.after_read = too_large
        with patch(
            "sunderkey.custody_release_audit_chain.hashlib.sha256", wraps=hashlib.sha256
        ) as digest:
            with self.assertRaises(audit.CustodyAuditChainError):
                self.build().append_audit_event(request())
            # Request IDs are hashed before the external read. Oversized payload
            # must never itself reach hashing or JSON decoding.
            self.assertFalse(any(call.args == (b"x" * 16_385,) for call in digest.call_args_list))

    def test_foreign_and_changing_head_reads_cannot_be_used_as_current_sources(self):
        self.sink.append_audit_event(request())
        original = self.head()
        self.heads.after_read = lambda receipt: LedgerHeadReadReceipt(
            receipt.request_id, replace(original, deployment_id="deployment.foreign")
        )
        with self.assertRaises(audit.CustodyAuditChainError):
            self.build().append_audit_event(request())
        self.heads.after_read = None
        count = 0

        def missing_afterward(receipt):
            nonlocal count
            count += 1
            return receipt if count == 1 else LedgerHeadReadReceipt(receipt.request_id, None)

        self.heads.after_read = missing_afterward
        with self.assertRaisesRegex(audit.CustodyAuditChainError, "changed"):
            self.build().append_audit_event(request())

    def test_aware_forward_clock_and_explicit_reference_ports_have_no_fallback(self):
        for clock in (None, lambda: datetime(2026, 9, 27), lambda: "2026-09-27T12:00:00Z"):
            with (
                self.subTest(clock=type(clock).__name__),
                self.assertRaises(audit.CustodyAuditChainError),
            ):
                self.build(clock=clock).append_audit_event(request())
        self.heads.environment_class = "unattested_external_claim"
        with self.assertRaises(audit.CustodyAuditChainError):
            self.build()
        self.heads.environment_class = audit.ENVIRONMENT_CLASS
        self.sink.append_audit_event(request())
        self.clock.value -= timedelta(seconds=1)
        with self.assertRaises(audit.CustodyAuditChainError):
            self.sink.append_audit_event(request())

    def test_unchanged_d012_case_eleven_accepts_exact_adapter_and_blocks_signer_on_fault(self):
        sink = self.sink
        fault = reference.ReferenceFaultInjector()

        class FaultAwareAdapter:
            def append_audit_event(self, value):
                fault.rejects("audit_append")
                return sink.append_audit_event(value)

        signer = reference.InMemorySigner()
        bundle = SimpleNamespace(
            checkpoint=None,
            release_audit=FaultAwareAdapter(),
            release_signer=signer,
            audit_event=event(),
            signing_request=ReleaseHeadSigningRequest(
                "request.sign",
                LedgerHeadDescriptor("deployment.release", 1, "entry.one", SHA, None),
                "key.reference",
                SHA,
                "sha256_simulation",
                "2026-09-27T12:00:00Z",
            ),
        )
        case = next(row for row in CASE_DEFINITIONS if row.case_id == "audit_append_blocks_release")
        observed = _run_case(case, bundle, fault)
        self.assertEqual(observed.outcome, "pass")
        self.assertEqual(signer.call_count, 1)
        self.assertEqual(self.head().ledger_sequence, 1)
        self.assertEqual(
            [row.observed_outcome for row in observed.variant_observations], ["accepted", "blocked"]
        )

    def test_real_adapter_failure_prevents_following_reference_signing(self):
        signer = reference.InMemorySigner()

        def fail(_):
            raise TimeoutError("synthetic storage uncertainty")

        self.ledger.after_put = fail
        with self.assertRaises(audit.CustodyAuditAppendUnconfirmed):
            self.sink.append_audit_event(request())
            signer.sign_head(
                ReleaseHeadSigningRequest(
                    "request.sign",
                    LedgerHeadDescriptor("deployment.release", 1, "entry.one", SHA, None),
                    "key.reference",
                    SHA,
                    "sha256_simulation",
                    "2026-09-27T12:00:00Z",
                )
            )
        self.assertEqual(signer.call_count, 0)

    def test_no_cloud_network_signing_credentials_file_or_default_transport_surface(self):
        tree = ast.parse(inspect.getsource(audit))
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertFalse(
            imported.intersection(
                {
                    "requests",
                    "httpx",
                    "socket",
                    "urllib.request",
                    "google.cloud.storage",
                    "google.cloud.kms",
                    "os",
                    "subprocess",
                    "pathlib",
                    "cryptography",
                }
            )
        )
        signature = inspect.signature(audit.CustodyReleaseAuditChain)
        self.assertTrue(
            all(value.default is inspect.Parameter.empty for value in signature.parameters.values())
        )
        self.assertEqual(self.sink.environment_class, audit.ENVIRONMENT_CLASS)


if __name__ == "__main__":
    unittest.main()

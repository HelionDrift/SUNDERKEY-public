"""Bounded supplied-receipt capture over disposable signed local custody."""

from __future__ import annotations

import copy
import json
import socket
import tempfile
import unittest
from collections import deque
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey.target_health_capture as capture_module
from sunderkey.authorized_target_health_runtime import (
    HealthSignalState,
    TargetHealthStatus,
    parse_target_health_receipt,
)
from sunderkey.execution_control_runtime import canonical_json, canonical_sha256
from sunderkey.target_adapter_conformance import AdapterStopState
from sunderkey.target_health_capture import (
    TargetHealthCaptureError,
    capture_target_health_receipts,
)
from sunderkey.target_health_custody import SQLiteTargetHealthCustody, TargetHealthAppendResult
from sunderkey.target_health_custody_contracts import (
    TargetHealthCustodyReceipt,
    TargetHealthTrustRoot,
    execution_binding_sha256,
)
from tests.agents import test_target_health_custody_inspection_phase199 as phase199
from tests.agents import test_target_health_custody_phase198 as phase198


def receipt_bytes(receipt):
    return canonical_json(receipt.to_dict()).encode("ascii")


def native_json_bytes(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def readdress_receipt(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"kind", "schema_version", "receipt_id", "receipt_sha256"}
    }
    digest = canonical_sha256({"body": body, "kind": document["kind"]})
    document["receipt_id"] = f"THR-{digest[7:39].upper()}"
    document["receipt_sha256"] = digest
    return native_json_bytes(document)


class ReceiptSource:
    def __init__(self, *items, callback=None):
        self.items = deque(items)
        self.callback = callback
        self.calls = []

    def read_receipt(self, *, maximum_bytes):
        self.calls.append(maximum_bytes)
        if self.callback is not None:
            self.callback()
        return self.items.popleft() if self.items else None


class EnvelopeSigner:
    def __init__(self, key, *, callback=None, result=None):
        self.key = key
        self.callback = callback
        self.result = result
        self.calls = []

    def sign(self, payload):
        self.calls.append(payload)
        if self.callback is not None:
            self.callback()
        return self.key.sign(payload) if self.result is None else self.result


class CustodyPort:
    def __init__(self, store):
        self.store = store
        self.contexts = []
        self.context_arguments = []
        self.envelopes = []
        self.before_context = None
        self.after_context = None
        self.before_append = None
        self.after_append = None

    def prepare_signing_context(self, **arguments):
        self.context_arguments.append(arguments.copy())
        if self.before_context is not None:
            self.before_context()
        context = self.store.prepare_signing_context(**arguments)
        self.contexts.append(context)
        return context if self.after_context is None else self.after_context(context)

    def append_envelope(self, envelope):
        self.envelopes.append(envelope)
        if self.before_append is not None:
            self.before_append(envelope)
        result = self.store.append_envelope(envelope)
        return result if self.after_append is None else self.after_append(envelope, result)


class BytesAlias(bytes):
    pass


class TextAlias(str):
    pass


class TargetHealthCaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.factory = phase198.ContractFactory()
        self.clock = phase198.FixedClock("2026-09-21T12:00:10Z")
        self.policy = self.factory.make_policy()
        self.store = SQLiteTargetHealthCustody(
            self.directory / "capture.sqlite3",
            trust_root=self.factory.root,
            trusted_clock=self.clock,
        )
        self.store.publish_policy(self.policy)
        self.custody = CustodyPort(self.store)
        self.signer = EnvelopeSigner(self.factory.collector_keys[1])
        self.stop = AdapterStopState()
        self.deadline = phase198.instant("2026-09-21T12:01:00Z")

    def receipt(self, tick=10, observed_at="2026-09-21T12:00:05Z"):
        return self.factory.make_receipt(observed_at=observed_at, monotonic_tick=tick)

    def capture(self, source, **changes):
        arguments = {
            "trust_root": self.factory.root,
            "policy": self.policy,
            "source": source,
            "signer": self.signer,
            "custody": self.custody,
            "stop_state": self.stop,
            "clock": self.clock,
            "maximum_source_calls": 5,
            "maximum_receipt_bytes": 65536,
            "maximum_total_bytes": 262144,
            "deadline": self.deadline,
        }
        arguments.update(changes)
        return capture_target_health_receipts(**arguments)

    def snapshot(self):
        return phase198.TargetHealthCustodyPhase198Tests.durable_snapshot(self.store.path)

    def assert_counters(self, result, source, signer=None, custody=None):
        signer = signer or self.signer
        custody = custody or self.custody
        self.assertEqual(result.source_calls, len(source.calls))
        self.assertEqual(result.signing_calls, len(signer.calls))
        self.assertEqual(result.context_calls, len(custody.context_arguments))
        self.assertEqual(result.append_calls, len(custody.envelopes))

    def assert_no_publication(self, result):
        self.assertEqual(result.publications, ())

    def completed_custody(self, receipt, name):
        factory = phase198.ContractFactory()
        factory.binding = receipt.binding
        factory.binding_sha256 = execution_binding_sha256(receipt.binding)
        factory.root = replace(
            factory.root,
            effective_at="2026-09-20T00:00:00Z",
            expires_at="2026-09-21T00:00:00Z",
            trust_root_id="",
            trust_root_sha256="",
        )
        clock = phase198.FixedClock("2026-09-20T12:00:10Z")
        policy = factory.make_policy(
            issued_at="2026-09-20T10:59:00Z",
            effective_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T18:00:00Z",
            runtime_policy_id=receipt.runtime_policy_id,
            runtime_policy_sha256=receipt.runtime_policy_sha256,
        )
        store = SQLiteTargetHealthCustody(
            self.directory / f"{name}.sqlite3", trust_root=factory.root, trusted_clock=clock
        )
        store.publish_policy(policy)
        return factory, policy, store, clock

    def test_successive_supplied_bytes_use_genuine_signed_contiguous_custody(self):
        first = self.receipt()
        second = self.receipt(11, "2026-09-21T12:00:06Z")
        source = ReceiptSource(receipt_bytes(first), receipt_bytes(second), None)
        with patch.object(socket, "create_connection", side_effect=AssertionError("network")):
            result = self.capture(source)
        self.assertEqual(result.reason, "source_exhausted")
        self.assertEqual(len(result.publications), 2)
        a, b = result.publications
        self.assertEqual((a.envelope.sequence, b.envelope.sequence), (1, 2))
        self.assertEqual(b.envelope.predecessor_envelope_id, a.envelope.envelope_id)
        self.assertEqual(b.envelope.predecessor_envelope_sha256, a.envelope.envelope_sha256)
        self.assertEqual(a.envelope.receipt.to_dict(), first.to_dict())
        self.assertEqual(b.envelope.receipt.to_dict(), second.to_dict())
        expected = self.factory.make_envelope(
            self.policy,
            sequence=1,
            observed_at=first.observed_at,
            monotonic_tick=first.monotonic_tick,
            receipt=first,
        )
        self.assertEqual(a.envelope.to_dict(), expected.to_dict())
        self.assertEqual(self.signer.calls[0], expected.signing_bytes())
        self.assertEqual(
            result.source_bytes, len(receipt_bytes(first)) + len(receipt_bytes(second))
        )
        self.assertFalse(a.replayed)
        self.assertFalse(b.replayed)
        self.assertIsNone(result.uncertain_envelope)
        self.assertEqual(self.store.verify().envelope_count, 2)
        self.assert_counters(result, source)

    def test_restart_reads_durable_context_without_reseeding(self):
        first = self.capture(ReceiptSource(receipt_bytes(self.receipt()), None))
        reopened = SQLiteTargetHealthCustody(
            self.store.path, trust_root=self.factory.root, trusted_clock=self.clock
        )
        port = CustodyPort(reopened)
        source = ReceiptSource(receipt_bytes(self.receipt(11)), None)
        second = self.capture(source, custody=port)
        self.assertEqual(len(second.publications), 1)
        a = first.publications[0].envelope
        b = second.publications[0].envelope
        self.assertEqual(b.sequence, 2)
        self.assertEqual(b.predecessor_envelope_id, a.envelope_id)
        self.assertEqual(port.contexts[0].current_head_sequence, 1)
        self.assertEqual(reopened.verify().envelope_count, 2)

    def test_epoch_rotation_keeps_global_sequence_and_original_predecessor(self):
        first = self.capture(ReceiptSource(receipt_bytes(self.receipt()), None))
        old = first.publications[0].envelope
        key = Ed25519PrivateKey.generate()
        self.factory.collector_keys[2] = key
        replacement = self.factory.make_policy(
            revision=2, epoch=2, previous=self.policy, prior_envelope=old, collector_key=key
        )
        self.store.publish_policy(replacement)
        result = self.capture(
            ReceiptSource(receipt_bytes(self.receipt(11)), None),
            policy=replacement,
            signer=EnvelopeSigner(key),
        )
        self.assertEqual(len(result.publications), 1)
        envelope = result.publications[0].envelope
        self.assertEqual((envelope.collector_epoch, envelope.sequence), (2, 2))
        self.assertEqual(envelope.predecessor_envelope_id, old.envelope_id)
        self.assertEqual(self.store.verify().envelope_count, 2)

    def test_duplicate_receipt_is_not_republished_or_retried(self):
        raw = receipt_bytes(self.receipt())
        source = ReceiptSource(raw, raw, None)
        result = self.capture(source)
        self.assertEqual(len(result.publications), 1)
        self.assertEqual(self.store.verify().envelope_count, 1)
        self.assertEqual(result.source_calls, 2)
        self.assertLessEqual(result.append_calls, 2)
        self.assertNotEqual(result.reason, "source_exhausted")
        self.assert_counters(result, source)

    def test_competing_signed_producer_wins_once_without_adoption_or_retry(self):
        competitor = SQLiteTargetHealthCustody(
            self.store.path, trust_root=self.factory.root, trusted_clock=self.clock
        )
        competing_envelopes = []

        def before_append(_):
            context = competitor.prepare_signing_context(
                tenant_id=self.policy.tenant_id,
                mission_id=self.policy.mission_id,
                collector_id=self.policy.collector_id,
                binding_sha256=self.policy.binding_sha256,
            )
            envelope = self.factory.make_envelope(
                self.policy,
                sequence=context.next_sequence,
                observed_at="2026-09-21T12:00:06Z",
                monotonic_tick=11,
                predecessor_id=context.previous_envelope_id,
                predecessor_sha256=context.previous_envelope_sha256,
            )
            competitor.append_envelope(envelope)
            competing_envelopes.append(envelope)

        self.custody.before_append = before_append
        source = ReceiptSource(receipt_bytes(self.receipt()), None)
        result = self.capture(source)
        self.assert_no_publication(result)
        self.assertEqual(result.reason, "append_failed")
        self.assertEqual(result.append_calls, 1)
        self.assertEqual(result.signing_calls, 1)
        self.assertEqual(result.source_calls, 1)
        self.assertEqual(result.uncertain_envelope.receipt_id, self.receipt().receipt_id)
        self.assertNotEqual(
            result.uncertain_envelope.envelope_id, competing_envelopes[0].envelope_id
        )
        self.assertEqual(self.store.verify().envelope_count, 1)
        self.assert_counters(result, source)

    def test_advancing_producer_during_source_prevents_stale_signing(self):
        def advance():
            envelope = self.factory.make_envelope(
                self.policy,
                sequence=1,
                observed_at="2026-09-21T12:00:06Z",
                monotonic_tick=11,
            )
            self.store.append_envelope(envelope)

        source = ReceiptSource(receipt_bytes(self.receipt()), callback=advance)
        result = self.capture(source)
        self.assert_no_publication(result)
        self.assertEqual(result.reason, "context_mismatch")
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (1, 0, 0)
        )
        self.assertEqual(self.store.verify().envelope_count, 1)
        self.assertIsNone(result.uncertain_envelope)

    def test_invalid_epoch_one_genesis_predecessor_denies_before_source_or_signer(self):
        self.custody.after_context = lambda context: replace(
            context,
            previous_envelope_id="THCE-" + "A" * 32,
            previous_envelope_sha256="sha256:" + "a" * 64,
        )
        source = ReceiptSource(receipt_bytes(self.receipt()), None)
        result = self.capture(source)
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (0, 0, 0)
        )
        self.assertEqual(result.reason, "context_mismatch")
        self.assert_no_publication(result)
        self.assertIsNone(result.uncertain_envelope)
        self.assertEqual(self.store.verify().envelope_count, 0)
        self.assert_counters(result, source)

    def test_confirmed_head_rewind_or_same_sequence_substitution_denies_next_source(self):
        for change in ("rewind", "same-sequence-substitution"):
            with self.subTest(change=change):
                self.setUp()
                initial_context = []

                def alter(context):
                    if not initial_context:
                        initial_context.append(context)
                    if not self.custody.envelopes:
                        return context
                    if change == "rewind":
                        return initial_context[0]
                    return replace(
                        context,
                        current_head_envelope_id="THCE-" + "A" * 32,
                        current_head_envelope_sha256="sha256:" + "a" * 64,
                        previous_envelope_id="THCE-" + "A" * 32,
                        previous_envelope_sha256="sha256:" + "a" * 64,
                    )

                self.custody.after_context = alter
                source = ReceiptSource(
                    receipt_bytes(self.receipt()),
                    receipt_bytes(self.receipt(11, "2026-09-21T12:00:06Z")),
                    None,
                )
                result = self.capture(source)
                self.assertEqual(len(result.publications), 1)
                self.assertEqual(result.publications[0].envelope.sequence, 1)
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (1, 1, 1)
                )
                self.assertEqual(result.reason, "context_mismatch")
                self.assertIsNone(result.uncertain_envelope)
                self.assertEqual(self.store.verify().envelope_count, 1)
                self.assert_counters(result, source)

    def test_genuine_higher_external_head_is_allowed_between_confirmed_publications(self):
        external = []

        def advance(envelope, result):
            if envelope.sequence == 1:
                other = self.factory.make_envelope(
                    self.policy,
                    sequence=2,
                    observed_at="2026-09-21T12:00:06Z",
                    monotonic_tick=11,
                    predecessor_id=envelope.envelope_id,
                    predecessor_sha256=envelope.envelope_sha256,
                )
                self.store.append_envelope(other)
                external.append(other)
            return result

        self.custody.after_append = advance
        source = ReceiptSource(
            receipt_bytes(self.receipt()),
            receipt_bytes(self.receipt(12, "2026-09-21T12:00:07Z")),
            None,
        )
        result = self.capture(source)
        self.assertEqual(result.reason, "source_exhausted")
        self.assertEqual([item.envelope.sequence for item in result.publications], [1, 3])
        self.assertEqual(
            result.publications[1].envelope.predecessor_envelope_id, external[0].envelope_id
        )
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (3, 2, 2)
        )
        self.assertIsNone(result.uncertain_envelope)
        self.assertEqual(self.store.verify().envelope_count, 3)
        self.assert_counters(result, source)

    def test_policy_rotation_during_source_prevents_signing(self):
        def rotate():
            self.store.publish_policy(self.factory.make_policy(revision=2, previous=self.policy))

        result = self.capture(ReceiptSource(receipt_bytes(self.receipt()), callback=rotate))
        self.assert_no_publication(result)
        self.assertEqual(result.reason, "context_mismatch")
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
        self.assertEqual(self.store.verify().envelope_count, 0)

    def test_revocation_during_source_prevents_signing(self):
        def revoke():
            self.store.publish_revocation(
                self.factory.make_revocation(self.policy, revoked_at="2026-09-21T12:00:10Z")
            )

        result = self.capture(ReceiptSource(receipt_bytes(self.receipt()), callback=revoke))
        self.assert_no_publication(result)
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
        self.assertEqual(self.store.verify().revocation_count, 1)
        self.assertIsNone(result.uncertain_envelope)

    def test_rotation_or_revocation_during_signing_denies_native_acceptance(self):
        for operation in ("rotate", "revoke"):
            with self.subTest(operation=operation):
                self.setUp()

                def change():
                    if operation == "rotate":
                        self.store.publish_policy(
                            self.factory.make_policy(revision=2, previous=self.policy)
                        )
                    else:
                        self.store.publish_revocation(
                            self.factory.make_revocation(
                                self.policy, revoked_at="2026-09-21T12:00:10Z"
                            )
                        )

                signer = EnvelopeSigner(self.factory.collector_keys[1], callback=change)
                result = self.capture(ReceiptSource(receipt_bytes(self.receipt())), signer=signer)
                self.assert_no_publication(result)
                self.assertEqual((result.signing_calls, result.append_calls), (1, 1))
                self.assertEqual(result.reason, "append_failed")
                self.assertIsNotNone(result.uncertain_envelope)
                self.assertEqual(self.store.verify().envelope_count, 0)

    def test_stale_and_future_valid_receipts_deny_before_signing(self):
        for observed in ("2026-09-21T11:50:00Z", "2026-09-21T12:00:30Z"):
            with self.subTest(observed=observed):
                source = ReceiptSource(receipt_bytes(self.receipt(observed_at=observed)))
                result = self.capture(source)
                self.assert_no_publication(result)
                self.assertEqual(result.reason, "receipt_not_current")
                self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
                self.assertEqual(self.store.verify().envelope_count, 0)

    def test_foreign_valid_binding_receipt_is_not_signed(self):
        foreign = phase198.ContractFactory(mission_id="mission:foreign")
        foreign.binding = replace(foreign.binding, tenant_id="tenant:other")
        foreign.binding_sha256 = execution_binding_sha256(foreign.binding)
        raw = receipt_bytes(
            foreign.make_receipt(observed_at="2026-09-21T12:00:05Z", monotonic_tick=10)
        )
        self.assertEqual(parse_target_health_receipt(raw).binding.tenant_id, "tenant:other")
        result = self.capture(ReceiptSource(raw))
        self.assert_no_publication(result)
        self.assertEqual(result.reason, "receipt_mismatch")
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))

    def test_native_bytes_only_supplier_boundary_and_budget_accounting(self):
        raw = receipt_bytes(self.receipt())
        for invalid in (raw.decode("ascii"), bytearray(raw), BytesAlias(raw), {}, 0, False):
            with self.subTest(type=type(invalid)):
                source = ReceiptSource(invalid)
                result = self.capture(source)
                self.assertEqual(result.reason, "source_invalid")
                self.assertEqual(result.source_calls, 1)
                self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
                self.assert_no_publication(result)

    def test_schema_bool_float_duplicate_and_noncanonical_bytes_are_rejected(self):
        document = self.receipt().to_dict()
        boolean = {**document, "schema_version": True}
        self.assertEqual(
            parse_target_health_receipt(native_json_bytes(boolean)).receipt_id,
            self.receipt().receipt_id,
        )
        floating = {**document, "schema_version": 1.0}
        duplicate = receipt_bytes(self.receipt())[:-1] + b',"schema_version":1}'
        noncanonical = json.dumps(document).encode("ascii")
        for raw in (
            native_json_bytes(boolean),
            native_json_bytes(floating),
            duplicate,
            noncanonical,
        ):
            with self.subTest(raw=raw[:60]):
                result = self.capture(ReceiptSource(raw))
                self.assertEqual(result.reason, "receipt_invalid")
                self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
                self.assert_no_publication(result)

    def test_coherent_native_boolean_counter_alias_is_not_normalized(self):
        for field in (
            "external_call_performed",
            "network_call_performed",
            "browser_action_performed",
            "authentication_performed",
            "source_validation_performed",
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.receipt().to_dict())
                document[field] = 0
                raw = readdress_receipt(document)
                parsed = parse_target_health_receipt(raw)
                self.assertIs(type(getattr(parsed, field)), int)
                result = self.capture(ReceiptSource(raw))
                self.assertEqual(result.reason, "receipt_invalid")
                self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
                self.assert_no_publication(result)

    def test_oversized_receipt_is_charged_then_denied_before_parse(self):
        raw = receipt_bytes(self.receipt())
        source = ReceiptSource(raw)
        result = self.capture(source, maximum_receipt_bytes=len(raw) - 1)
        self.assertEqual(result.reason, "receipt_byte_limit")
        self.assertEqual(result.source_bytes, len(raw))
        self.assertEqual(source.calls, [len(raw) - 1])
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))

    def test_finite_source_and_total_byte_ceilings_do_not_retry(self):
        raw = receipt_bytes(self.receipt())
        source = ReceiptSource(raw, None)
        result = self.capture(source, maximum_source_calls=1)
        self.assertEqual(result.reason, "source_call_limit")
        self.assertEqual(len(result.publications), 1)
        self.assertEqual(source.calls, [65536])
        self.setUp()
        source = ReceiptSource(raw)
        result = self.capture(source, maximum_total_bytes=len(raw) - 1)
        self.assertEqual(source.calls, [len(raw) - 1])
        self.assertEqual(result.source_bytes, len(raw))
        self.assert_no_publication(result)
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))

    def test_preexisting_stop_or_deadline_prevents_all_port_calls(self):
        for stopped in ("cancel", "emergency_stop", "deadline"):
            with self.subTest(stopped=stopped):
                stop = AdapterStopState()
                deadline = self.deadline
                if stopped == "deadline":
                    deadline = self.clock.value
                else:
                    getattr(stop, stopped)()
                source = ReceiptSource(receipt_bytes(self.receipt()))
                result = self.capture(source, stop_state=stop, deadline=deadline)
                self.assert_no_publication(result)
                self.assertEqual(
                    (
                        result.source_calls,
                        result.context_calls,
                        result.signing_calls,
                        result.append_calls,
                    ),
                    (0, 0, 0, 0),
                )
                self.assertIsNone(result.uncertain_envelope)

    def test_stop_or_deadline_during_source_prevents_signing(self):
        for reason in ("canceled", "deadline_reached"):
            with self.subTest(reason=reason):
                self.setUp()

                def change():
                    if reason == "canceled":
                        self.stop.cancel()
                    else:
                        self.clock.value = self.deadline

                source = ReceiptSource(receipt_bytes(self.receipt()), callback=change)
                result = self.capture(source)
                self.assertEqual(result.reason, reason)
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (1, 0, 0)
                )
                self.assert_no_publication(result)

    def test_policy_or_evidence_expiry_during_source_does_not_sign(self):
        def expire():
            self.clock.value = phase198.instant("2026-09-21T18:00:00Z")

        result = self.capture(
            ReceiptSource(receipt_bytes(self.receipt()), callback=expire),
            deadline=phase198.instant("2026-09-21T19:00:00Z"),
        )
        self.assert_no_publication(result)
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
        self.assertEqual(self.store.verify().envelope_count, 0)

    def test_evidence_aging_during_source_or_signing_denies_before_append(self):
        for phase in ("source", "sign"):
            with self.subTest(phase=phase):
                self.setUp()

                def expire_evidence():
                    self.clock.value = phase198.instant("2026-09-21T12:02:06Z")

                source = ReceiptSource(
                    receipt_bytes(self.receipt()),
                    callback=expire_evidence if phase == "source" else None,
                )
                signer = EnvelopeSigner(
                    self.factory.collector_keys[1],
                    callback=expire_evidence if phase == "sign" else None,
                )
                result = self.capture(
                    source,
                    signer=signer,
                    deadline=phase198.instant("2026-09-21T12:03:00Z"),
                )
                self.assertEqual(result.reason, "receipt_not_current")
                self.assert_no_publication(result)
                self.assertEqual(result.signing_calls, 0 if phase == "source" else 1)
                self.assertEqual(result.append_calls, 0)
                self.assertEqual(self.store.verify().envelope_count, 0)

    def test_embedded_evidence_expiry_during_callbacks_keeps_current_policy_unsigned(self):
        for family in ("observation", "safety", "budget"):
            for phase in ("source", "sign"):
                with self.subTest(family=family, phase=phase):
                    original = phase199.TargetHealthCustodyInspectionPhase199Tests._receipt(
                        "healthy"
                    )
                    expiry = "2026-09-20T12:00:11Z"
                    if family == "observation":
                        first = replace(
                            original.observations[0],
                            expires_at=expiry,
                            observation_id="",
                            observation_sha256="",
                        )
                        receipt = replace(
                            original,
                            observations=(first, *original.observations[1:]),
                            receipt_id="",
                            receipt_sha256="",
                        )
                    elif family == "safety":
                        safety = replace(
                            original.safety_attestation, expires_at=expiry, attestation_sha256=""
                        )
                        receipt = replace(
                            original,
                            safety_attestation=safety,
                            safety_attestation_sha256=safety.attestation_sha256,
                            receipt_id="",
                            receipt_sha256="",
                        )
                    else:
                        budget = replace(
                            original.budget_state, expires_at=expiry, state_id="", state_sha256=""
                        )
                        receipt = replace(
                            original,
                            budget_state=budget,
                            budget_state_sha256=budget.state_sha256,
                            receipt_id="",
                            receipt_sha256="",
                        )
                    factory, policy, store, clock = self.completed_custody(
                        receipt, f"expired-{family}-{phase}"
                    )

                    def expire():
                        clock.value = phase198.instant(expiry)

                    source = ReceiptSource(
                        receipt_bytes(receipt), callback=expire if phase == "source" else None
                    )
                    signer = EnvelopeSigner(
                        factory.collector_keys[1], callback=expire if phase == "sign" else None
                    )
                    result = self.capture(
                        source,
                        trust_root=factory.root,
                        policy=policy,
                        clock=clock,
                        custody=CustodyPort(store),
                        signer=signer,
                        deadline=phase198.instant("2026-09-20T12:01:00Z"),
                    )
                    self.assertEqual(result.reason, "receipt_not_current")
                    self.assert_no_publication(result)
                    self.assertEqual(result.signing_calls, 0 if phase == "source" else 1)
                    self.assertEqual(result.append_calls, 0)
                    self.assertLess(clock.value, phase198.instant(policy.expires_at))
                    self.assertLess(
                        (clock.value - phase198.instant(receipt.observed_at)).seconds,
                        policy.maximum_observation_age_seconds,
                    )
                    self.assertEqual(store.verify().envelope_count, 0)

    def test_stop_or_deadline_during_signing_denies_append_without_retry(self):
        for reason in ("canceled", "deadline_reached"):
            with self.subTest(reason=reason):
                self.setUp()

                def stop_after_sign():
                    if reason == "canceled":
                        self.stop.cancel()
                    else:
                        self.clock.value = self.deadline

                signer = EnvelopeSigner(self.factory.collector_keys[1], callback=stop_after_sign)
                result = self.capture(ReceiptSource(receipt_bytes(self.receipt())), signer=signer)
                self.assertEqual(result.reason, reason)
                self.assert_no_publication(result)
                self.assertEqual((result.signing_calls, result.append_calls), (1, 0))
                self.assertIsNone(result.uncertain_envelope)
                self.assertEqual(self.store.verify().envelope_count, 0)

    def test_source_and_signer_errors_are_sanitized_without_retry(self):
        secret = "synthetic-private-exception-detail"
        source = ReceiptSource(callback=Mock(side_effect=RuntimeError(secret)))
        result = self.capture(source)
        self.assertEqual(result.reason, "source_failed")
        self.assertNotIn(secret, repr(result))
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (1, 0, 0)
        )
        signer = EnvelopeSigner(
            self.factory.collector_keys[1], callback=Mock(side_effect=RuntimeError(secret))
        )
        source = ReceiptSource(receipt_bytes(self.receipt()))
        result = self.capture(source, signer=signer)
        self.assertEqual(result.reason, "signer_failed")
        self.assertNotIn(secret, repr(result))
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (1, 1, 0)
        )

    def test_signer_native_length_wrong_key_and_wrong_payload_fail_before_append(self):
        good = self.factory.collector_keys[1].sign(b"wrong-signing-domain")
        for invalid in (
            bytes(63),
            bytes(65),
            bytes(64),
            bytearray(good),
            BytesAlias(good),
            good.decode("latin1"),
            good,
            Ed25519PrivateKey.generate().sign(b"unrelated"),
        ):
            with self.subTest(type=type(invalid), length=len(invalid)):
                signer = EnvelopeSigner(self.factory.collector_keys[1], result=invalid)
                result = self.capture(ReceiptSource(receipt_bytes(self.receipt())), signer=signer)
                self.assertEqual(result.reason, "signature_invalid")
                self.assertEqual((result.signing_calls, result.append_calls), (1, 0))
                self.assert_no_publication(result)

    def test_append_acknowledged_then_error_is_uncertain_not_rolled_back(self):
        def fail_after_commit(_, result):
            self.assertEqual(result.receipt.verification.sequence, 1)
            raise RuntimeError("synthetic-hidden-append-detail")

        self.custody.after_append = fail_after_commit
        source = ReceiptSource(receipt_bytes(self.receipt()), None)
        result = self.capture(source)
        self.assert_no_publication(result)
        self.assertEqual(result.reason, "append_failed")
        self.assertNotIn("synthetic-hidden-append-detail", repr(result))
        self.assertEqual(result.append_calls, 1)
        self.assertEqual(result.uncertain_envelope.receipt_id, self.receipt().receipt_id)
        self.assertEqual(self.store.verify().envelope_count, 1)
        self.assert_counters(result, source)

    def test_malformed_append_acknowledgement_after_commit_preserves_uncertainty(self):
        for mutation in ("wrong-type", "replayed-alias", "envelope-id"):
            with self.subTest(mutation=mutation):
                self.setUp()

                def malformed(_, result):
                    if mutation == "wrong-type":
                        return {}
                    if mutation == "replayed-alias":
                        object.__setattr__(result, "replayed", 1)
                    else:
                        object.__setattr__(
                            result.receipt.verification, "envelope_id", "THCE-" + "A" * 32
                        )
                    return result

                self.custody.after_append = malformed
                result = self.capture(ReceiptSource(receipt_bytes(self.receipt())))
                self.assert_no_publication(result)
                self.assertEqual(result.reason, "append_result_invalid")
                self.assertEqual(result.append_calls, 1)
                self.assertIsNotNone(result.uncertain_envelope)
                self.assertEqual(self.store.verify().envelope_count, 1)

    def test_full_original_ack_verification_flags_are_not_invented_by_flat_replay(self):
        for field in (
            "signatures_verified",
            "current_policy_verified",
            "current_head_verified",
            "evidence_current_verified",
        ):
            with self.subTest(field=field):
                self.setUp()

                def mutate(_, result):
                    before = result.receipt.to_dict()
                    object.__setattr__(result.receipt.verification, field, False)
                    self.assertEqual(result.receipt.to_dict(), before)
                    return result

                self.custody.after_append = mutate
                result = self.capture(ReceiptSource(receipt_bytes(self.receipt())))
                self.assertEqual(result.reason, "append_result_invalid")
                self.assert_no_publication(result)
                self.assertIsNotNone(result.uncertain_envelope)
                self.assertEqual(result.append_calls, 1)
                self.assertEqual(self.store.verify().envelope_count, 1)

    def test_genuine_ack_before_helper_preappend_time_is_uncertain_not_promoted(self):
        helper_clock = phase198.FixedClock("2026-09-21T12:00:10Z")

        def advance_helper_clock():
            helper_clock.value = phase198.instant("2026-09-21T12:00:11Z")

        signer = EnvelopeSigner(self.factory.collector_keys[1], callback=advance_helper_clock)
        result = self.capture(
            ReceiptSource(receipt_bytes(self.receipt())), clock=helper_clock, signer=signer
        )
        self.assertEqual(result.reason, "append_result_invalid")
        self.assert_no_publication(result)
        self.assertIsNotNone(result.uncertain_envelope)
        self.assertEqual(result.append_calls, 1)
        self.assertEqual(self.store.verify().envelope_count, 1)

    def test_coherent_future_ack_uses_available_postcallback_time_and_retains_prior_prefix(self):
        for after in ("ordinary", "deadline", "postclock-stop"):
            with self.subTest(after=after):
                self.setUp()
                armed = []
                post_clock_reads = []

                def helper_clock():
                    value = self.clock()
                    if armed:
                        post_clock_reads.append(value)
                        if after == "postclock-stop":
                            self.stop.cancel()
                    return value

                def future(envelope, result):
                    if envelope.sequence != 2:
                        return result
                    at = "2026-09-21T12:00:20Z"
                    if after == "deadline":
                        self.clock.value = self.deadline
                        at = "2026-09-21T12:01:01Z"
                    verification = replace(
                        result.receipt.verification,
                        verified_at=at,
                        verification_id="",
                        verification_sha256="",
                    )
                    receipt = TargetHealthCustodyReceipt(verification, at)
                    event = replace(
                        result.event,
                        custody_receipt_id=receipt.custody_receipt_id,
                        custody_receipt_sha256=receipt.custody_receipt_sha256,
                        recorded_at=at,
                        event_id="",
                        event_sha256="",
                    )
                    armed.append(True)
                    return TargetHealthAppendResult(receipt, event, result.replayed)

                self.custody.after_append = future
                source = ReceiptSource(
                    receipt_bytes(self.receipt()),
                    receipt_bytes(self.receipt(11, "2026-09-21T12:00:06Z")),
                    None,
                )
                result = self.capture(source, clock=helper_clock)
                self.assertEqual([item.envelope.sequence for item in result.publications], [1])
                self.assertEqual(result.reason, "append_result_invalid")
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (2, 2, 2)
                )
                self.assertEqual(result.uncertain_envelope.sequence, 2)
                self.assertEqual(
                    result.uncertain_envelope.receipt_id,
                    self.receipt(11, "2026-09-21T12:00:06Z").receipt_id,
                )
                self.assertEqual(len(post_clock_reads), 1)
                self.assertEqual(self.store.verify().envelope_count, 2)
                self.assert_counters(result, source)

    def test_current_context_native_alias_or_future_time_prevents_source(self):
        for change in ("native-alias", "future-time"):
            with self.subTest(change=change):
                self.setUp()

                def alter(context):
                    if change == "native-alias":
                        object.__setattr__(context, "current_head_sequence", False)
                    else:
                        object.__setattr__(context, "prepared_at", "2026-09-21T12:00:11Z")
                    return context

                self.custody.after_context = alter
                source = ReceiptSource(receipt_bytes(self.receipt()))
                result = self.capture(source)
                self.assertEqual(
                    result.reason,
                    "context_invalid" if change == "native-alias" else "context_time_invalid",
                )
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (0, 0, 0)
                )
                self.assertEqual(self.store.verify().envelope_count, 0)

    def test_scheduled_revocation_ack_retains_exact_declared_references(self):
        revocation = self.factory.make_revocation(self.policy, revoked_at="2026-09-21T12:00:11Z")
        self.store.publish_revocation(revocation)
        result = self.capture(ReceiptSource(receipt_bytes(self.receipt()), None))
        self.assertEqual(len(result.publications), 1)
        verification = result.publications[0].receipt.verification
        self.assertEqual(verification.policy_revocation_id, revocation.revocation_id)
        self.assertEqual(verification.policy_revocation_sha256, revocation.revocation_sha256)
        self.assertEqual(result.reason, "source_exhausted")
        self.assertEqual(self.store.verify().revocation_count, 1)

    def test_clock_invalid_failure_and_regression_fail_closed_without_retry(self):
        for clock, reason in (
            (lambda: datetime(2026, 9, 21, 12), "clock_invalid"),
            (lambda: "2026-09-21T12:00:10Z", "clock_invalid"),
            (Mock(side_effect=RuntimeError("synthetic-clock-detail")), "clock_failed"),
        ):
            with self.subTest(reason=reason):
                source = ReceiptSource(receipt_bytes(self.receipt()))
                result = self.capture(source, clock=clock)
                self.assertEqual(result.reason, reason)
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (0, 0, 0)
                )
                self.assertNotIn("synthetic-clock-detail", repr(result))

        def regress():
            self.clock.value = datetime(2026, 9, 21, 12, 0, 9, tzinfo=UTC)

        result = self.capture(ReceiptSource(receipt_bytes(self.receipt()), callback=regress))
        self.assertEqual(result.reason, "clock_regressed")
        self.assertEqual(
            (result.source_calls, result.signing_calls, result.append_calls), (1, 0, 0)
        )
        self.assert_no_publication(result)

    def test_valid_ack_retained_when_postcommit_boundary_denies_continuation(self):
        for reason in ("canceled", "deadline_reached", "policy_not_current"):
            with self.subTest(reason=reason):
                self.setUp()

                def change(_, result):
                    if reason == "canceled":
                        self.stop.cancel()
                    elif reason == "policy_not_current":
                        self.clock.value = phase198.instant("2026-09-21T18:00:00Z")
                    else:
                        self.clock.value = self.deadline
                    return result

                self.custody.after_append = change
                result = self.capture(
                    ReceiptSource(receipt_bytes(self.receipt()), None),
                    deadline=phase198.instant("2026-09-21T19:00:00Z")
                    if reason == "policy_not_current"
                    else self.deadline,
                )
                self.assertEqual(result.reason, reason)
                self.assertEqual(len(result.publications), 1)
                self.assertEqual(result.append_calls, 1)
                self.assertEqual(self.store.verify().envelope_count, 1)
                self.assertIsNone(result.uncertain_envelope)

    def test_valid_ack_is_retained_on_failed_invalid_or_regressing_postcallback_clock(self):
        for reason in ("clock_failed", "clock_invalid", "clock_regressed"):
            with self.subTest(reason=reason):
                self.setUp()
                helper_clock = Mock(side_effect=self.clock)

                def change(_, result):
                    if reason == "clock_failed":
                        helper_clock.side_effect = RuntimeError("synthetic-postclock-detail")
                    elif reason == "clock_invalid":
                        helper_clock.side_effect = lambda: None
                    else:
                        helper_clock.side_effect = lambda: phase198.instant("2026-09-21T12:00:09Z")
                    return result

                self.custody.after_append = change
                source = ReceiptSource(receipt_bytes(self.receipt()), None)
                result = self.capture(source, clock=helper_clock)
                self.assertEqual(result.reason, reason)
                self.assertEqual(len(result.publications), 1)
                self.assertEqual(
                    (result.source_calls, result.signing_calls, result.append_calls), (1, 1, 1)
                )
                self.assertNotIn("synthetic-postclock-detail", repr(result))
                self.assertIsNone(result.uncertain_envelope)
                self.assertEqual(self.store.verify().envelope_count, 1)
                self.assert_counters(result, source)

    def test_caller_policy_and_returned_context_mutation_cannot_rebind_private_capture(self):
        policy_original = copy.deepcopy(self.policy.to_dict())
        supplied_root = TargetHealthTrustRoot.from_dict(self.factory.root.to_dict())
        context_originals = []

        def alter_caller():
            context = self.custody.contexts[0]
            context_originals.append(copy.deepcopy(context.to_dict()))
            object.__setattr__(context, "next_sequence", 999)
            object.__setattr__(self.policy, "runtime_policy_id", "THP-" + "F" * 32)
            object.__setattr__(supplied_root, "deployment_attestation_id", "attestation:other")

        source = ReceiptSource(receipt_bytes(self.receipt()), callback=alter_caller)
        result = self.capture(source, trust_root=supplied_root, maximum_source_calls=1)
        self.assertEqual(len(result.publications), 1)
        envelope = result.publications[0].envelope
        self.assertEqual(envelope.runtime_policy_id, policy_original["runtime_policy_id"])
        self.assertEqual(envelope.sequence, context_originals[0]["next_sequence"])
        self.assertEqual(self.store.verify().envelope_count, 1)

    def test_delivered_envelope_is_not_reused_as_uncertain_original(self):
        original_receipt = self.receipt()

        def mutate_delivered(envelope):
            object.__setattr__(envelope, "receipt_id", "THR-" + "F" * 32)
            raise RuntimeError("synthetic-uncertain-write")

        self.custody.before_append = mutate_delivered
        result = self.capture(ReceiptSource(receipt_bytes(original_receipt)))
        self.assertEqual(result.reason, "append_failed")
        self.assert_no_publication(result)
        self.assertIsNot(result.uncertain_envelope, self.custody.envelopes[0])
        self.assertEqual(result.uncertain_envelope.receipt_id, original_receipt.receipt_id)
        self.assertEqual(self.store.verify().envelope_count, 0)

    def test_publications_detach_received_envelope_receipt_event_and_repeat_exports(self):
        returned = []

        def record_received(envelope, result):
            returned.append((envelope, result))
            return result

        self.custody.after_append = record_received
        result = self.capture(ReceiptSource(receipt_bytes(self.receipt()), None))
        publication = result.publications[0]
        delivered, accepted = returned[0]
        self.assertIsNot(publication.envelope, delivered)
        self.assertIsNot(publication.envelope.receipt, delivered.receipt)
        self.assertIsNot(publication.receipt, accepted.receipt)
        self.assertIsNot(publication.event, accepted.event)
        original = copy.deepcopy(publication.envelope.to_dict())
        object.__setattr__(delivered, "sequence", 999)
        object.__setattr__(accepted.receipt, "recorded_at", "2026-09-21T12:00:59Z")
        self.assertEqual(publication.envelope.to_dict(), original)
        self.assertEqual(publication.receipt.recorded_at, "2026-09-21T12:00:10Z")
        exported = result.to_dict()
        expected_export = copy.deepcopy(exported)
        exported["publications"][0]["envelope"]["sequence"] = 999
        exported["publications"][0]["receipt"]["verified_at"] = "2026-09-21T12:00:59Z"
        self.assertEqual(result.to_dict(), expected_export)

    def test_rejected_and_completed_adverse_receipts_remain_non_authorizing(self):
        for state in ("rejected", "degraded", "unhealthy"):
            with self.subTest(state=state):
                receipt = phase199.TargetHealthCustodyInspectionPhase199Tests._receipt(state)
                factory = phase198.ContractFactory()
                factory.binding = receipt.binding
                factory.binding_sha256 = execution_binding_sha256(receipt.binding)
                factory.root = replace(
                    factory.root,
                    effective_at="2026-09-20T00:00:00Z",
                    expires_at="2026-09-21T00:00:00Z",
                    trust_root_id="",
                    trust_root_sha256="",
                )
                clock = phase198.FixedClock("2026-09-20T12:00:10Z")
                policy = factory.make_policy(
                    issued_at="2026-09-20T10:59:00Z",
                    effective_at="2026-09-20T11:00:00Z",
                    expires_at="2026-09-20T18:00:00Z",
                    runtime_policy_id=receipt.runtime_policy_id,
                    runtime_policy_sha256=receipt.runtime_policy_sha256,
                )
                store = SQLiteTargetHealthCustody(
                    self.directory / f"{state}.sqlite3",
                    trust_root=factory.root,
                    trusted_clock=clock,
                )
                store.publish_policy(policy)
                result = self.capture(
                    ReceiptSource(receipt_bytes(receipt), None),
                    trust_root=factory.root,
                    policy=policy,
                    clock=clock,
                    custody=CustodyPort(store),
                    signer=EnvelopeSigner(factory.collector_keys[1]),
                    deadline=phase198.instant("2026-09-20T12:01:00Z"),
                )
                self.assertEqual(len(result.publications), 1)
                envelope = result.publications[0].envelope
                self.assertEqual(envelope.receipt.to_dict(), receipt.to_dict())
                if state == "rejected":
                    self.assertIs(envelope.receipt.status, TargetHealthStatus.REJECTED)
                    self.assertIsNone(envelope.receipt.overall_health)
                else:
                    self.assertIs(envelope.receipt.overall_health, HealthSignalState(state))
                for field in (
                    "authority_effect",
                    "pause_effect",
                    "resume_effect",
                    "qualification_effect",
                ):
                    self.assertEqual(envelope.to_dict()[field], "none")
                self.assertFalse(envelope.to_dict()["target_effect_performed"])
                self.assertFalse(envelope.to_dict()["network_call_performed"])
                self.assertEqual(store.verify().envelope_count, 1)

    def test_configuration_native_limits_deadline_and_signed_source_reject_before_ports(self):
        for field, value in (
            ("maximum_source_calls", True),
            ("maximum_source_calls", 129),
            ("maximum_source_calls", 0),
            ("maximum_receipt_bytes", 1.0),
            ("maximum_receipt_bytes", 1048577),
            ("maximum_total_bytes", False),
            ("maximum_total_bytes", 134217729),
            ("deadline", "2026-09-21T12:01:00Z"),
            ("deadline", datetime(2026, 9, 21, 12, 1)),
            ("policy", object()),
            ("trust_root", object()),
        ):
            with self.subTest(field=field, value=value):
                source = ReceiptSource(receipt_bytes(self.receipt()))
                before = self.snapshot()
                with self.assertRaises(TargetHealthCaptureError):
                    self.capture(source, **{field: value})
                self.assertEqual(source.calls, [])
                self.assertEqual(self.signer.calls, [])
                self.assertEqual(self.custody.envelopes, [])
                self.assertEqual(self.snapshot(), before)
        forged = replace(
            self.policy, root_signature=phase198.b64(bytes(64)), policy_id="", policy_sha256=""
        )
        with self.assertRaises(TargetHealthCaptureError):
            self.capture(ReceiptSource(receipt_bytes(self.receipt())), policy=forged)

    def test_incomplete_exact_stop_state_is_configuration_error_before_clock_or_ports(self):
        stop = object.__new__(AdapterStopState)
        clock = Mock(side_effect=self.clock)
        source = ReceiptSource(receipt_bytes(self.receipt()))
        before = self.snapshot()
        with self.assertRaises(TargetHealthCaptureError):
            self.capture(source, stop_state=stop, clock=clock)
        clock.assert_not_called()
        self.assertEqual(source.calls, [])
        self.assertEqual(self.custody.context_arguments, [])
        self.assertEqual(self.signer.calls, [])
        self.assertEqual(self.custody.envelopes, [])
        self.assertEqual(self.snapshot(), before)

    def test_node_and_depth_byte_inputs_reject_before_existing_semantic_parser(self):
        nested = 0
        for _ in range(capture_module.MAX_DOCUMENT_DEPTH + 2):
            nested = [nested]
        for document in (
            {"bounded_negative": [None] * (capture_module.MAX_DOCUMENT_NODES + 1)},
            {"bounded_negative": nested},
        ):
            with self.subTest(
                family="nodes"
                if isinstance(document["bounded_negative"][0], type(None))
                else "depth"
            ):
                raw = native_json_bytes(document)
                self.assertLess(len(raw), 65536)
                source = ReceiptSource(raw)
                with patch.object(
                    capture_module,
                    "parse_target_health_receipt",
                    side_effect=AssertionError("semantic parser was reached"),
                ) as parser:
                    result = self.capture(source)
                parser.assert_not_called()
                self.assertEqual(result.reason, "receipt_invalid")
                self.assertEqual(result.source_bytes, len(raw))
                self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
                self.assert_no_publication(result)

    def test_transparent_reduced_combined_byte_bound_is_enforced_before_signer(self):
        # Placement control only, not a demonstrated production-limit bypass.
        receipt = self.receipt()
        context = self.store.prepare_signing_context(
            tenant_id=self.policy.tenant_id,
            mission_id=self.policy.mission_id,
            collector_id=self.policy.collector_id,
            binding_sha256=self.policy.binding_sha256,
        )
        envelope = self.factory.make_envelope(
            self.policy,
            sequence=context.next_sequence,
            observed_at=receipt.observed_at,
            monotonic_tick=receipt.monotonic_tick,
            receipt=receipt,
        )
        originals = (
            receipt.to_dict(),
            context.to_dict(),
            self.policy.to_dict(),
            self.factory.root.to_dict(),
        )
        largest_input = max(len(native_json_bytes(item)) for item in originals)
        combined = max(len(native_json_bytes(envelope.to_dict())), len(envelope.signing_bytes()))
        reduced = combined - 1
        self.assertLess(largest_input, reduced)
        self.assertLess(reduced, capture_module.MAX_DOCUMENT_BYTES)
        raw = receipt_bytes(receipt)
        source = ReceiptSource(raw)
        before = self.snapshot()
        with patch.object(capture_module, "MAX_DOCUMENT_BYTES", reduced):
            result = self.capture(source, maximum_receipt_bytes=reduced)
        self.assertEqual((result.terminal_stage, result.reason), ("sign", "envelope_invalid"))
        self.assertEqual(result.source_bytes, len(raw))
        self.assertEqual(result.source_calls, 1)
        self.assertEqual((result.signing_calls, result.append_calls), (0, 0))
        self.assert_no_publication(result)
        self.assertIsNone(result.uncertain_envelope)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()

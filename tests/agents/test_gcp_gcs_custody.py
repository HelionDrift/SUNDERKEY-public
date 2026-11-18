"""Synthetic two-port GCS mapping and unchanged D012 reference conformance."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import json
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import sunderkey.gcp_gcs_custody as gcs
from sunderkey.candidate_enrollment_production_custody_conformance import (
    CASE_DEFINITIONS,
    REFERENCE_ENVIRONMENT,
    build_production_custody_conformance_suite,
    run_production_custody_conformance,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    ConditionalLedgerHeadProvider,
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutRequest,
    LedgerObjectReadRequest,
    ProviderPolicyRejection,
    RetentionLockedLedgerObjectProvider,
    RetentionStateReadRequest,
    provider_subject_sha256,
)
from sunderkey.gcp_gcs_custody import (
    GCSAmbiguousWrite,
    GCSBucketProfile,
    GCSConditionalLedgerHeadProvider,
    GCSCustodyError,
    GCSCustodyProfiles,
    GCSObjectMetadata,
    GCSObjectRead,
    GCSPreconditionFailed,
    GCSReadRequest,
    GCSRetentionLockedLedgerObjectProvider,
    GCSWriteRequest,
)
from sunderkey.qualification import _canonical_json, _canonical_sha256
from tests.agents import test_production_custody_conformance_phase185 as reference

NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)
RETENTION_UNTIL = "2026-09-20T02:00:00Z"


def digest(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def profiles(namespace="namespace.ledger", failure="failure.ledger"):
    return GCSCustodyProfiles(
        GCSBucketProfile("gcs-offline-ledger-fixture", namespace, failure, False, True, 86400),
        GCSBucketProfile(
            "gcs-offline-head-fixture", "namespace.head", "failure.head", False, False, 0
        ),
    )


def head_document(head):
    return {
        "deployment_id": head.deployment_id,
        "ledger_sequence": head.ledger_sequence,
        "entry_id": head.entry_id,
        "entry_sha256": head.entry_sha256,
        "previous_head_sha256": head.previous_head_sha256,
    }


class DeterministicGCSTransport:
    """Test-only object state, not a Google client or cloud enforcement proof."""

    def __init__(self, declared, fault=None):
        self.profiles = {item.bucket: replace(item) for item in (declared.ledger, declared.head)}
        self.ledger_bucket = declared.ledger.bucket
        self.fault = fault
        self.objects = {}
        self.calls = []
        self.write_attempts = []
        self.applied_writes = 0
        self.ambiguous = None
        self.before_write = None
        self.metadata_transform = None
        self.read_transform = None
        self.write_transform = None

    def read_bucket_profile(self, bucket):
        self.calls.append(("bucket", bucket))
        if self.fault is not None and bucket == self.ledger_bucket:
            self.fault.rejects("retention_unavailable")
        return replace(self.profiles[bucket])

    def read_object_metadata(self, bucket, object_name):
        self.calls.append(("metadata", bucket, object_name))
        stored = self.objects.get((bucket, object_name))
        value = None if stored is None else copy.deepcopy(stored.metadata)
        return value if self.metadata_transform is None else self.metadata_transform(value)

    def read_object(self, request):
        self.calls.append(("read", request))
        stored = self.objects.get((request.bucket, request.object_name))
        if (
            stored is None
            or stored.metadata.generation != request.generation
            or stored.metadata.metageneration != request.metageneration
        ):
            raise GCSPreconditionFailed("Pinned read cannot be satisfied")
        value = copy.deepcopy(stored)
        return value if self.read_transform is None else self.read_transform(value)

    def write_object(self, request):
        self.calls.append(("write", request))
        self.write_attempts.append(copy.deepcopy(request))
        if self.ambiguous == "before":
            raise GCSAmbiguousWrite("Synthetic acknowledgement lost before application")
        if self.before_write is not None:
            hook, self.before_write = self.before_write, None
            hook(request)
        coordinates = (request.bucket, request.object_name)
        current = self.objects.get(coordinates)
        if request.if_generation_match == "0":
            if current is not None:
                raise GCSPreconditionFailed("Live object already exists")
        elif (
            current is None
            or current.metadata.generation != request.if_generation_match
            or current.metadata.metageneration != request.if_metageneration_match
        ):
            raise GCSPreconditionFailed("Content or metadata generation changed")
        self.applied_writes += 1
        # Tokens intentionally differ from logical sequences and need not increase.
        generation = str(
            1_000_000 + self.applied_writes if self.applied_writes % 2 else 15 + self.applied_writes
        )
        policy = self.profiles[request.bucket]
        retention = (
            (NOW + timedelta(seconds=policy.retention_period_seconds)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            if policy.retention_policy_locked
            else None
        )
        metadata = GCSObjectMetadata(
            request.bucket,
            request.object_name,
            generation,
            "1",
            len(request.payload),
            retention,
            copy.deepcopy(request.ledger_object),
            True,
        )
        self.objects[coordinates] = GCSObjectRead(metadata, request.payload)
        if self.ambiguous == "after":
            raise GCSAmbiguousWrite("Synthetic acknowledgement lost after application")
        return metadata if self.write_transform is None else self.write_transform(metadata)


class GCSMappedReferenceFactory(reference.ReferenceAdapterFactory):
    """Two GCS-mapped ports plus six existing in-memory reference ports."""

    def create_bundle(self, case_id, fault_injector):
        bundle = super().create_bundle(case_id, fault_injector)
        declared = profiles(
            bundle.ledger_object.namespace_id, bundle.ledger_object.failure_domain_id
        )
        required = datetime.fromisoformat(
            bundle.ledger_object.retention_until.removesuffix("Z") + "+00:00"
        )
        declared = replace(
            declared,
            ledger=replace(
                declared.ledger, retention_period_seconds=int((required - NOW).total_seconds())
            ),
        )
        transport = DeterministicGCSTransport(declared, fault_injector)
        result = replace(
            bundle,
            provider_descriptor={
                **bundle.provider_descriptor,
                "adapter_id": "gcs_mapped_two_port_reference_composite",
                "build_sha256": _canonical_sha256({"fixture": "gcs_two_port_reference_v1"}),
                "configuration_sha256": _canonical_sha256(asdict(declared)),
            },
            ledger_objects=GCSRetentionLockedLedgerObjectProvider(
                transport, declared, clock=lambda: NOW
            ),
            ledger_heads=GCSConditionalLedgerHeadProvider(transport, declared, clock=lambda: NOW),
        )
        self.bundles[-1] = result
        return result


class GCPCustodyMappingTests(unittest.TestCase):
    def setUp(self):
        self.profiles = profiles()
        self.transport = DeterministicGCSTransport(self.profiles)
        self.ledger = GCSRetentionLockedLedgerObjectProvider(
            self.transport, self.profiles, clock=lambda: NOW
        )
        self.heads = GCSConditionalLedgerHeadProvider(
            self.transport, self.profiles, clock=lambda: NOW
        )
        self.payload = b"synthetic offline ledger bytes"
        self.descriptor = LedgerObjectDescriptor(
            "entry.fixture",
            digest(self.payload),
            len(self.payload),
            RETENTION_UNTIL,
            self.profiles.ledger.namespace_id,
            self.profiles.ledger.failure_domain_id,
        )
        self.put = LedgerObjectPutRequest("request.create", self.descriptor, self.payload)
        self.initial = LedgerHeadDescriptor(
            "deployment.fixture", 1, "entry.first", digest(b"1"), None
        )
        self.successor = LedgerHeadDescriptor(
            "deployment.fixture",
            2,
            "entry.second",
            digest(b"2"),
            _canonical_sha256(head_document(self.initial)),
        )

    def create_ledger(self):
        return self.ledger.put_if_absent(self.put)

    def create_head(self):
        return self.heads.compare_and_swap_head(
            LedgerHeadCompareAndSwapRequest("request.head.initial", None, self.initial)
        )

    def test_native_two_port_create_replay_read_and_retention(self):
        self.assertIsInstance(self.ledger, RetentionLockedLedgerObjectProvider)
        self.assertIsInstance(self.heads, ConditionalLedgerHeadProvider)
        created = self.create_ledger()
        self.assertEqual(created.write_status, "created")
        self.assertTrue(created.retention_lock_verified)
        replay = self.ledger.put_if_absent(replace(self.put, request_id="request.replay"))
        self.assertEqual(replay.write_status, "already_present_same_digest")
        read = self.ledger.read_verified(
            LedgerObjectReadRequest(
                "request.read", self.descriptor.object_id, self.descriptor.sha256
            )
        )
        self.assertEqual(read.object, self.descriptor)
        self.assertEqual(read.payload, self.payload)
        retention = self.ledger.read_retention_state(
            RetentionStateReadRequest(
                "request.retention", self.descriptor.object_id, RETENTION_UNTIL
            )
        )
        self.assertTrue(retention.retention_lock_verified)
        self.assertTrue(retention.deletion_protection_verified)
        self.assertEqual(self.transport.applied_writes, 1)
        for request in self.transport.write_attempts:
            self.assertIs(type(request), GCSWriteRequest)
            self.assertEqual(request.if_generation_match, "0")
            self.assertIsNone(request.if_metageneration_match)
        pinned = [call[1] for call in self.transport.calls if call[0] == "read"]
        self.assertTrue(pinned)
        self.assertTrue(all(type(item) is GCSReadRequest for item in pinned))

    def test_collision_has_exact_policy_rejection_not_a_transport_error(self):
        self.create_ledger()
        other = b"different bytes"
        descriptor = replace(self.descriptor, sha256=digest(other), size_bytes=len(other))
        request = LedgerObjectPutRequest("request.collision", descriptor, other)
        with self.assertRaises(ProviderPolicyRejection) as raised:
            self.ledger.put_if_absent(request)
        self.assertEqual(raised.exception.rejection_code, "immutable_ledger_overwrite")
        self.assertEqual(raised.exception.request_id, request.request_id)
        self.assertEqual(raised.exception.subject_sha256, provider_subject_sha256(descriptor))
        self.assertEqual(self.transport.applied_writes, 1)

    def test_unsupported_profiles_are_rejected_without_any_transport_call(self):
        cases = (
            ("ledger", "versioning_enabled", True),
            ("head", "versioning_enabled", True),
            ("ledger", "retention_policy_locked", False),
            ("ledger", "retention_period_seconds", 0),
            ("head", "retention_policy_locked", True),
            ("head", "retention_period_seconds", 1),
            ("head", "bucket", self.profiles.ledger.bucket),
            ("head", "namespace_id", self.profiles.ledger.namespace_id),
            ("ledger", "versioning_enabled", 0),
            ("ledger", "retention_period_seconds", True),
        )
        for role, field, value in cases:
            with self.subTest(role=role, field=field):
                altered = copy.deepcopy(self.profiles)
                object.__setattr__(getattr(altered, role), field, value)
                with self.assertRaises(GCSCustodyError):
                    GCSRetentionLockedLedgerObjectProvider(
                        self.transport, altered, clock=lambda: NOW
                    )
        self.assertFalse(self.transport.calls)

    def test_observed_policy_or_frozen_profile_changes_cannot_enable_writes(self):
        self.transport.profiles[self.profiles.ledger.bucket] = replace(
            self.profiles.ledger, retention_policy_locked=False
        )
        with self.assertRaises(GCSCustodyError):
            self.create_ledger()
        self.assertFalse(self.transport.write_attempts)
        self.transport.profiles[self.profiles.ledger.bucket] = self.profiles.ledger
        object.__setattr__(self.ledger._profiles.head, "retention_policy_locked", True)
        with self.assertRaises(GCSCustodyError):
            self.create_ledger()
        self.assertFalse(self.transport.write_attempts)

    def test_invalid_request_and_wrong_profile_bindings_fail_before_mutation(self):
        cases = (
            ("size_bytes", len(self.payload) + 1),
            ("namespace_id", "namespace.other"),
            ("failure_domain_id", "failure.other"),
            ("retention_until", "2026-09-22T00:00:00Z"),
            ("retention_until", "2026-09-19T00:00:00Z"),
            ("sha256", digest(b"not the requested bytes")),
            ("size_bytes", float(len(self.payload))),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                request = copy.deepcopy(self.put)
                object.__setattr__(request.object, field, value)
                with self.assertRaises(GCSCustodyError):
                    self.ledger.put_if_absent(request)
        self.assertFalse(self.transport.write_attempts)

    def test_metadata_coordinates_tokens_and_native_types_are_revalidated(self):
        self.create_ledger()
        cases = (
            ("bucket", "gcs-other-fixture"),
            ("object_name", "ledger/other"),
            ("generation", "0"),
            ("generation", "01"),
            ("generation", 1),
            ("generation", str(2**63)),
            ("metageneration", True),
            ("size_bytes", float(len(self.payload))),
            ("is_live", False),
            ("retention_until", "2026-09-20T01:00:00Z"),
            ("retention_until", "2026-09-19T00:00:00Z"),
            ("retention_until", None),
            ("ledger_object", None),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):

                def alter(metadata):
                    object.__setattr__(metadata, field, value)
                    return metadata

                self.transport.metadata_transform = alter
                with self.assertRaises(GCSCustodyError):
                    self.ledger.read_verified(
                        LedgerObjectReadRequest(
                            "request.read", self.descriptor.object_id, self.descriptor.sha256
                        )
                    )
        self.transport.metadata_transform = None
        self.assertEqual(self.transport.applied_writes, 1)

    def test_pinned_read_rejects_generation_metadata_and_byte_substitution(self):
        self.create_ledger()
        transforms = (
            lambda value: replace(value, metadata=replace(value.metadata, generation="97")),
            lambda value: replace(value, metadata=replace(value.metadata, metageneration="2")),
            lambda value: replace(value, payload=b"x" * len(self.payload)),
            lambda value: replace(
                value,
                metadata=replace(
                    value.metadata,
                    ledger_object=replace(self.descriptor, sha256=digest(b"x" * len(self.payload))),
                ),
                payload=b"x" * len(self.payload),
            ),
        )
        for transform in transforms:
            with self.subTest(transform=transform):
                self.transport.read_transform = transform
                with self.assertRaises(GCSCustodyError):
                    self.ledger.read_verified(
                        LedgerObjectReadRequest(
                            "request.read", self.descriptor.object_id, self.descriptor.sha256
                        )
                    )
        self.transport.read_transform = None
        with self.assertRaises(GCSCustodyError):
            self.ledger.read_verified(
                LedgerObjectReadRequest(
                    "request.wrongdigest", self.descriptor.object_id, digest(b"wrong")
                )
            )
        with self.assertRaises(GCSCustodyError):
            self.ledger.read_retention_state(
                RetentionStateReadRequest(
                    "request.tooshort", self.descriptor.object_id, "2026-09-22T00:00:00Z"
                )
            )
        with self.assertRaises(GCSCustodyError):
            self.ledger.read_retention_state(
                RetentionStateReadRequest(
                    "request.undeclared", self.descriptor.object_id, "2026-09-20T03:00:00Z"
                )
            )

    def test_ambiguous_ledger_writes_do_not_retry_or_claim_policy_denial(self):
        for placement in ("before", "after"):
            with self.subTest(placement=placement):
                transport = DeterministicGCSTransport(self.profiles)
                transport.ambiguous = placement
                provider = GCSRetentionLockedLedgerObjectProvider(
                    transport, self.profiles, clock=lambda: NOW
                )
                with self.assertRaises(GCSCustodyError) as raised:
                    provider.put_if_absent(self.put)
                self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
                self.assertEqual(len(transport.write_attempts), 1)
                self.assertEqual(transport.applied_writes, int(placement == "after"))
                transport.ambiguous = None
                receipt = provider.put_if_absent(self.put)
                self.assertEqual(
                    receipt.write_status,
                    "created" if placement == "before" else "already_present_same_digest",
                )

    def test_head_cas_uses_provider_tokens_not_logical_sequence(self):
        empty = self.heads.read_head(LedgerHeadReadRequest("request.empty", "deployment.fixture"))
        self.assertIsNone(empty.head)
        self.assertEqual(self.create_head().compare_and_swap_status, "advanced")
        first_write = self.transport.write_attempts[-1]
        self.assertEqual(first_write.if_generation_match, "0")
        observed = self.transport.objects[(self.profiles.head.bucket, "heads/deployment.fixture")]
        self.assertNotEqual(observed.metadata.generation, str(self.initial.ledger_sequence))
        request = LedgerHeadCompareAndSwapRequest(
            "request.head.second", _canonical_sha256(head_document(self.initial)), self.successor
        )
        self.assertEqual(
            self.heads.compare_and_swap_head(request).compare_and_swap_status, "advanced"
        )
        second_write = self.transport.write_attempts[-1]
        self.assertEqual(second_write.if_generation_match, observed.metadata.generation)
        self.assertEqual(second_write.if_metageneration_match, observed.metadata.metageneration)
        current = self.transport.objects[(self.profiles.head.bucket, "heads/deployment.fixture")]
        self.assertLess(int(current.metadata.generation), int(observed.metadata.generation))
        self.assertEqual(
            self.heads.read_head(
                LedgerHeadReadRequest("request.current", "deployment.fixture")
            ).head,
            self.successor,
        )
        self.assertEqual(
            self.heads.compare_and_swap_head(request).compare_and_swap_status,
            "already_current_same_digest",
        )
        self.assertEqual(self.transport.applied_writes, 2)

    def test_head_fork_gap_rollback_have_exact_rejection_bindings(self):
        self.create_head()
        expected = _canonical_sha256(head_document(self.initial))
        self.heads.compare_and_swap_head(
            LedgerHeadCompareAndSwapRequest("request.second", expected, self.successor)
        )
        current_digest = _canonical_sha256(head_document(self.successor))
        cases = (
            (replace(self.successor, entry_id="entry.fork"), expected, "ledger_head_conflict"),
            (
                LedgerHeadDescriptor(
                    "deployment.fixture", 4, "entry.gap", digest(b"4"), current_digest
                ),
                current_digest,
                "ledger_sequence_gap",
            ),
            (
                LedgerHeadDescriptor(
                    "deployment.fixture", 2, "entry.rollback", digest(b"old"), current_digest
                ),
                current_digest,
                "ledger_sequence_gap",
            ),
        )
        for proposed, predecessor, code in cases:
            with self.subTest(code=code):
                request = LedgerHeadCompareAndSwapRequest("request.denied", predecessor, proposed)
                with self.assertRaises(ProviderPolicyRejection) as raised:
                    self.heads.compare_and_swap_head(request)
                self.assertEqual(raised.exception.rejection_code, code)
                self.assertEqual(raised.exception.request_id, request.request_id)
                self.assertEqual(raised.exception.subject_sha256, provider_subject_sha256(proposed))
        self.assertEqual(self.transport.applied_writes, 2)

    def test_head_race_and_metadata_race_do_not_retry(self):
        for metadata_only in (False, True):
            with self.subTest(metadata_only=metadata_only):
                transport = DeterministicGCSTransport(self.profiles)
                provider = GCSConditionalLedgerHeadProvider(
                    transport, self.profiles, clock=lambda: NOW
                )
                provider.compare_and_swap_head(
                    LedgerHeadCompareAndSwapRequest("request.initial", None, self.initial)
                )
                key = (self.profiles.head.bucket, "heads/deployment.fixture")

                def race(_):
                    stored = transport.objects[key]
                    payload = (
                        stored.payload
                        if metadata_only
                        else _canonical_json(
                            head_document(replace(self.successor, entry_id="entry.competitor"))
                        ).encode("utf-8")
                    )
                    metadata = replace(stored.metadata, metageneration="2", size_bytes=len(payload))
                    if not metadata_only:
                        metadata = replace(metadata, generation="79")
                    transport.objects[key] = GCSObjectRead(metadata, payload)

                transport.before_write = race
                request = LedgerHeadCompareAndSwapRequest(
                    "request.contender",
                    _canonical_sha256(head_document(self.initial)),
                    self.successor,
                )
                with self.assertRaises(
                    GCSCustodyError if metadata_only else ProviderPolicyRejection
                ):
                    provider.compare_and_swap_head(request)
                self.assertEqual(len(transport.write_attempts), 2)
                self.assertEqual(transport.applied_writes, 1)

    def test_ambiguous_head_application_requires_explicit_replay(self):
        self.transport.ambiguous = "after"
        with self.assertRaises(GCSCustodyError):
            self.create_head()
        self.assertEqual(len(self.transport.write_attempts), 1)
        self.transport.ambiguous = None
        self.assertEqual(self.create_head().compare_and_swap_status, "already_current_same_digest")
        self.assertEqual(len(self.transport.write_attempts), 1)

    def test_head_document_rejects_json_native_aliases_and_noncanonical_bytes(self):
        self.create_head()
        key = (self.profiles.head.bucket, "heads/deployment.fixture")
        original = self.transport.objects[key]
        documents = []
        for field, value in (
            ("ledger_sequence", True),
            ("ledger_sequence", 1.0),
            ("deployment_id", "deployment.other"),
        ):
            document = head_document(self.initial)
            document[field] = value
            documents.append(_canonical_json(document).encode("utf-8"))
        documents.extend(
            (
                json.dumps(head_document(self.initial)).encode("utf-8"),
                b'{"deployment_id":"deployment.fixture","deployment_id":"other"}',
                b"\xff",
                b"x" * (gcs.MAXIMUM_HEAD_BYTES + 1),
            )
        )
        for payload in documents:
            with self.subTest(payload=payload[:60]):
                self.transport.objects[key] = GCSObjectRead(
                    replace(original.metadata, size_bytes=len(payload)), payload
                )
                with self.assertRaises(GCSCustodyError):
                    self.heads.read_head(
                        LedgerHeadReadRequest("request.read", "deployment.fixture")
                    )
        self.transport.objects[key] = original

    def test_oversized_proposed_head_is_rejected_before_hooks_and_preserves_current_head(self):
        current = LedgerHeadDescriptor(
            "deployment.fixture", 10**3800, "entry.current", digest(b"current"), digest(b"previous")
        )
        current_payload = _canonical_json(head_document(current)).encode("utf-8")
        self.assertLessEqual(len(current_payload), gcs.MAXIMUM_HEAD_BYTES)
        coordinates = (self.profiles.head.bucket, "heads/deployment.fixture")
        metadata = GCSObjectMetadata(
            coordinates[0], coordinates[1], "39", "1", len(current_payload), None, None, True
        )
        self.transport.objects[coordinates] = GCSObjectRead(metadata, current_payload)
        proposed = LedgerHeadDescriptor(
            "deployment.fixture",
            current.ledger_sequence + 1,
            "a" * 128,
            digest(b"next"),
            _canonical_sha256(head_document(current)),
        )
        self.assertGreater(
            len(_canonical_json(head_document(proposed)).encode("utf-8")),
            gcs.MAXIMUM_HEAD_BYTES,
        )
        request = LedgerHeadCompareAndSwapRequest(
            "request.oversized", _canonical_sha256(head_document(current)), proposed
        )
        with self.assertRaisesRegex(GCSCustodyError, "Proposed head exceeds"):
            self.heads.compare_and_swap_head(request)
        self.assertFalse(self.transport.calls)
        self.assertFalse(self.transport.write_attempts)
        self.assertEqual(self.transport.applied_writes, 0)
        self.assertEqual(self.transport.objects[coordinates].payload, current_payload)
        self.assertEqual(
            self.heads.read_head(
                LedgerHeadReadRequest("request.retained", "deployment.fixture")
            ).head,
            current,
        )

    def test_typed_requests_and_subclasses_reconstruct_before_transport(self):
        class RequestSubclass(LedgerObjectPutRequest):
            pass

        with self.assertRaises(GCSCustodyError):
            self.ledger.put_if_absent(
                RequestSubclass(self.put.request_id, self.descriptor, self.payload)
            )
        request = copy.deepcopy(self.put)
        object.__setattr__(request, "payload", b"incorrect")
        with self.assertRaises(GCSCustodyError):
            self.ledger.put_if_absent(request)
        head_request = LedgerHeadCompareAndSwapRequest("request.head", None, self.initial)
        object.__setattr__(head_request.proposed_head, "ledger_sequence", True)
        with self.assertRaises(GCSCustodyError):
            self.heads.compare_and_swap_head(head_request)
        self.assertFalse(self.transport.calls)

    def test_native_string_fields_in_all_five_requests_fail_before_hooks(self):
        hooks = []

        class ForgedString(str):
            def __eq__(self, other):
                hooks.append("eq")
                return True

            def __ne__(self, other):
                hooks.append("ne")
                return False

        cases = (
            (self.ledger.put_if_absent, self.put, "request_id"),
            (
                self.ledger.read_verified,
                LedgerObjectReadRequest(
                    "request.read", self.descriptor.object_id, self.descriptor.sha256
                ),
                "expected_sha256",
            ),
            (
                self.ledger.read_retention_state,
                RetentionStateReadRequest(
                    "request.retention", self.descriptor.object_id, RETENTION_UNTIL
                ),
                "required_retention_until",
            ),
            (
                self.heads.read_head,
                LedgerHeadReadRequest("request.head", "deployment.fixture"),
                "deployment_id",
            ),
            (
                self.heads.compare_and_swap_head,
                LedgerHeadCompareAndSwapRequest("request.head", None, self.initial),
                "expected_head_sha256",
            ),
        )
        for operation, original, field in cases:
            with self.subTest(operation=operation.__name__):
                request = copy.deepcopy(original)
                object.__setattr__(request, field, ForgedString("unrelated"))
                with self.assertRaises(GCSCustodyError):
                    operation(request)
        self.assertFalse(hooks)
        self.assertFalse(self.transport.calls)

    def test_write_acknowledgements_cannot_substitute_coordinates_or_retention(self):
        for field, value in (
            ("bucket", "gcs-other-fixture"),
            ("object_name", "ledger/other"),
            ("generation", "0"),
            ("retention_until", "2026-09-19T00:00:00Z"),
            ("ledger_object", None),
        ):
            with self.subTest(field=field):
                transport = DeterministicGCSTransport(self.profiles)
                provider = GCSRetentionLockedLedgerObjectProvider(
                    transport, self.profiles, clock=lambda: NOW
                )

                def alter(metadata):
                    object.__setattr__(metadata, field, value)
                    return metadata

                transport.write_transform = alter
                with self.assertRaises(GCSCustodyError):
                    provider.put_if_absent(self.put)
                # Failure after application is not reported as an atomic rollback.
                self.assertEqual(transport.applied_writes, 1)
                self.assertEqual(len(transport.write_attempts), 1)

    def test_unconfirmed_precondition_and_pinned_read_failure_are_not_policy_evidence(self):
        def no_write(_):
            raise GCSPreconditionFailed("Synthetic unconfirmed precondition")

        self.transport.before_write = no_write
        with self.assertRaises(GCSCustodyError) as raised:
            self.create_ledger()
        self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
        self.assertEqual(self.transport.applied_writes, 0)
        self.create_ledger()

        def failed_read(_):
            raise GCSPreconditionFailed("Synthetic metadata changed during read")

        self.transport.read_transform = failed_read
        with self.assertRaises(GCSCustodyError) as raised:
            self.ledger.read_verified(
                LedgerObjectReadRequest(
                    "request.read", self.descriptor.object_id, self.descriptor.sha256
                )
            )
        self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
        self.assertEqual(self.transport.applied_writes, 1)

    def test_postwrite_policy_change_cannot_produce_a_verified_receipt(self):
        def changed_policy(metadata):
            self.transport.profiles[self.profiles.ledger.bucket] = replace(
                self.profiles.ledger, retention_policy_locked=False
            )
            return metadata

        self.transport.write_transform = changed_policy
        with self.assertRaises(GCSCustodyError):
            self.create_ledger()
        self.assertEqual(self.transport.applied_writes, 1)

    def test_declared_profiles_and_returned_receipt_descriptors_are_detached(self):
        object.__setattr__(self.profiles.head, "versioning_enabled", True)
        receipt = self.create_ledger()
        self.assertEqual(receipt.object, self.descriptor)
        stored = self.transport.objects[(self.profiles.ledger.bucket, "ledger/entry.fixture")]
        object.__setattr__(stored.metadata.ledger_object, "namespace_id", "namespace.other")
        self.assertEqual(receipt.object.namespace_id, "namespace.ledger")
        self.assertEqual(self.put.object.namespace_id, "namespace.ledger")

    def test_no_default_transport_sdk_d013_or_catalog_success_surface(self):
        self.assertEqual(gcs.ENVIRONMENT_CLASS, REFERENCE_ENVIRONMENT)
        for provider in (self.ledger, self.heads):
            self.assertFalse(hasattr(provider, "put_quarantined"))
            self.assertFalse(hasattr(provider, "put_sha256_object"))
            self.assertFalse(hasattr(provider, "delete_object"))
        with self.assertRaises(TypeError):
            GCSRetentionLockedLedgerObjectProvider()
        tree = ast.parse(inspect.getsource(gcs))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported |= {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and not node.level and node.module
        }
        self.assertFalse(
            imported & {"google", "requests", "urllib", "http", "socket", "subprocess"}
        )
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {"read_bytes", "write_bytes", "read_text", "write_text", "open"}
                for node in ast.walk(tree)
            )
        )


class GCSMappedConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference.ProductionCustodyConformancePhase185Tests.setUpClass()

    def test_unchanged_twelve_cases_with_two_gcs_mapped_reference_ports(self):
        fixture = reference.ProductionCustodyConformancePhase185Tests
        adapters = GCSMappedReferenceFactory(
            fixture.initial_intent,
            fixture.initial_record,
            fixture.replacement_intent,
            fixture.replacement_record,
        )
        suite = build_production_custody_conformance_suite(fixture.contract)
        try:
            report = run_production_custody_conformance(
                fixture.contract, suite, adapters, reference.ReferenceFaultFactory()
            )
        finally:
            adapters.close()
        self.assertEqual(report.overall_outcome, "conformant", report.to_dict())
        self.assertEqual(report.environment_class, "reference_simulation_nonqualifying")
        self.assertEqual(
            tuple(item.case_id for item in report.case_observations),
            tuple(item.case_id for item in CASE_DEFINITIONS),
        )
        self.assertEqual(len(report.case_observations), 12)
        self.assertTrue(all(item.outcome == "pass" for item in report.case_observations))
        document = report.to_dict()
        self.assertTrue(document["independent_review_required"])
        for field in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            self.assertEqual(document[field], "none")
        for bundle in adapters.bundles:
            self.assertIs(type(bundle.ledger_objects), GCSRetentionLockedLedgerObjectProvider)
            self.assertIs(type(bundle.ledger_heads), GCSConditionalLedgerHeadProvider)
            self.assertIs(type(bundle.catalog_objects), reference.InMemoryCatalogObjects)


if __name__ == "__main__":
    unittest.main()

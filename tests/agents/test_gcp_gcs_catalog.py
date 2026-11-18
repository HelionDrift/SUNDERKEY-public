"""Synthetic catalog mapping, fixed-horizon failures and unchanged D012 cases."""

from __future__ import annotations

import ast
import copy
import hashlib
import inspect
import unittest
from dataclasses import FrozenInstanceError, asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from sunderkey import gcp_gcs_catalog as catalog
from sunderkey.candidate_enrollment_production_custody_conformance import (
    CASE_DEFINITIONS,
    build_production_custody_conformance_suite,
    run_production_custody_conformance,
)
from sunderkey.candidate_enrollment_production_custody_contract import (
    CatalogObjectDescriptor,
    CatalogObjectPutRequest,
    CatalogObjectReadRequest,
    ImmutableCatalogObjectProvider,
    ProviderPolicyRejection,
    provider_subject_sha256,
)
from sunderkey.gcp_gcs_catalog import (
    ENVIRONMENT_CLASS,
    MAXIMUM_CONFIRMED_OBJECTS,
    MAXIMUM_OBJECT_BYTES,
    GCSCatalogBucketObservation,
    GCSCatalogDomain,
    GCSCatalogError,
    GCSCatalogObjectObservation,
    GCSCatalogObjectRead,
    GCSCatalogReadRequest,
    GCSCatalogSimulationProfile,
    GCSCatalogWriteRequest,
    GCSImmutableCatalogObjectProvider,
)
from sunderkey.gcp_gcs_custody import (
    GCSAmbiguousWrite,
    GCSConditionalLedgerHeadProvider,
    GCSPreconditionFailed,
    GCSRetentionLockedLedgerObjectProvider,
)
from sunderkey.qualification import _canonical_sha256
from tests.agents import test_production_custody_conformance_phase185 as reference
from tests.agents.test_gcp_gcs_custody import GCSMappedReferenceFactory

NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)
USE_UNTIL = "2026-09-20T02:00:00Z"
PAYLOAD = b"immutable-catalog-object"
ROOT = Path(__file__).resolve().parents[2]


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _profile(
    catalog_namespace="namespace.catalog",
    catalog_failure="failure.catalog",
    ledger_namespace="namespace.ledger",
    ledger_failure="failure.ledger",
) -> GCSCatalogSimulationProfile:
    return GCSCatalogSimulationProfile(
        GCSCatalogDomain(
            "gcs-offline-catalog-fixture", catalog_namespace, catalog_failure, "account.catalog"
        ),
        GCSCatalogDomain(
            "gcs-offline-ledger-fixture", ledger_namespace, ledger_failure, "account.ledger"
        ),
        "2026-09-20T00:00:00Z",
        USE_UNTIL,
        86400,
    )


class SyntheticCatalogTransport:
    """Only in-memory synthetic state, never a Google client or custody witness."""

    environment_class = ENVIRONMENT_CLASS

    def __init__(self, profile, fault=None):
        self.profile = copy.deepcopy(profile)
        self.fault = fault
        self.objects = {}
        self.calls = []
        self.write_attempts = []
        self.applied_writes = 0
        self.ambiguous = None
        self.before_write = None
        self.after_read = None
        self.bucket_transform = None
        self.metadata_transform = None
        self.read_transform = None
        self.write_transform = None

    def read_bucket(self, bucket, *, observed_at):
        self.calls.append(("bucket", bucket))
        result = GCSCatalogBucketObservation(
            self.profile.catalog,
            observed_at,
            True,
            False,
            True,
            self.profile.retention_period_seconds,
            False,
            False,
        )
        return result if self.bucket_transform is None else self.bucket_transform(result)

    def read_object_metadata(self, bucket, object_name, *, observed_at):
        self.calls.append(("metadata", bucket, object_name))
        stored = self.objects.get((bucket, object_name))
        result = None if stored is None else replace(stored.observation, observed_at=observed_at)
        return result if self.metadata_transform is None else self.metadata_transform(result)

    def read_object(self, request):
        self.calls.append(("read", copy.deepcopy(request)))
        stored = self.objects.get((request.bucket, request.object_name))
        if (
            stored is None
            or stored.observation.generation != request.generation
            or stored.observation.metageneration != request.metageneration
        ):
            raise GCSPreconditionFailed("Synthetic pinned read conflict")
        result = GCSCatalogObjectRead(
            replace(stored.observation, observed_at=request.observed_at), stored.payload
        )
        if self.after_read is not None:
            self.after_read()
        return result if self.read_transform is None else self.read_transform(result)

    def write_object(self, request):
        self.calls.append(("write", copy.deepcopy(request)))
        self.write_attempts.append(copy.deepcopy(request))
        if self.fault is not None:
            self.fault.rejects("catalog_put")
        if self.ambiguous == "before":
            raise GCSAmbiguousWrite("Synthetic lost acknowledgement before application")
        if self.before_write is not None:
            hook, self.before_write = self.before_write, None
            hook(request)
        coordinates = (request.bucket, request.object_name)
        if request.if_generation_match != "0" or request.if_metageneration_match is not None:
            raise AssertionError("Not a create-only catalog write")
        if coordinates in self.objects:
            raise GCSPreconditionFailed("Synthetic object already exists")
        self.applied_writes += 1
        result = GCSCatalogObjectObservation(
            request.bucket,
            request.object_name,
            str(1000 + self.applied_writes),
            "7",
            request.descriptor,
            "2026-09-21T00:00:00Z",
            request.observed_at,
            True,
            False,
            False,
            "bucket_policy",
        )
        self.objects[coordinates] = GCSCatalogObjectRead(result, request.payload)
        if self.ambiguous == "after":
            raise GCSAmbiguousWrite("Synthetic lost acknowledgement after application")
        return result if self.write_transform is None else self.write_transform(result)


class GCSCatalogMappingTests(unittest.TestCase):
    def setUp(self):
        self.profile = _profile()
        self.now = NOW
        self.transport = SyntheticCatalogTransport(self.profile)
        self.provider = GCSImmutableCatalogObjectProvider(
            self.transport, self.profile, clock=lambda: self.now
        )
        self.descriptor = CatalogObjectDescriptor(
            "catalog.release.1",
            _digest(PAYLOAD),
            len(PAYLOAD),
            "namespace.catalog",
            "failure.catalog",
        )

    def _put(self, *, descriptor=None, payload=PAYLOAD, request_id="request.catalog.create"):
        return self.provider.put_sha256_object(
            CatalogObjectPutRequest(
                request_id, self.descriptor if descriptor is None else descriptor, payload
            )
        )

    def _read(self, *, digest=None):
        return self.provider.read_sha256_object(
            CatalogObjectReadRequest(
                "request.catalog.read",
                self.descriptor.object_id,
                self.descriptor.sha256 if digest is None else digest,
            )
        )

    def _stored(self):
        return self.transport.objects[
            (self.profile.catalog.bucket, "catalog/" + self.descriptor.object_id)
        ]

    def _store_observation(self, **changes):
        stored = self._stored()
        changed = replace(stored.observation, **changes)
        self.transport.objects[(changed.bucket, changed.object_name)] = GCSCatalogObjectRead(
            changed, stored.payload
        )

    def test_create_exact_replay_and_read_use_stable_id_with_pinned_bytes(self):
        self.assertIsInstance(self.provider, ImmutableCatalogObjectProvider)
        created = self._put()
        self.assertEqual(created.write_status, "created")
        self.assertTrue(created.immutable_storage_verified)
        self.assertEqual(created.object, self.descriptor)
        self.assertIsNot(created.object, self.descriptor)
        write = self.transport.write_attempts[0]
        self.assertIs(type(write), GCSCatalogWriteRequest)
        self.assertEqual(write.object_name, "catalog/catalog.release.1")
        self.assertEqual((write.if_generation_match, write.if_metageneration_match), ("0", None))
        self.assertEqual(write.payload, PAYLOAD)
        self.now += timedelta(minutes=1)
        replay = self._put(request_id="request.catalog.replay")
        self.assertEqual(replay.write_status, "already_present_same_digest")
        read = self._read()
        self.assertEqual(read.payload, PAYLOAD)
        self.assertTrue(read.digest_verified)
        self.assertEqual(len(self.transport.write_attempts), 1)
        pinned = [item[1] for item in self.transport.calls if item[0] == "read"][-1]
        self.assertIs(type(pinned), GCSCatalogReadRequest)
        self.assertEqual((pinned.generation, pinned.metageneration), ("1001", "7"))
        self.assertEqual(pinned.descriptor, self.descriptor)

    def test_same_id_new_truthful_sha_has_exact_policy_rejection(self):
        self._put()
        foreign = b"different-catalog-bytes"
        descriptor = replace(self.descriptor, sha256=_digest(foreign), size_bytes=len(foreign))
        with self.assertRaises(ProviderPolicyRejection) as raised:
            self._put(descriptor=descriptor, payload=foreign, request_id="request.catalog.conflict")
        self.assertEqual(raised.exception.rejection_code, "immutable_catalog_overwrite")
        self.assertEqual(raised.exception.request_id, "request.catalog.conflict")
        self.assertEqual(raised.exception.subject_sha256, provider_subject_sha256(descriptor))
        self.assertEqual(self._read().payload, PAYLOAD)
        self.assertEqual(self.transport.applied_writes, 1)

    def test_wrong_read_sha_missing_object_and_same_digest_descriptor_collision(self):
        with self.assertRaises(GCSCatalogError):
            self._read()
        self._put()
        with self.assertRaises(GCSCatalogError):
            self._read(digest="sha256:" + "0" * 64)
        source = replace(self.descriptor, namespace_id="namespace.foreign")
        with self.assertRaises(GCSCatalogError):
            self._put(descriptor=source)
        self.assertEqual(self.transport.applied_writes, 1)

    def test_all_four_custody_declarations_must_be_distinct_and_complete(self):
        for name in ("bucket", "namespace_id", "failure_domain_id", "account_reference"):
            with self.subTest(name=name), self.assertRaises(GCSCatalogError):
                replace(
                    self.profile,
                    ledger=replace(
                        self.profile.ledger, **{name: getattr(self.profile.catalog, name)}
                    ),
                )
            with self.subTest(blank=name), self.assertRaises(GCSCatalogError):
                replace(self.profile.catalog, **{name: ""})
        with self.assertRaises(TypeError):
            GCSCatalogSimulationProfile(self.profile.catalog, self.profile.ledger)

    def test_horizon_is_explicit_fixed_and_bounded_not_refreshed_on_replay(self):
        self._put()
        before = self.profile.to_dict()
        self.now = NOW + timedelta(hours=2) - timedelta(seconds=1)
        self.assertEqual(self._put().write_status, "already_present_same_digest")
        self.now += timedelta(seconds=1)
        calls = len(self.transport.calls)
        for operation in (self._put, self._read):
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(GCSCatalogError, "horizon"),
            ):
                operation()
        self.assertEqual(len(self.transport.calls), calls)
        self.assertEqual(self.profile.to_dict(), before)
        self.assertEqual(self.provider._profile.simulation_use_until, USE_UNTIL)
        self.assertEqual(self.transport.applied_writes, 1)

    def test_absence_after_expiry_cannot_create_or_recreate_an_identity(self):
        self._put()
        self.transport.objects.clear()
        self.now = NOW + timedelta(hours=2)
        before = len(self.transport.calls)
        with self.assertRaises(GCSCatalogError):
            self._put()
        self.assertEqual(len(self.transport.calls), before)
        self.assertEqual(self.transport.applied_writes, 1)
        with self.assertRaises(GCSCatalogError):
            GCSImmutableCatalogObjectProvider(self.transport, self.profile, clock=lambda: self.now)
        self.assertEqual(len(self.transport.calls), before)

    def test_deleted_noncurrent_and_recreated_confirmed_versions_fail(self):
        self._put()
        original = copy.deepcopy(self._stored())
        coordinates = (self.profile.catalog.bucket, "catalog/" + self.descriptor.object_id)
        self.transport.objects.clear()
        for operation in (self._put, self._read):
            with self.subTest(absent=operation), self.assertRaises(GCSCatalogError):
                operation()
        self.assertEqual(self.transport.applied_writes, 1)
        self.transport.objects[coordinates] = GCSCatalogObjectRead(
            replace(original.observation, is_current=False), original.payload
        )
        with self.assertRaises(GCSCatalogError):
            self._read()
        self.transport.objects[coordinates] = GCSCatalogObjectRead(
            replace(original.observation, generation="2001"), original.payload
        )
        with self.assertRaisesRegex(GCSCatalogError, "recreated"):
            self._put()
        self.transport.objects[coordinates] = original
        self.assertEqual(self._read().payload, PAYLOAD)

    def test_object_holds_unsupported_mode_and_short_retention_fail(self):
        self._put()
        original = copy.deepcopy(self._stored())
        coordinates = (self.profile.catalog.bucket, "catalog/" + self.descriptor.object_id)
        for changes in (
            {"temporary_hold": True},
            {"event_based_hold": True},
            {"retention_mode": "object_lock"},
            {"retention_until": "2026-09-20T01:59:59Z"},
        ):
            self.transport.objects[coordinates] = original
            self._store_observation(**changes)
            with self.subTest(changes=changes), self.assertRaises(GCSCatalogError):
                self._read()
        self.transport.objects[coordinates] = original
        self.assertEqual(self._read().payload, PAYLOAD)

    def test_incomplete_noncurrent_or_unsupported_bucket_evidence_blocks_before_write(self):
        for changes in (
            {"is_current": False},
            {"versioning_enabled": True},
            {"retention_policy_locked": False},
            {"retention_period_seconds": 86399},
            {"retention_period_seconds": 86401},
            {"default_event_based_hold": True},
            {"object_retention_enabled": True},
            {"observed_at": NOW - timedelta(seconds=1)},
            {"domain": replace(self.profile.catalog, account_reference="account.foreign")},
        ):
            self.transport.bucket_transform = lambda value, changes=changes: replace(
                value, **changes
            )
            with self.subTest(changes=changes), self.assertRaises(GCSCatalogError):
                self._put()
        for observation in (None, {}, self.profile):
            self.transport.bucket_transform = lambda _, observation=observation: observation
            with self.subTest(observation=observation), self.assertRaises(GCSCatalogError):
                self._put()
        self.assertFalse(self.transport.write_attempts)

    def test_longer_observed_retention_never_extends_fixed_source_horizon(self):
        def longer(value):
            observed = replace(value, retention_until="2027-09-20T00:00:00Z")
            self.transport.objects[(observed.bucket, observed.object_name)] = GCSCatalogObjectRead(
                observed, PAYLOAD
            )
            return observed

        self.transport.write_transform = longer
        self.assertEqual(self._put().write_status, "created")
        self.assertEqual(self._put().write_status, "already_present_same_digest")
        self.assertEqual(self.provider._profile.simulation_use_until, USE_UNTIL)
        self.now = NOW + timedelta(hours=2)
        with self.assertRaisesRegex(GCSCatalogError, "horizon"):
            self._read()

    def test_protection_equal_to_horizon_is_enough_but_expiry_is_exclusive(self):
        self._put()
        stored = self._stored()
        self.transport.objects[(stored.observation.bucket, stored.observation.object_name)] = (
            GCSCatalogObjectRead(
                replace(stored.observation, retention_until=USE_UNTIL), stored.payload
            )
        )
        fresh = GCSImmutableCatalogObjectProvider(
            self.transport, self.profile, clock=lambda: self.now
        )
        request = CatalogObjectReadRequest(
            "request.exact.horizon", self.descriptor.object_id, self.descriptor.sha256
        )
        self.assertEqual(fresh.read_sha256_object(request).payload, PAYLOAD)
        self.now = NOW + timedelta(hours=2)
        with self.assertRaises(GCSCatalogError):
            fresh.read_sha256_object(request)

    def test_pinned_generation_metadata_descriptor_and_bytes_cannot_be_substituted(self):
        self._put()
        for field, value in (
            ("generation", "9"),
            ("metageneration", "8"),
            ("bucket", "gcs-foreign-fixture"),
            ("object_name", "catalog/foreign"),
            ("descriptor", replace(self.descriptor, failure_domain_id="failure.foreign")),
        ):
            self.transport.read_transform = lambda result, field=field, value=value: (
                GCSCatalogObjectRead(replace(result.observation, **{field: value}), result.payload)
            )
            with self.subTest(field=field), self.assertRaises(GCSCatalogError):
                self._read()
        self.transport.read_transform = lambda result: GCSCatalogObjectRead(
            result.observation, b"X" * len(PAYLOAD)
        )
        with self.assertRaises(GCSCatalogError):
            self._read()
        self.transport.read_transform = lambda _: (_ for _ in ()).throw(
            GCSPreconditionFailed("changed")
        )
        with self.assertRaises(GCSCatalogError):
            self._read()

    def test_ambiguous_writes_do_not_retry_or_claim_provider_denial(self):
        for outcome, expected in (("before", "created"), ("after", "already_present_same_digest")):
            transport = SyntheticCatalogTransport(self.profile)
            provider = GCSImmutableCatalogObjectProvider(transport, self.profile, clock=lambda: NOW)
            transport.ambiguous = outcome
            request = CatalogObjectPutRequest("request.ambiguous", self.descriptor, PAYLOAD)
            with self.subTest(outcome=outcome), self.assertRaises(GCSCatalogError) as raised:
                provider.put_sha256_object(request)
            self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
            self.assertEqual(len(transport.write_attempts), 1)
            transport.ambiguous = None
            receipt = provider.put_sha256_object(request)
            self.assertEqual(receipt.write_status, expected)
            self.assertEqual(transport.applied_writes, 1)

    def test_create_race_confirms_winner_or_returns_exact_collision_without_retry(self):
        for matching in (True, False):
            transport = SyntheticCatalogTransport(self.profile)
            provider = GCSImmutableCatalogObjectProvider(transport, self.profile, clock=lambda: NOW)

            def win(request):
                payload = request.payload if matching else b"foreign-catalog-bytes"
                descriptor = (
                    request.descriptor
                    if matching
                    else replace(
                        request.descriptor, sha256=_digest(payload), size_bytes=len(payload)
                    )
                )
                transport.write_object(
                    replace(
                        request, request_id="request.winner", descriptor=descriptor, payload=payload
                    )
                )

            transport.before_write = win
            request = CatalogObjectPutRequest("request.racer", self.descriptor, PAYLOAD)
            if matching:
                self.assertEqual(
                    provider.put_sha256_object(request).write_status, "already_present_same_digest"
                )
            else:
                with self.assertRaises(ProviderPolicyRejection) as raised:
                    provider.put_sha256_object(request)
                self.assertEqual(raised.exception.request_id, request.request_id)
            self.assertEqual(transport.applied_writes, 1)
            self.assertEqual(len(transport.write_attempts), 2)

    def test_unconfirmed_precondition_and_plain_transport_error_are_not_policy_evidence(self):
        self.transport.write_object = lambda _: (_ for _ in ()).throw(
            GCSPreconditionFailed("unconfirmed")
        )
        with self.assertRaises(GCSCatalogError) as raised:
            self._put()
        self.assertNotIsInstance(raised.exception, ProviderPolicyRejection)
        self.transport.write_object = lambda _: (_ for _ in ()).throw(
            RuntimeError("transport failed")
        )
        with self.assertRaises(RuntimeError):
            self._put()

    def test_postwrite_bucket_change_and_midcall_expiry_cannot_return_verified_receipts(self):
        calls = 0

        def change_second(observed):
            nonlocal calls
            calls += 1
            return observed if calls == 1 else replace(observed, retention_policy_locked=False)

        self.transport.bucket_transform = change_second
        with self.assertRaises(GCSCatalogError):
            self._put()
        self.assertEqual(self.transport.applied_writes, 1)
        self.assertFalse(self.provider._confirmed)
        self.transport.bucket_transform = None
        self.transport.after_read = lambda: setattr(self, "now", NOW + timedelta(hours=2))
        with self.assertRaises(GCSCatalogError):
            self._put()
        self.assertFalse(self.provider._confirmed)

    def test_native_sources_aliases_subclasses_and_late_mutation_fail_before_hooks(self):
        class Text(str):
            def __eq__(self, other):
                return True

        class Number(int):
            pass

        class Request(CatalogObjectPutRequest):
            pass

        for request in (
            Request("request.subclass", self.descriptor, PAYLOAD),
            CatalogObjectPutRequest("request.alias", self.descriptor, PAYLOAD),
        ):
            if type(request) is CatalogObjectPutRequest:
                object.__setattr__(request, "request_id", Text("request.alias"))
            with self.subTest(request=type(request)), self.assertRaises(GCSCatalogError):
                self.provider.put_sha256_object(request)
        for name, value in (
            ("size_bytes", True),
            ("size_bytes", float(len(PAYLOAD))),
            ("size_bytes", Number(len(PAYLOAD))),
            ("namespace_id", Text("namespace.foreign")),
        ):
            descriptor = copy.deepcopy(self.descriptor)
            request = CatalogObjectPutRequest("request.late", descriptor, PAYLOAD)
            object.__setattr__(descriptor, name, value)
            with self.subTest(name=name, value=value), self.assertRaises(GCSCatalogError):
                self.provider.put_sha256_object(request)
        oversized = CatalogObjectPutRequest("request.large", self.descriptor, PAYLOAD)
        object.__setattr__(oversized, "payload", b"x" * (MAXIMUM_OBJECT_BYTES + 1))
        with patch.object(catalog, "_digest", side_effect=AssertionError("hash before bound")):
            with self.assertRaises(GCSCatalogError):
                self.provider.put_sha256_object(oversized)
        self.assertFalse(self.transport.calls)

    def test_profile_ownership_hash_binding_and_detached_exports(self):
        before = self.profile.to_dict()
        exported = self.profile.to_dict()
        exported["catalog"]["account_reference"] = "account.foreign"
        exported["effects"]["qualification"] = "allowed"
        self.assertEqual(self.profile.to_dict(), before)
        self.assertIsNot(self.provider._profile, self.profile)
        self.assertIsNot(self.provider._profile.catalog, self.profile.catalog)
        object.__setattr__(self.profile, "simulation_use_until", "2026-09-20T03:00:00Z")
        with self.assertRaises(GCSCatalogError):
            self.profile.to_dict()
        self.assertEqual(self._put().write_status, "created")
        object.__setattr__(self.provider._profile, "simulation_use_until", "2026-09-20T03:00:00Z")
        with self.assertRaises(GCSCatalogError):
            self._read()

    def test_observation_native_aliases_and_late_mutation_are_reconstructed(self):
        self._put()
        for name, value in (("is_current", 1), ("observed_at", NOW.isoformat()), ("generation", 1)):

            def mutate(observed, name=name, value=value):
                object.__setattr__(observed, name, value)
                return observed

            self.transport.metadata_transform = mutate
            with self.subTest(name=name), self.assertRaises(GCSCatalogError):
                self._read()
        self.transport.metadata_transform = None

        def corrupt(result):
            object.__setattr__(result.observation.descriptor, "sha256", "sha256:" + "0" * 64)
            return result

        self.transport.read_transform = corrupt
        with self.assertRaises(GCSCatalogError):
            self._read()

    def test_exact_object_capacity_and_confirmed_identity_limit_are_bounded(self):
        payload = b"x" * MAXIMUM_OBJECT_BYTES
        descriptor = replace(self.descriptor, sha256=_digest(payload), size_bytes=len(payload))
        self.assertEqual(self._put(descriptor=descriptor, payload=payload).write_status, "created")
        self.assertEqual(len(self._read(digest=descriptor.sha256).payload), MAXIMUM_OBJECT_BYTES)
        source = replace(self.profile)
        provider = GCSImmutableCatalogObjectProvider(self.transport, source, clock=lambda: NOW)
        provider._confirmed = {
            f"catalog.witness.{index}": self._stored().observation
            for index in range(MAXIMUM_CONFIRMED_OBJECTS)
        }
        calls = len(self.transport.calls)
        with self.assertRaises(GCSCatalogError):
            provider.read_sha256_object(
                CatalogObjectReadRequest("request.capacity", "catalog.new", descriptor.sha256)
            )
        self.assertEqual(len(self.transport.calls), calls)

    def test_clock_profile_modes_missing_backend_and_early_identifier_bounds_fail(self):
        for now in (
            None,
            NOW.replace(tzinfo=None),
            NOW.astimezone(timezone(timedelta(hours=1))),
            NOW - timedelta(seconds=1),
        ):
            with self.subTest(now=now), self.assertRaises(GCSCatalogError):
                GCSImmutableCatalogObjectProvider(
                    self.transport, self.profile, clock=lambda now=now: now
                )
        for changes in (
            {"simulation_use_until": "2026-09-20T00:00:00Z"},
            {"retention_period_seconds": True},
            {"retention_period_seconds": 7199},
            {"retention_period_seconds": 3_155_760_001},
        ):
            with self.subTest(changes=changes), self.assertRaises(GCSCatalogError):
                replace(self.profile, **changes)
        with self.assertRaises(TypeError):
            GCSImmutableCatalogObjectProvider()
        with self.assertRaises(GCSCatalogError):
            GCSImmutableCatalogObjectProvider(object(), self.profile, clock=lambda: NOW)
        descriptor = replace(self.descriptor, object_id="x" * 129)
        with self.assertRaises(GCSCatalogError):
            self._put(descriptor=descriptor)
        self.assertFalse(self.transport.calls)

    def test_caller_and_receipt_mutation_cannot_change_confirmed_sources(self):
        receipt = self._put()
        object.__setattr__(self.descriptor, "namespace_id", "namespace.foreign")
        object.__setattr__(receipt.object, "sha256", "sha256:" + "0" * 64)
        request = CatalogObjectReadRequest("request.owned", "catalog.release.1", _digest(PAYLOAD))
        self.assertEqual(self.provider.read_sha256_object(request).payload, PAYLOAD)
        with self.assertRaises(FrozenInstanceError):
            self.profile.retention_period_seconds = 1

    def test_no_sdk_default_backend_runtime_authentication_or_file_operations(self):
        tree = ast.parse(inspect.getsource(catalog))
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
            imported
            & {"google", "requests", "urllib", "http", "socket", "subprocess", "os", "pathlib"}
        )
        forbidden = {
            "open",
            "read_bytes",
            "write_bytes",
            "read_text",
            "write_text",
            "connect",
            "execute",
            "sign",
            "verify_principal_assertion",
        }
        self.assertFalse(
            any(
                isinstance(node, ast.Call)
                and (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in forbidden
                    or isinstance(node.func, ast.Name)
                    and node.func.id in forbidden
                )
                for node in ast.walk(tree)
            )
        )
        self.assertEqual(set(self.profile.to_dict()["effects"].values()), {"none"})
        self.assertFalse(hasattr(self.provider, "append_audit_event"))
        self.assertFalse(hasattr(self.provider, "put_quarantined"))
        self.assertFalse(hasattr(self.provider, "delete_object"))
        for path in (
            ROOT / "src/sunderkey/gcp_gcs_catalog.py",
            ROOT / "tests/agents/test_gcp_gcs_catalog.py",
            ROOT / "docs/gcp-gcs-catalog-offline.md",
        ):
            self.assertTrue(path.read_bytes().isascii(), path)


class ThreeMappedCatalogFactory(GCSMappedReferenceFactory):
    def create_bundle(self, case_id, fault_injector):
        bundle = super().create_bundle(case_id, fault_injector)
        profile = _profile(
            bundle.catalog_object.namespace_id,
            bundle.catalog_object.failure_domain_id,
            bundle.ledger_object.namespace_id,
            bundle.ledger_object.failure_domain_id,
        )
        transport = SyntheticCatalogTransport(profile, fault_injector)
        result = replace(
            bundle,
            provider_descriptor={
                **bundle.provider_descriptor,
                "adapter_id": "gcs_mapped_three_port_reference_composite",
                "build_sha256": _canonical_sha256({"fixture": "gcs_three_port_reference_v1"}),
                "configuration_sha256": _canonical_sha256(
                    {
                        "prior": bundle.provider_descriptor["configuration_sha256"],
                        "catalog": asdict(profile),
                    }
                ),
            },
            catalog_objects=GCSImmutableCatalogObjectProvider(
                transport, profile, clock=lambda: NOW
            ),
        )
        self.bundles[-1] = result
        return result


class GCSCatalogConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        reference.ProductionCustodyConformancePhase185Tests.setUpClass()

    def test_unchanged_twelve_cases_compose_three_mapped_and_five_reference_ports(self):
        fixture = reference.ProductionCustodyConformancePhase185Tests
        adapters = ThreeMappedCatalogFactory(
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
        self.assertEqual(report.environment_class, ENVIRONMENT_CLASS)
        self.assertEqual(
            tuple(item.case_id for item in report.case_observations),
            tuple(item.case_id for item in CASE_DEFINITIONS),
        )
        self.assertEqual(len(report.case_observations), 12)
        self.assertTrue(all(item.outcome == "pass" for item in report.case_observations))
        self.assertTrue(report.to_dict()["independent_review_required"])
        for name in (
            "provider_selection_effect",
            "qualification_effect",
            "deployment_effect",
            "catalog_publication_effect",
            "enrollment_effect",
            "runtime_effect",
        ):
            self.assertEqual(report.to_dict()[name], "none")
        for bundle in adapters.bundles:
            self.assertIs(type(bundle.catalog_objects), GCSImmutableCatalogObjectProvider)
            self.assertIs(type(bundle.ledger_objects), GCSRetentionLockedLedgerObjectProvider)
            self.assertIs(type(bundle.ledger_heads), GCSConditionalLedgerHeadProvider)
            self.assertIs(type(bundle.release_signer), reference.InMemorySigner)
            self.assertIs(type(bundle.release_verifier), reference.InMemoryVerifier)
            self.assertIs(type(bundle.release_audit), reference.InMemoryAuditSink)
            self.assertIs(type(bundle.workload_identity), reference.InMemoryWorkloadIdentity)
            self.assertIs(type(bundle.checkpoint_access), reference.InMemoryCheckpointAccess)


if __name__ == "__main__":
    unittest.main()

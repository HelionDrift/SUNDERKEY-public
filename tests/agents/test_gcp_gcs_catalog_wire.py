"""Supplied local bytes exercise catalog wire syntax, never cloud access."""

from __future__ import annotations

import ast
import copy
import inspect
import json
import unittest
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import sunderkey.gcp_gcs_catalog_wire as wire
import sunderkey.gcp_gcs_wire as common
from sunderkey.candidate_enrollment_production_custody_contract import (
    CatalogObjectDescriptor,
    CatalogObjectPutRequest,
    CatalogObjectReadRequest,
    ProviderPolicyRejection,
)
from sunderkey.gcp_gcs_catalog import (
    ENVIRONMENT_CLASS,
    GCSCatalogBucketObservation,
    GCSCatalogError,
    GCSCatalogReadRequest,
    GCSCatalogWriteRequest,
    GCSImmutableCatalogObjectProvider,
)
from sunderkey.gcp_gcs_custody import GCSAmbiguousWrite, GCSPreconditionFailed
from sunderkey.qualification import _canonical_json
from tests.agents import test_gcp_gcs_catalog as reference

ROOT = Path(__file__).resolve().parents[2]


def encoded(value):
    return json.dumps(value, ensure_ascii=True).encode("ascii")


def bucket_response(profile):
    return {
        "name": profile.catalog.bucket,
        "metageneration": "7",
        "versioning": {"enabled": False},
        "retentionPolicy": {
            "retentionPeriod": str(profile.retention_period_seconds),
            "isLocked": True,
        },
        "defaultEventBasedHold": False,
    }


def object_response(observed, payload):
    return {
        "bucket": observed.bucket,
        "name": observed.object_name,
        "generation": observed.generation,
        "metageneration": observed.metageneration,
        "size": str(observed.descriptor.size_bytes),
        "contentType": "application/octet-stream",
        "crc32c": common.crc32c_base64(payload),
        "temporaryHold": False,
        "eventBasedHold": False,
        "retentionExpirationTime": observed.retention_until,
        "metadata": {wire.DESCRIPTOR_METADATA_KEY: _canonical_json(asdict(observed.descriptor))},
    }


class SyntheticRawCatalogBridge:
    """Only test state supplies absence, caller labels and a fixed UTC clock."""

    environment_class = ENVIRONMENT_CLASS

    def __init__(self, profile):
        self.profile = copy.deepcopy(profile)
        self.state = reference.SyntheticCatalogTransport(profile)
        self.descriptions = []

    def read_bucket(self, bucket, *, observed_at):
        if bucket != self.profile.catalog.bucket:
            raise AssertionError("Synthetic bucket mismatch")
        description = wire.describe_catalog_bucket_lookup(self.profile, observed_at=observed_at)
        self.descriptions.append(description)
        facts = wire.parse_catalog_bucket_response(
            description, 200, encoded(bucket_response(self.profile))
        )
        # This fixture supplies declarations and time. The codec does not observe them.
        return GCSCatalogBucketObservation(
            self.profile.catalog,
            observed_at,
            True,
            facts.versioning_enabled,
            facts.retention_policy_locked,
            facts.retention_period_seconds,
            facts.default_event_based_hold,
            facts.object_retention_configuration_present,
        )

    def read_object_metadata(self, bucket, name, *, observed_at):
        observed = self.state.read_object_metadata(bucket, name, observed_at=observed_at)
        if observed is None:
            return None  # Explicit synthetic absence, not an interpretation of HTTP 404.
        description = wire.describe_catalog_live_metadata(
            self.profile, name, observed_at=observed_at
        )
        self.descriptions.append(description)
        payload = self.state.objects[(bucket, name)].payload
        return wire.parse_catalog_object_response(
            description, 200, encoded(object_response(observed, payload))
        ).observation

    def read_object(self, request):
        result = self.state.read_object(request)
        observation = wire.GCSCatalogWireObjectObservation(
            result.observation, common.crc32c_base64(result.payload)
        )
        description = wire.describe_catalog_pinned_media_read(
            self.profile, request, observation=observation
        )
        self.descriptions.append(description)
        return wire.parse_catalog_media_response(description, 200, result.payload)

    def write_object(self, request):
        description = wire.describe_catalog_create_only_write(self.profile, request)
        self.descriptions.append(description)
        try:
            observed = self.state.write_object(request)
        except GCSPreconditionFailed:
            return wire.parse_catalog_object_response(description, 412, b"{}").observation
        return wire.parse_catalog_object_response(
            description, 200, encoded(object_response(observed, request.payload))
        ).observation


class GCSCatalogWireTests(unittest.TestCase):
    def setUp(self):
        self.profile = reference._profile()
        self.now = reference.NOW.replace(microsecond=123456, fold=1)
        self.payload = b"\x00catalog-binary\xff\r\n"
        self.descriptor = CatalogObjectDescriptor(
            "catalog:release.1",
            reference._digest(self.payload),
            len(self.payload),
            self.profile.catalog.namespace_id,
            self.profile.catalog.failure_domain_id,
        )
        self.name = "catalog/" + self.descriptor.object_id
        self.write = GCSCatalogWriteRequest(
            "request.create",
            self.profile.catalog.bucket,
            self.name,
            self.descriptor,
            self.payload,
            self.now,
        )
        state = reference.SyntheticCatalogTransport(self.profile)
        self.observed = state.write_object(self.write)
        self.observation = wire.GCSCatalogWireObjectObservation(
            self.observed, common.crc32c_base64(self.payload)
        )
        self.read = GCSCatalogReadRequest(
            self.observed.bucket,
            self.name,
            self.observed.generation,
            self.observed.metageneration,
            self.descriptor,
            self.now,
        )

    def description(self):
        return wire.describe_catalog_live_metadata(self.profile, self.name, observed_at=self.now)

    def test_fixed_origin_encoding_and_live_conditions_without_revision_selector(self):
        metadata = self.description()
        split = urlsplit(metadata.url)
        self.assertEqual(split.netloc, "storage.googleapis.com")
        self.assertTrue(split.path.endswith("/o/catalog%2Fcatalog%3Arelease.1"))
        query = parse_qs(split.query)
        self.assertEqual(query["fields"], [wire.OBJECT_FIELDS])
        self.assertEqual(query["projection"], ["noAcl"])
        self.assertNotIn("generation", query)
        pinned = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=self.observation
        )
        self.assertEqual(
            parse_qs(urlsplit(pinned.url).query),
            {
                "alt": ["media"],
                "ifGenerationMatch": [self.read.generation],
                "ifMetagenerationMatch": [self.read.metageneration],
            },
        )
        self.assertNotIn("Range", dict(pinned.headers))
        self.assertEqual(dict(pinned.headers)["Accept-Encoding"], "identity")
        self.assertEqual(pinned.environment_class, ENVIRONMENT_CLASS)

    def test_exact_time_microseconds_and_fold_survive_capture_and_response(self):
        description = self.description()
        source = json.loads(description.source_json)
        self.assertEqual(source["observed_at"]["microsecond"], 123456)
        self.assertEqual(source["observed_at"]["fold"], 1)
        observed = wire.parse_catalog_object_response(
            description, 200, encoded(object_response(self.observed, self.payload))
        ).observation
        self.assertEqual(observed.observed_at, self.now)
        self.assertEqual(observed.observed_at.microsecond, 123456)
        self.assertEqual(observed.observed_at.fold, 1)

    def test_deterministic_create_only_multipart_preserves_descriptor_and_raw_bytes(self):
        description = wire.describe_catalog_create_only_write(self.profile, self.write)
        self.assertEqual(
            description, wire.describe_catalog_create_only_write(self.profile, self.write)
        )
        query = parse_qs(urlsplit(description.url).query)
        self.assertEqual(query["ifGenerationMatch"], ["0"])
        self.assertNotIn("ifMetagenerationMatch", query)
        headers = dict(description.headers)
        self.assertNotIn("Authorization", headers)
        self.assertEqual(int(headers["Content-Length"]), len(description.body))
        boundary = headers["Content-Type"].split("boundary=", 1)[1].encode("ascii")
        pieces = description.body.split(b"--" + boundary)
        self.assertEqual(len(pieces), 4)
        metadata = json.loads(pieces[1].split(b"\r\n\r\n", 1)[1].removesuffix(b"\r\n"))
        self.assertEqual(
            metadata["metadata"],
            {wire.DESCRIPTOR_METADATA_KEY: _canonical_json(asdict(self.descriptor))},
        )
        self.assertEqual(pieces[2].split(b"\r\n\r\n", 1)[1], self.payload + b"\r\n")
        self.assertEqual(pieces[3], b"--\r\n")

    def test_bucket_facts_have_no_inferred_domain_account_or_observation_time(self):
        description = wire.describe_catalog_bucket_lookup(self.profile, observed_at=self.now)
        facts = wire.parse_catalog_bucket_response(
            description, 200, encoded(bucket_response(self.profile))
        )
        self.assertEqual(facts.retention_period_seconds, self.profile.retention_period_seconds)
        self.assertIs(facts.object_retention_configuration_present, False)
        for name in (
            "namespace_id",
            "failure_domain_id",
            "account_reference",
            "observed_at",
            "is_current",
        ):
            self.assertNotIn(name, asdict(facts))

    def test_explicit_false_bucket_facts_retention_and_supported_provider_endpoints(self):
        description = wire.describe_catalog_bucket_lookup(self.profile, observed_at=self.now)
        base = bucket_response(self.profile)
        mutations = (
            {"versioning": {"enabled": True}},
            {"versioning": {"enabled": 0}},
            {"defaultEventBasedHold": True},
            {"defaultEventBasedHold": 0},
            {"objectRetention": {"mode": "Enabled"}},
            {"softDeleteTime": None},
            {"retentionPolicy": {"retentionPeriod": "86400", "isLocked": 1}},
            {"retentionPolicy": {"retentionPeriod": 86400, "isLocked": True}},
            {"retentionPolicy": {"retentionPeriod": "086400", "isLocked": True}},
            {"metageneration": "0"},
            {"name": "foreign-bucket"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_bucket_response(description, 200, encoded(base | mutation))
        for name in ("versioning", "defaultEventBasedHold", "retentionPolicy"):
            raw = copy.deepcopy(base)
            del raw[name]
            with self.subTest(missing=name), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_bucket_response(description, 200, encoded(raw))
        profile = replace(
            self.profile, retention_period_seconds=wire.MAXIMUM_PROVIDER_RETENTION_SECONDS
        )
        description = wire.describe_catalog_bucket_lookup(profile, observed_at=self.now)
        self.assertEqual(
            wire.parse_catalog_bucket_response(
                description, 200, encoded(bucket_response(profile))
            ).retention_period_seconds,
            wire.MAXIMUM_PROVIDER_RETENTION_SECONDS,
        )
        unsupported = replace(self.profile, retention_period_seconds=3_155_760_000)
        with self.assertRaisesRegex(wire.GCSCatalogWireError, "provider wire subset"):
            wire.describe_catalog_bucket_lookup(unsupported, observed_at=self.now)
        self.assertEqual(unsupported.retention_period_seconds, 3_155_760_000)

    def test_object_fields_require_no_holds_no_deleted_modes_and_fixed_horizon(self):
        description = self.description()
        base = object_response(self.observed, self.payload)
        for mutation in (
            {"temporaryHold": True},
            {"eventBasedHold": 0},
            {"retention": {"mode": "Locked"}},
            {"contentEncoding": "gzip"},
            {"contentEncoding": None},
            {"contentType": "application/json"},
            {"timeDeleted": None},
            {"softDeleteTime": None},
            {"hardDeleteTime": None},
            {"retentionExpirationTime": "2026-09-20T01:59:59Z"},
            {"retentionExpirationTime": "2026-09-21T00:00:00.001Z"},
            {"bucket": "foreign-bucket"},
            {"name": "catalog/foreign"},
            {"generation": "01"},
            {"metageneration": True},
            {"size": len(self.payload)},
            {"size": "0"},
            {"crc32c": "bad"},
            {"crc32c": None},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, 200, encoded(base | mutation))
        for name in ("temporaryHold", "eventBasedHold", "retentionExpirationTime", "metadata"):
            raw = copy.deepcopy(base)
            del raw[name]
            with self.subTest(missing=name), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, 200, encoded(raw))
        raw = base | {"retentionExpirationTime": reference.USE_UNTIL}
        self.assertEqual(
            wire.parse_catalog_object_response(
                description, 200, encoded(raw)
            ).observation.retention_until,
            reference.USE_UNTIL,
        )
        for encoding in ({}, {"contentEncoding": "identity"}):
            with self.subTest(encoding=encoding):
                returned = wire.parse_catalog_object_response(
                    description, 200, encoded(base | encoding)
                )
                self.assertEqual(returned.crc32c, common.crc32c_base64(self.payload))
                omitted = base | encoding
                del omitted["crc32c"]
                self.assertIsNone(
                    wire.parse_catalog_object_response(description, 200, encoded(omitted)).crc32c
                )

    def test_descriptor_canonical_five_fields_labels_and_bytes_are_required(self):
        description = self.description()
        base = object_response(self.observed, self.payload)
        for text in (
            json.dumps(asdict(self.descriptor)),
            _canonical_json(asdict(self.descriptor) | {"namespace_id": "namespace.foreign"}),
            _canonical_json(asdict(self.descriptor) | {"failure_domain_id": "failure.foreign"}),
            _canonical_json(asdict(self.descriptor) | {"object_id": "catalog.foreign"}),
            _canonical_json(asdict(self.descriptor) | {"size_bytes": True}),
            _canonical_json(asdict(self.descriptor) | {"retention_until": reference.USE_UNTIL}),
            '{"object_id":"a","object_id":"b"}',
        ):
            raw = base | {"metadata": {wire.DESCRIPTOR_METADATA_KEY: text}}
            with self.subTest(text=text[:40]), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, 200, encoded(raw))
        for custom in (
            {common.DESCRIPTOR_METADATA_KEY: "{}"},
            {wire.DESCRIPTOR_METADATA_KEY: asdict(self.descriptor)},
            {},
        ):
            with self.subTest(custom=custom), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(
                    description, 200, encoded(base | {"metadata": custom})
                )

    def test_sha_size_and_optional_crc_are_independent_mandatory_content_checks(self):
        description = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=self.observation
        )
        self.assertEqual(
            wire.parse_catalog_media_response(description, 200, self.payload).payload, self.payload
        )
        for payload in (self.payload[:-1], b"x" * len(self.payload)):
            with self.subTest(payload=payload), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_media_response(description, 200, payload)
        with self.assertRaises(wire.GCSCatalogWireError):
            wire.parse_catalog_media_response(
                description, 200, self.payload, content_encoding="gzip"
            )
        no_crc = replace(self.observation, crc32c=None)
        description = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=no_crc
        )
        self.assertEqual(
            wire.parse_catalog_media_response(description, 200, self.payload).payload, self.payload
        )
        with self.assertRaises(wire.GCSCatalogWireError):
            wire.parse_catalog_media_response(description, 200, b"x" * len(self.payload))
        incorrect_crc = replace(self.observation, crc32c=common.crc32c_base64(b"other"))
        description = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=incorrect_crc
        )
        with self.assertRaises(wire.GCSCatalogWireError):
            wire.parse_catalog_media_response(description, 200, self.payload)
        raw = object_response(self.observed, self.payload)
        del raw["crc32c"]
        self.assertIsNone(
            wire.parse_catalog_object_response(self.description(), 200, encoded(raw)).crc32c
        )

    def test_create_acknowledgement_requires_exact_descriptor_and_any_reported_crc(self):
        description = wire.describe_catalog_create_only_write(self.profile, self.write)
        base = object_response(self.observed, self.payload)
        self.assertEqual(
            wire.parse_catalog_object_response(description, 200, encoded(base)), self.observation
        )
        foreign = replace(self.descriptor, sha256=reference._digest(b"x" * len(self.payload)))
        for mutation in (
            {"crc32c": common.crc32c_base64(b"foreign")},
            {"crc32c": None},
            {"contentEncoding": None},
            {"metadata": {wire.DESCRIPTOR_METADATA_KEY: _canonical_json(asdict(foreign))}},
        ):
            with self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, 200, encoded(base | mutation))
        omitted = base | {"contentEncoding": "identity"}
        del omitted["crc32c"]
        self.assertIsNone(
            wire.parse_catalog_object_response(description, 200, encoded(omitted)).crc32c
        )

    def test_conditional_statuses_no_absence_redirect_retry_or_rollback_inference(self):
        create = wire.describe_catalog_create_only_write(self.profile, self.write)
        read = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=self.observation
        )
        for description, parser in (
            (create, wire.parse_catalog_object_response),
            (read, wire.parse_catalog_media_response),
        ):
            with self.assertRaises(GCSPreconditionFailed):
                parser(description, 412, b"no body interpretation")
        for status in (201, 204, 302, 308, 400, 403, 404, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(GCSAmbiguousWrite):
                wire.parse_catalog_object_response(create, status, b"{}")
        for status in (206, 302, 404, 412, 503):
            with self.subTest(status=status), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(self.description(), status, b"{}")
        with self.assertRaises(wire.GCSCatalogWireError):
            wire.parse_catalog_media_response(read, 206, self.payload)

    def test_duplicate_numbers_unicode_arrays_depth_and_raw_byte_bounds_reject(self):
        description = wire.describe_catalog_bucket_lookup(self.profile, observed_at=self.now)
        for raw in (
            b'{"name":"a","na\\u006de":"b"}',
            b'{"a":1.0}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":9223372036854775808}',
            b'{"a":[]}',
            b'{"a":"\\u00e9"}',
            b'{"a":' + b'{"x":' * 10 + b"0" + b"}" * 10 + b"}",
        ):
            with self.subTest(raw=raw[:40]), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_bucket_response(description, 200, raw)
        with patch.object(wire, "_decode", wraps=wire._decode) as decoder:
            with self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_bucket_response(
                    description, 200, b"x" * (wire.MAXIMUM_JSON_BYTES + 1)
                )
            self.assertEqual(decoder.call_count, 1)  # Replayed source only, not oversized response.

    def test_description_sources_mutation_and_endpoint_substitution_precede_status(self):
        description = wire.describe_catalog_create_only_write(self.profile, self.write)
        for field, value in (
            ("method", "GET"),
            ("url", "https://example.invalid"),
            ("headers", (("Authorization", "forbidden"),)),
            ("body", b"substituted"),
            ("payload", b"different"),
            ("operation", "conditional_write"),
        ):
            altered = copy.deepcopy(description)
            object.__setattr__(altered, field, value)
            with self.subTest(field=field), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(altered, 412, b"{}")
        source = json.loads(description.source_json)
        source["profile"]["catalog"]["account_reference"] = "account.substituted"
        altered = copy.deepcopy(description)
        object.__setattr__(altered, "source_json", _canonical_json(source))
        with self.assertRaises(wire.GCSCatalogWireError):
            wire.parse_catalog_object_response(altered, 412, b"{}")

    def test_missing_description_and_observation_fields_reject_before_status(self):
        for field in ("source_json", "operation", "body", "headers"):
            altered = copy.deepcopy(self.description())
            object.__delattr__(altered, field)
            with self.subTest(field=field), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(altered, 404, b"not JSON")
        for field in ("observation", "crc32c"):
            altered = copy.deepcopy(self.observation)
            object.__delattr__(altered, field)
            with self.subTest(field=field), self.assertRaises(wire.GCSCatalogWireError):
                wire.describe_catalog_pinned_media_read(
                    self.profile, self.read, observation=altered
                )

    def test_nonnative_families_fail_before_field_access_hooks(self):
        hooks = []

        def unsafe_family(family):
            class Alternate(family):
                def __getattribute__(self, name):
                    hooks.append(name)
                    raise AssertionError("Nonnative fields must not be read")

            return object.__new__(Alternate)

        for call in (
            lambda: wire.describe_catalog_bucket_lookup(
                unsafe_family(type(self.profile)), observed_at=self.now
            ),
            lambda: wire.describe_catalog_create_only_write(
                self.profile, unsafe_family(GCSCatalogWriteRequest)
            ),
            lambda: wire.describe_catalog_pinned_media_read(
                self.profile, unsafe_family(GCSCatalogReadRequest), observation=self.observation
            ),
            lambda: wire.describe_catalog_pinned_media_read(
                self.profile,
                self.read,
                observation=unsafe_family(wire.GCSCatalogWireObjectObservation),
            ),
            lambda: wire.parse_catalog_object_response(
                unsafe_family(wire.GCSCatalogWireRequest), 200, b"{}"
            ),
        ):
            with self.assertRaises(GCSCatalogError):
                call()
        self.assertEqual(hooks, [])

    def test_captured_time_native_components_have_early_calendar_bounds(self):
        original = self.description()
        for name, value in (
            ("year", 2**63 - 1),
            ("year", 0),
            ("month", 13),
            ("day", 32),
            ("hour", 24),
            ("minute", 60),
            ("second", 60),
            ("microsecond", 1_000_000),
            ("fold", True),
            ("fold", 2),
        ):
            altered = copy.deepcopy(original)
            source = json.loads(original.source_json)
            source["observed_at"][name] = value
            object.__setattr__(altered, "source_json", _canonical_json(source))
            with self.subTest(name=name, value=value), self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(altered, 412, b"not JSON")
        with self.assertRaises(GCSCatalogError):
            wire.describe_catalog_bucket_lookup(
                self.profile, observed_at=self.now.replace(tzinfo=None)
            )

    def test_frozen_source_is_detached_from_original_request_profile_and_observation(self):
        original_write = copy.deepcopy(self.write)
        profile = copy.deepcopy(self.profile)
        description = wire.describe_catalog_create_only_write(profile, original_write)
        object.__setattr__(original_write, "payload", b"changed")
        object.__setattr__(original_write.descriptor, "namespace_id", "namespace.changed")
        object.__setattr__(profile.catalog, "account_reference", "account.changed")
        self.assertEqual(
            wire.parse_catalog_object_response(
                description, 200, encoded(object_response(self.observed, self.payload))
            ),
            self.observation,
        )
        observation = copy.deepcopy(self.observation)
        pinned = wire.describe_catalog_pinned_media_read(
            self.profile, self.read, observation=observation
        )
        object.__setattr__(observation.observation.descriptor, "sha256", "sha256:" + "0" * 64)
        self.assertEqual(
            wire.parse_catalog_media_response(pinned, 200, self.payload).payload, self.payload
        )

    def test_native_aliases_status_bytes_and_subclasses_fail_before_hooks(self):
        hooks = []

        class Alias(str):
            def __eq__(self, other):
                hooks.append("eq")
                return True

        class DateTimeSubclass(datetime):
            pass

        for field, value in (
            ("request_id", Alias("request.alias")),
            ("if_generation_match", Alias("0")),
        ):
            request = copy.deepcopy(self.write)
            object.__setattr__(request, field, value)
            with self.subTest(field=field), self.assertRaises(GCSCatalogError):
                wire.describe_catalog_create_only_write(self.profile, request)
        with self.assertRaises(GCSCatalogError):
            wire.describe_catalog_bucket_lookup(
                self.profile, observed_at=DateTimeSubclass(2026, 9, 20, tzinfo=UTC)
            )
        description = self.description()
        raw = encoded(object_response(self.observed, self.payload))
        for status in (True, 200.0, "200"):
            with self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, status, raw)
        for value in (bytearray(raw), memoryview(raw), raw.decode("ascii")):
            with self.assertRaises(wire.GCSCatalogWireError):
                wire.parse_catalog_object_response(description, 200, value)
        self.assertEqual(hooks, [])

    def test_pinned_substitutions_and_inactive_window_fail_without_provider_calls(self):
        for changes in (
            {"generation": "999"},
            {"metageneration": "999"},
            {"observed_at": self.now + timedelta(microseconds=1)},
        ):
            observation = wire.GCSCatalogWireObjectObservation(
                replace(self.observed, **changes), self.observation.crc32c
            )
            with self.subTest(changes=changes), self.assertRaises(wire.GCSCatalogWireError):
                wire.describe_catalog_pinned_media_read(
                    self.profile, self.read, observation=observation
                )
        for at in (reference.NOW - timedelta(microseconds=1), reference.NOW + timedelta(hours=2)):
            with self.assertRaises(wire.GCSCatalogWireError):
                wire.describe_catalog_bucket_lookup(self.profile, observed_at=at)
        request = copy.deepcopy(self.write)
        object.__setattr__(request, "if_generation_match", "1")
        with self.assertRaises(GCSCatalogError):
            wire.describe_catalog_create_only_write(self.profile, request)

    def test_exact_payload_capacity_oversize_aggregate_and_boundary_collision(self):
        payload = b"x" * wire.MAXIMUM_OBJECT_BYTES
        descriptor = replace(
            self.descriptor, sha256=reference._digest(payload), size_bytes=len(payload)
        )
        request = replace(self.write, descriptor=descriptor, payload=payload)
        description = wire.describe_catalog_create_only_write(self.profile, request)
        self.assertEqual(len(description.payload), wire.MAXIMUM_OBJECT_BYTES)
        object.__setattr__(request, "payload", payload + b"x")
        with (
            patch.object(
                common, "crc32c_base64", side_effect=AssertionError("bound before checksum")
            ),
            self.assertRaises(GCSCatalogError),
        ):
            wire.describe_catalog_create_only_write(self.profile, request)
        graph = {"a": "x" * 8192, "b": "x" * 8192, "c": "x" * 8192}
        with patch.object(common, "_canonical_json") as serialize:
            with self.assertRaises(wire.GCSCatalogWireError):
                wire._json(graph)
            serialize.assert_not_called()
        collision = b"--sunderkey_gcs_catalog_" + b"0" * 64
        descriptor = replace(
            self.descriptor, sha256=reference._digest(collision), size_bytes=len(collision)
        )
        request = replace(self.write, descriptor=descriptor, payload=collision)
        normal = wire.describe_catalog_create_only_write(self.profile, request)
        real_digest = wire.hashlib.sha256
        boundary_material = normal.source_json.encode("ascii") + real_digest(collision).digest()

        class BoundaryDigest:
            def hexdigest(self):
                return "0" * 64

        def selective_digest(data):
            return BoundaryDigest() if data == boundary_material else real_digest(data)

        with (
            patch.object(wire.hashlib, "sha256", side_effect=selective_digest),
            self.assertRaisesRegex(wire.GCSCatalogWireError, "boundary"),
        ):
            wire.describe_catalog_create_only_write(self.profile, request)

    def test_raw_byte_bridge_composes_real_catalog_create_replay_read_and_collision(self):
        bridge = SyntheticRawCatalogBridge(self.profile)
        provider = GCSImmutableCatalogObjectProvider(bridge, self.profile, clock=lambda: self.now)
        request = CatalogObjectPutRequest("request.create", self.descriptor, self.payload)
        self.assertEqual(provider.put_sha256_object(request).write_status, "created")
        self.assertEqual(
            provider.put_sha256_object(request).write_status, "already_present_same_digest"
        )
        self.assertEqual(
            provider.read_sha256_object(
                CatalogObjectReadRequest(
                    "request.read", self.descriptor.object_id, self.descriptor.sha256
                )
            ).payload,
            self.payload,
        )
        foreign = b"truthful conflicting bytes"
        descriptor = replace(
            self.descriptor, sha256=reference._digest(foreign), size_bytes=len(foreign)
        )
        with self.assertRaises(ProviderPolicyRejection) as raised:
            provider.put_sha256_object(
                CatalogObjectPutRequest("request.conflict", descriptor, foreign)
            )
        self.assertEqual(raised.exception.rejection_code, "immutable_catalog_overwrite")
        self.assertEqual(raised.exception.request_id, "request.conflict")
        self.assertEqual(bridge.state.applied_writes, 1)
        self.assertEqual({row.operation for row in bridge.descriptions}, wire._OPERATIONS)

    def test_raw_byte_bridge_genuine_create_races_and_lost_ack_do_not_retry(self):
        for matching in (False, True):
            with self.subTest(matching=matching):
                bridge = SyntheticRawCatalogBridge(self.profile)
                provider = GCSImmutableCatalogObjectProvider(
                    bridge, self.profile, clock=lambda: self.now
                )

                def race(delivered, *, matching=matching, bridge=bridge):
                    payload = delivered.payload if matching else b"foreign bytes"
                    descriptor = replace(
                        delivered.descriptor,
                        sha256=reference._digest(payload),
                        size_bytes=len(payload),
                    )
                    bridge.state.write_object(
                        replace(
                            delivered,
                            request_id="request.winner",
                            descriptor=descriptor,
                            payload=payload,
                        )
                    )

                bridge.state.before_write = race
                request = CatalogObjectPutRequest("request.race", self.descriptor, self.payload)
                if matching:
                    self.assertEqual(
                        provider.put_sha256_object(request).write_status,
                        "already_present_same_digest",
                    )
                else:
                    with self.assertRaises(ProviderPolicyRejection):
                        provider.put_sha256_object(request)
                self.assertEqual(len(bridge.state.write_attempts), 2)
                self.assertEqual(bridge.state.applied_writes, 1)
        bridge = SyntheticRawCatalogBridge(self.profile)
        provider = GCSImmutableCatalogObjectProvider(bridge, self.profile, clock=lambda: self.now)
        bridge.state.ambiguous = "after"
        request = CatalogObjectPutRequest("request.uncertain", self.descriptor, self.payload)
        with self.assertRaises(GCSCatalogError):
            provider.put_sha256_object(request)
        self.assertEqual(bridge.state.applied_writes, 1)
        self.assertEqual(len(bridge.state.write_attempts), 1)

    def test_module_is_inert_ascii_and_has_no_execution_or_default_transport(self):
        tree = ast.parse(inspect.getsource(wire))
        imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        imported |= {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertFalse(
            imported
            & {
                "requests",
                "httpx",
                "socket",
                "urllib.request",
                "google.cloud.storage",
                "os",
                "subprocess",
                "pathlib",
            }
        )
        self.assertFalse(hasattr(wire.GCSCatalogWireRequest, "send"))
        self.assertFalse(hasattr(wire, "transport"))
        for path in (
            "src/sunderkey/gcp_gcs_catalog_wire.py",
            "tests/agents/test_gcp_gcs_catalog_wire.py",
            "docs/gcp-gcs-catalog-wire-offline.md",
        ):
            self.assertTrue((ROOT / path).read_bytes().isascii(), path)


if __name__ == "__main__":
    unittest.main()

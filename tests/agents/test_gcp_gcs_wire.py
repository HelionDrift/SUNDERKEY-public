"""Synthetic raw bytes exercise an inert GCS codec, never an HTTP client."""

from __future__ import annotations

import ast
import copy
import inspect
import json
import unittest
from dataclasses import asdict, replace
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import sunderkey.gcp_gcs_wire as wire
from sunderkey.candidate_enrollment_production_custody_contract import (
    LedgerHeadCompareAndSwapRequest,
    LedgerHeadDescriptor,
    LedgerHeadReadRequest,
    LedgerObjectDescriptor,
    LedgerObjectPutRequest,
    LedgerObjectReadRequest,
    RetentionStateReadRequest,
)
from sunderkey.gcp_gcs_custody import (
    GCSAmbiguousWrite,
    GCSConditionalLedgerHeadProvider,
    GCSCustodyError,
    GCSObjectMetadata,
    GCSPreconditionFailed,
    GCSReadRequest,
    GCSRetentionLockedLedgerObjectProvider,
    GCSWriteRequest,
)
from sunderkey.qualification import _canonical_json
from tests.agents import test_gcp_gcs_custody as custody_test


def encoded(raw) -> bytes:
    return json.dumps(raw, ensure_ascii=True).encode("ascii")


def object_response(metadata, payload: bytes) -> dict:
    raw = {
        "bucket": metadata.bucket,
        "name": metadata.object_name,
        "generation": metadata.generation,
        "metageneration": metadata.metageneration,
        "size": str(metadata.size_bytes),
        "contentType": "application/octet-stream",
        "crc32c": wire.crc32c_base64(payload),
    }
    if metadata.retention_until is not None:
        raw["retentionExpirationTime"] = metadata.retention_until
    if metadata.ledger_object is not None:
        raw["metadata"] = {
            wire.DESCRIPTOR_METADATA_KEY: _canonical_json(asdict(metadata.ledger_object))
        }
    return raw


def bucket_response(profile) -> dict:
    raw = {"name": profile.bucket, "metageneration": "1", "versioning": {"enabled": False}}
    if profile.retention_policy_locked:
        raw["retentionPolicy"] = {
            "isLocked": True,
            "retentionPeriod": str(profile.retention_period_seconds),
        }
    return raw


class SyntheticRawByteFixture:
    """Only local deterministic object state; no provider dispatch operation exists."""

    def __init__(self, profiles):
        self.state = custody_test.DeterministicGCSTransport(profiles)
        self.profiles = {profile.bucket: profile for profile in (profiles.ledger, profiles.head)}
        self.descriptions = []

    def read_bucket_profile(self, bucket):
        profile = self.profiles[bucket]
        description = wire.describe_bucket_lookup(profile)
        self.descriptions.append(description)
        observation = wire.parse_bucket_response(
            description, 200, encoded(bucket_response(profile))
        )
        if observation.bucket != profile.bucket:
            raise AssertionError("Synthetic bucket substitution")
        return replace(profile)

    def read_object_metadata(self, bucket, name):
        metadata = self.state.read_object_metadata(bucket, name)
        if metadata is None:
            return None
        stored = self.state.objects[(bucket, name)]
        description = wire.describe_live_object_metadata(self.profiles[bucket], name)
        self.descriptions.append(description)
        return wire.parse_object_metadata_response(
            description,
            200,
            encoded(object_response(metadata, stored.payload)),
        ).metadata

    def read_object(self, request):
        stored = self.state.read_object(request)
        observation = wire.GCSWireObjectObservation(
            stored.metadata, wire.crc32c_base64(stored.payload)
        )
        description = wire.describe_pinned_media_read(
            self.profiles[request.bucket], request, observation=observation
        )
        self.descriptions.append(description)
        return wire.parse_media_response(description, 200, stored.payload)

    def write_object(self, request):
        description = wire.describe_conditional_object_write(self.profiles[request.bucket], request)
        self.descriptions.append(description)
        try:
            metadata = self.state.write_object(request)
        except GCSPreconditionFailed:
            return wire.parse_object_metadata_response(description, 412, b"{}").metadata
        return wire.parse_object_metadata_response(
            description,
            200,
            encoded(object_response(metadata, request.payload)),
        ).metadata


class GCSWireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = custody_test.profiles()
        self.payload = b"\x00synthetic-ledger\xff\r\n"
        self.descriptor = LedgerObjectDescriptor(
            "entry:synthetic",
            custody_test.digest(self.payload),
            len(self.payload),
            custody_test.RETENTION_UNTIL,
            self.profiles.ledger.namespace_id,
            self.profiles.ledger.failure_domain_id,
        )
        self.name = "ledger/" + self.descriptor.object_id
        self.metadata = GCSObjectMetadata(
            self.profiles.ledger.bucket,
            self.name,
            "7000001",
            "3",
            len(self.payload),
            self.descriptor.retention_until,
            self.descriptor,
            True,
        )
        self.observation = wire.GCSWireObjectObservation(
            self.metadata, wire.crc32c_base64(self.payload)
        )
        self.read = GCSReadRequest(self.metadata.bucket, self.name, "7000001", "3")
        self.write = GCSWriteRequest(
            "request:synthetic",
            self.metadata.bucket,
            self.name,
            self.payload,
            "0",
            None,
            self.descriptor,
        )

    def test_fixed_origin_single_component_encoding_and_narrow_fields(self) -> None:
        description = wire.describe_live_object_metadata(self.profiles.ledger, self.name)
        parsed = urlsplit(description.url)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "storage.googleapis.com")
        self.assertTrue(parsed.path.endswith("/o/ledger%2Fentry%3Asynthetic"))
        query = parse_qs(parsed.query)
        self.assertEqual(query["fields"], [wire.OBJECT_FIELDS])
        self.assertEqual(query["projection"], ["noAcl"])
        self.assertNotIn("generation", query)
        self.assertNotIn("softDeleted", query)
        self.assertEqual(description.body, b"")
        self.assertEqual(description.environment_class, "reference_simulation_nonqualifying")

    def test_pinned_media_uses_live_default_and_both_conditions_not_revision_selector(self) -> None:
        description = wire.describe_pinned_media_read(
            self.profiles.ledger, self.read, observation=self.observation
        )
        query = parse_qs(urlsplit(description.url).query)
        self.assertEqual(
            query,
            {"alt": ["media"], "ifGenerationMatch": ["7000001"], "ifMetagenerationMatch": ["3"]},
        )
        self.assertNotIn("generation", query)
        self.assertNotIn("Range", dict(description.headers))
        self.assertEqual(dict(description.headers)["Accept-Encoding"], "identity")
        receipt = wire.parse_media_response(description, 200, self.payload)
        self.assertEqual(receipt.metadata, self.metadata)
        self.assertEqual(receipt.payload, self.payload)

    def test_deterministic_multipart_preserves_exact_metadata_and_binary_payload(self) -> None:
        description = wire.describe_conditional_object_write(self.profiles.ledger, self.write)
        self.assertEqual(
            description, wire.describe_conditional_object_write(self.profiles.ledger, self.write)
        )
        self.assertEqual(description.method, "POST")
        self.assertEqual(
            urlsplit(description.url).path,
            "/upload/storage/v1/b/" + self.profiles.ledger.bucket + "/o",
        )
        query = parse_qs(urlsplit(description.url).query)
        self.assertEqual(query["ifGenerationMatch"], ["0"])
        self.assertEqual(query["uploadType"], ["multipart"])
        self.assertNotIn("ifMetagenerationMatch", query)
        headers = dict(description.headers)
        self.assertEqual(int(headers["Content-Length"]), len(description.body))
        boundary = headers["Content-Type"].split("boundary=", 1)[1].encode("ascii")
        pieces = description.body.split(b"--" + boundary)
        self.assertEqual(len(pieces), 4)
        metadata = json.loads(pieces[1].split(b"\r\n\r\n", 1)[1].removesuffix(b"\r\n"))
        self.assertEqual(metadata["name"], self.name)
        self.assertEqual(
            metadata["metadata"],
            {
                wire.DESCRIPTOR_METADATA_KEY: _canonical_json(asdict(self.descriptor)),
            },
        )
        self.assertEqual(pieces[2].split(b"\r\n\r\n", 1)[1], self.payload + b"\r\n")
        self.assertEqual(pieces[3], b"--\r\n")
        self.assertNotIn("Authorization", headers)

    def test_conditional_head_write_preserves_provider_tokens_not_logical_sequence(self) -> None:
        payload = _canonical_json(
            custody_test.head_document(
                LedgerHeadDescriptor(
                    "deployment:synthetic",
                    2,
                    "entry:next",
                    "sha256:" + "2" * 64,
                    "sha256:" + "1" * 64,
                )
            )
        ).encode("ascii")
        request = GCSWriteRequest(
            "request:head",
            self.profiles.head.bucket,
            "heads/deployment:synthetic",
            payload,
            "7000001",
            "3",
            None,
        )
        description = wire.describe_conditional_object_write(self.profiles.head, request)
        query = parse_qs(urlsplit(description.url).query)
        self.assertEqual(query["ifGenerationMatch"], ["7000001"])
        self.assertEqual(query["ifMetagenerationMatch"], ["3"])
        self.assertIn(b'"ledger_sequence":2', description.body)
        self.assertNotIn(wire.DESCRIPTOR_METADATA_KEY.encode("ascii"), description.body)

    def test_bucket_observations_are_unsigned_facts_not_namespace_authentication(self) -> None:
        for profile in (self.profiles.ledger, self.profiles.head):
            description = wire.describe_bucket_lookup(profile)
            facts = wire.parse_bucket_response(description, 200, encoded(bucket_response(profile)))
            self.assertEqual(facts.bucket, profile.bucket)
            self.assertEqual(facts.retention_period_seconds, profile.retention_period_seconds)
            self.assertNotIn("namespace_id", asdict(facts))
            self.assertNotIn("failure_domain_id", asdict(facts))
            self.assertNotIn("generation", parse_qs(urlsplit(description.url).query))

    def test_object_metadata_reproduces_local_descriptor_and_retention(self) -> None:
        description = wire.describe_live_object_metadata(self.profiles.ledger, self.name)
        observation = wire.parse_object_metadata_response(
            description, 200, encoded(object_response(self.metadata, self.payload))
        )
        self.assertEqual(observation, self.observation)
        self.assertIs(observation.metadata.is_live, True)
        no_crc = object_response(self.metadata, self.payload)
        del no_crc["crc32c"]
        self.assertIsNone(
            wire.parse_object_metadata_response(description, 200, encoded(no_crc)).crc32c
        )

    def test_status_412_is_conditional_only_and_other_errors_remain_unconfirmed(self) -> None:
        conditional = wire.describe_conditional_object_write(self.profiles.ledger, self.write)
        media = wire.describe_pinned_media_read(
            self.profiles.ledger, self.read, observation=self.observation
        )
        for description, parser in (
            (conditional, wire.parse_object_metadata_response),
            (media, wire.parse_media_response),
        ):
            with (
                self.subTest(operation=description.operation),
                self.assertRaises(GCSPreconditionFailed),
            ):
                parser(description, 412, b"not interpreted as a policy receipt")
        for description, parser in (
            (wire.describe_bucket_lookup(self.profiles.ledger), wire.parse_bucket_response),
            (
                wire.describe_live_object_metadata(self.profiles.ledger, self.name),
                wire.parse_object_metadata_response,
            ),
        ):
            with self.assertRaises(wire.GCSWireError):
                parser(description, 412, b"{}")
        for status in (201, 204, 302, 308, 400, 403, 404, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(GCSAmbiguousWrite):
                wire.parse_object_metadata_response(conditional, status, b"{}")
        for status in (206, 302, 404, 503):
            with self.subTest(status=status), self.assertRaises(wire.GCSWireError):
                wire.parse_media_response(media, status, self.payload)

    def test_duplicate_float_nonfinite_unicode_array_depth_and_size_are_rejected(self) -> None:
        description = wire.describe_bucket_lookup(self.profiles.ledger)
        cases = (
            b'{"name":"a","name":"b"}',
            b'{"value":1.0}',
            b'{"value":NaN}',
            b'{"value":Infinity}',
            b'{"value":1e2}',
            b'{"value":9223372036854775808}',
            b'{"value":"\\u00e9"}',
            b'{"value":[]}',
            b'{"value":' + b'{"x":' * 10 + b"0" + b"}" * 10 + b"}",
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]), self.assertRaises(GCSCustodyError):
                wire.parse_bucket_response(description, 200, raw)
        with patch("sunderkey.gcp_gcs_wire.json.loads") as decode:
            with self.assertRaises(wire.GCSWireError):
                wire.parse_bucket_response(description, 200, b" " * (wire.MAXIMUM_JSON_BYTES + 1))
            decode.assert_called_once()  # Captured bounded request only; response was not decoded.

    def test_bucket_policy_substitution_holds_retention_modes_and_missing_fields_fail(self) -> None:
        description = wire.describe_bucket_lookup(self.profiles.ledger)
        base = bucket_response(self.profiles.ledger)
        mutations = (
            {"name": "other-bucket"},
            {"versioning": {"enabled": True}},
            {"versioning": {"enabled": 0}},
            {"retentionPolicy": {"isLocked": 1, "retentionPeriod": "86400"}},
            {"retentionPolicy": {"isLocked": True, "retentionPeriod": 86400}},
            {"retentionPolicy": {"isLocked": True, "retentionPeriod": "086400"}},
            {"retentionPolicy": {"isLocked": False, "retentionPeriod": "86400"}},
            {"objectRetention": {"mode": "Enabled"}},
            {"defaultEventBasedHold": True},
            {"softDeleteTime": "2026-09-20T00:00:00Z"},
            {"metageneration": True},
            {"namespace_id": "claimed-by-provider"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(GCSCustodyError):
                wire.parse_bucket_response(description, 200, encoded({**base, **mutation}))
        for field in ("name", "versioning", "retentionPolicy"):
            raw = copy.deepcopy(base)
            del raw[field]
            with self.subTest(missing=field), self.assertRaises(GCSCustodyError):
                wire.parse_bucket_response(description, 200, encoded(raw))

    def test_object_coordinate_counter_hold_encoding_and_deleted_substitution_fail(self) -> None:
        description = wire.describe_live_object_metadata(self.profiles.ledger, self.name)
        base = object_response(self.metadata, self.payload)
        for mutation in (
            {"bucket": self.profiles.head.bucket},
            {"name": "ledger/other"},
            {"generation": True},
            {"generation": "07000001"},
            {"metageneration": 3},
            {"size": len(self.payload)},
            {"size": "0"},
            {"temporaryHold": True},
            {"eventBasedHold": 0},
            {"retention": {"mode": "Locked"}},
            {"contentEncoding": "gzip"},
            {"contentType": "application/json"},
            {"timeDeleted": "2026-09-20T00:00:00Z"},
            {"softDeleteTime": None},
            {"retentionExpirationTime": "2026-09-20T01:00:00Z"},
            {"retentionExpirationTime": "2026-09-20T02:00:00.123Z"},
            {"crc32c": "bad"},
            {"metadata": {wire.DESCRIPTOR_METADATA_KEY: asdict(self.descriptor)}},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(GCSCustodyError):
                wire.parse_object_metadata_response(description, 200, encoded({**base, **mutation}))

    def test_descriptor_exact_canonical_bytes_native_scalars_and_labels_are_required(self) -> None:
        description = wire.describe_live_object_metadata(self.profiles.ledger, self.name)
        base = object_response(self.metadata, self.payload)
        documents = (
            json.dumps(asdict(self.descriptor)),
            _canonical_json({**asdict(self.descriptor), "size_bytes": True}),
            _canonical_json({**asdict(self.descriptor), "namespace_id": "unrelated"}),
            _canonical_json({**asdict(self.descriptor), "failure_domain_id": "unrelated"}),
            _canonical_json({**asdict(self.descriptor), "object_id": "unrelated"}),
            _canonical_json({**asdict(self.descriptor), "unexpected": "value"}),
        )
        for document in documents:
            raw = copy.deepcopy(base)
            raw["metadata"][wire.DESCRIPTOR_METADATA_KEY] = document
            with self.subTest(document=document[:40]), self.assertRaises(GCSCustodyError):
                wire.parse_object_metadata_response(description, 200, encoded(raw))

    def test_media_checks_size_crc_descriptor_digest_and_rejects_decompression(self) -> None:
        description = wire.describe_pinned_media_read(
            self.profiles.ledger, self.read, observation=self.observation
        )
        for payload in (self.payload[:-1], b"x" * len(self.payload)):
            with self.assertRaises(wire.GCSWireError):
                wire.parse_media_response(description, 200, payload)
        with self.assertRaises(wire.GCSWireError):
            wire.parse_media_response(description, 200, self.payload, content_encoding="gzip")
        no_crc = wire.describe_pinned_media_read(
            self.profiles.ledger,
            self.read,
            observation=wire.GCSWireObjectObservation(self.metadata, None),
        )
        with self.assertRaises(wire.GCSWireError):
            wire.parse_media_response(no_crc, 200, b"x" * len(self.payload))
        self.assertEqual(wire.crc32c_base64(b"123456789"), "4waSgw==")

    def test_write_acknowledgement_requires_new_generation_and_exact_content_binding(self) -> None:
        description = wire.describe_conditional_object_write(self.profiles.ledger, self.write)
        raw = object_response(self.metadata, self.payload)
        self.assertEqual(
            wire.parse_object_metadata_response(description, 200, encoded(raw)), self.observation
        )
        for mutation in ({"crc32c": wire.crc32c_base64(b"wrong")}, {"size": "1"}):
            with self.assertRaises(GCSCustodyError):
                wire.parse_object_metadata_response(description, 200, encoded({**raw, **mutation}))
        payload = b"synthetic-head"
        request = GCSWriteRequest(
            "request:head",
            self.profiles.head.bucket,
            "heads/deployment:synthetic",
            payload,
            "9000001",
            "4",
            None,
        )
        description = wire.describe_conditional_object_write(self.profiles.head, request)
        metadata = GCSObjectMetadata(
            request.bucket, request.object_name, "9000002", "1", len(payload), None, None, True
        )
        raw = object_response(metadata, payload)
        self.assertEqual(
            wire.parse_object_metadata_response(description, 200, encoded(raw)).metadata, metadata
        )
        with self.assertRaises(wire.GCSWireError):
            wire.parse_object_metadata_response(
                description, 200, encoded({**raw, "generation": "9000001"})
            )

    def test_mutated_typed_request_profile_and_description_aliases_fail_before_hooks(self) -> None:
        class Alias(str):
            def __eq__(self, other):
                raise AssertionError("Alias equality must not execute")

            __hash__ = str.__hash__

        for field, value in (
            ("bucket", Alias(self.write.bucket)),
            ("if_generation_match", Alias("0")),
        ):
            request = copy.deepcopy(self.write)
            object.__setattr__(request, field, value)
            with self.subTest(field=field), self.assertRaises(GCSCustodyError):
                wire.describe_conditional_object_write(self.profiles.ledger, request)
        profile = copy.deepcopy(self.profiles.ledger)
        object.__setattr__(profile, "versioning_enabled", 0)
        with self.assertRaises(GCSCustodyError):
            wire.describe_bucket_lookup(profile)
        description = wire.describe_bucket_lookup(self.profiles.ledger)
        for field, value in (
            ("method", Alias("GET")),
            ("url", "https://example.invalid/unbound"),
            ("headers", (("Authorization", "forbidden"),)),
        ):
            altered = copy.deepcopy(description)
            object.__setattr__(altered, field, value)
            with self.subTest(field=field), self.assertRaises(GCSCustodyError):
                wire.parse_bucket_response(
                    altered, 200, encoded(bucket_response(self.profiles.ledger))
                )

    def test_frozen_source_capture_detaches_mutable_typed_objects(self) -> None:
        original = copy.deepcopy(self.write)
        description = wire.describe_conditional_object_write(self.profiles.ledger, original)
        object.__setattr__(original, "payload", b"changed")
        object.__setattr__(original.ledger_object, "namespace_id", "changed")
        observation = wire.parse_object_metadata_response(
            description, 200, encoded(object_response(self.metadata, self.payload))
        )
        self.assertEqual(observation.metadata.ledger_object, self.descriptor)
        self.assertEqual(description.payload, self.payload)

    def test_exact_families_native_status_bytes_and_descriptor_container_types(self) -> None:
        class UnsupportedRequest(GCSReadRequest):
            def __post_init__(self):
                pass

            def __getattribute__(self, name):
                if name == "__post_init__":
                    return object.__getattribute__(self, name)
                raise AssertionError("Unsupported request hook must not be called")

        unsupported = UnsupportedRequest(
            self.read.bucket, self.read.object_name, self.read.generation, self.read.metageneration
        )
        with self.assertRaises(GCSCustodyError):
            wire.describe_pinned_media_read(
                self.profiles.ledger, unsupported, observation=self.observation
            )
        description = wire.describe_bucket_lookup(self.profiles.ledger)
        body = encoded(bucket_response(self.profiles.ledger))
        for status in (True, 200.0, "200"):
            with self.subTest(status=status), self.assertRaises(wire.GCSWireError):
                wire.parse_bucket_response(description, status, body)
        for value in (bytearray(body), body.decode("ascii"), memoryview(body)):
            with self.subTest(kind=type(value).__name__), self.assertRaises(wire.GCSWireError):
                wire.parse_bucket_response(description, 200, value)
        with self.assertRaises(wire.GCSWireError):
            wire.parse_bucket_response(description, 200, b'{"name":"a","na\\u006de":"b"}')

    def test_missing_descriptors_wrong_classes_and_pinned_snapshot_substitution_fail(self) -> None:
        missing = GCSWriteRequest(
            "request:missing", self.metadata.bucket, self.name, self.payload, "0", None, None
        )
        with self.assertRaises(GCSCustodyError):
            wire.describe_conditional_object_write(self.profiles.ledger, missing)
        with self.assertRaises(GCSCustodyError):
            wire.describe_live_object_metadata(self.profiles.head, self.name)
        for change in (
            {"generation": "7000002"},
            {"metageneration": "4"},
            {"retention_until": None},
            {"ledger_object": None},
        ):
            bad = wire.GCSWireObjectObservation(
                replace(self.metadata, **change), self.observation.crc32c
            )
            with self.subTest(change=change), self.assertRaises(GCSCustodyError):
                wire.describe_pinned_media_read(self.profiles.ledger, self.read, observation=bad)

    def test_head_payload_bound_and_multipart_boundary_collision_fail_before_output(self) -> None:
        request = GCSWriteRequest(
            "request:large",
            self.profiles.head.bucket,
            "heads/deployment:synthetic",
            b"x" * 4097,
            "0",
            None,
            None,
        )
        with self.assertRaises(GCSCustodyError):
            wire.describe_conditional_object_write(self.profiles.head, request)
        payload = b"--sunderkey_gcs_" + b"0" * 64
        request = replace(request, payload=payload)
        with patch("sunderkey.gcp_gcs_wire.hashlib.sha256") as digest:
            digest.return_value.digest.return_value = b"\x00" * 32
            digest.return_value.hexdigest.return_value = "0" * 64
            with self.assertRaisesRegex(wire.GCSWireError, "boundary"):
                wire.describe_conditional_object_write(self.profiles.head, request)

    def test_typed_ports_compose_through_synthetic_raw_bytes_without_live_effects(self) -> None:
        fixture = SyntheticRawByteFixture(self.profiles)
        ledger = GCSRetentionLockedLedgerObjectProvider(
            fixture, self.profiles, clock=lambda: custody_test.NOW
        )
        receipt = ledger.put_if_absent(
            LedgerObjectPutRequest("request:put", self.descriptor, self.payload)
        )
        self.assertEqual(receipt.write_status, "created")
        self.assertEqual(
            ledger.read_verified(
                LedgerObjectReadRequest(
                    "request:read", self.descriptor.object_id, self.descriptor.sha256
                )
            ).payload,
            self.payload,
        )
        self.assertTrue(
            ledger.read_retention_state(
                RetentionStateReadRequest(
                    "request:retention", self.descriptor.object_id, self.descriptor.retention_until
                )
            ).retention_lock_verified
        )
        heads = GCSConditionalLedgerHeadProvider(
            fixture, self.profiles, clock=lambda: custody_test.NOW
        )
        head = LedgerHeadDescriptor(
            "deployment:synthetic", 1, self.descriptor.object_id, self.descriptor.sha256, None
        )
        self.assertEqual(
            heads.compare_and_swap_head(
                LedgerHeadCompareAndSwapRequest("request:cas", None, head)
            ).compare_and_swap_status,
            "advanced",
        )
        self.assertEqual(
            heads.read_head(LedgerHeadReadRequest("request:head", head.deployment_id)).head, head
        )
        self.assertEqual(
            {description.operation for description in fixture.descriptions}, wire._OPERATIONS
        )

    def test_module_is_inert_and_source_bounds_reject_before_json_serialization(self) -> None:
        tree = ast.parse(inspect.getsource(wire))
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
                    "os",
                    "subprocess",
                    "pathlib",
                }
            )
        )
        self.assertFalse(hasattr(wire.GCSWireRequest, "send"))
        value = "x" * 8192
        with patch("sunderkey.gcp_gcs_wire._canonical_json") as serialize:
            with self.assertRaises(wire.GCSWireError):
                wire._bounded_json({"a": value, "b": value, "c": value})
            serialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()

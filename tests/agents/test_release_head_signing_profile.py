"""Exact-byte vectors for the non-authorizing D012 release-head V1 profile."""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey import release_head_signing_profile as profile
from sunderkey.candidate_enrollment import ENROLLMENT_CATALOG_SIGNING_DOMAIN
from sunderkey.candidate_enrollment_production_custody_contract import (
    LedgerHeadDescriptor,
    ReleaseHeadSigningRequest,
    SignedReleaseHeadDescriptor,
    provider_subject_sha256,
)
from sunderkey.gcp_kms_ed25519 import (
    GcpKmsEd25519KeyVersionBinding,
    build_gcp_ed25519_sign_request,
    verify_gcp_ed25519_sign_response,
)
from sunderkey.identity import PRINCIPAL_ASSERTION_SIGNING_DOMAIN
from tests.agents.test_production_custody_conformance_phase185 import InMemorySigner

PREFIX = b"SUNDERKEY\x00PRODUCTION-CUSTODY-RELEASE-HEAD\x00D012\x00V1\x00"
GENESIS_HEAD_SHA256 = "sha256:55334d3316fa4e4cf5acaf1ffb47e0eb69e7a11ae2106fe524aabada60b6a195"
GENESIS_BYTES = PREFIX + (
    b'{"head":{"deployment_id":"deployment.offline","entry_id":"entry.genesis",'
    b'"entry_sha256":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"ledger_sequence":1,"previous_head_sha256":null},'
    b'"offline_root_authorization_sha256":'
    b'"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    b'"schema_version":1,"signed_at":"2026-09-28T12:34:56Z",'
    b'"signer_key_id":"key.release.offline","signing_algorithm":"Ed25519"}'
)
SUCCESSOR_BYTES = PREFIX + (
    b'{"head":{"deployment_id":"deployment.offline","entry_id":"entry.successor",'
    b'"entry_sha256":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",'
    b'"ledger_sequence":2,"previous_head_sha256":'
    b'"sha256:55334d3316fa4e4cf5acaf1ffb47e0eb69e7a11ae2106fe524aabada60b6a195"},'
    b'"offline_root_authorization_sha256":'
    b'"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",'
    b'"schema_version":1,"signed_at":"2026-09-28T12:34:56Z",'
    b'"signer_key_id":"key.release.offline","signing_algorithm":"Ed25519"}'
)
GENESIS_INPUT_SHA256 = "c98a3b2da0ead441a32632632df2884d0a3a2c71199ee31b9e948a5f17898c54"
SUCCESSOR_INPUT_SHA256 = "9f1ffcb2c0783051b982e64a9e2ea25aba802dc2389238414eda9b7d97d620ec"


def _head(*, successor=False):
    return LedgerHeadDescriptor(
        "deployment.offline",
        2 if successor else 1,
        "entry.successor" if successor else "entry.genesis",
        "sha256:" + ("c" if successor else "a") * 64,
        GENESIS_HEAD_SHA256 if successor else None,
    )


def _request(*, successor=False):
    return ReleaseHeadSigningRequest(
        "request.transport.1",
        _head(successor=successor),
        "key.release.offline",
        "sha256:" + "b" * 64,
        "Ed25519",
        "2026-09-28T12:34:56Z",
    )


def _signed(request=None, *, signature=bytes(64)):
    request = _request() if request is None else request
    return SignedReleaseHeadDescriptor(
        request.head,
        request.signer_key_id,
        request.offline_root_authorization_sha256,
        request.signing_algorithm,
        signature,
        request.requested_at,
    )


def _crc32c(data):
    remainder = 0xFFFFFFFF
    for byte in data:
        remainder ^= byte
        for _ in range(8):
            remainder = (remainder >> 1) ^ (0x82F63B78 if remainder & 1 else 0)
    return remainder ^ 0xFFFFFFFF


class TextAlias(str):
    def isascii(self):
        raise AssertionError("text alias hook must not run")


class IntegerAlias(int):
    pass


class BytesAlias(bytes):
    pass


class DictAlias(dict):
    pass


class ReleaseHeadSigningProfileTests(unittest.TestCase):
    def assert_rejected_before_serialization(self, value, *, signed=False):
        function = (
            profile.signed_release_head_signing_bytes
            if signed
            else profile.release_head_signing_bytes
        )
        with (
            patch.object(profile.json, "dumps", side_effect=AssertionError("must not serialize")),
            self.assertRaises(profile.ReleaseHeadSigningProfileError),
        ):
            function(value)

    def test_genesis_golden_bytes_and_digest_reconstruct_exactly(self):
        request = _request()
        self.assertEqual(profile.release_head_signing_bytes(request), GENESIS_BYTES)
        self.assertEqual(profile.signed_release_head_signing_bytes(_signed(request)), GENESIS_BYTES)
        self.assertEqual(len(GENESIS_BYTES), 493)
        self.assertEqual(hashlib.sha256(GENESIS_BYTES).hexdigest(), GENESIS_INPUT_SHA256)
        self.assertEqual(profile.SIGNING_DOMAIN, PREFIX)
        self.assertFalse(GENESIS_BYTES.endswith(b"\n"))

    def test_successor_golden_preserves_existing_head_and_predecessor_hash(self):
        request = _request(successor=True)
        self.assertEqual(profile.release_head_signing_bytes(request), SUCCESSOR_BYTES)
        self.assertEqual(
            profile.signed_release_head_signing_bytes(_signed(request)), SUCCESSOR_BYTES
        )
        self.assertEqual(len(SUCCESSOR_BYTES), 564)
        self.assertEqual(hashlib.sha256(SUCCESSOR_BYTES).hexdigest(), SUCCESSOR_INPUT_SHA256)
        self.assertEqual(provider_subject_sha256(_head()), GENESIS_HEAD_SHA256)
        self.assertNotEqual("sha256:" + GENESIS_INPUT_SHA256, request.head.previous_head_sha256)

    def test_transport_request_id_is_validated_but_excluded_from_bytes(self):
        changed = replace(_request(), request_id="request.transport.other")
        self.assertEqual(profile.release_head_signing_bytes(changed), GENESIS_BYTES)
        object.__setattr__(changed, "request_id", "unsupported/request")
        self.assert_rejected_before_serialization(changed)

    def test_signature_is_shape_checked_but_excluded_and_not_verified(self):
        for signature in (bytes(64), b"x" * 64):
            self.assertEqual(
                profile.signed_release_head_signing_bytes(_signed(signature=signature)),
                GENESIS_BYTES,
            )
        for signature in (b"", bytes(63), bytes(65), bytearray(64), BytesAlias(64), "x" * 64):
            with self.subTest(signature_type=type(signature).__name__, length=len(signature)):
                signed = _signed()
                object.__setattr__(signed, "signature", signature)
                self.assert_rejected_before_serialization(signed, signed=True)

    def test_each_signed_field_changes_the_reconstructed_input(self):
        original = _request(successor=True)
        changes = (
            {"head": replace(original.head, deployment_id="deployment.other")},
            {"head": replace(original.head, ledger_sequence=3)},
            {"head": replace(original.head, entry_id="entry.other")},
            {"head": replace(original.head, entry_sha256="sha256:" + "d" * 64)},
            {"head": replace(original.head, previous_head_sha256="sha256:" + "e" * 64)},
            {"signer_key_id": "key.other"},
            {"offline_root_authorization_sha256": "sha256:" + "f" * 64},
            {"requested_at": "2026-09-28T12:34:57Z"},
        )
        for change in changes:
            with self.subTest(fields=tuple(change)):
                changed = replace(original, **change)
                encoded = profile.release_head_signing_bytes(changed)
                self.assertNotEqual(encoded, SUCCESSOR_BYTES)
                self.assertEqual(
                    profile.signed_release_head_signing_bytes(_signed(changed)), encoded
                )

    def test_only_exact_ed25519_algorithm_is_supported_without_conversion(self):
        for algorithm in (
            "Ed25519ph",
            "ECDSA",
            "sha256_simulation",
            "ed25519",
            TextAlias("Ed25519"),
        ):
            with self.subTest(algorithm_type=type(algorithm).__name__):
                request = _request()
                object.__setattr__(request, "signing_algorithm", algorithm)
                self.assert_rejected_before_serialization(request)
                self.assert_rejected_before_serialization(_signed(request), signed=True)

    def test_timestamp_spelling_is_exact_and_invalid_dates_reject(self):
        for timestamp in (
            "2026-09-28T12:34:56+00:00",
            "2026-09-28T12:34:56.000000Z",
            "2026-09-28T12:34:56z",
            "2026-02-30T12:34:56Z",
            "2026-09-28T12:34:60Z",
            TextAlias("2026-09-28T12:34:56Z"),
        ):
            with self.subTest(timestamp_type=type(timestamp).__name__):
                request = _request()
                object.__setattr__(request, "requested_at", timestamp)
                self.assert_rejected_before_serialization(request)

    def test_native_outer_scalar_types_are_required_before_any_hooks(self):
        for field, value in (
            ("request_id", TextAlias("request.transport.1")),
            ("signer_key_id", TextAlias("key.release.offline")),
            ("offline_root_authorization_sha256", TextAlias("sha256:" + "b" * 64)),
            ("request_id", object()),
            ("signer_key_id", None),
            ("offline_root_authorization_sha256", "sha256:" + "B" * 64),
        ):
            with self.subTest(field=field, native_type=type(value).__name__):
                request = _request()
                object.__setattr__(request, field, value)
                self.assert_rejected_before_serialization(request)

    def test_signed_descriptor_native_fields_and_public_family_separation(self):
        for field, value in (
            ("signed_at", TextAlias("2026-09-28T12:34:56Z")),
            ("signed_at", "2026-09-28T12:34:56.000Z"),
            ("signer_key_id", TextAlias("key.release.offline")),
            ("offline_root_authorization_sha256", TextAlias("sha256:" + "b" * 64)),
            ("head", object()),
        ):
            with self.subTest(field=field, native_type=type(value).__name__):
                signed = _signed()
                object.__setattr__(signed, field, value)
                self.assert_rejected_before_serialization(signed, signed=True)
        self.assert_rejected_before_serialization(_signed())
        self.assert_rejected_before_serialization(_request(), signed=True)

    def test_native_head_types_and_initial_predecessor_relationship_are_required(self):
        for field, value in (
            ("deployment_id", TextAlias("deployment.offline")),
            ("entry_id", TextAlias("entry.genesis")),
            ("entry_sha256", TextAlias("sha256:" + "a" * 64)),
            ("ledger_sequence", True),
            ("ledger_sequence", 1.0),
            ("ledger_sequence", IntegerAlias(1)),
            ("ledger_sequence", 0),
            ("ledger_sequence", -1),
            ("previous_head_sha256", "sha256:" + "c" * 64),
        ):
            with self.subTest(field=field, native_type=type(value).__name__):
                request = _request()
                object.__setattr__(request.head, field, value)
                self.assert_rejected_before_serialization(request)
        request = _request(successor=True)
        object.__setattr__(request.head, "previous_head_sha256", None)
        self.assert_rejected_before_serialization(request)

    def test_predecessor_digest_must_be_native_canonical_and_bounded(self):
        for predecessor in (TextAlias(GENESIS_HEAD_SHA256), "sha256:" + "A" * 64, "x", 1):
            with self.subTest(predecessor_type=type(predecessor).__name__):
                request = _request(successor=True)
                object.__setattr__(request.head, "previous_head_sha256", predecessor)
                self.assert_rejected_before_serialization(request)

    def test_oversized_values_and_integers_reject_before_serialization(self):
        for family, field, value in (
            ("request", "request_id", "x" * 1_000_000),
            ("request", "signer_key_id", "x" * 257),
            ("head", "ledger_sequence", 1 << 1_000_000),
            ("head", "ledger_sequence", profile.MAX_LEDGER_SEQUENCE + 1),
            ("head", "entry_id", "x" * 257),
            ("signed", "signature", bytes(1_000_000)),
        ):
            with self.subTest(family=family, field=field):
                request = _request(successor=True)
                source = _signed(request) if family == "signed" else request
                object.__setattr__(source.head if family == "head" else source, field, value)
                self.assert_rejected_before_serialization(source, signed=family == "signed")

    def test_finite_upper_boundary_is_supported_without_changing_old_ports(self):
        request = replace(
            _request(successor=True),
            request_id="r" * 256,
            signer_key_id="k" * 256,
            head=LedgerHeadDescriptor(
                "d" * 256,
                profile.MAX_LEDGER_SEQUENCE,
                "e" * 256,
                "sha256:" + "c" * 64,
                GENESIS_HEAD_SHA256,
            ),
        )
        encoded = profile.release_head_signing_bytes(request)
        self.assertLessEqual(len(encoded), profile.MAX_SIGNING_BYTES)
        self.assertEqual(profile.signed_release_head_signing_bytes(_signed(request)), encoded)
        old_port_head = replace(request.head, ledger_sequence=profile.MAX_LEDGER_SEQUENCE + 1)
        self.assertEqual(old_port_head.ledger_sequence, profile.MAX_LEDGER_SEQUENCE + 1)
        self.assert_rejected_before_serialization(replace(request, head=old_port_head))

    def test_family_subclasses_reject_without_accessing_their_fields(self):
        class RequestAlias(ReleaseHeadSigningRequest):
            def __getattribute__(self, name):
                raise AssertionError("request subclass hook must not run")

        class HeadAlias(LedgerHeadDescriptor):
            def __getattribute__(self, name):
                raise AssertionError("head subclass hook must not run")

        class SignedAlias(SignedReleaseHeadDescriptor):
            def __getattribute__(self, name):
                raise AssertionError("signed subclass hook must not run")

        self.assert_rejected_before_serialization(object.__new__(RequestAlias))
        self.assert_rejected_before_serialization(object.__new__(SignedAlias), signed=True)
        request = _request()
        object.__setattr__(request, "head", object.__new__(HeadAlias))
        self.assert_rejected_before_serialization(request)

    def test_incomplete_forged_and_unknown_field_instances_fail_closed(self):
        self.assert_rejected_before_serialization(object.__new__(ReleaseHeadSigningRequest))
        self.assert_rejected_before_serialization(
            object.__new__(SignedReleaseHeadDescriptor), signed=True
        )
        request = _request()
        object.__setattr__(request, "head", object.__new__(LedgerHeadDescriptor))
        self.assert_rejected_before_serialization(request)
        for signed, nested in ((False, False), (False, True), (True, False), (True, True)):
            with self.subTest(signed=signed, nested=nested):
                source = _signed() if signed else _request()
                object.__setattr__(source.head if nested else source, "extra", "not supported")
                self.assert_rejected_before_serialization(source, signed=signed)

    def test_storage_subclasses_and_non_native_field_keys_reject_before_normalizing(self):
        for nested, alias_keys in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(nested=nested, alias_keys=alias_keys):
                request = _request()
                source = request.head if nested else request
                storage = vars(source)
                changed = (
                    {TextAlias(key): value for key, value in storage.items()}
                    if alias_keys
                    else DictAlias(storage)
                )
                object.__setattr__(source, "__dict__", changed)
                self.assert_rejected_before_serialization(request)

    def test_valid_late_source_changes_never_return_bytes(self):
        mutations = (
            (False, lambda value: object.__setattr__(value, "request_id", "request.other")),
            (False, lambda value: object.__setattr__(value, "signer_key_id", "key.other")),
            (
                False,
                lambda value: object.__setattr__(
                    value, "offline_root_authorization_sha256", "sha256:" + "f" * 64
                ),
            ),
            (
                False,
                lambda value: object.__setattr__(value, "requested_at", "2026-09-28T12:34:57Z"),
            ),
            (False, lambda value: object.__setattr__(value.head, "entry_id", "entry.other")),
            (False, lambda value: object.__setattr__(value, "head", replace(value.head))),
            (False, lambda value: object.__setattr__(value, "__dict__", dict(vars(value)))),
            (
                False,
                lambda value: object.__setattr__(value.head, "__dict__", dict(vars(value.head))),
            ),
            (True, lambda value: object.__setattr__(value, "signature", b"x" * 64)),
            (True, lambda value: object.__setattr__(value, "signed_at", "2026-09-28T12:34:57Z")),
        )
        real_dumps = profile.json.dumps
        for index, (signed, mutate) in enumerate(mutations):
            with self.subTest(index=index):
                source = _signed() if signed else _request()

                def serialize(document, *, source=source, mutate=mutate, **options):
                    mutate(source)
                    return real_dumps(document, **options)

                function = (
                    profile.signed_release_head_signing_bytes
                    if signed
                    else profile.release_head_signing_bytes
                )
                with (
                    patch.object(profile.json, "dumps", side_effect=serialize),
                    self.assertRaisesRegex(profile.ReleaseHeadSigningProfileError, "changed"),
                ):
                    function(source)

    def test_invalid_late_source_changes_fail_closed(self):
        request = _request()
        real_dumps = profile.json.dumps

        def serialize(document, **options):
            object.__setattr__(request.head, "ledger_sequence", True)
            return real_dumps(document, **options)

        with (
            patch.object(profile.json, "dumps", side_effect=serialize),
            self.assertRaises(profile.ReleaseHeadSigningProfileError),
        ):
            profile.release_head_signing_bytes(request)

    def test_result_is_detached_and_original_source_storage_is_unchanged(self):
        request = _request()
        outer_before = dict(vars(request))
        head_before = dict(vars(request.head))
        encoded = profile.release_head_signing_bytes(request)
        self.assertIs(type(encoded), bytes)
        self.assertEqual(vars(request), outer_before)
        self.assertEqual(vars(request.head), head_before)
        object.__setattr__(request.head, "entry_id", "entry.other")
        self.assertEqual(encoded, GENESIS_BYTES)
        self.assertNotEqual(profile.release_head_signing_bytes(request), encoded)

    def test_serializer_uses_closed_projection_and_exact_options(self):
        real_dumps = profile.json.dumps
        with patch.object(profile.json, "dumps", wraps=real_dumps) as dumps:
            self.assertEqual(profile.release_head_signing_bytes(_request()), GENESIS_BYTES)
        dumps.assert_called_once()
        document = dumps.call_args.args[0]
        self.assertEqual(
            set(document),
            {
                "schema_version",
                "head",
                "signer_key_id",
                "offline_root_authorization_sha256",
                "signing_algorithm",
                "signed_at",
            },
        )
        self.assertEqual(
            dumps.call_args.kwargs,
            {"allow_nan": False, "ensure_ascii": True, "separators": (",", ":"), "sort_keys": True},
        )

    def test_result_byte_bound_and_native_output_are_rechecked(self):
        for encoded in ("x" * profile.MAX_SIGNING_BYTES, TextAlias("{}"), "nonascii:\u00e9"):
            with (
                self.subTest(encoded_type=type(encoded).__name__),
                patch.object(profile.json, "dumps", return_value=encoded),
                self.assertRaises(profile.ReleaseHeadSigningProfileError),
            ):
                profile.release_head_signing_bytes(_request())

    def test_simulated_signature_golden_and_old_domains_remain_unchanged(self):
        simulated = replace(_request(), signing_algorithm="sha256_simulation")
        self.assertEqual(
            InMemorySigner.signature(simulated).hex(),
            "7b3109f7fb801b4c713db2b15659ef187f2943ec5aa86aa3f638b2325eb0a421",
        )
        self.assertEqual(
            ENROLLMENT_CATALOG_SIGNING_DOMAIN,
            b"SUNDERKEY\x00CANDIDATE-ENROLLMENT-CATALOG\x00V1\x00",
        )
        self.assertEqual(
            PRINCIPAL_ASSERTION_SIGNING_DOMAIN, b"SUNDERKEY\x00PRINCIPAL-ASSERTION\x00V1\x00"
        )
        self.assertNotEqual(profile.SIGNING_DOMAIN, ENROLLMENT_CATALOG_SIGNING_DOMAIN)
        self.assertNotEqual(profile.SIGNING_DOMAIN, PRINCIPAL_ASSERTION_SIGNING_DOMAIN)
        self.assert_rejected_before_serialization(simulated)

    def test_raw_kms_byte_interoperability_uses_only_disposable_synthetic_key(self):
        # This fixed local test seed is not a deployed or authorized signing key.
        private = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        binding = GcpKmsEd25519KeyVersionBinding(
            "projects/offline-fixture/locations/us-west3/keyRings/offline-fixtures/"
            "cryptoKeys/release-head-fixture/cryptoKeyVersions/1",
            "EC_SIGN_ED25519",
            "SOFTWARE",
            public,
            "sha256:" + hashlib.sha256(public).hexdigest(),
        )
        encoded = profile.release_head_signing_bytes(_request())
        mapped = build_gcp_ed25519_sign_request(binding, encoded)
        self.assertEqual(mapped.signing_input_sha256, "sha256:" + GENESIS_INPUT_SHA256)
        self.assertEqual(base64.b64decode(mapped.to_dict()["data"], validate=True), GENESIS_BYTES)
        signature = private.sign(encoded)
        response = {
            "signature": base64.b64encode(signature).decode("ascii"),
            "signatureCrc32c": str(_crc32c(signature)),
            "verifiedDataCrc32c": True,
            "name": binding.key_version_name,
            "protectionLevel": "SOFTWARE",
        }
        verified = verify_gcp_ed25519_sign_response(mapped, response)
        self.assertEqual(verified, base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"))
        self.assertEqual(
            profile.signed_release_head_signing_bytes(_signed(signature=signature)), GENESIS_BYTES
        )

    def test_leaf_has_no_authority_receipt_signer_backend_or_io(self):
        tree = ast.parse(inspect.getsource(profile))
        modules = {
            node.module if isinstance(node, ast.ImportFrom) else alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertEqual(
            modules,
            {
                "__future__",
                "json",
                "re",
                "dataclasses",
                "datetime",
                "candidate_enrollment_production_custody_contract",
            },
        )
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotIn(
                    node.func.id,
                    {"open", "ReleaseHeadVerificationReceipt", "eval", "exec", "compile"},
                )
        for function in (
            profile.release_head_signing_bytes,
            profile.signed_release_head_signing_bytes,
        ):
            self.assertEqual(len(inspect.signature(function).parameters), 1)


if __name__ == "__main__":
    unittest.main()

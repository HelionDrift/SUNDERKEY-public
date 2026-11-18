"""Fixed public vectors for the transport-free Cloud KMS Ed25519 codec."""

from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import unittest
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sunderkey import gcp_kms_ed25519 as codec
from sunderkey.gcp_kms_ed25519 import (
    MAX_KEY_VERSION_NAME_CHARS,
    MAX_PUBLIC_KEY_PEM_CHARS,
    MAX_SIGNING_BYTES,
    GcpKmsEd25519Error,
    GcpKmsEd25519KeyVersionBinding,
    GcpKmsEd25519SigningRequest,
    build_gcp_ed25519_sign_request,
    verify_gcp_ed25519_public_key_response,
    verify_gcp_ed25519_sign_response,
)
from sunderkey.identity import PrincipalAssertion

# Public material from IdentityGoldenVectorTests, with no private material here.
PUBLIC_KEY = "oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA"
OTHER_PUBLIC_KEY = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
SIGNATURE = "mDEAYLGkyN5LK4XHwlc3WUHTujE41A_HvJBwAqQRipELtQ_Xnc0jffA8HYwh4Qj4A0c5RX9XXCAGmsgY1kTjBw"
VERSION_NAME = (
    "projects/offline-fixture/locations/us-west3/keyRings/offline-fixtures/"
    "cryptoKeys/assertion-fixture/cryptoKeyVersions/7"
)
INPUT_SHA256 = "sha256:0a409ab61bb60d457e36bca932b27e9dcdea1203af8a5e187b765f3042ac11be"


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _crc32c(data: bytes) -> int:
    """Independent bitwise checksum for response fixtures."""
    remainder = 0xFFFFFFFF
    for byte in data:
        remainder ^= byte
        for _ in range(8):
            remainder = (remainder >> 1) ^ (0x82F63B78 if remainder & 1 else 0)
    return remainder ^ 0xFFFFFFFF


def _fingerprint(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _assertion() -> PrincipalAssertion:
    return PrincipalAssertion.from_dict(
        {
            "schema_version": 1,
            "assertion_id": "PAS-FFEEDDCCBBAA99887766554433221100",
            "policy_id": "POLICY-GOLDEN-V1",
            "policy_version": 42,
            "scope_grant_id": "SGR-00112233445566778899AABBCCDDEEFF",
            "scope_grant_sha256": (
                "sha256:69956418627780b77026bd64c63ac192dcb84a302eb98b8362e4d479a878a4e8"
            ),
            "issuer": "identity-provider",
            "key_id": "ASSERTION-GOLDEN-1",
            "subject": "operator:golden",
            "profile_id": "AOE-HQ-12",
            "audience": "sunderkey-runtime",
            "store_id": "STR-00112233445566778899AABBCCDDEEFF",
            "mission_id": "MISSION-GOLDEN-1",
            "operation": "sunderkey.mission.stop.v1",
            "operation_intent_sha256": (
                "sha256:95fd1bba969f855b61349abbade1e10976d1428026ebab681f0f29fa247d8a42"
            ),
            "issued_at": "2030-01-02T03:06:00Z",
            "not_before": "2030-01-02T03:06:00Z",
            "expires_at": "2030-01-02T03:11:00Z",
            "signature": SIGNATURE,
        }
    )


def _binding(**changes: object) -> GcpKmsEd25519KeyVersionBinding:
    raw = _decode(PUBLIC_KEY)
    values = {
        "key_version_name": VERSION_NAME,
        "algorithm": "EC_SIGN_ED25519",
        "protection_level": "SOFTWARE",
        "public_key": raw,
        "public_key_sha256": _fingerprint(raw),
    }
    values.update(changes)
    return GcpKmsEd25519KeyVersionBinding(**values)


def _request() -> GcpKmsEd25519SigningRequest:
    return build_gcp_ed25519_sign_request(_binding(), _assertion().signing_bytes())


def _pem(der: bytes) -> str:
    encoded = base64.b64encode(der).decode("ascii")
    lines = [encoded[offset : offset + 64] for offset in range(0, len(encoded), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def _public_response(*, public_key: bytes | None = None) -> dict[str, object]:
    key = Ed25519PublicKey.from_public_bytes(public_key or _decode(PUBLIC_KEY))
    pem = key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")
    return {
        "pem": pem,
        "pemCrc32c": str(_crc32c(pem.encode("ascii"))),
        "name": VERSION_NAME,
        "algorithm": "EC_SIGN_ED25519",
        "protectionLevel": "SOFTWARE",
    }


def _signature_response(*, signature: bytes | None = None) -> dict[str, object]:
    raw = _decode(SIGNATURE) if signature is None else signature
    return {
        "signature": base64.b64encode(raw).decode("ascii"),
        "signatureCrc32c": str(_crc32c(raw)),
        "name": VERSION_NAME,
        "protectionLevel": "SOFTWARE",
        "verifiedDataCrc32c": True,
    }


class TextSubclass(str):
    pass


class BytesSubclass(bytes):
    pass


class DictSubclass(dict):
    pass


class GcpKmsEd25519Tests(unittest.TestCase):
    def test_existing_canonical_vector_maps_exact_raw_bytes(self) -> None:
        assertion = _assertion()
        request = build_gcp_ed25519_sign_request(_binding(), assertion.signing_bytes())
        document = request.to_dict()
        self.assertEqual(len(request.signing_bytes), 775)
        self.assertEqual(request.signing_input_sha256, INPUT_SHA256)
        self.assertEqual(request.signing_bytes, assertion.signing_bytes())
        self.assertEqual(
            base64.b64decode(document["data"], validate=True), assertion.signing_bytes()
        )
        self.assertEqual(document["dataCrc32c"], str(_crc32c(assertion.signing_bytes())))
        self.assertEqual(set(document), {"name", "data", "dataCrc32c"})
        self.assertEqual(set(request.to_rest_body()), {"data", "dataCrc32c"})
        self.assertTrue(
            request.signing_bytes.startswith(b"SUNDERKEY\x00PRINCIPAL-ASSERTION\x00V1\x00")
        )

    def test_fixed_signature_composes_strict_existing_crypto_and_replays(self) -> None:
        response = _signature_response()
        first = verify_gcp_ed25519_sign_response(_request(), response)
        second = verify_gcp_ed25519_sign_response(_request(), dict(response))
        self.assertEqual(first, SIGNATURE)
        self.assertEqual(first, second)
        self.assertIs(type(first), str)
        self.assertEqual(_request().request_sha256, _request().request_sha256)
        self.assertEqual(_assertion().signature, SIGNATURE)

    def test_pinned_pem_response_composes_strict_public_key_validation(self) -> None:
        binding = _binding()
        response = _public_response()
        raw = verify_gcp_ed25519_public_key_response(binding, response)
        self.assertEqual(raw, binding.public_key)
        self.assertIs(type(raw), bytes)
        response["publicKeyFormat"] = "PUBLIC_KEY_FORMAT_UNSPECIFIED"
        self.assertEqual(verify_gcp_ed25519_public_key_response(binding, response), raw)
        response["pem"] = response["pem"].replace("\n", "\r\n")
        response["pemCrc32c"] = str(_crc32c(response["pem"].encode("ascii")))
        self.assertEqual(verify_gcp_ed25519_public_key_response(binding, response), raw)

    def test_crc32c_is_castagnoli_not_ordinary_crc32(self) -> None:
        self.assertEqual(codec._crc32c(b""), 0)
        self.assertEqual(codec._crc32c(b"123456789"), 0xE3069283)
        self.assertEqual(codec._crc32c(bytes(range(256))), _crc32c(bytes(range(256))))

    def test_binding_requires_explicit_version_algorithm_protection_and_fingerprint(self) -> None:
        self.assertEqual(
            verify_gcp_ed25519_sign_response(_request(), _signature_response()), SIGNATURE
        )
        changes = (
            {"key_version_name": VERSION_NAME.rsplit("/", 1)[0]},
            {"key_version_name": VERSION_NAME.rsplit("/", 1)[0] + "/latest"},
            {"key_version_name": VERSION_NAME.rsplit("/", 1)[0] + "/0"},
            {"key_version_name": VERSION_NAME.rsplit("/", 1)[0] + "/07"},
            {"key_version_name": VERSION_NAME.replace("us-west3", "../us-west3")},
            {"key_version_name": "x" * (MAX_KEY_VERSION_NAME_CHARS + 1)},
            {"algorithm": "EC_SIGN_P256_SHA256"},
            {"algorithm": TextSubclass("EC_SIGN_ED25519")},
            {"protection_level": "HSM"},
            {"protection_level": "EXTERNAL"},
            {"public_key_sha256": "sha256:" + "0" * 64},
            {"public_key_sha256": _fingerprint(_decode(PUBLIC_KEY)).upper()},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(GcpKmsEd25519Error):
                _binding(**change)

    def test_weak_noncanonical_and_non_native_public_keys_are_rejected(self) -> None:
        weak_keys = (bytes(32), b"\x01" + bytes(31), ((1 << 255) - 19).to_bytes(32, "little"))
        for raw in weak_keys:
            with (
                self.subTest(raw=raw.hex()),
                self.assertRaisesRegex(GcpKmsEd25519Error, "canonical prime-order"),
            ):
                _binding(public_key=raw, public_key_sha256=_fingerprint(raw))
        for raw in (bytearray(_decode(PUBLIC_KEY)), BytesSubclass(_decode(PUBLIC_KEY)), bytes(31)):
            with (
                self.subTest(kind=type(raw)),
                self.assertRaisesRegex(GcpKmsEd25519Error, "32 native raw"),
            ):
                _binding(public_key=raw)

    def test_ring_and_key_ids_allow_native_leading_hyphen_or_underscore_with_63_char_bound(
        self,
    ) -> None:
        for ring in ("_offline", "-offline", "_" * 63):
            for key in ("_key", "-key", "-" * 63):
                name = (
                    "projects/offline-fixture/locations/us-west3/"
                    f"keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/7"
                )
                with self.subTest(ring=ring, key=key):
                    self.assertEqual(_binding(key_version_name=name).key_version_name, name)
        for segment in ("keyRings/offline-fixtures", "cryptoKeys/assertion-fixture"):
            label = segment.split("/")[0]
            name = VERSION_NAME.replace(segment, label + "/" + "a" * 64)
            with self.subTest(segment=segment), self.assertRaises(GcpKmsEd25519Error):
                _binding(key_version_name=name)

    def test_request_owns_binding_and_exports_detached_dictionaries(self) -> None:
        caller_binding = _binding()
        request = build_gcp_ed25519_sign_request(caller_binding, _assertion().signing_bytes())
        self.assertIsNot(request.binding, caller_binding)
        self.assertEqual(request.binding, caller_binding)
        with self.assertRaises(FrozenInstanceError):
            request.data_crc32c = 0
        with self.assertRaises(FrozenInstanceError):
            caller_binding.algorithm = "EC_SIGN_P256_SHA256"
        exported = request.to_dict()
        exported["data"] = "changed"
        request.to_rest_body()["dataCrc32c"] = "0"
        request.binding.to_dict()["public_key_sha256"] = "changed"
        object.__setattr__(caller_binding, "key_version_name", VERSION_NAME[:-1] + "8")
        self.assertEqual(request.to_dict()["name"], VERSION_NAME)
        self.assertEqual(
            verify_gcp_ed25519_sign_response(request, _signature_response()), SIGNATURE
        )

    def test_request_late_mutation_cannot_keep_an_old_binding_or_digest(self) -> None:
        mutations = (
            ("signing_bytes", _assertion().signing_bytes() + b"\n"),
            ("data_crc32c", 0),
            ("data_crc32c", True),
            ("data_crc32c", float(_request().data_crc32c)),
            ("signing_input_sha256", "sha256:" + "0" * 64),
            ("signing_input_sha256", TextSubclass(_request().signing_input_sha256)),
            ("request_sha256", "sha256:" + "0" * 64),
            ("request_sha256", TextSubclass(_request().request_sha256)),
            ("binding", _binding(key_version_name=VERSION_NAME[:-1] + "8")),
        )
        for field_name, value in mutations:
            request = _request()
            object.__setattr__(request, field_name, value)
            with (
                self.subTest(field=field_name),
                self.assertRaisesRegex(GcpKmsEd25519Error, "no longer matches"),
            ):
                verify_gcp_ed25519_sign_response(request, _signature_response())

    def test_request_bounds_and_native_bytes_are_checked_before_mapping(self) -> None:
        for value in (
            b"",
            bytes(MAX_SIGNING_BYTES + 1),
            bytearray(b"a"),
            memoryview(b"a"),
            BytesSubclass(b"a"),
            True,
        ):
            with (
                self.subTest(kind=type(value)),
                self.assertRaisesRegex(GcpKmsEd25519Error, "native raw bytes"),
            ):
                build_gcp_ed25519_sign_request(_binding(), value)
        request = build_gcp_ed25519_sign_request(_binding(), bytes(MAX_SIGNING_BYTES))
        self.assertEqual(len(base64.b64decode(request.to_dict()["data"])), MAX_SIGNING_BYTES)
        self.assertIs(type(request.data_crc32c), int)

    def test_responses_require_closed_native_json_objects(self) -> None:
        pairs = (
            (verify_gcp_ed25519_public_key_response, _binding(), _public_response()),
            (verify_gcp_ed25519_sign_response, _request(), _signature_response()),
        )
        for verifier, binding, valid in pairs:
            self.assertIsNotNone(verifier(binding, valid))
            variants = (None, [], DictSubclass(valid), {**valid, "unknown": None})
            for variant in variants:
                with (
                    self.subTest(verifier=verifier.__name__, value=variant),
                    self.assertRaises(GcpKmsEd25519Error),
                ):
                    verifier(binding, variant)
            for field_name in valid:
                omitted = dict(valid)
                omitted.pop(field_name)
                with self.subTest(omitted=field_name), self.assertRaises(GcpKmsEd25519Error):
                    verifier(binding, omitted)
            non_native_key = {TextSubclass(key): value for key, value in valid.items()}
            with self.assertRaises(GcpKmsEd25519Error):
                verifier(binding, non_native_key)

    def test_wrong_resource_or_protection_is_rejected_for_both_responses(self) -> None:
        wrong_names = (
            VERSION_NAME.replace("offline-fixture/", "foreign-project/", 1),
            VERSION_NAME.replace("us-west3", "us-west2"),
            VERSION_NAME.replace("keyRings/offline-fixtures", "keyRings/foreign"),
            VERSION_NAME.replace("cryptoKeys/assertion-fixture", "cryptoKeys/foreign"),
            VERSION_NAME[:-1] + "8",
            TextSubclass(VERSION_NAME),
        )
        pairs = (
            (verify_gcp_ed25519_public_key_response, _binding(), _public_response),
            (verify_gcp_ed25519_sign_response, _request(), _signature_response),
        )
        for verifier, binding, factory in pairs:
            for name in wrong_names:
                with self.subTest(name=name), self.assertRaises(GcpKmsEd25519Error):
                    verifier(binding, {**factory(), "name": name})
            for level in ("HSM", "EXTERNAL", "HSM_SINGLE_TENANT", TextSubclass("SOFTWARE")):
                with self.subTest(level=level), self.assertRaises(GcpKmsEd25519Error):
                    verifier(binding, {**factory(), "protectionLevel": level})

    def test_public_key_algorithm_and_alternative_formats_do_not_downgrade(self) -> None:
        valid = _public_response()
        for algorithm in (
            "EC_SIGN_P256_SHA256",
            "RSA_SIGN_PSS_2048_SHA256",
            TextSubclass("EC_SIGN_ED25519"),
        ):
            with self.subTest(algorithm=algorithm), self.assertRaises(GcpKmsEd25519Error):
                verify_gcp_ed25519_public_key_response(
                    _binding(), {**valid, "algorithm": algorithm}
                )
        for changes in (
            {"publicKeyFormat": "DER"},
            {"publicKeyFormat": None},
            {"publicKeyFormat": TextSubclass("PUBLIC_KEY_FORMAT_UNSPECIFIED")},
            {"publicKey": {"data": valid["pem"], "crc32cChecksum": valid["pemCrc32c"]}},
        ):
            with self.subTest(changes=changes), self.assertRaises(GcpKmsEd25519Error):
                verify_gcp_ed25519_public_key_response(_binding(), {**valid, **changes})

    def test_public_key_response_requires_independent_pin_and_unambiguous_spki(self) -> None:
        with self.assertRaisesRegex(GcpKmsEd25519Error, "independent public key pin"):
            verify_gcp_ed25519_public_key_response(
                _binding(), _public_response(public_key=_decode(OTHER_PUBLIC_KEY))
            )
        original = _public_response()["pem"]
        # A public X25519 SPKI has a different algorithm OID, with no private material.
        wrong_type = _pem(bytes.fromhex("302a300506032b656e032100") + _decode(PUBLIC_KEY))
        correct_der = base64.b64decode("".join(original.splitlines()[1:-1]))
        for pem in (
            original + original,
            original + "unbound text",
            "garbage",
            wrong_type,
            _pem(correct_der + b"\x00"),
        ):
            response = {
                **_public_response(),
                "pem": pem,
                "pemCrc32c": str(_crc32c(pem.encode("ascii"))),
            }
            with self.subTest(pem=pem), self.assertRaises(GcpKmsEd25519Error):
                verify_gcp_ed25519_public_key_response(_binding(), response)

    def test_public_key_size_and_crc_fail_before_der_decode(self) -> None:
        valid = _public_response()
        with patch.object(
            codec.serialization, "load_der_public_key", side_effect=AssertionError("must not parse")
        ):
            for pem in ("x" * (MAX_PUBLIC_KEY_PEM_CHARS + 1), TextSubclass(valid["pem"]), "\u00e9"):
                with self.subTest(kind=type(pem)), self.assertRaises(GcpKmsEd25519Error):
                    verify_gcp_ed25519_public_key_response(_binding(), {**valid, "pem": pem})
            with self.assertRaisesRegex(GcpKmsEd25519Error, "CRC32C mismatch"):
                verify_gcp_ed25519_public_key_response(_binding(), {**valid, "pemCrc32c": "0"})

    def test_crc_wire_values_are_exact_bounded_decimal_strings(self) -> None:
        pairs = (
            (verify_gcp_ed25519_public_key_response, _binding(), _public_response(), "pemCrc32c"),
            (
                verify_gcp_ed25519_sign_response,
                _request(),
                _signature_response(),
                "signatureCrc32c",
            ),
        )
        values = (True, 0, 1.0, None, "", "-1", "+1", "01", "1.0", " 1", "4294967296", "9" * 11)
        for verifier, binding, response, field_name in pairs:
            for value in (*values, TextSubclass(response[field_name])):
                with (
                    self.subTest(field=field_name, value=value),
                    self.assertRaises(GcpKmsEd25519Error),
                ):
                    verifier(binding, {**response, field_name: value})

    def test_signature_checksum_is_not_a_signature_authentication_substitute(self) -> None:
        raw = _decode(SIGNATURE)
        corrupt = raw[:-1] + bytes([raw[-1] ^ 1])
        with self.assertRaisesRegex(GcpKmsEd25519Error, "signature verification failed"):
            verify_gcp_ed25519_sign_response(_request(), _signature_response(signature=corrupt))
        with self.assertRaisesRegex(GcpKmsEd25519Error, "CRC32C mismatch"):
            verify_gcp_ed25519_sign_response(
                _request(), {**_signature_response(), "signatureCrc32c": "0"}
            )

    def test_signature_data_checksum_flag_is_native_true_and_digest_claim_is_rejected(self) -> None:
        valid = _signature_response()
        self.assertEqual(verify_gcp_ed25519_sign_response(_request(), valid), SIGNATURE)
        self.assertEqual(
            verify_gcp_ed25519_sign_response(_request(), {**valid, "verifiedDigestCrc32c": False}),
            SIGNATURE,
        )
        for value in (False, True + 0, 1.0, "true", None):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(GcpKmsEd25519Error, "exactly true"),
            ):
                verify_gcp_ed25519_sign_response(_request(), {**valid, "verifiedDataCrc32c": value})
        for value in (True, 0, 0.0, "false", None):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(GcpKmsEd25519Error, "digest signing"),
            ):
                verify_gcp_ed25519_sign_response(
                    _request(), {**valid, "verifiedDigestCrc32c": value}
                )

    def test_signature_encoding_and_length_are_closed_and_bounded(self) -> None:
        valid = _signature_response()
        values = (
            TextSubclass(valid["signature"]),
            SIGNATURE,
            "?" * 88,
            "A" * 89,
            valid["signature"] + "\n",
            valid["signature"].rstrip("="),
            base64.b64encode(bytes(63)).decode("ascii"),
            base64.b64encode(bytes(65)).decode("ascii"),
        )
        for value in values:
            with self.subTest(value=value), self.assertRaises(GcpKmsEd25519Error):
                verify_gcp_ed25519_sign_response(_request(), {**valid, "signature": value})

    def test_noncanonical_r_and_s_are_rejected_by_existing_strict_verifier(self) -> None:
        raw = _decode(SIGNATURE)
        order = (1 << 252) + 27742317777372353535851937790883648493
        variants = (
            bytes(32) + raw[32:],
            b"\x01" + bytes(31) + raw[32:],
            ((1 << 255) - 19).to_bytes(32, "little") + raw[32:],
            raw[:32] + order.to_bytes(32, "little"),
        )
        for signature in variants:
            with (
                self.subTest(signature=signature.hex()),
                self.assertRaisesRegex(GcpKmsEd25519Error, "strict canonical Ed25519"),
            ):
                verify_gcp_ed25519_sign_response(
                    _request(), _signature_response(signature=signature)
                )

    def test_prehashed_or_reserialized_inputs_cannot_replay_the_raw_signature(self) -> None:
        original = _assertion().signing_bytes()
        wrong_inputs = (
            hashlib.sha256(original).digest(),
            original.replace(b"PRINCIPAL-ASSERTION", b"OTHER-ASSERTION"),
            original + b"\n",
        )
        self.assertEqual(
            verify_gcp_ed25519_sign_response(_request(), _signature_response()), SIGNATURE
        )
        for signing_bytes in wrong_inputs:
            request = build_gcp_ed25519_sign_request(_binding(), signing_bytes)
            with (
                self.subTest(signing_bytes=signing_bytes),
                self.assertRaisesRegex(GcpKmsEd25519Error, "signature verification failed"),
            ):
                verify_gcp_ed25519_sign_response(request, _signature_response())

    def test_version_rotation_does_not_rebind_old_response_or_grant_current_authority(self) -> None:
        historical = _request()
        old_response = _signature_response()
        new_raw = _decode(OTHER_PUBLIC_KEY)
        new_binding = _binding(
            key_version_name=VERSION_NAME[:-1] + "8",
            public_key=new_raw,
            public_key_sha256=_fingerprint(new_raw),
        )
        current = build_gcp_ed25519_sign_request(new_binding, historical.signing_bytes)
        with self.assertRaisesRegex(GcpKmsEd25519Error, "pinned key version"):
            verify_gcp_ed25519_sign_response(current, old_response)
        with self.assertRaisesRegex(GcpKmsEd25519Error, "signature verification failed"):
            verify_gcp_ed25519_sign_response(
                current, {**old_response, "name": new_binding.key_version_name}
            )
        self.assertNotEqual(historical.request_sha256, current.request_sha256)
        result = verify_gcp_ed25519_sign_response(historical, old_response)
        self.assertEqual(result, SIGNATURE)
        self.assertIs(type(result), str)
        self.assertFalse(hasattr(result, "_proof_is_valid"))

    def test_request_subclasses_are_not_verification_seams(self) -> None:
        class SubclassRequest(GcpKmsEd25519SigningRequest):
            pass

        class SubclassBinding(GcpKmsEd25519KeyVersionBinding):
            pass

        binding = _binding()
        values = (
            binding.key_version_name,
            binding.algorithm,
            binding.protection_level,
            binding.public_key,
            binding.public_key_sha256,
        )
        with self.assertRaisesRegex(GcpKmsEd25519Error, "exact GcpKmsEd25519KeyVersionBinding"):
            build_gcp_ed25519_sign_request(SubclassBinding(*values), b"data")
        with self.assertRaisesRegex(GcpKmsEd25519Error, "exact GcpKmsEd25519SigningRequest"):
            verify_gcp_ed25519_sign_response(
                SubclassRequest(binding, b"data"), _signature_response()
            )
        self.assertEqual(replace(_request()).request_sha256, _request().request_sha256)

    def test_module_has_no_transport_sdk_key_generation_or_authorizing_calls(self) -> None:
        source = inspect.getsource(codec)
        tree = ast.parse(source)
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(imported & {"google", "requests", "http", "socket", "subprocess", "os"})
        called_names = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(
            called_names & {"generate", "sign", "from_private_bytes", "record_principal_use"}
        )
        self.assertNotIn("verify_principal_assertion", source)


if __name__ == "__main__":
    unittest.main()

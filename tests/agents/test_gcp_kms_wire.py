"""Fixed public-vector checks for inert KMS request and response-byte boundaries."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from http import HTTPStatus
from pathlib import Path
from unittest.mock import patch

from sunderkey import gcp_kms_wire as wire
from sunderkey.gcp_kms_ed25519 import (
    MAX_SIGNING_BYTES,
    GcpKmsEd25519KeyVersionBinding,
    GcpKmsEd25519SigningRequest,
    build_gcp_ed25519_sign_request,
)
from sunderkey.gcp_kms_wire import (
    MAX_JSON_DEPTH,
    MAX_RESPONSE_BYTES,
    GcpKmsWireError,
    GcpKmsWireRequest,
    encode_gcp_kms_public_key_request,
    encode_gcp_kms_sign_request,
    verify_gcp_kms_public_key_from_bytes,
    verify_gcp_kms_signature_from_bytes,
)

# Existing fixed public material and pure fixture builders, not signing services.
from tests.agents.test_gcp_kms_ed25519 import (
    INPUT_SHA256,
    OTHER_PUBLIC_KEY,
    SIGNATURE,
    VERSION_NAME,
    _assertion,
    _binding,
    _decode,
    _public_response,
    _request,
    _signature_response,
)

ROOT = Path(__file__).resolve().parents[2]


def _bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _verify_signature(
    request: GcpKmsWireRequest, body: bytes | None = None, status: int = 200
) -> str:
    return verify_gcp_kms_signature_from_bytes(
        request,
        status_code=status,
        response_bytes=_bytes(_signature_response()) if body is None else body,
    )


class GcpKmsWireTests(unittest.TestCase):
    def _assert_fixed_headers_are_bound(
        self, request: GcpKmsWireRequest, headers: dict[str, str]
    ) -> None:
        document = request.to_dict()
        self.assertEqual(document["headers"], headers)
        self.assertNotIn("Authorization", document["headers"])
        claimed = document.pop("wire_request_sha256")
        self.assertEqual(
            claimed,
            "sha256:"
            + hashlib.sha256(_bytes({"domain": wire.DOMAIN, "request": document})).hexdigest(),
        )
        document["headers"] = {}
        self.assertNotEqual(
            claimed,
            "sha256:"
            + hashlib.sha256(_bytes({"domain": wire.DOMAIN, "request": document})).hexdigest(),
        )

    def test_default_public_key_get_is_fixed_empty_and_locally_addressed(self) -> None:
        binding = _binding()
        request = encode_gcp_kms_public_key_request(binding)
        raw = request.to_dict()
        self.assertEqual(raw["method"], "GET")
        self.assertEqual(raw["origin"], "https://cloudkms.googleapis.com")
        self.assertEqual(raw["path"], "/v1/" + VERSION_NAME + "/publicKey")
        self.assertEqual(raw["url"], raw["origin"] + raw["path"])
        self.assertEqual(request.body_bytes, b"")
        self.assertEqual(raw["body_base64"], "")
        self._assert_fixed_headers_are_bound(request, {"Accept": "application/json"})
        self.assertEqual(raw["query_parameters"], {})
        self.assertIsNone(raw["signing_request_sha256"])
        self.assertIsNone(raw["signing_input_sha256"])
        self.assertIsNot(request.binding, binding)
        self.assertEqual(raw["body_sha256"], "sha256:" + hashlib.sha256(b"").hexdigest())
        self.assertEqual(request, encode_gcp_kms_public_key_request(_binding()))

    def test_post_preserves_original_raw_bytes_and_deterministic_body(self) -> None:
        source = _request()
        request = encode_gcp_kms_sign_request(source)
        raw = request.to_dict()
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/v1/" + VERSION_NAME + ":asymmetricSign")
        self._assert_fixed_headers_are_bound(
            request, {"Accept": "application/json", "Content-Type": "application/json"}
        )
        self.assertEqual(request.body_bytes, _bytes(source.to_rest_body()))
        body = json.loads(request.body_bytes)
        self.assertEqual(set(body), {"data", "dataCrc32c"})
        self.assertEqual(
            base64.b64decode(body["data"], validate=True), _assertion().signing_bytes()
        )
        self.assertEqual(request.signing_request.signing_bytes, source.signing_bytes)
        self.assertEqual(raw["signing_input_sha256"], INPUT_SHA256)
        self.assertEqual(raw["signing_request_sha256"], source.request_sha256)
        self.assertIsNot(request.signing_request, source)
        self.assertIsNot(request.signing_request.binding, source.binding)
        self.assertEqual(request, encode_gcp_kms_sign_request(_request()))
        self.assertNotEqual(
            request.wire_request_sha256,
            encode_gcp_kms_public_key_request(_binding()).wire_request_sha256,
        )

    def test_fixed_public_key_and_signature_verify_through_existing_crypto(self) -> None:
        get = encode_gcp_kms_public_key_request(_binding())
        post = encode_gcp_kms_sign_request(_request())
        public = verify_gcp_kms_public_key_from_bytes(
            get, status_code=200, response_bytes=_bytes(_public_response())
        )
        self.assertEqual(public, _binding().public_key)
        self.assertIs(type(public), bytes)
        signature = _verify_signature(post)
        self.assertEqual(signature, SIGNATURE)
        self.assertIs(type(signature), str)
        self.assertEqual(_verify_signature(post), signature)
        self.assertEqual(set(post.to_dict()["effects"].values()), {"none"})
        self.assertIs(post.to_dict()["dispatch_performed"], False)

    def test_supported_optional_default_format_and_raw_crc_flag(self) -> None:
        response = _public_response()
        response["publicKeyFormat"] = "PUBLIC_KEY_FORMAT_UNSPECIFIED"
        self.assertEqual(
            verify_gcp_kms_public_key_from_bytes(
                encode_gcp_kms_public_key_request(_binding()),
                status_code=200,
                response_bytes=_bytes(response),
            ),
            _binding().public_key,
        )
        response = _signature_response()
        response["verifiedDigestCrc32c"] = False
        self.assertEqual(
            _verify_signature(encode_gcp_kms_sign_request(_request()), _bytes(response)), SIGNATURE
        )

    def test_non_200_status_rejects_without_parsing_body_or_suggesting_retry(self) -> None:
        get = encode_gcp_kms_public_key_request(_binding())
        post = encode_gcp_kms_sign_request(_request())
        secret_error = b'{"error":{"message":"untrusted-secret-retry-instruction"}}'
        for status in (
            100,
            201,
            202,
            204,
            206,
            301,
            302,
            303,
            307,
            308,
            400,
            401,
            403,
            404,
            429,
            500,
            503,
            599,
        ):
            for function, request in (
                (verify_gcp_kms_public_key_from_bytes, get),
                (verify_gcp_kms_signature_from_bytes, post),
            ):
                with (
                    self.subTest(status=status, function=function.__name__),
                    patch.object(wire, "_response_object") as parser,
                ):
                    with self.assertRaises(GcpKmsWireError) as raised:
                        function(request, status_code=status, response_bytes=secret_error)
                    parser.assert_not_called()
                    self.assertNotIn("secret", str(raised.exception))
                    self.assertNotIn("retry", str(raised.exception).lower())

    def test_status_requires_exact_native_integer(self) -> None:
        class Integer(int):
            pass

        for status in (True, False, 200.0, "200", HTTPStatus.OK, Integer(200), None):
            with self.subTest(status=status), self.assertRaises(GcpKmsWireError):
                _verify_signature(encode_gcp_kms_sign_request(_request()), status=status)

    def test_conflicting_and_identical_duplicate_names_crc_and_flags_reject(self) -> None:
        post = encode_gcp_kms_sign_request(_request())
        good = _bytes(_signature_response())
        for prefix in (
            b'"name":"foreign",',
            b'"name":' + _bytes(VERSION_NAME) + b",",
            b'"signatureCrc32c":"0",',
            b'"verifiedDataCrc32c":false,',
            b'"\\u006eame":"foreign",',
        ):
            with (
                self.subTest(prefix=prefix),
                self.assertRaisesRegex(GcpKmsWireError, "duplicate keys"),
            ):
                _verify_signature(post, b"{" + prefix + good[1:])
        get = encode_gcp_kms_public_key_request(_binding())
        good = _bytes(_public_response())
        with self.assertRaisesRegex(GcpKmsWireError, "duplicate keys"):
            verify_gcp_kms_public_key_from_bytes(
                get, status_code=200, response_bytes=b'{"pemCrc32c":"0",' + good[1:]
            )

    def test_duplicate_keys_at_nested_unsupported_positions_still_reject(self) -> None:
        good = _bytes(_signature_response())
        for prefix in (
            b'"extra":{"x":1,"x":2},',
            b'"extra":[{"x":false,"x":true}],',
            b'"extra":{"inner":{"x":"a","\\u0078":"b"}},',
        ):
            with (
                self.subTest(prefix=prefix),
                self.assertRaisesRegex(GcpKmsWireError, "duplicate keys"),
            ):
                _verify_signature(encode_gcp_kms_sign_request(_request()), b"{" + prefix + good[1:])

    def test_floats_nonfinite_and_large_integer_json_are_rejected(self) -> None:
        good = _bytes(_signature_response())
        for number in (
            b"1.0",
            b"1e0",
            b"NaN",
            b"Infinity",
            b"-Infinity",
            b"9223372036854775808",
            b"1" * 100,
        ):
            with self.subTest(number=number), self.assertRaises(GcpKmsWireError):
                _verify_signature(
                    encode_gcp_kms_sign_request(_request()), b'{"extra":' + number + b"," + good[1:]
                )

    def test_crc_and_flags_cannot_use_native_json_aliases(self) -> None:
        for field, value in (
            ("signatureCrc32c", 1),
            ("signatureCrc32c", True),
            ("signatureCrc32c", "01"),
            ("verifiedDataCrc32c", 1),
            ("verifiedDataCrc32c", "true"),
            ("verifiedDataCrc32c", False),
            ("verifiedDigestCrc32c", True),
            ("verifiedDigestCrc32c", 0),
        ):
            response = _signature_response()
            response[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(GcpKmsWireError):
                _verify_signature(encode_gcp_kms_sign_request(_request()), _bytes(response))

    def test_response_fields_and_default_public_key_mode_remain_closed(self) -> None:
        for field, value in (
            ("digest", {}),
            ("error", {"message": "ignore"}),
            ("authorization", "unsupported"),
        ):
            response = _signature_response()
            response[field] = value
            with self.subTest(field=field), self.assertRaises(GcpKmsWireError):
                _verify_signature(encode_gcp_kms_sign_request(_request()), _bytes(response))
        for field, value in (
            ("publicKeyFormat", "PEM"),
            ("publicKey", {"data": "ignored", "crc32cChecksum": "0"}),
            ("algorithm", "EC_SIGN_P256_SHA256"),
        ):
            response = _public_response()
            response[field] = value
            with self.subTest(field=field), self.assertRaises(GcpKmsWireError):
                verify_gcp_kms_public_key_from_bytes(
                    encode_gcp_kms_public_key_request(_binding()),
                    status_code=200,
                    response_bytes=_bytes(response),
                )

    def test_response_bytes_reject_aliases_invalid_encoding_empty_and_oversize(self) -> None:
        class Bytes(bytes):
            pass

        good = _bytes(_signature_response())
        for body in (
            b"",
            Bytes(good),
            bytearray(good),
            memoryview(good),
            good.decode(),
            None,
            b"\xff",
            b"\xef\xbb\xbf" + good,
            good.decode().encode("utf-16"),
            good + b"{}",
            b"[]",
            b"true",
            b'"text"',
            b" " * (MAX_RESPONSE_BYTES + 1),
        ):
            with self.subTest(body=repr(body)[:50]), self.assertRaises(GcpKmsWireError):
                verify_gcp_kms_signature_from_bytes(
                    encode_gcp_kms_sign_request(_request()), status_code=200, response_bytes=body
                )

    def test_exact_response_byte_bound_and_semantic_whitespace_are_supported(self) -> None:
        request = encode_gcp_kms_sign_request(_request())
        body = _bytes(_signature_response())
        padded = body + b" " * (MAX_RESPONSE_BYTES - len(body))
        self.assertEqual(_verify_signature(request, padded), SIGNATURE)
        with self.assertRaises(GcpKmsWireError):
            _verify_signature(request, padded + b" ")
        pretty = json.dumps(dict(reversed(list(_signature_response().items()))), indent=2).encode()
        self.assertEqual(_verify_signature(request, pretty), SIGNATURE)

    def test_deep_node_heavy_and_large_string_responses_fail_before_crypto(self) -> None:
        request = encode_gcp_kms_sign_request(_request())
        bodies = (
            b'{"extra":' + b"[" * MAX_JSON_DEPTH + b"0" + b"]" * MAX_JSON_DEPTH + b"}",
            _bytes({"extra": [None] * wire.MAX_JSON_NODES}),
            _bytes({"extra": "x" * (wire.MAX_JSON_STRING_CHARS + 1)}),
            _bytes({"extra": "\u00e9"}),
        )
        for body in bodies:
            with (
                self.subTest(body=body[:40]),
                patch.object(wire, "verify_gcp_ed25519_sign_response") as verifier,
            ):
                with self.assertRaises(GcpKmsWireError):
                    _verify_signature(request, body)
                verifier.assert_not_called()
        with self.assertRaisesRegex(GcpKmsWireError, "field bound"):
            _verify_signature(
                request, _bytes({str(index): None for index in range(wire.MAX_JSON_FIELDS + 1)})
            )

    def test_depth_scanner_does_not_count_escaped_string_brackets(self) -> None:
        raw = {"extra": "[" * 100 + '"\\' + "}" * 100}
        self.assertEqual(wire._response_object(_bytes(raw)), raw)
        request = encode_gcp_kms_sign_request(_request())
        response = {**_signature_response(), **raw}
        with self.assertRaisesRegex(GcpKmsWireError, "failed local verification"):
            _verify_signature(request, _bytes(response))

    def test_request_source_boundaries_reject_wrong_types_and_native_aliases(self) -> None:
        class Binding(GcpKmsEd25519KeyVersionBinding):
            pass

        class Signing(GcpKmsEd25519SigningRequest):
            pass

        binding = _binding()
        subclass = Binding(
            binding.key_version_name,
            binding.algorithm,
            binding.protection_level,
            binding.public_key,
            binding.public_key_sha256,
        )
        with self.assertRaises(GcpKmsWireError):
            encode_gcp_kms_public_key_request(subclass)
        for source in (None, {}, Signing(_binding(), _request().signing_bytes)):
            with self.subTest(source=type(source).__name__), self.assertRaises(GcpKmsWireError):
                encode_gcp_kms_sign_request(source)
        for operation in ("GET", "sign", True):
            with self.subTest(operation=operation), self.assertRaises(GcpKmsWireError):
                GcpKmsWireRequest(operation, _binding())
        with self.assertRaises(GcpKmsWireError):
            GcpKmsWireRequest("get_public_key", _binding(), _request())
        with self.assertRaises(GcpKmsWireError):
            GcpKmsWireRequest("asymmetric_sign", _binding(), None)

    def test_frozen_descriptor_has_no_endpoint_headers_or_retry_override(self) -> None:
        request = encode_gcp_kms_sign_request(_request())
        with self.assertRaises(FrozenInstanceError):
            request.origin = "https://elsewhere.example"
        for kwargs in (
            {"origin": "https://elsewhere.example"},
            {"headers": {"Authorization": "not-permitted"}},
            {"retries": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(TypeError):
                GcpKmsWireRequest("get_public_key", _binding(), **kwargs)
        with self.assertRaises(TypeError):
            encode_gcp_kms_public_key_request(_binding(), endpoint="https://elsewhere.example")

    def test_late_descriptor_field_mutation_rejects_export_and_response(self) -> None:
        class Text(str):
            pass

        mutations = (
            ("method", "GET"),
            ("origin", "https://elsewhere.example"),
            ("origin", Text(wire.ORIGIN)),
            ("path", "/v1/foreign:asymmetricSign"),
            ("body_bytes", b"{}"),
            ("body_bytes", bytearray(b"{}")),
            ("body_sha256", "sha256:" + "0" * 64),
            ("wire_request_sha256", "sha256:" + "0" * 64),
        )
        for field, value in mutations:
            request = encode_gcp_kms_sign_request(_request())
            object.__setattr__(request, field, value)
            with self.subTest(field=field), self.assertRaises(GcpKmsWireError):
                request.to_dict()
            with self.subTest(field=field, boundary="consume"), self.assertRaises(GcpKmsWireError):
                _verify_signature(request)

        for field in ("operation", "origin", "wire_request_sha256"):
            request = encode_gcp_kms_sign_request(_request())
            object.__delattr__(request, field)
            with self.subTest(field=field, boundary="missing"), self.assertRaises(GcpKmsWireError):
                request.to_dict()
            with (
                self.subTest(field=field, boundary="missing-consume"),
                self.assertRaises(GcpKmsWireError),
            ):
                _verify_signature(request)

    def test_late_signing_source_and_pin_mutation_rejects_every_boundary(self) -> None:
        for field, value in (
            ("signing_bytes", b"changed"),
            ("data_crc32c", True),
            ("request_sha256", "sha256:" + "0" * 64),
            ("signing_input_sha256", "sha256:" + "0" * 64),
        ):
            source = _request()
            object.__setattr__(source, field, value)
            with self.subTest(field=field), self.assertRaises(GcpKmsWireError):
                encode_gcp_kms_sign_request(source)
            request = encode_gcp_kms_sign_request(_request())
            object.__setattr__(request.signing_request, field, value)
            with self.subTest(field=field, boundary="consume"), self.assertRaises(GcpKmsWireError):
                _verify_signature(request)
        get = encode_gcp_kms_public_key_request(_binding())
        object.__setattr__(get.binding, "public_key_sha256", "sha256:" + "0" * 64)
        with self.assertRaises(GcpKmsWireError):
            verify_gcp_kms_public_key_from_bytes(
                get, status_code=200, response_bytes=_bytes(_public_response())
            )

    def test_owned_caller_material_and_detached_exports_do_not_change_request(self) -> None:
        source = _request()
        before = source.to_dict()
        request = encode_gcp_kms_sign_request(source)
        self.assertEqual(source.to_dict(), before)
        exported = request.to_dict()
        exported["headers"]["Authorization"] = "synthetic-invalid"
        exported["binding"]["key_version_name"] = "foreign"
        exported["effects"]["network"] = "allowed"
        object.__setattr__(source, "request_sha256", "sha256:" + "0" * 64)
        self.assertEqual(
            request.to_dict()["headers"],
            {"Accept": "application/json", "Content-Type": "application/json"},
        )
        self.assertEqual(set(request.to_dict()["effects"].values()), {"none"})
        self.assertEqual(_verify_signature(request), SIGNATURE)

    def test_response_version_protection_public_key_and_crc_substitution_rejects(self) -> None:
        request = encode_gcp_kms_sign_request(_request())
        with self.assertRaises(GcpKmsWireError):
            _verify_signature(request, _bytes(_signature_response(signature=bytes(64))))
        for field, value in (
            ("name", VERSION_NAME.rsplit("/", 1)[0] + "/8"),
            ("protectionLevel", "HSM"),
            ("signatureCrc32c", "0"),
        ):
            response = _signature_response()
            response[field] = value
            with self.subTest(field=field), self.assertRaises(GcpKmsWireError):
                _verify_signature(request, _bytes(response))
        changed = replace(_binding(), key_version_name=VERSION_NAME.rsplit("/", 1)[0] + "/8")
        with self.assertRaises(GcpKmsWireError):
            _verify_signature(
                encode_gcp_kms_sign_request(
                    build_gcp_ed25519_sign_request(changed, _request().signing_bytes)
                )
            )
        other = _decode(OTHER_PUBLIC_KEY)
        binding = _binding(
            public_key=other, public_key_sha256="sha256:" + hashlib.sha256(other).hexdigest()
        )
        with self.assertRaises(GcpKmsWireError):
            verify_gcp_kms_public_key_from_bytes(
                encode_gcp_kms_public_key_request(binding),
                status_code=200,
                response_bytes=_bytes(_public_response()),
            )
        with self.assertRaises(GcpKmsWireError):
            _verify_signature(
                encode_gcp_kms_sign_request(
                    build_gcp_ed25519_sign_request(binding, _request().signing_bytes)
                )
            )

    def test_prehash_wrong_domain_and_modified_bytes_cannot_replay_fixed_signature(self) -> None:
        original = _request().signing_bytes
        for data in (
            hashlib.sha256(original).digest(),
            original + b"\n",
            original.split(b"\x00", 3)[-1],
        ):
            request = encode_gcp_kms_sign_request(build_gcp_ed25519_sign_request(_binding(), data))
            with self.subTest(length=len(data)), self.assertRaises(GcpKmsWireError):
                _verify_signature(request)

    def test_wrong_operation_and_descriptor_subclass_consumers_are_rejected(self) -> None:
        get = encode_gcp_kms_public_key_request(_binding())
        post = encode_gcp_kms_sign_request(_request())
        with self.assertRaises(GcpKmsWireError):
            _verify_signature(get)
        with self.assertRaises(GcpKmsWireError):
            verify_gcp_kms_public_key_from_bytes(
                post, status_code=200, response_bytes=_bytes(_public_response())
            )

        class Description(GcpKmsWireRequest):
            pass

        with self.assertRaises(GcpKmsWireError):
            _verify_signature(Description("asymmetric_sign", _binding(), _request()))

    def test_existing_full_signing_capacity_is_preserved(self) -> None:
        data = bytes(range(256)) * (MAX_SIGNING_BYTES // 256)
        source = build_gcp_ed25519_sign_request(_binding(), data)
        request = encode_gcp_kms_sign_request(source)
        self.assertEqual(base64.b64decode(json.loads(request.body_bytes)["data"]), data)
        self.assertEqual(
            request.signing_request.signing_input_sha256,
            "sha256:" + hashlib.sha256(data).hexdigest(),
        )
        self.assertEqual(
            request.to_dict()["body_base64"], base64.b64encode(request.body_bytes).decode()
        )

    def test_module_and_accounted_public_fixtures_have_no_dispatch_or_private_keys(self) -> None:
        source_path = ROOT / "src/sunderkey/gcp_kms_wire.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertEqual(imports, {"base64", "hashlib", "json"})
        calls = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, (ast.Attribute, ast.Name))
        }
        self.assertFalse(
            calls.intersection(
                {
                    "open",
                    "execute",
                    "dispatch",
                    "connect",
                    "urlopen",
                    "request",
                    "sign",
                    "generate_private_key",
                    "getenv",
                }
            )
        )
        fixture_path = ROOT / "tests/agents/test_gcp_kms_ed25519.py"
        fixture_tree = ast.parse(fixture_path.read_text(encoding="utf-8"))
        fixture_calls = {
            node.func.attr
            for node in ast.walk(fixture_tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(
            fixture_calls.intersection({"generate_private_key", "sign", "private_bytes"})
        )
        for path in (source_path, Path(__file__), ROOT / "docs/gcp-kms-wire-offline.md"):
            self.assertTrue(path.read_text(encoding="utf-8").isascii())


if __name__ == "__main__":
    unittest.main()

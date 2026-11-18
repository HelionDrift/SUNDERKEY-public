"""Real disposable signature math and nonauthoritative supplied-source replay."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from datetime import UTC, datetime
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from sunderkey import offline_jose_analysis as jose

NOW = "2026-09-28T12:00:00Z"
EPOCH = int(datetime(2026, 9, 28, 12, tzinfo=UTC).timestamp())
ISSUER = "https://issuer.example.test"
AUDIENCE = "sunderkey-synthetic"
KEY_ID = "synthetic-public-key"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _uint(value: int) -> str:
    return _b64(value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big"))


def _ec_key():
    """Public synthetic fixture key; not operational key material."""
    return ec.derive_private_key(1, ec.SECP256R1())


def _claims() -> dict:
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": EPOCH - 60,
        "nbf": EPOCH - 60,
        "exp": EPOCH + 3600,
        "sub": "opaque-synthetic-subject-not-retained",
        "custom": ["opaque-synthetic-content-not-retained"],
    }


def _model(
    *, key=None, algorithm="ES256", claims=None, header=None, raw_header=None, raw_claims=None
):
    key = _ec_key() if key is None else key
    header = {"alg": algorithm, "kid": KEY_ID, "typ": "JWT"} if header is None else header
    claims = _claims() if claims is None else claims
    header_bytes = (
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if raw_header is None
        else raw_header
    )
    claims_bytes = (
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if raw_claims is None
        else raw_claims
    )
    first, second = _b64(header_bytes), _b64(claims_bytes)
    signing_input = (first + "." + second).encode("ascii")
    if algorithm == "ES256":
        encoded = key.sign(signing_input, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = utils.decode_dss_signature(encoded)
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        numbers = key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64(numbers.x.to_bytes(32, "big")),
            "y": _b64(numbers.y.to_bytes(32, "big")),
        }
    else:
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        numbers = key.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": _uint(numbers.n), "e": _uint(numbers.e)}
    jwk.update({"alg": algorithm, "kid": KEY_ID, "use": "sig", "key_ops": ["verify"]})
    return {
        "schema_version": 1,
        "compact_jws": first + "." + second + "." + _b64(signature),
        "public_jwk": jwk,
        "expected_algorithm": algorithm,
        "expected_issuer": ISSUER,
        "expected_audience": AUDIENCE,
        "evaluated_at": NOW,
    }


def component_fixture() -> dict:
    """Return a deterministic public-only synthetic compact JWS model."""
    return _model()


def _addressed(document: dict) -> dict:
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    raw = json.dumps(
        {"domain": "sunderkey.offline-jose-analysis.v1", "analysis": body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    return {
        **body,
        "analysis_id": "JSA-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class SuppliedJoseAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def analyze(self, model=None):
        return jose.analyze_supplied_jose(component_fixture() if model is None else model)

    def denied_before_key(self, model):
        with (
            mock.patch.object(
                jose, "_public_key", side_effect=AssertionError("must not construct key")
            ),
            self.assertRaises(jose.JoseAnalysisError),
        ):
            self.analyze(model)

    def test_deterministic_public_fixture_matches_literal_identity(self):
        first, second = component_fixture(), component_fixture()
        self.assertEqual(first, second)
        report = self.analyze(first)
        document = report.to_dict()
        self.assertEqual("JSA-E43CE88970BF7CB436F43ECECBA1FEE9", document["analysis_id"])
        self.assertEqual(
            "sha256:e43ce88970bf7cb436f43ececba1fee9bfab16d959fde497b1da2955f16b164d",
            document["analysis_sha256"],
        )
        self.assertEqual(
            {
                "compact_jws_bytes": 447,
                "compact_jws_sha256": (
                    "sha256:bf9a4c29192f7a124069d428c66222ac7dc19e7853a2773c0c619495a6cc7c28"
                ),
                "model_sha256": (
                    "sha256:53f901bc0be8dd68207a5c3d8ce21a7c72993b2b8a6d52328ce79d2c404726ec"
                ),
                "public_jwk_sha256": (
                    "sha256:5bb0a28ecf857ae46fa0f4094c4eb56aefaf42499db13e5dda03109274e6fe83"
                ),
            },
            document["sources"],
        )
        self.assertEqual("consistent_with_supplied_checks", document["analysis_status"])
        self.assertEqual("valid", document["checks"]["signature"])
        self.assertEqual("match", document["checks"]["issuer"])
        self.assertEqual("match", document["checks"]["audience"])
        self.assertEqual(64, document["statistics"]["signature_bytes"])
        self.assertEqual({"kty": "EC", "curve": "P-256", "bits": 256}, document["key"])
        self.assertEqual(
            report.to_json(), jose.verify_supplied_jose_analysis(report, model=first).to_json()
        )

    def test_rsa_signature_math_is_real_and_invalid_signature_remains_an_observation(self):
        model = _model(key=self.rsa_key, algorithm="RS256")
        report = self.analyze(model)
        self.assertEqual("valid", report.to_dict()["checks"]["signature"])
        first, second, signature = model["compact_jws"].split(".")
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        model["compact_jws"] = first + "." + second + "." + _b64(bytes([raw[0] ^ 1]) + raw[1:])
        changed = self.analyze(model).to_dict()
        self.assertEqual("invalid", changed["checks"]["signature"])
        self.assertEqual("match", changed["checks"]["issuer"])
        self.assertEqual("mismatch", changed["analysis_status"])

    def test_real_rsa_non_octet_key_width_uses_the_ceiling_and_upper_bound_is_supported(self):
        for bits in (2050, 4096):
            with self.subTest(bits=bits):
                key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
                model = _model(key=key, algorithm="RS256")
                document = self.analyze(model).to_dict()
                self.assertEqual(bits, document["key"]["bits"])
                self.assertEqual((bits + 7) // 8, document["statistics"]["signature_bytes"])
                self.assertEqual("valid", document["checks"]["signature"])
                self.assertFalse(document["key_origin_authenticated"])

    def test_valid_different_public_point_is_a_signature_mismatch_not_key_trust(self):
        model = component_fixture()
        other = ec.derive_private_key(2, ec.SECP256R1()).public_key().public_numbers()
        model["public_jwk"]["x"] = _b64(other.x.to_bytes(32, "big"))
        model["public_jwk"]["y"] = _b64(other.y.to_bytes(32, "big"))
        document = self.analyze(model).to_dict()
        self.assertEqual("invalid", document["checks"]["signature"])
        self.assertEqual("match", document["checks"]["issuer"])
        self.assertEqual("mismatch", document["analysis_status"])
        self.assertFalse(document["issuer_authenticated"])
        self.assertFalse(document["key_origin_authenticated"])

    def test_high_s_and_low_s_are_both_valid_without_a_replay_or_uniqueness_claim(self):
        model = component_fixture()
        first, second, signature = model["compact_jws"].split(".")
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        r, value = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        order = ec.SECP256R1().group_order
        reports = []
        for s in (min(value, order - value), max(value, order - value)):
            changed = copy.deepcopy(model)
            changed["compact_jws"] = (
                first + "." + second + "." + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
            )
            report = self.analyze(changed)
            self.assertEqual("valid", report.to_dict()["checks"]["signature"])
            self.assertFalse(report.to_dict()["replay_prevention_verified"])
            self.assertEqual(
                report.to_json(),
                jose.verify_supplied_jose_analysis(report, model=changed).to_json(),
            )
            reports.append(report.to_dict()["analysis_id"])
        self.assertNotEqual(*reports)

    def test_exact_es256_raw_signature_length_and_scalar_range(self):
        model = component_fixture()
        first, second, _ = model["compact_jws"].split(".")
        for raw in (b"\0" * 63, b"\0" * 65, utils.encode_dss_signature(1, 1)):
            changed = {**model, "compact_jws": first + "." + second + "." + _b64(raw)}
            with self.subTest(length=len(raw)), self.assertRaises(jose.JoseAnalysisError):
                self.analyze(changed)
        for r, s in (
            (0, 1),
            (1, 0),
            (ec.SECP256R1().group_order, 1),
            (1, ec.SECP256R1().group_order),
        ):
            changed = {
                **model,
                "compact_jws": first
                + "."
                + second
                + "."
                + _b64(r.to_bytes(32, "big") + s.to_bytes(32, "big")),
            }
            self.assertEqual("invalid", self.analyze(changed).to_dict()["checks"]["signature"])

    def test_signature_validation_uses_original_noncanonical_json_bytes(self):
        raw = json.dumps(_claims(), indent=2).encode("utf-8") + b"\n"
        model = _model(raw_claims=raw, raw_header=b'{ "typ": "JWT", "alg": "ES256" }')
        self.assertEqual("valid", self.analyze(model).to_dict()["checks"]["signature"])
        first, _, signature = model["compact_jws"].split(".")
        changed = {
            **model,
            "compact_jws": first
            + "."
            + _b64(json.dumps(_claims(), separators=(",", ":")).encode())
            + "."
            + signature,
        }
        self.assertEqual("invalid", self.analyze(changed).to_dict()["checks"]["signature"])

    def test_algorithm_key_type_and_curve_confusion_never_negotiate(self):
        for algorithm in ("none", "HS256", "ES384", "RS512", True, 1):
            model = component_fixture()
            model["expected_algorithm"] = algorithm
            self.denied_before_key(model)
        for header in ({"alg": "none"}, {"alg": "HS256"}, {"alg": "RS256"}, {"alg": True}):
            self.denied_before_key(_model(header=header))
        for values in ({"kty": "RSA"}, {"crv": "P-384"}, {"kty": "oct"}, {"crv": True}):
            model = component_fixture()
            model["public_jwk"].update(values)
            with self.subTest(values=values), self.assertRaises(jose.JoseAnalysisError):
                self.analyze(model)

    def test_private_symmetric_or_discovery_key_members_are_not_accepted(self):
        for name in ("d", "p", "q", "dp", "dq", "qi", "oth", "k", "jku", "x5u", "x5c", "jwk"):
            model = component_fixture()
            model["public_jwk"][name] = "synthetic-unsupported-input"
            with self.subTest(name=name), self.assertRaises(jose.JoseAnalysisError):
                self.analyze(model)

    def test_header_key_pointers_critical_extensions_and_types_are_denied_before_key(self):
        for name, value in (
            ("jku", "https://example.test/never-fetched"),
            ("jwk", {}),
            ("x5u", "https://example.test/no"),
            ("x5c", []),
            ("crit", ["custom"]),
            ("b64", False),
            ("cty", "JWT"),
        ):
            self.denied_before_key(_model(header={"alg": "ES256", name: value}))
        for typ in ("at+jwt", "JWE", True, None):
            self.denied_before_key(_model(header={"alg": "ES256", "typ": typ}))

    def test_public_jwk_metadata_and_paired_key_ids_are_exact(self):
        for name, value in (
            ("alg", "RS256"),
            ("use", "enc"),
            ("key_ops", ["sign"]),
            ("key_ops", ["verify", "verify"]),
            ("kid", "unselected-key"),
        ):
            model = component_fixture()
            model["public_jwk"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(jose.JoseAnalysisError):
                self.analyze(model)
        model = _model(header={"alg": "ES256"})
        for name in ("alg", "use", "key_ops", "kid"):
            model["public_jwk"].pop(name)
        self.assertEqual("valid", self.analyze(model).to_dict()["checks"]["signature"])

    def test_ec_coordinate_width_canonical_encoding_and_real_point_validation(self):
        for name, value in (
            ("x", _b64(b"\0" * 31)),
            ("x", _b64(b"\0" * 33)),
            ("y", _b64(b"\xff" * 32)),
            ("x", "A"),
            ("x", "===="),
        ):
            model = component_fixture()
            model["public_jwk"][name] = value
            with self.subTest(name=name), self.assertRaises(jose.JoseAnalysisError):
                self.analyze(model)

    def test_rsa_minimal_integer_and_finite_key_bounds(self):
        model = _model(key=self.rsa_key, algorithm="RS256")
        numbers = self.rsa_key.public_key().public_numbers()
        cases = (
            ("n", _b64(b"\0" + numbers.n.to_bytes(256, "big"))),
            ("n", _uint((1 << 2046) + 1)),
            ("n", _uint((1 << 4096) + 1)),
            ("n", _uint(numbers.n - 1)),
            ("e", "AA"),
            ("e", _uint(2)),
            ("e", _uint(1 << 32)),
            ("e", _b64(b"\0\x01\x00\x01")),
        )
        for name, value in cases:
            changed = copy.deepcopy(model)
            changed["public_jwk"][name] = value
            with (
                self.subTest(name=name, length=len(value)),
                self.assertRaises(jose.JoseAnalysisError),
            ):
                self.analyze(changed)

    def test_issuer_and_audience_match_does_not_authenticate_the_declared_issuer(self):
        for claims, check in (
            ({**_claims(), "iss": ISSUER.upper()}, "issuer"),
            ({**_claims(), "aud": "unselected"}, "audience"),
        ):
            document = self.analyze(_model(claims=claims)).to_dict()
            self.assertEqual("valid", document["checks"]["signature"])
            self.assertEqual("mismatch", document["checks"][check])
            self.assertEqual("mismatch", document["analysis_status"])
            self.assertFalse(document["issuer_authenticated"])
        claims = {**_claims(), "aud": ["other", AUDIENCE]}
        self.assertEqual(
            "match", self.analyze(_model(claims=claims)).to_dict()["checks"]["audience"]
        )

    def test_registered_claim_type_and_missing_coverage_are_not_generic_jwt_validity(self):
        for name in ("iss", "aud", "exp"):
            claims = _claims()
            claims.pop(name)
            document = self.analyze(_model(claims=claims)).to_dict()
            self.assertEqual("incomplete", document["analysis_status"])
            self.assertEqual("valid", document["checks"]["signature"])
        for name, value in (
            ("iss", 1),
            ("iss", ""),
            ("aud", True),
            ("aud", []),
            ("aud", [AUDIENCE, AUDIENCE]),
            ("aud", [AUDIENCE, 1]),
        ):
            document = self.analyze(_model(claims={**_claims(), name: value})).to_dict()
            self.assertEqual(
                "invalid_type", document["checks"]["issuer" if name == "iss" else "audience"]
            )
            self.assertEqual("mismatch", document["analysis_status"])

    def test_half_open_time_checks_and_caller_declared_evaluation_instant(self):
        for name, value, expected in (
            ("exp", EPOCH, "expired"),
            ("exp", EPOCH + 1, "before_expiration"),
            ("nbf", EPOCH, "reached"),
            ("nbf", EPOCH + 1, "not_reached"),
            ("iat", EPOCH, "not_future"),
            ("iat", EPOCH + 1, "future"),
        ):
            field = {"exp": "expiration", "nbf": "not_before", "iat": "issued_at"}[name]
            document = self.analyze(_model(claims={**_claims(), name: value})).to_dict()
            self.assertEqual(expected, document["checks"][field])
            self.assertFalse(document["live_use_approved"])
        claims = _claims()
        claims.pop("iat")
        claims.pop("nbf")
        document = self.analyze(_model(claims=claims)).to_dict()
        self.assertEqual("not_present", document["checks"]["issued_at"])
        self.assertEqual("not_present", document["checks"]["not_before"])
        self.assertEqual("consistent_with_supplied_checks", document["analysis_status"])

    def test_explicit_date_chronology_is_a_profile_check(self):
        for name in ("nbf", "iat"):
            document = self.analyze(_model(claims={**_claims(), name: EPOCH + 3600})).to_dict()
            self.assertEqual("contradictory", document["checks"]["date_order"])
            self.assertEqual("mismatch", document["analysis_status"])

    def test_fractional_dates_are_unsupported_not_a_universal_jwt_malformation(self):
        for name in ("exp", "iat", "nbf"):
            for value in (float(EPOCH), True, "1760000000", -1, jose.MAX_EPOCH + 1):
                model = _model(claims={**_claims(), name: value})
                with self.subTest(name=name, value=value):
                    self.denied_before_key(model)

    def test_duplicate_json_members_and_nonfinite_are_rejected_before_key(self):
        for header in (b'{"alg":"ES256","alg":"ES256"}', b'{"alg":"ES256","kid":"x","kid":"x"}'):
            self.denied_before_key(_model(raw_header=header))
        for claims in (
            b'{"iss":"first","iss":"second"}',
            b'{"exp":NaN}',
            b'{"exp":Infinity}',
            b'{"exp":' + b"9" * 10000 + b"}",
        ):
            self.denied_before_key(_model(raw_claims=claims))

    def test_compact_serialization_and_b64url_are_exact(self):
        model = component_fixture()
        for token in (
            "a.b",
            "a.b.c.d",
            ".b.c",
            "a..c",
            "a.b.",
            " " + model["compact_jws"],
            model["compact_jws"] + "=",
            model["compact_jws"] + "\n",
            "a/+.b.c",
            "A" * (jose.MAX_COMPACT_BYTES + 1),
        ):
            with self.subTest(length=len(token)), self.assertRaises(jose.JoseAnalysisError):
                self.analyze({**model, "compact_jws": token})
        first, second, signature = model["compact_jws"].split(".")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        index = alphabet.index(signature[-1])
        noncanonical = signature[:-1] + alphabet[index + 1]
        with self.assertRaisesRegex(jose.JoseAnalysisError, "canonical"):
            self.analyze({**model, "compact_jws": first + "." + second + "." + noncanonical})

    def test_native_model_scalar_and_collection_aliases_precede_hash_and_key(self):
        class StringAlias(str):
            pass

        class IntAlias(int):
            pass

        class DictAlias(dict):
            pass

        class ListAlias(list):
            pass

        cases = []
        for name, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("schema_version", IntAlias(1)),
            ("compact_jws", StringAlias(component_fixture()["compact_jws"])),
            ("public_jwk", DictAlias(component_fixture()["public_jwk"])),
        ):
            model = component_fixture()
            model[name] = value
            cases.append(model)
        model = component_fixture()
        model["public_jwk"]["key_ops"] = ListAlias(["verify"])
        cases.append(model)
        for model in cases:
            with (
                self.subTest(model_type=type(model)),
                mock.patch.object(jose, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(jose.JoseAnalysisError),
            ):
                self.analyze(model)
        with self.assertRaises(jose.JoseAnalysisError):
            self.analyze(DictAlias(component_fixture()))

    def test_native_shared_graph_cycles_and_costs_fail_before_serialization(self):
        shared = ['"\\' * 1000] * 32
        for value in ([shared] * 32, [None] * 4097, 2**10000):
            model = component_fixture()
            model["unexpected"] = value
            with (
                mock.patch.object(
                    jose.json, "dumps", side_effect=AssertionError("must not serialize")
                ),
                self.assertRaises(jose.JoseAnalysisError),
            ):
                self.analyze(model)
        cycle = []
        cycle.append(cycle)
        self.denied_before_key({**component_fixture(), "unexpected": cycle})

    def test_decoded_depth_and_node_budgets_precede_json_decoder(self):
        for payload in (
            b"[" * 14 + b"null" + b"]" * 14,
            b"[" + b",".join([b"null"] * 4097) + b"]",
            b'{"exp":' + b"9" * 10000 + b"}",
        ):
            model = _model(raw_claims=payload)
            original = jose.json.loads

            def loader(text, _payload=payload, _original=original, **kwargs):
                if text == _payload.decode():
                    raise AssertionError("bounded payload must not reach decoder")
                return _original(text, **kwargs)

            with mock.patch.object(jose.json, "loads", side_effect=loader):
                self.denied_before_key(model)

    def test_source_size_bounds_before_decoder_key_and_new_hash(self):
        for model in (
            _model(raw_header=b" " * (jose.MAX_HEADER_BYTES + 1)),
            _model(raw_claims=b" " * (jose.MAX_CLAIMS_BYTES + 1)),
        ):
            with (
                mock.patch.object(
                    jose.json, "loads", side_effect=AssertionError("must not decode")
                ),
                mock.patch.object(jose, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(jose.JoseAnalysisError),
            ):
                self.analyze(model)

    def test_invalid_utf8_and_unpaired_unicode_fail_before_key_construction(self):
        for raw in (b'{"custom":"\xff"}', b'{"custom":"\\ud800"}'):
            with self.subTest(raw=raw):
                self.denied_before_key(_model(raw_claims=raw))
        with (
            mock.patch.object(jose, "_hash", side_effect=AssertionError("must not hash")),
            self.assertRaises(jose.JoseAnalysisError),
        ):
            self.analyze({**component_fixture(), "expected_issuer": "\ud800"})

    def test_wrapper_roundtrip_is_owned_and_does_not_retain_raw_token_or_claims(self):
        model = component_fixture()
        report = self.analyze(model)
        original = report.to_json()
        model["public_jwk"]["key_ops"].append("sign")
        document = report.to_dict()
        document["checks"]["signature"] = "invalid"
        self.assertEqual(original, report.to_json())
        self.assertEqual(original, jose.JoseAnalysis.from_json(original).to_json())
        self.assertEqual(original, jose.JoseAnalysis.from_dict(report.to_dict()).to_json())
        for value in (
            component_fixture()["compact_jws"],
            ISSUER,
            AUDIENCE,
            "opaque-synthetic-subject-not-retained",
            "opaque-synthetic-content-not-retained",
            KEY_ID,
        ):
            self.assertNotIn(value, original)

    def test_cohashed_metadata_may_be_self_consistent_but_fails_original_source_replay(self):
        model = component_fixture()
        document = self.analyze(model).to_dict()
        document["checks"]["signature"] = "invalid"
        document["observations"] = ["signature_invalid"]
        document["analysis_status"] = "mismatch"
        altered = jose.JoseAnalysis.from_dict(_addressed(document))
        with self.assertRaisesRegex(jose.JoseAnalysisError, "does not reproduce"):
            jose.verify_supplied_jose_analysis(altered, model=model)
        document = self.analyze(model).to_dict()
        document["statistics"]["claim_members"] -= 1
        with self.assertRaisesRegex(jose.JoseAnalysisError, "does not reproduce"):
            jose.verify_supplied_jose_analysis(
                jose.JoseAnalysis.from_dict(_addressed(document)), model=model
            )

    def test_each_original_source_and_expected_context_is_bound_without_currentness(self):
        model = component_fixture()
        report = self.analyze(model)
        cases = []
        for name, value in (
            ("expected_issuer", "https://other.example.test"),
            ("expected_audience", "other"),
            ("evaluated_at", "2026-09-28T12:00:01Z"),
        ):
            cases.append({**model, name: value})
        changed = copy.deepcopy(model)
        changed["public_jwk"].pop("use")
        cases.append(changed)
        cases.append(_model(claims={**_claims(), "sub": "another-opaque-subject"}))
        for changed in cases:
            with (
                self.subTest(source=changed),
                self.assertRaisesRegex(jose.JoseAnalysisError, "does not reproduce"),
            ):
                jose.verify_supplied_jose_analysis(report, model=changed)
        self.assertEqual(
            report.to_json(), jose.verify_supplied_jose_analysis(report, model=model).to_json()
        )

    def test_unchanged_signature_math_cannot_promote_effects_or_flags(self):
        original = self.analyze().to_dict()
        for name in (
            "issuer_authenticated",
            "key_origin_authenticated",
            "key_currentness_verified",
            "live_use_approved",
            "replay_prevention_verified",
            "qualification_claimed",
        ):
            changed = copy.deepcopy(original)
            changed[name] = True
            with self.subTest(name=name), self.assertRaises(jose.JoseAnalysisError):
                jose.JoseAnalysis.from_dict(_addressed(changed))
        for name in original["operational_effects"]:
            changed = copy.deepcopy(original)
            changed["operational_effects"][name] = "granted"
            with self.subTest(effect=name), self.assertRaises(jose.JoseAnalysisError):
                jose.JoseAnalysis.from_dict(_addressed(changed))

    def test_report_exact_native_scalars_unknown_fields_and_duplicate_loader(self):
        original = self.analyze().to_dict()
        for name, value in (
            ("schema_version", True),
            ("offline_only", 1),
            ("issuer_authenticated", 0),
            ("statistics", {**original["statistics"], "signature_bytes": 64.0}),
        ):
            changed = copy.deepcopy(original)
            changed[name] = value
            with self.subTest(name=name), self.assertRaises(jose.JoseAnalysisError):
                jose.JoseAnalysis.from_dict(_addressed(changed))
        with self.assertRaises(jose.JoseAnalysisError):
            jose.JoseAnalysis.from_dict(_addressed({**original, "unknown": None}))
        raw = (
            self.analyze()
            .to_json()
            .replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        )
        with self.assertRaises(jose.JoseAnalysisError):
            jose.JoseAnalysis.from_json(raw)

    def test_forged_or_incomplete_wrapper_is_revalidated_not_a_same_process_sandbox(self):
        report = self.analyze()
        object.__setattr__(
            report,
            "document_json",
            report.to_json().replace('"schema_version":1', '"schema_version":true'),
        )
        with self.assertRaises(jose.JoseAnalysisError):
            jose.verify_supplied_jose_analysis(report, model=component_fixture())
        with self.assertRaises(jose.JoseAnalysisError):
            jose.verify_supplied_jose_analysis(
                object.__new__(jose.JoseAnalysis), model=component_fixture()
            )

    def test_unknown_model_fields_and_noncanonical_instants_have_no_default(self):
        for instant in (
            "2026-09-28T12:00:00+00:00",
            "2026-09-28T12:00:00.000Z",
            "2026-02-30T12:00:00Z",
            "1969-12-31T23:59:59Z",
            True,
        ):
            self.denied_before_key({**component_fixture(), "evaluated_at": instant})
        for model in (
            {**component_fixture(), "unknown": None},
            {name: value for name, value in component_fixture().items() if name != "evaluated_at"},
        ):
            self.denied_before_key(model)


if __name__ == "__main__":
    unittest.main()

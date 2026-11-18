"""Synthetic public-certificate tests; no operational keys or external services."""

import ast
import base64
import hashlib
import json
import unittest
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from sunderkey import offline_x509_chain_analysis as module
from sunderkey.offline_x509_chain_analysis import (
    CAPABILITY_ID,
    DOMAIN,
    PROFILE_ID,
    VECTOR_ID,
    X509ChainAnalysis,
    X509ChainAnalysisError,
    analyze_supplied_x509_chain,
    verify_supplied_x509_chain_analysis,
)

ROOT = Path(__file__).resolve().parents[2]
AT = "2026-09-28T12:00:00Z"
BEFORE = datetime(2026, 9, 28, 11, tzinfo=UTC)
AFTER = datetime(2026, 9, 28, 13, tzinfo=UTC)


def _key(label):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(("disposable-x509-test-only:" + label).encode("ascii")).digest()
    )


def _name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])


def _certificate(
    subject,
    key,
    issuer,
    signer,
    serial,
    *,
    ca=False,
    path_length=None,
    key_cert_sign=False,
    before=BEFORE,
    after=AFTER,
    extras=(),
    empty_usage=False,
    include_usage=True,
    bc_critical=True,
):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(before)
        .not_valid_after(after)
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca, path_length), bc_critical)
    if include_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=not empty_usage,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            True,
        )
    for extension, critical in extras:
        builder = builder.add_extension(extension, critical)
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, algorithm).public_bytes(serialization.Encoding.DER)


def _model(chain, at=AT):
    return {
        "schema_version": 1,
        "chain_der_base64": [base64.b64encode(der).decode("ascii") for der in chain],
        "declared_terminal_sha256": "sha256:" + hashlib.sha256(chain[-1]).hexdigest(),
        "evaluated_at": at,
    }


def synthetic_chain_model():
    """Return only deterministic disposable public DER for catalog example preparation."""
    terminal, intermediate, leaf = _key("terminal"), _key("intermediate"), _key("leaf")
    return _model(
        [
            _certificate("leaf", leaf, "intermediate", intermediate, 3),
            _certificate(
                "intermediate",
                intermediate,
                "terminal",
                terminal,
                2,
                ca=True,
                key_cert_sign=True,
                path_length=0,
            ),
            _certificate(
                "terminal",
                terminal,
                "terminal",
                terminal,
                1,
                ca=True,
                key_cert_sign=True,
                path_length=0,
            ),
        ]
    )


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    encoded = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    digest = (
        "sha256:"
        + hashlib.sha256(DOMAIN.encode("ascii") + b"\n" + encoded.encode("ascii")).hexdigest()
    )
    return {"analysis_id": "XCA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


def _codes(report, field="violations"):
    return {item["code"] for item in report.to_dict()[field]}


class OfflineX509ChainAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.model = synthetic_chain_model()

    def test_genuine_chain_signatures_and_structural_checks_are_reproducible(self):
        report = analyze_supplied_x509_chain(self.model)
        body = report.to_dict()
        self.assertEqual(body["supported_checks_outcome"], "pass")
        self.assertEqual(body["violations"], [])
        self.assertEqual(body["incomplete_reasons"], [])
        self.assertEqual(
            [link["signature_status"] for link in body["issuer_links"]], ["verified", "verified"]
        )
        self.assertEqual(
            [item["role"] for item in body["certificate_observations"]],
            ["leaf", "intermediate", "declared_terminal"],
        )
        self.assertEqual(
            verify_supplied_x509_chain_analysis(report, model=self.model).to_json(),
            report.to_json(),
        )
        self.assertEqual(X509ChainAnalysis.from_json(report.to_json()).to_dict(), body)
        self.assertEqual(X509ChainAnalysis.from_dict(body).to_dict(), body)

    def test_literal_public_source_and_analysis_goldens(self):
        report = analyze_supplied_x509_chain(self.model).to_dict()
        self.assertEqual(
            report["source"]["declared_terminal_sha256"],
            "sha256:33be164e37fe3f261c1e13439f69bb4363f5ec61263f45b6fe205549d335236d",
        )
        self.assertEqual(
            report["source"]["model_sha256"],
            "sha256:ecea61b6a7c5cf3bcebed5da44444ebe29218d41d8d2f350137b649e3a207c4d",
        )
        self.assertEqual(report["analysis_id"], "XCA-7E607F7FBDB71797A4A9C924EDDD1F9C")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:7e607f7fbdb71797a4a9c924eddd1f9cdf43488575d6e3e7ec156cd6325c1ab9",
        )

    def test_wrong_key_with_the_same_issuer_name_is_a_real_signature_violation(self):
        bad = _certificate("leaf", _key("leaf"), "intermediate", _key("unrelated"), 3)
        self.model["chain_der_base64"][0] = base64.b64encode(bad).decode("ascii")
        report = analyze_supplied_x509_chain(self.model)
        self.assertIn("certificate_signature_invalid", _codes(report))
        self.assertTrue(report.to_dict()["issuer_links"][0]["issuer_name_matches"])
        self.assertEqual(report.to_dict()["issuer_links"][0]["signature_status"], "invalid")

    def test_wrong_issuer_name_does_not_claim_signature_verification(self):
        bad = _certificate("leaf", _key("leaf"), "unrelated", _key("intermediate"), 3)
        self.model["chain_der_base64"][0] = base64.b64encode(bad).decode("ascii")
        report = analyze_supplied_x509_chain(self.model)
        self.assertIn("issuer_name_mismatch", _codes(report))
        self.assertEqual(report.to_dict()["issuer_links"][0]["signature_status"], "not_checked")

    def test_missing_and_reordered_issuers_cannot_pass_the_supported_checks(self):
        chain = [base64.b64decode(item) for item in self.model["chain_der_base64"]]
        for sources in ([chain[0], chain[2]], list(reversed(chain))):
            with self.subTest(count=len(sources)):
                report = analyze_supplied_x509_chain(_model(sources))
                self.assertIn("issuer_name_mismatch", _codes(report))
                self.assertNotEqual(report.to_dict()["supported_checks_outcome"], "pass")

    def test_duplicate_certificate_and_terminal_substitution_are_rejected(self):
        chain = [base64.b64decode(item) for item in self.model["chain_der_base64"]]
        with self.assertRaises(X509ChainAnalysisError):
            analyze_supplied_x509_chain(_model([chain[0], chain[1], chain[1], chain[2]]))
        changed = deepcopy(self.model)
        changed["declared_terminal_sha256"] = "sha256:" + "ab" * 32
        with self.assertRaises(X509ChainAnalysisError):
            analyze_supplied_x509_chain(changed)

    def test_certificate_validity_is_inclusive_and_no_live_clock_is_consulted(self):
        for at in ("2026-09-28T11:00:00Z", "2026-09-28T13:00:00Z"):
            with self.subTest(at=at):
                report = analyze_supplied_x509_chain({**self.model, "evaluated_at": at})
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
        for at in ("2026-09-28T10:59:59Z", "2026-09-28T13:00:01Z"):
            with self.subTest(at=at):
                report = analyze_supplied_x509_chain({**self.model, "evaluated_at": at})
                self.assertIn("outside_certificate_validity", _codes(report))
                self.assertEqual(len(report.to_dict()["violations"]), 2)

    def test_intermediate_requires_ca_and_present_key_cert_sign(self):
        for changes, code in (
            ({"ca": False, "key_cert_sign": False}, "intermediate_not_ca"),
            ({"ca": None, "key_cert_sign": False}, "intermediate_not_ca"),
            ({"ca": True, "key_cert_sign": False}, "intermediate_key_cert_sign_denied"),
        ):
            with self.subTest(changes=changes):
                bad = _certificate(
                    "intermediate", _key("intermediate"), "terminal", _key("terminal"), 2, **changes
                )
                model = deepcopy(self.model)
                model["chain_der_base64"][1] = base64.b64encode(bad).decode("ascii")
                report = analyze_supplied_x509_chain(model)
                self.assertIn(code, _codes(report))
                self.assertTrue(
                    all(
                        link["signature_status"] == "verified"
                        for link in report.to_dict()["issuer_links"]
                    )
                )

    def test_absent_intermediate_key_usage_is_not_an_invented_requirement(self):
        good = _certificate(
            "intermediate",
            _key("intermediate"),
            "terminal",
            _key("terminal"),
            2,
            ca=True,
            include_usage=False,
        )
        self.model["chain_der_base64"][1] = base64.b64encode(good).decode("ascii")
        self.assertEqual(
            analyze_supplied_x509_chain(self.model).to_dict()["supported_checks_outcome"], "pass"
        )

    def test_nonterminal_path_length_requires_present_key_cert_sign(self):
        for index, subject, issuer in (
            (0, "leaf", "intermediate"),
            (1, "intermediate", "terminal"),
        ):
            with self.subTest(index=index):
                der = _certificate(
                    subject,
                    _key(subject),
                    issuer,
                    _key(issuer),
                    3 - index,
                    ca=True,
                    path_length=0,
                    key_cert_sign=False,
                )
                certificate = x509.load_der_x509_certificate(der)
                declared_issuer = x509.load_der_x509_certificate(
                    base64.b64decode(self.model["chain_der_base64"][index + 1])
                )
                certificate.verify_directly_issued_by(declared_issuer)
                self.assertTrue(
                    certificate.extensions.get_extension_for_class(x509.BasicConstraints).critical
                )
                self.assertTrue(
                    certificate.extensions.get_extension_for_class(x509.KeyUsage).critical
                )
                model = deepcopy(self.model)
                model["chain_der_base64"][index] = base64.b64encode(der).decode("ascii")
                report = analyze_supplied_x509_chain(model)
                body = report.to_dict()
                self.assertIn("path_length_without_key_cert_sign", _codes(report))
                self.assertEqual(body["supported_checks_outcome"], "violations")
                self.assertIn(
                    {
                        "code": "path_length_without_key_cert_sign",
                        "certificate_index": index,
                        "related_certificate_index": None,
                    },
                    body["violations"],
                )
                self.assertEqual(body["incomplete_reasons"], [])
                self.assertTrue(
                    all(link["signature_status"] == "verified" for link in body["issuer_links"])
                )
                self.assertEqual(
                    verify_supplied_x509_chain_analysis(report, model=model).to_json(),
                    report.to_json(),
                )

    def test_cohashed_pass_cannot_erase_path_length_key_usage_violation(self):
        for index, subject, issuer in (
            (0, "leaf", "intermediate"),
            (1, "intermediate", "terminal"),
        ):
            with self.subTest(index=index):
                model = deepcopy(self.model)
                der = _certificate(
                    subject,
                    _key(subject),
                    issuer,
                    _key(issuer),
                    3 - index,
                    ca=True,
                    path_length=0,
                    key_cert_sign=False,
                )
                model["chain_der_base64"][index] = base64.b64encode(der).decode("ascii")
                document = analyze_supplied_x509_chain(model).to_dict()
                document["violations"] = [
                    entry
                    for entry in document["violations"]
                    if entry["code"] != "path_length_without_key_cert_sign"
                ]
                document["supported_checks_outcome"] = (
                    "violations" if document["violations"] else "pass"
                )
                with self.assertRaises(X509ChainAnalysisError):
                    X509ChainAnalysis.from_dict(_readdress(document))

    def test_nonterminal_ca_path_length_with_absent_key_usage_remains_supported(self):
        for index, subject, issuer in (
            (0, "leaf", "intermediate"),
            (1, "intermediate", "terminal"),
        ):
            with self.subTest(index=index):
                model = deepcopy(self.model)
                der = _certificate(
                    subject,
                    _key(subject),
                    issuer,
                    _key(issuer),
                    3 - index,
                    ca=True,
                    path_length=0,
                    include_usage=False,
                )
                model["chain_der_base64"][index] = base64.b64encode(der).decode("ascii")
                report = analyze_supplied_x509_chain(model)
                self.assertIsNone(report.to_dict()["certificate_observations"][index]["key_usage"])
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "pass")
                self.assertEqual(
                    verify_supplied_x509_chain_analysis(report, model=model).to_json(),
                    report.to_json(),
                )

    def test_terminal_path_length_with_denied_key_cert_sign_is_only_an_observation(self):
        terminal, leaf = _key("terminal-usage-declaration"), _key("terminal-usage-leaf")
        model = _model(
            [
                _certificate("leaf", leaf, "terminal", terminal, 53),
                _certificate(
                    "terminal",
                    terminal,
                    "terminal",
                    terminal,
                    52,
                    ca=True,
                    path_length=0,
                    key_cert_sign=False,
                ),
            ]
        )
        report = analyze_supplied_x509_chain(model)
        body = report.to_dict()
        self.assertEqual(body["supported_checks_outcome"], "pass")
        self.assertEqual(body["violations"], [])
        self.assertEqual(body["issuer_links"][0]["signature_status"], "verified")
        observation = body["certificate_observations"][-1]
        self.assertEqual(observation["role"], "declared_terminal")
        self.assertTrue(observation["basic_constraints"]["ca"])
        self.assertEqual(observation["basic_constraints"]["path_length"], 0)
        self.assertFalse(observation["key_usage"]["key_cert_sign"])
        self.assertIs(body["trust_established"], False)
        self.assertIs(body["full_pkix_validated"], False)
        self.assertEqual(
            verify_supplied_x509_chain_analysis(report, model=model).to_json(), report.to_json()
        )

    def test_non_self_issued_intermediate_path_length_violation_has_exact_witness(self):
        terminal, upper, lower, leaf = [_key(name) for name in ("root2", "upper", "lower", "leaf2")]
        chain = [
            _certificate("leaf2", leaf, "lower", lower, 13),
            _certificate("lower", lower, "upper", upper, 12, ca=True, key_cert_sign=True),
            _certificate(
                "upper", upper, "root2", terminal, 11, ca=True, key_cert_sign=True, path_length=0
            ),
            _certificate("root2", terminal, "root2", terminal, 10, ca=True, key_cert_sign=True),
        ]
        report = analyze_supplied_x509_chain(_model(chain))
        self.assertEqual(
            report.to_dict()["violations"],
            [
                {
                    "code": "intermediate_path_length_exceeded",
                    "certificate_index": 2,
                    "related_certificate_index": None,
                }
            ],
        )

    def test_genuine_self_issued_rollover_is_not_counted_as_a_path_length_step(self):
        terminal, old, new, leaf = [_key(name) for name in ("root3", "old", "new", "leaf3")]
        chain = [
            _certificate("leaf3", leaf, "rollover", new, 23),
            _certificate("rollover", new, "rollover", old, 22, ca=True, key_cert_sign=True),
            _certificate(
                "rollover", old, "root3", terminal, 21, ca=True, key_cert_sign=True, path_length=0
            ),
            _certificate(
                "root3", terminal, "root3", terminal, 20, ca=True, key_cert_sign=True, path_length=0
            ),
        ]
        report = analyze_supplied_x509_chain(_model(chain)).to_dict()
        self.assertTrue(report["certificate_observations"][1]["self_issued"])
        self.assertEqual(report["supported_checks_outcome"], "pass")
        self.assertEqual(
            [link["signature_status"] for link in report["issuer_links"]], ["verified"] * 3
        )

    def test_terminal_expiry_ca_key_usage_and_self_signature_are_only_observations(self):
        terminal, leaf = _key("nontrusted-terminal"), _key("terminal-test-leaf")
        chain = [
            _certificate("leaf", leaf, "terminal", terminal, 32),
            _certificate(
                "terminal",
                terminal,
                "not-supplied-issuer",
                _key("other-issuer"),
                31,
                ca=False,
                empty_usage=True,
                before=datetime(2025, 1, 1, tzinfo=UTC),
                after=datetime(2025, 1, 2, tzinfo=UTC),
            ),
        ]
        report = analyze_supplied_x509_chain(_model(chain)).to_dict()
        self.assertEqual(report["supported_checks_outcome"], "pass")
        self.assertFalse(report["certificate_observations"][-1]["valid_at_supplied_instant"])
        self.assertFalse(report["certificate_observations"][-1]["self_issued"])
        self.assertFalse(report["certificate_observations"][-1]["basic_constraints"]["ca"])
        self.assertEqual(report["issuer_links"][0]["signature_status"], "verified")
        self.assertFalse(report["trust_established"])
        self.assertFalse(report["full_pkix_validated"])

    def test_critical_leaf_basic_constraints_and_key_usage_are_processed(self):
        for changes, code in (
            ({"ca": False, "key_cert_sign": True}, "key_cert_sign_without_ca"),
            ({"empty_usage": True}, "empty_key_usage"),
        ):
            with self.subTest(changes=changes):
                leaf = _certificate(
                    "leaf", _key("leaf"), "intermediate", _key("intermediate"), 3, **changes
                )
                model = deepcopy(self.model)
                model["chain_der_base64"][0] = base64.b64encode(leaf).decode("ascii")
                report = analyze_supplied_x509_chain(model)
                self.assertIn(code, _codes(report))
                self.assertEqual(report.to_dict()["incomplete_reasons"], [])
        leaf = _certificate(
            "leaf",
            _key("leaf"),
            "intermediate",
            _key("intermediate"),
            3,
            ca=True,
            key_cert_sign=True,
            path_length=0,
        )
        model = deepcopy(self.model)
        model["chain_der_base64"][0] = base64.b64encode(leaf).decode("ascii")
        self.assertEqual(
            analyze_supplied_x509_chain(model).to_dict()["supported_checks_outcome"], "pass"
        )

    def test_unknown_and_unimplemented_critical_constraints_are_incomplete(self):
        extras = (
            x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"),
            x509.NameConstraints([x509.DNSName("example.test")], None),
            x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
        )
        for extension in extras:
            with self.subTest(extension=type(extension).__name__):
                leaf = _certificate(
                    "leaf",
                    _key("leaf"),
                    "intermediate",
                    _key("intermediate"),
                    3,
                    extras=((extension, True),),
                )
                model = deepcopy(self.model)
                model["chain_der_base64"][0] = base64.b64encode(leaf).decode("ascii")
                report = analyze_supplied_x509_chain(model)
                self.assertIn(
                    "unsupported_critical_extension", _codes(report, "incomplete_reasons")
                )
                self.assertEqual(report.to_dict()["supported_checks_outcome"], "incomplete")
                self.assertFalse(report.to_dict()["full_pkix_validated"])

    def test_terminal_unsupported_critical_constraints_do_not_become_anchor_policy(self):
        terminal = _certificate(
            "terminal",
            _key("terminal"),
            "terminal",
            _key("terminal"),
            1,
            extras=((x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4"), b"\x05\x00"), True),),
        )
        sources = [base64.b64decode(item) for item in self.model["chain_der_base64"]]
        sources[-1] = terminal
        report = analyze_supplied_x509_chain(_model(sources)).to_dict()
        self.assertEqual(report["supported_checks_outcome"], "pass")
        self.assertEqual(
            report["certificate_observations"][-1]["unsupported_critical_extension_oids"],
            ["1.2.3.4"],
        )
        self.assertFalse(report["trust_established"])

    def test_single_supplied_terminal_is_incomplete_not_a_chain_or_trust_proof(self):
        terminal = base64.b64decode(self.model["chain_der_base64"][-1])
        report = analyze_supplied_x509_chain(_model([terminal]))
        self.assertIn("no_issuer_link_supplied", _codes(report, "incomplete_reasons"))
        self.assertEqual(report.to_dict()["issuer_links"], [])
        self.assertFalse(report.to_dict()["positive_use_approved"])

    def test_rsa_and_ecdsa_issuance_are_verified_with_real_disposable_certificates(self):
        for signer, label in (
            (rsa.generate_private_key(public_exponent=65537, key_size=2048), "rsa"),
            (ec.generate_private_key(ec.SECP256R1()), "ecdsa"),
        ):
            with self.subTest(kind=label):
                leaf = _certificate("leaf", _key("algorithm-leaf"), "terminal", signer, 42)
                terminal = _certificate(
                    "terminal", signer, "terminal", signer, 41, ca=True, key_cert_sign=True
                )
                report = analyze_supplied_x509_chain(_model([leaf, terminal])).to_dict()
                self.assertEqual(report["issuer_links"][0]["issuer_key_kind"], label)
                self.assertEqual(report["issuer_links"][0]["signature_status"], "verified")

    def test_unsupported_signature_oid_is_incomplete_not_verified(self):
        leaf = base64.b64decode(self.model["chain_der_base64"][0])
        changed = leaf.replace(b"\x06\x03\x2b\x65\x70", b"\x06\x03\x2b\x65\x7f")
        self.assertNotEqual(changed, leaf)
        self.model["chain_der_base64"][0] = base64.b64encode(changed).decode("ascii")
        report = analyze_supplied_x509_chain(self.model)
        self.assertIn("unsupported_signature_or_issuer_key", _codes(report, "incomplete_reasons"))
        self.assertEqual(report.to_dict()["issuer_links"][0]["signature_status"], "unsupported")

    def test_der_malformed_trailing_and_duplicate_extensions_fail_closed(self):
        leaf = base64.b64decode(self.model["chain_der_base64"][0])
        duplicate = leaf.replace(b"\x06\x03\x55\x1d\x0f", b"\x06\x03\x55\x1d\x13")
        for content in (b"not DER", leaf + b"\x00", leaf[:-1], duplicate):
            with self.subTest(size=len(content)):
                model = deepcopy(self.model)
                model["chain_der_base64"][0] = base64.b64encode(content).decode("ascii")
                with self.assertRaises(X509ChainAnalysisError):
                    analyze_supplied_x509_chain(model)

    def test_base64_and_der_byte_ceilings_precede_certificate_parsing(self):
        for encoded in (
            "",
            "!!!!",
            self.model["chain_der_base64"][0] + "\n",
            "AB==",
            base64.b64encode(b"a" * (module.MAX_CERTIFICATE_BYTES + 1)).decode("ascii"),
        ):
            with (
                self.subTest(size=len(encoded)),
                patch.object(
                    module.x509,
                    "load_der_x509_certificate",
                    side_effect=AssertionError("parser reached"),
                ),
            ):
                model = deepcopy(self.model)
                model["chain_der_base64"][0] = encoded
                with self.assertRaises(X509ChainAnalysisError):
                    analyze_supplied_x509_chain(model)

    def test_native_model_aliases_subclasses_and_unsupported_fields_precede_hashing(self):
        class NativeInt(int):
            pass

        class NativeText(str):
            pass

        class NativeArray(list):
            pass

        class NativeObject(dict):
            pass

        models = [
            {**self.model, "schema_version": value} for value in (True, 1.0, "1", NativeInt(1))
        ] + [
            {**self.model, "evaluated_at": NativeText(AT)},
            {**self.model, "chain_der_base64": NativeArray(self.model["chain_der_base64"])},
            {**self.model, "chain_der_base64": tuple(self.model["chain_der_base64"])},
            {**self.model, "chain_der_base64": [NativeText(self.model["chain_der_base64"][0])]},
            {**self.model, "unknown": None},
            NativeObject(self.model),
        ]
        for model in models:
            with (
                self.subTest(kind=type(model).__name__),
                patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
                self.assertRaises(X509ChainAnalysisError),
            ):
                analyze_supplied_x509_chain(model)

    def test_explicit_time_requires_canonical_native_utc_without_aliases(self):
        for value in (
            True,
            datetime(2026, 9, 28, 12, tzinfo=UTC),
            "2026-09-28T12:00:00+00:00",
            "2026-09-28T12:00:00.001Z",
            "2026-02-30T12:00:00Z",
        ):
            with self.subTest(value=str(value)), self.assertRaises(X509ChainAnalysisError):
                analyze_supplied_x509_chain({**self.model, "evaluated_at": value})

    def test_aggregate_bytes_depth_nodes_and_large_native_integers_precede_serialization(self):
        shared = ["x" * module._MAX_BASE64] * 13
        graph = [0]
        for _ in range(5):
            graph = [graph] * 10
        deep = 0
        for _ in range(module.MAX_DEPTH + 2):
            deep = [deep]
        cycle = []
        cycle.append(cycle)
        for value in (shared, graph, deep, cycle, 2**1_000_000):
            with (
                self.subTest(kind=type(value).__name__),
                patch.object(
                    module, "_canonical", side_effect=AssertionError("serialization reached")
                ),
                self.assertRaises(X509ChainAnalysisError),
            ):
                analyze_supplied_x509_chain({"bad": value})

    def test_certificate_count_and_total_der_bounds_precede_parsing(self):
        excessive = [
            base64.b64encode(bytes([index]) * module.MAX_CERTIFICATE_BYTES).decode("ascii")
            for index in range(9)
        ]
        for sources in (self.model["chain_der_base64"] * 6, excessive):
            with (
                self.subTest(count=len(sources)),
                patch.object(
                    module.x509,
                    "load_der_x509_certificate",
                    side_effect=AssertionError("parser reached"),
                ),
                self.assertRaises(X509ChainAnalysisError),
            ):
                analyze_supplied_x509_chain({**self.model, "chain_der_base64": sources})

    def test_detached_input_and_output_cannot_mutate_the_owned_report(self):
        model = deepcopy(self.model)
        report = analyze_supplied_x509_chain(model)
        golden = report.to_json()
        model["chain_der_base64"].clear()
        returned = report.to_dict()
        returned["certificate_observations"][0]["self_issued"] = True
        returned["source"]["certificates"].clear()
        self.assertEqual(report.to_json(), golden)
        self.assertEqual(
            verify_supplied_x509_chain_analysis(report, model=self.model).to_json(), golden
        )

    def test_source_replay_rejects_a_separately_valid_readdressed_model(self):
        report = analyze_supplied_x509_chain(self.model)
        altered = {**self.model, "evaluated_at": "2026-09-28T12:00:01Z"}
        other = analyze_supplied_x509_chain(altered)
        self.assertEqual(other.to_dict()["supported_checks_outcome"], "pass")
        self.assertNotEqual(other.to_json(), report.to_json())
        with self.assertRaises(X509ChainAnalysisError):
            verify_supplied_x509_chain_analysis(other, model=self.model)
        with self.assertRaises(X509ChainAnalysisError):
            verify_supplied_x509_chain_analysis(report, model=altered)

    def test_cohashed_metadata_is_not_certificate_source_verification(self):
        report = analyze_supplied_x509_chain(self.model).to_dict()
        report["issuer_links"][0]["signature_status"] = "invalid"
        report["violations"] = [
            {
                "code": "certificate_signature_invalid",
                "certificate_index": 0,
                "related_certificate_index": 1,
            }
        ]
        report["supported_checks_outcome"] = "violations"
        declared = X509ChainAnalysis.from_dict(_readdress(report))
        self.assertFalse(declared.to_dict()["trust_established"])
        with self.assertRaises(X509ChainAnalysisError):
            verify_supplied_x509_chain_analysis(declared, model=self.model)

    def test_report_aliases_and_inconsistent_native_projection_are_rejected(self):
        original = analyze_supplied_x509_chain(self.model).to_dict()
        changes = (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("offline_only", 1),
            ("full_pkix_validated", 0),
            ("positive_use_approved", True),
            ("qualification_claimed", True),
            ("effects", {**original["effects"], "authority": "approved"}),
        )
        for key, value in changes:
            with self.subTest(field=key):
                report = {**original, key: value}
                with self.assertRaises(X509ChainAnalysisError):
                    X509ChainAnalysis.from_dict(_readdress(report))
        for field, value in (
            ("valid_at_supplied_instant", 1),
            ("self_issued", 0),
            ("index", False),
        ):
            with self.subTest(field=field):
                report = deepcopy(original)
                report["certificate_observations"][0][field] = value
                with self.assertRaises(X509ChainAnalysisError):
                    X509ChainAnalysis.from_dict(_readdress(report))
        for field in ("signature_status", "issuer_key_kind"):
            with self.subTest(field=field):
                report = deepcopy(original)
                report["issuer_links"][0][field] = {"foreign": "value"}
                with self.assertRaises(X509ChainAnalysisError):
                    X509ChainAnalysis.from_dict(_readdress(report))

    def test_report_parser_rejects_duplicate_unknown_float_and_unbounded_json(self):
        report = analyze_supplied_x509_chain(self.model)
        duplicate = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        for text in (
            duplicate,
            report.to_json().replace('"schema_version":1', '"schema_version":1.0'),
            "[" * 14 + "0" + "]" * 14,
            "x" * (module.MAX_DOCUMENT_BYTES + 1),
        ):
            with self.subTest(size=len(text)), self.assertRaises(X509ChainAnalysisError):
                X509ChainAnalysis.from_json(text)
        document = report.to_dict()
        document["unknown"] = None
        with self.assertRaises(X509ChainAnalysisError):
            X509ChainAnalysis.from_dict(_readdress(document))

    def test_forged_incomplete_and_subclass_wrappers_fail_closed(self):
        incomplete = object.__new__(X509ChainAnalysis)
        with self.assertRaises(X509ChainAnalysisError):
            verify_supplied_x509_chain_analysis(incomplete, model=self.model)
        report = analyze_supplied_x509_chain(self.model)
        object.__setattr__(report, "document_json", {"foreign": "value"})
        with self.assertRaises(X509ChainAnalysisError):
            report.to_dict()

        class ForeignReport(X509ChainAnalysis):
            pass

        with self.assertRaises(X509ChainAnalysisError):
            verify_supplied_x509_chain_analysis(
                ForeignReport(analyze_supplied_x509_chain(self.model).to_json()), model=self.model
            )

    def test_finite_mapping_and_unchanged_nonauthorizing_effects(self):
        body = analyze_supplied_x509_chain(self.model).to_dict()
        self.assertEqual(
            (body["profile_id"], body["capability_id"], body["vector_id"]),
            (PROFILE_ID, CAPABILITY_ID, VECTOR_ID),
        )
        self.assertEqual(body["input_provenance"], "operator_supplied_unverified")
        self.assertEqual(body["terminal_selection"], "caller_declared_untrusted")
        self.assertEqual(body["evaluation_time_basis"], "caller_supplied")
        self.assertTrue(body["offline_only"])
        self.assertTrue(all(value == "none" for value in body["effects"].values()))
        for field in (
            "full_pkix_validated",
            "trust_established",
            "positive_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(body[field], False)
        imports = {
            node.module.split(".")[0]
            for node in ast.walk(
                ast.parse(
                    (ROOT / "src/sunderkey/offline_x509_chain_analysis.py").read_text(
                        encoding="utf-8"
                    )
                )
            )
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imports.update(
            alias.name.split(".")[0]
            for node in ast.walk(
                ast.parse(
                    (ROOT / "src/sunderkey/offline_x509_chain_analysis.py").read_text(
                        encoding="utf-8"
                    )
                )
            )
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        self.assertTrue(
            imports.isdisjoint(
                {
                    "socket",
                    "ssl",
                    "requests",
                    "httpx",
                    "urllib",
                    "subprocess",
                    "os",
                    "pathlib",
                    "keyring",
                }
            )
        )


if __name__ == "__main__":
    unittest.main()

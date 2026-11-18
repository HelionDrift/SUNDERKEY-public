"""Synthetic public-certificate controls for supplied SAN reference arithmetic."""

from __future__ import annotations

import base64
import copy
import ipaddress
import json
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from sunderkey import offline_x509_san_analysis as m

_DATE = datetime(2026, 9, 28, tzinfo=UTC)


def _certificate(
    names: list[x509.GeneralName] | None, *, common_name: str = "cn.example.test"
) -> bytes:
    """Only a deterministic test key is used; no signature validity is asserted by the leaf."""
    key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(42)
        .not_valid_before(_DATE)
        .not_valid_after(datetime(2027, 9, 28, tzinfo=UTC))
    )
    if names is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(key, algorithm=None).public_bytes(serialization.Encoding.DER)


def _model(
    names: list[x509.GeneralName] | None = None,
    *,
    kind: str = "dns_id",
    reference: str = "www.example.test",
    wildcard: bool = True,
    der: bytes | None = None,
) -> dict:
    data = (
        _certificate(
            [x509.DNSName("www.example.test"), x509.DNSName("*.example.test")]
            if names is None
            else names
        )
        if der is None
        else der
    )
    return {
        "schema_version": 1,
        "source_id": "synthetic-san-test",
        "certificate_der_base64": base64.b64encode(data).decode("ascii"),
        "reference_kind": kind,
        "reference_value": reference,
        "wildcard_matching_permitted": wildcard,
    }


def component_fixture() -> dict:
    """Fresh public-only supplied model for static catalog examples."""
    return _model()


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


class X509SanAnalysisTests(unittest.TestCase):
    def test_literal_fixture_and_non_authorizing_flags(self) -> None:
        report = m.analyze_supplied_x509_san(component_fixture())
        body = report.to_dict()
        self.assertEqual(report.analysis_id, "XSA-76A0DFE949EDB4BE18100769CAD0905E")
        self.assertEqual(
            report.analysis_sha256,
            "sha256:76a0dfe949edb4be18100769cad0905e2e5afc59eaf8694348ecafafc07ae8f4",
        )
        self.assertEqual(
            body["source_model_sha256"],
            "sha256:d964d4397c2ea756cd625ee78af990189a0c16a35c5bc5c57580217c6bcbbc88",
        )
        self.assertEqual(body["analysis_status"], "match_observed")
        self.assertEqual(
            [row["comparison"] for row in body["san_observations"]], ["match", "match"]
        )
        self.assertEqual(body["flags"]["offline_only"], True)
        self.assertFalse(
            any(value for key, value in body["flags"].items() if key != "offline_only")
        )
        self.assertEqual(set(body["effects"].values()), {"none"})

    def test_ascii_case_insensitive_dns_and_order_preserved(self) -> None:
        model = _model([x509.DNSName("WWW.Example.TEST"), x509.DNSName("other.test")])
        rows = m.analyze_supplied_x509_san(model).to_dict()["san_observations"]
        self.assertEqual([row["comparison"] for row in rows], ["match", "no_match"])
        self.assertEqual([row["index"] for row in rows], [0, 1])

    def test_wildcard_exact_one_label_and_caller_policy(self) -> None:
        names = [x509.DNSName("*.example.test")]
        for reference, permitted, expected in (
            ("www.example.test", True, "match_observed"),
            ("example.test", True, "no_supported_match_observed"),
            ("a.b.example.test", True, "no_supported_match_observed"),
            ("www.example.test", False, "no_supported_match_observed"),
        ):
            with self.subTest(reference=reference, permitted=permitted):
                model = _model(names, reference=reference, wildcard=permitted)
                self.assertEqual(
                    m.analyze_supplied_x509_san(model).to_dict()["analysis_status"], expected
                )

    def test_partial_wildcard_is_ignored_not_matched(self) -> None:
        model = _model([x509.DNSName("w*.example.test")])
        body = m.analyze_supplied_x509_san(model).to_dict()
        self.assertEqual(body["analysis_status"], "no_supported_match_observed")
        self.assertEqual(body["san_observations"][0]["comparison"], "ignored_invalid_wildcard")

    def test_two_label_wildcard_is_arithmetic_match_without_public_suffix_policy(self) -> None:
        model = _model([x509.DNSName("*.test")], reference="www.test")
        body = m.analyze_supplied_x509_san(model).to_dict()
        self.assertEqual(body["analysis_status"], "match_observed")
        self.assertFalse(body["flags"]["service_authenticated"])

    def test_common_name_does_not_fall_back(self) -> None:
        for names in (None, [x509.DNSName("other.example.test")]):
            with self.subTest(names=names):
                der = _certificate(names, common_name="www.example.test")
                body = m.analyze_supplied_x509_san(_model(der=der)).to_dict()
                self.assertEqual(body["analysis_status"], "no_supported_match_observed")

    def test_ip_exact_octets_not_dns_or_network_prefix(self) -> None:
        names = [
            x509.DNSName("192.0.2.5"),
            x509.IPAddress(ipaddress.ip_address("192.0.2.5")),
            x509.IPAddress(ipaddress.ip_address("2001:db8::5")),
        ]
        for reference, expected in (
            ("192.0.2.5", "match_observed"),
            ("192.0.2.6", "no_supported_match_observed"),
            ("2001:db8::5", "match_observed"),
        ):
            with self.subTest(reference=reference):
                body = m.analyze_supplied_x509_san(
                    _model(names, kind="ip_id", reference=reference)
                ).to_dict()
                self.assertEqual(body["analysis_status"], expected)
        network = x509.IPAddress(ipaddress.ip_network("192.0.2.0/24"))
        with self.assertRaises(m.X509SanAnalysisError):
            m.analyze_supplied_x509_san(_model([network], kind="ip_id", reference="192.0.2.5"))

    def test_other_general_names_cannot_become_dns_or_ip_proof(self) -> None:
        names = [x509.UniformResourceIdentifier("https://www.example.test")]
        body = m.analyze_supplied_x509_san(_model(names)).to_dict()
        self.assertEqual(body["analysis_status"], "unassessed")
        self.assertEqual(body["san_observations"][0]["kind"], "other")

    def test_supported_match_does_not_erase_other_unassessed_names(self) -> None:
        names = [x509.DNSName("www.example.test"), x509.UniformResourceIdentifier("https://x.test")]
        body = m.analyze_supplied_x509_san(_model(names)).to_dict()
        self.assertEqual(body["analysis_status"], "match_observed")
        self.assertIn("other_general_name_not_evaluated", body["unassessed_reasons"])

    def test_reference_subset_and_native_aliases_fail(self) -> None:
        baseline = component_fixture()
        changes = (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("wildcard_matching_permitted", 1),
            ("reference_kind", "uri_id"),
            ("reference_value", "*.example.test"),
            ("reference_value", "xn--x.example.test"),
            ("reference_value", "www.example.test."),
        )
        for field, value in changes:
            with self.subTest(field=field, value=value):
                model = copy.deepcopy(baseline)
                model[field] = value
                with self.assertRaises(m.X509SanAnalysisError):
                    m.analyze_supplied_x509_san(model)
        for value in ("192.0.2.0/24", "192.000.002.005", "2001:0DB8::5", "2001:db8::5%eth0"):
            with self.subTest(value=value):
                with self.assertRaises(m.X509SanAnalysisError):
                    m.analyze_supplied_x509_san(_model(kind="ip_id", reference=value))

    def test_raw_duplicate_float_and_deep_native_rejected(self) -> None:
        baseline = component_fixture()
        raw = _canonical(baseline)
        for content in (
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            raw.replace('"schema_version":1', '"schema_version":1.0', 1),
            raw.replace('"schema_version":1', '"schema_version":--1', 1),
            raw.replace('"schema_version":1', '"schema_version":true', 1),
            raw.replace('"schema_version":1', '"schema_version":' + "[" * 20 + "1" + "]" * 20, 1),
        ):
            with self.subTest(content=content[:80]):
                with self.assertRaises(m.X509SanAnalysisError):
                    m.analyze_supplied_x509_san_bytes(model_bytes=content.encode("ascii"))
        model = component_fixture()
        model["extra"] = [model]
        with self.assertRaises(m.X509SanAnalysisError):
            m.analyze_supplied_x509_san(model)

    def test_der_noncanonical_trailing_and_source_swap(self) -> None:
        model = component_fixture()
        source = base64.b64decode(model["certificate_der_base64"])
        for der in (source + b"\x00", b"\x30\x01\x00", b""):
            with self.subTest(der=der[:4]):
                changed = copy.deepcopy(model)
                changed["certificate_der_base64"] = base64.b64encode(der).decode("ascii")
                with self.assertRaises(m.X509SanAnalysisError):
                    m.analyze_supplied_x509_san(changed)
        report = m.analyze_supplied_x509_san(model)
        changed = copy.deepcopy(model)
        changed["reference_value"] = "other.example.test"
        with self.assertRaises(m.X509SanAnalysisError):
            m.verify_supplied_x509_san_analysis(report, model=changed)

    def test_report_roundtrip_ownership_and_false_cohash(self) -> None:
        model = component_fixture()
        report = m.analyze_supplied_x509_san(model)
        initial = report.to_dict()
        model["reference_value"] = "other.example.test"
        self.assertEqual(report.to_dict(), initial)
        self.assertEqual(m.X509SanAnalysis.from_dict(initial).to_dict(), initial)
        self.assertEqual(m.X509SanAnalysis.from_json(report.to_json()).to_dict(), initial)
        self.assertEqual(m.X509SanAnalysis(report.to_json()).to_dict(), initial)
        self.assertEqual(
            m.verify_supplied_x509_san_analysis(report, model=initial["source_model"]).to_dict(),
            initial,
        )
        for field, value in (
            ("analysis_status", "no_supported_match_observed"),
            ("flags", {**initial["flags"], "service_authenticated": True}),
            ("san_observations", []),
        ):
            changed = copy.deepcopy(initial)
            changed[field] = value
            body = {k: v for k, v in changed.items() if k not in {"analysis_id", "analysis_sha256"}}
            digest = m._digest(m.DOMAIN, body)
            changed["analysis_sha256"] = digest
            changed["analysis_id"] = "XSA-" + digest[7:39].upper()
            with self.subTest(field=field), self.assertRaises(m.X509SanAnalysisError):
                m.X509SanAnalysis.from_dict(changed)

    def test_native_report_alias_and_late_wrapper_mutation(self) -> None:
        report = m.analyze_supplied_x509_san(component_fixture())
        body = report.to_dict()
        body["schema_version"] = True
        with self.assertRaises(m.X509SanAnalysisError):
            m.X509SanAnalysis.from_dict(body)
        object.__setattr__(
            report,
            "document_json",
            report.to_json().replace("match_observed", "no_supported_match_observed"),
        )
        with self.assertRaises(m.X509SanAnalysisError):
            report.to_json()

    def test_true_default_der_and_model_limits(self) -> None:
        model = component_fixture()
        model["certificate_der_base64"] = base64.b64encode(
            b"x" * (m.MAX_CERTIFICATE_BYTES + 1)
        ).decode("ascii")
        with self.assertRaises(m.X509SanAnalysisError):
            m.analyze_supplied_x509_san(model)
        oversized = b"{" + b" " * m.MAX_MODEL_BYTES + b"}"
        with self.assertRaises(m.X509SanAnalysisError):
            m.analyze_supplied_x509_san_bytes(model_bytes=oversized)

    def test_all_public_work_thresholds_before_first_digest(self) -> None:
        model = component_fixture()
        report = m.analyze_supplied_x509_san(model)
        document = report.to_dict()
        text = report.to_json()
        raw = _canonical(model).encode("ascii")
        operations = (
            lambda: m.analyze_supplied_x509_san(model),
            lambda: m.analyze_supplied_x509_san_bytes(model_bytes=raw),
            lambda: m.verify_supplied_x509_san_analysis(report, model=model),
            lambda: m.X509SanAnalysis(text),
            lambda: m.X509SanAnalysis.from_dict(document),
            lambda: m.X509SanAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
        )
        original = m._Budget.charge
        for operation in operations:
            marks: list[int] = []

            def tracked(budget: m._Budget, amount: int) -> None:
                original(budget, amount)
                marks.append(budget.used)

            with patch.object(m._Budget, "charge", tracked):
                operation()
            exact = max(marks)
            with self.subTest(operation=operation, exact=exact):

                def limited(budget: m._Budget, amount: int) -> None:
                    if amount > exact - budget.used:
                        raise m.X509SanAnalysisError("Lowered test work ceiling")
                    original(budget, amount)

                with patch.object(m._Budget, "charge", limited):
                    operation()

                def one_less(budget: m._Budget, amount: int) -> None:
                    if amount > exact - 1 - budget.used:
                        raise m.X509SanAnalysisError("Lowered test work ceiling")
                    original(budget, amount)

                with patch.object(m._Budget, "charge", one_less):
                    with patch.object(m.hashlib, "sha256", side_effect=AssertionError("late hash")):
                        with self.assertRaises(m.X509SanAnalysisError):
                            operation()


if __name__ == "__main__":
    unittest.main()

"""Synthetic supplied WSDL/SOAP structure and exact source replay controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from unittest import mock

from sunderkey import offline_soap_analysis as soap

MINIMAL_WSDL = (
    b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:f="urn:fixture"'
    b' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
    b' xmlns:s="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:fixture">'
    b'<types><xs:schema targetNamespace="urn:fixture" elementFormDefault="qualified">'
    b'<xs:element name="Lookup"><xs:complexType><xs:sequence>'
    b'<xs:element name="id" type="xs:int"/>'
    b'<xs:element name="verbose" type="xs:boolean" minOccurs="0"/>'
    b"</xs:sequence></xs:complexType></xs:element></xs:schema></types>"
    b'<message name="LookupRequest"><part name="parameters" element="f:Lookup"/>'
    b'</message><portType name="FixtureInterface"><operation name="Lookup">'
    b'<input message="f:LookupRequest"/></operation></portType>'
    b'<binding name="FixtureSoapBinding" type="f:FixtureInterface">'
    b'<s:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>'
    b'<operation name="Lookup"><s:operation soapAction="urn:fixture:lookup"/>'
    b'<input><s:body use="literal"/></input></operation></binding></definitions>'
)
MINIMAL_ENVELOPE = (
    b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
    b' xmlns:f="urn:fixture"><s:Body><f:Lookup><f:id>7</f:id>'
    b"<f:verbose>true</f:verbose></f:Lookup></s:Body></s:Envelope>"
)
WSDL = (
    b'<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" xmlns:f="urn:fixture"'
    b' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
    b' xmlns:s="http://schemas.xmlsoap.org/wsdl/soap/" targetNamespace="urn:fixture">'
    b'<types><xs:schema targetNamespace="urn:fixture" elementFormDefault="qualified">'
    b'<xs:element name="Lookup"><xs:complexType><xs:sequence>'
    b'<xs:element name="id" type="xs:int"/>'
    b'<xs:element name="ratio" type="xs:decimal" minOccurs="0"/>'
    b'<xs:element name="verbose" type="xs:boolean" minOccurs="0"/>'
    b'<xs:element name="label" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>'
    b"</xs:sequence></xs:complexType></xs:element>"
    b'<xs:element name="Reply" type="xs:string"/>'
    b'<xs:element name="Problem"><xs:complexType><xs:sequence>'
    b'<xs:element name="code" type="xs:int"/>'
    b"</xs:sequence></xs:complexType></xs:element>"
    b'<xs:element name="Auth" type="xs:string"/></xs:schema></types>'
    b'<message name="LookupRequest"><part name="parameters" element="f:Lookup"/>'
    b'</message><message name="LookupResponse"><part name="value" element="f:Reply"/>'
    b'</message><message name="LookupFault"><part name="problem" element="f:Problem"/>'
    b'</message><message name="AuthHeader"><part name="auth" element="f:Auth"/>'
    b'</message><portType name="FixtureInterface"><operation name="Lookup">'
    b'<input message="f:LookupRequest"/><output message="f:LookupResponse"/>'
    b'<fault name="Problem" message="f:LookupFault"/></operation></portType>'
    b'<binding name="FixtureSoapBinding" type="f:FixtureInterface">'
    b'<s:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>'
    b'<operation name="Lookup"><s:operation soapAction="urn:fixture:lookup"/>'
    b'<input><s:body use="literal" parts="parameters"/>'
    b'<s:header message="f:AuthHeader" part="auth" use="literal"/></input>'
    b'<output><s:body use="literal" parts="value"/></output>'
    b'<fault name="Problem"><s:fault name="Problem" use="literal"/></fault>'
    b"</operation></binding></definitions>"
)


def envelope(body: bytes, header: bytes | None = b"<f:Auth>synthetic-only</f:Auth>") -> bytes:
    return (
        b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        b' xmlns:f="urn:fixture">'
        + (b"<s:Header>" + header + b"</s:Header>" if header is not None else b"")
        + b"<s:Body>"
        + body
        + b"</s:Body></s:Envelope>"
    )


REQUEST = envelope(
    b"<f:Lookup><f:id>7</f:id><f:ratio>+.50</f:ratio><f:verbose>true</f:verbose>"
    b"<f:label>opaque-first</f:label><f:label>opaque-second</f:label></f:Lookup>"
)
RESPONSE = envelope(b"<f:Reply>synthetic-result</f:Reply>", None)
FAULT = envelope(
    b"<s:Fault><faultcode>s:Server</faultcode><faultstring>synthetic-error</faultstring>"
    b"<detail><f:Problem><f:code>17</f:code></f:Problem></detail></s:Fault>",
    None,
)
SELECTION = {
    "binding_qname": "{urn:fixture}FixtureSoapBinding",
    "operation_name": "Lookup",
    "message_kind": "request",
    "fault_name": None,
    "observed_action": "urn:fixture:lookup",
}
LIMITS = soap.SoapAnalysisLimits(8192, 8192, 2048, 1024, 32, 128)


def addressed(document: dict) -> dict:
    """Independently address an unsigned document, without source replay."""
    body = copy.deepcopy(document)
    body.pop("report_id", None)
    body.pop("report_sha256", None)
    canonical = json.dumps(
        {"domain": "sunderkey.offline-soap-analysis.v1", "analysis": body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    digest = hashlib.sha256(canonical).hexdigest()
    return {
        **body,
        "report_id": "SOA-" + digest[:32].upper(),
        "report_sha256": "sha256:" + digest,
    }


class SoapAnalysisTests(unittest.TestCase):
    def analyze(self, *, wsdl=WSDL, content=REQUEST, selection=None, limits=LIMITS):
        return soap.analyze_soap_contract_instance(
            wsdl_content=wsdl,
            envelope_content=content,
            wsdl_source_id="fixture-wsdl",
            envelope_source_id="fixture-envelope",
            selection=copy.deepcopy(SELECTION) if selection is None else selection,
            limits=limits,
        )

    def verify(self, report, *, wsdl=WSDL, content=REQUEST, selection=None, limits=LIMITS):
        return soap.verify_soap_contract_instance(
            report=report,
            wsdl_content=wsdl,
            envelope_content=content,
            wsdl_source_id="fixture-wsdl",
            envelope_source_id="fixture-envelope",
            selection=copy.deepcopy(SELECTION) if selection is None else selection,
            limits=limits,
        )

    def assert_code(self, report, code, *, status=None):
        document = report.to_dict()
        self.assertIn(code, {item["code"] for item in document["observations"]})
        if status is not None:
            self.assertEqual(status, document["analysis_status"])

    def test_literal_integration_fixture_identity_and_source_bytes(self):
        report = self.analyze(wsdl=MINIMAL_WSDL, content=MINIMAL_ENVELOPE)
        document = report.to_dict()
        self.assertEqual("SOA-F445D28C6C836F35ABD88CEA86CD90C8", document["report_id"])
        self.assertEqual(
            "sha256:f445d28c6c836f35abd88cea86cd90c8bc78630e099584a9ad5a27e938e4721a",
            document["report_sha256"],
        )
        self.assertEqual(977, document["wsdl_source"]["byte_count"])
        self.assertEqual(
            "sha256:b11ecf63616197d7b194bdbd76cbdca5d05cb2191a432cce3128928e7fc9ea64",
            document["wsdl_source"]["sha256"],
        )
        self.assertEqual(178, document["envelope_source"]["byte_count"])
        self.assertEqual(
            "sha256:a5aec996e6f239c7dd60589b9657efcad2e3b09440e7eb09e493ef0e5ef35c22",
            document["envelope_source"]["sha256"],
        )
        self.assertEqual("consistent_with_supported_subset", document["analysis_status"])
        self.assertEqual(2, document["statistics"]["scalar_checks"])
        self.assertEqual(
            report.to_json(),
            self.verify(report, wsdl=MINIMAL_WSDL, content=MINIMAL_ENVELOPE).to_json(),
        )

    def test_roundtrip_detachment_and_no_raw_body_content(self):
        selection = copy.deepcopy(SELECTION)
        report = self.analyze(selection=selection)
        original = report.to_json()
        selection["operation_name"] = "Other"
        detached = report.to_dict()
        detached["statistics"]["scalar_checks"] = 0
        self.assertEqual(original, report.to_json())
        self.assertEqual(original, soap.SoapAnalysisReport.from_dict(report.to_dict()).to_json())
        self.assertEqual(original, soap.SoapAnalysisReport.from_json(original).to_json())
        self.assertEqual(original, self.verify(report).to_json())
        for opaque in ("synthetic-only", "opaque-first", "opaque-second", "synthetic-result"):
            self.assertNotIn(opaque, original)
        self.assertEqual("none", report.to_dict()["operational_effects"]["execution"])
        self.assertFalse(report.to_dict()["full_xsd_validation_claimed"])
        self.assertFalse(report.to_dict()["receiver_processing_verified"])

    def test_request_response_and_declared_fault_are_actually_checked(self):
        cases = [
            (REQUEST, SELECTION, 6),
            (RESPONSE, {**SELECTION, "message_kind": "response", "observed_action": None}, 1),
            (
                FAULT,
                {
                    **SELECTION,
                    "message_kind": "fault",
                    "fault_name": "Problem",
                    "observed_action": None,
                },
                1,
            ),
        ]
        for content, selection, scalar_count in cases:
            with self.subTest(kind=selection["message_kind"]):
                report = self.analyze(content=content, selection=selection)
                self.assertEqual(
                    "consistent_with_supported_subset", report.to_dict()["analysis_status"]
                )
                self.assertEqual(scalar_count, report.to_dict()["statistics"]["scalar_checks"])
                self.assertEqual(
                    report.to_json(),
                    self.verify(report, content=content, selection=selection).to_json(),
                )

    def test_namespace_prefix_permutation_preserves_meaning_not_raw_hash(self):
        permuted = (
            REQUEST.replace(b"xmlns:f=", b"xmlns:local=")
            .replace(b"<f:", b"<local:")
            .replace(b"</f:", b"</local:")
        )
        report = self.analyze(content=permuted)
        self.assertEqual("consistent_with_supported_subset", report.to_dict()["analysis_status"])
        self.assertEqual(
            self.analyze().to_dict()["structural_summary"],
            report.to_dict()["structural_summary"],
        )
        self.assertNotEqual(
            self.analyze().to_dict()["envelope_source"], report.to_dict()["envelope_source"]
        )
        with self.assertRaises(soap.SoapAnalysisError):
            self.verify(report)

    def test_qname_resolution_uses_each_reference_nodes_namespace_scope(self):
        changes = [
            (b'type="f:FixtureInterface"', b'xmlns:f="urn:other" type="f:FixtureInterface"'),
            (
                b'<input message="f:LookupRequest"/>',
                b'<input xmlns:f="urn:other" message="f:LookupRequest"/>',
            ),
            (b'element="f:Lookup"', b'xmlns:f="urn:other" element="f:Lookup"'),
            (b'message="f:AuthHeader"', b'xmlns:f="urn:other" message="f:AuthHeader"'),
        ]
        for old, new in changes:
            with self.subTest(reference=old), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(wsdl=WSDL.replace(old, new))
        report = self.analyze(
            wsdl=WSDL.replace(
                b'name="id" type="xs:int"', b'name="id" xmlns:t="urn:other" type="t:int"'
            )
        )
        self.assert_code(report, "xsd_type_not_supported", status="unsupported")

    def test_exact_binding_operation_direction_and_part_joins(self):
        selections = [
            {**SELECTION, "binding_qname": "{urn:other}FixtureSoapBinding"},
            {**SELECTION, "operation_name": "Absent"},
            {**SELECTION, "message_kind": "fault", "fault_name": "Absent"},
        ]
        for selection in selections:
            with self.subTest(selection=selection), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(selection=selection)
        for old, new in [
            (b'parts="parameters"', b'parts="missing"'),
            (b'part="auth"', b'part="missing"'),
            (b'message="f:LookupRequest"', b'message="f:Absent"'),
        ]:
            with self.subTest(reference=old), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(wsdl=WSDL.replace(old, new))
        with self.assertRaises(soap.SoapAnalysisError):
            self.analyze(wsdl=MINIMAL_WSDL, selection={**SELECTION, "message_kind": "response"})

    def test_doc_literal_message_part_is_not_implicit_operation_wrapper(self):
        wsdl = WSDL.replace(b'<operation name="Lookup">', b'<operation name="RenamedOperation">')
        report = self.analyze(
            wsdl=wsdl, selection={**SELECTION, "operation_name": "RenamedOperation"}
        )
        self.assertEqual("consistent_with_supported_subset", report.to_dict()["analysis_status"])
        self.assertEqual(
            "{urn:fixture}Lookup", report.to_dict()["structural_summary"]["declared_payload_qname"]
        )
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"f:Lookup", b"f:RenamedOperation")),
            "body_element_mismatch",
            status="mismatch",
        )

    def test_envelope_version_name_order_and_cardinality(self):
        wrong_version = REQUEST.replace(soap.SOAP.encode(), soap.SOAP12.encode())
        self.assert_code(
            self.analyze(content=wrong_version), "soap_version_not_supported", status="unsupported"
        )
        self.assert_code(
            self.analyze(content=REQUEST.replace(soap.SOAP.encode(), b"urn:other")),
            "envelope_name_mismatch",
            status="mismatch",
        )
        header = b"<s:Header><f:Auth>synthetic-only</f:Auth></s:Header>"
        wrong_order = REQUEST.replace(header, b"").replace(b"</s:Body>", b"</s:Body>" + header)
        self.assert_code(
            self.analyze(content=wrong_order), "envelope_structure_mismatch", status="mismatch"
        )
        duplicated = REQUEST.replace(b"</s:Envelope>", b"<s:Body/></s:Envelope>")
        self.assert_code(
            self.analyze(content=duplicated), "envelope_structure_mismatch", status="mismatch"
        )
        empty = envelope(b"")
        self.assert_code(
            self.analyze(content=empty), "body_cardinality_mismatch", status="mismatch"
        )

    def test_unknown_header_is_unassessed_without_skipping_body_analysis(self):
        content = envelope(
            b"<f:Lookup><f:id>wrong</f:id></f:Lookup>", b"<f:Unspecified>opaque</f:Unspecified>"
        )
        report = self.analyze(content=content)
        self.assert_code(report, "unknown_header_semantics")
        self.assert_code(report, "declared_header_not_observed")
        self.assert_code(report, "scalar_lexical_mismatch", status="mismatch")
        valid = self.analyze(
            content=envelope(b"<f:Lookup><f:id>7</f:id></f:Lookup>", b"<f:Unspecified/>")
        )
        self.assert_code(valid, "unknown_header_semantics", status="partially_assessed")

    def test_header_must_understand_actor_and_namespace_are_distinct(self):
        for must in (b"0", b"1"):
            report = self.analyze(
                content=REQUEST.replace(b"<f:Auth>", b'<f:Auth s:mustUnderstand="' + must + b'">')
            )
            expected = "consistent_with_supported_subset" if must == b"0" else "partially_assessed"
            self.assertEqual(expected, report.to_dict()["analysis_status"])
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"<f:Auth>", b'<f:Auth s:mustUnderstand="true">')),
            "must_understand_lexical_mismatch",
            status="mismatch",
        )
        self.assert_code(
            self.analyze(
                content=REQUEST.replace(b"<f:Auth>", b'<f:Auth s:actor="urn:fixture:actor">')
            ),
            "header_actor_processing_unassessed",
            status="partially_assessed",
        )
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"f:Auth", b"Auth")),
            "header_namespace_missing",
            status="mismatch",
        )

    def test_missing_and_repeated_declared_headers_are_not_assumed_required(self):
        body = b"<f:Lookup><f:id>7</f:id></f:Lookup>"
        self.assert_code(
            self.analyze(content=envelope(body, None)),
            "declared_header_not_observed",
            status="partially_assessed",
        )
        self.assert_code(
            self.analyze(content=envelope(body, b"<f:Auth>a</f:Auth><f:Auth>b</f:Auth>")),
            "repeated_header_semantics_unassessed",
            status="partially_assessed",
        )

    def test_sequence_required_extra_order_and_cardinality_checks(self):
        cases = [
            (REQUEST.replace(b"<f:id>7</f:id>", b""), "field_cardinality_mismatch"),
            (REQUEST.replace(b"</f:Lookup>", b"<f:other/></f:Lookup>"), "field_not_declared"),
            (
                REQUEST.replace(b"<f:id>7</f:id>", b"").replace(
                    b"</f:Lookup>", b"<f:id>7</f:id></f:Lookup>"
                ),
                "sequence_order_mismatch",
            ),
            (
                REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>7</f:id><f:id>8</f:id>"),
                "field_cardinality_mismatch",
            ),
        ]
        for content, code in cases:
            with self.subTest(code=code):
                self.assert_code(self.analyze(content=content), code, status="mismatch")

    def test_optional_and_repeated_fields_use_compact_occurrence_counts(self):
        content = envelope(
            b"<f:Lookup><f:id>7</f:id>" + b"<f:label>a</f:label>" * 20 + b"</f:Lookup>"
        )
        report = self.analyze(content=content)
        self.assertEqual("consistent_with_supported_subset", report.to_dict()["analysis_status"])
        bound = WSDL.replace(b'maxOccurs="unbounded"', b'maxOccurs="50000"')
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(wsdl=bound, content=content).to_dict()["analysis_status"],
        )
        zero = WSDL.replace(b'maxOccurs="unbounded"', b'maxOccurs="0"')
        self.assert_code(self.analyze(wsdl=zero), "field_cardinality_mismatch", status="mismatch")
        for lexical in (b"9" * 4000, b"50001", b"-1", b"\xd9\xa1"):
            with self.subTest(lexical=lexical[:8]):
                self.assert_code(
                    self.analyze(
                        wsdl=WSDL.replace(b'maxOccurs="unbounded"', b'maxOccurs="' + lexical + b'"')
                    ),
                    "xsd_occurrence_bound_not_supported",
                    status="unsupported",
                )

    def test_scalar_lexicals_follow_xml_whitespace_and_ascii_numeric_subset(self):
        for scalar, marker, lexicals in [
            ("int", b"<f:id>7</f:id>", [b" \t+0007\r\n", b"-2147483648", b"2147483647", b"-000"]),
            ("boolean", b"<f:verbose>true</f:verbose>", [b"\n true \t", b"false", b"0", b"1"]),
            ("decimal", b"<f:ratio>+.50</f:ratio>", [b"\t-001.20\n", b"1.", b".5", b"+1"]),
        ]:
            tag = b"id" if scalar == "int" else b"verbose" if scalar == "boolean" else b"ratio"
            for lexical in lexicals:
                with self.subTest(scalar=scalar, lexical=lexical):
                    content = REQUEST.replace(
                        marker, b"<f:" + tag + b">" + lexical + b"</f:" + tag + b">"
                    )
                    self.assertEqual(
                        "consistent_with_supported_subset",
                        self.analyze(content=content).to_dict()["analysis_status"],
                    )

    def test_invalid_numeric_lexicals_do_not_claim_scalar_consistency(self):
        for tag, marker, lexicals in [
            (
                b"id",
                b"7",
                [b"2147483648", b"-2147483649", b"1.0", b"1 0", b"\xd9\xa7", b"9" * 4000],
            ),
            (b"verbose", b"true", [b"True", b"2", b"\xc2\xa0true\xc2\xa0"]),
            (b"ratio", b"+.50", [b"1e2", b"NaN", b"INF", b"1 2", b"\xd9\xa1.5"]),
        ]:
            old = b"<f:" + tag + b">" + marker + b"</f:" + tag + b">"
            for lexical in lexicals:
                with self.subTest(tag=tag, lexical=lexical[:16]):
                    content = REQUEST.replace(
                        old, b"<f:" + tag + b">" + lexical + b"</f:" + tag + b">"
                    )
                    self.assert_code(
                        self.analyze(content=content), "scalar_lexical_mismatch", status="mismatch"
                    )

    def test_local_element_namespace_forms_and_scalar_structure(self):
        unqualified = WSDL.replace(
            b'elementFormDefault="qualified"', b'elementFormDefault="unqualified"'
        )
        content = REQUEST
        for tag in (b"id", b"ratio", b"verbose", b"label"):
            content = content.replace(b"f:" + tag, tag)
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(wsdl=unqualified, content=content).to_dict()["analysis_status"],
        )
        self.assert_code(self.analyze(wsdl=unqualified), "field_not_declared", status="mismatch")
        explicit = WSDL.replace(b'name="id" type=', b'name="id" form="unqualified" type=')
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(wsdl=explicit, content=REQUEST.replace(b"f:id", b"id")).to_dict()[
                "analysis_status"
            ],
        )
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"<f:id>7</f:id>", b"<f:id><f:nested/></f:id>")),
            "scalar_structure_mismatch",
            status="mismatch",
        )

    def test_element_only_content_and_undeclared_attributes(self):
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"<f:Lookup>", b"<f:Lookup>not-element-only")),
            "soap_character_content",
            status="mismatch",
        )
        self.assert_code(
            self.analyze(content=REQUEST.replace(b"<f:id>", b'<f:id extra="not-declared">')),
            "unexpected_attribute",
            status="mismatch",
        )

    def test_soap11_fault_exact_structure_qname_and_detail(self):
        selection = {
            **SELECTION,
            "message_kind": "fault",
            "fault_name": "Problem",
            "observed_action": None,
        }
        cases = [
            (FAULT.replace(b"<faultcode>s:Server</faultcode>", b""), "fault_structure_mismatch"),
            (FAULT.replace(b"s:Server", b"missing:Server"), "fault_code_mismatch"),
            (
                FAULT.replace(b"<detail><f:Problem><f:code>17</f:code></f:Problem></detail>", b""),
                "fault_detail_missing",
            ),
            (FAULT.replace(b"f:Problem", b"f:Reply"), "body_element_mismatch"),
            (
                FAULT.replace(b"<f:code>17</f:code>", b"<f:code>wrong</f:code>"),
                "scalar_lexical_mismatch",
            ),
        ]
        for content, code in cases:
            with self.subTest(code=code):
                self.assert_code(
                    self.analyze(content=content, selection=selection), code, status="mismatch"
                )
        scoped = FAULT.replace(b"<faultcode>", b'<faultcode xmlns:c="urn:fixture:custom">').replace(
            b"s:Server", b"c:Custom"
        )
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(content=scoped, selection=selection).to_dict()["analysis_status"],
        )

    def test_fault_presence_and_extensions_are_not_silent_successes(self):
        self.assert_code(
            self.analyze(content=FAULT), "unexpected_fault_for_message_kind", status="mismatch"
        )
        selection = {
            **SELECTION,
            "message_kind": "fault",
            "fault_name": "Problem",
            "observed_action": None,
        }
        self.assert_code(
            self.analyze(selection=selection), "selected_fault_not_observed", status="mismatch"
        )
        namespaced = FAULT.replace(b"faultcode", b"f:faultcode")
        self.assert_code(
            self.analyze(content=namespaced, selection=selection),
            "fault_extension_not_supported",
            status="unsupported",
        )
        alongside = FAULT.replace(b"</s:Body>", b"<f:Reply>extra</f:Reply></s:Body>")
        self.assert_code(
            self.analyze(content=alongside, selection=selection),
            "fault_body_subset_not_supported",
            status="unsupported",
        )

    def test_action_is_exact_declared_metadata_not_authenticated_http(self):
        for action in (None, "", "urn:other"):
            with self.subTest(action=action):
                self.assert_code(
                    self.analyze(selection={**SELECTION, "observed_action": action}),
                    "action_mismatch",
                    status="mismatch",
                )
        for action in ("relative-action", ""):
            wsdl = WSDL.replace(b"urn:fixture:lookup", action.encode())
            report = self.analyze(wsdl=wsdl, selection={**SELECTION, "observed_action": action})
            self.assertEqual(
                "consistent_with_supported_subset", report.to_dict()["analysis_status"]
            )
            self.assertFalse(report.to_dict()["transport_metadata_authenticated"])
        response = {**SELECTION, "message_kind": "response"}
        self.assert_code(
            self.analyze(content=RESPONSE, selection=response),
            "response_action_semantics_unassessed",
            status="partially_assessed",
        )

    def test_duplicate_and_undefined_contract_symbols_fail_cleanly(self):
        cases = [
            WSDL.replace(b"</types>", b'</types><message name="LookupRequest"/>'),
            WSDL.replace(b"</portType>", b'</portType><portType name="FixtureInterface"/>'),
            WSDL.replace(
                b"</binding>",
                b'</binding><binding name="FixtureSoapBinding" type="f:FixtureInterface"/>',
            ),
            WSDL.replace(
                b'<xs:element name="Reply" type="xs:string"/>',
                b'<xs:element name="Reply" type="xs:string"/>' * 2,
            ),
            WSDL.replace(
                b'<part name="parameters" element="f:Lookup"/>',
                b'<part name="parameters" element="f:Lookup"/>' * 2,
            ),
            WSDL.replace(
                b'<input message="f:LookupRequest"/>', b'<input message="f:LookupRequest"/>' * 2
            ),
        ]
        for number, wsdl in enumerate(cases):
            with self.subTest(number=number), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(wsdl=wsdl)
        overloaded = WSDL.replace(
            b'<input message="f:LookupRequest"/>',
            b'<input message="f:LookupRequest"/></operation><operation name="Lookup">',
        )
        self.assert_code(
            self.analyze(wsdl=overloaded),
            "overloaded_wsdl_operation_not_supported",
            status="unsupported",
        )

    def test_unsupported_xsd_and_soap_features_never_claim_full_validation(self):
        cases = [
            (
                WSDL.replace(b"<xs:sequence>", b"<xs:choice>").replace(
                    b"</xs:sequence>", b"</xs:choice>"
                ),
                "contract_construct_not_supported",
            ),
            (WSDL.replace(b'type="xs:int"', b'type="xs:integer"'), "xsd_type_not_supported"),
            (WSDL.replace(b'style="document"', b'style="rpc"'), "soap_binding_not_supported"),
            (WSDL.replace(b'use="literal"', b'use="encoded"'), "encoded_soap_not_supported"),
            (
                WSDL.replace(
                    b'<part name="parameters" element="f:Lookup"/>',
                    b'<part name="parameters" element="f:Lookup"/>'
                    b'<part name="second" element="f:Reply"/>',
                ).replace(b' parts="parameters"', b""),
                "multipart_body_not_supported",
            ),
            (
                WSDL.replace(
                    b'<xs:element name="label"', b'<xs:element nillable="true" name="label"'
                ),
                "contract_attribute_not_supported",
            ),
        ]
        for wsdl, code in cases:
            with self.subTest(code=code):
                report = self.analyze(wsdl=wsdl)
                self.assert_code(report, code, status="unsupported")
                self.assertFalse(report.to_dict()["full_xsd_validation_claimed"])
                self.assertEqual(report.to_json(), self.verify(report, wsdl=wsdl).to_json())
        xsi = REQUEST.replace(
            b"<f:Lookup>",
            b'<f:Lookup xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true">',
        )
        self.assert_code(
            self.analyze(content=xsi), "xsi_override_not_supported", status="unsupported"
        )
        encoded = REQUEST.replace(b"<s:Body>", b'<s:Body s:encodingStyle="urn:fixture:encoding">')
        self.assert_code(
            self.analyze(content=encoded), "soap_encoding_not_supported", status="unsupported"
        )

    def test_hidden_children_or_text_in_contract_leaves_are_not_ignored(self):
        for old, new in [
            (b'type="xs:string"/>', b'type="xs:string"><xs:complexType/></xs:element>'),
            (
                b'<s:body use="literal" parts="parameters"/>',
                b'<s:body use="literal" parts="parameters"><s:unexpected/></s:body>',
            ),
            (
                b'<part name="parameters" element="f:Lookup"/>',
                b'<part name="parameters" element="f:Lookup"><extra/></part>',
            ),
        ]:
            with self.subTest(old=old):
                self.assert_code(
                    self.analyze(wsdl=WSDL.replace(old, new, 1)),
                    "contract_construct_not_supported",
                    status="unsupported",
                )
        with self.assertRaises(soap.SoapAnalysisError):
            self.analyze(
                wsdl=WSDL.replace(
                    b'<part name="parameters" element="f:Lookup"/>',
                    b'<part name="parameters" element="f:Lookup">text</part>',
                )
            )

    def test_external_resolution_syntax_is_denied_without_source_hashing(self):
        cases = [
            b'<!DOCTYPE definitions SYSTEM "https://invalid.example/external">' + WSDL,
            WSDL.replace(
                b"<types>",
                b'<import namespace="urn:other" location="https://invalid.example/wsdl"/><types>',
            ),
            WSDL.replace(
                b'<xs:element name="Lookup">',
                b'<xs:include schemaLocation="https://invalid.example/schema"/>'
                b'<xs:element name="Lookup">',
            ),
            WSDL.replace(
                b'<xs:element name="Lookup">',
                b'<i:include xmlns:i="http://www.w3.org/2001/XInclude"'
                b' href="https://invalid.example/content"/><xs:element name="Lookup">',
            ),
        ]
        for wsdl in cases:
            with (
                self.subTest(prefix=wsdl[:45]),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                self.analyze(wsdl=wsdl)

    def test_doctype_entity_cdata_and_processing_instruction_preflight(self):
        contents = [
            b'<!DOCTYPE root [<!ENTITY e "expansion">]>' + REQUEST,
            b"<?other data?>" + REQUEST,
            REQUEST.replace(b"<f:id>7</f:id>", b"<f:id><![CDATA[7]]></f:id>"),
            REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>&undeclared;</f:id>"),
        ]
        for content in contents[:3]:
            with (
                self.subTest(prefix=content[:30]),
                mock.patch.object(
                    soap.expat, "ParserCreate", side_effect=AssertionError("must not parse")
                ),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                self.analyze(content=content)
        with self.assertRaises(soap.SoapAnalysisError):
            self.analyze(content=contents[3])

    def test_malformed_xml_dup_attributes_and_undefined_prefixes(self):
        contents = [
            REQUEST[:-10],
            REQUEST + b"<second/>",
            REQUEST.replace(b"<f:id>", b'<f:id a="1" a="2">'),
            REQUEST.replace(b"<f:id>", b"<missing:id>").replace(b"</f:id>", b"</missing:id>"),
            b"\xff" + REQUEST,
        ]
        for content in contents:
            with self.subTest(prefix=content[:30]), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(content=content)
        declared = b'<?xml version="1.0" encoding="UTF-8"?>' + REQUEST
        commented = b"<!-- synthetic -->" + REQUEST
        for content in (declared, commented):
            self.assertEqual(
                "consistent_with_supported_subset",
                self.analyze(content=content).to_dict()["analysis_status"],
            )

    def test_xml_byte_depth_token_and_node_limits_before_parser_or_hash(self):
        cases = [
            (replace(LIMITS, max_wsdl_bytes=len(WSDL) - 1), WSDL, REQUEST),
            (replace(LIMITS, max_envelope_bytes=len(REQUEST) - 1), WSDL, REQUEST),
            (replace(LIMITS, max_xml_depth=2), WSDL, REQUEST),
            (replace(LIMITS, max_xml_tokens=2), WSDL, REQUEST),
            (replace(LIMITS, max_xml_nodes=2), WSDL, REQUEST),
        ]
        for limits, wsdl, content in cases:
            with (
                self.subTest(limits=limits),
                mock.patch.object(
                    soap.expat, "ParserCreate", side_effect=AssertionError("must not parse")
                ),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                self.analyze(wsdl=wsdl, content=content, limits=limits)

    def test_observation_budget_fails_without_truncating_or_hashing(self):
        content = REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>bad</f:id><f:id>bad</f:id>")
        with (
            mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
            self.assertRaisesRegex(soap.SoapAnalysisError, "observation limit"),
        ):
            self.analyze(content=content, limits=replace(LIMITS, max_observations=1))

    def test_limits_are_explicit_native_and_fixed_hard_ceilings(self):
        for key, ceiling in soap._LIMITS.items():
            for value in (True, 1.0, 0, -1, ceiling + 1):
                with self.subTest(key=key, value=value), self.assertRaises(soap.SoapAnalysisError):
                    replace(LIMITS, **{key: value})
        incomplete = object.__new__(soap.SoapAnalysisLimits)
        with (
            mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
            self.assertRaises(soap.SoapAnalysisError),
        ):
            self.analyze(limits=incomplete)

    def test_native_aliases_and_incomplete_public_wrappers_are_denied(self):
        class ForeignText(str):
            pass

        class ForeignBytes(bytes):
            pass

        class ForeignDict(dict):
            pass

        class ForeignLimits(soap.SoapAnalysisLimits):
            pass

        for selection in (
            ForeignDict(SELECTION),
            {**SELECTION, ForeignText("unexpected"): "value"},
            {**SELECTION, "operation_name": ForeignText("Lookup")},
        ):
            with self.subTest(selection=selection), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(selection=selection)
        for content in (ForeignBytes(REQUEST), bytearray(REQUEST)):
            with self.subTest(type=type(content)), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(content=content)
        with self.assertRaises(soap.SoapAnalysisError):
            self.analyze(limits=ForeignLimits(*LIMITS.to_dict().values()))
        with self.assertRaises(soap.SoapAnalysisError):
            soap.analyze_soap_contract_instance(
                wsdl_content=WSDL,
                envelope_content=REQUEST,
                wsdl_source_id=ForeignText("fixture-wsdl"),
                envelope_source_id="fixture-envelope",
                selection=SELECTION,
                limits=LIMITS,
            )
        incomplete = object.__new__(soap.SoapAnalysisReport)
        with self.assertRaises(soap.SoapAnalysisError):
            self.verify(incomplete)

    def test_selection_fields_and_source_ids_are_closed(self):
        for selection in (
            {**SELECTION, "extra": "value"},
            {**SELECTION, "binding_qname": "FixtureSoapBinding"},
            {**SELECTION, "operation_name": "namespace:Lookup"},
            {**SELECTION, "fault_name": "not-a-fault"},
            {**SELECTION, "message_kind": "subscription"},
        ):
            with self.subTest(selection=selection), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(selection=selection)
        for identifier in ("", "../source", "source with space", "x" * 129):
            with self.subTest(identifier=identifier), self.assertRaises(soap.SoapAnalysisError):
                soap.analyze_soap_contract_instance(
                    wsdl_content=WSDL,
                    envelope_content=REQUEST,
                    wsdl_source_id=identifier,
                    envelope_source_id="fixture-envelope",
                    selection=SELECTION,
                    limits=LIMITS,
                )

    def test_native_graph_budgets_charge_repeated_and_escaped_values_before_dumps(self):
        shared = "\\" * 4096
        excessive = {**SELECTION, "extra": [shared] * 150}
        deep = []
        for _ in range(34):
            deep = [deep]
        for selection in (
            excessive,
            {**SELECTION, "extra": deep},
            {**SELECTION, "extra": [None] * 50001},
        ):
            with (
                self.subTest(shape=type(selection["extra"])),
                mock.patch.object(
                    soap.json, "dumps", side_effect=AssertionError("must not serialize")
                ),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                self.analyze(selection=selection)
        cyclic = []
        cyclic.append(cyclic)
        with self.assertRaises(soap.SoapAnalysisError):
            self.analyze(selection={**SELECTION, "extra": cyclic})

    def test_raw_json_byte_depth_node_and_integer_bounds_before_decoder_and_hash(self):
        values = [
            " " * (soap.MAX_DOCUMENT_BYTES + 1),
            "[" * 34 + "null" + "]" * 34,
            "[" + ",".join(["null"] * 50000) + "]",
            '{"schema_version":' + "9" * 10000 + "}",
            '{"schema_version":9223372036854775808}',
            '{"schema_version":-9223372036854775808}',
        ]
        for text in values:
            with (
                self.subTest(prefix=text[:35]),
                mock.patch.object(
                    soap.json, "loads", side_effect=AssertionError("must not decode")
                ),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                soap.SoapAnalysisReport.from_json(text)
        with mock.patch.object(soap.json, "loads", wraps=json.loads) as loader:
            soap.SoapAnalysisReport.from_json(self.analyze().to_json())
        self.assertTrue(any("parse_int" in call.kwargs for call in loader.call_args_list))

    def test_report_json_duplicate_keys_floats_and_nonfinite_are_denied(self):
        original = self.analyze().to_json()
        documents = [
            original.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            original.replace('"schema_version":1', '"schema_version":1.0'),
            original.replace('"schema_version":1', '"schema_version":NaN'),
            original.replace('"schema_version":1', '"schema_version":Infinity'),
        ]
        for text in documents:
            with self.subTest(fragment=text[:30]), self.assertRaises(soap.SoapAnalysisError):
                soap.SoapAnalysisReport.from_json(text)

    def test_report_exact_primitives_effects_and_derived_count_checks(self):
        original = self.analyze().to_dict()
        cases = []
        for key in ("schema_version", "observation_count", "offline_only"):
            document = copy.deepcopy(original)
            document[key] = True if key != "offline_only" else 1
            cases.append(document)
        for key in ("scalar_checks", "sequence_checks"):
            document = copy.deepcopy(original)
            document["statistics"][key] = float(document["statistics"][key])
            cases.append(document)
        for value in (0, 0.0):
            document = copy.deepcopy(original)
            document["structural_summary"]["fault_present"] = value
            cases.append(document)
        document = copy.deepcopy(original)
        document["operational_effects"]["target"] = "granted"
        cases.append(document)
        document = copy.deepcopy(original)
        document["qualification_claimed"] = True
        cases.append(document)
        for document in cases:
            with self.subTest(value=document), self.assertRaises(soap.SoapAnalysisError):
                soap.SoapAnalysisReport.from_dict(addressed(document))

    def test_coherently_rehashed_false_observations_fail_source_replay(self):
        original = self.analyze().to_dict()
        changed = copy.deepcopy(original)
        changed["observations"] = [
            {
                "kind": "violation",
                "code": "scalar_lexical_mismatch",
                "path": "/Envelope/Body/part/field[0]",
                "expected": "xsd:int lexical form",
                "actual": "outside lexical subset",
            }
        ]
        changed["observation_count"] = 1
        changed["analysis_status"] = "mismatch"
        self_consistent = soap.SoapAnalysisReport.from_dict(addressed(changed))
        self.assertNotEqual(original["report_sha256"], self_consistent.to_dict()["report_sha256"])
        with self.assertRaisesRegex(soap.SoapAnalysisError, "does not reproduce"):
            self.verify(self_consistent)
        mismatch = self.analyze(content=REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>bad</f:id>"))
        changed = mismatch.to_dict()
        changed["observations"] = []
        changed["observation_count"] = 0
        changed["analysis_status"] = "consistent_with_supported_subset"
        with self.assertRaisesRegex(soap.SoapAnalysisError, "does not reproduce"):
            self.verify(
                soap.SoapAnalysisReport.from_dict(addressed(changed)),
                content=REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>bad</f:id>"),
            )

    def test_rehashed_statistics_summary_and_source_changes_fail_full_replay(self):
        original = self.analyze().to_dict()
        cases = []
        for key in ("scalar_checks", "sequence_checks", "wsdl_xml_tokens"):
            document = copy.deepcopy(original)
            document["statistics"][key] += 1
            cases.append(document)
        document = copy.deepcopy(original)
        document["structural_summary"]["fault_present"] = True
        cases.append(document)
        document = copy.deepcopy(original)
        document["wsdl_source"]["source_id"] = "other-source"
        cases.append(document)
        for document in cases:
            with self.subTest(document=document):
                report = soap.SoapAnalysisReport.from_dict(addressed(document))
                with self.assertRaisesRegex(soap.SoapAnalysisError, "does not reproduce"):
                    self.verify(report)

    def test_source_selection_and_limit_substitution_is_detected(self):
        report = self.analyze()
        cases = [
            {"wsdl": WSDL + b"\n"},
            {"content": REQUEST + b"\n"},
            {"selection": {**SELECTION, "observed_action": "urn:other"}},
            {"limits": replace(LIMITS, max_xml_tokens=2049)},
        ]
        for values in cases:
            with (
                self.subTest(values=values),
                self.assertRaisesRegex(soap.SoapAnalysisError, "does not reproduce"),
            ):
                self.verify(report, **values)

    def test_forged_public_report_document_is_revalidated_at_use(self):
        report = self.analyze()
        object.__setattr__(
            report,
            "document_json",
            report.to_json().replace('"schema_version":1', '"schema_version":true'),
        )
        with self.assertRaises(soap.SoapAnalysisError):
            self.verify(report)
        with self.assertRaises(soap.SoapAnalysisError):
            report.to_dict()
        with self.assertRaises(soap.SoapAnalysisError):
            soap.SoapAnalysisReport(" " + self.analyze().to_json())

    def test_predefined_numeric_character_references_remain_inert(self):
        content = REQUEST.replace(b"<f:id>7</f:id>", b"<f:id>&#55;</f:id>").replace(
            b"opaque-first", b"opaque&amp;first"
        )
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(content=content).to_dict()["analysis_status"],
        )
        self.assertNotIn("opaque&first", self.analyze(content=content).to_json())

    def test_wide_literal_and_native_integer_bounds_before_report_hash(self):
        documents = []
        original = self.analyze().to_dict()
        for value in (2**63, -(2**63), True, 1.0):
            document = copy.deepcopy(original)
            document["statistics"]["scalar_checks"] = value
            documents.append(document)
        for document in documents:
            with (
                self.subTest(value=document["statistics"]["scalar_checks"]),
                mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
                self.assertRaises(soap.SoapAnalysisError),
            ):
                soap.SoapAnalysisReport.from_dict(document)
        with mock.patch.object(soap.json, "loads", wraps=json.loads) as loader:
            with self.assertRaises(soap.SoapAnalysisError):
                soap.SoapAnalysisReport.from_json('{"value":9223372036854775807}')
        integer_hook = next(
            call.kwargs["parse_int"] for call in loader.call_args_list if "parse_int" in call.kwargs
        )
        self.assertEqual(2**63 - 1, integer_hook("9223372036854775807"))
        self.assertEqual(-(2**63 - 1), integer_hook("-9223372036854775807"))
        for lexical in ("9" * 10000, "9223372036854775808", "-9223372036854775808"):
            with self.subTest(lexical=lexical[:24]), self.assertRaises(soap.SoapAnalysisError):
                integer_hook(lexical)

    def test_substituted_envelope_and_wsdl_source_hashes_are_not_authenticity(self):
        document = self.analyze().to_dict()
        for side in ("wsdl", "envelope"):
            changed = copy.deepcopy(document)
            changed[f"{side}_source"]["sha256"] = "sha256:" + "a" * 64
            report = soap.SoapAnalysisReport.from_dict(addressed(changed))
            with (
                self.subTest(side=side),
                self.assertRaisesRegex(soap.SoapAnalysisError, "does not reproduce"),
            ):
                self.verify(report)

    def test_unknown_wssecurity_header_is_never_processed_or_approved(self):
        header = (
            b'<w:Security xmlns:w="urn:synthetic:wssecurity" s:mustUnderstand="1">'
            b"<w:Unprocessed>not-a-credential</w:Unprocessed></w:Security>"
        )
        report = self.analyze(content=envelope(b"<f:Lookup><f:id>7</f:id></f:Lookup>", header))
        self.assert_code(report, "unknown_header_semantics", status="partially_assessed")
        self.assert_code(report, "must_understand_processing_unassessed")
        self.assertFalse(report.to_dict()["receiver_processing_verified"])
        self.assertFalse(report.to_dict()["positive_use_approved"])
        self.assertNotIn("not-a-credential", report.to_json())

    def test_xmlrpc_is_not_mistaken_for_a_supported_soap_envelope(self):
        report = self.analyze(
            content=b"<methodCall><methodName>synthetic.only</methodName><params/></methodCall>"
        )
        self.assert_code(report, "envelope_name_mismatch", status="mismatch")
        self.assertIsNone(report.to_dict()["structural_summary"]["soap_version"])
        self.assertFalse(report.to_dict()["full_xsd_validation_claimed"])

    def test_body_parts_do_not_collapse_non_xml_unicode_whitespace(self):
        for whitespace in (b"&#160;", b"&#xA0;", b"\xc2\xa0", b"&#8195;", b"&#x2003;"):
            wsdl = WSDL.replace(
                b'parts="parameters"', b'parts="' + whitespace + b"parameters" + whitespace + b'"'
            )
            with self.subTest(whitespace=whitespace), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(wsdl=wsdl)

    def test_body_parts_xml_whitespace_omission_and_explicit_selection(self):
        for parts in (
            b'parts=" parameters "',
            b'parts="&#x9;parameters&#xA;"',
            b'parts="&#xD;parameters&#x9;"',
            b'parts=" \tparameters\r\n "',
            b"",
        ):
            wsdl = WSDL.replace(b'parts="parameters"', parts)
            with self.subTest(parts=parts):
                report = self.analyze(wsdl=wsdl)
                self.assertEqual(
                    "consistent_with_supported_subset", report.to_dict()["analysis_status"]
                )
                self.assertEqual(report.to_json(), self.verify(report, wsdl=wsdl).to_json())
        multipart = WSDL.replace(
            b'<part name="parameters" element="f:Lookup"/>',
            b'<part name="parameters" element="f:Lookup"/><part name="other" element="f:Reply"/>',
        )
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(wsdl=multipart).to_dict()["analysis_status"],
        )
        for parts in (b'parts="parameters other"', b""):
            with self.subTest(parts=parts):
                report = self.analyze(wsdl=multipart.replace(b'parts="parameters"', parts))
                self.assert_code(report, "multipart_body_not_supported", status="unsupported")
        for parts in (b'parts=""', b'parts=" :parameters "', b'parts="unknown"'):
            with self.subTest(parts=parts), self.assertRaises(soap.SoapAnalysisError):
                self.analyze(wsdl=WSDL.replace(b'parts="parameters"', parts))

    def test_namespace_context_storage_is_linear_in_declared_bindings(self):
        limits = soap.SoapAnalysisLimits(65536, 8192, 4096, 1024, 32, 128)
        retained_counts = []
        for count in (25, 50, 100, 200):
            declarations = b"".join(
                b' xmlns:p%d="urn:synthetic:%d"' % (index, index) for index in range(count)
            )
            services = b"".join(b'<service name="Synthetic%d"/>' % index for index in range(count))
            wsdl = WSDL.replace(b"<definitions ", b"<definitions" + declarations + b" ", 1)
            wsdl = wsdl.replace(b"</definitions>", services + b"</definitions>")
            contexts = []
            original = soap._Node

            def measured(*args, **kwargs):
                node = original(*args, **kwargs)
                contexts.append(node.namespaces)
                return node

            with mock.patch.object(soap, "_Node", side_effect=measured):
                report = self.analyze(wsdl=wsdl, limits=limits)
            seen = set()
            entries = 0
            for context in contexts:
                while context is not None and id(context) not in seen:
                    seen.add(id(context))
                    entries += len(getattr(context, "bindings", context))
                    context = getattr(context, "parent", None)
            retained_counts.append(entries)
            statistics = report.to_dict()["statistics"]
            with self.subTest(declarations=count):
                self.assertEqual(
                    "consistent_with_supported_subset", report.to_dict()["analysis_status"]
                )
                self.assertLessEqual(
                    entries,
                    statistics["wsdl_xml_nodes"] + statistics["envelope_xml_nodes"] + 2,
                )
                self.assertEqual(count + 8, entries)
                self.assertEqual(2, len(seen))
                self.assertEqual(
                    report.to_json(), self.verify(report, wsdl=wsdl, limits=limits).to_json()
                )
        self.assertLessEqual(retained_counts[-1], 9 * retained_counts[0])

    def test_namespace_context_bindings_are_immutable(self):
        contexts = []
        original = soap._Node

        def measured(*args, **kwargs):
            node = original(*args, **kwargs)
            contexts.append(node.namespaces)
            return node

        with mock.patch.object(soap, "_Node", side_effect=measured):
            self.analyze()
        bindings = getattr(contexts[0], "bindings", contexts[0])
        with self.assertRaises(TypeError):
            bindings["synthetic"] = "urn:unsupported-mutation"

    def test_namespace_local_overrides_and_default_qnames_do_not_leak(self):
        cases = (
            WSDL.replace(
                b'<part name="parameters" element="f:Lookup"/>',
                b'<w:part xmlns:w="http://schemas.xmlsoap.org/wsdl/" xmlns="urn:fixture"'
                b' name="parameters" element="Lookup"/>',
            ),
            WSDL.replace(
                b'<part name="parameters" element="f:Lookup"/>',
                b'<part xmlns:f="urn:shadow" xmlns:g="urn:fixture" name="parameters"'
                b' element="g:Lookup"/>',
            ),
            WSDL.replace(
                b'<xs:element name="id" type="xs:int"/>',
                b'<xs:element xmlns="http://www.w3.org/2001/XMLSchema" name="id" type="int"/>',
            ),
        )
        for wsdl in cases:
            with self.subTest(wsdl=wsdl):
                report = self.analyze(wsdl=wsdl)
                self.assertEqual(
                    "consistent_with_supported_subset", report.to_dict()["analysis_status"]
                )
                self.assertEqual(report.to_json(), self.verify(report, wsdl=wsdl).to_json())
        content = REQUEST.replace(
            b"<f:Lookup>",
            b'<Lookup xmlns="urn:fixture" xmlns:f="urn:shadow" xmlns:g="urn:fixture">',
        ).replace(b"</f:Lookup>", b"</Lookup>")
        body_start = content.index(b"<Lookup ")
        content = content[:body_start] + content[body_start:].replace(b"<f:", b"<g:").replace(
            b"</f:", b"</g:"
        )
        report = self.analyze(content=content)
        self.assertEqual("consistent_with_supported_subset", report.to_dict()["analysis_status"])
        self.assertEqual(report.to_json(), self.verify(report, content=content).to_json())

    def test_namespace_declaration_budget_is_checked_before_parser_allocation(self):
        declarations = b"".join(
            b' xmlns:p%d="urn:synthetic:%d"' % (index, index) for index in range(200)
        )
        wsdl = WSDL.replace(b"<definitions ", b"<definitions" + declarations + b" ", 1)
        limits = soap.SoapAnalysisLimits(65536, 8192, 4096, 1024, 32, 128)
        report = self.analyze(wsdl=wsdl, limits=limits)
        exact_nodes = report.to_dict()["statistics"]["wsdl_xml_nodes"]
        exact_limits = replace(limits, max_xml_nodes=exact_nodes)
        self.assertEqual(
            "consistent_with_supported_subset",
            self.analyze(wsdl=wsdl, limits=exact_limits).to_dict()["analysis_status"],
        )
        with (
            mock.patch.object(
                soap.expat, "ParserCreate", side_effect=AssertionError("must not parse")
            ),
            mock.patch.object(soap, "_hash", side_effect=AssertionError("must not hash")),
            self.assertRaisesRegex(soap.SoapAnalysisError, "before parsing"),
        ):
            self.analyze(wsdl=wsdl, limits=replace(exact_limits, max_xml_nodes=exact_nodes - 1))


if __name__ == "__main__":
    unittest.main()

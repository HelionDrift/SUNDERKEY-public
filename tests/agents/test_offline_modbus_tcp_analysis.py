"""Independent inert encoders and finite controls for supplied Modbus read structure."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest import mock

from sunderkey import offline_modbus_tcp_analysis as m


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def word(value):
    return bytes((value // 256, value % 256))


def adu(pdu, *, transaction=0x1234, protocol=0, unit=1, length=None):
    size = len(pdu) + 1 if length is None else length
    return word(transaction) + word(protocol) + word(size) + bytes((unit,)) + pdu


def model(request, response, context="bridge"):
    return {
        "schema_version": 1,
        "routing_context": context,
        "request_base64": base64.b64encode(request).decode("ascii"),
        "response_base64": base64.b64encode(response).decode("ascii"),
    }


def read_pair(function=3, *, start=107, quantity=3, values=None, context="bridge"):
    request = adu(bytes((function,)) + word(start) + word(quantity))
    if values is None:
        values = (
            [555, 0, 100] if quantity == 3 else [index * 257 % 65536 for index in range(quantity)]
        )
    if function in (1, 2):
        payload = bytes(
            sum((values[index + bit] & 1) << bit for bit in range(min(8, quantity - index)))
            for index in range(0, quantity, 8)
        )
    else:
        payload = b"".join(word(value) for value in values)
    return model(request, adu(bytes((function, len(payload))) + payload), context)


def report(value):
    return m.analyze_supplied_modbus_tcp(value).to_dict()


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        m.DOMAIN.encode("ascii") + b"\n" + canonical(body).encode("ascii")
    ).hexdigest()
    document["analysis_sha256"] = "sha256:" + digest
    document["analysis_id"] = "MBA-" + digest[:32].upper()
    return document


class ModbusTcpAnalysisTests(unittest.TestCase):
    def test_public_fixture_literal_goldens_and_decoded_facts(self):
        value = m.component_fixture()
        self.assertEqual(value, read_pair())
        actual = report(value)
        self.assertEqual(actual["analysis_id"], "MBA-E5E5C5DE7EDB86092DA55CBB427CE751")
        self.assertEqual(
            actual["analysis_sha256"],
            "sha256:e5e5c5de7edb86092da55cbb427ce7518510df8b459c458da13d5009ebf23c19",
        )
        self.assertEqual(
            actual["source_model_sha256"],
            "sha256:a8bc000ef961536de31f5824c1c4cd747ec305f406dfccff7925a45243dc7362",
        )
        self.assertEqual(
            actual["source_bytes"]["request_sha256"],
            "sha256:8f4cd21978cca1c7e69acfcb1346d5e9092080a32423733bb5de1fd49bfe7f94",
        )
        self.assertEqual(
            actual["source_bytes"]["response_sha256"],
            "sha256:97be12e00f702d304e7b0a01abbc786ed92449ba532e531ae8a07756a84193c8",
        )
        self.assertEqual(actual["request"]["starting_address"], 107)
        self.assertEqual(actual["request"]["quantity"], 3)
        self.assertEqual(actual["response"]["register_values"], [555, 0, 100])
        self.assertEqual(actual["outcome"], "consistent_supported_read_structure")
        self.assertEqual(actual["contradictions"], [])

    def test_all_public_round_trips_preserve_exact_identity(self):
        value = m.component_fixture()
        original = m.analyze_supplied_modbus_tcp(value)
        for candidate in (
            m.ModbusTcpAnalysis(original.to_json()),
            m.ModbusTcpAnalysis.from_dict(original.to_dict()),
            m.ModbusTcpAnalysis.from_json(original.to_json()),
            m.analyze_supplied_modbus_tcp_bytes(model_bytes=canonical(value).encode("ascii")),
            m.verify_supplied_modbus_tcp_analysis(original, model=value),
        ):
            self.assertEqual(candidate.to_json(), original.to_json())

    def test_independent_bit_encoder_oracle_all_quantities(self):
        for function in (1, 2):
            for quantity in range(1, 33):
                values = [int(index % 3 == 1) for index in range(quantity)]
                actual = report(read_pair(function, quantity=quantity, values=values))
                with self.subTest(function=function, quantity=quantity):
                    self.assertEqual(actual["response"]["bit_values"], values)
                    self.assertEqual(actual["response"]["byte_count"], (quantity + 7) // 8)
                    self.assertTrue(actual["correlation_checks"]["zero_unused_padding_bits"])
                    self.assertEqual(actual["outcome"], "consistent_supported_read_structure")

    def test_independent_register_encoder_oracle(self):
        for function in (3, 4):
            for quantity in range(1, 17):
                values = [index * 503 % 65536 for index in range(quantity)]
                actual = report(read_pair(function, quantity=quantity, values=values))
                with self.subTest(function=function, quantity=quantity):
                    self.assertEqual(actual["response"]["register_values"], values)
                    self.assertEqual(actual["response"]["byte_count"], 2 * quantity)
                    self.assertEqual(actual["outcome"], "consistent_supported_read_structure")

    def test_protocol_maximum_read_quantities_are_supported(self):
        for function in (1, 2, 3, 4):
            quantity = 2000 if function in (1, 2) else 125
            values = [index % 2 for index in range(quantity)]
            actual = report(read_pair(function, start=0, quantity=quantity, values=values))
            self.assertEqual(actual["outcome"], "consistent_supported_read_structure")
            self.assertEqual(
                len(
                    actual["response"]["bit_values"]
                    if function in (1, 2)
                    else actual["response"]["register_values"]
                ),
                quantity,
            )

    def test_quantities_zero_and_above_function_bound_are_contradictions(self):
        for function in (1, 2, 3, 4):
            for quantity in (0, 2001 if function in (1, 2) else 126):
                request = adu(bytes((function,)) + word(0) + word(quantity))
                response = adu(bytes((function + 128, 3)))
                actual = report(model(request, response))
                self.assertIn("read_quantity_outside_function_range", actual["contradictions"])
                self.assertEqual(actual["outcome"], "structural_contradictions_observed")

    def test_address_endpoint_arithmetic_does_not_invent_a_plc_map(self):
        self.assertEqual(
            report(read_pair(start=65535, quantity=1, values=[7]))["outcome"],
            "consistent_supported_read_structure",
        )
        actual = report(read_pair(start=65535, quantity=2, values=[7, 9]))
        self.assertIn("read_address_range_exceeds_unsigned16", actual["contradictions"])
        self.assertFalse(actual["claims"]["register_or_coil_truth_proven"])

    def test_all_truncated_prefixes_withhold_clean_structure(self):
        value = m.component_fixture()
        request = base64.b64decode(value["request_base64"])
        response = base64.b64decode(value["response_base64"])
        for side, raw in (("request", request), ("response", response)):
            for length in range(len(raw)):
                changed = dict(value)
                changed[side + "_base64"] = base64.b64encode(raw[:length]).decode("ascii")
                actual = report(changed)
                with self.subTest(side=side, length=length):
                    self.assertFalse(actual["outcome"].startswith("consistent_"))
                    self.assertTrue(actual["unassessed_reasons"])

    def test_trailing_bytes_are_not_silently_parsed_as_a_second_message(self):
        request = adu(b"\x03\x00\x00\x00\x01")
        response = adu(b"\x03\x02\x00\x01")
        for left, right, code in (
            (request + b"x", response, "request"),
            (request, response + b"x", "response"),
        ):
            actual = report(model(left, right))
            self.assertIn(code + "_trailing_bytes_after_declared_adu", actual["contradictions"])

    def test_declared_lengths_below_minimum_or_above_protocol_limit(self):
        for length, code in (
            (0, "request_mbap_length_below_unit_and_function"),
            (1, "request_mbap_length_below_unit_and_function"),
            (255, "request_mbap_length_above_protocol_adu_limit"),
            (65535, "request_mbap_length_above_protocol_adu_limit"),
        ):
            actual = report(
                model(adu(b"\x03\x00\x00\x00\x01", length=length), adu(b"\x03\x02\x00\x01"))
            )
            self.assertIn(code, actual["contradictions"])

    def test_exact_260_byte_unknown_adu_and_261_byte_software_rejection(self):
        request = adu(b"\x05" + b"x" * 252)
        self.assertEqual(len(request), 260)
        actual = report(model(request, adu(b"\x05")))
        self.assertIn("request_function_outside_read_projection", actual["unassessed_reasons"])
        with self.assertRaises(m.ModbusTcpAnalysisError):
            m.analyze_supplied_modbus_tcp(model(request + b"x", adu(b"\x05")))

    def test_non_modbus_protocol_fields_remain_unassessed(self):
        for side in ("request", "response"):
            value = m.component_fixture()
            raw = bytearray(base64.b64decode(value[side + "_base64"]))
            raw[2:4] = word(7)
            value[side + "_base64"] = base64.b64encode(raw).decode("ascii")
            actual = report(value)
            self.assertIn(side + "_non_modbus_protocol_identifier", actual["unassessed_reasons"])
            self.assertEqual(actual["outcome"], "incomplete_or_unassessed")

    def test_transaction_correlation_is_exact_but_not_connection_proof(self):
        request = adu(b"\x03\x00\x00\x00\x01", transaction=65535)
        response = adu(b"\x03\x02\x00\x01", transaction=0)
        actual = report(model(request, response))
        self.assertIn("transaction_identifier_mismatch", actual["contradictions"])
        self.assertFalse(actual["claims"]["shared_connection_proven"])

    def test_unit_mismatch_respects_all_three_declared_routing_contexts(self):
        request = adu(b"\x03\x00\x00\x00\x01", unit=1)
        response = adu(b"\x03\x02\x00\x01", unit=255)
        outcomes = {}
        for context in ("direct", "bridge", "unknown"):
            actual = report(model(request, response, context))
            outcomes[context] = actual["outcome"]
            self.assertFalse(actual["correlation_checks"]["unit_ids_equal"])
            self.assertEqual(
                "bridge_unit_identifier_mismatch" in actual["contradictions"], context == "bridge"
            )
        self.assertEqual(outcomes["direct"], "consistent_supported_read_structure")
        self.assertEqual(outcomes["bridge"], "structural_contradictions_observed")
        self.assertEqual(outcomes["unknown"], "incomplete_or_unassessed")

    def test_unknown_routing_withholds_even_when_unit_fields_equal(self):
        value = m.component_fixture()
        value["routing_context"] = "unknown"
        actual = report(value)
        self.assertTrue(actual["correlation_checks"]["unit_ids_equal"])
        self.assertIn("routing_context_unknown", actual["unassessed_reasons"])
        self.assertFalse(actual["supported_checks_complete"])

    def test_all_supported_exception_correlations_are_distinct_from_read_success(self):
        for function in (1, 2, 3, 4):
            for code in (1, 2, 3, 4):
                actual = report(
                    model(
                        adu(bytes((function,)) + word(0) + word(1)),
                        adu(bytes((function + 128, code))),
                    )
                )
                self.assertEqual(actual["outcome"], "consistent_supported_exception_structure")
                self.assertEqual(actual["response"]["exception_code"], code)
                self.assertEqual(actual["response"]["register_values"], [])
                self.assertEqual(actual["response"]["bit_values"], [])
                self.assertFalse(actual["claims"]["successful_read_proven"])

    def test_other_exception_codes_are_not_false_protocol_violations(self):
        for code in (0, 5, 6, 8, 10, 11, 255):
            actual = report(model(adu(b"\x03\x00\x00\x00\x01"), adu(bytes((131, code)))))
            self.assertIn("exception_code_outside_read_projection", actual["unassessed_reasons"])
            self.assertEqual(actual["contradictions"], [])
            self.assertEqual(actual["outcome"], "incomplete_or_unassessed")

    def test_exception_pdu_requires_exactly_one_exception_byte(self):
        for pdu in (b"\x83", b"\x83\x01x"):
            actual = report(model(adu(b"\x03\x00\x00\x00\x01"), adu(pdu)))
            self.assertIn("exception_response_pdu_length_mismatch", actual["contradictions"])

    def test_wrong_ordinary_and_exception_function_do_not_correlate(self):
        for pdu in (b"\x04\x02\x00\x01", b"\x84\x01", b"\x05"):
            actual = report(model(adu(b"\x03\x00\x00\x00\x01"), adu(pdu)))
            self.assertIn("response_function_not_correlated", actual["contradictions"])

    def test_zero_function_and_request_exception_bits_are_known_contradictions(self):
        for function in (0, 128, 129, 255):
            actual = report(model(adu(bytes((function,))), adu(b"\x00")))
            self.assertIn("invalid_request_function_code", actual["contradictions"])
            self.assertIn("invalid_response_function_code", actual["contradictions"])

    def test_wrong_request_pdu_length_and_response_byte_count_are_not_clean(self):
        for pdu in (b"\x03", b"\x03\x00\x00\x00", b"\x03\x00\x00\x00\x01x"):
            actual = report(model(adu(pdu), adu(b"\x03\x02\x00\x01")))
            self.assertIn("read_request_pdu_length_mismatch", actual["contradictions"])
        for pdu in (b"\x03", b"\x03\x01\x00\x01", b"\x03\x00"):
            actual = report(model(adu(b"\x03\x00\x00\x00\x01"), adu(pdu)))
            self.assertTrue(actual["contradictions"])

    def test_response_payload_and_request_quantity_are_independent_joins(self):
        actual = report(model(adu(b"\x03\x00\x00\x00\x02"), adu(b"\x03\x02\x00\x01")))
        self.assertIn("response_data_length_not_requested_quantity", actual["contradictions"])
        self.assertNotIn("response_byte_count_not_payload_length", actual["contradictions"])

    def test_padding_bits_for_every_partial_byte_are_exact(self):
        for function in (1, 2):
            for quantity in range(1, 8):
                for payload in range(256):
                    actual = report(
                        model(
                            adu(bytes((function,)) + word(0) + word(quantity)),
                            adu(bytes((function, 1, payload))),
                        )
                    )
                    expected = payload < 2**quantity
                    self.assertEqual(
                        actual["correlation_checks"]["zero_unused_padding_bits"], expected
                    )
                    self.assertEqual(
                        "nonzero_unused_response_padding_bits" in actual["contradictions"],
                        not expected,
                    )

    def test_full_bytes_have_no_unused_padding_and_registers_keep_unsigned_values(self):
        actual = report(read_pair(1, quantity=8, values=[1] * 8))
        self.assertEqual(actual["response"]["bit_values"], [1] * 8)
        self.assertTrue(actual["correlation_checks"]["zero_unused_padding_bits"])
        self.assertEqual(
            report(read_pair(4, quantity=2, values=[0, 65535]))["response"]["register_values"],
            [0, 65535],
        )

    def test_native_shape_schema_context_and_field_aliases_are_domain_rejections(self):
        changes = (
            {"schema_version": True},
            {"schema_version": 1.0},
            {"schema_version": 2},
            {"routing_context": None},
            {"routing_context": False},
            {"routing_context": "gateway"},
            {"request_base64": []},
            {"response_base64": 1},
            {"extra": "x"},
        )
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp({**m.component_fixture(), **changed})
        for value in (None, [], 1, True):
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp(value)
        for key in m.component_fixture():
            value = m.component_fixture()
            del value[key]
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp(value)

    def test_native_subclasses_cycles_and_repeated_container_budgets_reject(self):
        class Text(str):
            pass

        class Mapping(dict):
            pass

        for value in (
            Mapping(m.component_fixture()),
            {**m.component_fixture(), "routing_context": Text("bridge")},
        ):
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(m.ModbusTcpAnalysisError):
            m.ModbusTcpAnalysis.from_dict({"source_model": cycle})
        shared = [0] * 1024
        with self.assertRaises(m.ModbusTcpAnalysisError):
            m.ModbusTcpAnalysis.from_dict([shared] * 16)

    def test_base64_must_be_canonical_bounded_and_unambiguous(self):
        for text in ("AA", "AA===", "AB==", " AA==", "AA==\n", "-w==", "%%%%", "\u00e9"):
            value = m.component_fixture()
            value["request_base64"] = text
            with self.subTest(text=text), self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp(value)

    def test_raw_duplicate_keys_floats_nonfinite_and_integer_lexical_bounds(self):
        raw = canonical(m.component_fixture())
        samples = (
            raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            raw.replace('"schema_version":1', '"schema_version":1.0'),
            raw.replace('"schema_version":1', '"schema_version":NaN'),
            raw.replace('"schema_version":1', '"schema_version":9223372036854775808'),
            raw.replace('"schema_version":1', '"schema_version":-9223372036854775809'),
            raw.replace('"schema_version":1', '"schema_version":--1'),
        )
        for text in samples:
            with self.subTest(text=text), self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp_bytes(model_bytes=text.encode("ascii"))

    def test_raw_depth_nodes_and_integer_reject_before_decoder_or_hash(self):
        samples = (
            "[" * m.MAX_DEPTH + "0" + "]" * m.MAX_DEPTH,
            "[" + ",".join("0" for _ in range(m.MAX_NODES)) + "]",
            '{"x":' + "9" * 100 + "}",
        )
        for text in samples:
            with (
                self.subTest(length=len(text)),
                mock.patch.object(m.json, "loads", side_effect=AssertionError("decoder called")),
                mock.patch.object(m.hashlib, "sha256", side_effect=AssertionError("hash called")),
                self.assertRaises(m.ModbusTcpAnalysisError),
            ):
                m.analyze_supplied_modbus_tcp_bytes(model_bytes=text.encode("ascii"))

    def test_raw_bytes_encoding_empty_oversize_and_closed_ascii_projection(self):
        for value in (
            b"",
            b"\xff",
            b" " * (m.MAX_MODEL_BYTES + 1),
            "{}",
            bytearray(b"{}"),
            b'{"x":"\\ud800"}',
            b'{"x":"\\u00e9"}',
        ):
            with self.subTest(value_type=type(value)), self.assertRaises(m.ModbusTcpAnalysisError):
                m.analyze_supplied_modbus_tcp_bytes(model_bytes=value)

    def test_native_escape_cost_and_raw_string_limit_precede_serialization(self):
        value = {**m.component_fixture(), "a": "\x7f" * 2048, "b": "\x7f" * 2048}
        with (
            mock.patch.object(m, "_canonical", side_effect=AssertionError("serialized")),
            mock.patch.object(m.hashlib, "sha256", side_effect=AssertionError("hash called")),
            self.assertRaises(m.ModbusTcpAnalysisError),
        ):
            m.analyze_supplied_modbus_tcp(value)
        text = '{"x":"' + "a" * (m.MAX_STRING_BYTES + 1) + '"}'
        with (
            mock.patch.object(m.json, "loads", side_effect=AssertionError("decoder called")),
            self.assertRaises(m.ModbusTcpAnalysisError),
        ):
            m.analyze_supplied_modbus_tcp_bytes(model_bytes=text.encode("ascii"))

    def test_semantically_identical_raw_spacing_binds_canonical_snapshot_not_raw_json(self):
        value = m.component_fixture()
        canonical_report = m.analyze_supplied_modbus_tcp(value)
        alternate = json.dumps(dict(reversed(list(value.items()))), indent=2).encode("ascii")
        self.assertEqual(
            m.analyze_supplied_modbus_tcp_bytes(model_bytes=alternate).to_json(),
            canonical_report.to_json(),
        )

    def test_all_claims_effects_ownership_and_scope_are_nonqualifying(self):
        actual = report(m.component_fixture())
        self.assertTrue(all(not value for value in actual["claims"].values()))
        self.assertTrue(all(value == "none" for value in actual["effects"].values()))
        self.assertEqual(actual["independent_validator_id"], "AOE-HQ-33")
        self.assertEqual(actual["group_commander_profile_id"], "AOE-HQ-06")
        self.assertEqual(actual["roadmap_package_ids"], ["A7.4"])

    def test_fixture_input_and_exports_are_fresh_detached_native_values(self):
        value = m.component_fixture()
        original = m.analyze_supplied_modbus_tcp(value)
        text = original.to_json()
        value["routing_context"] = "direct"
        exported = original.to_dict()
        exported["response"]["register_values"][0] = 999
        exported["source_model"]["routing_context"] = "unknown"
        self.assertEqual(original.to_json(), text)
        self.assertEqual(m.component_fixture(), read_pair())
        with self.assertRaises(FrozenInstanceError):
            original.document_json = "{}"

    def test_cohashed_false_observations_claims_and_byte_provenance_reject(self):
        original = report(m.component_fixture())
        changed_documents = []
        for field, value in (
            ("outcome", "incomplete_or_unassessed"),
            ("response_kind", "exception"),
            ("supported_checks_complete", False),
        ):
            changed = copy.deepcopy(original)
            changed[field] = value
            changed_documents.append(changed)
        changed = copy.deepcopy(original)
        changed["response"]["register_values"][0] = 999
        changed_documents.append(changed)
        changed = copy.deepcopy(original)
        changed["claims"]["device_identity_proven"] = True
        changed_documents.append(changed)
        changed = copy.deepcopy(original)
        changed["source_bytes"]["request_sha256"] = "sha256:" + "a" * 64
        changed_documents.append(changed)
        for changed in changed_documents:
            changed = readdress(changed)
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.ModbusTcpAnalysis.from_dict(changed)
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.ModbusTcpAnalysis.from_json(canonical(changed))

    def test_report_native_aliases_cannot_keep_an_original_address(self):
        original = report(m.component_fixture())
        changes = []
        for field, value in (("schema_version", True), ("supported_checks_complete", 1)):
            changed = copy.deepcopy(original)
            changed[field] = value
            changes.append(changed)
        for value in (True, 3.0):
            changed = copy.deepcopy(original)
            changed["request"]["quantity"] = value
            changes.append(changed)
        for changed in changes:
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.ModbusTcpAnalysis.from_dict(changed)

    def test_separate_original_verifier_denies_valid_other_bytes_and_routing(self):
        original = m.analyze_supplied_modbus_tcp(m.component_fixture())
        alternatives = (
            read_pair(values=[555, 0, 101]),
            {**m.component_fixture(), "routing_context": "direct"},
        )
        for value in alternatives:
            changed = m.analyze_supplied_modbus_tcp(value)
            self.assertEqual(
                m.ModbusTcpAnalysis.from_json(changed.to_json()).to_json(), changed.to_json()
            )
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.verify_supplied_modbus_tcp_analysis(changed, model=m.component_fixture())
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.verify_supplied_modbus_tcp_analysis(original, model=value)

    def test_canonical_report_text_is_not_normalized_or_rehashed(self):
        original = m.analyze_supplied_modbus_tcp(m.component_fixture())
        for text in (
            json.dumps(original.to_dict(), indent=2),
            original.to_json() + "\n",
            original.to_json().replace(
                '"schema_version":1', '"schema_version":1,"schema_version":1', 1
            ),
        ):
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.ModbusTcpAnalysis.from_json(text)

    def test_missing_and_wrong_family_wrappers_reject(self):
        incomplete = object.__new__(m.ModbusTcpAnalysis)
        for value in (None, {}, incomplete):
            with self.assertRaises(m.ModbusTcpAnalysisError):
                m.verify_supplied_modbus_tcp_analysis(value, model=m.component_fixture())

        class Derived(m.ModbusTcpAnalysis):
            pass

        with self.assertRaises(m.ModbusTcpAnalysisError):
            Derived.from_json(m.analyze_supplied_modbus_tcp(m.component_fixture()).to_json())

    def test_retained_output_bytes_and_nodes_deny_before_any_hash(self):
        value = read_pair(1, start=0, quantity=2000, values=[1] * 2000)
        text = m.analyze_supplied_modbus_tcp(value).to_json()
        source_size = len(canonical(value))
        # The reduced bound is itself serialized. Fund that changed decimal width,
        # then make the actual complete derived report exactly one byte too large.
        byte_limit = len(text) - 1
        for _ in range(8):
            adjusted = len(text) - len(str(m.MAX_REPORT_BYTES)) + len(str(byte_limit)) - 1
            if adjusted == byte_limit:
                break
            byte_limit = adjusted
        for name, limit in (("MAX_REPORT_BYTES", byte_limit), ("MAX_NODES", 128)):
            with (
                self.subTest(bound=name),
                mock.patch.object(m, name, limit),
                mock.patch.object(m.hashlib, "sha256", side_effect=AssertionError("hash called")),
            ):
                self.assertLess(source_size, m.MAX_MODEL_BYTES)
                with self.assertRaises(m.ModbusTcpAnalysisError):
                    m.analyze_supplied_modbus_tcp(value)

    def test_complete_public_operation_work_is_reserved_before_first_digest(self):
        value = m.component_fixture()
        original = m.analyze_supplied_modbus_tcp(value)
        native = original.to_dict()
        text = original.to_json()
        operations = (
            lambda: m.analyze_supplied_modbus_tcp(value),
            lambda: m.analyze_supplied_modbus_tcp_bytes(
                model_bytes=canonical(value).encode("ascii")
            ),
            lambda: m.ModbusTcpAnalysis.from_dict(native),
            lambda: m.ModbusTcpAnalysis.from_json(text),
            lambda: m.ModbusTcpAnalysis(text),
            original.to_dict,
            original.to_json,
            lambda: m.verify_supplied_modbus_tcp_analysis(original, model=value),
        )
        real_charge = m._Budget.charge
        real_hash = m.hashlib.sha256
        for operation in operations:
            charges = []
            hashed = []

            def observe_charge(budget, amount, seen=hashed, records=charges):
                self.assertFalse(seen, "work charged after digest")
                records.append(amount)
                real_charge(budget, amount)

            def observe_hash(*args, seen=hashed, **kwargs):
                seen.append(True)
                return real_hash(*args, **kwargs)

            with (
                mock.patch.object(m._Budget, "charge", observe_charge),
                mock.patch.object(m.hashlib, "sha256", observe_hash),
            ):
                operation()
            exact = sum(charges)
            self.assertTrue(hashed)
            for limit, should_pass in ((exact - 1, False), (exact, True)):

                def limited_charge(budget, amount, ceiling=limit):
                    if amount > ceiling - budget.used:
                        raise m.ModbusTcpAnalysisError("Transparent test work ceiling")
                    real_charge(budget, amount)

                with mock.patch.object(m._Budget, "charge", limited_charge):
                    if should_pass:
                        operation()
                    else:
                        with (
                            mock.patch.object(
                                m.hashlib,
                                "sha256",
                                side_effect=AssertionError("hash before whole funding"),
                            ),
                            self.assertRaises(m.ModbusTcpAnalysisError),
                        ):
                            operation()


if __name__ == "__main__":
    unittest.main()

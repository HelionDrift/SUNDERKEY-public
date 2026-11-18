"""Synthetic byte/option geometry and full-source replay controls, without UDP."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from sunderkey import offline_coap_analysis as coap


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _field(number):
    if number < 13:
        return number, b""
    if number < 269:
        return 13, bytes([number - 13])
    high, low = divmod(number - 269, 256)
    return 14, bytes([high, low])


def _packet(*, kind=0, code=1, mid=0x1234, token=b"\xaa", options=(), payload=None):
    """Independent encoder with explicit option number/bytes, not a production decoder."""
    result = bytearray(struct.pack("!BBH", 0x40 + kind * 16 + len(token), code, mid))
    result.extend(token)
    previous = 0
    for number, value in options:
        delta, delta_bytes = _field(number - previous)
        length, length_bytes = _field(len(value))
        result.extend(bytes([delta * 16 + length]) + delta_bytes + length_bytes + value)
        previous = number
    if payload is not None:
        result.extend(b"\xff" + payload)
    return bytes(result)


def _model(request=None, response=None):
    result = coap.component_fixture()
    if request is not None:
        result["request_base64"] = base64.b64encode(request).decode("ascii")
    if response is not None:
        result["response_base64"] = base64.b64encode(response).decode("ascii")
    return result


def _document(request=None, response=None):
    return coap.analyze_supplied_coap(_model(request, response)).to_dict()


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256((coap.DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    document["analysis_id"] = "CPA-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest
    return document


def _unsafe_wrapper(document):
    result = object.__new__(coap.CoapAnalysis)
    object.__setattr__(result, "document_json", _canonical(document))
    return result


class OfflineCoapAnalysisTests(unittest.TestCase):
    def assertPrehashDenied(self, operation):
        with (
            patch.object(coap.hashlib, "sha256", side_effect=AssertionError("hash reached")),
            self.assertRaises(coap.CoapAnalysisError),
        ):
            operation()

    def test_literal_fixture_identity_and_selected_byte_facts(self):
        result = coap.analyze_supplied_coap(coap.component_fixture()).to_dict()
        self.assertEqual(result["analysis_id"], "CPA-66FB4FD8E250AD5B9C97C6175EF56DC6")
        self.assertEqual(
            result["analysis_sha256"],
            "sha256:66fb4fd8e250ad5b9c97c6175ef56dc6a6587578dc3b45681cb9d2d24dbf3256",
        )
        self.assertEqual(
            result["source_model_sha256"],
            "sha256:7ec3649cb3f658794a99afac75b6e64edd305b153953bcbdb96c8716832a4f71",
        )
        self.assertEqual(
            result["source_bytes"]["request_sha256"],
            "sha256:9baeecb837d4f0c70a12ab8250794284e1418922e105f861d30d838579eaac06",
        )
        self.assertEqual(
            result["source_bytes"]["response_sha256"],
            "sha256:88a5af4099419cfbfc59d551627f470de1252cc94ed66714d3c1f52eef0363f4",
        )
        self.assertEqual(result["outcome"], "consistent_supported_piggyback_structure")
        self.assertEqual(result["request"]["message_id"], 0x1234)
        self.assertEqual(result["request"]["options"][0]["number"], 17)
        self.assertEqual(result["request"]["options"][0]["uint_value"], 0)
        self.assertEqual(result["response"]["options"][0]["number"], 12)
        self.assertEqual(result["response"]["payload_hex"], "6f6b")
        self.assertEqual(result["contradictions"], [])
        self.assertFalse(any(result["claims"].values()))
        self.assertEqual(set(result["effects"].values()), {"none"})

    def test_public_fixture_is_fresh_and_independently_matches_encoder(self):
        first = coap.component_fixture()
        second = coap.component_fixture()
        first["request_source_id"] = "changed"
        self.assertEqual(second["request_source_id"], "synthetic-get")
        self.assertEqual(base64.b64decode(second["request_base64"]), _packet(options=[(17, b"")]))
        self.assertEqual(
            base64.b64decode(second["response_base64"]),
            _packet(kind=2, code=69, options=[(12, b"")], payload=b"ok"),
        )

    def test_all_public_round_trips_preserve_identity_and_exact_bytes(self):
        source = coap.component_fixture()
        report = coap.analyze_supplied_coap(source)
        text = report.to_json()
        for candidate in (
            coap.CoapAnalysis(text),
            coap.CoapAnalysis.from_dict(report.to_dict()),
            coap.CoapAnalysis.from_json(text),
            coap.analyze_supplied_coap_bytes(model_bytes=_canonical(source).encode()),
            coap.verify_supplied_coap_analysis(report, model=source),
        ):
            self.assertEqual(candidate.to_json(), text)

    def test_header_prefixes_are_incomplete_not_fabricated_clean_results(self):
        for side in ("request", "response"):
            original = base64.b64decode(coap.component_fixture()[side + "_base64"])
            for size in range(4):
                with self.subTest(side=side, size=size):
                    source = coap.component_fixture()
                    source[side + "_base64"] = base64.b64encode(original[:size]).decode()
                    doc = coap.analyze_supplied_coap(source).to_dict()
                    self.assertFalse(doc["selected_checks_complete"])
                    self.assertIn(side + "_truncated_header", doc["unassessed_reasons"])

    def test_all_token_lengths_zero_through_eight_are_opaque_and_match(self):
        for length in range(9):
            token = bytes(range(length))
            with self.subTest(length=length):
                doc = _document(_packet(token=token), _packet(kind=2, code=69, token=token))
                self.assertEqual(doc["outcome"], "consistent_supported_piggyback_structure")
                self.assertEqual(doc["request"]["token_hex"], token.hex())

    def test_reserved_token_lengths_nine_through_fifteen_are_format_contradictions(self):
        for length in range(9, 16):
            doc = _document(bytes([0x40 + length, 1, 0, 1]) + b"t" * length)
            self.assertIn("request_reserved_token_length", doc["contradictions"])
            self.assertFalse(doc["request"]["framing_complete"])

    def test_missing_token_octets_are_explicit_truncated_prefixes(self):
        for available in range(8):
            doc = _document(b"\x48\x01\x12\x34" + b"t" * available)
            self.assertIn("request_truncated_token", doc["unassessed_reasons"])

    def test_unknown_versions_do_not_inherit_version_one_geometry(self):
        for version in (0, 2, 3):
            doc = _document(bytes([version * 64 + 15, 1, 0, 1, 255]))
            self.assertIn("request_version_outside_rfc7252", doc["unassessed_reasons"])
            self.assertNotIn("request_reserved_token_length", doc["contradictions"])
            self.assertFalse(doc["request"]["framing_complete"])

    def test_independent_delta_and_length_extension_geometry_oracle(self):
        for delta in (0, 1, 12, 13, 268, 269, 524, 65_804):
            for length in (0, 1, 12, 13, 268, 269, 524):
                with self.subTest(delta=delta, length=length):
                    value = bytes([255]) * length
                    doc = _document(_packet(options=[(delta, value)]))
                    row = doc["request"]["options"][0]
                    self.assertEqual(
                        (row["number"], row["delta"], row["value_length"]), (delta, delta, length)
                    )
                    self.assertEqual(row["value_hex"], value.hex())
                    self.assertTrue(doc["request"]["framing_complete"])

    def test_option_deltas_accumulate_and_repeated_numbers_keep_original_order(self):
        values = [(11, b"a"), (11, b""), (15, b"x"), (269, b"z"), (537, b"p")]
        rows = _document(_packet(options=values))["request"]["options"]
        self.assertEqual([(r["number"], bytes.fromhex(r["value_hex"])) for r in rows], values)
        self.assertEqual([r["delta"] for r in rows], [11, 0, 4, 254, 268])

    def test_boundary_only_marker_preserves_ff_inside_values_and_extensions(self):
        raw = _packet(options=[(268, b"\xff"), (269, b"v" * 268)], payload=b"\xffdata")
        doc = _document(raw)
        self.assertEqual(len(doc["request"]["options"]), 2)
        self.assertEqual(doc["request"]["options"][0]["value_hex"], "ff")
        self.assertEqual(doc["request"]["payload_hex"], "ff64617461")
        self.assertEqual(doc["request"]["payload_marker_offset"], len(raw) - 6)

    def test_marker_with_zero_payload_is_a_format_contradiction(self):
        doc = _document(_packet(payload=b""))
        self.assertIn("request_marker_without_payload", doc["contradictions"])

    def test_reserved_option_nibbles_do_not_become_a_payload_marker(self):
        for header in (*range(240, 255), *range(15, 240, 16)):
            doc = _document(_packet() + bytes([header]) + b"v")
            self.assertIn("request_reserved_option_nibble", doc["contradictions"])
            self.assertIsNone(doc["request"]["payload_marker_offset"])

    def test_truncated_extended_option_headers_keep_uncertainty(self):
        for suffix, reason in (
            (b"\xd0", "delta"),
            (b"\xe0", "delta"),
            (b"\xe0\x01", "delta"),
            (b"\x0d", "length"),
            (b"\x0e", "length"),
            (b"\x0e\x01", "length"),
            (b"\xdd\x00", "length"),
        ):
            doc = _document(_packet() + suffix)
            self.assertIn("request_truncated_option_" + reason, doc["unassessed_reasons"])
            self.assertFalse(doc["request"]["framing_complete"])

    def test_truncated_declared_option_value_never_parses_suffix_as_marker(self):
        doc = _document(_packet() + b"\xbd\x00\xff")
        self.assertIn("request_truncated_option_value", doc["unassessed_reasons"])
        self.assertIsNone(doc["request"]["payload_marker_offset"])

    def test_leading_zero_uint_options_are_accepted_without_byte_normalization(self):
        for spelling in (b"", b"\x00", b"\x00\x00", b"\x01", b"\x00\x01"):
            doc = _document(_packet(options=[(17, spelling)]))
            row = doc["request"]["options"][0]
            self.assertEqual(row["uint_value"], int.from_bytes(spelling, "big"))
            self.assertEqual(row["value_hex"], spelling.hex())
            self.assertEqual(doc["outcome"], "consistent_supported_piggyback_structure")

    def test_all_four_max_age_octets_use_unsigned_network_order(self):
        for spelling in (b"", b"\x00", b"\x00\x00\x00\x01", b"\xff" * 4):
            doc = _document(response=_packet(kind=2, code=69, options=[(14, spelling)]))
            self.assertEqual(
                doc["response"]["options"][0]["uint_value"], int.from_bytes(spelling, "big")
            )

    def test_option_value_range_errors_are_unrecognized_not_framing_errors(self):
        for number, value in (
            (17, b"123"),
            (7, b"123"),
            (3, b""),
            (4, b""),
            (5, b"x"),
            (11, b"x" * 256),
        ):
            doc = _document(_packet(options=[(number, value)]))
            row = doc["request"]["options"][0]
            self.assertEqual(row["recognition"], "unrecognized_option_length")
            self.assertTrue(doc["request"]["framing_complete"])
            self.assertEqual(doc["contradictions"], [])
            self.assertFalse(doc["selected_checks_complete"])

    def test_supernumerary_singletons_preserve_first_and_odd_even_classification(self):
        for number in (3, 7, 17):
            value = b"h" if number == 3 else b""
            rows = _document(_packet(options=[(number, value)] * 2))["request"]["options"]
            self.assertTrue(rows[0]["recognition"].startswith("applicable"))
            self.assertEqual(rows[1]["recognition"], "unrecognized_supernumerary_option")
            self.assertTrue(rows[1]["critical"])
        doc = _document(response=_packet(kind=2, code=69, options=[(12, b"")] * 2))
        self.assertEqual(
            doc["response"]["options"][1]["recognition"], "unrecognized_supernumerary_option"
        )
        self.assertFalse(doc["response"]["options"][1]["critical"])
        self.assertEqual(doc["contradictions"], [])

    def test_request_etags_repeat_but_response_etag_supernumeraries_are_unrecognized(self):
        doc = _document(
            _packet(options=[(4, b"a"), (4, b"b")]),
            _packet(kind=2, code=69, options=[(4, b"a"), (4, b"b")]),
        )
        self.assertTrue(
            all(r["recognition"].startswith("applicable") for r in doc["request"]["options"])
        )
        self.assertEqual(
            doc["response"]["options"][1]["recognition"], "unrecognized_supernumerary_option"
        )

    def test_method_and_code_inapplicable_options_are_unrecognized_not_format_invalid(self):
        for request, response in (
            (_packet(options=[(14, b"")]), None),
            (None, _packet(kind=2, code=69, options=[(17, b"")])),
            (None, _packet(kind=2, code=132, options=[(4, b"tag")])),
        ):
            doc = _document(request, response)
            side = "request" if request is not None else "response"
            self.assertEqual(doc[side]["options"][0]["recognition"], "unrecognized_method_code")
            self.assertEqual(doc["contradictions"], [])
            self.assertTrue(doc[side]["framing_complete"])

    def test_unknown_options_are_odd_critical_even_elective_and_unassessed(self):
        for number in (0, 2, 19, 22, 65_804):
            doc = _document(_packet(options=[(number, b"x")]))
            row = doc["request"]["options"][0]
            self.assertEqual(row["critical"], bool(number % 2))
            self.assertEqual(row["recognition"], "unrecognized_option_number")
            self.assertEqual(doc["outcome"], "incomplete_or_unassessed")

    def test_string_conditional_and_proxy_semantics_are_not_silently_clean(self):
        for number, value in (
            (11, b".."),
            (11, b"\xff"),
            (3, b"host"),
            (1, b""),
            (5, b""),
            (35, b"coap://supplied"),
            (39, b"coap"),
        ):
            doc = _document(_packet(options=[(number, value)]))
            self.assertEqual(doc["outcome"], "incomplete_or_unassessed")
            self.assertEqual(doc["request"]["options"][0]["value_hex"], value.hex())
            self.assertEqual(doc["contradictions"], [])

    def test_mid_and_token_mismatches_are_selected_supplied_pair_contradictions(self):
        for mid, token, reason in (
            (1, b"\xaa", "ack_message_id_mismatch"),
            (0x1234, b"\xab", "piggyback_token_mismatch"),
            (1, b"\xab", "ack_message_id_mismatch"),
        ):
            doc = _document(response=_packet(kind=2, code=69, mid=mid, token=token))
            self.assertIn(reason, doc["contradictions"])
            self.assertEqual(doc["outcome"], "structural_contradictions_observed")

    def test_empty_ack_has_no_response_token_or_completed_exchange_claim(self):
        doc = _document(response=_packet(kind=2, code=0, token=b""))
        self.assertEqual(doc["response_kind"], "empty_ack")
        self.assertEqual(doc["outcome"], "incomplete_or_unassessed")
        self.assertTrue(doc["correlation_checks"]["message_ids_equal"])
        self.assertIsNone(doc["correlation_checks"]["tokens_equal"])
        self.assertFalse(doc["correlation_checks"]["piggyback_relation_assessed"])
        self.assertFalse(any(doc["claims"].values()))

    def test_empty_ack_wrong_mid_remains_a_declared_ack_contradiction(self):
        doc = _document(response=_packet(kind=2, code=0, token=b"", mid=9))
        self.assertIn("ack_message_id_mismatch", doc["contradictions"])
        self.assertIn("empty_ack_separate_response_not_supplied", doc["unassessed_reasons"])

    def test_empty_code_with_token_options_or_payload_is_a_format_contradiction(self):
        for raw in (
            _packet(kind=2, code=0),
            _packet(kind=2, code=0, token=b"", options=[(12, b"")]),
            _packet(kind=2, code=0, token=b"", payload=b"p"),
        ):
            doc = _document(response=raw)
            self.assertIn("response_nonempty_empty_message", doc["contradictions"])

    def test_separate_responses_do_not_inherit_piggyback_mid_matching(self):
        for kind in (0, 1):
            doc = _document(response=_packet(kind=kind, code=69, mid=42, token=b"\xbb"))
            self.assertEqual(doc["response_kind"], "separate_response_unassessed")
            self.assertEqual(doc["contradictions"], [])
            self.assertFalse(doc["correlation_checks"]["piggyback_relation_assessed"])
            self.assertIsNone(doc["correlation_checks"]["message_ids_equal"])

    def test_valid_code_requires_etag_and_no_payload_but_does_not_validate_representation(self):
        bad = _document(response=_packet(kind=2, code=67, payload=b"p"))
        self.assertIn("valid_response_without_recognized_etag", bad["contradictions"])
        self.assertIn("valid_response_has_payload", bad["contradictions"])
        good = _document(response=_packet(kind=2, code=67, options=[(4, b"t")]))
        self.assertEqual(good["contradictions"], [])
        self.assertEqual(good["outcome"], "incomplete_or_unassessed")
        self.assertIn("representation_validation_facts_unassessed", good["unassessed_reasons"])

    def test_unknown_methods_codes_and_nonconfirmable_requests_withhold_completeness(self):
        for request, response in (
            (_packet(kind=1), None),
            (_packet(code=2), None),
            (_packet(code=31), None),
            (None, _packet(kind=2, code=95)),
            (None, _packet(kind=2, code=65)),
        ):
            doc = _document(request, response)
            self.assertFalse(doc["selected_checks_complete"])
            self.assertEqual(doc["outcome"], "incomplete_or_unassessed")

    def test_known_error_ack_is_not_resource_access_or_delivery_truth(self):
        for code in (128, 129, 130, 131, 132, 133, 134, 140, 141, 143, 160, 165):
            doc = _document(response=_packet(kind=2, code=code))
            self.assertEqual(doc["outcome"], "consistent_supported_piggyback_structure")
            self.assertFalse(any(doc["claims"].values()))

    def test_ack_request_and_nonempty_reset_are_declared_type_code_contradictions(self):
        for raw, reason in (
            (_packet(kind=2, code=1), "ack_carries_request_code"),
            (_packet(kind=3, code=69), "nonempty_reset_message"),
        ):
            self.assertIn(reason, _document(response=raw)["contradictions"])

    def test_get_payload_is_preserved_but_not_assessed_as_method_content(self):
        doc = _document(_packet(payload=b"\x00\xff\x80"))
        self.assertEqual(doc["request"]["payload_hex"], "00ff80")
        self.assertIn("get_payload_semantics_unassessed", doc["unassessed_reasons"])

    def test_exact_datagram_and_option_software_ceiling_boundaries(self):
        raw = _packet(kind=2, code=69, payload=b"p" * (coap.MAX_DATAGRAM_BYTES - 6))
        self.assertEqual(len(raw), coap.MAX_DATAGRAM_BYTES)
        self.assertEqual(_document(response=raw)["response"]["payload_bytes"], len(raw) - 6)
        self.assertPrehashDenied(lambda: coap.analyze_supplied_coap(_model(response=raw + b"p")))
        accepted = _packet(options=[(17, b"")] * coap.MAX_OPTIONS)
        self.assertEqual(len(_document(accepted)["request"]["options"]), coap.MAX_OPTIONS)
        rejected = _packet(options=[(17, b"")] * (coap.MAX_OPTIONS + 1))
        self.assertPrehashDenied(lambda: coap.analyze_supplied_coap(_model(rejected)))

    def test_model_type_missing_field_and_primitive_alias_denials_are_before_hash(self):
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("request_source_id", None),
            ("response_source_id", 1),
            ("request_base64", []),
            ("response_base64", False),
        ):
            source = coap.component_fixture()
            source[field] = value
            self.assertPrehashDenied(lambda source=source: coap.analyze_supplied_coap(source))
        for field in coap.component_fixture():
            source = coap.component_fixture()
            del source[field]
            self.assertPrehashDenied(lambda source=source: coap.analyze_supplied_coap(source))

    def test_noncanonical_or_malformed_base64_never_becomes_original_bytes(self):
        for spelling in ("Q===", "QR==", "QQ", "QQ==\n", "QQ-_", "====", " AAE=", "\u00e9"):
            source = coap.component_fixture()
            source["request_base64"] = spelling
            self.assertPrehashDenied(lambda source=source: coap.analyze_supplied_coap(source))

    def test_raw_duplicate_keys_floats_nonfinite_and_oversize_ints_are_domain_errors(self):
        for text in (
            '{"schema_version":1,"schema_version":true}',
            '{"nested":{"x":1,"x":2}}',
            "1.0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "--1",
        ):
            self.assertPrehashDenied(
                lambda text=text: coap.analyze_supplied_coap_bytes(model_bytes=text.encode("ascii"))
            )

    def test_raw_node_scalar_depth_string_and_integer_guards_precede_decoder(self):
        for raw in (
            b"[" * 16 + b"0" + b"]" * 16,
            b"[" + b",".join([b"0"] * coap.MAX_NODES) + b"]",
            b'"' + b"x" * (coap.MAX_STRING_BYTES + 1) + b'"',
            b"1" * 21,
            b"9223372036854775808",
            b'"\\ud800"',
            b" " * (coap.MAX_MODEL_BYTES + 1),
            b'"\xff"',
        ):
            with patch.object(coap.json, "loads", side_effect=AssertionError("decoder reached")):
                self.assertPrehashDenied(
                    lambda raw=raw: coap.analyze_supplied_coap_bytes(model_bytes=raw)
                )

    def test_native_cycle_shared_graph_and_huge_integer_bounds_precede_dump(self):
        cyclic = []
        cyclic.append(cyclic)
        values = [
            cyclic,
            [list(range(1000))] * 20,
            {"huge": 1 << 100_000},
            {"huge": "\x7f" * coap.MAX_STRING_BYTES},
            {1: "bad"},
        ]
        for value in values:
            with patch.object(coap.json, "dumps", side_effect=AssertionError("dump reached")):
                self.assertPrehashDenied(lambda value=value: coap.analyze_supplied_coap(value))

    def test_all_eight_public_operations_fund_exact_complete_work_before_first_hash(self):
        source = coap.component_fixture()
        report = coap.analyze_supplied_coap(source)
        document, text = report.to_dict(), report.to_json()
        operations = (
            lambda: coap.analyze_supplied_coap(source),
            lambda: coap.analyze_supplied_coap_bytes(model_bytes=_canonical(source).encode()),
            lambda: coap.CoapAnalysis(text),
            lambda: coap.CoapAnalysis.from_dict(document),
            lambda: coap.CoapAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
            lambda: coap.verify_supplied_coap_analysis(report, model=source),
        )
        original_charge, original_sha = coap._Budget.charge, coap.hashlib.sha256
        for index, operation in enumerate(operations):
            with self.subTest(boundary=index):
                state = {"work": 0, "hashed": False, "budgets": set()}

                def observe(budget, amount, state=state):
                    self.assertFalse(state["hashed"], "charge occurred after a digest")
                    state["work"] += amount
                    state["budgets"].add(id(budget))
                    return original_charge(budget, amount)

                def hash_observer(*args, state=state, **kwargs):
                    state["hashed"] = True
                    return original_sha(*args, **kwargs)

                with (
                    patch.object(coap._Budget, "charge", observe),
                    patch.object(coap.hashlib, "sha256", hash_observer),
                ):
                    operation()
                self.assertEqual(len(state["budgets"]), 1)
                required = state["work"]
                for cap in (required - 1, required):
                    used = [0]

                    def bounded(budget, amount, cap=cap, used=used):
                        if amount > cap - used[0]:
                            raise coap.CoapAnalysisError("Transparent exact measured work cap")
                        used[0] += amount
                        return original_charge(budget, amount)

                    with patch.object(coap._Budget, "charge", bounded):
                        if cap < required:
                            self.assertPrehashDenied(operation)
                        else:
                            operation()
                            self.assertEqual(used[0], required)

    def test_genuine_retained_output_and_node_denials_precede_hashing(self):
        source = _model(
            _packet(options=[(17, b"")] * 128), _packet(kind=2, code=69, options=[(12, b"")] * 128)
        )
        # Reduced ceilings expose placement using genuine finite data, not a claimed
        # production-limit exploit or fabricated report shape.
        with patch.object(coap, "MAX_REPORT_BYTES", 8192):
            self.assertPrehashDenied(lambda: coap.analyze_supplied_coap(source))
        with patch.object(coap, "MAX_NODES", 1024):
            self.assertPrehashDenied(lambda: coap.analyze_supplied_coap(source))

    def test_cohashed_false_result_is_rejected_by_all_report_consumers(self):
        source = coap.component_fixture()
        original = coap.analyze_supplied_coap(source).to_dict()
        changes = (
            lambda x: x.__setitem__("outcome", "resource_access_proven"),
            lambda x: x["claims"].__setitem__("endpoint_identity_proven", True),
            lambda x: x["response"].__setitem__("payload_hex", "0000"),
            lambda x: x["request"]["options"][0].__setitem__("uint_value", 17),
            lambda x: x["correlation_checks"].__setitem__("tokens_equal", False),
            lambda x: x["source_bytes"].__setitem__("request_length", 8),
            lambda x: x["effects"].__setitem__("network", "performed"),
        )
        for change in changes:
            changed = copy.deepcopy(original)
            change(changed)
            _readdress(changed)
            text = _canonical(changed)
            wrapper = _unsafe_wrapper(changed)
            for operation in (
                lambda text=text: coap.CoapAnalysis(text),
                lambda changed=changed: coap.CoapAnalysis.from_dict(changed),
                lambda text=text: coap.CoapAnalysis.from_json(text),
                lambda wrapper=wrapper: wrapper.to_dict(),
                lambda wrapper=wrapper: wrapper.to_json(),
                lambda wrapper=wrapper: coap.verify_supplied_coap_analysis(wrapper, model=source),
            ):
                with self.assertRaises(coap.CoapAnalysisError):
                    operation()

    def test_original_source_replay_rejects_truthful_alternate_labels_and_datagrams(self):
        source = coap.component_fixture()
        report = coap.analyze_supplied_coap(source)
        for field, value in (
            ("request_source_id", "other-get"),
            ("response_source_id", "other-ack"),
            ("response_base64", base64.b64encode(_packet(kind=2, code=69)).decode()),
        ):
            other = copy.deepcopy(source)
            other[field] = value
            # The alternate is a genuine accepted model/report, not a stale address.
            alternate = coap.analyze_supplied_coap(other)
            self.assertNotEqual(alternate.to_json(), report.to_json())
            with self.assertRaises(coap.CoapAnalysisError):
                coap.verify_supplied_coap_analysis(report, model=other)

    def test_detachment_late_wrapper_mutation_and_noncanonical_exports(self):
        source = coap.component_fixture()
        report = coap.analyze_supplied_coap(source)
        text = report.to_json()
        exported = report.to_dict()
        exported["response"]["options"][0]["value_hex"] = "ffff"
        source["request_source_id"] = "later"
        self.assertEqual(report.to_json(), text)
        with self.assertRaises(coap.CoapAnalysisError):
            coap.CoapAnalysis.from_json(json.dumps(report.to_dict(), indent=2))
        object.__setattr__(
            report, "document_json", text.replace('"tokens_equal":true', '"tokens_equal":false')
        )
        with self.assertRaises(coap.CoapAnalysisError):
            report.to_dict()

    def test_missing_wrapper_slots_and_wrong_native_families_are_typed_rejections(self):
        incomplete = object.__new__(coap.CoapAnalysis)
        for operation in (
            lambda: incomplete.to_dict(),
            lambda: incomplete.to_json(),
            lambda: coap.verify_supplied_coap_analysis(incomplete, model=coap.component_fixture()),
            lambda: coap.analyze_supplied_coap_bytes(model_bytes=bytearray(b"{}")),
        ):
            with self.assertRaises(coap.CoapAnalysisError):
                operation()


if __name__ == "__main__":
    unittest.main()

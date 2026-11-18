"""Independent inert encoders and exact replay/cost controls for the DHCP subset."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_dhcpv4_analysis as d


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _uint(value, width):
    return bytes((value >> (8 * (width - index - 1))) & 255 for index in range(width))


def _option(code, value):
    return bytes((code, len(value))) + value


def _packet(
    kind=1,
    *,
    op=1,
    xid=0x12345678,
    flags=0,
    giaddr=0,
    chaddr=b"\x02\0\0\0\0\x01",
    options=None,
    file=b"",
    sname=b"",
    htype=1,
    hlen=6,
    hops=0,
    secs=0,
    ciaddr=0,
    yiaddr=0,
    siaddr=0,
):
    header = (
        bytes((op, htype, hlen, hops))
        + _uint(xid, 4)
        + _uint(secs, 2)
        + _uint(flags, 2)
        + _uint(ciaddr, 4)
        + _uint(yiaddr, 4)
        + _uint(siaddr, 4)
        + _uint(giaddr, 4)
        + chaddr.ljust(16, b"\0")
        + sname.ljust(64, b"\0")
        + file.ljust(128, b"\0")
    )
    if options is None:
        options = _option(53, bytes((kind,)))
        if op == 2:
            options += _option(54, b"\xc0\0\x02\x01") + _option(51, _uint(3600, 4))
        options += b"\xff"
    return header + b"\x63\x82\x53\x63" + options


def _model(request=None, response=None, **changes):
    result = {
        "schema_version": 1,
        "request_source_id": "synthetic-discover",
        "response_source_id": "synthetic-offer",
        "request_base64": base64.b64encode(_packet() if request is None else request).decode(),
        "response_base64": base64.b64encode(
            _packet(2, op=2, yiaddr=0xC000020A) if response is None else response
        ).decode(),
    }
    result.update(changes)
    return result


def _readdress(document):
    changed = copy.deepcopy(document)
    body = {
        key: value
        for key, value in changed.items()
        if key not in ("analysis_id", "analysis_sha256")
    }
    digest = (
        "sha256:"
        + hashlib.sha256(d.DOMAIN.encode() + b"\n" + _canonical(body).encode()).hexdigest()
    )
    changed["analysis_sha256"] = digest
    changed["analysis_id"] = "D4A-" + digest[7:39].upper()
    return changed


class Dhcpv4AnalysisTests(unittest.TestCase):
    def analyze(self, request=None, response=None, **changes):
        return d.analyze_supplied_dhcpv4(_model(request, response, **changes))

    def deny(self, operation, *, before_hash=True):
        if before_hash:
            with patch.object(d.hashlib, "sha256") as digest:
                with self.assertRaises(d.Dhcpv4AnalysisError):
                    operation()
                digest.assert_not_called()
        else:
            with self.assertRaises(d.Dhcpv4AnalysisError):
                operation()

    def codes(self, document):
        return {row["code"] for row in document["observations"]}

    def test_literal_fixture_matches_independent_encoder_and_golden(self):
        self.assertEqual(d.component_fixture(), _model())
        self.assertEqual(len(_packet()), 244)
        self.assertEqual(len(_packet(2, op=2, yiaddr=0xC000020A)), 256)
        document = self.analyze().to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertEqual(document["pair"]["selected_exchange"], "discover_offer")
        self.assertTrue(document["pair"]["copied_header_fields_match"])
        self.assertEqual(document["observations"], [])
        self.assertEqual(document["analysis_id"], "D4A-2448D8984FAB8D9ECA12DC19D87894B3")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:2448d8984fab8d9eca12dc19d87894b326eff77e5647731260a480a914075a63",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:13cbdb286a43aa757004d6789c907ecfb81f56670cb7bd0be44d6583ab24b1b9",
        )
        self.assertEqual(
            document["request_packet_sha256"],
            "sha256:ec90c51f444caff2a550c9224e71d9804c1f8abcf1efcd6cb798ea115f38b744",
        )
        self.assertEqual(
            document["response_packet_sha256"],
            "sha256:d08be45d5a9db3c7cf7284f926d4c5858386a9980995372489d2a0a3d1233946",
        )

    def test_all_native_parser_export_and_original_verifier_paths_equal(self):
        source = _model()
        report = d.analyze_supplied_dhcpv4(source)
        text, document = report.to_json(), report.to_dict()
        for returned in (
            d.analyze_supplied_dhcpv4_bytes(model_bytes=_canonical(source).encode()),
            d.Dhcpv4Analysis(text),
            d.Dhcpv4Analysis.from_dict(document),
            d.Dhcpv4Analysis.from_json(text),
            d.verify_supplied_dhcpv4_analysis(report, model=source),
        ):
            self.assertEqual(returned.to_json(), text)
        self.assertEqual(report.analysis_id, document["analysis_id"])
        self.assertEqual(report.analysis_sha256, document["analysis_sha256"])

    def test_request_ack_and_network_order_quantities(self):
        request = _packet(
            3,
            xid=0x89ABCDEF,
            flags=0x8000,
            giaddr=0xC6336401,
            ciaddr=0xC000020A,
            secs=0x1234,
            hops=1,
        )
        response = _packet(
            5,
            op=2,
            xid=0x89ABCDEF,
            flags=0x8000,
            giaddr=0xC6336401,
            ciaddr=0xC000020A,
            yiaddr=0xC000020A,
            siaddr=0xCB007101,
        )
        document = self.analyze(request, response).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertEqual(document["request"]["header"]["xid"], 0x89ABCDEF)
        self.assertEqual(document["request"]["header"]["secs"], 0x1234)
        self.assertEqual(document["response"]["header"]["siaddr_hex"], "cb007101")
        self.assertEqual(document["pair"]["selected_exchange"], "request_ack")

    def test_all_fixed_header_prefix_lengths_are_incomplete_not_clean(self):
        packet = _packet()
        for length in range(1, 240):
            with self.subTest(length=length):
                document = self.analyze(packet[:length]).to_dict()
                self.assertEqual(document["supported_checks_outcome"], "incomplete")
                self.assertIsNone(document["pair"]["selected_exchange"])

    def test_unknown_bootp_cookie_and_missing_dhcp_type_withhold_pair(self):
        for request in (
            _packet()[:236] + b"BOOT" + b"\x35\x01\x01\xff",
            _packet(options=b"\xff"),
        ):
            document = self.analyze(request).to_dict()
            self.assertEqual(document["supported_checks_outcome"], "incomplete")
            self.assertIsNone(document["request"]["message_type"])
        bootp = self.analyze(_packet(options=b"\xff")).to_dict()
        self.assertIn("dhcp_type_absent_bootp_unassessed", self.codes(bootp))

    def test_all_message_type_pairs_outside_two_exchanges_are_unassessed(self):
        for first in (0, 1, 3, 4, 7, 8, 255):
            for second in (0, 2, 5, 6, 255):
                if (first, second) in ((1, 2), (3, 5)):
                    continue
                document = self.analyze(_packet(first), _packet(second, op=2)).to_dict()
                self.assertIsNone(document["pair"]["selected_exchange"])
                self.assertIn("exchange_outside_subset", self.codes(document))

    def test_pad_and_end_do_not_become_zero_length_tlv_fragments(self):
        options = b"\0\0" + _option(53, b"\x01") + b"\0\xff\0\0"
        request = self.analyze(_packet(options=options)).to_dict()["request"]
        self.assertEqual(len(request["fragments"]), 1)
        self.assertEqual(request["fragments"][0]["offset"], 242)
        self.assertEqual(request["fields"][0]["pad_octets"], 3)
        self.assertEqual(request["fields"][0]["trailing_pad_octets"], 2)
        self.assertEqual(request["fields"][0]["end_marker_offset"], 246)

    def test_end_option_missing_or_incomplete_primary_tlv_preserves_prefix(self):
        for suffix, code in (
            (b"", "end_option_missing"),
            (b"\x32", "option_length_truncated"),
            (b"\x32\x04\0", "option_data_truncated"),
        ):
            document = self.analyze(_packet(options=_option(53, b"\x01") + suffix)).to_dict()
            self.assertIn(code, self.codes(document))
            self.assertFalse(document["request"]["options_complete"])
            self.assertEqual(len(document["request"]["fragments"]), 1)
            self.assertIsNone(document["request"]["message_type"])

    def test_bytes_after_end_never_reactivate_or_become_an_option(self):
        document = self.analyze(
            _packet(options=_option(53, b"\x01") + b"\xff\x34\x01\x03")
        ).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "incomplete")
        self.assertIn("nonpad_after_end", self.codes(document))
        self.assertEqual(len(document["request"]["fragments"]), 1)
        self.assertEqual(len(document["request"]["fields"]), 1)

    def test_rfc3396_concatenation_overload_order_and_no_recursive_activation(self):
        # Data order is primary, file, sname, NOT physical header order.
        primary = _option(53, b"\x01") + _option(52, b"\x03") + _option(200, b"ab") + b"\xff"
        request = _packet(
            options=primary, file=_option(200, b"cd") + b"\xff", sname=_option(200, b"ef") + b"\xff"
        )
        document = self.analyze(request).to_dict()
        parsed = document["request"]
        row = next(row for row in parsed["logical_options"] if row["code"] == 200)
        self.assertEqual(row["data_hex"], b"abcdef".hex())
        self.assertEqual([row["field"] for row in parsed["fields"]], ["options", "file", "sname"])
        self.assertEqual(
            [row["offset"] for row in parsed["fragments"] if row["code"] == 200], [246, 108, 44]
        )
        primary = _option(53, b"\x01") + _option(52, b"\x01") + b"\xff"
        recursive = _packet(
            options=primary,
            file=_option(52, b"\x02") + b"\xff",
            sname=_option(200, b"do-not-parse") + b"\xff",
        )
        document = self.analyze(recursive).to_dict()
        self.assertEqual(len(document["request"]["fields"]), 2)
        self.assertIn("secondary_overload_not_reactivated", self.codes(document))
        self.assertNotIn(200, [row["code"] for row in document["request"]["logical_options"]])

    def test_each_overload_value_activates_exact_fields_only(self):
        for overload, fields in (
            (1, ["options", "file"]),
            (2, ["options", "sname"]),
            (3, ["options", "file", "sname"]),
        ):
            request = _packet(
                options=_option(53, b"\x01") + _option(52, bytes((overload,))) + b"\xff",
                file=b"\xff",
                sname=b"\xff",
            )
            document = self.analyze(request).to_dict()
            self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
            self.assertEqual([row["field"] for row in document["request"]["fields"]], fields)

    def test_split_known_option_interpreted_after_concatenation(self):
        # A valid server identifier can be split on any octet, including zero-length portions.
        for split in range(5):
            value = b"\xc0\0\x02\x01"
            options = _option(53, b"\x02") + _option(54, value[:split]) + _option(54, value[split:])
            options += _option(51, _uint(3600, 4)) + b"\xff"
            document = self.analyze(response=_packet(2, op=2, options=options)).to_dict()
            self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
            row = next(row for row in document["response"]["logical_options"] if row["code"] == 54)
            self.assertEqual(row["wire_integer"], 0xC0000201)
            self.assertEqual(len(row["fragment_indices"]), 2)

    def test_split_fixed_option_across_options_file_and_sname(self):
        options = _option(53, b"\x02") + _option(52, b"\x03")
        options += _option(54, b"\xc0") + _option(51, _uint(3600, 4)) + b"\xff"
        response = _packet(
            2,
            op=2,
            options=options,
            file=_option(54, b"\0\x02") + b"\xff",
            sname=_option(54, b"\x01") + b"\xff",
        )
        document = self.analyze(response=response).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        row = next(row for row in document["response"]["logical_options"] if row["code"] == 54)
        self.assertEqual(row["data_hex"], "c0000201")

    def test_repeated_message_types_are_not_last_value_wins(self):
        options = _option(53, b"\x01") + _option(53, b"\x01") + b"\xff"
        document = self.analyze(_packet(options=options)).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "contradictions")
        self.assertIn("logical_option_length_invalid", self.codes(document))
        self.assertIsNone(document["request"]["message_type"])

    def test_overload_ambiguous_invalid_and_empty_portions(self):
        for value in (b"\0", b"\x04", b"\xff", b"\x01\x02"):
            document = self.analyze(
                _packet(options=_option(53, b"\x01") + _option(52, value) + b"\xff")
            ).to_dict()
            self.assertIn("overload_primary_value_invalid", self.codes(document))
            self.assertEqual(len(document["request"]["fields"]), 1)
        empty = self.analyze(
            _packet(options=_option(53, b"\x01") + _option(52, b"") + b"\xff")
        ).to_dict()
        self.assertIn("overload_activation_unavailable", self.codes(empty))
        self.assertEqual(empty["supported_checks_outcome"], "incomplete")
        split = _option(53, b"\x01") + _option(52, b"") + _option(52, b"\x01") + b"\xff"
        document = self.analyze(_packet(options=split, file=_option(52, b"") + b"\xff")).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_fixed_overload_field_requires_end_and_pad_and_cannot_cross_boundary(self):
        primary = _option(53, b"\x01") + _option(52, b"\x01") + b"\xff"
        for value, code in (
            (b"\0" * 128, "end_option_missing"),
            (b"\0" * 127 + b"\x32", "option_crosses_fixed_field"),
            (b"\x32\xff" + b"x" * 126, "option_crosses_fixed_field"),
            (b"\xff\x01", "nonpad_after_end"),
        ):
            document = self.analyze(_packet(options=primary, file=value)).to_dict()
            self.assertEqual(document["supported_checks_outcome"], "contradictions")
            self.assertIn(code, self.codes(document))

    def test_unselected_file_and_sname_stay_opaque(self):
        request = _packet(file=b"\x32\xffBAD", sname=b"\x34\x01\x03BAD")
        document = self.analyze(request).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertEqual(len(document["request"]["fields"]), 1)
        self.assertTrue(document["request"]["header"]["file_hex"].startswith("32ff"))

    def test_table3_copied_fields_and_required_zeroes_are_checked(self):
        for changed in (
            {"op": 1},
            {"xid": 5},
            {"flags": 0x8000},
            {"giaddr": 1},
            {"chaddr": b"\x02\0\0\0\0\x02"},
            {"hops": 1},
            {"secs": 1},
            {"ciaddr": 1},
            {"htype": 2},
            {"hlen": 5},
        ):
            document = self.analyze(
                response=_packet(2, op=changed.pop("op", 2), **changed)
            ).to_dict()
            self.assertEqual(document["supported_checks_outcome"], "contradictions")
            self.assertIn("declared_pair_field_mismatch", self.codes(document))

    def test_all16_chaddr_bytes_are_copied_not_only_hlen_prefix(self):
        original = b"\x02\0\0\0\0\x01" + b"A" * 10
        request = _packet(chaddr=original)
        response = _packet(2, op=2, chaddr=original[:-1] + b"B")
        document = self.analyze(request, response).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "contradictions")
        self.assertIn({"field": "chaddr_hex", "matches": False}, document["pair"]["checks"])

    def test_ack_ciaddr_can_be_zero_or_copied_but_not_foreign(self):
        request = _packet(3, ciaddr=0xC000020A)
        for value, expected in ((0, True), (0xC000020A, True), (0xC000020B, False)):
            document = self.analyze(request, _packet(5, op=2, ciaddr=value)).to_dict()
            check = next(
                row for row in document["pair"]["checks"] if row["field"] == "response_ciaddr"
            )
            self.assertIs(check["matches"], expected)

    def test_reserved_client_flags_hlen_and_unknown_op_differ(self):
        document = self.analyze(_packet(flags=1), _packet(2, op=2, flags=1)).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "contradictions")
        document = self.analyze(_packet(hlen=17), _packet(2, op=2, hlen=17)).to_dict()
        self.assertIn("hlen_exceeds_chaddr_field", self.codes(document))
        document = self.analyze(_packet(hlen=0), _packet(2, op=2, hlen=0)).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "incomplete")
        document = self.analyze(_packet(op=3)).to_dict()
        self.assertIn("bootp_op_unassessed", self.codes(document))

    def test_required_response_options_and_fixed_logical_lengths(self):
        for omitted in (51, 54):
            options = _option(53, b"\x02")
            for code, value in ((54, b"\xc0\0\x02\x01"), (51, _uint(3600, 4))):
                if code != omitted:
                    options += _option(code, value)
            document = self.analyze(response=_packet(2, op=2, options=options + b"\xff")).to_dict()
            self.assertIn("required_response_option_absent", self.codes(document))
        for code, width in ((50, 4), (51, 4), (53, 1), (54, 4)):
            for length in (0, width - 1, width + 1):
                options = _option(code, b"x" * length) + b"\xff"
                document = self.analyze(_packet(options=options)).to_dict()
                self.assertIn("logical_option_length_invalid", self.codes(document))

    def test_table3_forbidden_response_option_presence_is_not_unknown_absence(self):
        for code in (50, 55, 57):
            response = _packet(2, op=2)
            response = response[:-1] + _option(code, b"\0" * 4) + b"\xff"
            document = self.analyze(response=response).to_dict()
            self.assertIn("option_forbidden_in_selected_response", self.codes(document))

    def test_server_bootstrap_and_requested_address_are_not_invented_context(self):
        request = _packet(options=_option(53, b"\x01") + _option(50, b"\xc0\0\x02\x09") + b"\xff")
        response = _packet(2, op=2, yiaddr=0xC000020A, siaddr=0xCB007101)
        document = self.analyze(request, response).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertFalse(document["flags"]["server_selection_verified"])
        self.assertFalse(document["flags"]["address_availability_verified"])

    def test_unknown_options_and_opaque_identifiers_never_decode_text(self):
        options = (
            _option(53, b"\x01")
            + _option(200, b"\xff\0https://inert.invalid")
            + _option(61, b"\0\xff")
            + b"\xff"
        )
        document = self.analyze(_packet(options=options)).to_dict()
        self.assertEqual(document["supported_checks_outcome"], "incomplete")
        rows = {row["code"]: row for row in document["request"]["logical_options"]}
        self.assertEqual(rows[61]["semantic_status"], "opaque_client_identifier")
        self.assertEqual(rows[61]["data_hex"], "00ff")
        self.assertIsNone(rows[200]["wire_integer"])

    def test_client_identifier_minimum_and_unsigned_infinite_lease_wire_value(self):
        for value in (b"", b"\0"):
            document = self.analyze(
                _packet(options=_option(53, b"\x01") + _option(61, value) + b"\xff")
            ).to_dict()
            self.assertIn("client_identifier_too_short", self.codes(document))
        response = _packet(
            2,
            op=2,
            options=_option(53, b"\x02")
            + _option(54, b"\xc0\0\x02\x01")
            + _option(51, b"\xff" * 4)
            + b"\xff",
        )
        document = self.analyze(response=response).to_dict()
        lease = next(row for row in document["response"]["logical_options"] if row["code"] == 51)
        self.assertEqual(lease["wire_integer"], 2**32 - 1)
        self.assertFalse(document["flags"]["lease_validity_verified"])

    def test_base64_shape_pad_bits_and_declared_packet_bound_before_decode(self):
        for value in ("", "a", "====", "YR==", "YQ=", "YQ==\n", "YQ-_", [], b"YQ=="):
            self.deny(lambda value=value: self.analyze(request_base64=value))
        value = base64.b64encode(b"x" * (d.MAX_PACKET_BYTES + 1)).decode()
        with patch.object(d.base64, "b64decode") as decoder:
            self.deny(lambda: self.analyze(request_base64=value))
            decoder.assert_not_called()

    def test_real_packet_and_fragment_ceilings_and_fresh_detachment(self):
        request = _packet()
        padded = request + b"\0" * (d.MAX_PACKET_BYTES - len(request))
        document = self.analyze(padded).to_dict()
        self.assertEqual(document["request"]["byte_count"], d.MAX_PACKET_BYTES)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        options = (
            _option(53, b"\x01")
            + _option(61, b"") * (d.MAX_FRAGMENTS - 2)
            + _option(61, b"\0x")
            + b"\xff"
        )
        self.assertEqual(
            len(self.analyze(_packet(options=options)).to_dict()["request"]["fragments"]),
            d.MAX_FRAGMENTS,
        )
        self.deny(lambda: self.analyze(_packet(options=options[:-1] + _option(61, b"") + b"\xff")))
        first = d.component_fixture()
        first["schema_version"] = False
        self.assertEqual(d.component_fixture(), _model())

    def test_exact_native_model_types_missing_fields_aliases_and_cycles(self):
        class Text(str):
            pass

        class Number(int):
            pass

        class Mapping(dict):
            pass

        for source in (None, [], True, Mapping(_model()), {**_model(), "extra": 1}):
            self.deny(lambda source=source: d.analyze_supplied_dhcpv4(source))
        for field in _model():
            incomplete = _model()
            del incomplete[field]
            self.deny(lambda incomplete=incomplete: d.analyze_supplied_dhcpv4(incomplete))
        for value in (True, 1.0, Number(1), "1", None, 2**63):
            self.deny(lambda value=value: self.analyze(schema_version=value))
        for field in ("request_source_id", "response_source_id", "request_base64"):
            self.deny(lambda field=field: self.analyze(**{field: Text(_model()[field])}))
        for value in ("", "a" * 65, "x y", "\u007f", [], {}):
            self.deny(lambda value=value: self.analyze(request_source_id=value))
        cyclic = []
        cyclic.append(cyclic)
        self.deny(lambda: self.analyze(request_source_id=cyclic))

    def test_native_queued_nodes_repeated_graph_depth_bytes_before_copy(self):
        deep = None
        for _ in range(d.MAX_DEPTH):
            deep = [deep]
        shared = ["x" * 1024] * 64
        for source in (
            deep,
            {"nodes": [None] * d.MAX_MODEL_NODES},
            {"shared": [shared] * 8},
            {"escape": '"' * d.MAX_STRING_BYTES},
        ):
            with patch.object(d, "_copy") as copier:
                self.deny(lambda source=source: d.analyze_supplied_dhcpv4(source))
                copier.assert_not_called()

    def test_raw_lexical_alias_duplicate_depth_nodes_and_scalars_before_decoder(self):
        malformed = (
            "--1",
            "+1",
            "01",
            "-01",
            "1.0",
            "1e0",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "1" * 1000,
        )
        for token in malformed:
            raw = '{"schema_version":' + token + "}"
            with patch.object(d.json, "loads") as decoder:
                self.deny(lambda raw=raw: d.analyze_supplied_dhcpv4_bytes(model_bytes=raw.encode()))
                decoder.assert_not_called()
        raw_cases = (
            "[" * d.MAX_DEPTH + "null" + "]" * d.MAX_DEPTH,
            "[" + ",".join("null" for _ in range(d.MAX_MODEL_NODES)) + "]",
            '"' + "x" * (d.MAX_STRING_BYTES + 1) + '"',
            '"\\u007f"',
            '"\\ud800"',
            '"\\u0022' + "\\u0022" * d.MAX_STRING_BYTES + '"',
        )
        for raw in raw_cases:
            with patch.object(d.json, "loads") as decoder:
                self.deny(lambda raw=raw: d.analyze_supplied_dhcpv4_bytes(model_bytes=raw.encode()))
                decoder.assert_not_called()
        self.deny(
            lambda: d.analyze_supplied_dhcpv4_bytes(
                model_bytes=b'{"schema_version":1,"schema_version":1}'
            )
        )

    def test_raw_model_spelling_and_member_order_do_not_change_source_identity(self):
        source = _model()
        raw = json.dumps(dict(reversed(list(source.items()))), indent=2).replace(
            "synthetic", "\\u0073ynthetic"
        )
        self.assertEqual(
            d.analyze_supplied_dhcpv4_bytes(model_bytes=raw.encode()).to_json(),
            self.analyze().to_json(),
        )

    def test_cohashed_false_parse_pair_and_promotions_refuse(self):
        original = self.analyze().to_dict()
        changes = []
        for section, field, value in (
            ("pair", "copied_header_fields_match", False),
            ("flags", "source_authenticated", True),
            ("effects", "lease", "allocated"),
            ("bounds", "packet_bytes_each", 9000),
        ):
            changed = copy.deepcopy(original)
            changed[section][field] = value
            changes.append(changed)
        changed = copy.deepcopy(original)
        changed["request"]["header"]["xid"] += 1
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["response"]["logical_options"][0]["data_hex"] = "00000001"
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["request"]["fragments"][0]["offset"] += 1
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["observations"] = [{"code": "manufactured"}]
        changes.append(changed)
        for changed in changes:
            forged = _readdress(changed)
            self.deny(lambda forged=forged: d.Dhcpv4Analysis.from_dict(forged), before_hash=False)
            self.deny(
                lambda forged=forged: d.Dhcpv4Analysis.from_json(_canonical(forged)),
                before_hash=False,
            )

    def test_source_swap_alternate_genuine_pair_and_permutations_are_bound(self):
        original = _model()
        for foreign in (
            _model(request_source_id="other"),
            _model(response_source_id="other"),
            _model(_packet(xid=7), _packet(2, op=2, xid=7)),
            _model(_packet(options=b"\0" + _option(53, b"\x01") + b"\xff")),
        ):
            report = d.analyze_supplied_dhcpv4(foreign)
            d.Dhcpv4Analysis.from_json(report.to_json())
            self.deny(
                lambda report=report: d.verify_supplied_dhcpv4_analysis(report, model=original),
                before_hash=False,
            )
        changed = self.analyze().to_dict()
        foreign = _model(_packet(xid=7), _packet(2, op=2, xid=7))
        changed["source_model"] = foreign
        changed["source_model_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                d.MODEL_DOMAIN.encode() + b"\n" + _canonical(foreign).encode()
            ).hexdigest()
        )
        changed["request_packet_sha256"] = (
            "sha256:" + hashlib.sha256(base64.b64decode(foreign["request_base64"])).hexdigest()
        )
        changed["response_packet_sha256"] = (
            "sha256:" + hashlib.sha256(base64.b64decode(foreign["response_base64"])).hexdigest()
        )
        self.deny(lambda: d.Dhcpv4Analysis.from_dict(_readdress(changed)), before_hash=False)

    def test_immutable_detached_ownership_and_missing_or_forged_wrapper(self):
        source = _model()
        report = d.analyze_supplied_dhcpv4(source)
        baseline = report.to_json()
        source["schema_version"] = False
        document = report.to_dict()
        document["request"]["fragments"].clear()
        document["source_model"]["schema_version"] = False
        self.assertEqual(report.to_json(), baseline)
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"
        missing = object.__new__(d.Dhcpv4Analysis)
        for operation in (
            missing.to_dict,
            missing.to_json,
            lambda: d.verify_supplied_dhcpv4_analysis(missing, model=_model()),
        ):
            self.deny(operation)
        for value in ({}, None, True, baseline):
            self.deny(lambda value=value: d.verify_supplied_dhcpv4_analysis(value, model=_model()))

        class Derived(d.Dhcpv4Analysis):
            pass

        self.deny(lambda: Derived(baseline))
        self.deny(lambda: Derived.from_json(baseline))
        changed = report.to_dict()
        changed["pair"]["copied_header_fields_match"] = False
        object.__setattr__(report, "document_json", _canonical(_readdress(changed)))
        self.deny(report.to_json, before_hash=False)

    def test_report_exact_canonical_bytes_and_identity_fields_are_replayed(self):
        report = self.analyze()
        document = report.to_dict()
        for raw in (json.dumps(document, indent=2), report.to_json() + "\n", "{}"):
            self.deny(lambda raw=raw: d.Dhcpv4Analysis.from_json(raw), before_hash=False)
        for field in (
            "analysis_id",
            "analysis_sha256",
            "source_model_sha256",
            "request_packet_sha256",
            "response_packet_sha256",
        ):
            changed = copy.deepcopy(document)
            changed[field] = "foreign"
            self.deny(
                lambda changed=changed: d.Dhcpv4Analysis.from_dict(changed), before_hash=False
            )

    def test_every_effect_none_and_authenticity_authority_promotion_false(self):
        document = self.analyze().to_dict()
        self.assertTrue(all(value == "none" for value in document["effects"].values()))
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertEqual(document["wave_id"], "IW2-006")
        self.assertEqual(document["commander_id"], "AOE-GC-D13-CMD")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")

    def test_all_eight_public_passes_reserve_cumulative_work_before_digest(self):
        source = _model()
        report = self.analyze()
        document, text = report.to_dict(), report.to_json()
        operations = (
            lambda: d.analyze_supplied_dhcpv4(source),
            lambda: d.analyze_supplied_dhcpv4_bytes(model_bytes=_canonical(source).encode()),
            lambda: d.Dhcpv4Analysis(text),
            lambda: d.Dhcpv4Analysis.from_dict(document),
            lambda: d.Dhcpv4Analysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: d.verify_supplied_dhcpv4_analysis(report, model=source),
        )
        charge, digest = d._Budget.charge, d.hashlib.sha256
        for operation in operations:
            budgets = []
            state = {"hashed": False}

            def tracking(self, amount, state=state, budgets=budgets, self_test=self):
                self_test.assertFalse(state["hashed"], "budget charge after an own digest")
                if all(self is not seen for seen in budgets):
                    budgets.append(self)
                charge(self, amount)

            def tracked_digest(*args, state=state, **kwargs):
                state["hashed"] = True
                return digest(*args, **kwargs)

            with (
                patch.object(d._Budget, "charge", tracking),
                patch.object(d.hashlib, "sha256", tracked_digest),
            ):
                operation()
            self.assertEqual(len(budgets), 1)
            needed = budgets[0].used
            for delta in (-1, 0):

                def limited(self, amount, limit=needed + delta):
                    if amount > limit - self.used:
                        raise d.Dhcpv4AnalysisError("Independent transparent reduced work cap")
                    charge(self, amount)

                with patch.object(d._Budget, "charge", limited):
                    if delta == -1:
                        self.deny(operation)
                    else:
                        operation()

    def test_actual_report_retention_and_reduced_report_node_and_byte_denials_precede_hash(self):
        options = _option(53, b"\x01") + _option(200, b"x" * 255) * 30 + b"\xff"
        source = _model(_packet(options=options))
        report = d.analyze_supplied_dhcpv4(source)
        self.assertGreater(len(report.to_json()), 30_000)
        for name, limit in (
            ("MAX_REPORT_BYTES", 16_384),
            ("MAX_REPORT_NODES", 512),
            ("MAX_OPTION_DATA_BYTES", 7000),
            ("MAX_OBSERVATIONS", 1),
        ):
            with patch.object(d, name, limit):
                target = (
                    source
                    if name != "MAX_OBSERVATIONS"
                    else _model(
                        _packet(
                            options=_option(53, b"\x01")
                            + _option(200, b"x")
                            + _option(201, b"y")
                            + b"\xff"
                        )
                    )
                )
                self.deny(lambda target=target: d.analyze_supplied_dhcpv4(target))

    def test_all_eight_actual_work_constant_fixed_points_are_transparently_reduced(self):
        charge = d._Budget.charge
        source = _model()

        def operation(index, report, document, text):
            choices = (
                lambda: d.analyze_supplied_dhcpv4(source),
                lambda: d.analyze_supplied_dhcpv4_bytes(model_bytes=_canonical(source).encode()),
                lambda: d.Dhcpv4Analysis(text),
                lambda: d.Dhcpv4Analysis.from_dict(document),
                lambda: d.Dhcpv4Analysis.from_json(text),
                report.to_dict,
                report.to_json,
                lambda: d.verify_supplied_dhcpv4_analysis(report, model=source),
            )
            return choices[index]

        for index in range(8):
            cap = d.MAX_WORK
            for _ in range(10):
                with patch.object(d, "MAX_WORK", cap):
                    report = d.analyze_supplied_dhcpv4(source)
                    # Test setup reads the canonical stored text without adding a
                    # different export pass to the operation-specific fixed point.
                    text = report.document_json
                    document = json.loads(text)
                    budgets = []

                    def measured(self, amount, budgets=budgets):
                        if all(self is not seen for seen in budgets):
                            budgets.append(self)
                        charge(self, amount)

                    with patch.object(d._Budget, "charge", measured):
                        operation(index, report, document, text)()
                    needed = budgets[0].used
                    self.assertEqual(len(budgets), 1)
                    if needed == cap:
                        break
                cap = needed
            else:
                self.fail("Reduced actual-constant budget did not reach a fixed point")
            self.assertLess(cap, 1_000_000)
            with patch.object(d, "MAX_WORK", cap):
                operation(index, report, document, text)()
            with patch.object(d, "MAX_WORK", cap - 1):
                self.deny(operation(index, report, document, text))

    def test_byte_and_raw_report_wrong_families_are_leaf_errors(self):
        for value in (b"", bytearray(b"{}"), "{}", b"\xff", b" " * (d.MAX_MODEL_BYTES + 1)):
            self.deny(lambda value=value: d.analyze_supplied_dhcpv4_bytes(model_bytes=value))
        for value in (b"{}", None, "", " " * (d.MAX_REPORT_BYTES + 1)):
            self.deny(lambda value=value: d.Dhcpv4Analysis.from_json(value))


if __name__ == "__main__":
    unittest.main()

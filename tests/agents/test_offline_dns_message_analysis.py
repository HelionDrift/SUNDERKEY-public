"""Supplied DNS structures, independent binary encoders and exact replay controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import socket
import struct
import unittest
from unittest.mock import patch

from sunderkey import offline_dns_message_analysis as dns

GOLDEN_ID = "DNS-11459030D91AEAC582A266D52F657446"
GOLDEN_SHA = "sha256:11459030d91aeac582a266d52f657446235c11ab4c15df14e48cf6919bfc6faa"
GOLDEN_MODEL_SHA = "sha256:4809d977239b7072463f88bb270ad41d99af4b26d9d3e1bd3532e22b4ca2232e"
GOLDEN_MESSAGE_SHA = "sha256:6270b3a4da7e25f919d3ff157cc9ed96be863809cf8a66d84a0c9c777424d7ee"


def _header(q: int = 1, a: int = 0, ns: int = 0, ar: int = 0, flags: int = 0x8180) -> bytes:
    return struct.pack("!6H", 0x1234, flags, q, a, ns, ar)


def _name(labels: tuple[bytes, ...]) -> bytes:
    """Independent encoder: length octet followed by exact label, then root octet."""
    return b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"


def _pointer(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


def _question(name: bytes, kind: int = 1, rr_class: int = 1) -> bytes:
    return name + struct.pack("!2H", kind, rr_class)


def _record(name: bytes, kind: int, data: bytes, rr_class: int = 1, ttl: int = 300) -> bytes:
    return name + struct.pack("!HHIH", kind, rr_class, ttl, len(data)) + data


def _model(raw: bytes) -> dict:
    return {"schema_version": 1, "message_base64": base64.b64encode(raw).decode("ascii")}


def component_fixture() -> dict:
    """Fresh inert public payload; no acquisition, endpoints, keys or transport."""
    name = _name((b"www", b"example", b"com"))
    raw = (
        _header(a=2)
        + _question(name)
        + _record(_pointer(12), 1, bytes([192, 0, 2, 1]))
        + _record(_pointer(12), 16, b"\x02ok\x00", ttl=0)
    )
    return {"model": _model(raw)}


def _report(raw: bytes) -> dict:
    return dns.analyze_supplied_dns_message(_model(raw)).to_dict()


def _codes(document: dict) -> set[str]:
    return {note["code"] for note in document["observations"]}


def _decoded(name: dict) -> tuple[bytes, ...]:
    return tuple(base64.b64decode(label, validate=True) for label in name["labels_base64"])


def _semantic(value):
    if type(value) is dict:
        if "labels_base64" in value:
            return value["labels_base64"]
        return {
            key: _semantic(child)
            for key, child in value.items()
            if key not in {"start", "end", "rdata_start", "rdlength", "index"}
        }
    if type(value) is list:
        return [_semantic(child) for child in value]
    return value


def _readdress(document: dict) -> dict:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(
        dns.DOMAIN.encode("ascii") + b"\n" + canonical.encode("ascii")
    ).hexdigest()
    document["analysis_id"] = "DNS-" + digest[:32].upper()
    document["analysis_sha256"] = "sha256:" + digest
    return document


class DnsMessageAnalysisTests(unittest.TestCase):
    def test_literal_golden_and_roundtrips_remain_exact(self):
        model = component_fixture()["model"]
        report = dns.analyze_supplied_dns_message(model)
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], GOLDEN_ID)
        self.assertEqual(document["analysis_sha256"], GOLDEN_SHA)
        self.assertEqual(document["source"]["model_sha256"], GOLDEN_MODEL_SHA)
        self.assertEqual(document["source"]["message_sha256"], GOLDEN_MESSAGE_SHA)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        self.assertTrue(document["counted_sections_complete"])
        self.assertEqual(document["unconsumed_bytes"], 0)
        for parsed in (
            dns.DnsMessageAnalysis.from_dict(document),
            dns.DnsMessageAnalysis.from_json(report.to_json()),
            dns.verify_supplied_dns_message_analysis(report, model=model),
        ):
            self.assertEqual(parsed.to_json(), report.to_json())

    def test_fixture_is_fresh_and_native_byte_model_is_equivalent(self):
        first = component_fixture()
        second = component_fixture()
        first["model"]["schema_version"] = 2
        report = dns.analyze_supplied_dns_message(second["model"])
        text = json.dumps(second["model"], indent=2)
        for raw in (text, text.encode("ascii")):
            self.assertEqual(
                dns.analyze_supplied_dns_message_bytes(model_json=raw).to_json(), report.to_json()
            )

    def test_independent_encoder_oracle_preserves_arbitrary_labels_and_case(self):
        alphabet = (b"a", b"A", b"\x00.\xff", b"xy")
        for count in range(4):
            for labels in itertools.product(alphabet, repeat=count):
                with self.subTest(labels=labels):
                    raw = _header() + _question(_name(labels))
                    document = _report(raw)
                    name = document["sections"]["questions"][0]["name"]
                    self.assertEqual(_decoded(name), labels)
                    self.assertEqual(
                        name["expanded_wire_bytes"], sum(1 + len(x) for x in labels) + 1
                    )
                    self.assertEqual(
                        document["supported_checks_outcome"], "consistent_supplied_subset"
                    )

    def test_compressed_and_uncompressed_sections_have_equal_decoded_semantics(self):
        labels = (b"www", b"example", b"com")
        uncompressed = _name(labels)
        question = _question(uncompressed)
        for kind, data in (
            (1, b"\xc0\x00\x02\x01"),
            (28, bytes(range(16))),
            (2, uncompressed),
            (5, uncompressed),
            (12, uncompressed),
            (15, b"\x00\x0a" + uncompressed),
            (6, uncompressed * 2 + struct.pack("!5I", 1, 2, 3, 4, 5)),
            (16, b"\x03one\x00\x03two"),
        ):
            with self.subTest(kind=kind):
                compressed_data = {
                    2: _pointer(12),
                    5: _pointer(12),
                    12: _pointer(12),
                    15: b"\x00\x0a" + _pointer(12),
                    6: _pointer(12) * 2 + struct.pack("!5I", 1, 2, 3, 4, 5),
                }.get(kind, data)
                plain = _report(_header(a=1) + question + _record(uncompressed, kind, data))
                compressed = _report(
                    _header(a=1) + question + _record(_pointer(12), kind, compressed_data)
                )
                self.assertEqual(_semantic(plain["sections"]), _semantic(compressed["sections"]))
                self.assertEqual(
                    compressed["supported_checks_outcome"], "consistent_supplied_subset"
                )
                self.assertNotEqual(
                    plain["source"]["message_sha256"], compressed["source"]["message_sha256"]
                )

    def test_compressed_rdata_length_is_encoded_length_not_expanded_length(self):
        raw = _header(a=1) + _question(_name((b"long", b"example")))
        raw += _record(_pointer(12), 5, _pointer(12))
        document = _report(raw)
        record = document["sections"]["answers"][0]
        name = record["rdata"]["name"]
        self.assertEqual(record["rdlength"], 2)
        self.assertEqual(name["encoded_bytes"], 2)
        self.assertGreater(name["expanded_wire_bytes"], 2)
        self.assertEqual(record["end"], record["rdata_start"] + 2)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_prior_suffix_root_and_pointer_name_boundaries_are_supported(self):
        first = _name((b"one", b"example", b"com"))
        second_start = 12 + len(first) + 4
        questions = _question(first) + _question(b"\x03two" + _pointer(16))
        third_start = second_start + len(b"\x03two" + _pointer(16)) + 4
        questions += _question(_pointer(second_start))
        questions += _question(_pointer(third_start))
        root_offset = 12 + len(first) - 1
        questions += _question(_pointer(root_offset))
        document = _report(_header(q=5) + questions)
        names = [record["name"] for record in document["sections"]["questions"]]
        self.assertEqual(_decoded(names[1]), (b"two", b"example", b"com"))
        self.assertEqual(_decoded(names[2]), _decoded(names[1]))
        self.assertEqual(_decoded(names[3]), _decoded(names[1]))
        self.assertEqual(_decoded(names[4]), ())
        self.assertEqual(len(names[3]["pointer_chain"]), 3)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_exact_label_and_expanded_name_limits(self):
        for labels in ((b"x" * 63,), (b"a" * 63, b"b" * 63, b"c" * 63, b"d" * 61)):
            with self.subTest(lengths=tuple(map(len, labels))):
                document = _report(_header() + _question(_name(labels)))
                self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")
        document = _report(_header() + _question(_name((b"a" * 63,) * 3 + (b"d" * 62,))))
        self.assertIn("expanded_name_exceeds_255_octets", _codes(document))
        document = _report(_header() + _question(bytes([64]) + b"x" * 64 + b"\x00"))
        self.assertIn("extended_label_encoding_unassessed", _codes(document))
        self.assertEqual(document["supported_checks_outcome"], "incomplete")

    def test_all_three_record_sections_and_duplicates_preserve_order(self):
        question = _question(b"\x00")
        one = _record(_pointer(12), 1, b"\x01\x02\x03\x04", ttl=0)
        two = _record(_pointer(12), 1, b"\x05\x06\x07\x08", ttl=2**32 - 1)
        document = _report(_header(a=3, ns=1, ar=1) + question + one + two + one + two + one)
        self.assertEqual([row["ttl"] for row in document["sections"]["answers"]], [0, 2**32 - 1, 0])
        self.assertEqual(document["sections"]["authority"][0]["ttl"], 2**32 - 1)
        self.assertEqual(document["sections"]["additional"][0]["ttl"], 0)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_known_rdata_scalars_and_binary_txt_are_not_interpreted(self):
        name = b"\x00"
        soa = name * 2 + struct.pack("!5I", 2**32 - 1, 0, 3, 4, 5)
        raw = _header(a=3) + _question(name)
        raw += _record(_pointer(12), 15, b"\xff\xff\x00")
        raw += _record(_pointer(12), 6, soa)
        raw += _record(_pointer(12), 16, b"\x00\x03\x00\xff.")
        document = _report(raw)
        records = document["sections"]["answers"]
        self.assertEqual(records[0]["rdata"]["preference"], 65535)
        self.assertEqual(records[1]["rdata"]["serial"], 2**32 - 1)
        self.assertEqual(records[2]["rdata"]["strings_base64"], ["", "AP8u"])
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_zero_string_txt_is_a_supported_structural_contradiction(self):
        document = _report(_header(a=1) + _question(b"\x00") + _record(_pointer(12), 16, b""))
        self.assertIn("txt_requires_one_string", _codes(document))
        self.assertEqual(document["supported_checks_outcome"], "contradictions")
        self.assertEqual(document["sections"]["answers"], [])

    def test_txt_character_string_must_fit_rdata(self):
        document = _report(_header(a=1) + _question(b"\x00") + _record(_pointer(12), 16, b"\x02a"))
        self.assertIn("txt_string_exceeds_rdata", _codes(document))

    def test_fixed_address_lengths_reject_short_and_long_complete_rdata(self):
        for kind, length in ((1, 4), (28, 16)):
            for size in (0, length - 1, length + 1):
                with self.subTest(kind=kind, size=size):
                    document = _report(
                        _header(a=1) + _question(b"\x00") + _record(_pointer(12), kind, bytes(size))
                    )
                    self.assertIn("rdata_size_mismatch", _codes(document))

    def test_rdata_names_must_consume_exact_field_grammar(self):
        for kind, data in (
            (2, b"\x00\x00"),
            (5, b"\x00x"),
            (12, b"\x00\x00"),
            (15, b"\x00"),
            (15, b"\x00\x01\x00x"),
            (6, b"\x00\x00" + bytes(19)),
            (6, b"\x00\x00" + bytes(21)),
        ):
            with self.subTest(kind=kind, data=data):
                document = _report(
                    _header(a=1) + _question(b"\x00") + _record(_pointer(12), kind, data)
                )
                self.assertEqual(document["supported_checks_outcome"], "contradictions")
                self.assertFalse(document["counted_sections_complete"])

    def test_name_cannot_read_past_rdata_into_following_record(self):
        for data in (b"\x01", b"\xc0", b"", b"\x01a"):
            with self.subTest(data=data):
                first = _record(_pointer(12), 5, data)
                second = _record(_pointer(12), 1, bytes(4))
                document = _report(_header(a=2) + _question(b"\x00") + first + second)
                self.assertIn("name_exceeds_rdata", _codes(document))
                self.assertEqual(document["sections"]["answers"], [])

    def test_unknown_rdata_remains_opaque_even_when_it_contains_pointer_octets(self):
        data = b"\xc0\x0c\x03www\x00"
        for kind, rr_class in ((65000, 1), (1, 3), (41, 1232), (46, 1)):
            with self.subTest(kind=kind, rr_class=rr_class):
                document = _report(
                    _header(a=1) + _question(b"\x00") + _record(_pointer(12), kind, data, rr_class)
                )
                record = document["sections"]["answers"][0]
                self.assertEqual(record["rdata"]["kind"], "opaque_unassessed")
                self.assertEqual(base64.b64decode(record["rdata"]["octets_base64"]), data)
                self.assertIn("record_type_or_class_unassessed", _codes(document))
                self.assertEqual(document["supported_checks_outcome"], "incomplete")
                self.assertTrue(document["counted_sections_complete"])

    def test_pointer_into_opaque_rdata_is_not_a_proven_name(self):
        question = _question(b"\x00")
        opaque_start = 12 + len(question) + 12
        opaque = _record(_pointer(12), 65000, _name((b"x",)))
        second = _record(_pointer(opaque_start), 1, bytes(4))
        document = _report(_header(a=2) + question + opaque + second)
        self.assertIn("compression_target_not_proven", _codes(document))
        self.assertEqual(len(document["sections"]["answers"]), 1)
        self.assertEqual(document["supported_checks_outcome"], "incomplete")

    def test_header_middle_self_forward_and_outside_pointers_never_pass(self):
        question = _question(_name((b"abc",)))
        second_start = 12 + len(question)
        for target, code in (
            (0, "compression_target_not_name_boundary"),
            (13, "compression_target_not_name_boundary"),
            (17, "compression_target_not_name_boundary"),
            (second_start, "compression_target_not_prior"),
            (second_start + 1, "compression_target_not_prior"),
            (16383, "compression_target_outside_message"),
        ):
            with self.subTest(target=target):
                document = _report(_header(q=2) + question + _question(_pointer(target)))
                self.assertIn(code, _codes(document))
                self.assertEqual(document["supported_checks_outcome"], "contradictions")

    def test_cycle_in_current_name_is_not_accepted(self):
        document = _report(_header() + _question(b"\x01x" + _pointer(12)))
        self.assertIn("compression_cycle", _codes(document))
        self.assertEqual(document["supported_checks_outcome"], "contradictions")

    def test_pointer_hop_limit_is_exact_and_excess_is_domain_rejection(self):
        raw = _header(q=33) + _question(b"\x00")
        previous = 12
        for _ in range(32):
            start = len(raw)
            raw += _question(_pointer(previous))
            previous = start
        document = _report(raw)
        self.assertEqual(len(document["sections"]["questions"][-1]["name"]["pointer_chain"]), 32)
        over = _header(q=34) + raw[12:] + _question(_pointer(previous))
        with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "pointer-hop"):
            dns.analyze_supplied_dns_message(_model(over))

    def test_every_strict_prefix_of_supported_fixture_is_incomplete(self):
        raw = base64.b64decode(component_fixture()["model"]["message_base64"])
        for length in range(1, len(raw)):
            with self.subTest(length=length):
                document = _report(raw[:length])
                self.assertEqual(document["supported_checks_outcome"], "incomplete")
                self.assertFalse(document["counted_sections_complete"])
                self.assertTrue(
                    any(note["kind"] == "truncated" for note in document["observations"])
                )
                self.assertLessEqual(document["confirmed_prefix_end"], length)

    def test_rdlength_beyond_supplied_message_is_truncated_not_complete(self):
        raw = _header(a=1) + _question(b"\x00")
        raw += _pointer(12) + struct.pack("!HHIH", 1, 1, 0, 4) + b"\x01\x02"
        document = _report(raw)
        self.assertIn("rdata_truncated", _codes(document))
        self.assertEqual(document["supported_checks_outcome"], "incomplete")

    def test_counts_do_not_invent_missing_or_suffix_records(self):
        raw = _header(q=2) + _question(b"\x00")
        missing = _report(raw)
        self.assertFalse(missing["counted_sections_complete"])
        self.assertEqual(len(missing["sections"]["questions"]), 1)
        suffix = _report(_header() + _question(b"\x00") + _header(q=0))
        self.assertIn("trailing_octets_unassessed", _codes(suffix))
        self.assertEqual(suffix["unconsumed_bytes"], 12)
        self.assertTrue(suffix["counted_sections_complete"])
        self.assertEqual(suffix["supported_checks_outcome"], "incomplete")

    def test_unknown_opcode_flags_and_question_semantics_withhold_completeness(self):
        cases = (
            (0x8980, 1, 1, "opcode_unassessed"),
            (0x8380, 1, 1, "truncation_flag_set"),
            (0x81A0, 1, 1, "extension_flags_unassessed"),
            (0x8190, 1, 1, "extension_flags_unassessed"),
            (0x8180, 255, 1, "question_type_or_class_unassessed"),
            (0x8180, 1, 255, "question_type_or_class_unassessed"),
        )
        for flags, kind, rr_class, code in cases:
            with self.subTest(flags=flags, kind=kind, rr_class=rr_class):
                document = _report(_header(flags=flags) + _question(b"\x00", kind, rr_class))
                self.assertIn(code, _codes(document))
                self.assertEqual(document["supported_checks_outcome"], "incomplete")
                self.assertEqual(document["header"]["raw_flags"], flags)

    def test_header_reserved_bit_is_a_supported_contradiction(self):
        document = _report(_header(flags=0x81C0) + _question(b"\x00"))
        self.assertIn("reserved_header_bit_set", _codes(document))
        self.assertEqual(document["supported_checks_outcome"], "contradictions")

    def test_declared_count_ceilings_reject_before_loops_and_hashes(self):
        for q, a, ns, ar in ((65, 0, 0, 0), (0, 257, 0, 0), (0, 128, 128, 1), (65535, 0, 0, 0)):
            with self.subTest(counts=(q, a, ns, ar)), patch.object(dns, "_sha") as hashed:
                with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "section counts"):
                    dns.analyze_supplied_dns_message(_model(_header(q, a, ns, ar)))
                hashed.assert_not_called()

    def test_maximum_question_and_record_counts_are_supported(self):
        questions = _question(b"\x00") * 64
        document = _report(
            _header(q=64, a=256) + questions + _record(_pointer(12), 1, bytes(4)) * 256
        )
        self.assertEqual(len(document["sections"]["questions"]), 64)
        self.assertEqual(len(document["sections"]["answers"]), 256)
        self.assertEqual(document["supported_checks_outcome"], "consistent_supplied_subset")

    def test_maximum_message_and_predecode_base64_limits(self):
        prefix = _header(q=0, a=1) + b"\x00"
        data = b"x" * (65535 - len(prefix) - 10)
        raw = prefix + struct.pack("!HHIH", 65000, 1, 0, len(data)) + data
        document = _report(raw)
        self.assertEqual(document["source"]["byte_count"], 65535)
        self.assertEqual(document["supported_checks_outcome"], "incomplete")
        oversized = _model(raw + b"x")
        with patch.object(dns.base64, "b64decode") as decoded, patch.object(dns, "_sha") as hashed:
            with self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message(oversized)
            decoded.assert_not_called()
            hashed.assert_not_called()

    def test_txt_string_budget_is_aggregate_and_checked_before_hash(self):
        raw = _header(a=2) + _question(b"\x00")
        raw += _record(_pointer(12), 16, b"\x00" * 512) * 2
        document = _report(raw)
        self.assertEqual(document["costs"]["txt_strings"], 1024)
        with patch.object(dns, "_sha") as hashed:
            with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "TXT strings"):
                dns.analyze_supplied_dns_message(
                    _model(
                        _header(a=1)
                        + _question(b"\x00")
                        + _record(_pointer(12), 16, b"\x00" * 1025)
                    )
                )
            hashed.assert_not_called()

    def test_resource_ceilings_deny_before_hash_and_output_dump(self):
        model = component_fixture()["model"]
        for bound, value in (
            ("MAX_WORK", 1),
            ("MAX_EXPANDED_NAME_BYTES", 2),
            ("MAX_PROVEN_BOUNDARIES", 1),
            ("MAX_NAMES", 0),
            ("MAX_DOCUMENT_BYTES", 16),
        ):
            with (
                self.subTest(bound=bound),
                patch.object(dns, bound, value),
                patch.object(dns, "_sha") as hashed,
                patch.object(dns.json, "dumps") as dumped,
            ):
                with self.assertRaises(dns.DnsMessageAnalysisError):
                    dns.analyze_supplied_dns_message(model)
                hashed.assert_not_called()
                dumped.assert_not_called()
        # Transparent private lowering proves final whole-document charging, not a
        # claimed bypass of production limits or a caller-configurable product seam.
        baseline = dns.analyze_supplied_dns_message(model).to_dict()
        fragments = baseline["costs"]["retained_fragment_bytes"]
        with (
            patch.object(dns, "MAX_DOCUMENT_BYTES", fragments + 1),
            patch.object(dns, "_sha") as hashed,
            patch.object(dns.json, "dumps") as dumped,
        ):
            with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "aggregate byte"):
                dns.analyze_supplied_dns_message(model)
            hashed.assert_not_called()
            dumped.assert_not_called()

    def test_expansion_denial_precedes_label_base64_and_retention(self):
        raw = _header() + _question(_name((b"abc",)))
        with (
            patch.object(dns, "MAX_EXPANDED_NAME_BYTES", 3),
            patch.object(dns._Budget, "encoded") as encoded,
        ):
            with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "expansion"):
                dns.analyze_supplied_dns_message(_model(raw))
            encoded.assert_not_called()

    def test_native_schema_and_family_aliases_are_rejected(self):
        class AliasedText(str):
            pass

        class AliasedMap(dict):
            pass

        for value in (True, 1.0, False, 0, 2):
            model = component_fixture()["model"]
            model["schema_version"] = value
            with self.subTest(value=value), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message(model)
        for model in (
            AliasedMap(component_fixture()["model"]),
            {"schema_version": 1, "message_base64": AliasedText("AA==")},
            {1: 1, "message_base64": "AA=="},
            {"schema_version": 1, "message_base64": "AA==", "endpoint": "not-accepted"},
        ):
            with self.subTest(model=model), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message(model)

    def test_duplicate_keys_float_huge_and_malformed_integer_denial_before_decoder(self):
        for text in (
            '{"schema_version":1,"schema_version":2,"message_base64":"AA=="}',
            '{"schema_version":1,"message_base64":"AA==","x":{"a":1,"a":2}}',
        ):
            with self.subTest(text=text), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message_bytes(model_json=text)
        for token in (
            "1.0",
            "1e0",
            "9223372036854775808",
            "-9223372036854775809",
            "--1",
            "9" * 1000,
        ):
            text = '{"schema_version":' + token + ',"message_base64":"AA=="}'
            with self.subTest(token=token[:30]), patch.object(dns.json, "loads") as decoded:
                with self.assertRaises(dns.DnsMessageAnalysisError):
                    dns.analyze_supplied_dns_message_bytes(model_json=text)
                decoded.assert_not_called()
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message_bytes(
                    model_json='{"schema_version":' + token + "}"
                )

    def test_raw_node_depth_and_byte_budgets_precede_decoder(self):
        for text in (
            "[" * 17 + "0" + "]" * 17,
            "[" * 17 + '"x"' + "]" * 17,
            "[" + ",".join("0" for _ in range(dns.MAX_NODES)) + "]",
            " " * (dns.MAX_MODEL_BYTES + 1),
        ):
            with self.subTest(length=len(text)), patch.object(dns.json, "loads") as decoded:
                with self.assertRaises(dns.DnsMessageAnalysisError):
                    dns.analyze_supplied_dns_message_bytes(model_json=text)
                decoded.assert_not_called()
        self.assertEqual(
            dns._json("[" * 16 + "0" + "]" * 16), [dns._json("[" * 15 + "0" + "]" * 15)]
        )

    def test_native_cycles_shared_subtrees_escapes_and_final_charge_are_bounded(self):
        cycle = []
        cycle.append(cycle)
        for value in (
            cycle,
            ["x"] * (dns.MAX_NODES + 1),
            {"x": "\\" * (dns._MAX_BASE64 + 1)},
            {"x": "\ud800"},
            {"x": 2**63},
        ):
            with self.subTest(kind=type(value)), self.assertRaises(dns.DnsMessageAnalysisError):
                dns._capture(value)
        shared = ["x" * 500]
        with self.assertRaises(dns.DnsMessageAnalysisError):
            dns._capture([shared] * 4, maximum_bytes=1000)
        for value in (None, False, True, "\\"):
            with self.subTest(value=value), self.assertRaises(dns.DnsMessageAnalysisError):
                dns._capture(value, maximum_bytes=1)
        self.assertEqual(dns._capture(1, maximum_bytes=1), (1, 1, 1))
        with self.assertRaises(dns.DnsMessageAnalysisError):
            dns._capture(1, maximum_bytes=0)

    def test_empty_noncanonical_and_invalid_base64_are_domain_rejections(self):
        for text in ("", "AR==", "AA", "AA==\n", "_w==", "!bad", "\u00e9", "\\ud800"):
            with self.subTest(text=text), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message({"schema_version": 1, "message_base64": text})
        for raw in (b"\xff", b"", "", "{", b'"\\ud800"'):
            with self.subTest(raw=raw), self.assertRaises(dns.DnsMessageAnalysisError):
                dns.analyze_supplied_dns_message_bytes(model_json=raw)

    def test_cohashed_false_parse_and_claims_cannot_pass_embedded_source_replay(self):
        baseline = dns.analyze_supplied_dns_message(component_fixture()["model"]).to_dict()
        mutations = (
            lambda d: d["header"].__setitem__("transaction_id", 1),
            lambda d: d["sections"]["answers"][0].__setitem__("ttl", 10),
            lambda d: d["sections"]["questions"][0]["name"]["labels_base64"].__setitem__(
                0, "Zm9yZWlnbg=="
            ),
            lambda d: d.__setitem__("confirmed_prefix_end", 12),
            lambda d: d.__setitem__("supported_checks_outcome", "incomplete"),
            lambda d: d.__setitem__("message_authenticity_verified", True),
            lambda d: d["effects"].__setitem__("execution", "approved"),
            lambda d: d["source"].__setitem__("message_sha256", "sha256:" + "a" * 64),
            lambda d: d["costs"].__setitem__("parser_work", 1),
        )
        for mutate in mutations:
            document = copy.deepcopy(baseline)
            mutate(document)
            _readdress(document)
            for parse in (
                dns.DnsMessageAnalysis.from_dict,
                lambda value: dns.DnsMessageAnalysis.from_json(json.dumps(value)),
            ):
                with (
                    self.subTest(mutate=mutate, parse=parse),
                    self.assertRaises(dns.DnsMessageAnalysisError),
                ):
                    parse(document)

    def test_boolean_integer_metadata_aliases_deny_before_replay_hashes(self):
        baseline = dns.analyze_supplied_dns_message(component_fixture()["model"]).to_dict()
        for family, key, value in (
            ("header", "transaction_id", True),
            ("header", "qr", 1),
            ("source", "byte_count", True),
            ("costs", "names", True),
        ):
            document = copy.deepcopy(baseline)
            document[family][key] = value
            _readdress(document)
            with self.subTest(family=family, key=key), patch.object(dns, "_sha") as hashed:
                with self.assertRaises(dns.DnsMessageAnalysisError):
                    dns.DnsMessageAnalysis.from_dict(document)
                hashed.assert_not_called()

    def test_valid_alternate_source_is_not_original_source_verification(self):
        original = component_fixture()["model"]
        raw = bytearray(base64.b64decode(original["message_base64"]))
        raw[0] ^= 1
        alternate = _model(bytes(raw))
        report = dns.analyze_supplied_dns_message(alternate)
        self.assertEqual(
            dns.DnsMessageAnalysis.from_dict(report.to_dict()).to_json(), report.to_json()
        )
        with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "original source"):
            dns.verify_supplied_dns_message_analysis(report, model=original)

    def test_owned_outputs_missing_slots_and_late_wrapper_mutation(self):
        model = component_fixture()["model"]
        report = dns.analyze_supplied_dns_message(model)
        original = report.to_json()
        model["message_base64"] = "AA=="
        detached = report.to_dict()
        detached["sections"]["answers"].clear()
        self.assertEqual(report.to_json(), original)
        incomplete = object.__new__(dns.DnsMessageAnalysis)
        with self.assertRaisesRegex(dns.DnsMessageAnalysisError, "slots"):
            incomplete.to_dict()
        corrupted = report.to_dict()
        corrupted["header"]["question_count"] += 1
        object.__setattr__(report, "document_json", json.dumps(_readdress(corrupted)))
        for read in (report.to_dict, report.to_json):
            with self.assertRaises(dns.DnsMessageAnalysisError):
                read()

    def test_exact_report_family_nonpromotion_and_no_network_calls(self):
        with patch.object(socket, "socket", side_effect=AssertionError("no socket")):
            report = dns.analyze_supplied_dns_message(component_fixture()["model"])
            document = report.to_dict()
            self.assertTrue(document["offline_only"])
            for key in (
                "comprehensive_dns_validity_verified",
                "message_authenticity_verified",
                "vulnerability_proven",
                "live_use_approved",
                "qualification_claimed",
            ):
                self.assertIs(document[key], False)
            self.assertEqual(set(document["effects"].values()), {"none"})
            with self.assertRaises(dns.DnsMessageAnalysisError):
                dns.verify_supplied_dns_message_analysis(
                    document, model=component_fixture()["model"]
                )


if __name__ == "__main__":
    unittest.main()

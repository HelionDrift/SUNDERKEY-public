"""Independent supplied IPv4 byte, interval, ownership and resource controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest import mock

from sunderkey import offline_ipv4_fragment_analysis as ipv4


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def packet(
    payload=b"abcdefgh",
    *,
    offset=0,
    more=False,
    df=False,
    reserved=False,
    ident=0x1234,
    protocol=17,
    ttl=64,
    ds=0,
    options=b"",
    source=b"\xc0\x00\x02\x01",
    destination=b"\xc6\x33\x64\x02",
):
    """A separately written network-order encoder, not a production parser helper."""
    assert len(options) % 4 == 0 and len(options) <= 40
    length = 20 + len(options) + len(payload)
    flags = (int(reserved) << 15) + (int(df) << 14) + (int(more) << 13) + offset
    header = (
        bytes((0x45 + len(options) // 4, ds))
        + length.to_bytes(2, "big")
        + ident.to_bytes(2, "big")
        + flags.to_bytes(2, "big")
        + bytes((ttl, protocol, 0, 0))
        + source
        + destination
        + options
    )
    # Modulo 65535 arithmetic is independent of the parser's repeated carry fold.
    words = [256 * header[i] + header[i + 1] for i in range(0, len(header), 2)]
    checksum = (65_535 - sum(words) % 65_535) % 65_535
    return header[:10] + checksum.to_bytes(2, "big") + header[12:] + payload


def model(*groups, source_id="independent-ipv4"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "fragment_sets": [
            {
                "set_id": f"set-{index}",
                "packets": [
                    {
                        "packet_id": f"packet-{index}-{number}",
                        "packet_base64": base64.b64encode(raw).decode("ascii"),
                    }
                    for number, raw in enumerate(group)
                ],
            }
            for index, group in enumerate(groups)
        ],
    }


def changed_octets(document, position, value):
    owned = copy.deepcopy(document)
    row = owned["fragment_sets"][0]["packets"][0]
    raw = bytearray(base64.b64decode(row["packet_base64"]))
    raw[position] = value
    row["packet_base64"] = base64.b64encode(raw).decode("ascii")
    return owned


def readdress(document):
    owned = copy.deepcopy(document)
    body = {
        key: value for key, value in owned.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        b"sunderkey.offline-ipv4-fragment-analysis.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    owned["analysis_sha256"] = "sha256:" + digest
    owned["analysis_id"] = "IPFA-" + digest[:32].upper()
    return owned


def interval_oracle(specifications):
    """A finite octet-to-value-set oracle, independent of interval union code."""
    occupied = {}
    ends = set()
    for start, payload, more in specifications:
        for position, value in enumerate(payload, start):
            occupied.setdefault(position, set()).add(value)
        if not more:
            ends.add(start + len(payload))
    endpoint = next(iter(ends)) if len(ends) == 1 else None
    gaps = None
    if endpoint is not None:
        absent = [i for i in range(endpoint) if i not in occupied]
        gaps = []
        for position in absent:
            if gaps and gaps[-1][1] == position:
                gaps[-1][1] += 1
            else:
                gaps.append([position, position + 1])
    return len(occupied), sorted(ends), endpoint, gaps, any(len(v) > 1 for v in occupied.values())


class IPv4FragmentAnalysisTests(unittest.TestCase):
    def analyze(self, source):
        return ipv4.analyze_supplied_ipv4_fragments(source).to_dict()

    def no_hash(self, operation, regex=None):
        with mock.patch.object(
            ipv4.hashlib, "sha256", side_effect=AssertionError("SHA reached")
        ) as digest:
            if regex is None:
                with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
                    operation()
            else:
                with self.assertRaisesRegex(ipv4.IPv4FragmentAnalysisError, regex):
                    operation()
            digest.assert_not_called()

    def before_decoder(self, content, *, report=False):
        with mock.patch.object(
            ipv4.json, "loads", side_effect=AssertionError("Decoder reached")
        ) as decoder:
            self.no_hash(
                lambda: (
                    ipv4.IPv4FragmentAnalysis.from_json(content)
                    if report
                    else ipv4.analyze_supplied_ipv4_fragments_bytes(
                        model_bytes=content.encode("ascii")
                    )
                )
            )
            decoder.assert_not_called()

    def test_literal_fixture_is_fresh_and_independently_checks_out(self):
        fixture = ipv4.component_fixture()
        self.assertEqual(set(fixture), {"schema_version", "source_id", "fragment_sets"})
        rows = fixture["fragment_sets"][0]["packets"]
        first, last = (base64.b64decode(row["packet_base64"]) for row in rows)
        self.assertEqual(first, packet(b"abcdefghijklmnop", more=True))
        self.assertEqual(last, packet(b"qrstuvwx", offset=2))
        self.assertEqual(first[:20].hex(), "450000241234200040115c5ec0000201c6336402")
        self.assertEqual(last[:20].hex(), "4500001c1234000240117c64c0000201c6336402")
        report = self.analyze(fixture)
        self.assertEqual(report["analysis_id"], "IPFA-64520398ED7C645DF9A533D3EA01F3EB")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:64520398ed7c645df9a533d3ea01f3eb66af82e8a86bec5a2e6479204bb29275",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:f330cc090b6a5d91fcdf6b78f176d13f783aade52278415166856cc53a97f4d7",
        )
        self.assertEqual(
            [row["packet_sha256"] for row in report["packets"]],
            [
                "sha256:59804cfb9d46e8a29c2841509c011fa740550a306cb90a854020f0db4a96173f",
                "sha256:18c2800776139e2740497c9cb92e25f856bcaea199d81a3fa7edf339713ac193",
            ],
        )
        self.assertEqual(report["contradictions"], [])
        self.assertEqual(report["unassessed_reasons"], [])
        group = report["fragment_sets"][0]
        self.assertEqual(
            group["conditional_single_tuple_conclusion"], "consistent_supplied_arithmetic"
        )
        self.assertEqual(group["merged_supplied_intervals"], [[0, 24]])
        self.assertEqual(group["literal_unique_mf_zero_endpoint"], 24)
        self.assertEqual(group["overlap_relation"], "no_overlap")
        self.assertEqual(report["accounting"]["decoded_packet_octets"], 64)
        self.assertTrue(all(row["header_checksum_equation_holds"] for row in report["packets"]))
        self.assertTrue(all(value is False for value in report["claims"].values()))
        self.assertEqual(set(report["effects"].values()), {"none"})
        self.assertEqual(
            report["blueprint_sha256"],
            "sha256:566fbac84eb4d1b27b0c94dfd8cc04d5da90239b3b49645784ef54646c9bcdb6",
        )
        fixture["fragment_sets"].clear()
        self.assertEqual(len(ipv4.component_fixture()["fragment_sets"]), 1)

    def test_all_public_forms_roundtrip_exact_complete_report(self):
        source = ipv4.component_fixture()
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        text, document = report.to_json(), report.to_dict()
        forms = (
            ipv4.analyze_supplied_ipv4_fragments_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            ipv4.IPv4FragmentAnalysis(text),
            ipv4.IPv4FragmentAnalysis.from_dict(document),
            ipv4.IPv4FragmentAnalysis.from_json(text),
            ipv4.verify_supplied_ipv4_fragment_analysis(report, model=source),
        )
        for candidate in forms:
            self.assertEqual(candidate.to_json(), text)
        digest = hashlib.sha256(
            b"sunderkey.offline-ipv4-fragment-model.v1\n" + canonical(source).encode("ascii")
        ).hexdigest()
        self.assertEqual(document["source_model_sha256"], "sha256:" + digest)
        body = {
            key: value
            for key, value in document.items()
            if key not in {"analysis_id", "analysis_sha256"}
        }
        analysis_digest = hashlib.sha256(
            b"sunderkey.offline-ipv4-fragment-analysis.v1\n" + canonical(body).encode("ascii")
        ).hexdigest()
        self.assertEqual(document["analysis_sha256"], "sha256:" + analysis_digest)
        self.assertEqual(document["analysis_id"], "IPFA-" + analysis_digest[:32].upper())
        for row, supplied in zip(
            document["packets"], source["fragment_sets"][0]["packets"], strict=True
        ):
            self.assertEqual(
                row["packet_sha256"],
                "sha256:" + hashlib.sha256(base64.b64decode(supplied["packet_base64"])).hexdigest(),
            )

    def test_every_supported_ihl_checksum_matches_independent_arithmetic(self):
        for words in range(5, 16):
            with self.subTest(words=words):
                raw = packet(options=b"\x01" * (4 * words - 20))
                report = self.analyze(model([raw]))
                row = report["packets"][0]
                self.assertEqual(row["ihl_words"], words)
                self.assertEqual(row["header_length"], 4 * words)
                self.assertEqual(row["header_folded_sum"], 65_535)
                self.assertTrue(row["checksum_spelling_matches_canonical"])
                self.assertEqual(report["contradictions"], [])

    def test_checksum_negative_zero_equivalent_spelling_is_not_rejected(self):
        template = packet(ident=0)
        header = template[:20]
        other = sum(256 * header[i] + header[i + 1] for i in range(0, 20, 2) if i not in (4, 10))
        ident = (65_535 - other % 65_535) % 65_535
        zero = packet(ident=ident)
        self.assertEqual(zero[10:12], b"\0\0")
        negative_zero = zero[:10] + b"\xff\xff" + zero[12:]
        for wire, spelling in ((zero, True), (negative_zero, False)):
            with self.subTest(checksum=wire[10:12].hex()):
                report = self.analyze(model([wire]))
                row = report["packets"][0]
                self.assertTrue(row["header_checksum_equation_holds"])
                self.assertEqual(row["canonical_zeroed_field_checksum"], 0)
                self.assertEqual(row["checksum_spelling_matches_canonical"], spelling)
                self.assertEqual(report["contradictions"], [])

    def test_bad_checksum_is_retained_without_silent_byte_repair(self):
        source = model([packet()])
        wire = base64.b64decode(source["fragment_sets"][0]["packets"][0]["packet_base64"])
        source = changed_octets(source, 10, wire[10] ^ 1)
        report = self.analyze(source)
        self.assertEqual(report["source_model"], source)
        self.assertFalse(report["packets"][0]["header_checksum_equation_holds"])
        self.assertIn(
            "header_checksum_equation_failed", {r["code"] for r in report["contradictions"]}
        )
        self.assertEqual(report["fragment_sets"][0]["union_octets"], 8)

    def test_all_flag_combinations_preserve_received_df_and_reserved_observation(self):
        for reserved, df, more, offset in itertools.product(
            (False, True), (False, True), (False, True), (0, 1)
        ):
            with self.subTest(reserved=reserved, df=df, more=more, offset=offset):
                report = self.analyze(
                    model([packet(reserved=reserved, df=df, more=more, offset=offset)])
                )
                row = report["packets"][0]
                self.assertEqual(row["atomic_fields"], df and not more and offset == 0)
                self.assertEqual(row["dont_fragment"], df)
                codes = {r["code"] for r in report["contradictions"]}
                self.assertEqual("reserved_header_flag_nonzero" in codes, reserved)
                self.assertFalse(any("dont_fragment" in code or "df_" in code for code in codes))

    def test_ds_ttl_and_protocol_octets_are_not_legacy_tos_or_transport_validation(self):
        for ds, ttl, protocol in itertools.product((0, 3, 255), (0, 64, 255), (0, 6, 17, 255)):
            report = self.analyze(model([packet(ds=ds, ttl=ttl, protocol=protocol)]))
            row = report["packets"][0]
            self.assertEqual(
                (row["ds_octet"], row["ttl_octet"], row["protocol_octet"]), (ds, ttl, protocol)
            )
            self.assertEqual(report["contradictions"], [])

    def test_nonterminal_alignment_is_independent_of_checksum(self):
        for length in range(1, 17):
            report = self.analyze(model([packet(b"a" * length, more=True)]))
            self.assertTrue(report["packets"][0]["header_checksum_equation_holds"])
            codes = {r["code"] for r in report["contradictions"]}
            self.assertEqual(
                "nonterminal_payload_not_eight_octet_multiple" in codes, bool(length % 8)
            )

    def test_eol_nop_and_zero_padding_are_supported(self):
        for options in (b"\0" * 4, b"\x01" * 4, b"\x01\0\0\0", b"\x01" * 7 + b"\0"):
            report = self.analyze(model([packet(options=options)]))
            self.assertEqual(report["contradictions"], [])
            self.assertEqual(report["unassessed_reasons"], [])

    def test_nonzero_eol_padding_is_preserved_as_a_contradiction(self):
        report = self.analyze(model([packet(options=b"\0\0\x01\0")]))
        self.assertIn(
            "nonzero_after_end_option_padding", {r["code"] for r in report["contradictions"]}
        )
        self.assertEqual(len(report["packets"][0]["options"]), 1)

    def test_unknown_tlv_keeps_exact_framing_copy_flag_and_uncertainty(self):
        for code in (2, 130, 222, 254):
            source = model([packet(options=bytes((code, 4, 0xAA, 0xBB)))])
            report = self.analyze(source)
            option = report["packets"][0]["options"][0]
            self.assertEqual(option["bytes_hex"], bytes((code, 4, 0xAA, 0xBB)).hex())
            self.assertEqual(option["copied_bit"], bool(code & 128))
            self.assertEqual(option["framing"], "opaque_tlv")
            self.assertEqual(report["contradictions"], [])
            self.assertIn(
                "opaque_option_semantics_unassessed",
                {r["code"] for r in report["unassessed_reasons"]},
            )

    def test_malformed_option_extents_stop_without_guessing_option_data(self):
        for options in (b"\x02\0\0\0", b"\x02\x01\0\0", b"\x02\x05\0\0", b"\x01\x01\x01\x02"):
            report = self.analyze(model([packet(options=options)]))
            self.assertTrue(report["contradictions"])
            self.assertTrue(report["unassessed_reasons"])
            self.assertEqual(report["packets"][0]["payload_length"], 8)
            self.assertTrue(report["packets"][0]["header_checksum_equation_holds"])

    def test_fragment_ihl_options_and_ttl_need_not_equal(self):
        first = packet(more=True, ttl=64, options=b"\0" * 4)
        last = packet(offset=1, ttl=2, options=b"\x01" * 8)
        report = self.analyze(model([first, last]))
        self.assertEqual(report["contradictions"], [])
        self.assertEqual(report["unassessed_reasons"], [])
        self.assertEqual(
            report["fragment_sets"][0]["conditional_single_tuple_conclusion"],
            "consistent_supplied_arithmetic",
        )

    def test_each_changed_tuple_field_withholds_conditional_interpretation(self):
        for change in (
            {"ident": 1},
            {"protocol": 6},
            {"source": b"\xc0\0\2\2"},
            {"destination": b"\xc6\x33\x64\3"},
        ):
            report = self.analyze(model([packet(more=True), packet(offset=1, **change)]))
            group = report["fragment_sets"][0]
            self.assertEqual(group["tuple_relation"], "different_wire_tuples")
            self.assertFalse(group["conditional_nonatomic_tuple_assessed"])
            self.assertEqual(group["merged_supplied_intervals"], [[0, 16]])
            self.assertEqual(group["literal_gaps_to_unique_endpoint"], [])
            self.assertFalse(
                any(r["code"].startswith("conditional_") for r in report["contradictions"])
            )

    def test_atomic_ids_never_bind_groups_or_imply_network_duplicates(self):
        for ident in (0, 1, 0x1234):
            first = packet(b"aaaaaaaa", df=True, ident=ident)
            second = packet(b"bbbbbbbb", df=True, ident=ident)
            report = self.analyze(model([first, second]))
            group = report["fragment_sets"][0]
            self.assertTrue(group["atomic_packet_present"])
            self.assertFalse(group["conditional_nonatomic_tuple_assessed"])
            self.assertEqual(group["overlap_relation"], "conflicting_octets")
            self.assertEqual(report["contradictions"], [])
            self.assertFalse(report["claims"]["identification_uniqueness_proven"])

    def test_independent_exhaustive_small_interval_and_octet_set_oracle(self):
        alternatives = tuple(itertools.product((0, 8, 16), (8, 16), (False, True)))
        for a, b in itertools.product(alternatives, repeat=2):
            first = (a[0], b"a" * a[1], a[2])
            second = (b[0], b"b" * b[1], b[2])
            supplied = [
                packet(payload, offset=start // 8, more=more)
                for start, payload, more in (first, second)
            ]
            group = self.analyze(model(supplied))["fragment_sets"][0]
            count, endpoints, endpoint, gaps, conflict = interval_oracle((first, second))
            self.assertEqual(group["union_octets"], count)
            self.assertEqual(group["literal_mf_zero_endpoints"], endpoints)
            self.assertEqual(group["literal_unique_mf_zero_endpoint"], endpoint)
            self.assertEqual(group["literal_gaps_to_unique_endpoint"], gaps)
            self.assertEqual(group["overlap_relation"] == "conflicting_octets", conflict)

    def test_nested_equal_and_conflicting_overlaps_have_exact_witnesses(self):
        base = b"abcdefghijklmnopqrstuvwx"
        for payload, expected in (
            (base[8:16], None),
            (b"X" + base[9:16], 8),
            (base[8:15] + b"X", 15),
        ):
            report = self.analyze(model([packet(base, more=True), packet(payload, offset=1)]))
            row = report["fragment_sets"][0]["pairs"][0]
            self.assertEqual(row["overlap_extent"], [8, 16])
            self.assertEqual(row["first_different_octet_offset"], expected)
            self.assertEqual(row["overlap_octets_equal"], expected is None)

    def test_supplied_octet_duplicates_are_distinct_from_equal_payload_extents(self):
        first = packet()
        for second, duplicate in ((first, True), (packet(ttl=1), False)):
            row = self.analyze(model([first, second]))["fragment_sets"][0]["pairs"][0]
            self.assertTrue(row["equal_extents"])
            self.assertTrue(row["overlap_octets_equal"])
            self.assertEqual(row["exact_supplied_packet_octets_equal"], duplicate)

    def test_terminal_endpoint_disagreement_is_only_conditional(self):
        first, second = packet(), packet(b"abcdefghijklmnop")
        report = self.analyze(model([first, second]))
        self.assertIn(
            "conditional_terminal_extents_disagree", {r["code"] for r in report["contradictions"]}
        )
        mixed = self.analyze(model([first, packet(b"abcdefghijklmnop", ident=3)]))
        self.assertEqual(mixed["fragment_sets"][0]["literal_mf_zero_endpoints"], [8, 16])
        self.assertFalse(any(r["code"].startswith("conditional_") for r in mixed["contradictions"]))

    def test_missing_first_last_and_gaps_are_incomplete_evidence(self):
        cases = (
            ([packet(offset=1)], "initial_fragment_not_supplied"),
            ([packet(more=True)], "terminal_fragment_not_supplied"),
            ([packet(more=True), packet(offset=2)], "supplied_octet_coverage_has_gaps"),
        )
        for packets, code in cases:
            report = self.analyze(model(packets))
            self.assertIn(code, {r["code"] for r in report["unassessed_reasons"]})
            self.assertEqual(report["contradictions"], [])

    def test_nonterminal_at_or_past_unique_last_extent_is_conditionally_incompatible(self):
        report = self.analyze(
            model([packet(more=True), packet(offset=1, more=True), packet(offset=1)])
        )
        codes = {r["code"] for r in report["contradictions"]}
        self.assertIn("conditional_nonterminal_reaches_terminal_extent", codes)
        report = self.analyze(model([packet(b"a" * 24, more=True), packet(offset=1)]))
        self.assertIn(
            "conditional_payload_past_terminal_extent",
            {r["code"] for r in report["contradictions"]},
        )

    def test_ipv4_original_extent_capacity_is_not_an_eager_reassembly_buffer(self):
        report = self.analyze(model([packet(offset=8191)]))
        self.assertEqual(report["packets"][0]["fragment_end"], 65_536)
        self.assertIn(
            "conditional_payload_extent_exceeds_ipv4_capacity",
            {r["code"] for r in report["contradictions"]},
        )
        first = packet(more=True, options=b"\0" * 40)
        last = packet(offset=8188)
        report = self.analyze(model([first, last]))
        self.assertIn(
            "conditional_initial_header_plus_payload_too_large",
            {r["code"] for r in report["contradictions"]},
        )
        self.assertEqual(len(report["fragment_sets"][0]["merged_supplied_intervals"]), 2)

    def test_known_contradictions_survive_unknown_options_or_withheld_group(self):
        raw = bytearray(packet(options=b"\x82\x04\0\0", reserved=True))
        raw[10] ^= 1
        report = self.analyze(model([bytes(raw), packet(ident=2)]))
        codes = {r["code"] for r in report["contradictions"]}
        self.assertIn("header_checksum_equation_failed", codes)
        self.assertIn("reserved_header_flag_nonzero", codes)
        self.assertTrue(report["unassessed_reasons"])
        self.assertFalse(report["fragment_sets"][0]["conditional_nonatomic_tuple_assessed"])

    def test_unsupported_version_ihl_total_length_truncation_and_empty_payload_refuse(self):
        valid = packet()
        bad = [valid[:n] for n in range(20)]
        bad += [
            b"\x65" + valid[1:],
            b"\x44" + valid[1:],
            b"\x4f" + valid[1:],
            valid + b"x",
            valid[:-1],
        ]
        bad += [valid[:2] + b"\0\x13" + valid[4:], valid[:2] + b"\0\x14" + valid[4:20]]
        for raw in bad:
            self.no_hash(lambda raw=raw: ipv4.analyze_supplied_ipv4_fragments(model([raw])))

    def test_empty_or_noncanonical_base64_refuses_before_hash(self):
        source = model([packet()])
        for text in ("", "YQ", "YR==", "YQ===", "YQ==\n", "____", " YQ=="):
            bad = copy.deepcopy(source)
            bad["fragment_sets"][0]["packets"][0]["packet_base64"] = text
            self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))

    def test_closed_rows_and_unique_source_ids_are_enforced(self):
        source = model([packet()], [packet(ident=2)])
        alternatives = []
        for key in ("extra", "semantics_profile"):
            bad = copy.deepcopy(source)
            bad[key] = None
            alternatives.append(bad)
        for level in ("set", "packet"):
            bad = copy.deepcopy(source)
            target = (
                bad["fragment_sets"][0] if level == "set" else bad["fragment_sets"][0]["packets"][0]
            )
            target["extra"] = None
            alternatives.append(bad)
        bad = copy.deepcopy(source)
        bad["fragment_sets"][1]["set_id"] = bad["fragment_sets"][0]["set_id"]
        alternatives.append(bad)
        bad = copy.deepcopy(source)
        bad["fragment_sets"][1]["packets"][0]["packet_id"] = bad["fragment_sets"][0]["packets"][0][
            "packet_id"
        ]
        alternatives.append(bad)
        for bad in alternatives:
            self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))

    def test_malformed_native_shapes_and_scalar_aliases_use_leaf_error(self):
        source = model([packet()])
        for key, values in (
            ("schema_version", (True, 1.0, "1", None)),
            ("source_id", ([], {}, 1, True, "", "x" * 129, "not a label")),
            ("fragment_sets", (None, (), {}, [], True)),
        ):
            for value in values:
                bad = copy.deepcopy(source)
                bad[key] = value
                self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))
        for key in ("set_id", "packets"):
            for value in (None, True, {}, (), 1):
                bad = copy.deepcopy(source)
                bad["fragment_sets"][0][key] = value
                self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))
        for key in ("packet_id", "packet_base64"):
            for value in (None, True, [], {}, 1):
                bad = copy.deepcopy(source)
                bad["fragment_sets"][0]["packets"][0][key] = value
                self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))

    def test_native_subclasses_hooks_and_cycles_refuse_before_digest(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Object(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        class Array(list):
            def __iter__(self):
                raise AssertionError("Subclass hook reached")

        class Bytes(bytes):
            pass

        source = model([packet()])
        for bad in (Object(source), Array([source]), Text("source"), object()):
            self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))
        for key, value in (
            ("source_id", Text("source")),
            ("schema_version", Integer(1)),
            ("fragment_sets", Array(source["fragment_sets"])),
        ):
            bad = copy.deepcopy(source)
            bad[key] = value
            self.no_hash(lambda bad=bad: ipv4.analyze_supplied_ipv4_fragments(bad))
        bad = copy.deepcopy(source)
        bad["extra"] = bad
        self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(bad))
        self.no_hash(
            lambda: ipv4.analyze_supplied_ipv4_fragments_bytes(
                model_bytes=Bytes(canonical(source).encode("ascii"))
            )
        )

    def test_incomplete_or_foreign_report_wrappers_are_not_verified(self):
        class Foreign(ipv4.IPv4FragmentAnalysis):
            pass

        report = ipv4.analyze_supplied_ipv4_fragments(ipv4.component_fixture())
        document = report.to_dict()
        incomplete = object.__new__(ipv4.IPv4FragmentAnalysis)
        self.no_hash(incomplete.to_dict)
        self.no_hash(incomplete.to_json)
        self.no_hash(
            lambda: ipv4.verify_supplied_ipv4_fragment_analysis(
                incomplete, model=ipv4.component_fixture()
            )
        )
        self.no_hash(lambda: Foreign(report.document_json))
        self.no_hash(lambda: Foreign.from_dict(document))
        self.no_hash(lambda: Foreign.from_json(report.document_json))

    def test_duplicate_raw_keys_and_wrong_native_bytes_are_rejected(self):
        source = ipv4.component_fixture()
        text = canonical(source)
        duplicated = text.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        self.no_hash(
            lambda: ipv4.analyze_supplied_ipv4_fragments_bytes(
                model_bytes=duplicated.encode("ascii")
            )
        )
        for value in (
            text,
            bytearray(text.encode("ascii")),
            memoryview(text.encode("ascii")),
            None,
        ):
            self.no_hash(
                lambda value=value: ipv4.analyze_supplied_ipv4_fragments_bytes(model_bytes=value)
            )

    def test_raw_integer_grammar_and_signed64_ceilings_precede_decoder(self):
        for token in (
            "--1",
            "---1",
            "01",
            "-01",
            "+1",
            "1.0",
            "1e1",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "1" * 100,
        ):
            self.before_decoder('{"schema_version":' + token + "}")
        for token in ("-0", "-1", "9223372036854775807", "-9223372036854775808"):
            self.no_hash(
                lambda token=token: ipv4.analyze_supplied_ipv4_fragments_bytes(
                    model_bytes=('{"schema_version":' + token + "}").encode("ascii")
                )
            )

    def test_raw_escaped_strings_scalar_depth_and_nodes_precede_decoder(self):
        for text in (
            '"\\u0100"',
            '"\\ud800"',
            '"\\x20"',
            '"\\u00zz"',
            '"bad\ntext"',
            "[" * 16 + "0" + "]" * 16,
        ):
            self.before_decoder(text)
        self.before_decoder('"' + "a" * (ipv4.MAX_STRING_BYTES + 1) + '"')
        self.before_decoder("[" + ",".join("null" for _ in range(ipv4.MAX_MODEL_NODES)) + "]")

    def test_default_raw_model_report_byte_and_report_node_caps_are_real(self):
        self.before_decoder(" " * (ipv4.MAX_MODEL_BYTES + 1))
        self.before_decoder(" " * (ipv4.MAX_REPORT_BYTES + 1), report=True)
        content = "[" + ",".join("null" for _ in range(ipv4.MAX_REPORT_NODES)) + "]"
        self.assertLess(len(content), ipv4.MAX_REPORT_BYTES)
        self.before_decoder(content, report=True)

    def test_actual_packet_and_aggregate_bytes_are_predecoded(self):
        largest = packet(b"a" * 65_515)
        report = self.analyze(model([largest]))
        self.assertEqual(report["packets"][0]["byte_length"], 65_535)
        too_large = model([largest + b"x"])
        with mock.patch.object(
            ipv4.base64, "b64decode", side_effect=AssertionError("Decode reached")
        ):
            self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(too_large))
        source = model([largest] * 8 + [packet(b"a")])
        with mock.patch.object(
            ipv4.base64, "b64decode", side_effect=AssertionError("Decode reached")
        ):
            self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(source), "Aggregate")

    def test_real_set_packet_and_aggregate_counts_are_predecoded(self):
        wire = packet()
        sources = (
            model(*([wire] for _ in range(17))),
            model([wire] * 65),
            model([wire] * 64, [wire] * 64, [wire]),
        )
        with mock.patch.object(
            ipv4.base64, "b64decode", side_effect=AssertionError("Decode reached")
        ):
            for source in sources:
                self.no_hash(lambda source=source: ipv4.analyze_supplied_ipv4_fragments(source))
        for source in (
            model(*([wire] for _ in range(16))),
            model([wire] * 64),
            model(*([wire] * 8 for _ in range(16))),
        ):
            report = ipv4.analyze_supplied_ipv4_fragments(source)
            self.assertEqual(
                json.loads(report.document_json)["accounting"]["packet_count"],
                sum(len(g["packets"]) for g in source["fragment_sets"]),
            )

    def test_actual_2048_pair_boundary_and_next_evaluation(self):
        wire = packet()
        source = model([wire] * 64, [wire] * 8, [wire] * 3, [wire] * 2)
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        self.assertEqual(json.loads(report.document_json)["accounting"]["pair_evaluations"], 2_048)
        self.no_hash(
            lambda: ipv4.analyze_supplied_ipv4_fragments(model([wire] * 64, [wire] * 9)), "pair"
        )

    def test_honestly_reduced_overlap_octet_boundary(self):
        with mock.patch.object(ipv4, "MAX_OVERLAP_BYTES", 1_024):
            source = model([packet(b"a" * 1_024)] * 2)
            document = self.analyze(source)
            self.assertEqual(document["accounting"]["compared_overlap_octets"], 1_024)
            self.no_hash(
                lambda: ipv4.analyze_supplied_ipv4_fragments(model([packet(b"a" * 1_025)] * 2)),
                "overlap",
            )

    def test_actual_observation_ceiling_does_not_discard_unknown_options(self):
        full = packet(options=b"\x82\x02" * 20)
        partial = packet(options=b"\x82\x02" * 8)
        packets = [full] * 102 + [partial]
        source = model(*(packets[i : i + 7] for i in range(0, len(packets), 7)))
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        self.assertEqual(json.loads(report.document_json)["accounting"]["observation_count"], 2_048)
        packets[-1] = packet(options=b"\x82\x02" * 9 + b"\0\0")
        oversized = model(*(packets[i : i + 7] for i in range(0, len(packets), 7)))
        self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(oversized), "observation")

    def test_honestly_reduced_native_node_and_depth_boundaries(self):
        source = ipv4.component_fixture()
        for setting in ("MAX_MODEL_NODES", "MAX_REPORT_NODES", "MAX_DEPTH"):
            with mock.patch.object(ipv4, setting, 1):
                self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(source))
        with mock.patch.object(ipv4, "MAX_DEPTH", 1):
            self.before_decoder("[0]")

    def test_final_report_byte_reservation_includes_fixed_width_addresses(self):
        source = ipv4.component_fixture()
        document = self.analyze(source)
        actual_size = len(canonical(document))
        bounds = document["bounds"]
        with mock.patch.object(ipv4, "_bounds", return_value=bounds):
            with mock.patch.object(ipv4, "MAX_REPORT_BYTES", actual_size):
                self.assertEqual(
                    ipv4.analyze_supplied_ipv4_fragments(source).document_json, canonical(document)
                )
            with mock.patch.object(ipv4, "MAX_REPORT_BYTES", actual_size - 1):
                self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(source), "byte")

    def test_real_high_cost_source_denies_work_before_digest(self):
        wire = packet(b"a" * 4_096)
        source = model([wire] * 64)
        self.assertLess(
            sum(
                len(base64.b64decode(r["packet_base64"]))
                for r in source["fragment_sets"][0]["packets"]
            ),
            ipv4.MAX_TOTAL_PACKET_BYTES,
        )
        self.assertLess(64 * 63 // 2, ipv4.MAX_PAIRS)
        self.assertLess((64 * 63 // 2) * 4_096, ipv4.MAX_OVERLAP_BYTES)
        self.no_hash(lambda: ipv4.analyze_supplied_ipv4_fragments(source), "work")

    def test_all_eight_whole_operation_work_thresholds_precede_first_sha(self):
        source = ipv4.component_fixture()
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        text, document = report.to_json(), report.to_dict()
        content = canonical(source).encode("ascii")
        operations = (
            lambda: ipv4.analyze_supplied_ipv4_fragments(source),
            lambda: ipv4.analyze_supplied_ipv4_fragments_bytes(model_bytes=content),
            lambda: ipv4.IPv4FragmentAnalysis(text),
            lambda: ipv4.IPv4FragmentAnalysis.from_dict(document),
            lambda: ipv4.IPv4FragmentAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: ipv4.verify_supplied_ipv4_fragment_analysis(report, model=source),
        )
        original_charge = ipv4._Budget.charge
        original_hash = hashlib.sha256
        costs = []
        for index, operation in enumerate(operations):
            state = {"hashed": False, "totals": {}, "digest_count": 0}

            def charge(budget, amount, state=state):
                self.assertFalse(state["hashed"], "Charge after hashing")
                original_charge(budget, amount)
                state["totals"][id(budget)] = budget.used

            def digest(*args, state=state, **kwargs):
                state["hashed"] = True
                state["digest_count"] += 1
                return original_hash(*args, **kwargs)

            with (
                mock.patch.object(ipv4._Budget, "charge", charge),
                mock.patch.object(ipv4.hashlib, "sha256", digest),
            ):
                operation()
            self.assertEqual(len(state["totals"]), 1)
            self.assertEqual(state["digest_count"], 8 if index == 7 else 4)
            cost = next(iter(state["totals"].values()))
            costs.append(cost)
            with mock.patch.object(ipv4, "_bounds", return_value=document["bounds"]):
                with mock.patch.object(ipv4, "MAX_WORK", cost):
                    operation()
                with mock.patch.object(ipv4, "MAX_WORK", cost - 1):
                    self.no_hash(operation, "work")
        self.assertEqual(len(costs), 8)

    def test_separate_original_plans_share_work_but_not_structural_counters(self):
        source = ipv4.component_fixture()
        with mock.patch.object(ipv4, "MAX_PAIRS", 1):
            report = ipv4.analyze_supplied_ipv4_fragments(source)
            document = report.to_dict()
            totals = {}
            original_charge = ipv4._Budget.charge

            def charge(budget, amount):
                original_charge(budget, amount)
                totals[id(budget)] = budget.used

            with (
                mock.patch.object(ipv4._Budget, "charge", charge),
                mock.patch.object(ipv4, "_plan", wraps=ipv4._plan) as plans,
            ):
                verified = ipv4.verify_supplied_ipv4_fragment_analysis(report, model=source)
            self.assertEqual(plans.call_count, 2)
            self.assertIs(plans.call_args_list[0].args[1], plans.call_args_list[1].args[1])
            self.assertEqual(len(totals), 1)
            self.assertEqual(verified.document_json, report.document_json)
            self.assertEqual(document["accounting"]["pair_evaluations"], 1)
            cost = next(iter(totals.values()))
            with mock.patch.object(ipv4, "_bounds", return_value=document["bounds"]):
                with mock.patch.object(ipv4, "MAX_WORK", cost):
                    self.assertEqual(
                        ipv4.verify_supplied_ipv4_fragment_analysis(
                            report, model=source
                        ).document_json,
                        report.document_json,
                    )
                with mock.patch.object(ipv4, "MAX_WORK", cost - 1):
                    self.no_hash(
                        lambda: ipv4.verify_supplied_ipv4_fragment_analysis(report, model=source),
                        "work",
                    )

    def test_coherently_rehashed_false_derived_rows_still_fail_complete_replay(self):
        document = self.analyze(ipv4.component_fixture())
        mutations = (
            lambda d: d["packets"][0].update(header_checksum_equation_holds=False),
            lambda d: d["packets"][0].update(fragment_end=17),
            lambda d: d["fragment_sets"][0].update(union_octets=25),
            lambda d: d["fragment_sets"][0].update(literal_gaps_to_unique_endpoint=[[0, 1]]),
            lambda d: d["fragment_sets"][0]["pairs"][0].update(
                exact_supplied_packet_octets_equal=True
            ),
            lambda d: d["fragment_sets"][0].update(conditional_nonatomic_tuple_assessed=False),
            lambda d: d["accounting"].update(pair_evaluations=0),
            lambda d: d["claims"].update(receiver_reassembly_proven=True),
            lambda d: d["effects"].update(network="performed"),
            lambda d: d.update(source_model_sha256="sha256:" + "a" * 64),
        )
        for mutation in mutations:
            bad = copy.deepcopy(document)
            mutation(bad)
            bad = readdress(bad)
            with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
                ipv4.IPv4FragmentAnalysis.from_dict(bad)
            with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
                ipv4.IPv4FragmentAnalysis.from_json(canonical(bad))
            with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
                ipv4.IPv4FragmentAnalysis(canonical(bad))

    def test_separate_original_source_label_wire_and_order_swaps_are_rejected(self):
        source = ipv4.component_fixture()
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        label_swap = copy.deepcopy(source)
        label_swap["source_id"] = "different-source"
        order_swap = copy.deepcopy(source)
        order_swap["fragment_sets"][0]["packets"].reverse()
        wire_swap = changed_octets(source, 20, ord("X"))
        for other in (label_swap, order_swap, wire_swap):
            valid_other = ipv4.analyze_supplied_ipv4_fragments(other)
            with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
                ipv4.verify_supplied_ipv4_fragment_analysis(report, model=other)
            self.assertNotEqual(valid_other.document_json, report.document_json)

    def test_original_order_is_retained_without_arrival_order_simulation(self):
        wires = (packet(more=True), packet(offset=2), packet(offset=1, more=True))
        facts = []
        for order in itertools.permutations(wires):
            source = model(list(order))
            report = self.analyze(source)
            group = report["fragment_sets"][0]
            self.assertEqual(report["source_model"], source)
            facts.append(
                (
                    group["union_octets"],
                    group["literal_unique_mf_zero_endpoint"],
                    group["merged_supplied_intervals"],
                    group["literal_gaps_to_unique_endpoint"],
                )
            )
            self.assertFalse(report["claims"]["receiver_overlap_rule_proven"])
        self.assertTrue(all(fact == facts[0] for fact in facts))

    def test_caller_and_export_mutations_are_detached(self):
        source = ipv4.component_fixture()
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        original = report.to_json()
        source["fragment_sets"].clear()
        document = report.to_dict()
        document["source_model"]["source_id"] = "other"
        document["fragment_sets"][0]["pairs"].clear()
        document["claims"]["receiver_reassembly_proven"] = True
        self.assertEqual(report.to_json(), original)
        clone = ipv4.IPv4FragmentAnalysis.from_dict(report.to_dict())
        self.assertEqual(clone.to_json(), original)

    def test_canonical_report_is_required_but_raw_model_spacing_is_not_identity(self):
        source = ipv4.component_fixture()
        report = ipv4.analyze_supplied_ipv4_fragments(source)
        self.assertEqual(
            ipv4.analyze_supplied_ipv4_fragments_bytes(
                model_bytes=json.dumps(source, indent=2).encode("ascii")
            ).document_json,
            report.document_json,
        )
        self.no_hash(
            lambda: ipv4.IPv4FragmentAnalysis.from_dict({"source_model": source, "extra": object()})
        )
        with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
            ipv4.IPv4FragmentAnalysis.from_json(" " + report.document_json)
        bad = report.to_dict()
        bad["schema_version"] = True
        with self.assertRaises(ipv4.IPv4FragmentAnalysisError):
            ipv4.IPv4FragmentAnalysis.from_dict(readdress(bad))


if __name__ == "__main__":
    unittest.main()

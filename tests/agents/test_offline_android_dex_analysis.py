"""Independent DEX035 encoders, finite string tables and genuine source replay."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
import zlib
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_android_dex_analysis as d


def _u32(value):
    return value.to_bytes(4, "little")


def _uleb(value):
    octets = []
    while value >= 128:
        octets.append((value & 127) | 128)
        value //= 128
    return bytes([*octets, value])


def _mutf(units):
    result = bytearray()
    for unit in units:
        if unit == 0:
            result.extend((192, 128))
        elif unit < 128:
            result.append(unit)
        elif unit < 2048:
            result.extend((192 | (unit // 64), 128 | (unit % 64)))
        else:
            result.extend((224 | (unit // 4096), 128 | ((unit // 64) % 64), 128 | (unit % 64)))
    return bytes(result)


def _integrity(data):
    result = bytearray(data)
    result[12:32] = hashlib.sha1(result[32:], usedforsecurity=False).digest()
    result[8:12] = _u32(zlib.adler32(result[12:]))
    return bytes(result)


def _file(
    strings=((0, 65), (72, 101, 108, 108, 111), (0xD800,)),
    *,
    raw_strings=None,
    fixed=(),
    variable=(),
    target_size=None,
):
    """Manual little-endian assembly, without any leaf parser, planner or address."""
    payloads = (
        [_uleb(len(units)) + _mutf(units) + b"\0" for units in strings]
        if raw_strings is None
        else list(raw_strings)
    )
    count = len(payloads)
    data = bytearray(b"\0" * 112)
    fixed_entries = []
    if count:
        string_ids_off = len(data)
        data.extend(b"\0" * (4 * count))
        fixed_entries.append((1, count, string_ids_off))
    else:
        string_ids_off = 0
    for code, content, width in fixed:
        start = len(data)
        data.extend(content)
        fixed_entries.append((code, len(content) // width, start))
    data_off = len(data)
    variables = []
    if payloads:
        variables.append((0x2002, count, len(data)))
        for index, payload in enumerate(payloads):
            data[string_ids_off + 4 * index : string_ids_off + 4 * index + 4] = _u32(len(data))
            data.extend(payload)
    for code, content, item_count in variable:
        if code in (0x1001, 0x1002, 0x1003, 0x2001, 0x2006):
            data.extend(b"\0" * (-len(data) % 4))
        variables.append((code, item_count, len(data)))
        data.extend(content)
    data.extend(b"\0" * (-len(data) % 4))
    map_count = 2 + len(fixed_entries) + len(variables)
    if target_size is not None:
        data.extend(b"\0" * (target_size - (4 + 12 * map_count) - len(data)))
    map_off = len(data)
    entries = [(0, 1, 0), *fixed_entries, *variables, (0x1000, 1, map_off)]
    data.extend(_u32(map_count))
    for code, size, offset in entries:
        data.extend(code.to_bytes(2, "little") + b"\0\0" + _u32(size) + _u32(offset))
    values = [len(data), 112, 0x12345678, 0, 0, map_off]
    by_code = {code: (size, offset) for code, size, offset in fixed_entries}
    for code in range(1, 7):
        values.extend(by_code.get(code, (0, 0)))
    values.extend((len(data) - data_off, data_off))
    data[:8] = b"dex\n035\0"
    data[32:112] = b"".join(_u32(value) for value in values)
    return _integrity(data)


def _model(data=None, source_id="synthetic-dex035"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "dex_file_base64": base64.b64encode(_file() if data is None else data).decode("ascii"),
    }


def _change(data, offset, value, width=4):
    result = bytearray(data)
    result[offset : offset + width] = value.to_bytes(width, "little")
    return _integrity(result)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            d.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "DXA-" + digest[7:39].upper()
    return document


class AndroidDexAnalysisTests(unittest.TestCase):
    def analyze(self, data=None):
        return d.analyze_supplied_android_dex(_model(data))

    def deny(self, operation, *, before_hash=True, before_decoder=False):
        with (
            patch.object(d.hashlib, "sha1", wraps=d.hashlib.sha1) as sha1,
            patch.object(d.hashlib, "sha256", wraps=d.hashlib.sha256) as sha256,
            patch.object(d.zlib, "adler32", wraps=d.zlib.adler32) as adler,
        ):
            if before_decoder:
                with patch.object(d.json, "loads", wraps=d.json.loads) as decoder:
                    with self.assertRaises(d.AndroidDexAnalysisError):
                        operation()
                    decoder.assert_not_called()
            else:
                with self.assertRaises(d.AndroidDexAnalysisError):
                    operation()
            if before_hash:
                sha1.assert_not_called()
                sha256.assert_not_called()
                adler.assert_not_called()

    def test_public_fixture_is_literal_independent_file_and_golden(self):
        source = d.component_fixture()
        self.assertEqual(source, _model())
        report = d.analyze_supplied_android_dex(source)
        document = report.to_dict()
        self.assertEqual(document["source_file_bytes"], 196)
        self.assertEqual(
            [r["utf16_units"] for r in document["string_observations"]],
            [[0, 65], [72, 101, 108, 108, 111], [0xD800]],
        )
        self.assertEqual(document["analysis_status"], "supported_structure_subset_consistent")
        self.assertEqual(document["analysis_id"], "DXA-3D127A90FAF3E4D797F6BBAB7C33F484")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:3d127a90faf3e4d797f6bbab7c33f4847d7753c35f55a914dca39cf869d157c8",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:a7fa488a9300cf4144a75c600ca571b1b44ec3ef16f1f6c3df9461d4ab53d2ac",
        )
        self.assertEqual(
            document["source_file_sha256"],
            "sha256:b71e003f3542b9a2e41cb83db6bf819a8201933344069afa635c9deec35bc970",
        )
        self.assertEqual(
            document["header"]["signature_sha1_hex"], "e52ee2bf19021ff15e52930fd4c320882c887e7b"
        )
        self.assertEqual(document["header"]["checksum"], 1_831_671_287)
        self.assertEqual((len(_canonical(source)), len(report.to_json())), (336, 4783))

    def test_original_ownership_and_no_authority_or_signing_claim(self):
        document = self.analyze().to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D08-S01")
        self.assertEqual(document["capability_id"], "army.gb.d08.s01")
        self.assertEqual(document["wave_id"], "IW2-005")
        self.assertEqual(document["commander_id"], "AOE-GB-D08-CMD")
        self.assertEqual(document["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(set(document["flags"].values()), {False})
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(
            document["integrity"],
            {"adler32_matches": True, "sha1_matches": True, "authenticates_origin": False},
        )

    def test_independent_domain_and_exact_file_address(self):
        source = _model()
        document = d.analyze_supplied_android_dex(source).to_dict()
        expected = (
            "sha256:"
            + hashlib.sha256(
                d.MODEL_DOMAIN.encode("ascii") + b"\n" + _canonical(source).encode("ascii")
            ).hexdigest()
        )
        self.assertEqual(document["source_model_sha256"], expected)
        self.assertEqual(
            document["source_file_sha256"], "sha256:" + hashlib.sha256(_file()).hexdigest()
        )
        self.assertEqual(_readdress(copy.deepcopy(document)), document)

    def test_all_public_replay_paths_preserve_genuine_bytes(self):
        source = _model()
        report = self.analyze()
        document, text = report.to_dict(), report.to_json()
        for result in (
            d.AndroidDexAnalysis(text),
            d.AndroidDexAnalysis.from_dict(document),
            d.AndroidDexAnalysis.from_json(text),
            d.verify_supplied_android_dex_analysis(report, model=source),
        ):
            self.assertEqual(result.to_json(), text)
        self.assertEqual(report.analysis_id, document["analysis_id"])
        self.assertEqual(report.analysis_sha256, document["analysis_sha256"])
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"

    def test_raw_whitespace_escapes_and_native_projection_are_equivalent(self):
        source = _model()
        expected = d.analyze_supplied_android_dex(source).to_json()
        for content in (
            json.dumps(source, indent=2),
            _canonical(source).replace("synthetic", "\\u0073ynthetic"),
        ):
            result = d.analyze_supplied_android_dex_bytes(model_bytes=content.encode("ascii"))
            self.assertEqual(result.to_json(), expected)

    def test_fixture_sources_exports_and_wrappers_are_detached(self):
        source = _model()
        report = d.analyze_supplied_android_dex(source)
        before = report.to_json()
        source["dex_file_base64"] = "wrong"
        exported = report.to_dict()
        exported["string_observations"][0]["utf16_units"].clear()
        exported["source_model"]["source_id"] = "other"
        fresh = d.component_fixture()
        fresh["source_id"] = "other"
        self.assertEqual(report.to_json(), before)
        self.assertEqual(d.component_fixture()["source_id"], "synthetic-dex035")

    def test_empty_string_table_and_empty_raw_string_are_distinct_valid_inputs(self):
        for strings, sizes in (((), []), (((),), [0])):
            document = self.analyze(_file(strings)).to_dict()
            self.assertEqual([r["utf16_size"] for r in document["string_observations"]], sizes)

    def test_mutf8_boundary_table_preserves_all_utf16_units(self):
        units = (0, 1, 127, 128, 2047, 2048, 0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFFFF)
        document = self.analyze(_file(tuple((unit,) for unit in units))).to_dict()
        self.assertEqual(
            [row["utf16_units"] for row in document["string_observations"]],
            [[unit] for unit in units],
        )

    def test_nul_and_isolated_or_reversed_surrogates_are_not_utf8_scalar_errors(self):
        strings = ((0,), (0xD800,), (0xD800, 0xDC00), (0xDC00,), (0xDC00, 0xD800))
        document = self.analyze(_file(strings)).to_dict()
        self.assertEqual(
            [row["utf16_units"] for row in document["string_observations"]],
            [list(units) for units in strings],
        )

    def test_string_sorting_uses_units_not_encoded_bytes_or_unicode_scalars(self):
        for strings in (((0,), (65,)), ((0xD800, 0xDC00), (0xE000,))):
            self.analyze(_file(strings)).to_dict()
        for strings in (((65,), (0,)), ((0xE000,), (0xD800, 0xDC00)), ((65,), (65,))):
            data = _file(strings)
            self.deny(lambda data=data: self.analyze(data))

    def test_physical_string_order_need_not_equal_string_id_order(self):
        data = bytearray(_file(((66,), (65,))))
        first, second = data[112:116], data[116:120]
        data[112:116], data[116:120] = second, first
        document = self.analyze(_integrity(data)).to_dict()
        self.assertEqual(
            [row["utf16_units"] for row in document["string_observations"]], [[65], [66]]
        )
        self.assertGreater(
            document["string_observations"][0]["data_offset"],
            document["string_observations"][1]["data_offset"],
        )

    def test_nonminimal_but_bounded_uleb_is_not_invented_invalidity(self):
        for raw in (b"\x81\x00A\0", b"\x81\x80\x00A\0", b"\x80\x00\0"):
            document = self.analyze(_file(raw_strings=(raw,))).to_dict()
            self.assertEqual(
                document["string_observations"][0]["utf16_units"],
                [] if raw.startswith(b"\x80") else [65],
            )

    def test_independent_uleb_size_boundaries_127_128_4096(self):
        for count, width in ((0, 1), (127, 1), (128, 2), (4096, 2)):
            document = self.analyze(_file(((65,) * count,))).to_dict()
            row = document["string_observations"][0]
            self.assertEqual((row["utf16_size"], row["uleb128_byte_count"]), (count, width))

    def test_uleb_fifth_payload_overflow_and_continuation_reject_before_digest(self):
        for raw in (
            b"\x80" * 5 + b"\0",
            b"\xff\xff\xff\xff\x10\0",
            b"\xff\xff\xff\xff\x0f\0",
            b"\x81\x20\0",
        ):
            data = _file(raw_strings=(raw,))
            self.deny(lambda data=data: self.analyze(data))

    def test_mutf8_malformed_continuation_overlong_and_four_byte_forms_reject(self):
        malformed = (
            b"\x01\x80\0",
            b"\x01\xc0\x81\0",
            b"\x01\xc1\x80\0",
            b"\x01\xe0\x80\x80\0",
            b"\x01\xc2A\0",
            b"\x01\xe1\x80A\0",
            b"\x01\xf0\x90\x80\x80\0",
            b"\x81\x80\0\xc2",
        )
        for raw in malformed:
            data = _file(raw_strings=(raw,))
            self.deny(lambda data=data: self.analyze(data))

    def test_declared_unit_count_and_bounded_terminator_are_actual_joins(self):
        for raw in (b"\x02A\0", b"\x00A\0", b"\x03ABC", b"\x81\x80\0\xe1"):
            data = _file(raw_strings=(raw,))
            self.deny(lambda data=data: self.analyze(data))

    def test_string_byte_spans_cannot_cross_next_item_or_next_map_start(self):
        data = _file(((65,), (66,)))
        first = int.from_bytes(data[112:116], "little")
        second = int.from_bytes(data[116:120], "little")
        for target in (first + 1, second - 1, int.from_bytes(data[52:56], "little")):
            changed = _change(data, 116, target)
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_string_reference_duplicate_and_wrong_mapped_first_start_reject(self):
        data = _file()
        first = int.from_bytes(data[112:116], "little")
        for changed in (_change(data, 116, first), _change(data, 112, first + 1)):
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_string_map_count_presence_and_header_references_are_exact(self):
        data = _file()
        map_off = int.from_bytes(data[52:56], "little")
        for changed in (
            _change(data, map_off + 4 + 24 + 4, 2),
            _change(data, map_off + 4 + 24, 0x2003, 2),
        ):
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_known_fixed_sections_have_ranges_but_no_content_semantics_claim(self):
        fixed = (
            (2, b"\xff" * 4, 4),
            (3, b"\xff" * 12, 12),
            (4, b"\xff" * 8, 8),
            (5, b"\xff" * 8, 8),
            (6, b"\xff" * 32, 32),
        )
        document = self.analyze(_file(fixed=fixed)).to_dict()
        rows = [row for row in document["map_observations"] if row["type_code"] in range(2, 7)]
        self.assertEqual(len(rows), 5)
        self.assertEqual({row["content_check"] for row in rows}, {"unassessed_fixed_contents"})
        self.assertFalse(document["flags"]["class_semantics_validated"])

    def test_unknown_variable_map_extent_is_unassessed_not_guessed(self):
        for code in (0x2001, 0x1001, 0xBEEF, 0x0007):
            document = self.analyze(_file(variable=((code, b"\xff", 0xFFFFFFFF),))).to_dict()
            row = next(r for r in document["map_observations"] if r["type_code"] == code)
            self.assertIsNone(row["end_offset"])
            self.assertEqual(row["extent_check"], "unassessed_variable_extent")
            self.assertFalse(document["flags"]["full_map_nonoverlap_verified"])
            self.assertFalse(document["flags"]["full_dex_validity_verified"])

    def test_actual_magic_endian_link_and_header_sizes_reject_readdressed_bytes(self):
        data = _file()
        malformed = []
        for magic in (b"dex\n037\0", b"dex\n041\0", b"cdex001\0"):
            changed = bytearray(data)
            changed[:8] = magic
            malformed.append(_integrity(changed))
        malformed.extend(
            _change(data, offset, value)
            for offset, value in (
                (32, len(data) - 1),
                (36, 120),
                (40, 0x78563412),
                (44, 1),
                (48, 112),
                (104, 71),
                (108, 123),
            )
        )
        for changed in malformed:
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_header_fixed_empty_offsets_ranges_order_and_count_bounds(self):
        data = _file(fixed=((2, b"\0" * 4, 4),))
        for offset, value in (
            (68, 113),
            (64, 65536),
            (76, 116),
            (60, 108),
            (60, 113),
            (56, 4097),
            (64, 0),
            (68, 0),
        ):
            changed = _change(data, offset, value)
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_header_data_map_nonzero_alignment_and_end_are_checked(self):
        data = _file()
        for offset, value in (
            (52, 0),
            (52, 145),
            (52, len(data)),
            (104, 68),
            (108, 112),
            (108, len(data)),
            (104, 0),
        ):
            changed = _change(data, offset, value)
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_map_uniqueness_order_positive_counts_and_unused_closed_subset(self):
        data = _file()
        map_off = int.from_bytes(data[52:56], "little")
        for offset, value, width in (
            (map_off, 1, 4),
            (map_off, 129, 4),
            (map_off + 16, 0, 2),
            (map_off + 6, 1, 2),
            (map_off + 20, 0, 4),
            (map_off + 24, 0, 4),
            (map_off + 24, 0xFFFFFFFF, 4),
        ):
            changed = _change(data, offset, value, width)
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_map_header_fixed_self_counts_offsets_and_missing_types_join(self):
        data = _file()
        map_off = int.from_bytes(data[52:56], "little")
        for offset, value, width in (
            (map_off + 8, 2, 4),
            (map_off + 12, 4, 4),
            (map_off + 20, 2, 4),
            (map_off + 24, 116, 4),
            (map_off + 40, 0x1001, 2),
            (map_off + 44, 2, 4),
            (map_off + 48, map_off + 4, 4),
        ):
            changed = _change(data, offset, value, width)
            self.deny(lambda changed=changed: self.analyze(changed))

    def test_known_extent_cannot_overlap_unknown_following_start(self):
        data = _file(variable=((0x2003, b"\x00", 1),))
        map_off = int.from_bytes(data[52:56], "little")
        changed = bytearray(data)
        variable_entry = changed[map_off + 40 : map_off + 52]
        self_entry = changed[map_off + 52 : map_off + 64]
        changed[map_off + 40 : map_off + 52] = self_entry
        changed[map_off + 52 : map_off + 64] = variable_entry
        changed[map_off + 60 : map_off + 64] = _u32(map_off + 4)
        changed = _integrity(changed)
        with self.assertRaisesRegex(d.AndroidDexAnalysisError, "overlap"):
            self.analyze(changed)

    def test_raw_file_truncation_must_not_leak_struct_or_index_errors(self):
        data = _file()
        for cut in (0, 8, 111, 112, 123, 144, 147, 195):
            self.deny(lambda cut=cut: self.analyze(data[:cut]))

    def test_integrity_fields_are_actual_corruption_checks_not_signatures(self):
        data = bytearray(_file())
        data[12] ^= 1
        self.deny(lambda: self.analyze(bytes(data)), before_hash=False)
        data = bytearray(_file())
        data[8] ^= 1
        self.deny(lambda: self.analyze(bytes(data)), before_hash=False)
        repaired = _change(_file(), 12, 1, 1)
        document = self.analyze(repaired).to_dict()
        self.assertFalse(document["flags"]["apk_signature_verified"])

    def test_string_and_aggregate_unit_limits_have_exact_ordinary_positives(self):
        for strings in (((65,) * 4096,), tuple((i, *((65,) * 4095)) for i in range(16))):
            document = self.analyze(_file(strings)).to_dict()
            self.assertEqual(document["aggregate_utf16_units"], sum(map(len, strings)))
        for strings in (((65,) * 4097,), tuple((i, *((65,) * 4095)) for i in range(17))):
            data = _file(strings)
            self.deny(lambda data=data: self.analyze(data))

    def test_4096_unique_strings_are_valid_but_more_are_a_software_limit(self):
        document = self.analyze(_file(tuple((i,) for i in range(4096)))).to_dict()
        self.assertEqual(len(document["string_observations"]), 4096)
        data = _file(tuple((i,) for i in range(4097)))
        self.deny(lambda: self.analyze(data))

    def test_base64_canonical_padding_bits_and_declared_size_before_decoder(self):
        for encoded in ("", "A===", " AAAAA==", "AA=A", "AAAA\n", "Zh=="):
            source = _model()
            source["dex_file_base64"] = encoded
            self.deny(lambda source=source: d.analyze_supplied_android_dex(source))
        source = _model()
        source["dex_file_base64"] = "A" * (d.MAX_BASE64_BYTES + 4)
        with patch.object(d.base64, "b64decode") as decoder:
            self.deny(lambda: d.analyze_supplied_android_dex(source))
            decoder.assert_not_called()
        # Valid length, noncanonical low padding bits on a 196-byte benign file.
        source = _model()
        source["dex_file_base64"] = source["dex_file_base64"][:-3] + "B=="
        self.deny(lambda: d.analyze_supplied_android_dex(source))

    def test_model_shape_exact_native_types_aliases_and_cycles(self):
        class Text(str):
            def __str__(self):
                raise AssertionError("String hook must not run")

        class Number(int):
            def __str__(self):
                raise AssertionError("Integer hook must not run")

        for value in (True, False, 1.0, "1", None, Number(1)):
            source = _model()
            source["schema_version"] = value
            self.deny(lambda source=source: d.analyze_supplied_android_dex(source))
        for field in ("source_id", "dex_file_base64"):
            for value in (None, True, [], {}, Text("synthetic")):
                source = _model()
                source[field] = value
                self.deny(lambda source=source: d.analyze_supplied_android_dex(source))
        for value in (None, True, (), 1.0, b"{}"):
            self.deny(lambda value=value: d.analyze_supplied_android_dex(value))
        source = _model()
        source["extra"] = source
        self.deny(lambda: d.analyze_supplied_android_dex(source))
        self.deny(lambda: d.analyze_supplied_android_dex({"huge": 2**10000}))

    def test_raw_duplicates_number_grammar_and_primitive_depth_before_decoder(self):
        for raw in (
            "--1",
            "01",
            "-01",
            "1.0",
            "NaN",
            "9" * 21,
            "9223372036854775808",
            "-9223372036854775809",
            "[" * 16 + "true" + "]" * 16,
        ):
            self.deny(
                lambda raw=raw: d.analyze_supplied_android_dex_bytes(
                    model_bytes=raw.encode("ascii")
                ),
                before_decoder=True,
            )
        for raw in (
            '{"a":1,"a":1}',
            '{"a":{"b":1,"b":1}}',
            _canonical(_model()).replace(
                '"schema_version":1', '"schema_version":1,"schema_version":1'
            ),
        ):
            self.deny(
                lambda raw=raw: d.analyze_supplied_android_dex_bytes(
                    model_bytes=raw.encode("ascii")
                )
            )

    def test_raw_node_string_escaped_and_byte_costs_precede_json_decode(self):
        for raw in (
            "[" + ",".join("0" for _ in range(d.MAX_MODEL_NODES)) + "]",
            '"' + "A" * (d.MAX_BASE64_BYTES + 1) + '"',
            '"' + "\\u0041" * (d.MAX_BASE64_BYTES + 1) + '"',
            '"\\ud800"',
            '"\\u007f"',
            " " * (d.MAX_MODEL_BYTES + 1),
        ):
            self.deny(
                lambda raw=raw: d.analyze_supplied_android_dex_bytes(
                    model_bytes=raw.encode("ascii")
                ),
                before_decoder=True,
            )

    def test_raw_legal_integer_and_depth_shapes_reach_only_closed_model_rejection(self):
        for raw in ("-0", "9223372036854775807", "-9223372036854775808", "[" * 15 + "0" + "]" * 15):
            real = d.json.loads
            with patch.object(d.json, "loads", wraps=real) as decoder:
                self.deny(
                    lambda raw=raw: d.analyze_supplied_android_dex_bytes(
                        model_bytes=raw.encode("ascii")
                    )
                )
                self.assertEqual(decoder.call_count, 1)

    def test_native_repeated_graph_and_escape_cost_are_measured_before_clone(self):
        shared = ["a" * 4096] * 128
        for source in ({"repeated": [shared] * 16}, {"quoted": '"' * d.MAX_BASE64_BYTES}):
            with patch.object(d, "_clone") as clone:
                self.deny(lambda source=source: d.analyze_supplied_android_dex(source))
                clone.assert_not_called()

    def test_cohashed_false_header_map_strings_and_integrity_cannot_replay(self):
        original = self.analyze().to_dict()
        changes = []
        for section, field, value in (
            ("header", "map_off", 0),
            ("header", "checksum", 0),
            ("integrity", "sha1_matches", False),
            ("flags", "full_dex_validity_verified", True),
        ):
            changed = copy.deepcopy(original)
            changed[section][field] = value
            changes.append(changed)
        changed = copy.deepcopy(original)
        changed["string_observations"][0]["utf16_units"] = [65]
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["map_observations"][2]["end_offset"] += 1
        changes.append(changed)
        for changed in changes:
            value = _readdress(changed)
            self.deny(lambda value=value: d.AndroidDexAnalysis.from_dict(value), before_hash=False)
            self.deny(
                lambda value=value: d.AndroidDexAnalysis.from_json(_canonical(value)),
                before_hash=False,
            )

    def test_native_alias_effect_and_bounds_readdressing_does_not_replay(self):
        original = self.analyze().to_dict()
        for value in (True, 1.0, "1", None):
            changed = copy.deepcopy(original)
            changed["schema_version"] = value
            self.deny(
                lambda changed=changed: d.AndroidDexAnalysis.from_dict(_readdress(changed)),
                before_hash=False,
            )
        for section, field, value in (
            ("effects", "execution", "performed"),
            ("flags", "source_authenticated", True),
            ("bounds", "strings", 8192),
        ):
            changed = copy.deepcopy(original)
            changed[section][field] = value
            value = _readdress(changed)
            self.deny(lambda value=value: d.AndroidDexAnalysis.from_dict(value), before_hash=False)

    def test_alternate_valid_source_is_not_the_original_and_ids_are_bound(self):
        source = _model()
        for foreign_source in (_model(_file(((66,),))), _model(source_id="other")):
            report = d.analyze_supplied_android_dex(foreign_source)
            self.assertEqual(
                d.AndroidDexAnalysis.from_json(report.to_json()).to_json(), report.to_json()
            )
            self.deny(
                lambda report=report: d.verify_supplied_android_dex_analysis(report, model=source),
                before_hash=False,
            )

    def test_cohashed_embedded_file_substitution_cannot_keep_old_observations(self):
        changed = self.analyze().to_dict()
        alternate = _model(_file(((66,),)))
        changed["source_model"] = alternate
        changed["source_model_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                d.MODEL_DOMAIN.encode("ascii") + b"\n" + _canonical(alternate).encode("ascii")
            ).hexdigest()
        )
        changed["source_file_sha256"] = "sha256:" + hashlib.sha256(_file(((66,),))).hexdigest()
        value = _readdress(changed)
        self.deny(lambda: d.AndroidDexAnalysis.from_dict(value), before_hash=False)

    def test_unknown_wrapper_missing_slots_subclasses_and_mutation_reject(self):
        source = _model()
        missing = object.__new__(d.AndroidDexAnalysis)
        for operation in (
            missing.to_dict,
            missing.to_json,
            lambda: d.verify_supplied_android_dex_analysis(missing, model=source),
        ):
            self.deny(operation)
        for value in (None, {}, True, "{}"):
            self.deny(
                lambda value=value: d.verify_supplied_android_dex_analysis(value, model=source)
            )

        class Derived(d.AndroidDexAnalysis):
            pass

        text = self.analyze().to_json()
        self.deny(lambda: Derived(text))
        self.deny(lambda: Derived.from_json(text))
        report = self.analyze()
        changed = report.to_dict()
        changed["header"]["file_size"] += 1
        object.__setattr__(report, "document_json", _canonical(_readdress(changed)))
        self.deny(report.to_json, before_hash=False)

    def test_report_json_is_exact_canonical_and_identity_tampering_rejects(self):
        document = self.analyze().to_dict()
        for raw in (json.dumps(document, indent=2), _canonical(document) + "\n", "{}"):
            self.deny(lambda raw=raw: d.AndroidDexAnalysis.from_json(raw), before_hash=False)
        for field in (
            "analysis_id",
            "analysis_sha256",
            "source_model_sha256",
            "source_file_sha256",
        ):
            changed = copy.deepcopy(document)
            changed[field] = "wrong"
            self.deny(
                lambda changed=changed: d.AndroidDexAnalysis.from_dict(changed), before_hash=False
            )

    def test_each_public_pass_has_one_budget_and_funds_all_digests_before_cost_denial(self):
        source = _model()
        report = self.analyze()
        document = report.to_dict()
        text = report.to_json()
        operations = (
            lambda: d.analyze_supplied_android_dex(source),
            lambda: d.analyze_supplied_android_dex_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            lambda: d.AndroidDexAnalysis(text),
            lambda: d.AndroidDexAnalysis.from_dict(document),
            lambda: d.AndroidDexAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: d.verify_supplied_android_dex_analysis(report, model=source),
        )
        original = d._Budget.charge
        for operation in operations:
            seen = []

            def observe(self, amount, seen=seen):
                if all(self is not item for item in seen):
                    seen.append(self)
                original(self, amount)

            with patch.object(d._Budget, "charge", observe):
                operation()
            self.assertEqual(len(seen), 1)
            needed = seen[0].used
            for delta in (-1, 0):
                cap = needed + delta

                def capped(self, amount, cap=cap):
                    if amount > cap - self.used:
                        raise d.AndroidDexAnalysisError("Independent exact work cap")
                    original(self, amount)

                with patch.object(d._Budget, "charge", capped):
                    if delta < 0:
                        self.deny(operation)
                    else:
                        operation()

    def test_real_high_unit_report_retention_refuses_before_every_digest(self):
        source = _model(_file(tuple((i, *((65,) * 4095)) for i in range(16))))
        with patch.object(d, "MAX_REPORT_BYTES", 262_144):
            self.deny(lambda: d.analyze_supplied_android_dex(source))
        with patch.object(d, "MAX_REPORT_NODES", 65_536):
            self.deny(lambda: d.analyze_supplied_android_dex(source))

    def test_bounded_bytes_wrong_family_and_report_text_inputs_are_domain_errors(self):
        for value in (b"", bytearray(b"{}"), "{}", b"\xff", b" " * (d.MAX_MODEL_BYTES + 1)):
            self.deny(lambda value=value: d.analyze_supplied_android_dex_bytes(model_bytes=value))
        for value in (b"{}", None, "", " " * (d.MAX_REPORT_BYTES + 1)):
            self.deny(lambda value=value: d.AndroidDexAnalysis.from_json(value))


if __name__ == "__main__":
    unittest.main()

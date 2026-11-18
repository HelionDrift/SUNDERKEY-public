"""Independent inert PE encoders, declared geometry and complete replay controls."""

import base64
import copy
import dataclasses
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_pe32_layout_analysis as m


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _put(data, offset, width, value):
    data[offset : offset + width] = value.to_bytes(width, "little")


def _file(
    *,
    sections=None,
    alignment=4096,
    file_alignment=512,
    headers=512,
    image_size=None,
    machine=0x8664,
    optional_size=240,
    directory_count=16,
    pe=128,
    data_size=None,
):
    sections = [(32, 4096, 512, 512)] if sections is None else sections
    image_size = (len(sections) + 1) * alignment if image_size is None else image_size
    size = max(
        [headers, pe + 24 + optional_size + len(sections) * 40]
        + [pointer + raw for _virtual, _rva, raw, pointer in sections if raw]
    )
    data = bytearray(size if data_size is None else max(size, data_size))
    data[:2] = b"MZ"
    _put(data, 60, 4, pe)
    data[pe : pe + 4] = b"PE\0\0"
    coff = pe + 4
    for offset, width, value in (
        (0, 2, machine),
        (2, 2, len(sections)),
        (16, 2, optional_size),
        (18, 2, 0x22),
    ):
        _put(data, coff + offset, width, value)
    optional = pe + 24
    for offset, width, value in (
        (0, 2, 0x20B),
        (8, 4, sum(s[2] for s in sections)),
        (24, 8, 0x140000000),
        (32, 4, alignment),
        (36, 4, file_alignment),
        (56, 4, image_size),
        (60, 4, headers),
        (68, 2, 3),
        (72, 8, 0x100000),
        (80, 8, 0x1000),
        (88, 8, 0x100000),
        (96, 8, 0x1000),
        (108, 4, directory_count),
    ):
        _put(data, optional + offset, width, value)
    for index, (virtual, rva, raw, pointer) in enumerate(sections):
        section = optional + optional_size + index * 40
        data[section : section + 8] = b".data\0\0\0"
        for offset, width, value in (
            (8, 4, virtual),
            (12, 4, rva),
            (16, 4, raw),
            (20, 4, pointer),
            (36, 4, 0xC0000040),
        ):
            _put(data, section + offset, width, value)
        if raw:
            data[pointer : pointer + min(4, raw)] = b"DATA"[: min(4, raw)]
    return bytes(data)


def _model(data=None):
    return {
        "schema_version": 1,
        "source_id": "synthetic-pe32plus",
        "pe_file_base64": base64.b64encode(_file() if data is None else data).decode("ascii"),
    }


def _changed(offset, width, value, *, data=None):
    result = bytearray(_file() if data is None else data)
    _put(result, offset, width, value)
    return bytes(result)


def _directory(index, address, size, *, data=None):
    data = _file() if data is None else data
    pe = int.from_bytes(data[60:64], "little")
    offset = pe + 24 + 112 + 8 * index
    return _changed(offset + 4, 4, size, data=_changed(offset, 4, address, data=data))


def _certificates(entries=((9, 0x200, 2),), *, offset=1024, data=None):
    data = bytearray(_file() if data is None else data)
    occupied = sum((length + 7) // 8 * 8 for length, _revision, _kind in entries)
    data.extend(bytes(max(0, offset + occupied - len(data))))
    cursor = offset
    for length, revision, kind in entries:
        _put(data, cursor, 4, length)
        _put(data, cursor + 4, 2, revision)
        _put(data, cursor + 6, 2, kind)
        if length > 8:
            data[cursor + 8 : cursor + length] = b"P" * (length - 8)
        cursor += (length + 7) // 8 * 8
    return _directory(4, offset, occupied, data=bytes(data))


def _rehash(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"sunderkey.offline-pe32plus-layout-analysis.v1\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "PLA-" + digest[7:39].upper()
    return document


class Pe32PlusLayoutAnalysisTests(unittest.TestCase):
    def analyze(self, data=None):
        return m.analyze_supplied_pe32plus_layout(_model(data))

    def deny(self, operation):
        with patch.object(m.hashlib, "sha256", wraps=m.hashlib.sha256) as digest:
            with self.assertRaises(m.Pe32PlusLayoutAnalysisError):
                operation()
            digest.assert_not_called()

    def test_independent_literal_fixture_and_distinct_hash_domains(self):
        self.assertEqual(m.component_fixture(), _model())
        report = self.analyze().to_dict()
        self.assertEqual(report["source_file_bytes"], 1024)
        self.assertEqual(report["analysis_id"], "PLA-1050EEA7981D9E9098761D1618D067BE")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:1050eea7981d9e9098761d1618d067be4503044f91dc276c53a37a280095dba7",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:7461f2cd0568c3fa36424a87b857bc4e7a3f1dfbeff4c6d78bcddd8ea2ad5d2a",
        )
        self.assertEqual(
            report["source_file_sha256"],
            "sha256:93bf34e6f0767776c2f21bebaf595b0d3cce91a2f5747d0fd9da49ae6813bacf",
        )
        self.assertEqual(
            report["source_file_sha256"], "sha256:" + hashlib.sha256(_file()).hexdigest()
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:"
            + hashlib.sha256(
                b"sunderkey.offline-pe32plus-model.v1\n" + _canonical(_model()).encode("ascii")
            ).hexdigest(),
        )
        self.assertNotEqual(report["source_file_sha256"], report["source_model_sha256"])
        self.assertEqual(report["analysis_status"], "supported_layout_subset_consistent")
        self.assertEqual(report["unassessed_reasons"], [])
        self.assertEqual(report["header"]["image_base_hex"], "0x0000000140000000")
        self.assertEqual(report["section_observations"][0]["raw_beyond_logical_bytes"], 480)

    def test_original_ownership_and_every_nonqualifying_effect_remain_exact(self):
        report = self.analyze().to_dict()
        expected = {
            "component_id": "windows_supplied_pe32plus_layout",
            "profile_id": "AOE-GB-D08-S15",
            "capability_id": "army.gb.d08.s15",
            "vector_id": "AV-GB-D08-S15-01",
            "work_package_id": "IWP2-AOE-GB-D08-S15",
            "wave_id": "IW2-001",
            "commander_id": "AOE-GB-D08-CMD",
            "group_owner_id": "AOE-HQ-04",
            "independent_validator_id": "AOE-HQ-19",
            "blueprint_sha256": (
                "sha256:e17edd936887b65ab10f39ee99a24783d1d68c4f97ec2258b1d43a11e1a6c21c"
            ),
        }
        for key, value in expected.items():
            self.assertEqual(report[key], value)
        self.assertEqual(report["roadmap_package_ids"], ["A7.4"])
        self.assertTrue(all(value is False for value in report["flags"].values()))
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_all_eight_public_boundaries_replay_the_complete_supplied_file(self):
        report = self.analyze()
        text, document = report.to_json(), report.to_dict()
        outputs = (
            self.analyze(),
            m.analyze_supplied_pe32plus_layout_bytes(
                model_bytes=_canonical(_model()).encode("ascii")
            ),
            m.Pe32PlusLayoutAnalysis(text),
            m.Pe32PlusLayoutAnalysis.from_dict(document),
            m.Pe32PlusLayoutAnalysis.from_json(text),
            m.verify_supplied_pe32plus_layout_analysis(report, model=_model()),
        )
        for output in outputs:
            self.assertEqual(output.to_json(), text)
            self.assertEqual(output.to_dict(), document)

    def test_sources_exports_and_fixture_are_detached_and_frozen(self):
        source = _model()
        report = m.analyze_supplied_pe32plus_layout(source)
        original = report.to_json()
        source["source_id"] = "changed"
        document = report.to_dict()
        document["source_model"]["source_id"] = "changed"
        document["header"]["image_bytes"] = 1
        document["section_observations"].clear()
        self.assertEqual(report.to_json(), original)
        fixture = m.component_fixture()
        fixture["source_id"] = "changed"
        self.assertEqual(m.component_fixture(), _model())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.document_json = "{}"

    def test_signatures_and_header_file_ranges_refuse_before_hash(self):
        for data in (
            b"MZ",
            _file()[:63],
            _changed(0, 2, 0),
            _changed(60, 4, 63),
            _changed(60, 4, 0xFFFFFFFF),
            _changed(128, 4, 0),
            _file()[:151],
        ):
            self.deny(lambda data=data: self.analyze(data))

    def test_coff_optional_magic_counts_and_declared_table_extents_refuse(self):
        cases = (
            (134, 2, 97),
            (148, 2, 111),
            (148, 2, 0xFFFF),
            (152, 2, 0x10B),
            (260, 4, 33),
            (260, 4, 17),
            (212, 4, 400),
            (208, 4, 511),
        )
        for offset, width, value in cases:
            self.deny(
                lambda offset=offset, width=width, value=value: self.analyze(
                    _changed(offset, width, value)
                )
            )

    def test_directory_table_uses_declared_optional_size_not_fixed_sixteen_entries(self):
        data = _file(optional_size=112, directory_count=0)
        report = self.analyze(data).to_dict()
        self.assertEqual(report["directory_observations"], [])
        self.assertEqual(report["header"]["section_table_file_offset"], 264)
        data = _file(
            optional_size=368,
            directory_count=32,
            headers=1024,
            sections=[(32, 4096, 512, 1024)],
            data_size=1536,
        )
        self.assertEqual(len(self.analyze(data).to_dict()["directory_observations"]), 32)

    def test_uint64_values_keep_hex_and_image_base_alignment_or_overflow_refuses(self):
        data = _changed(176, 8, 0x8000000000000000)
        for offset in (224, 232, 240, 248):
            data = _changed(offset, 8, 0xFFFFFFFFFFFFFFFF, data=data)
        report = self.analyze(data).to_dict()
        self.assertEqual(report["header"]["image_end_hex"], "0x8000000000002000")
        self.assertEqual(report["header"]["stack_reserve_hex"], "0xffffffffffffffff")
        self.deny(lambda: self.analyze(_changed(176, 8, 0x140000001)))
        self.deny(
            lambda: self.analyze(
                _changed(176, 8, 0xFFFFFFFFFFFF0000, data=_changed(208, 4, 131072))
            )
        )

    def test_ordinary_named_alignment_profile_refuses_misaligned_geometry(self):
        for offset, width, value in (
            (184, 4, 0),
            (184, 4, 4095),
            (188, 4, 256),
            (188, 4, 1023),
            (188, 4, 131072),
            (208, 4, 8193),
            (212, 4, 513),
            (408, 4, 511),
            (412, 4, 513),
        ):
            self.deny(
                lambda offset=offset, width=width, value=value: self.analyze(
                    _changed(offset, width, value)
                )
            )

    def test_low_alignment_subset_requires_equal_alignments_and_raw_offset_rva(self):
        data = _file(
            alignment=512, file_alignment=512, sections=[(32, 512, 512, 512)], image_size=1024
        )
        report = self.analyze(data).to_dict()
        self.assertEqual(report["header"]["alignment_profile"], "amd64_selected_low_alignment")
        self.deny(lambda: self.analyze(_changed(188, 4, 256, data=data)))
        self.deny(
            lambda: self.analyze(
                _file(alignment=512, sections=[(32, 512, 512, 1024)], image_size=1024)
            )
        )

    def test_logical_virtual_size_is_distinct_from_raw_padding_and_zero_fill(self):
        for virtual, expected_fill, expected_padding in ((32, 0, 480), (512, 0, 0), (600, 88, 0)):
            report = self.analyze(_file(sections=[(virtual, 4096, 512, 512)])).to_dict()
            section = report["section_observations"][0]
            self.assertEqual(section["logical_virtual_end"], 4096 + virtual)
            self.assertEqual(section["raw_file_end"], 1024)
            self.assertEqual(section["declared_zero_fill_bytes"], expected_fill)
            self.assertEqual(section["raw_beyond_logical_bytes"], expected_padding)

    def test_zero_virtual_size_does_not_invent_a_loader_raw_size_fallback(self):
        report = self.analyze(_file(sections=[(0, 4097, 512, 512)])).to_dict()
        section = report["section_observations"][0]
        self.assertIsNone(section["logical_virtual_end"])
        self.assertIsNone(section["declared_zero_fill_bytes"])
        self.assertIsNone(section["raw_beyond_logical_bytes"])
        self.assertEqual(section["geometry_status"], "logical_size_unassessed")
        self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")

    def test_no_file_data_pointer_is_opaque_not_a_bogus_file_extent(self):
        report = self.analyze(_file(sections=[(32, 4096, 0, 0xFFFFFFFF)], data_size=512)).to_dict()
        section = report["section_observations"][0]
        self.assertEqual(section["raw_file_offset"], 0xFFFFFFFF)
        self.assertIsNone(section["raw_file_end"])
        self.assertEqual(section["declared_zero_fill_bytes"], 32)

    def test_reversed_nonoverlapping_raw_sections_cannot_claim_supported_order(self):
        forward = _file(sections=[(32, 4096, 512, 512), (32, 8192, 512, 1024)])
        self.assertEqual(
            self.analyze(forward).to_dict()["analysis_status"], "supported_layout_subset_consistent"
        )
        reverse = _file(sections=[(32, 4096, 512, 1024), (32, 8192, 512, 512)])
        self.deny(lambda: self.analyze(reverse))

    def test_logical_section_order_adjacency_extent_and_aligned_image_refuse(self):
        for sections in (
            [(32, 8192, 512, 512)],
            [(32, 4096, 512, 512), (32, 12288, 512, 1024)],
            [(32, 4096, 512, 512), (32, 4096, 512, 1024)],
            [(4097, 4096, 512, 512)],
            [(0xFFFFFFFF, 4096, 512, 512)],
        ):
            self.deny(lambda sections=sections: self.analyze(_file(sections=sections)))

    def test_nonempty_raw_extents_cannot_overlap_headers_each_other_or_truncate(self):
        for data in (
            _changed(412, 4, 0),
            _file()[:-1],
            _file(sections=[(32, 4096, 512, 512), (32, 8192, 512, 512)]),
            _changed(408, 4, 0xFFFFFE00),
            _changed(412, 4, 0xFFFFFE00),
        ):
            self.deny(lambda data=data: self.analyze(data))

    def test_unknown_machine_does_not_inherit_amd64_alignment_or_directory_mapping(self):
        data = _file(
            machine=0xAA64,
            alignment=3,
            file_alignment=5,
            image_size=8192,
            sections=[(32, 4097, 511, 513)],
            data_size=1024,
        )
        data = _changed(176, 8, 0x140000001, data=data)
        report = self.analyze(_directory(1, 4097, 8, data=data)).to_dict()
        self.assertEqual(report["header"]["alignment_profile"], "machine_unassessed")
        self.assertIsNone(report["directory_observations"][1]["file_backing_offset"])
        self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")

    def test_unknown_flags_subsystems_symbols_and_reserved_fields_remain_unassessed(self):
        for offset, width, value in (
            (150, 2, 0x8022),
            (222, 2, 1),
            (220, 2, 1),
            (140, 4, 512),
            (204, 4, 1),
            (256, 4, 1),
            (428, 4, 0xC0001040),
            (416, 4, 1),
            (424, 2, 1),
        ):
            report = self.analyze(_changed(offset, width, value)).to_dict()
            self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")
            self.assertTrue(report["unassessed_reasons"])
        data = _file(optional_size=248)
        self.assertEqual(self.analyze(data).to_dict()["header"]["optional_extension_bytes"], 8)

    def test_directory_unique_header_and_logical_raw_backing_are_only_envelopes(self):
        for address, size, expected in ((128, 8, 128), (4096, 8, 512), (4112, 16, 528)):
            report = self.analyze(_directory(1, address, size)).to_dict()
            directory = report["directory_observations"][1]
            self.assertEqual(directory["file_backing_offset"], expected)
            self.assertEqual(
                directory["geometry_status"], "unique_logical_raw_backing_contents_unassessed"
            )
            self.assertFalse(report["flags"]["directory_contents_validated"])

    def test_directory_zero_fill_raw_padding_and_cross_section_never_invent_backing(self):
        cases = (
            (_file(), 4128, 8),
            (_file(sections=[(600, 4096, 512, 512)]), 4600, 16),
            (
                _file(sections=[(4096, 4096, 4096, 512), (32, 8192, 512, 4608)], data_size=5120),
                8190,
                4,
            ),
        )
        for data, address, size in cases:
            report = self.analyze(_directory(1, address, size, data=data)).to_dict()
            self.assertIsNone(report["directory_observations"][1]["file_backing_offset"])
            self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")

    def test_partial_reserved_and_global_pointer_directory_declarations_are_distinct(self):
        report = self.analyze().to_dict()
        self.assertEqual(
            report["directory_observations"][4]["geometry_status"], "absent_declared_pair"
        )
        for index, address, size in (
            (1, 0, 8),
            (1, 4096, 0),
            (4, 1024, 0),
            (7, 0xFFFFFFFF, 0xFFFFFFFF),
            (15, 1, 1),
        ):
            report = self.analyze(_directory(index, address, size)).to_dict()
            self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")
            self.assertIsNone(report["directory_observations"][index]["file_backing_offset"])
        report = self.analyze(_directory(8, 4096, 0)).to_dict()
        self.assertEqual(
            report["directory_observations"][8]["geometry_status"],
            "declared_global_pointer_rva_only",
        )

    def test_nonempty_directory_rva_end_cannot_overflow_or_exceed_image(self):
        for address, size in ((0xFFFFFFFF, 2), (8190, 4)):
            self.deny(lambda address=address, size=size: self.analyze(_directory(1, address, size)))

    def test_certificate_directory_is_a_file_offset_even_beyond_image_rvas(self):
        report = self.analyze(_certificates(offset=9000)).to_dict()
        directory = report["directory_observations"][4]
        self.assertEqual(directory["address_kind"], "file_offset")
        self.assertEqual(directory["declared_end"], 9016)
        self.assertEqual(directory["file_backing_offset"], 9000)
        self.assertEqual(report["certificate_observations"][0]["occupied_file_end"], 9016)
        self.assertFalse(report["flags"]["certificate_payload_validated"])
        self.assertFalse(report["flags"]["authenticode_verified"])

    def test_certificate_rounded_walk_retains_lengths_without_inventing_payload_size(self):
        data = _certificates(((9, 0x200, 2), (16, 0x200, 2), (8, 0x100, 2)))
        report = self.analyze(data).to_dict()
        self.assertEqual(
            [row["dw_length"] for row in report["certificate_observations"]], [9, 16, 8]
        )
        self.assertEqual(
            [row["rounded_occupied_bytes"] for row in report["certificate_observations"]],
            [16, 16, 8],
        )
        self.assertEqual(
            [row["file_offset"] for row in report["certificate_observations"]], [1024, 1040, 1056]
        )
        self.assertEqual(report["directory_observations"][4]["size_raw"], 40)
        self.assertTrue(
            all("payload_bytes" not in row for row in report["certificate_observations"])
        )

    def test_certificate_truncation_overlap_alignment_lengths_and_count_refuse(self):
        data = _certificates()
        cases = (
            _directory(4, 1025, 8, data=data),
            _directory(4, 512, 8, data=data),
            _directory(4, 1024, 7, data=data),
            _directory(4, 1024, 15, data=data),
            _directory(4, 1024, 17, data=data),
            _changed(1024, 4, 7, data=data),
            _changed(1024, 4, 0xFFFFFFFF, data=data),
            _directory(4, 0xFFFFFFFF, 8, data=data),
        )
        for malformed in cases:
            self.deny(lambda malformed=malformed: self.analyze(malformed))
        accepted = _certificates(((8, 0x200, 2),) * 64)
        self.assertEqual(len(self.analyze(accepted).to_dict()["certificate_observations"]), 64)
        self.deny(lambda: self.analyze(_certificates(((8, 0x200, 2),) * 65)))

    def test_certificate_unknown_types_duplicate_envelopes_and_padding_are_opaque(self):
        data = _certificates(((9, 0xFFFF, 0xFFFF), (9, 0xFFFF, 0xFFFF)))
        data = _changed(1033, 1, 0xA5, data=data)
        report = self.analyze(data).to_dict()
        self.assertEqual(len(report["certificate_observations"]), 2)
        self.assertEqual(report["certificate_observations"][0]["certificate_type_hex"], "0xffff")
        self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")
        self.assertFalse(report["flags"]["certificate_signature_verified"])

    def test_actual_overlay_bytes_are_retained_addressed_and_never_authenticated(self):
        first = self.analyze(_file() + b"untrusted-overlay")
        second = self.analyze(_file() + b"untrusted-overlaY")
        report = first.to_dict()
        self.assertEqual(report["trailing_file_extent"], {"file_offset": 1024, "bytes": 17})
        self.assertNotEqual(first.analysis_sha256, second.analysis_sha256)
        self.assertEqual(
            base64.b64decode(report["source_model"]["pe_file_base64"]),
            _file() + b"untrusted-overlay",
        )

    def test_closed_native_model_and_scalar_aliases_refuse_without_hash(self):
        class String(str):
            pass

        class Integer(int):
            pass

        for source in (None, [], {}, _model() | {"extra": None}):
            self.deny(lambda source=source: m.analyze_supplied_pe32plus_layout(source))
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("schema_version", Integer(1)),
            ("source_id", String("synthetic-pe32plus")),
            ("source_id", ""),
            ("source_id", "a" * 65),
            ("source_id", "a\nb"),
            ("pe_file_base64", b"AAAA"),
        ):
            self.deny(
                lambda field=field, value=value: m.analyze_supplied_pe32plus_layout(
                    _model() | {field: value}
                )
            )

    def test_native_hooks_cycles_depth_queued_nodes_and_bigints_precede_copy(self):
        class Hook(dict):
            def items(self):
                raise AssertionError("Foreign mapping invoked")

        self.deny(lambda: m.analyze_supplied_pe32plus_layout(Hook(_model())))
        source = _model()
        source["extra"] = source
        deep = []
        for _ in range(17):
            deep = [deep]
        for extra in (source, deep, [None] * m.MAX_MODEL_NODES, 1 << 4096):
            with patch.object(m, "_clone") as clone:
                self.deny(
                    lambda extra=extra: m.analyze_supplied_pe32plus_layout(
                        _model() | {"extra": extra}
                    )
                )
                clone.assert_not_called()

    def test_canonical_base64_preflight_denies_oversize_and_invalid_spelling(self):
        for encoded in ("AAAA", "AAAA=", "A===", "!!!!", "A" * (m.MAX_BASE64_BYTES + 1)):
            with patch.object(m.base64, "b64decode") as decoder:
                self.deny(
                    lambda encoded=encoded: m.analyze_supplied_pe32plus_layout(
                        _model() | {"pe_file_base64": encoded}
                    )
                )
                decoder.assert_not_called()
        source = _model()
        source["pe_file_base64"] = source["pe_file_base64"][:-3] + "B=="
        self.deny(lambda: m.analyze_supplied_pe32plus_layout(source))

    def test_raw_native_byte_families_and_full_lexical_limits_precede_decoder(self):
        for value in (None, "{}", bytearray(b"{}"), b"", b"\xff", b" " * (m.MAX_MODEL_BYTES + 1)):
            self.deny(
                lambda value=value: m.analyze_supplied_pe32plus_layout_bytes(model_bytes=value)
            )
        for lexical in (
            "--1",
            "---1",
            "--0",
            "+1",
            "-",
            "1.0",
            "NaN",
            "9223372036854775808",
            "1" * 100,
        ):
            text = '{"schema_version":' + lexical + "}"
            with patch.object(m.json, "loads") as decoder:
                self.deny(
                    lambda text=text: m.analyze_supplied_pe32plus_layout_bytes(
                        model_bytes=text.encode("ascii")
                    )
                )
                decoder.assert_not_called()
        for text in ('{"x":"\\u0000"}', "[" * 16 + "0" + "]" * 16, '{"x":"unterminated}'):
            with patch.object(m.json, "loads") as decoder:
                self.deny(
                    lambda text=text: m.analyze_supplied_pe32plus_layout_bytes(
                        model_bytes=text.encode("ascii")
                    )
                )
                decoder.assert_not_called()

    def test_raw_duplicate_keys_and_noncanonical_report_text_refuse(self):
        for text in ('{"schema_version":1,"schema_version":1}', '{"x":{"a":1,"a":2}}'):
            self.deny(
                lambda text=text: m.analyze_supplied_pe32plus_layout_bytes(
                    model_bytes=text.encode("ascii")
                )
            )
        report = self.analyze()
        for text in (json.dumps(report.to_dict(), indent=2), report.to_json() + "\n", "{}"):
            self.deny(lambda text=text: m.Pe32PlusLayoutAnalysis.from_json(text))
        source = json.dumps(_model(), indent=2).replace("synthetic", "\\u0073ynthetic")
        self.assertEqual(
            m.analyze_supplied_pe32plus_layout_bytes(model_bytes=source.encode("ascii")).to_json(),
            report.to_json(),
        )

    def test_cohashed_false_geometry_flags_effects_ownership_and_source_refuse(self):
        original = self.analyze().to_dict()
        for kind in (
            "geometry",
            "promotion",
            "effect",
            "ownership",
            "source",
            "drop",
            "extra",
            "bool",
            "float",
        ):
            changed = copy.deepcopy(original)
            if kind == "geometry":
                changed["section_observations"][0]["logical_virtual_end"] += 1
            elif kind == "promotion":
                changed["flags"]["positive_use_approved"] = True
            elif kind == "effect":
                changed["effects"]["process"] = "execute"
            elif kind == "ownership":
                changed["profile_id"] = "AOE-GB-D08-S17"
            elif kind == "source":
                alternate = _model(_changed(400, 4, 64))
                changed["source_model"] = alternate
                changed["source_model_sha256"] = (
                    "sha256:"
                    + hashlib.sha256(
                        b"sunderkey.offline-pe32plus-model.v1\n"
                        + _canonical(alternate).encode("ascii")
                    ).hexdigest()
                )
                changed["source_file_sha256"] = (
                    "sha256:"
                    + hashlib.sha256(base64.b64decode(alternate["pe_file_base64"])).hexdigest()
                )
            elif kind == "drop":
                changed["directory_observations"].pop()
            elif kind == "extra":
                changed["extra"] = None
            elif kind == "bool":
                changed["header"]["section_count"] = True
            else:
                changed["header"]["section_count"] = 1.0
            changed = _rehash(changed)
            self.deny(lambda changed=changed: m.Pe32PlusLayoutAnalysis.from_dict(changed))

    def test_separate_original_verifier_rejects_other_valid_source_not_just_hash_tamper(self):
        alternate = _model() | {"source_id": "other-valid-source"}
        report = m.analyze_supplied_pe32plus_layout(alternate)
        self.assertEqual(
            m.Pe32PlusLayoutAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(m.Pe32PlusLayoutAnalysisError):
            m.verify_supplied_pe32plus_layout_analysis(report, model=_model())
        self.assertEqual(
            m.verify_supplied_pe32plus_layout_analysis(report, model=alternate).to_json(),
            report.to_json(),
        )

    def test_missing_report_fields_wrong_family_and_late_native_mutation_refuse(self):
        report = self.analyze()
        for wrong in (
            None,
            {},
            object(),
            report.to_json(),
            object.__new__(m.Pe32PlusLayoutAnalysis),
        ):
            self.deny(
                lambda wrong=wrong: m.verify_supplied_pe32plus_layout_analysis(
                    wrong, model=_model()
                )
            )
        for field in (
            "source_model",
            "source_file_sha256",
            "source_model_sha256",
            "analysis_id",
            "analysis_sha256",
        ):
            changed = report.to_dict()
            changed.pop(field)
            self.deny(lambda changed=changed: m.Pe32PlusLayoutAnalysis.from_dict(changed))
        changed = report.to_dict()
        changed["flags"]["full_pe_validity_verified"] = True
        text = _canonical(_rehash(changed))
        object.__setattr__(report, "document_json", text)
        for operation in (
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_pe32plus_layout_analysis(report, model=_model()),
        ):
            self.deny(operation)

    def test_all_eight_public_passes_fund_remaining_work_before_any_hash(self):
        report = self.analyze()
        source, text, document = _model(), report.to_json(), report.to_dict()
        operations = (
            lambda: m.analyze_supplied_pe32plus_layout(source),
            lambda: m.analyze_supplied_pe32plus_layout_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            lambda: m.Pe32PlusLayoutAnalysis(text),
            lambda: m.Pe32PlusLayoutAnalysis.from_dict(document),
            lambda: m.Pe32PlusLayoutAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_pe32plus_layout_analysis(report, model=source),
        )
        real_charge, real_hash = m._Budget.charge, m.hashlib.sha256
        for index, operation in enumerate(operations):
            budgets, events = [], []

            def counted(budget, amount, budgets=budgets, events=events):
                if all(budget is not item for item in budgets):
                    budgets.append(budget)
                events.append("charge")
                real_charge(budget, amount)

            def hashed(*args, events=events, **kwargs):
                events.append("hash")
                return real_hash(*args, **kwargs)

            with (
                patch.object(m._Budget, "charge", counted),
                patch.object(m.hashlib, "sha256", hashed),
            ):
                operation()
            self.assertEqual(len(budgets), 1)
            self.assertNotIn("charge", events[events.index("hash") :])
            self.assertEqual(events.count("hash"), 6 if index == 7 else 3)
            for delta in (-1, 0):
                ceiling = budgets[0].used + delta

                def capped(budget, amount, ceiling=ceiling):
                    if amount > ceiling - budget.used:
                        raise m.Pe32PlusLayoutAnalysisError("Independent exact work ceiling")
                    real_charge(budget, amount)

                with patch.object(m._Budget, "charge", capped):
                    if delta < 0:
                        self.deny(operation)
                    else:
                        operation()

    def test_retained_document_node_and_work_bounds_deny_before_any_digest(self):
        for constant, value in (
            ("MAX_REPORT_BYTES", 1024),
            ("MAX_REPORT_NODES", 128),
            ("MAX_WORK", 1),
        ):
            with patch.object(m, constant, value):
                self.deny(lambda: self.analyze())
        document = self.analyze().to_dict()
        with patch.object(m, "MAX_REPORT_BYTES", len(_canonical(document)) - 1):
            self.deny(lambda: m.Pe32PlusLayoutAnalysis.from_dict(document))

    def test_actual_file_byte_ceiling_and_plus_one_precede_decode(self):
        data = _file() + bytes(m.MAX_FILE_BYTES - len(_file()))
        self.assertEqual(self.analyze(data).to_dict()["source_file_bytes"], m.MAX_FILE_BYTES)
        with patch.object(m.base64, "b64decode") as decoder:
            self.deny(lambda: self.analyze(data + b"x"))
            decoder.assert_not_called()

    def test_independent_small_section_padding_and_mapping_grid(self):
        controls = 0
        for virtual in (1, 32, 511, 512, 513, 1024):
            for raw_size in (0, 512, 1024):
                for delta in (0, 1, 31, 510, 511, 512, 1023):
                    data = _file(sections=[(virtual, 4096, raw_size, 512 if raw_size else 0)])
                    report = self.analyze(_directory(1, 4096 + delta, 1, data=data)).to_dict()
                    directory = report["directory_observations"][1]
                    expected = 512 + delta if delta < min(virtual, raw_size) else None
                    self.assertEqual(directory["file_backing_offset"], expected)
                    self.assertFalse(report["flags"]["directory_contents_validated"])
                    controls += 1
        self.assertEqual(controls, 126)


if __name__ == "__main__":
    unittest.main()

"""Independent inert ELF encoders and replay/limit controls."""

import base64
import copy
import dataclasses
import hashlib
import json
import struct
import unittest
from unittest.mock import patch

from sunderkey import offline_elf64_layout_analysis as m


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _file(*, programs=1, kind=2):
    start = 64 + programs * 56 + 3 * 64
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9),
        kind,
        62,
        1,
        0x4000,
        64,
        64 + programs * 56,
        0,
        64,
        56,
        programs,
        64,
        3,
        0,
    )
    program = b"".join(
        struct.pack("<IIQQQQQQ", 1, 6, start, 0x4000 + 4 * i, 0, 4, 8, 4) for i in range(programs)
    )
    regular = struct.pack("<IIQQQQIIQQ", 0, 1, 2, 0x4000, start, 4, 0, 0, 4, 0)
    nobits = struct.pack("<IIQQQQIIQQ", 0, 8, 2, 0x4004, start + 4, 4, 0, 0, 4, 0)
    return header + program + bytes(64) + regular + nobits + b"DATA"


def _model(data=None):
    return {
        "schema_version": 1,
        "source_id": "synthetic-elf64",
        "elf_file_base64": base64.b64encode(_file() if data is None else data).decode("ascii"),
    }


def _changed(offset, width, value, *, data=None):
    result = bytearray(_file() if data is None else data)
    struct.pack_into("<" + width, result, offset, value)
    return bytes(result)


def _rehash(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = (
        "sha256:"
        + hashlib.sha256(
            b"sunderkey.offline-elf64-layout-analysis.v1\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "ELA-" + digest[7:39].upper()
    return document


class Elf64LayoutAnalysisTests(unittest.TestCase):
    def analyze(self, data=None):
        return m.analyze_supplied_elf64_layout(_model(data))

    def deny(self, operation):
        with patch.object(m.hashlib, "sha256") as digest:
            with self.assertRaises(m.Elf64LayoutAnalysisError):
                operation()
            digest.assert_not_called()

    def test_independent_literal_fixture_and_golden_domains(self):
        self.assertEqual(m.component_fixture(), _model())
        report = self.analyze().to_dict()
        self.assertEqual(report["source_file_bytes"], 316)
        self.assertEqual(report["analysis_id"], "ELA-FB5174CB553DB919349588D8ACCD4F1B")
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:633dd628bfe58bbaaa0a9bb4d9c862d146fc8c389aa480098dc054e28fdd3703",
        )
        self.assertEqual(
            report["source_file_sha256"],
            "sha256:78418ead13916081cf1088b6e2473643aa7053d27b1a3f2a4e16495917f92296",
        )
        expected = (
            "sha256:"
            + hashlib.sha256(
                b"sunderkey.offline-elf64-model.v1\n" + _canonical(_model()).encode("ascii")
            ).hexdigest()
        )
        self.assertEqual(expected, report["source_model_sha256"])
        self.assertEqual(report["analysis_status"], "supported_layout_subset_consistent")
        self.assertEqual(report["unassessed_reasons"], [])

    def test_existing_profile_ownership_and_no_runtime_or_authority_claim(self):
        report = self.analyze().to_dict()
        self.assertEqual(report["component_id"], "linux_supplied_elf64_layout")
        self.assertEqual(report["profile_id"], "AOE-GB-D08-S17")
        self.assertEqual(report["wave_id"], "IW2-003")
        self.assertEqual(report["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(report["independent_validator_id"], "AOE-HQ-19")
        self.assertTrue(all(value is False for value in report["flags"].values()))
        self.assertEqual(set(report["effects"].values()), {"none"})

    def test_all_eight_public_forms_replay_the_complete_supplied_source(self):
        report = self.analyze()
        text = report.to_json()
        document = report.to_dict()
        outputs = (
            m.analyze_supplied_elf64_layout(_model()),
            m.analyze_supplied_elf64_layout_bytes(model_bytes=_canonical(_model()).encode("ascii")),
            m.Elf64LayoutAnalysis(text),
            m.Elf64LayoutAnalysis.from_dict(document),
            m.Elf64LayoutAnalysis.from_json(text),
            m.verify_supplied_elf64_layout_analysis(report, model=_model()),
        )
        for output in outputs:
            self.assertEqual(output.to_json(), text)
        self.assertEqual(document["source_model"], _model())

    def test_input_aliases_and_nested_exports_are_detached(self):
        source = _model()
        report = m.analyze_supplied_elf64_layout(source)
        original = report.to_json()
        source["source_id"] = "mutated"
        exported = report.to_dict()
        exported["program_observations"][0]["geometry_status"] = "mutated"
        exported["source_model"]["source_id"] = "mutated"
        self.assertEqual(report.to_json(), original)
        fixture = m.component_fixture()
        fixture["source_id"] = "mutated"
        self.assertEqual(m.component_fixture(), _model())

    def test_wrapper_is_frozen_and_exact_family(self):
        report = self.analyze()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.document_json = "{}"
        for wrong in (None, {}, object(), report.to_json()):
            self.deny(
                lambda wrong=wrong: m.verify_supplied_elf64_layout_analysis(wrong, model=_model())
            )

    def test_elf32_big_endian_other_magic_versions_and_header_sizes_refuse(self):
        cases = [
            _changed(4, "B", 1),
            _changed(5, "B", 2),
            _changed(6, "B", 2),
            _changed(20, "I", 2),
            _changed(52, "H", 63),
            b"not ELF",
            _changed(0, "I", 0),
            _file()[:63],
        ]
        for data in cases:
            self.deny(lambda data=data: self.analyze(data))

    def test_header_width_counts_extended_indices_and_table_ranges_refuse(self):
        cases = [
            (54, "H", 55),
            (58, "H", 63),
            (56, "H", 129),
            (60, "H", 1025),
            (60, "H", 0),
            (62, "H", 0xFFFF),
            (62, "H", 3),
            (32, "Q", 63),
            (40, "Q", 80),
            (32, "Q", 2**64 - 1),
            (40, "Q", 2**64 - 1),
        ]
        for offset, width, value in cases:
            self.deny(
                lambda offset=offset, width=width, value=value: self.analyze(
                    _changed(offset, width, value)
                )
            )

    def test_initial_section_entry_ordinary_profile_is_exact(self):
        for offset, width in (
            (120, "I"),
            (124, "I"),
            (128, "Q"),
            (136, "Q"),
            (144, "Q"),
            (152, "Q"),
            (160, "I"),
            (164, "I"),
            (168, "Q"),
            (176, "Q"),
        ):
            self.deny(lambda offset=offset, width=width: self.analyze(_changed(offset, width, 1)))

    def test_pt_null_retains_undefined_fields_without_file_or_vm_claim(self):
        data = _changed(64, "I", 0)
        for offset in (72, 80, 88, 96, 104, 112):
            data = _changed(offset, "Q", 2**64 - 1, data=data)
        item = self.analyze(data).to_dict()["program_observations"][0]
        self.assertFalse(item["file_backed"])
        self.assertIsNone(item["file_end_hex"])
        self.assertIsNone(item["memory_end_hex"])
        self.assertEqual(item["geometry_status"], "inactive_fields_uninterpreted")

    def test_nobits_has_no_file_extent_even_with_large_conceptual_offset(self):
        report = self.analyze(_changed(272, "Q", 2**64 - 1)).to_dict()
        item = report["section_observations"][2]
        self.assertEqual(item["file_offset_hex"], "0xffffffffffffffff")
        self.assertIsNone(item["file_end_hex"])
        self.assertFalse(item["file_backed"])
        self.assertEqual(item["memory_end_hex"], "0x0000000000004008")

    def test_noninitial_null_section_undefined_fields_are_not_interpreted(self):
        data = _changed(252, "I", 0)
        for offset in (256, 264, 272, 280, 296, 304):
            data = _changed(offset, "Q", 2**64 - 1, data=data)
        item = self.analyze(data).to_dict()["section_observations"][2]
        self.assertFalse(item["file_backed"])
        self.assertIsNone(item["memory_end_hex"])

    def test_load_size_alignment_and_address_order_are_checked(self):
        for offset, value in ((96, 9), (80, 0x4001), (112, 3), (112, 16)):
            self.deny(lambda offset=offset, value=value: self.analyze(_changed(offset, "Q", value)))
        self.deny(lambda: self.analyze(_changed(136, "Q", 0x3FFF, data=_file(programs=2))))

    def test_overlapping_load_segments_are_not_blanket_rejected(self):
        items = self.analyze(_file(programs=2)).to_dict()["program_observations"]
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["file_offset_hex"], items[1]["file_offset_hex"])
        self.assertEqual(items[0]["memory_end_hex"], "0x0000000000004008")

    def test_section_alignment_is_address_not_file_offset_alignment(self):
        data = _changed(208, "Q", 313)
        data = _changed(216, "Q", 3, data=data)
        report = self.analyze(data).to_dict()
        self.assertEqual(report["section_observations"][1]["file_offset_hex"], "0x0000000000000139")
        self.deny(lambda: self.analyze(_changed(200, "Q", 0x4001)))
        self.deny(lambda: self.analyze(_changed(232, "Q", 3)))

    def test_known_ranges_cannot_overflow_uint64_or_truncate_supplied_bytes(self):
        for offset in (72, 80, 200, 208, 264):
            self.deny(lambda offset=offset: self.analyze(_changed(offset, "Q", 2**64 - 1)))
        self.deny(lambda: self.analyze(_file()[:-1]))

    def test_sections_do_not_overlap_headers_tables_or_each_other(self):
        self.deny(lambda: self.analyze(_changed(208, "Q", 60)))
        self.deny(lambda: self.analyze(_changed(208, "Q", 120)))
        self.deny(lambda: self.analyze(_changed(272, "Q", 312, data=_changed(252, "I", 1))))

    def test_uint64_high_addresses_remain_hex_without_signed64_coercion(self):
        data = _changed(80, "Q", 2**63)
        data = _changed(200, "Q", 2**63, data=data)
        data = _changed(264, "Q", 2**63 + 4, data=data)
        report = self.analyze(data).to_dict()
        self.assertEqual(report["program_observations"][0]["memory_end_hex"], "0x8000000000000008")
        self.assertEqual(report["section_observations"][2]["address_hex"], "0x8000000000000004")

    def test_unknown_file_types_programs_flags_and_abi_metadata_stay_unassessed(self):
        cases = (
            _file(kind=1),
            _file(kind=4),
            _changed(64, "I", 3),
            _changed(68, "I", 0x80000006),
            _changed(192, "Q", 0x1002),
            _changed(188, "I", 0x70000001),
            _changed(7, "B", 3),
            _changed(48, "I", 1),
            _changed(224, "I", 1),
        )
        for data in cases:
            report = self.analyze(data).to_dict()
            self.assertEqual(report["analysis_status"], "layout_semantics_unassessed")
            self.assertTrue(report["unassessed_reasons"])
            self.assertFalse(report["flags"]["loader_compatibility_verified"])

    def test_unknown_program_still_checks_its_declared_nonempty_file_extent(self):
        data = _changed(64, "I", 3)
        self.deny(lambda: self.analyze(_changed(72, "Q", 2**64 - 1, data=data)))

    def test_no_tables_and_zero_length_extents_do_not_invent_bytes(self):
        data = bytearray(_file()[:64])
        for offset in (32, 40):
            struct.pack_into("<Q", data, offset, 0)
        for offset in (54, 56, 58, 60, 62):
            struct.pack_into("<H", data, offset, 0)
        report = self.analyze(bytes(data)).to_dict()
        self.assertEqual(report["program_observations"], [])
        self.assertEqual(report["section_observations"], [])
        data = _changed(96, "Q", 0)
        data = _changed(72, "Q", 2**64 - 1, data=data)
        data = _changed(112, "Q", 0, data=data)
        self.assertIsNone(self.analyze(data).to_dict()["program_observations"][0]["file_end_hex"])

    def test_native_closed_fields_exact_types_and_source_identity_refuse(self):
        cases = [None, [], {"schema_version": 1}, _model() | {"extra": None}]
        for field, value in (
            ("schema_version", True),
            ("source_id", ""),
            ("source_id", "a\nb"),
            ("source_id", "a" * 65),
            ("elf_file_base64", b"AAAA"),
        ):
            cases.append(_model() | {field: value})
        for source in cases:
            self.deny(lambda source=source: m.analyze_supplied_elf64_layout(source))

    def test_native_hooks_cycles_depth_and_queued_nodes_precede_clone(self):
        class Hook(dict):
            def items(self):
                raise AssertionError("Foreign mapping hook invoked")

        self.deny(lambda: m.analyze_supplied_elf64_layout(Hook(_model())))
        source = _model()
        source["extra"] = source
        with patch.object(m, "_clone") as clone:
            self.deny(lambda: m.analyze_supplied_elf64_layout(source))
            clone.assert_not_called()
        deep = []
        for _ in range(17):
            deep = [deep]
        for extra in (deep, [None] * m.MAX_MODEL_NODES):
            with patch.object(m, "_clone") as clone:
                self.deny(
                    lambda extra=extra: m.analyze_supplied_elf64_layout(_model() | {"extra": extra})
                )
                clone.assert_not_called()

    def test_canonical_base64_and_declared_size_precede_decode(self):
        for encoded in ("AAAA=", "AAAA", "A===", "!!!!", "a" * (m.MAX_BASE64_BYTES + 1)):
            with patch.object(m.base64, "b64decode") as decoder:
                self.deny(
                    lambda encoded=encoded: m.analyze_supplied_elf64_layout(
                        _model() | {"elf_file_base64": encoded}
                    )
                )
                decoder.assert_not_called()
        self.deny(
            lambda: m.analyze_supplied_elf64_layout(
                _model() | {"elf_file_base64": _model()["elf_file_base64"][:-3] + "R=="}
            )
        )

    def test_raw_equivalent_whitespace_and_escapes_keep_model_identity(self):
        text = json.dumps(_model(), indent=2).replace("synthetic", "\\u0073ynthetic")
        report = m.analyze_supplied_elf64_layout_bytes(model_bytes=text.encode("ascii"))
        self.assertEqual(report.to_json(), self.analyze().to_json())

    def test_raw_duplicate_keys_numeric_families_and_lexical_limits_precede_decoder(self):
        valid = _canonical(_model())
        cases = (
            '{"schema_version":1,"schema_version":1}',
            '{"a":{"x":1,"x":2}}',
            valid.replace('"schema_version":1', '"schema_version":1.0'),
            valid.replace('"schema_version":1', '"schema_version":NaN'),
            valid.replace('"schema_version":1', '"schema_version":9223372036854775808'),
            "[" * 17 + "0" + "]" * 17,
            '{"x":"\\u0000"}',
        )
        for text in cases:
            self.deny(
                lambda text=text: m.analyze_supplied_elf64_layout_bytes(
                    model_bytes=text.encode("ascii")
                )
            )
        for text in ('{"x":1.0}', "[" * 17 + "0" + "]" * 17):
            with patch.object(m.json, "loads") as decoder:
                self.deny(
                    lambda text=text: m.analyze_supplied_elf64_layout_bytes(
                        model_bytes=text.encode("ascii")
                    )
                )
                decoder.assert_not_called()

    def test_raw_input_family_and_model_size_are_closed(self):
        for content in (None, "", bytearray(b"{}"), b"", b"\xff", b" " * (m.MAX_MODEL_BYTES + 1)):
            self.deny(
                lambda content=content: m.analyze_supplied_elf64_layout_bytes(model_bytes=content)
            )

    def test_source_substitution_coherent_alternate_requires_separate_original(self):
        alternate = _model() | {"source_id": "alternate"}
        report = m.analyze_supplied_elf64_layout(alternate)
        self.assertEqual(
            m.Elf64LayoutAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        with self.assertRaises(m.Elf64LayoutAnalysisError):
            m.verify_supplied_elf64_layout_analysis(report, model=_model())
        accepted = m.verify_supplied_elf64_layout_analysis(report, model=alternate)
        self.assertEqual(accepted.to_json(), report.to_json())

    def test_cohashed_false_geometry_source_promotion_and_dropped_rows_refuse(self):
        original = self.analyze().to_dict()
        for kind in ("geometry", "source", "promotion", "drop", "extra"):
            changed = copy.deepcopy(original)
            if kind == "geometry":
                changed["program_observations"][0]["memory_end_hex"] = "0x0000000000004009"
            elif kind == "source":
                changed["source_model"]["elf_file_base64"] = _model(_changed(80, "Q", 0x5000))[
                    "elf_file_base64"
                ]
                changed["source_model_sha256"] = (
                    "sha256:"
                    + hashlib.sha256(
                        b"sunderkey.offline-elf64-model.v1\n"
                        + _canonical(changed["source_model"]).encode("ascii")
                    ).hexdigest()
                )
                changed["source_file_sha256"] = (
                    "sha256:"
                    + hashlib.sha256(
                        base64.b64decode(changed["source_model"]["elf_file_base64"])
                    ).hexdigest()
                )
            elif kind == "promotion":
                changed["flags"]["positive_use_approved"] = True
            elif kind == "drop":
                changed["section_observations"].pop()
            else:
                changed["extra"] = None
            with self.assertRaises(m.Elf64LayoutAnalysisError):
                m.Elf64LayoutAnalysis.from_dict(_rehash(changed))

    def test_reports_require_complete_canonical_text_addresses_and_embedded_source(self):
        report = self.analyze()
        for text in (json.dumps(report.to_dict(), indent=2), report.to_json() + "\n", "{}"):
            with self.assertRaises(m.Elf64LayoutAnalysisError):
                m.Elf64LayoutAnalysis.from_json(text)
        document = report.to_dict()
        for key in (
            "source_model",
            "source_file_sha256",
            "source_model_sha256",
            "analysis_id",
            "analysis_sha256",
        ):
            changed = copy.deepcopy(document)
            changed.pop(key)
            with self.assertRaises(m.Elf64LayoutAnalysisError):
                m.Elf64LayoutAnalysis.from_dict(changed)

    def test_each_public_form_funds_complete_work_before_any_digest(self):
        source = _model()
        report = self.analyze()
        document, text = report.to_dict(), report.to_json()
        operations = (
            lambda: m.analyze_supplied_elf64_layout(source),
            lambda: m.analyze_supplied_elf64_layout_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            lambda: m.Elf64LayoutAnalysis(text),
            lambda: m.Elf64LayoutAnalysis.from_dict(document),
            lambda: m.Elf64LayoutAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_elf64_layout_analysis(report, model=source),
        )
        real_charge, real_digest = m._Budget.charge, m.hashlib.sha256
        for operation in operations:
            budgets, events = [], []

            def counted(budget, amount, budgets=budgets, events=events):
                if all(budget is not item for item in budgets):
                    budgets.append(budget)
                events.append("charge")
                real_charge(budget, amount)

            def digest(*args, events=events, **kwargs):
                events.append("digest")
                return real_digest(*args, **kwargs)

            with (
                patch.object(m._Budget, "charge", counted),
                patch.object(m.hashlib, "sha256", digest),
            ):
                operation()
            self.assertEqual(len(budgets), 1)
            first = events.index("digest")
            self.assertNotIn("charge", events[first:])
            self.assertEqual(events.count("digest"), 6 if operation is operations[-1] else 3)
            needed = budgets[0].used
            for delta in (-1, 0):
                cap = needed + delta

                def capped(budget, amount, cap=cap):
                    if amount > cap - budget.used:
                        raise m.Elf64LayoutAnalysisError("Independent exact work ceiling")
                    real_charge(budget, amount)

                with patch.object(m._Budget, "charge", capped):
                    if delta < 0:
                        self.deny(operation)
                    else:
                        operation()

    def test_reduced_report_and_retained_limits_deny_before_digest(self):
        for constant, limit in (
            ("MAX_REPORT_BYTES", 1_024),
            ("MAX_REPORT_NODES", 128),
            ("MAX_WORK", 1),
        ):
            with patch.object(m, constant, limit):
                self.deny(lambda: self.analyze())

    def test_actual_file_byte_limit_and_plus_one_precede_oversized_decode(self):
        data = _file() + bytes(m.MAX_FILE_BYTES - len(_file()))
        report = self.analyze(data).to_dict()
        self.assertEqual(report["source_file_bytes"], m.MAX_FILE_BYTES)
        with patch.object(m.base64, "b64decode") as decoder:
            self.deny(lambda: self.analyze(data + b"x"))
            decoder.assert_not_called()

    def test_independent_load_geometry_grid(self):
        cases = 0
        for file_size in range(5):
            for memory_size in range(5):
                for address in (0x4000, 0x4001):
                    for alignment in (0, 1, 2, 3, 4, 8):
                        data = _file()
                        for offset, value in (
                            (96, file_size),
                            (104, memory_size),
                            (80, address),
                            (112, alignment),
                        ):
                            data = _changed(offset, "Q", value, data=data)
                        expected = file_size <= memory_size and (
                            alignment in (0, 1)
                            or (alignment in (2, 4, 8) and address % alignment == 312 % alignment)
                        )
                        if expected:
                            self.analyze(data)
                        else:
                            self.deny(lambda data=data: self.analyze(data))
                        cases += 1
        self.assertEqual(cases, 300)


if __name__ == "__main__":
    unittest.main()

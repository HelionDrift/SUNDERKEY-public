"""Independent manual Mach-O64 bytes and declared-layout/replay controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_macho_analysis as m


def _u(value, width=4, *, signed=False):
    return value.to_bytes(width, "little", signed=signed)


def _name(value):
    return value + b"\0" * (16 - len(value))


def _section(fields):
    return (
        _name(fields.get("name", b"__data"))
        + _name(fields.get("segment_name", b"__DATA"))
        + _u(fields["address"], 8)
        + _u(fields["size"], 8)
        + b"".join(
            _u(fields.get(key, 0))
            for key in (
                "offset",
                "align",
                "reloff",
                "nreloc",
                "flags",
                "reserved1",
                "reserved2",
                "reserved3",
            )
        )
    )


def _command(code, payload=b""):
    padded = payload + b"\0" * (-len(payload) % 8)
    return _u(code) + _u(8 + len(padded)) + padded


def _file(
    *,
    file_type=1,
    sections=None,
    flags=0,
    name=b"",
    address=0,
    vm_size=None,
    file_offset=None,
    file_size=None,
    uuid=False,
    other=(),
    payload=b"DATA",
    target_size=None,
    commands=None,
):
    """Independent field-by-field encoder; never uses a leaf parser or struct layout."""
    declarations = [{"size": 4, "align": 2}] if sections is None else list(sections)
    tail = ([_command(0x1B, bytes(range(16)))] if uuid else []) + list(other)
    command_bytes = 72 + 80 * len(declarations) + sum(map(len, tail))
    begin = 32 + command_bytes
    start = (begin if file_type == 1 else 0) if file_offset is None else file_offset
    length = (
        (len(payload) if file_type == 1 else begin + len(payload))
        if file_size is None
        else file_size
    )
    vm_size = length if vm_size is None else vm_size
    records = []
    for index, declaration in enumerate(declarations):
        row = {
            "address": address + (begin - start) + 4 * index,
            "offset": begin + 4 * index,
            **declaration,
        }
        records.append(_section(row))
    segment = (
        _u(0x19)
        + _u(72 + 80 * len(records))
        + _name(name)
        + _u(address, 8)
        + _u(vm_size, 8)
        + _u(start, 8)
        + _u(length, 8)
        + _u(7, signed=True)
        + _u(3, signed=True)
        + _u(len(records))
        + _u(flags)
        + b"".join(records)
    )
    actual_commands = [segment, *tail] if commands is None else list(commands)
    size = sum(map(len, actual_commands))
    header = (
        b"\xcf\xfa\xed\xfe"
        + _u(0x0100000C, signed=True)
        + _u(0, signed=True)
        + _u(file_type)
        + _u(len(actual_commands))
        + _u(size)
        + _u(0)
        + _u(0)
    )
    data = header + b"".join(actual_commands) + payload
    if target_size is not None:
        data += b"\0" * (target_size - len(data))
    return data


def _model(data=None, source_id="synthetic-macho64"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "macho_file_base64": base64.b64encode(_file() if data is None else data).decode("ascii"),
    }


def _change(data, offset, value, width=4):
    result = bytearray(data)
    result[offset : offset + width] = _u(value, width)
    return bytes(result)


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
            m.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
        ).hexdigest()
    )
    document["analysis_sha256"] = digest
    document["analysis_id"] = "MCA-" + digest[7:39].upper()
    return document


class MachOAnalysisTests(unittest.TestCase):
    def analyze(self, data=None):
        return m.analyze_supplied_macho_layout(_model(data))

    def deny(self, operation, *, before_hash=True, before_decoder=False):
        with patch.object(m.hashlib, "sha256", wraps=m.hashlib.sha256) as digest:
            if before_decoder:
                with patch.object(m.json, "loads", wraps=m.json.loads) as decoder:
                    with self.assertRaises(m.MachOAnalysisError):
                        operation()
                    decoder.assert_not_called()
            else:
                with self.assertRaises(m.MachOAnalysisError):
                    operation()
            if before_hash:
                digest.assert_not_called()

    def test_public_fixture_has_independent_literal_bytes_and_golden(self):
        self.assertEqual(m.component_fixture(), _model())
        report = self.analyze()
        document = report.to_dict()
        self.assertEqual(document["source_file_bytes"], 188)
        self.assertEqual(document["header"]["commands_end_offset"], 184)
        self.assertEqual(document["analysis_status"], "supported_layout_subset_consistent")
        self.assertEqual(
            document["segment_observations"][0]["sections"][0]["file_end"], "0x00000000000000bc"
        )
        self.assertEqual(document["analysis_id"], "MCA-B483D07354A521FE0B2D95415A832051")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:b483d07354a521fe0b2d95415a832051b829859a054df519838f923f0b31486a",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:031a34c99aff789d8c46cd0ddf0a8b7fb0914557baa1cb29d6bbfc1fa5b9016d",
        )
        self.assertEqual(
            document["source_file_sha256"],
            "sha256:c4a9316bf97b6f99c4e311875423fb9f30e9d2b856bfb0a6fc443398830badbc",
        )
        self.assertEqual((len(_canonical(_model())), len(report.to_json())), (327, 5090))

    def test_existing_ownership_and_no_loader_signature_authority_claim(self):
        document = self.analyze().to_dict()
        self.assertEqual(document["component_id"], "ios_supplied_macho64_layout")
        self.assertEqual(document["profile_id"], "AOE-GB-D08-S05")
        self.assertEqual(document["capability_id"], "army.gb.d08.s05")
        self.assertEqual(document["vector_id"], "AV-GB-D08-S05-01")
        self.assertEqual(document["work_package_id"], "IWP2-AOE-GB-D08-S05")
        self.assertEqual(document["wave_id"], "IW2-009")
        self.assertEqual(document["commander_id"], "AOE-GB-D08-CMD")
        self.assertEqual(document["group_owner_id"], "AOE-HQ-04")
        self.assertEqual(document["independent_validator_id"], "AOE-HQ-19")
        self.assertEqual(
            document["primary_source_revision"], "e6231be02a03711ca404e5121a151b24afbff733"
        )
        self.assertEqual(set(document["flags"].values()), {False})
        self.assertEqual(set(document["effects"].values()), {"none"})

    def test_independent_model_file_and_report_domain_addresses(self):
        source = _model()
        document = self.analyze().to_dict()
        self.assertEqual(
            document["source_file_sha256"], "sha256:" + hashlib.sha256(_file()).hexdigest()
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:"
            + hashlib.sha256(
                m.MODEL_DOMAIN.encode("ascii") + b"\n" + _canonical(source).encode("ascii")
            ).hexdigest(),
        )
        self.assertEqual(_readdress(copy.deepcopy(document)), document)

    def test_all_roundtrip_entrypoints_replay_exact_source(self):
        source = _model()
        report = self.analyze()
        text, document = report.to_json(), report.to_dict()
        for actual in (
            m.MachOAnalysis(text),
            m.MachOAnalysis.from_dict(document),
            m.MachOAnalysis.from_json(text),
            m.analyze_supplied_macho_layout_bytes(model_bytes=_canonical(source).encode("ascii")),
            m.verify_supplied_macho_layout_analysis(report, model=source),
        ):
            self.assertEqual(actual.to_json(), text)
            self.assertEqual(actual.to_dict(), document)

    def test_native_intake_and_nested_exports_are_detached(self):
        source = _model()
        before = copy.deepcopy(source)
        report = m.analyze_supplied_macho_layout(source)
        self.assertEqual(source, before)
        source["source_id"] = "changed"
        document = report.to_dict()
        document["segment_observations"][0]["sections"][0]["name_hex"] = "0" * 32
        document["source_model"]["source_id"] = "changed"
        self.assertEqual(report.to_dict()["source_model"], before)
        self.assertEqual(
            report.to_dict()["segment_observations"][0]["sections"][0]["name_hex"],
            _name(b"__data").hex(),
        )
        first = m.component_fixture()
        first["source_id"] = "changed"
        self.assertEqual(m.component_fixture(), before)

    def test_frozen_wrapper_and_exact_family(self):
        report = self.analyze()
        with self.assertRaises(FrozenInstanceError):
            report.document_json = "{}"
        self.assertEqual(report.analysis_id, report.to_dict()["analysis_id"])
        self.assertEqual(report.analysis_sha256, report.to_dict()["analysis_sha256"])

    def test_executable_first_segment_may_contain_header_commands(self):
        document = self.analyze(_file(file_type=2)).to_dict()
        segment = document["segment_observations"][0]
        self.assertTrue(segment["contains_header_and_commands"])
        self.assertEqual(segment["file_offset"], "0x0000000000000000")
        self.assertEqual(segment["sections"][0]["file_offset"], 184)
        self.assertEqual(document["analysis_status"], "supported_layout_subset_consistent")

    def test_object_unnamed_segment_does_not_require_named_section_equality(self):
        segment = self.analyze().to_dict()["segment_observations"][0]
        self.assertEqual(segment["name_hex"], "0" * 32)
        self.assertFalse(segment["sections"][0]["declared_segment_name_matches"])
        self.assertEqual(segment["geometry_check"], "ordinary_subset_checked")

    def test_all_sixteen_name_bytes_retained_without_normalization(self):
        raw = bytes(range(240, 256))
        data = _file(name=raw, sections=[{"size": 4, "name": raw, "segment_name": b"a\0tail"}])
        segment = self.analyze(data).to_dict()["segment_observations"][0]
        self.assertEqual(segment["name_hex"], raw.hex())
        self.assertEqual(segment["sections"][0]["name_hex"], raw.hex())
        self.assertEqual(
            segment["sections"][0]["declared_segment_name_hex"], _name(b"a\0tail").hex()
        )

    def test_zero_fill_offset_is_not_a_file_extent(self):
        data = _file(
            sections=[{"size": 4, "address": 0, "offset": 0xFFFFFFFF, "flags": 1}],
            vm_size=4,
            file_size=0,
            payload=b"",
        )
        row = self.analyze(data).to_dict()["segment_observations"][0]["sections"][0]
        self.assertEqual(row["file_offset"], 0xFFFFFFFF)
        self.assertIsNone(row["file_end"])
        self.assertEqual(row["file_extent_check"], "zero_fill_no_file_extent")

    def test_zero_fill_follows_regular_and_vm_size_can_exceed_file(self):
        data = _file(
            sections=[{"size": 4}, {"size": 8, "address": 4, "offset": 0, "flags": 1}], vm_size=12
        )
        segment = self.analyze(data).to_dict()["segment_observations"][0]
        self.assertEqual(segment["vm_size"], "0x000000000000000c")
        self.assertIsNone(segment["sections"][1]["file_end"])

    def test_known_regular_section_after_zero_fill_is_denied(self):
        data = _file(
            sections=[
                {"size": 0, "address": 0, "offset": 0, "flags": 1},
                {"size": 4, "address": 0, "offset": 264},
            ]
        )
        self.deny(lambda: self.analyze(data))

    def test_uint64_fields_remain_fixed_hex_above_signed64(self):
        for address in (2**63, 2**64 - 1):
            data = _file(
                address=address,
                vm_size=0,
                file_size=0,
                payload=b"",
                sections=[{"address": address, "size": 0, "offset": 0}],
            )
            segment = self.analyze(data).to_dict()["segment_observations"][0]
            self.assertEqual(segment["vm_address"], f"0x{address:016x}")
            self.assertEqual(segment["sections"][0]["vm_end"], f"0x{address:016x}")

    def test_checked_interval_end_bound_is_narrow_not_validity_certificate(self):
        for data in (
            _file(address=2**64 - 1, vm_size=1, sections=[], payload=b"", file_size=0),
            _file(
                sections=[{"address": 2**64 - 1, "size": 1, "flags": 1}],
                flags=1,
                vm_size=0,
                file_size=0,
                payload=b"",
            ),
            _file(file_offset=2**64 - 1, file_size=1, sections=[], flags=1),
        ):
            self.deny(lambda data=data: self.analyze(data))

    def test_high_vm_and_unknown_flags_do_not_use_ordinary_geometry(self):
        for flags in (1, 2, 4, 8, 16, 32, 0xFFFFFFFF):
            data = _file(
                flags=flags,
                address=100,
                vm_size=0,
                sections=[{"address": 1, "size": 4, "align": 0}],
            )
            document = self.analyze(data).to_dict()
            self.assertEqual(document["analysis_status"], "layout_semantics_unassessed")
            segment = document["segment_observations"][0]
            self.assertEqual(segment["geometry_check"], "unassessed_mapping")
            self.assertEqual(segment["sections"][0]["geometry_check"], "unassessed_mapping_or_type")

    def test_unknown_commands_including_required_dyld_remain_unassessed(self):
        for code in (0, 0x1D, 0x2C, 0x800000FF, 0xFFFFFFFF):
            document = self.analyze(_file(other=[_command(code, b"opaque!")])).to_dict()
            row = document["command_observations"][1]
            self.assertEqual(row["kind"], "unassessed_command")
            self.assertEqual(row["requires_dyld"], bool(code & 0x80000000))
            self.assertEqual(document["analysis_status"], "layout_semantics_unassessed")
            self.assertFalse(document["flags"]["code_signature_verified"])

    def test_uuid_bytes_not_uniqueness_authentication_or_platform_truth(self):
        document = self.analyze(
            _file(uuid=True, other=[_command(0x1B, bytes(range(16)))])
        ).to_dict()
        self.assertEqual(
            [row["uuid_hex"] for row in document["command_observations"][1:]],
            [bytes(range(16)).hex()] * 2,
        )
        self.assertEqual(document["analysis_status"], "supported_layout_subset_consistent")
        self.assertFalse(document["flags"]["source_authenticated"])

    def test_other_file_type_keeps_known_records_but_withholds_geometry(self):
        for file_type in (0, 3, 4, 6, 8, 0xFFFFFFFF):
            document = self.analyze(_file(file_type=file_type, vm_size=0)).to_dict()
            self.assertFalse(document["header"]["known_geometry_file_type"])
            self.assertEqual(document["analysis_status"], "layout_semantics_unassessed")

    def test_unknown_section_type_does_not_invent_file_range(self):
        for kind in (2, 0xC, 0x12, 0xFF):
            data = _file(
                sections=[{"address": 123, "size": 100, "offset": 0xFFFFFFFF, "flags": kind}],
                vm_size=0,
                file_size=0,
                payload=b"",
            )
            document = self.analyze(data).to_dict()
            self.assertIsNone(document["segment_observations"][0]["sections"][0]["file_end"])
            self.assertIn("unassessed_section_type", document["unassessed_reasons"])

    def test_attributes_relocations_protections_reserved_are_not_validated(self):
        data = _file(
            sections=[
                {
                    "size": 4,
                    "flags": 0x80000000,
                    "reloff": 0xFFFFFFFF,
                    "nreloc": 0xFFFFFFFF,
                    "reserved1": 0xFFFFFFFF,
                }
            ]
        )
        data = _change(data, 88, 0xFFFFFFFF)
        data = _change(data, 92, 0x80000000)
        document = self.analyze(data).to_dict()
        segment = document["segment_observations"][0]
        self.assertEqual(segment["maximum_protection"], -1)
        self.assertEqual(segment["initial_protection"], -(2**31))
        self.assertEqual(segment["sections"][0]["relocation_count"], 0xFFFFFFFF)
        self.assertEqual(document["analysis_status"], "layout_semantics_unassessed")

    def test_wrong_magic_short_headers_and_other_containers_refuse_cleanly(self):
        for data in (
            b"",
            b"\xcf\xfa\xed\xfe" * 7,
            b"\xca\xfe\xba\xbe" + _file()[4:],
            b"\xfe\xed\xfa\xcf" + _file()[4:],
            b"\xce\xfa\xed\xfe" + _file()[4:],
        ):
            self.deny(lambda data=data: self.analyze(data))

    def test_header_count_and_command_size_must_match_actual_block(self):
        for offset, value in (
            (16, 0),
            (16, 2),
            (16, m.MAX_COMMANDS + 1),
            (20, 0),
            (20, 151),
            (20, 160),
            (20, 0xFFFFFFFF),
        ):
            self.deny(
                lambda offset=offset, value=value: self.analyze(_change(_file(), offset, value))
            )
        self.analyze(_file(commands=[], payload=b""))

    def test_command_size_alignment_range_and_exact_consumption(self):
        for width in (0, 4, 7, 12, 144, 160, 0xFFFFFFFF):
            self.deny(lambda width=width: self.analyze(_change(_file(), 36, width)))
        self.deny(lambda: self.analyze(_file()[:100]))

    def test_segment_count_geometry_and_aggregate_limits_precede_expansion(self):
        for count in (0, 2, 0xFFFFFFFF, m.MAX_SECTIONS + 1):
            self.deny(lambda count=count: self.analyze(_change(_file(), 96, count)))
        empty_segment = _file(sections=[], payload=b"")[32:104]
        self.deny(lambda: self.analyze(_file(commands=[empty_segment] * (m.MAX_SEGMENTS + 1))))
        data = _file(
            sections=[{"size": 0, "offset": 0, "address": 0}] * m.MAX_SECTIONS,
            file_size=0,
            vm_size=0,
            payload=b"",
        )
        document = self.analyze(data).to_dict()
        self.assertEqual(len(document["segment_observations"][0]["sections"]), m.MAX_SECTIONS)

    def test_uuid_supported_structure_size_is_exact(self):
        for payload in (b"", b"a" * 8, b"a" * 24):
            self.deny(lambda payload=payload: self.analyze(_file(other=[_command(0x1B, payload)])))

    def test_regular_file_range_boundary_and_header_overlap(self):
        for offset, size in ((0, 4), (180, 4), (185, 4), (188, 1), (0xFFFFFFFF, 1)):
            data = _file(sections=[{"offset": offset, "size": size}], vm_size=100)
            self.deny(lambda data=data: self.analyze(data))
        self.analyze(_file(sections=[{"size": 4, "offset": 184}]))

    def test_known_section_vm_and_file_containment_are_independent(self):
        self.deny(lambda: self.analyze(_file(sections=[{"address": 1, "size": 4}], vm_size=4)))
        self.deny(
            lambda: self.analyze(_file(sections=[{"address": 0, "size": 4}], address=4, vm_size=8))
        )
        self.deny(
            lambda: self.analyze(
                _file(
                    file_offset=185,
                    file_size=3,
                    vm_size=8,
                    sections=[{"address": 0, "size": 4, "offset": 184}],
                )
            )
        )

    def test_alignment_shift_is_bounded_and_known_alignment_checked(self):
        for exponent in (64, 0xFFFFFFFF):
            self.deny(
                lambda exponent=exponent: self.analyze(
                    _file(sections=[{"size": 4, "align": exponent}], flags=1)
                )
            )
        for fields in (
            {"size": 4, "address": 1, "align": 2},
            {"size": 3, "offset": 185, "align": 2},
        ):
            self.deny(lambda fields=fields: self.analyze(_file(sections=[fields], vm_size=8)))
        self.analyze(
            _file(
                sections=[{"size": 0, "address": 0, "offset": 0, "align": 63}],
                file_size=0,
                vm_size=0,
                payload=b"",
            )
        )

    def test_object_segment_cannot_map_header_when_interpreted_ordinary(self):
        self.deny(lambda: self.analyze(_file(file_offset=0, file_size=188, vm_size=188)))
        self.analyze(_file(file_offset=0, file_size=188, vm_size=188, flags=1))

    def test_ordinary_segment_file_size_cannot_exceed_vm_but_flagged_is_unassessed(self):
        self.deny(lambda: self.analyze(_file(vm_size=3)))
        document = self.analyze(_file(vm_size=3, flags=1)).to_dict()
        self.assertEqual(document["analysis_status"], "layout_semantics_unassessed")

    def test_empty_section_and_segment_offsets_do_not_invent_content(self):
        document = self.analyze(
            _file(
                sections=[{"size": 0, "address": 0xFFFFFFFF, "offset": 0xFFFFFFFF}],
                file_offset=2**64 - 1,
                file_size=0,
                vm_size=0,
                payload=b"",
            )
        ).to_dict()
        self.assertEqual(document["segment_observations"][0]["file_end"], "0xffffffffffffffff")
        self.assertEqual(
            document["segment_observations"][0]["sections"][0]["file_extent_check"],
            "empty_regular_no_bytes",
        )

    def test_independent_interval_oracle_over_small_layouts(self):
        # Different formulation: enumerate actual covered byte/address positions,
        # not the leaf's endpoint comparisons. Zero-size means no content positions.
        for width in range(6):
            for vm_offset in range(7):
                for file_delta in range(7):
                    section = {"size": width, "address": vm_offset, "offset": 184 + file_delta}
                    data = _file(sections=[section], vm_size=6, payload=b"abcdef")
                    permitted = set(range(6))
                    addresses = set(range(vm_offset, vm_offset + width))
                    bytes_used = set(range(file_delta, file_delta + width))
                    expected = addresses <= permitted and bytes_used <= permitted
                    if expected:
                        self.analyze(data)
                    else:
                        self.deny(lambda data=data: self.analyze(data))

    def test_native_aliases_and_inert_hooks_fail_before_copy_or_decode(self):
        class Text(str):
            pass

        class Integer(int):
            pass

        class Mapping(dict):
            pass

        class Unexpected:
            def __str__(self):
                raise AssertionError("no coercion hook")

        for source in (_model(), Mapping(_model())):
            if type(source) is dict:
                source["schema_version"] = Integer(1)
            self.deny(lambda source=source: m.analyze_supplied_macho_layout(source))
        for key, values in (
            ("schema_version", (True, 1.0, "1", None, Unexpected())),
            ("source_id", (Text("valid"), [], {}, Unexpected())),
            ("macho_file_base64", (Text(_model()["macho_file_base64"]), [], {})),
        ):
            for value in values:
                source = _model()
                source[key] = value
                self.deny(lambda source=source: m.analyze_supplied_macho_layout(source))

    def test_cycles_depth_queued_nodes_and_repeated_graph_precede_clone(self):
        cycle = []
        cycle.append(cycle)
        deep = 0
        for _ in range(16):
            deep = [deep]
        repeated = ["x" * 4096] * 128
        for source in (
            cycle,
            deep,
            [0] * m.MAX_MODEL_NODES,
            {"repeated": [repeated] * 16},
            {"escape": '"' * m.MAX_BASE64_BYTES},
        ):
            with patch.object(m, "_clone") as clone:
                self.deny(lambda source=source: m.analyze_supplied_macho_layout(source))
                clone.assert_not_called()

    def test_closed_model_ids_and_nonprintable_metadata_reject(self):
        for identity in ("", "a" * 65, ".x", " x", "x y", "x\n", chr(127), chr(256)):
            self.deny(
                lambda identity=identity: m.analyze_supplied_macho_layout(
                    _model(source_id=identity)
                )
            )
        for source in ({}, {**_model(), "extra": 1}, {"schema_version": 1}, []):
            self.deny(lambda source=source: m.analyze_supplied_macho_layout(source))

    def test_base64_canonical_and_declared_size_are_checked_before_decoding(self):
        for encoded in (
            "",
            "AA==",
            " AAAA",
            "a-a_",
            "A" * (m.MAX_BASE64_BYTES + 4),
            "A" * m.MAX_BASE64_BYTES,
        ):
            source = {**_model(), "macho_file_base64": encoded}
            with patch.object(m.base64, "b64decode") as decoder:
                self.deny(lambda source=source: m.analyze_supplied_macho_layout(source))
                decoder.assert_not_called()
        encoded = _model()["macho_file_base64"]
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = alphabet.index(encoded[-2])
        changed = encoded[:-2] + alphabet[last + 1] + "="
        self.deny(
            lambda: m.analyze_supplied_macho_layout({**_model(), "macho_file_base64": changed})
        )

    def test_raw_native_bytes_families_and_equivalent_whitespace_escapes(self):
        source = _model()
        text = json.dumps(source, indent=2).replace("synthetic", "\\u0073ynthetic")
        self.assertEqual(
            m.analyze_supplied_macho_layout_bytes(model_bytes=text.encode("ascii")).to_json(),
            self.analyze().to_json(),
        )
        for value in (None, bytearray(b"{}"), "{}", b"", b"\xff", b" " * (m.MAX_MODEL_BYTES + 1)):
            self.deny(lambda value=value: m.analyze_supplied_macho_layout_bytes(model_bytes=value))

    def test_raw_numeric_grammar_and_scalar_depth_before_decoder(self):
        for raw in (
            "--1",
            "---1",
            "00",
            "-01",
            "1.0",
            "1e0",
            "NaN",
            "9" * 21,
            "9223372036854775808",
            "-9223372036854775809",
            "[" * 16 + "0" + "]" * 16,
        ):
            self.deny(
                lambda raw=raw: m.analyze_supplied_macho_layout_bytes(
                    model_bytes=raw.encode("ascii")
                ),
                before_decoder=True,
            )
        for raw in ("-0", "9223372036854775807", "-9223372036854775808", "[" * 15 + "0" + "]" * 15):
            with patch.object(m.json, "loads", wraps=m.json.loads) as decoder:
                self.deny(
                    lambda raw=raw: m.analyze_supplied_macho_layout_bytes(
                        model_bytes=raw.encode("ascii")
                    )
                )
                self.assertEqual(decoder.call_count, 1)

    def test_raw_node_string_and_escaped_costs_before_decoder(self):
        for raw in (
            "[" + ",".join("0" for _ in range(m.MAX_MODEL_NODES)) + "]",
            '"' + "A" * (m.MAX_BASE64_BYTES + 1) + '"',
            '"\\ud800"',
            '"\\u007f"',
            '"' + "\\u0041" * (m.MAX_BASE64_BYTES + 1) + '"',
        ):
            self.deny(
                lambda raw=raw: m.analyze_supplied_macho_layout_bytes(
                    model_bytes=raw.encode("ascii")
                ),
                before_decoder=True,
            )

    def test_raw_duplicate_keys_every_depth_and_incomplete_syntax_reject(self):
        for raw in (
            '{"a":1,"a":1}',
            '{"a":{"b":1,"b":1}}',
            _canonical(_model()).replace(
                '"schema_version":1', '"schema_version":1,"schema_version":1'
            ),
            '{"schema_version":',
            "[0}",
            '"\\q"',
            '"\\u00"',
        ):
            self.deny(
                lambda raw=raw: m.analyze_supplied_macho_layout_bytes(
                    model_bytes=raw.encode("ascii")
                )
            )

    def test_cohashed_false_geometry_uuid_and_promotions_do_not_replay(self):
        original = self.analyze(_file(uuid=True)).to_dict()
        changes = []
        for path, field, value in (
            ("header", "command_count", 0),
            ("flags", "loader_compatibility_verified", True),
            ("effects", "device", "performed"),
            ("bounds", "aggregate_sections", 2048),
        ):
            changed = copy.deepcopy(original)
            changed[path][field] = value
            changes.append(changed)
        changed = copy.deepcopy(original)
        changed["segment_observations"][0]["vm_size"] = "0xffffffffffffffff"
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["command_observations"][1]["uuid_hex"] = "0" * 32
        changes.append(changed)
        changed = copy.deepcopy(original)
        changed["segment_observations"][0]["sections"][0]["name_hex"] = "0" * 32
        changes.append(changed)
        for changed in changes:
            value = _readdress(changed)
            self.deny(lambda value=value: m.MachOAnalysis.from_dict(value), before_hash=False)
            self.deny(
                lambda value=value: m.MachOAnalysis.from_json(_canonical(value)), before_hash=False
            )

    def test_native_report_aliases_unknown_fields_and_dropped_rows_reject(self):
        document = self.analyze().to_dict()
        for value in (True, 1.0, "1", None):
            changed = copy.deepcopy(document)
            changed["schema_version"] = value
            self.deny(
                lambda changed=changed: m.MachOAnalysis.from_dict(_readdress(changed)),
                before_hash=False,
            )
        for changed in (
            {**document, "extra": 0},
            {**document, "segment_observations": []},
            {**document, "command_observations": []},
        ):
            self.deny(
                lambda changed=changed: m.MachOAnalysis.from_dict(_readdress(changed)),
                before_hash=False,
            )

    def test_separate_original_model_required_even_for_coherent_alternate_report(self):
        source = _model()
        for other in (
            _model(source_id="other"),
            _model(_file(payload=b"DIFF")),
            _model(_file(uuid=True)),
        ):
            report = m.analyze_supplied_macho_layout(other)
            self.assertEqual(
                m.MachOAnalysis.from_json(report.to_json()).to_json(), report.to_json()
            )
            self.deny(
                lambda report=report: m.verify_supplied_macho_layout_analysis(report, model=source),
                before_hash=False,
            )

    def test_source_substitution_cannot_retain_old_observations_when_rehashed(self):
        changed = self.analyze().to_dict()
        data = _file(sections=[{"name": b"foreign", "size": 4}])
        source = _model(data)
        changed["source_model"] = source
        changed["source_model_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                m.MODEL_DOMAIN.encode("ascii") + b"\n" + _canonical(source).encode("ascii")
            ).hexdigest()
        )
        changed["source_file_sha256"] = "sha256:" + hashlib.sha256(data).hexdigest()
        self.deny(lambda: m.MachOAnalysis.from_dict(_readdress(changed)), before_hash=False)

    def test_missing_wrappers_foreign_families_and_declared_native_mutation_reject(self):
        missing = object.__new__(m.MachOAnalysis)
        for operation in (
            missing.to_dict,
            missing.to_json,
            lambda: m.verify_supplied_macho_layout_analysis(missing, model=_model()),
        ):
            self.deny(operation)

        class Derived(m.MachOAnalysis):
            pass

        text = self.analyze().to_json()
        self.deny(lambda: Derived(text))
        self.deny(lambda: Derived.from_json(text))
        for foreign in (None, {}, text, True):
            self.deny(
                lambda foreign=foreign: m.verify_supplied_macho_layout_analysis(
                    foreign, model=_model()
                )
            )
        report = self.analyze()
        changed = report.to_dict()
        changed["header"]["flags"] = 1
        object.__setattr__(report, "document_json", _canonical(_readdress(changed)))
        self.deny(report.to_json, before_hash=False)

    def test_report_requires_exact_canonical_text_and_all_addresses(self):
        document = self.analyze().to_dict()
        for text in (json.dumps(document, indent=2), _canonical(document) + "\n", "{}"):
            self.deny(lambda text=text: m.MachOAnalysis.from_json(text), before_hash=False)
        for field in (
            "analysis_id",
            "analysis_sha256",
            "source_file_sha256",
            "source_model_sha256",
        ):
            changed = copy.deepcopy(document)
            changed[field] = "wrong"
            self.deny(lambda changed=changed: m.MachOAnalysis.from_dict(changed), before_hash=False)

    def test_each_public_operation_funds_complete_pass_before_any_digest(self):
        source = _model()
        report = self.analyze()
        document = report.to_dict()
        text = report.to_json()
        operations = (
            lambda: m.analyze_supplied_macho_layout(source),
            lambda: m.analyze_supplied_macho_layout_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            lambda: m.MachOAnalysis(text),
            lambda: m.MachOAnalysis.from_dict(document),
            lambda: m.MachOAnalysis.from_json(text),
            report.to_dict,
            report.to_json,
            lambda: m.verify_supplied_macho_layout_analysis(report, model=source),
        )
        real = m._Budget.charge
        for operation in operations:
            budgets = []

            def counted(self, amount, budgets=budgets):
                if all(self is not old for old in budgets):
                    budgets.append(self)
                real(self, amount)

            with patch.object(m._Budget, "charge", counted):
                operation()
            self.assertEqual(len(budgets), 1)
            needed = budgets[0].used
            for delta in (-1, 0):
                cap = needed + delta

                def capped(self, amount, cap=cap):
                    if amount > cap - self.used:
                        raise m.MachOAnalysisError("Independent exact work cap")
                    real(self, amount)

                with patch.object(m._Budget, "charge", capped):
                    if delta < 0:
                        self.deny(operation)
                    else:
                        operation()

    def test_fixed_retained_reservations_cover_largest_observed_native_fields(self):
        data = _file(
            name=bytes(range(240, 256)),
            address=2**64 - 1,
            vm_size=0,
            file_offset=2**64 - 1,
            file_size=0,
            flags=0xFFFFFFFF,
            uuid=True,
            payload=b"",
            sections=[
                {
                    "name": bytes(range(240, 256)),
                    "segment_name": bytes(range(240, 256)),
                    "address": 2**64 - 1,
                    "size": 0,
                    "offset": 0xFFFFFFFF,
                    "align": 63,
                    "reloff": 0xFFFFFFFF,
                    "nreloc": 0xFFFFFFFF,
                    "flags": 0xFFFFFFFF,
                    "reserved1": 0xFFFFFFFF,
                    "reserved2": 0xFFFFFFFF,
                    "reserved3": 0xFFFFFFFF,
                }
            ],
        )
        document = self.analyze(data).to_dict()

        def nodes(value):
            if type(value) is dict:
                return 1 + sum(1 + nodes(child) for child in value.values())
            if type(value) is list:
                return 1 + sum(map(nodes, value))
            return 1

        for command in document["command_observations"]:
            self.assertLessEqual(len(_canonical(command)) + 1, 512)
            self.assertLessEqual(nodes(command), 40)
        segment = document["segment_observations"][0]
        for section in segment["sections"]:
            self.assertLessEqual(len(_canonical(section)) + 1, 1536)
            self.assertLessEqual(nodes(section), 64)
        segment = {**segment, "sections": []}
        self.assertLessEqual(len(_canonical(segment)) + 1, 1024)
        self.assertLessEqual(nodes(segment), 60)

    def test_real_high_retained_layout_cost_and_nodes_deny_before_digest(self):
        source = _model(
            _file(
                sections=[{"size": 0, "offset": 0, "address": 0}] * m.MAX_SECTIONS,
                file_size=0,
                vm_size=0,
                payload=b"",
                target_size=m.MAX_FILE_BYTES,
            )
        )
        # Each individual declaration/file limit fits, while the funded retained
        # section reservations plus original source do not fit the report ceiling.
        self.deny(lambda: m.analyze_supplied_macho_layout(source))
        with patch.object(m, "MAX_REPORT_NODES", 128):
            self.deny(lambda: self.analyze())
        with patch.object(m, "MAX_WORK", 4_000_000):
            self.deny(
                lambda: m.analyze_supplied_macho_layout(_model(_file(target_size=m.MAX_FILE_BYTES)))
            )

    def test_exact_file_limit_and_declared_limit_plus_one(self):
        source = _model(_file(target_size=m.MAX_FILE_BYTES))
        report = m.analyze_supplied_macho_layout(source)
        self.assertEqual(report.to_dict()["source_file_bytes"], m.MAX_FILE_BYTES)
        self.assertEqual(
            m.verify_supplied_macho_layout_analysis(report, model=source).to_json(),
            report.to_json(),
        )
        with patch.object(m.base64, "b64decode") as decoder:
            self.deny(
                lambda: m.analyze_supplied_macho_layout(
                    _model(_file(target_size=m.MAX_FILE_BYTES + 1))
                )
            )
            decoder.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Independent inert PACK/stored-DEFLATE encoders and exact reconstruction controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import unittest
import zlib
from unittest.mock import patch

from sunderkey import offline_git_pack_analysis as pack


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _adler(data):
    first, second = 1, 0
    for value in data:
        first = (first + value) % 65_521
        second = (second + first) % 65_521
    return struct.pack("!I", second * 65_536 + first)


def _stored(data):
    """Own RFC1950/1951 stored-block encoder, without a product encoder/import."""
    result = bytearray(b"\x78\x01")
    chunks = [data[index : index + 65_535] for index in range(0, len(data), 65_535)] or [b""]
    for index, chunk in enumerate(chunks):
        length = len(chunk)
        result.append(int(index == len(chunks) - 1))
        result.extend(struct.pack("<HH", length, 65_535 - length))
        result.extend(chunk)
    return bytes(result) + _adler(data)


def _header(kind, size):
    first = kind * 16 + size % 16
    size //= 16
    result = bytearray([first + (128 if size else 0)])
    while size:
        low, size = size % 128, size // 128
        result.append(low + (128 if size else 0))
    return bytes(result)


def _integer(size):
    result = bytearray()
    while size >= 128:
        low, size = size % 128, size // 128
        result.append(low + 128)
    result.append(size)
    return bytes(result)


def _distance(number):
    parts = [number % 128]
    number //= 128
    while number:
        number -= 1
        parts.insert(0, 128 + number % 128)
        number //= 128
    return bytes(parts)


def _copy(offset, size, *, presence=None):
    values = list(struct.pack("<I", offset)) + list(struct.pack("<I", size)[:3])
    mask = sum(1 << index for index, value in enumerate(values) if value)
    if presence is not None:
        mask = presence
    return bytes([128 + mask]) + bytes(
        value for index, value in enumerate(values) if mask & (1 << index)
    )


def _insert(data):
    assert 1 <= len(data) <= 127
    return bytes([len(data)]) + data


def _delta(base_size, result_size, commands):
    return _integer(base_size) + _integer(result_size) + commands


def _base(kind, data, *, stream=None, declared=None):
    return _header(kind, len(data) if declared is None else declared) + (
        _stored(data) if stream is None else stream
    )


def _ofs(instructions, distance, *, declared=None, stream=None):
    return (
        _header(6, len(instructions) if declared is None else declared)
        + _distance(distance)
        + (_stored(instructions) if stream is None else stream)
    )


def _pack(entries=(), *, version=2, count=None, trailer=None):
    body = (
        b"PACK"
        + struct.pack("!II", version, len(entries) if count is None else count)
        + b"".join(entries)
    )
    return body + (hashlib.sha1(body).digest() if trailer is None else trailer)


def _model(raw, *, label="synthetic-pack"):
    return {
        "schema_version": 1,
        "source_id": label,
        "object_format": "sha1",
        "pack_base64": base64.b64encode(raw).decode("ascii"),
    }


def _fixture_bytes():
    first = _base(3, b"abcdef")
    instructions = _delta(6, 6, _copy(0, 2) + _insert(b"XY") + _copy(4, 2))
    return _pack([first, _ofs(instructions, len(first))])


def _document(raw):
    return pack.analyze_supplied_git_pack(_model(raw)).to_dict()


def _object_id(kind, data):
    return (
        "sha1:"
        + hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).hexdigest()
    )


def _readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256((pack.DOMAIN + "\n" + _canonical(body)).encode()).hexdigest()
    document["analysis_sha256"] = "sha256:" + digest
    document["analysis_id"] = "GPA-" + digest[:32].upper()
    return document


def _unsafe_wrapper(document):
    result = object.__new__(pack.GitPackAnalysis)
    object.__setattr__(result, "document_json", _canonical(document))
    return result


class OfflineGitPackAnalysisTests(unittest.TestCase):
    def assertPrehashDenied(self, operation):
        with (
            patch.object(pack.hashlib, "sha1", side_effect=AssertionError("SHA1 reached")),
            patch.object(pack.hashlib, "sha256", side_effect=AssertionError("SHA256 reached")),
            self.assertRaises(pack.GitPackAnalysisError),
        ):
            operation()

    def test_literal_fixture_and_independent_reconstructed_object_facts(self):
        doc = pack.analyze_supplied_git_pack(pack.component_fixture()).to_dict()
        self.assertEqual(doc["analysis_id"], "GPA-BEBB5F5D47375804D82DAB4E0EB7D4F6")
        self.assertEqual(
            doc["analysis_sha256"],
            "sha256:bebb5f5d47375804d82dab4e0eb7d4f6bb98c024577a01822f5fdba8cf2c2052",
        )
        self.assertEqual(
            doc["source_model_sha256"],
            "sha256:13ec6e9bc3cde8abcfad4ae9c51386eae3b716f9c68e53e2f0080fd25cb65de7",
        )
        self.assertEqual(
            doc["source_pack_sha256"],
            "sha256:84ef6b88d6815e1841616772f923c591de73c5958615fcb3d841b5596f94d448",
        )
        self.assertEqual(
            doc["pack"]["computed_pack_sha1"], "sha1:e8b282eca972340cd5c381556a9672d686fff267"
        )
        entries = doc["pack"]["entries"]
        self.assertEqual(
            [base64.b64decode(row["reconstructed_base64"]) for row in entries],
            [b"abcdef", b"abXYef"],
        )
        self.assertEqual([row["entry_offset"] for row in entries], [12, 30])
        self.assertEqual([row["end_offset"] for row in entries], [30, 53])
        self.assertEqual(entries[1]["inflated_entry_bytes"], 10)
        self.assertEqual(entries[1]["reconstructed_bytes"], 6)
        self.assertEqual(entries[1]["base_entry_offset"], 12)
        self.assertEqual(entries[1]["copy_instructions"], 2)
        self.assertEqual(entries[1]["insert_instructions"], 1)
        self.assertEqual(entries[1]["mechanical_object_sha1"], _object_id("blob", b"abXYef"))
        self.assertTrue(doc["pack"]["checksum_matches"])
        self.assertEqual(doc["pack"]["outcome"], "supported_pack_reconstruction_consistent")
        self.assertFalse(any(doc["claims"].values()))
        self.assertEqual(set(doc["effects"].values()), {"none"})

    def test_public_fixture_is_fresh_and_matches_independent_stored_encoder(self):
        first, second = pack.component_fixture(), pack.component_fixture()
        first["source_id"] = "changed"
        self.assertEqual(second["source_id"], "synthetic-pack")
        self.assertEqual(base64.b64decode(second["pack_base64"]), _fixture_bytes())

    def test_all_eight_public_forms_preserve_canonical_identity(self):
        model = _model(_fixture_bytes())
        report = pack.analyze_supplied_git_pack(model)
        text, doc = report.to_json(), report.to_dict()
        for other in (
            pack.GitPackAnalysis(text),
            pack.GitPackAnalysis.from_dict(doc),
            pack.GitPackAnalysis.from_json(text),
            pack.analyze_supplied_git_pack_bytes(model_bytes=_canonical(model).encode()),
            pack.verify_supplied_git_pack_analysis(report, model=model),
        ):
            self.assertEqual(other.to_json(), text)

    def test_all_base_types_empty_bodies_and_duplicate_order_are_opaque(self):
        entries = [_base(kind, data) for kind in (1, 2, 3, 4) for data in (b"", b"\x00\xffbody")]
        rows = _document(_pack(entries + entries))["pack"]["entries"]
        expected = [
            (kind, data)
            for kind in ("commit", "tree", "blob", "tag")
            for data in (b"", b"\x00\xffbody")
        ]
        self.assertEqual(
            [(row["resolved_type"], base64.b64decode(row["reconstructed_base64"])) for row in rows],
            expected * 2,
        )
        self.assertEqual(
            [row["mechanical_object_sha1"] for row in rows[:8]],
            [_object_id(kind, data) for kind, data in expected],
        )

    def test_versions_two_three_and_zero_objects_have_exact_trailer_geometry(self):
        for version in (2, 3):
            doc = _document(_pack(version=version))
            self.assertEqual(doc["pack"]["version"], version)
            self.assertEqual(doc["pack"]["trailer_offset"], 12)
            self.assertEqual(doc["pack"]["entries"], [])
            self.assertTrue(doc["pack"]["checksum_matches"])

    def test_bad_declared_pack_sha1_is_an_adverse_fixed_shape_report(self):
        raw = _fixture_bytes()
        changed = raw[:-20] + b"\x00" * 20
        doc = _document(changed)
        self.assertFalse(doc["pack"]["checksum_matches"])
        self.assertEqual(doc["pack"]["outcome"], "declared_pack_checksum_mismatch")
        self.assertEqual(doc["pack"]["declared_pack_sha1"], "sha1:" + "0" * 40)
        self.assertEqual(
            doc["pack"]["computed_pack_sha1"], "sha1:" + hashlib.sha1(raw[:-20]).hexdigest()
        )
        self.assertEqual(
            base64.b64decode(doc["pack"]["entries"][1]["reconstructed_base64"]), b"abXYef"
        )
        self.assertFalse(any(doc["claims"].values()))

    def test_every_fixture_prefix_refuses_without_hashing(self):
        raw = _fixture_bytes()
        for length in range(len(raw)):
            with self.subTest(length=length):
                self.assertPrehashDenied(
                    lambda length=length: pack.analyze_supplied_git_pack(_model(raw[:length]))
                )

    def test_signature_versions_counts_and_extra_body_are_typed_refusals(self):
        fixture = _fixture_bytes()
        cases = [b"NOPE" + fixture[4:]]
        cases += [_pack(version=version) for version in (0, 1, 4, 0xFFFFFFFF)]
        cases += [_pack([_base(3, b"a")], count=count) for count in (0, 2, 0xFFFFFFFF)]
        cases += [_pack([_base(3, b"a") + b"x"])]
        for raw in cases:
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_ref_reserved_type_and_sha256_are_explicit_subset_refusals(self):
        for kind in (0, 5, 7):
            raw = _pack([_header(kind, 0) + b"\0" * 20 + _stored(b"")])
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))
        source = _model(_fixture_bytes())
        source["object_format"] = "sha256"
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(source))

    def test_entry_size_varints_and_nonminimal_within_bound_spellings(self):
        for size in (0, 1, 15, 16, 127, 128, 2047, 2048, 16_384):
            doc = _document(_pack([_base(3, b"d" * size)]))
            self.assertEqual(doc["pack"]["entries"][0]["reconstructed_bytes"], size)
        doc = _document(_pack([b"\xb0\x00" + _stored(b"")]))
        self.assertEqual(doc["pack"]["entries"][0]["reconstructed_bytes"], 0)

    def test_overflowing_entry_ofs_and_delta_varints_refuse_before_hash(self):
        first = _base(3, b"a")
        for raw in (
            _pack([b"\xb0" + b"\x80" * 10 + b"\0"]),
            _pack([first, _header(6, 0) + b"\xff" * 12 + b"\0" + _stored(b"")]),
            _pack([first, _ofs(b"\x80" * 12 + b"\0\0", len(first))]),
        ):
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_ofs_biased_big_endian_boundary_oracle(self):
        for distance in (18, 127, 128, 255, 16_383, 16_384, 16_511, 16_512, 65_535):
            data_size = distance - 12
            first = _base(3, b"b" * data_size)
            # Stored stream geometry is size+11, plus its size-dependent PACK header.
            # Search only small nearby lengths to realize the requested exact entry distance.
            for delta_size in range(-8, 9):
                data = b"b" * max(0, data_size + delta_size)
                candidate = _base(3, data)
                if len(candidate) == distance:
                    first = candidate
                    break
            else:
                self.fail("Independent encoder could not realize distance")
            base_size = len(data)
            instructions = _delta(base_size, 1, _insert(b"z"))
            rows = _document(_pack([first, _ofs(instructions, distance)]))["pack"]["entries"]
            self.assertEqual(rows[1]["ofs_distance"], distance)
            self.assertEqual(rows[1]["base_entry_offset"], 12)
            self.assertEqual(base64.b64decode(rows[1]["reconstructed_base64"]), b"z")

    def test_ofs_reference_must_be_a_prior_entry_boundary_not_header_or_middle(self):
        first = _base(3, b"abcdef")
        for distance in (0, 1, len(first) - 1, len(first) + 1, len(first) + 12, 1000):
            raw = _pack([first, _ofs(_delta(6, 0, b""), distance)])
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_chained_delta_inherits_original_base_type_and_tracks_depth(self):
        for kind, name in ((1, "commit"), (2, "tree"), (3, "blob"), (4, "tag")):
            entries = [_base(kind, b"abc")]
            previous = b"abc"
            for data in (b"xy", b"1234", b""):
                previous_size = len(previous)
                commands = _insert(data) if data else b""
                entries.append(_ofs(_delta(previous_size, len(data), commands), len(entries[-1])))
                previous = data
            rows = _document(_pack(entries))["pack"]["entries"]
            self.assertEqual([row["delta_depth"] for row in rows], [0, 1, 2, 3])
            self.assertEqual([row["resolved_type"] for row in rows], [name] * 4)
            self.assertEqual(base64.b64decode(rows[-1]["reconstructed_base64"]), b"")

    def test_copy_insert_overlap_repeat_and_opaque_byte_reconstruction(self):
        base = bytes(range(256))
        commands = _copy(200, 20) + _insert(b"\xff\0") + _copy(200, 20) + _copy(0, 3)
        wanted = base[200:220] + b"\xff\0" + base[200:220] + base[:3]
        first = _base(3, base)
        row = _document(_pack([first, _ofs(_delta(len(base), len(wanted), commands), len(first))]))[
            "pack"
        ]["entries"][1]
        self.assertEqual(base64.b64decode(row["reconstructed_base64"]), wanted)
        self.assertEqual(row["copy_instructions"], 3)
        self.assertEqual(row["insert_instructions"], 1)

    def test_omitted_copy_operands_keep_fixed_positions_and_zero_size_means_65536(self):
        base = bytes(index % 251 for index in range(70_000))
        first = _base(3, base, stream=zlib.compress(base))
        masks = (0, 1, 2, 3, 4, 8, 15, 16, 17, 18, 31, 32, 33, 48, 64, 65, 80, 96, 112, 127)
        for mask in masks:
            offset = (1 if mask & 1 else 0) + (256 if mask & 2 else 0)
            size = 3 if mask & 16 else 65_536
            command = _copy(offset, 3 if mask & 16 else 0, presence=mask)
            raw = _pack([first, _ofs(_delta(len(base), size, command), len(first))])
            row = _document(raw)["pack"]["entries"][1]
            self.assertEqual(
                base64.b64decode(row["reconstructed_base64"]), base[offset : offset + size]
            )

    def test_default_copy_size_and_two_byte_size_with_nonzero_high_position(self):
        base = b"v" * 65_536
        first = _base(3, base, stream=zlib.compress(base))
        for command, size in ((b"\x80", 65_536), (b"\xa0\x01", 256), (b"\xc0\x00", 65_536)):
            row = _document(_pack([first, _ofs(_delta(len(base), size, command), len(first))]))[
                "pack"
            ]["entries"][1]
            self.assertEqual(row["reconstructed_bytes"], size)
            self.assertEqual(base64.b64decode(row["reconstructed_base64"]), base[:size])

    def test_delta_base_result_copy_insert_and_reserved_command_mismatches_refuse(self):
        first = _base(3, b"abcdef")
        instructions = (
            _delta(5, 1, _insert(b"x")),
            _delta(6, 2, _insert(b"x")),
            _delta(6, 0, _insert(b"x")),
            _delta(6, 1, _copy(6, 1)),
            _delta(6, 2, _copy(5, 2)),
            _delta(6, 1, _copy(0, 2)),
            _delta(6, 0, b"\0"),
            _delta(6, 2, b"\x02x"),
            _delta(6, 1, b"\x91\0"),
            b"\x80",
        )
        for commands in instructions:
            raw = _pack([first, _ofs(commands, len(first))])
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_delta_pack_header_is_instruction_length_not_result_length(self):
        base = b"x" * 512
        first = _base(3, base)
        commands = _delta(len(base), len(base), _copy(0, len(base)))
        good = _document(_pack([first, _ofs(commands, len(first))]))["pack"]["entries"][1]
        self.assertEqual(good["inflated_entry_bytes"], len(commands))
        self.assertEqual(good["reconstructed_bytes"], len(base))
        raw = _pack([first, _ofs(commands, len(first), declared=len(base))])
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(raw)))

    def test_decompressed_declared_size_underflow_and_sentinel_overflow_refuse(self):
        for actual, declared in ((b"", 1), (b"x", 0), (b"xx", 1), (b"x", 2), (b"x" * 8192, 7)):
            raw = _pack([_base(3, actual, declared=declared)])
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_zlib_header_dictionary_adler_and_missing_eof_have_distinct_domain_refusals(self):
        stream = _stored(b"abc")
        cases = [
            b"\x79\x01" + stream[2:],
            b"\x88\x1c" + stream[2:],
            b"\x78\0" + stream[2:],
            b"\x78\x20" + b"\0" * 4 + stream[2:],
            stream[:-1],
            stream[:-4] + b"\0" * 4,
        ]
        for compressed in cases:
            raw = _pack([_base(3, b"abc", stream=compressed)])
            self.assertPrehashDenied(lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw)))

    def test_stored_fixed_dynamic_deflate_streams_share_reconstructed_object_identity(self):
        data = b"abc123\0\xff" * 128
        fixed = zlib.compressobj(strategy=zlib.Z_FIXED)
        streams = (_stored(data), fixed.compress(data) + fixed.flush(), zlib.compress(data))
        identities = []
        for compressed in streams:
            row = _document(_pack([_base(3, data, stream=compressed)]))["pack"]["entries"][0]
            self.assertEqual(base64.b64decode(row["reconstructed_base64"]), data)
            identities.append(row["mechanical_object_sha1"])
        self.assertEqual(identities, [_object_id("blob", data)] * 3)

    def test_exact_consumed_stream_end_is_only_basis_for_next_entry(self):
        entries = [_base(3, b""), _base(3, b"first"), _base(4, b"second")]
        rows = _document(_pack(entries))["pack"]["entries"]
        position = 12
        for entry, row in zip(entries, rows, strict=True):
            self.assertEqual(row["entry_offset"], position)
            self.assertEqual(row["end_offset"], position + len(entry))
            self.assertEqual(
                row["compressed_bytes_consumed"], row["end_offset"] - row["zlib_start_offset"]
            )
            position += len(entry)
        extra_stream = _pack([_base(3, b"x") + _stored(b"x")])
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(extra_stream)))

    def test_bounded_inflate_max_length_tail_accounting_and_no_flush(self):
        data = b"z" * 20_000
        raw = _pack([_base(3, data, stream=zlib.compress(data)), _base(3, b"tail")])
        original = pack.zlib.decompressobj
        calls = []

        class Observed:
            def __init__(self, **kwargs):
                self.inner = original(**kwargs)

            def __getattr__(self, name):
                self_outer.assertNotEqual(name, "flush")
                return getattr(self.inner, name)

            def decompress(self, compressed, *, max_length):
                self_outer.assertTrue(0 < max_length <= pack.INFLATE_CHUNK_BYTES)
                self_outer.assertLessEqual(len(compressed), pack.INFLATE_CHUNK_BYTES)
                calls.append((len(compressed), max_length))
                return self.inner.decompress(compressed, max_length=max_length)

        self_outer = self
        with patch.object(pack.zlib, "decompressobj", Observed):
            result = pack.analyze_supplied_git_pack(_model(raw)).to_dict()
        self.assertGreater(len(calls), 4)
        self.assertEqual(result["pack"]["entries"][1]["resolved_type"], "blob")

    def test_per_inflate_call_work_precharge_precedes_decoder_and_tail_allocation(self):
        raw = _pack([_base(3, b"x" * 8192)])
        original_factory, original_charge = pack.zlib.decompressobj, pack._Budget.inflate
        permits = []

        def charge(budget, input_size, cap):
            original_charge(budget, input_size, cap)
            permits.append((input_size, cap))

        class Observed:
            def __init__(self, **kwargs):
                self.inner = original_factory(**kwargs)

            def __getattr__(self, name):
                return getattr(self.inner, name)

            def decompress(self, compressed, *, max_length):
                self_outer.assertTrue(permits)
                self_outer.assertEqual(permits.pop(0), (len(compressed), max_length))
                return self.inner.decompress(compressed, max_length=max_length)

        self_outer = self
        with (
            patch.object(pack._Budget, "inflate", charge),
            patch.object(pack.zlib, "decompressobj", Observed),
        ):
            pack.analyze_supplied_git_pack(_model(raw))
        self.assertEqual(permits, [])

    def test_actual_object_count_256_257_boundaries(self):
        empty = _base(3, b"")
        self.assertEqual(len(_document(_pack([empty] * 256))["pack"]["entries"]), 256)
        raw = _pack([empty] * 257)
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(raw)))

    def test_actual_delta_depth_32_33_boundaries(self):
        entries = [_base(3, b"x")]
        commands = _delta(1, 1, _copy(0, 1))
        for _ in range(32):
            entries.append(_ofs(commands, len(entries[-1])))
        self.assertEqual(_document(_pack(entries))["pack"]["entries"][-1]["delta_depth"], 32)
        entries.append(_ofs(commands, len(entries[-1])))
        raw = _pack(entries)
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(raw)))

    def test_actual_instruction_8192_8193_boundaries(self):
        first = _base(3, b"x")
        for count in (8192, 8193):
            commands = _delta(1, count, _copy(0, 1) * count)
            raw = _pack([first, _ofs(commands, len(first))])
            if count == 8192:
                self.assertEqual(_document(raw)["pack"]["total_delta_instructions"], count)
            else:
                self.assertPrehashDenied(
                    lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw))
                )

    def test_actual_object_byte_ceiling_and_plus_one(self):
        for size in (pack.MAX_OBJECT_BYTES, pack.MAX_OBJECT_BYTES + 1):
            data = b"a" * size
            raw = _pack([_base(3, data, stream=zlib.compress(data))])
            if size == pack.MAX_OBJECT_BYTES:
                self.assertEqual(_document(raw)["pack"]["entries"][0]["reconstructed_bytes"], size)
            else:
                self.assertPrehashDenied(
                    lambda raw=raw: pack.analyze_supplied_git_pack(_model(raw))
                )

    def test_actual_pack_byte_ceiling_and_plus_one_before_decompression(self):
        # A stored block PACK can be adjusted to the exact input ceiling without
        # forcing a 512KiB reconstructed object plus its stream/header overhead.
        data = b"a" * (pack.MAX_PACK_BYTES - 100)
        while True:
            raw = _pack([_base(3, data)])
            difference = pack.MAX_PACK_BYTES - len(raw)
            if not difference:
                break
            data = data + b"a" * difference if difference > 0 else data[:difference]
        self.assertEqual(len(raw), pack.MAX_PACK_BYTES)
        self.assertEqual(_document(raw)["source_pack_bytes"], pack.MAX_PACK_BYTES)
        source = _model(raw + b"a")
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(source))

    def test_aggregate_reconstruction_inflated_and_call_bounds_are_before_hash(self):
        data = b"x" * 300_000
        first = _base(3, data, stream=zlib.compress(data))
        commands = _delta(len(data), len(data), _copy(0, len(data)))
        entries = [first]
        for _ in range(7):
            entries.append(_ofs(commands, len(entries[-1])))
        raw = _pack(entries)
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(raw)))
        # Transparent reduced placements distinguish three independent guards.
        fixture_model = _model(_fixture_bytes())
        for name, limit in (
            ("MAX_TOTAL_INFLATED_BYTES", 5),
            ("MAX_TOTAL_RECONSTRUCTED_BYTES", 5),
            ("MAX_INFLATE_CALLS", 1),
        ):
            with patch.object(pack, name, limit):
                self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(fixture_model))

    def test_genuine_default_report_overflow_and_reduced_node_bound_deny_before_hash(self):
        data = b"x" * 400_000
        first = _base(3, data, stream=zlib.compress(data))
        commands = _delta(len(data), len(data), _copy(0, len(data)))
        entries = [first]
        for _ in range(3):
            entries.append(_ofs(commands, len(entries[-1])))
        raw = _pack(entries)
        self.assertLess(len(raw), pack.MAX_PACK_BYTES)
        self.assertLess(len(data) * 4, pack.MAX_TOTAL_RECONSTRUCTED_BYTES)
        self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(_model(raw)))
        fixture_model = _model(_fixture_bytes())
        with patch.object(pack, "MAX_REPORT_NODES", 64):
            self.assertPrehashDenied(lambda: pack.analyze_supplied_git_pack(fixture_model))

    def test_exact_native_types_missing_fields_and_subclasses_reject_before_dump_hash(self):
        class Text(str):
            pass

        class Mapping(dict):
            pass

        model = _model(_fixture_bytes())
        values = [None, [], Mapping(model)]
        for field, value in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("source_id", Text("s")),
            ("object_format", None),
            ("pack_base64", []),
        ):
            changed = copy.deepcopy(model)
            changed[field] = value
            values.append(changed)
        for field in model:
            changed = copy.deepcopy(model)
            del changed[field]
            values.append(changed)
        for value in values:
            with patch.object(pack.json, "dumps", side_effect=AssertionError("dump reached")):
                self.assertPrehashDenied(lambda value=value: pack.analyze_supplied_git_pack(value))

    def test_native_cycles_shared_references_escaped_cost_and_integer_budgets(self):
        cyclic = {}
        cyclic["loop"] = cyclic
        shared = list(range(2000))
        values = (
            cyclic,
            {"shared": [shared] * 10},
            {"large": 1 << 100_000},
            {1: "bad"},
            {"text": "\x7f" * 200_000},
            {"text": "\ud800"},
        )
        for value in values:
            with patch.object(pack.json, "dumps", side_effect=AssertionError("dump reached")):
                self.assertPrehashDenied(lambda value=value: pack.analyze_supplied_git_pack(value))

    def test_raw_duplicate_floating_nonfinite_bad_integer_and_utf8_contracts(self):
        values = (
            b'{"x":1,"x":2}',
            b'{"x":{"z":1,"z":2}}',
            b"1.0",
            b"NaN",
            b"Infinity",
            b"--1",
            b"9223372036854775808",
            b"-9223372036854775809",
            b'"\xff"',
            b'"\\ud800"',
        )
        for raw in values:
            self.assertPrehashDenied(
                lambda raw=raw: pack.analyze_supplied_git_pack_bytes(model_bytes=raw)
            )

    def test_predecoder_scalar_depth_node_string_and_lexical_bounds(self):
        values = (
            b"[" * 16 + b"0" + b"]" * 16,
            b"[" + b",".join([b"0"] * pack.MAX_MODEL_NODES) + b"]",
            b'"' + b"x" * (pack.MAX_STRING_BYTES + 1) + b'"',
            b"1" * 21,
            b"9223372036854775808",
            b" " * (pack.MAX_MODEL_BYTES + 1),
            b'"\\u0080"',
        )
        for raw in values:
            with patch.object(pack.json, "loads", side_effect=AssertionError("decoder reached")):
                self.assertPrehashDenied(
                    lambda raw=raw: pack.analyze_supplied_git_pack_bytes(model_bytes=raw)
                )

    def test_base64_padding_spelling_and_non_native_bytes_are_typed_denials(self):
        for spelling in ("Q===", "QR==", "QQ", "QQ==\n", "QQ-_", "====", " AAE=", "\u00e9"):
            source = _model(_fixture_bytes())
            source["pack_base64"] = spelling
            self.assertPrehashDenied(lambda source=source: pack.analyze_supplied_git_pack(source))
        for value in (bytearray(b"{}"), "{}", None, b""):
            self.assertPrehashDenied(
                lambda value=value: pack.analyze_supplied_git_pack_bytes(model_bytes=value)
            )

    def test_all_eight_operations_fund_complete_work_before_first_sha1_or_sha256(self):
        source = _model(_fixture_bytes())
        report = pack.analyze_supplied_git_pack(source)
        doc, text = report.to_dict(), report.to_json()
        operations = (
            lambda: pack.analyze_supplied_git_pack(source),
            lambda: pack.analyze_supplied_git_pack_bytes(model_bytes=_canonical(source).encode()),
            lambda: pack.GitPackAnalysis(text),
            lambda: pack.GitPackAnalysis.from_dict(doc),
            lambda: pack.GitPackAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
            lambda: pack.verify_supplied_git_pack_analysis(report, model=source),
        )
        charge, sha1, sha256 = pack._Budget.charge, pack.hashlib.sha1, pack.hashlib.sha256
        for index, operation in enumerate(operations):
            state = {"used": 0, "hashed": False, "budgets": set()}

            def observed(budget, amount, state=state):
                self.assertFalse(state["hashed"], "charge occurred after first digest")
                state["used"] += amount
                state["budgets"].add(id(budget))
                return charge(budget, amount)

            def first_hash(*args, state=state, **kwargs):
                state["hashed"] = True
                return sha1(*args, **kwargs)

            def second_hash(*args, state=state, **kwargs):
                state["hashed"] = True
                return sha256(*args, **kwargs)

            with self.subTest(boundary=index):
                with (
                    patch.object(pack._Budget, "charge", observed),
                    patch.object(pack.hashlib, "sha1", first_hash),
                    patch.object(pack.hashlib, "sha256", second_hash),
                ):
                    operation()
                self.assertEqual(len(state["budgets"]), 1)
                required = state["used"]
                for cap in (required - 1, required):
                    used = [0]

                    def bounded(budget, amount, cap=cap, used=used):
                        if amount > cap - used[0]:
                            raise pack.GitPackAnalysisError(
                                "Transparent measured cumulative work ceiling"
                            )
                        used[0] += amount
                        return charge(budget, amount)

                    with patch.object(pack._Budget, "charge", bounded):
                        if cap < required:
                            self.assertPrehashDenied(operation)
                        else:
                            operation()
                            self.assertEqual(used[0], required)

    def test_checksum_mismatch_branch_also_funds_before_any_digest(self):
        raw = _fixture_bytes()[:-20] + b"\0" * 20
        model = _model(raw)
        charge = pack._Budget.charge
        hashed = [False]
        sha1 = pack.hashlib.sha1

        def observe(budget, amount):
            self.assertFalse(hashed[0])
            return charge(budget, amount)

        def digest(*args, **kwargs):
            hashed[0] = True
            return sha1(*args, **kwargs)

        with (
            patch.object(pack._Budget, "charge", observe),
            patch.object(pack.hashlib, "sha1", digest),
        ):
            report = pack.analyze_supplied_git_pack(model)
        self.assertTrue(hashed[0])
        self.assertEqual(report.to_dict()["pack"]["outcome"], "declared_pack_checksum_mismatch")

    def test_cohashed_false_reconstruction_identity_offsets_claims_and_checksum_reject(self):
        source = _model(_fixture_bytes())
        original = pack.analyze_supplied_git_pack(source).to_dict()
        changes = (
            lambda x: x["pack"]["entries"][1].__setitem__("reconstructed_base64", "YWJjZGVm"),
            lambda x: x["pack"]["entries"][1].__setitem__(
                "mechanical_object_sha1", _object_id("blob", b"abcdef")
            ),
            lambda x: x["pack"]["entries"][1].__setitem__("base_entry_offset", 13),
            lambda x: x["pack"].__setitem__("checksum_matches", False),
            lambda x: x["pack"].__setitem__("total_delta_instructions", 0),
            lambda x: x["source_model"].__setitem__("source_id", "other"),
            lambda x: x["claims"].__setitem__("source_authenticated", True),
            lambda x: x["effects"].__setitem__("checkout", "performed"),
        )
        for change in changes:
            changed = copy.deepcopy(original)
            change(changed)
            _readdress(changed)
            text, wrapper = _canonical(changed), _unsafe_wrapper(changed)
            for operation in (
                lambda text=text: pack.GitPackAnalysis(text),
                lambda changed=changed: pack.GitPackAnalysis.from_dict(changed),
                lambda text=text: pack.GitPackAnalysis.from_json(text),
                lambda wrapper=wrapper: wrapper.to_dict(),
                lambda wrapper=wrapper: wrapper.to_json(),
                lambda wrapper=wrapper: pack.verify_supplied_git_pack_analysis(
                    wrapper, model=source
                ),
            ):
                with self.assertRaises(pack.GitPackAnalysisError):
                    operation()

    def test_true_alternate_sources_are_not_original_source_verification(self):
        source = _model(_fixture_bytes())
        report = pack.analyze_supplied_git_pack(source)
        for other in (
            _model(_fixture_bytes(), label="other"),
            _model(_pack([_base(3, b"different")])),
        ):
            alternate = pack.analyze_supplied_git_pack(other)
            self.assertNotEqual(alternate.to_json(), report.to_json())
            with self.assertRaises(pack.GitPackAnalysisError):
                pack.verify_supplied_git_pack_analysis(report, model=other)

    def test_detachment_noncanonical_json_late_mutation_and_missing_wrapper_slots(self):
        source = _model(_fixture_bytes())
        report = pack.analyze_supplied_git_pack(source)
        text = report.to_json()
        doc = report.to_dict()
        doc["pack"]["entries"][0]["reconstructed_base64"] = ""
        source["source_id"] = "later"
        self.assertEqual(report.to_json(), text)
        with self.assertRaises(pack.GitPackAnalysisError):
            pack.GitPackAnalysis.from_json(json.dumps(report.to_dict(), indent=2))
        object.__setattr__(
            report,
            "document_json",
            text.replace('"checksum_matches":true', '"checksum_matches":false'),
        )
        with self.assertRaises(pack.GitPackAnalysisError):
            report.to_json()
        incomplete = object.__new__(pack.GitPackAnalysis)
        for operation in (
            incomplete.to_dict,
            incomplete.to_json,
            lambda: pack.verify_supplied_git_pack_analysis(incomplete, model=source),
        ):
            with self.assertRaises(pack.GitPackAnalysisError):
                operation()


if __name__ == "__main__":
    unittest.main()

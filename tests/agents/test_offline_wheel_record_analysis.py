"""Real supplied ZIP/RECORD bytes for the bounded Wheel integrity subset."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import struct
import unittest
import zlib
from unittest.mock import patch

from sunderkey import offline_wheel_record_analysis as wheel

PREFIX = "sample_pkg-1.0.dist-info/"
FILENAME = "sample_pkg-1.0-py3-none-any.whl"
STANDARD = [
    ("sample_pkg/__init__.py", b"value = 7\n"),
    (PREFIX + "METADATA", b"Metadata-Version: 2.1\nName: sample-pkg\nVersion: 1.0\n"),
    (PREFIX + "WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
]


def _rows(
    files: list[tuple[str, bytes]],
    *,
    missing: str = "",
    extra: str = "",
    digest_override: str = "",
    size_override: str = "",
) -> bytes:
    sink = io.StringIO(newline="")
    writer = csv.writer(sink, lineterminator="\n")
    for name, data in files:
        if name == missing:
            continue
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        )
        writer.writerow(
            [name, digest_override or "sha256=" + digest, size_override or str(len(data))]
        )
    if extra:
        writer.writerow([extra, "sha256=" + "A" * 43, "1"])
    writer.writerow([PREFIX + "RECORD", "", ""])
    return sink.getvalue().encode("ascii")


def _archive(
    files: list[tuple[str, bytes]],
    *,
    method: int = 0,
    descriptor: str = "none",
    local_name: str = "",
    local_crc_change: bool = False,
    central_crc_change: bool = False,
    suffix: bytes = b"",
    prepend: bytes = b"",
    compression_override: int | None = None,
    local_extra: bytes = b"",
    central_extra: bytes = b"",
) -> bytes:
    local = bytearray(prepend)
    central = bytearray()
    for index, (name, data) in enumerate(files):
        encoded = name.encode("ascii")
        local_encoded = (local_name if index == 0 and local_name else name).encode("ascii")
        if method == 8:
            codec = zlib.compressobj(level=6, wbits=-15)
            packed = codec.compress(data) + codec.flush()
        else:
            packed = data
        flags = 8 if descriptor != "none" else 0
        crc = zlib.crc32(data) & 0xFFFFFFFF
        listed_crc = crc ^ (1 if central_crc_change and index == 0 else 0)
        local_crc = crc ^ (1 if local_crc_change and index == 0 else 0)
        offset = len(local)
        local.extend(
            struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50,
                20,
                flags,
                compression_override if compression_override is not None and index == 0 else method,
                0,
                0,
                0 if flags else local_crc,
                0 if flags else len(packed),
                0 if flags else len(data),
                len(local_encoded),
                len(local_extra),
            )
        )
        local.extend(local_encoded)
        local.extend(local_extra)
        local.extend(packed)
        if descriptor == "signed":
            local.extend(struct.pack("<IIII", 0x08074B50, listed_crc, len(packed), len(data)))
        elif descriptor == "unsigned":
            local.extend(struct.pack("<III", listed_crc, len(packed), len(data)))
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                flags,
                method,
                0,
                0,
                listed_crc,
                len(packed),
                len(data),
                len(encoded),
                len(central_extra),
                0,
                0,
                0,
                0,
                offset,
            )
        )
        central.extend(encoded)
        central.extend(central_extra)
    central_start = len(local)
    local.extend(central)
    local.extend(
        struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), central_start, 0
        )
    )
    local.extend(suffix)
    return bytes(local)


def _model(
    *,
    files: list[tuple[str, bytes]] | None = None,
    record: bytes | None = None,
    **archive_options: object,
) -> dict:
    source_files = list(STANDARD if files is None else files)
    source_files.append((PREFIX + "RECORD", _rows(source_files) if record is None else record))
    return {
        "schema_version": 1,
        "source_id": "independent-synthetic-wheel",
        "wheel_filename": FILENAME,
        "wheel_base64": base64.b64encode(_archive(source_files, **archive_options)).decode("ascii"),
    }


def _alter(report: wheel.WheelRecordAnalysis, change: callable) -> dict:
    body = report.to_dict()
    change(body)
    source = body["source_model"]
    body["source_model_sha256"] = wheel._digest(wheel.MODEL_DOMAIN, source)
    unsigned = {
        key: value for key, value in body.items() if key not in ("analysis_id", "analysis_sha256")
    }
    body["analysis_sha256"] = wheel._digest(wheel.DOMAIN, unsigned)
    body["analysis_id"] = "WRA-" + body["analysis_sha256"][7:39].upper()
    return body


class OfflineWheelRecordAnalysisTests(unittest.TestCase):
    def test_public_fixture_is_fresh_and_internal_bytes_match(self) -> None:
        first = wheel.component_fixture()
        second = wheel.component_fixture()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        report = wheel.analyze_supplied_wheel_record(first).to_dict()
        self.assertEqual(report["component_id"], wheel.COMPONENT_ID)
        self.assertEqual(report["outcome"], "internal_integrity_matches")
        self.assertEqual(report["member_count"], 4)
        self.assertTrue(all(row["zip_crc32_matches"] for row in report["members"]))
        self.assertEqual(sum(row["record_digest_matches"] is True for row in report["members"]), 3)
        self.assertEqual(sum(row["record_exempt"] for row in report["members"]), 1)
        self.assertEqual(report["analysis_id"], "WRA-AEAFD0AEC743831D9C04F1A251D5FF2A")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:aeafd0aec743831d9c04f1a251d5ff2a9307d64346a1971ad3ea193a84d38f1e",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:ef435ad40241d7242149d778710d82f011367a690c0aba51409c391026424845",
        )

    def test_all_public_paths_recompute_owned_original(self) -> None:
        model = _model()
        report = wheel.analyze_supplied_wheel_record(model)
        canonical = json.dumps(model, sort_keys=True, separators=(",", ":")).encode("ascii")
        self.assertEqual(
            wheel.analyze_supplied_wheel_record_bytes(model_bytes=canonical).to_json(),
            report.to_json(),
        )
        self.assertEqual(wheel.WheelRecordAnalysis(report.to_json()).to_json(), report.to_json())
        self.assertEqual(
            wheel.WheelRecordAnalysis.from_dict(report.to_dict()).to_json(), report.to_json()
        )
        self.assertEqual(
            wheel.WheelRecordAnalysis.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            wheel.verify_supplied_wheel_record_analysis(report, model=model).to_json(),
            report.to_json(),
        )
        detached = report.to_dict()
        detached["members"][0]["name"] = "unrelated"
        self.assertNotEqual(detached["members"][0]["name"], report.to_dict()["members"][0]["name"])

    def test_stored_and_deflate_with_signed_and_unsigned_descriptors(self) -> None:
        for method in (0, 8):
            for descriptor in ("none", "signed", "unsigned"):
                with self.subTest(method=method, descriptor=descriptor):
                    model = _model(method=method, descriptor=descriptor)
                    body = wheel.analyze_supplied_wheel_record(model).to_dict()
                    self.assertEqual(body["outcome"], "internal_integrity_matches")
                    expected = {
                        "none": "none",
                        "signed": "with_signature",
                        "unsigned": "without_signature",
                    }
                    self.assertEqual(
                        {row["data_descriptor"] for row in body["members"]}, {expected[descriptor]}
                    )

    def test_csv_quoted_comma_and_quote_in_name(self) -> None:
        files = list(STANDARD) + [('sample_pkg/a,"b".py', b"x=1\n")]
        body = wheel.analyze_supplied_wheel_record(_model(files=files)).to_dict()
        self.assertEqual(body["outcome"], "internal_integrity_matches")
        self.assertIn('sample_pkg/a,"b".py', [row["name"] for row in body["members"]])

    def test_crc_mismatch_is_adverse_even_with_matching_record_digest(self) -> None:
        body = wheel.analyze_supplied_wheel_record(
            _model(central_crc_change=True, local_crc_change=True)
        ).to_dict()
        self.assertEqual(body["outcome"], "internal_integrity_mismatch")
        self.assertFalse(body["members"][0]["zip_crc32_matches"])
        self.assertTrue(body["members"][0]["record_digest_matches"])

    def test_record_digest_mismatch_is_adverse_even_with_matching_crc(self) -> None:
        wrong = "sha256=" + "A" * 43
        body = wheel.analyze_supplied_wheel_record(
            _model(record=_rows(STANDARD, digest_override=wrong))
        ).to_dict()
        self.assertEqual(body["outcome"], "internal_integrity_mismatch")
        self.assertTrue(all(row["zip_crc32_matches"] for row in body["members"]))
        self.assertFalse(body["members"][0]["record_digest_matches"])

    def test_record_size_mismatch_is_adverse(self) -> None:
        body = wheel.analyze_supplied_wheel_record(
            _model(record=_rows(STANDARD, size_override="99"))
        ).to_dict()
        self.assertEqual(body["outcome"], "internal_integrity_mismatch")
        self.assertFalse(body["members"][0]["record_size_matches"])

    def test_coherently_rewritten_payload_and_record_does_not_prove_authenticity(self) -> None:
        other = list(STANDARD)
        other[0] = (other[0][0], b"value = 8\n")
        original = wheel.analyze_supplied_wheel_record(_model())
        rewritten_model = _model(files=other)
        rewritten = wheel.analyze_supplied_wheel_record(rewritten_model)
        self.assertEqual(rewritten.to_dict()["outcome"], "internal_integrity_matches")
        self.assertNotEqual(
            original.to_dict()["source_wheel_sha256"], rewritten.to_dict()["source_wheel_sha256"]
        )
        self.assertFalse(any(rewritten.to_dict()["claims"].values()))
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.verify_supplied_wheel_record_analysis(rewritten, model=_model())

    def test_local_central_name_method_crc_and_size_disagreement_refused(self) -> None:
        for changes in (
            {"local_name": "sample_pkg/alternate.py"},
            {"compression_override": 8},
            {"local_crc_change": True},
        ):
            with self.subTest(changes=changes), self.assertRaises(wheel.WheelRecordAnalysisError):
                wheel.analyze_supplied_wheel_record(_model(**changes))

    def test_duplicate_case_alias_and_dot_alias_names_refused(self) -> None:
        for name in (
            "sample_pkg/__init__.py",
            "SAMPLE_PKG/__INIT__.PY",
            "sample_pkg/../escape.py",
            "sample_pkg//other.py",
            "sample_pkg\\other.py",
        ):
            with self.subTest(name=name), self.assertRaises(wheel.WheelRecordAnalysisError):
                wheel.analyze_supplied_wheel_record(_model(files=list(STANDARD) + [(name, b"x")]))

    def test_foreign_dist_info_alias_is_not_ordinary_wheel_content(self) -> None:
        for name in ("other-1.0.dist-info/METADATA", "other-1.0.DIST-INFO/METADATA"):
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(wheel.WheelRecordAnalysisError, "foreign dist-info"),
            ):
                wheel.analyze_supplied_wheel_record(
                    _model(files=list(STANDARD) + [(name, b"unrelated")])
                )

    def test_prefix_suffix_extra_and_hidden_local_bytes_refused(self) -> None:
        for options in (
            {"prepend": b"MZ"},
            {"suffix": b"tail"},
            {"local_extra": b"xx"},
            {"central_extra": b"xx"},
        ):
            with self.subTest(options=options), self.assertRaises(wheel.WheelRecordAnalysisError):
                wheel.analyze_supplied_wheel_record(_model(**options))

    def test_missing_extra_duplicate_and_self_hashed_record_rows_refused(self) -> None:
        cases = [
            _rows(STANDARD, missing=STANDARD[0][0]),
            _rows(STANDARD, extra="unlisted.py"),
            _rows(STANDARD) + _rows(STANDARD),
            _rows(STANDARD).replace(
                (PREFIX + "RECORD,,").encode(),
                (PREFIX + "RECORD,sha256=" + "A" * 43 + ",1").encode(),
            ),
        ]
        for value in cases:
            with self.subTest(value=value[-70:]), self.assertRaises(wheel.WheelRecordAnalysisError):
                wheel.analyze_supplied_wheel_record(_model(record=value))

    def test_record_legacy_signature_entries_are_exempt_not_verified(self) -> None:
        files = list(STANDARD) + [(PREFIX + "RECORD.jws", b"untrusted legacy bytes")]
        report = wheel.analyze_supplied_wheel_record(
            _model(files=files, record=_rows(STANDARD))
        ).to_dict()
        self.assertEqual(report["outcome"], "internal_integrity_matches")
        self.assertTrue(
            [row for row in report["members"] if row["name"].endswith("RECORD.jws")][0][
                "record_exempt"
            ]
        )
        self.assertFalse(report["claims"]["signature_verified"])

    def test_record_row_ceiling_is_checked_before_retaining_an_extra_row(self) -> None:
        files = list(STANDARD) + [
            (f"sample_pkg/file_{index:03d}.txt", b"x") for index in range(252)
        ]
        record = _rows(files)
        self.assertEqual(
            wheel.analyze_supplied_wheel_record(_model(files=files, record=record)).to_dict()[
                "member_count"
            ],
            wheel.MAX_MEMBERS,
        )
        duplicate = record.splitlines(keepends=True)[0]
        with self.assertRaisesRegex(wheel.WheelRecordAnalysisError, "RECORD row ceiling"):
            wheel.analyze_supplied_wheel_record(_model(files=files, record=record + duplicate))

    def test_record_hash_algorithm_alphabet_padding_and_size_subset_refused(self) -> None:
        good = _rows(STANDARD)
        digest = base64.urlsafe_b64encode(hashlib.sha256(STANDARD[0][1]).digest()).rstrip(b"=")
        for replacement in (
            b"md5=" + digest,
            b"sha256=" + digest + b"=",
            b"sha256=" + b"+" * 43,
            b"sha256=" + b"A" * 42,
        ):
            changed = good.replace(b"sha256=" + digest, replacement, 1)
            with (
                self.subTest(replacement=replacement),
                self.assertRaises(wheel.WheelRecordAnalysisError),
            ):
                wheel.analyze_supplied_wheel_record(_model(record=changed))

    def test_unsupported_flags_compression_and_nonregular_paths_refused(self) -> None:
        model = _model()
        raw = bytearray(base64.b64decode(model["wheel_base64"]))
        cases = []
        for offset, byte in ((6, 1), (8, 99)):
            changed = bytearray(raw)
            changed[offset] = byte
            cases.append(bytes(changed))
        for data in cases:
            alternate = dict(model, wheel_base64=base64.b64encode(data).decode())
            with self.assertRaises(wheel.WheelRecordAnalysisError):
                wheel.analyze_supplied_wheel_record(alternate)

    def test_native_model_alias_cycles_and_bytes_subclass_denied(self) -> None:
        original = _model()
        variants = [
            dict(original, schema_version=True),
            dict(original, schema_version=1.0),
            dict(original, schema_version="1"),
            dict(original, source_id=1),
            dict(original, wheel_base64=b"bytes"),
            dict(original, extra=1),
        ]
        cyclic = dict(original)
        cyclic["extra"] = cyclic
        variants.append(cyclic)
        for model in variants:
            with (
                self.subTest(type=type(model.get("schema_version"))),
                self.assertRaises(wheel.WheelRecordAnalysisError),
            ):
                wheel.analyze_supplied_wheel_record(model)

        class ForeignBytes(bytes):
            pass

        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.analyze_supplied_wheel_record_bytes(model_bytes=ForeignBytes(b"{}"))

    def test_raw_float_deep_and_oversize_denied_before_json_decoder(self) -> None:
        model = _model()
        normal = json.dumps(model, separators=(",", ":")).encode()
        cases = [
            normal.replace(b'"schema_version":1', b'"schema_version":1.0', 1),
            b"[" * (wheel.MAX_DEPTH + 1) + b"0" + b"]" * (wheel.MAX_DEPTH + 1),
            b" " * (wheel.MAX_MODEL_BYTES + 1),
        ]
        for raw in cases:
            with self.subTest(size=len(raw)):
                with patch.object(
                    wheel.json, "loads", side_effect=AssertionError("decoder reached")
                ):
                    with self.assertRaises(wheel.WheelRecordAnalysisError):
                        wheel.analyze_supplied_wheel_record_bytes(model_bytes=raw)

    def test_duplicate_raw_json_keys_are_not_silently_overwritten(self) -> None:
        normal = json.dumps(_model(), separators=(",", ":")).encode()
        duplicate = normal.replace(
            b'"schema_version":1,', b'"schema_version":1,"schema_version":1,', 1
        )
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.analyze_supplied_wheel_record_bytes(model_bytes=duplicate)

    def test_false_observation_readdress_cannot_replay(self) -> None:
        report = wheel.analyze_supplied_wheel_record(_model())
        for change in (
            lambda body: body.update(outcome="internal_integrity_mismatch"),
            lambda body: body["members"][0].update(record_digest_matches=False),
            lambda body: body["claims"].update(safe_to_install=True),
            lambda body: body["members"][0].update(computed_sha256="sha256:" + "0" * 64),
        ):
            with self.subTest(change=change):
                altered = _alter(report, change)
                with self.assertRaises(wheel.WheelRecordAnalysisError):
                    wheel.WheelRecordAnalysis.from_dict(altered)

    def test_mutated_frozen_wrapper_is_rechecked_at_export_and_verify(self) -> None:
        report = wheel.analyze_supplied_wheel_record(_model())
        object.__setattr__(
            report,
            "document_json",
            report.to_json().replace("internal_integrity_matches", "internal_integrity_mismatch"),
        )
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            report.to_dict()
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.verify_supplied_wheel_record_analysis(report, model=_model())

    def test_actual_archive_member_and_model_byte_ceiling(self) -> None:
        good = _model(
            files=list(STANDARD) + [("sample_pkg/large.bin", b"x" * wheel.MAX_MEMBER_BYTES)]
        )
        # The source archive ceiling can bind before this stored member; a
        # compressed method keeps the true expanded maximum within raw input.
        compressed = _model(
            files=list(STANDARD) + [("sample_pkg/large.bin", b"x" * wheel.MAX_MEMBER_BYTES)],
            method=8,
        )
        self.assertEqual(
            wheel.analyze_supplied_wheel_record(compressed).to_dict()["outcome"],
            "internal_integrity_matches",
        )
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.analyze_supplied_wheel_record(
                _model(
                    files=list(STANDARD)
                    + [("sample_pkg/large.bin", b"x" * (wheel.MAX_MEMBER_BYTES + 1))],
                    method=8,
                )
            )
        with self.assertRaises(wheel.WheelRecordAnalysisError):
            wheel.analyze_supplied_wheel_record(good)

    def test_all_eight_public_paths_fund_exact_work_before_first_sha(self) -> None:
        model = _model()
        report = wheel.analyze_supplied_wheel_record(model)
        text = report.to_json()
        document = report.to_dict()
        wire = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        operations = (
            lambda: wheel.analyze_supplied_wheel_record(model),
            lambda: wheel.analyze_supplied_wheel_record_bytes(model_bytes=wire),
            lambda: wheel.WheelRecordAnalysis(text),
            lambda: wheel.WheelRecordAnalysis.from_dict(document),
            lambda: wheel.WheelRecordAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
            lambda: wheel.verify_supplied_wheel_record_analysis(report, model=model),
        )
        original_charge = wheel._Budget.charge
        original_sha = wheel.hashlib.sha256
        for operation in operations:
            last: list[wheel._Budget] = []
            first_sha: list[int] = []

            def charge(budget: wheel._Budget, amount: int) -> None:
                last[:] = [budget]
                original_charge(budget, amount)

            def digest(*args: object, **kwargs: object) -> object:
                if not first_sha:
                    first_sha.append(last[-1].used)
                return original_sha(*args, **kwargs)

            with (
                patch.object(wheel._Budget, "charge", charge),
                patch.object(wheel.hashlib, "sha256", digest),
            ):
                operation()
            self.assertEqual(len(first_sha), 1)
            threshold = first_sha[0]
            self.assertLess(threshold, wheel.MAX_WORK)

            def lowered_charge(budget: wheel._Budget, amount: int) -> None:
                if amount > threshold - 1 - budget.used:
                    raise wheel.WheelRecordAnalysisError("Test work ceiling exhausted")
                original_charge(budget, amount)

            with patch.object(wheel._Budget, "charge", lowered_charge):
                with patch.object(
                    wheel.hashlib, "sha256", side_effect=AssertionError("hash reached")
                ):
                    with self.assertRaises(wheel.WheelRecordAnalysisError):
                        operation()


if __name__ == "__main__":
    unittest.main()

"""Independent supplied-octet controls for the bounded BGP UPDATE leaf."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import struct
import unittest
from unittest import mock

from sunderkey import offline_bgp_update_analysis as bgp


def _prefix(length: int, octets: bytes) -> bytes:
    if len(octets) != (length + 7) // 8:
        raise AssertionError("Independent prefix fixture length mismatch")
    return bytes([length]) + octets


def _attribute(flags: int, code: int, value: bytes, *, extended: bool = False) -> bytes:
    actual = flags | (0x10 if extended else 0)
    size = struct.pack("!H", len(value)) if extended else bytes([len(value)])
    return bytes([actual, code]) + size + value


def _base_attributes(*, width: int = 2, origin: int = 0) -> tuple[bytes, ...]:
    number = (64512).to_bytes(width, "big")
    return (
        _attribute(0x40, 1, bytes([origin])),
        _attribute(0x40, 2, bytes([2, 1]) + number),
        _attribute(0x40, 3, b"\xc0\x00\x02\x01"),
    )


def _update(
    *,
    withdrawn: tuple[bytes, ...] = (),
    attributes: tuple[bytes, ...] | None = None,
    announced: tuple[bytes, ...] = (_prefix(24, b"\xcb\x00\x71"),),
    marker: bytes = b"\xff" * 16,
    kind: int = 2,
    length_override: int | None = None,
) -> bytes:
    if attributes is None:
        attributes = _base_attributes()
    withdrawn_bytes = b"".join(withdrawn)
    attribute_bytes = b"".join(attributes)
    body = (
        struct.pack("!H", len(withdrawn_bytes))
        + withdrawn_bytes
        + struct.pack("!H", len(attribute_bytes))
        + attribute_bytes
        + b"".join(announced)
    )
    return marker + struct.pack("!H", length_override or 19 + len(body)) + bytes([kind]) + body


def _model(raw: bytes | None = None, *, width: int = 2, source_id: str = "fixture") -> dict:
    return {
        "schema_version": 1,
        "source_id": source_id,
        "asn_width_octets": width,
        "update_base64": base64.b64encode(raw if raw is not None else _update()).decode("ascii"),
    }


def _wire(report: bgp.BgpUpdateAnalysis) -> dict:
    return report.to_dict()


def _readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {
        key: value
        for key, value in changed.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        bgp.REPORT_DOMAIN.encode("ascii")
        + b"\n"
        + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    changed["analysis_sha256"] = "sha256:" + digest
    changed["analysis_id"] = "BGPA-" + digest[:32].upper()
    return changed


class BgpUpdateAnalysisTests(unittest.TestCase):
    def test_literal_fixture_and_semantic_golden(self) -> None:
        fixture = bgp.component_fixture()
        self.assertEqual(fixture, _model(source_id="synthetic-bgp-update"))
        self.assertEqual(
            fixture["update_base64"],
            "/////////////////////wAtAgAAABJAAQEAQAIEAgH8AEADBMAAAgEYywBx",
        )
        self.assertEqual(len(base64.b64decode(fixture["update_base64"])), 45)
        report = _wire(bgp.analyze_supplied_bgp_update(fixture))
        self.assertEqual(report["analysis_id"], "BGPA-F2A0501B056602E2E5081C3D52955BE9")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:f2a0501b056602e2e5081c3d52955be9ed00a2f33a1a6c1f593a094d9164421d",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:37e6e1e6c363184a203b16d706469376f1476e2462743c74aec2e976bce6d337",
        )
        self.assertEqual(
            report["update_sha256"],
            "sha256:b6175faaf7cfad337ddae805520a66f4e4efb681499bcc0d7e6942906264bc5f",
        )
        self.assertEqual(report["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(report["withdrawn_prefixes"], [])
        self.assertEqual(report["announced_prefixes"][0]["canonical_prefix"], "203.0.113.0/24")
        self.assertEqual(report["path_attributes"][0]["known_value"], {"origin": 0})
        self.assertEqual(
            report["path_attributes"][1]["known_value"],
            {"as_path_segments": [{"segment_type": 2, "count": 1, "as_numbers": [64512]}]},
        )
        self.assertEqual(
            report["path_attributes"][2]["known_value"], {"next_hop_ipv4": "192.0.2.1"}
        )
        self.assertEqual(report["effects"]["network"], "none")
        self.assertFalse(any(report["claims"].values()))

    def test_native_and_bytes_have_identical_canonical_report(self) -> None:
        source = _model()
        native = bgp.analyze_supplied_bgp_update(source)
        encoded = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        raw = bgp.analyze_supplied_bgp_update_bytes(model_bytes=encoded)
        self.assertEqual(native.to_json(), raw.to_json())

    def test_two_and_four_octet_as_premises(self) -> None:
        for width in (2, 4):
            raw = _update(attributes=_base_attributes(width=width))
            row = _wire(bgp.analyze_supplied_bgp_update(_model(raw, width=width)))
            self.assertEqual(
                row["path_attributes"][1]["known_value"]["as_path_segments"][0]["as_numbers"],
                [64512],
            )
            self.assertEqual(row["header"]["asn_width_octets_premise"], width)
            self.assertFalse(row["claims"]["asn_width_negotiated"])

    def test_wrong_as_width_is_not_silently_reinterpreted(self) -> None:
        raw = _update(attributes=_base_attributes(width=4))
        row = _wire(bgp.analyze_supplied_bgp_update(_model(raw, width=2)))
        segments = row["path_attributes"][1]["known_value"]["as_path_segments"]
        self.assertEqual(segments[0]["as_numbers"], [0])
        self.assertIn("as_path_segment_type_outside_set_sequence", row["unassessed_reasons"])

    def test_withdrawal_only_requires_no_path_attributes(self) -> None:
        raw = _update(withdrawn=(_prefix(24, b"\xc0\x00\x02"),), attributes=(), announced=())
        row = _wire(bgp.analyze_supplied_bgp_update(_model(raw)))
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(row["withdrawn_prefixes"][0]["canonical_prefix"], "192.0.2.0/24")

    def test_attributes_without_nlri_are_not_a_contradiction(self) -> None:
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(announced=()))))
        self.assertEqual(row["known_contradictions"], [])
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")

    def test_empty_update_is_exact_minimum_23_octets(self) -> None:
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=(), announced=()))))
        self.assertEqual(row["header"]["message_octets"], 23)

    def test_prefix_zero_32_and_ignored_trailing_bits(self) -> None:
        prefixes = (_prefix(0, b""), _prefix(32, b"\xc0\x00\x02\x01"), _prefix(23, b"\xcb\x00\x71"))
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(announced=prefixes))))
        self.assertEqual(
            [item["canonical_prefix"] for item in row["announced_prefixes"]],
            ["0.0.0.0/0", "192.0.2.1/32", "203.0.112.0/23"],
        )
        self.assertEqual(row["announced_prefixes"][2]["raw_prefix_hex"], "CB0071")
        self.assertTrue(row["announced_prefixes"][2]["nonzero_ignored_fill_bits"])

    def test_same_prefix_withdrawn_and_announced_is_advisory(self) -> None:
        prefix = _prefix(24, b"\xcb\x00\x71")
        row = _wire(
            bgp.analyze_supplied_bgp_update(
                _model(_update(withdrawn=(prefix,), announced=(prefix,)))
            )
        )
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertIn("same_prefix_withdrawn_and_announced_permitted", row["advisories"])

    def test_duplicate_prefixes_are_mechanical_advisory(self) -> None:
        prefix = _prefix(24, b"\xcb\x00\x71")
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(announced=(prefix, prefix)))))
        self.assertIn("repeated_announced_prefix", row["advisories"])

    def test_short_and_extended_attribute_length_forms(self) -> None:
        for extended in (False, True):
            attrs = (_attribute(0x40, 1, b"\x00", extended=extended),) + _base_attributes()[1:]
            row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
            self.assertEqual(row["path_attributes"][0]["extended_length"], extended)
            self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")

    def test_missing_each_mandatory_attribute_only_with_nlri(self) -> None:
        base = _base_attributes()
        for missing, name in ((0, "origin"), (1, "as_path"), (2, "next_hop")):
            raw = _update(attributes=base[:missing] + base[missing + 1 :])
            row = _wire(bgp.analyze_supplied_bgp_update(_model(raw)))
            self.assertIn(f"missing_mandatory_{name}_with_nlri", row["known_contradictions"])

    def test_duplicate_attribute_type_is_a_contradiction(self) -> None:
        attrs = _base_attributes() + (_attribute(0x40, 1, b"\x00"),)
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertIn("duplicate_attribute_type", row["known_contradictions"])

    def test_received_reserved_low_flag_bits_are_ignored(self) -> None:
        attrs = (_attribute(0x4F, 1, b"\x00"),) + _base_attributes()[1:]
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertEqual(row["known_contradictions"], [])
        self.assertEqual(row["path_attributes"][0]["flags_octet"], 0x4F)
        self.assertIn("received_reserved_low_attribute_flag_bits_ignored", row["advisories"])

    def test_mandatory_attribute_flag_mismatch_is_a_contradiction(self) -> None:
        attrs = (_attribute(0xC0, 1, b"\x00"),) + _base_attributes()[1:]
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertIn("mandatory_attribute_flags_mismatch", row["known_contradictions"])

    def test_origin_unsupported_value_and_length(self) -> None:
        for value in (b"\x03", b"\x00\x01", b""):
            attrs = (_attribute(0x40, 1, value),) + _base_attributes()[1:]
            row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
            self.assertIn("origin_length_or_value_invalid", row["known_contradictions"])

    def test_next_hop_length_is_checked_without_peer_semantics(self) -> None:
        attrs = _base_attributes()[:2] + (_attribute(0x40, 3, b"\xc0\x00\x02"),)
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertIn("next_hop_length_not_four", row["known_contradictions"])
        self.assertFalse(row["claims"]["next_hop_reachable"])

    def test_empty_and_multiple_as_segments(self) -> None:
        for path, expected in ((b"", []), (b"\x02\x01\xfc\x00\x01\x01\xfc\x01", [64512, 64513])):
            attrs = (_base_attributes()[0], _attribute(0x40, 2, path), _base_attributes()[2])
            row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
            values = [
                number
                for segment in row["path_attributes"][1]["known_value"]["as_path_segments"]
                for number in segment["as_numbers"]
            ]
            self.assertEqual(values, expected)

    def test_zero_count_and_overrunning_as_segment(self) -> None:
        for path, reason in (
            (b"\x02\x00", "as_path_empty_segment"),
            (b"\x02\x02\xfc\x00", "as_path_segment_length_exceeds_attribute"),
        ):
            attrs = (_base_attributes()[0], _attribute(0x40, 2, path), _base_attributes()[2])
            row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
            self.assertIn(reason, row["known_contradictions"])

    def test_unknown_segment_and_as4_attribute_are_unassessed(self) -> None:
        attrs = (
            _base_attributes()[0],
            _attribute(0x40, 2, b"\x03\x01\xfc\x00"),
            _base_attributes()[2],
            _attribute(0xC0, 17, b"\x00"),
        )
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertFalse(row["claims"]["as4_path_reconstructed"])
        self.assertIn("as4_attribute_reconstruction_not_attempted", row["unassessed_reasons"])

    def test_unknown_attribute_is_not_a_clean_verdict(self) -> None:
        attrs = _base_attributes() + (_attribute(0x80, 99, b"\x01"),)
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertEqual(row["path_attributes"][-1]["raw_value_hex"], "01")

    def test_known_contradiction_dominates_unassessed(self) -> None:
        attrs = (
            (_attribute(0x40, 1, b"\x03"),) + _base_attributes()[1:] + (_attribute(0x80, 99, b""),)
        )
        row = _wire(bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs))))
        self.assertEqual(row["analysis_status"], "contradicts_declared_subset")
        self.assertTrue(row["unassessed_reasons"])

    def test_exact_frame_marker_type_length_and_truncation(self) -> None:
        baseline = _update()
        invalid = (
            _update(marker=b"\x00" * 16),
            _update(kind=1),
            _update(length_override=len(baseline) + 1),
            baseline[:-1],
            baseline + b"\x00",
            baseline[:23],
        )
        for raw in invalid:
            with self.subTest(raw=raw.hex()), self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update(_model(raw))

    def test_declared_withdrawn_and_attribute_bounds(self) -> None:
        raw = bytearray(_update())
        raw[19:21] = b"\xff\xff"
        for candidate in (bytes(raw), _update(attributes=(_attribute(0x40, 1, b"\x00")[:-1],))):
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update(_model(candidate))

    def test_prefix_above_ipv4_width_is_contradiction(self) -> None:
        row = _wire(
            bgp.analyze_supplied_bgp_update(
                _model(_update(announced=(_prefix(33, b"\x01\x02\x03\x04\x05"),)))
            )
        )
        self.assertIn("announced_prefix_length_above_ipv4_32", row["known_contradictions"])

    def test_aggregate_prefix_ceiling_refuses_before_extra_row(self) -> None:
        raw = _update(announced=(_prefix(0, b""),) * (bgp.MAX_PREFIXES + 1))
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            bgp.analyze_supplied_bgp_update(_model(raw))

    def test_local_attribute_ceiling_refuses_before_extra_row(self) -> None:
        attrs = _base_attributes() + (_attribute(0x80, 90, b""),) * (bgp.MAX_ATTRIBUTES - 2)
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            bgp.analyze_supplied_bgp_update(_model(_update(attributes=attrs)))

    def test_exact_native_types_duplicate_keys_and_raw_numbers(self) -> None:
        for bad in (True, 2.0, "2", [], {}):
            source = _model()
            source["asn_width_octets"] = bad
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update(source)
        source = _model()
        text = json.dumps(source, separators=(",", ":"))
        variants = (
            text[:-1] + ',"source_id":"second"}',
            text.replace('"schema_version":1', '"schema_version":1.0'),
            text.replace('"schema_version":1', '"schema_version":--1'),
        )
        for raw in variants:
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update_bytes(model_bytes=raw.encode("ascii"))

    def test_native_subclasses_cycles_and_incomplete_wrappers(self) -> None:
        class Text(str):
            pass

        class Number(int):
            pass

        for field, bad in (("source_id", Text("fixture")), ("schema_version", Number(1))):
            source = _model()
            source[field] = bad
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update(source)
        source = _model()
        source["extra"] = source
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            bgp.analyze_supplied_bgp_update(source)
        incomplete = object.__new__(bgp.BgpUpdateAnalysis)
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            incomplete.to_dict()

    def test_canonical_base64_and_source_limit(self) -> None:
        for wire in ("*", "AAAA", "AAAA=", "=" * 8, "A" * 5):
            source = _model()
            source["update_base64"] = wire
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                bgp.analyze_supplied_bgp_update(source)

    def test_all_eight_public_forms_exact_replay(self) -> None:
        source = _model()
        report = bgp.analyze_supplied_bgp_update(source)
        text = report.to_json()
        body = report.to_dict()
        forms = (
            report,
            bgp.analyze_supplied_bgp_update_bytes(model_bytes=json.dumps(source).encode("ascii")),
            bgp.BgpUpdateAnalysis(text),
            bgp.BgpUpdateAnalysis.from_dict(body),
            bgp.BgpUpdateAnalysis.from_json(text),
            bgp.verify_supplied_bgp_update_analysis(report, model=source),
        )
        self.assertTrue(all(form.to_json() == text for form in forms))
        self.assertEqual(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")), text)

    def test_coherently_readdressed_false_conclusion_is_refused(self) -> None:
        source = _model()
        body = bgp.analyze_supplied_bgp_update(source).to_dict()
        body["analysis_status"] = "unassessed"
        forged = _readdress(body)
        for entry in (
            lambda: bgp.BgpUpdateAnalysis.from_dict(forged),
            lambda: bgp.BgpUpdateAnalysis.from_json(
                json.dumps(forged, sort_keys=True, separators=(",", ":"))
            ),
        ):
            with self.assertRaises(bgp.BgpUpdateAnalysisError):
                entry()

    def test_separate_original_source_and_mutation_detachment(self) -> None:
        source = _model()
        report = bgp.analyze_supplied_bgp_update(source)
        prior = report.to_json()
        source["source_id"] = "later"
        self.assertEqual(report.to_json(), prior)
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            bgp.verify_supplied_bgp_update_analysis(report, model=source)
        result = report.to_dict()
        result["announced_prefixes"][0]["canonical_prefix"] = "other"
        self.assertEqual(report.to_json(), prior)

    def test_report_native_forgery_and_promotion_flags(self) -> None:
        report = bgp.analyze_supplied_bgp_update(_model())
        body = report.to_dict()
        body["claims"]["route_accepted"] = True
        with self.assertRaises(bgp.BgpUpdateAnalysisError):
            bgp.BgpUpdateAnalysis.from_dict(_readdress(body))

    def test_real_and_reduced_structural_ceiling(self) -> None:
        source = _model()
        self.assertLess(len(_update()), bgp.MAX_UPDATE_BYTES)
        self.assertEqual(
            _wire(bgp.analyze_supplied_bgp_update(source))["accounting"]["update_octets"], 45
        )
        with (
            mock.patch.object(bgp, "MAX_UPDATE_BYTES", 44),
            self.assertRaises(bgp.BgpUpdateAnalysisError),
        ):
            bgp.analyze_supplied_bgp_update(source)

    def test_all_eight_public_work_thresholds_refuse_before_first_hash(self) -> None:
        source = _model()
        report = bgp.analyze_supplied_bgp_update(source)
        text = report.to_json()
        body = report.to_dict()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        operations = (
            lambda: bgp.analyze_supplied_bgp_update(source),
            lambda: bgp.analyze_supplied_bgp_update_bytes(model_bytes=raw),
            lambda: bgp.BgpUpdateAnalysis(text),
            lambda: bgp.BgpUpdateAnalysis.from_dict(body),
            lambda: bgp.BgpUpdateAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
            lambda: bgp.verify_supplied_bgp_update_analysis(report, model=source),
        )
        original_charge = bgp._Budget.charge
        for operation in operations:

            def measured_cost(current_operation=operation) -> int:
                costs: list[int] = []

                def measured(budget: bgp._Budget, amount: int) -> None:
                    original_charge(budget, amount)
                    costs.append(budget.used)

                with mock.patch.object(bgp._Budget, "charge", measured):
                    current_operation()
                return max(costs)

            exact = measured_cost()

            # Leave the content-addressed advertised MAX_WORK unchanged.
            # Enforce a reduced per-operation cap at the actual charge seam.
            def reduced(cap: int):
                def charge(budget: bgp._Budget, amount: int) -> None:
                    if amount > cap - budget.used:
                        raise bgp.BgpUpdateAnalysisError("Reduced cumulative work exhausted")
                    original_charge(budget, amount)

                return charge

            with mock.patch.object(bgp._Budget, "charge", reduced(exact)):
                operation()
            with (
                mock.patch.object(bgp._Budget, "charge", reduced(exact - 1)),
                mock.patch.object(
                    bgp.hashlib, "sha256", side_effect=AssertionError("hash before refusal")
                ),
                self.assertRaises(bgp.BgpUpdateAnalysisError),
            ):
                operation()


if __name__ == "__main__":
    unittest.main()

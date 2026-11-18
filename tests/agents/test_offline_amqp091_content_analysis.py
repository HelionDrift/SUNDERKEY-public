"""Independent supplied-octet controls for the bounded AMQP publish leaf."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from unittest import mock

from sunderkey import offline_amqp091_content_analysis as amqp


def _frame(kind: int, channel: int, payload: bytes) -> bytes:
    return (
        bytes([kind])
        + channel.to_bytes(2, "big")
        + len(payload).to_bytes(4, "big")
        + payload
        + b"\xce"
    )


def _publish(
    exchange: bytes = b"x", routing_key: bytes = b"key", *, ticket: int = 0, bits: int = 0
) -> bytes:
    return (
        b"\x00\x3c\x00\x28"
        + ticket.to_bytes(2, "big")
        + bytes([len(exchange)])
        + exchange
        + bytes([len(routing_key)])
        + routing_key
        + bytes([bits])
    )


def _header(size: int, *, class_id: int = 60, weight: int = 0, flags: bytes = b"\x00\x00") -> bytes:
    return class_id.to_bytes(2, "big") + weight.to_bytes(2, "big") + size.to_bytes(8, "big") + flags


def _source(*frames: bytes, source_id: str = "independent-amqp-fixture") -> dict:
    return {
        "schema_version": 1,
        "source_id": source_id,
        "direction": "client_to_server",
        "frames_base64": base64.b64encode(b"".join(frames)).decode("ascii"),
    }


def _single(body: bytes = b"abc", chunks: tuple[bytes, ...] | None = None) -> dict:
    if chunks is None:
        chunks = (body,) if body else ()
    return _source(
        _frame(1, 1, _publish()),
        _frame(2, 1, _header(len(body))),
        *(_frame(3, 1, chunk) for chunk in chunks),
    )


def _report(source: dict) -> dict:
    return amqp.analyze_supplied_amqp091_content(source).to_dict()


def _readdress(document: dict) -> dict:
    changed = copy.deepcopy(document)
    body = {
        key: value
        for key, value in changed.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        amqp.REPORT_DOMAIN.encode("ascii")
        + b"\n"
        + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    changed["analysis_sha256"] = "sha256:" + digest
    changed["analysis_id"] = "AMQA-" + digest[:32].upper()
    return changed


class Amqp091ContentAnalysisTests(unittest.TestCase):
    def test_public_fixture_is_fresh_and_has_two_interleaved_publications(self) -> None:
        first = amqp.component_fixture()
        second = amqp.component_fixture()
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(
            first["frames_base64"],
            "AQABAAAACwA8ACgAAAF4AWEAzgEAAgAAAAsAPAAoAAABeQFiAc4CAAEAAAAO"
            "ADwAAAAAAAAAAAADAADOAgACAAAADgA8AAAAAAAAAAAAAwAAzgMAAQAAAAFh"
            "zgMAAgAAAAN4eXrOAwABAAAAAmJjzg==",
        )
        first["source_id"] = "changed"
        self.assertEqual(second["source_id"], "synthetic-amqp-publish-content")
        report = _report(second)
        self.assertEqual(report["analysis_id"], "AMQA-50544EB621585EAD1578D248F0B94A78")
        self.assertEqual(
            report["analysis_sha256"],
            "sha256:50544eb621585ead1578d248f0b94a78cc556e0617bb32535720e088a844e3a9",
        )
        self.assertEqual(
            report["source_model_sha256"],
            "sha256:1185bcba044ffe691e5b6f0da4a5806076d6d8c6c3690f1b93695d6ced8c31b4",
        )
        self.assertEqual(
            report["frame_stream_sha256"],
            "sha256:ac648c433b1a665e76fc71038cd4fc6627564ba41acc30b41d4d755d9bcd107c",
        )
        self.assertEqual(report["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(report["accounting"]["frame_count"], 7)
        self.assertEqual(report["accounting"]["complete_publication_count"], 2)
        self.assertEqual([item["channel"] for item in report["publications"]], [1, 2])
        self.assertEqual(
            [item["body_hex"] for item in report["publications"]], ["616263", "78797A"]
        )
        self.assertFalse(any(report["claims"].values()))
        self.assertTrue(all(value == "none" for value in report["effects"].values()))

    def test_single_complete_publish_and_exact_octet_offsets(self) -> None:
        source = _single(b"abc")
        row = _report(source)
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual([item["type_octet"] for item in row["frames"]], [1, 2, 3])
        self.assertEqual(row["frames"][0]["offset"], 0)
        self.assertEqual(row["frames"][1]["offset"], 8 + len(_publish()))
        self.assertEqual(row["publications"][0]["body_hex"], "616263")
        self.assertEqual(row["publications"][0]["body_frame_indices"], [2])

    def test_fragmented_body_and_same_channel_sequential_publications(self) -> None:
        source = _source(
            _frame(1, 7, _publish()),
            _frame(2, 7, _header(3)),
            _frame(3, 7, b"a"),
            _frame(3, 7, b"bc"),
            _frame(1, 7, _publish(routing_key=b"next")),
            _frame(2, 7, _header(0)),
        )
        row = _report(source)
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(
            [item["assembly_state"] for item in row["publications"]], ["complete", "complete"]
        )
        self.assertEqual(row["publications"][1]["body_frame_indices"], [])

    def test_cross_channel_interleaving_does_not_mix_bodies(self) -> None:
        source = _source(
            _frame(1, 1, _publish(routing_key=b"a")),
            _frame(1, 2, _publish(routing_key=b"b")),
            _frame(2, 1, _header(2)),
            _frame(2, 2, _header(2)),
            _frame(3, 2, b"B"),
            _frame(3, 1, b"AA"),
            _frame(3, 2, b"B"),
        )
        row = _report(source)
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual([item["body_hex"] for item in row["publications"]], ["4141", "4242"])

    def test_zero_length_content_needs_header_but_no_body_frame(self) -> None:
        row = _report(_single(b""))
        self.assertEqual(row["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(row["publications"][0]["assembly_state"], "complete")
        self.assertEqual(row["accounting"]["frame_count"], 2)

    def test_missing_header_and_body_are_incomplete_supplied_prefixes(self) -> None:
        for frames, expected_state in (
            ((_frame(1, 1, _publish()),), "awaiting_header"),
            (
                (_frame(1, 1, _publish()), _frame(2, 1, _header(3)), _frame(3, 1, b"a")),
                "awaiting_body",
            ),
        ):
            with self.subTest(state=expected_state):
                row = _report(_source(*frames))
                self.assertEqual(row["analysis_status"], "unassessed")
                self.assertEqual(row["publications"][0]["assembly_state"], expected_state)
                self.assertIn(
                    "supplied_stream_ends_with_pending_content", row["unassessed_reasons"]
                )

    def test_same_channel_method_interrupts_not_a_delivery_or_failure_claim(self) -> None:
        row = _report(
            _source(
                _frame(1, 1, _publish()),
                _frame(2, 1, _header(3)),
                _frame(3, 1, b"a"),
                _frame(1, 1, _publish(routing_key=b"new")),
                _frame(2, 1, _header(0)),
            )
        )
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertEqual(
            [item["assembly_state"] for item in row["publications"]],
            ["interrupted", "complete"],
        )
        self.assertFalse(row["claims"]["message_delivered"])

    def test_second_header_on_pending_channel_is_contradiction(self) -> None:
        row = _report(
            _source(
                _frame(1, 1, _publish()),
                _frame(2, 1, _header(2)),
                _frame(2, 1, _header(2)),
                _frame(3, 1, b"ab"),
            )
        )
        self.assertIn("second_header_before_content_completion", row["known_contradictions"])

    def test_orphan_header_and_body_are_not_clean(self) -> None:
        for kind, payload in ((2, _header(0)), (3, b"x")):
            row = _report(_source(_frame(kind, 1, payload)))
            self.assertEqual(row["analysis_status"], "contradicts_declared_subset")

    def test_unknown_method_with_following_content_is_unassessed(self) -> None:
        row = _report(
            _source(
                _frame(1, 1, b"\x00\x3c\x00\x32"),
                _frame(2, 1, _header(1)),
                _frame(3, 1, b"x"),
            )
        )
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertEqual(row["publications"], [])

    def test_heartbeat_or_other_framed_extension_withholds_clean_result(self) -> None:
        row = _report(_source(_frame(4, 0, b""), *_single_frames()))
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertEqual(row["accounting"]["complete_publication_count"], 1)

    def test_unsupported_channel_frame_does_not_make_following_header_orphan(self) -> None:
        row = _report(_source(_frame(4, 1, b""), _frame(2, 1, _header(0))))
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertEqual(row["known_contradictions"], [])
        self.assertIn("frame_type_outside_method_header_body_subset", row["unassessed_reasons"])
        self.assertIn("header_without_supported_pending_method", row["unassessed_reasons"])

    def test_method_ticket_bits_and_raw_shortstrings_remain_visible(self) -> None:
        row = _report(
            _source(
                _frame(1, 1, _publish(b"", b"key", ticket=1, bits=0xFF)),
                _frame(2, 1, _header(0)),
            )
        )
        self.assertIn("basic_publish_reserved_ticket_not_zero", row["known_contradictions"])
        self.assertIn("basic_publish_unused_bit_positions_nonzero", row["unassessed_reasons"])
        method = row["publications"][0]["method"]
        self.assertEqual(method["exchange_hex"], "")
        self.assertTrue(method["mandatory"])
        self.assertTrue(method["immediate"])

    def test_nonzero_unused_publish_bits_withhold_clean_conclusion(self) -> None:
        row = _report(_source(_frame(1, 1, _publish(bits=0x80)), _frame(2, 1, _header(0))))
        self.assertEqual(row["known_contradictions"], [])
        self.assertEqual(row["analysis_status"], "unassessed")
        self.assertIn("basic_publish_unused_bit_positions_nonzero", row["unassessed_reasons"])

    def test_utf8_and_zero_octet_shortstring_declarations(self) -> None:
        for value, reason in (
            (b"\x00", "basic_publish_shortstr_contains_zero_octet"),
            (b"\xff", "basic_publish_shortstr_not_utf8"),
        ):
            row = _report(_source(_frame(1, 1, _publish(value)), _frame(2, 1, _header(0))))
            self.assertIn(reason, row["known_contradictions"])

    def test_wrong_header_class_weight_and_nonzero_properties(self) -> None:
        cases = (
            (_header(0, class_id=61), "content_header_class_mismatch", "known_contradictions"),
            (_header(0, weight=1), "content_header_weight_not_zero", "known_contradictions"),
            (
                _header(0, flags=b"\x80\x00\x00"),
                "basic_properties_outside_zero_flags_subset",
                "unassessed_reasons",
            ),
        )
        for header, reason, channel in cases:
            with self.subTest(reason=reason):
                row = _report(_source(_frame(1, 1, _publish()), _frame(2, 1, header)))
                self.assertIn(reason, row[channel])

    def test_body_overrun_and_body_before_header_are_contradictions(self) -> None:
        for source, reason in (
            (
                _source(_frame(1, 1, _publish()), _frame(2, 1, _header(2)), _frame(3, 1, b"abc")),
                "content_body_exceeds_declared_octets",
            ),
            (_source(_frame(1, 1, _publish()), _frame(3, 1, b"x")), "body_precedes_content_header"),
        ):
            row = _report(source)
            self.assertIn(reason, row["known_contradictions"])

    def test_connection_channel_zero_cannot_cleanly_publish_content(self) -> None:
        row = _report(_source(_frame(1, 0, _publish()), _frame(2, 0, _header(0))))
        self.assertIn("basic_publish_uses_connection_channel_zero", row["known_contradictions"])
        self.assertIn("content_header_uses_connection_channel_zero", row["known_contradictions"])

    def test_bad_frame_end_and_declared_length_refuse_before_partial_report(self) -> None:
        valid = _frame(1, 1, _publish())
        candidates = (
            valid[:-1] + b"\x00",
            valid[:-1],
            valid[:3] + b"\xff\xff\xff\xff" + valid[7:],
            valid + b"\x01",
        )
        for candidate in candidates:
            with (
                self.subTest(wire=candidate.hex()),
                self.assertRaises(amqp.Amqp091ContentAnalysisError),
            ):
                amqp.analyze_supplied_amqp091_content(_source(candidate))

    def test_truncated_method_and_header_fields_refuse(self) -> None:
        candidates = (
            _source(_frame(1, 1, b"\x00\x3c")),
            _source(_frame(1, 1, b"\x00\x3c\x00\x28\x00\x00\x01")),
            _source(_frame(1, 1, _publish()), _frame(2, 1, b"\x00" * 13)),
        )
        for source in candidates:
            with self.assertRaises(amqp.Amqp091ContentAnalysisError):
                amqp.analyze_supplied_amqp091_content(source)

    def test_exact_native_types_cycles_and_duplicate_raw_keys(self) -> None:
        for field, value in (
            ("schema_version", True),
            ("direction", None),
            ("source_id", 1),
            ("frames_base64", []),
        ):
            source = _single()
            source[field] = value
            with self.assertRaises(amqp.Amqp091ContentAnalysisError):
                amqp.analyze_supplied_amqp091_content(source)
        source = _single()
        source["extra"] = source
        with self.assertRaises(amqp.Amqp091ContentAnalysisError):
            amqp.analyze_supplied_amqp091_content(source)
        raw = json.dumps(_single(), separators=(",", ":"))
        with self.assertRaises(amqp.Amqp091ContentAnalysisError):
            amqp.analyze_supplied_amqp091_content_bytes(
                model_bytes=(raw[:-1] + ',"source_id":"second"}').encode("ascii")
            )

    def test_source_bytes_and_native_have_identical_report(self) -> None:
        source = _single()
        native = amqp.analyze_supplied_amqp091_content(source)
        encoded = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        parsed = amqp.analyze_supplied_amqp091_content_bytes(model_bytes=encoded)
        self.assertEqual(native.to_json(), parsed.to_json())

    def test_complete_public_replay_and_separate_original(self) -> None:
        source = _single()
        report = amqp.analyze_supplied_amqp091_content(source)
        text, document = report.to_json(), report.to_dict()
        forms = (
            amqp.Amqp091ContentAnalysis(text),
            amqp.Amqp091ContentAnalysis.from_dict(document),
            amqp.Amqp091ContentAnalysis.from_json(text),
            amqp.verify_supplied_amqp091_content_analysis(report, model=source),
        )
        self.assertTrue(all(item.to_json() == text for item in forms))
        self.assertEqual(json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":")), text)

    def test_mutation_detachment_and_alternate_original_denial(self) -> None:
        source = _single()
        report = amqp.analyze_supplied_amqp091_content(source)
        original = report.to_json()
        source["source_id"] = "changed"
        self.assertEqual(report.to_json(), original)
        with self.assertRaises(amqp.Amqp091ContentAnalysisError):
            amqp.verify_supplied_amqp091_content_analysis(report, model=source)
        exported = report.to_dict()
        exported["publications"][0]["body_hex"] = "00"
        self.assertEqual(report.to_json(), original)

    def test_coherently_readdressed_false_assembly_is_refused(self) -> None:
        source = _single()
        document = _report(source)
        document["publications"][0]["assembly_state"] = "incomplete"
        forged = _readdress(document)
        for operation in (
            lambda: amqp.Amqp091ContentAnalysis.from_dict(forged),
            lambda: amqp.Amqp091ContentAnalysis.from_json(
                json.dumps(forged, sort_keys=True, separators=(",", ":"))
            ),
        ):
            with self.assertRaises(amqp.Amqp091ContentAnalysisError):
                operation()

    def test_software_stream_and_frame_ceilings(self) -> None:
        valid = _single()
        self.assertLess(len(base64.b64decode(valid["frames_base64"])), amqp.MAX_STREAM_BYTES)
        with (
            mock.patch.object(amqp, "MAX_STREAM_BYTES", 8),
            self.assertRaises(amqp.Amqp091ContentAnalysisError),
        ):
            amqp.analyze_supplied_amqp091_content(valid)
        source = _source(_frame(3, 1, b"abc"))
        with (
            mock.patch.object(amqp, "MAX_FRAME_PAYLOAD", 2),
            self.assertRaises(amqp.Amqp091ContentAnalysisError),
        ):
            amqp.analyze_supplied_amqp091_content(source)

    def test_genuine_retained_report_overflow_refuses_before_first_hash(self) -> None:
        body = b"x" * 60_000
        frames = []
        for channel in range(1, 5):
            frames.extend(
                (
                    _frame(1, channel, _publish()),
                    _frame(2, channel, _header(len(body))),
                    _frame(3, channel, body),
                )
            )
        source = _source(*frames)
        self.assertLess(len(base64.b64decode(source["frames_base64"])), amqp.MAX_STREAM_BYTES)
        with (
            mock.patch.object(
                amqp.hashlib, "sha256", side_effect=AssertionError("hash before cap")
            ),
            self.assertRaises(amqp.Amqp091ContentAnalysisError),
        ):
            amqp.analyze_supplied_amqp091_content(source)

    def test_all_eight_public_work_thresholds_refuse_before_first_hash(self) -> None:
        source = _single()
        report = amqp.analyze_supplied_amqp091_content(source)
        text, body = report.to_json(), report.to_dict()
        raw = json.dumps(source, sort_keys=True, separators=(",", ":")).encode("ascii")
        operations = (
            lambda: amqp.analyze_supplied_amqp091_content(source),
            lambda: amqp.analyze_supplied_amqp091_content_bytes(model_bytes=raw),
            lambda: amqp.Amqp091ContentAnalysis(text),
            lambda: amqp.Amqp091ContentAnalysis.from_dict(body),
            lambda: amqp.Amqp091ContentAnalysis.from_json(text),
            lambda: report.to_dict(),
            lambda: report.to_json(),
            lambda: amqp.verify_supplied_amqp091_content_analysis(report, model=source),
        )
        original_charge = amqp._Budget.charge
        for operation in operations:
            costs: list[int] = []

            def measured(budget: amqp._Budget, amount: int) -> None:
                original_charge(budget, amount)
                costs.append(budget.used)

            with mock.patch.object(amqp._Budget, "charge", measured):
                operation()
            exact = max(costs)

            def reduced(budget: amqp._Budget, amount: int) -> None:
                if amount > exact - 1 - budget.used:
                    raise amqp.Amqp091ContentAnalysisError("Reduced work ceiling exhausted")
                original_charge(budget, amount)

            with (
                mock.patch.object(amqp._Budget, "charge", reduced),
                mock.patch.object(
                    amqp.hashlib, "sha256", side_effect=AssertionError("hash before refusal")
                ),
                self.assertRaises(amqp.Amqp091ContentAnalysisError),
            ):
                operation()


def _single_frames() -> tuple[bytes, ...]:
    return (_frame(1, 1, _publish()), _frame(2, 1, _header(1)), _frame(3, 1, b"x"))


if __name__ == "__main__":
    unittest.main()

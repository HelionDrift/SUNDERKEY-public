"""Synthetic supplied-byte controls, never WebSocket acquisition or emission."""

import ast
import base64
import hashlib
import itertools
import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_websocket_frame_analysis as module
from sunderkey.offline_websocket_frame_analysis import (
    WebSocketFrameAnalysis,
    WebSocketFrameAnalysisError,
    analyze_supplied_websocket_frames,
    parse_supplied_websocket_frame_model,
    verify_supplied_websocket_frame_analysis,
)

HELLO = b"\x81\x05Hello"
MASKED_HELLO = bytes.fromhex("818537fa213d7f9f4d5158")


def component_fixture():
    """A fresh exact model containing only the literal inert server Hello frame."""
    return {
        "schema_version": 1,
        "semantics_profile": "rfc6455-unextended-message-boundary-prefix-v1",
        "source_id": "synthetic:websocket-hello",
        "sender_role": "server",
        "initial_state": "message_boundary",
        "stream_base64": "gQVIZWxsbw==",
    }


def supplied_model(raw, role="server"):
    model = component_fixture()
    model["sender_role"] = role
    model["stream_base64"] = base64.b64encode(raw).decode("ascii")
    return model


def inert_frame(opcode, payload=b"", *, fin=True, masked=False, rsv=0, width=None):
    """Construct tiny synthetic test octets only, with no production send interface."""
    length = len(payload)
    width = width if width is not None else 7 if length < 126 else 16 if length < 65536 else 64
    header = bytes([(128 if fin else 0) | rsv | opcode])
    mask = 128 if masked else 0
    if width == 7:
        header += bytes([mask | length])
    elif width == 16:
        header += bytes([mask | 126]) + length.to_bytes(2, "big")
    else:
        header += bytes([mask | 127]) + length.to_bytes(8, "big")
    if masked:
        key = b"\x01\x02\x03\x04"
        return header + key + bytes(value ^ key[index % 4] for index, value in enumerate(payload))
    return header + payload


def analysis(raw=HELLO, role="server"):
    return analyze_supplied_websocket_frames(supplied_model(raw, role))


def codes(document, category=None):
    return {
        row["code"]
        for row in document["observations"]
        if category is None or row["category"] == category
    }


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    canonical = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    digest = (
        "sha256:"
        + hashlib.sha256(
            module.DOMAIN.encode("ascii") + b"\n" + canonical.encode("ascii")
        ).hexdigest()
    )
    return {"analysis_id": "WFA-" + digest[7:39].upper(), "analysis_sha256": digest, **body}


class WebSocketFrameAnalysisTests(unittest.TestCase):
    def test_literal_genuine_fixture_identity_is_frozen(self):
        report = analyze_supplied_websocket_frames(component_fixture())
        document = report.to_dict()
        self.assertEqual(document["analysis_id"], "WFA-8D74F3875E545019F308BF162F35716A")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:8d74f3875e545019f308bf162f35716aa010af06d105938b9807a3eb41160b34",
        )
        self.assertEqual(
            document["source"]["model_sha256"],
            "sha256:54d012f43dd6075436af00356910ca6168ae69aff0239ad6fe29d04839f6470c",
        )
        self.assertEqual(len(report.to_json()), 3390)
        self.assertEqual(document["summary"]["parser_work_used"], 30)

    def test_literal_hello_has_exact_offsets_hashes_and_complete_message(self):
        report = analyze_supplied_websocket_frames(component_fixture())
        document = report.to_dict()
        self.assertEqual(document["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(document["observations"], [])
        frame = document["frames"][0]
        self.assertEqual((frame["start"], frame["payload_start"], frame["end"]), (0, 2, 7))
        self.assertEqual(
            (frame["opcode"], frame["length_encoding"], frame["payload_length"]), (1, 7, 5)
        )
        self.assertIs(frame["fin"], True)
        self.assertIs(frame["masked"], False)
        self.assertEqual(frame["wire_sha256"], "sha256:" + hashlib.sha256(HELLO).hexdigest())
        self.assertEqual(
            frame["decoded_payload_sha256"], "sha256:" + hashlib.sha256(b"Hello").hexdigest()
        )
        self.assertEqual(
            document["messages"],
            [
                {
                    "index": 0,
                    "first_frame_index": 0,
                    "last_frame_index": 0,
                    "message_type": "text",
                    "fragment_count": 1,
                    "payload_bytes": 5,
                    "payload_sha256": "sha256:" + hashlib.sha256(b"Hello").hexdigest(),
                    "complete": True,
                    "utf8_status": "valid",
                    "termination": "fin",
                }
            ],
        )
        self.assertEqual(document["summary"]["consumed_bytes"], 7)
        self.assertEqual(document["summary"]["unconsumed_bytes"], 0)
        self.assertEqual(report.to_json(), WebSocketFrameAnalysis.from_dict(document).to_json())
        self.assertEqual(
            report.to_json(), WebSocketFrameAnalysis.from_json(report.to_json()).to_json()
        )
        self.assertEqual(
            report.to_json(),
            verify_supplied_websocket_frame_analysis(report, model=component_fixture()).to_json(),
        )

    def test_literal_masked_hello_and_sender_roles(self):
        document = analysis(MASKED_HELLO, "client").to_dict()
        self.assertEqual(document["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(document["frames"][0]["payload_start"], 6)
        self.assertEqual(
            document["messages"][0]["payload_sha256"],
            "sha256:" + hashlib.sha256(b"Hello").hexdigest(),
        )
        for raw, role in ((HELLO, "client"), (MASKED_HELLO, "server")):
            with self.subTest(role=role):
                result = analysis(raw, role).to_dict()
                self.assertIn("mask_direction_mismatch", codes(result, "violation"))
                self.assertEqual(result["analysis_status"], "structural_violation")

    def test_minimal_7_16_64_bit_lengths(self):
        for size in (0, 125, 126, 65535, 65536):
            with self.subTest(size=size):
                document = analysis(inert_frame(2, b"A" * size)).to_dict()
                self.assertEqual(document["analysis_status"], "consistent_with_supported_subset")
                self.assertEqual(document["frames"][0]["payload_length"], size)
                self.assertEqual(document["messages"][0]["payload_bytes"], size)

    def test_nonminimal_length_encodings_are_contradictions(self):
        for payload, width in ((b"A", 16), (b"A" * 125, 16), (b"", 64), (b"A" * 126, 64)):
            with self.subTest(size=len(payload), width=width):
                result = analysis(inert_frame(2, payload, width=width)).to_dict()
                self.assertIn("payload_length_not_minimal", codes(result, "violation"))

    def test_length_high_bit_is_invalid_not_a_budget_or_truncation(self):
        document = analysis(b"\x82\x7f\x80" + b"\x00" * 7).to_dict()
        self.assertEqual(document["analysis_status"], "structural_violation")
        self.assertEqual(codes(document), {"payload_length_msb_set"})
        self.assertEqual(document["frames"], [])

    def test_declaration_budget_precedes_payload_allocation_and_hash(self):
        raw = b"\x82\x7f" + (module.MAX_FRAME_PAYLOAD_BYTES + 1).to_bytes(8, "big")
        with patch.object(module, "_sha", side_effect=AssertionError("hash reached")):
            with self.assertRaisesRegex(WebSocketFrameAnalysisError, "software budget: declared"):
                analysis(raw)

    def test_supported_frame_payload_boundary(self):
        result = analysis(inert_frame(2, b"A" * module.MAX_FRAME_PAYLOAD_BYTES)).to_dict()
        self.assertEqual(result["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(result["messages"][0]["payload_bytes"], module.MAX_FRAME_PAYLOAD_BYTES)

    def test_every_literal_header_key_payload_truncation_is_incomplete(self):
        cases = [HELLO, MASKED_HELLO, inert_frame(2, b"A" * 126), inert_frame(2, b"A" * 65536)]
        for raw in cases:
            header_size = (
                6 if raw == MASKED_HELLO else 4 if raw[1] == 126 else 10 if raw[1] == 127 else 2
            )
            cutoffs = set(range(header_size + 1)) | {len(raw) - 1}
            for cutoff in sorted(cutoffs):
                with self.subTest(size=len(raw), cutoff=cutoff):
                    result = analysis(
                        raw[:cutoff], "client" if raw == MASKED_HELLO else "server"
                    ).to_dict()
                    self.assertEqual(result["analysis_status"], "incomplete_supplied_prefix")
                    self.assertEqual(result["frames"], [])
                    self.assertEqual(result["summary"]["unconsumed_bytes"], cutoff)

    def test_finished_prefix_is_retained_before_a_truncated_next_frame(self):
        document = analysis(HELLO + b"\x89").to_dict()
        self.assertEqual(document["summary"]["frame_count"], 1)
        self.assertEqual(document["summary"]["message_count"], 1)
        self.assertEqual(document["summary"]["consumed_bytes"], len(HELLO))
        self.assertEqual(document["summary"]["unconsumed_bytes"], 1)
        self.assertIn("truncated_base_header", codes(document))

    def test_fragmented_utf8_codepoint_with_interleaved_controls(self):
        raw = (
            inert_frame(1, b"\xe2", fin=False)
            + inert_frame(9, b"\xff")
            + inert_frame(0, b"\x82", fin=False)
            + inert_frame(10, b"x")
            + inert_frame(0, b"\xac")
        )
        document = analysis(raw).to_dict()
        self.assertEqual(document["analysis_status"], "consistent_with_supported_subset")
        message = document["messages"][0]
        self.assertEqual(
            (message["first_frame_index"], message["last_frame_index"], message["fragment_count"]),
            (0, 4, 3),
        )
        self.assertEqual(
            message["payload_sha256"], "sha256:" + hashlib.sha256(b"\xe2\x82\xac").hexdigest()
        )
        self.assertEqual(message["utf8_status"], "valid")

    def test_binary_and_ping_bytes_are_not_utf8_text(self):
        document = analysis(inert_frame(2, b"\xff") + inert_frame(9, b"\xff")).to_dict()
        self.assertEqual(document["analysis_status"], "consistent_with_supported_subset")
        self.assertEqual(document["messages"][0]["utf8_status"], "not_applicable")

    def test_invalid_utf8_including_fragment_completion_is_observed(self):
        cases = [
            inert_frame(1, b"\xff"),
            inert_frame(1, b"\xc0\xaf"),
            inert_frame(1, b"\xed\xa0\x80"),
            inert_frame(1, b"\xe2", fin=False) + inert_frame(0, b"x"),
            inert_frame(1, b"\xe2", fin=False) + inert_frame(0),
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                result = analysis(raw).to_dict()
                self.assertIn("text_message_invalid_utf8", codes(result, "violation"))
                self.assertEqual(result["messages"][0]["utf8_status"], "invalid")

    def test_unfinished_text_prefix_is_not_invalid_utf8(self):
        result = analysis(inert_frame(1, b"\xe2", fin=False)).to_dict()
        self.assertEqual(result["analysis_status"], "incomplete_supplied_prefix")
        self.assertEqual(result["messages"][0]["utf8_status"], "valid_prefix")
        self.assertIs(result["messages"][0]["complete"], False)
        self.assertNotIn("text_message_invalid_utf8", codes(result))

    def test_fragment_order_and_new_data_interleaving_fail(self):
        for raw, code in (
            (inert_frame(0, b"A"), "continuation_without_open_message"),
            (
                inert_frame(1, b"A", fin=False) + inert_frame(2, b"B"),
                "new_data_during_fragmented_message",
            ),
        ):
            with self.subTest(code=code):
                self.assertIn(code, codes(analysis(raw).to_dict(), "violation"))

    def test_control_fin_and_payload_limits_include_truncated_controls(self):
        for raw, expected in (
            (inert_frame(9, fin=False), "control_frame_fragmented"),
            (inert_frame(10, b"A" * 126), "control_payload_exceeds_125"),
            (b"\x89\x7e\x00\x7e", "control_payload_exceeds_125"),
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, codes(analysis(raw).to_dict(), "violation"))
        result = analysis(inert_frame(9, b"A" * 125)).to_dict()
        self.assertEqual(result["analysis_status"], "consistent_with_supported_subset")

    def test_close_empty_and_known_codes_are_structurally_distinguished(self):
        self.assertEqual(
            analysis(inert_frame(8)).to_dict()["frames"][0]["close_code_class"], "absent"
        )
        for code in (1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011):
            with self.subTest(code=code):
                result = analysis(inert_frame(8, code.to_bytes(2, "big") + b"inert")).to_dict()
                self.assertEqual(result["frames"][0]["close_code_class"], "rfc6455_defined")
                self.assertEqual(result["frames"][0]["close_reason_utf8"], "valid")

    def test_forbidden_and_out_of_range_close_codes(self):
        for code in (0, 999, 1004, 1005, 1006, 1015, 5000, 65535):
            with self.subTest(code=code):
                result = analysis(inert_frame(8, code.to_bytes(2, "big"))).to_dict()
                self.assertEqual(result["analysis_status"], "structural_violation")
                self.assertTrue(codes(result, "violation"))

    def test_defined_codes_do_not_certify_role_specific_initiation_or_echo(self):
        for role, code in itertools.product(("client", "server"), (1010, 1011)):
            with self.subTest(role=role, code=code):
                raw = inert_frame(8, code.to_bytes(2, "big"), masked=role == "client")
                result = analysis(raw, role).to_dict()
                self.assertEqual(result["frames"][0]["close_code_class"], "rfc6455_defined")
                self.assertEqual(result["observations"], [])
                self.assertIs(result["live_use_approved"], False)
                self.assertTrue(
                    any(
                        "role-specific initiation or a peer echo" in text
                        for text in result["limitations"]
                    )
                )

    def test_unknown_later_registered_and_private_codes_are_unassessed(self):
        for code, label in (
            (1012, "unassessed_later_or_extension"),
            (2999, "unassessed_later_or_extension"),
            (3000, "unassessed_registered_application"),
            (4000, "unassessed_private_application"),
            (4999, "unassessed_private_application"),
        ):
            with self.subTest(code=code):
                result = analysis(inert_frame(8, code.to_bytes(2, "big"))).to_dict()
                self.assertEqual(result["analysis_status"], "unsupported")
                self.assertEqual(result["frames"][0]["close_code_class"], label)
                self.assertEqual(codes(result, "violation"), set())

    def test_close_one_byte_and_invalid_reason_are_adverse(self):
        for raw, code in (
            (inert_frame(8, b"x"), "close_payload_length_one"),
            (inert_frame(8, b"\x03\xe8\xff"), "close_reason_invalid_utf8"),
        ):
            with self.subTest(code=code):
                self.assertIn(code, codes(analysis(raw).to_dict(), "violation"))

    def test_no_data_after_sender_close_but_no_peer_response_inference(self):
        for opcode in (0, 1, 2):
            self.assertIn(
                "data_after_sender_close",
                codes(analysis(inert_frame(8) + inert_frame(opcode)).to_dict()),
            )
        result = analysis(inert_frame(8) + inert_frame(9) + inert_frame(10)).to_dict()
        self.assertEqual(result["analysis_status"], "consistent_with_supported_subset")
        self.assertIs(result["summary"]["sender_close_observed"], True)
        self.assertNotIn("connection_closed", result["summary"])

    def test_close_can_interrupt_an_unfinished_message_without_new_obligation(self):
        result = analysis(inert_frame(1, b"\xe2", fin=False) + inert_frame(8)).to_dict()
        self.assertEqual(codes(result, "violation"), set())
        self.assertEqual(result["messages"][0]["termination"], "sender_close")
        self.assertIs(result["messages"][0]["complete"], False)

    def test_rsv_and_all_reserved_opcodes_withhold_payload_interpretation(self):
        cases = [inert_frame(1, b"\xff", rsv=bit) for bit in (16, 32, 64)]
        cases += [inert_frame(opcode, b"\xff") for opcode in (*range(3, 8), *range(11, 16))]
        for raw in cases:
            with self.subTest(raw=raw):
                result = analysis(raw + HELLO).to_dict()
                self.assertEqual(result["analysis_status"], "unsupported")
                self.assertEqual(result["frames"][0]["payload_interpretation"], "unassessed")
                self.assertIsNone(result["frames"][0]["decoded_payload_sha256"])
                self.assertEqual(result["messages"], [])
                self.assertNotIn("text_message_invalid_utf8", codes(result))
                self.assertEqual(result["summary"]["unconsumed_bytes"], len(HELLO))

    def test_supported_prefix_survives_unsupported_fragment(self):
        result = analysis(
            inert_frame(1, b"A", fin=False) + inert_frame(0, b"\xff", rsv=16)
        ).to_dict()
        self.assertEqual(result["analysis_status"], "unsupported")
        self.assertEqual(result["messages"][0]["payload_bytes"], 1)
        self.assertIs(result["messages"][0]["complete"], False)
        self.assertEqual(result["messages"][0]["utf8_status"], "valid_prefix")

    def test_independent_small_fragment_close_control_state_oracle(self):
        symbols = ((1, True), (1, False), (0, True), (0, False), (9, True), (8, True))
        for size in (1, 2, 3):
            for sequence in itertools.product(symbols, repeat=size):
                opened = closed = invalid = False
                for opcode, fin in sequence:
                    if opcode in (0, 1) and closed:
                        invalid = True
                        break
                    if opcode == 1:
                        if opened:
                            invalid = True
                            break
                        opened = not fin
                    elif opcode == 0:
                        if not opened:
                            invalid = True
                            break
                        opened = not fin
                    elif opcode == 8:
                        closed = True
                raw = b"".join(inert_frame(opcode, fin=fin) for opcode, fin in sequence)
                result = analysis(raw).to_dict()
                with self.subTest(sequence=sequence):
                    self.assertEqual(bool(codes(result, "violation")), invalid)
                    if not invalid:
                        self.assertEqual(bool(codes(result, "incomplete")), opened)

    def test_native_model_families_aliases_and_missing_fields_fail_before_hash(self):
        class Text(str):
            pass

        class Number(int):
            pass

        class Object(dict):
            pass

        bad = [Object(component_fixture()), [], None]
        for field, values in {
            "schema_version": (True, 1.0, Number(1)),
            "sender_role": ([], {}, Text("server"), None),
            "source_id": (Text("synthetic:ok"), "x" * 129, "bad/id"),
            "stream_base64": (Text("gQVIZWxsbw=="), b"gQVIZWxsbw=="),
            "initial_state": (Text("message_boundary"), "unknown"),
        }.items():
            for value in values:
                model = component_fixture()
                model[field] = value
                bad.append(model)
        for field in component_fixture():
            model = component_fixture()
            del model[field]
            bad.append(model)
        model = component_fixture()
        model["callback"] = lambda: None
        bad.append(model)
        with patch.object(module, "_sha", side_effect=AssertionError("hash reached")):
            for model in bad:
                with self.subTest(model=model), self.assertRaises(WebSocketFrameAnalysisError):
                    analyze_supplied_websocket_frames(model)

    def test_base64_canonical_shape_and_decode_budget(self):
        for encoded in ("gQVIZWxsbw", "gQVIZWxsbw==\n", "!!!!", "gQVIZWxsbx==", "===="):
            model = component_fixture()
            model["stream_base64"] = encoded
            with self.subTest(encoded=encoded), self.assertRaises(WebSocketFrameAnalysisError):
                analyze_supplied_websocket_frames(model)
        model = supplied_model(b"A" * (module.MAX_STREAM_BYTES + 1))
        with patch.object(module.base64, "b64decode", side_effect=AssertionError("decode reached")):
            with self.assertRaisesRegex(WebSocketFrameAnalysisError, "software budget"):
                analyze_supplied_websocket_frames(model)

    def test_bytes_loader_and_canonical_model_identity_ignore_json_whitespace(self):
        native = component_fixture()
        raw = json.dumps(native, indent=2).encode("ascii")
        self.assertEqual(parse_supplied_websocket_frame_model(raw), native)
        self.assertEqual(
            analyze_supplied_websocket_frames(parse_supplied_websocket_frame_model(raw)).to_json(),
            analyze_supplied_websocket_frames(native).to_json(),
        )
        for value in (bytearray(raw), memoryview(raw), "{}", b"\xff", b""):
            with self.subTest(kind=type(value)), self.assertRaises(WebSocketFrameAnalysisError):
                parse_supplied_websocket_frame_model(value)

    def test_raw_depth_nodes_strings_bytes_before_decoder(self):
        cases = [
            "[" * 16 + "0" + "]" * 16,
            "[" + ",".join("0" for _ in range(module.MAX_NATIVE_NODES)) + "]",
            '"' + "x" * (module._MAX_BASE64 + 1) + '"',
            " " * (module.MAX_DOCUMENT_BYTES + 1),
        ]
        with patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")):
            for raw in cases:
                with self.subTest(size=len(raw)), self.assertRaises(WebSocketFrameAnalysisError):
                    WebSocketFrameAnalysis.from_json(raw)

    def test_raw_integer_grammar_float_nonfinite_and_range_before_decoder(self):
        invalid = (
            "--1",
            "---0",
            "01",
            "-01",
            "1.0",
            "1e3",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "1" * 1000,
        )
        with patch.object(module.json, "loads", side_effect=AssertionError("decoder reached")):
            for token in invalid:
                with self.subTest(token=token[:24]), self.assertRaises(WebSocketFrameAnalysisError):
                    WebSocketFrameAnalysis.from_json('{"schema_version":' + token + "}")
        for token in ("-0", "-9223372036854775808", "9223372036854775807"):
            with self.subTest(token=token):
                self.assertEqual(module._decode(token), int(token))

    def test_duplicate_keys_and_escaped_nonnative_strings_fail_cleanly(self):
        for raw in ('{"schema_version":1,"schema_version":1}', '"\\ud800"', '"\\u00a0"'):
            with self.subTest(raw=raw), self.assertRaises(WebSocketFrameAnalysisError):
                WebSocketFrameAnalysis.from_json(raw)

    def test_native_cycles_shared_escaped_graphs_and_queued_nodes_precede_hash(self):
        cycle = []
        cycle.append(cycle)
        shared = ["\\" * 8192] * 40
        cases = [cycle, [0] * module.MAX_NATIVE_NODES, [shared] * 4, {"x": 2**63}, {"x": 1.0}]
        with (
            patch.object(module, "_sha", side_effect=AssertionError("hash reached")),
            patch.object(module.json, "dumps", side_effect=AssertionError("serialization reached")),
        ):
            for value in cases:
                with self.subTest(kind=type(value)), self.assertRaises(WebSocketFrameAnalysisError):
                    analyze_supplied_websocket_frames(value)

    def test_record_message_observation_work_and_document_ceilings_fail_closed(self):
        cases = [
            ("MAX_FRAMES", 1, inert_frame(9) + inert_frame(10)),
            ("MAX_MESSAGES", 1, inert_frame(1) + inert_frame(2)),
            ("MAX_MESSAGE_BYTES", 1, inert_frame(2, b"AB")),
            ("MAX_OBSERVATIONS", 1, HELLO + HELLO),
            ("MAX_PARSER_WORK", 2, HELLO),
            ("MAX_DOCUMENT_BYTES", 1000, HELLO),
        ]
        for field, value, raw in cases:
            with self.subTest(field=field), patch.object(module, field, value):
                with self.assertRaisesRegex(WebSocketFrameAnalysisError, "software budget"):
                    analysis(raw, "client" if field == "MAX_OBSERVATIONS" else "server")

    def test_next_frame_count_budget_rejects_before_that_frame_hash(self):
        first, second = inert_frame(9, b"A"), inert_frame(10, b"B")
        observed = []
        real = module._sha

        def watched(value):
            observed.append(value)
            return real(value)

        with (
            patch.object(module, "MAX_FRAMES", 1),
            patch.object(module, "_sha", side_effect=watched),
        ):
            with self.assertRaisesRegex(WebSocketFrameAnalysisError, "software budget"):
                analysis(first + second)
        self.assertIn(first, observed)
        self.assertNotIn(second, observed)

    def test_false_readdressed_derivations_cannot_replay_embedded_source(self):
        original = analysis().to_dict()
        changes = [
            lambda d: d["frames"][0].update(end=6),
            lambda d: d["frames"][0].update(fin=1),
            lambda d: d["frames"][0].update(payload_length=5.0),
            lambda d: d["messages"][0].update(payload_bytes=4),
            lambda d: d["messages"][0].update(complete=1),
            lambda d: d["messages"][0].update(payload_sha256="sha256:" + "0" * 64),
            lambda d: d["summary"].update(frame_count=True),
            lambda d: d["source"].update(stream_sha256="sha256:" + "0" * 64),
            lambda d: d.update(analysis_status="unsupported"),
            lambda d: d.update(qualification_claimed=0),
            lambda d: d["effects"].update(target="permitted"),
            lambda d: d["bounds"].update(maximum_frames=4096),
        ]
        for change in changes:
            document = deepcopy(original)
            change(document)
            with self.subTest(change=change), self.assertRaises(WebSocketFrameAnalysisError):
                WebSocketFrameAnalysis.from_dict(readdress(document))

    def test_observation_order_and_stream_permutation_are_source_bound(self):
        raw = inert_frame(9, fin=False, masked=True)
        document = analysis(raw).to_dict()
        self.assertGreaterEqual(len(document["observations"]), 2)
        document["observations"].reverse()
        with self.assertRaises(WebSocketFrameAnalysisError):
            WebSocketFrameAnalysis.from_json(json.dumps(readdress(document)))
        first, second = inert_frame(1, b"A"), inert_frame(2, b"B")
        with self.assertRaises(WebSocketFrameAnalysisError):
            verify_supplied_websocket_frame_analysis(
                analysis(first + second), model=supplied_model(second + first)
            )

    def test_valid_foreign_source_or_role_is_not_original_source(self):
        report = analysis()
        for model in (supplied_model(inert_frame(2, b"Hello")), supplied_model(HELLO, "client")):
            with self.assertRaises(WebSocketFrameAnalysisError):
                verify_supplied_websocket_frame_analysis(report, model=model)
        model = component_fixture()
        model["source_id"] = "synthetic:different"
        other = analyze_supplied_websocket_frames(model)
        self.assertNotEqual(other.to_json(), report.to_json())
        with self.assertRaises(WebSocketFrameAnalysisError):
            verify_supplied_websocket_frame_analysis(other, model=component_fixture())

    def test_detached_original_model_result_and_fixture(self):
        original = component_fixture()
        frozen = deepcopy(original)
        report = analyze_supplied_websocket_frames(original)
        before = report.to_json()
        original["stream_base64"] = ""
        original["source_id"] = "synthetic:changed"
        detached = report.to_dict()
        detached["source_model"]["stream_base64"] = ""
        detached["frames"][0]["start"] = 99
        self.assertEqual(report.to_json(), before)
        self.assertEqual(
            verify_supplied_websocket_frame_analysis(report, model=frozen).to_json(), before
        )
        self.assertEqual(component_fixture(), frozen)

    def test_incomplete_and_forged_public_wrapper_slots_fail_on_use(self):
        empty = object.__new__(WebSocketFrameAnalysis)
        for method in (
            empty.to_dict,
            empty.to_json,
            lambda: verify_supplied_websocket_frame_analysis(empty, model=component_fixture()),
        ):
            with self.assertRaises(WebSocketFrameAnalysisError):
                method()
        forged = object.__new__(WebSocketFrameAnalysis)
        document = analysis().to_dict()
        document["summary"]["consumed_bytes"] = 0
        object.__setattr__(forged, "document_json", json.dumps(readdress(document)))
        with self.assertRaises(WebSocketFrameAnalysisError):
            verify_supplied_websocket_frame_analysis(forged, model=component_fixture())

        class Foreign(WebSocketFrameAnalysis):
            pass

        with self.assertRaises(WebSocketFrameAnalysisError):
            Foreign(analysis().to_json())

    def test_no_effects_live_truth_or_rendered_application_values(self):
        document = analysis().to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S05")
        self.assertEqual(document["capability_id"], "army.gb.d06.s05")
        self.assertEqual(document["wave_id"], "IW2-012")
        self.assertIs(document["offline_only"], True)
        for field in ("server_vulnerability_proven", "live_use_approved", "qualification_claimed"):
            self.assertIs(document[field], False)
        self.assertEqual(set(document["effects"].values()), {"none"})
        summary_text = json.dumps({"frames": document["frames"], "messages": document["messages"]})
        self.assertNotIn("Hello", summary_text)
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            node.names[0].name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
        }
        self.assertFalse(imports & {"socket", "subprocess", "os", "requests", "urllib", "pathlib"})


if __name__ == "__main__":
    unittest.main()

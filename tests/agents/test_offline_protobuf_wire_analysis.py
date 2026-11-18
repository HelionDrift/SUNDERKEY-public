"""Independent arithmetic encoders, original-source replay and bounded wire controls."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from sunderkey import offline_protobuf_wire_analysis as m


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def varint(value):
    result = []
    while value >= 128:
        result.append(value % 128 + 128)
        value //= 128
    return bytes((*result, value))


def tag(number, wire):
    return varint(number * 8 + wire)


def scalar(number, value):
    return tag(number, 0) + varint(value)


def length(number, value):
    return tag(number, 2) + varint(len(value)) + value


def declaration(number=1, kind="uint64", repeated=False, nested=None):
    return {
        "field_number": number,
        "field_type": kind,
        "repeated": repeated,
        "message_type": nested,
    }


def model(payload=b"", fields=None, messages=None):
    return {
        "schema_version": 1,
        "source_id": "independent.wire",
        "root_message": "Root",
        "messages": [{"message_id": "Root", "fields": [] if fields is None else fields}]
        if messages is None
        else messages,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }


def report(value):
    return m.analyze_supplied_protobuf_wire(value).to_dict()


def readdress(document):
    body = {
        key: value
        for key, value in document.items()
        if key not in ("analysis_id", "analysis_sha256")
    }
    digest = hashlib.sha256(
        b"sunderkey.offline-protobuf-wire-analysis.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    document["analysis_sha256"] = "sha256:" + digest
    document["analysis_id"] = "PWA-" + digest[:32].upper()
    return document


class ProtobufWireAnalysisTests(unittest.TestCase):
    def test_literal_fixture_goldens_and_independent_byte_encoder(self):
        fixture = m.component_fixture()
        payload = scalar(1, 150) + length(2, b"testing") + length(3, bytes((1, 2, 3)))
        payload += length(4, scalar(1, 7)) + length(9, b"\xff\0")
        self.assertEqual(base64.b64decode(fixture["payload_base64"]), payload)
        actual = report(fixture)
        self.assertEqual(actual["analysis_id"], "PWA-02722282DD5DD43063BDF55EAEE4A331")
        self.assertEqual(
            actual["analysis_sha256"],
            "sha256:02722282dd5dd43063bdf55eaee4a3316939431e8d1cd196f01954acc3ff8002",
        )
        self.assertEqual(
            actual["source_model_sha256"],
            "sha256:4096206c844230f74ac16c27d9fb6d595b34553e11ecc6b8b4430f8351c07cbe",
        )
        self.assertEqual(
            actual["source_payload_sha256"],
            "sha256:2f57c5035af80e17efca93a248982d423fe73f44a1a22dc16f9813e2b11f49e2",
        )
        self.assertEqual(
            actual["summary"], {"occurrences": 6, "packed_values": 3, "unassessed_occurrences": 1}
        )
        rows = actual["wire_occurrences"]
        self.assertEqual(rows[0]["numeric_value"]["declared_value_decimal"], "150")
        self.assertTrue(rows[1]["utf8_valid"])
        self.assertEqual(
            [item["declared_value_decimal"] for item in rows[2]["packed_values"]], ["-1", "1", "-2"]
        )
        self.assertEqual(rows[4]["parent_occurrence_index"], 3)
        self.assertEqual(rows[5]["typing_status"], "unknown_field_opaque")
        self.assertEqual(actual, readdress(copy.deepcopy(actual)))

    def test_every_public_round_trip_replays_full_source(self):
        fixture = m.component_fixture()
        original = m.analyze_supplied_protobuf_wire(fixture)
        candidates = (
            m.ProtobufWireAnalysis(original.to_json()),
            m.ProtobufWireAnalysis.from_dict(original.to_dict()),
            m.ProtobufWireAnalysis.from_json(original.to_json()),
            m.analyze_supplied_protobuf_wire_bytes(model_bytes=canonical(fixture).encode()),
            m.verify_supplied_protobuf_wire_analysis(original, model=fixture),
        )
        for candidate in candidates:
            self.assertEqual(candidate.to_json(), original.to_json())

    def test_empty_wire_message_is_valid_not_an_absence_assertion(self):
        actual = report(model())
        self.assertEqual(actual["wire_occurrences"], [])
        self.assertEqual(actual["source_payload_bytes"], 0)
        self.assertFalse(actual["claims"]["generated_object_equivalence_proven"])

    def test_unsigned_varints_literal_and_arithmetic_table(self):
        numbers = (0, 1, 127, 128, 150, 16383, 16384, 2**31, 2**32 - 1, 2**63, 2**64 - 1)
        for value in numbers:
            with self.subTest(value=value):
                actual = report(model(scalar(1, value), [declaration()]))
                numeric = actual["wire_occurrences"][0]["numeric_value"]
                self.assertEqual(numeric["wire_unsigned_decimal"], str(value))
                self.assertEqual(numeric["declared_value_decimal"], str(value))
        self.assertEqual(varint(150), b"\x96\x01")
        self.assertEqual(varint(2**64 - 1), b"\xff" * 9 + b"\x01")

    def test_zigzag_signed_width_extrema_and_dense_small_oracle(self):
        for kind, width in (("sint32", 32), ("sint64", 64)):
            values = (*range(-32, 33), -(2 ** (width - 1)), 2 ** (width - 1) - 1)
            payload = b"".join(
                scalar(1, 2 * value if value >= 0 else -2 * value - 1) for value in values
            )
            actual = report(model(payload, [declaration(kind=kind, repeated=True)]))
            self.assertEqual(
                [
                    row["numeric_value"]["declared_value_decimal"]
                    for row in actual["wire_occurrences"]
                ],
                [str(value) for value in values],
            )

    def test_int32_sign_extension_is_distinct_from_unsigned_truncation(self):
        values = (0, 2**31 - 1, 2**31, 2**32 - 1, 2**64 - 2**31, 2**64 - 1)
        actual = report(
            model(b"".join(scalar(1, value) for value in values), [declaration(kind="int32")])
        )
        self.assertEqual(
            [row["numeric_value"]["declared_value_decimal"] for row in actual["wire_occurrences"]],
            ["0", str(2**31 - 1), None, None, str(-(2**31)), "-1"],
        )
        self.assertEqual(actual["summary"]["unassessed_occurrences"], 2)

    def test_int64_twos_complement_unsigned_wire_is_retained(self):
        values = (0, 2**63 - 1, 2**63, 2**64 - 1)
        actual = report(
            model(b"".join(scalar(1, value) for value in values), [declaration(kind="int64")])
        )
        self.assertEqual(
            [row["numeric_value"]["declared_value_decimal"] for row in actual["wire_occurrences"]],
            ["0", str(2**63 - 1), str(-(2**63)), "-1"],
        )

    def test_uint32_and_sint32_outside_subset_withhold_without_wire_loss(self):
        for kind in ("uint32", "sint32"):
            actual = report(model(scalar(1, 2**40), [declaration(kind=kind)]))
            row = actual["wire_occurrences"][0]
            self.assertEqual(row["numeric_value"]["wire_unsigned_decimal"], str(2**40))
            self.assertIsNone(row["numeric_value"]["declared_value_decimal"])
            self.assertEqual(row["typing_status"], "numeric_value_outside_selected_subset")

    def test_boolean_nonzero_outside_selected_subset_is_not_protocol_malformed(self):
        actual = report(
            model(b"".join(scalar(1, n) for n in (0, 1, 2, 255)), [declaration(kind="bool")])
        )
        self.assertEqual(
            [row["numeric_value"]["declared_boolean"] for row in actual["wire_occurrences"]],
            [False, True, None, None],
        )
        self.assertEqual(actual["source_payload_bytes"], 9)

    def test_fixed_width_little_endian_signed_and_unsigned_tables(self):
        for kind, wire, width in (
            ("fixed32", 5, 4),
            ("sfixed32", 5, 4),
            ("fixed64", 1, 8),
            ("sfixed64", 1, 8),
        ):
            values = (0, 1, 255, 2 ** (width * 8 - 1), 2 ** (width * 8) - 1)
            payload = b"".join(
                tag(1, wire) + bytes((value // 256**i) % 256 for i in range(width))
                for value in values
            )
            rows = report(model(payload, [declaration(kind=kind)]))["wire_occurrences"]
            for value, row in zip(values, rows, strict=True):
                expected = (
                    value - 2 ** (width * 8)
                    if kind.startswith("s") and value >= 2 ** (width * 8 - 1)
                    else value
                )
                self.assertEqual(row["numeric_value"]["declared_value_decimal"], str(expected))

    def test_packed_unpacked_interleaving_and_multiple_chunks_keep_original_order(self):
        payload = length(1, bytes((1, 2))) + scalar(1, 3) + scalar(9, 99)
        payload += length(1, b"") + length(1, bytes((4, 5)))
        rows = report(model(payload, [declaration(repeated=True)]))["wire_occurrences"]
        values = []
        for row in rows:
            if row["field_number"] != 1:
                continue
            if row["wire_type"] == 2:
                values.extend(value["declared_value_decimal"] for value in row["packed_values"])
            else:
                values.append(row["numeric_value"]["declared_value_decimal"])
        self.assertEqual(values, ["1", "2", "3", "4", "5"])
        self.assertEqual(
            [row["occurrence_for_field"] for row in rows if row["field_number"] == 1], [1, 2, 3, 4]
        )
        self.assertEqual(len(rows), 5)

    def test_packed_fixed_elements_need_complete_width(self):
        for kind, width in (("fixed32", 4), ("sfixed64", 8)):
            valid = length(1, b"\xff" * width + b"\0" * width)
            rows = report(model(valid, [declaration(kind=kind, repeated=True)]))["wire_occurrences"]
            self.assertEqual(len(rows[0]["packed_values"]), 2)
            with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    m.analyze_supplied_protobuf_wire(
                        model(
                            length(1, b"\0" * (width + 1)), [declaration(kind=kind, repeated=True)]
                        )
                    )

    def test_nonrepeated_numeric_length_delimited_is_opaque_type_mismatch(self):
        row = report(model(length(1, b"\xff"), [declaration()]))["wire_occurrences"][0]
        self.assertEqual(row["typing_status"], "declared_wire_type_mismatch")
        self.assertEqual(row["packed_values"], [])

    def test_duplicate_singular_scalars_and_nested_messages_are_not_merged(self):
        payload = scalar(1, 1) + scalar(1, 2) + length(2, scalar(1, 3)) + length(2, scalar(1, 4))
        value = model(
            payload,
            messages=[
                {
                    "message_id": "Root",
                    "fields": [declaration(), declaration(2, "message", nested="Child")],
                },
                {"message_id": "Child", "fields": [declaration()]},
            ],
        )
        rows = report(value)["wire_occurrences"]
        self.assertEqual(
            [
                row["numeric_value"]["declared_value_decimal"]
                for row in rows
                if row["wire_type"] == 0
            ],
            ["1", "2", "3", "4"],
        )
        self.assertEqual(
            [row["parent_occurrence_index"] for row in rows], [None, None, None, 2, None, 4]
        )

    def test_unknown_length_delimited_bytes_are_never_guessed_as_submessages(self):
        for payload in (b"\0", b"\xff", b"\x08\x96\x01", b"\x0b\x0c"):
            rows = report(model(length(9, payload)))["wire_occurrences"]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["typing_status"], "unknown_field_opaque")
            self.assertIsNone(rows[0]["utf8_valid"])

    def test_declared_utf8_validation_retains_exact_bytes_without_text_normalization(self):
        for payload, valid in (
            (b"", True),
            ("e\u0301".encode(), True),
            ("\U0001f600".encode(), True),
            (b"\xc0\x80", False),
            (b"\xed\xa0\x80", False),
            (b"\xff", False),
        ):
            actual = report(model(length(1, payload), [declaration(kind="string")]))
            row = actual["wire_occurrences"][0]
            self.assertIs(row["utf8_valid"], valid)
            self.assertEqual(
                actual["source_model"]["payload_base64"],
                base64.b64encode(length(1, payload)).decode(),
            )
            self.assertFalse(actual["claims"]["canonical_protobuf_proven"])

    def test_recursive_declarations_expand_only_actual_bounded_wire(self):
        fields = [declaration(kind="message", nested="Root")]
        self.assertEqual(report(model(b"", fields))["wire_occurrences"], [])
        payload = b""
        for _ in range(15):
            payload = length(1, payload)
        self.assertEqual(len(report(model(payload, fields))["wire_occurrences"]), 15)
        payload = length(1, payload)
        with self.assertRaises(m.ProtobufWireAnalysisError):
            m.analyze_supplied_protobuf_wire(model(payload, fields))

    def test_length_prefix_cannot_cross_supplied_nested_message_boundary(self):
        value = model(
            length(1, b"\x12\x04x") + b"abc", [declaration(kind="message", nested="Root")]
        )
        with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire(value)

    def test_nonminimal_supported_tag_length_and_scalar_varints_are_retained(self):
        payload = b"\x88\0\x81\0" + b"\x92\0\x81\0x"
        value = model(payload, [declaration(), declaration(2, "bytes")])
        rows = report(value)["wire_occurrences"]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["numeric_value"]["declared_value_decimal"], "1")
        self.assertEqual(rows[0]["value_offset"], 2)
        self.assertEqual(rows[1]["value_offset"], 8)
        self.assertEqual(base64.b64decode(report(value)["source_model"]["payload_base64"]), payload)

    def test_varint_truncation_overflow_and_unsupported_wire_refuse_before_hash(self):
        cases = (
            b"\x80",
            b"\x08\x80",
            b"\x08" + b"\xff" * 9 + b"\x02",
            b"\x08" + b"\x80" * 10,
            b"\0",
            b"\x0b",
            b"\x0c",
            b"\x0e",
            b"\x0f",
            b"\x12\x80",
            b"\x12\x04ab",
            b"\x0d\0",
            b"\x09\0",
            b"\x80" * 5 + b"\x01",
            varint(2**32),
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with patch.object(
                    m.hashlib, "sha256", side_effect=AssertionError("premature hash")
                ):
                    with self.assertRaises(m.ProtobufWireAnalysisError):
                        m.analyze_supplied_protobuf_wire(model(payload))

    def test_maximum_field_number_and_reserved_declaration_band_are_source_bound(self):
        for number in (19000, 19999, 536_870_911):
            rows = report(model(scalar(number, 7), [declaration(number)]))["wire_occurrences"]
            self.assertEqual(rows[0]["field_number"], number)
        for number in (0, 536_870_912, True, -1):
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire(model(b"", [declaration(number)]))

    def test_closed_schema_and_local_references_deny_before_hash(self):
        cases = []
        for key, value in (
            ("schema_version", True),
            ("source_id", ""),
            ("source_id", "\u00e9"),
            ("root_message", "missing"),
            ("messages", []),
        ):
            changed = model()
            changed[key] = value
            cases.append(changed)
        changed = model()
        changed["callback"] = "no"
        cases.append(changed)
        for field in (
            declaration(kind="float"),
            declaration(kind="enum"),
            declaration(repeated=1),
            declaration(kind="uint64", nested="Root"),
            declaration(kind="message", nested="absent"),
            {**declaration(), "packed": True},
        ):
            cases.append(model(b"", [field]))
        cases.append(model(b"", [declaration(), declaration()]))
        cases.append(model(messages=[{"message_id": "Root", "fields": []}] * 2))
        for value in cases:
            with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    m.analyze_supplied_protobuf_wire(value)

    def test_payload_base64_is_canonical_and_bounded_before_decode_or_hash(self):
        for value in ("YQ", "YQ==\n", "YR==", "?", "\u00e9"):
            supplied = model()
            supplied["payload_base64"] = value
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire(supplied)
        supplied = model()
        supplied["payload_base64"] = "A" * (4 * ((m.MAX_PAYLOAD_BYTES + 2) // 3) + 1)
        with patch.object(m.base64, "b64decode", side_effect=AssertionError("premature decode")):
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire(supplied)

    def test_schema_occurrence_packed_and_retention_caps_are_pre_hash(self):
        cases = [
            (
                "MAX_MESSAGES",
                1,
                model(
                    messages=[
                        {"message_id": "Root", "fields": []},
                        {"message_id": "Other", "fields": []},
                    ]
                ),
            ),
            ("MAX_FIELDS", 1, model(b"", [declaration(), declaration(2)])),
            ("MAX_OCCURRENCES", 3, model(b"".join(scalar(1, n) for n in range(4)))),
            (
                "MAX_PACKED_VALUES",
                3,
                model(length(1, bytes(range(4))), [declaration(repeated=True)]),
            ),
            ("MAX_RETAINED_ANALYSIS_BYTES", 32, model(scalar(1, 1))),
        ]
        for name, ceiling, value in cases:
            with self.subTest(ceiling=name):
                with patch.object(m, name, ceiling):
                    with patch.object(
                        m.hashlib, "sha256", side_effect=AssertionError("premature hash")
                    ):
                        with self.assertRaises(m.ProtobufWireAnalysisError):
                            m.analyze_supplied_protobuf_wire(value)
        # A genuinely wide, default-budget packed report also refuses before any digest.
        wide = model(length(1, b"\x01" * 8000), [declaration(repeated=True)])
        with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire(wide)

    def test_canonical_report_rehashed_fabrications_cannot_replace_source_replay(self):
        original = report(m.component_fixture())
        mutations = (
            lambda doc: doc["wire_occurrences"][0]["numeric_value"].update(
                declared_value_decimal="151"
            ),
            lambda doc: doc["wire_occurrences"][4].update(parent_occurrence_index=0),
            lambda doc: doc["wire_occurrences"][5].update(
                typing_status="interpreted_under_supplied_declaration"
            ),
            lambda doc: doc["wire_occurrences"][2]["packed_values"].reverse(),
            lambda doc: doc["summary"].update(unassessed_occurrences=0),
            lambda doc: doc["claims"].update(rpc_executed=True),
            lambda doc: doc["effects"].update(network="approved"),
            lambda doc: doc.update(source_payload_sha256="sha256:" + "0" * 64),
            lambda doc: doc.update(blueprint_sha256="sha256:" + "1" * 64),
        )
        for mutation in mutations:
            changed = copy.deepcopy(original)
            mutation(changed)
            readdress(changed)
            for parse in (
                lambda: m.ProtobufWireAnalysis.from_dict(changed),
                lambda: m.ProtobufWireAnalysis.from_json(canonical(changed)),
            ):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    parse()

    def test_changed_source_valid_report_needs_separate_original_verification(self):
        original = m.component_fixture()
        changed = copy.deepcopy(original)
        changed["source_id"] = "other.original"
        changed_result = m.analyze_supplied_protobuf_wire(changed)
        self.assertEqual(changed_result.to_dict()["source_model"], changed)
        with self.assertRaises(m.ProtobufWireAnalysisError):
            m.verify_supplied_protobuf_wire_analysis(changed_result, model=original)
        original_result = m.analyze_supplied_protobuf_wire(original)
        changed = copy.deepcopy(original)
        changed["messages"].reverse()
        with self.assertRaises(m.ProtobufWireAnalysisError):
            m.verify_supplied_protobuf_wire_analysis(original_result, model=changed)

    def test_frozen_wrappers_and_detached_exports_do_not_mutate_sources(self):
        original = m.component_fixture()
        before = copy.deepcopy(original)
        result = m.analyze_supplied_protobuf_wire(original)
        original["messages"].clear()
        exported = result.to_dict()
        exported["wire_occurrences"].clear()
        self.assertEqual(result.to_dict()["source_model"], before)
        self.assertEqual(result.to_dict()["summary"]["occurrences"], 6)
        with self.assertRaises(FrozenInstanceError):
            result.document_json = "{}"
        forged = object.__new__(m.ProtobufWireAnalysis)
        with self.assertRaises(m.ProtobufWireAnalysisError):
            forged.to_dict()
        with self.assertRaises(m.ProtobufWireAnalysisError):
            m.verify_supplied_protobuf_wire_analysis(result.to_dict(), model=before)

    def test_native_and_raw_aliases_floats_cycles_int64_and_closed_keys_fail(self):
        class Alias(dict):
            pass

        cases = (Alias(model()), {"huge": 2**64}, {"float": 1.0}, {"source_id": object()})
        for value in cases:
            with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    m.analyze_supplied_protobuf_wire(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(m.ProtobufWireAnalysisError):
            m.analyze_supplied_protobuf_wire({"cycle": cycle})
        raws = (
            b'{"schema_version":1,"schema_version":1}',
            b'{"n":9223372036854775808}',
            b'{"n":-9223372036854775809}',
            b'{"n":1.5}',
            b'{"n":NaN}',
            b'{"n":Infinity}',
            b'{"n":1e0}',
            b'{"n":-01}',
            b'{"a":"\\uD800"}',
            b'{"a":"\\u00e9"}',
            b"\xff",
            b"",
            bytearray(b"{}"),
        )
        for raw in raws:
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire_bytes(model_bytes=raw)

    def test_native_raw_node_depth_string_and_bytes_predecode_bounds(self):
        too_deep = 0
        for _ in range(m.MAX_DEPTH):
            too_deep = [too_deep]
        cases = (
            {"deep": too_deep},
            {"wide": [0] * m.MAX_MODEL_NODES},
            {"wide": "A" * (m.MAX_STRING_BYTES + 1)},
        )
        for value in cases:
            with patch.object(m.hashlib, "sha256", side_effect=AssertionError("premature hash")):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    m.analyze_supplied_protobuf_wire(value)
        for raw in (
            b"[" * 17 + b"0" + b"]" * 17,
            b'{"s":"' + b"A" * (m.MAX_STRING_BYTES + 1) + b'"}',
            b"[" + b"0," * m.MAX_MODEL_NODES + b"0]",
        ):
            with patch.object(m.json, "loads", side_effect=AssertionError("premature JSON decode")):
                with self.assertRaises(m.ProtobufWireAnalysisError):
                    m.analyze_supplied_protobuf_wire_bytes(model_bytes=raw)
        with patch.object(m.json, "loads", side_effect=AssertionError("premature JSON decode")):
            with self.assertRaises(m.ProtobufWireAnalysisError):
                m.analyze_supplied_protobuf_wire_bytes(model_bytes=b" " * (m.MAX_MODEL_BYTES + 1))

    def test_all_eight_public_operations_share_one_budget_before_first_digest(self):
        source = m.component_fixture()
        raw = canonical(source).encode()
        original = m.analyze_supplied_protobuf_wire(source)
        text, doc = original.to_json(), original.to_dict()
        operations = (
            lambda: m.analyze_supplied_protobuf_wire(source),
            lambda: m.analyze_supplied_protobuf_wire_bytes(model_bytes=raw),
            lambda: m.ProtobufWireAnalysis(text),
            lambda: m.ProtobufWireAnalysis.from_dict(doc),
            lambda: m.ProtobufWireAnalysis.from_json(text),
            lambda: original.to_dict(),
            lambda: original.to_json(),
            lambda: m.verify_supplied_protobuf_wire_analysis(original, model=source),
        )
        real_charge = m._Budget.charge
        real_sha = hashlib.sha256
        for index, operation in enumerate(operations):
            state = {"started": False, "budgets": set(), "hashes": 0}

            def charged(budget, amount):
                self.assertFalse(state["started"], "work was charged after a digest started")
                state["budgets"].add(id(budget))
                return real_charge(budget, amount)

            def hashed(*args, **kwargs):
                state["started"] = True
                state["hashes"] += 1
                return real_sha(*args, **kwargs)

            with self.subTest(operation=index):
                with (
                    patch.object(m._Budget, "charge", charged),
                    patch.object(m.hashlib, "sha256", hashed),
                ):
                    operation()
                self.assertEqual(len(state["budgets"]), 1)
                self.assertGreaterEqual(state["hashes"], 3)

    def test_cumulative_work_refuses_before_any_digest_for_each_public_operation(self):
        source = m.component_fixture()
        original = m.analyze_supplied_protobuf_wire(source)
        text, doc = original.to_json(), original.to_dict()
        operations = (
            lambda: m.analyze_supplied_protobuf_wire(source),
            lambda: m.analyze_supplied_protobuf_wire_bytes(model_bytes=canonical(source).encode()),
            lambda: m.ProtobufWireAnalysis(text),
            lambda: m.ProtobufWireAnalysis.from_dict(doc),
            lambda: m.ProtobufWireAnalysis.from_json(text),
            lambda: original.to_dict(),
            lambda: original.to_json(),
            lambda: m.verify_supplied_protobuf_wire_analysis(original, model=source),
        )
        for index, operation in enumerate(operations):
            with self.subTest(operation=index):
                with patch.object(m, "MAX_WORK", 1):
                    with patch.object(
                        m.hashlib, "sha256", side_effect=AssertionError("premature hash")
                    ):
                        with self.assertRaises(m.ProtobufWireAnalysisError):
                            operation()

    def test_all_eight_exact_funding_and_minus_one_boundaries(self):
        source = model(scalar(1, 150), [declaration()])
        raw = canonical(source).encode()
        real_charge = m._Budget.charge
        real_sha = hashlib.sha256

        def operation(index):
            if index == 0:
                return lambda: m.analyze_supplied_protobuf_wire(source)
            if index == 1:
                return lambda: m.analyze_supplied_protobuf_wire_bytes(model_bytes=raw)
            original = m.analyze_supplied_protobuf_wire(source)
            # Test setup reads already-owned storage without invoking a second public pass.
            text = original.document_json
            doc = json.loads(text)
            return (
                None,
                None,
                lambda: m.ProtobufWireAnalysis(text),
                lambda: m.ProtobufWireAnalysis.from_dict(doc),
                lambda: m.ProtobufWireAnalysis.from_json(text),
                lambda: original.to_dict(),
                lambda: original.to_json(),
                lambda: m.verify_supplied_protobuf_wire_analysis(original, model=source),
            )[index]

        for index in range(8):
            ceiling = m.MAX_WORK
            # The reported decimal ceiling changes its own encoded width. Find a
            # transparent fixed point instead of assuming the old report size.
            for _ in range(8):
                with patch.object(m, "MAX_WORK", ceiling):
                    selected = operation(index)
                    state = {"hash_started": False, "used": 0, "budgets": set()}

                    def charged(budget, amount):
                        self.assertFalse(state["hash_started"])
                        state["budgets"].add(id(budget))
                        real_charge(budget, amount)
                        state["used"] = budget.used

                    def hashed(*args, **kwargs):
                        state["hash_started"] = True
                        return real_sha(*args, **kwargs)

                    with (
                        patch.object(m._Budget, "charge", charged),
                        patch.object(m.hashlib, "sha256", hashed),
                    ):
                        selected()
                    self.assertEqual(len(state["budgets"]), 1)
                    self.assertTrue(state["hash_started"])
                if state["used"] == ceiling:
                    break
                ceiling = state["used"]
            else:
                self.fail("The exact funding fixed point did not converge")
            with self.subTest(operation=index, exact_work=ceiling):
                with patch.object(m, "MAX_WORK", ceiling - 1):
                    selected = operation(index)
                    with patch.object(
                        m.hashlib, "sha256", side_effect=AssertionError("premature digest")
                    ):
                        with self.assertRaises(m.ProtobufWireAnalysisError):
                            selected()

    def test_full_source_substitution_changes_raw_identity_not_semantic_equivalence(self):
        first = model(scalar(1, 1), [declaration()])
        second = model(b"\x08\x81\0", [declaration()])
        a, b = report(first), report(second)
        self.assertEqual(
            a["wire_occurrences"][0]["numeric_value"]["declared_value_decimal"],
            b["wire_occurrences"][0]["numeric_value"]["declared_value_decimal"],
        )
        self.assertNotEqual(a["analysis_id"], b["analysis_id"])
        self.assertNotEqual(a["source_payload_sha256"], b["source_payload_sha256"])
        self.assertFalse(a["claims"]["canonical_protobuf_proven"])

    def test_bounds_ownership_and_none_effects_remain_explicit(self):
        actual = report(m.component_fixture())
        self.assertEqual(actual["profile_id"], "AOE-GB-D06-S03")
        self.assertEqual(actual["independent_validator_id"], "AOE-HQ-34")
        self.assertEqual(actual["roadmap_package_ids"], ["A2.10", "A7.4"])
        self.assertTrue(all(value == "none" for value in actual["effects"].values()))
        self.assertTrue(all(value is False for value in actual["claims"].values()))
        self.assertEqual(actual["bounds"]["payload_bytes"], 262144)
        self.assertEqual(actual["bounds"]["message_depth"], 16)
        self.assertIn("Unknown length-delimited", " ".join(actual["limitations"]))


if __name__ == "__main__":
    unittest.main()

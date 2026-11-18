"""Inert independently encoded binary and type-oracle controls for the older subset."""

from __future__ import annotations

import base64
import copy
import hashlib
import itertools
import json
import unittest
from unittest import mock

from sunderkey import offline_wasm_numeric_stack_analysis as m

_MAGIC = b"\x00asm\x01\x00\x00\x00"
_TYPES = ("i32", "i64", "f32", "f64")
_ENCODING = {"i32": b"\x7f", "i64": b"\x7e", "f32": b"\x7d", "f64": b"\x7c"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _u(value):
    output = bytearray()
    while value >= 128:
        output.append((value % 128) + 128)
        value //= 128
    output.append(value)
    return bytes(output)


def _s(value):
    output = bytearray()
    while True:
        digit = value & 127
        value >>= 7
        done = (value == 0 and digit < 64) or (value == -1 and digit >= 64)
        output.append(digit if done else digit + 128)
        if done:
            return bytes(output)


def _vec(rows):
    return _u(len(rows)) + b"".join(rows)


def _name(value):
    return _u(len(value)) + value


def _type(parameters=(), results=()):
    return (
        b"\x60" + _vec([_ENCODING[v] for v in parameters]) + _vec([_ENCODING[v] for v in results])
    )


def _section(identity, content):
    return bytes([identity]) + _u(len(content)) + content


def _body(instructions=b"\x0b", locals_=()):
    raw = _vec([_u(number) + _ENCODING[value] for number, value in locals_]) + instructions
    return _u(len(raw)) + raw


def _module(parameters=(), results=(), instructions=b"\x0b", locals_=(), imports=(), exports=()):
    sections = [_section(1, _vec([_type(parameters, results)]))]
    if imports:
        sections.append(
            _section(
                2,
                _vec(
                    [
                        _name(module) + _name(name) + b"\x00" + _u(index)
                        for module, name, index in imports
                    ]
                ),
            )
        )
    sections.append(_section(3, b"\x01\x00"))
    if exports:
        sections.append(
            _section(7, _vec([_name(name) + b"\x00" + _u(index) for name, index in exports]))
        )
    sections.append(_section(10, _vec([_body(instructions, locals_)])))
    return _MAGIC + b"".join(sections)


def _model(data, source_id="synthetic-wasm-test"):
    return {
        "schema_version": 1,
        "source_id": source_id,
        "module_base64": base64.b64encode(data).decode("ascii"),
    }


def component_fixture():
    return m.component_fixture()


def _readdress(document):
    value = copy.deepcopy(document)
    body = {
        key: child for key, child in value.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    digest = hashlib.sha256(
        m.DOMAIN.encode("ascii") + b"\n" + _canonical(body).encode("ascii")
    ).hexdigest()
    value["analysis_sha256"] = "sha256:" + digest
    value["analysis_id"] = "WSA-" + digest[:32].upper()
    return value


def _oracle(parameters, results, operations):
    """Separate tuple transition model, with no calls to production predicates."""
    stack = ()
    for operation, value in operations:
        if operation == "constant":
            stack += (value,)
        elif operation == "get":
            if value >= len(parameters):
                return False
            stack += (parameters[value],)
        elif operation == "drop":
            if not stack:
                return False
            stack = stack[:-1]
        elif operation == "binary":
            if len(stack) < 2 or stack[-2:] != (value, value):
                return False
            stack = stack[:-2] + (value,)
        elif operation == "call":
            args, returns = value
            if len(stack) < len(args) or (args and stack[-len(args) :] != tuple(args)):
                return False
            stack = (stack[: -len(args)] if args else stack) + tuple(returns)
        else:
            raise AssertionError("Unknown independent test operation")
    return stack == tuple(results)


def _instruction(operation, value):
    if operation == "constant":
        return {
            "i32": b"\x41\x00",
            "i64": b"\x42\x00",
            "f32": b"\x43" + b"\x00" * 4,
            "f64": b"\x44" + b"\x00" * 8,
        }[value]
    if operation == "get":
        return b"\x20" + _u(value)
    if operation == "drop":
        return b"\x1a"
    if operation == "binary":
        return {"i32": b"\x6a", "i64": b"\x7c", "f32": b"\x92", "f64": b"\xa0"}[value]
    raise AssertionError("Unknown independent test instruction")


class _String(str):
    pass


class _Integer(int):
    pass


class _List(list):
    pass


class WasmNumericStackAnalysisTests(unittest.TestCase):
    def analyze(self, data=None):
        source = component_fixture() if data is None else _model(data)
        return m.analyze_supplied_wasm_numeric_stack(source).to_dict()

    def test_literal_fixture_addresses_and_declared_facts(self):
        source = component_fixture()
        result = self.analyze()
        self.assertEqual(result["analysis_id"], "WSA-D4337DA9B92BBAFA34E1F4278AAC2294")
        self.assertEqual(
            result["analysis_sha256"],
            "sha256:d4337da9b92bbafa34e1f4278aac2294d34ad9392a1e9f5d648ed962cefceb5a",
        )
        self.assertEqual(
            result["source_model_sha256"],
            "sha256:075864c9d3752e97544313f64284a2d615701f79f22e7fabab16aa669e396814",
        )
        self.assertEqual(
            result["source_file_sha256"],
            "sha256:88d1ef2dcb2197e0e82e163b9ba50a2bceaa640f2d93286b2aa4c4b5ef24a998",
        )
        self.assertEqual(result["selected_subset_status"], "consistent")
        self.assertEqual(len(result["types"]), 2)
        self.assertEqual(len(result["imports"]), 2)
        self.assertEqual(result["imports"][0]["field_name"], result["imports"][1]["field_name"])
        self.assertEqual(result["functions"][0]["function_index"], 2)
        self.assertEqual(result["functions"][0]["terminal_result_types"], ["i32"])
        self.assertEqual(result["functions"][0]["scanned_instruction_count"], 5)
        self.assertEqual(result["exports"][0]["function_index"], 2)
        self.assertEqual(result["source_model"], source)
        self.assertTrue(all(value is False for value in result["flags"].values()))
        self.assertEqual(set(result["effects"].values()), {"none"})

    def test_empty_module_and_omitted_empty_vectors_are_consistent(self):
        for data in (
            _MAGIC,
            _MAGIC + _section(1, b"\x00") + _section(3, b"\x00") + _section(10, b"\x00"),
        ):
            result = self.analyze(data)
            self.assertEqual(result["selected_subset_status"], "consistent")
            self.assertEqual(result["functions"], [])

    def test_parameters_are_locals_not_an_initial_operand_stack(self):
        good = self.analyze(_module(("i32",), ("i32",), b"\x20\x00\x0b"))
        self.assertEqual(good["selected_subset_status"], "consistent")
        bad = self.analyze(_module(("i32",), ("i32",), b"\x0b"))
        self.assertEqual(bad["selected_subset_status"], "adverse")
        self.assertIn(
            "terminal_result_stack_mismatch", [r["code"] for r in bad["semantic_observations"]]
        )

    def test_independent_small_numeric_stack_transition_oracle(self):
        choices = (
            ("constant", "i32"),
            ("constant", "i64"),
            ("get", 0),
            ("drop", None),
            ("binary", "i32"),
        )
        controls = 0
        for width in range(4):
            for operations in itertools.product(choices, repeat=width):
                encoded = b"".join(_instruction(*operation) for operation in operations) + b"\x0b"
                for results in ((), ("i32",), ("i64",)):
                    result = self.analyze(_module(("i32",), results, encoded))
                    self.assertEqual(
                        result["selected_subset_status"] == "consistent",
                        _oracle(("i32",), results, operations),
                    )
                    controls += 1
        self.assertEqual(controls, 468)

    def test_all_four_numeric_binop_families_require_exact_operand_types(self):
        groups = (
            ("i32", (0x6A, 0x6B, 0x6C)),
            ("i64", (0x7C, 0x7D, 0x7E)),
            ("f32", (0x92, 0x93, 0x94)),
            ("f64", (0xA0, 0xA1, 0xA2)),
        )
        for expected, opcodes in groups:
            for opcode, actual in itertools.product(opcodes, _TYPES):
                instruction = _instruction("constant", actual)
                result = self.analyze(
                    _module((), (expected,), instruction * 2 + bytes([opcode, 11]))
                )
                self.assertEqual(
                    result["selected_subset_status"] == "consistent", actual == expected
                )

    def test_local_set_tee_get_and_bad_indexes_use_declared_local_types(self):
        data = _module((), ("i64",), b"\x42\x01\x22\x00\x1a\x20\x00\x0b", ((1, "i64"),))
        self.assertEqual(self.analyze(data)["selected_subset_status"], "consistent")
        for instructions in (
            b"\x20\x01\x0b",
            b"\x42\x00\x21\x01\x0b",
            b"\x41\x00\x21\x00\x0b",
            b"\x21\x00\x0b",
        ):
            self.assertEqual(
                self.analyze(_module((), (), instructions, ((1, "i64"),)))[
                    "selected_subset_status"
                ],
                "adverse",
            )

    def test_direct_calls_apply_only_signature_types_including_recursion(self):
        for params, results in itertools.product(((), ("i32",), ("i64",)), repeat=2):
            for actual in (None, "i32", "i64"):
                prefix = b"" if actual is None else _instruction("constant", actual)
                operations = (() if actual is None else (("constant", actual),)) + (
                    ("call", (params, results)),
                )
                result = self.analyze(_module(params, results, prefix + b"\x10\x00\x0b"))
                self.assertEqual(
                    result["selected_subset_status"] == "consistent",
                    _oracle(params, results, operations),
                )
        recursive = self.analyze(_module((), (), b"\x10\x00\x0b"))
        self.assertEqual(recursive["selected_subset_status"], "consistent")
        self.assertFalse(recursive["flags"]["function_execution"])

    def test_wrong_call_and_source_type_indexes_are_known_adverse_observations(self):
        result = self.analyze(_module((), (), b"\x10\x01\x0b"))
        self.assertIn(
            "call_function_index_out_of_range", [r["code"] for r in result["semantic_observations"]]
        )
        for data in (
            _MAGIC + _section(2, b"\x01\x00\x00\x00\x00"),
            _MAGIC + _section(3, b"\x01\x01") + _section(10, b"\x01\x02\x00\x0b"),
        ):
            self.assertEqual(self.analyze(data)["selected_subset_status"], "adverse")

    def test_duplicate_import_pairs_are_retained_and_legal(self):
        result = self.analyze(_module((), (), imports=((b"env", b"f", 0), (b"env", b"f", 0))))
        self.assertEqual(result["selected_subset_status"], "consistent")
        self.assertEqual([r["function_index"] for r in result["imports"]], [0, 1])
        self.assertEqual(result["functions"][0]["function_index"], 2)

    def test_export_utf8_names_are_exact_without_unicode_normalization(self):
        names = (b"e\xcc\x81", b"\xc3\xa9", b"x\x00y")
        result = self.analyze(_module(exports=tuple((name, 0) for name in names)))
        self.assertEqual(result["selected_subset_status"], "consistent")
        self.assertEqual(
            [base64.b64decode(r["name"]["name_base64"]) for r in result["exports"]], list(names)
        )
        duplicate = self.analyze(_module(exports=((names[0], 0), (names[0], 0))))
        self.assertEqual(duplicate["selected_subset_status"], "adverse")
        bad_index = self.analyze(_module(exports=((b"f", 1),)))
        self.assertEqual(bad_index["selected_subset_status"], "adverse")

    def test_custom_sections_anywhere_and_data_count_before_code_order(self):
        custom = _section(0, _name(b"opaque") + b"\xff\x00")
        data = (
            _MAGIC
            + custom
            + _section(1, b"\x01\x60\x00\x00")
            + custom
            + _section(3, b"\x01\x00")
            + _section(12, b"\x00")
            + custom
            + _section(10, b"\x01\x02\x00\x0b")
        )
        result = self.analyze(data)
        self.assertEqual([r["section_id"] for r in result["sections"]], [0, 1, 0, 3, 12, 0, 10])
        self.assertEqual(result["selected_subset_status"], "unassessed")
        self.assertIn("deferred_standard_section_12", result["unassessed_reasons"])
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module() + _section(12, b"\x00"))

    def test_standard_duplicates_and_prescribed_not_numeric_order_are_refused(self):
        for data in (
            _MAGIC + _section(1, b"\x00") * 2,
            _MAGIC + _section(10, b"\x00") + _section(7, b"\x00"),
            _MAGIC + _section(13, b""),
        ):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(data)

    def test_recognized_deferred_sections_are_extent_only_not_full_validation(self):
        for identity in (4, 5, 6, 8, 9, 12, 11):
            result = self.analyze(_MAGIC + _section(identity, b"opaque-not-interpreted"))
            self.assertEqual(result["selected_subset_status"], "unassessed")
            self.assertEqual(result["sections"][0]["assessment"], "deferred_opaque_extent")
            self.assertFalse(result["flags"]["full_wasm_validation"])

    def test_deferred_reference_vector_and_multivalue_signatures_are_not_resolved(self):
        types = (b"\x60\x01\x70\x00", b"\x60\x00\x01\x7b", b"\x60\x00\x02\x7f\x7e")
        for signature in types:
            data = (
                _MAGIC
                + _section(1, b"\x01" + signature)
                + _section(3, b"\x01\x00")
                + _section(7, b"\x01\x01f\x00\x00")
                + _section(10, b"\x01\x02\x00\x0b")
            )
            result = self.analyze(data)
            self.assertEqual(result["selected_subset_status"], "unassessed")
            self.assertFalse(result["exports"][0]["numeric_interface_resolved"])
            self.assertIsNone(result["functions"][0]["terminal_result_types"])

    def test_nonfunction_descriptors_and_unknown_type_constructors_are_subset_refusals(self):
        for data in (
            _MAGIC + _section(1, b"\x01\x61\x00\x00"),
            _MAGIC + _section(1, b"\x01\x60\x01\x01\x00"),
            _MAGIC + _section(2, b"\x01\x00\x00\x02\x00\x00"),
            _MAGIC + _section(7, b"\x01\x00\x01\x00"),
        ):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(data)

    def test_unknown_and_structured_opcodes_stop_without_guessing_immediates(self):
        for opcode in (0x00, 0x02, 0x1B, 0x11, 0x23, 0x28, 0xFD, 0xFF):
            for suffix in (b"", b"\xff\xff\xff\x0b"):
                result = self.analyze(_module(instructions=bytes([opcode]) + suffix))
                self.assertEqual(result["selected_subset_status"], "unassessed")
                self.assertFalse(result["functions"][0]["terminal_end_observed"])
                self.assertIsNone(result["functions"][0]["terminal_result_types"])

    def test_known_contradiction_before_unknown_opcode_remains_adverse(self):
        result = self.analyze(_module(instructions=b"\x1a\x02\xff"))
        self.assertEqual(result["selected_subset_status"], "adverse")
        self.assertEqual(result["functions"][0]["selected_stack_conclusion"], "adverse")
        self.assertEqual(result["semantic_observations"][0]["code"], "operand_stack_underflow")
        self.assertIn("deferred_or_unknown_opcode", result["unassessed_reasons"])

    def test_terminal_result_exactness_and_no_trailing_known_body_bytes(self):
        for results, instruction in (((), b"\x41\x00\x0b"), (("i32",), b"\x42\x00\x0b")):
            self.assertEqual(
                self.analyze(_module((), results, instruction))["selected_subset_status"], "adverse"
            )
        for instruction in (b"", b"\x01", b"\x0b\x01", b"\x41", b"\x43\x00"):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(_module(instructions=instruction))

    def test_function_code_count_and_known_section_body_extents_are_exact(self):
        cases = (
            _MAGIC + _section(3, b"\x01\x00"),
            _MAGIC + _section(10, b"\x01\x02\x00\x0b"),
            _MAGIC + b"\x01\x04\x00",
            _MAGIC + _section(1, b"\x00\x00"),
            _MAGIC + _section(3, b"\x01\x00") + _section(10, b"\x01\x03\x00\x0b"),
        )
        for data in cases:
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(data)

    def test_legal_padded_unsigned_and_signed_leb_spellings_are_retained(self):
        data = _MAGIC + b"\x01\x85\x00\x81\x00\x60\x00\x00"
        self.assertEqual(self.analyze(data)["selected_subset_status"], "consistent")
        for width, opcode, value in ((32, 0x41, 0), (32, 0x41, -1), (64, 0x42, 0), (64, 0x42, -1)):
            maximum = (width + 6) // 7
            padded = bytes([0x80 if value == 0 else 0xFF]) * (maximum - 1) + bytes(
                [0 if value == 0 else 0x7F]
            )
            result = self.analyze(
                _module((), ("i32" if width == 32 else "i64",), bytes([opcode]) + padded + b"\x0b")
            )
            self.assertEqual(result["semantic_observations"][0]["signed_value"], value)

    def test_malformed_leb_terminal_bits_width_and_truncation_are_refused(self):
        for encoded in (b"\x80" * 5 + b"\x00", b"\xff\xff\xff\xff\x10", b"\x80"):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(_MAGIC + b"\x01" + encoded)
        for opcode, encoded in (
            (0x41, b"\xff\xff\xff\xff\x08"),
            (0x41, b"\x80\x80\x80\x80\x70"),
            (0x42, b"\xff" * 9 + b"\x01"),
            (0x42, b"\x80" * 10 + b"\x00"),
        ):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(_module(instructions=bytes([opcode]) + encoded + b"\x0b"))

    def test_signed64_extremes_and_float_nan_bits_are_not_json_floats(self):
        for value in (-(2**63), 2**63 - 1, -(2**31), 2**31 - 1):
            result = self.analyze(_module((), ("i64",), b"\x42" + _s(value) + b"\x0b"))
            self.assertIs(type(result["semantic_observations"][0]["signed_value"]), int)
            self.assertEqual(result["semantic_observations"][0]["signed_value"], value)
        for value_type, opcode, bits in (
            ("f32", 0x43, b"\x01\x00\x80\x7f"),
            ("f64", 0x44, b"\x01\x00\x00\x00\x00\x00\xf0\x7f"),
        ):
            row = self.analyze(_module((), (value_type,), bytes([opcode]) + bits + b"\x0b"))[
                "semantic_observations"
            ][0]
            self.assertIsNone(row["signed_value"])
            self.assertEqual(base64.b64decode(row["float_bits_base64"]), bits)

    def test_utf8_name_validation_empty_and_actual_name_caps(self):
        self.analyze(_module(exports=((b"", 0),)))
        self.analyze(_module(exports=((b"a" * 128, 0),)))
        for name in (b"a" * 129, b"\xc0\xaf", b"\xed\xa0\x80", b"\xff"):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(_module(exports=((name, 0),)))
        imports = tuple((b"m" * 128, b"", 0) for _ in range(128))
        self.assertEqual(self.analyze(_module(imports=imports))["total_name_bytes"], 16_384)
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(imports=imports, exports=((b"f", 128),)))

    def test_actual_module_and_section_row_limits(self):
        # Empty-name custom payloads are intentionally opaque and never executed.
        payload_width = m.MAX_MODULE_BYTES - 13
        data = _MAGIC + _section(0, b"\x00" + b"X" * payload_width)
        self.assertEqual(len(data), m.MAX_MODULE_BYTES)
        self.analyze(data)
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(data + b"X")
        self.analyze(_MAGIC + _section(0, b"\x00") * 256)
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_MAGIC + _section(0, b"\x00") * 257)

    def test_actual_type_parameter_result_and_import_export_function_limits(self):
        self.analyze(_MAGIC + _section(1, _vec([_type()] * 128)))
        self.analyze(_module(tuple("i32" for _ in range(64))))
        framed = self.analyze(_MAGIC + _section(1, _vec([_type((), ("i32",) * 64)])))
        self.assertEqual(len(framed["types"][0]["result_types"]), 64)
        self.assertEqual(framed["selected_subset_status"], "unassessed")
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_MAGIC + _section(1, _vec([_type((), ("i32",) * 65)])))
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(tuple("i32" for _ in range(65))))
        for identity, count in ((1, 129), (2, 129), (3, 129), (7, 129), (10, 129)):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(_MAGIC + _section(identity, _u(count)))
        data = (
            _MAGIC
            + _section(1, b"\x01\x60\x00\x00")
            + _section(3, _vec([b"\x00"] * 128))
            + _section(
                7,
                _vec(
                    [
                        _name(str(index).encode("ascii")) + b"\x00" + _u(index)
                        for index in range(128)
                    ]
                ),
            )
            + _section(10, _vec([_body()] * 128))
        )
        self.assertEqual(len(self.analyze(data)["functions"]), 128)

    def test_actual_locals_stack_instruction_and_observation_limits(self):
        result = self.analyze(_module(locals_=((16_384, "i32"),)))
        self.assertEqual(result["expanded_locals_including_parameters"], 16_384)
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(locals_=((16_385, "i32"),)))
        data = _module(("i32",), (), b"\x20\x00" * 4096 + b"\x1a" * 4096 + b"\x0b")
        self.assertEqual(self.analyze(data)["functions"][0]["maximum_operand_stack"], 4096)
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(("i32",), (), b"\x20\x00" * 4097 + b"\x0b"))
        self.assertEqual(
            self.analyze(_module(instructions=b"\x01" * 65535 + b"\x0b"))[
                "scanned_instruction_count"
            ],
            65536,
        )
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(instructions=b"\x01" * 65536 + b"\x0b"))
        self.assertEqual(
            len(
                self.analyze(_module(instructions=(b"\x41\x00\x1a" * 1024) + b"\x0b"))[
                    "semantic_observations"
                ]
            ),
            1024,
        )
        with self.assertRaises(m.WasmNumericStackError):
            self.analyze(_module(instructions=(b"\x41\x00\x1a" * 1025) + b"\x0b"))

    def test_source_native_aliases_unknowns_and_cycles_precede_clone_and_hash(self):
        source = component_fixture()
        controls = (
            None,
            [],
            {**source, "schema_version": True},
            {**source, "schema_version": 1.0},
            {**source, "schema_version": _Integer(1)},
            {**source, "source_id": _String("x")},
            {**source, "module_base64": _String(source["module_base64"])},
            {**source, "unknown": "unselected"},
        )
        for value in controls:
            with (
                mock.patch.object(m, "_clone") as clone,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.analyze_supplied_wasm_numeric_stack(value)
            clone.assert_not_called()
            digest.assert_not_called()
        cycle = []
        cycle.append(cycle)
        with mock.patch.object(m, "_clone") as clone, self.assertRaises(m.WasmNumericStackError):
            m.WasmNumericStackAnalysis.from_dict({"cycle": cycle})
        clone.assert_not_called()

    def test_base64_pad_bits_grammar_magic_and_version_are_not_normalized(self):
        source = component_fixture()
        for value in (source["module_base64"].rstrip("="), "AAAA\n", "!!!!", "AB==", "AA-_", ""):
            with self.assertRaises(m.WasmNumericStackError):
                m.analyze_supplied_wasm_numeric_stack({**source, "module_base64": value})
        for data in (b"", b"\x00asm", b"Xasm\x01\x00\x00\x00", b"\x00asm\x02\x00\x00\x00"):
            with self.assertRaises(m.WasmNumericStackError):
                self.analyze(data)

    def test_raw_duplicates_scalars_and_escapes_are_denied_before_decoder_or_hash(self):
        raw = _canonical(component_fixture())
        cases = (
            raw.replace('"schema_version":1', '"schema_version":--1'),
            raw.replace('"schema_version":1', '"schema_version":1.0'),
            raw.replace('"schema_version":1', '"schema_version":9223372036854775808'),
            raw.replace('"schema_version":1', '"schema_version":01'),
            '{"source_id":"bad\\u000a"}',
            "[" * 16 + "0" + "]" * 16,
        )
        for text in cases:
            with (
                mock.patch.object(m.json, "loads") as decoder,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.analyze_supplied_wasm_numeric_stack_bytes(model_bytes=text.encode("ascii"))
            decoder.assert_not_called()
            digest.assert_not_called()
        duplicate = raw[:-1] + ',"schema_version":1}'
        with self.assertRaises(m.WasmNumericStackError):
            m.analyze_supplied_wasm_numeric_stack_bytes(model_bytes=duplicate.encode("ascii"))

    def test_raw_bytes_and_model_node_byte_ceiling_guards_are_early(self):
        exact = _canonical(component_fixture()).encode("ascii").ljust(m.MAX_MODEL_BYTES, b" ")
        self.assertEqual(len(exact), m.MAX_MODEL_BYTES)
        m.analyze_supplied_wasm_numeric_stack_bytes(model_bytes=exact)
        for value in (bytearray(b"{}"), "{}", b"", b"\xff", b" " * (m.MAX_MODEL_BYTES + 1)):
            with self.assertRaises(m.WasmNumericStackError):
                m.analyze_supplied_wasm_numeric_stack_bytes(model_bytes=value)
        for attribute in ("MAX_MODEL_BYTES", "MAX_MODEL_NODES", "MAX_DEPTH"):
            with (
                mock.patch.object(m, attribute, 1),
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.analyze_supplied_wasm_numeric_stack(component_fixture())
            digest.assert_not_called()

    def test_complete_public_roundtrips_replay_embedded_original_bytes(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_wasm_numeric_stack(source)
        document, text = wrapper.to_dict(), wrapper.to_json()
        values = (
            m.WasmNumericStackAnalysis(text),
            m.WasmNumericStackAnalysis.from_dict(document),
            m.WasmNumericStackAnalysis.from_json(text),
            m.analyze_supplied_wasm_numeric_stack_bytes(
                model_bytes=_canonical(source).encode("ascii")
            ),
            m.verify_supplied_wasm_numeric_stack_analysis(wrapper, model=source),
        )
        for value in values:
            self.assertEqual(value.to_dict(), document)
            self.assertEqual(value.to_json(), text)

    def test_report_scalar_family_aliases_are_rejected_before_clone_or_hash(self):
        original = self.analyze()
        changes = (
            ("schema_version", True),
            ("source_file_bytes", float(original["source_file_bytes"])),
            ("known_contradiction_count", False),
            ("sections", _List(original["sections"])),
        )
        paths = (
            (("functions", 0, "terminal_end_observed"), 1),
            (("imports", 0, "numeric_interface_resolved"), 1),
            (("semantic_observations", 1, "signed_value"), True),
            (("flags", "function_execution"), 0),
            (("bounds", "supported_results_per_type"), True),
            (("effects", "network"), _String("none")),
        )
        controls = []
        for key, value in changes:
            controls.append({**original, key: value})
        for path, value in paths:
            document = copy.deepcopy(original)
            node = document
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            controls.append(document)
        for document in controls:
            with (
                mock.patch.object(m, "_clone") as clone,
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.WasmNumericStackAnalysis.from_dict(document)
            clone.assert_not_called()
            digest.assert_not_called()

    def test_cohashed_false_stack_interface_constant_offset_and_promotion_are_denied(self):
        original = self.analyze()
        changes = (
            lambda d: d["functions"][0].__setitem__("terminal_result_types", []),
            lambda d: d["imports"][0].__setitem__("type_index", 1),
            lambda d: d["exports"][0].__setitem__("function_index", 0),
            lambda d: d["semantic_observations"][1].__setitem__("signed_value", 2),
            lambda d: d["sections"][0].__setitem__("payload_end", 1),
            lambda d: d.__setitem__("selected_subset_status", "adverse"),
            lambda d: d.__setitem__("source_file_sha256", "sha256:" + "a" * 64),
            lambda d: d["flags"].__setitem__("full_wasm_validation", True),
            lambda d: d["effects"].__setitem__("execution", "allowed"),
        )
        for change in changes:
            value = copy.deepcopy(original)
            change(value)
            value = _readdress(value)
            for operation in (
                lambda value=value: m.WasmNumericStackAnalysis.from_dict(value),
                lambda value=value: m.WasmNumericStackAnalysis.from_json(_canonical(value)),
            ):
                with self.assertRaises(m.WasmNumericStackError):
                    operation()

    def test_separate_original_source_identity_and_legal_leb_spelling_swaps_deny(self):
        original = _model(_MAGIC + _section(1, b"\x00"))
        report = m.analyze_supplied_wasm_numeric_stack(original)
        spelling = _model(_MAGIC + _section(1, b"\x80\x00"))
        changed = m.analyze_supplied_wasm_numeric_stack(spelling)
        self.assertEqual(report.to_dict()["types"], changed.to_dict()["types"])
        self.assertNotEqual(report.analysis_sha256, changed.analysis_sha256)
        for source in (spelling, {**original, "source_id": "different-label"}):
            with self.assertRaises(m.WasmNumericStackError):
                m.verify_supplied_wasm_numeric_stack_analysis(report, model=source)

    def test_source_export_detachment_and_fresh_fixture(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_wasm_numeric_stack(source)
        original = wrapper.to_json()
        source["source_id"] = "changed-outside"
        exported = wrapper.to_dict()
        exported["source_model"]["module_base64"] = "AA=="
        exported["functions"].clear()
        self.assertEqual(wrapper.to_json(), original)
        self.assertNotEqual(source, component_fixture())

    def test_late_wrapper_mutation_and_foreign_incomplete_families_fail_closed(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_wasm_numeric_stack(source)
        document = wrapper.to_dict()
        document["functions"][0]["terminal_result_types"] = []
        object.__setattr__(wrapper, "document_json", _canonical(_readdress(document)))
        for operation in (
            wrapper.to_dict,
            wrapper.to_json,
            lambda: m.verify_supplied_wasm_numeric_stack_analysis(wrapper, model=source),
        ):
            with self.assertRaises(m.WasmNumericStackError):
                operation()

        class Foreign(m.WasmNumericStackAnalysis):
            pass

        for value in (
            None,
            {},
            object.__new__(m.WasmNumericStackAnalysis),
            object.__new__(Foreign),
        ):
            with self.assertRaises(m.WasmNumericStackError):
                m.verify_supplied_wasm_numeric_stack_analysis(value, model=source)
        with self.assertRaises(m.WasmNumericStackError):
            Foreign(m.analyze_supplied_wasm_numeric_stack(source).to_json())

    def test_noncanonical_report_unknown_keys_and_real_preappend_report_caps(self):
        document = self.analyze()
        with self.assertRaises(m.WasmNumericStackError):
            m.WasmNumericStackAnalysis.from_json(json.dumps(document, indent=2))
        document["unselected"] = None
        with (
            mock.patch.object(m.hashlib, "sha256") as digest,
            self.assertRaises(m.WasmNumericStackError),
        ):
            m.WasmNumericStackAnalysis.from_dict(document)
        digest.assert_not_called()
        for attribute in ("MAX_REPORT_BYTES", "MAX_REPORT_NODES"):
            with (
                mock.patch.object(m, attribute, 1),
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.analyze_supplied_wasm_numeric_stack(component_fixture())
            digest.assert_not_called()

    def test_vector_expansion_and_semantic_row_caps_deny_before_sha(self):
        for source in (
            _model(_MAGIC + _section(1, _u(2**32 - 1))),
            _model(_module(locals_=((2**32 - 1, "i32"),))),
            _model(_module(instructions=b"\x41\x00\x1a" * 1025 + b"\x0b")),
        ):
            with (
                mock.patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.WasmNumericStackError),
            ):
                m.analyze_supplied_wasm_numeric_stack(source)
            digest.assert_not_called()

    def test_all_eight_public_paths_fund_every_hash_equality_and_export_before_first_sha(self):
        source = component_fixture()
        wrapper = m.analyze_supplied_wasm_numeric_stack(source)
        document, text = wrapper.to_dict(), wrapper.to_json()
        encoded = _canonical(source).encode("ascii")
        bounds = m._bounds()
        operations = (
            lambda: m.analyze_supplied_wasm_numeric_stack(source),
            lambda: m.analyze_supplied_wasm_numeric_stack_bytes(model_bytes=encoded),
            lambda: m.WasmNumericStackAnalysis(text),
            lambda: m.WasmNumericStackAnalysis.from_dict(document),
            lambda: m.WasmNumericStackAnalysis.from_json(text),
            wrapper.to_dict,
            wrapper.to_json,
            lambda: m.verify_supplied_wasm_numeric_stack_analysis(wrapper, model=source),
        )
        charge = m._Budget.charge
        sha = m.hashlib.sha256
        for index, operation in enumerate(operations):
            budgets = []
            hashes = []

            def charged(instance, amount, captured_hashes=hashes, captured_budgets=budgets):
                self.assertEqual(
                    captured_hashes, [], "A reservation occurred after the first digest"
                )
                charge(instance, amount)
                if not any(instance is old for old in captured_budgets):
                    captured_budgets.append(instance)

            def digest(*args, captured_hashes=hashes, **kwargs):
                captured_hashes.append(True)
                return sha(*args, **kwargs)

            with (
                self.subTest(operation=index),
                mock.patch.object(m._Budget, "charge", new=charged),
                mock.patch.object(m.hashlib, "sha256", side_effect=digest),
            ):
                operation()
            self.assertEqual(len(budgets), 1)
            self.assertGreaterEqual(len(hashes), 3)
            exact = budgets[0].used
            with (
                mock.patch.object(m, "MAX_WORK", exact),
                mock.patch.object(m, "_bounds", return_value=bounds),
            ):
                operation()
            with (
                mock.patch.object(m, "MAX_WORK", exact - 1),
                mock.patch.object(m, "_bounds", return_value=bounds),
                mock.patch.object(m.hashlib, "sha256") as denied_hash,
                self.assertRaises(m.WasmNumericStackError),
            ):
                operation()
            denied_hash.assert_not_called()


if __name__ == "__main__":
    unittest.main()

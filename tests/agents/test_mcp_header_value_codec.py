"""Pure MCP header encoding cannot turn local rehearsal into a request."""

from __future__ import annotations

import copy
import unittest

from sunderkey.mcp_header_annotation_preflight import (
    SAFE_INTEGER,
    build_mcp_header_annotation_preflight,
)
from sunderkey.mcp_header_value_codec import (
    MCPHeaderValueCodecError,
    check_mcp_parameter_header_body_parity,
    decode_mcp_parameter_header_value,
    encode_mcp_parameter_header_value,
)
from tests.agents.test_mcp_header_annotation_preflight import fixture


class MCPHeaderValueCodecTests(unittest.TestCase):
    def annotation(self) -> dict:
        inputs = fixture({
            "type": "object",
            "properties": {"nested": {
                "type": "object", "properties": {
                    "value": {"type": "string", "x-mcp-header": "Value"},
                },
            }},
        })
        result = build_mcp_header_annotation_preflight(*inputs)
        return result["tools"][0]["headers"][0]

    def test_safe_ascii_utf8_spacing_control_and_sentinel_round_trip(self) -> None:
        values = (
            "plain-ascii", "Hello, world", "Hello, 世界", " padded ",
            "line1\r\nline2", "=?base64?literal?=", "", "a\tb",
        )
        for value in values:
            with self.subTest(value=value):
                encoded = encode_mcp_parameter_header_value(value, "string")
                self.assertEqual(
                    decode_mcp_parameter_header_value(encoded, "string"), value
                )
                self.assertNotIn("\r", encoded)
                self.assertNotIn("\n", encoded)
        self.assertEqual(
            encode_mcp_parameter_header_value("plain-ascii", "string"),
            "plain-ascii",
        )
        self.assertTrue(
            encode_mcp_parameter_header_value("=?base64?literal?=", "string")
            .startswith("=?base64?")
        )

    def test_injected_plain_or_bad_base64_header_fails(self) -> None:
        values = (
            "line1\r\nHeader: injected", " bad", "bad ", "é",
            "=?base64?%%%?=", "=?base64?/w==?=", "=?base64?YQ?=",
        )
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(MCPHeaderValueCodecError):
                    decode_mcp_parameter_header_value(value, "string")

    def test_boolean_and_safe_integer_types_are_exact(self) -> None:
        self.assertEqual(encode_mcp_parameter_header_value(True, "boolean"), "true")
        self.assertIs(decode_mcp_parameter_header_value("false", "boolean"), False)
        self.assertEqual(
            decode_mcp_parameter_header_value(str(SAFE_INTEGER), "integer"),
            SAFE_INTEGER,
        )
        self.assertEqual(decode_mcp_parameter_header_value("42.0", "integer"), 42)
        for value, kind in (
            (True, "integer"), (1, "boolean"), (SAFE_INTEGER + 1, "integer"),
            (float("nan"), "integer"), (1.5, "integer"),
        ):
            with self.subTest(value=value, kind=kind):
                with self.assertRaises(MCPHeaderValueCodecError):
                    encode_mcp_parameter_header_value(value, kind)
        for value in (str(SAFE_INTEGER + 1), "1e2", "not-a-number"):
            with self.subTest(value=value):
                with self.assertRaises(MCPHeaderValueCodecError):
                    decode_mcp_parameter_header_value(value, "integer")

    def test_body_parity_handles_present_absent_null_and_mismatch(self) -> None:
        annotation = self.annotation()
        arguments = {"nested": {"value": "Hello, 世界"}}
        encoded = encode_mcp_parameter_header_value("Hello, 世界", "string")
        result = check_mcp_parameter_header_body_parity(
            annotation=annotation, arguments=arguments, header_value=encoded
        )
        self.assertEqual(result["status"], "matches")
        self.assertFalse(result["network_call_performed"])
        self.assertFalse(result["positive_use_approved"])
        for body in ({}, {"nested": {}}, {"nested": {"value": None}}):
            result = check_mcp_parameter_header_body_parity(
                annotation=annotation, arguments=body, header_value=None
            )
            self.assertFalse(result["header_present"])
            with self.assertRaisesRegex(MCPHeaderValueCodecError, "omitted"):
                check_mcp_parameter_header_body_parity(
                    annotation=annotation, arguments=body, header_value=encoded
                )
        with self.assertRaisesRegex(MCPHeaderValueCodecError, "missing"):
            check_mcp_parameter_header_body_parity(
                annotation=annotation, arguments=arguments, header_value=None
            )
        with self.assertRaisesRegex(MCPHeaderValueCodecError, "differ"):
            check_mcp_parameter_header_body_parity(
                annotation=annotation, arguments=arguments, header_value="different"
            )

    def test_numeric_parity_and_annotation_rebinding_fail(self) -> None:
        annotation = {
            "header_name": "Mcp-Param-Count",
            "property_path": ["count"],
            "primitive_type": "integer",
            "runtime_integer_range_check_required": True,
        }
        result = check_mcp_parameter_header_body_parity(
            annotation=annotation, arguments={"count": 42.0}, header_value="42"
        )
        self.assertEqual(result["status"], "matches")
        changed = copy.deepcopy(annotation)
        changed["primitive_type"] = ["integer"]
        with self.assertRaisesRegex(MCPHeaderValueCodecError, "annotation"):
            check_mcp_parameter_header_body_parity(
                annotation=changed, arguments={"count": 42}, header_value="42"
            )
        changed = copy.deepcopy(annotation)
        changed["header_name"] = "Mcp-Param-Count\r\nInjected"
        with self.assertRaisesRegex(MCPHeaderValueCodecError, "annotation"):
            check_mcp_parameter_header_body_parity(
                annotation=changed, arguments={"count": 42}, header_value="42"
            )
        changed = copy.deepcopy(self.annotation())
        changed["runtime_integer_range_check_required"] = True
        with self.assertRaisesRegex(MCPHeaderValueCodecError, "annotation"):
            check_mcp_parameter_header_body_parity(
                annotation=changed,
                arguments={"nested": {"value": "same"}},
                header_value="same",
            )


if __name__ == "__main__":
    unittest.main()

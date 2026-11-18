"""Schema positions stay separate from bounded literal MCP metadata."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from sunderkey.mcp_catalog_preflight import build_mcp_catalog_preflight
from sunderkey.mcp_schema_byte_preflight import build_mcp_schema_byte_preflight
from sunderkey.mcp_schema_semantic_preflight import (
    DOMAIN,
    MAX_SCHEMA_DEPTH,
    MAX_SCHEMA_NODES,
    MCPSchemaSemanticPreflightError,
    build_mcp_schema_semantic_preflight,
    verify_mcp_schema_semantic_preflight,
)
from tests.agents.test_mcp_schema_byte_preflight import sources
from tests.agents.test_mcp_schema_semantic_preflight import replace_schema

SINGLE_SCHEMA_POSITIONS = (
    "additionalProperties",
    "unevaluatedProperties",
    "propertyNames",
    "items",
    "contains",
    "unevaluatedItems",
    "not",
    "if",
    "then",
    "else",
    "contentSchema",
)
SCHEMA_MAP_POSITIONS = (
    "$defs",
    "properties",
    "patternProperties",
    "dependentSchemas",
    "definitions",
    "dependencies",
)
SCHEMA_ARRAY_POSITIONS = ("prefixItems", "allOf", "anyOf", "oneOf")
SCHEMA_POSITIONS = (
    SINGLE_SCHEMA_POSITIONS + SCHEMA_MAP_POSITIONS + SCHEMA_ARRAY_POSITIONS
)
DATA_POSITIONS = ("const", "default", "enum", "examples", "x-business-data")
PINNED_DIALECT = "https://json-schema.org/draft/2020-12/schema"
OLD_LITERAL_REFERENCE_DIGEST = (
    "sha256:d5d851e50bf11e53499ebd329ee115adfdccca689c61ca9142d06cb92671d523"
)


def schema_position(keyword: str, child: object) -> dict:
    if keyword in SCHEMA_MAP_POSITIONS:
        value = {"field": child}
    elif keyword in SCHEMA_ARRAY_POSITIONS:
        value = [child]
    else:
        value = child
    return {"type": "object", keyword: value}


def data_position(keyword: str, value: object) -> dict:
    if keyword in ("enum", "examples"):
        value = [value]
    return {"type": "object", keyword: value}


def nested_value(levels: int) -> object:
    value: object = "leaf"
    for _ in range(levels):
        value = {"next": value}
    return value


def replay_digest(result: dict) -> str:
    body = {
        key: value
        for key, value in result.items()
        if key != "semantic_preflight_sha256"
    }
    raw = json.dumps(
        {"domain": DOMAIN, "body": body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class MCPSchemaSemanticScopeTests(unittest.TestCase):
    def fixture(
        self, schema: object | None = None, *, output_schema: object | None = None
    ) -> tuple[dict, dict, dict, dict]:
        manifest, _, bundle = sources()
        if schema is not None:
            replace_schema(manifest, bundle, field="input_schema", schema=schema)
        if output_schema is not None:
            replace_schema(
                manifest, bundle, field="output_schema", schema=output_schema
            )
        preflight = build_mcp_catalog_preflight(manifest)
        byte_result = build_mcp_schema_byte_preflight(manifest, preflight, bundle)
        return manifest, preflight, bundle, byte_result

    def checked_result(self, schema: dict) -> dict:
        Draft202012Validator.check_schema(schema)
        return build_mcp_schema_semantic_preflight(*self.fixture(schema))

    def assert_summary(self, result: dict, references: int, external: int) -> None:
        summary = result["tools"][0]["input_schema"]
        self.assertEqual(summary["reference_count"], references)
        self.assertEqual(summary["external_reference_count"], external)
        self.assertEqual(summary["reference_resolution"], "not_performed")
        self.assertFalse(result["external_references_resolved"])
        self.assertFalse(result["live_server_schema_verified"])
        self.assertEqual(result["qualification_effect"], "none")
        self.assertTrue(all(value == "none" for value in result["effects"].values()))

    def test_all_21_schema_positions_keep_nested_local_and_external_refs(self) -> None:
        self.assertEqual(len(SCHEMA_POSITIONS), 21)
        for keyword in SCHEMA_POSITIONS:
            with self.subTest(keyword=keyword):
                result = self.checked_result(
                    schema_position(
                        keyword,
                        {
                            "$schema": PINNED_DIALECT,
                            "$ref": "#/$defs/local",
                            "$dynamicRef": "remote-schema.json#anchor",
                        },
                    )
                )
                self.assert_summary(result, 2, 1)

    def test_all_21_schema_positions_reject_actual_unsupported_dialects(self) -> None:
        for keyword in SCHEMA_POSITIONS:
            with self.subTest(keyword=keyword):
                schema = schema_position(
                    keyword, {"$schema": "https://example.test/unsupported"}
                )
                Draft202012Validator.check_schema(schema)
                with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "dialect"):
                    build_mcp_schema_semantic_preflight(*self.fixture(schema))

    def test_all_21_schema_positions_still_accept_boolean_subschemas(self) -> None:
        for keyword in SCHEMA_POSITIONS:
            for child in (True, False):
                with self.subTest(keyword=keyword, child=child):
                    self.assert_summary(
                        self.checked_result(schema_position(keyword, child)), 0, 0
                    )

    def test_all_21_schema_positions_still_enforce_nested_metaschema(self) -> None:
        for keyword in SCHEMA_POSITIONS:
            with self.subTest(keyword=keyword):
                schema = schema_position(keyword, {"minLength": -1})
                with self.assertRaisesRegex(
                    MCPSchemaSemanticPreflightError, "metaschema"
                ):
                    build_mcp_schema_semantic_preflight(*self.fixture(schema))

    def test_schema_map_names_are_not_schema_keywords(self) -> None:
        for keyword in SCHEMA_MAP_POSITIONS:
            with self.subTest(keyword=keyword):
                schema = {
                    "type": "object",
                    keyword: {
                        "$schema": {"type": "string"},
                        "$ref": {"type": "string"},
                        "$dynamicRef": {"type": "string"},
                    },
                }
                self.assert_summary(self.checked_result(schema), 0, 0)

    def test_map_names_do_not_hide_real_nested_schema_references(self) -> None:
        for keyword in SCHEMA_MAP_POSITIONS:
            with self.subTest(keyword=keyword):
                schema = {
                    "type": "object",
                    keyword: {
                        "$schema": {"$ref": "#/$defs/local"},
                        "$ref": {"$dynamicRef": "remote-schema.json#anchor"},
                    },
                }
                self.assert_summary(self.checked_result(schema), 2, 1)

    def test_literal_values_are_not_schema_nodes(self) -> None:
        literal = {
            "$schema": "inert-business-value",
            "$ref": "inert-business-reference",
            "$dynamicRef": "inert-business-dynamic-reference",
            "properties": {"field": {"minLength": -1}},
        }
        for keyword in ("const", "default", "enum", "examples"):
            with self.subTest(keyword=keyword):
                self.assert_summary(
                    self.checked_result(data_position(keyword, literal)), 0, 0
                )

    def test_unknown_extensions_remain_inert_bounded_data(self) -> None:
        for keyword in ("x-business-data", "example", "additionalItems"):
            with self.subTest(keyword=keyword):
                schema = {
                    "type": "object",
                    keyword: {
                        "$schema": "inert-extension-value",
                        "$ref": "https://example.test/inert-extension",
                        "allOf": [{"$dynamicRef": "#inert-extension-anchor"}],
                    },
                }
                self.assert_summary(self.checked_result(schema), 0, 0)

    def test_dependency_name_arrays_are_data_but_schema_entries_are_inspected(
        self,
    ) -> None:
        schema = {
            "type": "object",
            "dependencies": {
                "$schema": ["$ref", "$dynamicRef"],
                "$ref": False,
                "schema": {"$ref": "#/$defs/local"},
            },
            "dependentRequired": {"$schema": ["$ref", "$dynamicRef"]},
        }
        self.assert_summary(self.checked_result(schema), 1, 0)

    def test_literal_and_extension_children_inside_real_schemas_are_ignored(
        self,
    ) -> None:
        literal = {"$schema": "inert-value", "$ref": "inert-reference"}
        schema = {
            "type": "object",
            "$defs": {
                "entry": {
                    "$ref": "remote-schema.json",
                    "const": literal,
                    "default": literal,
                    "enum": [literal],
                    "examples": [literal],
                    "x-business-data": literal,
                }
            },
            "properties": {"entry": {"$ref": "#/$defs/entry"}},
        }
        self.assert_summary(self.checked_result(schema), 2, 1)

    def test_output_literals_and_boolean_root_preserve_output_contract(self) -> None:
        for output_schema in (
            True,
            False,
            {"const": {"$schema": "inert-value", "$ref": "inert-reference"}},
        ):
            with self.subTest(output_schema=output_schema):
                result = build_mcp_schema_semantic_preflight(
                    *self.fixture(output_schema=output_schema)
                )
                summary = result["tools"][0]["output_schema"]
                self.assertEqual(summary["root_type"], "unrestricted")
                self.assertEqual(summary["reference_count"], 0)
                self.assertEqual(summary["external_reference_count"], 0)

    def test_whole_json_depth_bound_still_covers_ignored_data(self) -> None:
        self.assertEqual(MAX_SCHEMA_DEPTH, 64)
        for keyword in DATA_POSITIONS:
            base_depth = 2 if keyword in ("enum", "examples") else 1
            with self.subTest(keyword=keyword):
                allowed = data_position(
                    keyword, nested_value(MAX_SCHEMA_DEPTH - base_depth)
                )
                self.assert_summary(self.checked_result(allowed), 0, 0)
                excessive = data_position(
                    keyword, nested_value(MAX_SCHEMA_DEPTH - base_depth + 1)
                )
                with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "bounds"):
                    build_mcp_schema_semantic_preflight(*self.fixture(excessive))

    def test_whole_json_node_bound_still_covers_ignored_data(self) -> None:
        self.assertEqual(MAX_SCHEMA_NODES, 10_000)
        for keyword in DATA_POSITIONS:
            with self.subTest(keyword=keyword):
                # Root object, type string, and data array contribute three nodes.
                allowed = {
                    "type": "object",
                    keyword: list(range(MAX_SCHEMA_NODES - 3)),
                }
                self.assert_summary(self.checked_result(allowed), 0, 0)
                excessive = {
                    "type": "object",
                    keyword: list(range(MAX_SCHEMA_NODES - 2)),
                }
                with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "bounds"):
                    build_mcp_schema_semantic_preflight(*self.fixture(excessive))

    def test_existing_legitimate_fixture_hashes_are_unchanged(self) -> None:
        composition = {
            "type": "object",
            "$defs": {"id": {"type": "string", "minLength": 1}},
            "properties": {"id": {"$ref": "#/$defs/id"}},
            "oneOf": [{"required": ["id"]}, {"maxProperties": 0}],
        }
        external = {
            "type": "object",
            "properties": {"id": {"$ref": "https://example.test/schema"}},
        }
        for schema, output_schema, expected in (
            (
                None,
                None,
                "sha256:77486944ba3384baaea524acc5b2f835f0b38a39216b92c6f09c7cd70e239247",
            ),
            (
                composition,
                True,
                "sha256:13eb529724cb6e354f4d105ad34cbf9e803138301260eb2fb1ef0f35260c1052",
            ),
            (
                external,
                None,
                "sha256:26d55ad2fa97b066f55908ba56007a6acbeee77d5eccb0fbf309c1c6ddd91dfb",
            ),
        ):
            with self.subTest(expected=expected):
                fixture = self.fixture(schema, output_schema=output_schema)
                result = build_mcp_schema_semantic_preflight(*fixture)
                self.assertEqual(result["semantic_preflight_sha256"], expected)
                self.assertEqual(
                    result["semantic_preflight_sha256"], replay_digest(result)
                )
                self.assertEqual(
                    verify_mcp_schema_semantic_preflight(*fixture, result)["status"],
                    "valid",
                )

    def test_corrected_counts_repeat_exactly_and_old_false_positive_does_not_replay(
        self,
    ) -> None:
        schema = {
            "type": "object",
            "examples": [
                {
                    "$ref": "inert-example-reference",
                    "$dynamicRef": "inert-example-dynamic-reference",
                }
            ],
        }
        fixture = self.fixture(schema)
        result = build_mcp_schema_semantic_preflight(*fixture)
        self.assert_summary(result, 0, 0)
        self.assertEqual(build_mcp_schema_semantic_preflight(*fixture), result)
        self.assertEqual(result["semantic_preflight_sha256"], replay_digest(result))
        self.assertEqual(
            verify_mcp_schema_semantic_preflight(*fixture, copy.deepcopy(result))[
                "status"
            ],
            "valid",
        )
        old_summary = copy.deepcopy(result)
        old_summary["tools"][0]["input_schema"]["reference_count"] = 2
        old_summary["tools"][0]["input_schema"]["external_reference_count"] = 2
        old_summary["semantic_preflight_sha256"] = replay_digest(old_summary)
        self.assertEqual(
            old_summary["semantic_preflight_sha256"], OLD_LITERAL_REFERENCE_DIGEST
        )
        self.assertNotEqual(
            result["semantic_preflight_sha256"], OLD_LITERAL_REFERENCE_DIGEST
        )
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "reproduce"):
            verify_mcp_schema_semantic_preflight(*fixture, old_summary)

    def test_exact_count_types_and_nonqualification_flags_are_preserved(self) -> None:
        fixture = self.fixture({"type": "object", "const": {"$ref": "inert-value"}})
        result = build_mcp_schema_semantic_preflight(*fixture)
        for replacement in (False, 0.0):
            with self.subTest(replacement=replacement):
                changed = copy.deepcopy(result)
                changed["tools"][0]["input_schema"]["reference_count"] = replacement
                with self.assertRaisesRegex(
                    MCPSchemaSemanticPreflightError, "reproduce"
                ):
                    verify_mcp_schema_semantic_preflight(*fixture, changed)
        for field, replacement in (
            ("external_references_resolved", True),
            ("live_server_schema_verified", True),
            ("qualification_effect", "qualified"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(result)
                changed[field] = replacement
                changed["semantic_preflight_sha256"] = replay_digest(changed)
                with self.assertRaisesRegex(
                    MCPSchemaSemanticPreflightError, "reproduce"
                ):
                    verify_mcp_schema_semantic_preflight(*fixture, changed)

    def test_exact_byte_result_and_source_binding_are_not_weakened(self) -> None:
        fixture = self.fixture({"type": "object", "default": {"$ref": "inert-value"}})
        result = build_mcp_schema_semantic_preflight(*fixture)
        manifest, preflight, bundle, byte_result = copy.deepcopy(fixture)
        raw = base64.b64decode(bundle["tools"][0]["input_schema_base64"])
        bundle["tools"][0]["input_schema_base64"] = base64.b64encode(b" " + raw).decode(
            "ascii"
        )
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "byte preflight"):
            build_mcp_schema_semantic_preflight(
                manifest, preflight, bundle, byte_result
            )
        changed_byte_result = copy.deepcopy(fixture[3])
        count = changed_byte_result["tools"][0]["input_schema_byte_count"]
        changed_byte_result["tools"][0]["input_schema_byte_count"] = float(count)
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "byte preflight"):
            build_mcp_schema_semantic_preflight(*fixture[:3], changed_byte_result)
        changed_fixture = self.fixture(
            {"type": "object", "default": {"$ref": "different-inert-value"}}
        )
        with self.assertRaisesRegex(MCPSchemaSemanticPreflightError, "reproduce"):
            verify_mcp_schema_semantic_preflight(*changed_fixture, result)

    def test_nested_external_refs_are_not_fetched(self) -> None:
        schema = {
            "type": "object",
            "allOf": [
                {"$ref": "https://example.test/schema"},
                {"$dynamicRef": "other-schema.json#anchor"},
                {"$ref": "#local"},
            ],
        }
        with (
            patch(
                "socket.create_connection",
                side_effect=AssertionError("network forbidden"),
            ),
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch(
                "urllib.request.urlopen", side_effect=AssertionError("fetch forbidden")
            ),
        ):
            result = self.checked_result(schema)
        self.assert_summary(result, 3, 2)


if __name__ == "__main__":
    unittest.main()

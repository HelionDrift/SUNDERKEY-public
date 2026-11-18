"""Trace and MCP artifacts require exact JSON types at every replay boundary."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from collections import UserDict, UserList
from contextlib import redirect_stdout
from decimal import Decimal
from fractions import Fraction
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from sunderkey.agent_trace_regression import (
    AgentTraceRegressionError,
    build_agent_trace_regression,
    verify_agent_trace_regression,
)
from sunderkey.agent_trace_review import (
    AgentTraceReviewError,
    build_agent_trace_review,
    verify_agent_trace_review,
)
from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.json_contract_integrity import (
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    JsonContractIntegrityError,
    canonical_json_bytes,
)
from sunderkey.mcp_api_read_bindings import (
    MCPApiReadBindingError,
    build_mcp_api_read_bindings,
    verify_mcp_api_read_bindings,
)
from sunderkey.mcp_catalog_preflight import (
    MCPCatalogPreflightError,
    build_mcp_catalog_preflight,
    verify_mcp_catalog_preflight,
)
from sunderkey.mcp_header_annotation_preflight import (
    MCPHeaderAnnotationPreflightError,
    build_mcp_header_annotation_preflight,
    verify_mcp_header_annotation_preflight,
)
from sunderkey.mcp_schema_byte_preflight import (
    MCPSchemaBytePreflightError,
    build_mcp_schema_byte_preflight,
    verify_mcp_schema_byte_preflight,
)
from sunderkey.mcp_schema_semantic_preflight import (
    MCPSchemaSemanticPreflightError,
    build_mcp_schema_semantic_preflight,
    verify_mcp_schema_semantic_preflight,
)
from tests.agents.test_agent_trace_regression import pair
from tests.agents.test_mcp_api_read_bindings import source
from tests.agents.test_mcp_header_annotation_preflight import fixture as schema_fixture


class DictSubclass(dict):
    pass


class ListSubclass(list):
    pass


class StringSubclass(str):
    pass


class IntegerSubclass(int):
    pass


def reordered(value):
    if type(value) is dict:
        return {key: reordered(item) for key, item in reversed(tuple(value.items()))}
    if type(value) is list:
        return [reordered(item) for item in value]
    return value


def integer_paths(value, path=()):
    if type(value) is int:
        yield path, value
    elif type(value) is dict:
        for key, item in value.items():
            yield from integer_paths(item, (*path, key))
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from integer_paths(item, (*path, index))


def replaced(value, path, replacement):
    result = copy.deepcopy(value)
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result


class CanonicalJsonIntegrityTests(unittest.TestCase):
    def test_types_are_distinct_but_key_order_is_not(self) -> None:
        encoded = [canonical_json_bytes(value, max_bytes=32) for value in (True, 1, 1.0)]
        self.assertEqual(encoded, [b"true", b"1", b"1.0"])
        self.assertEqual(
            canonical_json_bytes({"b": None, "a": [False, "x"]}, max_bytes=64),
            canonical_json_bytes({"a": [False, "x"], "b": None}, max_bytes=64),
        )

    def test_exact_byte_limit_accounts_for_unicode_escaping(self) -> None:
        value = {"a": "\u00e9"}
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.assertEqual(canonical_json_bytes(value, max_bytes=len(encoded)), encoded.encode())
        with self.assertRaises(JsonContractIntegrityError):
            canonical_json_bytes(value, max_bytes=len(encoded) - 1)

    def test_custom_containers_scalars_and_non_json_values_fail(self) -> None:
        for value in (
            UserDict({"a": 1}), MappingProxyType({"a": 1}), DictSubclass(a=1),
            UserList([1]), ListSubclass([1]), (1,), {1}, b"x", object(),
            Decimal(1), Fraction(1), IntegerSubclass(1), StringSubclass("x"),
            {1: "x"}, {StringSubclass("a"): 1},
        ):
            with self.subTest(kind=type(value).__name__), self.assertRaises(
                JsonContractIntegrityError
            ):
                canonical_json_bytes(value, max_bytes=128)

    def test_nonfinite_numbers_fail_at_any_depth(self) -> None:
        for number in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(number=number), self.assertRaises(JsonContractIntegrityError):
                canonical_json_bytes({"nested": [number]}, max_bytes=128)

    def test_shared_containers_are_not_cycles(self) -> None:
        shared = {"a": 1}
        self.assertEqual(canonical_json_bytes([shared, shared], max_bytes=64), b'[{"a":1},{"a":1}]')
        cyclic_list = []
        cyclic_list.append(cyclic_list)
        cyclic_dict = {}
        cyclic_dict["self"] = cyclic_dict
        for value in (cyclic_list, cyclic_dict):
            with self.assertRaises(JsonContractIntegrityError):
                canonical_json_bytes(value, max_bytes=128)

    def test_depth_node_and_integer_limits_fail_before_serialization(self) -> None:
        value = None
        for _ in range(MAX_JSON_DEPTH):
            value = [value]
        canonical_json_bytes(value, max_bytes=1000)
        for oversized in ([value], [None] * MAX_JSON_NODES, 1 << 1024):
            with self.assertRaises(JsonContractIntegrityError):
                canonical_json_bytes(oversized, max_bytes=128)
        for limit in (True, 0, -1, 1.0):
            with self.assertRaises(JsonContractIntegrityError):
                canonical_json_bytes(None, max_bytes=limit)


class OfflineTypedEvidenceReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.prior, self.current = pair()
        self.prior_review = build_agent_trace_review(self.prior)
        self.current_review = build_agent_trace_review(self.current)
        self.comparison = build_agent_trace_regression(
            self.prior, self.prior_review, self.current, self.current_review,
        )
        self.manifest, self.preflight, self.request = source()
        self.plan = build_mcp_api_read_bindings(self.manifest, self.preflight, self.request)
        self.cases = (
            ("review", self.current_review, AgentTraceReviewError,
             lambda value: verify_agent_trace_review(self.current, value)),
            ("comparison", self.comparison, AgentTraceRegressionError,
             lambda value: verify_agent_trace_regression(
                 self.prior, self.prior_review, self.current, self.current_review, value,
             )),
            ("preflight", self.preflight, MCPCatalogPreflightError,
             lambda value: verify_mcp_catalog_preflight(self.manifest, value)),
            ("plan", self.plan, MCPApiReadBindingError,
             lambda value: verify_mcp_api_read_bindings(
                 self.manifest, self.preflight, self.request, value,
             )),
        )

    def test_valid_v1_content_addresses_are_unchanged(self) -> None:
        actual = (
            self.prior_review["review_sha256"], self.current_review["review_sha256"],
            self.comparison["comparison_sha256"], self.preflight["preflight_sha256"],
            self.plan["plan_sha256"],
        )
        self.assertEqual(actual, tuple("sha256:" + item for item in (
            "6e64785652df2e73c583e3d8899aca1805faca379cc0fa72bc40d57a78c9430c",
            "b7a02ae747c8ac53e320785d1c2a1d5573e7d88f15680fd377b98cbf08669f13",
            "d28a52ccc7110f0897712eba7b86116b39a292965d1f938a3519ff34e1d673e0",
            "abb2fb81d9c11a03f8c828f0554c67ebe35aae2776ffeb675b8406837710d5a2",
            "4955bda19aab54b5c41dc3df0bd929fb96df19b2a8dd892dc4702ffeb8a5fe38",
        )))

    def test_every_integer_rejects_equal_float_decimal_and_fraction(self) -> None:
        for name, artifact, error, verify in self.cases:
            for path, integer in integer_paths(artifact):
                for number in (float(integer), Decimal(integer), Fraction(integer)):
                    with self.subTest(name=name, path=path, kind=type(number).__name__):
                        altered = replaced(artifact, path, number)
                        self.assertEqual(artifact, altered)
                        with self.assertRaises(error):
                            verify(altered)

    def test_zero_and_one_reject_equal_boolean(self) -> None:
        for name, artifact, error, verify in self.cases:
            for path, integer in integer_paths(artifact):
                if integer in (0, 1):
                    with self.subTest(name=name, path=path):
                        altered = replaced(artifact, path, bool(integer))
                        self.assertEqual(artifact, altered)
                        with self.assertRaises(error):
                            verify(altered)

    def test_root_and_nested_equal_custom_containers_are_not_json(self) -> None:
        for name, artifact, error, verify in self.cases:
            for wrapper in (UserDict, DictSubclass, MappingProxyType):
                with self.subTest(name=name, wrapper=wrapper.__name__):
                    with self.assertRaises(error):
                        verify(wrapper(artifact))
                    key = "effects" if "effects" in artifact else "newly_observed_issues"
                    nested = artifact[key]
                    replacement = wrapper(nested) if type(nested) is dict else ListSubclass(nested)
                    changed = replaced(artifact, (key,), replacement)
                    self.assertEqual(changed, artifact)
                    with self.assertRaises(error):
                        verify(changed)

    def test_tuple_lists_cannot_be_normalized_into_valid_evidence(self) -> None:
        for name, artifact, error, verify in self.cases:
            key = "bindings" if name == "plan" else (
                "newly_observed_issues" if name == "comparison" else "issues"
            )
            altered = replaced(artifact, (key,), tuple(artifact[key]))
            self.assertEqual(
                json.dumps(altered, sort_keys=True), json.dumps(artifact, sort_keys=True),
            )
            with self.subTest(name=name), self.assertRaises(error):
                verify(altered)

    def test_missing_extra_nonfinite_cyclic_and_oversized_output_fail_closed(self) -> None:
        for name, artifact, error, verify in self.cases:
            cyclic = copy.deepcopy(artifact)
            cyclic["extra"] = cyclic
            deep = None
            for _ in range(MAX_JSON_DEPTH + 1):
                deep = [deep]
            variants = (
                {key: value for key, value in artifact.items() if key != "schema_version"},
                {**artifact, "extra": None}, {**artifact, "extra": float("nan")},
                cyclic, {**artifact, "extra": deep}, {**artifact, "extra": "x" * 1_000_001},
            )
            for index, altered in enumerate(variants):
                with self.subTest(name=name, index=index), self.assertRaises(error):
                    verify(altered)

    def test_dictionary_key_reordering_remains_valid_without_mutation(self) -> None:
        for name, artifact, _, verify in self.cases:
            before = copy.deepcopy(artifact)
            with self.subTest(name=name):
                self.assertEqual(verify(reordered(artifact))["status"], "valid")
                self.assertEqual(artifact, before)
                self.assertEqual(artifact["qualification_effect"], "none")
                self.assertTrue(all(
                    item == "none" for item in artifact.get("effects", {}).values()
                ))

    def test_issue_list_order_is_part_of_exact_replay(self) -> None:
        trace = copy.deepcopy(self.prior)
        trace["events"][1]["actor"] = "candidate"
        review = build_agent_trace_review(trace)
        self.assertGreater(len(review["issues"]), 1)
        review["issues"].reverse()
        with self.assertRaises(AgentTraceReviewError):
            verify_agent_trace_review(trace, review)

    def test_tampered_review_cannot_enter_regression_build_or_verify(self) -> None:
        for path in (("schema_version",), ("tool_execution_count",), ("issues", 0, "sequence")):
            target = self.current_review
            for key in path:
                target = target[key]
            for number in (float(target), Decimal(target), Fraction(target)):
                altered = replaced(self.current_review, path, number)
                with self.subTest(path=path, kind=type(number).__name__):
                    with self.assertRaises(AgentTraceRegressionError):
                        build_agent_trace_regression(
                            self.prior, self.prior_review, self.current, altered,
                        )
                    with self.assertRaises(AgentTraceRegressionError):
                        verify_agent_trace_regression(
                            self.prior, self.prior_review, self.current, altered, self.comparison,
                        )

    def test_tampered_preflight_cannot_enter_binding_build_or_verify(self) -> None:
        for key in ("schema_version", "tool_count", "action_tool_count"):
            for number in (bool(self.preflight[key]), float(self.preflight[key])):
                altered = replaced(self.preflight, (key,), number)
                self.assertEqual(altered, self.preflight)
                with self.subTest(key=key, kind=type(number).__name__):
                    with self.assertRaises(MCPApiReadBindingError):
                        build_mcp_api_read_bindings(self.manifest, altered, self.request)
                    with self.assertRaises(MCPApiReadBindingError):
                        verify_mcp_api_read_bindings(
                            self.manifest, altered, self.request, self.plan,
                        )

    def test_tampered_preflight_cannot_enter_schema_or_header_replay(self) -> None:
        inputs = schema_fixture({"type": "object"})
        builders = (
            (3, build_mcp_schema_byte_preflight, verify_mcp_schema_byte_preflight,
             MCPSchemaBytePreflightError),
            (4, build_mcp_schema_semantic_preflight, verify_mcp_schema_semantic_preflight,
             MCPSchemaSemanticPreflightError),
            (5, build_mcp_header_annotation_preflight, verify_mcp_header_annotation_preflight,
             MCPHeaderAnnotationPreflightError),
        )
        for count, build, verify, error in builders:
            output = build(*inputs[:count])
            for value in (True, 1.0):
                sources = list(copy.deepcopy(inputs[:count]))
                sources[1]["tool_count"] = value
                with self.subTest(count=count, value=value):
                    with self.assertRaises(error):
                        build(*sources)
                    with self.assertRaises(error):
                        verify(*sources, output)

    def test_serialized_numeric_substitutions_fail_in_each_cli_verifier(self) -> None:
        cases = (
            ("agent-trace-review-verify", {
                "trace": self.current, "review": self.current_review,
            }, "review"),
            ("agent-trace-regression-verify", {
                "prior-trace": self.prior, "prior-review": self.prior_review,
                "current-trace": self.current, "current-review": self.current_review,
                "comparison": self.comparison,
            }, "comparison"),
            ("mcp-catalog-preflight-verify", {
                "manifest": self.manifest, "preflight": self.preflight,
            }, "preflight"),
            ("mcp-api-read-bindings-verify", {
                "manifest": self.manifest, "preflight": self.preflight,
                "bindings": self.request, "plan": self.plan,
            }, "plan"),
        )
        parser = build_parser()
        with tempfile.TemporaryDirectory() as directory:
            for command, artifacts, changed_name in cases:
                options = []
                for name, artifact in artifacts.items():
                    value = copy.deepcopy(artifact)
                    if name == changed_name:
                        value["schema_version"] = True
                    path = Path(directory) / (name + ".json")
                    path.write_text(json.dumps(value), encoding="utf-8")
                    options.extend(("--" + name, str(path)))
                args = parser.parse_args([command, *options])
                with self.subTest(command=command), redirect_stdout(output := io.StringIO()):
                    with self.assertRaises(SunderkeyError):
                        args.handler(args)
                    self.assertEqual(output.getvalue(), "")

    def test_non_json_source_containers_fail_at_the_domain_boundary(self) -> None:
        trace = replaced(self.prior, ("policy",), UserDict(self.prior["policy"]))
        manifest = replaced(self.manifest, ("tools",), tuple(self.manifest["tools"]))
        request = replaced(self.request, ("bindings", 0), DictSubclass(self.request["bindings"][0]))
        with self.assertRaises(AgentTraceReviewError):
            build_agent_trace_review(trace)
        with self.assertRaises(MCPCatalogPreflightError):
            build_mcp_catalog_preflight(manifest)
        with self.assertRaises(MCPApiReadBindingError):
            build_mcp_api_read_bindings(self.manifest, self.preflight, request)

    def test_domain_source_and_output_byte_limits_are_enforced(self) -> None:
        source_cases = (
            ("sunderkey.agent_trace_review.MAX_INPUT_BYTES", self.prior, AgentTraceReviewError,
             lambda: build_agent_trace_review(self.prior)),
            ("sunderkey.mcp_catalog_preflight.MAX_INPUT_BYTES", self.manifest,
             MCPCatalogPreflightError, lambda: build_mcp_catalog_preflight(self.manifest)),
            ("sunderkey.mcp_api_read_bindings.MAX_BINDINGS_BYTES", self.request,
             MCPApiReadBindingError,
             lambda: build_mcp_api_read_bindings(self.manifest, self.preflight, self.request)),
        )
        for constant, artifact, error, build in source_cases:
            size = len(canonical_json_bytes(artifact, max_bytes=1_000_000))
            with self.subTest(constant=constant):
                with patch(constant, size):
                    build()
                with patch(constant, size - 1), self.assertRaises(error):
                    build()
        output_constants = (
            "sunderkey.agent_trace_review.MAX_REVIEW_BYTES",
            "sunderkey.agent_trace_regression.MAX_COMPARISON_BYTES",
            "sunderkey.mcp_catalog_preflight.MAX_PREFLIGHT_BYTES",
            "sunderkey.mcp_api_read_bindings.MAX_PLAN_BYTES",
        )
        for constant, case in zip(output_constants, self.cases, strict=True):
            _, artifact, error, verify = case
            size = len(canonical_json_bytes(artifact, max_bytes=1_000_000))
            with self.subTest(constant=constant):
                with patch(constant, size):
                    self.assertEqual(verify(artifact)["status"], "valid")
                with patch(constant, size - 1), self.assertRaises(error):
                    verify(artifact)


if __name__ == "__main__":
    unittest.main()

"""Inert Redis command/key arithmetic and exact supplied-model replay controls."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import socket
import unittest
from unittest.mock import patch

from sunderkey import offline_redis_acl_analysis as acl

GOLDEN_ID = "RAC-9DF56DA03849C2B975EAB1E3F966289A"
GOLDEN_SHA = "sha256:9df56da03849c2b975eab1e3f966289a43abe4eac13e4df33dac602cd2ddbc4b"
GOLDEN_SOURCE_SHA = "sha256:f98e1228b11485ca617b19b4f9ddee98907d707d12363cf2ee00630e60d3b743"


def component_fixture() -> dict:
    """Return public inert input only, with no Redis connection or credential values."""
    return {
        "model": {
            "schema_version": 1,
            "semantics": "redis_7_2_5_acl_key_subset",
            "resource_ref": "supplied:cache:test",
            "username": "application",
            "selectors_complete": True,
            "unsupported_features": [],
            "root_selector": {
                "selector_id": "root",
                "commands": ["get", "mget", "del", "getdel"],
                "key_patterns": [{"pattern": "app1:*", "permissions": "read_write"}],
            },
            "selectors": [
                {
                    "selector_id": "app2-read",
                    "commands": ["get", "mget", "copy"],
                    "key_patterns": [{"pattern": "app2:*", "permissions": "read"}],
                },
                {
                    "selector_id": "copy-bridge",
                    "commands": ["copy"],
                    "key_patterns": [
                        {"pattern": "app2:*", "permissions": "read"},
                        {"pattern": "app1:*", "permissions": "write"},
                    ],
                },
            ],
            "queries": [
                {"query_id": "app1-read", "command": "GET", "keys": ["app1:user"]},
                {"query_id": "app2-read", "command": "get", "keys": ["app2:user"]},
                {"query_id": "app2-write", "command": "del", "keys": ["app2:user"]},
                {
                    "query_id": "split-mget",
                    "command": "mget",
                    "keys": ["app1:user", "app2:user"],
                },
                {
                    "query_id": "copy-into-app1",
                    "command": "copy",
                    "keys": ["app2:user", "app1:user"],
                },
                {
                    "query_id": "copy-reversed",
                    "command": "copy",
                    "keys": ["app1:user", "app2:user"],
                },
                {"query_id": "app2-getdel", "command": "getdel", "keys": ["app2:user"]},
            ],
        }
    }


def _one(patterns: list[dict], command: str = "get", keys: list[str] | None = None) -> dict:
    model = component_fixture()["model"]
    model["selectors"] = []
    model["root_selector"]["commands"] = [command.lower()]
    model["root_selector"]["key_patterns"] = patterns
    model["queries"] = [{"query_id": "query", "command": command, "keys": keys or ["secret:one"]}]
    return model


def _rows(model: dict) -> dict:
    return {
        row["query_id"]: row for row in acl.analyze_supplied_redis_acl(model).to_dict()["results"]
    }


def _readdress(document: dict) -> dict:
    body = {
        key: value
        for key, value in document.items()
        if key not in {"analysis_id", "analysis_sha256"}
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(
        acl.DOMAIN.encode("ascii") + b"\n" + canonical.encode("ascii")
    ).hexdigest()
    document["analysis_sha256"] = "sha256:" + digest
    document["analysis_id"] = "RAC-" + digest[:32].upper()
    return document


class OfflineRedisAclAnalysisTests(unittest.TestCase):
    def test_literal_fixture_addresses_and_all_canonical_round_trips(self) -> None:
        model = component_fixture()["model"]
        analysis = acl.analyze_supplied_redis_acl(model)
        document = analysis.to_dict()
        self.assertEqual(document["analysis_id"], GOLDEN_ID)
        self.assertEqual(document["analysis_sha256"], GOLDEN_SHA)
        self.assertEqual(document["source_model_sha256"], GOLDEN_SOURCE_SHA)
        wire = analysis.to_json()
        self.assertEqual(acl.RedisAclAnalysis.from_dict(document).to_json(), wire)
        self.assertEqual(acl.RedisAclAnalysis.from_json(wire).to_json(), wire)
        self.assertEqual(
            acl.verify_supplied_redis_acl_analysis(analysis, model=model).to_json(), wire
        )
        self.assertEqual(
            acl.verify_supplied_redis_acl_analysis(document, model=model).to_json(), wire
        )
        self.assertEqual(acl.analyze_supplied_redis_acl(model).to_json(), wire)

    def test_fixture_known_grants_and_adverse_requests(self) -> None:
        rows = _rows(component_fixture()["model"])
        allowed = {"app1-read", "app2-read", "copy-into-app1"}
        for query_id, row in rows.items():
            with self.subTest(query=query_id):
                self.assertEqual(
                    row["status"],
                    "allowed_by_supplied_acl"
                    if query_id in allowed
                    else "not_allowed_by_supplied_acl",
                )
        self.assertEqual(rows["copy-into-app1"]["matching_selector_ids"], ["copy-bridge"])

    def test_split_selectors_cannot_jointly_authorize_multikey_request(self) -> None:
        model = _one([{"pattern": "a:*", "permissions": "read"}], "mget", ["a:one", "b:two"])
        model["selectors"] = [
            {
                "selector_id": "other",
                "commands": ["mget"],
                "key_patterns": [{"pattern": "b:*", "permissions": "read"}],
            }
        ]
        row = _rows(model)["query"]
        self.assertEqual(row["status"], "not_allowed_by_supplied_acl")
        self.assertEqual(row["matching_selector_ids"], [])
        self.assertEqual(
            sorted(check["unmatched_key_indices"] for check in row["selector_checks"]), [[0], [1]]
        )

    def test_same_selector_can_authorize_all_multikey_positions(self) -> None:
        model = _one(
            [{"pattern": "a:*", "permissions": "read"}, {"pattern": "b:*", "permissions": "read"}],
            "mget",
            ["a:one", "b:two", "a:one"],
        )
        row = _rows(model)["query"]
        self.assertEqual(row["status"], "allowed_by_supplied_acl")
        self.assertEqual([item["key_index"] for item in row["required_keys"]], [0, 1, 2])
        self.assertEqual(len(row["selector_checks"][0]["key_witnesses"]), 3)

    def test_command_and_key_permissions_cannot_cross_selectors(self) -> None:
        model = _one([{"pattern": "secret:*", "permissions": "read"}])
        model["root_selector"]["commands"] = []
        model["selectors"] = [
            {"selector_id": "commands-only", "commands": ["get"], "key_patterns": []}
        ]
        self.assertEqual(_rows(model)["query"]["status"], "not_allowed_by_supplied_acl")

    def test_distinct_overlapping_patterns_cannot_union_getdel_flags(self) -> None:
        patterns = [
            {"pattern": "secret:*", "permissions": "read"},
            {"pattern": "*", "permissions": "write"},
        ]
        for command, expected in (("get", True), ("del", True), ("getdel", False)):
            with self.subTest(command=command):
                row = _rows(_one(patterns, command))["query"]
                self.assertEqual(row["status"] == "allowed_by_supplied_acl", expected)

    def test_getdel_requires_one_read_write_pattern(self) -> None:
        row = _rows(_one([{"pattern": "secret:*", "permissions": "read_write"}], "getdel"))["query"]
        self.assertEqual(row["status"], "allowed_by_supplied_acl")
        self.assertEqual(row["required_keys"][0]["permissions"], "read_write")

    def test_copy_access_direction_and_same_key_positions_remain_separate(self) -> None:
        patterns = [
            {"pattern": "source:*", "permissions": "read"},
            {"pattern": "*", "permissions": "write"},
        ]
        forward = _rows(_one(patterns, "copy", ["source:one", "destination:two"]))["query"]
        reverse = _rows(_one(patterns, "copy", ["destination:two", "source:one"]))["query"]
        same = _rows(_one(patterns, "copy", ["source:one", "source:one"]))["query"]
        self.assertEqual(forward["status"], "allowed_by_supplied_acl")
        self.assertEqual(reverse["status"], "not_allowed_by_supplied_acl")
        self.assertEqual(same["status"], "allowed_by_supplied_acl")
        self.assertEqual([item["permissions"] for item in same["required_keys"]], ["read", "write"])

    def test_read_only_and_write_only_patterns_are_not_command_categories(self) -> None:
        for permission in ("read", "write", "read_write"):
            for command in ("get", "del", "getdel"):
                with self.subTest(permission=permission, command=command):
                    row = _rows(_one([{"pattern": "*", "permissions": permission}], command))[
                        "query"
                    ]
                    required = {"get": 1, "del": 2, "getdel": 3}[command]
                    flags = {"read": 1, "write": 2, "read_write": 3}[permission]
                    self.assertEqual(
                        row["status"] == "allowed_by_supplied_acl", flags & required == required
                    )

    def test_glob_subset_has_independent_finite_mathematical_oracle(self) -> None:
        keys = [
            "".join(parts)
            for length in (1, 2)
            for parts in itertools.product("ab*?", repeat=length)
        ]
        cases = {
            "a": lambda key: key == "a",
            "*": lambda key: True,
            "?": lambda key: len(key) == 1,
            "a*": lambda key: key.startswith("a"),
            "*a": lambda key: key.endswith("a"),
            "a?": lambda key: len(key) == 2 and key.startswith("a"),
            "[ab]": lambda key: len(key) == 1 and key in "ab",
            "[^a]": lambda key: len(key) == 1 and key != "a",
            "[b-a]": lambda key: len(key) == 1 and key in "ab",
            r"\*": lambda key: key == "*",
            r"a\?": lambda key: key == "a?",
            r"[\*?]": lambda key: len(key) == 1 and key in "*?",
            "**a**": lambda key: "a" in key,
            "[^*?]": lambda key: len(key) == 1 and key not in "*?",
        }
        for pattern, oracle in cases.items():
            model = _one([{"pattern": pattern, "permissions": "read"}])
            model["queries"] = [
                {"query_id": f"q{index:02}", "command": "get", "keys": [key]}
                for index, key in enumerate(keys)
            ]
            rows = _rows(model)
            for index, key in enumerate(keys):
                with self.subTest(pattern=pattern, key=key):
                    self.assertEqual(
                        rows[f"q{index:02}"]["status"] == "allowed_by_supplied_acl", oracle(key)
                    )

    def test_case_sensitive_keys_and_case_insensitive_query_command(self) -> None:
        model = _one([{"pattern": "App:*", "permissions": "read"}], "GeT", ["App:one"])
        self.assertEqual(_rows(model)["query"]["status"], "allowed_by_supplied_acl")
        model["queries"][0]["keys"] = ["app:one"]
        self.assertEqual(_rows(model)["query"]["status"], "not_allowed_by_supplied_acl")

    def test_escaped_brackets_caret_and_reversed_ranges(self) -> None:
        cases = [
            (r"\[a\]", "[a]", True),
            (r"[\]]", "]", True),
            ("[z-a]", "m", True),
            ("[!a]", "b", False),
            ("[!a]", "!", True),
            ("[^a]", "b", True),
        ]
        for pattern, key, expected in cases:
            with self.subTest(pattern=pattern, key=key):
                row = _rows(_one([{"pattern": pattern, "permissions": "read"}], keys=[key]))[
                    "query"
                ]
                self.assertEqual(row["status"] == "allowed_by_supplied_acl", expected)

    def test_malformed_globs_reject_before_any_canonicalization_or_hash(self) -> None:
        for pattern in ("[", "[]", "[^]", "[a-]", "[a-\\z]", "a\\", "[a\\"):
            with (
                self.subTest(pattern=pattern),
                patch.object(acl.json, "dumps") as dumps,
                patch.object(acl.hashlib, "sha256") as sha,
            ):
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl(
                        _one([{"pattern": pattern, "permissions": "read"}])
                    )
                dumps.assert_not_called()
                sha.assert_not_called()

    def test_incomplete_inventory_retains_known_witness_without_final_grant(self) -> None:
        model = _one([{"pattern": "*", "permissions": "read"}])
        model["selectors_complete"] = False
        row = _rows(model)["query"]
        self.assertEqual(row["status"], "inconclusive")
        self.assertEqual(row["matching_selector_ids"], ["root"])
        self.assertIn("incomplete_selector_inventory", row["reasons"])

    def test_each_declared_unsupported_feature_withholds_all_final_conclusions(self) -> None:
        for feature in acl._UNSUPPORTED_FEATURES:
            with self.subTest(feature=feature):
                model = component_fixture()["model"]
                model["unsupported_features"] = [feature]
                rows = _rows(model)
                self.assertTrue(all(row["status"] == "inconclusive" for row in rows.values()))
                self.assertEqual(rows["app1-read"]["matching_selector_ids"], ["root"])

    def test_closed_snapshot_rejects_unknown_features_and_authentication_flags(self) -> None:
        for change in (
            {"unsupported_features": ["future_feature"]},
            {"on": False},
            {"passwords": []},
            {"unsupported_features": ["pubsub", "pubsub"]},
        ):
            with self.subTest(change=change):
                model = component_fixture()["model"]
                model.update(change)
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl(model)

    def test_duplicate_ids_commands_and_identical_patterns_are_nonnormalized(self) -> None:
        models = []
        model = component_fixture()["model"]
        model["selectors"][0]["selector_id"] = "root"
        models.append(model)
        model = component_fixture()["model"]
        model["queries"].append(copy.deepcopy(model["queries"][0]))
        models.append(model)
        model = _one(
            [{"pattern": "*", "permissions": "read"}, {"pattern": "*", "permissions": "write"}],
            "getdel",
        )
        models.append(model)
        model = component_fixture()["model"]
        model["root_selector"]["commands"].append("get")
        models.append(model)
        for index, model in enumerate(models):
            with self.subTest(case=index), self.assertRaises(acl.RedisAclAnalysisError):
                acl.analyze_supplied_redis_acl(model)

    def test_invalid_positional_shapes_and_unknown_commands_reject(self) -> None:
        for command, keys in (
            ("get", []),
            ("get", ["a", "b"]),
            ("getdel", ["a", "b"]),
            ("copy", ["a"]),
            ("copy", ["a", "b", "c"]),
            ("mget", []),
            ("del", []),
            ("set", ["a"]),
            ("GET value", ["a"]),
        ):
            model = component_fixture()["model"]
            model["queries"] = [{"query_id": "q", "command": command, "keys": keys}]
            with (
                self.subTest(command=command, keys=keys),
                self.assertRaises(acl.RedisAclAnalysisError),
            ):
                acl.analyze_supplied_redis_acl(model)

    def test_native_aliases_and_conversion_hooks_are_rejected_before_hash(self) -> None:
        class Text(str):
            def __str__(self):
                raise AssertionError("conversion hook")

        class NativeMap(dict):
            def items(self):
                raise AssertionError("mapping hook")

        mutations = [
            ("schema_version", True),
            ("schema_version", 1.0),
            ("selectors_complete", 1),
            ("username", Text("application")),
            ("root_selector", NativeMap(component_fixture()["model"]["root_selector"])),
        ]
        for field, value in mutations:
            model = component_fixture()["model"]
            model[field] = value
            with (
                self.subTest(field=field, kind=type(value).__name__),
                patch.object(acl.hashlib, "sha256") as sha,
            ):
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl(model)
                sha.assert_not_called()

    def test_nonprintable_empty_and_oversized_keys_reject(self) -> None:
        for key in ("", "key\n", "\u00e9", "\ud800", "x" * 129, True, 1):
            model = component_fixture()["model"]
            model["queries"][0]["keys"] = [key]
            with self.subTest(key=repr(key)), self.assertRaises(acl.RedisAclAnalysisError):
                acl.analyze_supplied_redis_acl(model)

    def test_native_cyclic_deep_and_repeated_shared_data_are_bounded(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        deep = 0
        for _ in range(acl.MAX_MODEL_DEPTH):
            deep = [deep]
        repeated = [["x"]] * (acl.MAX_MODEL_NODES // 2)
        for value in (cyclic, deep, repeated, ["x" * 256] * 1025):
            with (
                self.subTest(kind=type(value).__name__),
                patch.object(acl.json, "dumps") as dumps,
                patch.object(acl.hashlib, "sha256") as sha,
            ):
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl(value)
                dumps.assert_not_called()
                sha.assert_not_called()

    def test_input_and_output_mutations_do_not_alias_the_owned_analysis(self) -> None:
        model = component_fixture()["model"]
        analysis = acl.analyze_supplied_redis_acl(model)
        wire = analysis.to_json()
        detached = analysis.to_dict()
        detached["source_model"]["root_selector"]["key_patterns"][0]["permissions"] = "write"
        model["root_selector"]["commands"] = []
        self.assertEqual(analysis.to_json(), wire)
        with self.assertRaises(acl.RedisAclAnalysisError):
            acl.verify_supplied_redis_acl_analysis(analysis, model=model)

    def test_shared_valid_subtrees_are_counted_and_captured_per_occurrence(self) -> None:
        shared = {"pattern": "*", "permissions": "read"}
        model = _one([shared])
        model["selectors"] = [
            {"selector_id": "other", "commands": ["get"], "key_patterns": [shared]}
        ]
        analysis = acl.analyze_supplied_redis_acl(model)
        self.assertEqual(
            analysis.to_dict()["results"][0]["matching_selector_ids"], ["other", "root"]
        )
        shared["permissions"] = "write"
        self.assertEqual(
            analysis.to_dict()["source_model"]["root_selector"]["key_patterns"][0]["permissions"],
            "read",
        )

    def test_source_permutations_preserve_results_but_not_source_addresses(self) -> None:
        first = component_fixture()["model"]
        second = copy.deepcopy(first)
        second["selectors"].reverse()
        second["queries"].reverse()
        second["root_selector"]["commands"].reverse()
        for selector in second["selectors"]:
            selector["commands"].reverse()
            selector["key_patterns"].reverse()
        a, b = (
            acl.analyze_supplied_redis_acl(first).to_dict(),
            acl.analyze_supplied_redis_acl(second).to_dict(),
        )
        self.assertEqual(a["results"], b["results"])
        self.assertEqual(a["summary"], b["summary"])
        self.assertNotEqual(a["source_model_sha256"], b["source_model_sha256"])
        self.assertNotEqual(a["analysis_sha256"], b["analysis_sha256"])

    def test_bytes_provenance_is_canonical_parsed_model_not_raw_wire(self) -> None:
        model = component_fixture()["model"]
        compact = json.dumps(model, separators=(",", ":")).encode("ascii")
        pretty = json.dumps(model, indent=2).encode("ascii")
        escaped = compact.replace(b"application", b"applic\\u0061tion")
        self.assertNotEqual(compact, pretty)
        a = acl.analyze_supplied_redis_acl_bytes(model_json=compact).to_json()
        self.assertEqual(acl.analyze_supplied_redis_acl_bytes(model_json=pretty).to_json(), a)
        self.assertEqual(acl.analyze_supplied_redis_acl_bytes(model_json=escaped).to_json(), a)

    def test_duplicate_json_keys_at_root_and_nested_positions_reject(self) -> None:
        wire = json.dumps(component_fixture()["model"], separators=(",", ":"))
        for text in (
            wire.replace('"schema_version":1', '"schema_version":1,"schema_version":1', 1),
            wire.replace('"pattern":"app1:*"', '"pattern":"app1:*","pattern":"app1:*"', 1),
        ):
            with self.subTest(text=text[:80]), self.assertRaises(acl.RedisAclAnalysisError):
                acl.analyze_supplied_redis_acl_bytes(model_json=text.encode("ascii"))

    def test_raw_depth_value_escape_and_integer_limits_precede_decoder(self) -> None:
        cases = [
            b"x" * (acl.MAX_MODEL_BYTES + 1),
            b"[" * acl.MAX_MODEL_DEPTH + b"0" + b"]" * acl.MAX_MODEL_DEPTH,
            b"[" + b"0," * acl.MAX_MODEL_NODES + b"0]",
            ('"' + "\\u0041" * 257 + '"').encode("ascii"),
            b"9223372036854775808",
            b"-9223372036854775809",
            b"9" * 10000,
            b"1.0",
            b"NaN",
        ]
        for raw in cases:
            with (
                self.subTest(prefix=raw[:32]),
                patch.object(acl.json, "loads") as loads,
                patch.object(acl.hashlib, "sha256") as sha,
            ):
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl_bytes(model_json=raw)
                loads.assert_not_called()
                sha.assert_not_called()

    def test_raw_lexical_boundary_controls_and_escaped_structure(self) -> None:
        self.assertEqual(acl._json("-9223372036854775808"), -(1 << 63))
        self.assertEqual(acl._json("9223372036854775807"), (1 << 63) - 1)
        self.assertEqual(acl._json('"' + "\\u0041" * 256 + '"'), "A" * 256)
        self.assertEqual(acl._json('"[]{}\\\\\\""'), '[]{}\\"')
        nested = "[" * (acl.MAX_MODEL_DEPTH - 1) + "0" + "]" * (acl.MAX_MODEL_DEPTH - 1)
        self.assertIsInstance(acl._json(nested), list)

    def test_malformed_json_and_wrong_byte_families_have_domain_errors(self) -> None:
        for raw in (
            b"",
            b"--1",
            b"---1",
            b"--0",
            b"true false",
            b"[}",
            b'{"x":}',
            b'"\\ud800"',
            b'"\\n"',
            b"\xff",
            bytearray(b"{}"),
            "{}",
        ):
            with self.subTest(raw=repr(raw)), self.assertRaises(acl.RedisAclAnalysisError):
                acl.analyze_supplied_redis_acl_bytes(model_json=raw)

    def test_selector_and_pattern_capacity_controls(self) -> None:
        model = _one([])
        model["root_selector"]["commands"] = []
        model["selectors"] = [
            {"selector_id": f"s{i:02}", "commands": [], "key_patterns": []} for i in range(31)
        ]
        self.assertEqual(
            acl.analyze_supplied_redis_acl(model).to_dict()["summary"]["selector_count"], 32
        )
        model["selectors"].append({"selector_id": "overflow", "commands": [], "key_patterns": []})
        with self.assertRaises(acl.RedisAclAnalysisError):
            acl.analyze_supplied_redis_acl(model)
        model = _one([{"pattern": f"p{i:02}", "permissions": "read"} for i in range(64)])
        self.assertEqual(
            acl.analyze_supplied_redis_acl(model).to_dict()["summary"]["pattern_count"], 64
        )
        model["root_selector"]["key_patterns"].append(
            {"pattern": "overflow", "permissions": "read"}
        )
        with self.assertRaises(acl.RedisAclAnalysisError):
            acl.analyze_supplied_redis_acl(model)

    def test_aggregate_pattern_and_query_key_bounds_precede_hash(self) -> None:
        pattern_model = _one([{"pattern": "root", "permissions": "read"}])
        pattern_model["selectors"] = [
            {
                "selector_id": f"s{i}",
                "commands": [],
                "key_patterns": [{"pattern": f"p{j}", "permissions": "read"} for j in range(64)],
            }
            for i in range(8)
        ]
        key_model = _one([], "mget")
        key_model["queries"] = [
            {"query_id": f"q{i}", "command": "mget", "keys": ["key"] * 32} for i in range(32)
        ]
        self.assertEqual(
            acl.analyze_supplied_redis_acl(key_model).to_dict()["summary"]["query_count"], 32
        )
        key_model["queries"].append({"query_id": "overflow", "command": "get", "keys": ["key"]})
        for model in (pattern_model, key_model):
            with patch.object(acl.hashlib, "sha256") as sha:
                with self.assertRaises(acl.RedisAclAnalysisError):
                    acl.analyze_supplied_redis_acl(model)
                sha.assert_not_called()

    def test_real_matching_work_limit_fails_before_serialization_or_hash(self) -> None:
        model = _one([{"pattern": f"{i:02}" + "*" * 126, "permissions": "read"} for i in range(64)])
        model["queries"] = [
            {"query_id": f"q{i}", "command": "get", "keys": ["x" * 127 + chr(65 + i)]}
            for i in range(4)
        ]
        with patch.object(acl.json, "dumps") as dumps, patch.object(acl.hashlib, "sha256") as sha:
            with self.assertRaisesRegex(acl.RedisAclAnalysisError, "work budget"):
                acl.analyze_supplied_redis_acl(model)
            dumps.assert_not_called()
            sha.assert_not_called()

    def test_real_retained_node_overflow_precedes_addressing(self) -> None:
        model = _one([{"pattern": "*", "permissions": "read"}], "mget")
        model["selectors"] = [
            {
                "selector_id": f"s{i}",
                "commands": ["mget"],
                "key_patterns": [{"pattern": "*", "permissions": "read"}],
            }
            for i in range(2)
        ]
        model["queries"] = [
            {"query_id": f"q{i:02}", "command": "mget", "keys": ["key"] * 32} for i in range(32)
        ]
        with patch.object(acl.json, "dumps") as dumps, patch.object(acl.hashlib, "sha256") as sha:
            with self.assertRaisesRegex(acl.RedisAclAnalysisError, "node"):
                acl.analyze_supplied_redis_acl(model)
            dumps.assert_not_called()
            sha.assert_not_called()

    def test_reduced_witness_cache_and_retained_byte_guards_before_hash(self) -> None:
        # Transparent guard placement tests, not claimed production-limit bypasses.
        model = component_fixture()["model"]
        for name, limit, message in (
            ("MAX_WITNESSES", 1, "witness"),
            ("MAX_MATCH_CACHE_ENTRIES", 1, "cache"),
            ("MAX_REPORT_BYTES", 2000, "byte"),
        ):
            with (
                self.subTest(guard=name),
                patch.object(acl, name, limit),
                patch.object(acl.hashlib, "sha256") as sha,
            ):
                with self.assertRaisesRegex(acl.RedisAclAnalysisError, message):
                    acl.analyze_supplied_redis_acl(model)
                sha.assert_not_called()

    def test_each_supplied_binding_change_fails_original_source_replay(self) -> None:
        original = component_fixture()["model"]
        changes = [
            lambda model: model.update(resource_ref="supplied:other"),
            lambda model: model.update(username="other"),
            lambda model: model.update(selectors_complete=False),
            lambda model: model["root_selector"].update(commands=[]),
            lambda model: model["root_selector"]["key_patterns"][0].update(permissions="write"),
            lambda model: model["queries"][0].update(keys=["app2:user"]),
        ]
        for change in changes:
            altered = copy.deepcopy(original)
            change(altered)
            genuine_alternate = acl.analyze_supplied_redis_acl(altered)
            with (
                self.subTest(source=genuine_alternate.to_dict()["source_model_sha256"]),
                self.assertRaises(acl.RedisAclAnalysisError),
            ):
                acl.verify_supplied_redis_acl_analysis(genuine_alternate, model=original)

    def test_cohashed_false_outcomes_and_witnesses_fail_embedded_replay(self) -> None:
        original = acl.analyze_supplied_redis_acl(component_fixture()["model"]).to_dict()
        for field in (
            "status",
            "matching_selector_ids",
            "key_witnesses",
            "unmatched_key_indices",
            "work_steps",
        ):
            document = copy.deepcopy(original)
            row = next(item for item in document["results"] if item["query_id"] == "split-mget")
            if field == "status":
                row["status"] = "allowed_by_supplied_acl"
            elif field == "matching_selector_ids":
                row[field] = ["root"]
            elif field == "work_steps":
                document["summary"][field] += 1
            else:
                check = next(
                    item for item in row["selector_checks"] if item["selector_id"] == "root"
                )
                check[field] = []
            _readdress(document)
            with self.subTest(field=field), self.assertRaises(acl.RedisAclAnalysisError):
                acl.RedisAclAnalysis.from_dict(document)

    def test_native_report_counter_flag_and_effect_aliases_cannot_rehash(self) -> None:
        original = acl.analyze_supplied_redis_acl(component_fixture()["model"]).to_dict()
        for field, alias in (
            ("schema_version", True),
            ("schema_version", 1.0),
            ("source_authenticated", True),
            ("offline_only", 1),
        ):
            document = copy.deepcopy(original)
            document[field] = alias
            with self.subTest(field=field), self.assertRaises(acl.RedisAclAnalysisError):
                acl.RedisAclAnalysis.from_dict(_readdress(document))
        for alias in (True, 7.0):
            document = copy.deepcopy(original)
            document["summary"]["query_count"] = alias
            with self.subTest(counter=alias), self.assertRaises(acl.RedisAclAnalysisError):
                acl.RedisAclAnalysis.from_dict(_readdress(document))
        document = copy.deepcopy(original)
        document["effects"]["execution"] = "performed"
        with self.assertRaises(acl.RedisAclAnalysisError):
            acl.RedisAclAnalysis.from_dict(_readdress(document))

    def test_wrapper_missing_slot_late_mutation_and_foreign_source_reject(self) -> None:
        model = component_fixture()["model"]
        incomplete = object.__new__(acl.RedisAclAnalysis)
        with self.assertRaises(acl.RedisAclAnalysisError):
            incomplete.to_dict()
        analysis = acl.analyze_supplied_redis_acl(model)
        document = analysis.to_dict()
        document["summary"]["query_count"] = True
        object.__setattr__(analysis, "document_json", json.dumps(_readdress(document)))
        with self.assertRaises(acl.RedisAclAnalysisError):
            analysis.to_json()
        foreign = copy.deepcopy(model)
        foreign["username"] = "other"
        analysis = acl.analyze_supplied_redis_acl(model)
        object.__setattr__(
            analysis, "document_json", acl.analyze_supplied_redis_acl(foreign).to_json()
        )
        with self.assertRaises(acl.RedisAclAnalysisError):
            acl.verify_supplied_redis_acl_analysis(analysis, model=model)

    def test_metadata_and_effects_never_become_authority_or_dispatch(self) -> None:
        with patch.object(socket, "socket", side_effect=AssertionError("no sockets")):
            document = acl.analyze_supplied_redis_acl(component_fixture()["model"]).to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D07-S05")
        self.assertEqual(document["validator_id"], "AOE-HQ-34")
        self.assertTrue(document["offline_only"])
        for name in (
            "source_authenticated",
            "principal_authenticated",
            "effective_access_proven",
            "live_use_approved",
            "qualification_claimed",
        ):
            self.assertIs(document[name], False)
        self.assertTrue(all(value == "none" for value in document["effects"].values()))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_postgresql_rls_analysis as m


def boolean(value: bool | None) -> dict:
    return {"op": "bool", "value": value}


def policy(identifier: str, value: bool | None, mode: str = "PERMISSIVE") -> dict:
    return {
        "policy_id": identifier,
        "command": "SELECT",
        "mode": mode,
        "to_roles": [{"kind": "public"}],
        "using": boolean(value),
    }


def component_fixture() -> dict:
    """Fresh wholly synthetic model; no database or actual principal is involved."""
    return {
        "schema_version": 1,
        "semantics_profile": m.SEMANTICS_PROFILE,
        "roles": [
            {"name": name, "superuser": False, "bypass_rls": False}
            for name in ("alice", "reader", "owner")
        ],
        "memberships": [{"member_role": "alice", "granted_role": "reader", "inherit": True}],
        "role_membership_complete": True,
        "table": {
            "table_ref": "table:synthetic",
            "relation_kind": "ordinary_table",
            "owner_role": "owner",
            "rls_enabled": True,
            "force_rls": False,
            "policy_inventory_complete": True,
            "select_grantees": [{"kind": "role", "name": "reader"}],
            "select_grants_complete": True,
            "columns": {"owner": "text_c", "active": "boolean", "level": "int8"},
            "policies": [
                {
                    "policy_id": "own_rows",
                    "command": "SELECT",
                    "mode": "PERMISSIVE",
                    "to_roles": [{"kind": "role", "name": "reader"}],
                    "using": {
                        "op": "eq",
                        "left": {"kind": "column", "name": "owner"},
                        "right": {"kind": "current_user"},
                    },
                },
                {
                    "policy_id": "active_rows",
                    "command": "ALL",
                    "mode": "RESTRICTIVE",
                    "to_roles": [{"kind": "public"}],
                    "using": {
                        "op": "eq",
                        "left": {"kind": "column", "name": "active"},
                        "right": {"kind": "literal", "type": "boolean", "value": True},
                    },
                },
            ],
        },
        "contexts": [
            {"context_id": "context:alice", "current_role": "alice", "row_security_on": True}
        ],
        "rows": [
            {"row_id": "own", "values": {"owner": "alice", "active": True, "level": 1}},
            {"row_id": "other", "values": {"owner": "bob", "active": True, "level": 2}},
            {"row_id": "null", "values": {"owner": "alice", "active": None, "level": None}},
        ],
        "queries": [
            {"query_id": "query:" + row, "context_id": "context:alice", "row_id": row}
            for row in ("own", "other", "null")
        ],
    }


def address_report(raw: dict) -> dict:
    body = {
        key: value for key, value in raw.items() if key not in {"analysis_id", "analysis_sha256"}
    }
    text = json.dumps(
        {"domain": m.DOMAIN, "content": body},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    digest = hashlib.sha256(text.encode("ascii")).hexdigest()
    return {
        **body,
        "analysis_id": "PRL-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class PostgreSQLRlsAnalysisTests(unittest.TestCase):
    def analyze(self, model: dict | None = None) -> dict:
        return m.analyze_supplied_postgresql_rls(
            component_fixture() if model is None else model
        ).to_dict()

    def one(self, model: dict) -> dict:
        model["queries"] = model["queries"][:1]
        return self.analyze(model)["query_results"][0]

    def test_literal_fixture_and_roundtrip(self) -> None:
        original = component_fixture()
        before = copy.deepcopy(original)
        report = m.analyze_supplied_postgresql_rls(original)
        document = report.to_dict()
        self.assertEqual(original, before)
        self.assertEqual(document["component_id"], "postgresql_supplied_select_rls")
        self.assertEqual(document["profile_id"], "AOE-GB-D07-S14")
        self.assertEqual(document["wave_id"], "IW2-014")
        self.assertEqual(document["validator_id"], "AOE-HQ-34")
        self.assertEqual(document["analysis_id"], "PRL-289CEA05ECF972F68D012DE260DD6540")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:289cea05ecf972f68d012de260dd6540ed361a032bfb03dbd7d10051162de9c5",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:6655425e192d439a19efc90af4900e15fc6202bb18a9a18629d3184c36e1fa6f",
        )
        self.assertEqual(len(report.to_json().encode("ascii")), 5469)
        self.assertEqual(document["work_units"], 89)
        self.assertEqual(
            [row["outcome"] for row in document["query_results"]],
            [
                "row_available_in_supplied_select_rls_model",
                "row_filtered_in_supplied_select_rls_model",
                "row_filtered_in_supplied_select_rls_model",
            ],
        )
        self.assertEqual(
            report.to_json(), m.SuppliedPostgreSQLRlsAnalysis.from_dict(document).to_json()
        )
        self.assertEqual(
            report.to_json(), m.SuppliedPostgreSQLRlsAnalysis.from_json(report.to_json()).to_json()
        )
        self.assertEqual(
            report.to_json(),
            m.SuppliedPostgreSQLRlsAnalysis.from_bytes(report.to_json().encode()).to_json(),
        )
        self.assertEqual(
            report.to_json(),
            m.verify_supplied_postgresql_rls_analysis(report, model=original).to_json(),
        )

    def test_exact_bytes_model_intake_is_detached(self) -> None:
        model = component_fixture()
        raw = json.dumps(model).encode()
        restored = m.parse_supplied_postgresql_rls_model(raw)
        self.assertEqual(restored, model)
        restored["roles"].clear()
        self.assertEqual(len(model["roles"]), 3)
        self.assertEqual(raw, json.dumps(model).encode())

    def test_inherit_only_closure_and_noninherited_attributes(self) -> None:
        model = component_fixture()
        model["roles"][1].update(superuser=True, bypass_rls=True)
        document = self.analyze(model)
        context = document["context_results"][0]
        self.assertEqual(context["effective_roles"], ["alice", "reader"])
        self.assertIs(context["own_superuser"], False)
        self.assertIs(context["own_bypass_rls"], False)
        self.assertEqual(document["query_results"][0]["rls"]["mode"], "active")
        model["memberships"][0]["inherit"] = False
        row = self.one(model)
        self.assertIs(row["select_privilege"]["allowed"], False)
        self.assertIs(row["rls"]["row_passes"], False)

    def test_owner_and_inherited_owner_do_not_manufacture_select(self) -> None:
        for direct in (True, False):
            model = component_fixture()
            model["table"]["select_grantees"] = []
            if direct:
                model["contexts"][0]["current_role"] = "owner"
            else:
                model["memberships"].append(
                    {"member_role": "reader", "granted_role": "owner", "inherit": True}
                )
            with self.subTest(direct=direct):
                row = self.one(model)
                self.assertEqual(row["rls"]["mode"], "bypass_owner_privileges")
                self.assertIs(row["select_privilege"]["allowed"], False)
                self.assertEqual(row["outcome"], "select_not_granted_in_supplied_model")

    def test_independent_small_inheritance_graph_oracle(self) -> None:
        edges = (("alice", "reader"), ("reader", "owner"), ("alice", "owner"))
        for states in itertools.product((None, False, True), repeat=len(edges)):
            model = component_fixture()
            model["memberships"] = [
                {"member_role": member, "granted_role": granted, "inherit": state}
                for (member, granted), state in zip(edges, states)
                if state is not None
            ]
            model["table"]["select_grantees"] = [{"kind": "role", "name": "owner"}]
            model["table"]["policies"] = [policy("denied", False)]
            expected = {"alice"}
            while True:
                expanded = expected | {
                    granted
                    for (member, granted), state in zip(edges, states)
                    if state is True and member in expected
                }
                if expanded == expected:
                    break
                expected = expanded
            with self.subTest(states=states):
                report = self.analyze(model)
                self.assertEqual(report["context_results"][0]["effective_roles"], sorted(expected))
                row = report["query_results"][0]
                self.assertIs(row["select_privilege"]["allowed"], "owner" in expected)
                self.assertEqual(
                    row["rls"]["mode"],
                    "bypass_owner_privileges" if "owner" in expected else "active",
                )

    def test_own_bypass_is_not_select_own_superuser_is_separate(self) -> None:
        model = component_fixture()
        model["table"].update(force_rls=True, select_grantees=[])
        model["roles"][0]["bypass_rls"] = True
        row = self.one(model)
        self.assertEqual(row["rls"]["mode"], "bypass_own_attribute")
        self.assertIs(row["select_privilege"]["allowed"], False)
        model["roles"][0]["superuser"] = True
        row = self.one(model)
        self.assertEqual(row["rls"]["mode"], "bypass_own_superuser")
        self.assertIs(row["select_privilege"]["allowed"], True)

    def test_force_rls_owner_and_disabled_table_controls(self) -> None:
        model = component_fixture()
        model["contexts"][0]["current_role"] = "owner"
        model["table"]["select_grantees"] = [{"kind": "public"}]
        self.assertEqual(self.one(copy.deepcopy(model))["rls"]["mode"], "bypass_owner_privileges")
        model["table"]["force_rls"] = True
        self.assertEqual(self.one(copy.deepcopy(model))["rls"]["mode"], "active")
        model["table"]["rls_enabled"] = False
        model["contexts"][0]["row_security_on"] = False
        row = self.one(model)
        self.assertEqual(row["rls"]["mode"], "disabled")
        self.assertIs(row["rls"]["row_passes"], True)

    def test_row_security_off_is_error_not_policy_bypass(self) -> None:
        model = component_fixture()
        model["contexts"][0]["row_security_on"] = False
        row = self.one(model)
        self.assertEqual(row["outcome"], "row_security_off_error_in_supplied_model")
        self.assertIsNone(row["rls"]["row_passes"])
        model["roles"][0]["bypass_rls"] = True
        self.assertEqual(self.one(model)["rls"]["mode"], "bypass_own_attribute")

    def test_no_permissive_and_restrictive_only_default_deny(self) -> None:
        for policies in ([], [policy("restrict", True, "RESTRICTIVE")]):
            model = component_fixture()
            model["table"]["policies"] = policies
            row = self.one(model)
            self.assertIs(row["rls"]["row_passes"], False)
            self.assertEqual(row["rls"]["permissive_value"], "false")

    def test_independent_permissive_restrictive_three_valued_oracle(self) -> None:
        values = (True, False, None)
        for first, second, third in itertools.product(values, repeat=3):
            model = component_fixture()
            model["table"]["policies"] = [
                policy("a", first),
                policy("b", second),
                policy("r", third, "RESTRICTIVE"),
            ]
            # Independent truth-set oracle, not production helpers.
            expected = (first is True or second is True) and third is True
            with self.subTest(values=(first, second, third)):
                self.assertIs(self.one(model)["rls"]["row_passes"], expected)

    def test_independent_and_or_not_sql_null_tables(self) -> None:
        for operator, left, right in itertools.product(
            ("and", "or"), (True, False, None), (True, False, None)
        ):
            model = component_fixture()
            ast = {"op": operator, "args": [boolean(left), boolean(right)]}
            item = policy("truth", True)
            item["using"] = ast
            model["table"]["policies"] = [item]
            expected = (
                (left is True and right is True)
                if operator == "and"
                else (left is True or right is True)
            )
            with self.subTest(operator=operator, left=left, right=right):
                self.assertIs(self.one(model)["rls"]["row_passes"], expected)
        for value in (True, False, None):
            model = component_fixture()
            item = policy("not", True)
            item["using"] = {"op": "not", "arg": boolean(value)}
            model["table"]["policies"] = [item]
            self.assertIs(self.one(model)["rls"]["row_passes"], value is False)

    def test_absent_using_is_not_explicit_sql_null(self) -> None:
        model = component_fixture()
        item = policy("absent", True)
        item["using"] = None
        model["table"]["policies"] = [item]
        row = self.one(model)
        self.assertIs(row["rls"]["row_passes"], True)
        self.assertEqual(row["rls"]["policy_evaluations"][0]["using_form"], "absent_implicit_true")
        item["using"] = boolean(None)
        row = self.one(model)
        self.assertIs(row["rls"]["row_passes"], False)
        self.assertEqual(row["rls"]["policy_evaluations"][0]["value"], "sql_null")

    def test_null_comparison_and_null_predicates(self) -> None:
        for operator, expected in (
            ("eq", False),
            ("ne", False),
            ("is_null", True),
            ("is_not_null", False),
        ):
            model = component_fixture()
            model["rows"][0]["values"]["level"] = None
            operand = {"kind": "column", "name": "level"}
            ast = (
                {"op": operator, "arg": operand}
                if operator.startswith("is_")
                else {
                    "op": operator,
                    "left": operand,
                    "right": {"kind": "literal", "type": "int8", "value": None},
                }
            )
            item = policy("null", True)
            item["using"] = ast
            model["table"]["policies"] = [item]
            self.assertIs(self.one(model)["rls"]["row_passes"], expected)

    def test_full_int8_boundaries_are_native_and_raw_positive(self) -> None:
        for number in (-(2**63), 2**63 - 1, 0):
            model = component_fixture()
            model["rows"][0]["values"]["level"] = number
            restored = m.parse_supplied_postgresql_rls_model(json.dumps(model).encode())
            self.assertIs(type(restored["rows"][0]["values"]["level"]), int)
            self.assertEqual(
                self.analyze(model)["source_model"]["rows"][0]["values"]["level"], number
            )

    def test_integer_comparisons_do_not_coerce_other_types(self) -> None:
        for op, expected in (
            ("eq", True),
            ("ne", False),
            ("lt", False),
            ("le", True),
            ("gt", False),
            ("ge", True),
        ):
            model = component_fixture()
            item = policy("compare", True)
            item["using"] = {
                "op": op,
                "left": {"kind": "column", "name": "level"},
                "right": {"kind": "literal", "type": "int8", "value": 1},
            }
            model["table"]["policies"] = [item]
            self.assertIs(self.one(model)["rls"]["row_passes"], expected)

    def test_public_and_exact_role_selectors_no_owner_inference(self) -> None:
        model = component_fixture()
        model["table"]["select_grantees"] = [{"kind": "role", "name": "owner"}]
        self.assertIs(self.one(copy.deepcopy(model))["select_privilege"]["allowed"], False)
        model["table"]["select_grantees"] = [{"kind": "public"}]
        self.assertIs(self.one(model)["select_privilege"]["allowed"], True)

    def test_nonselect_policy_does_not_supply_permissive_select(self) -> None:
        model = component_fixture()
        item = policy("update", True)
        item["command"] = "UPDATE"
        model["table"]["policies"] = [item]
        self.assertIs(self.one(model)["rls"]["row_passes"], False)

    def test_incomplete_coverage_and_late_unsupported_withhold_all_queries(self) -> None:
        for location, key in (
            ("root", "role_membership_complete"),
            ("table", "select_grants_complete"),
            ("table", "policy_inventory_complete"),
        ):
            model = component_fixture()
            (model if location == "root" else model["table"])[key] = False
            with self.subTest(key=key):
                self.assertEqual(
                    {r["outcome"] for r in self.analyze(model)["query_results"]}, {"unassessed"}
                )
        model = component_fixture()
        item = policy("unused", True)
        item.update(command="UPDATE", using={"op": "unsupported", "feature": "function"})
        model["table"]["policies"].append(item)
        self.assertEqual(
            {r["outcome"] for r in self.analyze(model)["query_results"]}, {"unassessed"}
        )

    def test_membership_cycles_self_edges_duplicates_and_missing_roles_reject(self) -> None:
        cases = [
            {"member_role": "reader", "granted_role": "alice", "inherit": False},
            {"member_role": "alice", "granted_role": "alice", "inherit": True},
            {"member_role": "alice", "granted_role": "reader", "inherit": False},
            {"member_role": "unknown", "granted_role": "reader", "inherit": True},
        ]
        for edge in cases:
            model = component_fixture()
            model["memberships"].append(edge)
            with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                self.analyze(model)

    def test_rows_are_exact_and_missing_is_not_null(self) -> None:
        model = component_fixture()
        model["rows"][0]["values"].pop("active")
        with self.assertRaisesRegex(m.PostgreSQLRlsAnalysisError, "unavailable"):
            self.analyze(model)

    def test_duplicate_and_unresolved_record_identities_reject(self) -> None:
        for key in ("roles", "contexts", "rows", "queries"):
            model = component_fixture()
            model[key].append(copy.deepcopy(model[key][0]))
            with self.subTest(key=key), self.assertRaises(m.PostgreSQLRlsAnalysisError):
                self.analyze(model)
        model = component_fixture()
        model["queries"][0]["row_id"] = "missing"
        with self.assertRaises(m.PostgreSQLRlsAnalysisError):
            self.analyze(model)

    def test_native_boolean_integer_aliases_and_subclasses_reject_before_hash(self) -> None:
        class Text(str):
            pass

        class Integer(int):
            pass

        class Object(dict):
            pass

        for transform in (
            lambda d: d.update(schema_version=True),
            lambda d: d.update(schema_version=1.0),
            lambda d: d["roles"][0].update(superuser=1),
            lambda d: d["memberships"][0].update(inherit=0),
            lambda d: d["rows"][0]["values"].update(level=True),
            lambda d: d["rows"][0]["values"].update(level=Integer(1)),
            lambda d: d["roles"][0].update(name=Text("alice")),
            lambda d: d.update(table=Object(d["table"])),
        ):
            model = component_fixture()
            transform(model)
            with patch.object(m.hashlib, "sha256") as digest:
                with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                    self.analyze(model)
                digest.assert_not_called()

    def test_closed_ast_and_native_unsupported_shapes_reject(self) -> None:
        for ast in (
            {"op": []},
            {"op": "bool", "value": 0},
            {"op": "unsupported", "feature": {}},
            {"op": "call", "arg": "never"},
            {"op": "and", "args": []},
            {
                "op": "eq",
                "left": {"kind": "column", "name": "missing"},
                "right": {"kind": "current_user"},
            },
        ):
            model = component_fixture()
            model["table"]["policies"][0]["using"] = ast
            with self.subTest(ast=ast), self.assertRaises(m.PostgreSQLRlsAnalysisError):
                self.analyze(model)

    def test_rehashed_false_results_contexts_sources_and_flags_do_not_replay(self) -> None:
        original = self.analyze()
        for change in (
            lambda d: d["query_results"][0].update(
                outcome="row_filtered_in_supplied_select_rls_model"
            ),
            lambda d: d["query_results"][0]["select_privilege"].update(allowed=False),
            lambda d: d["query_results"][0]["rls"].update(mode="disabled"),
            lambda d: d["context_results"][0].update(own_superuser=True),
            lambda d: d["context_results"][0].update(effective_roles=["alice"]),
            lambda d: d.update(positive_use_approved=True),
            lambda d: d.update(work_units=False),
            lambda d: d["bounds"].update(max_roles=65),
            lambda d: d.update(source_model_sha256="sha256:" + "a" * 64),
        ):
            document = copy.deepcopy(original)
            change(document)
            with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                m.SuppliedPostgreSQLRlsAnalysis.from_dict(address_report(document))

    def test_coherent_foreign_model_cannot_replace_separately_original_source(self) -> None:
        original = component_fixture()
        changed = copy.deepcopy(original)
        changed["table"]["rls_enabled"] = False
        report = m.analyze_supplied_postgresql_rls(changed)
        self.assertEqual(
            report.to_json(), m.SuppliedPostgreSQLRlsAnalysis.from_json(report.to_json()).to_json()
        )
        with self.assertRaises(m.PostgreSQLRlsAnalysisError):
            m.verify_supplied_postgresql_rls_analysis(report, model=original)

    def test_detached_original_output_and_metadata_arrays(self) -> None:
        original = component_fixture()
        report = m.analyze_supplied_postgresql_rls(original)
        saved = report.to_json()
        original["roles"].clear()
        detached = report.to_dict()
        detached["source_model"]["memberships"].clear()
        detached["context_results"][0]["effective_roles"].clear()
        self.assertEqual(report.to_json(), saved)

    def test_source_array_order_and_native_key_order_binding(self) -> None:
        original = component_fixture()
        reverse = copy.deepcopy(original)
        reverse["roles"].reverse()
        self.assertNotEqual(
            self.analyze(original)["source_model_sha256"],
            self.analyze(reverse)["source_model_sha256"],
        )
        reordered = {key: original[key] for key in reversed(original)}
        self.assertEqual(self.analyze(original), self.analyze(reordered))

    def test_public_wrapper_subclass_incomplete_and_noncanonical_reject(self) -> None:
        class Foreign(m.SuppliedPostgreSQLRlsAnalysis):
            pass

        report = m.analyze_supplied_postgresql_rls(component_fixture())
        for invalid in (
            object.__new__(m.SuppliedPostgreSQLRlsAnalysis),
            object.__new__(Foreign),
            object(),
        ):
            with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                m.verify_supplied_postgresql_rls_analysis(invalid, model=component_fixture())
        with self.assertRaises(m.PostgreSQLRlsAnalysisError):
            m.SuppliedPostgreSQLRlsAnalysis(" " + report.to_json())

    def test_raw_duplicate_float_nonfinite_and_integer_grammar_predecoder(self) -> None:
        for token in (
            "--1",
            "---1",
            "01",
            "-01",
            "+1",
            "1.0",
            "1e1",
            "NaN",
            "Infinity",
            "9223372036854775808",
            "-9223372036854775809",
            "1" * 1000,
        ):
            content = ('{"schema_version":' + token + "}").encode()
            with patch.object(m.json, "loads") as decoder:
                with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                    m.parse_supplied_postgresql_rls_model(content)
                decoder.assert_not_called()
        with self.assertRaises(m.PostgreSQLRlsAnalysisError):
            m.parse_supplied_postgresql_rls_model(b'{"schema_version":1,"schema_version":1}')

    def test_raw_bytes_depth_nodes_and_string_limits_predecode(self) -> None:
        cases = [
            b" " * (m.MAX_DOCUMENT_BYTES + 1),
            b"[" * m.MAX_NATIVE_DEPTH + b"0" + b"]" * m.MAX_NATIVE_DEPTH,
            b'"' + b"a" * (m.MAX_STRING_BYTES + 1) + b'"',
            b'"\\u0000"',
            b'"\\u00a0"',
            b"[" + b"0," * m.MAX_NATIVE_NODES + b"0]",
        ]
        for raw in cases:
            with patch.object(m.json, "loads") as decoder:
                with self.subTest(size=len(raw)), self.assertRaises(m.PostgreSQLRlsAnalysisError):
                    m.SuppliedPostgreSQLRlsAnalysis.from_bytes(raw)
                decoder.assert_not_called()

    def test_native_cost_cycles_repeated_escapes_and_huge_int_pre_serialization(self) -> None:
        cyclic = []
        cyclic.append(cyclic)
        for raw in (
            {"cycle": cyclic},
            {"value": 10**1000},
            {"value": ["\\" * 512] * 1100},
            {"value": [0] * m.MAX_NATIVE_NODES},
        ):
            with (
                patch.object(m.json, "dumps") as serializer,
                patch.object(m.hashlib, "sha256") as digest,
            ):
                with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                    m.analyze_supplied_postgresql_rls(raw)
                serializer.assert_not_called()
                digest.assert_not_called()

    def test_graph_closures_and_predicates_are_cached_per_reconstruction(self) -> None:
        model = component_fixture()
        model["queries"] = [
            {"query_id": "q:" + str(i), "context_id": "context:alice", "row_id": "own"}
            for i in range(40)
        ]
        model["contexts"].append(
            {"context_id": "second", "current_role": "alice", "row_security_on": True}
        )
        with (
            patch.object(m, "_build", wraps=m._build) as build,
            patch.object(m, "_closure", wraps=m._closure) as closure,
            patch.object(m, "_compile_predicate", wraps=m._compile_predicate) as compile_node,
        ):
            result = self.analyze(model)
            self.assertGreater(build.call_count, 0)
            self.assertEqual(closure.call_count, build.call_count)
            self.assertEqual(compile_node.call_count, 2 * build.call_count)
            self.assertEqual(len(result["query_results"]), 40)

    def test_exact_retained_output_node_and_byte_limits_before_hash(self) -> None:
        original = component_fixture()
        report = m.analyze_supplied_postgresql_rls(original)
        document = report.to_dict()

        def nodes(value: object) -> int:
            if type(value) is dict:
                return 1 + sum(1 + nodes(child) for child in value.values())
            if type(value) is list:
                return 1 + sum(nodes(child) for child in value)
            return 1

        for name, ceiling in (
            ("MAX_DOCUMENT_BYTES", len(report.to_json())),
            ("MAX_NATIVE_NODES", nodes(document)),
        ):
            with self.subTest(limit=name), patch.object(m, name, ceiling):
                self.assertEqual(
                    m.analyze_supplied_postgresql_rls(original).to_json(), report.to_json()
                )
            with (
                self.subTest(limit=name, exceeded=True),
                patch.object(m, name, ceiling - 1),
                patch.object(m.hashlib, "sha256") as digest,
                self.assertRaises(m.PostgreSQLRlsAnalysisError),
            ):
                m.analyze_supplied_postgresql_rls(original)
            digest.assert_not_called()

    def test_work_and_ast_limits_reject_before_addressing(self) -> None:
        for limit in (1, 10):
            with patch.object(m, "MAX_WORK", limit), patch.object(m.hashlib, "sha256") as digest:
                with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                    self.analyze()
                digest.assert_not_called()
        model = component_fixture()
        ast = boolean(True)
        for _ in range(m.MAX_AST_DEPTH):
            ast = {"op": "not", "arg": ast}
        model["table"]["policies"][0]["using"] = ast
        with self.assertRaises(m.PostgreSQLRlsAnalysisError):
            self.analyze(model)
        with patch.object(m, "MAX_AST_NODES", 2), patch.object(m.hashlib, "sha256") as digest:
            with self.assertRaises(m.PostgreSQLRlsAnalysisError):
                self.analyze()
            digest.assert_not_called()

    def test_collection_ceilings_and_empty_evidence(self) -> None:
        for key, ceiling in (
            ("roles", m.MAX_ROLES),
            ("memberships", m.MAX_MEMBERSHIPS),
            ("contexts", m.MAX_CONTEXTS),
            ("rows", m.MAX_ROWS),
            ("queries", m.MAX_QUERIES),
        ):
            model = component_fixture()
            model[key] = [model[key][0]] * (ceiling + 1)
            with self.subTest(key=key), self.assertRaises(m.PostgreSQLRlsAnalysisError):
                self.analyze(model)
        model = component_fixture()
        model.update(contexts=[], rows=[], queries=[])
        self.assertEqual(self.analyze(model)["query_results"], [])

    def test_effects_remain_none_and_no_privilege_proof(self) -> None:
        report = self.analyze()
        self.assertEqual(set(report["effects"].values()), {"none"})
        for flag in m._FLAGS:
            self.assertIs(report[flag], False)


if __name__ == "__main__":
    unittest.main()

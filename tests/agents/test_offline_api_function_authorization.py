"""Supplied function-matrix contradictions, uncertainty and replay controls."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_api_function_authorization as auth

ERROR = auth.ApiFunctionAuthorizationAnalysisError


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def fixture():
    return auth.component_fixture()


def one_case():
    source = fixture()
    source["subjects"] = source["subjects"][:1]
    source["invocations"] = source["invocations"][:1]
    return source


def observe(source):
    return auth.analyze_supplied_api_function_authorization(source).to_dict()[
        "invocation_observations"
    ][0]


def readdress(document):
    body = copy.deepcopy(document)
    body.pop("analysis_id", None)
    body.pop("analysis_sha256", None)
    digest = hashlib.sha256(
        b"sunderkey.offline-api-function-authorization.v1\n" + canonical(body).encode("ascii")
    ).hexdigest()
    return {
        **body,
        "analysis_id": "AFA-" + digest[:32].upper(),
        "analysis_sha256": "sha256:" + digest,
    }


class ApiFunctionAuthorizationTests(unittest.TestCase):
    def deny_before_hash(self, source):
        with patch.object(auth, "_address") as address:
            with self.assertRaises(ERROR):
                auth.analyze_supplied_api_function_authorization(source)
            address.assert_not_called()

    def test_fixture_exact_addresses_outcomes_and_boundary(self):
        document = auth.analyze_supplied_api_function_authorization(fixture()).to_dict()
        self.assertEqual(document["analysis_id"], "AFA-8AD3A57BA37D4022ECB7EAFA29790DE5")
        self.assertEqual(
            document["analysis_sha256"],
            "sha256:8ad3a57ba37d4022ecb7eafa29790de5d19fb6aab8d2e7e03711bfadc6ea0bcc",
        )
        self.assertEqual(
            document["source_model_sha256"],
            "sha256:7353350965a280510eecf90db93ec41138f027618babe61cb165043963d122f2",
        )
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S10")
        self.assertEqual(document["blueprint_sha256"], auth.BLUEPRINT_SHA256)
        self.assertEqual(
            (
                document["invocation_count"],
                document["candidate_contradiction_count"],
                document["unknown_count"],
            ),
            (3, 1, 1),
        )
        rows = document["invocation_observations"]
        self.assertEqual(
            [row["outcome"] for row in rows],
            ["candidate_contradiction", "matches_declared_policy", "unknown"],
        )
        self.assertEqual(rows[0]["contradiction_direction"], "declared_deny_supplied_allowed")
        self.assertEqual(
            rows[2]["uncertainty"],
            [
                "invocation_observation_incomplete",
                "invocation_outcome_unknown",
            ],
        )
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertTrue(all(value is False for value in document["flags"].values()))
        self.assertNotIn("url", document["source_model"])

    def test_all_two_by_two_permission_and_outcome_comparisons(self):
        for permission in ("allow", "deny"):
            for observed in ("allowed", "denied"):
                source = one_case()
                source["functions"][0]["role_permissions"]["reader"] = permission
                source["invocations"][0]["outcome"] = observed
                row = observe(source)
                contradiction = (permission == "allow") != (observed == "allowed")
                self.assertEqual(
                    row["outcome"],
                    "candidate_contradiction" if contradiction else "matches_declared_policy",
                )
                self.assertEqual(row["expected_permission"], permission)
                self.assertEqual(row["uncertainty"], [])
                self.assertEqual(
                    row["contradiction_direction"],
                    (
                        "declared_allow_supplied_denied"
                        if permission == "allow"
                        else "declared_deny_supplied_allowed"
                    )
                    if contradiction
                    else None,
                )

    def test_multiple_roles_any_allow_and_all_deny(self):
        source = one_case()
        source["subjects"][0]["role_ids"] = ["reader", "writer"]
        row = observe(source)
        self.assertEqual(row["expected_permission"], "allow")
        self.assertEqual(row["outcome"], "matches_declared_policy")
        source["functions"][0]["role_permissions"]["writer"] = "deny"
        row = observe(source)
        self.assertEqual(row["expected_permission"], "deny")
        self.assertEqual(row["outcome"], "candidate_contradiction")
        self.assertEqual(row["declared_role_permissions"], {"reader": "deny", "writer": "deny"})

    def test_complete_no_role_subject_has_declared_denial(self):
        for observed, expected_outcome in (
            ("allowed", "candidate_contradiction"),
            ("denied", "matches_declared_policy"),
        ):
            source = one_case()
            source["subjects"][0]["role_ids"] = []
            source["invocations"][0]["outcome"] = observed
            row = observe(source)
            self.assertEqual(row["held_role_ids"], [])
            self.assertEqual(row["declared_role_permissions"], {})
            self.assertEqual(row["expected_permission"], "deny")
            self.assertEqual(row["outcome"], expected_outcome)
            self.assertEqual(row["uncertainty"], [])
        source = one_case()
        source["subjects"][0]["role_ids"] = []
        source["subjects"][0]["roles_complete"] = False
        row = observe(source)
        self.assertIsNone(row["expected_permission"])
        self.assertEqual(row["outcome"], "unknown")
        self.assertIn("subject_roles_incomplete", row["uncertainty"])

    def test_each_missing_premise_makes_invocation_unknown(self):
        changes = (
            ("subject_roles_incomplete", lambda x: x["subjects"][0].update(roles_complete=False)),
            (
                "function_matrix_incomplete",
                lambda x: x["functions"][0].update(matrix_complete=False),
            ),
            (
                "held_role_permission_unknown",
                lambda x: x["functions"][0]["role_permissions"].update(reader="unknown"),
            ),
            (
                "invocation_observation_incomplete",
                lambda x: x["invocations"][0].update(observation_complete=False),
            ),
            ("invocation_outcome_unknown", lambda x: x["invocations"][0].update(outcome="unknown")),
        )
        for reason, change in changes:
            source = one_case()
            change(source)
            row = observe(source)
            self.assertEqual(row["outcome"], "unknown", reason)
            self.assertIsNone(row["expected_permission"])
            self.assertIsNone(row["contradiction_direction"])
            self.assertIn(reason, row["uncertainty"])
        source = one_case()
        source["functions"][0]["matrix_complete"] = False
        del source["functions"][0]["role_permissions"]["reader"]
        self.assertIn("held_role_rule_missing", observe(source)["uncertainty"])

    def test_complete_matrix_must_enumerate_all_roles(self):
        source = one_case()
        del source["functions"][0]["role_permissions"]["writer"]
        self.deny_before_hash(source)
        source["functions"][0]["matrix_complete"] = False
        self.assertEqual(observe(source)["outcome"], "unknown")

    def test_roundtrip_detachment_and_separate_originals(self):
        source = fixture()
        original = copy.deepcopy(source)
        report = auth.analyze_supplied_api_function_authorization(source)
        expected = report.to_json()
        for rebuilt in (
            auth.ApiFunctionAuthorizationAnalysis.from_dict(report.to_dict()),
            auth.ApiFunctionAuthorizationAnalysis.from_json(expected),
            auth.analyze_supplied_api_function_authorization_bytes(
                model_bytes=canonical(source).encode("ascii")
            ),
            auth.verify_supplied_api_function_authorization_analysis(report, model=source),
        ):
            self.assertEqual(rebuilt.to_json(), expected)
        self.assertEqual(report.analysis_id, report.to_dict()["analysis_id"])
        self.assertEqual(report.analysis_sha256, report.to_dict()["analysis_sha256"])
        source["invocations"][0]["outcome"] = "denied"
        exported = report.to_dict()
        exported["invocation_observations"].clear()
        self.assertEqual(report.to_json(), expected)
        with self.assertRaises(ERROR):
            auth.verify_supplied_api_function_authorization_analysis(report, model=source)
        self.assertEqual(
            auth.verify_supplied_api_function_authorization_analysis(
                report, model=original
            ).to_json(),
            expected,
        )

    def test_closed_shapes_ids_aliases_and_references(self):
        source = one_case()
        for version in (True, 1.0, "1", None, 0, 2):
            self.deny_before_hash({**source, "schema_version": version})
        self.deny_before_hash({**source, "extra": None})
        for field in source["subjects"][0]:
            changed = copy.deepcopy(source)
            changed["subjects"][0].pop(field)
            self.deny_before_hash(changed)
        for field in source["functions"][0]:
            changed = copy.deepcopy(source)
            changed["functions"][0].pop(field)
            self.deny_before_hash(changed)
        for field in source["invocations"][0]:
            changed = copy.deepcopy(source)
            changed["invocations"][0].pop(field)
            self.deny_before_hash(changed)
        for field, value in (
            ("subject_id", "missing"),
            ("function_id", "missing"),
            ("outcome", "maybe"),
            ("outcome", True),
            ("observation_complete", 1),
        ):
            changed = copy.deepcopy(source)
            changed["invocations"][0][field] = value
            self.deny_before_hash(changed)
        for roles in (["missing"], ["reader", "reader"], ["writer", "reader"], ["x"] * 33):
            changed = copy.deepcopy(source)
            changed["subjects"][0]["role_ids"] = roles
            self.deny_before_hash(changed)
        for role in (True, 1, "", "bad space", "x" * 129):
            changed = copy.deepcopy(source)
            changed["roles"] = [role]
            self.deny_before_hash(changed)

        class Mapping(dict):
            def items(self):
                raise AssertionError("Subclass hook reached")

        self.deny_before_hash(Mapping(source))

    def test_duplicate_entities_policy_types_and_no_object_fields(self):
        source = one_case()
        source["subjects"].append(copy.deepcopy(source["subjects"][0]))
        self.deny_before_hash(source)
        source = one_case()
        source["functions"].append(copy.deepcopy(source["functions"][0]))
        self.deny_before_hash(source)
        source = one_case()
        source["invocations"].append(copy.deepcopy(source["invocations"][0]))
        self.deny_before_hash(source)
        for permission in (True, 1, None, "grant"):
            source = one_case()
            source["functions"][0]["role_permissions"]["reader"] = permission
            self.deny_before_hash(source)
        source = one_case()
        source["invocations"][0]["object_id"] = "record"
        self.deny_before_hash(source)
        source = one_case()
        source["invocations"][0]["url"] = "https://example.invalid"
        self.deny_before_hash(source)

    def test_max_invocations_preserve_order_and_one_more_denied(self):
        source = one_case()
        template = source["invocations"][0]
        source["invocations"] = [
            {**copy.deepcopy(template), "invocation_id": f"case-{i}"} for i in range(128)
        ]
        document = auth.analyze_supplied_api_function_authorization(source).to_dict()
        self.assertEqual(document["candidate_contradiction_count"], 128)
        self.assertEqual(
            [row["invocation_id"] for row in document["invocation_observations"]],
            [f"case-{i}" for i in range(128)],
        )
        source["invocations"].append({**copy.deepcopy(template), "invocation_id": "case-128"})
        self.deny_before_hash(source)

    def test_raw_duplicate_keys_lexical_bounds_and_bytes(self):
        source = canonical(fixture())
        for raw in (
            source.replace('"schema_version":1', '"schema_version":1,"schema_version":1'),
            source.replace('"outcome":"allowed"', '"outcome":"allowed","outcome":"denied"', 1),
            source.replace('"schema_version":1', '"schema_version":01'),
            source.replace('"schema_version":1', '"schema_version":1.0'),
            '"' + "x" * 257 + '"',
            '"' + "\\u0078" * 257 + '"',
            '"\\u00e4"',
            "[" * 16 + "0" + "]" * 16,
            "9" * 20000,
        ):
            with patch.object(auth, "_address") as address, self.assertRaises(ERROR):
                auth.analyze_supplied_api_function_authorization_bytes(
                    model_bytes=raw.encode("ascii")
                )
            address.assert_not_called()

        class Bytes(bytes):
            pass

        for content in (b"", b"\xff", "{}", bytearray(b"{}"), memoryview(b"{}"), Bytes(b"{}")):
            with self.assertRaises(ERROR):
                auth.analyze_supplied_api_function_authorization_bytes(model_bytes=content)
        expected = auth.analyze_supplied_api_function_authorization(fixture()).to_json()
        for raw in (
            json.dumps(fixture(), indent=2),
            source.replace("synthetic-deny", "\\u0073ynthetic-deny"),
        ):
            self.assertEqual(
                auth.analyze_supplied_api_function_authorization_bytes(
                    model_bytes=raw.encode("ascii")
                ).to_json(),
                expected,
            )

    def test_cycles_depth_work_and_shape_bounds(self):
        cycle = []
        cycle.append(cycle)
        nested = 0
        for _ in range(16):
            nested = [nested]
        for value in (cycle, nested, [None] * 32768, ["\\" * 256] * 2100):
            with patch.object(auth.json, "dumps") as serializer:
                self.deny_before_hash(value)
                serializer.assert_not_called()
        with patch.object(auth, "MAX_WORK", 1):
            self.deny_before_hash(fixture())
        source = one_case()
        source["roles"] = [f"role-{i}" for i in range(33)]
        self.deny_before_hash(source)
        source = one_case()
        source["subjects"] = [
            {**copy.deepcopy(source["subjects"][0]), "subject_id": f"s-{i}"} for i in range(33)
        ]
        self.deny_before_hash(source)
        source = one_case()
        source["functions"] = [
            {**copy.deepcopy(source["functions"][0]), "function_id": f"f-{i}"} for i in range(33)
        ]
        self.deny_before_hash(source)

    def test_cohashed_forgery_effect_promotion_and_wrapper_tamper(self):
        document = auth.analyze_supplied_api_function_authorization(fixture()).to_dict()
        for field, value in (
            ("expected_permission", "allow"),
            ("outcome", "verified_bypass"),
            ("contradiction_direction", None),
            ("uncertainty", ["none"]),
        ):
            changed = copy.deepcopy(document)
            changed["invocation_observations"][0][field] = value
            with self.assertRaises(ERROR):
                auth.ApiFunctionAuthorizationAnalysis.from_dict(readdress(changed))
        for section, field, value in (
            ("flags", "bypass_verified", True),
            ("effects", "network", "invoked"),
            ("bounds", "invocations", 129),
        ):
            changed = copy.deepcopy(document)
            changed[section][field] = value
            with self.assertRaises(ERROR):
                auth.ApiFunctionAuthorizationAnalysis.from_json(canonical(readdress(changed)))
        changed = copy.deepcopy(document)
        changed["source_model_sha256"] = "sha256:" + "a" * 64
        with self.assertRaises(ERROR):
            auth.ApiFunctionAuthorizationAnalysis.from_dict(readdress(changed))
        report = auth.analyze_supplied_api_function_authorization(fixture())
        object.__setattr__(report, "_document_json", canonical(readdress(changed)))
        with self.assertRaises(ERROR):
            report.to_dict()
        for foreign in ({}, None, "{}", object()):
            with self.assertRaises(ERROR):
                auth.verify_supplied_api_function_authorization_analysis(foreign, model=fixture())

    def test_no_file_network_process_or_credentials(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem access")),
            patch("socket.socket", side_effect=AssertionError("network access")),
            patch("subprocess.Popen", side_effect=AssertionError("process access")),
        ):
            report = auth.analyze_supplied_api_function_authorization(fixture())
            self.assertEqual(report.to_dict()["candidate_contradiction_count"], 1)


if __name__ == "__main__":
    unittest.main()

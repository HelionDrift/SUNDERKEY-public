"""Tests for bounded supplied JSON and form field-shape comparison."""

from __future__ import annotations

import copy
import json
import unittest
from unittest.mock import patch

from sunderkey import offline_content_type_differential as analysis


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class ContentTypeDifferentialTests(unittest.TestCase):
    def test_fixture_is_fresh_source_addressed_and_replayable(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_content_type_differential(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], "AOE-GB-D06-S12")
        self.assertEqual(document["capability_id"], "army.gb.d06.s12")
        self.assertEqual(document["vector_id"], "AV-GB-D06-S12-01")
        self.assertEqual(document["source"]["source_id"], "synthetic-pair")
        self.assertEqual(document["source"]["json_request"]["source_id"], "request-json")
        self.assertTrue(document["report_id"].startswith("CTD-"))
        self.assertTrue(document["report_sha256"].startswith("sha256:"))
        self.assertEqual(document["effects"]["network"], "none")
        self.assertFalse(document["target_behavior_verified"])
        self.assertEqual(
            analysis.ContentTypeDifferentialReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.ContentTypeDifferentialReport.from_dict(document).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_content_type_differential(report, model=model).to_json(),
            report.to_json(),
        )
        other = analysis.component_fixture()
        other["json_request"]["body"] = "{}"
        self.assertNotEqual(other, model)

    def test_deterministic_differences_are_field_shapes_only(self):
        report = analysis.analyze_supplied_content_type_differential(analysis.component_fixture())
        document = report.to_dict()
        self.assertEqual([row["field"] for row in document["differences"]], ["active", "roles"])
        self.assertEqual(
            document["differences"][0]["reasons"],
            ["representation_type", "form_wire_type_vs_declaration"],
        )
        self.assertEqual(
            document["differences"][1]["reasons"],
            ["representation_type", "form_repeated_key", "form_wire_type_vs_declaration"],
        )
        self.assertEqual(
            document["request_fields"]["json"]["roles"],
            {"type": "array", "element_types": ["string"]},
        )
        self.assertEqual(
            document["request_fields"]["form"]["roles"],
            {"type": "string", "occurrences": 2},
        )
        self.assertNotIn("reader", canonical(document["differences"]))
        self.assertNotIn("writer", canonical(document["differences"]))
        self.assertEqual(
            report.to_json(),
            analysis.analyze_supplied_content_type_differential(
                analysis.component_fixture()
            ).to_json(),
        )

    def test_equivalent_string_shapes_have_no_difference(self):
        model = analysis.component_fixture()
        model["json_request"]["body"] = '{"title":"hello"}'
        model["form_request"]["body"] = "title=hello"
        model["declared_schema"]["fields"] = [
            {"name": "title", "type": "string", "required": True},
            {"name": "optional", "type": "integer", "required": False},
        ]
        self.assertEqual(
            analysis.analyze_supplied_content_type_differential(model).to_dict()["differences"],
            [],
        )

    def test_response_comparison_is_optional_and_unclaimed(self):
        model = analysis.component_fixture()
        model["responses"] = {
            "json": {
                "source_id": "response-json",
                "content_type": "application/json",
                "body": '{"ok":true,"count":2}',
            },
            "form": {
                "source_id": "response-form",
                "content_type": "application/x-www-form-urlencoded",
                "body": "ok=true&extra=1",
            },
        }
        document = analysis.analyze_supplied_content_type_differential(model).to_dict()
        self.assertEqual(
            [row["field"] for row in document["differences"] if row["phase"] == "response"],
            ["count", "extra", "ok"],
        )
        self.assertEqual(document["response_fields"]["json"]["count"], {"type": "integer"})
        self.assertFalse(document["target_behavior_verified"])

    def test_literal_form_keys_and_percent_decoding_without_coercion(self):
        model = analysis.component_fixture()
        model["json_request"]["body"] = '{"a[b]":1}'
        model["form_request"]["body"] = "a%5Bb%5D=1&a%5Bb%5D=2"
        model["declared_schema"]["fields"] = [{"name": "a[b]", "type": "integer", "required": True}]
        document = analysis.analyze_supplied_content_type_differential(model).to_dict()
        self.assertEqual(
            document["request_fields"]["form"],
            {"a[b]": {"type": "string", "occurrences": 2}},
        )
        self.assertIn("form_repeated_key", document["differences"][0]["reasons"])

    def test_missing_required_and_undeclared_are_declared_differences(self):
        model = analysis.component_fixture()
        model["json_request"]["body"] = '{"extra":null}'
        model["form_request"]["body"] = ""
        rows = analysis.analyze_supplied_content_type_differential(model).to_dict()["differences"]
        self.assertEqual([row["field"] for row in rows], ["active", "extra", "roles"])
        self.assertIn("declared_required_absent", rows[0]["reasons"])
        self.assertIn("undeclared_field", rows[1]["reasons"])

    def test_duplicate_json_keys_rejected_at_any_depth(self):
        for body in ('{"x":1,"x":2}', '{"x":{"a":1,"a":2}}'):
            with self.subTest(body=body):
                model = analysis.component_fixture()
                model["json_request"]["body"] = body
                with self.assertRaises(analysis.ContentTypeDifferentialError):
                    analysis.analyze_supplied_content_type_differential(model)
        text = canonical(analysis.component_fixture()).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.analyze_supplied_content_type_differential_bytes(
                model_bytes=text.encode("ascii")
            )

    def test_malformed_and_oversized_sources_fail_closed(self):
        for form in ("x", "x=%", "x=%GG", "x=%FF", "=value", "x=1&", "x=1;z=2"):
            with self.subTest(form=form):
                model = analysis.component_fixture()
                model["form_request"]["body"] = form
                if form == "x=1;z=2":
                    document = analysis.analyze_supplied_content_type_differential(model).to_dict()
                    self.assertEqual(document["request_fields"]["form"]["x"]["occurrences"], 1)
                else:
                    with self.assertRaises(analysis.ContentTypeDifferentialError):
                        analysis.analyze_supplied_content_type_differential(model)
        model = analysis.component_fixture()
        model["form_request"]["body"] = "a=1&" * (analysis.MAX_FORM_PAIRS + 1)
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.analyze_supplied_content_type_differential(model)
        model = analysis.component_fixture()
        model["json_request"]["body"] = '{"x":' + "[" * 20 + "0" + "]" * 20 + "}"
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.analyze_supplied_content_type_differential(model)
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.analyze_supplied_content_type_differential_bytes(model_bytes=b"\xff")

    def test_schema_and_source_identity_fail_closed(self):
        cases = []
        bad = analysis.component_fixture()
        bad["json_request"]["content_type"] = "text/plain"
        cases.append(bad)
        bad = analysis.component_fixture()
        bad["form_request"]["source_id"] = bad["json_request"]["source_id"]
        cases.append(bad)
        bad = analysis.component_fixture()
        bad["declared_schema"]["fields"].append(copy.deepcopy(bad["declared_schema"]["fields"][0]))
        cases.append(bad)
        bad = analysis.component_fixture()
        bad["unknown"] = True
        cases.append(bad)
        bad = analysis.component_fixture()
        bad["schema_version"] = True
        cases.append(bad)
        for model in cases:
            with self.subTest(model=model):
                with self.assertRaises(analysis.ContentTypeDifferentialError):
                    analysis.analyze_supplied_content_type_differential(model)

    def test_report_tamper_and_source_mismatch_rejected(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_content_type_differential(model)
        changed = report.to_dict()
        changed["target_behavior_verified"] = True
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.ContentTypeDifferentialReport.from_dict(changed)
        changed = report.to_dict()
        changed["differences"] = []
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.ContentTypeDifferentialReport.from_json(canonical(changed))
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.ContentTypeDifferentialReport.from_json(" " + report.to_json())
        other = copy.deepcopy(model)
        other["form_request"]["body"] = "active=false&roles=reader"
        with self.assertRaises(analysis.ContentTypeDifferentialError):
            analysis.verify_supplied_content_type_differential(report, model=other)

    def test_no_network_process_or_credential_resolution(self):
        model = analysis.component_fixture()
        model["json_request"]["body"] = '{"token":"not-a-real-secret"}'
        model["form_request"]["body"] = "token=not-a-real-secret"
        model["declared_schema"]["fields"] = [{"name": "token", "type": "string", "required": True}]
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            report = analysis.analyze_supplied_content_type_differential(model)
            self.assertEqual(report.to_dict()["differences"], [])
            self.assertEqual(report.to_dict()["effects"]["credential_resolution"], "none")
            self.assertNotIn("not-a-real-secret", report.to_json())


if __name__ == "__main__":
    unittest.main()

"""Supplied serverless event declaration checks."""

from __future__ import annotations

import copy
import json
import unittest

from sunderkey.offline_serverless_event_declarations import (
    ServerlessEventDeclarationError,
    analyze_supplied_serverless_event_declarations,
    component_fixture,
    verify_supplied_serverless_event_declarations,
    verify_supplied_serverless_event_declarations_bytes,
)


class ServerlessEventDeclarationTests(unittest.TestCase):
    def test_matching_declarations_are_inert_and_replayable(self) -> None:
        model = component_fixture()
        report = analyze_supplied_serverless_event_declarations(model)
        body = report.to_dict()
        self.assertEqual(body["disposition"], "supplied_binding_consistent")
        self.assertEqual(body["candidate_count"], 0)
        self.assertTrue(body["event_source_rows"][0]["reciprocal_match"])
        self.assertFalse(body["provider_contacted"])
        self.assertFalse(body["function_invoked"])
        self.assertFalse(body["event_delivered"])
        self.assertFalse(body["authorization_verified"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_serverless_event_declarations(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            verify_supplied_serverless_event_declarations_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_complete_conflict_is_only_a_candidate_about_supplied_values(self) -> None:
        model = component_fixture()
        model["event_sources"][0]["target_function_id"] = "function-other"
        body = analyze_supplied_serverless_event_declarations(model).to_dict()
        self.assertEqual(body["disposition"], "candidate_supplied_binding_mismatch")
        self.assertEqual(body["candidate_count"], 2)
        self.assertEqual(
            {item["issue"] for item in body["mismatches"]},
            {"function_event_source_binding_mismatch", "event_target_binding_mismatch"},
        )
        self.assertFalse(body["finding_claimed"])

    def test_incomplete_and_empty_inventory_are_unknown(self) -> None:
        model = component_fixture()
        model["inventory_complete"] = False
        model["event_sources"][0]["target_function_id"] = "function-other"
        body = analyze_supplied_serverless_event_declarations(model).to_dict()
        self.assertEqual(body["disposition"], "unknown")
        self.assertEqual(body["candidate_count"], 0)
        self.assertEqual(body["mismatches"], [])
        self.assertIsNone(body["event_source_rows"][0]["reciprocal_match"])
        empty = component_fixture()
        empty["functions"] = []
        empty["event_sources"] = []
        self.assertEqual(
            analyze_supplied_serverless_event_declarations(empty).to_dict()["disposition"],
            "unknown",
        )

    def test_closed_subset_and_exact_native_types(self) -> None:
        cases = []
        for field, value in (("schema_version", True), ("inventory_complete", 1)):
            model = component_fixture()
            model[field] = value
            cases.append(model)
        model = component_fixture()
        model["functions"][0]["extra"] = "x"
        cases.append(model)
        model = component_fixture()
        model["functions"][0]["event_source_ids"] = ["source-a", "source-a"]
        cases.append(model)
        model = component_fixture()
        model["event_sources"].append(copy.deepcopy(model["event_sources"][0]))
        cases.append(model)
        model = component_fixture()
        model["event_sources"][0]["event_source_id"] = 1
        cases.append(model)
        model = component_fixture()
        model["functions"] *= 65
        cases.append(model)
        for model in cases:
            with self.subTest(model=model), self.assertRaises(ValueError):
                analyze_supplied_serverless_event_declarations(model)

    def test_original_replay_rejects_changed_source_and_forged_export(self) -> None:
        model = component_fixture()
        report = analyze_supplied_serverless_event_declarations(model)
        changed = copy.deepcopy(model)
        changed["event_sources"][0]["target_function_id"] = "other"
        with self.assertRaises(ServerlessEventDeclarationError):
            verify_supplied_serverless_event_declarations(report, model=changed)
        with self.assertRaises(ServerlessEventDeclarationError):
            verify_supplied_serverless_event_declarations(report.to_dict(), model=model)
        tampered = report.to_dict()
        tampered["candidate_count"] = 10
        with self.assertRaises(ServerlessEventDeclarationError):
            verify_supplied_serverless_event_declarations_bytes(
                json.dumps(tampered).encode("ascii"), model=model
            )
        duplicated = report.to_json().replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1', 1
        )
        with self.assertRaises(ValueError):
            verify_supplied_serverless_event_declarations_bytes(
                duplicated.encode("ascii"), model=model
            )


if __name__ == "__main__":
    unittest.main()

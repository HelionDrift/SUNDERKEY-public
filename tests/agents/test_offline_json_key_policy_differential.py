"""Local JSON key policies do not establish target parser behavior."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_json_key_policy_differential import (
    JsonKeyPolicyDifferential,
    JsonKeyPolicyDifferentialError,
    analyze_supplied_json_key_policies,
    verify_supplied_json_key_policies,
)

ROOT = Path(__file__).resolve().parents[2]


def model(text: str = '{"role":"viewer","role":"admin","enabled":true}') -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-flat-json-key-policies-v1",
        "source_id": "source.synthetic-1",
        "document_text": text,
    }


class JsonKeyPolicyDifferentialTests(unittest.TestCase):
    def test_checked_example_uses_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-json-key-policy-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S04")
        self.assertEqual(
            result["component"]["component_id"], "supplied_json_key_policy_differential"
        )
        self.assertEqual(
            result["analysis"]["field_interpretations"][1]["disposition"],
            "candidate_first_last_difference",
        )
        self.assertFalse(result["analysis"]["flags"]["target_parser_behavior_verified"])

    def test_first_last_interpretations_replay_without_a_target_claim(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_json_key_policies(source)
        self.assertEqual(source, original)
        document = report.to_dict()
        by_name = {row["field_name"]: row for row in document["field_interpretations"]}
        self.assertEqual(by_name["role"]["first_value"], "viewer")
        self.assertEqual(by_name["role"]["last_value"], "admin")
        self.assertEqual(by_name["role"]["occurrence_count"], 2)
        self.assertEqual(by_name["role"]["disposition"], "candidate_first_last_difference")
        self.assertEqual(by_name["enabled"]["disposition"], "single_occurrence")
        self.assertFalse(document["flags"]["target_parser_behavior_verified"])
        self.assertFalse(document["flags"]["parser_differential_exploitable"])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_json_key_policies(report, model=source).to_json(),
            report.to_json(),
        )

    def test_decoded_key_equivalence_and_scalar_type_are_explicit(self) -> None:
        source = model(r'{"a":1,"\u0061":2,"same":1,"same":1,"flag":true,"flag":1}')
        rows = analyze_supplied_json_key_policies(source).to_dict()["field_interpretations"]
        by_name = {row["field_name"]: row for row in rows}
        self.assertEqual(by_name["a"]["occurrence_count"], 2)
        self.assertEqual(by_name["a"]["disposition"], "candidate_first_last_difference")
        self.assertEqual(by_name["same"]["disposition"], "duplicate_same_endpoint_value")
        self.assertEqual(by_name["flag"]["disposition"], "candidate_first_last_difference")

    def test_unsupported_and_resource_bearing_sources_are_refused(self) -> None:
        for text in (
            '["not", "an", "object"]',
            '{"nested":{"x":1}}',
            '{"array":[1]}',
            '{"floating":1.25}',
            '{"nonfinite":NaN}',
            '{"large":9223372036854775808}',
            r'{"\ud800":1}',
            r'{"text":"\ud800"}',
            '{"broken":',
            '{}',
        ):
            with self.subTest(text=text):
                with self.assertRaises(JsonKeyPolicyDifferentialError):
                    analyze_supplied_json_key_policies(model(text))
        resource = model()
        resource["network_permission"] = True
        with self.assertRaises(JsonKeyPolicyDifferentialError):
            analyze_supplied_json_key_policies(resource)
        cyclic = model()
        cyclic["cycle"] = cyclic
        with self.assertRaises(JsonKeyPolicyDifferentialError):
            analyze_supplied_json_key_policies(cyclic)

    def test_tampered_report_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_json_key_policies(source)
        changed = report.to_dict()
        changed["field_interpretations"][1]["disposition"] = "single_occurrence"
        with self.assertRaises(JsonKeyPolicyDifferentialError):
            JsonKeyPolicyDifferential(changed)
        alternate = model('{"role":"viewer","role":"owner"}')
        with self.assertRaises(JsonKeyPolicyDifferentialError):
            verify_supplied_json_key_policies(report, model=alternate)
        with self.assertRaises(JsonKeyPolicyDifferentialError):
            verify_supplied_json_key_policies(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

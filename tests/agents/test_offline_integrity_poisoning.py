"""Supplied digest mismatch does not verify artifact poisoning."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_specialist_components as components
from sunderkey.offline_integrity_poisoning import (
    IntegrityPoisoning,
    IntegrityPoisoningError,
    analyze_supplied_integrity_poisoning,
    verify_supplied_integrity_poisoning,
)

ROOT = Path(__file__).resolve().parents[2]


def request() -> dict:
    return json.loads(
        (ROOT / "examples/offline-integrity-poisoning-component.json").read_text(
            encoding="utf-8"
        )
    )


class IntegrityPoisoningTests(unittest.TestCase):
    def test_catalog_dispatch_and_replay(self) -> None:
        source = request()
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            source, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S15")
        self.assertEqual(result["analysis"]["projections"][0]["disposition"],
                         "candidate_declared_untrusted_content_consumption")
        self.assertFalse(any(result["analysis"]["flags"].values()))
        model = source["payload"]["model"]
        report = analyze_supplied_integrity_poisoning(model)
        self.assertEqual(report.to_dict()["source_model"], model)
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_integrity_poisoning(report, model=model).to_json(),
            report.to_json(),
        )

    def test_policy_and_uncertainty(self) -> None:
        model = request()["payload"]["model"]
        model["artifacts"][0]["origin_trust"] = "trusted"
        row = analyze_supplied_integrity_poisoning(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "candidate_declared_integrity_policy_conflict")
        model["artifacts"][0]["declared_consumption"] = "deny"
        row = analyze_supplied_integrity_poisoning(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "declared_integrity_rejection_consistent")
        model["artifacts"][0]["origin_trust"] = "unknown"
        row = analyze_supplied_integrity_poisoning(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "unresolved_origin_or_consumption")
        model["artifacts"][0]["origin_trust"] = "trusted"
        model["policy"]["require_digest_match"] = False
        row = analyze_supplied_integrity_poisoning(model).to_dict()["projections"][0]
        self.assertEqual(row["disposition"], "no_declared_integrity_conflict")

    def test_invalid_sources_and_tampered_replay(self) -> None:
        model = request()["payload"]["model"]
        cases = []
        item = copy.deepcopy(model)
        item["artifacts"][0]["presented_digest"] = "sha256:bad"
        cases.append(item)
        item = copy.deepcopy(model)
        item["artifacts"][0]["artifact_ref"] = "https://example.com"
        cases.append(item)
        item = copy.deepcopy(model)
        item["artifacts"][0]["origin_trust"] = "attacker"
        cases.append(item)
        item = copy.deepcopy(model)
        item["artifacts"].append(copy.deepcopy(item["artifacts"][0]))
        cases.append(item)
        item = copy.deepcopy(model)
        item["filesystem"] = True
        cases.append(item)
        for item in cases:
            with self.assertRaises(IntegrityPoisoningError):
                analyze_supplied_integrity_poisoning(item)
        report = analyze_supplied_integrity_poisoning(model)
        changed = report.to_dict()
        changed["flags"]["poisoning_verified"] = True
        with self.assertRaises(IntegrityPoisoningError):
            IntegrityPoisoning(changed)
        alternate = copy.deepcopy(model)
        alternate["artifacts"][0]["declared_consumption"] = "deny"
        with self.assertRaises(IntegrityPoisoningError):
            verify_supplied_integrity_poisoning(report, model=alternate)


if __name__ == "__main__":
    unittest.main()

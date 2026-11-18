"""Supplied technology labels never become live fingerprint findings."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_recon_evidence_core import ReconEvidenceError
from sunderkey.offline_technology_evidence import (
    analyze_supplied_technology_evidence,
    verify_supplied_technology_evidence,
)


def model() -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-technology-evidence-v1",
        "observations": [
            {
                "observation_id": "o1",
                "subject_ref": "subject:sha256:" + "a" * 64,
                "label": "fictional-stack",
                "kind": "response_header",
                "source_ref": "source:sha256:" + "b" * 64,
                "asserted_present": True,
            },
            {
                "observation_id": "o2",
                "subject_ref": "subject:sha256:" + "a" * 64,
                "label": "fictional-stack",
                "kind": "package_manifest",
                "source_ref": "source:sha256:" + "c" * 64,
                "asserted_present": True,
            },
        ],
    }


class TechnologyEvidenceTests(unittest.TestCase):
    def test_replay_and_conflict_are_only_supplied_assertions(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_technology_evidence(source)
        self.assertEqual(source, original)
        self.assertEqual(
            report.to_dict()["findings"][0]["disposition"], "multi_source_supplied_pattern"
        )
        self.assertFalse(report.to_dict()["flags"]["live_subject_state_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_technology_evidence(report, model=source).to_json(), report.to_json()
        )
        source["observations"].append(
            {
                **source["observations"][1],
                "observation_id": "o3",
                "source_ref": "source:sha256:" + "d" * 64,
                "asserted_present": False,
            }
        )
        self.assertEqual(
            analyze_supplied_technology_evidence(source).to_dict()["findings"][0]["disposition"],
            "conflicting_supplied_assertions",
        )
        with self.assertRaises(ReconEvidenceError):
            verify_supplied_technology_evidence(report, model=source)

    def test_invalid_refs_duplicate_signature_and_non_native_are_refused(self) -> None:
        source = model()
        source["observations"][0]["subject_ref"] = "real.example"
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_technology_evidence(source)
        source = model()
        source["observations"][1] = {**source["observations"][0], "observation_id": "o2"}
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_technology_evidence(source)
        source = model()
        source["observations"][0]["asserted_present"] = 1
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_technology_evidence(source)
        source = model()
        source["observations"][0]["label"] = object()
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_technology_evidence(source)

    def test_bounded_input_and_tamper_are_refused(self) -> None:
        source = model()
        source["observations"] = [
            {
                **source["observations"][0],
                "observation_id": f"o{index}",
                "source_ref": f"source:sha256:{index:064x}",
            }
            for index in range(256)
        ]
        report = analyze_supplied_technology_evidence(source)
        self.assertLessEqual(len(report.to_json()), 524_288)
        source["observations"].append({**source["observations"][0], "observation_id": "overflow"})
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_technology_evidence(source)
        report_body = report.to_dict()
        report_body["flags"]["live_subject_state_proven"] = True
        from sunderkey.offline_recon_evidence_core import ReconEvidenceReport
        from sunderkey.offline_technology_evidence import SPEC

        with self.assertRaises(ReconEvidenceError):
            ReconEvidenceReport(report_body, spec=SPEC)


if __name__ == "__main__":
    unittest.main()

"""Supplied deception cues remain non-dispositive review inputs."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_deception_evidence import (
    analyze_supplied_deception_cues,
    verify_supplied_deception_cues,
)
from sunderkey.offline_recon_evidence_core import ReconEvidenceError


def model() -> dict:
    subject = "subject:sha256:" + "a" * 64
    return {
        "schema_version": 1,
        "semantics_profile": "supplied-deception-cues-v1",
        "observations": [
            {
                "observation_id": "cue1",
                "subject_ref": subject,
                "label": "fictional-cue",
                "kind": "synthetic_marker",
                "source_ref": "source:sha256:" + "b" * 64,
                "asserted_present": True,
            },
            {
                "observation_id": "cue2",
                "subject_ref": subject,
                "label": "fictional-cue",
                "kind": "service_identity_conflict",
                "source_ref": "source:sha256:" + "c" * 64,
                "asserted_present": True,
            },
        ],
    }


class DeceptionEvidenceTests(unittest.TestCase):
    def test_cues_are_replayable_but_not_honeypot_proof(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        report = analyze_supplied_deception_cues(source)
        self.assertEqual(source, original)
        self.assertEqual(
            report.to_dict()["findings"][0]["disposition"], "multi_source_supplied_pattern"
        )
        self.assertFalse(report.to_dict()["flags"]["vulnerability_or_deception_proven"])
        self.assertEqual(set(report.to_dict()["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_deception_cues(report, model=source).to_json(), report.to_json()
        )

    def test_conflicting_and_all_negative_assertions(self) -> None:
        source = model()
        source["observations"][1]["asserted_present"] = False
        self.assertEqual(
            analyze_supplied_deception_cues(source).to_dict()["findings"][0]["disposition"],
            "conflicting_supplied_assertions",
        )
        source["observations"][0]["asserted_present"] = False
        self.assertEqual(
            analyze_supplied_deception_cues(source).to_dict()["findings"][0]["disposition"],
            "no_positive_supplied_assertion",
        )

    def test_invalid_kind_semantics_and_modified_replay_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_deception_cues(source)
        source["observations"][0]["kind"] = "live_probe"
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_deception_cues(source)
        source = model()
        source["semantics_profile"] = "supplied-technology-evidence-v1"
        with self.assertRaises(ReconEvidenceError):
            analyze_supplied_deception_cues(source)
        source = model()
        source["observations"][1]["asserted_present"] = False
        with self.assertRaises(ReconEvidenceError):
            verify_supplied_deception_cues(report, model=source)


if __name__ == "__main__":
    unittest.main()

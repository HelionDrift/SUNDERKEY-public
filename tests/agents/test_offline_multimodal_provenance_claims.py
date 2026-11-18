"""Synthetic multimodal provenance-claim boundary tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_multimodal_provenance_claims import (
    MultimodalProvenanceError,
    MultimodalProvenanceReport,
    analyze_supplied_multimodal_provenance,
    component_fixture,
    verify_supplied_multimodal_provenance,
)


class MultimodalProvenanceTests(unittest.TestCase):
    def test_flag_is_not_deepfake_detection(self) -> None:
        body = analyze_supplied_multimodal_provenance(component_fixture()).to_dict()
        self.assertEqual(body["flagged_asset_refs"], ["asset-opaque-a"])
        self.assertFalse(body["media_bytes_processed"])
        self.assertFalse(body["signature_verified"])
        self.assertFalse(body["deepfake_detected"])
        self.assertEqual(body["candidate_count"], 0)

    def test_unknown_source_remains_unknown(self) -> None:
        model = component_fixture()
        model["media_claims"][0]["source_ref"] = "source-opaque-b"
        body = analyze_supplied_multimodal_provenance(model).to_dict()
        self.assertEqual(body["unknown_source_asset_refs"], ["asset-opaque-a"])
        self.assertEqual(body["disposition"], "unknown")

    def test_rejects_duplicate_and_nonsynthetic(self) -> None:
        model = component_fixture()
        model["media_claims"].append(copy.deepcopy(model["media_claims"][0]))
        with self.assertRaises(MultimodalProvenanceError):
            analyze_supplied_multimodal_provenance(model)
        model = component_fixture()
        model["synthetic_fixture"] = False
        with self.assertRaises(MultimodalProvenanceError):
            analyze_supplied_multimodal_provenance(model)

    def test_replay_and_owned_wrapper(self) -> None:
        model = component_fixture()
        report = analyze_supplied_multimodal_provenance(model)
        self.assertEqual(
            verify_supplied_multimodal_provenance(
                report, model=copy.deepcopy(model)
            ).to_json(), report.to_json(),
        )
        changed = copy.deepcopy(model)
        changed["media_claims"][0]["transformation_disclosed"] = True
        with self.assertRaises(MultimodalProvenanceError):
            verify_supplied_multimodal_provenance(report, model=changed)
        with self.assertRaises(MultimodalProvenanceError):
            MultimodalProvenanceReport(report.to_dict())


if __name__ == "__main__":
    unittest.main()

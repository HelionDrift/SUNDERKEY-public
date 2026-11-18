"""Supplied model-artifact bytes retain digest and origin boundaries."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path

from sunderkey import offline_model_artifact_integrity as analysis

ROOT = Path(__file__).resolve().parents[2]


class ModelArtifactIntegrityTests(unittest.TestCase):
    def test_fixture_distinguishes_equality_mismatch_origin_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_model_artifact_integrity(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 2)
        self.assertEqual(value["unknown_count"], 1)
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["release_manifest_authenticated"])
        self.assertFalse(value["signature_verified"])
        self.assertFalse(value["provider_fetch_performed"])
        self.assertNotIn("source_model", value)
        self.assertNotIn("blob_base64", report.to_json())
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertEqual(
            [row["disposition"] for row in value["artifact_projections"]],
            [
                "declared_matching_digest_unverified",
                "candidate_declared_digest_mismatch",
                "candidate_declared_unapproved_origin",
                "unknown_expected_digest",
            ],
        )
        self.assertEqual(
            value["artifact_projections"][0]["artifact_sha256"],
            model["artifacts"][0]["expected_sha256"],
        )
        self.assertEqual(
            analysis.verify_supplied_model_artifact_integrity(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_model_artifact_integrity_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_declared_origin_unknown_never_becomes_positive(self) -> None:
        model = analysis.component_fixture()
        model["artifacts"] = [copy.deepcopy(model["artifacts"][0])]
        model["artifacts"][0]["declared_origin"] = "unknown"
        value = analysis.analyze_supplied_model_artifact_integrity(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 1)
        self.assertEqual(value["artifact_projections"][0]["disposition"], "unknown_origin")
        self.assertFalse(value["positive_use_approved"])

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_model_artifact_integrity(model)
        changed = copy.deepcopy(model)
        changed["artifacts"][0]["declared_origin"] = "unknown"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_model_artifact_integrity(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_model_artifact_integrity_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_invalid_digest_bytes_and_duplicate_artifacts_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["artifacts"][0].update(expected_sha256="sha256:abc"),
            lambda m: m["artifacts"][0].update(blob_base64="%%"),
            lambda m: m["artifacts"][0].update(
                blob_base64=base64.b64encode(b"X" * 16_385).decode("ascii")
            ),
            lambda m: m["artifacts"].append(copy.deepcopy(m["artifacts"][0])),
            lambda m: m["artifacts"][0].update(declared_origin=True),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_model_artifact_integrity(invalid)

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-model-artifact-integrity-component.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(request["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(request["component_id"], analysis.COMPONENT_ID)
        self.assertEqual(request["action_tier"], "R0")
        self.assertTrue(request["dry_run"])
        self.assertEqual(request["credential_refs"], [])
        self.assertEqual(
            request["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(request["payload"]["model"], analysis.component_fixture())


if __name__ == "__main__":
    unittest.main()

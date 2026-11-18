"""Contracts for the supplied, inert extension/media gate comparison."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_web_content_handling as analysis


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class OfflineWebContentHandlingTests(unittest.TestCase):
    def test_fixture_projection_and_round_trip(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_web_content_handling(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(
            [(row["case_id"], row["disposition"]) for row in document["case_projections"]],
            [
                ("case-agree", "declared_gate_agreement_allow"),
                ("case-differential", "candidate_declared_gate_differential"),
                ("case-missing", "unknown_missing_gate_rule"),
            ],
        )
        difference = document["case_projections"][1]
        self.assertEqual(
            (difference["extension_gate"], difference["media_gate"]), ("allow", "deny")
        )
        self.assertFalse(difference["media_extension_mismatch"])
        self.assertEqual(
            document["source"]["evidence_source_ids"], ["synthetic-cases", "synthetic-policy"]
        )
        self.assertEqual(
            analysis.WebContentHandlingReport.from_json(report.to_json()).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.WebContentHandlingReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.verify_supplied_web_content_handling(report, model=model).to_json(),
            report.to_json(),
        )

    def test_checked_component_example(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "examples"
            / "offline-web-content-handling-component.json"
        )
        component = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(component["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(component["component_id"], "supplied_web_content_handling")
        self.assertEqual(component["action_tier"], "R0")
        self.assertTrue(component["dry_run"])
        self.assertEqual(component["credential_refs"], [])
        self.assertEqual(
            component["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(component["payload"]["model"], analysis.component_fixture())

    def test_declared_deny_agreement(self):
        model = analysis.component_fixture()
        model["cases"].append(
            {
                "case_id": "case-deny",
                "extension_token": "extension-b",
                "declared_media_token": "media-b",
                "source_id": "synthetic-cases",
            }
        )
        rows = analysis.analyze_supplied_web_content_handling(model).to_dict()["case_projections"]
        row = next(row for row in rows if row["case_id"] == "case-deny")
        self.assertEqual(row["disposition"], "declared_gate_agreement_deny")
        self.assertFalse(row["media_extension_mismatch"])

    def test_same_gate_decisions_with_media_mismatch_stay_unknown(self):
        model = analysis.component_fixture()
        model["extension_rules"][0]["expected_media_token"] = "media-expected"
        row = analysis.analyze_supplied_web_content_handling(model).to_dict()["case_projections"][0]
        self.assertEqual(row["disposition"], "unknown_media_extension_mismatch_policy")
        self.assertTrue(row["media_extension_mismatch"])

    def test_differential_in_both_directions(self):
        model = analysis.component_fixture()
        model["extension_rules"].append(
            {
                "extension_token": "extension-d",
                "expected_media_token": "media-a",
                "disposition": "deny",
                "source_id": "synthetic-policy",
            }
        )
        model["cases"].append(
            {
                "case_id": "case-reverse",
                "extension_token": "extension-d",
                "declared_media_token": "media-a",
                "source_id": "synthetic-cases",
            }
        )
        rows = analysis.analyze_supplied_web_content_handling(model).to_dict()["case_projections"]
        reverse = next(row for row in rows if row["case_id"] == "case-reverse")
        self.assertEqual(reverse["disposition"], "candidate_declared_gate_differential")
        self.assertEqual((reverse["extension_gate"], reverse["media_gate"]), ("deny", "allow"))
        self.assertFalse(reverse["media_extension_mismatch"])

    def test_differing_gates_with_media_mismatch_stay_unknown(self):
        model = analysis.component_fixture()
        model["cases"].append(
            {
                "case_id": "case-mismatched-difference",
                "extension_token": "extension-a",
                "declared_media_token": "media-b",
                "source_id": "synthetic-cases",
            }
        )
        rows = analysis.analyze_supplied_web_content_handling(model).to_dict()["case_projections"]
        row = next(row for row in rows if row["case_id"] == "case-mismatched-difference")
        self.assertEqual((row["extension_gate"], row["media_gate"]), ("allow", "deny"))
        self.assertTrue(row["media_extension_mismatch"])
        self.assertEqual(row["disposition"], "unknown_media_extension_mismatch_policy")

    def test_missing_extension_gate_is_unknown_not_differential(self):
        model = analysis.component_fixture()
        model["cases"].append(
            {
                "case_id": "case-no-extension",
                "extension_token": "extension-unknown",
                "declared_media_token": "media-a",
                "source_id": "synthetic-cases",
            }
        )
        rows = analysis.analyze_supplied_web_content_handling(model).to_dict()["case_projections"]
        row = next(row for row in rows if row["case_id"] == "case-no-extension")
        self.assertEqual(row["disposition"], "unknown_missing_gate_rule")
        self.assertIsNone(row["expected_media_token"])
        self.assertIsNone(row["media_extension_mismatch"])

    def test_order_independence_of_projections(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_web_content_handling(model).to_dict()
        model["evidence_sources"].reverse()
        model["extension_rules"].reverse()
        model["media_rules"].reverse()
        model["cases"].reverse()
        changed = analysis.analyze_supplied_web_content_handling(model).to_dict()
        self.assertEqual(changed["case_projections"], original["case_projections"])
        self.assertNotEqual(changed["source"]["model_sha256"], original["source"]["model_sha256"])

    def test_duplicate_json_keys_rejected(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.analyze_supplied_web_content_handling_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"disposition":"allow"', '"disposition":"allow","disposition":"deny"', 1
        )
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.analyze_supplied_web_content_handling_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_web_content_handling(model)
        text = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.WebContentHandlingReport.from_json(text)

    def test_duplicate_rules_cases_and_missing_provenance_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["evidence_sources"].append(copy.deepcopy(change["evidence_sources"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        duplicate = copy.deepcopy(change["extension_rules"][0])
        duplicate["disposition"] = "deny"
        change["extension_rules"].append(duplicate)
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["media_rules"].append(copy.deepcopy(change["media_rules"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["cases"].append(copy.deepcopy(change["cases"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["extension_rules"][0]["source_id"] = "unlisted-source"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["media_rules"][0]["source_id"] = "unlisted-source"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["cases"][0]["source_id"] = "unlisted-source"
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.WebContentHandlingError):
                    analysis.analyze_supplied_web_content_handling(change)

    def test_unsupported_schema_native_types_and_size_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["schema_version"] = True
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["cases"] = []
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["extension_rules"][0]["disposition"] = "maybe"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["cases"][0]["extension_token"] = "https://host.example/path"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["media_rules"][0]["extra"] = "unsupported"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["cases"] *= analysis.MAX_CASES
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["unknown"] = 1
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.WebContentHandlingError):
                    analysis.analyze_supplied_web_content_handling(change)
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.analyze_supplied_web_content_handling_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.analyze_supplied_web_content_handling_bytes(model_bytes=bytearray(b"{}"))

    def test_forged_report_even_with_recomputed_hash_is_rejected(self):
        report = analysis.analyze_supplied_web_content_handling(analysis.component_fixture())
        forged = report.to_dict()
        forged["case_projections"][0]["disposition"] = "candidate_declared_gate_differential"
        unsigned = {k: v for k, v in forged.items() if k not in {"report_id", "report_sha256"}}
        digest = hashlib.sha256(
            canonical({"domain": analysis.DOMAIN, "report": unsigned}).encode("ascii")
        ).hexdigest()
        forged["report_id"] = "WCH-" + digest[:32].upper()
        forged["report_sha256"] = "sha256:" + digest
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.WebContentHandlingReport.from_dict(forged)
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.WebContentHandlingReport(canonical(forged))

    def test_retained_model_replay_does_not_replace_original_source(self):
        original = analysis.component_fixture()
        changed = copy.deepcopy(original)
        changed["media_rules"][1]["disposition"] = "allow"
        changed_report = analysis.analyze_supplied_web_content_handling(changed)
        analysis.WebContentHandlingReport.from_json(changed_report.to_json())
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.verify_supplied_web_content_handling(changed_report, model=original)

    def test_wrapper_and_canonical_text_rejected(self):
        report = analysis.analyze_supplied_web_content_handling(analysis.component_fixture())
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.WebContentHandlingReport.from_json(" " + report.to_json())
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.WebContentHandlingReport("invalid-json")
        with self.assertRaises(analysis.WebContentHandlingError):
            analysis.verify_supplied_web_content_handling(
                report.to_dict(), model=analysis.component_fixture()
            )

    def test_no_filesystem_network_process_or_credential_effect(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem effect")),
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            document = analysis.analyze_supplied_web_content_handling(
                analysis.component_fixture()
            ).to_dict()
            self.assertTrue(all(value == "none" for value in document["effects"].values()))
            self.assertTrue(document["offline_only"])
            self.assertFalse(document["target_behavior_verified"])
            self.assertIsNone(document["live_vulnerability_verdict"])


if __name__ == "__main__":
    unittest.main()

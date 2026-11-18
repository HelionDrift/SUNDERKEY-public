"""Contracts for the inert supplied template-context projection."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_template_context as analysis


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def slot_rows(model: dict) -> dict[str, dict]:
    report = analysis.analyze_supplied_template_context(model)
    return {row["slot_id"]: row for row in report.to_dict()["slot_projections"]}


class OfflineTemplateContextTests(unittest.TestCase):
    def test_fixture_projection_and_round_trip(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_template_context(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        rows = {row["slot_id"]: row["disposition"] for row in document["slot_projections"]}
        self.assertEqual(
            rows,
            {
                "slot-attribute": "candidate_declared_escape_mismatch",
                "slot-script": "candidate_declared_unescaped_flow",
                "slot-title": "declared_matching_escape_unverified",
                "slot-trusted": "declared_trusted_origin_unverified",
                "slot-unbound": "unknown_unbound_slot",
            },
        )
        self.assertEqual(
            document["source"]["evidence_source_ids"], ["synthetic-bindings", "synthetic-template"]
        )
        self.assertEqual(
            analysis.TemplateContextReport.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.TemplateContextReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.verify_supplied_template_context(report, model=model).to_json(),
            report.to_json(),
        )

    def test_checked_component_example(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "examples"
            / "offline-template-context-component.json"
        )
        component = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(component["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(component["component_id"], "supplied_template_context")
        self.assertEqual(component["action_tier"], "R0")
        self.assertTrue(component["dry_run"])
        self.assertEqual(component["credential_refs"], [])
        self.assertEqual(
            component["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(component["payload"]["model"], analysis.component_fixture())

    def test_contextual_autoescape_declared_unverified_not_candidate(self):
        model = analysis.component_fixture()
        model["engine"]["autoescape"] = "contextual"
        rows = slot_rows(model)
        self.assertEqual(
            rows["slot-script"]["disposition"], "declared_engine_autoescape_unverified"
        )
        self.assertEqual(rows["slot-attribute"]["disposition"], "unknown_contextual_engine_effect")
        self.assertEqual(rows["slot-title"]["disposition"], "declared_matching_escape_unverified")

    def test_unknown_autoescape_does_not_infer_candidate(self):
        model = analysis.component_fixture()
        model["engine"]["autoescape"] = "unknown"
        rows = slot_rows(model)
        self.assertEqual(rows["slot-script"]["disposition"], "unknown_engine_escape")
        self.assertEqual(rows["slot-attribute"]["disposition"], "unknown_engine_escape")

    def test_opaque_escape_and_unknown_origin_are_unknown(self):
        model = analysis.component_fixture()
        model["bindings"][1]["explicit_escape"] = "opaque"
        model["bindings"][2]["origin"] = "unknown"
        rows = slot_rows(model)
        self.assertEqual(rows["slot-attribute"]["disposition"], "unknown_opaque_escape")
        self.assertEqual(rows["slot-script"]["disposition"], "unknown_origin")

    def test_explicit_matching_escape_stays_unverified_with_autoescape_off(self):
        model = analysis.component_fixture()
        model["bindings"][1]["explicit_escape"] = "html_attribute"
        row = slot_rows(model)["slot-attribute"]
        self.assertEqual(row["disposition"], "declared_matching_escape_unverified")
        self.assertEqual(row["origin"], "untrusted")

    def test_order_independent_projection_and_source_sensitive_hash(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_template_context(model).to_dict()
        model["evidence_sources"].reverse()
        model["slots"].reverse()
        model["bindings"].reverse()
        changed = analysis.analyze_supplied_template_context(model).to_dict()
        self.assertEqual(changed["slot_projections"], original["slot_projections"])
        self.assertNotEqual(changed["source"]["model_sha256"], original["source"]["model_sha256"])

    def test_duplicate_json_keys_rejected(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.TemplateContextError):
            analysis.analyze_supplied_template_context_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"origin":"untrusted"', '"origin":"untrusted","origin":"trusted"', 1
        )
        with self.assertRaises(analysis.TemplateContextError):
            analysis.analyze_supplied_template_context_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_template_context(model)
        text = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.TemplateContextError):
            analysis.TemplateContextReport.from_json(text)

    def test_duplicate_and_unbound_references_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["evidence_sources"].append(copy.deepcopy(change["evidence_sources"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"].append(copy.deepcopy(change["slots"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["bindings"].append(copy.deepcopy(change["bindings"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["bindings"][0]["slot_id"] = "absent-slot"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["engine"]["source_id"] = "absent-source"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"][0]["source_id"] = "absent-source"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["bindings"][0]["source_id"] = "absent-source"
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.TemplateContextError):
                    analysis.analyze_supplied_template_context(change)

    def test_unsupported_semantics_native_types_and_bounds_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["schema_version"] = True
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"] = []
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["engine"]["autoescape"] = "framework_default"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"][0]["context"] = "shell"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["bindings"][0]["explicit_escape"] = "eval"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["bindings"][0]["origin"] = "network"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"][0]["slot_id"] = "https://host.example/path"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["slots"] *= analysis.MAX_SLOTS
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["unknown"] = "extra"
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.TemplateContextError):
                    analysis.analyze_supplied_template_context(change)
        with self.assertRaises(analysis.TemplateContextError):
            analysis.analyze_supplied_template_context_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.TemplateContextError):
            analysis.analyze_supplied_template_context_bytes(model_bytes=bytearray(b"{}"))

    def test_forged_report_even_with_recomputed_hash_is_rejected(self):
        report = analysis.analyze_supplied_template_context(analysis.component_fixture())
        forged = report.to_dict()
        forged["slot_projections"][0]["disposition"] = "declared_matching_escape_unverified"
        unsigned = {k: v for k, v in forged.items() if k not in {"report_id", "report_sha256"}}
        digest = hashlib.sha256(
            canonical({"domain": analysis.DOMAIN, "report": unsigned}).encode("ascii")
        ).hexdigest()
        forged["report_id"] = "TCX-" + digest[:32].upper()
        forged["report_sha256"] = "sha256:" + digest
        with self.assertRaises(analysis.TemplateContextError):
            analysis.TemplateContextReport.from_dict(forged)
        with self.assertRaises(analysis.TemplateContextError):
            analysis.TemplateContextReport(canonical(forged))

    def test_retained_model_replay_does_not_replace_original_source(self):
        original = analysis.component_fixture()
        changed = copy.deepcopy(original)
        changed["engine"]["autoescape"] = "contextual"
        changed_report = analysis.analyze_supplied_template_context(changed)
        analysis.TemplateContextReport.from_json(changed_report.to_json())
        with self.assertRaises(analysis.TemplateContextError):
            analysis.verify_supplied_template_context(changed_report, model=original)

    def test_wrapper_and_canonical_text_rejected(self):
        report = analysis.analyze_supplied_template_context(analysis.component_fixture())
        with self.assertRaises(analysis.TemplateContextError):
            analysis.TemplateContextReport.from_json(" " + report.to_json())
        with self.assertRaises(analysis.TemplateContextError):
            analysis.TemplateContextReport("invalid-json")
        with self.assertRaises(analysis.TemplateContextError):
            analysis.verify_supplied_template_context(
                report.to_dict(), model=analysis.component_fixture()
            )

    def test_no_template_filesystem_network_process_or_credential_effect(self):
        with (
            patch("builtins.open", side_effect=AssertionError("filesystem effect")),
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            document = analysis.analyze_supplied_template_context(
                analysis.component_fixture()
            ).to_dict()
            self.assertTrue(all(value == "none" for value in document["effects"].values()))
            self.assertTrue(document["offline_only"])
            self.assertFalse(document["target_behavior_verified"])
            self.assertIsNone(document["live_vulnerability_verdict"])


if __name__ == "__main__":
    unittest.main()

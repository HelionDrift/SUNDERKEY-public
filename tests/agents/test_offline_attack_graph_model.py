"""Contracts for the supplied, inert attack-graph projection."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_attack_graph_model as analysis


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


class OfflineAttackGraphModelTests(unittest.TestCase):
    def test_fixture_projection_and_round_trip(self):
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_attack_graph(model)
        document = report.to_dict()
        self.assertEqual(document["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(document["analysis_status"], "complete_supplied_graph")
        self.assertEqual(
            [(row["objective_id"], row["disposition"]) for row in document["pair_projections"]],
            [
                ("objective-d", "supplied_supported_reachability"),
                ("objective-e", "unknown_hypothesized_edge"),
            ],
        )
        self.assertEqual(
            document["pair_projections"][0]["node_path"], ["entry-a", "boundary-b", "objective-d"]
        )
        self.assertEqual(document["pair_projections"][0]["edge_path"], ["edge-ab", "edge-bd"])
        self.assertEqual(
            document["pair_projections"][1]["edge_path"], ["edge-ab", "edge-bc", "edge-ce"]
        )
        self.assertEqual(
            document["source"]["evidence_source_ids"],
            ["synthetic-inventory", "synthetic-relationships"],
        )
        self.assertEqual(
            analysis.AttackGraphModelReport.from_json(report.to_json()).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.AttackGraphModelReport.from_dict(document).to_json(), report.to_json()
        )
        self.assertEqual(
            analysis.verify_supplied_attack_graph(report, model=model).to_json(), report.to_json()
        )

    def test_checked_component_example(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "examples"
            / "offline-attack-graph-model-component.json"
        )
        component = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(
            set(component),
            {
                "schema_version",
                "profile_id",
                "component_id",
                "environment",
                "action_tier",
                "dry_run",
                "credential_refs",
                "resources",
                "payload",
            },
        )
        self.assertEqual(component["profile_id"], analysis.PROFILE_ID)
        self.assertEqual(component["action_tier"], "R0")
        self.assertTrue(component["dry_run"])
        self.assertEqual(component["credential_refs"], [])
        self.assertEqual(
            component["resources"],
            {"network": [], "filesystem": [], "process": [], "credential": []},
        )
        self.assertEqual(component["payload"]["model"], analysis.component_fixture())
        analysis.verify_supplied_attack_graph(
            analysis.analyze_supplied_attack_graph(component["payload"]["model"]),
            model=component["payload"]["model"],
        )

    def test_permuted_declaration_order_has_same_pair_projection(self):
        model = analysis.component_fixture()
        original = analysis.analyze_supplied_attack_graph(model).to_dict()
        model["nodes"].reverse()
        model["edges"].reverse()
        model["evidence_sources"].reverse()
        changed = analysis.analyze_supplied_attack_graph(model).to_dict()
        self.assertEqual(changed["pair_projections"], original["pair_projections"])
        self.assertEqual(
            changed["source"]["evidence_source_ids"], original["source"]["evidence_source_ids"]
        )
        self.assertNotEqual(changed["source"]["model_sha256"], original["source"]["model_sha256"])

    def test_supported_path_wins_over_shorter_hypothesized_branch(self):
        model = analysis.component_fixture()
        model["edges"].append(
            {
                "edge_id": "edge-ad",
                "from_id": "entry-a",
                "to_id": "objective-d",
                "relation": "declared_access",
                "status": "hypothesized",
                "source_id": "synthetic-relationships",
            }
        )
        row = analysis.analyze_supplied_attack_graph(model).to_dict()["pair_projections"][0]
        self.assertEqual(row["disposition"], "supplied_supported_reachability")
        self.assertEqual(row["edge_path"], ["edge-ab", "edge-bd"])

    def test_blocked_edges_are_not_traversed(self):
        model = analysis.component_fixture()
        model["edges"][1]["status"] = "blocked"
        model["edges"][2]["status"] = "blocked"
        rows = analysis.analyze_supplied_attack_graph(model).to_dict()["pair_projections"]
        self.assertEqual(
            [row["disposition"] for row in rows], ["no_supplied_path", "no_supplied_path"]
        )
        self.assertTrue(all(row["edge_path"] is None and row["node_path"] is None for row in rows))

    def test_incomplete_graph_is_unknown_for_absent_path_but_retains_supported_path(self):
        model = analysis.component_fixture()
        model["graph_complete"] = False
        model["edges"][2]["status"] = "blocked"
        rows = analysis.analyze_supplied_attack_graph(model).to_dict()["pair_projections"]
        self.assertEqual(rows[0]["disposition"], "supplied_supported_reachability")
        self.assertEqual(rows[1]["disposition"], "unknown_incomplete_graph")

    def test_cycle_terminates_and_does_not_create_a_candidate(self):
        model = analysis.component_fixture()
        model["edges"].append(
            {
                "edge_id": "edge-cb",
                "from_id": "boundary-c",
                "to_id": "boundary-b",
                "relation": "declared_dependency",
                "status": "supported",
                "source_id": "synthetic-relationships",
            }
        )
        rows = analysis.analyze_supplied_attack_graph(model).to_dict()["pair_projections"]
        self.assertEqual(rows[0]["disposition"], "supplied_supported_reachability")
        self.assertEqual(rows[1]["disposition"], "unknown_hypothesized_edge")

    def test_shortest_path_tie_is_stable(self):
        model = analysis.component_fixture()
        model["edges"].extend(
            [
                {
                    "edge_id": "edge-ac",
                    "from_id": "entry-a",
                    "to_id": "boundary-c",
                    "relation": "declared_access",
                    "status": "supported",
                    "source_id": "synthetic-relationships",
                },
                {
                    "edge_id": "edge-cd",
                    "from_id": "boundary-c",
                    "to_id": "objective-d",
                    "relation": "declared_trust",
                    "status": "supported",
                    "source_id": "synthetic-relationships",
                },
            ]
        )
        rows = analysis.analyze_supplied_attack_graph(model).to_dict()["pair_projections"]
        self.assertEqual(rows[0]["edge_path"], ["edge-ab", "edge-bd"])
        self.assertEqual(rows[1]["disposition"], "supplied_supported_reachability")
        self.assertEqual(rows[1]["edge_path"], ["edge-ac", "edge-ce"])

    def test_duplicate_key_rejected_in_model_and_report(self):
        model = analysis.component_fixture()
        text = canonical(model).replace(
            '"schema_version":1', '"schema_version":1,"schema_version":1'
        )
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.analyze_supplied_attack_graph_bytes(model_bytes=text.encode("ascii"))
        text = canonical(model).replace(
            '"status":"supported"', '"status":"supported","status":"blocked"', 1
        )
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.analyze_supplied_attack_graph_bytes(model_bytes=text.encode("ascii"))
        report = analysis.analyze_supplied_attack_graph(model)
        text = report.to_json().replace(
            '"offline_only":true', '"offline_only":true,"offline_only":false'
        )
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.AttackGraphModelReport.from_json(text)

    def test_bad_identity_provenance_and_edge_semantics_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["evidence_sources"].append(copy.deepcopy(change["evidence_sources"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["nodes"][0]["source_id"] = "absent-source"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["nodes"].append(copy.deepcopy(change["nodes"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"].append(copy.deepcopy(change["edges"][0]))
        bad_models.append(change)
        change = copy.deepcopy(base)
        conflicting = copy.deepcopy(change["edges"][0])
        conflicting["edge_id"] = "edge-ab-conflict"
        conflicting["status"] = "blocked"
        change["edges"].append(conflicting)
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"][0]["from_id"] = "absent-node"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"][0]["to_id"] = "entry-a"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"][0]["relation"] = "exploit"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"][0]["status"] = "verified_live"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["evidence_sources"][0]["provenance_kind"] = "signed"
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.AttackGraphModelError):
                    analysis.analyze_supplied_attack_graph(change)

    def test_schema_native_type_and_bounds_rejected(self):
        base = analysis.component_fixture()
        bad_models = []
        change = copy.deepcopy(base)
        change["schema_version"] = True
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["graph_complete"] = 1
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["nodes"][0]["node_id"] = "https://host.example/path"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["nodes"][0]["extra"] = "no"
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["nodes"] = change["nodes"][1:]
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["edges"] *= analysis.MAX_EDGES
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["evidence_sources"] *= analysis.MAX_SOURCES
        bad_models.append(change)
        change = copy.deepcopy(base)
        change["unsupported"] = []
        bad_models.append(change)
        for change in bad_models:
            with self.subTest(change=change):
                with self.assertRaises(analysis.AttackGraphModelError):
                    analysis.analyze_supplied_attack_graph(change)
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.analyze_supplied_attack_graph_bytes(model_bytes=b"\xff")
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.analyze_supplied_attack_graph_bytes(model_bytes=bytearray(b"{}"))

    def test_forged_report_even_with_recomputed_hash_is_rejected(self):
        report = analysis.analyze_supplied_attack_graph(analysis.component_fixture())
        forged = report.to_dict()
        forged["pair_projections"][1]["disposition"] = "supplied_supported_reachability"
        forged["report_id"] = ""
        forged["report_sha256"] = ""
        unsigned = {k: v for k, v in forged.items() if k not in {"report_id", "report_sha256"}}
        digest = hashlib.sha256(
            canonical({"domain": analysis.DOMAIN, "report": unsigned}).encode("ascii")
        ).hexdigest()
        forged["report_id"] = "AGM-" + digest[:32].upper()
        forged["report_sha256"] = "sha256:" + digest
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.AttackGraphModelReport.from_dict(forged)
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.AttackGraphModelReport(canonical(forged))

    def test_retained_model_replay_is_not_original_source_assurance(self):
        original = analysis.component_fixture()
        changed = copy.deepcopy(original)
        changed["edges"][2]["status"] = "supported"
        forged_source_report = analysis.analyze_supplied_attack_graph(changed)
        self.assertEqual(
            forged_source_report.to_dict()["pair_projections"][1]["disposition"],
            "supplied_supported_reachability",
        )
        analysis.AttackGraphModelReport.from_json(forged_source_report.to_json())
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.verify_supplied_attack_graph(forged_source_report, model=original)

    def test_report_wrapper_and_canonical_text_rejected(self):
        report = analysis.analyze_supplied_attack_graph(analysis.component_fixture())
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.AttackGraphModelReport.from_json(" " + report.to_json())
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.AttackGraphModelReport("not-json")
        with self.assertRaises(analysis.AttackGraphModelError):
            analysis.verify_supplied_attack_graph(
                report.to_dict(), model=analysis.component_fixture()
            )

    def test_no_network_process_credential_or_payload_effects(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network effect")),
            patch("subprocess.Popen", side_effect=AssertionError("process effect")),
        ):
            document = analysis.analyze_supplied_attack_graph(
                analysis.component_fixture()
            ).to_dict()
            effects = document["effects"]
            self.assertTrue(all(value == "none" for value in effects.values()))
            self.assertTrue(document["offline_only"])
            self.assertFalse(document["target_behavior_verified"])
            self.assertIsNone(document["live_vulnerability_verdict"])


if __name__ == "__main__":
    unittest.main()

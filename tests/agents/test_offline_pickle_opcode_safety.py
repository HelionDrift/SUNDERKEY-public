"""Bounded pickle opcode analysis never loads the supplied bytes."""

from __future__ import annotations

import base64
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_pickle_opcode_safety as analysis

ROOT = Path(__file__).resolve().parents[2]


class PickleOpcodeSafetyTests(unittest.TestCase):
    def test_fixture_distinguishes_risk_policy_negative_and_unknown(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_pickle_opcodes(model)
        value = report.to_dict()
        self.assertEqual(value["candidate_count"], 1)
        self.assertEqual(value["unknown_count"], 1)
        self.assertFalse(value["deserialization_performed"])
        self.assertFalse(value["source_authenticated"])
        self.assertFalse(value["positive_use_approved"])
        self.assertNotIn("source_model", value)
        self.assertNotIn("blob_base64", report.to_json())
        self.assertEqual(set(value["operational_effects"].values()), {"none"})
        self.assertEqual(
            [item["disposition"] for item in value["artifact_projections"]],
            [
                "no_risky_opcode_observed_unverified",
                "candidate_risky_pickle_opcode",
                "declared_denied_loader_with_risky_opcode",
                "unknown_parse",
            ],
        )
        self.assertEqual(value["artifact_projections"][1]["risky_opcode_names"], ["GLOBAL"])
        self.assertEqual(
            analysis.verify_supplied_pickle_opcodes(report, model=model).to_json(),
            report.to_json(),
        )
        self.assertEqual(
            analysis.verify_supplied_pickle_opcodes_bytes(
                report.to_json().encode("ascii"), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_no_deserializer_or_import_is_called_for_supplied_pickle(self) -> None:
        with patch("pickle.loads") as loads, patch("pickle.load") as load:
            report = analysis.analyze_supplied_pickle_opcodes(analysis.component_fixture())
        loads.assert_not_called()
        load.assert_not_called()
        self.assertFalse(report.to_dict()["deserialization_performed"])

    def test_unknown_loader_and_trailing_bytes_abstain(self) -> None:
        model = analysis.component_fixture()
        model["artifacts"] = [copy.deepcopy(model["artifacts"][1])]
        model["artifacts"][0]["declared_loader_policy"] = "unknown"
        value = analysis.analyze_supplied_pickle_opcodes(model).to_dict()
        self.assertEqual(value["candidate_count"], 0)
        self.assertEqual(value["unknown_count"], 1)
        self.assertEqual(
            value["artifact_projections"][0]["disposition"],
            "unknown_loader_policy_with_risky_opcode",
        )
        model["artifacts"][0]["blob_base64"] = base64.b64encode(
            b"cbuiltins\nlist\n.extra"
        ).decode("ascii")
        value = analysis.analyze_supplied_pickle_opcodes(model).to_dict()
        self.assertEqual(value["artifact_projections"][0]["disposition"], "unknown_parse")

    def test_invalid_base64_duplicate_and_oversized_models_fail(self) -> None:
        model = analysis.component_fixture()
        for mutate in (
            lambda m: m["artifacts"][0].update(blob_base64="%%%"),
            lambda m: m["artifacts"][0].update(blob_base64="STEKLg="),
            lambda m: m["artifacts"][0].update(
                blob_base64=base64.b64encode(b"I" * 8_193).decode()
            ),
            lambda m: m["artifacts"].append(copy.deepcopy(m["artifacts"][0])),
            lambda m: m["artifacts"][0].update(declared_loader_policy=True),
        ):
            with self.subTest(mutate=mutate):
                invalid = copy.deepcopy(model)
                mutate(invalid)
                with self.assertRaises(ValueError):
                    analysis.analyze_supplied_pickle_opcodes(invalid)

    def test_changed_original_and_tampered_export_fail(self) -> None:
        model = analysis.component_fixture()
        report = analysis.analyze_supplied_pickle_opcodes(model)
        changed = copy.deepcopy(model)
        changed["artifacts"][1]["declared_loader_policy"] = "denied"
        with self.assertRaisesRegex(ValueError, "original model"):
            analysis.verify_supplied_pickle_opcodes(report, model=changed)
        exported = report.to_dict()
        exported["candidate_count"] = 0
        with self.assertRaisesRegex(ValueError, "original replay"):
            analysis.verify_supplied_pickle_opcodes_bytes(
                json.dumps(exported).encode("utf-8"), model=model
            )

    def test_checked_example_is_inert(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-pickle-opcode-safety-component.json").read_text(
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

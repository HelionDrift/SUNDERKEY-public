"""Supplied pickle opcode inventory never unpickles source bytes."""

from __future__ import annotations

import base64
import copy
import json
import pickle
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey import offline_specialist_components as components
from sunderkey.offline_pickle_opcode_inventory import (
    PickleOpcodeInventory,
    PickleOpcodeInventoryError,
    analyze_supplied_pickle_opcodes,
    verify_supplied_pickle_opcodes,
)

ROOT = Path(__file__).resolve().parents[2]
SAFE = bytes.fromhex("80044e2e")
GLOBAL = bytes.fromhex("636275696c74696e730a6c6973740a2e")


def model(raw: bytes = SAFE) -> dict:
    return {
        "schema_version": 1,
        "semantics_profile": "python-pickletools-opcode-inventory-v1",
        "source_id": "source.synthetic-1",
        "payload_b64": base64.b64encode(raw).decode("ascii"),
    }


class PickleOpcodeInventoryTests(unittest.TestCase):
    def test_checked_example_uses_fixed_catalog_dispatch(self) -> None:
        request = json.loads(
            (ROOT / "examples/offline-pickle-opcode-component.json").read_text(
                encoding="utf-8"
            )
        )
        catalog = components.build_offline_specialist_component_catalog(repository_root=ROOT)
        result = components.run_offline_specialist_component(
            request, catalog=catalog, repository_root=ROOT
        )
        self.assertEqual(result["component"]["profile_id"], "AOE-GE-D23-S03")
        self.assertEqual(
            result["component"]["component_id"], "supplied_pickle_opcode_inventory"
        )
        self.assertEqual(
            result["analysis"]["review_disposition"],
            "candidate_dynamic_behavior_opcodes",
        )
        self.assertFalse(result["analysis"]["flags"]["pickle_loaded"])

    def test_safe_inventory_replays_without_unpickling(self) -> None:
        source = model()
        original = copy.deepcopy(source)
        with patch.object(pickle, "loads", side_effect=AssertionError("unpickle called")):
            report = analyze_supplied_pickle_opcodes(source)
            verified = verify_supplied_pickle_opcodes(report, model=source)
        document = report.to_dict()
        self.assertEqual(source, original)
        self.assertEqual(verified.to_json(), report.to_json())
        self.assertEqual(document["declared_protocol"], 4)
        self.assertEqual(document["opcode_count"], 3)
        self.assertEqual(document["review_disposition"], "no_tracked_dynamic_behavior_opcodes")
        self.assertEqual(document["review_positions"]["resolution"], [])
        self.assertEqual(set(document["operational_effects"].values()), {"none"})

    def test_global_is_only_a_review_candidate(self) -> None:
        document = analyze_supplied_pickle_opcodes(model(GLOBAL)).to_dict()
        self.assertEqual(document["review_positions"]["resolution"], [0])
        self.assertEqual(document["declared_protocol"], None)
        self.assertEqual(document["review_disposition"], "candidate_dynamic_behavior_opcodes")
        self.assertFalse(document["flags"]["exploitability_verified"])
        self.assertFalse(document["flags"]["target_deserializer_behavior_verified"])

    def test_malformed_or_resource_bearing_source_is_refused(self) -> None:
        for raw in (b"", b"not a pickle", SAFE + b"extra", b"\x80\x04N", b"\xff."):
            with self.subTest(raw=raw):
                with self.assertRaises(PickleOpcodeInventoryError):
                    analyze_supplied_pickle_opcodes(model(raw))
        altered = model()
        altered["network_permission"] = True
        with self.assertRaises(PickleOpcodeInventoryError):
            analyze_supplied_pickle_opcodes(altered)
        altered = model()
        altered["payload_b64"] = "gAROLg="
        with self.assertRaises(PickleOpcodeInventoryError):
            analyze_supplied_pickle_opcodes(altered)
        cycle = model()
        cycle["cycle"] = cycle
        with self.assertRaises(PickleOpcodeInventoryError):
            analyze_supplied_pickle_opcodes(cycle)

    def test_single_byte_inputs_are_bounded_or_refused_without_crashing(self) -> None:
        for byte in range(256):
            with self.subTest(byte=byte):
                try:
                    analyze_supplied_pickle_opcodes(model(bytes((byte,))))
                except PickleOpcodeInventoryError:
                    pass

    def test_tampering_and_alternate_source_are_refused(self) -> None:
        source = model()
        report = analyze_supplied_pickle_opcodes(source)
        changed = report.to_dict()
        changed["opcode_inventory"][0]["count"] = 5
        with self.assertRaises(PickleOpcodeInventoryError):
            PickleOpcodeInventory(changed)
        with self.assertRaises(PickleOpcodeInventoryError):
            verify_supplied_pickle_opcodes(report, model=model(GLOBAL))
        with self.assertRaises(PickleOpcodeInventoryError):
            verify_supplied_pickle_opcodes(report.to_dict(), model=source)


if __name__ == "__main__":
    unittest.main()

"""Offline effect declarations cannot be changed through returned documents."""

from __future__ import annotations

import ast
import importlib
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / "src" / "sunderkey"
HARDENED_MODULES = (
    "advisory_asset_applicability",
    "advisory_transition_review",
    "api_role_response_matrix",
    "asset_reconciliation",
    "durable_scheduler_contracts",
    "event_assessment_planning",
    "human_escalation_routing",
    "metadata_impact_review",
)


class OfflineEffectsIsolationTests(unittest.TestCase):
    def test_hardened_no_effects_constants_are_read_only(self) -> None:
        for name in HARDENED_MODULES:
            with self.subTest(module=name):
                module = importlib.import_module(f"sunderkey.{name}")
                key = next(iter(module.NO_EFFECTS))
                with self.assertRaises(TypeError):
                    module.NO_EFFECTS[key] = "changed"

    def test_no_result_builder_returns_a_shared_effects_dictionary(self) -> None:
        exposed: list[str] = []
        for path in SOURCE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Dict):
                    continue
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "effects"
                        and isinstance(value, ast.Name)
                        and value.id == "NO_EFFECTS"
                    ):
                        exposed.append(f"{path.name}:{node.lineno}")
        self.assertEqual(exposed, [])


if __name__ == "__main__":
    unittest.main()

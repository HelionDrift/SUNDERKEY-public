"""Supplied WASM import allowlist and replay tests."""

from __future__ import annotations

import copy
import unittest

from sunderkey.offline_wasm_host_import_boundary import (
    WasmHostImportBoundaryError,
    analyze_supplied_wasm_host_imports,
    component_fixture,
    verify_supplied_wasm_host_imports,
    verify_supplied_wasm_host_imports_bytes,
)


class WasmHostImportBoundaryTests(unittest.TestCase):
    def test_outside_allowlist_is_inert_candidate(self) -> None:
        model = component_fixture()
        report = analyze_supplied_wasm_host_imports(model)
        body = report.to_dict()
        self.assertEqual(body["candidate_count"], 1)
        self.assertEqual(
            body["module_projections"][0]["outside_allowlist_import_ids"], ["import-two"]
        )
        self.assertFalse(body["wasm_binary_parsed"])
        self.assertFalse(body["positive_use_approved"])
        self.assertEqual(set(body["operational_effects"].values()), {"none"})
        self.assertEqual(
            verify_supplied_wasm_host_imports(report, model=model).to_json(), report.to_json()
        )
        self.assertEqual(
            verify_supplied_wasm_host_imports_bytes(
                report.to_json().encode(), model=model
            ).to_json(),
            report.to_json(),
        )

    def test_allowed_and_incomplete_context(self) -> None:
        model = component_fixture()
        model["modules"][0]["allowed_imports"].append(
            {"namespace_id": "extra-host", "function_id": "write-state"}
        )
        self.assertEqual(analyze_supplied_wasm_host_imports(model).to_dict()["candidate_count"], 0)
        model["modules"][0]["context_complete"] = False
        self.assertEqual(analyze_supplied_wasm_host_imports(model).to_dict()["unknown_count"], 1)

    def test_replay_rejects_changed_source_and_forgery(self) -> None:
        model = component_fixture()
        report = analyze_supplied_wasm_host_imports(model)
        changed = copy.deepcopy(model)
        changed["modules"][0]["imports"][1]["function_id"] = "other-function"
        with self.assertRaises(WasmHostImportBoundaryError):
            verify_supplied_wasm_host_imports(report, model=changed)
        with self.assertRaises(WasmHostImportBoundaryError):
            verify_supplied_wasm_host_imports(report.to_dict(), model=model)
        with self.assertRaises(WasmHostImportBoundaryError):
            verify_supplied_wasm_host_imports_bytes(b"{}", model=model)

    def test_rejects_duplicate_import_and_allowed_pair(self) -> None:
        model = component_fixture()
        model["modules"][0]["imports"][1]["import_id"] = "import-one"
        with self.assertRaises(WasmHostImportBoundaryError):
            analyze_supplied_wasm_host_imports(model)
        model = component_fixture()
        model["modules"][0]["allowed_imports"].append(
            {"namespace_id": "safe-host", "function_id": "read-state"}
        )
        with self.assertRaises(WasmHostImportBoundaryError):
            analyze_supplied_wasm_host_imports(model)


if __name__ == "__main__":
    unittest.main()

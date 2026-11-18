"""Phase 29 deterministic implementation wave selection."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_implementation_wave_package import (
    build_parser,
    build_report,
)
from sunderkey.errors import QualificationError
from sunderkey.implementation_work_packages import (
    ImplementationWaveSelectionReport,
    load_implementation_work_package_report,
    select_implementation_wave_package,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGES_PATH = (
    ROOT / "registry" / "implementation-work-packages-army-v1.json"
)
EXAMPLE_PATH = (
    ROOT / "examples" / "implementation" / "iw-001-work-package.json"
)


class ImplementationWaveSelectionPhase29Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.packages = load_implementation_work_package_report(PACKAGES_PATH)

    def select(self, wave_id: str = "IW-001") -> ImplementationWaveSelectionReport:
        return select_implementation_wave_package(self.packages, wave_id)

    def test_report_is_deterministic_and_self_identifying(self) -> None:
        first = self.select()
        second = self.select()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            ImplementationWaveSelectionReport.from_dict(document),
            first,
        )
        self.assertEqual(
            document["report_id"],
            "IWS-6DD2B7CCD840ED5E49C288D3B9609344",
        )
        self.assertEqual(
            document["report_sha256"],
            "sha256:6dd2b7ccd840ed5e49c288d3b9609344"
            "8e1242aa4637e306edf2828e7409c743",
        )

    def test_checked_in_example_matches_deterministic_builder(self) -> None:
        expected = build_report(build_parser().parse_args([]))
        self.assertEqual(
            EXAMPLE_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_selection_preserves_exact_parent_package(self) -> None:
        parent = self.packages.to_dict()
        document = self.select().to_dict()
        expected = next(
            package
            for package in parent["packages"]
            if package["wave_id"] == "IW-001"
        )

        self.assertEqual(
            document["status"],
            "implementation_wave_package_selected",
        )
        self.assertEqual(document["selection_effect"], "none")
        self.assertEqual(
            document["work_package_report"],
            {
                "report_id": self.packages.report_id,
                "sha256": self.packages.report_sha256,
            },
        )
        self.assertEqual(document["package"], expected)
        self.assertEqual(
            document["summary"],
            {
                "group_count": 5,
                "domain_command_count": 23,
                "specialist_lane_count": 23,
                "work_item_count": 207,
                "ready_for_authoring_work_item_count": 23,
                "waiting_on_dependencies_work_item_count": 161,
                "blocked_by_decision_work_item_count": 23,
            },
        )

    def test_every_wave_can_be_selected_once(self) -> None:
        parent = self.packages.to_dict()
        selections = [
            self.select(str(package["wave_id"])).to_dict()
            for package in parent["packages"]
        ]
        self.assertEqual(len(selections), 18)
        self.assertEqual(
            len({selection["report_id"] for selection in selections}),
            18,
        )
        self.assertEqual(
            [selection["selected_wave_id"] for selection in selections],
            [package["wave_id"] for package in parent["packages"]],
        )

    def test_malformed_and_unknown_wave_ids_fail_closed(self) -> None:
        for wave_id in ("IW-1", "iw-001", "IW-0001", "IW-001\n"):
            with self.subTest(wave_id=wave_id), self.assertRaisesRegex(
                QualificationError,
                "IW-NNN form",
            ):
                self.select(wave_id)
        with self.assertRaisesRegex(
            QualificationError,
            "does not exist: IW-999",
        ):
            self.select("IW-999")

    def test_parent_loader_rejects_tampering(self) -> None:
        raw = self.packages.to_dict()
        raw["summary"]["work_item_count"] -= 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packages.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(QualificationError, "hash is invalid"):
                load_implementation_work_package_report(path)

    def test_selection_report_rejects_tampering(self) -> None:
        document = self.select().to_dict()
        document["summary"]["work_item_count"] -= 1
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            ImplementationWaveSelectionReport.from_dict(document)

    def test_selection_does_not_mutate_parent(self) -> None:
        before = copy.deepcopy(self.packages.to_dict())
        self.select()
        self.assertEqual(self.packages.to_dict(), before)

    def test_modules_have_no_network_or_execution_dependencies(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "subprocess",
            "urllib",
        }
        for path in (
            ROOT
            / "src"
            / "sunderkey"
            / "implementation_work_packages.py",
            ROOT / "scripts" / "build_implementation_wave_package.py",
        ):
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                imported = {
                    alias.name.split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Import)
                    for alias in node.names
                }
                imported.update(
                    str(node.module).split(".")[0]
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                )
                self.assertFalse(imported & prohibited)


if __name__ == "__main__":
    unittest.main()

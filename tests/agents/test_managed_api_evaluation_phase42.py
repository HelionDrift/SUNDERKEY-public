"""Phase 42 managed API evaluation boundary coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from scripts.build_managed_api_evaluation_boundary import build_parser, build_record
from sunderkey.errors import QualificationError
from sunderkey.managed_api_evaluation import (
    MISSING_BINDINGS,
    SELECTED_ARCHITECTURE,
    ManagedApiEvaluationBoundary,
    build_managed_api_evaluation_boundary,
    load_managed_api_evaluation_boundary,
)

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "examples" / "implementation" / "passive-osint"
BOUNDARY_PATH = SOURCE / "managed-api-evaluation-boundary-v1.json"
CANDIDATES_PATH = SOURCE / "candidate-implementations-v1.json"
SUITE_PATH = SOURCE / "evaluation-suite-v1.json"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


class ManagedApiEvaluationPhase42Tests(unittest.TestCase):
    def build(self) -> ManagedApiEvaluationBoundary:
        return build_managed_api_evaluation_boundary(
            load_json(CANDIDATES_PATH),
            load_json(SUITE_PATH),
        )

    def test_record_is_deterministic_and_self_identifying(self) -> None:
        first = self.build()
        second = self.build()
        document = first.to_dict()
        self.assertEqual(first, second)
        self.assertEqual(ManagedApiEvaluationBoundary.from_dict(document), first)
        self.assertEqual(
            document["boundary_id"],
            "MAB-E1317CB8CB214C864A32CCC63B84BBED",
        )
        self.assertEqual(
            document["boundary_sha256"],
            "sha256:e1317cb8cb214c864a32ccc63b84bbed5cb44c3be391c3cc3db7dcdbc413908e",
        )

    def test_checked_record_matches_deterministic_builder(self) -> None:
        expected = build_record(build_parser().parse_args([]))
        self.assertEqual(
            BOUNDARY_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_owner_decision_selects_managed_api_architecture(self) -> None:
        document = self.build().to_dict()
        self.assertEqual(document["decision_id"], "D010")
        self.assertEqual(document["decision_status"], "approved")
        self.assertEqual(document["selected_architecture"], SELECTED_ARCHITECTURE)
        self.assertEqual(
            document["approval_basis"]["authority_role"],
            "repository_owner",
        )

    def test_exact_candidate_and_suite_are_bound(self) -> None:
        document = self.build().to_dict()
        self.assertEqual(
            document["candidate"]["candidate_id"],
            "development.passive-osint",
        )
        self.assertEqual(document["evaluation_suite"]["case_count"], 29)
        self.assertEqual(
            document["evaluation_suite"]["suite_sha256"],
            "sha256:61b1c530ffc2875983e0be31903af1693c41f73cacc832e0a36ac37b862796e7",
        )
        self.assertEqual(
            document["candidate"]["candidate_artifact_sha256"],
            document["evaluation_suite"]["candidate_artifact_sha256"],
        )

    def test_runtime_remains_unselected_and_execution_blocked(self) -> None:
        document = self.build().to_dict()
        self.assertEqual(
            set(document["runtime_binding"].values()),
            {"unselected"},
        )
        self.assertEqual(
            tuple(document["readiness"]["missing_bindings"]),
            MISSING_BINDINGS,
        )
        self.assertFalse(document["readiness"]["execution_enabled"])
        self.assertEqual(document["worker_boundary"]["network_default"], "deny")
        self.assertEqual(document["worker_boundary"]["automatic_retries"], 0)

    def test_data_and_tool_boundaries_are_closed(self) -> None:
        boundary = self.build().to_dict()["data_boundary"]
        self.assertFalse(boundary["target_data_allowed"])
        self.assertFalse(boundary["credential_data_allowed"])
        self.assertFalse(boundary["retrieval_allowed"])
        self.assertFalse(boundary["tool_calls_allowed"])
        self.assertFalse(boundary["unreviewed_context_allowed"])

    def test_runtime_or_safety_tampering_fails_closed(self) -> None:
        for path, value, message in (
            (("runtime_binding", "provider_id"), "provider", "runtime_binding"),
            (("readiness", "execution_enabled"), True, "execution"),
            (("worker_boundary", "network_default"), "allow", "worker_boundary"),
            (("data_boundary", "target_data_allowed"), True, "data_boundary"),
        ):
            with self.subTest(path=path):
                document = self.build().to_dict()
                document[path[0]][path[1]] = value
                with self.assertRaisesRegex(QualificationError, message):
                    ManagedApiEvaluationBoundary.from_dict(document)

    def test_hash_and_unknown_field_tampering_fails_closed(self) -> None:
        document = self.build().to_dict()
        document["boundary_sha256"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            ManagedApiEvaluationBoundary.from_dict(document)
        document = self.build().to_dict()
        document["api_key"] = "not-allowed"
        with self.assertRaisesRegex(QualificationError, "unsupported fields"):
            ManagedApiEvaluationBoundary.from_dict(document)

    def test_builder_rejects_candidate_or_suite_mismatch(self) -> None:
        candidates = load_json(CANDIDATES_PATH)
        suite = load_json(SUITE_PATH)
        changed = copy.deepcopy(candidates)
        changed["candidates"][0]["candidate_version"] = "2.0.0"
        with self.assertRaisesRegex(QualificationError, "candidate_version"):
            build_managed_api_evaluation_boundary(changed, suite)
        changed_suite = copy.deepcopy(suite)
        changed_suite["candidate"]["candidate_version"] = "2.0.0"
        with self.assertRaisesRegex(QualificationError, "candidate binding"):
            build_managed_api_evaluation_boundary(candidates, changed_suite)

    def test_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(QualificationError, "Could not load"):
                load_managed_api_evaluation_boundary(path)

    def test_modules_have_no_network_secret_or_execution_dependencies(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "keyring",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for path in (
            ROOT / "src" / "sunderkey" / "managed_api_evaluation.py",
            ROOT / "scripts" / "build_managed_api_evaluation_boundary.py",
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

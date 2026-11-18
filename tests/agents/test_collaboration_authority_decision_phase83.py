"""Phase 83 approved D001 through D005 collaboration decision coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from scripts.build_collaboration_authority_decision import build_parser, build_record
from sunderkey.cli import build_parser as build_cli_parser
from sunderkey.collaboration_authority_decision import (
    CollaborationAuthorityDecisionRecord,
    load_collaboration_authority_decision_record,
    load_collaboration_authority_decision_submission,
    verify_collaboration_authority_decision_record,
)
from sunderkey.collaboration_authority_dossier import (
    load_collaboration_authority_decision_dossier,
)
from sunderkey.errors import CollaborationPlanError

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "registry"
DOSSIER_PATH = REGISTRY / "collaboration-authority-dossier-d001-d005.json"
SUBMISSION_PATH = (
    REGISTRY / "collaboration-authority-decision-submission-d001-d005.json"
)
DECISION_PATH = REGISTRY / "collaboration-authority-decision-d001-d005.json"
SCHEMA_PATH = (
    REGISTRY / "schemas" / "collaboration-authority-decision-record-v1.schema.json"
)


class CollaborationAuthorityDecisionPhase83Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = load_collaboration_authority_decision_dossier(DOSSIER_PATH)
        cls.submission = load_collaboration_authority_decision_submission(SUBMISSION_PATH)
        cls.record = load_collaboration_authority_decision_record(DECISION_PATH)

    def test_checked_record_matches_deterministic_builder(self) -> None:
        expected = build_record(build_parser().parse_args([]))
        self.assertEqual(
            DECISION_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )
        self.assertEqual(self.record.to_dict(), expected)
        self.assertEqual(
            verify_collaboration_authority_decision_record(
                self.record, self.dossier
            ),
            self.record,
        )

    def test_full_recommended_bundle_is_approved(self) -> None:
        document = self.record.to_dict()
        self.assertEqual(
            document["decision_ids"], ["D001", "D002", "D003", "D004", "D005"]
        )
        self.assertEqual(
            document["selected_alternative"], "reviewed_reconfiguration_ledger"
        )
        self.assertEqual(document["recommendation_alignment"]["selected_option_count"], 5)
        self.assertTrue(
            document["recommendation_alignment"]["all_recommended_options_selected"]
        )
        self.assertEqual(
            document["decision_effect"],
            "collaboration_reconfiguration_contract_implementation_authorized",
        )

    def test_current_runtime_boundary_stays_closed(self) -> None:
        document = self.record.to_dict()
        self.assertEqual(document["implementation_status"], "not_started")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(document["registry_effect"], "none")
        serialized = json.dumps(document, sort_keys=True)
        self.assertNotIn("\u2014", serialized)
        for field in (
            '"private_key":',
            '"credential":',
            '"network_endpoint":',
            '"worker_session":',
            '"mission_id":',
        ):
            with self.subTest(field=field):
                self.assertNotIn(field, serialized)

    def test_unknown_option_and_tampered_hash_are_rejected(self) -> None:
        unknown = copy.deepcopy(self.record.to_dict())
        unknown["selected_options"]["D003"] = "unreviewed_transfer"
        with self.assertRaisesRegex(CollaborationPlanError, "D003"):
            CollaborationAuthorityDecisionRecord.from_dict(unknown)
        tampered = copy.deepcopy(self.record.to_dict())
        tampered["approval"]["rationale"] = "Different approval"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationAuthorityDecisionRecord.from_dict(tampered)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_record_matches_published_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(self.record.to_dict())

    def test_public_commands_are_registered(self) -> None:
        parser = build_cli_parser()
        with tempfile.TemporaryDirectory() as temporary:
            output = str(Path(temporary) / "record.json")
            args = parser.parse_args(
                [
                    "collaboration-authority-decision-record",
                    "--dossier",
                    str(DOSSIER_PATH),
                    "--submission",
                    str(SUBMISSION_PATH),
                    "--output",
                    output,
                ]
            )
            self.assertTrue(callable(args.handler))
        verify = parser.parse_args(
            [
                "collaboration-authority-decision-record-verify",
                "--dossier",
                str(DOSSIER_PATH),
                "--record",
                str(DECISION_PATH),
            ]
        )
        self.assertTrue(callable(verify.handler))

    def test_builder_has_no_network_storage_or_execution_imports(self) -> None:
        prohibited = {
            "asyncio",
            "http",
            "requests",
            "socket",
            "sqlite3",
            "subprocess",
            "urllib",
        }
        for relative in (
            "src/sunderkey/collaboration_authority_decision.py",
            "scripts/build_collaboration_authority_decision.py",
        ):
            tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
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

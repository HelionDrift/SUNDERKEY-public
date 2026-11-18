"""Phase 31 approved D008 qualification authority decision record."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_qualification_authority_decision import (
    build_parser,
    build_record,
)
from sunderkey.errors import QualificationError
from sunderkey.qualification_authority_decision import (
    APPROVED_OPTIONS,
    QualificationAuthorityDecisionRecord,
    load_qualification_authority_decision_record,
    record_qualification_authority_decision,
)
from sunderkey.qualification_authority_dossier import (
    QualificationAuthorityDecisionDossier,
)

ROOT = Path(__file__).resolve().parents[2]
DOSSIER_PATH = ROOT / "registry" / "qualification-authority-dossier-d008.json"
DECISION_PATH = ROOT / "registry" / "qualification-authority-decision-d008.json"


class QualificationAuthorityDecisionPhase31Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dossier = QualificationAuthorityDecisionDossier.from_dict(
            json.loads(DOSSIER_PATH.read_text(encoding="utf-8"))
        )

    def record(self) -> QualificationAuthorityDecisionRecord:
        return record_qualification_authority_decision(self.dossier)

    def test_record_is_deterministic_and_self_identifying(self) -> None:
        first = self.record()
        second = self.record()
        document = first.to_dict()

        self.assertEqual(first, second)
        self.assertEqual(
            QualificationAuthorityDecisionRecord.from_dict(document),
            first,
        )
        self.assertEqual(
            document["record_id"],
            "QDR-7242E7ED90734BBE96A8036647FA227F",
        )
        self.assertEqual(
            document["record_sha256"],
            "sha256:7242e7ed90734bbe96a8036647fa227f"
            "65ef9c254e08cd4e50d3bf3684174850",
        )

    def test_checked_in_record_matches_deterministic_builder(self) -> None:
        expected = build_record(build_parser().parse_args([]))
        self.assertEqual(
            DECISION_PATH.read_text(encoding="utf-8"),
            json.dumps(expected, ensure_ascii=True, indent=2) + "\n",
        )

    def test_record_selects_every_approved_option(self) -> None:
        document = self.record().to_dict()
        self.assertEqual(document["decision_id"], "D008")
        self.assertEqual(document["decision_status"], "approved")
        self.assertEqual(
            document["decision_effect"],
            "contract_implementation_authorized",
        )
        self.assertEqual(document["selected_options"], APPROVED_OPTIONS)
        self.assertEqual(
            document["source_dossier"],
            {
                "report_id": self.dossier.report_id,
                "sha256": self.dossier.report_sha256,
            },
        )

    def test_operational_contract_is_asymmetric_and_fail_closed(self) -> None:
        contract = self.record().to_dict()["operational_contract"]
        self.assertFalse(contract["qualification_state_in_runtime_store"])
        self.assertTrue(contract["offline_verification_required"])
        self.assertEqual(
            contract["authoritative_routing_source"],
            "reviewed_versioned_registry",
        )
        suspension = contract["emergency_suspension"]
        self.assertEqual(suspension["authorized_role"], "independent_control")
        self.assertTrue(suspension["signed_reason_required"])
        self.assertFalse(suspension["may_grant_qualification"])
        self.assertFalse(suspension["may_reinstate"])
        self.assertEqual(
            contract["reinstatement"],
            "full_independent_review_required",
        )

    def test_record_authorizes_contracts_but_no_live_authority(self) -> None:
        document = self.record().to_dict()
        self.assertEqual(len(document["authorized_next_steps"]), 8)
        self.assertEqual(len(document["prohibited_effects"]), 9)
        serialized = json.dumps(document, sort_keys=True)
        for prohibited_field in (
            '"private_key"',
            '"public_key"',
            '"signature"',
            '"reviewer_id"',
            '"credential_id"',
        ):
            with self.subTest(field=prohibited_field):
                self.assertNotIn(prohibited_field, serialized)

    def test_selected_option_tampering_fails_closed(self) -> None:
        document = self.record().to_dict()
        document["selected_options"]["authority_model"] = (
            "local_runtime_qualification_ledger"
        )
        with self.assertRaisesRegex(
            QualificationError,
            "selected_options.authority_model",
        ):
            QualificationAuthorityDecisionRecord.from_dict(document)

    def test_operational_contract_tampering_fails_closed(self) -> None:
        document = self.record().to_dict()
        document["operational_contract"][
            "qualification_state_in_runtime_store"
        ] = True
        with self.assertRaisesRegex(
            QualificationError,
            "qualification_state_in_runtime_store",
        ):
            QualificationAuthorityDecisionRecord.from_dict(document)

    def test_content_hash_tampering_fails_closed(self) -> None:
        document = self.record().to_dict()
        document["source_dossier"]["sha256"] = "sha256:" + ("0" * 64)
        with self.assertRaisesRegex(QualificationError, "hash is invalid"):
            QualificationAuthorityDecisionRecord.from_dict(document)

    def test_unknown_fields_fail_closed(self) -> None:
        document = self.record().to_dict()
        document["override"] = True
        with self.assertRaisesRegex(QualificationError, "unsupported fields"):
            QualificationAuthorityDecisionRecord.from_dict(document)

    def test_loader_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"schema_version":1}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                QualificationError,
                "Could not load qualification authority decision record",
            ):
                load_qualification_authority_decision_record(path)

    def test_builder_does_not_mutate_dossier(self) -> None:
        before = copy.deepcopy(self.dossier.to_dict())
        self.record()
        self.assertEqual(self.dossier.to_dict(), before)

    def test_module_has_no_network_or_execution_dependencies(self) -> None:
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
            / "qualification_authority_decision.py",
            ROOT / "scripts" / "build_qualification_authority_decision.py",
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

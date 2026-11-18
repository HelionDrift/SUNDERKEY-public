"""Cross-batch custody checks for offline API evidence."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from pathlib import Path

from scripts.run_offline_api_assessment import _native_adapter, _prepare_case, run_case
from sunderkey.finding_validators import EvidenceRecord
from sunderkey.offline_api_assessment import (
    OfflineApiCaseSource,
    build_offline_api_batch,
    evaluate_offline_api_case,
)
from sunderkey.offline_api_source_ledger import (
    OfflineApiSourceLedgerError,
    append_offline_api_source_batch,
    verify_offline_api_source_ledger,
)
from tests.agents._public_test_values import ForgedString

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "offline-api-assessment"


class OfflineApiSourceLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.adapter = _native_adapter()
        sources = []
        for name in (
            "corroborated-synthetic-case.json",
            "denied-synthetic-retest-case.json",
        ):
            raw = json.loads((EXAMPLES / name).read_text(encoding="utf-8"))
            case_id, invocation, evidence = _prepare_case(raw, cls.adapter)
            sources.append(OfflineApiCaseSource(case_id, invocation, evidence, run_case(raw)))
        cls.sources = tuple(sources)

    def append(self, source, prior=None):
        batch = build_offline_api_batch(adapter=self.adapter, sources=(source,)).to_dict()
        return append_offline_api_source_batch(
            adapter=self.adapter,
            sources=(source,),
            batch=batch,
            prior_ledger=prior,
        )

    def sourced(self, source, evidence_id: str) -> OfflineApiCaseSource:
        original = source.evidence[0]
        record = EvidenceRecord.from_bytes(
            evidence_id,
            original.content,
            media_type=original.media_type,
            role=original.role,
            status_code=original.status_code,
            attributes={
                **dict(original.attributes),
                "source_receipt_sha256": "sha256:" + "a" * 64,
                "source_session_id": "session.synthetic.001",
                "source_scope_id": source.invocation.scope_id,
                "source_scope_sha256": "sha256:" + "b" * 64,
                "source_target_id": source.invocation.target_id,
                "source_target_sha256": "sha256:" + "c" * 64,
            },
        )
        attributes = record.attributes
        invocation = replace(
            source.invocation,
            input_data={
                "exchanges": [
                    {
                        "evidence_id": evidence_id,
                        "subject_id": attributes["principal_id"],
                        "object_id": attributes["object_id"],
                        "expected_permitted": attributes["expected_access"],
                        "status_code": record.status_code,
                    }
                ]
            },
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=source.case_id,
            invocation=invocation,
            evidence=(record,),
        )
        return OfflineApiCaseSource(source.case_id, invocation, (record,), result.to_dict())

    def test_distinct_retest_batches_retain_order_and_identity(self) -> None:
        first = self.append(self.sources[0])
        second = self.append(self.sources[1], first)
        self.assertEqual(second, verify_offline_api_source_ledger(second))
        self.assertEqual(second["source_mode"], "synthetic_unsourced")
        self.assertEqual(len(second["cases"]), 2)
        self.assertEqual(len(second["batch_sha256s"]), 2)
        self.assertEqual(second["batch_sha256s"][0], first["batch_sha256s"][0])
        self.assertEqual(second["effects"]["source_authentication"], "none")

    def test_replay_of_prior_batch_fails(self) -> None:
        first = self.append(self.sources[0])
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "batch replay"):
            self.append(self.sources[0], first)

    def test_reused_invocation_across_distinct_cases_fails(self) -> None:
        first = self.append(self.sources[0])
        second = self.sources[1]
        changed_invocation = replace(
            second.invocation,
            invocation_id=self.sources[0].invocation.invocation_id,
        )
        result = evaluate_offline_api_case(
            adapter=self.adapter,
            case_id=second.case_id,
            invocation=changed_invocation,
            evidence=second.evidence,
        )
        changed = OfflineApiCaseSource(
            second.case_id, changed_invocation, second.evidence, result.to_dict()
        )
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "invocation_id replay"):
            self.append(changed, first)

    def test_receipt_replay_across_separate_batches_fails(self) -> None:
        first = self.sourced(self.sources[0], "response.synthetic.first")
        second = self.sourced(self.sources[1], "response.synthetic.second")
        prior = self.append(first)
        self.assertEqual(prior["source_mode"], "receipt_sourced")
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "receipt replay"):
            self.append(second, prior)

    def test_tampered_ledger_is_rejected(self) -> None:
        document = self.append(self.sources[0])
        changed = copy.deepcopy(document)
        changed["cases"][0]["result_sha256"] = "sha256:" + "a" * 64
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "content identity"):
            verify_offline_api_source_ledger(changed)
        changed = copy.deepcopy(document)
        changed["batch_sha256s"].append(changed["batch_sha256s"][0])
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "batch replay"):
            verify_offline_api_source_ledger(changed)
        changed = copy.deepcopy(document)
        changed["cases"][0]["batch_sha256"] = "sha256:" + "d" * 64
        with self.assertRaisesRegex(OfflineApiSourceLedgerError, "batch case links"):
            verify_offline_api_source_ledger(changed)

    def test_content_address_hooks_cannot_hide_changed_mission(self) -> None:
        changed = self.append(self.sources[0])
        changed["mission_id"] = "mission.unrelated"
        with self.assertRaises(OfflineApiSourceLedgerError):
            verify_offline_api_source_ledger(changed)
        forged = []
        for field in ("ledger_id", "ledger_sha256"):
            changed[field] = ForgedString(changed[field])
            forged.append(changed[field])
        with self.assertRaises(OfflineApiSourceLedgerError):
            verify_offline_api_source_ledger(changed)
        self.assertTrue(all(value.hooks == [] for value in forged))

    def test_ledger_context_and_case_primitives_reject_hooks(self) -> None:
        original = self.append(self.sourced(self.sources[0], "response.synthetic.first"))
        paths = [(field,) for field, value in original.items() if type(value) is str]
        paths += [("batch_sha256s", 0)]
        paths += [
            ("cases", 0, field)
            for field, value in original["cases"][0].items()
            if type(value) is str
        ]
        paths += [("cases", 0, field, 0) for field in ("evidence_sha256s", "receipt_sha256s")]
        paths += [
            ("cases", 0, "session_principals", 0, field) for field in ("session_id", "principal_id")
        ]
        for path in paths:
            with self.subTest(path=path):
                changed = copy.deepcopy(original)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                forged = ForgedString(parent[path[-1]])
                parent[path[-1]] = forged
                with self.assertRaises(OfflineApiSourceLedgerError):
                    verify_offline_api_source_ledger(changed)
                self.assertEqual(forged.hooks, [])

    def test_ledger_aliased_fields_reject_before_lookup(self) -> None:
        from tests.agents.test_offline_task_review_receipts import aliased_mapping

        original = self.append(self.sourced(self.sources[0], "response.synthetic.first"))
        for path, field in (
            ((), "mission_id"),
            (("cases", 0), "case_id"),
            (("cases", 0, "session_principals", 0), "principal_id"),
            (("effects",), "authority"),
        ):
            with self.subTest(path=path):
                changed = copy.deepcopy(original)
                parent = changed
                for key in path[:-1]:
                    parent = parent[key]
                if path:
                    parent[path[-1]], alias = aliased_mapping(parent[path[-1]], field)
                else:
                    changed, alias = aliased_mapping(changed, field)
                with self.assertRaises(OfflineApiSourceLedgerError):
                    verify_offline_api_source_ledger(changed)
                self.assertEqual(alias.hooks, [])


if __name__ == "__main__":
    unittest.main()

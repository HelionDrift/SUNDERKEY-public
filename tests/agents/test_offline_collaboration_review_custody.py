"""Restartable local custody of unsigned collaboration review assertions."""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sunderkey import offline_collaboration_review_custody as custody
from sunderkey import offline_collaboration_review_handoff as handoff
from sunderkey import offline_specialist_components as components
from . import test_offline_collaboration_review_handoff as fixture


class OfflineCollaborationReviewCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = fixture.OfflineCollaborationReviewHandoffTests
        source.setUpClass()
        cls.catalog = source.catalog
        cls.contexts = source.contexts
        cls.model = source.model
        cls.report = source.report
        cls.root = Path(__file__).resolve().parents[2]
        with patch.object(
            components, "_catalog_document", return_value=cls.catalog.to_dict()
        ):
            cls.packet = handoff.prepare_offline_collaboration_review_handoff(
                cls.report, model=cls.model, source_contexts=cls.contexts,
                catalog=cls.catalog, repository_root=cls.root,
            )

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "review.sqlite"
        self.store = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        self.store.initialize()

    def sources(self) -> dict:
        return {
            "packet": self.packet,
            "report": self.report,
            "model": self.model,
            "source_contexts": self.contexts,
            "catalog": self.catalog,
            "repository_root": self.root,
        }

    def record(
        self, *, request_id: str = "request.one", item_kind: str = "claim",
        item_id: str = "gcp", reviewer_role: str = "independent_control",
        reviewer_subject: str = "person.control", disposition: str = "challenge",
        reason_code: str = "source_scope_challenge", recorded_at: str = "2026-10-02T12:00:00Z",
        real_replay: bool = False,
        **source_overrides,
    ) -> dict:
        sources = {**self.sources(), **source_overrides}
        if real_replay:
            with patch.object(
                components, "_catalog_document", return_value=self.catalog.to_dict()
            ):
                return self.store.record_review(
                    request_id=request_id, item_kind=item_kind, item_id=item_id,
                    reviewer_role=reviewer_role, reviewer_subject=reviewer_subject,
                    disposition=disposition, reason_code=reason_code,
                    recorded_at=recorded_at, **sources,
                )
        with patch.object(
            custody, "_checked_handoff", return_value=sources["packet"]
        ):
            return self.store.record_review(
                request_id=request_id, item_kind=item_kind, item_id=item_id,
                reviewer_role=reviewer_role, reviewer_subject=reviewer_subject,
                disposition=disposition, reason_code=reason_code,
                recorded_at=recorded_at, **sources,
            )

    def revoke(self, entry: dict, *, request_id: str = "request.revoke", **changes) -> dict:
        return self.store.revoke_review(
            request_id=request_id,
            target_entry_sha256=entry["entry_sha256"],
            reviewer_subject=changes.pop("reviewer_subject", "person.control"),
            reason_code=changes.pop("reason_code", "reviewer_correction"),
            recorded_at=changes.pop("recorded_at", "2026-10-02T12:01:00Z"),
        )

    def current(self, *, real_replay: bool = False, **overrides) -> dict:
        sources = {**self.sources(), **overrides}
        if real_replay:
            with patch.object(
                components, "_catalog_document", return_value=self.catalog.to_dict()
            ):
                return self.store.verify_current(**sources)
        with patch.object(custody, "_checked_handoff", return_value=sources["packet"]):
            return self.store.verify_current(**sources)

    def test_append_restart_and_no_effect_summary(self) -> None:
        first = self.record(real_replay=True)
        self.assertEqual(first["sequence"], 1)
        reopened = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        reopened.initialize()
        self.assertEqual(reopened.verify_history()["head_sequence"], 1)
        report = self.current()
        row = next(row for row in report["item_review_states"] if row["item_id"] == "gcp")
        self.assertEqual(row["state"], "contested_operator_assertion")
        self.assertEqual(report["identity_assurance"], "operator_asserted_unsigned")
        self.assertEqual(report["scope_assurance"], "caller_declared_unverified")
        self.assertFalse(report["independent_review_accepted"])
        self.assertFalse(report["positive_use_approved"])
        self.assertTrue(all(value == "none" for value in report["operational_effects"].values()))

    def test_two_distinct_asserted_roles_do_not_become_accepted_review(self) -> None:
        self.record(disposition="accept_for_review_only", reason_code="declared_match")
        self.record(
            request_id="request.two", reviewer_role="independent_assurance",
            reviewer_subject="person.assurance", disposition="accept_for_review_only",
            reason_code="declared_match",
        )
        row = next(row for row in self.current()["item_review_states"] if row["item_id"] == "gcp")
        self.assertEqual(row["state"], "dual_operator_assertions_unverified")
        self.assertEqual(self.current()["review_status"], "assertions_recorded_not_accepted")

    def test_contradictory_or_unassessed_item_cannot_receive_acceptance(self) -> None:
        alternate = copy.deepcopy(self.packet)
        for item in alternate["claim_review_items"]:
            if item["claim_id"] == "gcp":
                item["status"] = "contradicts_declared_expectation"
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(packet=alternate, real_replay=True)
        status_by_id = {
            item["claim_id"]: item["status"]
            for item in self.packet["claim_review_items"]
        }
        for item_id, status in status_by_id.items():
            if status != "matches_declared_expectation":
                with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
                    self.record(
                        item_id=item_id, disposition="accept_for_review_only",
                        reason_code="declared_match",
                    )

    def test_exact_idempotency_and_rebinding(self) -> None:
        first = self.record()
        self.assertEqual(first, self.record())
        self.assertEqual(self.store.verify_history()["head_sequence"], 1)
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(disposition="needs_evidence", reason_code="missing_evidence")

    def test_same_role_or_same_subject_across_roles_fails(self) -> None:
        self.record()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(request_id="request.two", reviewer_subject="person.other")
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(
                request_id="request.three", reviewer_role="independent_assurance",
                reviewer_subject="person.control",
            )
        self.assertEqual(self.store.verify_history()["head_sequence"], 1)

    def test_revocation_preserves_history_and_allows_replacement(self) -> None:
        first = self.record()
        revoked = self.revoke(first)
        self.assertEqual(revoked, self.revoke(first))
        self.assertEqual(self.store.verify_history()["active_assertion_count"], 0)
        self.record(
            request_id="request.replacement", reviewer_subject="person.other",
            disposition="needs_evidence", reason_code="missing_evidence",
            recorded_at="2026-10-02T12:02:00Z",
        )
        row = next(row for row in self.current()["item_review_states"] if row["item_id"] == "gcp")
        self.assertEqual(row["state"], "needs_evidence_operator_assertion")
        self.assertEqual(self.store.verify_history()["head_sequence"], 3)

    def test_revocation_wrong_actor_target_or_repeat_fails(self) -> None:
        first = self.record()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.revoke(first, reviewer_subject="person.other")
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.revoke({"entry_sha256": custody.GENESIS})
        self.revoke(first)
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.revoke(first, request_id="request.revoke.again")

    def test_unsigned_withdrawal_does_not_need_current_sources(self) -> None:
        first = self.record()
        with patch.object(
            custody, "_checked_handoff",
            side_effect=custody.OfflineCollaborationReviewCustodyError("source drift"),
        ):
            self.revoke(first)
        self.assertEqual(self.store.verify_history()["active_assertion_count"], 0)

    def test_changed_sources_or_handoff_are_refused_before_append(self) -> None:
        changed_model = copy.deepcopy(self.model)
        changed_model["graph_label"] = "different"
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(model=changed_model, real_replay=True)
        self.assertEqual(self.store.verify_history()["head_sequence"], 0)

    def test_missing_item_or_declared_scope_mismatch_fails(self) -> None:
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(item_id="absent")
        foreign = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.other", declared_scope_id="declared.scope"
        )
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            foreign.verify_history()
        wrong_scope = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.example", declared_scope_id="other.scope"
        )
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            wrong_scope.verify_history()

    def test_history_tamper_and_schema_changes_fail_closed(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE custody_entries SET request_id='tampered'")
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.commit()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.store.verify_history()

    def test_same_name_noop_trigger_is_refused(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.execute(
                "CREATE TRIGGER custody_entries_no_update BEFORE UPDATE ON custody_entries "
                "BEGIN SELECT 1; END"
            )
            connection.commit()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.store.verify_history()

    def test_boolean_stored_request_schema_version_is_refused(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "SELECT entry_json FROM custody_entries WHERE sequence=1"
            ).fetchone()
            entry = json.loads(row[0])
            entry["request"]["schema_version"] = True
            request_sha = custody._digest("request", entry["request"])
            entry["request_sha256"] = request_sha
            body = {key: value for key, value in entry.items() if key not in {
                "entry_id", "entry_sha256",
            }}
            entry_sha = custody._digest("entry", body)
            entry["entry_sha256"] = entry_sha
            entry["entry_id"] = "OCR-" + entry_sha[7:39].upper()
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.execute(
                "UPDATE custody_entries SET request_sha256=?,entry_sha256=?,entry_json=? "
                "WHERE sequence=1",
                (request_sha, entry_sha, custody._canonical(entry)),
            )
            connection.execute(
                "UPDATE custody_metadata SET value=? WHERE key='head_sha256'",
                (entry_sha,),
            )
            connection.execute(custody._SCHEMA[2])
            connection.commit()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.store.verify_history()

    def test_scalar_stored_entry_is_refused_with_custody_error(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.execute("UPDATE custody_entries SET entry_json='1' WHERE sequence=1")
            connection.execute(custody._SCHEMA[2])
            connection.commit()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.store.verify_history()

    def test_missing_stored_time_is_refused_with_custody_error(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "SELECT entry_json FROM custody_entries WHERE sequence=1"
            ).fetchone()
            entry = json.loads(row[0])
            del entry["request"]["recorded_at"]
            request_sha = custody._digest("request", entry["request"])
            entry["request_sha256"] = request_sha
            body = {key: value for key, value in entry.items() if key not in {
                "entry_id", "entry_sha256",
            }}
            entry_sha = custody._digest("entry", body)
            entry["entry_sha256"] = entry_sha
            entry["entry_id"] = "OCR-" + entry_sha[7:39].upper()
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.execute(
                "UPDATE custody_entries SET request_sha256=?,entry_sha256=?,entry_json=? "
                "WHERE sequence=1",
                (request_sha, entry_sha, custody._canonical(entry)),
            )
            connection.execute(
                "UPDATE custody_metadata SET value=? WHERE key='head_sha256'",
                (entry_sha,),
            )
            connection.execute(custody._SCHEMA[2])
            connection.commit()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.store.verify_history()

    def test_store_cannot_be_rebound_to_another_handoff(self) -> None:
        self.record()
        changed = copy.deepcopy(self.packet)
        changed["handoff_sha256"] = custody.GENESIS
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.current(packet=changed)
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            self.record(request_id="request.two", packet=changed)

    def test_failed_initialization_rolls_back_all_schema_objects(self) -> None:
        path = Path(self.directory.name) / "failed-init.sqlite"
        fresh = custody.OfflineCollaborationReviewCustodyStore(
            path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        with patch.object(
            fresh, "_verify_locked",
            side_effect=custody.OfflineCollaborationReviewCustodyError("injected failure"),
        ):
            with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
                fresh.initialize()
        with closing(sqlite3.connect(path)) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_existing_empty_database_is_not_adopted(self) -> None:
        path = Path(self.directory.name) / "foreign-empty.sqlite"
        with closing(sqlite3.connect(path)):
            pass
        before = path.read_bytes()
        foreign = custody.OfflineCollaborationReviewCustodyStore(
            path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            foreign.initialize()
        self.assertEqual(path.read_bytes(), before)

    def test_existing_valid_store_is_verified_without_write(self) -> None:
        before = self.path.read_bytes()
        reopened = custody.OfflineCollaborationReviewCustodyStore(
            self.path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        reopened.initialize()
        self.assertEqual(self.path.read_bytes(), before)

    def test_symlink_database_is_refused(self) -> None:
        alias = Path(self.directory.name) / "alias.sqlite"
        try:
            alias.symlink_to(self.path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"disposable file symlinks unavailable: {exc}")
        linked = custody.OfflineCollaborationReviewCustodyStore(
            alias, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            linked.initialize()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            linked.verify_history()

    @unittest.skipUnless(os.name == "nt", "Windows reparse attributes only")
    def test_windows_reparse_attribute_is_refused(self) -> None:
        original = custody.os.lstat

        def marked(candidate):
            info = original(candidate)
            if Path(candidate) == self.path:
                return SimpleNamespace(
                    st_mode=info.st_mode,
                    st_size=info.st_size,
                    st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT,
                )
            return info

        with patch.object(custody.os, "lstat", side_effect=marked):
            with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
                self.store.verify_history()

    def test_malformed_database_raises_custody_error(self) -> None:
        path = Path(self.directory.name) / "malformed.sqlite"
        path.write_bytes(b"not a SQLite database")
        malformed = custody.OfflineCollaborationReviewCustodyStore(
            path, tenant_id="tenant.example", declared_scope_id="declared.scope"
        )
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            malformed.verify_history()
        with self.assertRaises(custody.OfflineCollaborationReviewCustodyError):
            malformed.initialize()

    def test_oversized_entry_is_refused_before_json_parse(self) -> None:
        self.record()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TRIGGER custody_entries_no_update")
            connection.execute(
                "UPDATE custody_entries SET entry_json=? WHERE sequence=1",
                ("x" * (custody.MAX_ENTRY_JSON_BYTES + 1),),
            )
            connection.execute(custody._SCHEMA[2])
            connection.commit()
        with self.assertRaisesRegex(
            custody.OfflineCollaborationReviewCustodyError, "byte limit"
        ):
            self.store.verify_history()

    def test_over_limit_rows_are_refused_before_replay(self) -> None:
        with closing(sqlite3.connect(self.path)) as connection:
            connection.executemany(
                "INSERT INTO custody_entries VALUES(?,?,?,?,?)",
                (
                    (
                        index, f"request.{index}", custody.GENESIS,
                        f"sha256:{index:064x}", "{}",
                    )
                    for index in range(1, custody.MAX_ENTRIES + 2)
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(
            custody.OfflineCollaborationReviewCustodyError, "history limit"
        ):
            self.store.verify_history()


if __name__ == "__main__":
    unittest.main()

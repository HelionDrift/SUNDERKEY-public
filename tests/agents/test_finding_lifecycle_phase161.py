"""Phase 161 finding lifecycle, dedupe, and retest contract tests."""

from __future__ import annotations

import copy
import json
import re
import unittest
from collections import deque
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.finding_lifecycle import (
    ALLOWED_TRANSITIONS,
    DedupeOutcome,
    FindingClassification,
    FindingIdentity,
    FindingLifecycleError,
    FindingSnapshot,
    FindingState,
    RetestAttempt,
    RetestPlan,
    build_finding_report,
    canonical_json,
    compare_findings,
    create_finding,
    create_merge_record,
    create_retest_plan,
    create_supersession_record,
    record_retest_attempt,
    replay_finding_events,
    transition_finding,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "finding-lifecycle-snapshot-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "finding_lifecycle.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "finding-lifecycle.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def identity(**overrides: str) -> FindingIdentity:
    values = {
        "asset": "HTTPS://API.Example.Test/",
        "surface": " Accounts API ",
        "vulnerability_class": "CWE-79",
        "root_cause": "Missing output encoding",
        "affected_boundary": "POST /v1/accounts/{id}/profile/",
        "semantic_claim": "Stored user content reaches an HTML text context",
    }
    values.update(overrides)
    return FindingIdentity(**values)


class FindingLifecyclePhase161Tests(unittest.TestCase):
    def make_finding(
        self,
        *,
        identity_value: FindingIdentity | None = None,
        minute: int = 0,
        evidence: tuple[str, ...] = (digest("a"),),
    ) -> FindingSnapshot:
        return create_finding(
            identity_value or identity(),
            classification=FindingClassification(
                severity="high",
                cwe_refs=("CWE-79",),
                cvss_refs=("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",),
            ),
            evidence_digests=evidence,
            created_at=f"2026-09-20T00:{minute:02d}:00Z",
            actor_id="principal.reviewer.1",
            authority_ref="authority.assessment.1",
            provenance_digests=(digest("b"),),
            review_decision="pending",
        )

    def advance(
        self,
        finding: FindingSnapshot,
        target: FindingState,
        minute: int,
    ) -> FindingSnapshot:
        return transition_finding(
            finding,
            target,
            occurred_at=f"2026-09-20T01:{minute:02d}:00Z",
            actor_id="principal.reviewer.1",
            authority_ref="authority.assessment.1",
            provenance_digests=(digest("c"),),
            review_decision="approved",
            reason_code="reviewed_transition",
        )

    def path_to(self, target: FindingState) -> list[FindingState]:
        queue = deque([(FindingState.NEW, [])])
        seen = {FindingState.NEW}
        while queue:
            state, path = queue.popleft()
            if state is target:
                return path
            for candidate in sorted(ALLOWED_TRANSITIONS[state], key=lambda item: item.value):
                if candidate not in seen:
                    seen.add(candidate)
                    queue.append((candidate, [*path, candidate]))
        self.fail(f"no state path to {target.value}")

    def finding_in_state(self, target: FindingState) -> FindingSnapshot:
        finding = self.make_finding()
        for minute, state in enumerate(self.path_to(target), start=1):
            finding = self.advance(finding, state, minute)
        return finding

    def test_snapshot_is_deterministic_content_addressed_and_schema_valid(self) -> None:
        first = self.make_finding()
        second = self.make_finding()
        self.assertEqual(first, second)
        self.assertEqual(first.identity.asset, "https://api.example.test")
        self.assertEqual(first.identity.surface, "accounts api")
        self.assertEqual(first.identity.affected_boundary, "post /v1/accounts/{id}/profile")
        document = first.to_dict()
        self.assertRegex(document["snapshot_sha256"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(document["dedupe_fingerprint"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("cvss_score", canonical_json(document))
        self.assertEqual(set(document["effects"].values()), {"none"})
        self.assertEqual(FindingSnapshot.from_dict(document), first)
        if Draft202012Validator is not None:
            schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(document)

    def test_every_declared_transition_path_is_accepted(self) -> None:
        for source, targets in ALLOWED_TRANSITIONS.items():
            for target in targets:
                with self.subTest(source=source.value, target=target.value):
                    current = self.finding_in_state(source)
                    successor = self.advance(current, target, 50)
                    self.assertEqual(successor.state, target)
                    self.assertEqual(successor.finding_version, current.finding_version + 1)
                    successor.verify_parent(current)

    def test_every_undeclared_transition_is_rejected(self) -> None:
        for source in FindingState:
            current = self.finding_in_state(source)
            for target in FindingState:
                if target in ALLOWED_TRANSITIONS[source]:
                    continue
                with (
                    self.subTest(source=source.value, target=target.value),
                    self.assertRaises(FindingLifecycleError),
                ):
                    self.advance(current, target, 50)

    def test_tamper_unknown_fields_rollback_and_evidence_substitution_fail(self) -> None:
        parent = self.make_finding()
        child = self.advance(parent, FindingState.TRIAGED, 1)
        cases = []

        unknown = copy.deepcopy(child.to_dict())
        unknown["payload"] = "raw request body"
        cases.append(unknown)

        effect = copy.deepcopy(child.to_dict())
        effect["effects"]["network"] = "enabled"
        cases.append(effect)

        digest_tamper = copy.deepcopy(child.to_dict())
        digest_tamper["identity"]["asset"] = "https://other.example.test"
        cases.append(digest_tamper)

        event_tamper = copy.deepcopy(child.to_dict())
        event_tamper["events"][1]["previous_event_sha256"] = digest("f")
        cases.append(event_tamper)

        rollback = copy.deepcopy(child.to_dict())
        rollback["events"][1]["finding_version"] = 1
        cases.append(rollback)

        substitution = copy.deepcopy(child.to_dict())
        substitution["events"][0]["evidence_digests"] = [digest("d")]
        cases.append(substitution)

        for document in cases:
            with self.subTest(case=cases.index(document)), self.assertRaises(FindingLifecycleError):
                FindingSnapshot.from_dict(document)

        wrong_parent = self.make_finding(minute=2)
        with self.assertRaises(FindingLifecycleError):
            child.verify_parent(wrong_parent)

    def test_secret_raw_evidence_and_mutable_evidence_are_rejected(self) -> None:
        with self.assertRaises(FindingLifecycleError):
            identity(semantic_claim="Authorization: Bearer abcdefghijklmnop")
        with self.assertRaises(FindingLifecycleError):
            create_finding(
                identity(),
                evidence_digests=({"payload": "raw"},),
                created_at="2026-09-20T00:00:00Z",
                actor_id="principal.one",
                authority_ref="authority.one",
                provenance_digests=(digest("b"),),
            )
        mutable = copy.deepcopy(self.make_finding().to_dict())
        mutable["evidence"] = [{"uri": "https://mutable.invalid/evidence"}]
        with self.assertRaises(FindingLifecycleError):
            FindingSnapshot.from_dict(mutable)

    def test_dedupe_all_outcomes_and_ambiguity_never_auto_merge(self) -> None:
        exact = compare_findings(identity(), identity(asset=" https://api.example.test "))
        self.assertEqual(exact.outcome, DedupeOutcome.EXACT_DUPLICATE)

        likely = compare_findings(
            identity(),
            identity(
                root_cause="Template context is not encoded",
                semantic_claim="Stored content reaches an HTML attribute context",
            ),
        )
        self.assertEqual(likely.outcome, DedupeOutcome.LIKELY_RELATED)

        distinct = compare_findings(
            identity(),
            identity(affected_boundary="GET /v1/public/catalog"),
        )
        self.assertEqual(distinct.outcome, DedupeOutcome.DISTINCT)

        incomplete = compare_findings(identity(), identity(root_cause="unknown"))
        self.assertEqual(incomplete.outcome, DedupeOutcome.INSUFFICIENT_EVIDENCE)

        weak = compare_findings(
            identity(),
            identity(
                surface="admin console",
                root_cause="missing authorization check",
                semantic_claim="a user can delete another account",
            ),
        )
        self.assertEqual(weak.outcome, DedupeOutcome.INSUFFICIENT_EVIDENCE)
        for decision in (exact, likely, distinct, incomplete, weak):
            self.assertFalse(decision.auto_merge_permitted)
            self.assertTrue(decision.reason_codes)

    def test_merge_supersession_preserve_sources_and_reject_cycles(self) -> None:
        canonical = self.make_finding(minute=0)
        source_a = self.make_finding(minute=1)
        source_b = self.make_finding(minute=2)
        merge = create_merge_record(
            canonical,
            (source_b, source_a),
            created_at="2026-09-20T02:00:00Z",
            actor_id="principal.reviewer.2",
            authority_ref="authority.canonicalization.1",
            provenance_digests=(digest("d"),),
            review_decision="approved",
            reason_code="reviewed_duplicate",
        )
        self.assertEqual(
            set(merge.all_finding_ids),
            {canonical.finding_id, source_a.finding_id, source_b.finding_id},
        )
        self.assertEqual(type(merge).from_dict(merge.to_dict()), merge)

        successor = self.make_finding(minute=3)
        supersession = create_supersession_record(
            successor,
            (canonical,),
            existing_records=(merge,),
            created_at="2026-09-20T02:01:00Z",
            actor_id="principal.reviewer.2",
            authority_ref="authority.canonicalization.1",
            provenance_digests=(digest("d"),),
            review_decision="approved",
            reason_code="model_replaced",
        )
        self.assertEqual(supersession.source_finding_ids, (canonical.finding_id,))

        with self.assertRaises(FindingLifecycleError):
            create_merge_record(
                source_a,
                (canonical,),
                existing_records=(merge,),
                created_at="2026-09-20T02:02:00Z",
                actor_id="principal.reviewer.2",
                authority_ref="authority.canonicalization.1",
                provenance_digests=(digest("d"),),
                review_decision="approved",
                reason_code="cycle_attempt",
            )
        with self.assertRaises(FindingLifecycleError):
            create_merge_record(
                canonical,
                (source_a,),
                created_at="2026-09-20T02:02:00Z",
                actor_id="principal.reviewer.2",
                authority_ref="authority.canonicalization.1",
                provenance_digests=(digest("d"),),
                review_decision="pending",
                reason_code="unreviewed",
            )

    def make_retest_pending(self) -> FindingSnapshot:
        current = self.make_finding()
        for minute, state in enumerate(
            (
                FindingState.TRIAGED,
                FindingState.VALIDATED,
                FindingState.ACCEPTED,
                FindingState.REMEDIATION_IN_PROGRESS,
                FindingState.RETEST_PENDING,
            ),
            start=1,
        ):
            current = self.advance(current, state, minute)
        return current

    def make_plan(self, finding: FindingSnapshot, *, mode: str = "original") -> RetestPlan:
        return create_retest_plan(
            finding=finding,
            original_validation_result="validated",
            original_validation_evidence_digests=(digest("a"),),
            scope_ref="scope.authorized.1",
            technique_ref="technique.original.1",
            technique_mode=mode,
            candidate_validator_versions=("validator.b.v2", "validator.a.v1"),
            authorized_at="2026-09-20T02:00:00Z",
            actor_id="principal.reviewer.3",
            authority_ref="authority.retest.1",
            provenance_digests=(digest("e"),),
            review_decision="approved",
        )

    def test_retest_results_bind_plan_prior_version_and_new_evidence(self) -> None:
        expected_states = {
            "fixed": FindingState.RESOLVED,
            "persists": FindingState.REOPENED,
            "regressed": FindingState.REOPENED,
            "inconclusive": FindingState.RETEST_PENDING,
            "abstained": FindingState.RETEST_PENDING,
        }
        evidence_characters = ("f", "1", "2", "3", "4")
        for index, (result, expected_state) in enumerate(expected_states.items()):
            with self.subTest(result=result):
                finding = self.make_retest_pending()
                plan = self.make_plan(finding)
                attempt, updated = record_retest_attempt(
                    plan,
                    finding,
                    result=result,
                    new_evidence_digests=(digest(evidence_characters[index]),),
                    recorded_at="2026-09-20T02:01:00Z",
                    actor_id="principal.validator.1",
                    authority_ref="authority.retest.1",
                    provenance_digests=(digest("e"),),
                    review_decision="approved",
                )
                self.assertEqual(updated.state, expected_state)
                self.assertEqual(attempt.prior_finding_version, finding.finding_version)
                self.assertEqual(attempt.prior_snapshot_sha256, finding.snapshot_sha256)
                self.assertEqual(attempt.original_validation_result.value, "validated")
                self.assertEqual(
                    RetestAttempt.from_dict(attempt.to_dict(), expected_plan=plan),
                    attempt,
                )
                self.assertEqual(RetestPlan.from_dict(plan.to_dict()), plan)

    def test_alternate_plan_stale_binding_and_evidence_reuse_fail(self) -> None:
        finding = self.make_retest_pending()
        alternate = self.make_plan(finding, mode="alternate")
        with self.assertRaises(FindingLifecycleError):
            record_retest_attempt(
                alternate,
                finding,
                result="persists",
                new_evidence_digests=(digest("f"),),
                recorded_at="2026-09-20T02:01:00Z",
                actor_id="principal.validator.1",
                authority_ref="authority.retest.1",
                provenance_digests=(digest("e"),),
                review_decision="approved",
            )

        plan = self.make_plan(finding)
        stale = transition_finding(
            finding,
            FindingState.REOPENED,
            occurred_at="2026-09-20T02:01:00Z",
            actor_id="principal.reviewer.3",
            authority_ref="authority.retest.1",
            provenance_digests=(digest("e"),),
            review_decision="approved",
            reason_code="manual_reopen",
        )
        with self.assertRaises(FindingLifecycleError):
            record_retest_attempt(
                plan,
                stale,
                result="persists",
                new_evidence_digests=(digest("f"),),
                recorded_at="2026-09-20T02:02:00Z",
                actor_id="principal.validator.1",
                authority_ref="authority.retest.1",
                provenance_digests=(digest("e"),),
                review_decision="approved",
            )
        with self.assertRaises(FindingLifecycleError):
            record_retest_attempt(
                plan,
                finding,
                result="fixed",
                new_evidence_digests=(digest("a"),),
                recorded_at="2026-09-20T02:01:00Z",
                actor_id="principal.validator.1",
                authority_ref="authority.retest.1",
                provenance_digests=(digest("e"),),
                review_decision="approved",
            )

    def test_replay_report_determinism_and_no_effect_fields(self) -> None:
        finding = self.make_retest_pending()
        plan = self.make_plan(finding)
        attempt, updated = record_retest_attempt(
            plan,
            finding,
            result="fixed",
            new_evidence_digests=(digest("f"),),
            recorded_at="2026-09-20T02:01:00Z",
            actor_id="principal.validator.1",
            authority_ref="authority.retest.1",
            provenance_digests=(digest("e"),),
            review_decision="approved",
        )
        replay = replay_finding_events(updated.events)
        self.assertEqual(replay.current_state, updated.state)
        self.assertEqual(replay.finding_version, updated.finding_version)
        self.assertEqual(replay.evidence_digests, updated.evidence_digests)
        report_a = build_finding_report(updated, retest_attempts=(attempt,))
        report_b = build_finding_report(updated, retest_attempts=(attempt,))
        self.assertEqual(report_a, report_b)
        report = report_a.to_dict()
        self.assertEqual(report["current_state"], "resolved")
        self.assertEqual(len(report["history"]), updated.finding_version)
        self.assertEqual(set(report["effects"].values()), {"none"})
        self.assertNotIn("payload", canonical_json(report))

    def test_retest_tamper_unknown_fields_and_operational_effect_fail(self) -> None:
        finding = self.make_retest_pending()
        plan = self.make_plan(finding)
        attempt, _ = record_retest_attempt(
            plan,
            finding,
            result="fixed",
            new_evidence_digests=(digest("f"),),
            recorded_at="2026-09-20T02:01:00Z",
            actor_id="principal.validator.1",
            authority_ref="authority.retest.1",
            provenance_digests=(digest("e"),),
            review_decision="approved",
        )
        for raw, parser in (
            (plan.to_dict(), RetestPlan.from_dict),
            (attempt.to_dict(), RetestAttempt.from_dict),
        ):
            unknown = copy.deepcopy(raw)
            unknown["execute"] = True
            with self.assertRaises(FindingLifecycleError):
                parser(unknown)
            effect = copy.deepcopy(raw)
            effect["effects"]["tools"] = "invoke"
            with self.assertRaises(FindingLifecycleError):
                parser(effect)
            tamper = copy.deepcopy(raw)
            digest_field = "plan_sha256" if "plan_sha256" in tamper else "attempt_sha256"
            tamper[digest_field] = digest("9")
            with self.assertRaises(FindingLifecycleError):
                parser(tamper)

    def test_files_have_no_dash_unicode_or_incomplete_markers(self) -> None:
        marker_pattern = re.compile(
            r"(?i)(?:\bTO" + r"DO\b|\bFIX" + r"ME\b|\bT" + r"BD\b|"
            r"not[ _-]imple" + r"mented|place" + r"holder)"
        )
        for path in FILES:
            with self.subTest(path=path):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                self.assertIsNone(marker_pattern.search(text))


if __name__ == "__main__":
    unittest.main()
